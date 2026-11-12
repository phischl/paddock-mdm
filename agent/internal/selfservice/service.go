package selfservice

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"log/slog"
	"net/http"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/phischl/paddock-mdm/agent/internal/desktop"
	"github.com/phischl/paddock-mdm/agent/internal/reconcile"
	"github.com/phischl/paddock-mdm/pkg/bundle"
	"github.com/phischl/paddock-mdm/pkg/protocol"
)

// Limits of the executor (plan M13b decisions 12 and 13, ADR 0049 decision 8).
const (
	// OperationTimeout ends a running operation as failed/timeout; its command is killed.
	OperationTimeout = 30 * time.Minute
	// ProbeTimeout bounds one probe of the installed state: a user-scope probe runs in the user's own service
	// manager, which that user can stall.
	ProbeTimeout = 30 * time.Second
	// MaxQueuedPerUser bounds the queued and running operations of one UID.
	MaxQueuedPerUser = 5
	// NoticesPerHour bounds the desktop notifications of one user.
	NoticesPerHour = 5
	// keepFinished bounds the finished operations kept for GET /v1/operations/{id}.
	keepFinished = 100
)

// Operation states (plan M13b §3.1).
const (
	StateQueued  = "queued"
	StateRunning = "running"
)

// DefaultNotice is the first-start transparency notice (plan M13b §6.5).
const DefaultNotice = "Your organization offers applications through Paddock. Installing, updating or removing an " +
	"application here is recorded with your user name. Nothing else about how you use this device is collected."

// Packages are the software reconciler's primitives the executor runs (reconcile.Software).
type Packages interface {
	InstallOne(ctx context.Context, sp bundle.SoftwareSpec, p bundle.SoftwarePackage, uid int) reconcile.SelfServiceResult
	UpdateOne(ctx context.Context, sp bundle.SoftwareSpec, p bundle.SoftwarePackage, uid int) reconcile.SelfServiceResult
	RemoveOne(ctx context.Context, sp bundle.SoftwareSpec, p bundle.SoftwarePackage, uid int) reconcile.SelfServiceResult
	SelfServiceInstalled(ctx context.Context, p bundle.SoftwarePackage, uid int) (bool, string, error)
}

// IconFetch fetches the PNG icon of a catalog entry from the server (the device client's GET /v1/catalog/{id}/icon).
type IconFetch func(ctx context.Context, entryID string) ([]byte, error)

// Config are the dependencies of a Service.
type Config struct {
	Sys      reconcile.System
	Packages Packages
	// Version is the agent version GET /v1/status names.
	Version string
	Now     func() time.Time
	// Notify tells the sessions of uid; nil uses desktop.NotifyUser.
	Notify func(ctx context.Context, uid int, summary, body string)
	// ProbeTimeout overrides the package ProbeTimeout when not zero.
	ProbeTimeout time.Duration
}

// Service is the self-service: the authorization view of the applied bundle, the operation queue and its executor.
// The agent's run loop hands it every applied bundle (SetBundle) and spools what Events delivers; the socket server
// and the executor goroutine read it under mu.
type Service struct {
	cfg    Config
	mu     sync.Mutex
	snap   snapshot
	record Record
	ops    map[string]*operation
	queue  []*operation
	run    *operation
	// installed caches whether an application is installed (probeKey), refreshed by the executor goroutine: a request
	// answers from memory, never by running a package tool.
	installed map[string]probe
	failed    map[string]*operation // the last failed or refused operation per probeKey of a user
	finished  []string
	rate      map[int]*window
	notices   map[int][]time.Time
	icons     iconCache
	wake      chan struct{}
	iconWake  chan struct{}
	reconcile bool
	events    chan protocol.SoftwareSelfService
	requests  chan protocol.SoftwareRequest
	withdrawn chan protocol.SoftwareRequestWithdrawn
	asked     map[int][]time.Time // the recent requests per UID (RequestsPerHour)
}

// snapshot is what the service knows of the applied bundle.
type snapshot struct {
	applied bool
	spec    bundle.SoftwareSpec
	domain  string
	version int64
	fetch   IconFetch
}

type probe struct {
	installed bool
	version   string
}

type operation struct {
	id         string
	principal  Principal
	pkg        bundle.SoftwarePackage
	action     string
	state      string
	reason     string
	startedAt  *time.Time
	finishedAt *time.Time
}

// OperationView is the body of GET /v1/operations/{id} (plan M13b §6.2).
type OperationView struct {
	ID         string     `json:"id"`
	EntryID    string     `json:"entry_id"`
	Action     string     `json:"action"`
	State      string     `json:"state"`
	Position   int        `json:"position"`
	Reason     string     `json:"reason,omitempty"`
	StartedAt  *time.Time `json:"started_at"`
	FinishedAt *time.Time `json:"finished_at"`
}

// AppView is one application of GET /v1/apps (plan M13b §6.2). The bundle carries no catalog texts, so Name is the
// package or the Flatpak application ID and Description and Category stay empty.
type AppView struct {
	EntryID     string `json:"entry_id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Category    string `json:"category"`
	Kind        string `json:"kind"`
	Scope       string `json:"scope"`
	Intent      string `json:"intent"`
	Managed     bool   `json:"managed"`
	Installable bool   `json:"installable"`
	Removable   bool   `json:"removable"`
	Updatable   bool   `json:"updatable"`
	State       string `json:"state"`
	Version     string `json:"version,omitempty"`
	Reason      string `json:"reason,omitempty"`
	Icon        bool   `json:"icon"`
	// Approval is bundle.SoftwareApprovalRequired for an entry that requires approval (plan M13c decision 9).
	// Requestable is set when the caller may ask for it; Request is the caller's pending or denied request.
	Approval    string       `json:"approval,omitempty"`
	Requestable bool         `json:"requestable"`
	Request     *RequestView `json:"request,omitempty"`
}

// Problem is a refusal of the socket API: an HTTP status and a stable code. Its detail never names another user's
// entries or operations.
type Problem struct {
	Status int
	Code   string
	Detail string
}

func (p *Problem) Error() string { return p.Code + ": " + p.Detail }

// Codes of the socket API's problems besides the refusal reasons of protocol.SoftwareSelfService.
const (
	CodeNoBundle        = "no_bundle"
	CodeUnknownEntry    = "unknown_entry"
	CodeNotFound        = "not_found"
	CodeBusy            = "busy"
	CodeRateLimited     = "rate_limited"
	CodeUnauthenticated = "unauthenticated"
	CodeBodyTooLarge    = "body_too_large"
)

var errNoBundle = &Problem{Status: http.StatusServiceUnavailable, Code: CodeNoBundle, Detail: "no policy has been applied on this device yet"}

// New creates the service. It reads the record; Start runs the executor.
func New(cfg Config) *Service {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.ProbeTimeout == 0 {
		cfg.ProbeTimeout = ProbeTimeout
	}
	if cfg.Notify == nil {
		sys := cfg.Sys
		cfg.Notify = func(ctx context.Context, uid int, summary, body string) {
			if _, err := desktop.NotifyUser(ctx, sys, uid, summary, body); err != nil {
				slog.WarnContext(ctx, "self-service notification not shown", "error", err)
			}
		}
	}
	return &Service{cfg: cfg, record: loadRecord(cfg.Sys), ops: map[string]*operation{}, installed: map[string]probe{},
		failed: map[string]*operation{}, rate: map[int]*window{}, notices: map[int][]time.Time{}, icons: iconCache{tried: map[string]bool{}, gap: iconGap},
		wake: make(chan struct{}, 1), iconWake: make(chan struct{}, 1), events: make(chan protocol.SoftwareSelfService, 64),
		requests: make(chan protocol.SoftwareRequest, 64), withdrawn: make(chan protocol.SoftwareRequestWithdrawn, 64),
		asked: map[int][]time.Time{}}
}

// Events delivers the software.self_service events; the run loop spools them (the spool is the loop's alone).
func (s *Service) Events() <-chan protocol.SoftwareSelfService { return s.events }

// SetBundle hands the service the applied bundle (nil: none yet); a report-only bundle offers nothing to execute
// (plan M11). It also refreshes the installed state and the icons, and so runs after every drift pass too: a
// self-service app removed by hand leaves the record there (F10). fetch fetches icons with the device's credentials.
func (s *Service) SetBundle(b *bundle.Bundle, fetch IconFetch) {
	snap := snapshot{fetch: fetch}
	if b != nil && b.Mode != bundle.ModeReportOnly {
		snap.applied, snap.version = true, b.BundleVersion
		if b.Software != nil {
			snap.spec = *b.Software
		}
		snap.domain = loginDomain(b)
	}
	s.mu.Lock()
	s.snap = snap
	s.reconcile = true
	if snap.applied {
		if kept, dropped := pruneRequests(s.record.Requests, snap.spec, s.cfg.Now()); dropped {
			s.record.Requests = kept
			if err := saveRecord(s.cfg.Sys, s.record); err != nil {
				slog.Error("writing the self-service record failed", "error", err)
			}
		}
	}
	s.mu.Unlock()
	signal(s.wake)
	signal(s.iconWake)
}

func signal(ch chan struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}

func loginDomain(b *bundle.Bundle) string {
	for _, r := range b.Resources {
		var spec bundle.LoginSpec
		if r.Type == bundle.TypeLogin && json.Unmarshal(r.Spec, &spec) == nil {
			return spec.Himmelblau.Domain
		}
	}
	return ""
}

// Start runs the executor and the icon cache until ctx ends. An operation the last process left running is reported
// as failed/interrupted first (F4); the next drift pass reconciles the device.
func (s *Service) Start(ctx context.Context) {
	s.interrupted(ctx)
	go s.execute(ctx)
	go s.fillIcons(ctx)
}

// interrupted reports the operation of RunningFile as failed/interrupted and keeps it for the app to poll.
func (s *Service) interrupted(ctx context.Context) {
	data, _, err := s.cfg.Sys.ReadFile(RunningFile)
	if errors.Is(err, fs.ErrNotExist) {
		return
	}
	defer func() {
		if err := s.cfg.Sys.Remove(RunningFile); err != nil && !errors.Is(err, fs.ErrNotExist) {
			slog.WarnContext(ctx, "removing the self-service running marker failed", "error", err)
		}
	}()
	var r running
	if err == nil {
		err = json.Unmarshal(data, &r)
	}
	if err != nil {
		slog.WarnContext(ctx, "self-service running marker unreadable", "error", err)
		return
	}
	upn := ""
	if r.UID >= DirectoryUIDMin && r.UID <= DirectoryUIDMax {
		upn = r.User
	}
	op := &operation{id: r.ID, principal: Principal{UID: r.UID, Name: r.User, UPN: upn}, action: r.Action, state: StateRunning,
		pkg: bundle.SoftwarePackage{CatalogEntryID: r.EntryID, Package: r.Package, FlatpakRef: r.FlatpakRef, Scope: scopeField(r.Scope)}}
	started := r.StartedAt
	op.startedAt = &started
	s.mu.Lock()
	s.ops[op.id] = op
	s.mu.Unlock()
	s.finish(ctx, op, protocol.SelfServiceFailed, protocol.SelfServiceInterrupted, "")
}

func scopeField(sc string) string {
	if sc == bundle.SoftwareScopeUser {
		return sc
	}
	return ""
}

// Enqueue queues an operation of p on entryID after the authorization of ADR 0049 decision 3: the entry is one p may
// see; install needs an available entry of p's audience that is not installed, remove and update one that
// self-service installed (for p, when it is user scope); a managed entry is read-only.
func (s *Service) Enqueue(p Principal, entryID, action string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.snap.applied {
		return "", errNoBundle
	}
	pkg, ok := find(s.snap.spec, entryID, p)
	if !ok {
		return "", &Problem{Status: http.StatusNotFound, Code: CodeUnknownEntry, Detail: "no such application"}
	}
	if managed(pkg) || action != protocol.SelfServiceInstall && !s.record.has(pkg, p.UID) {
		return "", &Problem{Status: http.StatusForbidden, Code: protocol.SelfServiceRequiredByPolicy,
			Detail: "the application is managed by your organization"}
	}
	if action == protocol.SelfServiceInstall && s.installed[probeKey(pkg, p.UID)].installed {
		return "", &Problem{Status: http.StatusForbidden, Code: protocol.SelfServiceRequiredByPolicy,
			Detail: "the application is already installed"}
	}
	if action == protocol.SelfServiceInstall && !approvedFor(pkg, p) {
		return "", &Problem{Status: http.StatusForbidden, Code: CodeApprovalRequired,
			Detail: "the application needs an administrator's approval"}
	}
	n := 0
	for _, op := range s.queue {
		if op.principal.UID == p.UID {
			n++
		}
	}
	if s.run != nil && s.run.principal.UID == p.UID {
		n++
	}
	if n >= MaxQueuedPerUser {
		return "", &Problem{Status: http.StatusTooManyRequests, Code: CodeBusy, Detail: "too many operations are queued"}
	}
	id, err := newID()
	if err != nil {
		return "", err
	}
	op := &operation{id: id, principal: p, pkg: pkg, action: action, state: StateQueued}
	s.ops[id] = op
	s.queue = append(s.queue, op)
	signal(s.wake)
	return id, nil
}

func newID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// Operation returns p's operation; another user's operation is not found (plan M13b §6.2).
func (s *Service) Operation(p Principal, id string) (OperationView, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	op, ok := s.ops[id]
	if !ok || op.principal.UID != p.UID {
		return OperationView{}, false
	}
	v := OperationView{ID: op.id, EntryID: op.pkg.CatalogEntryID, Action: op.action, State: op.state, Reason: op.reason,
		StartedAt: op.startedAt, FinishedAt: op.finishedAt}
	if i := slices.Index(s.queue, op); i >= 0 {
		v.Position = i + 1
	}
	return v, true
}

// execute is the executor goroutine: one operation at a time (ADR 0049 decision 2), and after a new bundle or drift
// pass the refresh of the installed state and the record.
func (s *Service) execute(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.wake:
		}
		s.drain(ctx)
	}
}

// drain runs the pending refresh and the queued operations until neither is left. A refresh never runs twice in a
// row while operations wait: the drift pass asks for one every few minutes, and refreshes alone must not keep every
// user's operations from running (plan M13b decision 13).
func (s *Service) drain(ctx context.Context) {
	refreshed := false
	for ctx.Err() == nil {
		s.mu.Lock()
		refresh := s.reconcile && (!refreshed || len(s.queue) == 0)
		if refresh {
			s.reconcile = false
		}
		idle := !refresh && len(s.queue) == 0
		s.mu.Unlock()
		switch {
		case refresh:
			s.refresh(ctx)
			refreshed = true
		case idle:
			return
		default:
			refreshed = false
			if op := s.next(ctx); op != nil {
				s.runOp(ctx, op)
			}
		}
	}
}

// next takes the next queued operation and re-authorizes it against the bundle applied now (F3); a refused one is
// finished here and nil returned when nothing runnable is left.
func (s *Service) next(ctx context.Context) *operation {
	for {
		s.mu.Lock()
		if len(s.queue) == 0 {
			s.mu.Unlock()
			return nil
		}
		op := s.queue[0]
		s.queue = s.queue[1:]
		reason := s.reauthorize(op)
		if reason == "" {
			now := s.cfg.Now()
			op.state, op.startedAt, s.run = StateRunning, &now, op
		}
		s.mu.Unlock()
		if reason == "" {
			return op
		}
		s.finish(ctx, op, protocol.SelfServiceRefused, reason, "")
	}
}

// reauthorize returns the refusal reason of op under the bundle applied now, "" when it may run. Called with mu held.
func (s *Service) reauthorize(op *operation) string {
	if !s.snap.applied {
		return protocol.SelfServiceNotInAudience
	}
	i := slices.IndexFunc(s.snap.spec.Packages, func(p bundle.SoftwarePackage) bool { return samePackage(p, op.pkg) })
	if i < 0 {
		return protocol.SelfServiceNotInAudience
	}
	pkg := s.snap.spec.Packages[i]
	switch {
	case managed(pkg):
		return protocol.SelfServiceRequiredByPolicy
	case pkg.CatalogEntryID != op.pkg.CatalogEntryID || !inAudience(pkg, op.principal):
		return protocol.SelfServiceNotInAudience
	case op.action != protocol.SelfServiceInstall && !s.record.has(pkg, op.principal.UID):
		return protocol.SelfServiceRequiredByPolicy
	case op.action == protocol.SelfServiceInstall && s.installed[probeKey(pkg, op.principal.UID)].installed:
		return protocol.SelfServiceRequiredByPolicy
	case op.action == protocol.SelfServiceInstall && !approvedFor(pkg, op.principal):
		// The event's closed reason set has no approval reason; without approval the user is not offered the install.
		return protocol.SelfServiceNotInAudience
	}
	op.pkg = pkg
	return ""
}

// runOp runs a re-authorized operation with OperationTimeout. RunningFile marks it while it runs: an agent stopped
// meanwhile reports it as interrupted at its next start (F4), so a stopping agent finishes nothing here.
func (s *Service) runOp(ctx context.Context, op *operation) {
	s.mu.Lock()
	sp := s.snap.spec
	s.mu.Unlock()
	marker, _ := json.Marshal(running{ID: op.id, UID: op.principal.UID, User: op.principal.User(), EntryID: op.pkg.CatalogEntryID,
		Package: op.pkg.Package, FlatpakRef: op.pkg.FlatpakRef, Scope: scope(op.pkg), Action: op.action, StartedAt: *op.startedAt})
	if err := s.cfg.Sys.WriteFileAtomic(RunningFile, marker, 0o600, 0, 0); err != nil {
		slog.WarnContext(ctx, "writing the self-service running marker failed", "error", err)
	}
	octx, cancel := context.WithTimeout(ctx, OperationTimeout)
	var res reconcile.SelfServiceResult
	switch op.action {
	case protocol.SelfServiceRemove:
		res = s.cfg.Packages.RemoveOne(octx, sp, op.pkg, op.principal.UID)
	case protocol.SelfServiceUpdate:
		res = s.cfg.Packages.UpdateOne(octx, sp, op.pkg, op.principal.UID)
	default:
		res = s.cfg.Packages.InstallOne(octx, sp, op.pkg, op.principal.UID)
	}
	timedOut := errors.Is(octx.Err(), context.DeadlineExceeded)
	cancel()
	if ctx.Err() != nil {
		return
	}
	if err := s.cfg.Sys.Remove(RunningFile); err != nil && !errors.Is(err, fs.ErrNotExist) {
		slog.WarnContext(ctx, "removing the self-service running marker failed", "error", err)
	}
	if timedOut && res.Failed() {
		res.Reason = protocol.SelfServiceTimeout
	}
	if res.Failed() {
		slog.WarnContext(ctx, "self-service operation failed", "action", op.action, "entry_id", op.pkg.CatalogEntryID,
			"reason", res.Reason, "error", res.Error)
		s.finish(ctx, op, protocol.SelfServiceFailed, res.Reason, res.Version)
		return
	}
	if res.Present {
		// Installed outside self-service (by the policy, the image or by hand): it never enters the record, so no
		// audience user can remove it (ADR 0049 decision 3).
		s.mu.Lock()
		s.installed[probeKey(op.pkg, op.principal.UID)] = probe{installed: true, version: res.Version}
		s.mu.Unlock()
		s.finish(ctx, op, protocol.SelfServiceRefused, protocol.SelfServiceRequiredByPolicy, res.Version)
		return
	}
	s.recordResult(ctx, op, res.Version)
	s.finish(ctx, op, protocol.SelfServiceSucceeded, "", res.Version)
}

// recordResult keeps the record and the installed state of a succeeded operation.
func (s *Service) recordResult(ctx context.Context, op *operation, version string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	uid := op.principal.UID
	installs := slices.DeleteFunc(slices.Clone(s.record.Installs), func(i Install) bool { return i.installedBy(op.pkg, uid) })
	if op.action != protocol.SelfServiceRemove {
		inst := Install{EntryID: op.pkg.CatalogEntryID, Package: op.pkg.Package, FlatpakRef: op.pkg.FlatpakRef, Scope: scope(op.pkg),
			Username: op.principal.User(), InstalledAt: s.cfg.Now().UTC(), Version: version}
		if userScoped(op.pkg) {
			inst.UID = uid
		}
		installs = append(installs, inst)
	}
	s.record.Installs = installs
	s.installed[probeKey(op.pkg, uid)] = probe{installed: op.action != protocol.SelfServiceRemove, version: version}
	if err := saveRecord(s.cfg.Sys, s.record); err != nil {
		slog.ErrorContext(ctx, "writing the self-service record failed", "error", err)
	}
}

// finish ends an operation: its state, one capped notification of the user who asked (ADR 0049 decision 8) and
// exactly one software.self_service event (decision 7).
func (s *Service) finish(ctx context.Context, op *operation, outcome, reason, version string) {
	now := s.cfg.Now()
	s.mu.Lock()
	op.state, op.reason, op.finishedAt = outcome, reason, &now
	if s.run == op {
		s.run = nil
	}
	key := failKey(op.pkg, op.principal.UID)
	if outcome == protocol.SelfServiceSucceeded {
		delete(s.failed, key)
	} else {
		s.failed[key] = op
	}
	s.finished = append(s.finished, op.id)
	for len(s.finished) > keepFinished {
		delete(s.ops, s.finished[0])
		s.finished = s.finished[1:]
	}
	// ADR 0024: only a server that renders available packages or Flatpak sources knows the event.
	emit := selfServiceBundle(s.snap.spec)
	notify := s.noticeAllowed(op.principal.UID, now)
	s.mu.Unlock()
	if notify {
		summary, body := notice(desktop.Language(s.cfg.Sys), op, outcome, reason)
		s.cfg.Notify(ctx, op.principal.UID, summary, body)
	}
	if emit {
		ev := protocol.SoftwareSelfService{User: op.principal.User(), EntryID: op.pkg.CatalogEntryID, Package: op.pkg.Package,
			FlatpakRef: op.pkg.FlatpakRef, Scope: scope(op.pkg), Action: op.action, Outcome: outcome, Reason: reason, Version: version}
		select {
		case s.events <- ev:
		case <-ctx.Done():
		}
	}
}

// selfServiceBundle reports whether the spec has an available package or a Flatpak source.
func selfServiceBundle(sp bundle.SoftwareSpec) bool {
	return slices.ContainsFunc(sp.Packages, func(p bundle.SoftwarePackage) bool { return p.Intent == bundle.SoftwareAvailable }) ||
		slices.ContainsFunc(sp.Sources, func(src bundle.SoftwareSource) bool { return src.Kind == bundle.SoftwareSourceFlatpak })
}

// noticeAllowed counts a notification of uid at now against NoticesPerHour. Called with mu held.
func (s *Service) noticeAllowed(uid int, now time.Time) bool {
	recent := slices.DeleteFunc(s.notices[uid], func(t time.Time) bool { return now.Sub(t) >= time.Hour })
	if len(recent) >= NoticesPerHour {
		s.notices[uid] = recent
		return false
	}
	s.notices[uid] = append(recent, now)
	return true
}

// probeKey names an application's installation: the device's, or the user's for a user-scope one.
func probeKey(pkg bundle.SoftwarePackage, uid int) string {
	key := pkg.Package
	if pkg.FlatpakRef != "" {
		key = "flatpak:" + pkg.FlatpakRef
	}
	if userScoped(pkg) {
		key += "@" + strconv.Itoa(uid)
	}
	return key
}

// failKey names the last failed operation of one user on an application.
func failKey(pkg bundle.SoftwarePackage, uid int) string {
	return probeKey(pkg, uid) + "#" + strconv.Itoa(uid)
}

// refresh probes the installed state of the bundle's applications and reconciles the record: an install the user
// removed by hand is dropped and never reinstalled (F10), and one the policy now requires belongs to the policy
// (F11). A user-scope install whose user cannot be reached keeps its entry; that user's further probes are skipped
// for this refresh, so one user's stalled service manager costs at most one ProbeTimeout.
func (s *Service) refresh(ctx context.Context) {
	s.mu.Lock()
	sp := s.snap.spec
	installs := slices.Clone(s.record.Installs)
	s.mu.Unlock()
	probes := map[string]probe{}
	for _, pkg := range sp.Packages {
		if userScoped(pkg) || pkg.CatalogEntryID == bundle.SoftwareRuntimeEntryID {
			continue
		}
		installed, version, err := s.probe(ctx, pkg, -1)
		if err == nil {
			probes[probeKey(pkg, -1)] = probe{installed: installed, version: version}
		}
	}
	var dropped []Install
	unreachable := map[int]bool{}
	for _, inst := range installs {
		i := slices.IndexFunc(sp.Packages, func(p bundle.SoftwarePackage) bool {
			return p.Package == inst.Package && p.FlatpakRef == inst.FlatpakRef
		})
		pkg := bundle.SoftwarePackage{CatalogEntryID: inst.EntryID, Package: inst.Package, FlatpakRef: inst.FlatpakRef, Scope: scopeField(inst.Scope)}
		if i >= 0 && sp.Packages[i].Intent == bundle.SoftwareRequired {
			dropped = append(dropped, inst)
			continue
		}
		key := probeKey(pkg, inst.UID)
		pr, known := probes[key]
		if !known {
			if userScoped(pkg) && unreachable[inst.UID] {
				continue
			}
			installed, version, err := s.probe(ctx, pkg, inst.UID)
			if err != nil {
				if userScoped(pkg) {
					unreachable[inst.UID] = true
				}
				continue
			}
			pr = probe{installed: installed, version: version}
			probes[key] = pr
		}
		if !pr.installed {
			dropped = append(dropped, inst)
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.installed = probes
	if len(dropped) == 0 {
		return
	}
	s.record.Installs = slices.DeleteFunc(s.record.Installs, func(i Install) bool { return slices.Contains(dropped, i) })
	slog.InfoContext(ctx, "self-service installs left the record", "count", len(dropped))
	if err := saveRecord(s.cfg.Sys, s.record); err != nil {
		slog.ErrorContext(ctx, "writing the self-service record failed", "error", err)
	}
}

// probe asks the package tools whether pkg is installed (for uid when it is user scope), bounded by ProbeTimeout.
func (s *Service) probe(ctx context.Context, pkg bundle.SoftwarePackage, uid int) (bool, string, error) {
	pctx, cancel := context.WithTimeout(ctx, s.cfg.ProbeTimeout)
	defer cancel()
	return s.cfg.Packages.SelfServiceInstalled(pctx, pkg, uid)
}

// Apps returns the applications p may see (plan M13b decision 11) with their state from memory.
func (s *Service) Apps(p Principal) ([]AppView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.snap.applied {
		return nil, errNoBundle
	}
	apps := []AppView{}
	seen := map[string]bool{}
	for _, pkg := range s.snap.spec.Packages {
		if seen[pkg.CatalogEntryID] || !visible(pkg, p) {
			continue
		}
		seen[pkg.CatalogEntryID] = true
		apps = append(apps, s.view(pkg, p))
	}
	return apps, nil
}

// App returns one application p may see.
func (s *Service) App(p Principal, entryID string) (AppView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.snap.applied {
		return AppView{}, errNoBundle
	}
	pkg, ok := find(s.snap.spec, entryID, p)
	if !ok {
		return AppView{}, &Problem{Status: http.StatusNotFound, Code: CodeUnknownEntry, Detail: "no such application"}
	}
	return s.view(pkg, p), nil
}

// view is the AppView of a visible package. Called with mu held.
func (s *Service) view(pkg bundle.SoftwarePackage, p Principal) AppView {
	v := AppView{EntryID: pkg.CatalogEntryID, Name: pkg.Package, Kind: "apt", Scope: scope(pkg), Intent: pkg.Intent,
		Managed: managed(pkg), Icon: s.icons.has(pkg.CatalogEntryID)}
	if pkg.FlatpakRef != "" {
		v.Name, v.Kind = pkg.FlatpakRef, "flatpak"
	}
	pr, known := s.installed[probeKey(pkg, p.UID)]
	ownInstall := !v.Managed && s.record.has(pkg, p.UID)
	if !known && ownInstall {
		pr.installed = true
	}
	v.State, v.Version = protocol.SoftwareStateAbsent, pr.version
	if pr.installed {
		v.State = protocol.SoftwareStateInstalled
	}
	pending := s.run != nil && s.concerns(s.run, pkg, p) || slices.ContainsFunc(s.queue, func(op *operation) bool { return s.concerns(op, pkg, p) })
	switch {
	case pending:
		v.State = protocol.SoftwareStatePending
	case !v.Managed:
		if op, ok := s.failed[failKey(pkg, p.UID)]; ok && !pr.installed {
			v.State, v.Reason = protocol.SoftwareStateFailed, op.reason
		}
	}
	if !v.Managed && !pending {
		v.Installable = !pr.installed
		v.Removable = ownInstall && pr.installed
		v.Updatable = v.Removable
	}
	s.requestView(&v, pkg, p, pr.installed, pending)
	return v
}

// concerns reports whether op acts on the installation of pkg that p sees: the device's, or p's own one.
func (s *Service) concerns(op *operation, pkg bundle.SoftwarePackage, p Principal) bool {
	return samePackage(op.pkg, pkg) && (!userScoped(pkg) || op.principal.UID == p.UID)
}

// Status is the body of GET /v1/status.
type Status struct {
	AgentVersion  string     `json:"agent_version"`
	BundleVersion int64      `json:"bundle_version"`
	Notice        string     `json:"notice"`
	User          StatusUser `json:"user"`
	Queue         int        `json:"queue"`
}

// StatusUser names the caller to itself.
type StatusUser struct {
	Name      string `json:"name"`
	Directory bool   `json:"directory"`
}

// Status returns the status for p; Queue counts p's own queued and running operations.
func (s *Service) Status(p Principal) (Status, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.snap.applied {
		return Status{}, errNoBundle
	}
	n := 0
	for _, op := range s.queue {
		if op.principal.UID == p.UID {
			n++
		}
	}
	if s.run != nil && s.run.principal.UID == p.UID {
		n++
	}
	return Status{AgentVersion: s.cfg.Version, BundleVersion: s.snap.version, Notice: DefaultNotice,
		User: StatusUser{Name: p.User(), Directory: p.Directory}, Queue: n}, nil
}
