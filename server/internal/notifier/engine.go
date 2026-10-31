package notifier

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/domain/outbound"
	"github.com/phischl/paddock-mdm/server/internal/platform/bao"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/problem"
)

// Limits of plan M9 decisions 20–22.
const (
	DefaultPollInterval = 30 * time.Second
	MinPollInterval     = 5 * time.Second
	DefaultStallAfter   = 15 * time.Minute
	MinStallAfter       = time.Minute
	DefaultBatch        = 100
	MaxBatch            = 100
	// ScanWindow is how many index events one scan reads after the cursor.
	ScanWindow = 500
	// MaxDeliveriesPerRound bounds the deliveries of one destination in one round.
	MaxDeliveriesPerRound = 20
	// DestinationBudget bounds one destination's deliveries in a round besides MaxDeliveriesPerRound: no new delivery
	// starts after it, and a slow receiver continues in the next round instead of holding the round up for everyone. It
	// bounds the start, not the end: a requested test before the events and a delivery started just before the bound
	// may each still take the 30 s transport timeout, so the worst case is about 120 s per destination and round.
	DestinationBudget = 60 * time.Second
	// MaxParallelDestinations bounds the destinations served at the same time; destinations are independent, so a
	// slow or failing receiver does not hold up the others (plan M9 decision 21).
	MaxParallelDestinations = 16
	// LookupLifetime is how long a pseudonym lookup is kept (plan M9 decision 18).
	LookupLifetime = 10 * time.Minute
	firstBackoff   = 5 * time.Second
	maxBackoff     = 10 * time.Minute
)

// notifierLockKey is the advisory lock of the round, so a destination is never served by two replicas ("padd ntf",
// plan M9 amendment B5.3).
const notifierLockKey = 0x70616464206e7466

// Config configures the engine.
type Config struct {
	PollInterval time.Duration
	StallAfter   time.Duration
	Batch        int
	// PublicAdminURL is the portal's base URL for the links of a message, without a trailing slash.
	PublicAdminURL string
}

// Decrypter decrypts the notification ciphertexts of an organization (bao.Client).
type Decrypter interface {
	DecryptContext(ctx context.Context, key string, org uuid.UUID, field bao.ContextField, ciphertext string) ([]byte, error)
}

// Engine runs the delivery rounds.
type Engine struct {
	cfg        Config
	leader     Leader
	store      Store
	index      Index
	keys       Decrypter
	transports map[outbound.Type]Transport
	metrics    *Metrics
	now        func() time.Time
	newID      func() uuid.UUID
	mu         sync.Mutex
	// oldest is the commit (recorded_at) time of each destination's oldest undelivered matching event, zero when it
	// is caught up; kept across rounds, so the lag keeps rising while a destination waits for its backoff.
	oldest map[uuid.UUID]time.Time
}

// errStale reports a state change that no longer applied (Store.Succeeded or Failed returned false).
var errStale = errors.New("notifier: the destination's state changed meanwhile")

// NewEngine creates the engine.
func NewEngine(cfg Config, leader Leader, store Store, index Index, keys Decrypter,
	transports map[outbound.Type]Transport, metrics *Metrics) *Engine {
	return &Engine{
		cfg: cfg, leader: leader, store: store, index: index, keys: keys, transports: transports, metrics: metrics,
		now: time.Now, newID: func() uuid.UUID { return uuid.Must(uuid.NewV7()) }, oldest: map[uuid.UUID]time.Time{},
	}
}

// Run runs a round at start and then every poll interval until ctx ends; only the replica holding the lock acts.
func (e *Engine) Run(ctx context.Context) error {
	tick := time.NewTicker(e.cfg.PollInterval)
	defer tick.Stop()
	for {
		if err := e.Round(ctx); err != nil && ctx.Err() == nil {
			slog.WarnContext(ctx, "notifier round failed; retrying next round", "error", err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
		}
	}
}

// Round serves every organization and the platform once; a failing scope or destination does not stop the others.
func (e *Engine) Round(ctx context.Context) error {
	sys := principal.With(ctx, principal.Principal{Kind: principal.KindSystem, Display: "notifier"})
	_, err := e.leader.WithLeaderLock(sys, notifierLockKey, func(ctx context.Context) error {
		started := e.now()
		defer func() { e.metrics.round(e.now().Sub(started)) }()
		orgs, err := e.store.Organizations(ctx)
		if err != nil {
			return fmt.Errorf("notifier: organizations: %w", err)
		}
		seen := map[uuid.UUID]bool{}
		var errs []error
		var jobs []job
		for _, sc := range append(scopes(orgs), Scope{Org: audit.PlatformOrganizationID}) {
			scopeJobs, err := e.prepareScope(ctx, sc)
			if err != nil {
				errs = append(errs, fmt.Errorf("scope %s: %w", sc.Org, err))
			}
			for _, j := range scopeJobs {
				seen[j.row.Destination.ID] = true
			}
			jobs = append(jobs, scopeJobs...)
		}
		errs = append(errs, e.serveAll(ctx, jobs)...)
		e.mu.Lock()
		for id := range e.oldest {
			if !seen[id] {
				delete(e.oldest, id)
			}
		}
		e.mu.Unlock()
		e.metrics.forget(seen)
		return errors.Join(errs...)
	})
	return err
}

// job is one destination to serve in a round.
type job struct {
	r   *scopeRound
	row Row
}

// serveAll serves the destinations in parallel, at most MaxParallelDestinations at a time.
func (e *Engine) serveAll(ctx context.Context, jobs []job) []error {
	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		errs []error
	)
	slots := make(chan struct{}, MaxParallelDestinations)
	for _, j := range jobs {
		wg.Add(1)
		slots <- struct{}{}
		go func() {
			defer func() { <-slots; wg.Done() }()
			if err := e.serveDestination(ctx, j.r, j.row); err != nil {
				mu.Lock()
				errs = append(errs, fmt.Errorf("destination %s: %w", j.row.Destination.ID, err))
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	return errs
}

// setOldest records the commit time of the destination's oldest undelivered event; the zero time means caught up.
func (e *Engine) setOldest(id uuid.UUID, at time.Time) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.oldest[id] = at
}

// oldestPending reports whether the oldest undelivered event of the destination is known (a non-zero time).
func (e *Engine) oldestPending(id uuid.UUID) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return !e.oldest[id].IsZero()
}

// lagOf is now minus the commit time of the destination's oldest undelivered event, 0 when caught up or unknown.
func (e *Engine) lagOf(id uuid.UUID) float64 {
	e.mu.Lock()
	at := e.oldest[id]
	e.mu.Unlock()
	if at.IsZero() {
		return 0
	}
	return max(e.now().Sub(at).Seconds(), 0)
}

func scopes(orgs []uuid.UUID) []Scope {
	out := make([]Scope, 0, len(orgs)+1)
	for _, o := range orgs {
		if o != audit.PlatformOrganizationID {
			out = append(out, Scope{Org: o})
		}
	}
	return out
}

// scopeRound is the per-round cache of one scope, shared by its destinations.
type scopeRound struct {
	sc   Scope
	data ScopeData
	mu   sync.Mutex
	// pseudonymKey is the decrypted key, read once per round.
	pseudonymKey []byte
}

// prepareScope reads the scope, answers its pseudonym lookups and returns its destinations.
func (e *Engine) prepareScope(ctx context.Context, sc Scope) ([]job, error) {
	data, err := e.store.Load(ctx, sc)
	if err != nil {
		return nil, err
	}
	r := &scopeRound{sc: sc, data: data}
	var lookupErr error
	if !sc.Platform() {
		if err := e.resolveLookups(ctx, r); err != nil {
			lookupErr = fmt.Errorf("pseudonym lookups: %w", err)
		}
	}
	jobs := make([]job, 0, len(data.Rows))
	for _, row := range data.Rows {
		jobs = append(jobs, job{r: r, row: row})
	}
	return jobs, lookupErr
}

// resolveLookups deletes expired pseudonym lookups and answers the pending ones with the organization's key: the
// matching user or administrator name, or "" (plan M9 decision 18).
func (e *Engine) resolveLookups(ctx context.Context, r *scopeRound) error {
	now := e.now()
	if err := e.store.PurgeLookups(ctx, r.sc, now.Add(-LookupLifetime)); err != nil {
		return err
	}
	lookups, err := e.store.Lookups(ctx, r.sc)
	if err != nil || len(lookups) == 0 {
		return err
	}
	key, err := e.pseudonymKey(ctx, r)
	if err != nil {
		return err
	}
	names, err := e.store.Usernames(ctx, r.sc)
	if err != nil {
		return err
	}
	byPseudonym := make(map[string]string, len(names))
	for _, n := range names {
		byPseudonym[outbound.Pseudonym(key, n)] = n
	}
	for _, l := range lookups {
		if err := e.store.ResolveLookup(ctx, r.sc, l.ID, byPseudonym[l.Pseudonym], now); err != nil {
			return err
		}
	}
	return nil
}

func (e *Engine) pseudonymKey(ctx context.Context, r *scopeRound) ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.pseudonymKey != nil {
		return r.pseudonymKey, nil
	}
	if r.data.PseudonymKey == "" {
		return nil, errors.New("the organization has no pseudonym key")
	}
	key, err := e.keys.DecryptContext(ctx, app.NotificationPseudonymKey, r.sc.Org, bao.FieldPseudonym, r.data.PseudonymKey)
	if err != nil {
		return nil, fmt.Errorf("decrypt pseudonym key: %w", err)
	}
	r.pseudonymKey = key
	return key, nil
}

// destRound is one destination's work in a round.
type destRound struct {
	*scopeRound
	d         Destination
	st        State
	transport Transport
	delivered bool
}

// serveDestination runs plan M9 decision 21 for one destination: the cursor skip, (a) a requested test, (b) the
// pending batch, (c) new batches, (d) a heartbeat.
func (e *Engine) serveDestination(ctx context.Context, r *scopeRound, row Row) error {
	t, ok := e.transports[row.Destination.Type]
	dr := &destRound{scopeRound: r, d: row.Destination, st: row.State, transport: t}
	defer func() {
		e.metrics.stall(dr.d, dr.st.Status == StatusStalled)
		e.metrics.destination(dr.d, e.lagOf(dr.d.ID))
	}()
	if !ok {
		return nil
	}
	if dr.st.StartAtLatest {
		if resolved, err := e.startAtLatest(ctx, dr); err != nil || !resolved {
			return err
		}
	}
	if dr.st.NextAttemptAt != nil && dr.st.NextAttemptAt.After(e.now()) {
		e.learnOldest(ctx, dr)
		return nil
	}
	if err := e.unseal(ctx, dr, row); err != nil {
		return e.internal(ctx, dr, err, e.firstUndelivered(dr))
	}
	err := e.serveTest(ctx, dr)
	if err == nil {
		err = e.serveEvents(ctx, dr)
	}
	if err == nil {
		if dr.st.Pending == uuid.Nil {
			e.setOldest(dr.d.ID, time.Time{})
		}
		err = e.serveHeartbeat(ctx, dr)
	}
	if errors.Is(err, errStale) {
		slog.InfoContext(ctx, "notification destination changed during the round; continuing next round",
			"destination_id", dr.d.ID)
		return nil
	}
	return err
}

// learnOldest finds the oldest undelivered event of a destination that is not served this round (it waits for its
// backoff, or failed before anything was sent), so the lag keeps rising meanwhile: the pending batch's first event, or
// else the first event after the cursor that matches its filter. It reads only while no undelivered event is known.
func (e *Engine) learnOldest(ctx context.Context, dr *destRound) {
	if e.oldestPending(dr.d.ID) {
		return
	}
	if dr.st.Pending != uuid.Nil {
		if b, err := e.pendingBatch(ctx, dr); err == nil && len(b.events) > 0 {
			e.setOldest(dr.d.ID, b.events[0].Event.RecordedAt)
			return
		}
	}
	events, err := e.index.After(ctx, dr.sc, dr.st.Cursor, ScanWindow)
	if err != nil {
		slog.WarnContext(ctx, "notification lag unknown: index unreadable", "destination_id", dr.d.ID, "error", err)
		return
	}
	for _, ev := range events {
		if outbound.Matches(dr.d.Filter, dr.d.Codes, ev.Event) {
			e.setOldest(dr.d.ID, ev.Event.RecordedAt)
			return
		}
	}
}

// internal records a failure that happened before anything was sent (a ciphertext that does not decrypt, a pending
// batch that cannot be read) as a failed attempt of class internal, so it backs off and stalls like a refused
// delivery and the stall alert fires; the cause is logged, never recorded.
// forward is the first forward sequence number not delivered yet (the stall event's forward_seq).
func (e *Engine) internal(ctx context.Context, dr *destRound, cause error, forward int64) error {
	slog.WarnContext(ctx, "notification destination cannot be served", "destination_id", dr.d.ID, "error", cause)
	err := e.failed(ctx, dr, uuid.Nil, forward, &DeliveryError{Class: "internal"})
	e.learnOldest(ctx, dr)
	if errors.Is(err, errStale) {
		return nil
	}
	return errors.Join(cause, err)
}

// firstUndelivered is the first forward sequence number not delivered yet: the pending batch's first, or the next one.
func (e *Engine) firstUndelivered(dr *destRound) int64 {
	if dr.st.Pending != uuid.Nil && dr.st.PendingFrom > 0 {
		return dr.st.PendingFrom
	}
	return dr.st.ForwardSeq + 1
}

// startAtLatest resolves a skip request before anything is delivered: the cursor moves to the scope's newest commit
// sequence, and a pending batch, whose events lie at or below it, is dropped without counting as a failure.
func (e *Engine) startAtLatest(ctx context.Context, dr *destRound) (bool, error) {
	latest, err := e.index.Latest(ctx, dr.sc)
	if err != nil {
		return false, fmt.Errorf("latest commit sequence: %w", err)
	}
	cursor, ok, err := e.store.StartAtLatest(ctx, dr.sc, dr.d.ID, latest, dr.st.Pending)
	if err != nil || !ok {
		return false, err
	}
	dr.st.Cursor, dr.st.StartAtLatest, dr.st.Pending, dr.st.PendingFrom, dr.st.NextAttemptAt = cursor, false, uuid.Nil, 0, nil
	return true, nil
}

// unseal decrypts a webhook's URL and secret for this round; they are never logged.
func (e *Engine) unseal(ctx context.Context, dr *destRound, row Row) error {
	if dr.d.Type != outbound.TypeWebhook {
		return nil
	}
	u, err := e.keys.DecryptContext(ctx, app.NotificationWrapKey, dr.sc.Org, bao.FieldURL, row.URLCiphertext)
	if err != nil {
		return fmt.Errorf("decrypt url: %w", err)
	}
	s, err := e.keys.DecryptContext(ctx, app.NotificationWrapKey, dr.sc.Org, bao.FieldSecret, row.SecretCiphertext)
	if err != nil {
		return fmt.Errorf("decrypt secret: %w", err)
	}
	dr.d.URL, dr.d.Secret = string(u), s
	return nil
}

func (e *Engine) message(dr *destRound, kind string, delivery uuid.UUID) outbound.Message {
	return outbound.Message{
		Schema: outbound.MessageSchema, Kind: kind, DeliveryID: delivery.String(), DestinationID: dr.d.ID.String(),
		OrganizationID: dr.sc.Org.String(), Organization: dr.data.Slug, SentAt: e.now().UTC(),
	}
}

// serveTest delivers a requested test once and records notification.test_sent with the result (plan M9 decision 17).
func (e *Engine) serveTest(ctx context.Context, dr *destRound) error {
	t, ok, err := e.store.NextTest(ctx, dr.sc, dr.d.ID)
	if err != nil || !ok {
		return err
	}
	m := e.message(dr, outbound.KindTest, t.ID)
	m.Events = []outbound.MessageEvent{}
	derr := dr.transport.Deliver(ctx, dr.d, m)
	class := ""
	params := map[string]any{"name": dr.d.Name, "type": string(dr.d.Type), "destination_id": dr.d.ID.String(),
		"requested_by": t.RequestedBy}
	rec := Record{Code: audit.CodeNotificationTestSent, Params: params}
	if derr != nil {
		class = ErrorClass(derr)
		params["error"] = class
		rec.Failure = problem.UpstreamUnavailable.WithDetail("test delivery failed: " + class)
	}
	e.metrics.delivery(dr.d.Type, derr == nil)
	return e.store.FinishTest(ctx, dr.sc, TestResult{
		Destination: dr.d.ID, Name: dr.d.Name, Delivery: t.ID, Class: class, At: e.now(), Record: rec,
	})
}

// batch is a batch being delivered; advanceTo is where the cursor goes when it succeeds.
type batch struct {
	id        uuid.UUID
	attempts  int
	refs      []EventRef
	events    []IndexedEvent
	advanceTo int64
}

func (b batch) from() int64 { return b.refs[0].ForwardSeq }
func (b batch) to() int64   { return b.refs[len(b.refs)-1].ForwardSeq }

// serveEvents retries the pending batch, then cuts and delivers new ones, at most MaxDeliveriesPerRound, and stops at
// the first failure: deliveries of one destination are strictly sequential.
func (e *Engine) serveEvents(ctx context.Context, dr *destRound) error {
	start := e.now()
	for n, scans := 0, 0; n < MaxDeliveriesPerRound && scans < MaxDeliveriesPerRound &&
		e.now().Sub(start) < DestinationBudget; {
		var b batch
		if dr.st.Pending != uuid.Nil {
			var err error
			if b, err = e.pendingBatch(ctx, dr); err != nil {
				return e.internal(ctx, dr, err, e.firstUndelivered(dr))
			}
		} else {
			scans++
			cut, found, more, err := e.cut(ctx, dr)
			if err != nil {
				return err
			}
			if !found {
				if more {
					continue
				}
				return nil
			}
			b = cut
		}
		n++
		ok, err := e.deliverBatch(ctx, dr, b)
		if err != nil || !ok {
			return err
		}
	}
	return nil
}

// pendingBatch rebuilds the pending batch from its recorded events; the index is immutable, so the same events with
// the same forward sequence numbers are sent again.
func (e *Engine) pendingBatch(ctx context.Context, dr *destRound) (batch, error) {
	p, err := e.store.Pending(ctx, dr.sc, dr.st.Pending)
	if err != nil {
		return batch{}, fmt.Errorf("pending batch: %w", err)
	}
	if len(p.Refs) == 0 {
		return batch{}, fmt.Errorf("pending batch %s has no events", p.ID)
	}
	first, last := p.Refs[0].CommitSeq, p.Refs[len(p.Refs)-1].CommitSeq
	events, err := e.index.After(ctx, dr.sc, first-1, int(last-first+1))
	if err != nil {
		return batch{}, fmt.Errorf("pending batch events: %w", err)
	}
	byID := make(map[uuid.UUID]IndexedEvent, len(events))
	for _, ev := range events {
		byID[ev.Event.EventID] = ev
	}
	b := batch{id: p.ID, attempts: p.Attempts, refs: p.Refs, advanceTo: last}
	for _, ref := range p.Refs {
		if ev, ok := byID[ref.EventID]; ok {
			b.events = append(b.events, ev)
		}
	}
	return b, nil
}

// cut scans up to ScanWindow events after the cursor and creates a batch of the first Batch that match. found is
// false when nothing matched; more is true when a full window matched nothing, the cursor moved past it and the next
// window may be scanned in the same round.
func (e *Engine) cut(ctx context.Context, dr *destRound) (b batch, found, more bool, err error) {
	events, err := e.index.After(ctx, dr.sc, dr.st.Cursor, ScanWindow)
	if err != nil {
		return batch{}, false, false, fmt.Errorf("scan index: %w", err)
	}
	if len(events) == 0 {
		return batch{}, false, false, nil
	}
	var matched []IndexedEvent
	scannedTo := events[len(events)-1].CommitSeq
	for _, ev := range events {
		if outbound.Matches(dr.d.Filter, dr.d.Codes, ev.Event) {
			matched = append(matched, ev)
			if len(matched) == e.cfg.Batch {
				scannedTo = ev.CommitSeq
				break
			}
		}
	}
	if len(matched) == 0 {
		if len(events) < ScanWindow {
			return batch{}, false, false, nil
		}
		if err := e.store.AdvanceCursor(ctx, dr.sc, dr.d.ID, scannedTo); err != nil {
			return batch{}, false, false, fmt.Errorf("advance cursor: %w", err)
		}
		dr.st.Cursor = scannedTo
		return batch{}, false, true, nil
	}
	b = batch{id: e.newID(), events: matched, advanceTo: scannedTo}
	for i, ev := range matched {
		b.refs = append(b.refs, EventRef{ForwardSeq: dr.st.ForwardSeq + int64(i) + 1, EventID: ev.Event.EventID,
			CommitSeq: ev.CommitSeq})
	}
	if err := e.store.CreateBatch(ctx, dr.sc, dr.d.ID, NewBatch{ID: b.id, Refs: b.refs}); err != nil {
		return batch{}, false, false, fmt.Errorf("create batch: %w", err)
	}
	dr.st.ForwardSeq, dr.st.Pending, dr.st.PendingFrom = b.to(), b.id, b.from()
	return b, true, false, nil
}

// deliverBatch sends a batch and records the outcome; it reports whether the delivery succeeded.
func (e *Engine) deliverBatch(ctx context.Context, dr *destRound, b batch) (bool, error) {
	m := e.message(dr, outbound.KindEvents, b.id)
	m.ForwardSeq = &outbound.SeqRange{From: b.from(), To: b.to()}
	forward := make(map[uuid.UUID]int64, len(b.refs))
	for _, ref := range b.refs {
		forward[ref.EventID] = ref.ForwardSeq
	}
	m.Events = make([]outbound.MessageEvent, 0, len(b.events))
	for _, ev := range b.events {
		me, err := e.messageEvent(ctx, dr, ev)
		if err != nil {
			return false, e.internal(ctx, dr, err, b.from())
		}
		me.ForwardSeq = forward[ev.Event.EventID]
		m.Events = append(m.Events, me)
	}
	if len(b.events) > 0 {
		e.setOldest(dr.d.ID, b.events[0].Event.RecordedAt)
	}
	derr := dr.transport.Deliver(ctx, dr.d, m)
	e.metrics.delivery(dr.d.Type, derr == nil)
	if derr != nil {
		return false, e.failed(ctx, dr, b.id, b.from(), derr)
	}
	attempts := b.attempts + 1
	resumed := dr.st.Status == StatusStalled
	advance := b.advanceTo
	if err := e.succeeded(ctx, dr, b.id, b.id, &advance, &Record{Code: audit.CodeNotificationDelivered, Params: map[string]any{
		"destination": dr.d.Name, "destination_id": dr.d.ID.String(), "kind": outbound.KindEvents,
		"forward_from": b.from(), "forward_to": b.to(), "count": len(b.refs), "attempts": attempts, "resumed": resumed,
	}}, map[string]any{"forward_from": b.from(), "forward_to": b.to()}); err != nil {
		return false, err
	}
	dr.st.Cursor, dr.st.Pending, dr.st.PendingFrom = advance, uuid.Nil, 0
	e.setOldest(dr.d.ID, time.Time{})
	return true, nil
}

func (e *Engine) messageEvent(ctx context.Context, dr *destRound, ev IndexedEvent) (outbound.MessageEvent, error) {
	event := ev.Event
	if dr.d.Pseudonymize {
		key, err := e.pseudonymKey(ctx, dr.scopeRound)
		if err != nil {
			return outbound.MessageEvent{}, err
		}
		event = outbound.Pseudonymize(key, event)
	}
	me := outbound.MessageEvent{CommitSeq: ev.CommitSeq, Event: event}
	if event.Target != nil && event.Target.Type == "device" && event.Target.ID != "" {
		me.Links = &outbound.Links{Device: e.cfg.PublicAdminURL + "/devices/" + event.Target.ID}
	}
	return me, nil
}

// succeeded records a successful events batch or heartbeat; a stalled destination resumes in the same transaction
// (notification.destination_resumed). pending is the batch the state must still hold (uuid.Nil for a heartbeat).
func (e *Engine) succeeded(ctx context.Context, dr *destRound, delivery, pending uuid.UUID, cursor *int64, rec *Record,
	resumedParams map[string]any) error {
	now := e.now()
	s := Success{Destination: dr.d.ID, Name: dr.d.Name, Delivery: delivery, Pending: pending, Cursor: cursor, At: now,
		Record: rec}
	if dr.st.Status == StatusStalled {
		params := map[string]any{"destination": dr.d.Name, "destination_id": dr.d.ID.String(), "stalled_for_s": 0}
		if dr.st.StalledSince != nil {
			params["stalled_for_s"] = int64(now.Sub(*dr.st.StalledSince).Seconds())
		}
		for k, v := range resumedParams {
			params[k] = v
		}
		s.Resume = &Record{Code: audit.CodeNotificationDestinationResumed, Params: params}
	}
	applied, err := e.store.Succeeded(ctx, dr.sc, s)
	if err != nil {
		return fmt.Errorf("record delivery: %w", err)
	}
	if !applied {
		return errStale
	}
	dr.delivered = true
	dr.st.ConsecutiveFailures, dr.st.FirstFailureAt, dr.st.NextAttemptAt = 0, nil, nil
	dr.st.Status, dr.st.StalledSince = StatusActive, nil
	return nil
}

// Backoff is the wait after the n-th consecutive failure: 5 s doubling, at most 10 minutes (plan M9 decision 22).
func Backoff(n int) time.Duration {
	if n < 1 {
		n = 1
	}
	exp := math.Min(float64(n-1), 20)
	return min(time.Duration(float64(firstBackoff)*math.Pow(2, exp)), maxBackoff)
}

// failed records a failed delivery: the backoff, and the stall once the failures last longer than StallAfter.
func (e *Engine) failed(ctx context.Context, dr *destRound, delivery uuid.UUID, forwardSeq int64, derr error) error {
	now := e.now()
	class := ErrorClass(derr)
	n := dr.st.ConsecutiveFailures + 1
	first := now
	if dr.st.FirstFailureAt != nil {
		first = *dr.st.FirstFailureAt
	}
	f := Failure{
		Destination: dr.d.ID, Name: dr.d.Name, Delivery: delivery, Pending: dr.st.Pending,
		PreviousStatus: dr.st.Status, Class: class, At: now, ConsecutiveFailures: n,
		FirstFailureAt: first, NextAttemptAt: now.Add(Backoff(n)), Status: dr.st.Status, StalledSince: dr.st.StalledSince,
	}
	if dr.st.Status != StatusStalled && now.Sub(first) >= e.cfg.StallAfter {
		f.Status, f.StalledSince = StatusStalled, &now
		f.Record = &Record{Code: audit.CodeNotificationDestinationStalled, Params: map[string]any{
			"destination": dr.d.Name, "destination_id": dr.d.ID.String(), "since_s": int64(now.Sub(first).Seconds()),
			"last_error": class, "forward_seq": forwardSeq,
		}}
	}
	slog.InfoContext(ctx, "notification delivery failed", "destination_id", dr.d.ID, "class", class,
		"consecutive_failures", n, "status", f.Status)
	applied, err := e.store.Failed(ctx, dr.sc, f)
	if err != nil {
		return fmt.Errorf("record failure: %w", err)
	}
	if !applied {
		return errStale
	}
	dr.st.ConsecutiveFailures, dr.st.FirstFailureAt, dr.st.NextAttemptAt = n, &first, &f.NextAttemptAt
	dr.st.Status, dr.st.StalledSince = f.Status, f.StalledSince
	return nil
}

// serveHeartbeat sends a heartbeat when the interval passed without a delivery or heartbeat and nothing is pending.
func (e *Engine) serveHeartbeat(ctx context.Context, dr *destRound) error {
	if dr.d.HeartbeatInterval <= 0 || dr.delivered || dr.st.Pending != uuid.Nil ||
		(dr.st.NextAttemptAt != nil && dr.st.NextAttemptAt.After(e.now())) {
		return nil
	}
	due := e.now().Add(-dr.d.HeartbeatInterval)
	if (dr.st.LastHeartbeatAt != nil && dr.st.LastHeartbeatAt.After(due)) ||
		(dr.st.LastSuccessAt != nil && dr.st.LastSuccessAt.After(due)) {
		return nil
	}
	id := e.newID()
	if err := e.store.CreateHeartbeat(ctx, dr.sc, dr.d.ID, id); err != nil {
		return fmt.Errorf("create heartbeat: %w", err)
	}
	m := outbound.Heartbeat(dr.st.ForwardSeq, dr.st.Cursor)
	base := e.message(dr, outbound.KindHeartbeat, id)
	m.DeliveryID, m.DestinationID, m.OrganizationID, m.Organization, m.SentAt =
		base.DeliveryID, base.DestinationID, base.OrganizationID, base.Organization, base.SentAt
	derr := dr.transport.Deliver(ctx, dr.d, m)
	e.metrics.delivery(dr.d.Type, derr == nil)
	if derr != nil {
		return e.failed(ctx, dr, id, dr.st.ForwardSeq+1, derr)
	}
	return e.succeeded(ctx, dr, id, uuid.Nil, nil, nil, nil)
}

// DeliveryError is a failed delivery with its class of plan M9 decision 22: dns, dial, tls, timeout, http_<status>,
// redirect, denied_address, smtp_<code>. The class is all that is recorded: never a URL, address or response.
type DeliveryError struct{ Class string }

func (e *DeliveryError) Error() string { return "notification delivery failed: " + e.Class }

// ErrorClass returns the class of a delivery error; an error of unknown kind is "dial".
func ErrorClass(err error) string {
	var d *DeliveryError
	if errors.As(err, &d) && d.Class != "" && !strings.ContainsAny(d.Class, " /:") {
		return d.Class
	}
	return "dial"
}
