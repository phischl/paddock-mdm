package worker

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/inventory"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/platform/httpx"
	"github.com/phischl/paddock-mdm/server/internal/ports"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
)

// failingSettings fails its first calls, then succeeds.
type failingSettings struct {
	failures int32
	calls    atomic.Int32
}

func (s *failingSettings) EnsureSettings(context.Context) ([]string, error) {
	if s.calls.Add(1) <= s.failures {
		return nil, errors.New("fleet: HTTP 502")
	}
	return []string{"features"}, nil
}

// TestInventorySettingsRetryUntilChecked: an unreachable Fleet is retried soon; once the settings are checked, the
// next round waits for the round interval (plan M5a decision 2).
func TestInventorySettingsRetryUntilChecked(t *testing.T) {
	s := &failingSettings{failures: 2}
	i := &Inventory{settings: s, every: time.Hour, retry: time.Millisecond}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- i.RunSettings(ctx) }()

	deadline := time.Now().Add(5 * time.Second)
	for s.calls.Load() < 3 {
		if time.Now().After(deadline) {
			t.Fatalf("%d calls after 5 s, want 3", s.calls.Load())
		}
		time.Sleep(time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond)
	if n := s.calls.Load(); n != 3 {
		t.Fatalf("%d calls, want 3 (no retry after success)", n)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

// fakeSource is an inventory system with fixed hosts; it records the since of every listing and the hosts read.
type fakeSource struct {
	hosts     []ports.InventoryHost
	since     []time.Time
	read      []ports.HostRef
	policies  int
	vulnState string
	deleted   []ports.HostRef
	// deleteErr makes every host deletion fail; deleteCalls counts the deletions asked for.
	deleteErr   error
	deleteCalls int
	// results and evaluatedAt are every host's policy results and policy evaluation time; applied is the last set
	// of policies applied, applyErr fails ApplyPolicies.
	results     []ports.PolicyResult
	unanswered  []string
	evaluatedAt *time.Time
	applied     []ports.PolicyDefinition
	applyErr    error
	// perHost replaces the policy answers and evaluation time for the hosts it lists.
	perHost map[ports.HostRef]ports.HostInventory
	// seenAt and enrolledAt are the listed hosts' last contact and latest enrollment (zero and nil when absent).
	seenAt     map[ports.HostRef]time.Time
	enrolledAt map[ports.HostRef]*time.Time
	// hostErr fails the host detail of the hosts it lists; listErr fails the host list; onRead runs before a host
	// detail is answered.
	hostErr map[ports.HostRef]error
	listErr error
	onRead  func(ports.HostRef)
}

func (s *fakeSource) VulnerabilityState(context.Context) (string, error) { return s.vulnState, nil }

func (s *fakeSource) ListHostsChangedSince(_ context.Context, since time.Time, cursor string) (ports.HostPage, error) {
	s.since = append(s.since, since)
	if s.listErr != nil {
		return ports.HostPage{}, s.listErr
	}
	if cursor == "" { // two pages, the first of one host
		return ports.HostPage{Hosts: s.hosts[:1], Seen: s.seen(s.hosts[:1]), Next: "1"}, nil
	}
	return ports.HostPage{Hosts: s.hosts[1:], Seen: s.seen(s.hosts[1:])}, nil
}

// uniqueRef is a host ID no other test uses: the inventory system's IDs are unique, and the shared database keeps
// every test's stored hosts.
func uniqueRef() ports.HostRef { return ports.HostRef(strconv.FormatInt(rand.Int64N(1e15), 10)) }

// seen lists hosts as the adapter does: every host with a hardware UUID, in list order.
func (s *fakeSource) seen(hosts []ports.InventoryHost) []ports.HostSeen {
	out := []ports.HostSeen{}
	for _, h := range hosts {
		out = append(out, ports.HostSeen{Ref: h.Ref, HardwareUUID: h.HardwareUUID, SeenAt: s.seenAt[h.Ref], EnrolledAt: s.enrolledAt[h.Ref]})
	}
	return out
}

func (s *fakeSource) HostInventory(_ context.Context, ref ports.HostRef) (ports.HostInventory, error) {
	s.read = append(s.read, ref)
	if s.onRead != nil {
		s.onRead(ref)
	}
	if err := s.hostErr[ref]; err != nil {
		return ports.HostInventory{}, err
	}
	if h, ok := s.perHost[ref]; ok {
		return ports.HostInventory{OSVersion: cmp.Or(h.OSVersion, "Ubuntu 26.04.1 LTS"), Software: h.Software, Policies: h.Policies, UnansweredPolicies: h.UnansweredPolicies,
			PolicyUpdatedAt: h.PolicyUpdatedAt}, nil
	}
	return ports.HostInventory{OSVersion: "Ubuntu 26.04.1 LTS", Software: []ports.SoftwarePackage{{Name: "bash", Version: "5.2", Source: "deb_packages"}},
		Policies: s.results, UnansweredPolicies: s.unanswered, PolicyUpdatedAt: s.evaluatedAt}, nil
}

// DeleteHost records the deleted hosts (ports.InventoryAdmin of the retention round).
func (s *fakeSource) DeleteHost(_ context.Context, ref ports.HostRef) error {
	s.deleteCalls++
	if s.deleteErr != nil {
		return s.deleteErr
	}
	s.deleted = append(s.deleted, ref)
	return nil
}

// HostSeenAt reports every host as never seen, so the retention round deletes it.
func (s *fakeSource) HostSeenAt(context.Context, ports.HostRef) (time.Time, error) {
	return time.Time{}, nil
}

func (s *fakeSource) ApplyPolicies(_ context.Context, p []ports.PolicyDefinition) error {
	if s.applyErr != nil {
		return s.applyErr
	}
	s.policies, s.applied = len(p), p
	return nil
}

// TestInventoryRound (plan M5a decision 6): a round pushes the policies, reads every page, stores the hosts that map
// to a device and skips the others; after the first (full) round only changes since the previous round are listed,
// all hosts again when the vulnerability state changed and every inventoryFullEvery rounds.
func TestInventoryRound(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	platform, err := db.NewPlatformPool(ctx, pgtest.SharedPaddock(t).Platform, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(platform.Close)
	hw := uuid.NewString()
	dev := uuid.Must(uuid.NewV7())
	if _, err := f.super.Exec(ctx, "INSERT INTO device (id, organization_id, hostname, state, hardware_uuid) VALUES ($1, $2, 'lt-inv', 'active', $3)",
		dev, f.org, hw); err != nil {
		t.Fatal(err)
	}
	one := uniqueRef()
	src := &fakeSource{hosts: []ports.InventoryHost{{Ref: one, HardwareUUID: strings.ToUpper(hw)}, {Ref: uniqueRef(), HardwareUUID: uuid.NewString()}}}
	runner := app.NewActionRunner(f.pool, platform, httpx.RequestID)
	i := NewInventory(nil, src, app.NewInventorySync(runner, f.pool, platform),
		app.NewVulnerabilitySummary(runner), f.pool, platform, time.Minute)
	sys := principal.With(ctx, principal.Principal{Kind: principal.KindSystem, Display: "worker"})
	for n := range inventoryFullEvery + 1 {
		if n == 5 {
			src.vulnState = "new matches" // a full round
		}
		if err := i.Round(sys); err != nil {
			t.Fatal(err)
		}
	}
	if src.policies != 3 || !slices.Equal(src.read[:2], []ports.HostRef{one, one}) {
		t.Fatalf("policies %d, read %v", src.policies, src.read)
	}
	var n int
	if err := f.super.QueryRow(ctx, "SELECT count(*) FROM installed_software WHERE device_id = $1", dev).Scan(&n); err != nil || n != 1 {
		t.Fatalf("%d packages, %v", n, err)
	}
	full := 0
	for k, s := range src.since {
		if s.IsZero() {
			full++
		} else if k > 0 && !s.After(src.since[k-2]) {
			t.Fatalf("listing %d since %v, not after the previous round", k, s)
		}
	}
	if full != 6 { // two pages each in rounds 1, 6 (new vulnerability matches) and 13
		t.Fatalf("%d full listings in %v", full, src.since)
	}
}

// TestInventoryRoundRecordsCriticalSummary (plan M9 decision 37): a round records the critical CVE summary of an
// organization with new critical findings, and the next round of the same day records no second one.
func TestInventoryRoundRecordsCriticalSummary(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	platform, err := db.NewPlatformPool(ctx, pgtest.SharedPaddock(t).Platform, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(platform.Close)
	dev := uuid.Must(uuid.NewV7())
	if _, err := f.super.Exec(ctx, "INSERT INTO device (id, organization_id, hostname, state) VALUES ($1, $2, 'lt-sum', 'active')", dev, f.org); err != nil {
		t.Fatal(err)
	}
	if _, err := f.super.Exec(ctx, `INSERT INTO vulnerability_finding (device_id, organization_id, cve, software_name, software_version,
		severity, first_seen_at) VALUES ($1, $2, 'CVE-2026-1111', 'p', '1', 'critical', now() - interval '1 hour')`, dev, f.org); err != nil {
		t.Fatal(err)
	}
	runner := app.NewActionRunner(f.pool, platform, httpx.RequestID)
	i := NewInventory(nil, &fakeSource{hosts: []ports.InventoryHost{{Ref: "1", HardwareUUID: uuid.NewString()}, {Ref: "2", HardwareUUID: uuid.NewString()}}}, app.NewInventorySync(runner, f.pool, platform),
		app.NewVulnerabilitySummary(runner), f.pool, platform, time.Minute)
	sys := principal.With(ctx, principal.Principal{Kind: principal.KindSystem, Display: "worker"})
	for range 2 {
		if err := i.Round(sys); err != nil {
			t.Fatal(err)
		}
	}
	var n int
	if err := f.super.QueryRow(ctx, "SELECT count(*) FROM action WHERE organization_id = $1 AND code = 'vulnerability.critical_summary'", f.org).Scan(&n); err != nil || n != 1 {
		t.Fatalf("%d summaries, %v", n, err)
	}
}

// failingSLASummary fails every organization's patch SLA summary and records which organizations it was asked for.
type failingSLASummary struct{ orgs map[uuid.UUID]bool }

func (f *failingSLASummary) Record(ctx context.Context, _ time.Time) error {
	p, _ := principal.From(ctx)
	f.orgs[p.OrganizationID] = true
	return errors.New("injected sla summary failure")
}

// TestInventoryRoundSurvivesSLASummaryFailure (PDK-814 review 1): a failing patch SLA summary is logged and skipped;
// the round still succeeds and tries every organization: with two organizations of its own and every summary failing,
// both are attempted whichever comes first, and the critical summary is recorded.
func TestInventoryRoundSurvivesSLASummaryFailure(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	platform, err := db.NewPlatformPool(ctx, pgtest.SharedPaddock(t).Platform, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(platform.Close)
	dev := uuid.Must(uuid.NewV7())
	if _, err := f.super.Exec(ctx, "INSERT INTO device (id, organization_id, hostname, state) VALUES ($1, $2, 'lt-sla', 'active')", dev, f.org); err != nil {
		t.Fatal(err)
	}
	if _, err := f.super.Exec(ctx, `INSERT INTO vulnerability_finding (device_id, organization_id, cve, software_name, software_version,
		severity, first_seen_at) VALUES ($1, $2, 'CVE-2026-2222', 'p', '1', 'critical', now() - interval '1 hour')`, dev, f.org); err != nil {
		t.Fatal(err)
	}
	second := uuid.Must(uuid.NewV7())
	if _, err := f.super.Exec(ctx, "INSERT INTO organization (id, slug, name, status) VALUES ($1, $2, 'W2', 'active')",
		second, "w2"+second.String()[24:]); err != nil {
		t.Fatal(err)
	}
	runner := app.NewActionRunner(f.pool, platform, httpx.RequestID)
	failing := &failingSLASummary{orgs: map[uuid.UUID]bool{}}
	i := NewInventory(nil, &fakeSource{hosts: []ports.InventoryHost{{Ref: "1", HardwareUUID: uuid.NewString()}}}, app.NewInventorySync(runner, f.pool, platform),
		app.NewVulnerabilitySummary(runner), f.pool, platform, time.Minute).WithSLASummary(failing)
	if err := i.Round(principal.With(ctx, principal.Principal{Kind: principal.KindSystem, Display: "worker"})); err != nil {
		t.Fatalf("round = %v", err)
	}
	if !failing.orgs[f.org] || !failing.orgs[second] {
		t.Fatalf("sla summary attempted for %v, want both %s and %s: the loop stopped at the first failure", failing.orgs, f.org, second)
	}
	var n int
	if err := f.super.QueryRow(ctx, "SELECT count(*) FROM action WHERE organization_id = $1 AND code = 'vulnerability.critical_summary'", f.org).Scan(&n); err != nil || n != 1 {
		t.Fatalf("%d critical summaries, %v", n, err)
	}
}

// fakeHashes is the hash set of published agent artifacts; publish replaces it right after the next read, as a
// release published during a round would.
type fakeHashes struct {
	hashes, publish []string
	reads           int
}

func (f *fakeHashes) PublishedAgentHashes(context.Context) ([]string, error) {
	f.reads++
	out := f.hashes
	if f.publish != nil {
		f.hashes, f.publish = f.publish, nil
	}
	return out, nil
}

// binaryRig is an inventory round over one mapped host with a controllable clock and hash set.
type binaryRig struct {
	f      fixture
	dev    uuid.UUID
	src    *fakeSource
	hashes *fakeHashes
	inv    *Inventory
	clock  time.Time
	sys    context.Context
}

func newBinaryRig(t *testing.T, hashes ...string) *binaryRig {
	t.Helper()
	f := newFixture(t)
	ctx := context.Background()
	platform, err := db.NewPlatformPool(ctx, pgtest.SharedPaddock(t).Platform, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(platform.Close)
	hw := uuid.NewString()
	dev := uuid.Must(uuid.NewV7())
	if _, err := f.super.Exec(ctx, "INSERT INTO device (id, organization_id, hostname, state, hardware_uuid) VALUES ($1, $2, 'lt-bin', 'active', $3)",
		dev, f.org, hw); err != nil {
		t.Fatal(err)
	}
	r := &binaryRig{f: f, dev: dev, hashes: &fakeHashes{hashes: hashes}, clock: time.Now().UTC().Truncate(time.Second),
		src: &fakeSource{hosts: []ports.InventoryHost{{Ref: uniqueRef(), HardwareUUID: hw}, {Ref: uniqueRef(), HardwareUUID: uuid.NewString()}}},
		sys: principal.With(ctx, principal.Principal{Kind: principal.KindSystem, Display: "worker"})}
	runner := app.NewActionRunner(f.pool, platform, httpx.RequestID)
	r.inv = NewInventory(nil, r.src, app.NewInventorySync(runner, f.pool, platform), app.NewVulnerabilitySummary(runner), f.pool, platform, time.Minute)
	r.inv.hashes, r.inv.now = r.hashes, func() time.Time { return r.clock }
	return r
}

// host sets the host's agent binary result, evaluated at the given offset from the last apply.
func (r *binaryRig) host(passing bool, sinceApplied time.Duration) {
	at := r.inv.binaryAppliedAt.Add(sinceApplied)
	r.src.results, r.src.unanswered = []ports.PolicyResult{{Key: inventory.PolicyAgentBinaryKnown, Passing: passing}}, nil
	r.src.evaluatedAt = &at
}

// unansweredAt sets the host's agent binary policy as listed without an answer, as Fleet does after a query change,
// with the host's evaluation time at.
func (r *binaryRig) unansweredAt(at time.Time) {
	r.src.results, r.src.unanswered, r.src.evaluatedAt = nil, []string{inventory.PolicyAgentBinaryKnown}, &at
}

func (r *binaryRig) round(t *testing.T) {
	t.Helper()
	if err := r.inv.Round(r.sys); err != nil {
		t.Fatal(err)
	}
}

func (r *binaryRig) reports(t *testing.T) int {
	t.Helper()
	var n int
	if err := r.f.super.QueryRow(context.Background(), "SELECT count(*) FROM action WHERE code = 'device.tamper_agent_binary_changed' AND target ->> 'id' = $1",
		r.dev.String()).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// binaryPolicy is the agent binary policy of the last apply.
func (r *binaryRig) binaryPolicy(t *testing.T) ports.PolicyDefinition {
	t.Helper()
	for _, p := range r.src.applied {
		if p.Key == inventory.PolicyAgentBinaryKnown {
			return p
		}
	}
	t.Fatalf("no agent binary policy in %+v", r.src.applied)
	return ports.PolicyDefinition{}
}

// TestInventoryRoundAgentBinary (plan M5a amendment 2026-11-16, A2 and A3): every round applies the binary policy;
// a failure counts only from an evaluation at least 2 minutes after the current hash set was applied, and is reported
// once; passing and failing again reports again. An unchanged hash set keeps the apply time, a new hash moves it.
func TestInventoryRoundAgentBinary(t *testing.T) {
	a, b := strings.Repeat("a", 64), strings.Repeat("b", 64)
	r := newBinaryRig(t, a)
	r.src.results = []ports.PolicyResult{{Key: inventory.PolicyAgentBinaryKnown}} // failing, never evaluated
	r.round(t)
	applied := r.inv.binaryAppliedAt
	if !applied.Equal(r.clock) || !strings.Contains(r.binaryPolicy(t).Query, a) || r.reports(t) != 0 {
		t.Fatalf("first round: applied %v, policy %q, %d reports", applied, r.binaryPolicy(t).Query, r.reports(t))
	}

	r.clock = r.clock.Add(5 * time.Minute)
	r.host(false, 3*time.Minute)
	r.round(t)
	if n := r.reports(t); n != 1 {
		t.Fatalf("%d reports for a failure evaluated 3 minutes after the apply, want 1", n)
	}
	r.clock = r.clock.Add(5 * time.Minute)
	r.round(t)
	if n := r.reports(t); n != 1 {
		t.Fatalf("%d reports after the next round, want still 1", n)
	}
	if !r.inv.binaryAppliedAt.Equal(applied) {
		t.Fatalf("an unchanged hash set moved the apply time from %v to %v", applied, r.inv.binaryAppliedAt)
	}

	r.host(true, 4*time.Minute)
	r.round(t)
	r.host(false, 5*time.Minute)
	r.round(t)
	if n := r.reports(t); n != 2 {
		t.Fatalf("%d reports after passing and failing again, want 2", n)
	}

	r.hashes.hashes = []string{a, b}
	r.clock = r.clock.Add(5 * time.Minute)
	r.host(true, 0)
	r.round(t)
	if !r.inv.binaryAppliedAt.Equal(r.clock) || !strings.Contains(r.binaryPolicy(t).Query, b) {
		t.Fatalf("a new hash: applied %v (want %v), policy %q", r.inv.binaryAppliedAt, r.clock, r.binaryPolicy(t).Query)
	}
	r.host(false, time.Minute)
	r.round(t)
	if n := r.reports(t); n != 2 {
		t.Fatalf("%d reports for an evaluation 1 minute after the new apply, want still 2", n)
	}
	r.host(false, 3*time.Minute)
	r.round(t)
	if n := r.reports(t); n != 3 {
		t.Fatalf("%d reports once the host evaluated the new definition, want 3", n)
	}
}

// TestInventoryRoundAgentBinaryPublishRace (A3): a release published between the round's two reads of the hash set
// skips the round's binary reports with one Info line; the next round applies the new set and waits for an evaluation
// of it.
func TestInventoryRoundAgentBinaryPublishRace(t *testing.T) {
	a, b := strings.Repeat("a", 64), strings.Repeat("b", 64)
	r := newBinaryRig(t, a)
	r.round(t)
	r.clock = r.clock.Add(5 * time.Minute)
	r.host(false, 3*time.Minute)
	r.hashes.publish = []string{a, b}

	var logs bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelInfo})))
	t.Cleanup(func() { slog.SetDefault(prev) })
	r.round(t)
	if n := r.reports(t); n != 0 {
		t.Fatalf("%d reports in a round with a publish between the reads, want 0", n)
	}
	if n := strings.Count(logs.String(), "agent binary reports wait for the next round"); n != 1 || !strings.Contains(logs.String(), "level=INFO msg=\"the published") {
		t.Fatalf("%d skip lines: %s", n, logs.String())
	}
	r.clock = r.clock.Add(5 * time.Minute)
	r.round(t)
	if n := r.reports(t); n != 0 {
		t.Fatalf("%d reports for an evaluation older than the new definition, want 0", n)
	}
}

// TestInventoryRoundAgentBinaryApplyFails (A3): a failing apply fails the round and reports nothing.
func TestInventoryRoundAgentBinaryApplyFails(t *testing.T) {
	r := newBinaryRig(t, strings.Repeat("a", 64))
	r.round(t)
	r.clock = r.clock.Add(5 * time.Minute)
	r.host(false, 3*time.Minute)
	r.src.applyErr = errors.New("fleet: HTTP 502")
	if err := r.inv.Round(r.sys); err == nil {
		t.Fatal("the round succeeded although applying the policies failed")
	}
	if n := r.reports(t); n != 0 {
		t.Fatalf("%d reports after a failed apply, want 0", n)
	}
}

// TestInventoryRoundAgentBinaryNoRelease (A1, A3): without a published release the policy is SELECT 1; and a failing
// result is never reported.
func TestInventoryRoundAgentBinaryNoRelease(t *testing.T) {
	r := newBinaryRig(t)
	r.round(t)
	r.clock = r.clock.Add(5 * time.Minute)
	r.host(false, 3*time.Minute)
	r.round(t)
	if q := r.binaryPolicy(t).Query; q != "SELECT 1;" {
		t.Fatalf("policy %q", q)
	}
	if n := r.reports(t); n != 0 {
		t.Fatalf("%d reports without a published release, want 0", n)
	}
	if r.hashes.reads != 2 {
		t.Fatalf("%d hash reads, want one per round and no second read for an empty set", r.hashes.reads)
	}
}

// TestInventoryRoundAgentBinaryUnansweredAfterPublish (plan M5a amendment 2026-11-16, review round 1, A7): a reported
// device whose binary policy Fleet resets at a publish and that fails again with the new definition is not reported a
// second time.
func TestInventoryRoundAgentBinaryUnansweredAfterPublish(t *testing.T) {
	a, b := strings.Repeat("a", 64), strings.Repeat("b", 64)
	r := newBinaryRig(t, a)
	r.round(t)
	r.clock = r.clock.Add(5 * time.Minute)
	r.host(false, 3*time.Minute)
	r.round(t)
	if n := r.reports(t); n != 1 {
		t.Fatalf("%d reports for the failure, want 1", n)
	}
	r.hashes.hashes = []string{a, b}
	r.clock = r.clock.Add(5 * time.Minute)
	r.unansweredAt(r.clock)
	r.round(t)
	r.clock = r.clock.Add(5 * time.Minute)
	r.host(false, 3*time.Minute)
	r.round(t)
	if n := r.reports(t); n != 1 {
		t.Fatalf("%d reports after the publish reset the policy and it failed again, want still 1", n)
	}
}

// TestInventoryRoundAgentBinaryUnansweredNotReported (A7): an unreported failure of the previous definition is not
// kept while the policy is unanswered, so an unanswered policy evaluated after the new gate reports nothing, and
// neither does passing afterwards.
func TestInventoryRoundAgentBinaryUnansweredNotReported(t *testing.T) {
	a, b := strings.Repeat("a", 64), strings.Repeat("b", 64)
	r := newBinaryRig(t, a)
	r.round(t)
	r.clock = r.clock.Add(5 * time.Minute)
	r.host(false, time.Minute)
	r.round(t)
	r.hashes.hashes = []string{a, b}
	r.clock = r.clock.Add(5 * time.Minute)
	r.unansweredAt(r.clock.Add(3 * time.Minute)) // the round below applies the new definition at r.clock
	r.round(t)
	if n := r.reports(t); n != 0 {
		t.Fatalf("%d reports for an unanswered policy, want 0", n)
	}
	r.clock = r.clock.Add(5 * time.Minute)
	r.host(true, 4*time.Minute)
	r.round(t)
	if n := r.reports(t); n != 0 {
		t.Fatalf("%d reports after passing, want 0", n)
	}
}

// TestInventoryRoundAgentBinaryNewReleaseSelfTest (decision alpha11 §146): the supervisor's self-test and version
// call of a staged release are judged processes. A device stages only a published release, so a host that evaluated
// the previous definition while such a child ran is never reported, and once the new definition is applied the
// child passes.
func TestInventoryRoundAgentBinaryNewReleaseSelfTest(t *testing.T) {
	a, b := strings.Repeat("a", 64), strings.Repeat("b", 64)
	r := newBinaryRig(t, a)
	r.round(t)
	r.clock = r.clock.Add(10 * time.Minute)
	r.hashes.hashes = []string{a, b}             // published; the device then stages b and runs its self-test
	r.host(false, 10*time.Minute+30*time.Second) // the previous definition, which does not list b, during the self-test
	r.clock = r.clock.Add(time.Minute)
	r.round(t)
	if n := r.reports(t); n != 0 {
		t.Fatalf("%d reports for an evaluation of the previous definition during the self-test, want 0", n)
	}
	r.clock = r.clock.Add(2 * time.Minute)
	r.host(false, time.Minute) // still the previous definition, 1 minute after the apply
	r.round(t)
	if n := r.reports(t); n != 0 {
		t.Fatalf("%d reports for an evaluation within the lag after the apply, want 0", n)
	}
	r.clock = r.clock.Add(5 * time.Minute)
	r.host(true, 3*time.Minute)
	r.round(t)
	if n := r.reports(t); n != 0 || !strings.Contains(r.binaryPolicy(t).Query, b) {
		t.Fatalf("%d reports once the policy lists the staged release, want 0; policy %q", n, r.binaryPolicy(t).Query)
	}
}

// TestInventoryRoundAgentBinaryManyHashes (plan M5a amendment 2026-11-16, review round 1, A10): the round that
// applies more than 1,000 hashes warns once with their number; the next round and a set of 1,000 do not warn.
func TestInventoryRoundAgentBinaryManyHashes(t *testing.T) {
	set := func(n int) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = fmt.Sprintf("%064x", i)
		}
		return out
	}
	var logs bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelInfo})))
	t.Cleanup(func() { slog.SetDefault(prev) })
	warns := func() int {
		return strings.Count(logs.String(), "level=WARN msg=\"the agent binary policy accepts many")
	}

	r := newBinaryRig(t, set(1000)...)
	r.round(t)
	if n := warns(); n != 0 || !strings.Contains(logs.String(), "hashes=1000") {
		t.Fatalf("%d warnings for 1,000 hashes, want 0 and one hashes line: %s", n, logs.String())
	}
	r.hashes.hashes = set(1001)
	r.round(t)
	if n := warns(); n != 1 || !strings.Contains(logs.String(), "hashes=1001 warn_above=1000") {
		t.Fatalf("%d warnings for 1,001 hashes, want 1: %s", n, logs.String())
	}
	r.round(t)
	if n := warns(); n != 1 {
		t.Fatalf("%d warnings after an unchanged round, want still 1", n)
	}
}

// TestInventoryRoundPolicyUnansweredMetric (plan M5a addendum 2026-11-16, review round 2, A13): a full round counts
// the mapped hosts that evaluated a policy's current definition at least 2 minutes after it was applied and still
// list it without an answer, and warns once per such policy; a changed-host round sets nothing; a policy whose text
// just changed counts only once its hosts evaluated the new text.
func TestInventoryRoundPolicyUnansweredMetric(t *testing.T) {
	r := newBinaryRig(t, strings.Repeat("a", 64))
	hw := uuid.NewString()
	if _, err := r.f.super.Exec(context.Background(), "INSERT INTO device (id, organization_id, hostname, state, hardware_uuid) VALUES ($1, $2, 'lt-bin2', 'active', $3)",
		uuid.Must(uuid.NewV7()), r.f.org, hw); err != nil {
		t.Fatal(err)
	}
	r.src.hosts[1].HardwareUUID = hw
	at := func(d time.Duration) *time.Time { v := r.clock.Add(d); return &v }
	unanswered := func(key string, evaluated *time.Time) ports.HostInventory {
		return ports.HostInventory{UnansweredPolicies: []string{key}, PolicyUpdatedAt: evaluated}
	}
	var logs bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelInfo})))
	t.Cleanup(func() { slog.SetDefault(prev) })
	warns := func() int { return strings.Count(logs.String(), "level=WARN msg=\"a Paddock policy did not run") }
	gauge := func(key string) float64 { return testutil.ToFloat64(metricPolicyUnanswered.WithLabelValues(key)) }

	// The first round is full and applies every definition at r.clock.
	r.src.perHost = map[ports.HostRef]ports.HostInventory{
		r.src.hosts[0].Ref: unanswered("disk_encrypted", at(3*time.Minute)),
		r.src.hosts[1].Ref: unanswered("disk_encrypted", at(time.Minute)),
	}
	r.round(t)
	if g, n := gauge("disk_encrypted"), warns(); g != 1 || n != 1 || !strings.Contains(logs.String(), "policy=disk_encrypted hosts=1") {
		t.Fatalf("full round: gauge %v, %d warnings, want 1 and 1: %s", g, n, logs.String())
	}

	r.clock = r.clock.Add(5 * time.Minute)
	r.src.perHost[r.src.hosts[1].Ref] = unanswered("disk_encrypted", at(-time.Minute))
	r.round(t)
	if g, n := gauge("disk_encrypted"), warns(); g != 1 || n != 1 {
		t.Fatalf("changed-host round: gauge %v, %d warnings, want 1 and still 1", g, n)
	}

	r.hashes.hashes = []string{strings.Repeat("a", 64), strings.Repeat("b", 64)}
	r.src.vulnState = "changed" // a full round
	r.clock = r.clock.Add(5 * time.Minute)
	r.src.perHost = map[ports.HostRef]ports.HostInventory{
		r.src.hosts[0].Ref: unanswered(inventory.PolicyAgentBinaryKnown, at(time.Minute)),
		r.src.hosts[1].Ref: {PolicyUpdatedAt: at(time.Minute)},
	}
	r.round(t)
	if g, b, n := gauge("disk_encrypted"), gauge(inventory.PolicyAgentBinaryKnown), warns(); g != 0 || b != 0 || n != 1 {
		t.Fatalf("new hash: gauges %v and %v, %d warnings; want 0, 0 and still 1", g, b, n)
	}
}

// TestInventoryRoundAgentAbsentWhileCheckingIn (plan M5a decision 8 as amended 2026-11-16 b): a host whose
// agent-running policy fails in evaluations 10 minutes apart while its device keeps checking in is reported once, in
// the round whose evaluation is at least 15 minutes after the first failing one; a pass ends the failure, and a new
// failure in two evaluations 15 minutes apart is reported again.
func TestInventoryRoundAgentAbsentWhileCheckingIn(t *testing.T) {
	r := newBinaryRig(t, strings.Repeat("a", 64))
	ctx := context.Background()
	if _, err := r.f.super.Exec(ctx, "INSERT INTO device_status (device_id, organization_id, last_contact_at) VALUES ($1, $2, $3)",
		r.dev, r.f.org, r.clock); err != nil {
		t.Fatal(err)
	}
	reports := func() int {
		var n int
		if err := r.f.super.QueryRow(ctx, "SELECT count(*) FROM action WHERE code = 'device.tamper_agent_not_running' AND target ->> 'id' = $1",
			r.dev.String()).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	start := r.clock
	steps := []struct {
		after   time.Duration
		passing bool
		want    int
	}{
		{0, false, 0}, {10 * time.Minute, false, 0}, {20 * time.Minute, false, 1}, {30 * time.Minute, false, 1},
		{40 * time.Minute, true, 1}, {50 * time.Minute, false, 1}, {65 * time.Minute, false, 2},
	}
	for k, s := range steps {
		r.clock = start.Add(s.after)
		at := r.clock
		if _, err := r.f.super.Exec(ctx, "UPDATE device_status SET last_contact_at = $2 WHERE device_id = $1", r.dev, r.clock.Add(-time.Minute)); err != nil {
			t.Fatal(err)
		}
		r.src.results = []ports.PolicyResult{{Key: inventory.PolicyAgentRunning, Passing: s.passing}}
		r.src.unanswered, r.src.evaluatedAt = nil, &at
		r.round(t)
		if n := reports(); n != s.want {
			t.Fatalf("round %d (evaluation +%v, passing %v): %d events, want %d", k+1, s.after, s.passing, n, s.want)
		}
	}
}
