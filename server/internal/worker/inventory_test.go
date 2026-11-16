package worker

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

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
	evaluatedAt *time.Time
	applied     []ports.PolicyDefinition
	applyErr    error
}

func (s *fakeSource) VulnerabilityState(context.Context) (string, error) { return s.vulnState, nil }

func (s *fakeSource) ListHostsChangedSince(_ context.Context, since time.Time, cursor string) (ports.HostPage, error) {
	s.since = append(s.since, since)
	if cursor == "" { // two pages of one host each
		return ports.HostPage{Hosts: s.hosts[:1], Next: "1"}, nil
	}
	return ports.HostPage{Hosts: s.hosts[1:]}, nil
}

func (s *fakeSource) HostInventory(_ context.Context, ref ports.HostRef) (ports.HostInventory, error) {
	s.read = append(s.read, ref)
	return ports.HostInventory{OSVersion: "Ubuntu 26.04.1 LTS", Software: []ports.SoftwarePackage{{Name: "bash", Version: "5.2", Source: "deb_packages"}},
		Policies: s.results, PolicyUpdatedAt: s.evaluatedAt}, nil
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
	src := &fakeSource{hosts: []ports.InventoryHost{{Ref: "1", HardwareUUID: strings.ToUpper(hw)}, {Ref: "2", HardwareUUID: uuid.NewString()}}}
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
	if src.policies != 3 || !slices.Equal(src.read[:2], []ports.HostRef{"1", "1"}) {
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
		src: &fakeSource{hosts: []ports.InventoryHost{{Ref: "1", HardwareUUID: hw}, {Ref: "2", HardwareUUID: uuid.NewString()}}},
		sys: principal.With(ctx, principal.Principal{Kind: principal.KindSystem, Display: "worker"})}
	runner := app.NewActionRunner(f.pool, platform, httpx.RequestID)
	r.inv = NewInventory(nil, r.src, app.NewInventorySync(runner, f.pool, platform), app.NewVulnerabilitySummary(runner), f.pool, platform, time.Minute)
	r.inv.hashes, r.inv.now = r.hashes, func() time.Time { return r.clock }
	return r
}

// host sets the host's agent binary result, evaluated at the given offset from the last apply.
func (r *binaryRig) host(passing bool, sinceApplied time.Duration) {
	at := r.inv.binaryAppliedAt.Add(sinceApplied)
	r.src.results = []ports.PolicyResult{{Key: inventory.PolicyAgentBinaryKnown, Passing: passing}}
	r.src.evaluatedAt = &at
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
