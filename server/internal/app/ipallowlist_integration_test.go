package app_test

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/domain/ipallowlist"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/platform/httpx"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/problem"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
)

type fakeVersion struct {
	mu    sync.Mutex
	n     int64
	fail  bool
	bumps int
}

func (v *fakeVersion) Bump(context.Context) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.bumps++
	if v.fail {
		return errors.New("valkey down")
	}
	v.n++
	return nil
}

func (v *fakeVersion) Get(context.Context) (int64, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.n, nil
}

type allowlistHarness struct {
	t        *testing.T
	list     *app.IPAllowlist
	version  *fakeVersion
	super    *pgx.Conn
	apiDSN   string
	reloads  int
	platform principal.Principal
}

func newAllowlistHarness(t *testing.T) *allowlistHarness {
	t.Helper()
	env := pgtest.SharedPaddock(t)
	ctx := context.Background()
	orgPool, err := db.NewOrgPool(ctx, env.API, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(orgPool.Close)
	platform, err := db.NewPlatformPool(ctx, env.Platform, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(platform.Close)
	super, err := pgx.Connect(ctx, env.Super)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = super.Close(ctx) })
	// The table is platform-wide: every test starts from and leaves an empty list.
	clear := func() {
		if _, err := super.Exec(context.Background(), "DELETE FROM ip_allowlist_entry"); err != nil {
			t.Fatal(err)
		}
	}
	clear()
	t.Cleanup(clear)
	h := &allowlistHarness{t: t, version: &fakeVersion{}, super: super, apiDSN: env.API}
	runner := app.NewActionRunner(orgPool, platform, httpx.RequestID)
	h.list = app.NewIPAllowlist(runner, platform, h.version)
	h.list.AfterChange(func(context.Context) { h.reloads++ })
	h.platform = principal.Principal{Kind: principal.KindPlatformAdmin, ID: uuid.Must(uuid.NewV7()), Display: "root@test",
		Role: principal.RolePlatform, IP: "192.0.2.9", StepUpAt: time.Now()}
	return h
}

// ctx is a request context of the platform admin with its own correlation ID.
func (h *allowlistHarness) ctx() (context.Context, string) {
	id := uuid.NewString()
	return principal.With(httpx.WithRequestID(context.Background(), id), h.platform), id
}

// event returns "code:outcome:error_code" of the single action recorded under requestID.
func (h *allowlistHarness) event(requestID string) string {
	h.t.Helper()
	rows, err := h.super.Query(context.Background(),
		"SELECT code || ':' || coalesce(outcome, status) || ':' || coalesce(error_code, '') FROM action WHERE correlation_id = $1", requestID)
	if err != nil {
		h.t.Fatal(err)
	}
	out, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		h.t.Fatal(err)
	}
	if len(out) != 1 {
		h.t.Fatalf("events for %s: %v, want exactly one", requestID, out)
	}
	return out[0]
}

func (h *allowlistHarness) params(requestID string) map[string]any {
	h.t.Helper()
	var params map[string]any
	if err := h.super.QueryRow(context.Background(), "SELECT params FROM action WHERE correlation_id = $1", requestID).Scan(&params); err != nil {
		h.t.Fatal(err)
	}
	return params
}

// TestIPAllowlistRoleCannotRead: the organization role paddock_api has no grant on the table (platform data).
func TestIPAllowlistRoleCannotRead(t *testing.T) {
	h := newAllowlistHarness(t)
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, h.apiDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close(ctx) }()
	var n int
	err = conn.QueryRow(ctx, "SELECT count(*) FROM ip_allowlist_entry").Scan(&n)
	if err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("paddock_api read the ip allow list: %v", err)
	}
}

// TestIPAllowlistLifecycle: consequence checks, confirmations, duplicates, the audit params and the propagation
// (plan M7a decision 12).
func TestIPAllowlistLifecycle(t *testing.T) {
	h := newAllowlistHarness(t)
	ctx, id := h.ctx()
	if _, err := h.list.Create(ctx, "198.51.100.0/24", "office", ipallowlist.ConsequenceNone); !errors.Is(err, problem.LockoutConfirmationRequired) {
		t.Fatalf("first entry excluding the caller: %v", err)
	}
	if got := h.event(id); got != "platform.ip_allowlist_changed:failure:lockout_confirmation_required" {
		t.Fatal(got)
	}
	if h.reloads != 0 || h.version.bumps != 0 {
		t.Fatal("a refused change must not propagate")
	}
	ctx, id = h.ctx()
	mine, err := h.list.Create(ctx, " 192.0.2.9/32 ", " gate host ", ipallowlist.ConsequenceNone)
	if err != nil || !mine.CoversCaller || mine.Label != "gate host" || mine.CreatedBy != "root@test" {
		t.Fatalf("own address: %+v %v", mine, err)
	}
	if got := h.event(id); got != "platform.ip_allowlist_changed:success:" {
		t.Fatal(got)
	}
	p := h.params(id)
	if p["action"] != "added" || p["cidr"] != "192.0.2.9/32" || p["consequence"] != "none" || p["entries"] != float64(1) {
		t.Fatalf("params %v", p)
	}
	if h.reloads != 1 || h.version.bumps != 1 {
		t.Fatalf("propagation: reloads %d bumps %d", h.reloads, h.version.bumps)
	}
	ctx, _ = h.ctx()
	office, err := h.list.Create(ctx, "198.51.100.0/24", "office", ipallowlist.ConsequenceNone)
	if err != nil || office.CoversCaller {
		t.Fatalf("second entry: %+v %v", office, err)
	}
	ctx, id = h.ctx()
	if _, err := h.list.Create(ctx, "198.51.100.0/24", "again", ipallowlist.ConsequenceNone); !errors.Is(err, problem.AlreadyExists) {
		t.Fatalf("duplicate: %v", err)
	}
	if got := h.event(id); got != "platform.ip_allowlist_changed:failure:already_exists" {
		t.Fatal(got)
	}
	ctx, id = h.ctx()
	if _, err := h.list.Create(ctx, "10.0.0.1/8", "bad", ipallowlist.ConsequenceNone); !errors.Is(err, problem.InvalidRequest) {
		t.Fatalf("host bits: %v", err)
	}
	if got := h.event(id); got != "platform.ip_allowlist_changed:failure:invalid_request" {
		t.Fatal(got)
	}

	ctx, id = h.ctx()
	label := "branch office"
	updated, err := h.list.Update(ctx, office.ID, nil, &label, ipallowlist.ConsequenceNone)
	if err != nil || updated.Label != label || updated.CIDR != office.CIDR {
		t.Fatalf("label update: %+v %v", updated, err)
	}
	if p := h.params(id); p["action"] != "updated" || p["previous_label"] != "office" || p["previous_cidr"] != "198.51.100.0/24" || p["consequence"] != "none" {
		t.Fatalf("update params %v", p)
	}
	ctx, _ = h.ctx()
	if _, err := h.list.Update(ctx, office.ID, nil, nil, ipallowlist.ConsequenceNone); !errors.Is(err, problem.InvalidRequest) {
		t.Fatalf("empty update: %v", err)
	}
	ctx, _ = h.ctx()
	wide := "192.0.2.0/24"
	if _, err := h.list.Update(ctx, mine.ID, &wide, nil, ipallowlist.ConsequenceNone); err != nil {
		t.Fatalf("widening the own entry keeps the caller covered: %v", err)
	}
	ctx, _ = h.ctx()
	elsewhere := "203.0.113.0/24"
	if _, err := h.list.Update(ctx, mine.ID, &elsewhere, nil, ipallowlist.ConsequenceNone); !errors.Is(err, problem.LockoutConfirmationRequired) {
		t.Fatalf("moving the own entry away: %v", err)
	}
	ctx, _ = h.ctx()
	if _, err := h.list.Update(ctx, uuid.New(), &label, nil, ipallowlist.ConsequenceNone); !errors.Is(err, problem.NotFound) {
		t.Fatalf("unknown id: %v", err)
	}

	ctx, _ = h.ctx()
	if err := h.list.Delete(ctx, mine.ID, ipallowlist.ConsequenceNone); !errors.Is(err, problem.LockoutConfirmationRequired) {
		t.Fatalf("removing the own coverage: %v", err)
	}
	ctx, id = h.ctx()
	if err := h.list.Delete(ctx, office.ID, ipallowlist.ConsequenceNone); err != nil {
		t.Fatalf("removing another entry: %v", err)
	}
	if p := h.params(id); p["action"] != "removed" || p["entries"] != float64(1) {
		t.Fatalf("delete params %v", p)
	}
	ctx, _ = h.ctx()
	if err := h.list.Delete(ctx, mine.ID, ipallowlist.ConsequenceLockout); !errors.Is(err, problem.DisableConfirmationRequired) {
		t.Fatalf("the wrong confirmation does not count: %v", err)
	}
	ctx, id = h.ctx()
	if err := h.list.Delete(ctx, mine.ID, ipallowlist.ConsequenceDisable); err != nil {
		t.Fatalf("switching off with confirmation: %v", err)
	}
	if p := h.params(id); p["consequence"] != "disable" || p["entries"] != float64(0) {
		t.Fatalf("disable params %v", p)
	}
	if prefixes, err := h.list.Load(context.Background()); err != nil || len(prefixes) != 0 {
		t.Fatalf("after: %v %v", prefixes, err)
	}

	// Without a step-up every write is denied before anything is read.
	noStepUp := h.platform
	noStepUp.StepUpAt = time.Time{}
	ctx = principal.With(httpx.WithRequestID(context.Background(), "nostepup-"+uuid.NewString()), noStepUp)
	if _, err := h.list.Create(ctx, "192.0.2.9/32", "x", ipallowlist.ConsequenceNone); !errors.Is(err, problem.StepUpRequired) {
		t.Fatalf("without step-up: %v", err)
	}
	if got := h.event(httpx.RequestID(ctx)); got != "platform.ip_allowlist_changed:denied:step_up_required" {
		t.Fatal(got)
	}
	// A failing version bump is logged, not returned: the replicas reload periodically.
	h.version.fail = true
	ctx, _ = h.ctx()
	if _, err := h.list.Create(ctx, "192.0.2.9/32", "x", ipallowlist.ConsequenceNone); err != nil {
		t.Fatalf("with Valkey down: %v", err)
	}
}

// TestIPAllowlistConcurrentWriters: the table lock serializes the consequence checks, so two concurrent removals of
// the two entries covering the caller cannot both succeed and switch the feature off unconfirmed.
func TestIPAllowlistConcurrentWriters(t *testing.T) {
	h := newAllowlistHarness(t)
	ctx, _ := h.ctx()
	a, err := h.list.Create(ctx, "192.0.2.9/32", "a", ipallowlist.ConsequenceNone)
	if err != nil {
		t.Fatal(err)
	}
	ctx, _ = h.ctx()
	b, err := h.list.Create(ctx, "192.0.2.0/24", "b", ipallowlist.ConsequenceNone)
	if err != nil {
		t.Fatal(err)
	}
	for range 5 {
		results := make(chan error, 2)
		for _, id := range []uuid.UUID{a.ID, b.ID} {
			go func() {
				ctx, _ := h.ctx()
				results <- h.list.Delete(ctx, id, ipallowlist.ConsequenceNone)
			}()
		}
		var ok, refused int
		for range 2 {
			switch err := <-results; {
			case err == nil:
				ok++
			case errors.Is(err, problem.DisableConfirmationRequired):
				refused++
			default:
				t.Fatalf("unexpected: %v", err)
			}
		}
		if ok != 1 || refused != 1 {
			t.Fatalf("round: %d succeeded, %d refused", ok, refused)
		}
		left, err := h.list.Load(context.Background())
		if err != nil || len(left) != 1 {
			t.Fatalf("one entry must remain: %v %v", left, err)
		}
		// Restore both entries for the next round.
		ctx, _ = h.ctx()
		if _, err := h.list.DisableAll(context.Background()); err != nil {
			t.Fatal(err)
		}
		if a, err = h.list.Create(ctx, "192.0.2.9/32", "a", ipallowlist.ConsequenceNone); err != nil {
			t.Fatal(err)
		}
		ctx, _ = h.ctx()
		if b, err = h.list.Create(ctx, "192.0.2.0/24", "b", ipallowlist.ConsequenceNone); err != nil {
			t.Fatal(err)
		}
	}
}

// TestIPAllowlistBreakGlass: the host-side operations run under a system principal without step-up or consequence
// check, are audited with actor system, and DisableAll returns the removed ranges (plan M7a decision 21).
func TestIPAllowlistBreakGlass(t *testing.T) {
	h := newAllowlistHarness(t)
	if removed, err := h.list.DisableAll(context.Background()); err != nil || len(removed) != 0 {
		t.Fatalf("already off: %v %v", removed, err)
	}
	var before int
	if err := h.super.QueryRow(context.Background(), "SELECT count(*) FROM action WHERE code = 'platform.ip_allowlist_disabled'").Scan(&before); err != nil {
		t.Fatal(err)
	}
	ctx := httpx.WithRequestID(context.Background(), "bg-"+uuid.NewString())
	item, err := h.list.AddBreakGlass(ctx, "203.0.113.0/24", "host")
	if err != nil || item.CreatedBy != "paddock-server admin" || item.CoversCaller {
		t.Fatalf("break-glass add: %+v %v", item, err)
	}
	if got := h.event(httpx.RequestID(ctx)); got != "platform.ip_allowlist_changed:success:" {
		t.Fatal(got)
	}
	var actor string
	if err := h.super.QueryRow(context.Background(), "SELECT actor->>'type' FROM action WHERE correlation_id = $1", httpx.RequestID(ctx)).Scan(&actor); err != nil || actor != "system" {
		t.Fatalf("actor %q %v", actor, err)
	}
	if p := h.params(httpx.RequestID(ctx)); p["consequence"] != "none" || p["entries"] != float64(1) {
		t.Fatalf("params %v", p)
	}
	ctx = httpx.WithRequestID(context.Background(), "bg-"+uuid.NewString())
	if _, err := h.list.AddBreakGlass(ctx, "203.0.113.0/24", "host"); !errors.Is(err, problem.AlreadyExists) {
		t.Fatalf("duplicate: %v", err)
	}
	if _, err := h.list.AddBreakGlass(ctx, "2001:db8::/32", "v6"); err != nil {
		t.Fatal(err)
	}
	entries, err := h.list.Entries(context.Background())
	if err != nil || len(entries) != 2 || entries[0].CIDR.String() != "203.0.113.0/24" {
		t.Fatalf("entries %v %v", entries, err)
	}

	ctx = httpx.WithRequestID(context.Background(), "bg-"+uuid.NewString())
	removed, err := h.list.DisableAll(ctx)
	if err != nil || len(removed) != 2 {
		t.Fatalf("disable: %v %v", removed, err)
	}
	if got := h.event(httpx.RequestID(ctx)); got != "platform.ip_allowlist_disabled:success:" {
		t.Fatal(got)
	}
	p := h.params(httpx.RequestID(ctx))
	if p["method"] != "cli" || p["entries_removed"] != float64(2) {
		t.Fatalf("params %v", p)
	}
	if got, _ := p["removed"].([]any); len(got) != 2 {
		t.Fatalf("removed %v", p["removed"])
	}
	var after int
	if err := h.super.QueryRow(context.Background(), "SELECT count(*) FROM action WHERE code = 'platform.ip_allowlist_disabled'").Scan(&after); err != nil {
		t.Fatal(err)
	}
	if after != before+1 {
		t.Fatalf("disabled events: %d → %d", before, after)
	}
	if _, err := h.list.Load(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx = httpx.WithRequestID(context.Background(), "bg-"+uuid.NewString())
	if err := h.list.RecordBypass(ctx); err != nil {
		t.Fatal(err)
	}
	if p := h.params(httpx.RequestID(ctx)); p["method"] != "env" || p["entries_removed"] != float64(0) {
		t.Fatalf("bypass params %v", p)
	}
	if _, err := netip.ParsePrefix(removed[0].String()); err != nil {
		t.Fatal(err)
	}
}
