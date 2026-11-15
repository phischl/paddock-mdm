package db_test

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
)

// fakeMonotonic is an injected monotonic clock for the status cache.
type fakeMonotonic struct{ ns atomic.Int64 }

func (c *fakeMonotonic) since() time.Duration    { return time.Duration(c.ns.Load()) }
func (c *fakeMonotonic) advance(d time.Duration) { c.ns.Add(int64(d)) }

func setStatus(ctx context.Context, t *testing.T, super *pgx.Conn, org uuid.UUID, status string) {
	t.Helper()
	if _, err := super.Exec(ctx, "UPDATE organization SET status = $2 WHERE id = $1", org, status); err != nil {
		t.Fatal(err)
	}
}

// TestOrgGateStatusCache: the gate decides from the per-process status cache while it is at most 5 s old on the
// process's monotonic clock, and from one status read in the transaction once it is older, so a cache that stopped
// refreshing fails closed (plan M17 amendment 2026-11-15 j points 1 and 2). The statuses are set behind the cache's
// back, so each step shows which of the two decided.
func TestOrgGateStatusCache(t *testing.T) {
	ctx := context.Background()
	env := sharedPaddock(t)
	super, err := pgx.Connect(ctx, env.Super)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = super.Close(ctx) })
	org := offboardingFixture(ctx, t, super, 0)
	other := offboardingFixture(ctx, t, super, 0)

	clock := &fakeMonotonic{}
	p, err := db.NewOrgPoolWithClock(ctx, env.API, db.Options{}, clock.since)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	db.StopStatusPoller(p)

	setStatus(ctx, t, super, org, "deleting")

	t.Run("a fresh cache decides without reading the status", func(t *testing.T) {
		clock.advance(5 * time.Second)
		if err := p.InOrg(orgCtx(org), noop); err != nil {
			t.Errorf("InOrg with a cache of exactly 5 s that has the organization active: %v", err)
		}
	})

	t.Run("a stale cache falls back to the status read and refuses", func(t *testing.T) {
		clock.advance(time.Nanosecond)
		for path, enter := range map[string]func() error{
			"InOrg":         func() error { return p.InOrg(orgCtx(org), noop) },
			"InOrgSnapshot": func() error { return p.InOrgSnapshot(orgCtx(org), noop) },
		} {
			err := enter()
			wantUnavailable(t, path+" on a stale cache", err)
			if got := db.OrganizationUnavailableStatus(err); got != "deleting" {
				t.Errorf("%s: refused status %q, want deleting", path, got)
			}
		}
		if err := p.InOrg(orgCtx(other), noop); err != nil {
			t.Errorf("InOrg of another organization on a stale cache: %v", err)
		}
	})

	t.Run("a failed refresh does not make the cache fresh", func(t *testing.T) {
		cancelled, cancel := context.WithCancel(ctx)
		cancel()
		if err := p.RefreshOrganizationStatus(cancelled); err == nil {
			t.Fatal("refresh with a cancelled context succeeded")
		}
		wantUnavailable(t, "InOrg after a failed refresh", p.InOrg(orgCtx(org), noop))
	})

	t.Run("a refreshed cache refuses from memory", func(t *testing.T) {
		if err := p.RefreshOrganizationStatus(ctx); err != nil {
			t.Fatal(err)
		}
		setStatus(ctx, t, super, org, "active")
		err := p.InOrg(orgCtx(org), noop)
		wantUnavailable(t, "InOrg on a cache that has the organization deleting", err)
		if got := db.OrganizationUnavailableStatus(err); got != "deleting" {
			t.Errorf("refused status %q, want deleting", got)
		}
		if err := p.InOrg(orgCtx(other), noop); err != nil {
			t.Errorf("InOrg of another organization: %v", err)
		}
	})

	t.Run("the cache ages on the monotonic clock only", func(t *testing.T) {
		clock.advance(5 * time.Second)
		wantUnavailable(t, "InOrg on a 5 s old cache", p.InOrg(orgCtx(org), noop))
		clock.advance(time.Nanosecond)
		if err := p.InOrg(orgCtx(org), noop); err != nil {
			t.Errorf("InOrg on a stale cache, organization active again: %v", err)
		}
	})
}

// TestOrgGatePoller: without any explicit refresh, the poller brings a committed deleting into the gate within about
// one refresh interval, long before the 5 s fallback could (amendment j point 1).
func TestOrgGatePoller(t *testing.T) {
	ctx := context.Background()
	env := sharedPaddock(t)
	super, err := pgx.Connect(ctx, env.Super)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = super.Close(ctx) })
	org := offboardingFixture(ctx, t, super, 0)
	p, err := db.NewOrgPool(ctx, env.Worker, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	if err := p.InOrg(orgCtx(org), noop); err != nil {
		t.Fatalf("InOrg of an active organization: %v", err)
	}
	setDeleting(ctx, t, super, org)
	start := time.Now()
	for {
		err := p.InOrg(orgCtx(org), noop)
		if err != nil {
			wantUnavailable(t, "InOrg after the poll", err)
			break
		}
		if time.Since(start) > 3*time.Second {
			t.Fatal("the poller did not bring the deleting status into the gate within 3 s")
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Logf("refused %v after the status change", time.Since(start).Round(time.Millisecond))
}

// TestOrgGateBeforeGateHook: a status committed between a caller's earlier check and the gate is refused once the
// cache has read it; the hook is how tests (PDK-1036's export race) place that commit, now that no lock pauses the
// gate.
func TestOrgGateBeforeGateHook(t *testing.T) {
	ctx := context.Background()
	env := sharedPaddock(t)
	super, err := pgx.Connect(ctx, env.Super)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = super.Close(ctx) })
	org := offboardingFixture(ctx, t, super, 0)
	p, err := db.NewOrgPool(ctx, env.API, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	var calls int
	db.SetBeforeGate(p, func(entered uuid.UUID) {
		calls++
		if entered != org || calls > 1 {
			return
		}
		setDeleting(ctx, t, super, org)
		if err := p.RefreshOrganizationStatus(ctx); err != nil {
			t.Error(err)
		}
	})
	ran := false
	err = p.InOrg(orgCtx(org), func(context.Context, *pgstore.Queries) error { ran = true; return nil })
	wantUnavailable(t, "InOrg with deleting committed before the gate", err)
	if ran || calls != 1 {
		t.Errorf("fn ran: %v, hook calls %d", ran, calls)
	}
}

// syncBuffer is a bytes.Buffer safe for the poller and the test at once.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// TestOrgGateRefreshFailures: a failing refresh is counted every time and logged once per failure streak, its
// recovery once; the gate keeps failing closed meanwhile (plan M17 amendment j point 2, PDK-1038 review v4 minor 1).
func TestOrgGateRefreshFailures(t *testing.T) {
	ctx := context.Background()
	env := sharedPaddock(t)
	super, err := pgx.Connect(ctx, env.Super)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = super.Close(ctx) })
	exec := func(sql string) {
		t.Helper()
		if _, err := super.Exec(ctx, sql); err != nil {
			t.Fatal(err)
		}
	}
	const (
		revoke = "REVOKE EXECUTE ON FUNCTION paddock_inactive_organizations() FROM paddock_api"
		grant  = "GRANT EXECUTE ON FUNCTION paddock_inactive_organizations() TO paddock_api"
	)
	org := offboardingFixture(ctx, t, super, 0)
	logs := &syncBuffer{}
	p, err := db.NewOrgPoolWithLogger(ctx, env.API, db.Options{}, slog.New(slog.NewTextHandler(logs, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	db.StopStatusPoller(p)

	exec(revoke)
	t.Cleanup(func() { exec(grant) })
	before := db.GateRefreshFailures()
	for range 3 {
		if err := p.RefreshOrganizationStatus(ctx); err == nil {
			t.Fatal("refresh without EXECUTE succeeded")
		}
	}
	if got := db.GateRefreshFailures() - before; got != 3 {
		t.Errorf("paddock_org_gate_refresh_failures_total rose by %v, want 3", got)
	}
	if n := strings.Count(logs.String(), "status cache refresh failed"); n != 1 {
		t.Errorf("%d warnings for one failure streak, want 1:\n%s", n, logs.String())
	}
	if strings.Contains(logs.String(), "password") {
		t.Errorf("the warning names a password:\n%s", logs.String())
	}

	exec(grant)
	if err := p.RefreshOrganizationStatus(ctx); err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(logs.String(), "status cache refresh recovered"); n != 1 {
		t.Errorf("%d recovery lines, want 1:\n%s", n, logs.String())
	}
	if err := p.InOrg(orgCtx(org), noop); err != nil {
		t.Errorf("InOrg after the recovery: %v", err)
	}

	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	before = db.GateRefreshFailures()
	_ = p.RefreshOrganizationStatus(cancelled)
	if got := db.GateRefreshFailures() - before; got != 0 {
		t.Errorf("a refresh ended by its own context counted %v failures, want 0", got)
	}
}
