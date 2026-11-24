package worker

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/platform/httpx"
	"github.com/phischl/paddock-mdm/server/internal/ports"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/problem"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
)

// skipRig is an inventory round over two organizations with two devices each; hosts[n] speaks for devs[n], and devs
// 0 and 1 belong to the first organization.
type skipRig struct {
	f     fixture
	orgB  uuid.UUID
	devs  []uuid.UUID
	hosts []ports.HostRef
	src   *fakeSource
	inv   *Inventory
	sys   context.Context
}

func newSkipRig(t *testing.T) *skipRig { return newSkipRigTimeout(t, 0) }

// newSkipRigTimeout is newSkipRig whose organization pool ends every transaction after timeout (0: never).
func newSkipRigTimeout(t *testing.T, timeout time.Duration) *skipRig {
	t.Helper()
	ctx := context.Background()
	a, b := newFixture(t), newFixture(t)
	if timeout > 0 {
		pool, err := db.NewOrgPool(ctx, pgtest.SharedPaddock(t).Worker, db.Options{TransactionTimeout: timeout})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(pool.Close)
		a.pool = pool
	}
	platform, err := db.NewPlatformPool(ctx, pgtest.SharedPaddock(t).Platform, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(platform.Close)
	r := &skipRig{f: a, orgB: b.org, src: &fakeSource{perHost: map[ports.HostRef]ports.HostInventory{}, hostErr: map[ports.HostRef]error{}}}
	for n, org := range []uuid.UUID{a.org, a.org, b.org, b.org} {
		dev, hw := uuid.Must(uuid.NewV7()), uuid.NewString()
		if _, err := a.super.Exec(ctx, "INSERT INTO device (id, organization_id, hostname, state, hardware_uuid) VALUES ($1, $2, $3, 'active', $4)",
			dev, org, fmt.Sprintf("lt-skip-%d", n), hw); err != nil {
			t.Fatal(err)
		}
		ref := uniqueRef()
		r.devs, r.hosts = append(r.devs, dev), append(r.hosts, ref)
		r.src.hosts = append(r.src.hosts, ports.InventoryHost{Ref: ref, HardwareUUID: hw})
	}
	runner := app.NewActionRunner(a.pool, platform, httpx.RequestID)
	r.inv = NewInventory(nil, r.src, app.NewInventorySync(runner, a.pool, platform), app.NewVulnerabilitySummary(runner),
		a.pool, platform, time.Minute)
	r.sys = principal.With(ctx, principal.Principal{Kind: principal.KindSystem, Display: "worker"})
	return r
}

// stored reports whether the round stored an inventory for the device.
func (r *skipRig) stored(t *testing.T, dev uuid.UUID) bool {
	t.Helper()
	var n int
	if err := r.f.super.QueryRow(context.Background(), "SELECT count(*) FROM device_inventory_ref WHERE device_id = $1", dev).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n == 1
}

// count returns the single number a query of the rig's database answers.
func (r *skipRig) count(t *testing.T, sql string, args ...any) int {
	t.Helper()
	var n int
	if err := r.f.super.QueryRow(context.Background(), sql, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// rejections returns the device.tamper_inventory_rejected events and tamper findings of the device.
func (r *skipRig) rejections(t *testing.T, dev uuid.UUID) (events, findings int) {
	t.Helper()
	code := string(audit.CodeDeviceTamperInventoryRejected)
	return r.count(t, "SELECT count(*) FROM action WHERE code = $1 AND target ->> 'id' = $2", code, dev.String()),
		r.count(t, "SELECT count(*) FROM finding WHERE kind = 'tamper' AND code = $1 AND device_id = $2", code, dev)
}

// TestInventoryRoundSkipsFailingHost (PDK-1122k): a host whose data the database refuses (a NUL byte that reached the
// store) and a host Fleet no longer knows are skipped and counted by reason; the other hosts of both organizations are
// stored, the round completes and the next one lists only changes since.
func TestInventoryRoundSkipsFailingHost(t *testing.T) {
	r := newSkipRig(t)
	r.src.perHost[r.hosts[0]] = ports.HostInventory{OSVersion: "Ubuntu\x00 26.04"}
	r.src.hostErr[r.hosts[3]] = fmt.Errorf("%w: get fleet host: HTTP 404", problem.NotFound)
	store, fetch := metricHostsSkipped.WithLabelValues("store_refused"), metricHostsSkipped.WithLabelValues("fetch_refused")
	storeBefore, fetchBefore := testutil.ToFloat64(store), testutil.ToFloat64(fetch)
	if err := r.inv.Round(r.sys); err != nil {
		t.Fatalf("round failed: %v", err)
	}
	for n, want := range []bool{false, true, true, false} {
		if got := r.stored(t, r.devs[n]); got != want {
			t.Fatalf("device %d stored %v, want %v", n, got, want)
		}
	}
	if d := testutil.ToFloat64(store) - storeBefore; d != 1 {
		t.Fatalf("store_refused counted %v, want 1", d)
	}
	if d := testutil.ToFloat64(fetch) - fetchBefore; d != 1 {
		t.Fatalf("fetch_refused counted %v, want 1", d)
	}
	if err := r.inv.Round(r.sys); err != nil {
		t.Fatal(err)
	}
	if len(r.src.since) != 4 || !r.src.since[0].IsZero() || r.src.since[2].IsZero() {
		t.Fatalf("listings since %v: the first round did not advance", r.src.since)
	}
}

// TestInventoryRoundFailsWhenFleetFails (PDK-1122k): a failing host list and a Fleet failure on one host's detail are
// not about one host; the round fails and does not advance.
func TestInventoryRoundFailsWhenFleetFails(t *testing.T) {
	for name, set := range map[string]func(r *skipRig){
		"list": func(r *skipRig) {
			r.src.listErr = fmt.Errorf("%w: list fleet hosts: HTTP 502", problem.UpstreamUnavailable)
		},
		"detail": func(r *skipRig) {
			r.src.hostErr[r.hosts[1]] = fmt.Errorf("%w: get fleet host: HTTP 502", problem.UpstreamUnavailable)
		},
	} {
		t.Run(name, func(t *testing.T) {
			r := newSkipRig(t)
			set(r)
			if err := r.inv.Round(r.sys); !errors.Is(err, problem.UpstreamUnavailable) {
				t.Fatalf("round %v, want upstream_unavailable", err)
			}
			if !r.inv.since.IsZero() || r.inv.rounds != 0 {
				t.Fatalf("the failed round advanced: since %v, rounds %d", r.inv.since, r.inv.rounds)
			}
		})
	}
}

// TestInventoryRoundSkipsOverlongSoftware (PDK-1122k, review 1 M1): a software name too long for the btree key of
// installed_software, which the adapter caps but another source may not, skips only its host.
func TestInventoryRoundSkipsOverlongSoftware(t *testing.T) {
	r := newSkipRig(t)
	var name strings.Builder
	for range 100 { // random, so that PostgreSQL cannot compress the key below its limit
		name.WriteString(uuid.NewString())
	}
	r.src.perHost[r.hosts[2]] = ports.HostInventory{Software: []ports.SoftwarePackage{
		{Name: name.String(), Version: "1", Source: "deb_packages"}}}
	store := metricHostsSkipped.WithLabelValues("store_refused")
	before := testutil.ToFloat64(store)
	if err := r.inv.Round(r.sys); err != nil {
		t.Fatalf("round failed: %v", err)
	}
	for n, want := range []bool{true, true, false, true} {
		if got := r.stored(t, r.devs[n]); got != want {
			t.Fatalf("device %d stored %v, want %v", n, got, want)
		}
	}
	if d := testutil.ToFloat64(store) - before; d != 1 {
		t.Fatalf("store_refused counted %v, want 1", d)
	}
}

// TestInventoryRoundStoreFailureNotPerHost (PDK-1122k, review 1 L2): a store that fails for a reason other than the
// host's data (here the transaction timeout while another transaction locks the device) and a context canceled during
// the round fail the round: nothing is skipped, counted or reported, and the round does not advance.
func TestInventoryRoundStoreFailureNotPerHost(t *testing.T) {
	cases := map[string]func(t *testing.T) (*skipRig, context.Context){
		"database": func(t *testing.T) (*skipRig, context.Context) {
			r := newSkipRigTimeout(t, 2*time.Second)
			ctx := context.Background()
			r.src.onRead = func(ref ports.HostRef) {
				if ref != r.hosts[1] {
					return
				}
				tx, err := r.f.super.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = tx.Rollback(ctx) })
				if _, err := tx.Exec(ctx, "SELECT 1 FROM device WHERE id = $1 FOR UPDATE", r.devs[1]); err != nil {
					t.Fatal(err)
				}
			}
			return r, r.sys
		},
		"canceled": func(t *testing.T) (*skipRig, context.Context) {
			r := newSkipRig(t)
			ctx, cancel := context.WithCancel(r.sys)
			r.src.onRead = func(ref ports.HostRef) {
				if ref == r.hosts[2] {
					cancel()
				}
			}
			r.src.hostErr[r.hosts[2]] = fmt.Errorf("%w: get fleet host: HTTP 404", problem.NotFound)
			return r, ctx
		},
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			r, ctx := setup(t)
			store, fetch := metricHostsSkipped.WithLabelValues("store_refused"), metricHostsSkipped.WithLabelValues("fetch_refused")
			before := testutil.ToFloat64(store) + testutil.ToFloat64(fetch)
			err := r.inv.Round(ctx)
			if err == nil || db.IsDataError(err) {
				t.Fatalf("round %v, want a failure that is not a data error", err)
			}
			t.Logf("round failed: %v", err)
			if d := testutil.ToFloat64(store) + testutil.ToFloat64(fetch) - before; d != 0 {
				t.Fatalf("%v hosts skipped, want 0", d)
			}
			if !r.inv.since.IsZero() || r.inv.rounds != 0 {
				t.Fatalf("the failed round advanced: since %v, rounds %d", r.inv.since, r.inv.rounds)
			}
			for _, dev := range r.devs {
				if ev, _ := r.rejections(t, dev); ev != 0 {
					t.Fatalf("device %s: %d rejection events", dev, ev)
				}
			}
		})
	}
}

// TestInventoryRoundReportsRejectionOncePerEpisode (PDK-1122k, decision §198/§199): a skipped device records
// device.tamper_inventory_rejected with a tamper finding for that device only, in its own organization, naming its own
// host; not again while it stays skipped; again after its inventory was stored in between.
func TestInventoryRoundReportsRejectionOncePerEpisode(t *testing.T) {
	r := newSkipRig(t)
	bad := ports.HostInventory{OSVersion: "Ubuntu\x00 26.04"}
	r.src.perHost[r.hosts[0]] = bad
	steps := []struct {
		failing bool
		want    int
	}{{true, 1}, {true, 1}, {false, 1}, {true, 2}}
	for k, s := range steps {
		if s.failing {
			r.src.perHost[r.hosts[0]] = bad
		} else {
			delete(r.src.perHost, r.hosts[0])
		}
		if err := r.inv.Round(r.sys); err != nil {
			t.Fatalf("round %d: %v", k+1, err)
		}
		if ev, fi := r.rejections(t, r.devs[0]); ev != s.want || fi != 1 {
			t.Fatalf("round %d: %d events, %d findings; want %d, 1", k+1, ev, fi, s.want)
		}
	}
	code := string(audit.CodeDeviceTamperInventoryRejected)
	if n := r.count(t, `SELECT count(*) FROM action WHERE code = $1 AND target ->> 'id' = $2 AND organization_id = $3
		AND params ->> 'reason' = 'store_refused' AND params ->> 'fleet_host' = $4`, code, r.devs[0].String(), r.f.org,
		string(r.hosts[0])); n != 2 {
		t.Fatalf("%d events in the device's organization naming its host, want 2", n)
	}
	for _, dev := range r.devs[1:] {
		if ev, fi := r.rejections(t, dev); ev+fi != 0 {
			t.Fatalf("device %s: %d events, %d findings of another device's host", dev, ev, fi)
		}
	}
	if n := r.count(t, "SELECT count(*) FROM action WHERE code = $1 AND organization_id = $2", code, r.orgB); n != 0 {
		t.Fatalf("%d events in the other organization", n)
	}
	if n := r.count(t, "SELECT count(*) FROM finding WHERE code = $1 AND organization_id = $2", code, r.orgB); n != 0 {
		t.Fatalf("%d findings in the other organization", n)
	}
}

// TestInventoryRoundRejectionEpisodeSkewedClock (PDK-1122k, review 2 L-b): a worker clock behind the database's
// still reports one event per episode: the episode compares times of the database's clock only.
func TestInventoryRoundRejectionEpisodeSkewedClock(t *testing.T) {
	r := newSkipRig(t)
	r.inv.now = func() time.Time { return time.Now().Add(-2 * time.Minute) }
	for k := range 4 {
		if k > 0 {
			r.src.perHost[r.hosts[0]] = ports.HostInventory{OSVersion: "Ubuntu\x00 26.04"}
		}
		if err := r.inv.Round(r.sys); err != nil {
			t.Fatalf("round %d: %v", k+1, err)
		}
	}
	if !r.stored(t, r.devs[0]) {
		t.Fatal("the first round did not store the device")
	}
	if ev, fi := r.rejections(t, r.devs[0]); ev != 1 || fi != 1 {
		t.Fatalf("%d events, %d findings after three skipped rounds, want 1, 1", ev, fi)
	}
}
