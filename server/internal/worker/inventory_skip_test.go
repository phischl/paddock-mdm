package worker

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/phischl/paddock-mdm/server/internal/app"
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
	devs  []uuid.UUID
	hosts []ports.HostRef
	src   *fakeSource
	inv   *Inventory
	sys   context.Context
}

func newSkipRig(t *testing.T) *skipRig {
	t.Helper()
	ctx := context.Background()
	a, b := newFixture(t), newFixture(t)
	platform, err := db.NewPlatformPool(ctx, pgtest.SharedPaddock(t).Platform, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(platform.Close)
	r := &skipRig{f: a, src: &fakeSource{perHost: map[ports.HostRef]ports.HostInventory{}, hostErr: map[ports.HostRef]error{}}}
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
