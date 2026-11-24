package worker

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/inventory"
	"github.com/phischl/paddock-mdm/server/internal/platform/httpx"
	"github.com/phischl/paddock-mdm/server/internal/ports"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/problem"
)

// setOrgStatus changes an organization's status for the rest of the test.
func (r *bindRig) setOrgStatus(t *testing.T, org uuid.UUID, status string) {
	t.Helper()
	if _, err := r.f.super.Exec(context.Background(), "UPDATE organization SET status = $2 WHERE id = $1", org, status); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = r.f.super.Exec(context.Background(), "UPDATE organization SET status = 'active' WHERE id = $1", org)
	})
}

// TestInventoryRoundSuspendedOrgReservationInUse (review round 3, S1, regression): a left host of a device of a
// suspended organization stays reserved: no other device is bound to it or stores it, it is not removed while the
// organization is suspended, and it is removed once after the organization is active again.
func TestInventoryRoundSuspendedOrgReservationInUse(t *testing.T) {
	r := newBindRig(t)
	admin := withLeftHostRemoval(r)
	admin.errs = []error{fmt.Errorf("%w: refused", problem.InvalidState)}
	hwV, hwD := uuid.NewString(), uuid.NewString()
	orgV, v := r.foreignDevice(t, hwV)
	d := r.device(t, hwD)
	r.host(r.id(5), hwV, true)
	r.round(t)
	r.host(r.id(6), hwV, true)
	r.relabel(r.id(5), hwD)
	r.advance(5*time.Minute, r.id(5), r.id(6))
	r.round(t)
	if !r.reserved(t, v, r.id(5)) || len(admin.calls) != 1 {
		t.Fatalf("reserved %v, calls %v", r.reserved(t, v, r.id(5)), admin.calls)
	}
	r.setOrgStatus(t, orgV, "suspended")
	for n := range 3 {
		token := uuid.NewString()
		r.binder.hosts[token] = ports.HostSeen{Ref: r.id(5), HardwareUUID: hwD}
		r.report(t, d, token, r.clock)
		r.advance(inventory.LeftHostRetryAfter, r.id(5), r.id(6))
		r.round(t)
		if r.boundHost(t, d) == r.id(5) || r.externalID(t, d) == r.id(5) {
			t.Fatalf("round %d: D bound %q, stores %q", n+1, r.boundHost(t, d), r.externalID(t, d))
		}
	}
	if len(admin.calls) != 1 {
		t.Fatalf("deleted while the organization was suspended: %v", admin.calls)
	}
	r.setOrgStatus(t, orgV, "active")
	r.round(t)
	if strings.Count(fmt.Sprint(admin.calls), string(r.id(5))) != 2 || r.reserved(t, v, r.id(5)) {
		t.Fatalf("after reactivation: calls %v, reserved %v", admin.calls, r.reserved(t, v, r.id(5)))
	}
	if got := r.removals(t, orgV); !slices.Equal(got, []string{"failure relisted", "success relisted"}) {
		t.Fatalf("events %v", got)
	}
}

// TestInventoryRoundSuspendedOrgSkippedByRemoval (review round 3, S1): reservations of a suspended organization are
// skipped without using the round's removal budget or the metric.
func TestInventoryRoundSuspendedOrgSkippedByRemoval(t *testing.T) {
	r := newBindRig(t)
	if _, err := r.f.super.Exec(context.Background(), "UPDATE device_inventory_left_host SET removed_at = now() WHERE removed_at IS NULL"); err != nil {
		t.Fatal(err)
	}
	admin := withLeftHostRemoval(r)
	r.inv.leftPerRound = 1
	orgS, s := r.foreignDevice(t, uuid.NewString())
	v := r.device(t, uuid.NewString())
	r.host(r.id(1), uuid.NewString(), true)
	r.reserve(t, orgS, s, r.id(5))
	r.reserve(t, orgS, s, r.id(6))
	r.reserve(t, r.f.org, v, r.id(7))
	if _, err := r.f.super.Exec(context.Background(), "UPDATE device_inventory_left_host SET left_at = left_at - interval '1 hour' WHERE device_id = $1", s); err != nil {
		t.Fatal(err)
	}
	r.setOrgStatus(t, orgS, "suspended")
	before := testutil.ToFloat64(metricPreviousHosts.WithLabelValues("removed"))
	r.round(t)
	if !slices.Equal(admin.calls, []ports.HostRef{r.id(7)}) {
		t.Fatalf("calls %v", admin.calls)
	}
	if got := testutil.ToFloat64(metricPreviousHosts.WithLabelValues("removed")) - before; got != 1 {
		t.Fatalf("removed +%v", got)
	}
}

// TestInventoryRoundRetiredHostNotBoundElsewhere (review round 3, retired, regression): a retired device's stored host
// stays reserved for it: another device's token for it is refused, and the host is removed once, recorded in the
// retired device's organization.
func TestInventoryRoundRetiredHostNotBoundElsewhere(t *testing.T) {
	r := newBindRig(t)
	hwV, hwD := uuid.NewString(), uuid.NewString()
	orgV, v := r.foreignDevice(t, hwV)
	orgD, d := r.foreignDevice(t, hwD)
	r.host(r.id(1), uuid.NewString(), true)
	r.host(r.id(5), hwV, true)
	r.round(t)
	if _, err := r.f.super.Exec(context.Background(), "UPDATE device SET uninstalled_at = now() WHERE id = $1", v); err != nil {
		t.Fatal(err)
	}
	reports := app.NewDeviceReports(app.NewActionRunner(r.f.pool, nil, httpx.RequestID), r.f.pool)
	sys := principal.With(context.Background(), principal.Principal{Kind: principal.KindSystem, Display: "worker", OrganizationID: orgV})
	if retired, err := reports.RetireUninstalled(httpx.WithRequestID(sys, uuid.NewString()), v); err != nil || !retired {
		t.Fatalf("retire: %v %v", retired, err)
	}
	r.relabel(r.id(5), hwD)
	before := testutil.ToFloat64(metricHostBindings.WithLabelValues("host_in_use"))
	for n := range 2 {
		token := uuid.NewString()
		r.binder.hosts[token] = ports.HostSeen{Ref: r.id(5), HardwareUUID: hwD}
		if _, err := r.f.super.Exec(context.Background(), `INSERT INTO device_fleet_binding (device_id, organization_id, pending_token,
			token_reported_at) VALUES ($1, $2, $3, $4) ON CONFLICT (device_id) DO UPDATE SET pending_token = EXCLUDED.pending_token,
			token_reported_at = EXCLUDED.token_reported_at`, d, orgD, token, r.clock); err != nil {
			t.Fatal(err)
		}
		r.advance(5*time.Minute, r.id(5))
		r.round(t)
		if r.boundHost(t, d) != "" || r.externalID(t, d) != "" {
			t.Fatalf("round %d: D bound %q, stores %q", n+1, r.boundHost(t, d), r.externalID(t, d))
		}
	}
	if got := testutil.ToFloat64(metricHostBindings.WithLabelValues("host_in_use")) - before; got != 2 {
		t.Fatalf("host_in_use +%v", got)
	}
	admin := withLeftHostRemoval(r)
	r.round(t)
	r.round(t)
	if !slices.Equal(admin.calls, []ports.HostRef{r.id(5)}) {
		t.Fatalf("calls %v", admin.calls)
	}
	if got := r.removals(t, orgV); !slices.Equal(got, []string{"success retired"}) {
		t.Fatalf("events in V's organization %v", got)
	}
	if got := r.removals(t, orgD); len(got) != 0 {
		t.Fatalf("events in D's organization %v", got)
	}
}

// TestInventoryRoundRetiredDeviceHoldsItsUUID (review round 4, regression): after a retired device's host was removed,
// a new host with its hardware UUID is stored for no other unbound device until retention purged the retired device's
// inventory.
func TestInventoryRoundRetiredDeviceHoldsItsUUID(t *testing.T) {
	r := newBindRig(t)
	admin := withLeftHostRemoval(r)
	ctx := context.Background()
	hw := uuid.NewString()
	orgY, vr := r.foreignDevice(t, hw)
	r.host(r.id(1), uuid.NewString(), true)
	r.host(r.id(82), hw, true)
	for _, sql := range []string{
		"INSERT INTO device_inventory_ref (device_id, organization_id, external_id) VALUES ($1, $2, $3)",
		"INSERT INTO device_fleet_binding (device_id, organization_id, host_id, bound_at) VALUES ($1, $2, $3, now())",
		`INSERT INTO device_inventory_left_host (device_id, organization_id, host_id, reason, left_at)
			VALUES ($1, $2, $3, 'retired', now())`,
	} {
		if _, err := r.f.super.Exec(ctx, sql, vr, orgY, string(r.id(82))); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := r.f.super.Exec(ctx, "UPDATE device SET state = 'retired' WHERE id = $1", vr); err != nil {
		t.Fatal(err)
	}
	r.round(t)
	if !slices.Contains(admin.calls, r.id(82)) {
		t.Fatalf("the retired device's host was not removed: %v", admin.calls)
	}
	dup := r.device(t, hw)
	r.host(r.id(87), hw, false)
	for n := range 3 {
		r.advance(5*time.Minute, r.id(87))
		r.round(t)
		if r.externalID(t, dup) != "" || r.boundHost(t, dup) != "" {
			t.Fatalf("round %d: the device sharing the UUID stores %q", n+1, r.externalID(t, dup))
		}
	}
	if n := r.events(t, claimCode, dup) + r.events(t, agentBinaryCode, dup) + r.events(t, agentNotRunningCode, dup); n != 0 {
		t.Fatalf("%d claim or tamper events", n)
	}
	if _, err := r.f.super.Exec(ctx, "DELETE FROM device_inventory_ref WHERE device_id = $1", vr); err != nil {
		t.Fatal(err)
	}
	r.advance(5*time.Minute, r.id(87))
	r.round(t)
	if got := r.externalID(t, dup); got != r.id(87) {
		t.Fatalf("after retention purged the retired device: stores %q", got)
	}
}
