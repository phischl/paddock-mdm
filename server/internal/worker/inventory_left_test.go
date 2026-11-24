package worker

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/phischl/paddock-mdm/server/internal/inventory"
	"github.com/phischl/paddock-mdm/server/internal/ports"
	"github.com/phischl/paddock-mdm/server/internal/problem"
)

// fakeAdmin deletes hosts from the rig's inventory system: a deleted host is no longer listed and its tokens no longer
// resolve. errs answers the next calls in order.
type fakeAdmin struct {
	r     *bindRig
	errs  []error
	calls []ports.HostRef
}

func (a *fakeAdmin) DeleteHost(_ context.Context, ref ports.HostRef) error {
	a.calls = append(a.calls, ref)
	if len(a.errs) > 0 {
		err := a.errs[0]
		a.errs = a.errs[1:]
		if err != nil {
			return err
		}
	}
	a.r.drop(ref)
	for token, h := range a.r.binder.hosts {
		if h.Ref == ref {
			delete(a.r.binder.hosts, token)
		}
	}
	return nil
}

func (a *fakeAdmin) HostSeenAt(context.Context, ports.HostRef) (time.Time, error) {
	return time.Time{}, nil
}

// withLeftHostRemoval makes the rig remove left hosts through a fake admin.
func withLeftHostRemoval(r *bindRig) *fakeAdmin {
	a := &fakeAdmin{r: r}
	r.inv.WithAdmin(a)
	return a
}

// foreignDevice inserts an active device with the hardware UUID into a new organization.
func (r *bindRig) foreignDevice(t *testing.T, hw string) (uuid.UUID, uuid.UUID) {
	t.Helper()
	ctx := context.Background()
	org, dev := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	if _, err := r.f.super.Exec(ctx, "INSERT INTO organization (id, slug, name, status) VALUES ($1, $2, 'O', 'active')", org,
		"o"+org.String()[24:]); err != nil {
		t.Fatal(err)
	}
	if _, err := r.f.super.Exec(ctx, "INSERT INTO device (id, organization_id, hostname, state, hardware_uuid) VALUES ($1, $2, 'lt-y', 'active', $3)",
		dev, org, hw); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = r.f.super.Exec(ctx, "UPDATE device SET state = 'retired' WHERE id = $1", dev)
		_, _ = r.f.super.Exec(ctx, "UPDATE device_inventory_left_host SET removed_at = now() WHERE organization_id = $1", org)
	})
	return org, dev
}

func (r *bindRig) removals(t *testing.T, org uuid.UUID) []string {
	t.Helper()
	rows, err := r.f.super.Query(context.Background(), `SELECT outcome || ' ' || coalesce(params ->> 'reason', '') FROM action
		WHERE code = 'device.inventory_host_removed' AND organization_id = $1 ORDER BY started_at`, org)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			t.Fatal(err)
		}
		out = append(out, s)
	}
	return out
}

func (r *bindRig) reserve(t *testing.T, org, dev uuid.UUID, host ports.HostRef) {
	t.Helper()
	if _, err := r.f.super.Exec(context.Background(), `INSERT INTO device_inventory_left_host (device_id, organization_id, host_id, reason,
		left_at) VALUES ($1, $2, $3, 'replaced', now() - interval '1 minute')`, dev, org, string(host)); err != nil {
		t.Fatal(err)
	}
}

func (r *bindRig) reserved(t *testing.T, dev uuid.UUID, host ports.HostRef) bool {
	return r.value(t, "SELECT 'y' FROM device_inventory_left_host WHERE device_id = $1 AND host_id = $2 AND removed_at IS NULL",
		dev, string(host)) == "y"
}

// TestInventoryRoundLeftHostNotBoundElsewhere (review round 2, regression): a stored host that the inventory system
// lists with another device's hardware UUID is never bound to or stored for that device; the device that left it
// speaks from its other host, and the left host is removed once, recorded in the device's organization only.
func TestInventoryRoundLeftHostNotBoundElsewhere(t *testing.T) {
	r := newBindRig(t)
	admin := withLeftHostRemoval(r)
	hwV, hwD := uuid.NewString(), uuid.NewString()
	v := r.device(t, hwV)
	orgD, d := r.foreignDevice(t, hwD)
	r.host(r.id(5), hwV, true)
	r.round(t)
	r.host(r.id(6), hwV, true)
	r.relabel(r.id(5), hwD)
	for n := range 3 {
		token := uuid.NewString()
		if !slices.Contains(admin.calls, r.id(5)) {
			r.binder.hosts[token] = ports.HostSeen{Ref: r.id(5), HardwareUUID: hwD}
		}
		if _, err := r.f.super.Exec(context.Background(), `INSERT INTO device_fleet_binding (device_id, organization_id, pending_token,
			token_reported_at) VALUES ($1, $2, $3, $4) ON CONFLICT (device_id) DO UPDATE SET pending_token = EXCLUDED.pending_token,
			token_reported_at = EXCLUDED.token_reported_at`, d, orgD, token, r.clock); err != nil {
			t.Fatal(err)
		}
		r.advance(5*time.Minute, r.id(5), r.id(6))
		r.round(t)
		if r.boundHost(t, d) == r.id(5) || r.externalID(t, d) == r.id(5) {
			t.Fatalf("round %d: D bound to %q, stores %q", n+1, r.boundHost(t, d), r.externalID(t, d))
		}
	}
	if r.externalID(t, v) != r.id(6) || r.events(t, claimCode, v) != 1 || r.claimParam(t, v, "kind") != "reenrolled" {
		t.Fatalf("V stores %s with %d claims (%s)", r.externalID(t, v), r.events(t, claimCode, v), r.claimParam(t, v, "kind"))
	}
	if n := strings.Count(fmt.Sprint(admin.calls), string(r.id(5))); n != 1 {
		t.Fatalf("host 5 deleted %d times: %v", n, admin.calls)
	}
	if got := r.removals(t, r.f.org); !slices.Equal(got, []string{"success relisted"}) {
		t.Fatalf("V's organization: %v", got)
	}
	if got := r.removals(t, orgD); len(got) != 0 {
		t.Fatalf("D's organization: %v", got)
	}
}

// TestInventoryRoundPreviousHostRemovedAfterBind (review round 2): the host a device stored before it was bound is
// removed; a worker started after the store still removes it.
func TestInventoryRoundPreviousHostRemovedAfterBind(t *testing.T) {
	r := newBindRig(t)
	hw := uuid.NewString()
	v := r.device(t, hw)
	r.host(r.id(5), hw, true)
	r.round(t)
	r.host(r.id(9), hw, true)
	r.bindNow(t, v, r.id(9), hw)
	if r.externalID(t, v) != r.id(9) || !r.reserved(t, v, r.id(5)) {
		t.Fatalf("V stores %s; host 5 reserved %v", r.externalID(t, v), r.reserved(t, v, r.id(5)))
	}
	r.inv = r.fresh()
	admin := withLeftHostRemoval(r)
	r.advance(5*time.Minute, r.id(5), r.id(9))
	r.round(t)
	if !slices.Equal(admin.calls, []ports.HostRef{r.id(5)}) || r.reserved(t, v, r.id(5)) {
		t.Fatalf("deleted %v, still reserved %v", admin.calls, r.reserved(t, v, r.id(5)))
	}
	if got := r.removals(t, r.f.org); !slices.Equal(got, []string{"success replaced"}) {
		t.Fatalf("events %v", got)
	}
}

// TestInventoryRoundLeftHostUsedElsewhereNotDeleted (review round 2): a left host that a device of another
// organization stores, is bound to or holds reserved is not deleted; the reservation goes without an event, and nothing
// names the other device or organization.
func TestInventoryRoundLeftHostUsedElsewhereNotDeleted(t *testing.T) {
	for _, use := range []string{"stored", "bound", "reserved"} {
		t.Run(use, func(t *testing.T) {
			logs := captureLogs(t)
			r := newBindRig(t)
			admin := withLeftHostRemoval(r)
			v := r.device(t, uuid.NewString())
			orgY, y := r.foreignDevice(t, uuid.NewString())
			host := r.id(5)
			r.host(r.id(1), uuid.NewString(), true)
			r.reserve(t, r.f.org, v, host)
			ctx := context.Background()
			var err error
			switch use {
			case "stored":
				_, err = r.f.super.Exec(ctx, "INSERT INTO device_inventory_ref (device_id, organization_id, external_id) VALUES ($1, $2, $3)", y, orgY, string(host))
			case "bound":
				_, err = r.f.super.Exec(ctx, "INSERT INTO device_fleet_binding (device_id, organization_id, host_id) VALUES ($1, $2, $3)", y, orgY, string(host))
			case "reserved":
				// Y's own reservation waits for its retry, so that only V's is handled in this round.
				r.reserve(t, orgY, y, host)
				_, err = r.f.super.Exec(ctx, "UPDATE device_inventory_left_host SET attempted_at = now() WHERE device_id = $1", y)
			}
			if err != nil {
				t.Fatal(err)
			}
			before := testutil.ToFloat64(metricPreviousHosts.WithLabelValues("in_use"))
			r.round(t)
			if slices.Contains(admin.calls, host) || r.reserved(t, v, host) {
				t.Fatalf("deleted %v, V's reservation kept %v", admin.calls, r.reserved(t, v, host))
			}
			if got := testutil.ToFloat64(metricPreviousHosts.WithLabelValues("in_use")) - before; got != 1 {
				t.Fatalf("in_use +%v", got)
			}
			if len(r.removals(t, r.f.org))+len(r.removals(t, orgY)) != 0 {
				t.Fatal("an event was recorded")
			}
			reg := prometheus.NewRegistry()
			if err := reg.Register(metricPreviousHosts); err != nil {
				t.Fatal(err)
			}
			families, _ := reg.Gather()
			for _, id := range []string{y.String(), orgY.String()} {
				if strings.Contains(logs.String(), id) || strings.Contains(fmt.Sprint(families), id) {
					t.Fatalf("%s is named in the logs or the metric", id)
				}
			}
		})
	}
}

// TestInventoryRoundLeftHostDeleteRetried (review round 2): an unavailable inventory system keeps the reservation,
// ends the removal step without failing the round and is retried next round; a refused deletion waits an hour.
func TestInventoryRoundLeftHostDeleteRetried(t *testing.T) {
	r := newBindRig(t)
	admin := withLeftHostRemoval(r)
	v := r.device(t, uuid.NewString())
	r.host(r.id(1), uuid.NewString(), true)
	r.reserve(t, r.f.org, v, r.id(5))
	r.reserve(t, r.f.org, v, r.id(6))
	admin.errs = []error{fmt.Errorf("%w: delete fleet host: HTTP 502", problem.UpstreamUnavailable)}
	r.round(t)
	if len(admin.calls) != 1 || !r.reserved(t, v, admin.calls[0]) {
		t.Fatalf("calls %v", admin.calls)
	}
	if got := r.removals(t, r.f.org); !slices.Equal(got, []string{"failure replaced"}) {
		t.Fatalf("events %v", got)
	}
	r.round(t)
	if len(admin.calls) != 3 || r.reserved(t, v, r.id(5)) || r.reserved(t, v, r.id(6)) {
		t.Fatalf("second round: calls %v", admin.calls)
	}

	w := r.device(t, uuid.NewString())
	r.reserve(t, r.f.org, w, r.id(7))
	admin.errs = []error{fmt.Errorf("%w: delete fleet host: refused", problem.InvalidState)}
	r.round(t)
	r.advance(5 * time.Minute)
	r.round(t)
	if strings.Count(fmt.Sprint(admin.calls), string(r.id(7))) != 1 || !r.reserved(t, w, r.id(7)) {
		t.Fatalf("refused host retried within the hour: %v", admin.calls)
	}
	r.advance(inventory.LeftHostRetryAfter)
	r.round(t)
	if strings.Count(fmt.Sprint(admin.calls), string(r.id(7))) != 2 || r.reserved(t, w, r.id(7)) {
		t.Fatalf("refused host not retried after the hour: %v", admin.calls)
	}
}

// TestInventoryRoundLeftHostReservedUntilRemoved (review round 2): while a left host is reserved, no other device is
// bound to it or stores it.
func TestInventoryRoundLeftHostReservedUntilRemoved(t *testing.T) {
	r := newBindRig(t)
	hwV, hwD, hwU := uuid.NewString(), uuid.NewString(), uuid.NewString()
	v := r.device(t, hwV)
	r.host(r.id(5), hwV, true)
	r.round(t)
	r.host(r.id(9), hwV, true)
	r.bindNow(t, v, r.id(9), hwV)
	d, u := r.device(t, hwD), r.device(t, hwU)
	r.relabel(r.id(5), hwD)
	before := testutil.ToFloat64(metricHostBindings.WithLabelValues("host_in_use"))
	for n := range 2 {
		token := uuid.NewString()
		r.binder.hosts[token] = ports.HostSeen{Ref: r.id(5), HardwareUUID: hwD}
		r.report(t, d, token, r.clock)
		r.advance(5*time.Minute, r.id(5), r.id(9))
		r.round(t)
		if r.boundHost(t, d) != "" || r.externalID(t, d) != "" {
			t.Fatalf("round %d: D bound %q, stores %q", n+1, r.boundHost(t, d), r.externalID(t, d))
		}
	}
	if got := testutil.ToFloat64(metricHostBindings.WithLabelValues("host_in_use")) - before; got != 2 {
		t.Fatalf("host_in_use +%v", got)
	}
	r.relabel(r.id(5), hwU)
	r.advance(5*time.Minute, r.id(5), r.id(9))
	r.round(t)
	if got := r.externalID(t, u); got != "" {
		t.Fatalf("U stores %s", got)
	}
}

// TestInventoryRoundLeftHostCap (review round 2): at most LeftHostDeletesPerRound left hosts are handled per round.
func TestInventoryRoundLeftHostCap(t *testing.T) {
	r := newBindRig(t)
	if _, err := r.f.super.Exec(context.Background(), "UPDATE device_inventory_left_host SET removed_at = now() WHERE removed_at IS NULL"); err != nil {
		t.Fatal(err)
	}
	admin := withLeftHostRemoval(r)
	v := r.device(t, uuid.NewString())
	r.host(r.id(1), uuid.NewString(), true)
	for n := range 60 {
		r.reserve(t, r.f.org, v, r.id(int64(100+n)))
	}
	r.round(t)
	if len(admin.calls) != inventory.LeftHostDeletesPerRound {
		t.Fatalf("first round: %d deletions", len(admin.calls))
	}
	r.round(t)
	if len(admin.calls) != 60 {
		t.Fatalf("second round: %d deletions", len(admin.calls))
	}
}

// TestInventoryRoundUnboundHostIDsSwapped (review round 2): unbound devices whose stored host IDs the inventory system
// swapped get both hosts removed and store their machines' new hosts within three rounds, without a second_host claim.
func TestInventoryRoundUnboundHostIDsSwapped(t *testing.T) {
	r := newBindRig(t)
	admin := withLeftHostRemoval(r)
	hwV, hwW := uuid.NewString(), uuid.NewString()
	v, w := r.device(t, hwV), r.device(t, hwW)
	r.host(r.id(5), hwV, true)
	r.host(r.id(6), hwW, true)
	r.round(t)
	r.relabel(r.id(5), hwW)
	r.relabel(r.id(6), hwV)
	r.advance(5*time.Minute, r.id(5), r.id(6))
	r.round(t)
	if !slices.Contains(admin.calls, r.id(5)) || !slices.Contains(admin.calls, r.id(6)) {
		t.Fatalf("deleted %v", admin.calls)
	}
	r.host(r.id(7), hwV, true)
	r.host(r.id(8), hwW, true)
	for range 3 {
		r.advance(5*time.Minute, r.id(7), r.id(8))
		r.round(t)
	}
	if r.externalID(t, v) != r.id(7) || r.externalID(t, w) != r.id(8) {
		t.Fatalf("V stores %s, W stores %s", r.externalID(t, v), r.externalID(t, w))
	}
	for _, dev := range []uuid.UUID{v, w} {
		if r.value(t, "SELECT count(*)::text FROM action WHERE code = $1 AND target ->> 'id' = $2 AND params ->> 'kind' = 'second_host'",
			claimCode, dev.String()) != "0" {
			t.Fatalf("%s: second_host claim", dev)
		}
	}
}
