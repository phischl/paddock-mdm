package inventory_test

import (
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/inventory"
	"github.com/phischl/paddock-mdm/server/internal/ports"
)

var claimNow = time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)

func ago(d time.Duration) *time.Time { v := claimNow.Add(-d); return &v }

// claimRound runs WatchClaims for one device whose hosts are listed in the given order; the first host is seen now,
// so it sets the reference time.
func claimRound(d inventory.ClaimDevice, hosts ...ports.HostSeen) inventory.ClaimWatch {
	var bindings []inventory.Binding
	if d.BoundHost != "" {
		bindings = append(bindings, inventory.Binding{DeviceID: d.DeviceID, HardwareUUID: d.HardwareUUID, Host: d.BoundHost})
	}
	devices := []inventory.ClaimDevice{d}
	return inventory.WatchClaims(devices, hosts, inventory.HostTargets(hosts, bindings, devices, nil), claimNow)
}

func host(ref ports.HostRef, seenAgo time.Duration) ports.HostSeen {
	return ports.HostSeen{Ref: ref, HardwareUUID: devUUID, SeenAt: claimNow.Add(-seenAgo), EnrolledAt: ago(48 * time.Hour)}
}

func claimDevice() inventory.ClaimDevice {
	return inventory.ClaimDevice{DeviceID: uuid.New(), OrganizationID: uuid.New(), HardwareUUID: devUUID, ExternalID: "9",
		BoundHost: "9", EnrolledAt: ago(48 * time.Hour), Active: true}
}

func TestWatchClaims(t *testing.T) {
	t.Run("second host starts an episode, then is due after HostClaimConfirm", func(t *testing.T) {
		d := claimDevice()
		w := claimRound(d, host("7", time.Minute), host("9", 0))
		if !slices.Equal(w.ClaimStart, []uuid.UUID{d.DeviceID}) || len(w.Claims) != 0 {
			t.Fatalf("first round: %+v", w)
		}
		d.ClaimSince = ago(inventory.HostClaimConfirm - time.Second)
		if w := claimRound(d, host("7", time.Minute), host("9", 0)); len(w.Claims) != 0 || len(w.ClaimStart) != 0 {
			t.Fatalf("before the confirmation: %+v", w)
		}
		d.ClaimSince = ago(inventory.HostClaimConfirm)
		w = claimRound(d, host("7", time.Minute), host("9", 0), host("12", time.Hour))
		if len(w.Claims) != 1 {
			t.Fatalf("after the confirmation: %+v", w)
		}
		c := w.Claims[0]
		if c.Kind != inventory.ClaimSecondHost || c.Binding != inventory.BindingDevice || c.Bound != "9" ||
			!slices.Equal(c.Others, []ports.HostRef{"7"}) || c.Hosts != 2 {
			t.Fatalf("claim: %+v", c)
		}
	})
	t.Run("live window", func(t *testing.T) {
		d := claimDevice()
		if w := claimRound(d, host("9", 0), host("7", inventory.HostClaimLive)); len(w.ClaimStart) != 0 {
			t.Fatalf("seen HostClaimLive ago is not live: %+v", w)
		}
		if w := claimRound(d, host("9", 0), host("7", inventory.HostClaimLive-time.Second)); len(w.ClaimStart) != 1 {
			t.Fatalf("seen just inside the window is live: %+v", w)
		}
		if w := claimRound(d, host("9", 0), ports.HostSeen{Ref: "7", HardwareUUID: devUUID}); len(w.ClaimStart) != 0 {
			t.Fatalf("never seen is not live: %+v", w)
		}
	})
	t.Run("a host that stopped before the episode never becomes due", func(t *testing.T) {
		d := claimDevice()
		d.BoundHost, d.ExternalID = "12", "12"
		for _, at := range []time.Duration{0, 5 * time.Minute, 20 * time.Minute} {
			w := claimRound(d, host("9", inventory.HostClaimLive+at), host("12", 0))
			if len(w.ClaimStart) != 0 || len(w.Claims) != 0 {
				t.Fatalf("previous host: %+v", w)
			}
		}
	})
	t.Run("re-enrolled speaking host is due at once", func(t *testing.T) {
		d := claimDevice()
		h := host("9", 0)
		h.EnrolledAt = ago(time.Minute)
		w := claimRound(d, h)
		if !slices.Equal(w.Reenrolled, []uuid.UUID{d.DeviceID}) || len(w.ClaimStart) != 1 || len(w.Claims) != 1 ||
			w.Claims[0].Kind != inventory.ClaimReenrolled || !w.Enrolled[d.DeviceID].Equal(*h.EnrolledAt) {
			t.Fatalf("re-enrolled: %+v", w)
		}
		d.ExternalID = "7"
		if w := claimRound(d, h); len(w.Reenrolled) != 0 || len(w.Claims) != 0 {
			t.Fatalf("another stored host is a rebinding: %+v", w)
		}
		d.ExternalID, d.EnrolledAt = "9", nil
		w = claimRound(d, h)
		if len(w.Reenrolled) != 0 || len(w.Claims) != 0 || !w.Enrolled[d.DeviceID].Equal(*h.EnrolledAt) {
			t.Fatalf("first observation only records: %+v", w)
		}
	})
	t.Run("episode ends after ClaimQuiet", func(t *testing.T) {
		d := claimDevice()
		d.ClaimSince, d.ClaimReportedAt, d.ReenrolledAt = ago(2*time.Hour), ago(2*time.Hour), ago(inventory.ClaimQuiet+time.Minute)
		if w := claimRound(d, host("9", 0)); !slices.Equal(w.ClaimClear, []uuid.UUID{d.DeviceID}) {
			t.Fatalf("61 min: %+v", w)
		}
		d.ReenrolledAt = ago(inventory.ClaimQuiet - time.Minute)
		if w := claimRound(d, host("9", 0)); len(w.ClaimClear) != 0 || len(w.Claims) != 0 || w.Guard[inventory.BindingDevice].Claimed != 1 {
			t.Fatalf("59 min: %+v", w)
		}
	})
	t.Run("binding modes", func(t *testing.T) {
		d := claimDevice()
		d.ClaimSince = ago(time.Hour)
		w := claimRound(d, host("7", 0), host("9", 0))
		if len(w.Claims) != 1 || w.Claims[0].Bound != "9" || w.Claims[0].Binding != inventory.BindingDevice {
			t.Fatalf("device: %+v", w)
		}
		d.BoundHost, d.ExternalID = "", "7"
		w = claimRound(d, host("7", 0), host("9", 0))
		if len(w.Claims) != 1 || w.Claims[0].Bound != "7" || w.Claims[0].Binding != inventory.BindingFirst ||
			!slices.Equal(w.Claims[0].Others, []ports.HostRef{"9"}) {
			t.Fatalf("first: %+v", w)
		}
	})
	t.Run("already reported", func(t *testing.T) {
		d := claimDevice()
		d.ClaimSince, d.ClaimReportedAt = ago(time.Hour), ago(time.Minute)
		if w := claimRound(d, host("7", 0), host("9", 0)); len(w.Claims) != 0 || len(w.ClaimClear) != 0 {
			t.Fatalf("%+v", w)
		}
	})
	t.Run("other hosts are sorted numerically", func(t *testing.T) {
		d := claimDevice()
		d.ClaimSince = ago(time.Hour)
		w := claimRound(d, host("9", 0), host("100", 0), host("20", 0))
		if !slices.Equal(w.Claims[0].Others, []ports.HostRef{"20", "100"}) || w.Claims[0].Hosts != 3 {
			t.Fatalf("%+v", w.Claims[0])
		}
	})
}

// guardRound is one round over watched devices, each with its own UUID and listed speaking host: the first reenrolled
// devices of each mode were enrolled again, the first second of them have a live other host.
func guardRound(bound, first, reenrolledBound, reenrolledFirst, second int) inventory.ClaimWatch {
	var devices []inventory.ClaimDevice
	var seen []ports.HostSeen
	var bindings []inventory.Binding
	for n := range bound + first {
		d := claimDevice()
		d.HardwareUUID = uuid.NewString()
		d.ExternalID = ports.HostRef(fmt.Sprint(100 + n))
		d.BoundHost = d.ExternalID
		if n >= bound {
			d.BoundHost = ""
		} else {
			bindings = append(bindings, inventory.Binding{DeviceID: d.DeviceID, HardwareUUID: d.HardwareUUID, Host: d.ExternalID})
		}
		h := ports.HostSeen{Ref: d.ExternalID, HardwareUUID: d.HardwareUUID, SeenAt: claimNow, EnrolledAt: d.EnrolledAt}
		if n < reenrolledBound || n >= bound && n < bound+reenrolledFirst {
			h.EnrolledAt = ago(time.Minute)
		}
		if n < second {
			d.ClaimSince = ago(inventory.HostClaimConfirm)
			seen = append(seen, ports.HostSeen{Ref: ports.HostRef(fmt.Sprint(900 + n)), HardwareUUID: d.HardwareUUID, SeenAt: claimNow})
		}
		devices, seen = append(devices, d), append(seen, h)
	}
	return inventory.WatchClaims(devices, seen, inventory.HostTargets(seen, bindings, devices, nil), claimNow)
}

func kinds(w inventory.ClaimWatch, kind, binding string) int {
	n := 0
	for _, c := range w.Claims {
		if c.Kind == kind && c.Binding == binding {
			n++
		}
	}
	return n
}

// TestWatchClaimsGuardCountsReenrollmentsPerMode (review round 1, F4, regression): second hosts are never held; the
// guard holds the re-enrollments of a binding mode only when most of that mode's devices re-enrolled.
func TestWatchClaimsGuardCountsReenrollmentsPerMode(t *testing.T) {
	if w := guardRound(6, 0, 0, 0, 4); kinds(w, inventory.ClaimSecondHost, inventory.BindingDevice) != 4 {
		t.Fatalf("4 of 6 with second hosts: %+v", w.Claims)
	}
	w := guardRound(6, 0, 4, 0, 0)
	if !w.Guard[inventory.BindingDevice].Suppressed || w.Guard[inventory.BindingDevice].Held != 4 || len(w.Claims) != 0 ||
		len(w.Reenrolled) != 4 {
		t.Fatalf("4 of 6 bound re-enrolled: %+v %+v", w.Guard[inventory.BindingDevice], w.Claims)
	}
	w = guardRound(4, 5, 1, 4, 0)
	if !w.Guard[inventory.BindingFirst].Suppressed || w.Guard[inventory.BindingDevice].Suppressed ||
		kinds(w, inventory.ClaimReenrolled, inventory.BindingDevice) != 1 || kinds(w, inventory.ClaimReenrolled, inventory.BindingFirst) != 0 {
		t.Fatalf("4 of 5 first and 1 of 4 bound: %+v %+v", w.Guard, w.Claims)
	}
	if w := guardRound(3, 0, 2, 0, 0); w.Guard[inventory.BindingDevice].Suppressed || len(w.Claims) != 2 {
		t.Fatalf("2 of 3: %+v", w.Claims)
	}
	if w := guardRound(6, 0, 3, 0, 0); w.Guard[inventory.BindingDevice].Suppressed || len(w.Claims) != 3 {
		t.Fatalf("3 of 6: %+v", w.Claims)
	}
}

func TestWatchClaimsAnnouncedReset(t *testing.T) {
	first := func() inventory.ClaimDevice {
		d := claimDevice()
		d.BoundHost, d.ExternalID = "", "9"
		return d
	}
	hosts := []ports.HostSeen{host("9", 0), host("12", 0)}

	d := first()
	d.ResetAnnouncedAt = ago(20 * time.Minute)
	w := claimRound(d, hosts...)
	if len(w.ClaimStart) != 0 || len(w.Claims) != 0 || len(w.Resetting) != 1 {
		t.Fatalf("announced 20 min ago: %+v", w)
	}
	d.ClaimSince = ago(inventory.HostClaimConfirm)
	if w := claimRound(d, hosts...); len(w.Claims) != 0 {
		t.Fatalf("a running episode is not due while resetting: %+v", w)
	}

	d = first()
	d.ClaimSince = ago(inventory.HostClaimConfirm)
	if w := claimRound(d, hosts...); len(w.Claims) != 1 || w.Claims[0].Kind != inventory.ClaimSecondHost {
		t.Fatalf("without an announcement: %+v", w)
	}

	d.ResetAnnouncedAt = ago(inventory.ClaimQuiet + time.Minute)
	if w := claimRound(d, hosts...); len(w.Claims) != 1 {
		t.Fatalf("announced 61 min ago: %+v", w)
	}

	d.ResetAnnouncedAt, d.BoundAt = ago(20*time.Minute), ago(10*time.Minute)
	if w := claimRound(d, hosts...); len(w.Claims) != 1 {
		t.Fatalf("bound after the announcement: %+v", w)
	}

	d = first()
	d.ResetAnnouncedAt = ago(20 * time.Minute)
	reenrolled := host("9", 0)
	reenrolled.EnrolledAt = ago(time.Minute)
	if w := claimRound(d, reenrolled, host("12", 0)); len(w.Claims) != 1 || w.Claims[0].Kind != inventory.ClaimReenrolled {
		t.Fatalf("a reset never hides a re-enrollment: %+v", w)
	}
}

func TestClaimWatchForOrganization(t *testing.T) {
	a, b := claimDevice(), claimDevice()
	w := inventory.ClaimWatch{Enrolled: map[uuid.UUID]*time.Time{a.DeviceID: ago(0), b.DeviceID: ago(0)},
		ClaimStart: []uuid.UUID{a.DeviceID, b.DeviceID}, Claims: []inventory.ClaimedDevice{{ClaimDevice: b}}}
	got := w.ForOrganization(a.OrganizationID, []inventory.ClaimDevice{a, b})
	if len(got.Enrolled) != 1 || !slices.Equal(got.ClaimStart, []uuid.UUID{a.DeviceID}) || len(got.Claims) != 0 {
		t.Fatalf("%+v", got)
	}
}

// TestWatchClaimsSuspendedAndReplacedSpeaker (review round 1, F1 and F2): other hosts of a device with a suspended
// binding do not count for ClaimQuiet; another host taking the place of a stored host that no device named is a
// re-enrollment.
func TestWatchClaimsSuspendedAndReplacedSpeaker(t *testing.T) {
	d := claimDevice()
	d.ClaimSince, d.SuspendedAt = ago(inventory.HostClaimConfirm), ago(20*time.Minute)
	if w := claimRound(d, host("7", 0)); len(w.Claims) != 0 || len(w.Suspended) != 0 {
		t.Fatalf("suspended 20 min: %+v", w)
	}
	d.SuspendedAt = ago(inventory.ClaimQuiet + time.Minute)
	if w := claimRound(d, host("7", 0)); len(w.Claims) != 1 || len(w.Suspended) != 1 {
		t.Fatalf("suspended 61 min: %+v", w)
	}

	f := claimDevice()
	f.BoundHost, f.ExternalID = "", "20"
	w := claimRound(f, host("10", 0))
	if len(w.Claims) != 1 || w.Claims[0].Kind != inventory.ClaimReenrolled || w.Claims[0].Bound != "10" || len(w.Reenrolled) != 1 {
		t.Fatalf("stored host replaced: %+v", w)
	}
	if w := claimRound(f, host("20", 0), host("10", 0)); len(w.Reenrolled) != 0 {
		t.Fatalf("the stored host still speaks: %+v", w)
	}
}
