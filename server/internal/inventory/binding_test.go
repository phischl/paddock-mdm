package inventory_test

import (
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/inventory"
	"github.com/phischl/paddock-mdm/server/internal/ports"
)

const devUUID = "4c4c4544-0000-1000-8000-000000000001"

func TestHostTargets(t *testing.T) {
	other := "4c4c4544-0000-1000-8000-000000000002"
	seen := []ports.HostSeen{{Ref: "7", HardwareUUID: devUUID}, {Ref: "9", HardwareUUID: devUUID},
		{Ref: "11", HardwareUUID: strings.ToUpper(other)}}

	got := inventory.HostTargets(seen, nil, nil, nil)
	if len(got.Listed[devUUID]) != 2 || len(got.Listed[other]) != 1 || len(got.Bound) != 0 || len(got.InUse) != 0 {
		t.Fatalf("no bindings: %+v", got)
	}

	a := inventory.Binding{DeviceID: uuid.New(), HardwareUUID: devUUID, Host: "9"}
	stored := inventory.ClaimDevice{DeviceID: uuid.New(), HardwareUUID: other, ExternalID: "11"}
	got = inventory.HostTargets(seen, []inventory.Binding{a}, []inventory.ClaimDevice{stored}, nil)
	if got.Bound["9"].DeviceID != a.DeviceID || !got.BindingUUIDs[devUUID] || got.InUse["9"] != a.DeviceID ||
		got.InUse["11"] != stored.DeviceID {
		t.Fatalf("bound to 9: %+v", got)
	}

	b := inventory.Binding{DeviceID: uuid.New(), HardwareUUID: devUUID, Host: "9"}
	got = inventory.HostTargets(seen, []inventory.Binding{a, b}, nil, nil)
	if _, ok := got.Bound["9"]; ok || len(got.Excluded["9"]) != 2 {
		t.Fatalf("bound twice: %+v", got)
	}

	foreign := inventory.Binding{DeviceID: uuid.New(), HardwareUUID: "4c4c4544-0000-1000-8000-0000000000ff", Host: "11"}
	got = inventory.HostTargets(seen, []inventory.Binding{foreign}, nil, nil)
	if _, ok := got.Bound["11"]; ok || got.InUse["11"] != uuid.Nil {
		t.Fatalf("a bound host listed with another UUID is not the device's: %+v", got)
	}

	unlisted := inventory.Binding{DeviceID: uuid.New(), HardwareUUID: devUUID, Host: "77"}
	got = inventory.HostTargets(seen, []inventory.Binding{unlisted}, nil, nil)
	if _, ok := got.Bound["77"]; ok || got.InUse["77"] != unlisted.DeviceID {
		t.Fatalf("an unlisted bound host stays in use: %+v", got)
	}
}

// TestFirstSpeaker (review round 1, F2): the stored host keeps speaking while it is listed with the UUID and free;
// otherwise the free listed host with the lowest ID speaks.
func TestFirstSpeaker(t *testing.T) {
	dev, other := uuid.New(), uuid.New()
	seen := []ports.HostSeen{{Ref: "20", HardwareUUID: devUUID}, {Ref: "10", HardwareUUID: devUUID}, {Ref: "9", HardwareUUID: devUUID}}
	bound := []inventory.Binding{{DeviceID: other, HardwareUUID: devUUID, Host: "9"}}
	tg := inventory.HostTargets(seen, bound, []inventory.ClaimDevice{{DeviceID: dev, HardwareUUID: devUUID, ExternalID: "20"}}, nil)
	if got := inventory.FirstSpeaker(dev, devUUID, "20", tg); got != "20" {
		t.Fatalf("stored host: %q", got)
	}
	if got := inventory.FirstSpeaker(dev, devUUID, "", tg); got != "10" {
		t.Fatalf("lowest free host: %q", got)
	}
	if got := inventory.FirstSpeaker(dev, devUUID, "30", tg); got != "10" {
		t.Fatalf("stored host gone: %q", got)
	}
	tg = inventory.HostTargets(seen, bound, []inventory.ClaimDevice{{DeviceID: other, HardwareUUID: devUUID, ExternalID: "20"}}, nil)
	if got := inventory.FirstSpeaker(dev, devUUID, "20", tg); got != "10" {
		t.Fatalf("stored host in use by another device: %q", got)
	}
}

// TestDecideBindingCurrentNeedsHardwareUUID (review round 1, F1, regression): a live bound host listed with another
// hardware UUID is no reason to skip the resolution.
func TestDecideBindingCurrentNeedsHardwareUUID(t *testing.T) {
	now := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	reported := now.Add(-time.Minute)
	b := inventory.Binding{DeviceID: uuid.New(), HardwareUUID: devUUID, Host: "9", PendingToken: "t", TokenReportedAt: &reported}
	seen := map[ports.HostRef]ports.HostSeen{"9": {Ref: "9", HardwareUUID: "4c4c4544-0000-1000-8000-0000000000ff", SeenAt: now}}
	if got := inventory.DecideBinding(b, seen, now, now, nil, uuid.Nil); got != inventory.DecideResolve {
		t.Fatalf("got %d, want DecideResolve", got)
	}
}

func TestDecideBinding(t *testing.T) {
	now := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	r := now.Add(-time.Minute)
	at := func(d time.Duration) *time.Time { v := now.Add(-d); return &v }
	seen := map[ports.HostRef]ports.HostSeen{
		"9":  {Ref: "9", HardwareUUID: devUUID, SeenAt: r.Add(-inventory.BindingStale + time.Second)},
		"10": {Ref: "10", HardwareUUID: devUUID, SeenAt: r.Add(-inventory.BindingStale)},
		"12": {Ref: "12", HardwareUUID: devUUID},
	}
	bound := func(host ports.HostRef, age time.Duration) inventory.Binding {
		return inventory.Binding{HardwareUUID: devUUID, Host: host, PendingToken: "t", TokenReportedAt: at(age)}
	}
	for _, tc := range []struct {
		name     string
		b        inventory.Binding
		resolved *ports.HostSeen
		want     inventory.Decision
		owner    uuid.UUID
	}{
		{"expired at TokenMaxAge", bound("", inventory.TokenMaxAge), nil, inventory.DecideExpired, uuid.Nil},
		{"resolve just before TokenMaxAge", bound("", inventory.TokenMaxAge-time.Second), nil, inventory.DecideResolve, uuid.Nil},
		{"no report time", inventory.Binding{HardwareUUID: devUUID, PendingToken: "t"}, nil, inventory.DecideExpired, uuid.Nil},
		{"bound host talks", bound("9", time.Minute), nil, inventory.DecideCurrent, uuid.Nil},
		{"bound host silent for BindingStale", bound("10", time.Minute), nil, inventory.DecideResolve, uuid.Nil},
		{"bound host without seen time", bound("12", time.Minute), nil, inventory.DecideResolve, uuid.Nil},
		{"bound host not listed", bound("13", time.Minute), nil, inventory.DecideResolve, uuid.Nil},
		{"uuid mismatch", bound("", time.Minute), &ports.HostSeen{Ref: "9", HardwareUUID: "4c4c4544-0000-1000-8000-0000000000ff"}, inventory.DecideUUIDMismatch, uuid.Nil},
		{"device without uuid", inventory.Binding{PendingToken: "t", TokenReportedAt: at(time.Minute)}, &ports.HostSeen{Ref: "9"}, inventory.DecideUUIDMismatch, uuid.Nil},
		{"upper-case uuid of the host", bound("", time.Minute), &ports.HostSeen{Ref: "9", HardwareUUID: "4C4C4544-0000-1000-8000-000000000001"}, inventory.DecideBind, uuid.Nil},
		{"the bound host", bound("9", time.Minute), &ports.HostSeen{Ref: "9", HardwareUUID: devUUID}, inventory.DecideCurrent, uuid.Nil},
		{"bind", bound("", time.Minute), &ports.HostSeen{Ref: "9", HardwareUUID: devUUID}, inventory.DecideBind, uuid.Nil},
		{"rebind", bound("9", time.Minute), &ports.HostSeen{Ref: "14", HardwareUUID: devUUID}, inventory.DecideRebind, uuid.Nil},
		{"host in use by another device", bound("", time.Minute), &ports.HostSeen{Ref: "14", HardwareUUID: devUUID}, inventory.DecideHostInUse, uuid.New()},
		{"uuid mismatch before host in use", bound("", time.Minute), &ports.HostSeen{Ref: "14"}, inventory.DecideUUIDMismatch, uuid.New()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := inventory.DecideBinding(tc.b, seen, r, now, tc.resolved, tc.owner); got != tc.want {
				t.Fatalf("got %d, want %d", got, tc.want)
			}
		})
	}
}

// TestHostTargetsLeftHosts (review round 2): a stored host listed with another hardware UUID stays in use by its device
// and is left, unless it is the device's bound host; a reservation keeps its host in use unless a binding or a stored
// host sets it.
func TestHostTargetsLeftHosts(t *testing.T) {
	other := "4c4c4544-0000-1000-8000-0000000000ff"
	seen := []ports.HostSeen{{Ref: "5", HardwareUUID: other}, {Ref: "6", HardwareUUID: other}, {Ref: "7", HardwareUUID: devUUID}}
	unbound := inventory.ClaimDevice{DeviceID: uuid.New(), HardwareUUID: devUUID, ExternalID: "5"}
	got := inventory.HostTargets(seen, nil, []inventory.ClaimDevice{unbound}, nil)
	if got.InUse["5"] != unbound.DeviceID || len(got.Left) != 1 || got.Left[0].Host != "5" || got.Left[0].Reason != inventory.LeftRelisted {
		t.Fatalf("unbound: %+v", got)
	}

	bound := inventory.ClaimDevice{DeviceID: uuid.New(), HardwareUUID: devUUID, ExternalID: "5"}
	binding := inventory.Binding{DeviceID: bound.DeviceID, HardwareUUID: devUUID, Host: "5"}
	got = inventory.HostTargets(seen, []inventory.Binding{binding}, []inventory.ClaimDevice{bound}, nil)
	if _, ok := got.InUse["5"]; ok || len(got.Left) != 0 {
		t.Fatalf("relisted bound host: %+v", got)
	}

	binding.Host = "7"
	got = inventory.HostTargets(seen, []inventory.Binding{binding}, []inventory.ClaimDevice{bound}, nil)
	if got.InUse["5"] != bound.DeviceID || len(got.Left) != 1 {
		t.Fatalf("stored host other than the bound host: %+v", got)
	}

	reserver, storer := uuid.New(), inventory.ClaimDevice{DeviceID: uuid.New(), HardwareUUID: other, ExternalID: "6"}
	left := []inventory.LeftHost{{DeviceID: reserver, Host: "6"}, {DeviceID: reserver, Host: "8"}}
	got = inventory.HostTargets(seen, nil, []inventory.ClaimDevice{storer}, left)
	if got.InUse["6"] != storer.DeviceID || got.InUse["8"] != reserver {
		t.Fatalf("reservations: %+v", got.InUse)
	}
}
