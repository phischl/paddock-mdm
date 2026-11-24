package inventory

import (
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/ports"
)

// Bounds of the binding of inventory hosts to devices (ADR 0057; plan M5a amendment 2026-11-17 e, H5).
const (
	// TokenMaxAge is how long a reported device token is kept undecided; the inventory system honours it for an hour.
	TokenMaxAge = 50 * time.Minute
	// BindingStale is how long a bound host may be silent before a reported token is resolved again.
	BindingStale = 15 * time.Minute
	// ResolvePerRound bounds the inventory system's device token requests per round.
	ResolvePerRound = 200
)

// Binding is a device's row of paddock_inventory_bindings.
type Binding struct {
	DeviceID, OrganizationID uuid.UUID
	// HardwareUUID is the device's hardware UUID in lower case.
	HardwareUUID string
	// Host is the bound host; "" when the device is not bound.
	Host            ports.HostRef
	PendingToken    string
	TokenReportedAt *time.Time
	// ResetAnnouncedAt, BoundAt and SuspendedAt order the decisions (review round 1, L2) and drive the suspension (F1).
	ResetAnnouncedAt, BoundAt, SuspendedAt *time.Time
}

// Valid reports whether the device's bound host is listed with the device's hardware UUID (review round 1, F1).
func (b Binding) Valid(seen map[ports.HostRef]ports.HostSeen) bool {
	h, ok := seen[b.Host]
	return b.Host != "" && ok && strings.ToLower(h.HardwareUUID) == b.HardwareUUID
}

// Urgent reports whether the device announced an enrollment reset not followed by a binding, or its binding is
// suspended: its token is decided before the others (review round 1, L2).
func (b Binding) Urgent(now time.Time) bool {
	resetting := b.ResetAnnouncedAt != nil && now.Sub(*b.ResetAnnouncedAt) < ClaimQuiet &&
		(b.BoundAt == nil || b.BoundAt.Before(*b.ResetAnnouncedAt))
	return resetting || b.SuspendedAt != nil
}

// Decision is the outcome of rules 1, 2, 6, 7, 8 and 9 of H5 for one binding.
type Decision int

// Decisions of DecideBinding.
const (
	DecideResolve Decision = iota // resolve the token through the inventory system (rules 3 to 5 are the worker's)
	DecideExpired
	DecideCurrent
	DecideUUIDMismatch
	DecideBind
	DecideRebind
	DecideHostInUse
)

// DecideBinding returns the decision for a binding with a pending token before the inventory system was asked
// (resolved nil: rules 1 and 2, else DecideResolve) or after it answered (resolved: the host and its hardware UUID;
// rules 6 to 9 with 6b). seen indexes the round's listed hosts; r is the newest seen time among them; owner is the
// device the resolved host is in use by (uuid.Nil when none). It is pure.
func DecideBinding(b Binding, seen map[ports.HostRef]ports.HostSeen, r, now time.Time, resolved *ports.HostSeen,
	owner uuid.UUID) Decision {
	if resolved == nil {
		if b.TokenReportedAt == nil || now.Sub(*b.TokenReportedAt) >= TokenMaxAge {
			return DecideExpired
		}
		if h := seen[b.Host]; b.Valid(seen) && !h.SeenAt.IsZero() && r.Sub(h.SeenAt) < BindingStale {
			return DecideCurrent
		}
		return DecideResolve
	}
	switch {
	case b.HardwareUUID == "" || strings.ToLower(resolved.HardwareUUID) != b.HardwareUUID:
		return DecideUUIDMismatch
	case owner != uuid.Nil && owner != b.DeviceID:
		return DecideHostInUse
	case resolved.Ref == b.Host:
		return DecideCurrent
	case b.Host == "":
		return DecideBind
	}
	return DecideRebind
}

// Targets says which listed hosts may be stored (H6, review round 1).
type Targets struct {
	// Bound maps a valid bound host of exactly one device to that device's binding.
	Bound map[ports.HostRef]Binding
	// Excluded maps a host bound to two or more devices to those devices.
	Excluded map[ports.HostRef][]uuid.UUID
	// InUse maps a host to the active or quarantined device it is bound to or stored for, unless the host is listed with
	// another hardware UUID than that device's (review round 1, N1).
	InUse map[ports.HostRef]uuid.UUID
	// BindingUUIDs holds the lower-case hardware UUIDs of the devices with a binding row.
	BindingUUIDs map[string]bool
	// Listed holds the listed hosts per lower-case hardware UUID, in list order.
	Listed map[string][]ports.HostSeen
	// Left holds the stored hosts listed with another hardware UUID than their device's that are not that device's
	// bound host, in device order; the worker records them as left hosts (reason LeftRelisted).
	Left []LeftHost
}

// Reasons a host became a left host (plan M5a amendment e, review round 2).
const (
	LeftReplaced = "replaced"
	LeftRelisted = "relisted"
	LeftRetired  = "retired"
)

const (
	// LeftHostDeletesPerRound bounds the left hosts the worker removes from the inventory system per round.
	LeftHostDeletesPerRound = 50
	// LeftHostRetryAfter is how long a left host the inventory system refused to delete waits for the next attempt.
	LeftHostRetryAfter = time.Hour
)

// LeftHost is a host a device no longer speaks from, reserved for it until the inventory system deleted it.
type LeftHost struct {
	DeviceID, OrganizationID uuid.UUID
	Host                     ports.HostRef
	Reason                   string
	Hostname                 string
	LeftAt                   time.Time
	AttemptedAt              *time.Time
	// OrgActive is set when the organization is active; only then does the removal step handle the reservation.
	OrgActive bool
}

// HostTargets computes Targets from the listed hosts in list order, the bindings, the devices with a stored host and the
// reserved left hosts. It is pure.
func HostTargets(seen []ports.HostSeen, bindings []Binding, devices []ClaimDevice, left []LeftHost) Targets {
	t := Targets{Bound: map[ports.HostRef]Binding{}, Excluded: map[ports.HostRef][]uuid.UUID{},
		InUse: map[ports.HostRef]uuid.UUID{}, BindingUUIDs: map[string]bool{}, Listed: map[string][]ports.HostSeen{}}
	index := map[ports.HostRef]ports.HostSeen{}
	for _, h := range seen {
		index[h.Ref] = h
		u := strings.ToLower(h.HardwareUUID)
		t.Listed[u] = append(t.Listed[u], h)
	}
	byHost, boundOf := map[ports.HostRef][]Binding{}, map[uuid.UUID]ports.HostRef{}
	for _, b := range bindings {
		t.BindingUUIDs[b.HardwareUUID] = true
		boundOf[b.DeviceID] = b.Host
		if b.Host != "" {
			byHost[b.Host] = append(byHost[b.Host], b)
		}
		if b.Host != "" && !relisted(b, index) {
			t.InUse[b.Host] = b.DeviceID
		}
	}
	for host, bs := range byHost {
		switch {
		case len(bs) > 1:
			for _, b := range bs {
				t.Excluded[host] = append(t.Excluded[host], b.DeviceID)
			}
		case bs[0].Valid(index):
			t.Bound[host] = bs[0]
		}
	}
	for _, d := range devices {
		stored := Binding{Host: d.ExternalID, HardwareUUID: d.HardwareUUID}
		if _, ok := t.InUse[d.ExternalID]; d.ExternalID == "" || ok {
			continue
		}
		switch {
		// Fleet gave the bound host's ID to another machine, which must be able to use it (review round 1, N1).
		case relisted(stored, index) && d.ExternalID == boundOf[d.DeviceID]:
			continue
		// The device left a stored host Fleet now lists for another machine; it keeps it until Fleet deleted it, so
		// that its data never reaches another device (review round 2).
		case relisted(stored, index):
			t.Left = append(t.Left, LeftHost{DeviceID: d.DeviceID, OrganizationID: d.OrganizationID, Host: d.ExternalID,
				Reason: LeftRelisted})
		}
		t.InUse[d.ExternalID] = d.DeviceID
	}
	for _, l := range left {
		if _, ok := t.InUse[l.Host]; !ok {
			t.InUse[l.Host] = l.DeviceID
		}
	}
	return t
}

// relisted reports whether the inventory system lists b's host with another hardware UUID than b's device: Fleet gave
// the ID to another machine, so it no longer marks the host as the device's.
func relisted(b Binding, index map[ports.HostRef]ports.HostSeen) bool {
	h, ok := index[b.Host]
	return ok && strings.ToLower(h.HardwareUUID) != b.HardwareUUID
}

// FirstSpeaker returns the host that speaks for a device that is not bound (review round 1, F2): its stored host while
// that is listed with the device's hardware UUID and not in use by another device, else the listed host with that UUID
// and the lowest ID that no other device uses. "" when there is none. It is pure.
func FirstSpeaker(device uuid.UUID, hardwareUUID string, stored ports.HostRef, t Targets) ports.HostRef {
	free := func(ref ports.HostRef) bool { owner, ok := t.InUse[ref]; return !ok || owner == device }
	var best ports.HostRef
	for _, h := range t.Listed[hardwareUUID] {
		switch {
		case !free(h.Ref):
		case h.Ref == stored:
			return stored
		case best == "" || compareRefs(h.Ref, best) < 0:
			best = h.Ref
		}
	}
	return best
}

// NewestSeen returns the newest seen time of the listed hosts, the reference of every liveness comparison in the
// inventory system's clock.
func NewestSeen(seen []ports.HostSeen) time.Time {
	var r time.Time
	for _, h := range seen {
		if h.SeenAt.After(r) {
			r = h.SeenAt
		}
	}
	return r
}
