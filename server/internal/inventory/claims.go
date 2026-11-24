package inventory

import (
	"cmp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/ports"
)

// Bounds of the claim watch (ADR 0057; plan M5a amendment 2026-11-17 e, H7 to H9 and H14).
const (
	// HostClaimLive is how recently another claimant must have contacted the inventory system to count; shorter than
	// HostClaimConfirm, so a host that stopped before an episode started can never make it due.
	HostClaimLive = 10 * time.Minute
	// HostClaimConfirm is how long another live claimant must persist before it is reported.
	HostClaimConfirm = 15 * time.Minute
	// ClaimQuiet is how long a re-enrollment holds the inventory-derived agent reports and keeps an episode open, and
	// how long an announced enrollment reset lasts at most.
	ClaimQuiet = 60 * time.Minute
	// ClaimMajorityMin is the least number of claimed devices at which the majority guard applies (H9).
	ClaimMajorityMin = 3
	// ClaimHostsInParam caps the other hosts named in the event.
	ClaimHostsInParam = 10
)

// Claim kinds and binding modes of device.tamper_fleet_host_claimed.
const (
	ClaimSecondHost = "second_host"
	ClaimReenrolled = "reenrolled"
	BindingDevice   = "device"
	BindingFirst    = "first"
)

// ClaimDevice is one watched device (paddock_inventory_claim_devices).
type ClaimDevice struct {
	DeviceID, OrganizationID uuid.UUID
	// HardwareUUID is the device's hardware UUID in lower case.
	HardwareUUID string
	// ExternalID is the stored host.
	ExternalID ports.HostRef
	// BoundHost is the bound host; "" when the device is not bound (binding mode first).
	BoundHost ports.HostRef
	// ResetAnnouncedAt is the agent's announced enrollment reset, BoundAt when the device was last bound (H14).
	ResetAnnouncedAt, BoundAt                             *time.Time
	EnrolledAt, ReenrolledAt, ClaimSince, ClaimReportedAt *time.Time
	// SuspendedAt is when the device's binding was suspended (review round 1, F1).
	SuspendedAt *time.Time
	// Active is false for a quarantined device: its hosts are in use, but it is not watched.
	Active bool
}

// ClaimedDevice is a device to report.
type ClaimedDevice struct {
	ClaimDevice
	Kind    string
	Binding string
	Bound   ports.HostRef
	// Others are the other live claimants in ascending order.
	Others []ports.HostRef
	// Hosts is the number of live claimants including the speaking host.
	Hosts int
	// SpeakingEnrolledAt is the speaking host's latest enrollment.
	SpeakingEnrolledAt *time.Time
	// Since is when the episode started.
	Since time.Time
}

// ClaimWatch is one round's decision.
type ClaimWatch struct {
	// Enrolled holds the fleet_enrolled_at values to store.
	Enrolled                           map[uuid.UUID]*time.Time
	Reenrolled, ClaimStart, ClaimClear []uuid.UUID
	// Claims are the devices to report, without the re-enrollments of a suppressed binding mode.
	Claims []ClaimedDevice
	// Resetting are the devices whose other live claimants were not counted because of an announced reset;
	// Suspended the devices whose binding has been suspended for ClaimQuiet or longer.
	Resetting, Suspended []ClaimDevice
	// Guard is the wave guard per binding mode (review round 1, F4).
	Guard map[string]*ModeGuard
}

// ModeGuard counts one binding mode's active watched devices, those whose open episode saw a re-enrollment, and the
// re-enrollment claims held because they are the majority (claim_majority).
type ModeGuard struct {
	Watched, Claimed, Held int
	Suppressed             bool
}

// WatchClaims decides one round (H7, H9, H14, review round 1). seen is the round's listed hosts; t is the round's
// Targets. devices hold the values from before the round's store. It is pure.
func WatchClaims(devices []ClaimDevice, seen []ports.HostSeen, t Targets, now time.Time) ClaimWatch {
	r := NewestSeen(seen)
	w := ClaimWatch{Enrolled: map[uuid.UUID]*time.Time{}, Guard: map[string]*ModeGuard{BindingDevice: {}, BindingFirst: {}}}
	var due []ClaimedDevice
	for _, d := range devices {
		if !d.Active {
			continue
		}
		speaking, binding := d.BoundHost, BindingDevice
		if speaking == "" {
			speaking, binding = FirstSpeaker(d.DeviceID, d.HardwareUUID, d.ExternalID, t), BindingFirst
		}
		guard := w.Guard[binding]
		guard.Watched++
		var others []ports.HostRef
		var speaker *ports.HostSeen
		hosts := 0
		for _, h := range t.Listed[d.HardwareUUID] {
			live := !h.SeenAt.IsZero() && r.Sub(h.SeenAt) < HostClaimLive
			if h.Ref == speaking {
				speaker = &h
			} else if live {
				others = append(others, h.Ref)
			}
			if live {
				hosts++
			}
		}
		reenrolled := false
		if speaker != nil {
			if !sameTime(speaker.EnrolledAt, d.EnrolledAt) {
				w.Enrolled[d.DeviceID] = speaker.EnrolledAt
			}
			reenrolled = speaking == d.ExternalID && speaker.EnrolledAt != nil && d.EnrolledAt != nil &&
				!speaker.EnrolledAt.Equal(*d.EnrolledAt)
		}
		// A device that has not named its host cannot tell a new speaker apart from a re-enrollment, so both are
		// reported alike (review round 1, F2).
		reenrolled = reenrolled || binding == BindingFirst && d.ExternalID != "" && speaking != "" && speaking != d.ExternalID
		suspended := d.SuspendedAt != nil && now.Sub(*d.SuspendedAt) < ClaimQuiet
		if d.SuspendedAt != nil && !suspended {
			w.Suspended = append(w.Suspended, d)
		}
		second := len(others) > 0
		if second && resetting(d, now) {
			w.Resetting = append(w.Resetting, d)
		}
		second = second && !resetting(d, now) && !suspended
		reenrolledAt := d.ReenrolledAt
		if reenrolled {
			reenrolledAt = &now
			w.Reenrolled = append(w.Reenrolled, d.DeviceID)
		}
		if !second && (reenrolledAt == nil || reenrolledAt.Before(now.Add(-ClaimQuiet))) {
			if d.ClaimSince != nil || d.ClaimReportedAt != nil {
				w.ClaimClear = append(w.ClaimClear, d.DeviceID)
			}
			continue
		}
		since := d.ClaimSince
		if since == nil {
			since = &now
			w.ClaimStart = append(w.ClaimStart, d.DeviceID)
		}
		sawReenrollment := reenrolledAt != nil && !reenrolledAt.Before(*since)
		if sawReenrollment {
			guard.Claimed++
		}
		confirmed := second && now.Sub(*since) >= HostClaimConfirm
		if d.ClaimReportedAt != nil || !sawReenrollment && !confirmed {
			continue
		}
		c := ClaimedDevice{ClaimDevice: d, Kind: ClaimSecondHost, Binding: binding, Bound: speaking, Others: sortRefs(others),
			Hosts: hosts, Since: *since}
		if sawReenrollment {
			c.Kind = ClaimReenrolled
		}
		if speaker != nil {
			c.SpeakingEnrolledAt = speaker.EnrolledAt
		}
		due = append(due, c)
	}
	for _, g := range w.Guard {
		g.Suppressed = g.Claimed >= ClaimMajorityMin && 2*g.Claimed > g.Watched
	}
	for _, c := range due {
		// Only a re-enrollment of most hosts of a mode is a restore's signature; a second host is never held.
		if g := w.Guard[c.Binding]; c.Kind == ClaimReenrolled && g.Suppressed {
			g.Held++
			continue
		}
		w.Claims = append(w.Claims, c)
	}
	return w
}

// resetting reports whether the device announced an enrollment reset within ClaimQuiet and has not been bound since
// (H14): its new host may then be listed before the device names it.
func resetting(d ClaimDevice, now time.Time) bool {
	return d.ResetAnnouncedAt != nil && now.Sub(*d.ResetAnnouncedAt) < ClaimQuiet &&
		(d.BoundAt == nil || d.BoundAt.Before(*d.ResetAnnouncedAt))
}

// ForOrganization returns the part of w that concerns the devices of one organization.
func (w ClaimWatch) ForOrganization(org uuid.UUID, devices []ClaimDevice) ClaimWatch {
	in := map[uuid.UUID]bool{}
	for _, d := range devices {
		if d.OrganizationID == org {
			in[d.DeviceID] = true
		}
	}
	keep := func(ids []uuid.UUID) []uuid.UUID {
		return slices.DeleteFunc(slices.Clone(ids), func(id uuid.UUID) bool { return !in[id] })
	}
	out := ClaimWatch{Enrolled: map[uuid.UUID]*time.Time{}, Reenrolled: keep(w.Reenrolled), ClaimStart: keep(w.ClaimStart),
		ClaimClear: keep(w.ClaimClear)}
	for id, at := range w.Enrolled {
		if in[id] {
			out.Enrolled[id] = at
		}
	}
	for _, c := range w.Claims {
		if in[c.DeviceID] {
			out.Claims = append(out.Claims, c)
		}
	}
	return out
}

// sortRefs orders host references numerically, the inventory system's IDs.
func sortRefs(refs []ports.HostRef) []ports.HostRef {
	slices.SortFunc(refs, compareRefs)
	return refs
}

func compareRefs(a, b ports.HostRef) int {
	x, _ := strconv.ParseInt(string(a), 10, 64)
	y, _ := strconv.ParseInt(string(b), 10, 64)
	return cmp.Or(cmp.Compare(x, y), strings.Compare(string(a), string(b)))
}

func sameTime(a, b *time.Time) bool {
	return a == nil && b == nil || a != nil && b != nil && a.Equal(*b)
}
