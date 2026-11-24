package inventory

import (
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/ports"
)

// Bounds of the fleetd silence watch (plan M5a amendments 2026-11-16 c, E1 and E2, and d, F5).
const (
	// FleetSilence is how much older than the newest contact of any host a device's contact may be before it is stale.
	FleetSilence = 15 * time.Minute
	// FleetSilenceConfirm is how long a stale device that checks in must stay so before it is due.
	FleetSilenceConfirm = 15 * time.Minute
	// PolicySilence is how much older than the newest stored policy results of any host a device's may be before it
	// is stale: three times Fleet's default policy interval.
	PolicySilence = 30 * time.Minute
)

// Reasons of device.tamper_fleetd_silent and of a suppressed round.
const (
	SilentContact           = "contact"
	SilentPolicies          = "policies"
	SuppressedNoFreshPeer   = "no_fresh_peer"
	SuppressedFreshMinority = "fresh_minority"
)

// WatchedDevice is an active device with an inventory reference, as paddock_fleet_watch_devices returns it.
type WatchedDevice struct {
	DeviceID, OrganizationID uuid.UUID
	// HardwareUUID is the device's hardware UUID in lower case.
	HardwareUUID string
	// ExternalID is the stored host, BoundHost the bound host ("" when the device is not bound).
	ExternalID, BoundHost ports.HostRef
	// LastSeenAt and PolicyUpdatedAt are the stored host's values, used when the speaking host is not listed.
	LastContactAt, LastSeenAt, PolicyUpdatedAt, SilentSince, ReportedAt *time.Time
}

// SilentDevice is a device to report, with the inventory system's times the decision used (nil when unknown).
type SilentDevice struct {
	WatchedDevice
	FleetdSeenAt, FleetdPolicyUpdatedAt *time.Time
	Reason                              string
}

// FleetWatch are the decisions of one round.
type FleetWatch struct {
	Start, Reset, Clear []uuid.UUID
	Report              []SilentDevice
	// Due counts the devices due this round, Live the devices that check in, Fresh those of them that are not stale.
	Due, Live, Fresh int
	// Suppressed is SuppressedNoFreshPeer or SuppressedFreshMinority when due devices were held back, else "".
	Suppressed string
}

// WatchFleet decides one round (E1 to E3, F5). seen is the round's complete host list and t its Targets; a device is
// judged by its speaking host, else by its stored values. live is app.AgentSilence. It is pure: no clock, no I/O.
func WatchFleet(devices []WatchedDevice, seen []ports.HostSeen, t Targets, now time.Time, live time.Duration) FleetWatch {
	var w FleetWatch
	r := NewestSeen(seen)
	// Without any contact in the list there is nothing to compare with; judging by stored values alone would report
	// every device after the inventory system lost its hosts.
	if r.IsZero() {
		return w
	}
	var p time.Time
	for _, h := range seen {
		if h.PolicyUpdatedAt != nil && h.PolicyUpdatedAt.After(p) {
			p = *h.PolicyUpdatedAt
		}
	}
	var due []SilentDevice
	for _, d := range devices {
		seenAt, policyAt := d.LastSeenAt, d.PolicyUpdatedAt
		if h, ok := speakingHost(d, t); ok {
			seenAt, policyAt = nil, h.PolicyUpdatedAt
			if !h.SeenAt.IsZero() {
				at := h.SeenAt
				seenAt = &at
			}
		}
		contactStale := seenAt == nil || seenAt.Before(r.Add(-FleetSilence))
		policyStale := policyAt != nil && policyAt.Before(p.Add(-PolicySilence))
		stale := contactStale || policyStale
		isLive := d.LastContactAt != nil && !d.LastContactAt.Before(now.Add(-live))
		if isLive {
			w.Live++
			if !stale {
				w.Fresh++
			}
		}
		switch {
		case !stale:
			if d.SilentSince != nil || d.ReportedAt != nil {
				w.Clear = append(w.Clear, d.DeviceID)
			}
		case !isLive:
			if d.SilentSince != nil {
				w.Reset = append(w.Reset, d.DeviceID)
			}
		case d.SilentSince == nil:
			w.Start = append(w.Start, d.DeviceID)
		case d.ReportedAt == nil && now.Sub(*d.SilentSince) >= FleetSilenceConfirm:
			s := SilentDevice{WatchedDevice: d, FleetdSeenAt: seenAt, FleetdPolicyUpdatedAt: policyAt, Reason: SilentPolicies}
			if contactStale {
				s.Reason = SilentContact
			}
			due = append(due, s)
		}
	}
	w.Due = len(due)
	switch {
	case w.Due == 0:
	case w.Fresh == 0:
		w.Suppressed = SuppressedNoFreshPeer
	case 2*w.Fresh < w.Live:
		w.Suppressed = SuppressedFreshMinority
	default:
		w.Report = due
	}
	return w
}

// speakingHost returns the listed host that speaks for d (plan M5a amendment 2026-11-16 d, D-c1): the bound host, else
// the device's FirstSpeaker; false when it is not listed with the device's hardware UUID.
func speakingHost(d WatchedDevice, t Targets) (ports.HostSeen, bool) {
	ref := d.BoundHost
	if ref == "" {
		ref = FirstSpeaker(d.DeviceID, d.HardwareUUID, d.ExternalID, t)
	}
	for _, h := range t.Listed[d.HardwareUUID] {
		if ref != "" && h.Ref == ref {
			return h, true
		}
	}
	return ports.HostSeen{}, false
}

// ForOrganization returns the part of w that concerns the devices of one organization.
func (w FleetWatch) ForOrganization(org uuid.UUID, devices []WatchedDevice) FleetWatch {
	in := map[uuid.UUID]bool{}
	for _, d := range devices {
		if d.OrganizationID == org {
			in[d.DeviceID] = true
		}
	}
	keep := func(ids []uuid.UUID) []uuid.UUID {
		var out []uuid.UUID
		for _, id := range ids {
			if in[id] {
				out = append(out, id)
			}
		}
		return out
	}
	out := FleetWatch{Start: keep(w.Start), Reset: keep(w.Reset), Clear: keep(w.Clear)}
	for _, s := range w.Report {
		if in[s.DeviceID] {
			out.Report = append(out.Report, s)
		}
	}
	return out
}
