package inventory

import (
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/ports"
)

var watchNow = time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)

// watchHost is a listed host: how long before watchNow it made contact and stored policy results.
type watchHost struct {
	seenAgo, policyAgo time.Duration
	noPolicy           bool
}

// watchCase is one device and its host; host nil means the host is not listed.
type watchCase struct {
	host                                         *watchHost
	storedSeenAgo, storedPolicyAgo               *time.Duration
	contactAgo, sinceAgo, reportedAgo            *time.Duration
	checkinAgo                                   *time.Duration
	resetAgo, boundAgo, suspendedAgo, reenrolled *time.Duration
	resetHoldAgo                                 *time.Duration
	// bound binds the device to boundHost, else to its own host.
	bound      bool
	boundHost  ports.HostRef
	extraHosts []watchHost
}

func ago(d time.Duration) *time.Duration { return &d }

func at(d *time.Duration) *time.Time {
	if d == nil {
		return nil
	}
	t := watchNow.Add(-*d)
	return &t
}

// build lists the hosts and devices of cases: device n speaks from host "1n0"; extra hosts are peers without a device.
func build(cases []watchCase) ([]WatchedDevice, []ports.HostSeen) {
	var devices []WatchedDevice
	var seen []ports.HostSeen
	listed := func(ref ports.HostRef, hw string, h watchHost) ports.HostSeen {
		s := ports.HostSeen{Ref: ref, HardwareUUID: hw, SeenAt: watchNow.Add(-h.seenAgo)}
		if !h.noPolicy {
			p := watchNow.Add(-h.policyAgo)
			s.PolicyUpdatedAt = &p
		}
		return s
	}
	for n, c := range cases {
		hw := fmt.Sprintf("00000000-0000-0000-0000-%012d", n)
		ref := ports.HostRef(fmt.Sprintf("1%d0", n))
		d := WatchedDevice{DeviceID: uuid.New(), OrganizationID: uuid.New(), HardwareUUID: hw, ExternalID: ref,
			LastSeenAt: at(c.storedSeenAgo), PolicyUpdatedAt: at(c.storedPolicyAgo), LastContactAt: at(c.contactAgo),
			SilentSince: at(c.sinceAgo), ReportedAt: at(c.reportedAgo), CheckinAt: at(c.checkinAgo),
			ResetAnnouncedAt: at(c.resetAgo), BoundAt: at(c.boundAgo), SuspendedAt: at(c.suspendedAgo), ReenrolledAt: at(c.reenrolled),
			ResetHoldAt: at(c.resetHoldAgo)}
		if c.bound {
			d.BoundHost = ref
			if c.boundHost != "" {
				d.BoundHost = c.boundHost
			}
		}
		if c.host != nil {
			seen = append(seen, listed(ref, hw, *c.host))
		}
		for k, h := range c.extraHosts {
			seen = append(seen, listed(ports.HostRef(fmt.Sprintf("1%d%d", n, k+1)), hw, h))
		}
		devices = append(devices, d)
	}
	return devices, seen
}

func peers(n int) []watchCase {
	out := make([]watchCase, n)
	for k := range out {
		out[k] = watchCase{host: &watchHost{}, contactAgo: ago(time.Minute)}
	}
	return out
}

func ids(w FleetWatch, devices []WatchedDevice, pick func(FleetWatch) []uuid.UUID) []int {
	var out []int
	for n, d := range devices {
		if slices.Contains(pick(w), d.DeviceID) {
			out = append(out, n)
		}
	}
	return out
}

func reported(w FleetWatch, devices []WatchedDevice) []int {
	return ids(w, devices, func(w FleetWatch) []uuid.UUID {
		var out []uuid.UUID
		for _, s := range w.Report {
			out = append(out, s.DeviceID)
		}
		return out
	})
}

// TestWatchFleet covers plan M5a amendment 2026-11-16 c, section 8, amendment d, section 8, and amendment 2026-11-24 f,
// section F-8: device 0 is the one under test, the others are peers.
func TestWatchFleet(t *testing.T) {
	stale16 := &watchHost{seenAgo: 16 * time.Minute}
	stale25 := &watchHost{seenAgo: 25 * time.Minute}
	live := ago(time.Minute)
	m := func(n float64) *time.Duration { return ago(time.Duration(n * float64(time.Minute))) }
	// due is a confirmed episode: started 15 min ago, first check-in noted 10 min ago, checked in again since.
	due := func(c watchCase) watchCase {
		c.contactAgo, c.sinceAgo, c.checkinAgo = live, m(15), m(10)
		return c
	}
	heldStale := watchCase{host: stale25, contactAgo: live, resetAgo: m(35), resetHoldAgo: m(35), sinceAgo: m(20), checkinAgo: m(10)}
	reportedStale := watchCase{host: stale25, contactAgo: live, sinceAgo: m(60), checkinAgo: m(50), reportedAgo: m(30)}
	policyStale := watchCase{host: &watchHost{policyAgo: 40 * time.Minute}, contactAgo: live}
	type want struct {
		start, held, note, reset, clear, report []int
		suppressed                              string
		reason                                  string
		live                                    int
	}
	rows := []struct {
		name  string
		cases []watchCase
		want  want
	}{
		{"impostor: stale 16 min, live, confirmed", append([]watchCase{due(watchCase{host: stale16})}, peers(3)...),
			want{report: []int{0}, reason: SilentContact}},
		{"confirmation boundary", append([]watchCase{{host: stale16, contactAgo: live, sinceAgo: ago(15*time.Minute - time.Second), checkinAgo: m(10)}}, peers(3)...),
			want{}},
		{"first sight", append([]watchCase{{host: stale16, contactAgo: live}}, peers(3)...), want{start: []int{0}}},
		{"fresh again after a report", append([]watchCase{{host: &watchHost{}, contactAgo: live, sinceAgo: ago(time.Hour), checkinAgo: m(50), reportedAgo: ago(time.Hour)}}, peers(3)...),
			want{clear: []int{0}}},
		{"gone: no check-in for 61 min", append([]watchCase{{host: stale16, contactAgo: m(61), sinceAgo: m(70), checkinAgo: m(65), reportedAgo: ago(time.Minute)}}, peers(3)...),
			want{reset: []int{0}}},
		{"no check-in for 59 min, open episode", append([]watchCase{{host: stale16, contactAgo: m(59), sinceAgo: m(20)}}, peers(3)...),
			want{}},
		{"resume: live, stale, no since", append([]watchCase{{host: &watchHost{seenAgo: 3 * time.Hour}, contactAgo: live}}, peers(3)...),
			want{start: []int{0}}},
		{"host missing: stale by stored last_seen_at", append([]watchCase{due(watchCase{storedSeenAgo: m(20)})}, peers(3)...),
			want{report: []int{0}, reason: SilentContact}},
		{"host missing: fresh by stored last_seen_at", append([]watchCase{due(watchCase{storedSeenAgo: m(1)})}, peers(3)...),
			want{clear: []int{0}}},
		{"host missing, no stored last_seen_at: stale", append([]watchCase{{contactAgo: live}}, peers(3)...), want{start: []int{0}}},
		{"speaking host stale, another claimant fresh (D-c1 7)", append([]watchCase{due(watchCase{host: &watchHost{seenAgo: 20 * time.Minute},
			extraHosts: []watchHost{{}}})}, peers(3)...), want{report: []int{0}, reason: SilentContact}},
		{"devices cannot reach the inventory system: every contact frozen alike", []watchCase{
			{host: &watchHost{seenAgo: 40 * time.Minute, policyAgo: 40 * time.Minute}, contactAgo: live, sinceAgo: ago(20 * time.Minute)},
			{host: &watchHost{seenAgo: 40 * time.Minute, policyAgo: 40 * time.Minute}, contactAgo: live},
			{host: &watchHost{seenAgo: 40 * time.Minute, policyAgo: 40 * time.Minute}, contactAgo: live}}, want{clear: []int{0}}},
		{"restart: one host back, others stale and live, no since", []watchCase{
			{host: &watchHost{seenAgo: 20 * time.Minute}, contactAgo: live}, {host: &watchHost{seenAgo: 20 * time.Minute}, contactAgo: live},
			{host: &watchHost{seenAgo: 20 * time.Minute}, contactAgo: live}, {host: &watchHost{}, contactAgo: live}},
			want{start: []int{0, 1, 2}}},
		{"restart: 1 fresh of 4 live, confirmed", []watchCase{due(watchCase{host: &watchHost{seenAgo: 20 * time.Minute}}),
			due(watchCase{host: &watchHost{seenAgo: 20 * time.Minute}}), due(watchCase{host: &watchHost{seenAgo: 20 * time.Minute}}),
			{host: &watchHost{}, contactAgo: live}}, want{suppressed: SuppressedFreshMinority}},
		{"no fresh peer", []watchCase{due(watchCase{host: stale16}), {host: &watchHost{}, contactAgo: m(20)}},
			want{suppressed: SuppressedNoFreshPeer}},
		{"majority boundary: 2 fresh of 4 live", append([]watchCase{due(watchCase{host: stale16}),
			{host: stale16, contactAgo: live, sinceAgo: ago(time.Hour)}}, peers(2)...),
			want{note: []int{1}, report: []int{0}, reason: SilentContact}},
		{"majority boundary: 1 fresh of 3 live", append([]watchCase{due(watchCase{host: stale16}),
			{host: stale16, contactAgo: live, sinceAgo: ago(time.Hour)}}, peers(1)...),
			want{note: []int{1}, suppressed: SuppressedFreshMinority}},
		{"policies: 31 min older than the newest", append([]watchCase{due(watchCase{host: &watchHost{policyAgo: 31 * time.Minute}})}, peers(3)...),
			want{report: []int{0}, reason: SilentPolicies}},
		{"policies: 29 min older is not stale", append([]watchCase{due(watchCase{host: &watchHost{policyAgo: 29 * time.Minute}})}, peers(3)...),
			want{clear: []int{0}}},
		{"policies: never stored is not stale", append([]watchCase{due(watchCase{host: &watchHost{noPolicy: true}})}, peers(3)...),
			want{clear: []int{0}}},
		{"policies: stored value when the host is not listed", append([]watchCase{due(watchCase{storedSeenAgo: m(1), storedPolicyAgo: m(60)})}, peers(3)...),
			want{report: []int{0}, reason: SilentPolicies}},
		{"policies: a stall of every host", []watchCase{
			{host: &watchHost{policyAgo: 40 * time.Minute}, contactAgo: live, sinceAgo: ago(time.Hour)},
			{host: &watchHost{policyAgo: 40 * time.Minute}, contactAgo: live}, {host: &watchHost{policyAgo: 40 * time.Minute}, contactAgo: live}},
			want{clear: []int{0}}},
		{"already reported: nothing again", append([]watchCase{{host: stale16, contactAgo: live, sinceAgo: ago(time.Hour), checkinAgo: m(50), reportedAgo: ago(time.Minute)}}, peers(3)...),
			want{}},
		{"note: a check-in after the start", append([]watchCase{{host: stale25, contactAgo: live, sinceAgo: m(20)}}, peers(3)...),
			want{note: []int{0}}},
		{"note: a check-in at the start is not after it", append([]watchCase{{host: stale25, contactAgo: m(20), sinceAgo: m(20)}}, peers(3)...),
			want{}},
		{"second check-in at the noted one: not due", append([]watchCase{{host: stale25, contactAgo: m(1), sinceAgo: m(20), checkinAgo: m(1)}}, peers(3)...),
			want{}},
		{"second check-in one second after the noted one: due", append([]watchCase{{host: stale25, contactAgo: m(1), sinceAgo: m(20), checkinAgo: ago(time.Minute + time.Second)}}, peers(3)...),
			want{report: []int{0}, reason: SilentContact}},
		{"announced reset, not bound since: held (regression H1-a)", append([]watchCase{heldStale}, peers(3)...),
			want{live: 3}},
		{"announced reset, bound since to the stale host: reported", append([]watchCase{{host: stale25, contactAgo: live, resetAgo: m(35), boundAgo: m(30),
			bound: true, sinceAgo: m(20), checkinAgo: m(10)}}, peers(3)...), want{report: []int{0}, reason: SilentContact}},
		{"hold end boundary: not yet due", append([]watchCase{{host: stale25, contactAgo: live, resetAgo: m(74), resetHoldAgo: m(74), sinceAgo: m(55), checkinAgo: m(13)}}, peers(3)...),
			want{}},
		{"hold end boundary: due", append([]watchCase{{host: stale25, contactAgo: live, resetAgo: m(75), resetHoldAgo: m(75), sinceAgo: m(55), checkinAgo: m(13)}}, peers(3)...),
			want{report: []int{0}, reason: SilentContact}},
		{"an announcement recorded after the start round does not hold (M-1)", append([]watchCase{{host: stale25, contactAgo: live,
			resetAgo: m(30), sinceAgo: m(20), checkinAgo: m(10)}}, peers(3)...), want{report: []int{0}, reason: SilentContact}},
		{"an announcement older than ClaimQuiet: a plain start", append([]watchCase{{host: stale25, contactAgo: live, resetAgo: m(61)}}, peers(3)...),
			want{start: []int{0}}},
		{"an announcement after the episode start does not hold", append([]watchCase{{host: stale25, contactAgo: live, resetAgo: m(2), sinceAgo: m(20), checkinAgo: m(10)}}, peers(3)...),
			want{report: []int{0}, reason: SilentContact}},
		{"suspended binding: held (regression H1-b)", append([]watchCase{{storedSeenAgo: m(30), bound: true, boundHost: "999", suspendedAgo: m(25),
			contactAgo: live, sinceAgo: m(15), checkinAgo: m(10)}}, peers(3)...), want{live: 3}},
		{"suspended after the episode start: reported", append([]watchCase{{storedSeenAgo: m(30), bound: true, boundHost: "999", suspendedAgo: m(10),
			contactAgo: live, sinceAgo: m(15), checkinAgo: m(10)}}, peers(3)...), want{report: []int{0}, reason: SilentContact}},
		{"re-enrollment before the episode start: held", append([]watchCase{due(watchCase{host: stale25, reenrolled: m(20)})}, peers(3)...),
			want{live: 3}},
		{"guard without held devices", append([]watchCase{due(watchCase{host: stale25}), heldStale, heldStale, heldStale}, peers(1)...),
			want{report: []int{0}, reason: SilentContact, live: 2}},
		{"guard without reported devices (M2)", append([]watchCase{due(watchCase{host: stale25}), reportedStale, reportedStale, reportedStale,
			reportedStale}, peers(2)...), want{report: []int{0}, reason: SilentContact, live: 3}},
		{"no start for a device that last checked in 30 min ago (L-1)", append([]watchCase{{host: stale25, contactAgo: m(30)}}, peers(3)...),
			want{}},
		{"reset hold: none granted yet, a held start", append([]watchCase{{host: stale25, contactAgo: live, resetAgo: m(1)}}, peers(3)...),
			want{start: []int{0}, held: []int{0}}},
		{"reset hold: 23 h after the granted one, a plain start", append([]watchCase{{host: stale25, contactAgo: live, resetAgo: m(1),
			resetHoldAgo: m(23*60 + 1)}}, peers(3)...), want{start: []int{0}}},
		{"reset hold: 23 h after the granted one, reported (regression L-1)", append([]watchCase{{host: stale25, contactAgo: live, resetAgo: m(25),
			resetHoldAgo: m(23*60 + 25), sinceAgo: m(20), checkinAgo: m(10)}}, peers(3)...), want{report: []int{0}, reason: SilentContact}},
		{"reset hold: 24 h after the granted one, a held start", append([]watchCase{{host: stale25, contactAgo: live, resetAgo: m(1),
			resetHoldAgo: m(24*60 + 1)}}, peers(3)...), want{start: []int{0}, held: []int{0}}},
		{"reset hold: the granted announcement continues", append([]watchCase{{host: stale25, contactAgo: live, resetAgo: m(35),
			resetHoldAgo: m(35), sinceAgo: m(20), checkinAgo: m(10)}}, peers(3)...), want{live: 3}},
		{"only fully fresh devices are fresh (M-a)", append([]watchCase{due(watchCase{host: stale25}), policyStale, policyStale}, peers(1)...),
			want{start: []int{1, 2}, suppressed: SuppressedFreshMinority, live: 4}},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			devices, seen := build(row.cases)
			w := WatchFleet(devices, seen, HostTargets(seen, nil, nil, nil), watchNow, 15*time.Minute)
			got := want{start: ids(w, devices, func(w FleetWatch) []uuid.UUID { return w.Start }),
				held:   ids(w, devices, func(w FleetWatch) []uuid.UUID { return w.HeldStart }),
				note:   ids(w, devices, func(w FleetWatch) []uuid.UUID { return w.Note }),
				reset:  ids(w, devices, func(w FleetWatch) []uuid.UUID { return w.Reset }),
				clear:  ids(w, devices, func(w FleetWatch) []uuid.UUID { return w.Clear }),
				report: reported(w, devices), suppressed: w.Suppressed, live: row.want.live}
			if len(w.Report) > 0 {
				got.reason = w.Report[0].Reason
			}
			if row.want.live != 0 && w.Live != row.want.live {
				got.live = w.Live
			}
			if fmt.Sprint(got) != fmt.Sprint(row.want) {
				t.Fatalf("got %+v, want %+v (live %d, fresh %d, due %d)", got, row.want, w.Live, w.Fresh, w.Due)
			}
		})
	}
}

// timelineDevice is the device of TestWatchFleetTimeline, in minutes since its fleetd froze: seen is its own host's last
// contact, contact its last check-in (false when none) at a round's time; a non-zero bindAt announces a reset at 0,
// lists a new fresh host from minute 1 and binds the device to it in the round at bindAt.
type timelineDevice struct {
	seen    func(m int) int
	contact func(m int) (int, bool)
	bindAt  int
	// resets are further reset announcements of a device bound to its own host before minute 0 (F-15).
	resets []int
	// late are announcements {arrival, value} that arrive after the round of their value, backdated (review 4, M-1).
	late [][2]int
}

// every checks in every interval minutes at offset off, also before minute 0; none during the gaps.
func every(interval, off int, gaps ...[2]int) func(m int) (int, bool) {
	return func(m int) (int, bool) {
		for c := off + ((m-off)/interval)*interval + interval; c >= -interval; c-- {
			if c > m || (c-off)%interval != 0 {
				continue
			}
			inGap := false
			for _, g := range gaps {
				inGap = inGap || c > g[0] && c < g[1]
			}
			if !inGap {
				return c, true
			}
		}
		return 0, false
	}
}

// runTimeline runs rounds every 5 minutes over 4 hours with 3 fresh peers, applies each round's transitions to the
// device's state and returns the rounds that reported it.
func runTimeline(d timelineDevice) []int {
	base := watchNow
	minute := func(m int) *time.Time { t := base.Add(time.Duration(m) * time.Minute); return &t }
	dev := WatchedDevice{DeviceID: uuid.New(), OrganizationID: uuid.New(), HardwareUUID: "h-0", ExternalID: "100"}
	if d.bindAt != 0 {
		dev.ResetAnnouncedAt = minute(0)
	}
	if d.resets != nil || d.late != nil {
		dev.BoundHost, dev.BoundAt = "100", minute(-60)
	}
	var reports []int
	for m := 0; m <= 240; m += 5 {
		now := *minute(m)
		seen := []ports.HostSeen{{Ref: "100", HardwareUUID: "h-0", SeenAt: *minute(d.seen(m)), PolicyUpdatedAt: minute(d.seen(m))}}
		if d.bindAt != 0 && m >= 1 {
			seen = append(seen, ports.HostSeen{Ref: "101", HardwareUUID: "h-0", SeenAt: now, PolicyUpdatedAt: &now})
		}
		devices := []WatchedDevice{}
		for k := range 3 {
			ref := ports.HostRef(fmt.Sprintf("20%d", k))
			hw := fmt.Sprintf("p-%d", k)
			seen = append(seen, ports.HostSeen{Ref: ref, HardwareUUID: hw, SeenAt: now, PolicyUpdatedAt: &now})
			devices = append(devices, WatchedDevice{DeviceID: uuid.New(), HardwareUUID: hw, ExternalID: ref, LastContactAt: minute(m - 1)})
		}
		if d.bindAt != 0 && m >= d.bindAt && dev.BoundHost == "" {
			dev.BoundHost, dev.BoundAt = "101", &now
		}
		for _, a := range d.resets {
			if a <= m {
				dev.ResetAnnouncedAt = minute(a)
			}
		}
		for _, a := range d.late {
			if a[0] <= m {
				dev.ResetAnnouncedAt = minute(a[1])
			}
		}
		dev.LastContactAt = nil
		if c, ok := d.contact(m); ok {
			dev.LastContactAt = minute(c)
		}
		w := WatchFleet(append(devices, dev), seen, HostTargets(seen, nil, nil, nil), now, 15*time.Minute)
		has := func(ids []uuid.UUID) bool { return slices.Contains(ids, dev.DeviceID) }
		switch {
		case has(w.Clear):
			dev.SilentSince, dev.CheckinAt, dev.ReportedAt = nil, nil, nil
		case has(w.Reset):
			dev.SilentSince, dev.CheckinAt = nil, nil
		case has(w.Start):
			dev.SilentSince = &now
			if has(w.HeldStart) {
				dev.ResetHoldAt = dev.ResetAnnouncedAt
			}
		case has(w.Note):
			dev.CheckinAt = dev.LastContactAt
		}
		for _, r := range w.Report {
			if r.DeviceID == dev.DeviceID {
				dev.ReportedAt = &now
				reports = append(reports, m)
			}
		}
	}
	return reports
}

// TestWatchFleetTimeline (plan M5a amendment 2026-11-24 f, F-8; AC-f1, AC-f3, AC-f4): rounds every 5 minutes, check-ins
// offset 2 minutes from them.
func TestWatchFleetTimeline(t *testing.T) {
	frozen := func(int) int { return 0 }
	reconnects := func(stop, back int) func(m int) int {
		return func(m int) int {
			if m > stop && m < back {
				return stop
			}
			return m
		}
	}
	rows := []struct {
		name string
		d    timelineDevice
		want []int
	}{
		{"check-in every 5 min", timelineDevice{seen: frozen, contact: every(5, 2)}, []int{35}},
		{"check-in every 10 min", timelineDevice{seen: frozen, contact: every(10, 2)}, nil},
		{"check-in every 16 min", timelineDevice{seen: frozen, contact: every(16, 2)}, nil},
		{"check-in every 20 min", timelineDevice{seen: frozen, contact: every(20, 2)}, nil},
		{"check-in every 25 min", timelineDevice{seen: frozen, contact: every(25, 2)}, nil},
		{"check-in every 30 min", timelineDevice{seen: frozen, contact: every(30, 2)}, nil},
		{"check-in every 55 min", timelineDevice{seen: frozen, contact: every(55, 2)}, nil},
		{"check-in every 65 min", timelineDevice{seen: frozen, contact: every(65, 2)}, []int{}},
		{"suspend for 40 min", timelineDevice{seen: reconnects(60, 102), contact: every(5, 2, [2]int{60, 100})}, []int{}},
		{"episode open before a 25-min suspend", timelineDevice{seen: reconnects(39, 83), contact: every(5, 2, [2]int{55, 81})}, []int{}},
		{"boot after 3 h off", timelineDevice{seen: reconnects(0, 183), contact: every(5, 0, [2]int{-3, 180})}, []int{}},
		{"announced reset, bound at 40 (regression H1-a)", timelineDevice{seen: frozen, contact: every(5, 1), bindAt: 40}, []int{}},
		{"announced reset, bound at 80", timelineDevice{seen: frozen, contact: every(5, 1), bindAt: 80}, []int{75}},
		{"a reset announced per check-in period (regression L-1)", timelineDevice{seen: func(int) int { return -300 },
			contact: every(5, 1, [2]int{-1000, 1}, [2]int{51, 121}, [2]int{171, 1000}), resets: []int{0, 120}}, []int{140}},
		{"backdated announcements arriving after each start round (regression M-1)", timelineDevice{seen: func(int) int { return -300 },
			contact: every(5, 1, [2]int{-1000, 1}, [2]int{51, 121}, [2]int{171, 1000}), late: [][2]int{{10, 0}, {130, 120}}}, []int{20}},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			got := runTimeline(row.d)
			switch {
			case row.want == nil && len(got) != 1:
				t.Fatalf("reports in rounds %v, want exactly one", got)
			case row.want != nil && fmt.Sprint(got) != fmt.Sprint(row.want) && !(len(got) == 0 && len(row.want) == 0):
				t.Fatalf("reports in rounds %v, want %v", got, row.want)
			}
		})
	}
}

// TestWatchFleetEmptyList: without any listed host nothing is judged, even a device whose stored contact is old.
func TestWatchFleetEmptyList(t *testing.T) {
	devices, _ := build([]watchCase{{storedSeenAgo: ago(time.Hour), contactAgo: ago(time.Minute), sinceAgo: ago(time.Hour)}})
	w := WatchFleet(devices, nil, HostTargets(nil, nil, nil, nil), watchNow, 15*time.Minute)
	if fmt.Sprint(w) != fmt.Sprint(FleetWatch{}) {
		t.Fatalf("%+v", w)
	}
}

// TestWatchFleetReportTimes: a report carries the speaking host's times and the device's contact and silence start;
// ForOrganization keeps only the organization's devices.
func TestWatchFleetReportTimes(t *testing.T) {
	devices, seen := build(append([]watchCase{{host: &watchHost{seenAgo: 20 * time.Minute, policyAgo: 25 * time.Minute},
		contactAgo: ago(time.Minute), sinceAgo: ago(16 * time.Minute), checkinAgo: ago(10 * time.Minute)}}, peers(2)...))
	w := WatchFleet(devices, seen, HostTargets(seen, nil, nil, nil), watchNow, 15*time.Minute)
	if len(w.Report) != 1 || w.Live != 3 || w.Fresh != 2 || w.Due != 1 {
		t.Fatalf("%+v", w)
	}
	r := w.Report[0]
	if !r.FleetdSeenAt.Equal(watchNow.Add(-20*time.Minute)) || !r.FleetdPolicyUpdatedAt.Equal(watchNow.Add(-25*time.Minute)) ||
		!r.LastContactAt.Equal(watchNow.Add(-time.Minute)) || !r.SilentSince.Equal(watchNow.Add(-16*time.Minute)) {
		t.Fatalf("report %+v", r)
	}
	if part := w.ForOrganization(devices[1].OrganizationID, devices); len(part.Report) != 0 {
		t.Fatalf("other organization %+v", part)
	}
	if part := w.ForOrganization(devices[0].OrganizationID, devices); len(part.Report) != 1 {
		t.Fatalf("own organization %+v", part)
	}
}

// TestWatchFleetBoundHost: a bound device is judged by its bound host, not by another host with its UUID that is
// stored or listed first.
func TestWatchFleetBoundHost(t *testing.T) {
	devices, seen := build(append([]watchCase{{host: &watchHost{}, extraHosts: []watchHost{{seenAgo: time.Hour}},
		contactAgo: ago(time.Minute), sinceAgo: ago(time.Hour), checkinAgo: ago(10 * time.Minute)}}, peers(2)...))
	devices[0].BoundHost = "101"
	b := []Binding{{DeviceID: devices[0].DeviceID, HardwareUUID: devices[0].HardwareUUID, Host: "101"}}
	w := WatchFleet(devices, seen, HostTargets(seen, b, nil, nil), watchNow, 15*time.Minute)
	if len(w.Report) != 1 || w.Report[0].Reason != SilentContact {
		t.Fatalf("%+v", w)
	}
}
