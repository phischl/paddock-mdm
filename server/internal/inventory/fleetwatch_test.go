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
	host                              *watchHost
	storedSeenAgo, storedPolicyAgo    *time.Duration
	contactAgo, sinceAgo, reportedAgo *time.Duration
	extraHosts                        []watchHost
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
			SilentSince: at(c.sinceAgo), ReportedAt: at(c.reportedAgo)}
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

// TestWatchFleet covers plan M5a amendment 2026-11-16 c, section 8, and amendment d, section 8: device 0 is the one
// under test, the others are peers.
func TestWatchFleet(t *testing.T) {
	stale16 := &watchHost{seenAgo: 16 * time.Minute}
	live := ago(time.Minute)
	gone := ago(20 * time.Minute)
	type want struct {
		start, reset, clear, report []int
		suppressed                  string
		reason                      string
	}
	rows := []struct {
		name  string
		cases []watchCase
		want  want
	}{
		{"impostor: stale 16 min, live, confirmed", append([]watchCase{{host: stale16, contactAgo: live, sinceAgo: ago(15 * time.Minute)}}, peers(3)...),
			want{report: []int{0}, reason: SilentContact}},
		{"confirmation boundary", append([]watchCase{{host: stale16, contactAgo: live, sinceAgo: ago(15*time.Minute - time.Second)}}, peers(3)...),
			want{}},
		{"first sight", append([]watchCase{{host: stale16, contactAgo: live}}, peers(3)...), want{start: []int{0}}},
		{"fresh again after a report", append([]watchCase{{host: &watchHost{}, contactAgo: live, sinceAgo: ago(time.Hour), reportedAgo: ago(time.Hour)}}, peers(3)...),
			want{clear: []int{0}}},
		{"not live: suspend or network loss", append([]watchCase{{host: stale16, contactAgo: gone, sinceAgo: ago(20 * time.Minute), reportedAgo: ago(time.Minute)}}, peers(3)...),
			want{reset: []int{0}}},
		{"resume: live, stale, no since", append([]watchCase{{host: &watchHost{seenAgo: 3 * time.Hour}, contactAgo: live}}, peers(3)...),
			want{start: []int{0}}},
		{"host missing: stale by stored last_seen_at", append([]watchCase{{storedSeenAgo: ago(20 * time.Minute), contactAgo: live, sinceAgo: ago(16 * time.Minute)}}, peers(3)...),
			want{report: []int{0}, reason: SilentContact}},
		{"host missing: fresh by stored last_seen_at", append([]watchCase{{storedSeenAgo: ago(time.Minute), contactAgo: live, sinceAgo: ago(16 * time.Minute)}}, peers(3)...),
			want{clear: []int{0}}},
		{"host missing, no stored last_seen_at: stale", append([]watchCase{{contactAgo: live}}, peers(3)...), want{start: []int{0}}},
		{"speaking host stale, another claimant fresh (D-c1 7)", append([]watchCase{{host: &watchHost{seenAgo: 20 * time.Minute}, extraHosts: []watchHost{{}},
			contactAgo: live, sinceAgo: ago(15 * time.Minute)}}, peers(3)...), want{report: []int{0}, reason: SilentContact}},
		{"devices cannot reach the inventory system: every contact frozen alike", []watchCase{
			{host: &watchHost{seenAgo: 40 * time.Minute, policyAgo: 40 * time.Minute}, contactAgo: live, sinceAgo: ago(20 * time.Minute)},
			{host: &watchHost{seenAgo: 40 * time.Minute, policyAgo: 40 * time.Minute}, contactAgo: live},
			{host: &watchHost{seenAgo: 40 * time.Minute, policyAgo: 40 * time.Minute}, contactAgo: live}}, want{clear: []int{0}}},
		{"restart: one host back, others stale and live, no since", []watchCase{
			{host: &watchHost{seenAgo: 20 * time.Minute}, contactAgo: live}, {host: &watchHost{seenAgo: 20 * time.Minute}, contactAgo: live},
			{host: &watchHost{seenAgo: 20 * time.Minute}, contactAgo: live}, {host: &watchHost{}, contactAgo: live}},
			want{start: []int{0, 1, 2}}},
		{"restart: 1 fresh of 4 live, confirmed", []watchCase{
			{host: &watchHost{seenAgo: 20 * time.Minute}, contactAgo: live, sinceAgo: ago(15 * time.Minute)},
			{host: &watchHost{seenAgo: 20 * time.Minute}, contactAgo: live, sinceAgo: ago(15 * time.Minute)},
			{host: &watchHost{seenAgo: 20 * time.Minute}, contactAgo: live, sinceAgo: ago(15 * time.Minute)},
			{host: &watchHost{}, contactAgo: live}}, want{suppressed: SuppressedFreshMinority}},
		{"no fresh peer", []watchCase{{host: stale16, contactAgo: live, sinceAgo: ago(time.Hour)}, {host: &watchHost{}, contactAgo: gone}},
			want{suppressed: SuppressedNoFreshPeer}},
		{"majority boundary: 2 fresh of 4 live", append([]watchCase{{host: stale16, contactAgo: live, sinceAgo: ago(time.Hour)},
			{host: stale16, contactAgo: live, sinceAgo: ago(time.Hour), reportedAgo: ago(time.Minute)}}, peers(2)...),
			want{report: []int{0}, reason: SilentContact}},
		{"majority boundary: 1 fresh of 3 live", append([]watchCase{{host: stale16, contactAgo: live, sinceAgo: ago(time.Hour)},
			{host: stale16, contactAgo: live, sinceAgo: ago(time.Hour), reportedAgo: ago(time.Minute)}}, peers(1)...),
			want{suppressed: SuppressedFreshMinority}},
		{"policies: 31 min older than the newest", append([]watchCase{{host: &watchHost{policyAgo: 31 * time.Minute}, contactAgo: live, sinceAgo: ago(15 * time.Minute)}}, peers(3)...),
			want{report: []int{0}, reason: SilentPolicies}},
		{"policies: 29 min older is not stale", append([]watchCase{{host: &watchHost{policyAgo: 29 * time.Minute}, contactAgo: live, sinceAgo: ago(15 * time.Minute)}}, peers(3)...),
			want{clear: []int{0}}},
		{"policies: never stored is not stale", append([]watchCase{{host: &watchHost{noPolicy: true}, contactAgo: live, sinceAgo: ago(15 * time.Minute)}}, peers(3)...),
			want{clear: []int{0}}},
		{"policies: stored value when the host is not listed", append([]watchCase{{storedSeenAgo: ago(time.Minute), storedPolicyAgo: ago(time.Hour), contactAgo: live, sinceAgo: ago(15 * time.Minute)}}, peers(3)...),
			want{report: []int{0}, reason: SilentPolicies}},
		{"policies: a stall of every host", []watchCase{
			{host: &watchHost{policyAgo: 40 * time.Minute}, contactAgo: live, sinceAgo: ago(time.Hour)},
			{host: &watchHost{policyAgo: 40 * time.Minute}, contactAgo: live}, {host: &watchHost{policyAgo: 40 * time.Minute}, contactAgo: live}},
			want{clear: []int{0}}},
		{"already reported: nothing again", append([]watchCase{{host: stale16, contactAgo: live, sinceAgo: ago(time.Hour), reportedAgo: ago(time.Minute)}}, peers(3)...),
			want{}},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			devices, seen := build(row.cases)
			w := WatchFleet(devices, seen, HostTargets(seen, nil, nil, nil), watchNow, 15*time.Minute)
			got := want{start: ids(w, devices, func(w FleetWatch) []uuid.UUID { return w.Start }),
				reset:  ids(w, devices, func(w FleetWatch) []uuid.UUID { return w.Reset }),
				clear:  ids(w, devices, func(w FleetWatch) []uuid.UUID { return w.Clear }),
				report: reported(w, devices), suppressed: w.Suppressed}
			if len(w.Report) > 0 {
				got.reason = w.Report[0].Reason
			}
			if fmt.Sprint(got) != fmt.Sprint(row.want) {
				t.Fatalf("got %+v, want %+v (live %d, fresh %d, due %d)", got, row.want, w.Live, w.Fresh, w.Due)
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
		contactAgo: ago(time.Minute), sinceAgo: ago(16 * time.Minute)}}, peers(2)...))
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
		contactAgo: ago(time.Minute), sinceAgo: ago(time.Hour)}}, peers(2)...))
	devices[0].BoundHost = "101"
	b := []Binding{{DeviceID: devices[0].DeviceID, HardwareUUID: devices[0].HardwareUUID, Host: "101"}}
	w := WatchFleet(devices, seen, HostTargets(seen, b, nil, nil), watchNow, 15*time.Minute)
	if len(w.Report) != 1 || w.Report[0].Reason != SilentContact {
		t.Fatalf("%+v", w)
	}
}
