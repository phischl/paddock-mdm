package patchsla_test

import (
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/domain/patchsla"
)

// TestSLADays (plan M13c decision 17): severity → days of the SLA; 0 is no SLA and an unknown severity has none.
func TestSLADays(t *testing.T) {
	s := patchsla.SLA{CriticalDays: 7, HighDays: 30, MediumDays: 90, LowDays: 0}
	for _, c := range []struct {
		severity string
		days     int
	}{{"critical", 7}, {"high", 30}, {"medium", 90}, {"low", 0}, {"unknown", 0}, {"", 0}} {
		if got := s.Days(c.severity); got != c.days {
			t.Errorf("Days(%q) = %d, want %d", c.severity, got, c.days)
		}
	}
	if patchsla.Defaults() != s {
		t.Errorf("Defaults() = %+v, want %+v", patchsla.Defaults(), s)
	}
}

func TestSLAValidate(t *testing.T) {
	for _, c := range []struct {
		name string
		sla  patchsla.SLA
		ok   bool
	}{
		{"defaults", patchsla.Defaults(), true},
		{"all zero", patchsla.SLA{}, true},
		{"upper bound", patchsla.SLA{CriticalDays: 365, HighDays: 365, MediumDays: 365, LowDays: 365}, true},
		{"negative", patchsla.SLA{CriticalDays: -1}, false},
		{"above bound", patchsla.SLA{LowDays: 366}, false},
	} {
		if err := c.sla.Validate(); (err == nil) != c.ok {
			t.Errorf("%s: Validate() = %v, want ok %v", c.name, err, c.ok)
		}
	}
}

// TestDaysOpenAndBreached (plan M13c decision 18): days open are whole days since first_seen_at; a finding breaches
// when it is open longer than its severity's SLA, never when the severity has none.
func TestDaysOpenAndBreached(t *testing.T) {
	now := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
	s := patchsla.SLA{CriticalDays: 7, HighDays: 30, MediumDays: 90}
	for _, c := range []struct {
		name     string
		severity string
		age      time.Duration
		days     int
		breached bool
	}{
		{"critical 8 days", "critical", 8 * 24 * time.Hour, 8, true},
		{"critical exactly 7 days", "critical", 7 * 24 * time.Hour, 7, false},
		{"critical 7 days 23 hours", "critical", 8*24*time.Hour - time.Hour, 7, false},
		{"high 31 days", "high", 31 * 24 * time.Hour, 31, true},
		{"medium 90 days", "medium", 90 * 24 * time.Hour, 90, false},
		{"low has no SLA", "low", 400 * 24 * time.Hour, 400, false},
		{"first seen in the future", "critical", -time.Hour, 0, false},
	} {
		days := patchsla.DaysOpen(now.Add(-c.age), now)
		if days != c.days {
			t.Errorf("%s: DaysOpen = %d, want %d", c.name, days, c.days)
		}
		if got := s.Breached(c.severity, days); got != c.breached {
			t.Errorf("%s: Breached = %v, want %v", c.name, got, c.breached)
		}
	}
}

func TestCompareVersions(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want int
	}{
		{"1.0", "1.0", 0},
		{"1.0-1", "1.0-2", -1},
		{"1.10", "1.9", 1},
		{"1.0~rc1", "1.0", -1},
		{"1.0", "1.0+b1", -1},
		{"1:0.9", "2.0", 1},
		{"0:1.0", "1.0", 0},
		{"2.34-0ubuntu3.2", "2.34-0ubuntu3.10", -1},
		{"1.0a", "1.0", 1},
		{"1.0.0", "1.0", 1},
		{"1.00", "1.0", 0},
		{"8.9p1-3ubuntu0.10", "8.9p1-3ubuntu0.6", 1},
	} {
		if got := patchsla.CompareVersions(c.a, c.b); got != c.want {
			t.Errorf("CompareVersions(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
		if got := patchsla.CompareVersions(c.b, c.a); got != -c.want {
			t.Errorf("CompareVersions(%q, %q) = %d, want %d", c.b, c.a, got, -c.want)
		}
	}
}

// TestComputeEmpty (plan M13c §3.8 L10): a report without inventory has empty sections and no devices, never nil
// lists.
func TestComputeEmpty(t *testing.T) {
	r := patchsla.Compute(patchsla.Input{SLA: patchsla.Defaults(), Now: time.Now()})
	if r.Summary != (patchsla.Summary{}) || r.DevicesTotal != 0 {
		t.Errorf("summary = %+v, total %d", r.Summary, r.DevicesTotal)
	}
	if r.BySeverity == nil || r.ByGroup == nil || r.Devices == nil || r.Catalog == nil ||
		len(r.BySeverity)+len(r.ByGroup)+len(r.Devices)+len(r.Catalog) != 0 {
		t.Errorf("sections = %+v", r)
	}
	if got := r.BreachedBySeverity(); len(got) != 4 || got["critical"] != 0 || got["low"] != 0 {
		t.Errorf("BreachedBySeverity = %v", got)
	}
}

func id(n byte) uuid.UUID { return uuid.UUID{n} }

// TestCompute (plan M13c decision 18): breached counts per severity and group, percentiles of the days open, devices
// most breaches first, and the devices behind a pinned required version.
func TestCompute(t *testing.T) {
	now := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
	ago := func(days int) time.Time { return now.Add(-time.Duration(days) * 24 * time.Hour) }
	a, b, c, outside := id(1), id(2), id(3), id(9)
	in := patchsla.Input{
		SLA:     patchsla.SLA{CriticalDays: 7, HighDays: 30, MediumDays: 90},
		Now:     now,
		Devices: []patchsla.Device{{ID: a, Hostname: "alpha"}, {ID: b, Hostname: "bravo"}, {ID: c, Hostname: "charlie"}},
		Memberships: []patchsla.Membership{
			{GroupID: id(20), Name: "laptops", DeviceID: a}, {GroupID: id(20), Name: "laptops", DeviceID: c},
			{GroupID: id(21), Name: "desktops", DeviceID: b}, {GroupID: id(21), Name: "desktops", DeviceID: outside},
		},
		Findings: []patchsla.Finding{
			{DeviceID: a, CVE: "CVE-1", Package: "openssl", Severity: "critical", FixedVersion: "3.0.2-1", FirstSeenAt: ago(8)},
			{DeviceID: a, CVE: "CVE-2", Package: "curl", Severity: "high", FixedVersion: "8.0", FirstSeenAt: ago(40)},
			{DeviceID: a, CVE: "CVE-3", Package: "zlib", Severity: "low", FixedVersion: "1.3", FirstSeenAt: ago(500)},
			{DeviceID: b, CVE: "CVE-1", Package: "openssl", Severity: "critical", FixedVersion: "3.0.2-1", FirstSeenAt: ago(2)},
			{DeviceID: c, CVE: "CVE-4", Package: "vim", Severity: "medium", FixedVersion: "9.1", FirstSeenAt: ago(91)},
			{DeviceID: outside, CVE: "CVE-1", Package: "openssl", Severity: "critical", FixedVersion: "3.0.2-1", FirstSeenAt: ago(30)},
		},
		Pins: []patchsla.Pin{{AssignmentID: id(30), Entry: "Firefox", RequiredVersion: "120.0"},
			{AssignmentID: id(31), Entry: "Chrome", RequiredVersion: "1:2.0"}},
		Installs: []patchsla.Install{
			{AssignmentID: id(30), DeviceID: a, Version: "119.0"}, {AssignmentID: id(30), DeviceID: b, Version: "120.0"},
			{AssignmentID: id(30), DeviceID: c, Version: "121.0~beta"}, {AssignmentID: id(30), DeviceID: outside, Version: "1.0"},
			{AssignmentID: id(31), DeviceID: a, Version: "3.0"},
		},
	}
	r := patchsla.Compute(in)

	if r.Summary != (patchsla.Summary{Devices: 3, Compliant: 1, Breached: 2}) {
		t.Errorf("summary = %+v", r.Summary)
	}
	want := []patchsla.SeverityStats{
		{Severity: "critical", FindingsOpen: 2, FindingsBreached: 1, MedianDaysOpen: 2, P90DaysOpen: 8},
		{Severity: "high", FindingsOpen: 1, FindingsBreached: 1, MedianDaysOpen: 40, P90DaysOpen: 40},
		{Severity: "medium", FindingsOpen: 1, FindingsBreached: 1, MedianDaysOpen: 91, P90DaysOpen: 91},
		{Severity: "low", FindingsOpen: 1, FindingsBreached: 0, MedianDaysOpen: 500, P90DaysOpen: 500},
	}
	if len(r.BySeverity) != len(want) {
		t.Fatalf("by severity = %+v", r.BySeverity)
	}
	for i := range want {
		if r.BySeverity[i] != want[i] {
			t.Errorf("by severity %d = %+v, want %+v", i, r.BySeverity[i], want[i])
		}
	}
	if got := r.BreachedBySeverity(); got["critical"] != 1 || got["high"] != 1 || got["medium"] != 1 || got["low"] != 0 {
		t.Errorf("BreachedBySeverity = %v", got)
	}
	if len(r.ByGroup) != 2 || r.ByGroup[0] != (patchsla.GroupStats{GroupID: id(21), Name: "desktops", Devices: 1, Breached: 0}) ||
		r.ByGroup[1] != (patchsla.GroupStats{GroupID: id(20), Name: "laptops", Devices: 2, Breached: 2}) {
		t.Errorf("by group = %+v", r.ByGroup)
	}
	if r.DevicesTotal != 2 || len(r.Devices) != 2 || r.Devices[0].Hostname != "alpha" || r.Devices[1].Hostname != "charlie" {
		t.Fatalf("devices = %+v (total %d)", r.Devices, r.DevicesTotal)
	}
	if got := r.Devices[0].Breached; len(got) != 2 ||
		got[0] != (patchsla.Breach{CVE: "CVE-1", Package: "openssl", Severity: "critical", DaysOpen: 8, FixedVersion: "3.0.2-1", SLADays: 7}) ||
		got[1].CVE != "CVE-2" || got[1].SLADays != 30 {
		t.Errorf("alpha breaches = %+v", got)
	}
	if len(r.Catalog) != 2 || r.Catalog[0].Entry != "Firefox" || r.Catalog[0].DevicesBehind != 1 ||
		r.Catalog[1].Entry != "Chrome" || r.Catalog[1].DevicesBehind != 1 {
		t.Errorf("catalog = %+v", r.Catalog)
	}
}

// TestComputeDeviceCap: Compute lists every device with a breach; Capped stops the list at DeviceCap and the total
// counts every device.
func TestComputeDeviceCap(t *testing.T) {
	now := time.Now()
	in := patchsla.Input{SLA: patchsla.Defaults(), Now: now}
	for i := range patchsla.DeviceCap + 5 {
		d := uuid.New()
		in.Devices = append(in.Devices, patchsla.Device{ID: d, Hostname: "h" + d.String()})
		in.Findings = append(in.Findings, patchsla.Finding{DeviceID: d, CVE: "CVE-" + string(rune('a'+i%26)), Severity: "critical",
			FirstSeenAt: now.Add(-30 * 24 * time.Hour)})
	}
	full := patchsla.Compute(in)
	if len(full.Devices) != patchsla.DeviceCap+5 {
		t.Errorf("uncapped devices = %d", len(full.Devices))
	}
	r := full.Capped(patchsla.DeviceCap)
	if r.DevicesTotal != patchsla.DeviceCap+5 || len(r.Devices) != patchsla.DeviceCap || r.Summary.Breached != patchsla.DeviceCap+5 {
		t.Errorf("total %d, listed %d, breached %d", r.DevicesTotal, len(r.Devices), r.Summary.Breached)
	}
}
