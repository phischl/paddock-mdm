// Package patchsla is the organization's patch SLA and the patch compliance report computed against it (plan M13c
// decisions 17 and 18): how many days a vulnerability with a fixed version may stay open per severity, which open
// findings exceed it, and which devices run a pinned required package older than its pin.
package patchsla

import (
	"cmp"
	"fmt"
	"slices"
	"time"

	"github.com/google/uuid"
)

// Severities of a finding, most severe first.
const (
	SeverityCritical = "critical"
	SeverityHigh     = "high"
	SeverityMedium   = "medium"
	SeverityLow      = "low"
)

// Severities returns the severities most severe first.
func Severities() []string {
	return []string{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow}
}

// MaxDays bounds every SLA value; 0 means the severity has no SLA.
const MaxDays = 365

// DeviceCap bounds the devices of the report's view (Capped); DevicesTotal counts every device with a breach.
const DeviceCap = 1000

// SLA is the number of days a finding of each severity may stay open; 0 is no SLA.
type SLA struct {
	CriticalDays, HighDays, MediumDays, LowDays int
}

// Defaults returns the SLA of a new organization: 7, 30 and 90 days, none for low.
func Defaults() SLA {
	return SLA{CriticalDays: 7, HighDays: 30, MediumDays: 90, LowDays: 0}
}

// Validate checks that every value lies between 0 and MaxDays.
func (s SLA) Validate() error {
	for _, v := range []struct {
		name string
		days int
	}{{"critical_days", s.CriticalDays}, {"high_days", s.HighDays}, {"medium_days", s.MediumDays}, {"low_days", s.LowDays}} {
		if v.days < 0 || v.days > MaxDays {
			return fmt.Errorf("%s must be between 0 and %d", v.name, MaxDays)
		}
	}
	return nil
}

// Days returns the SLA of severity; 0 for no SLA and for an unknown severity.
func (s SLA) Days(severity string) int {
	switch severity {
	case SeverityCritical:
		return s.CriticalDays
	case SeverityHigh:
		return s.HighDays
	case SeverityMedium:
		return s.MediumDays
	case SeverityLow:
		return s.LowDays
	}
	return 0
}

// DaysOpen returns the whole days between firstSeen and now; 0 for a firstSeen in the future.
func DaysOpen(firstSeen, now time.Time) int {
	if !now.After(firstSeen) {
		return 0
	}
	return int(now.Sub(firstSeen) / (24 * time.Hour))
}

// Breached reports whether a finding of severity open for daysOpen days exceeds the SLA: the severity has one and the
// finding is open longer than it.
func (s SLA) Breached(severity string, daysOpen int) bool {
	days := s.Days(severity)
	return days > 0 && daysOpen > days
}

func severityRank(severity string) int {
	if i := slices.Index(Severities(), severity); i >= 0 {
		return i
	}
	return len(Severities())
}

// Device is a device in the scope of the report.
type Device struct {
	ID       uuid.UUID
	Hostname string
}

// Membership is a device's membership in a device group.
type Membership struct {
	GroupID  uuid.UUID
	Name     string
	DeviceID uuid.UUID
}

// Finding is an open finding with a fixed version.
type Finding struct {
	DeviceID     uuid.UUID
	CVE          string
	Package      string
	Severity     string
	FixedVersion string
	FirstSeenAt  time.Time
}

// Pin is a required assignment pinned to a version.
type Pin struct {
	AssignmentID    uuid.UUID
	Entry           string
	RequiredVersion string
}

// Install is an installed package of a pin's entry on a device the pin targets.
type Install struct {
	AssignmentID uuid.UUID
	DeviceID     uuid.UUID
	Version      string
}

// Input is everything the report is computed from.
type Input struct {
	SLA         SLA
	Now         time.Time
	Devices     []Device
	Memberships []Membership
	Findings    []Finding
	Pins        []Pin
	Installs    []Install
}

// Summary counts the devices in scope, those without a breach and those with at least one.
type Summary struct {
	Devices, Compliant, Breached int
}

// SeverityStats are the open findings of one severity: how many, how many exceed the SLA, and the median and 90th
// percentile of their days open (nearest rank).
type SeverityStats struct {
	Severity         string
	FindingsOpen     int
	FindingsBreached int
	MedianDaysOpen   int
	P90DaysOpen      int
}

// GroupStats are the devices in scope of one device group and how many of them have a breach.
type GroupStats struct {
	GroupID  uuid.UUID
	Name     string
	Devices  int
	Breached int
}

// Breach is a finding open longer than its severity's SLA.
type Breach struct {
	CVE          string
	Package      string
	Severity     string
	DaysOpen     int
	FixedVersion string
	SLADays      int
}

// DeviceBreaches are the breaches of one device.
type DeviceBreaches struct {
	DeviceID uuid.UUID
	Hostname string
	Breached []Breach
}

// CatalogRow is a pinned required assignment and the number of devices it targets that run an older version.
type CatalogRow struct {
	AssignmentID    uuid.UUID
	Entry           string
	RequiredVersion string
	DevicesBehind   int
}

// Report is the patch compliance report; every list is empty, never nil, when there is nothing to show.
type Report struct {
	Summary    Summary
	BySeverity []SeverityStats
	ByGroup    []GroupStats
	// Devices are the devices with a breach, most breaches first; DevicesTotal counts all of them, also after Capped.
	Devices      []DeviceBreaches
	DevicesTotal int
	Catalog      []CatalogRow
}

// BreachedBySeverity returns the number of breached findings per severity, every severity present.
func (r Report) BreachedBySeverity() map[string]int {
	out := make(map[string]int, len(Severities()))
	for _, s := range Severities() {
		out[s] = 0
	}
	for _, s := range r.BySeverity {
		out[s.Severity] = s.FindingsBreached
	}
	return out
}

// Compute computes the report. Findings and installs of devices outside in.Devices are ignored.
func Compute(in Input) Report {
	out := Report{BySeverity: []SeverityStats{}, ByGroup: []GroupStats{}, Devices: []DeviceBreaches{}, Catalog: []CatalogRow{}}
	hostnames := make(map[uuid.UUID]string, len(in.Devices))
	for _, d := range in.Devices {
		hostnames[d.ID] = d.Hostname
	}
	open := map[string][]int{}
	breachedCount := map[string]int{}
	breaches := map[uuid.UUID][]Breach{}
	for _, f := range in.Findings {
		if _, ok := hostnames[f.DeviceID]; !ok {
			continue
		}
		days := DaysOpen(f.FirstSeenAt, in.Now)
		open[f.Severity] = append(open[f.Severity], days)
		if in.SLA.Breached(f.Severity, days) {
			breachedCount[f.Severity]++
			breaches[f.DeviceID] = append(breaches[f.DeviceID], Breach{CVE: f.CVE, Package: f.Package, Severity: f.Severity,
				DaysOpen: days, FixedVersion: f.FixedVersion, SLADays: in.SLA.Days(f.Severity)})
		}
	}
	severities := Severities()
	for s := range open {
		if !slices.Contains(severities, s) {
			severities = append(severities, s)
		}
	}
	for _, s := range severities {
		days := open[s]
		if len(days) == 0 {
			continue
		}
		slices.Sort(days)
		out.BySeverity = append(out.BySeverity, SeverityStats{Severity: s, FindingsOpen: len(days),
			FindingsBreached: breachedCount[s], MedianDaysOpen: percentile(days, 50), P90DaysOpen: percentile(days, 90)})
	}

	out.Summary = Summary{Devices: len(in.Devices), Breached: len(breaches), Compliant: len(in.Devices) - len(breaches)}
	out.ByGroup = groupStats(in.Memberships, hostnames, breaches)
	out.Devices, out.DevicesTotal = deviceBreaches(breaches, hostnames)
	out.Catalog = catalogRows(in.Pins, in.Installs, hostnames)
	return out
}

// percentile returns the nearest-rank percentile p (1–100) of sorted, which is not empty.
func percentile(sorted []int, p int) int {
	rank := (p*len(sorted) + 99) / 100
	return sorted[max(rank, 1)-1]
}

func groupStats(memberships []Membership, hostnames map[uuid.UUID]string, breaches map[uuid.UUID][]Breach) []GroupStats {
	out := []GroupStats{}
	index := map[uuid.UUID]int{}
	for _, m := range memberships {
		if _, ok := hostnames[m.DeviceID]; !ok {
			continue
		}
		i, ok := index[m.GroupID]
		if !ok {
			i = len(out)
			index[m.GroupID] = i
			out = append(out, GroupStats{GroupID: m.GroupID, Name: m.Name})
		}
		out[i].Devices++
		if len(breaches[m.DeviceID]) > 0 {
			out[i].Breached++
		}
	}
	slices.SortFunc(out, func(a, b GroupStats) int {
		return cmp.Or(cmp.Compare(a.Name, b.Name), slices.Compare(a.GroupID[:], b.GroupID[:]))
	})
	return out
}

func deviceBreaches(breaches map[uuid.UUID][]Breach, hostnames map[uuid.UUID]string) ([]DeviceBreaches, int) {
	out := make([]DeviceBreaches, 0, len(breaches))
	for id, list := range breaches {
		slices.SortFunc(list, func(a, b Breach) int {
			return cmp.Or(cmp.Compare(severityRank(a.Severity), severityRank(b.Severity)), cmp.Compare(b.DaysOpen, a.DaysOpen),
				cmp.Compare(a.CVE, b.CVE), cmp.Compare(a.Package, b.Package))
		})
		out = append(out, DeviceBreaches{DeviceID: id, Hostname: hostnames[id], Breached: list})
	}
	slices.SortFunc(out, func(a, b DeviceBreaches) int {
		return cmp.Or(cmp.Compare(len(b.Breached), len(a.Breached)), cmp.Compare(a.Hostname, b.Hostname),
			slices.Compare(a.DeviceID[:], b.DeviceID[:]))
	})
	return out, len(out)
}

// Capped returns r with at most n devices; DevicesTotal keeps counting all of them.
func (r Report) Capped(n int) Report {
	r.Devices = r.Devices[:min(len(r.Devices), n)]
	return r
}

func catalogRows(pins []Pin, installs []Install, hostnames map[uuid.UUID]string) []CatalogRow {
	byPin := map[uuid.UUID]map[uuid.UUID]bool{}
	required := make(map[uuid.UUID]string, len(pins))
	for _, p := range pins {
		required[p.AssignmentID] = p.RequiredVersion
	}
	for _, i := range installs {
		pin, ok := required[i.AssignmentID]
		if _, known := hostnames[i.DeviceID]; !ok || !known || CompareVersions(i.Version, pin) >= 0 {
			continue
		}
		if byPin[i.AssignmentID] == nil {
			byPin[i.AssignmentID] = map[uuid.UUID]bool{}
		}
		byPin[i.AssignmentID][i.DeviceID] = true
	}
	out := make([]CatalogRow, len(pins))
	for n, p := range pins {
		out[n] = CatalogRow{AssignmentID: p.AssignmentID, Entry: p.Entry, RequiredVersion: p.RequiredVersion,
			DevicesBehind: len(byPin[p.AssignmentID])}
	}
	return out
}
