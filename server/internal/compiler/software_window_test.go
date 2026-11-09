package compiler_test

import (
	"testing"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/pkg/bundle"
	"github.com/phischl/paddock-mdm/server/internal/domain/statechange"
)

// TestSoftwareWindowsAndUrgent (PDK-809, plan M13c decisions 5 and 7, decision Q17): a device in two groups gets the
// union of their maintenance windows in its software section, identical windows once; a device in neither gets none; a
// package of an urgent assignment of the winning intent is urgent, one whose urgent assignment lost the merge is not.
func TestSoftwareWindowsAndUrgent(t *testing.T) {
	w := newWorld(t)
	both := w.v2Device("{1,2}", w.g1, w.g2)
	first := w.v2Device("{1,2}", w.g1)
	none := w.v2Device("{1,2}")
	for _, d := range []uuid.UUID{both, first, none} {
		w.ubuntu(d, "amd64")
	}
	nano := w.entry("Nano", nil, [4]string{"ubuntu", "*", "*", "nano"})
	vim := w.entry("Vim", nil, [4]string{"ubuntu", "*", "*", "vim"})
	w.assign(nano, nil, "required", "latest", nil)
	urgentForbid := w.assign(vim, w.g1, "forbid", "latest", nil)
	w.assign(vim, nil, "required", "latest", nil)
	w.exec("UPDATE software_assignment SET urgent = true, reason = 'CVE' WHERE id = $1 OR catalog_entry_id = $2 AND device_group_id IS NULL", urgentForbid, nano)
	w.exec(`INSERT INTO device_group_maintenance_window (organization_id, device_group_id, days, start_minute, duration_minutes, timezone)
		VALUES ($1, $2, '{5,1}', 1320, 120, 'Europe/Berlin'), ($1, $3, '{6,7}', 0, 1440, 'UTC')`, w.org, w.g1, w.g2)
	w.mustCompile(statechange.ScopeOrg, w.org)

	s := w.fetch(both).Software
	if s == nil || len(s.Windows) != 2 {
		t.Fatalf("windows of a device in two groups: %+v", s)
	}
	if got := s.Windows[0]; got.Timezone != "Europe/Berlin" || len(got.Days) != 2 || got.Days[0] != 1 || got.Days[1] != 5 ||
		got.StartMinute != 1320 || got.DurationMinutes != 120 {
		t.Fatalf("first window %+v", got)
	}
	if got := s.Windows[1]; got.Timezone != "UTC" || got.DurationMinutes != 1440 {
		t.Fatalf("second window %+v", got)
	}
	if err := bundle.ValidateSoftware(*s); err != nil {
		t.Fatalf("compiled section fails ValidateSoftware: %v", err)
	}
	if p := pkgOf(s, "nano"); p == nil || !p.Urgent {
		t.Fatalf("urgent required package %+v", p)
	}
	if p := pkgOf(s, "vim"); p == nil || p.Intent != bundle.SoftwareForbid || !p.Urgent {
		t.Fatalf("urgent forbid package %+v", p)
	}
	if s := w.fetch(first).Software; s == nil || len(s.Windows) != 1 || s.Windows[0].Timezone != "Europe/Berlin" {
		t.Fatalf("windows of a device in one group: %+v", s)
	}
	s = w.fetch(none).Software
	if s == nil || s.Windows != nil {
		t.Fatalf("windows of a device in no group: %+v", s)
	}
	if p := pkgOf(s, "vim"); p == nil || p.Intent != bundle.SoftwareRequired || p.Urgent {
		t.Fatalf("a package whose urgent assignment does not apply: %+v", p)
	}

	// The same window in both groups is carried once.
	w.exec("UPDATE device_group_maintenance_window SET days = '{1,5}', start_minute = 1320, duration_minutes = 120, timezone = 'Europe/Berlin' WHERE device_group_id = $1", w.g2)
	w.mustCompile(statechange.ScopeOrg, w.org)
	if s := w.fetch(both).Software; s == nil || len(s.Windows) != 1 {
		t.Fatalf("identical windows: %+v", s)
	}

	// Only groups with a window contribute to the union (Q17, architect decision A10-16): a device in a group with a
	// window and in one without stays restricted to the first group's window; a device whose only group has no window
	// is never restricted.
	only2 := w.v2Device("{1,2}", w.g2)
	w.ubuntu(only2, "amd64")
	w.exec("DELETE FROM device_group_maintenance_window WHERE device_group_id = $1", w.g2)
	w.mustCompile(statechange.ScopeOrg, w.org)
	if s := w.fetch(both).Software; s == nil || len(s.Windows) != 1 || s.Windows[0].Timezone != "Europe/Berlin" || s.Windows[0].StartMinute != 1320 {
		t.Fatalf("union with a group without a window: %+v", s)
	}
	if s := w.fetch(only2).Software; s == nil || s.Windows != nil {
		t.Fatalf("a device whose only group has no window: %+v", s)
	}
}
