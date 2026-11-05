package app

import (
	"encoding/csv"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestPeriodResolve(t *testing.T) {
	now := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	got, err := Period{}.resolve(now)
	if err != nil || !got.To.Equal(now) || got.To.Sub(got.From) != AccessReviewDefaultPeriod {
		t.Fatalf("default: %+v %v", got, err)
	}
	if _, err := (Period{From: now.Add(-AccessReviewMaxPeriod)}).resolve(now); err != nil {
		t.Fatalf("exactly 400 days: %v", err)
	}
	for name, p := range map[string]Period{
		"401 days": {From: now.Add(-AccessReviewMaxPeriod - time.Hour)},
		"reversed": {From: now, To: now.Add(-time.Hour)},
		"empty":    {From: now, To: now},
	} {
		if _, err := p.resolve(now); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestCSVSafe(t *testing.T) {
	for in, want := range map[string]string{
		"=1+1": "'=1+1", "+1": "'+1", "-1": "'-1", "@SUM(A1)": "'@SUM(A1)", "\tx": "'\tx", "\rx": "'\rx",
		"plain": "plain", "": "", "a=b": "a=b",
	} {
		if got := csvSafe(in); got != want {
			t.Errorf("csvSafe(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestReportCSVMarksTruncatedSections(t *testing.T) {
	r := Report{Reveals: Section[Reveal]{Total: 1500, Items: []Reveal{{Code: "local_admin.revealed", Actor: "=evil"}}}}
	b, err := r.csv()
	if err != nil {
		t.Fatal(err)
	}
	out := string(b)
	if !strings.Contains(out, "reveals_truncated,,,,,,,,,,,,,,,,,,,1500") || !strings.Contains(out, "'=evil") {
		t.Fatalf("csv:\n%s", out)
	}
}

func TestReportCSVKeepsEmptyRole(t *testing.T) {
	at := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	r := Report{Roles: []RoleMembers{{Role: "org_auditor", SnapshotTakenAt: &at}}}
	b, err := r.csv()
	if err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(strings.NewReader(string(b))).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	header := rows[0]
	col := func(row []string, name string) string { return row[slices.Index(header, name)] }
	var found bool
	for _, row := range rows[1:] {
		if col(row, "section") == "role_members" {
			found = true
			if col(row, "role") != "org_auditor" || col(row, "count") != "0" || col(row, "at") != "2026-11-04T12:00:00Z" {
				t.Errorf("empty role row: %v", row)
			}
		}
	}
	if !found {
		t.Fatalf("no role_members row for an empty role:\n%s", b)
	}
}
