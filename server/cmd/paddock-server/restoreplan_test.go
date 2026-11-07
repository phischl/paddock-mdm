package main

import (
	"bytes"
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/app"
)

// TestParseRestoreReport: the command line restore.sh sends (PDK-734), and the lines it never sends are usage errors.
func TestParseRestoreReport(t *testing.T) {
	plan := uuid.New()
	in, err := parseRestoreReport([]string{"--outcome", "failed", "--operator", "alice", "--source", "target",
		"--components", "postgres,openbao", "--plan", plan.String(), "--at", "2026-11-03T11:00:00Z", "--component", "fleet",
		"--detail", "the step fleet failed"})
	if err != nil || in.Outcome != "failed" || in.Operator != "alice" || in.Source != "target" ||
		strings.Join(in.Components, ",") != "postgres,openbao" || *in.PlanID != plan ||
		!in.At.Equal(time.Date(2026, 11, 3, 11, 0, 0, 0, time.UTC)) || in.Component != "fleet" || in.Detail != "the step fleet failed" {
		t.Fatalf("%+v %v", in, err)
	}
	if in, err := parseRestoreReport([]string{"--outcome", "completed", "--operator", "root", "--source", "set",
		"--components", "backup-repo"}); err != nil || in.PlanID != nil || in.At != nil {
		t.Fatalf("without a plan: %+v %v", in, err)
	}
	if in, err := parseRestoreReport([]string{"--outcome", "completed", "--operator", "root", "--source", "set",
		"--components", "escrow", "--escrow-skipped-destroyed", "3"}); err != nil || in.EscrowSkippedDestroyed == nil ||
		*in.EscrowSkippedDestroyed != 3 {
		t.Fatalf("escrow skip count: %+v %v", in, err)
	}
	for _, args := range [][]string{
		{"--operator", "alice", "--source", "set", "--components", "postgres"},
		{"--outcome", "completed", "--operator", "alice", "--source", "set"},
		{"--outcome", "completed", "--operator", "alice", "--source", "set", "--components", "postgres", "--plan", "x"},
		{"--outcome", "completed", "--operator", "alice", "--source", "set", "--components", "postgres", "--at", "yesterday"},
		{"--outcome", "completed", "--operator", "alice", "--source", "set", "--components", "postgres", "extra"},
		{"--outcome", "completed", "--operator", "alice", "--source", "set", "--components", "escrow", "--escrow-skipped-destroyed", "-1"},
		{"--outcome", "completed", "--operator", "alice", "--source", "set", "--components", "escrow", "--escrow-skipped-destroyed", "two"},
	} {
		if _, err := parseRestoreReport(args); !errors.Is(err, errUsage) {
			t.Errorf("%v: %v", args, err)
		}
	}
}

// restoreField is restore_plan_field of restore.sh (PDK-734): a string value, empty for null.
func restoreField(json, name string) string {
	m := regexp.MustCompile(`"` + name + `"[[:space:]]*:[[:space:]]*"([A-Za-z0-9:._+-]*)"`).FindStringSubmatch(json)
	if m == nil {
		return ""
	}
	return m[1]
}

// TestPrintHostPlan: restore.sh reads the fields it needs with its fixed patterns; any plan but an approved one is
// refused with exit 1 after it is printed.
func TestPrintHostPlan(t *testing.T) {
	id, target := uuid.New(), uuid.New()
	at := time.Date(2026, 11, 3, 11, 0, 0, 0, time.FixedZone("CET", 3600))
	expires := at.Add(24 * time.Hour)
	name := "offsite"
	var out bytes.Buffer
	p := app.Plan{ID: id, Kind: "point_in_time", State: "approved", ExpiresAt: &expires, At: &at, Source: "target",
		SourceTargetID: &target, SourceTargetName: &name, Components: []string{"postgres", "openbao"}}
	if err := printHostPlan(&out, p); err != nil {
		t.Fatal(err)
	}
	js := out.String()
	for field, want := range map[string]string{"state": "approved", "expires_at": "2026-11-04T10:00:00Z",
		"at": "2026-11-03T10:00:00Z", "source_target_id": target.String(), "source_target_name": "offsite"} {
		if got := restoreField(js, field); got != want {
			t.Errorf("%s = %q, want %q in %s", field, got, want, js)
		}
	}
	if !strings.Contains(js, `"components":["postgres","openbao"]`) {
		t.Errorf("components: %s", js)
	}

	out.Reset()
	repo := app.Plan{ID: id, Kind: "components", State: "expired", ExpiresAt: &expires, Source: "repo", Components: []string{"fleet"}}
	if err := printHostPlan(&out, repo); !errors.Is(err, errPlanNotExecutable) || exitCode(err) != 1 {
		t.Fatalf("expired plan: %v", err)
	}
	if restoreField(out.String(), "state") != "expired" || restoreField(out.String(), "at") != "" ||
		restoreField(out.String(), "source_target_id") != "" || !strings.Contains(out.String(), `"source_target_id":null`) {
		t.Errorf("expired plan JSON: %s", out.String())
	}

	// ON DELETE SET NULL: an approved target plan without its target must not run from the local repository.
	out.Reset()
	orphan := app.Plan{ID: id, Kind: "components", State: "approved", ExpiresAt: &expires, Source: "target",
		Components: []string{"fleet"}}
	if err := printHostPlan(&out, orphan); !errors.Is(err, errPlanNotExecutable) || exitCode(err) != 1 {
		t.Fatalf("plan without its target: %v", err)
	}
}
