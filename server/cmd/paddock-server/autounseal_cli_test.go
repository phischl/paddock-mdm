package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/server/internal/domain/autounseal"
)

type fakeAutoUnsealCLI struct {
	setting  autounseal.Setting
	disabled int
}

func (f *fakeAutoUnsealCLI) Load(context.Context) (autounseal.Setting, error) { return f.setting, nil }
func (f *fakeAutoUnsealCLI) DisableCLI(context.Context) (autounseal.Setting, error) {
	f.disabled++
	f.setting.State, f.setting.DisabledBy = autounseal.StateDisabled, "paddock-server admin"
	return f.setting, nil
}

// TestAutoUnsealCLI covers plan M8u decision 8: verify passes only with the acknowledgement and names it; show prints
// every field; disable runs the CLI use case.
func TestAutoUnsealCLI(t *testing.T) {
	ctx := context.Background()
	f := &fakeAutoUnsealCLI{setting: autounseal.Setting{State: autounseal.StateDisabled}}
	var out bytes.Buffer
	err := runAutoUnsealCLI(ctx, "verify", f, &out)
	if !errors.Is(err, errAutoUnsealNotEnabled) || exitCode(err) != 1 ||
		out.String() != "automatic unseal is not enabled: a platform administrator enables it in the portal first (Platform → OpenBao)\n" {
		t.Fatalf("verify while disabled: %v %q", err, out.String())
	}

	at := time.Date(2026, 10, 17, 9, 30, 0, 0, time.UTC)
	f.setting = autounseal.Setting{State: autounseal.StateEnabled, DisclaimerVersion: "2026-10-17",
		Acknowledgement: "I understand and accept the risk", AcknowledgedBy: "Root Admin", AcknowledgedAt: at,
		Report: autounseal.Report{UnsealCount: 2, LastFailureReason: autounseal.FailureReasonInvalidShare}}
	out.Reset()
	if err := runAutoUnsealCLI(ctx, "verify", f, &out); err != nil ||
		out.String() != "automatic unseal acknowledged by Root Admin on 2026-10-17T09:30:00Z (disclaimer 2026-10-17)\n" {
		t.Fatalf("verify while enabled: %v %q", err, out.String())
	}

	out.Reset()
	if err := runAutoUnsealCLI(ctx, "show", f, &out); err != nil {
		t.Fatal(err)
	}
	for _, line := range []string{"state: enabled", "disclaimer_version: 2026-10-17", "acknowledged_by: Root Admin",
		"acknowledged_at: 2026-10-17T09:30:00Z", "disabled_by: -", "unsealer_running: false", "unsealer_shares_present: false",
		"unseal_count: 2", "failure_count: 0", "last_failure_reason: invalid_share", "current_disclaimer_version: 2026-10-17"} {
		if !strings.Contains(out.String(), line+"\n") {
			t.Errorf("show lacks %q:\n%s", line, out.String())
		}
	}
	if n := strings.Count(out.String(), "\n"); n != 17 {
		t.Errorf("show printed %d lines, want 17", n)
	}

	out.Reset()
	if err := runAutoUnsealCLI(ctx, "disable", f, &out); err != nil || f.disabled != 1 ||
		!strings.Contains(out.String(), "state: disabled\n") || !strings.Contains(out.String(), "disabled_by: paddock-server admin\n") {
		t.Fatalf("disable: %v %d %q", err, f.disabled, out.String())
	}
}
