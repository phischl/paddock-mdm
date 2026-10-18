package agent

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"testing"

	"github.com/phischl/paddock-mdm/agent/internal/buildinfo"
	"github.com/phischl/paddock-mdm/agent/internal/reconcile/fakesys"
	"github.com/phischl/paddock-mdm/agent/internal/supervisorpkg"
	"github.com/phischl/paddock-mdm/agent/internal/testgw"
)

func reportedComponents(t *testing.T, g *testgw.Gateway, i int) map[string]string {
	t.Helper()
	var h struct {
		Components map[string]string `json:"components"`
	}
	if err := json.Unmarshal(g.Checkins[i].Req.Health, &h); err != nil {
		t.Fatal(err)
	}
	return h.Components
}

// TestCheckinReportsComponents (plan M8d decision 52): every check-in carries the five components; a package that is
// not installed is "", a supervisor whose version cannot be read keeps the last value.
func TestCheckinReportsComponents(t *testing.T) {
	ctx := context.Background()
	g := testgw.New(t)
	a := newAgent(t, g)
	sys := fakesys.New()
	sys.Packages["himmelblau"], sys.Versions["himmelblau"] = true, "4.0.4-1"
	sys.Packages["fleet-osquery"], sys.Versions["fleet-osquery"] = true, "1.43.0"
	a.d.Sys = sys
	supervisor, supervisorErr := "0.1.0-alpha.4", error(nil)
	a.d.SupervisorVersion = func(context.Context) (string, error) { return supervisor, supervisorErr }
	a.Cycle(ctx)
	want := map[string]string{"paddockd": buildinfo.Version, "paddock_supervisor": "0.1.0-alpha.4", "paddock_revoke": "",
		"himmelblau": "4.0.4-1", "fleetd": "1.43.0"}
	if got := reportedComponents(t, g, 0); !maps.Equal(got, want) {
		t.Fatalf("components %v, want %v", got, want)
	}
	supervisorErr = errors.New("exec failed")
	sys.Packages["himmelblau"] = false
	a.Cycle(ctx)
	want["himmelblau"] = ""
	if got := reportedComponents(t, g, 1); !maps.Equal(got, want) {
		t.Fatalf("after a failed supervisor lookup %v, want %v", got, want)
	}
}

// TestSupervisorVersion: the supervisor's own answer; "" without the binary.
func TestSupervisorVersion(t *testing.T) {
	a := newAgent(t, testgw.New(t))
	if v, err := supervisorVersion(context.Background(), a.d.Layout); err != nil || v != "" {
		t.Fatalf("without a supervisor: %q, %v", v, err)
	}
	bin := a.d.Layout.Join(supervisorpkg.Binary)
	if err := os.MkdirAll(filepath.Dir(bin), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bin, []byte("#!/bin/sh\n[ \"$1\" = version ] && echo 0.1.0-alpha.4\n"), 0o755); err != nil { //nolint:gosec // a test executable
		t.Fatal(err)
	}
	if v, err := supervisorVersion(context.Background(), a.d.Layout); err != nil || v != "0.1.0-alpha.4" {
		t.Fatalf("supervisor version %q, %v", v, err)
	}
}
