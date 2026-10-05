package selftest

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/paddock-mdm/paddock/agent/internal/paths"
	"github.com/paddock-mdm/paddock/agent/internal/testgw"
	"github.com/paddock-mdm/paddock/pkg/bundle"
)

func result(r Report, name string) string {
	for _, c := range r.Checks {
		if c.Name == name {
			return c.Result
		}
	}
	return ""
}

func TestRun(t *testing.T) {
	g := testgw.New(t)
	l, _ := g.Enrolled(t)
	r := Run(context.Background(), l)
	// The fake's certificate is not trusted by the system pool: the server is "unreachable", which is inconclusive.
	if !r.OK || result(r, "agent_config") != Pass || result(r, "identity_key") != Pass || result(r, "bundle") != Skipped ||
		result(r, "server") != Inconclusive {
		t.Fatalf("report %+v", r)
	}
	// A cached schema 2 bundle verifies: a release must pass its self-test on a device with login management.
	env, _ := testgw.SignedBundle(t, bundle.Bundle{
		SchemaVersion: bundle.SchemaVersion2, BundleVersion: 3, DeviceID: testgw.DeviceID, OrganizationID: testgw.OrgID, IssuedAt: time.Now(),
	})
	if err := os.WriteFile(l.Bundle(), env, 0o600); err != nil {
		t.Fatal(err)
	}
	if r := Run(context.Background(), l); !r.OK || result(r, "bundle") != Pass {
		t.Fatalf("cached schema 2 bundle: %+v", r)
	}
	if err := os.WriteFile(l.Bundle(), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if r := Run(context.Background(), l); r.OK || result(r, "bundle") != Fail {
		t.Fatalf("a cached bundle that does not verify must fail: %+v", r)
	}
	if r := Run(context.Background(), paths.Layout{Root: t.TempDir()}); r.OK || result(r, "agent_config") != Fail || result(r, "server") != Skipped {
		t.Fatalf("unconfigured device: %+v", r)
	}
}
