package authentik_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/phischl/paddock-mdm/server/internal/problem"
)

func (f *fakeAuthentik) flowPK(slug string) string {
	for pk, fl := range f.objects["flows"] {
		if fl["slug"] == slug {
			return pk
		}
	}
	return ""
}

// TestEnsureBrandFlows: the default brand of a fresh Authentik gets Paddock's recovery, device-code and authentication
// flows; a second run changes nothing, and a flow changed by hand is set back (plan M3.1 decision 5, plan M8x
// decision 4).
func TestEnsureBrandFlows(t *testing.T) {
	f, srv := newFake(t)
	c := client(srv)
	ctx := context.Background()
	check := func() {
		t.Helper()
		b := f.brands[0]
		if b["flow_recovery"] != f.flowPK("paddock-recovery") || b["flow_device_code"] != f.flowPK("paddock-device-code") ||
			b["flow_authentication"] != f.flowPK("paddock-admin-login") {
			t.Fatalf("brand flows recovery %v, device code %v, authentication %v", b["flow_recovery"],
				b["flow_device_code"], b["flow_authentication"])
		}
	}
	if err := c.EnsureBrandFlows(ctx); err != nil {
		t.Fatal(err)
	}
	check()
	if err := c.EnsureBrandFlows(ctx); err != nil || f.count("PATCH /api/v3/core/brands/") != 1 {
		t.Fatalf("second run: %v, %d PATCHes", err, f.count("PATCH /api/v3/core/brands/"))
	}
	f.brands[0]["flow_recovery"] = f.flowPK("default-provider-invalidation-flow")
	if err := c.EnsureBrandFlows(ctx); err != nil {
		t.Fatal(err)
	}
	check()
}

// TestEnsureBrandFlowsAuthentication: a brand whose authentication flow is Authentik's default flow is patched to
// paddock-admin-login; a brand that already uses it is not patched (plan M8x decision 4).
func TestEnsureBrandFlowsAuthentication(t *testing.T) {
	f, srv := newFake(t)
	c := client(srv)
	ctx := context.Background()
	f.brands[0]["flow_recovery"] = f.flowPK("paddock-recovery")
	f.brands[0]["flow_device_code"] = f.flowPK("paddock-device-code")
	if err := c.EnsureBrandFlows(ctx); err != nil {
		t.Fatal(err)
	}
	if f.count("PATCH /api/v3/core/brands/") != 1 || f.brands[0]["flow_authentication"] != f.flowPK("paddock-admin-login") {
		t.Fatalf("authentication flow %v after %d PATCHes", f.brands[0]["flow_authentication"],
			f.count("PATCH /api/v3/core/brands/"))
	}
	if err := c.EnsureBrandFlows(ctx); err != nil || f.count("PATCH /api/v3/core/brands/") != 1 {
		t.Fatalf("matching brand: %v, %d PATCHes", err, f.count("PATCH /api/v3/core/brands/"))
	}
}

// TestEnsureBrandFlowsNeedsThePortalBlueprint: without the portal login flow the brand stays as it is and the error
// names the blueprint.
func TestEnsureBrandFlowsNeedsThePortalBlueprint(t *testing.T) {
	f, srv := newFake(t)
	delete(f.objects["flows"], f.flowPK("paddock-admin-login"))
	err := client(srv).EnsureBrandFlows(context.Background())
	if !errors.Is(err, problem.UpstreamUnavailable) || !strings.Contains(err.Error(), "paddock-portal.yaml") {
		t.Fatalf("error %v", err)
	}
	if f.count("PATCH /api/v3/core/brands/") != 0 {
		t.Fatal("the brand was changed without the portal login flow")
	}
}

// TestEnsureBrandFlowsNeedsTheBlueprints: before Authentik has applied the recovery blueprint the brand stays as it is
// and the error names the blueprint.
func TestEnsureBrandFlowsNeedsTheBlueprints(t *testing.T) {
	f, srv := newFake(t)
	delete(f.objects["flows"], f.flowPK("paddock-recovery"))
	err := client(srv).EnsureBrandFlows(context.Background())
	if !errors.Is(err, problem.UpstreamUnavailable) || !strings.Contains(err.Error(), "paddock-recovery.yaml") {
		t.Fatalf("error %v", err)
	}
	if f.count("PATCH /api/v3/core/brands/") != 0 || f.brands[0]["flow_recovery"] != nil {
		t.Fatal("the brand was changed without the recovery flow")
	}
}
