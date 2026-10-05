package authentik_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/paddock-mdm/paddock/server/internal/problem"
)

func (f *fakeAuthentik) flowPK(slug string) string {
	for pk, fl := range f.objects["flows"] {
		if fl["slug"] == slug {
			return pk
		}
	}
	return ""
}

// TestEnsureBrandFlows: the default brand of a fresh Authentik gets Paddock's recovery and device-code flows; a second
// run changes nothing, and a flow changed by hand is set back (plan M3.1 decision 5).
func TestEnsureBrandFlows(t *testing.T) {
	f, srv := newFake(t)
	c := client(srv)
	ctx := context.Background()
	check := func() {
		t.Helper()
		b := f.brands[0]
		if b["flow_recovery"] != f.flowPK("paddock-recovery") || b["flow_device_code"] != f.flowPK("paddock-device-code") {
			t.Fatalf("brand flows recovery %v, device code %v", b["flow_recovery"], b["flow_device_code"])
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
