package acceptance

import (
	"strings"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/test/acceptance/internal/stack"
)

// TestOpsListenersOffEdge is decisions-alpha10 A10-1: the worker, the escrow-reader and the revocation-issuer sit on
// network edge only to call the public names, so a container on edge (a compromised Caddy, Authentik or Fleet) reaches
// neither their ops port 9090 nor the escrow-reader's API, while Prometheus's network data still reaches 9090 (the
// positive control).
func TestOpsListenersOffEdge(t *testing.T) {
	ctx := testContext(t, 3*time.Minute)
	image, err := stack.Image("GO_BUILD_IMAGE")
	if err != nil {
		t.Fatal(err)
	}
	curl := func(network, url string) string {
		t.Helper()
		out, err := stack.Docker(ctx, nil, "run", "--rm", "--network", stack.Network(network), image, "sh", "-c",
			"curl -sS -m 5 -o /dev/null -w 'status=%{http_code} ' "+url+"; echo exit=$?")
		if err != nil {
			t.Fatalf("from network %s: %s: %v", network, url, err)
		}
		return out
	}
	for _, role := range []string{"paddock-worker", "paddock-escrow-reader", "paddock-revocation-issuer"} {
		t.Run(role, func(t *testing.T) {
			url := "http://" + role + ":9090/healthz"
			if out := curl("edge", url); !strings.Contains(out, "exit=7") {
				t.Errorf("from network edge: %s: %q, want connection refused (curl exit 7)", url, out)
			}
			if out := curl("data", url); !strings.Contains(out, "status=200") || !strings.Contains(out, "exit=0") {
				t.Errorf("from network data: %s: %q, want 200", url, out)
			}
		})
	}
	t.Run("escrow-reader API", func(t *testing.T) {
		if out := curl("edge", "-X POST http://paddock-escrow-reader:8080/internal/v1/decrypt"); !strings.Contains(out, "exit=7") {
			t.Errorf("from network edge: %q, want connection refused (curl exit 7)", out)
		}
	})
}
