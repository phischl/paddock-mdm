package acceptance

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/paddock-mdm/paddock/test/acceptance/internal/env"
	"github.com/paddock-mdm/paddock/test/acceptance/internal/stack"
)

// TestAuthentikBrandFlows is gate I-recovery (plan M3.1 decision 5, AC2): paddock-worker has set the default brand's
// recovery and device-code flows to Paddock's (make dev-seed waits for it), so creating a local user returns a
// recovery link without any manual change in Authentik.
func TestAuthentikBrandFlows(t *testing.T) {
	ak, err := env.NewAuthentik()
	if err != nil {
		t.Fatal(err)
	}
	mismatches, err := ak.BrandFlowMismatches(testContext(t, time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if len(mismatches) > 0 {
		t.Fatalf("default brand: %s", strings.Join(mismatches, "; "))
	}
	createLocalUser(t, login(t, env.Alice), "ir")
}

// TestDeviceLoginThrottle: production Compose passes PADDOCK_DEVICE_LOGIN_THROTTLE (default 600/hour) to both
// Authentik containers as the device authorization throttle (plan M3.1 decision 2).
func TestDeviceLoginThrottle(t *testing.T) {
	ctx := testContext(t, time.Minute)
	for _, c := range []struct{ value, want string }{{"", "600/hour"}, {"50/minute", "50/minute"}} {
		out, err := stack.ComposeProduction(ctx, []string{"PADDOCK_DEVICE_LOGIN_THROTTLE=" + c.value}, "config", "--format", "json")
		if err != nil {
			t.Fatal(err)
		}
		var cfg struct {
			Services map[string]struct {
				Environment map[string]*string `json:"environment"`
			} `json:"services"`
		}
		// docker compose may print warnings before the JSON document.
		start := strings.Index(out, "{")
		if start < 0 {
			t.Fatalf("no JSON in docker compose config output: %s", out)
		}
		if err := json.Unmarshal([]byte(out[start:]), &cfg); err != nil {
			t.Fatal(err)
		}
		for _, svc := range []string{"authentik-server", "authentik-worker"} {
			got := cfg.Services[svc].Environment["AUTHENTIK_THROTTLE__PROVIDERS__OAUTH2__DEVICE"]
			if got == nil || *got != c.want {
				t.Errorf("%s with PADDOCK_DEVICE_LOGIN_THROTTLE=%q: throttle %v, want %s", svc, c.value, got, c.want)
			}
		}
	}
}
