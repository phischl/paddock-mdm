package acceptance

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/test/acceptance/internal/stack"
)

// prometheusURL is the development Prometheus (compose.dev.yaml publishes it on 127.0.0.1:9091).
func prometheusURL() string { return stack.Env("PADDOCK_TEST_PROMETHEUS_URL", "http://127.0.0.1:9091") }

func prometheusGet(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, prometheusURL()+path, nil)
	if err != nil {
		return err
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: %s", path, res.Status)
	}
	return json.NewDecoder(res.Body).Decode(out)
}

type promTargets struct {
	Data struct {
		ActiveTargets []struct {
			Labels    map[string]string `json:"labels"`
			Health    string            `json:"health"`
			LastError string            `json:"lastError"`
		} `json:"activeTargets"`
	} `json:"data"`
}

type promAlerts struct {
	Data struct {
		Alerts []struct {
			Labels map[string]string `json:"labels"`
			State  string            `json:"state"`
		} `json:"alerts"`
	} `json:"data"`
}

// TestObservability is gate P-4 (plan M6a §4, AC3): every scrape target of the running stack is up, and stopping the
// audit writer fires its alert in Prometheus within 15 minutes. `promtool check rules` and the rule tests run in
// `make lint-prometheus`.
func TestObservability(t *testing.T) {
	ctx := testContext(t, 25*time.Minute)

	t.Run("all targets up", func(t *testing.T) {
		roles := map[string]bool{}
		var down []string
		deadline := time.Now().Add(2 * time.Minute)
		for {
			var targets promTargets
			if err := prometheusGet(ctx, "/api/v1/targets?state=active", &targets); err != nil {
				t.Fatalf("Prometheus API (profile observability running?): %v", err)
			}
			down = nil
			for _, tg := range targets.Data.ActiveTargets {
				roles[tg.Labels["role"]] = true
				if tg.Health != "up" {
					down = append(down, fmt.Sprintf("%s: %s %s", tg.Labels["role"], tg.Health, tg.LastError))
				}
			}
			if len(down) == 0 && len(targets.Data.ActiveTargets) > 0 || time.Now().After(deadline) {
				break
			}
			time.Sleep(5 * time.Second)
		}
		if len(down) > 0 {
			t.Fatalf("targets not up: %v", down)
		}
		for _, role := range []string{"paddock-api", "paddock-gateway", "paddock-worker", "paddock-compiler",
			"paddock-outbox-relay", "paddock-escrow-reader", "paddock-revocation-issuer", "paddock-audit-writer", "rabbitmq"} {
			if !roles[role] {
				t.Errorf("no scrape target for %s", role)
			}
		}
	})

	t.Run("stopped audit writer fires its alert", func(t *testing.T) {
		if _, err := stack.Compose(ctx, nil, "--profile", "paddock", "stop", "paddock-audit-writer"); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			ctx := context.Background()
			if _, err := stack.Compose(ctx, nil, "--profile", "paddock", "start", "paddock-audit-writer"); err != nil {
				t.Errorf("restart the audit writer: %v", err)
			}
			if err := stack.WaitHealthy(ctx); err != nil {
				t.Errorf("stack not healthy after the test: %v", err)
			}
		})
		stopped := time.Now()
		deadline := stopped.Add(15 * time.Minute)
		for {
			var alerts promAlerts
			if err := prometheusGet(ctx, "/api/v1/alerts", &alerts); err != nil {
				t.Fatal(err)
			}
			for _, a := range alerts.Data.Alerts {
				if a.Labels["alertname"] == "PaddockRoleDown" && a.Labels["role"] == "paddock-audit-writer" && a.State == "firing" {
					t.Logf("PaddockRoleDown fired %s after the audit writer stopped", time.Since(stopped).Round(time.Second))
					return
				}
			}
			if time.Now().After(deadline) {
				t.Fatalf("PaddockRoleDown for paddock-audit-writer did not fire within 15 minutes: %+v", alerts.Data.Alerts)
			}
			time.Sleep(15 * time.Second)
		}
	})
}
