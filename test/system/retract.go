package system

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/pkg/protocol"
	"github.com/phischl/paddock-mdm/test/acceptance/devicesim"
	"github.com/phischl/paddock-mdm/test/acceptance/portal"
)

// retractRelease ends the rollout of a gate's release, so that it does not stay the release the devices of later
// gates update to (a broken supervisor of S-UP2b restarted the agents of the uninstall gates mid-removal). It is the
// system tests' counterpart of the acceptance gates' retractRelease: a running rollout is halted by hand; a completed
// one cannot be (409), so a simulated device of the organization reports agent.update_failed and the worker halts it
// — such a rollout must have been started with failure_threshold_min 1 and failure_threshold_percent 0.
func retractRelease(t *testing.T, version string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	root, err := portal.Login(ctx, portal.PlatformAdmin)
	if err != nil {
		t.Fatalf("retract %s: %v", version, err)
	}
	status := func() string {
		res, err := root.Do(ctx, http.MethodGet, "/api/platform/v1/agent-releases/"+version, nil)
		if err != nil || res.Status != http.StatusOK {
			t.Fatalf("release %s: %v HTTP %d %s", version, err, res.Status, res.Body)
		}
		var r struct {
			Rollout *struct {
				Status string `json:"status"`
			} `json:"rollout"`
		}
		if err := json.Unmarshal(res.Body, &r); err != nil {
			t.Fatalf("release %s: %v", version, err)
		}
		if r.Rollout == nil {
			return ""
		}
		return r.Rollout.Status
	}
	if status() == "running" {
		// A running rollout may complete between the read and the halt; the 409 then leads to the report below.
		if res, err := root.Do(ctx, http.MethodPost, "/api/platform/v1/agent-releases/"+version+"/rollout/halt", nil); err != nil {
			t.Fatalf("halt %s: %v", version, err)
		} else if res.Status != http.StatusOK && res.Status != http.StatusConflict {
			t.Fatalf("halt %s: HTTP %d %s", version, res.Status, res.Body)
		}
	}
	switch status() {
	case "halted", "":
		return
	case "completed":
		reportUpdateFailed(ctx, t, version)
	}
	Until(t, "rollout of "+version+" halted", 3*time.Minute, 5*time.Second, nil, func() bool { return status() == "halted" })
}

// reportUpdateFailed enrolls a simulated device in alice's organization and reports agent.update_failed of version
// from it. The device stays enrolled like the simulated devices of the acceptance gates; its token is revoked.
func reportUpdateFailed(ctx context.Context, t *testing.T, version string) {
	t.Helper()
	alice, err := portal.Login(ctx, portal.Alice)
	if err != nil {
		t.Fatal(err)
	}
	res, err := alice.Do(ctx, http.MethodPost, "/api/v1/enrollment-tokens", map[string]any{
		"name": "systest retract " + unique(), "max_uses": 1, "auto_approve": true,
		"expires_at": time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
	})
	if err != nil || res.Status != http.StatusCreated {
		t.Fatalf("enrollment token: %v HTTP %d %s", err, res.Status, res.Body)
	}
	var created struct {
		Token struct {
			ID string `json:"id"`
		} `json:"token"`
		EnrollmentConfig protocol.EnrollmentConfig `json:"enrollment_config"`
	}
	if err := json.Unmarshal(res.Body, &created); err != nil {
		t.Fatalf("enrollment token %s: %v", res.Body, err)
	}
	defer func() {
		if res, err := alice.Do(ctx, http.MethodPost, "/api/v1/enrollment-tokens/"+created.Token.ID+"/revoke", nil); err != nil ||
			res.Status != http.StatusOK {
			t.Errorf("revoke enrollment token: %v HTTP %d %s", err, res.Status, res.Body)
		}
	}()
	client, err := portal.NewHTTPClient()
	if err != nil {
		t.Fatal(err)
	}
	d, err := devicesim.New(created.EnrollmentConfig, client)
	if err != nil {
		t.Fatal(err)
	}
	if res, err := d.Enroll(ctx, "systest-retract-"+unique()); err != nil || res.Status != http.StatusAccepted {
		t.Fatalf("enroll: %v HTTP %d %s", err, res.Status, res.Body)
	}
	s, err := d.WaitEnrollment(ctx, func(s protocol.EnrollStatus) bool { return s.Status != protocol.EnrollProcessing })
	if err != nil || s.Status != protocol.EnrollActive {
		t.Fatalf("enrollment %+v, %v; want active", s, err)
	}
	data, _ := json.Marshal(map[string]string{"version": version, "from_version": "0.0.0-devicesim", "outcome": "update_failed"})
	sent, err := d.SendEvents(ctx, []protocol.Event{{EventSeq: 1, Type: protocol.EventAgentUpdateFailed, OccurredAt: time.Now(), Data: data}})
	if err != nil || sent.Status != http.StatusAccepted {
		t.Fatalf("events: %v HTTP %d %s", err, sent.Status, sent.Body)
	}
}
