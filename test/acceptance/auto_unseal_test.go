package acceptance

import (
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
	"github.com/phischl/paddock-mdm/test/acceptance/internal/stack"
)

const (
	autoUnsealPath    = "/api/platform/v1/openbao/auto-unseal"
	disclaimerVersion = "2026-10-17"
	acknowledgementEN = "I understand and accept the risk"
	acknowledgementDE = "Ich verstehe und akzeptiere das Risiko"
)

// autoUnsealStatus is the part of AutoUnsealStatus the gates read.
type autoUnsealStatus struct {
	State                  string  `json:"state"`
	DisclaimerVersion      string  `json:"disclaimer_version"`
	AcknowledgementVersion *string `json:"acknowledgement_version"`
	Acknowledgement        *string `json:"acknowledgement"`
	AcknowledgedBy         *string `json:"acknowledged_by"`
	DisabledBy             *string `json:"disabled_by"`
	Unsealer               struct {
		Running       bool       `json:"running"`
		SharesPresent bool       `json:"shares_present"`
		UnsealCount   int64      `json:"unseal_count"`
		LastUnsealAt  *time.Time `json:"last_unseal_at"`
	} `json:"unsealer"`
	Seal struct {
		Reachable bool   `json:"reachable"`
		Sealed    bool   `json:"sealed"`
		Type      string `json:"type"`
		Threshold int    `json:"threshold"`
		Shares    int    `json:"shares"`
	} `json:"seal"`
}

func getAutoUnseal(t *testing.T, p *env.Portal) autoUnsealStatus {
	t.Helper()
	res := call(t, p, http.MethodGet, autoUnsealPath, nil)
	expectStatus(t, res, http.StatusOK, "")
	var s autoUnsealStatus
	if err := res.JSON(&s); err != nil {
		t.Fatal(err)
	}
	return s
}

func enableAutoUnseal(t *testing.T, p *env.Portal, version, ack string) env.Response {
	t.Helper()
	return call(t, p, http.MethodPost, autoUnsealPath+"/enable", map[string]any{"disclaimer_version": version, "acknowledgement": ack})
}

// restoreAutoUnseal returns the platform setting to the state the gate found (a new session and step-up, so that it
// also works after a failed assertion).
func restoreAutoUnseal(t *testing.T, found string) {
	t.Helper()
	root := login(t, env.PlatformAdmin)
	if getAutoUnseal(t, root).State == found {
		return
	}
	stepUp(t, root, env.PlatformAdmin, true)
	if found == "enabled" {
		expectStatus(t, enableAutoUnseal(t, root, disclaimerVersion, acknowledgementEN), http.StatusOK, "")
		return
	}
	expectStatus(t, call(t, root, http.MethodPost, autoUnsealPath+"/disable", nil), http.StatusOK, "")
}

// TestAutoUnsealAcknowledgement is gates U1–U3 (plan M8u §9): platform administrators read the setting; enabling
// needs a step-up, the current disclaimer version and an acknowledgement sentence; disabling needs a step-up; an
// organization administrator and an API token are refused; every attempt is in the audit trail.
func TestAutoUnsealAcknowledgement(t *testing.T) {
	root := login(t, env.PlatformAdmin)
	alice := login(t, env.Alice)
	idx := auditIndex(t)
	found := getAutoUnseal(t, root)
	t.Cleanup(func() { restoreAutoUnseal(t, found.State) })

	// U1
	if found.DisclaimerVersion != disclaimerVersion || !found.Seal.Reachable || found.Seal.Type != "shamir" ||
		found.Seal.Threshold != 3 || found.Seal.Shares != 5 {
		t.Fatalf("GET: %+v", found)
	}
	expectStatus(t, call(t, alice, http.MethodGet, autoUnsealPath, nil), http.StatusForbidden, "forbidden")
	stepUp(t, alice, env.Alice, true)
	res := postAPIToken(t, alice, apiTokenName("auto-unseal"), "org_admin", 2*time.Hour)
	expectStatus(t, res, http.StatusCreated, "")
	var created apiTokenCreated
	if err := res.JSON(&created); err != nil {
		t.Fatal(err)
	}
	if res := call(t, tokenPortal(t, created.Secret), http.MethodGet, autoUnsealPath, nil); res.Status < 401 || res.Status == http.StatusOK {
		t.Fatalf("GET with an API token: %d", res.Status)
	}
	res = enableAutoUnseal(t, alice, disclaimerVersion, acknowledgementEN)
	expectStatus(t, res, http.StatusForbidden, "forbidden")
	// An organization administrator's denied platform action is recorded in its own organization (ActionRunner).
	expectOneEvent(t, alice, res.RequestID, "platform.auto_unseal_enabled", "denied")

	if found.State == "enabled" {
		stepUp(t, root, env.PlatformAdmin, true)
		expectStatus(t, call(t, root, http.MethodPost, autoUnsealPath+"/disable", nil), http.StatusOK, "")
		root = login(t, env.PlatformAdmin)
	}

	// U2
	res = enableAutoUnseal(t, root, disclaimerVersion, acknowledgementEN)
	expectStatus(t, res, http.StatusForbidden, "step_up_required")
	expectOneIndexEvent(t, idx, platformOrg, "correlation_id = $1", res.RequestID, "platform.auto_unseal_enabled", "denied", auditPollTimeout)

	stepUp(t, root, env.PlatformAdmin, true)
	res = enableAutoUnseal(t, root, "2000-01-01", acknowledgementEN)
	expectStatus(t, res, http.StatusConflict, "disclaimer_outdated")
	outdated := res.RequestID
	res = enableAutoUnseal(t, root, disclaimerVersion, "I accept")
	expectStatus(t, res, http.StatusBadRequest, "invalid_request")
	mismatch := res.RequestID
	res = enableAutoUnseal(t, root, disclaimerVersion, acknowledgementDE)
	expectStatus(t, res, http.StatusOK, "")
	var enabled autoUnsealStatus
	if err := res.JSON(&enabled); err != nil {
		t.Fatal(err)
	}
	ev := expectOneIndexEvent(t, idx, platformOrg, "correlation_id = $1", res.RequestID, "platform.auto_unseal_enabled", "success", auditPollTimeout)
	if enabled.State != "enabled" || enabled.AcknowledgedBy == nil || *enabled.AcknowledgedBy != ev.ActorDisplay ||
		enabled.AcknowledgementVersion == nil || *enabled.AcknowledgementVersion != disclaimerVersion ||
		enabled.Acknowledgement == nil || *enabled.Acknowledgement != acknowledgementDE {
		t.Fatalf("enabled: %+v (actor %q)", enabled, ev.ActorDisplay)
	}
	if ev.Params["disclaimer_version"] != disclaimerVersion || ev.Params["acknowledgement"] != acknowledgementDE ||
		ev.Params["previous_state"] != "disabled" {
		t.Fatalf("event params: %v", ev.Params)
	}
	expectOneIndexEvent(t, idx, platformOrg, "correlation_id = $1", outdated, "platform.auto_unseal_enabled", "failure", auditPollTimeout)
	expectOneIndexEvent(t, idx, platformOrg, "correlation_id = $1", mismatch, "platform.auto_unseal_enabled", "failure", auditPollTimeout)

	// U3
	root = login(t, env.PlatformAdmin)
	res = call(t, root, http.MethodPost, autoUnsealPath+"/disable", nil)
	expectStatus(t, res, http.StatusForbidden, "step_up_required")
	expectOneIndexEvent(t, idx, platformOrg, "correlation_id = $1", res.RequestID, "platform.auto_unseal_disabled", "denied", auditPollTimeout)
	stepUp(t, root, env.PlatformAdmin, true)
	res = call(t, root, http.MethodPost, autoUnsealPath+"/disable", nil)
	expectStatus(t, res, http.StatusOK, "")
	var disabled autoUnsealStatus
	if err := res.JSON(&disabled); err != nil {
		t.Fatal(err)
	}
	if disabled.State != "disabled" || disabled.DisabledBy == nil || disabled.Acknowledgement == nil ||
		*disabled.Acknowledgement != acknowledgementDE || disabled.AcknowledgedBy == nil {
		t.Fatalf("disabled: %+v", disabled)
	}
	ev = expectOneIndexEvent(t, idx, platformOrg, "correlation_id = $1", res.RequestID, "platform.auto_unseal_disabled", "success", auditPollTimeout)
	if ev.Params["previous_state"] != "enabled" || ev.Params["method"] != "portal" {
		t.Fatalf("event params: %v", ev.Params)
	}
}

// unsealDevelopment unseals the development OpenBao with the stored development shares.
func unsealDevelopment(t *testing.T) {
	t.Helper()
	root, err := stack.RepoRoot()
	if err != nil {
		t.Error(err)
		return
	}
	cmd := exec.CommandContext(testContext(t, 3*time.Minute), "bash", filepath.Join(root, "deploy", "compose", "scripts", "openbao-bootstrap.sh"), "unseal") //nolint:gosec // fixed script
	cmd.Dir = root
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Errorf("unseal OpenBao: %v: %s", err, out)
	}
}

// waitAutoUnseal polls GET until cond holds or timeout passes and returns the last status.
func waitAutoUnseal(t *testing.T, p *env.Portal, timeout time.Duration, cond func(autoUnsealStatus) bool) (autoUnsealStatus, bool) {
	t.Helper()
	var s autoUnsealStatus
	for deadline := time.Now().Add(timeout); ; time.Sleep(2 * time.Second) {
		res := call(t, p, http.MethodGet, autoUnsealPath, nil)
		// While OpenBao is sealed the api answers on (its session keys are loaded); a failed request is retried.
		if res.Status == http.StatusOK && res.JSON(&s) == nil && cond(s) {
			return s, true
		}
		if time.Now().After(deadline) {
			return s, false
		}
	}
}

// restartOpenBao restarts the development OpenBao container; it comes back sealed.
func restartOpenBao(t *testing.T) {
	t.Helper()
	if out, err := stack.Compose(testContext(t, 3*time.Minute), nil, "restart", "openbao"); err != nil {
		t.Fatalf("restart openbao: %v: %s", err, out)
	}
}

// TestAutoUnsealRestart is gate U4 (plan M8u §9). It restarts OpenBao twice, so it runs only with
// PADDOCK_ACCEPTANCE_DISRUPTIVE=1, in its own CI step; the cleanup unseals OpenBao with the development shares
// whatever happened.
func TestAutoUnsealRestart(t *testing.T) {
	if os.Getenv("PADDOCK_ACCEPTANCE_DISRUPTIVE") != "1" {
		t.Skip("restarts OpenBao; set PADDOCK_ACCEPTANCE_DISRUPTIVE=1")
	}
	root := login(t, env.PlatformAdmin)
	idx := auditIndex(t)
	found := getAutoUnseal(t, root)
	t.Cleanup(func() {
		unsealDevelopment(t)
		restoreAutoUnseal(t, found.State)
	})

	if found.State != "enabled" {
		stepUp(t, root, env.PlatformAdmin, true)
		expectStatus(t, enableAutoUnseal(t, root, disclaimerVersion, acknowledgementEN), http.StatusOK, "")
	}
	before, ok := waitAutoUnseal(t, root, 70*time.Second, func(s autoUnsealStatus) bool {
		return s.Unsealer.Running && s.Unsealer.SharesPresent
	})
	if !ok {
		t.Fatalf("the development unsealer does not report shares within 70 s: %+v", before)
	}

	restartedAt := time.Now()
	restartOpenBao(t)
	after, ok := waitAutoUnseal(t, root, 90*time.Second, func(s autoUnsealStatus) bool {
		return s.Seal.Reachable && !s.Seal.Sealed && s.Unsealer.UnsealCount == before.Unsealer.UnsealCount+1
	})
	if !ok || after.Unsealer.LastUnsealAt == nil ||
		(before.Unsealer.LastUnsealAt != nil && !after.Unsealer.LastUnsealAt.After(*before.Unsealer.LastUnsealAt)) {
		t.Fatalf("not unsealed automatically within 90 s: before %+v, after %+v", before, after)
	}
	var events []env.IndexEvent
	for deadline := time.Now().Add(auditPollTimeout + 30*time.Second); ; time.Sleep(2 * time.Second) {
		var err error
		events, err = idx.Events(testContext(t, time.Minute), platformOrg,
			"code = 'platform.openbao_auto_unsealed' AND outcome = 'success' AND occurred_at > $1", restartedAt)
		if err != nil {
			t.Fatal(err)
		}
		if len(events) > 0 || time.Now().After(deadline) {
			break
		}
	}
	if len(events) != 1 || events[0].Params["unseals"] != float64(1) || events[0].ActorDisplay != "paddock-unsealer" {
		t.Fatalf("events of the automatic unseal: %+v", events)
	}

	root = login(t, env.PlatformAdmin)
	stepUp(t, root, env.PlatformAdmin, true)
	expectStatus(t, call(t, root, http.MethodPost, autoUnsealPath+"/disable", nil), http.StatusOK, "")
	restartOpenBao(t)
	time.Sleep(30 * time.Second)
	sealed := getAutoUnseal(t, root)
	if !sealed.Seal.Sealed || sealed.Unsealer.UnsealCount != after.Unsealer.UnsealCount {
		t.Fatalf("OpenBao was unsealed although automatic unseal is disabled: %+v", sealed)
	}
}
