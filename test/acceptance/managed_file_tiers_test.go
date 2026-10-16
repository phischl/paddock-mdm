package acceptance

import (
	"net/http"
	"testing"

	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
)

// TestManagedFileTiers is gate S6 of plan M8s (ADR 0034 decision 2): a sensitive path needs an organization
// administrator with a step-up, a denied path is refused for everyone, an ordinary path stays with the operator, an
// execute bit makes any path sensitive, and an auditor manages nothing.
func TestManagedFileTiers(t *testing.T) {
	admin := adminUser(t, "s6")
	noStepUp := withoutStepUp(t, admin)
	operator := operatorUser(t)
	auditor := login(t, env.Bob)
	sfx := uniqueSuffix()
	file := func(path, mode string) map[string]any {
		return map[string]any{"path": path, "mode": mode, "content": "s6\n"}
	}
	post := func(p *env.Portal, body map[string]any) env.Response {
		return call(t, p, http.MethodPost, "/api/v1/managed-files", body)
	}
	cron := file("/etc/cron.d/s6-"+sfx, "0644")

	expectRefusal(t, admin.Portal, post(operator.Portal, cron), http.StatusForbidden, "forbidden", "managed_file.created")
	expectRefusal(t, admin.Portal, post(noStepUp, cron), http.StatusForbidden, "step_up_required", "managed_file.created")

	admin.stepUp(t)
	res := post(admin.Portal, cron)
	expectStatus(t, res, http.StatusCreated, "")
	createdID(t, admin.Portal, "/api/v1/managed-files", res)
	var created struct {
		Tier                 string  `json:"tier"`
		SensitiveConfirmedAt *string `json:"sensitive_confirmed_at"`
	}
	if err := res.JSON(&created); err != nil || created.Tier != "sensitive" || created.SensitiveConfirmedAt == nil {
		t.Fatalf("sensitive file %s (%v)", res.Body, err)
	}
	if ev := expectOneEvent(t, admin.Portal, res.RequestID, "managed_file.created", "success"); ev.Params["tier"] != "sensitive" || !ev.Actor.StepUp {
		t.Fatalf("event %+v", ev)
	}

	for _, denied := range []string{"/etc/ld.so.preload", "/etc/tmpfiles.d/s6-" + sfx + ".conf"} {
		res := post(admin.Portal, file(denied, "0644"))
		expectStatus(t, res, http.StatusUnprocessableEntity, "path_not_allowed")
		expectOneEvent(t, admin.Portal, res.RequestID, "managed_file.created", "failure")
	}

	ordinary := "/etc/myapp-" + sfx + "/app.conf"
	res = post(operator.Portal, file(ordinary, "0644"))
	expectStatus(t, res, http.StatusCreated, "")
	createdID(t, admin.Portal, "/api/v1/managed-files", res)
	if ev := expectOneEvent(t, admin.Portal, res.RequestID, "managed_file.created", "success"); ev.Params["tier"] != "ordinary" {
		t.Fatalf("event %+v", ev)
	}
	expectRefusal(t, admin.Portal, post(operator.Portal, file(ordinary, "0755")), http.StatusForbidden, "forbidden", "managed_file.created")
	expectRefusal(t, admin.Portal, post(auditor, file("/etc/myapp-"+sfx+"/other.conf", "0644")), http.StatusForbidden, "forbidden", "managed_file.created")
}
