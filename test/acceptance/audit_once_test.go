package acceptance

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/paddock-mdm/paddock/test/acceptance/internal/authflow"
	"github.com/paddock-mdm/paddock/test/acceptance/internal/env"
	"github.com/paddock-mdm/paddock/test/acceptance/internal/stack"
)

// auditWorld holds the sessions of the portal gate.
type auditWorld struct {
	alice, bob, root *env.Portal
	acme             uuid.UUID
	idx              *env.AuditIndex
}

// auditCase is one request against a privileged operation and the single audit event it must produce.
type auditCase struct {
	name string
	run  func(t *testing.T, w *auditWorld)
}

// auditCases maps every operation with x-paddock-audit ("METHOD path") to its cases: success, validation failure,
// wrong role, not found and conflict where applicable. The gate fails when the contract has a privileged
// operation without an entry here.
var auditCases = map[string][]auditCase{
	"GET /api/auth/callback": {
		{"success", func(t *testing.T, w *auditWorld) {
			p := login(t, env.Alice)
			expectOneEvent(t, w.alice, p.LoginRequestID, "admin.login", "success")
		}},
		{"denied", func(t *testing.T, w *auditWorld) {
			user, pw := tempUser(t, "noadmin", env.RootGroup("acme"))
			p, err := loginAs(t, user, pw)
			if !errors.Is(err, authflow.ErrDenied) {
				t.Fatalf("login = %v, want denied", err)
			}
			expectOneIndexEvent(t, w.idx, platformOrg, "correlation_id = $1", p.LoginRequestID, "admin.login", "denied", auditPollTimeout)
		}},
	},
	"POST /api/v1/device-groups": {
		{"success", func(t *testing.T, w *auditWorld) {
			res := call(t, w.alice, http.MethodPost, "/api/v1/device-groups", map[string]string{"name": uniqueName("audit create")})
			expectStatus(t, res, http.StatusCreated, "")
			expectOneEvent(t, w.alice, res.RequestID, "device_group.created", "success")
		}},
		{"validation failure", func(t *testing.T, w *auditWorld) {
			res := call(t, w.alice, http.MethodPost, "/api/v1/device-groups", map[string]string{"name": ""})
			expectStatus(t, res, http.StatusBadRequest, "invalid_request")
			expectOneEvent(t, w.alice, res.RequestID, "device_group.created", "failure")
		}},
		{"wrong role", func(t *testing.T, w *auditWorld) {
			res := call(t, w.bob, http.MethodPost, "/api/v1/device-groups", map[string]string{"name": uniqueName("auditor")})
			expectStatus(t, res, http.StatusForbidden, "forbidden")
			expectOneEvent(t, w.alice, res.RequestID, "device_group.created", "denied")
		}},
		{"conflict", func(t *testing.T, w *auditWorld) {
			name := createGroup(t, w.alice).name
			res := call(t, w.alice, http.MethodPost, "/api/v1/device-groups", map[string]string{"name": name})
			expectStatus(t, res, http.StatusConflict, "name_taken")
			expectOneEvent(t, w.alice, res.RequestID, "device_group.created", "failure")
		}},
	},
	"PATCH /api/v1/device-groups/{id}": {
		{"success", func(t *testing.T, w *auditWorld) {
			g := createGroup(t, w.alice)
			res := call(t, w.alice, http.MethodPatch, "/api/v1/device-groups/"+g.id, map[string]string{"name": g.name + " renamed"})
			expectStatus(t, res, http.StatusOK, "")
			expectOneEvent(t, w.alice, res.RequestID, "device_group.updated", "success")
		}},
		{"validation failure", func(t *testing.T, w *auditWorld) {
			g := createGroup(t, w.alice)
			res := call(t, w.alice, http.MethodPatch, "/api/v1/device-groups/"+g.id, map[string]string{"name": strings.Repeat("x", 101)})
			expectStatus(t, res, http.StatusBadRequest, "invalid_request")
			expectOneEvent(t, w.alice, res.RequestID, "device_group.updated", "failure")
		}},
		{"wrong role", func(t *testing.T, w *auditWorld) {
			g := createGroup(t, w.alice)
			res := call(t, w.bob, http.MethodPatch, "/api/v1/device-groups/"+g.id, map[string]string{"name": "auditor edit"})
			expectStatus(t, res, http.StatusForbidden, "forbidden")
			expectOneEvent(t, w.alice, res.RequestID, "device_group.updated", "denied")
		}},
		{"not found", func(t *testing.T, w *auditWorld) {
			res := call(t, w.alice, http.MethodPatch, "/api/v1/device-groups/"+uuid.NewString(), map[string]string{"name": "ghost"})
			expectStatus(t, res, http.StatusNotFound, "not_found")
			expectOneEvent(t, w.alice, res.RequestID, "device_group.updated", "failure")
		}},
		{"conflict", func(t *testing.T, w *auditWorld) {
			a, b := createGroup(t, w.alice), createGroup(t, w.alice)
			res := call(t, w.alice, http.MethodPatch, "/api/v1/device-groups/"+b.id, map[string]string{"name": a.name})
			expectStatus(t, res, http.StatusConflict, "name_taken")
			expectOneEvent(t, w.alice, res.RequestID, "device_group.updated", "failure")
		}},
	},
	"DELETE /api/v1/device-groups/{id}": {
		{"success", func(t *testing.T, w *auditWorld) {
			g := createGroup(t, w.alice)
			res := call(t, w.alice, http.MethodDelete, "/api/v1/device-groups/"+g.id, nil)
			expectStatus(t, res, http.StatusNoContent, "")
			expectOneEvent(t, w.alice, res.RequestID, "device_group.deleted", "success")
		}},
		{"validation failure", func(t *testing.T, w *auditWorld) {
			res := call(t, w.alice, http.MethodDelete, "/api/v1/device-groups/not-a-uuid", nil)
			expectStatus(t, res, http.StatusBadRequest, "invalid_request")
			expectOneEvent(t, w.alice, res.RequestID, "device_group.deleted", "failure")
		}},
		{"wrong role", func(t *testing.T, w *auditWorld) {
			g := createGroup(t, w.alice)
			res := call(t, w.bob, http.MethodDelete, "/api/v1/device-groups/"+g.id, nil)
			expectStatus(t, res, http.StatusForbidden, "forbidden")
			expectOneEvent(t, w.alice, res.RequestID, "device_group.deleted", "denied")
		}},
		{"not found", func(t *testing.T, w *auditWorld) {
			res := call(t, w.alice, http.MethodDelete, "/api/v1/device-groups/"+uuid.NewString(), nil)
			expectStatus(t, res, http.StatusNotFound, "not_found")
			expectOneEvent(t, w.alice, res.RequestID, "device_group.deleted", "failure")
		}},
	},
	"POST /api/platform/v1/organizations": {
		{"success", func(t *testing.T, w *auditWorld) {
			res := call(t, w.root, http.MethodPost, "/api/platform/v1/organizations", newOrg())
			expectStatus(t, res, http.StatusCreated, "")
			org := responseID(t, res)
			expectOneIndexEvent(t, w.idx, org, "correlation_id = $1", res.RequestID, "organization.created", "success", auditPollTimeout)
		}},
		{"validation failure", func(t *testing.T, w *auditWorld) {
			res := call(t, w.root, http.MethodPost, "/api/platform/v1/organizations", map[string]string{"slug": "Not A Slug", "name": "x"})
			expectStatus(t, res, http.StatusBadRequest, "invalid_request")
			expectOneIndexEvent(t, w.idx, platformOrg, "correlation_id = $1", res.RequestID, "organization.created", "failure", auditPollTimeout)
		}},
		{"wrong role", func(t *testing.T, w *auditWorld) {
			res := call(t, w.alice, http.MethodPost, "/api/platform/v1/organizations", newOrg())
			expectStatus(t, res, http.StatusForbidden, "forbidden")
			expectOneEvent(t, w.alice, res.RequestID, "organization.created", "denied")
		}},
		{"conflict", func(t *testing.T, w *auditWorld) {
			res := call(t, w.root, http.MethodPost, "/api/platform/v1/organizations", map[string]string{"slug": "acme", "name": "Acme again"})
			expectStatus(t, res, http.StatusConflict, "slug_taken")
			expectOneIndexEvent(t, w.idx, platformOrg, "correlation_id = $1", res.RequestID, "organization.created", "failure", auditPollTimeout)
		}},
	},
}

type group struct{ id, name string }

func createGroup(t *testing.T, p *env.Portal) group {
	t.Helper()
	name := uniqueName("audit gate")
	res := call(t, p, http.MethodPost, "/api/v1/device-groups", map[string]string{"name": name})
	expectStatus(t, res, http.StatusCreated, "")
	return group{id: responseID(t, res).String(), name: name}
}

func responseID(t *testing.T, res env.Response) uuid.UUID {
	t.Helper()
	var body struct {
		ID string `json:"id"`
	}
	if err := res.JSON(&body); err != nil {
		t.Fatal(err)
	}
	return uuid.MustParse(body.ID)
}

func newOrg() map[string]string {
	slug := "gate-" + uuid.NewString()[:8]
	return map[string]string{"slug": slug, "name": "Gate " + slug}
}

func newAuditWorld(t *testing.T) *auditWorld {
	t.Helper()
	w := &auditWorld{alice: login(t, env.Alice), bob: login(t, env.Bob), root: login(t, env.PlatformAdmin), idx: auditIndex(t)}
	w.acme = orgOf(t, w.alice)
	return w
}

// TestAuditExactlyOnce is gate A3 (plan M0 §8, AC3): every privileged action produces exactly one audit event
// with the matching outcome — on success, validation failure, denial, missing resource and conflict.
func TestAuditExactlyOnce(t *testing.T) {
	doc := loadSpec(t)
	w := newAuditWorld(t)
	var ops []string
	for path, item := range doc.Paths.Map() {
		for method, op := range item.Operations() {
			if _, ok := op.Extensions["x-paddock-audit"]; ok {
				ops = append(ops, fixtureKey(method, path))
			}
		}
	}
	sort.Strings(ops)
	if len(ops) < 5 {
		t.Fatalf("only %d privileged operations in the contract", len(ops))
	}
	for _, op := range ops {
		cases, ok := auditCases[op]
		if !ok {
			t.Errorf("privileged operation %s has no cases in audit_once_test.go", op)
			continue
		}
		for _, c := range cases {
			t.Run(op+"/"+c.name, func(t *testing.T) { c.run(t, w) })
		}
	}
}

// TestAuditExternalFailures covers the RunExternal paths of A3 against the real stack: organization creation with
// Authentik stopped (502, exactly one failure event, stored as WORM object), re-provisioning, and a crash of
// paddock-api during the external call (exactly one event with outcome unknown from the reaper). It stops and
// restarts containers.
func TestAuditExternalFailures(t *testing.T) {
	w := newAuditWorld(t)

	t.Run("authentik unreachable", func(t *testing.T) {
		ctx := testContext(t, 10*time.Minute)
		if _, err := stack.Compose(ctx, nil, "stop", "authentik-server"); err != nil {
			t.Fatal(err)
		}
		restarted := false
		restart := func() {
			if restarted {
				return
			}
			restarted = true
			if _, err := stack.Compose(context.Background(), nil, "start", "authentik-server"); err != nil {
				t.Errorf("restart authentik: %v", err)
			}
			if err := stack.WaitHealthy(context.Background()); err != nil {
				t.Errorf("stack not healthy after restarting authentik: %v", err)
			}
		}
		t.Cleanup(restart)

		body := newOrg()
		res := call(t, w.root, http.MethodPost, "/api/platform/v1/organizations", body)
		expectStatus(t, res, http.StatusBadGateway, "upstream_unavailable")
		org := organizationBySlug(t, w.root, body["slug"])
		if org.status != "provisioning_failed" {
			t.Fatalf("organization status %s, want provisioning_failed", org.status)
		}
		ev := expectOneIndexEvent(t, w.idx, org.id, "correlation_id = $1", res.RequestID, "organization.created", "failure", auditPollTimeout)
		if ev.Params["error_code"] != "upstream_unavailable" {
			t.Fatalf("error_code %v, want upstream_unavailable", ev.Params["error_code"])
		}
		// The event is in the WORM store exactly once, under the organization's prefix.
		if !strings.HasPrefix(ev.ObjectKey, "org/"+org.id.String()+"/") {
			t.Fatalf("object key %s is not below org/%s/", ev.ObjectKey, org.id)
		}
		n := 0
		for _, e := range objectEvents(t, rootS3(t), ev.ObjectKey) {
			if e["event_id"] == ev.EventID.String() {
				n++
			}
		}
		if n != 1 {
			t.Fatalf("event %s appears %d times in %s", ev.EventID, n, ev.ObjectKey)
		}

		restart()
		// Re-provisioning the failed organization with the same slug succeeds (AC8).
		var retry env.Response
		for deadline := time.Now().Add(2 * time.Minute); ; time.Sleep(5 * time.Second) {
			retry = call(t, w.root, http.MethodPost, "/api/platform/v1/organizations", body)
			if retry.Status != http.StatusBadGateway || time.Now().After(deadline) {
				break
			}
		}
		expectStatus(t, retry, http.StatusOK, "")
		if got := organizationBySlug(t, w.root, body["slug"]); got.status != "active" {
			t.Fatalf("re-provisioned organization status %s, want active", got.status)
		}
		expectOneIndexEvent(t, w.idx, org.id, "correlation_id = $1", retry.RequestID, "organization.created", "success", auditPollTimeout)
	})

	t.Run("api crash during the external call", func(t *testing.T) {
		ctx := testContext(t, 15*time.Minute)
		// Development-only hooks: delay the external call; reap stuck actions after 20 s instead of 10 min.
		recreate := func(env []string, services ...string) {
			if _, err := stack.Compose(ctx, env, append([]string{"--profile", "paddock", "up", "-d", "--no-deps"}, services...)...); err != nil {
				t.Fatal(err)
			}
			if err := stack.WaitHealthy(ctx); err != nil {
				t.Fatal(err)
			}
		}
		t.Cleanup(func() { recreate(nil, "paddock-api", "paddock-outbox-relay") })
		recreate([]string{"PADDOCK_TEST_EXTERNAL_DELAY=60s", "PADDOCK_REAPER_THRESHOLD=20s"}, "paddock-api", "paddock-outbox-relay")

		body := newOrg()
		done := make(chan struct{})
		go func() {
			defer close(done)
			_, _ = w.root.Do(ctx, http.MethodPost, "/api/platform/v1/organizations", body)
		}()
		time.Sleep(8 * time.Second) // the action row (status started) is committed before the delayed call
		if _, err := stack.Compose(ctx, nil, "kill", "paddock-api"); err != nil {
			t.Fatal(err)
		}
		<-done
		recreate(nil, "paddock-api")

		org := organizationBySlug(t, w.root, body["slug"])
		if org.status != "provisioning" {
			t.Fatalf("organization status %s, want provisioning (the crash left it unfinished)", org.status)
		}
		ev := expectOneIndexEvent(t, w.idx, org.id, "code = $1", "organization.created", "organization.created", "unknown", 4*time.Minute)
		if ev.Params["error_code"] != "reaped" {
			t.Fatalf("error_code %v, want reaped", ev.Params["error_code"])
		}
	})
}

type orgRow struct {
	id     uuid.UUID
	status string
}

func organizationBySlug(t *testing.T, root *env.Portal, slug string) orgRow {
	t.Helper()
	res := call(t, root, http.MethodGet, "/api/platform/v1/organizations?page_size=100&q="+url.QueryEscape(slug), nil)
	expectStatus(t, res, http.StatusOK, "")
	var page struct {
		Items []struct {
			ID     string `json:"id"`
			Slug   string `json:"slug"`
			Status string `json:"status"`
		} `json:"items"`
	}
	if err := res.JSON(&page); err != nil {
		t.Fatal(err)
	}
	for _, o := range page.Items {
		if o.Slug == slug {
			return orgRow{id: uuid.MustParse(o.ID), status: o.Status}
		}
	}
	t.Fatalf("organization %s not found", slug)
	return orgRow{}
}
