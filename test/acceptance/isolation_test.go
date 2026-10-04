package acceptance

import (
	"context"
	"net/http"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/paddock-mdm/paddock/test/acceptance/internal/env"
)

// TestOrganizationIsolation is gate A2 (plan M0 §8, AC2): every /api/v1 operation called by an acme admin with
// globex IDs answers 404, and no response ever contains a globex ID — including the audit log and the searches
// and filters of every list (plan M0.2 AC5).
func TestOrganizationIsolation(t *testing.T) {
	doc := loadSpec(t)
	w := &isolationWorld{top: t, alice: login(t, env.Alice), carol: login(t, env.Carol)}
	acme, globex := orgOf(t, w.alice), orgOf(t, w.carol)
	if acme == globex {
		t.Fatal("alice and carol are in the same organization; run `make dev-seed`")
	}
	w.globexIDs = append(w.globexIDs, globex.String(), whoami(t, w.carol).ID)

	// Globex activity that must stay invisible to acme, including its audit events.
	globexGroup(t, w)
	seedGlobexDevices(t, w)
	seedGlobexIdentity(t, w)
	seedGlobexUpstream(t, w)
	ctx := testContext(t, time.Minute)
	var globexEvents []env.AuditEvent
	for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline); time.Sleep(time.Second) {
		var err error
		if globexEvents, err = w.carol.AuditEvents(ctx, "device_group.created"); err != nil {
			t.Fatal(err)
		}
		if len(globexEvents) > 0 {
			break
		}
	}
	if len(globexEvents) == 0 {
		t.Fatal("globex has no audit events to hide")
	}
	for _, e := range globexEvents {
		w.globexIDs = append(w.globexIDs, e.EventID)
	}

	var ops []string
	for path, item := range doc.Paths.Map() {
		if !strings.HasPrefix(path, "/api/v1/") {
			continue
		}
		for method := range item.Operations() {
			ops = append(ops, fixtureKey(method, path))
		}
	}
	sort.Strings(ops)
	if len(ops) == 0 {
		t.Fatal("no /api/v1 operations in the contract")
	}
	for _, op := range ops {
		t.Run(op, func(t *testing.T) {
			fx, ok := isolationFixtures[op]
			if !ok {
				t.Fatalf("operation %s has no fixture mapping in isolation_fixtures.go", op)
			}
			method := strings.SplitN(op, " ", 2)[0]
			path, body := fx.request(t, w)
			res := call(t, w.alice, method, path, body)
			if method == http.MethodPost && res.Status == http.StatusCreated {
				removeCreated(t, w.alice, path, res)
			}
			switch fx.kind {
			case isoItem:
				expectStatus(t, res, http.StatusNotFound, "not_found")
			case isoList, isoOwn:
				if res.Status >= 300 {
					t.Fatalf("HTTP %d: %s", res.Status, res.Body)
				}
			}
			if leaked := containsAny(res.Body, w.globexIDs); leaked != "" {
				t.Fatalf("response contains globex ID %s: %s", leaked, res.Body)
			}
		})
	}

	// Searches and filters of every list find globex data as carol but never as alice.
	for path := range collectionGETs(doc) {
		if !strings.HasPrefix(path, "/api/v1/") {
			continue
		}
		t.Run("search and filters "+path, func(t *testing.T) {
			queries, ok := listIsolationQueries[path]
			if !ok {
				t.Fatalf("collection GET %s has no entry in listIsolationQueries", path)
			}
			resolved, parent := path, listParents[path]
			if parent != nil {
				resolved = strings.Replace(path, "{id}", parent(w), 1)
			}
			for _, q := range queries {
				target := resolved + "?" + q.Encode()
				// The audit pipeline is asynchronous: wait until carol sees this run's globex data.
				var res env.Response
				for deadline := time.Now().Add(30 * time.Second); ; time.Sleep(time.Second) {
					var own struct {
						Total int `json:"total"`
					}
					res = call(t, w.carol, http.MethodGet, target, nil)
					expectStatus(t, res, http.StatusOK, "")
					if err := res.JSON(&own); err == nil && own.Total > 0 {
						break
					}
					if time.Now().After(deadline) {
						t.Fatalf("%s finds no globex data as carol, the check would be vacuous: %s", target, res.Body)
					}
				}
				res = call(t, w.alice, http.MethodGet, target, nil)
				if parent != nil {
					// The parent belongs to globex: not found, exactly like a missing parent.
					expectStatus(t, res, http.StatusNotFound, "not_found")
				} else {
					expectStatus(t, res, http.StatusOK, "")
				}
				if leaked := containsAny(res.Body, w.globexIDs); leaked != "" {
					t.Fatalf("%s as alice contains globex ID %s: %s", target, leaked, res.Body)
				}
				if strings.Contains(string(res.Body), "globex") || strings.Contains(string(res.Body), "carol") {
					t.Fatalf("%s as alice contains globex data: %s", target, res.Body)
				}
			}
		})
	}

	// An upstream group without an acme member cannot be imported by acme: not found, like a missing group.
	t.Run("import of a globex-only upstream group", func(t *testing.T) {
		res := call(t, w.alice, http.MethodPost, "/api/v1/user-groups", map[string]string{
			"slug": "acme-iso-" + uniqueSuffix(), "name": "acme-iso import", "upstream_group_id": w.globexUpstream,
		})
		if res.Status == http.StatusCreated {
			removeCreated(t, w.alice, "/api/v1/user-groups", res)
		}
		expectStatus(t, res, http.StatusNotFound, "not_found")
		if leaked := containsAny(res.Body, w.globexIDs); leaked != "" {
			t.Fatalf("response contains globex ID %s: %s", leaked, res.Body)
		}
	})

	// Nothing was changed in globex by the acme calls.
	for _, id := range w.globexGroups {
		res := call(t, w.carol, http.MethodGet, "/api/v1/device-groups/"+id, nil)
		expectStatus(t, res, http.StatusOK, "")
		if strings.Contains(string(res.Body), "taken over by acme") {
			t.Fatalf("globex group %s was modified by acme", id)
		}
	}
	// And the acme audit log as a whole holds no globex event.
	acmeEvents, err := w.alice.AuditEvents(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range acmeEvents {
		if leaked := containsAny([]byte(e.EventID+" "+e.CorrelationID), w.globexIDs); leaked != "" {
			t.Fatalf("acme audit log contains globex event %s", leaked)
		}
	}
}

// seedGlobexUpstream creates, directly in Authentik, an upstream group "globex-iso upstream …" whose only member is a
// user of paddock.globex: carol may list and import it, alice must neither see nor import it (plan M3b decision 1).
func seedGlobexUpstream(t *testing.T, w *isolationWorld) {
	t.Helper()
	ak, err := env.NewAuthentik()
	if err != nil {
		t.Fatal(err)
	}
	ctx := testContext(t, time.Minute)
	member := newDeviceUser(w.top, ak, "globex-iso-upstream", "globex.test", env.RootGroup("globex"))
	name := "globex-iso upstream " + uniqueSuffix()
	pk, err := ak.EnsureGroup(ctx, name)
	if err != nil {
		t.Fatal(err)
	}
	w.top.Cleanup(func() { _ = ak.Delete(context.Background(), "/core/groups/"+pk+"/") })
	if err := ak.AddToGroup(ctx, member.name, name); err != nil {
		t.Fatal(err)
	}
	w.globexUpstream = pk
	w.globexIDs = append(w.globexIDs, pk)
}

// TestPlatformEndpointsForbiddenForOrganizations extends the isolation gate to the platform API (plan M2b decision
// 20): an organization administrator gets 403 on every /api/platform/ operation.
func TestPlatformEndpointsForbiddenForOrganizations(t *testing.T) {
	doc := loadSpec(t)
	alice := login(t, env.Alice)
	replacer := strings.NewReplacer("{id}", uuid.NewString(), "{version}", "9.9.9", "{arch}", "amd64")
	n := 0
	for path, item := range doc.Paths.Map() {
		if !strings.HasPrefix(path, "/api/platform/") {
			continue
		}
		for method := range item.Operations() {
			n++
			t.Run(method+" "+path, func(t *testing.T) {
				var body any
				if method != http.MethodGet {
					body = map[string]any{}
				}
				expectStatus(t, call(t, alice, method, replacer.Replace(path), body), http.StatusForbidden, "forbidden")
			})
		}
	}
	if n < 8 {
		t.Fatalf("only %d platform operations in the contract", n)
	}
}
