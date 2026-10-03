package acceptance

import (
	"net/http"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/paddock-mdm/paddock/test/acceptance/internal/env"
)

// TestOrganizationIsolation is gate A2 (plan M0 §8, AC2): every /api/v1 operation called by an acme admin with
// globex IDs answers 404, and no response ever contains a globex ID — including the audit log.
func TestOrganizationIsolation(t *testing.T) {
	doc := loadSpec(t)
	w := &isolationWorld{alice: login(t, env.Alice), carol: login(t, env.Carol)}
	acme, globex := orgOf(t, w.alice), orgOf(t, w.carol)
	if acme == globex {
		t.Fatal("alice and carol are in the same organization; run `make dev-seed`")
	}
	w.globexIDs = append(w.globexIDs, globex.String(), whoami(t, w.carol).ID)

	// Globex activity that must stay invisible to acme, including its audit events.
	globexGroup(t, w)
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
