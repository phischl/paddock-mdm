package prodcheck_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/phischl/paddock-mdm/server/internal/prodcheck"
)

// shippedBrokerDefinitions are the permissions of the shipped definitions template.
func shippedBrokerDefinitions(t *testing.T) []prodcheck.BrokerPermission {
	t.Helper()
	f, err := os.Open(filepath.Join("..", "..", "..", "deploy", "compose", "rabbitmq", "definitions.json.tmpl"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	want, err := prodcheck.ParseBrokerDefinitions(f)
	if err != nil {
		t.Fatal(err)
	}
	return want
}

// TestBrokerPermissions (PDK-1017, main §44): the broker's permissions equal to the shipped definitions pass; a missing
// user, other patterns (the audit writer's write of a release before paddock.offboarding) and a user the definitions
// do not name fail with their names and patterns; no password of the template appears.
func TestBrokerPermissions(t *testing.T) {
	want := shippedBrokerDefinitions(t)
	byUser := map[string]prodcheck.BrokerPermission{}
	for _, p := range want {
		byUser[p.User] = p
	}
	if w := byUser["audit_writer"]; w.Write != `^paddock\.offboarding$` || w.Read != `^audit\.writer$` || w.Configure != "^$" {
		t.Fatalf("shipped audit_writer permissions %+v", w)
	}
	if w := byUser["worker"]; w.Write != "^$" || !strings.Contains(w.Read, `worker\.offboarding`) {
		t.Fatalf("shipped worker permissions %+v", w)
	}
	raw, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	got, err := prodcheck.ParseBrokerPermissions(strings.NewReader(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	if r := prodcheck.CheckBrokerPermissions(prodcheck.BrokerPermissions{Want: want, Got: got}); !r.OK ||
		r.Item != prodcheck.BrokerPermissionsItem {
		t.Fatalf("equal permissions: %+v", r)
	}

	var older []prodcheck.BrokerPermission
	for _, p := range got {
		switch p.User {
		case "worker":
			continue
		case "audit_writer":
			p.Write = "^$"
		}
		older = append(older, p)
	}
	older = append(older, prodcheck.BrokerPermission{User: "guest", Configure: ".*", Write: ".*", Read: ".*"})
	r := prodcheck.CheckBrokerPermissions(prodcheck.BrokerPermissions{Want: want, Got: older})
	for _, s := range []string{`audit_writer: configure "^$" write "^$" read "^audit\\.writer$", want configure "^$" write "^paddock\\.offboarding$"`,
		"worker: missing", "guest: has permissions on vhost paddock that the definitions do not grant", "./paddock bootstrap broker"} {
		if r.OK || !strings.Contains(r.Detail, s) {
			t.Errorf("older broker: %+v lacks %q", r, s)
		}
	}
	if strings.Contains(r.Detail, "PASSWORD") {
		t.Fatalf("the finding names a password placeholder: %s", r.Detail)
	}

	if _, err := prodcheck.ParseBrokerDefinitions(strings.NewReader(`{"permissions":[]}`)); err == nil {
		t.Fatal("definitions without permissions on the vhost passed")
	}
	if _, err := prodcheck.ParseBrokerPermissions(strings.NewReader(`not json`)); err == nil {
		t.Fatal("an unreadable listing passed")
	}
}
