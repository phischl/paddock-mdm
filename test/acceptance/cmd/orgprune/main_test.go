package main

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
)

func fakeDo(status int, body string) doFunc {
	return func(context.Context, string, string, any) (env.Response, error) {
		return env.Response{Status: status, Body: []byte(body)}, nil
	}
}

func TestRequireDevelopment(t *testing.T) {
	for _, c := range []struct {
		name    string
		status  int
		body    string
		refused bool
	}{
		{"development reports step_up", http.StatusOK, `{"step_up":{"window_seconds":300,"max_auth_age_seconds":60}}`, false},
		{"production has no step_up", http.StatusOK, `{"user":"x"}`, true},
		{"null step_up", http.StatusOK, `{"step_up":null}`, true},
		{"not authorized", http.StatusUnauthorized, `{}`, true},
		{"unreadable body", http.StatusOK, `not json`, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			err := requireDevelopment(context.Background(), fakeDo(c.status, c.body))
			if (err != nil) != c.refused {
				t.Fatalf("err = %v, refused = %v", err, c.refused)
			}
		})
	}
}

func TestListGateOrgsKeepsOnlyGateNames(t *testing.T) {
	body := `{"items":[
		{"id":"1","slug":"gate-aaaaaaaa","name":"Gate gate-aaaaaaaa","status":"active"},
		{"id":"2","slug":"gate-notours","name":"My Gate gate-x","status":"active"},
		{"id":"3","slug":"acme","name":"Acme Corporation","status":"active"},
		{"id":"4","slug":"gate-bbbbbbbb","name":"Gate gate-bbbbbbbb","status":"active"}]}`
	var paths []string
	do := func(_ context.Context, _, path string, _ any) (env.Response, error) {
		paths = append(paths, path)
		return env.Response{Status: http.StatusOK, Body: []byte(body)}, nil
	}
	orgs, err := listGateOrgs(context.Background(), do)
	if err != nil {
		t.Fatal(err)
	}
	if len(orgs) != 2 || orgs[0].ID != "1" || orgs[1].ID != "4" {
		t.Fatalf("selected %+v, want organizations 1 and 4", orgs)
	}
	if len(paths) != 1 || !strings.Contains(paths[0], "q=gate-") {
		t.Fatalf("requests %v, want one search for gate-", paths)
	}
}

func TestListGateOrgsFailsOnListError(t *testing.T) {
	if _, err := listGateOrgs(context.Background(), fakeDo(http.StatusForbidden, `{}`)); err == nil {
		t.Fatal("a refused list must fail, not report no organizations")
	}
}
