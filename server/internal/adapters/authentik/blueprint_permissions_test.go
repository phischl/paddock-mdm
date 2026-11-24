package authentik

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// TestServiceRoleMayDeleteOrganization: the paddock-service role in paddock-portal.yaml holds the view and delete
// permission for every collection offboarding.go touches, and its table lists exactly those collections, so a new
// object kind in DeleteOrganization cannot ship without its permission.
func TestServiceRoleMayDeleteOrganization(t *testing.T) {
	// deletionPermissions maps every collection DeleteOrganization lists and deletes from (plan M17 decision 10) to the
	// permissions the service role needs for it. Authentik answers a missing delete permission with 403, which leaves the
	// deletion step failing forever.
	deletionPermissions := map[string][]string{
		"/api/v3/core/applications/":               {"authentik_core.view_application", "authentik_core.delete_application"},
		"/api/v3/providers/oauth2/":                {"authentik_providers_oauth2.view_oauth2provider", "authentik_providers_oauth2.delete_oauth2provider"},
		"/api/v3/policies/expression/":             {"authentik_policies_expression.view_expressionpolicy", "authentik_policies_expression.delete_expressionpolicy"},
		"/api/v3/policies/bindings/":               {"authentik_policies.view_policybinding", "authentik_policies.delete_policybinding"},
		"/api/v3/propertymappings/provider/scope/": {"authentik_providers_oauth2.view_scopemapping", "authentik_providers_oauth2.delete_scopemapping"},
		"/api/v3/core/users/":                      {"authentik_core.view_user", "authentik_core.delete_user"},
		"/api/v3/core/groups/":                     {"authentik_core.view_group", "authentik_core.delete_group"},
	}
	src, err := os.ReadFile("offboarding.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range regexp.MustCompile(`"(/api/v3/[a-z0-9_/]+/)"`).FindAllStringSubmatch(string(src), -1) {
		if _, ok := deletionPermissions[m[1]]; !ok {
			t.Errorf("offboarding.go touches %s, which has no entry in deletionPermissions", m[1])
		}
	}
	for collection := range deletionPermissions {
		if !strings.Contains(string(src), `"`+collection+`"`) {
			t.Errorf("deletionPermissions lists %s, which offboarding.go does not touch", collection)
		}
	}
	granted := serviceRolePermissions(t)
	for collection, perms := range deletionPermissions {
		for _, p := range perms {
			if !slices.Contains(granted, p) {
				t.Errorf("service role lacks %s, needed to delete from %s", p, collection)
			}
		}
	}
}

// serviceRolePermissions returns the permissions of the role with id service-role in paddock-portal.yaml, read as
// text: the blueprint uses Authentik's custom YAML tags.
func serviceRolePermissions(t *testing.T) []string {
	t.Helper()
	path := filepath.Join("..", "..", "..", "..", "deploy", "compose", "authentik", "blueprints", "paddock-portal.yaml")
	f, err := os.Open(path) //nolint:gosec // fixed path in the repository
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	var perms []string
	inRole, inPerms := false, false
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case !inRole:
			inRole = line == "id: service-role"
		case !inPerms:
			inPerms = line == "permissions:"
		case strings.HasPrefix(line, "#"):
		case strings.HasPrefix(line, "- ") && !strings.HasPrefix(line, "- model:"):
			perms = append(perms, strings.TrimSpace(strings.TrimPrefix(line, "- ")))
		default:
			return perms
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	if len(perms) == 0 {
		t.Fatal("paddock-portal.yaml has no permissions under id: service-role")
	}
	return perms
}
