package admin

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/paddock-mdm/paddock/server/internal/transport/http/admin/listing"
)

// lists maps the operationId of every collection GET to its list definition and its static list query.
var lists = map[string]struct {
	spec       listing.Spec
	queryFile  string // relative to server/internal/adapters
	queryName  string
	tieBreaker string
}{
	"listDeviceGroups":  {deviceGroupList, "postgres/queries/device_group.sql", "ListDeviceGroups", "id"},
	"listAuditEvents":   {auditEventList, "auditpg/queries/audit.sql", "ListAuditEvents", "event_id"},
	"listOrganizations": {organizationList, "postgres/queries/organization.sql", "ListOrganizations", "id"},
}

// TestListSpecsMatchContract keeps the handlers' list definitions equal to x-paddock-list and the sort enum of the
// contract (ADR 0018).
func TestListSpecsMatchContract(t *testing.T) {
	doc := loadSpec(t)
	seen := map[string]bool{}
	for path, item := range doc.Paths.Map() {
		op := item.Get
		if op == nil || strings.Contains(path, "{") || strings.HasPrefix(path, "/api/auth/") || path == "/api/v1/me" {
			continue
		}
		seen[op.OperationID] = true
		l, ok := lists[op.OperationID]
		if !ok {
			t.Errorf("collection GET %s (%s) has no list definition", path, op.OperationID)
			continue
		}
		ext, ok := op.Extensions["x-paddock-list"].(map[string]any)
		if !ok {
			t.Errorf("%s: missing x-paddock-list", path)
			continue
		}
		if got := strs(ext["sort"]); !slices.Equal(got, l.spec.Sort) {
			t.Errorf("%s: x-paddock-list.sort %v, handler %v", path, got, l.spec.Sort)
		}
		if ext["default_sort"] != l.spec.DefaultSort {
			t.Errorf("%s: x-paddock-list.default_sort %v, handler %s", path, ext["default_sort"], l.spec.DefaultSort)
		}
		var want []string
		for _, f := range l.spec.Sort {
			want = append(want, f, "-"+f)
		}
		param := op.Parameters.GetByInAndName("query", "sort")
		if param == nil {
			t.Errorf("%s: no sort parameter", path)
			continue
		}
		var enum []string
		for _, v := range param.Schema.Value.Enum {
			enum = append(enum, v.(string))
		}
		slices.Sort(want)
		slices.Sort(enum)
		if !slices.Equal(enum, want) {
			t.Errorf("%s: sort enum %v, want %v", path, enum, want)
		}
		if param.Schema.Value.Default != l.spec.DefaultSort {
			t.Errorf("%s: sort default %v, want %s", path, param.Schema.Value.Default, l.spec.DefaultSort)
		}
	}
	for id := range lists {
		if !seen[id] {
			t.Errorf("list definition %s has no collection GET in the contract", id)
		}
	}
}

// TestListQueriesSortBranches checks decision 2 of plan M0.2: every allowed sort value has an ascending and a
// descending ORDER BY branch, and the primary key is the last sort key.
func TestListQueriesSortBranches(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	adapters := filepath.Join(filepath.Dir(file), "..", "..", "..", "adapters")
	for id, l := range lists {
		raw, err := os.ReadFile(filepath.Join(adapters, l.queryFile)) //nolint:gosec // fixed paths of the test table
		if err != nil {
			t.Fatal(err)
		}
		query := sqlQuery(string(raw), l.queryName)
		if query == "" {
			t.Errorf("%s: query %s not found in %s", id, l.queryName, l.queryFile)
			continue
		}
		for _, f := range l.spec.Sort {
			for _, branch := range []string{
				"CASE WHEN @sort::text = '" + f + "' THEN " + f + " END ASC",
				"CASE WHEN @sort::text = '-" + f + "' THEN " + f + " END DESC",
			} {
				if !strings.Contains(query, branch) {
					t.Errorf("%s: %s lacks %q", id, l.queryName, branch)
				}
			}
		}
		if !regexp.MustCompile(`,\s*` + l.tieBreaker + `\s+LIMIT `).MatchString(query) {
			t.Errorf("%s: %s does not end its ORDER BY with the tie-breaker %s", id, l.queryName, l.tieBreaker)
		}
	}
}

// sqlQuery returns the text of the sqlc query name in a query file.
func sqlQuery(file, name string) string {
	_, rest, ok := strings.Cut(file, "-- name: "+name+" ")
	if !ok {
		return ""
	}
	query, _, _ := strings.Cut(rest, "-- name: ")
	return query
}

func strs(v any) []string {
	list, _ := v.([]any)
	out := make([]string, 0, len(list))
	for _, s := range list {
		str, _ := s.(string)
		out = append(out, str)
	}
	return out
}
