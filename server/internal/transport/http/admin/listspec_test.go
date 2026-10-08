package admin

import (
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"

	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin/listing"
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

	"listEnrollmentTokens":   {enrollmentTokenList, "postgres/queries/enrollment_token.sql", "ListEnrollmentTokens", "id"},
	"listDevices":            {deviceList, "postgres/queries/device.sql", "ListDevices", "id"},
	"listDeviceGroupDevices": {deviceList, "postgres/queries/device.sql", "ListDevices", "id"},
	"listDeviceCommands":     {deviceCommandList, "postgres/queries/command.sql", "ListDeviceCommands", "id"},
	"listManagedFiles":       {managedFileList, "postgres/queries/managed_config.sql", "ListManagedFiles", "id"},
	"listManagedUnits":       {managedUnitList, "postgres/queries/managed_config.sql", "ListManagedUnits", "id"},
	"listAttention":          {attentionList, "postgres/queries/attention.sql", "ListAttention", "device_id, kind"},
	"listPackageHolds":       {packageHoldList, "postgres/queries/updates.sql", "ListPackageHolds", "id"},

	"listAgentReleases": {agentReleaseList, "postgres/queries/agent_release.sql", "ListAgentReleases", "version"},

	"listDeviceSoftware":        {deviceSoftwareList, "postgres/queries/inventory.sql", "ListDeviceSoftware", "name, version, source"},
	"listDeviceVulnerabilities": {findingList, "postgres/queries/inventory.sql", "ListDeviceVulnerabilities", "cve, software_name, software_version"},
	"listSoftware":              {softwareList, "postgres/queries/inventory.sql", "ListSoftware", "name, version"},
	"listVulnerabilities":       {vulnerabilityList, "postgres/queries/inventory.sql", "ListVulnerabilities", "cve"},
	"listVulnerabilityDevices":  {vulnerableDeviceList, "postgres/queries/inventory.sql", "ListVulnerabilityDevices", "device_id, software_name, software_version"},

	"listRevocationRequests": {revocationRequestList, "postgres/queries/revocation.sql", "ListRevocationRequests", `revocation_request\.id`},

	"listUsers":              {userList, "postgres/queries/user.sql", "ListAppUsers", "id"},
	"listUserGroupMembers":   {userList, "postgres/queries/user.sql", "ListAppUsers", "id"},
	"listUserGroups":         {userGroupList, "postgres/queries/user.sql", "ListUserGroups", "id"},
	"listPermissionProfiles": {permissionProfileList, "postgres/queries/privilege.sql", "ListPermissionProfiles", "id"},
	"listProfileAssignments": {profileAssignmentList, "postgres/queries/privilege.sql", "ListProfileAssignments", "id"},
	// Authentik groups, listed from the identity provider and sorted in memory: no query.
	"listUpstreamGroups": {upstreamGroupList, "", "", ""},
}

// TestListSpecsMatchContract keeps the handlers' list definitions equal to x-paddock-list and the sort enum of the
// contract (ADR 0018).
func TestListSpecsMatchContract(t *testing.T) {
	doc := loadSpec(t)
	seen := map[string]bool{}
	for path, item := range doc.Paths.Map() {
		op := item.Get
		if !isCollection(op) {
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

// isCollection reports whether op is a collection GET: its 200 response is an object with an items array.
func isCollection(op *openapi3.Operation) bool {
	if op == nil {
		return false
	}
	ok := op.Responses.Status(http.StatusOK)
	if ok == nil || ok.Value == nil || ok.Value.Content.Get("application/json") == nil {
		return false
	}
	items := ok.Value.Content.Get("application/json").Schema.Value.Properties["items"]
	return items != nil && items.Value.Type.Is("array")
}

// TestListQueriesSortBranches checks decision 2 of plan M0.2: every allowed sort value has an ascending and a
// descending ORDER BY branch, and the primary key is the last sort key.
func TestListQueriesSortBranches(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	adapters := filepath.Join(filepath.Dir(file), "..", "..", "..", "adapters")
	for id, l := range lists {
		if l.queryFile == "" {
			continue
		}
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
