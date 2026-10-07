package acceptance

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/jackc/pgx/v5"

	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
	"github.com/phischl/paddock-mdm/test/acceptance/internal/stack"
)

// listParams are the parameters every collection GET must declare (ADR 0018).
var listParams = []string{"page", "page_size", "sort", "q"}

// collectionGETs returns the paths of every collection GET in the contract: a GET whose 200 response is an object
// with an items array.
func collectionGETs(doc *openapi3.T) map[string]*openapi3.Operation {
	out := map[string]*openapi3.Operation{}
	for path, item := range doc.Paths.Map() {
		if item.Get == nil {
			continue
		}
		ok := item.Get.Responses.Status(http.StatusOK)
		if ok == nil || ok.Value == nil || ok.Value.Content.Get("application/json") == nil {
			continue
		}
		schema := ok.Value.Content.Get("application/json").Schema.Value
		if items := schema.Properties["items"]; items != nil && items.Value.Type.Is("array") {
			out[path] = item.Get
		}
	}
	return out
}

// listExtension is x-paddock-list.
type listExtension struct {
	Sort        []string `json:"sort"`
	DefaultSort string   `json:"default_sort"`
	Search      []string `json:"search"`
	Filters     []string `json:"filters"`
}

func extension(t *testing.T, op *openapi3.Operation) listExtension {
	t.Helper()
	raw, ok := op.Extensions["x-paddock-list"]
	if !ok {
		t.Fatal("missing x-paddock-list")
	}
	data, err := json.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	var ext listExtension
	if err := json.Unmarshal(data, &ext); err != nil {
		t.Fatalf("x-paddock-list: %v", err)
	}
	if len(ext.Sort) == 0 || ext.DefaultSort == "" || ext.Search == nil || ext.Filters == nil {
		t.Fatalf("x-paddock-list needs sort, default_sort, search and filters: %+v", ext)
	}
	return ext
}

// TestListContract is the list contract gate of plan M0.2 (AC2): every collection GET of the admin API declares
// page, page_size, sort, q and x-paddock-list, and the running server honours every allowed sort and rejects
// unknown sorts and page sizes.
func TestListContract(t *testing.T) {
	doc := loadSpec(t)
	lists := collectionGETs(doc)
	if len(lists) < 3 {
		t.Fatalf("expected at least 3 collection GETs, found %d", len(lists))
	}
	sessions := map[bool]*env.Portal{false: login(t, env.Alice), true: login(t, env.PlatformAdmin)}
	seedListData(t, sessions[false])
	// Collections below an item are listed for an acme parent with at least one member.
	parentGroup := namedGroup(t, sessions[false], "list contract members")
	member := activeDevice(t, sessions[false], parentGroup, "list-contract-"+uniqueSuffix())
	for range 2 {
		expectStatus(t, call(t, sessions[false], http.MethodPost, "/api/v1/devices/"+member.DeviceID+"/local-admin/rotate", nil), http.StatusAccepted, "")
	}
	userGroup := listContractUserGroup(t, sessions[false])
	cve := seedListInventory(t, member.DeviceID)
	parents := map[string]string{"/api/v1/device-groups/{id}/devices": parentGroup, "/api/v1/user-groups/{id}/members": userGroup,
		"/api/v1/devices/{id}/commands": member.DeviceID, "/api/v1/devices/{id}/software": member.DeviceID,
		"/api/v1/devices/{id}/vulnerabilities": member.DeviceID, "/api/v1/vulnerabilities/{cve}/devices": cve}
	order := newCollation(t)
	paths := make([]string, 0, len(lists))
	for p := range lists {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, path := range paths {
		op := lists[path]
		t.Run(path, func(t *testing.T) {
			target := path
			if strings.Contains(path, "{") {
				parent, ok := parents[path]
				if !ok {
					t.Fatalf("collection %s below an item has no parent in this gate", path)
				}
				target = pathParam.ReplaceAllString(path, parent)
			}
			for _, name := range listParams {
				if op.Parameters.GetByInAndName("query", name) == nil {
					t.Errorf("parameter %s missing", name)
				}
			}
			ext := extension(t, op)
			for _, f := range ext.Filters {
				if op.Parameters.GetByInAndName("query", f) == nil {
					t.Errorf("filter %s of x-paddock-list is not a declared query parameter", f)
				}
			}
			var want []string
			for _, f := range ext.Sort {
				want = append(want, f, "-"+f)
			}
			var enum []string
			if p := op.Parameters.GetByInAndName("query", "sort"); p != nil {
				for _, v := range p.Schema.Value.Enum {
					enum = append(enum, fmt.Sprint(v))
				}
			}
			if !slices.Equal(sorted(enum), sorted(want)) {
				t.Errorf("sort enum %v, want %v", enum, want)
			}
			if t.Failed() {
				return
			}

			item := op.Responses.Status(http.StatusOK).Value.Content.Get("application/json").Schema.Value.Properties["items"].Value.Items.Value
			session := sessions[strings.HasPrefix(path, "/api/platform/")]
			for _, s := range want {
				q := url.Values{"sort": {s}, "page_size": {"100"}}
				res := call(t, session, http.MethodGet, target+"?"+q.Encode(), nil)
				expectStatus(t, res, http.StatusOK, "")
				var page struct {
					Items []map[string]any `json:"items"`
					Sort  string           `json:"sort"`
					Total int              `json:"total"`
				}
				if err := res.JSON(&page); err != nil {
					t.Fatal(err)
				}
				if page.Sort != s {
					t.Errorf("sort=%s: response sort %q", s, page.Sort)
				}
				field := strings.TrimPrefix(s, "-")
				prop := item.Properties[field]
				if prop == nil {
					t.Fatalf("sort field %s is not a property of the items", field)
				}
				keys := make([]string, len(page.Items))
				for i, it := range page.Items {
					keys[i] = fmt.Sprint(it[field])
				}
				if s[0] == '-' {
					reverse(keys, nullsLast[field])
				}
				if err := order.ascending(keys, prop.Value); err != nil {
					t.Errorf("sort=%s: %v", s, err)
				}
				t.Logf("sort=%s: %d of %d items in order", s, len(page.Items), page.Total)
			}
			expectStatus(t, call(t, session, http.MethodGet, target+"?sort=no_such_field", nil), http.StatusBadRequest, "invalid_request")
			expectStatus(t, call(t, session, http.MethodGet, target+"?page_size=7", nil), http.StatusBadRequest, "invalid_request")
			expectStatus(t, call(t, session, http.MethodGet, target+"?page=401&page_size=25", nil), http.StatusBadRequest, "page_out_of_range")
		})
	}
}

// seedListData creates device groups whose name, creation and update orders differ (mixed case, so byte order and
// collation disagree) and deletes them when the test ends; their audit events feed the audit log list.
func seedListData(t *testing.T, alice *env.Portal) {
	t.Helper()
	var ids []string
	t.Cleanup(func() {
		for _, id := range ids {
			_, _ = alice.Do(context.Background(), http.MethodDelete, "/api/v1/device-groups/"+id, nil)
		}
	})
	for _, name := range []string{"list Contract b", "List contract A", "LIST contract d", "list contract c"} {
		res := call(t, alice, http.MethodPost, "/api/v1/device-groups", map[string]string{"name": uniqueName(name)})
		expectStatus(t, res, http.StatusCreated, "")
		var g struct {
			ID string `json:"id"`
		}
		if err := res.JSON(&g); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, g.ID)
	}
	res := call(t, alice, http.MethodPatch, "/api/v1/device-groups/"+ids[0], map[string]string{"description": "touched"})
	expectStatus(t, res, http.StatusOK, "")
}

// collation compares strings with the database's collation, which decides the server's order (Go's byte order
// differs from en_US.utf8).
type collation struct {
	conn *pgx.Conn
	ctx  context.Context
}

func newCollation(t *testing.T) *collation {
	t.Helper()
	dsn, err := stack.AuditIndexDSN()
	if err != nil {
		t.Fatal(err)
	}
	ctx := testContext(t, 5*time.Minute)
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close(context.Background()) })
	return &collation{conn: conn, ctx: ctx}
}

// ascending reports the first adjacent pair out of ascending order. Missing values (null) sort after every value,
// as PostgreSQL orders NULL in ascending order (and first in descending order, which the caller reverses). Numbers
// compare as numbers, date-time strings as times, other strings in the database's collation.
func (c *collation) ascending(keys []string, prop *openapi3.Schema) error {
	for i := 1; i < len(keys); i++ {
		a, b := keys[i-1], keys[i]
		var ok bool
		switch {
		case a == nullKey || b == nullKey:
			ok = b == nullKey
		case prop.Type.Is("number") || prop.Type.Is("integer"):
			na, errA := strconv.ParseFloat(a, 64)
			nb, errB := strconv.ParseFloat(b, 64)
			if errA != nil || errB != nil {
				return fmt.Errorf("not numbers: %q, %q", a, b)
			}
			ok = na <= nb
		case prop.Format == "date-time":
			ta, errA := time.Parse(time.RFC3339Nano, a)
			tb, errB := time.Parse(time.RFC3339Nano, b)
			if errA != nil || errB != nil {
				return fmt.Errorf("not RFC 3339: %q, %q", a, b)
			}
			ok = !ta.After(tb)
		default:
			if err := c.conn.QueryRow(c.ctx, "SELECT $1::text <= $2::text", a, b).Scan(&ok); err != nil {
				return err
			}
		}
		if !ok {
			return fmt.Errorf("items %d and %d out of order: %q, %q", i-1, i, a, b)
		}
	}
	return nil
}

// nullKey is fmt.Sprint of a JSON null.
const nullKey = "<nil>"

// nullsLast are the sort fields whose missing values sort last in both directions: findings without CVSS score
// (Fleet free reports none) stay below the scored ones also when sorted by descending score.
var nullsLast = map[string]bool{"cvss_score": true}

// reverse turns the keys of a descending sort into ascending order; with nullsLast, only the values before the first
// null are reversed, so a null before a value stays there and fails the order check.
func reverse(keys []string, nullsLast bool) {
	n := len(keys)
	if i := slices.Index(keys, nullKey); nullsLast && i >= 0 {
		n = i
	}
	slices.Reverse(keys[:n])
}

// pathParam is the path parameter of a collection below an item ({id}, {cve}).
var pathParam = regexp.MustCompile(`\{[a-z]+\}`)

// seedListInventory stores packages and findings of an acme device whose name, version and score orders differ,
// with a finding without score, and returns the CVE of a finding for the list of its devices.
func seedListInventory(t *testing.T, device string) string {
	t.Helper()
	cve := uniqueCVE()
	storeInventory(t, device, [][2]string{{"Zlib-list", "1:1.3"}, {"apt-list", "2.10"}, {"Bash-list", "10.0"}},
		[][4]string{{cve, "apt-list", "2.10", "9.8"}, {uniqueCVE(), "Bash-list", "10.0", ""}, {uniqueCVE(), "Zlib-list", "1:1.3", "10"},
			{uniqueCVE(), "apt-list", "2.10", "4.3"}})
	return cve
}

func sorted(s []string) []string {
	s = slices.Clone(s)
	slices.Sort(s)
	return s
}

// listContractUserGroup creates a user group with two members (deleted when the gate ends) for the member list.
func listContractUserGroup(t *testing.T, alice *env.Portal) string {
	t.Helper()
	res := call(t, alice, http.MethodPost, "/api/v1/user-groups", map[string]string{"slug": "list-" + uniqueSuffix(), "name": uniqueName("list contract")})
	expectStatus(t, res, http.StatusCreated, "")
	group := createdID(t, alice, "/api/v1/user-groups", res)
	for _, prefix := range []string{"list-b", "List-a"} {
		u := createLocalUser(t, alice, strings.ToLower(prefix))
		res := call(t, alice, http.MethodPost, "/api/v1/user-groups/"+group+"/members", map[string]string{"user_id": u.ID})
		expectStatus(t, res, http.StatusNoContent, "")
	}
	return group
}
