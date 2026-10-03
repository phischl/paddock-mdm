package acceptance

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/jackc/pgx/v5"

	"github.com/paddock-mdm/paddock/test/acceptance/internal/env"
	"github.com/paddock-mdm/paddock/test/acceptance/internal/stack"
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
	order := newCollation(t)
	paths := make([]string, 0, len(lists))
	for p := range lists {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, path := range paths {
		op := lists[path]
		t.Run(path, func(t *testing.T) {
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
				res := call(t, session, http.MethodGet, path+"?"+q.Encode(), nil)
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
					slices.Reverse(keys)
				}
				if err := order.ascending(keys, prop.Value.Format == "date-time"); err != nil {
					t.Errorf("sort=%s: %v", s, err)
				}
				t.Logf("sort=%s: %d of %d items in order", s, len(page.Items), page.Total)
			}
			expectStatus(t, call(t, session, http.MethodGet, path+"?sort=no_such_field", nil), http.StatusBadRequest, "invalid_request")
			expectStatus(t, call(t, session, http.MethodGet, path+"?page_size=7", nil), http.StatusBadRequest, "invalid_request")
			expectStatus(t, call(t, session, http.MethodGet, path+"?page=401&page_size=25", nil), http.StatusBadRequest, "page_out_of_range")
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

// ascending reports the first adjacent pair out of ascending order.
func (c *collation) ascending(keys []string, timestamps bool) error {
	for i := 1; i < len(keys); i++ {
		a, b := keys[i-1], keys[i]
		var ok bool
		if timestamps {
			ta, errA := time.Parse(time.RFC3339Nano, a)
			tb, errB := time.Parse(time.RFC3339Nano, b)
			if errA != nil || errB != nil {
				return fmt.Errorf("not RFC 3339: %q, %q", a, b)
			}
			ok = !ta.After(tb)
		} else if err := c.conn.QueryRow(c.ctx, "SELECT $1::text <= $2::text", a, b).Scan(&ok); err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("items %d and %d out of order: %q, %q", i-1, i, a, b)
		}
	}
	return nil
}

func sorted(s []string) []string {
	s = slices.Clone(s)
	slices.Sort(s)
	return s
}
