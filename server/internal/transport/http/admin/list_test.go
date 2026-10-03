package admin_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/paddock-mdm/paddock/server/internal/adapters/auditpg/auditstore"
	"github.com/paddock-mdm/paddock/server/internal/principal"
)

// listPage is the list envelope with the fields the tests compare.
type listPage struct {
	Items []struct {
		Name          string `json:"name"`
		Slug          string `json:"slug"`
		CorrelationID string `json:"correlation_id"`
	} `json:"items"`
	Page        int    `json:"page"`
	PageSize    int    `json:"page_size"`
	Total       int    `json:"total"`
	TotalCapped bool   `json:"total_capped"`
	Sort        string `json:"sort"`
}

// list GETs path?query (validated against the contract) and returns the page.
func (e *env) list(cookie *http.Cookie, path string, query url.Values) listPage {
	e.t.Helper()
	r := e.do(call{method: "GET", path: path + "?" + query.Encode(), cookie: cookie})
	if r.status != http.StatusOK {
		e.t.Fatalf("GET %s?%s: %d %s", path, query.Encode(), r.status, r.body)
	}
	var p listPage
	if err := json.Unmarshal(r.body, &p); err != nil {
		e.t.Fatal(err)
	}
	return p
}

// names returns one field of every item: name, slug or correlation_id.
func (p listPage) names(field string) []string {
	out := []string{}
	for _, it := range p.Items {
		switch field {
		case "slug":
			out = append(out, it.Slug)
		case "correlation_id":
			out = append(out, it.CorrelationID)
		default:
			out = append(out, it.Name)
		}
	}
	return out
}

func sorted(s []string) []string {
	s = slices.Clone(s)
	slices.Sort(s)
	return s
}

// expectRejected sends a request that violates the contract on purpose and expects 400 with code.
func (e *env) expectRejected(cookie *http.Cookie, path, code string) {
	e.t.Helper()
	r := e.do(call{method: "GET", path: path, cookie: cookie, skipReqCheck: true})
	if r.status != http.StatusBadRequest || r.problemCode(e.t) != code {
		e.t.Fatalf("GET %s: %d %s, want 400 %s", path, r.status, r.body, code)
	}
}

// insertGroup inserts a device group with fixed timestamps (as superuser, bypassing the use case).
func (e *env) insertGroup(org uuid.UUID, name, description string, created, updated time.Time) {
	e.t.Helper()
	_, err := e.super.Exec(context.Background(), `INSERT INTO device_group (id, organization_id, name, description, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6)`, uuid.Must(uuid.NewV7()), org, name, description, created, updated)
	if err != nil {
		e.t.Fatal(err)
	}
}

func TestDeviceGroupListContract(t *testing.T) {
	e := newEnv(t)
	org := e.org("lists")
	admin := e.session(org, principal.RoleOrgAdmin)
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	h := func(n int) time.Time { return t0.Add(time.Duration(n) * time.Hour) }
	e.insertGroup(org, "alpha", "", h(3), h(2))
	e.insertGroup(org, "bravo", "", h(1), h(3))
	e.insertGroup(org, "charlie", "", h(2), h(1))
	// delta and echo tie on both timestamps: the id (insertion order) decides, ascending in both directions.
	e.insertGroup(org, "delta", "", h(4), h(0))
	e.insertGroup(org, "echo", "", h(4), h(0))

	for sort, want := range map[string][]string{
		"":            {"alpha", "bravo", "charlie", "delta", "echo"},
		"name":        {"alpha", "bravo", "charlie", "delta", "echo"},
		"-name":       {"echo", "delta", "charlie", "bravo", "alpha"},
		"created_at":  {"bravo", "charlie", "alpha", "delta", "echo"},
		"-created_at": {"delta", "echo", "alpha", "charlie", "bravo"},
		"updated_at":  {"delta", "echo", "charlie", "alpha", "bravo"},
		"-updated_at": {"bravo", "alpha", "charlie", "delta", "echo"},
	} {
		q := url.Values{}
		if sort != "" {
			q.Set("sort", sort)
		}
		p := e.list(admin, "/api/v1/device-groups", q)
		if got := p.names("name"); !slices.Equal(got, want) {
			t.Errorf("sort %q: %v, want %v", sort, got, want)
		}
		wantSort := sort
		if sort == "" {
			wantSort = "name"
		}
		if p.Sort != wantSort || p.Total != 5 || p.TotalCapped || p.Page != 1 || p.PageSize != 25 {
			t.Errorf("sort %q: envelope %+v", sort, p)
		}
	}

	p := e.list(admin, "/api/v1/device-groups", url.Values{"page_size": {"10"}, "page": {"2"}})
	if len(p.Items) != 0 || p.Total != 5 || p.Page != 2 || p.PageSize != 10 {
		t.Fatalf("page beyond total: %+v", p)
	}

	search := e.org("search")
	searcher := e.session(search, principal.RoleOrgOperator)
	for _, g := range [][2]string{
		{"100% pure", ""}, {"100 x pure", ""}, {"a_b", ""}, {"axb", ""}, {"Laptops", "for the HR team"}, {`C:\temp`, ""},
	} {
		e.insertGroup(search, g[0], g[1], t0, t0)
	}
	for q, want := range map[string][]string{
		"100%":    {"100% pure"},
		"a_b":     {"a_b"},
		"LAPTOP":  {"Laptops"},
		"hr te":   {"Laptops"},
		"pure":    {"100 x pure", "100% pure"},
		`C:\t`:    {`C:\temp`},
		"zzz":     {},
		" a_b  ":  {"a_b"},
		"0% pure": {"100% pure"},
	} {
		p := e.list(searcher, "/api/v1/device-groups", url.Values{"q": {q}})
		if got := sorted(p.names("name")); !slices.Equal(got, sorted(want)) || p.Total != len(want) {
			t.Errorf("q %q: %v (total %d), want %v", q, got, p.Total, want)
		}
	}
	// The acme organization of another session never sees these groups.
	other := e.session(e.acme, principal.RoleOrgAdmin)
	if p := e.list(other, "/api/v1/device-groups", url.Values{"q": {"pure"}}); p.Total != 0 {
		t.Fatalf("cross-organization search: %+v", p)
	}

	e.expectRejected(admin, "/api/v1/device-groups?page_size=7", "invalid_request")
	e.expectRejected(admin, "/api/v1/device-groups?sort=description", "invalid_request")
	e.expectRejected(admin, "/api/v1/device-groups?sort=-id", "invalid_request")
	e.expectRejected(admin, "/api/v1/device-groups?page=0", "invalid_request")
	e.expectRejected(admin, "/api/v1/device-groups?page=abc", "invalid_request")
	e.expectRejected(admin, "/api/v1/device-groups?q=a", "invalid_request")
	r := e.do(call{method: "GET", path: "/api/v1/device-groups?page=401&page_size=25", cookie: admin})
	if r.status != http.StatusBadRequest || r.problemCode(t) != "page_out_of_range" {
		t.Fatalf("page 401 × 25: %d %s", r.status, r.body)
	}
}

func TestDeviceGroupListTotalCapped(t *testing.T) {
	e := newEnv(t)
	org := e.org("bulk")
	admin := e.session(org, principal.RoleOrgAuditor)
	_, err := e.super.Exec(context.Background(), `INSERT INTO device_group (id, organization_id, name, description)
		SELECT gen_random_uuid(), $1, 'bulk ' || g, '' FROM generate_series(1, 10050) g`, org)
	if err != nil {
		t.Fatal(err)
	}
	p := e.list(admin, "/api/v1/device-groups", url.Values{"page_size": {"100"}})
	if p.Total != 10000 || !p.TotalCapped || len(p.Items) != 100 {
		t.Fatalf("capped: total %d capped %v items %d", p.Total, p.TotalCapped, len(p.Items))
	}
	last := e.list(admin, "/api/v1/device-groups", url.Values{"page_size": {"100"}, "page": {"100"}})
	if len(last.Items) != 100 || !last.TotalCapped {
		t.Fatalf("deepest page: items %d capped %v", len(last.Items), last.TotalCapped)
	}
	r := e.do(call{method: "GET", path: "/api/v1/device-groups?page_size=100&page=101", cookie: admin})
	if r.status != http.StatusBadRequest || r.problemCode(t) != "page_out_of_range" {
		t.Fatalf("page 101 × 100: %d %s", r.status, r.body)
	}
	narrow := e.list(admin, "/api/v1/device-groups", url.Values{"q": {"bulk 1005"}})
	if got := sorted(narrow.names("name")); narrow.Total != 2 || narrow.TotalCapped || !slices.Equal(got, []string{"bulk 1005", "bulk 10050"}) {
		t.Fatalf("narrowed: %+v", narrow)
	}
}

func TestOrganizationListContract(t *testing.T) {
	e := newEnv(t)
	root := e.platformSession()
	tok := "ls" + strings.ReplaceAll(uuid.NewString()[:8], "-", "")
	nameTok := "N" + uuid.NewString()[:8]
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, o := range []struct {
		suffix, name, status string
		created              time.Time
	}{
		{"c", "Alpha", "active", t0.Add(3 * time.Hour)},
		{"a", "Charlie", "suspended", t0.Add(time.Hour)},
		{"b", "Bravo", "provisioning_failed", t0.Add(2 * time.Hour)},
	} {
		_, err := e.super.Exec(context.Background(), `INSERT INTO organization (id, slug, name, status, created_at) VALUES ($1, $2, $3, $4, $5)`,
			uuid.Must(uuid.NewV7()), tok+"-"+o.suffix, o.name+" "+nameTok, o.status, o.created)
		if err != nil {
			t.Fatal(err)
		}
	}
	slug := func(s ...string) []string {
		out := []string{}
		for _, x := range s {
			out = append(out, tok+"-"+x)
		}
		return out
	}
	for sort, want := range map[string][]string{
		"":            slug("a", "b", "c"),
		"-slug":       slug("c", "b", "a"),
		"name":        slug("c", "b", "a"),
		"-name":       slug("a", "b", "c"),
		"created_at":  slug("a", "b", "c"),
		"-created_at": slug("c", "b", "a"),
		"status":      slug("c", "b", "a"),
		"-status":     slug("a", "b", "c"),
	} {
		q := url.Values{"q": {tok}}
		if sort != "" {
			q.Set("sort", sort)
		}
		p := e.list(root, "/api/platform/v1/organizations", q)
		if got := p.names("slug"); !slices.Equal(got, want) || p.Total != 3 {
			t.Errorf("sort %q: %v, want %v", sort, got, want)
		}
	}
	for _, tc := range []struct {
		query url.Values
		want  []string
	}{
		{url.Values{"q": {nameTok}}, slug("a", "b", "c")},
		{url.Values{"q": {tok}, "status": {"suspended"}}, slug("a")},
		{url.Values{"q": {tok}, "status": {"active", "suspended"}}, slug("a", "c")},
		{url.Values{"q": {tok}, "status": {"provisioning"}}, []string{}},
	} {
		if got := e.list(root, "/api/platform/v1/organizations", tc.query).names("slug"); !slices.Equal(got, tc.want) {
			t.Errorf("%s: %v, want %v", tc.query.Encode(), got, tc.want)
		}
	}
	e.expectRejected(root, "/api/platform/v1/organizations?status=deleted", "invalid_request")
	e.expectRejected(root, "/api/platform/v1/organizations?sort=id", "invalid_request")
	e.expectRejected(root, "/api/platform/v1/organizations?page_size=1000", "invalid_request")
}

func TestAuditListContract(t *testing.T) {
	e := newEnv(t)
	org := e.org("auditlist")
	auditor := e.session(org, principal.RoleOrgAuditor)
	now := time.Now().UTC().Truncate(time.Second)
	events := []struct {
		id, code, outcome, actor, target string
	}{
		{"e1", "device_group.created", "success", `{"type":"admin","display":"alice","step_up":false}`, `{"type":"device_group","id":"1","display":"Laptops"}`},
		{"e2", "device_group.deleted", "failure", `{"type":"admin","display":"bob","step_up":false}`, `{"type":"device_group","id":"2","display":"Servers"}`},
		{"e3", "organization.created", "denied", `{"type":"platform_admin","display":"root","step_up":false}`, `{"type":"organization","id":"3","display":"100%_org"}`},
		{"e4", "admin.login", "unknown", `{"type":"anonymous","step_up":false}`, ``},
		{"e5", "device_group.updated", "success", `{"type":"system","display":"reaper","step_up":false}`, `{"type":"device_group","id":"1","display":"Laptops"}`},
	}
	err := e.writer.InWriter(context.Background(), func(ctx context.Context, q *auditstore.Queries) error {
		for _, month := range []time.Time{now, now.AddDate(0, -1, 0)} {
			if err := q.EnsureAuditPartition(ctx, month); err != nil {
				return err
			}
		}
		for i, ev := range events {
			var target []byte
			if ev.target != "" {
				target = []byte(ev.target)
			}
			_, err := q.InsertAuditEvent(ctx, auditstore.InsertAuditEventParams{
				EventID: uuid.Must(uuid.NewV7()), OrganizationID: org, OccurredAt: now.Add(-time.Duration(i+1) * time.Minute),
				RecordedAt: now, Code: ev.code, Outcome: ev.outcome, Source: "portal", Actor: []byte(ev.actor), Target: target,
				Params: []byte(`{}`), CorrelationID: ev.id, ObjectKey: "k",
			})
			if err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for sort, want := range map[string][]string{
		"":             {"e1", "e2", "e3", "e4", "e5"},
		"-occurred_at": {"e1", "e2", "e3", "e4", "e5"},
		"occurred_at":  {"e5", "e4", "e3", "e2", "e1"},
		"code":         {"e4", "e1", "e2", "e5", "e3"},
		"-code":        {"e3", "e5", "e2", "e1", "e4"},
		// e1 and e5 tie on outcome: event_id (insertion order) decides, ascending in both directions.
		"outcome":  {"e3", "e2", "e1", "e5", "e4"},
		"-outcome": {"e4", "e1", "e5", "e2", "e3"},
	} {
		q := url.Values{}
		if sort != "" {
			q.Set("sort", sort)
		}
		p := e.list(auditor, "/api/v1/audit-events", q)
		if got := p.names("correlation_id"); !slices.Equal(got, want) || p.Total != 5 {
			t.Errorf("sort %q: %v (total %d), want %v", sort, got, p.Total, want)
		}
	}
	for _, tc := range []struct {
		query url.Values
		want  []string
	}{
		{url.Values{"code": {"device_group.created", "device_group.deleted"}}, []string{"e1", "e2"}},
		{url.Values{"outcome": {"success"}}, []string{"e1", "e5"}},
		{url.Values{"outcome": {"denied", "unknown"}}, []string{"e3", "e4"}},
		{url.Values{"actor_type": {"anonymous"}}, []string{"e4"}},
		{url.Values{"actor_type": {"system", "platform_admin"}}, []string{"e3", "e5"}},
		{url.Values{"q": {"laptops"}}, []string{"e1", "e5"}},
		{url.Values{"q": {"bob"}}, []string{"e2"}},
		{url.Values{"q": {"LOGIN"}}, []string{"e4"}},
		{url.Values{"q": {"0%_o"}}, []string{"e3"}},
		{url.Values{"q": {"0%x"}}, []string{}},
		{url.Values{"q": {"laptops"}, "outcome": {"success"}, "actor_type": {"system"}}, []string{"e5"}},
		{url.Values{"from": {now.Add(-150 * time.Second).Format(time.RFC3339)}}, []string{"e1", "e2"}},
	} {
		p := e.list(auditor, "/api/v1/audit-events", tc.query)
		if got := p.names("correlation_id"); !slices.Equal(got, tc.want) || p.Total != len(tc.want) {
			t.Errorf("%s: %v (total %d), want %v", tc.query.Encode(), got, p.Total, tc.want)
		}
	}
	// Another organization never sees the events, also not through search or filters.
	other := e.session(e.globex, principal.RoleOrgAdmin)
	for _, q := range []url.Values{{"q": {"laptops"}}, {"outcome": {"success"}}, {"actor_type": {"anonymous"}}} {
		if p := e.list(other, "/api/v1/audit-events", q); p.Total != 0 {
			t.Errorf("cross-organization %s: %+v", q.Encode(), p)
		}
	}
	e.expectRejected(auditor, "/api/v1/audit-events?outcome=maybe", "invalid_request")
	e.expectRejected(auditor, "/api/v1/audit-events?actor_type=robot", "invalid_request")
	e.expectRejected(auditor, "/api/v1/audit-events?sort=source", "invalid_request")
	e.expectRejected(auditor, "/api/v1/audit-events?page_size=7", "invalid_request")
}
