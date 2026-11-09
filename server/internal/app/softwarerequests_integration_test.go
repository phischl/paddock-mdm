package app_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/phischl/paddock-mdm/pkg/protocol"
	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/platform/httpx"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/problem"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
)

// requestHarness runs the event path and the expiry with the worker's role and the decisions with the api's, as in
// production.
type requestHarness struct {
	reports  *app.DeviceReports
	worker   *app.SoftwareRequests
	api      *app.SoftwareRequests
	apiPool  *db.OrgPool
	super    *pgx.Conn
	org, dev uuid.UUID
}

func newRequestHarness(t *testing.T) requestHarness {
	t.Helper()
	env := pgtest.SharedPaddock(t)
	ctx := context.Background()
	pool := func(dsn string) *db.OrgPool {
		p, err := db.NewOrgPool(ctx, dsn, db.Options{})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(p.Close)
		return p
	}
	workerPool, apiPool := pool(env.Worker), pool(env.API)
	platform, err := db.NewPlatformPool(ctx, env.Platform, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(platform.Close)
	super, err := pgx.Connect(ctx, env.Super)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = super.Close(ctx) })
	workerRunner := app.NewActionRunner(workerPool, platform, httpx.RequestID)
	apiRunner := app.NewActionRunner(apiPool, platform, httpx.RequestID)
	h := requestHarness{
		reports: app.NewDeviceReports(workerRunner, workerPool), worker: app.NewSoftwareRequests(workerRunner, workerPool),
		api: app.NewSoftwareRequests(apiRunner, apiPool), apiPool: apiPool, super: super,
	}
	h.org, h.dev = h.orgWithDevice(t)
	return h
}

func (h requestHarness) exec(t *testing.T, sql string, args ...any) {
	t.Helper()
	if _, err := h.super.Exec(context.Background(), sql, args...); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
}

func (h requestHarness) orgWithDevice(t *testing.T) (org, dev uuid.UUID) {
	t.Helper()
	org, dev = uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	h.exec(t, "INSERT INTO organization (id, slug, name, status) VALUES ($1, $2, 'R', 'active')", org, "q"+org.String()[24:])
	h.exec(t, "INSERT INTO device (id, organization_id, hostname, state) VALUES ($1, $2, $3, 'active')", dev, org, "ws-"+dev.String()[24:])
	return org, dev
}

// entry adds a catalog entry of org with approval, available to the whole organization.
func (h requestHarness) entry(t *testing.T, org uuid.UUID, approval string) uuid.UUID {
	t.Helper()
	id := uuid.Must(uuid.NewV7())
	h.exec(t, `INSERT INTO software_catalog_entry (id, organization_id, name, packages, approval) VALUES ($1, $2, $3,
		'[{"distribution":"ubuntu","release":"*","architecture":"*","package":"nano"}]', $4)`, id, org, "E "+id.String(), approval)
	h.exec(t, `INSERT INTO software_assignment (id, organization_id, catalog_entry_id, intent) VALUES ($1, $2, $3, 'available')`,
		uuid.Must(uuid.NewV7()), org, id)
	return id
}

func (h requestHarness) user(t *testing.T, org uuid.UUID, username string) uuid.UUID {
	t.Helper()
	id := uuid.Must(uuid.NewV7())
	h.exec(t, "INSERT INTO app_user (id, organization_id, authentik_pk, username, source) VALUES ($1, $2, $3, $4, 'local')",
		id, org, id.String(), username)
	return id
}

func requestEvent(seq int64, user string, entry uuid.UUID) protocol.Event {
	data, _ := json.Marshal(map[string]string{"user": user, "entry_id": entry.String(), "justification": "secret text"})
	return protocol.Event{EventSeq: seq, Type: protocol.EventSoftwareRequest, OccurredAt: time.Now().UTC(), Data: data}
}

func (h requestHarness) count(t *testing.T, sql string, args ...any) int {
	t.Helper()
	var n int
	if err := h.super.QueryRow(context.Background(), sql, args...).Scan(&n); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
	return n
}

func (h requestHarness) events(t *testing.T, code string) int {
	t.Helper()
	return h.count(t, "SELECT count(*) FROM action WHERE organization_id = $1 AND code = $2", h.org, code)
}

// TestSoftwareRequestIngest (plan M13c decisions 9 and 10): a device's software.request opens one request per device,
// entry and user with device.software_requested and software_request.opened; a repeat while it is open, a redelivery,
// an entry without approval, another organization's entry and malformed data open none, and the justification a device
// sends is never recorded.
func TestSoftwareRequestIngest(t *testing.T) {
	h := newRequestHarness(t)
	alice := "alice-" + h.org.String()[24:] + "@acme.test"
	aliceID := h.user(t, h.org, alice)
	required, none := h.entry(t, h.org, "required"), h.entry(t, h.org, "none")
	otherOrg, _ := h.orgWithDevice(t)
	foreign := h.entry(t, otherOrg, "required")
	received := time.Now().UTC().Truncate(time.Second)

	batch := []protocol.Event{requestEvent(1, alice, required), requestEvent(2, alice, required), requestEvent(3, alice, none),
		requestEvent(4, alice, foreign), requestEvent(5, "Not Valid", required), requestEvent(6, "bob@acme.test", required)}
	for range 2 {
		if err := h.reports.RecordEvents(systemCtx(h.org), h.dev, received, batch); err != nil {
			t.Fatal(err)
		}
	}
	if got := h.events(t, "device.software_requested"); got != 6 {
		t.Fatalf("device.software_requested: %d, want one per event", got)
	}
	if got := h.events(t, "software_request.opened"); got != 2 {
		t.Fatalf("software_request.opened: %d, want 2 (alice and bob)", got)
	}
	var user uuid.NullUUID
	var expires time.Time
	if err := h.super.QueryRow(context.Background(), `SELECT user_id, expires_at FROM software_request
		WHERE device_id = $1 AND catalog_entry_id = $2 AND username = $3 AND state = 'requested'`, h.dev, required, alice).
		Scan(&user, &expires); err != nil {
		t.Fatal(err)
	}
	if !user.Valid || user.UUID != aliceID || !expires.Equal(received.Add(30*24*time.Hour)) {
		t.Fatalf("user %v, expires %v", user, expires)
	}
	if n := h.count(t, "SELECT count(*) FROM software_request WHERE device_id = $1 AND username = 'bob@acme.test' AND user_id IS NULL", h.dev); n != 1 {
		t.Fatalf("an unknown user's request: %d rows", n)
	}
	if n := h.count(t, "SELECT count(*) FROM action WHERE organization_id = $1 AND params::text LIKE '%secret text%'", h.org); n != 0 {
		t.Fatalf("the justification was recorded in %d events", n)
	}
	var params map[string]any
	if err := h.super.QueryRow(context.Background(), `SELECT params FROM action WHERE organization_id = $1
		AND code = 'software_request.opened' AND params->>'user' = $2`, h.org, alice).Scan(&params); err != nil {
		t.Fatal(err)
	}
	if params["catalog_entry_id"] != required.String() || params["device_id"] != h.dev.String() || params["hostname"] == "" ||
		params["expires_at"] == nil {
		t.Fatalf("opened params %v", params)
	}
	if fresh, err := h.reports.RecordEvent(systemCtx(h.org), h.dev, requestEvent(7, alice, required)); err != nil || !fresh {
		t.Fatalf("single event: %v, %v", fresh, err)
	}
	if got := h.events(t, "software_request.opened"); got != 2 {
		t.Fatalf("a repeat of an open request opened another: %d", got)
	}
}

// TestSoftwareRequestDecisions (plan M13c decisions 9 and 10, Q15): an organization administrator approves or denies
// without a step-up; a denial needs a reason; only an open request is decided; an operator is refused; another
// organization's request is not found; a new request within 24 hours of a denial opens nothing; every attempt is one
// audit event.
func TestSoftwareRequestDecisions(t *testing.T) {
	h := newRequestHarness(t)
	entry := h.entry(t, h.org, "required")
	alice, bob := "alice@acme.test", "bob@acme.test"
	if err := h.reports.RecordEvents(systemCtx(h.org), h.dev, time.Now(), []protocol.Event{
		requestEvent(1, alice, entry), requestEvent(2, bob, entry)}); err != nil {
		t.Fatal(err)
	}
	admin := adminCtx(h.org, principal.RoleOrgAdmin, "Ada Admin")
	list, err := h.api.List(adminCtx(h.org, principal.RoleOrgAuditor, "aud"), app.SoftwareRequestQuery{
		Page: app.ListPage{Sort: "username", Limit: 10}, States: []string{"requested"}})
	if err != nil || list.Count != 2 || list.Items[0].Username != alice || list.Items[1].Username != bob {
		t.Fatalf("list %+v, %v", list, err)
	}
	aliceReq, bobReq := list.Items[0].ID, list.Items[1].ID

	if _, err := h.api.Approve(adminCtx(h.org, principal.RoleOrgOperator, "op"), aliceReq, ""); !errors.Is(err, problem.Forbidden) {
		t.Fatalf("operator: %v", err)
	}
	otherOrg, _ := h.orgWithDevice(t)
	if _, err := h.api.Approve(adminCtx(otherOrg, principal.RoleOrgAdmin, "x"), aliceReq, ""); !errors.Is(err, problem.NotFound) {
		t.Fatalf("another organization's approval: %v", err)
	}
	if _, err := h.api.Get(adminCtx(otherOrg, principal.RoleOrgAdmin, "x"), aliceReq); !errors.Is(err, problem.NotFound) {
		t.Fatalf("another organization's read: %v", err)
	}
	if other, err := h.api.List(adminCtx(otherOrg, principal.RoleOrgAdmin, "x"), app.SoftwareRequestQuery{Page: app.ListPage{Sort: "username", Limit: 10}}); err != nil || other.Count != 0 {
		t.Fatalf("another organization's list: %+v, %v", other, err)
	}
	if _, err := h.api.Deny(admin, bobReq, "   "); !errors.Is(err, problem.InvalidRequest) {
		t.Fatalf("deny without reason: %v", err)
	}
	got, err := h.api.Approve(admin, aliceReq, "  ok for the project ")
	if err != nil || got.State != "approved" || got.DecidedBy == nil || *got.DecidedBy != "Ada Admin" ||
		got.DecisionReason == nil || *got.DecisionReason != "ok for the project" || got.DecidedAt == nil {
		t.Fatalf("approve: %+v, %v", got, err)
	}
	if _, err := h.api.Deny(admin, aliceReq, "too late"); !errors.Is(err, problem.InvalidState) {
		t.Fatalf("deny of an approved request: %v", err)
	}
	if got, err := h.api.Deny(admin, bobReq, "no licence left"); err != nil || got.State != "denied" {
		t.Fatalf("deny: %+v, %v", got, err)
	}
	if err := h.reports.RecordEvents(systemCtx(h.org), h.dev, time.Now(), []protocol.Event{requestEvent(3, bob, entry)}); err != nil {
		t.Fatal(err)
	}
	if n := h.count(t, "SELECT count(*) FROM software_request WHERE device_id = $1 AND username = $2", h.dev, bob); n != 1 {
		t.Fatalf("a request within 24 hours of a denial opened: %d rows", n)
	}
	if err := h.reports.RecordEvents(systemCtx(h.org), h.dev, time.Now().Add(25*time.Hour), []protocol.Event{requestEvent(4, bob, entry)}); err != nil {
		t.Fatal(err)
	}
	if n := h.count(t, "SELECT count(*) FROM software_request WHERE device_id = $1 AND username = $2 AND state = 'requested'", h.dev, bob); n != 1 {
		t.Fatalf("a request 25 hours after a denial: %d open rows", n)
	}

	outcomes := func(code string) string {
		rows, err := h.super.Query(context.Background(), `SELECT outcome || ':' || coalesce(error_code, '') FROM action
			WHERE organization_id = $1 AND code = $2 ORDER BY started_at, id`, h.org, code)
		if err != nil {
			t.Fatal(err)
		}
		s, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			t.Fatal(err)
		}
		b, _ := json.Marshal(s)
		return string(b)
	}
	if got := outcomes("software_request.approved"); got != `["denied:forbidden","success:"]` {
		t.Fatalf("approved events %s", got)
	}
	if got := outcomes("software_request.denied"); got != `["failure:invalid_request","failure:invalid_state","success:"]` {
		t.Fatalf("denied events %s", got)
	}
	var params map[string]any
	if err := h.super.QueryRow(context.Background(), `SELECT params FROM action WHERE organization_id = $1
		AND code = 'software_request.approved' AND outcome = 'success'`, h.org).Scan(&params); err != nil {
		t.Fatal(err)
	}
	if params["user"] != alice || params["reason"] != "ok for the project" || params["catalog_entry_id"] != entry.String() {
		t.Fatalf("approved params %v", params)
	}
	if n := h.count(t, `SELECT count(*) FROM outbox WHERE organization_id = $1 AND payload->>'scope' = 'device' AND payload->>'id' = $2`,
		h.org, h.dev.String()); n != 1 {
		t.Fatalf("approval queued %d compiles of the device, want 1", n)
	}
}

// TestSoftwareRequestExpiry (plan M13c §3.7, §3.8 L4, architect decision A10-17): the worker expires an open request
// whose validity ended and one whose entry no longer requires approval, and an approved one whose entry lost its
// available assignment, each with software_request.expired and its cause; other decided requests stay; the attention
// list shows a device with open requests until they are gone.
func TestSoftwareRequestExpiry(t *testing.T) {
	h := newRequestHarness(t)
	old, freed, dropped := h.entry(t, h.org, "required"), h.entry(t, h.org, "required"), h.entry(t, h.org, "required")
	if err := h.reports.RecordEvents(systemCtx(h.org), h.dev, time.Now(), []protocol.Event{
		requestEvent(1, "a@acme.test", old), requestEvent(2, "b@acme.test", freed), requestEvent(3, "c@acme.test", old),
		requestEvent(4, "d@acme.test", dropped)}); err != nil {
		t.Fatal(err)
	}
	attention := func() []string {
		rows, err := app.NewAttention(h.apiPool).List(adminCtx(h.org, principal.RoleOrgAdmin, "a"), app.AttentionQuery{
			Page: app.ListPage{Sort: "kind", Limit: 10}, Kinds: []string{"software_requests_open"}})
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, r := range rows.Items {
			out = append(out, r.Kind+" "+r.Detail+" "+r.DeviceID.String())
		}
		return out
	}
	if got := attention(); len(got) != 1 || got[0] != "software_requests_open 4 "+h.dev.String() {
		t.Fatalf("attention %v", got)
	}
	h.exec(t, "UPDATE software_request SET state = 'approved' WHERE username IN ('c@acme.test', 'd@acme.test')")
	h.exec(t, "DELETE FROM software_assignment WHERE catalog_entry_id = $1", dropped)
	h.exec(t, "UPDATE software_request SET expires_at = now() - interval '1 second' WHERE username IN ('a@acme.test', 'c@acme.test')")
	h.exec(t, "UPDATE software_catalog_entry SET approval = 'none' WHERE id = $1", freed)
	if _, err := h.worker.Expire(adminCtx(h.org, principal.RoleOrgAdmin, "a"), time.Now()); !errors.Is(err, problem.Unauthenticated) {
		t.Fatalf("expiry by an administrator: %v", err)
	}
	n, err := h.worker.Expire(systemCtx(h.org), time.Now())
	if err != nil || n != 3 {
		t.Fatalf("expired %d, %v", n, err)
	}
	if n, err := h.worker.Expire(systemCtx(h.org), time.Now()); err != nil || n != 0 {
		t.Fatalf("second round expired %d, %v", n, err)
	}
	rows, err := h.super.Query(context.Background(), `SELECT params->>'user' || ' ' || (params->>'cause') FROM action
		WHERE organization_id = $1 AND code = 'software_request.expired' ORDER BY params->>'user'`, h.org)
	if err != nil {
		t.Fatal(err)
	}
	got, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil || len(got) != 3 || got[0] != "a@acme.test validity_ended" || got[1] != "b@acme.test approval_removed" ||
		got[2] != "d@acme.test assignment_removed" {
		t.Fatalf("expired events %v, %v", got, err)
	}
	if n := h.count(t, "SELECT count(*) FROM software_request WHERE device_id = $1 AND state = 'approved'", h.dev); n != 1 {
		t.Fatalf("approved requests %d, want 1", n)
	}
	if got := attention(); len(got) != 0 {
		t.Fatalf("attention after the expiry %v", got)
	}
}
