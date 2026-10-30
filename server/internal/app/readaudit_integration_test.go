package app_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
)

// readWorld records the reads of one organization of the harness with a settable clock.
type readWorld struct {
	harness
	reads *app.ReadAudit
	now   time.Time
}

func newReadWorld(t *testing.T, searches, views bool) *readWorld {
	t.Helper()
	w := &readWorld{harness: newHarness(t), now: time.Date(2026, 10, 30, 10, 15, 0, 0, time.UTC)}
	w.reads = app.NewReadAudit(w.runner)
	w.reads.SetClock(func() time.Time { return w.now })
	w.switches(t, w.org, searches, views)
	return w
}

// switches sets the read-access switches of org's privacy settings.
func (h harness) switches(t *testing.T, org uuid.UUID, searches, views bool) {
	t.Helper()
	tag, err := h.super.Exec(context.Background(), `UPDATE organization_privacy_settings
		SET audit_search_recorded = $2, inventory_view_recorded = $3 WHERE organization_id = $1`, org, searches, views)
	if err != nil || tag.RowsAffected() != 1 {
		t.Fatalf("privacy settings of %s: %v (%d rows)", org, err, tag.RowsAffected())
	}
}

// otherOrg creates a second organization with the switches on.
func (h harness) otherOrg(t *testing.T) uuid.UUID {
	t.Helper()
	org := uuid.Must(uuid.NewV7())
	if _, err := h.super.Exec(context.Background(), "INSERT INTO organization (id, slug, name, status) VALUES ($1, $2, 'Other', 'active')",
		org, "o"+org.String()[24:]); err != nil {
		t.Fatal(err)
	}
	h.switches(t, org, true, true)
	return org
}

func (h harness) device(t *testing.T, org uuid.UUID, hostname string) uuid.UUID {
	t.Helper()
	id := uuid.Must(uuid.NewV7())
	if _, err := h.super.Exec(context.Background(), "INSERT INTO device (id, organization_id, hostname, state) VALUES ($1, $2, $3, 'active')",
		id, org, hostname); err != nil {
		t.Fatal(err)
	}
	return id
}

// as is the context of a principal of org.
func as(org uuid.UUID, p principal.Principal) context.Context {
	if p.Kind == "" {
		p.Kind = principal.KindAdmin
	}
	if p.Role == "" {
		p.Role = principal.RoleOrgAdmin
	}
	p.OrganizationID = org
	return principal.With(context.Background(), p)
}

// events returns org's outbox events of code in the order they were written; every one must have its action row.
func (h harness) events(t *testing.T, org uuid.UUID, code audit.Code) []audit.Event {
	t.Helper()
	ctx := context.Background()
	rows, err := h.super.Query(ctx, "SELECT payload FROM outbox WHERE organization_id = $1 AND payload->>'code' = $2 ORDER BY id", org, string(code))
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []audit.Event
	for rows.Next() {
		var raw []byte
		var ev audit.Event
		if err := rows.Scan(&raw); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(raw, &ev); err != nil {
			t.Fatal(err)
		}
		out = append(out, ev)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if n := countRows(t, h.super, "SELECT count(*) FROM action WHERE organization_id = $1 AND code = $2", org, string(code)); n != len(out) {
		t.Fatalf("%d %s action rows, %d outbox rows", n, code, len(out))
	}
	return out
}

// claimWindow is a claim that inserts a real window row of org under actor and then fails with err when it is set.
func claimWindow(org uuid.UUID, actor string, err error) func(context.Context, *pgstore.Queries, app.Recorder) (bool, error) {
	return func(ctx context.Context, q *pgstore.Queries, _ app.Recorder) (bool, error) {
		if _, cerr := q.ClaimReadAuditWindow(ctx, pgstore.ClaimReadAuditWindowParams{
			OrganizationID: org, ActorID: actor, Code: string(audit.CodeAuditSearched), WindowStart: time.Now().UTC().Truncate(time.Hour),
		}); cerr != nil {
			return false, cerr
		}
		return err == nil, err
	}
}

func expectRecorded(t *testing.T, recorded bool, err error, want bool) {
	t.Helper()
	if err != nil || recorded != want {
		t.Fatalf("recorded %v (%v), want %v", recorded, err, want)
	}
}

// TestRecordReadOnce (plan M10 decision 18): a claim that reports an existing window inserts no action and no outbox
// row; a fresh claim inserts its window row, the action and the outbox row in one transaction; a claim error rolls
// the window row back and is recorded as failure; a denied role is recorded as denied without running the claim.
func TestRecordReadOnce(t *testing.T) {
	h := newHarness(t)
	ctx := h.admin(principal.RoleOrgAdmin)
	corr := "corr-" + t.Name()
	claim := func(fresh bool) func(context.Context, *pgstore.Queries, app.Recorder) (bool, error) {
		return func(context.Context, *pgstore.Queries, app.Recorder) (bool, error) { return fresh, nil }
	}

	recorded, err := h.runner.RecordReadOnce(ctx, app.SpecAuditSearched, claim(false))
	expectRecorded(t, recorded, err, false)
	if actions, events := h.recorded(t, corr); len(actions) != 0 || len(events) != 0 {
		t.Fatalf("an existing window recorded %d actions, %d outbox rows", len(actions), len(events))
	}

	recorded, err = h.runner.RecordReadOnce(ctx, app.SpecAuditSearched, claimWindow(h.org, "fresh", nil))
	expectRecorded(t, recorded, err, true)
	ev := expectOne(t, h, audit.OutcomeSuccess, "")
	if ev.Code != audit.CodeAuditSearched {
		t.Fatalf("event %+v", ev)
	}
	if n := countRows(t, h.super, `SELECT count(*) FROM action a JOIN outbox o ON o.payload->>'event_id' = a.id::text
		JOIN read_audit_window w ON w.xmin = a.xmin
		WHERE a.correlation_id = $1 AND a.xmin = o.xmin AND w.actor_id = 'fresh'`, corr); n != 1 {
		t.Fatalf("window, action and outbox row in %d shared transactions, want 1", n)
	}

	t.Run("claim error", func(t *testing.T) {
		h := newHarness(t)
		_, err := h.runner.RecordReadOnce(h.admin(principal.RoleOrgAdmin), app.SpecAuditSearched,
			claimWindow(h.org, "broken", errors.New("claim broke")))
		if err == nil {
			t.Fatal("a claim error was not returned")
		}
		expectOne(t, h, audit.OutcomeFailure, "internal")
		if n := countRows(t, h.super, "SELECT count(*) FROM read_audit_window WHERE organization_id = $1", h.org); n != 0 {
			t.Fatalf("a failed claim left %d window rows", n)
		}
	})
	t.Run("denied", func(t *testing.T) {
		h := newHarness(t)
		called := false
		_, err := h.runner.RecordReadOnce(h.admin(principal.RoleOrgOperator), app.SpecAuditSearched,
			func(context.Context, *pgstore.Queries, app.Recorder) (bool, error) { called = true; return true, nil })
		if !errors.Is(err, app.ErrForbidden) || called {
			t.Fatalf("operator: %v, claim called %v", err, called)
		}
		expectOne(t, h, audit.OutcomeDenied, "forbidden")
	})
}

// TestReadAuditSearched (plan M10 decision 19): one audit.searched per actor and clock hour with the filters of the
// effective range and whether a search text was used, never the text; the next hour records again.
func TestReadAuditSearched(t *testing.T) {
	w := newReadWorld(t, true, false)
	alice := as(w.org, principal.Principal{ID: uuid.Must(uuid.NewV7()), Display: "alice"})
	target := uuid.Must(uuid.NewV7())
	pattern := "%secret%"
	q := app.AuditQuery{Codes: []string{"device.retired"}, TargetID: &target, Page: app.ListPage{QPattern: &pattern}}

	recorded, err := w.reads.AuditSearched(alice, q)
	expectRecorded(t, recorded, err, true)
	w.now = w.now.Add(40 * time.Minute)
	recorded, err = w.reads.AuditSearched(alice, app.AuditQuery{})
	expectRecorded(t, recorded, err, false)

	events := w.events(t, w.org, audit.CodeAuditSearched)
	if len(events) != 1 {
		t.Fatalf("%d audit.searched events in one hour, want 1", len(events))
	}
	p := events[0].Params
	if p["from"] != "2026-10-23T10:15:00Z" || p["to"] != "2026-10-30T10:15:00Z" || p["q_used"] != true ||
		p["window_start"] != "2026-10-30T10:00:00Z" || p["target_id"] != target.String() || p["outcomes"] != nil {
		t.Fatalf("params %v", p)
	}
	if codes, _ := p["codes"].([]any); len(codes) != 1 || codes[0] != "device.retired" {
		t.Fatalf("codes %v", p["codes"])
	}
	raw, _ := json.Marshal(p)
	if _, ok := p["q"]; ok || strings.Contains(string(raw), "secret") {
		t.Fatalf("the search text is recorded: %s", raw)
	}
	if events[0].Outcome != audit.OutcomeSuccess || events[0].Source != audit.SourcePortal {
		t.Fatalf("event %+v", events[0])
	}

	w.now = w.now.Add(10 * time.Minute)
	recorded, err = w.reads.AuditSearched(alice, app.AuditQuery{})
	expectRecorded(t, recorded, err, true)
	if p := w.events(t, w.org, audit.CodeAuditSearched)[1].Params; p["q_used"] != false || p["codes"] != nil || p["target_id"] != nil {
		t.Fatalf("params of the second hour %v", p)
	}
}

// TestReadAuditSearchedUnknownCodes (PDK-139): the code filter is free text, so only registered codes are recorded;
// the others, however long, are only counted.
func TestReadAuditSearchedUnknownCodes(t *testing.T) {
	w := newReadWorld(t, true, false)
	alice := as(w.org, principal.Principal{ID: uuid.Must(uuid.NewV7()), Display: "alice"})
	long := strings.Repeat("leak", 4096)
	recorded, err := w.reads.AuditSearched(alice, app.AuditQuery{Codes: []string{"not.registered", "device.retired", long}})
	expectRecorded(t, recorded, err, true)

	p := w.events(t, w.org, audit.CodeAuditSearched)[0].Params
	if codes, _ := p["codes"].([]any); len(codes) != 1 || codes[0] != "device.retired" {
		t.Fatalf("codes %v", p["codes"])
	}
	if p["codes_unknown"] != float64(2) {
		t.Fatalf("codes_unknown %v, want 2", p["codes_unknown"])
	}
	if raw, _ := json.Marshal(p); strings.Contains(string(raw), "not.registered") || strings.Contains(string(raw), "leak") {
		t.Fatalf("an unregistered code is recorded: %.200s", raw)
	}

	w.now = w.now.Add(time.Hour)
	recorded, err = w.reads.AuditSearched(alice, app.AuditQuery{Codes: []string{"not.registered"}})
	expectRecorded(t, recorded, err, true)
	if p := w.events(t, w.org, audit.CodeAuditSearched)[1].Params; p["codes"] != nil || p["codes_unknown"] != float64(1) {
		t.Fatalf("only unregistered codes: params %v", p)
	}
}

// TestReadAuditSearchedSwitchedOff (plan M10 decision 19): with audit_search_recorded off a search records nothing and
// claims no window; a role that may not read the audit log is recorded as denied whatever the switch.
func TestReadAuditSearchedSwitchedOff(t *testing.T) {
	w := newReadWorld(t, false, true)
	alice := as(w.org, principal.Principal{ID: uuid.Must(uuid.NewV7())})
	recorded, err := w.reads.AuditSearched(alice, app.AuditQuery{})
	expectRecorded(t, recorded, err, false)
	if n := len(w.events(t, w.org, audit.CodeAuditSearched)); n != 0 {
		t.Fatalf("%d events with the switch off", n)
	}
	if n := countRows(t, w.super, "SELECT count(*) FROM read_audit_window WHERE organization_id = $1", w.org); n != 0 {
		t.Fatalf("%d windows claimed with the switch off", n)
	}

	operator := as(w.org, principal.Principal{ID: uuid.Must(uuid.NewV7()), Role: principal.RoleOrgOperator})
	if _, err := w.reads.AuditSearched(operator, app.AuditQuery{}); !errors.Is(err, app.ErrForbidden) {
		t.Fatalf("operator search: %v, want forbidden", err)
	}
	events := w.events(t, w.org, audit.CodeAuditSearched)
	if len(events) != 1 || events[0].Outcome != audit.OutcomeDenied {
		t.Fatalf("events %+v, want one denied", events)
	}

	auditor := as(w.org, principal.Principal{ID: uuid.Must(uuid.NewV7()), Role: principal.RoleOrgAuditor})
	w.switches(t, w.org, true, true)
	recorded, err = w.reads.AuditSearched(auditor, app.AuditQuery{})
	expectRecorded(t, recorded, err, true)
	from := w.now.Add(time.Hour)
	recorded, err = w.reads.AuditSearched(auditor, app.AuditQuery{From: &from})
	expectRecorded(t, recorded, err, false)
}

// TestReadAuditActorKey (plan M10 amendment A5): an API token is coalesced by its token ID, not by the account that
// created it; an MCP session shares the window of its account's portal session and is recorded with source mcp.
func TestReadAuditActorKey(t *testing.T) {
	w := newReadWorld(t, true, true)
	account := uuid.Must(uuid.NewV7())
	portal := as(w.org, principal.Principal{ID: account, Display: "alice"})
	mcp := as(w.org, principal.Principal{ID: account, Display: "alice", Channel: principal.ChannelMCP, MCPClient: "claude"})
	token := uuid.Must(uuid.NewV7())
	apiToken := as(w.org, principal.Principal{ID: account, APITokenID: token, APITokenName: "sweep"})
	otherToken := as(w.org, principal.Principal{ID: account, APITokenID: uuid.Must(uuid.NewV7()), APITokenName: "other"})

	recorded, err := w.reads.AuditSearched(mcp, app.AuditQuery{})
	expectRecorded(t, recorded, err, true)
	recorded, err = w.reads.AuditSearched(portal, app.AuditQuery{})
	expectRecorded(t, recorded, err, false)
	recorded, err = w.reads.AuditSearched(apiToken, app.AuditQuery{})
	expectRecorded(t, recorded, err, true)
	recorded, err = w.reads.AuditSearched(apiToken, app.AuditQuery{})
	expectRecorded(t, recorded, err, false)
	recorded, err = w.reads.AuditSearched(otherToken, app.AuditQuery{})
	expectRecorded(t, recorded, err, true)

	events := w.events(t, w.org, audit.CodeAuditSearched)
	if len(events) != 3 {
		t.Fatalf("%d events, want 3", len(events))
	}
	if ev := events[0]; ev.Source != audit.SourceMCP || ev.Actor.Type != audit.ActorAdmin || ev.Actor.Client != "claude" {
		t.Fatalf("MCP event %+v", ev)
	}
	if ev := events[1]; ev.Source != audit.SourceAPI || ev.Actor.Type != audit.ActorAPIToken || ev.Actor.ID != token.String() {
		t.Fatalf("API token event %+v", ev)
	}

	w.now = w.now.Add(time.Hour)
	recorded, err = w.reads.AuditSearched(portal, app.AuditQuery{})
	expectRecorded(t, recorded, err, true)
	recorded, err = w.reads.AuditSearched(mcp, app.AuditQuery{})
	expectRecorded(t, recorded, err, false)
}

// TestReadAuditConcurrent (plan M10 decision 18): concurrent searches of one actor in one window record exactly one
// event; the others see the claimed window.
func TestReadAuditConcurrent(t *testing.T) {
	w := newReadWorld(t, true, true)
	alice := as(w.org, principal.Principal{ID: uuid.Must(uuid.NewV7())})
	dev := w.device(t, w.org, "conc")
	const n = 8
	var wg sync.WaitGroup
	results := make(chan bool, 2*n)
	errs := make(chan error, 2*n)
	for range n {
		wg.Add(2)
		go func() {
			defer wg.Done()
			ok, err := w.reads.AuditSearched(alice, app.AuditQuery{})
			results <- ok
			errs <- err
		}()
		go func() {
			defer wg.Done()
			ok, err := w.reads.InventoryViewed(alice, dev, app.InventoryViewSoftware)
			results <- ok
			errs <- err
		}()
	}
	wg.Wait()
	close(results)
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	recorded := 0
	for ok := range results {
		if ok {
			recorded++
		}
	}
	if recorded != 2 || len(w.events(t, w.org, audit.CodeAuditSearched)) != 1 || len(w.events(t, w.org, audit.CodeDeviceInventoryViewed)) != 1 {
		t.Fatalf("%d reads recorded, want one search and one view", recorded)
	}
}

// TestReadAuditInventoryViewed (plan M10 decisions 19–20): the software and then the vulnerabilities of one device on
// one UTC day record one device.inventory_viewed with the first view; the next day records again; a missing device,
// another organization's device and the switch off record nothing.
func TestReadAuditInventoryViewed(t *testing.T) {
	w := newReadWorld(t, false, true)
	alice := as(w.org, principal.Principal{ID: uuid.Must(uuid.NewV7()), Role: principal.RoleOrgOperator})
	dev := w.device(t, w.org, "ws-17")

	recorded, err := w.reads.InventoryViewed(alice, dev, app.InventoryViewSoftware)
	expectRecorded(t, recorded, err, true)
	w.now = w.now.Add(13 * time.Hour)
	recorded, err = w.reads.InventoryViewed(alice, dev, app.InventoryViewVulnerabilities)
	expectRecorded(t, recorded, err, false)
	events := w.events(t, w.org, audit.CodeDeviceInventoryViewed)
	if len(events) != 1 {
		t.Fatalf("%d events on one day, want 1", len(events))
	}
	ev := events[0]
	if ev.Target == nil || ev.Target.Type != "device" || ev.Target.ID != dev.String() || ev.Params["view"] != "software" ||
		ev.Params["hostname"] != "ws-17" || ev.Params["window_start"] != "2026-10-30T00:00:00Z" || ev.Outcome != audit.OutcomeSuccess {
		t.Fatalf("event %+v", ev)
	}

	w.now = w.now.Add(time.Hour)
	recorded, err = w.reads.InventoryViewed(alice, dev, app.InventoryViewVulnerabilities)
	expectRecorded(t, recorded, err, true)

	recorded, err = w.reads.InventoryViewed(alice, uuid.Must(uuid.NewV7()), app.InventoryViewSoftware)
	expectRecorded(t, recorded, err, false)
	other := w.otherOrg(t)
	foreign := w.device(t, other, "globex-1")
	recorded, err = w.reads.InventoryViewed(alice, foreign, app.InventoryViewSoftware)
	expectRecorded(t, recorded, err, false)
	if n := len(w.events(t, other, audit.CodeDeviceInventoryViewed)); n != 0 {
		t.Fatalf("a view of a foreign device recorded %d events in its organization", n)
	}
	if n := len(w.events(t, w.org, audit.CodeDeviceInventoryViewed)); n != 2 {
		t.Fatalf("%d events, want 2", n)
	}

	w.switches(t, w.org, false, false)
	w.now = w.now.Add(24 * time.Hour)
	recorded, err = w.reads.InventoryViewed(alice, dev, app.InventoryViewSoftware)
	expectRecorded(t, recorded, err, false)
}

// TestReadAuditOrganizations: windows belong to their organization. The same account claims its window in each
// organization it reads, a search in one organization never coalesces with or shows up in the other, and the API role
// sees only its own organization's windows.
func TestReadAuditOrganizations(t *testing.T) {
	w := newReadWorld(t, true, true)
	other := w.otherOrg(t)
	account := uuid.Must(uuid.NewV7())

	recorded, err := w.reads.AuditSearched(as(w.org, principal.Principal{ID: account}), app.AuditQuery{})
	expectRecorded(t, recorded, err, true)
	recorded, err = w.reads.AuditSearched(as(other, principal.Principal{ID: account}), app.AuditQuery{})
	expectRecorded(t, recorded, err, true)
	for _, org := range []uuid.UUID{w.org, other} {
		if n := len(w.events(t, org, audit.CodeAuditSearched)); n != 1 {
			t.Fatalf("organization %s has %d events, want 1", org, n)
		}
	}

	pool, err := db.NewOrgPool(context.Background(), pgtest.SharedPaddock(t).API, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	third := w.otherOrg(t)
	for org, want := range map[uuid.UUID]bool{w.org: true, third: false} {
		var visible bool
		if err := pool.InOrg(as(org, principal.Principal{ID: account}), func(ctx context.Context, q *pgstore.Queries) error {
			var err error
			visible, err = q.HasExpiredReadAuditWindows(ctx, w.now.Add(time.Hour))
			return err
		}); err != nil || visible != want {
			t.Fatalf("organization %s sees windows: %v (%v), want %v", org, visible, err, want)
		}
	}
	if n := countRows(t, w.super, "SELECT count(*) FROM read_audit_window WHERE actor_id = $1", account.String()); n != 2 {
		t.Fatalf("%d windows of the account, want one per organization", n)
	}
}

// TestRetentionPurgeReadWindowsOpenWindows: a development installation counts the 48 hours as seconds, yet the pass
// never deletes a key whose window may still be open (a UTC day), so coalescing keeps working there; only the system
// principal purges.
func TestRetentionPurgeReadWindowsOpenWindows(t *testing.T) {
	w := newRetentionWorld(t)
	ctx := context.Background()
	now := time.Now().UTC()
	org := w.organization(t, 0, now)
	for i, start := range []time.Time{now.Add(-10 * time.Second), now.Add(-23 * time.Hour), now.Add(-25 * time.Hour)} {
		if _, err := w.super.Exec(ctx, `INSERT INTO read_audit_window (organization_id, actor_id, code, window_start)
			VALUES ($1, $2, 'device.inventory_viewed', $3)`, org, uuid.NewString(), start); err != nil {
			t.Fatalf("window %d: %v", i, err)
		}
	}
	if _, err := w.retention.PurgeReadWindows(as(org, principal.Principal{ID: uuid.Must(uuid.NewV7())}), now); err == nil {
		t.Fatal("an administrator purged the read windows")
	}
	if n, err := w.retention.PurgeReadWindows(systemCtx(org), now); err != nil || n != 1 {
		t.Fatalf("purged %d (%v), want the window older than a day", n, err)
	}
	if n := countRows(t, w.super, "SELECT count(*) FROM read_audit_window WHERE organization_id = $1", org); n != 2 {
		t.Fatalf("%d windows left, want 2", n)
	}
	if n, err := w.retention.PurgeReadWindows(systemCtx(org), now); err != nil || n != 0 {
		t.Fatalf("second purge %d (%v)", n, err)
	}
	if n := countRows(t, w.super, `SELECT count(*) FROM action WHERE organization_id = $1 AND code = 'retention.purged'
		AND params->>'store' = 'read_audit_window'`, org); n != 1 {
		t.Fatalf("%d retention.purged events, want 1 (none without expired windows)", n)
	}
}
