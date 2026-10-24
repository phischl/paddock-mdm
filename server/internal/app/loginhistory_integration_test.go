package app_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/phischl/paddock-mdm/pkg/protocol"
	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/domain/loginsettings"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/platform/httpx"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/problem"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
)

type historyWorld struct {
	privilegesHarness
	settings *app.LoginSettings
	api      *app.LoginHistory
	worker   *app.LoginHistory
	reports  *app.DeviceReports
	device   uuid.UUID
	admin    context.Context
}

func newHistoryWorld(t *testing.T) historyWorld {
	t.Helper()
	h := newPrivilegesHarness(t)
	env := pgtest.SharedPaddock(t)
	ctx := context.Background()
	api, err := db.NewOrgPool(ctx, env.API, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(api.Close)
	workerPool, err := db.NewOrgPool(ctx, env.Worker, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(workerPool.Close)
	platform, err := db.NewPlatformPool(ctx, env.Platform, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(platform.Close)
	workerRunner := app.NewActionRunner(workerPool, platform, httpx.RequestID)
	w := historyWorld{
		privilegesHarness: h, settings: app.NewLoginSettings(h.runner, api), api: app.NewLoginHistory(h.runner, api, 24*time.Hour),
		worker: app.NewLoginHistory(workerRunner, workerPool, time.Second), reports: app.NewDeviceReports(workerRunner, workerPool),
		device: uuid.Must(uuid.NewV7()),
	}
	w.admin = principal.With(ctx, h.account(t, principal.RoleOrgAdmin, false))
	if _, err := h.super.Exec(ctx, "INSERT INTO device (id, organization_id, hostname, state) VALUES ($1, $2, 'lh', 'active')", w.device, h.org); err != nil {
		t.Fatal(err)
	}
	return w
}

// setHistory changes only the login history fields of the organization's login settings.
func (w historyWorld) setHistory(t *testing.T, enabled *bool, days *int) error {
	t.Helper()
	cur, err := w.settings.Get(w.admin)
	if err != nil {
		t.Fatal(err)
	}
	var hours *int
	if cur.RotateAfterRevealHours != nil {
		h := int(*cur.RotateAfterRevealHours)
		hours = &h
	}
	_, err = w.settings.Update(w.admin, loginsettings.Settings{
		HelloEnabled: cur.HelloEnabled, HelloPinMinLength: int(cur.HelloPinMinLength), UserLockSessionAction: cur.UserLockSessionAction,
		BreakGlassAccounts: cur.BreakGlassAccounts, SudoersDAllowlist: cur.SudoersDAllowlist, SudoLectureText: cur.SudoLectureText,
		LocalAdminUsername: cur.LocalAdminUsername, LocalAdminRotationDays: int(cur.LocalAdminRotationDays),
		RotateAfterRevealHours: hours, NoticeText: cur.NoticeText, BootPinMinLength: int(cur.BootPinMinLength),
		LoginHistoryEnabled: enabled, LoginHistoryDays: days,
	})
	return err
}

func (w historyWorld) logins(t *testing.T, seq int64, user string, at ...time.Time) {
	t.Helper()
	var events []protocol.Event
	for i, a := range at {
		data, _ := json.Marshal(protocol.SessionLogin{Username: user, At: a})
		events = append(events, protocol.Event{EventSeq: seq + int64(i), Type: protocol.EventSessionLogin, OccurredAt: a.Add(time.Second), Data: data})
	}
	if err := w.reports.RecordEvents(systemCtx(w.org), w.device, time.Now(), events); err != nil {
		t.Fatal(err)
	}
}

func (w historyWorld) count(t *testing.T, table string) int {
	t.Helper()
	var n int
	if err := w.super.QueryRow(context.Background(), fmt.Sprintf("SELECT count(*) FROM %s WHERE device_id = $1", table), w.device).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func boolPtr(b bool) *bool { return &b }
func intPtr(i int) *int    { return &i }

// TestLoginHistory (plan M8d decisions 14–19): off by default; while off a session login only refreshes
// device_user_seen; while on every session start is stored once; the list sorts, filters and isolates; the purge
// deletes expired rows with exactly one retention.purged; switching it off deletes every row with the count.
func TestLoginHistory(t *testing.T) {
	w := newHistoryWorld(t)
	cur, err := w.settings.Get(w.admin)
	if err != nil || cur.LoginHistoryEnabled || cur.LoginHistoryDays != 90 {
		t.Fatalf("defaults %v %d (%v)", cur.LoginHistoryEnabled, cur.LoginHistoryDays, err)
	}
	for _, days := range []int{6, 366} {
		if err := w.setHistory(t, boolPtr(true), intPtr(days)); !errors.Is(err, problem.InvalidRequest) {
			t.Fatalf("%d days: %v", days, err)
		}
	}
	now := time.Now().UTC().Truncate(time.Millisecond)
	w.logins(t, 1, "dave@acme.test", now.Add(-3*time.Minute), now.Add(-2*time.Minute), now.Add(-time.Minute))
	if w.count(t, "device_user_seen") != 1 || w.count(t, "device_login_event") != 0 {
		t.Fatalf("history off: seen %d, events %d", w.count(t, "device_user_seen"), w.count(t, "device_login_event"))
	}

	if err := w.setHistory(t, boolPtr(true), intPtr(30)); err != nil {
		t.Fatal(err)
	}
	// The logins below started before the switch-on above; date it back so they count (finding 13 is tested in
	// TestLoginHistoryBounds).
	if _, err := w.super.Exec(context.Background(), "UPDATE organization_login_settings SET login_history_enabled_at = $2 WHERE organization_id = $1",
		w.org, now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	ev := w.lastEvent(t)
	if ev.Params["login_history_enabled"] != true || ev.Params["login_history_days"] != float64(30) {
		t.Fatalf("enabled params %v", ev.Params)
	}
	w.logins(t, 10, "Dave@acme.test", now.Add(-3*time.Minute), now.Add(-2*time.Minute), now.Add(-time.Minute))
	w.logins(t, 20, "dave@acme.test", now.Add(-time.Minute)) // the same session start again
	w.logins(t, 30, "erin@acme.test", now)
	if n := w.count(t, "device_login_event"); n != 4 {
		t.Fatalf("%d login rows, want 4", n)
	}

	page := app.ListPage{Sort: "-at", Limit: 10}
	listed, err := w.api.List(w.admin, w.device, app.LoginEventQuery{Page: page})
	if err != nil || listed.Count != 4 || listed.Items[0].Username != "erin@acme.test" || !listed.Items[1].At.Equal(now.Add(-time.Minute)) {
		t.Fatalf("list %+v (%v)", listed, err)
	}
	dave := "dave@acme.test"
	if listed, err = w.api.List(w.admin, w.device, app.LoginEventQuery{Page: page, Username: &dave}); err != nil || listed.Count != 3 {
		t.Fatalf("filter %+v (%v)", listed, err)
	}
	if _, err := w.api.List(w.admin, uuid.Must(uuid.NewV7()), app.LoginEventQuery{Page: page}); !errors.Is(err, problem.NotFound) {
		t.Fatalf("unknown device %v", err)
	}
	other := principal.With(context.Background(), principal.Principal{Kind: principal.KindAdmin, ID: uuid.Must(uuid.NewV7()),
		Role: principal.RoleOrgAdmin, OrganizationID: w.otherOrg(t)})
	if _, err := w.api.List(other, w.device, app.LoginEventQuery{Page: page}); !errors.Is(err, problem.NotFound) {
		t.Fatalf("foreign device %v", err)
	}

	// The purge counts days as seconds here: at a point 200 s back nothing is older than 30 s; with 7 days (7 s)
	// shortly after now every login but the newest is.
	if n, err := w.worker.Purge(systemCtx(w.org), now.Add(-200*time.Second)); err != nil || n != 0 {
		t.Fatalf("nothing expired: %d (%v)", n, err)
	}
	if err := w.setHistory(t, nil, intPtr(7)); err != nil {
		t.Fatal(err)
	}
	if n, err := w.worker.Purge(systemCtx(w.org), now.Add(5*time.Second)); err != nil || n != 3 {
		t.Fatalf("purged %d (%v), want 3", n, err)
	}
	if n := w.count(t, "device_login_event"); n != 1 {
		t.Fatalf("%d rows after the purge, want 1", n)
	}
	var purged int
	if err := w.super.QueryRow(context.Background(), `SELECT count(*) FROM outbox WHERE payload ->> 'code' = 'retention.purged'
		AND payload ->> 'organization_id' = $1 AND payload -> 'params' ->> 'store' = 'device_login_event'
		AND (payload -> 'params' ->> 'deleted')::int = 3`, w.org.String()).Scan(&purged); err != nil || purged != 1 {
		t.Fatalf("%d retention.purged events (%v), want 1", purged, err)
	}

	if err := w.setHistory(t, boolPtr(false), nil); err != nil {
		t.Fatal(err)
	}
	ev = w.lastEvent(t)
	if ev.Params["login_history_enabled"] != false || ev.Params["login_history_deleted"] != float64(1) {
		t.Fatalf("disabled params %v", ev.Params)
	}
	if n := w.count(t, "device_login_event"); n != 0 {
		t.Fatalf("%d rows after switching off", n)
	}
}

// otherOrg inserts a second organization.
func (w historyWorld) otherOrg(t *testing.T) uuid.UUID {
	t.Helper()
	id := uuid.Must(uuid.NewV7())
	if _, err := w.super.Exec(context.Background(), "INSERT INTO organization (id, slug, name, status) VALUES ($1, $2, 'O', 'active')",
		id, "h"+id.String()[24:]); err != nil {
		t.Fatal(err)
	}
	return id
}

// TestLoginHistoryBounds (PDK-223 review 1 findings 4 and 13): a login dated in the future is stored at most
// protocol.MaxClockSkew after the server's time; a login before the switch-on or older than the retention window is
// not stored, while device_user_seen still notes the user.
func TestLoginHistoryBounds(t *testing.T) {
	w := newHistoryWorld(t)
	if err := w.setHistory(t, boolPtr(true), intPtr(7)); err != nil {
		t.Fatal(err)
	}
	future := time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)
	w.logins(t, 1, "fred@acme.test", future)
	var at time.Time
	if err := w.super.QueryRow(context.Background(), "SELECT at FROM device_login_event WHERE device_id = $1", w.device).Scan(&at); err != nil {
		t.Fatal(err)
	}
	if at.After(time.Now().Add(protocol.MaxClockSkew)) {
		t.Fatalf("future login stored at %s", at)
	}

	w.logins(t, 2, "gina@acme.test", time.Now().Add(-time.Hour))
	if n := w.count(t, "device_login_event"); n != 1 {
		t.Fatalf("a login before the switch-on was stored: %d rows", n)
	}
	if _, err := w.super.Exec(context.Background(), "UPDATE organization_login_settings SET login_history_enabled_at = now() - interval '30 days' WHERE organization_id = $1", w.org); err != nil {
		t.Fatal(err)
	}
	w.logins(t, 3, "gina@acme.test", time.Now().Add(-8*24*time.Hour))
	if n := w.count(t, "device_login_event"); n != 1 {
		t.Fatalf("a login older than the retention window was stored: %d rows", n)
	}
	w.logins(t, 4, "gina@acme.test", time.Now().Add(-time.Hour))
	if n := w.count(t, "device_login_event"); n != 2 {
		t.Fatalf("a login after the switch-on was not stored: %d rows", n)
	}
	var seen int
	if err := w.super.QueryRow(context.Background(), "SELECT count(*) FROM device_user_seen WHERE device_id = $1 AND username = 'gina@acme.test'", w.device).Scan(&seen); err != nil || seen != 1 {
		t.Fatalf("device_user_seen %d (%v)", seen, err)
	}
	if err := w.setHistory(t, boolPtr(true), nil); err != nil {
		t.Fatal(err)
	}
	var kept bool
	if err := w.super.QueryRow(context.Background(), "SELECT login_history_enabled_at < now() - interval '1 day' FROM organization_login_settings WHERE organization_id = $1", w.org).Scan(&kept); err != nil || !kept {
		t.Fatalf("saving the history on again moved the switch-on time (%v)", err)
	}
}

// TestLoginHistorySwitchOffRace (PDK-223 review 1 finding 3): the worker decides inside its insert transaction under
// the shared login history lock. A switch-off that holds the lock first leaves no row behind, and a switch-off while
// an insert holds the lock waits and deletes the inserted row.
func TestLoginHistorySwitchOffRace(t *testing.T) {
	w := newHistoryWorld(t)
	ctx := context.Background()
	lockAs := func(tx pgx.Tx, shared bool) {
		t.Helper()
		fn := "pg_advisory_xact_lock"
		if shared {
			fn = "pg_advisory_xact_lock_shared"
		}
		if _, err := tx.Exec(ctx, "SELECT set_config('paddock.org_id', $1, true)", w.org.String()); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, "SELECT "+fn+"(hashtextextended('login_history:' || current_setting('paddock.org_id'), 0))"); err != nil {
			t.Fatal(err)
		}
	}

	// A switch-off in progress (lock, update, delete — what LoginSettings.Update does) commits after the worker
	// started: the worker waits and then sees the history off.
	if err := w.setHistory(t, boolPtr(true), nil); err != nil {
		t.Fatal(err)
	}
	tx, err := w.super.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	lockAs(tx, false)
	if _, err := tx.Exec(ctx, "UPDATE organization_login_settings SET login_history_enabled = false, login_history_enabled_at = NULL WHERE organization_id = $1", w.org); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, "DELETE FROM device_login_event WHERE organization_id = $1", w.org); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		data, _ := json.Marshal(protocol.SessionLogin{Username: "hank@acme.test", At: time.Now()})
		_ = w.reports.RecordEvents(systemCtx(w.org), w.device, time.Now(), []protocol.Event{{EventSeq: 1, Type: protocol.EventSessionLogin,
			OccurredAt: time.Now(), Data: data}})
	}()
	select {
	case <-done:
		t.Fatal("the insert did not wait for the switch-off")
	case <-time.After(300 * time.Millisecond):
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	<-done
	if n := w.count(t, "device_login_event"); n != 0 {
		t.Fatalf("%d rows after a switch-off that committed first", n)
	}

	// An insert holds the shared lock: the switch-off waits for it and its deletion sees the row.
	if err := w.setHistory(t, boolPtr(true), nil); err != nil {
		t.Fatal(err)
	}
	tx, err = w.super.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	lockAs(tx, true)
	if _, err := tx.Exec(ctx, "INSERT INTO device_login_event (id, organization_id, device_id, username, at) VALUES ($1, $2, $3, 'ivy@acme.test', now())",
		uuid.Must(uuid.NewV7()), w.org, w.device); err != nil {
		t.Fatal(err)
	}
	off := make(chan error, 1)
	go func() { off <- w.setHistory(t, boolPtr(false), nil) }()
	select {
	case err := <-off:
		t.Fatalf("the switch-off did not wait for the insert: %v", err)
	case <-time.After(300 * time.Millisecond):
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-off; err != nil {
		t.Fatal(err)
	}
	if n := w.count(t, "device_login_event"); n != 0 {
		t.Fatalf("%d rows after a switch-off that waited for the insert", n)
	}
}
