package app_test

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/domain/outbound"
	"github.com/phischl/paddock-mdm/server/internal/platform/bao"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/problem"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
)

// fakeKeys stands in for Transit: the ciphertext names key, organization and field, so a test sees which context
// every secret was encrypted under, and never contains the plaintext.
type fakeKeys struct {
	mu    sync.Mutex
	calls []string
}

func (k *fakeKeys) Encrypt(_ context.Context, key string, org uuid.UUID, field bao.ContextField, plaintext []byte) (string, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.calls = append(k.calls, "encrypt "+key+" "+string(field))
	return fmt.Sprintf("vault:v1:%s:%s:%s:%d", key, org, field, len(k.calls)), nil
}

func (k *fakeKeys) WrappedDataKey(_ context.Context, key string, org uuid.UUID, field bao.ContextField) (string, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.calls = append(k.calls, "datakey "+key+" "+string(field))
	return fmt.Sprintf("vault:v1:%s:%s:%s", key, org, field), nil
}

type stubResolver map[string][]netip.Addr

func (r stubResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	if a, ok := r[host]; ok {
		return a, nil
	}
	return nil, errors.New("no such host")
}

type notificationWorld struct {
	harness
	n     *app.Notifications
	keys  *fakeKeys
	other uuid.UUID
	// with builds the use cases on the same pools with another SMTP setting.
	with func(emailEnabled bool) *app.Notifications
}

func newNotificationWorld(t *testing.T, emailEnabled bool) notificationWorld {
	t.Helper()
	h := newHarness(t)
	ctx := context.Background()
	env := pgtest.SharedPaddock(t)
	orgPool, err := db.NewOrgPool(ctx, env.API, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(orgPool.Close)
	platformPool, err := db.NewPlatformPool(ctx, env.Platform, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(platformPool.Close)
	keys := &fakeKeys{}
	policy := outbound.Policy{Resolver: stubResolver{
		"hooks.example.org":    {netip.MustParseAddr("93.184.215.14")},
		"intranet.example.org": {netip.MustParseAddr("10.1.2.3")},
	}}
	with := func(emailEnabled bool) *app.Notifications {
		return app.NewNotifications(h.runner, orgPool, platformPool, keys, policy, emailEnabled)
	}
	w := notificationWorld{harness: h, keys: keys, other: uuid.Must(uuid.NewV7()), n: with(emailEnabled), with: with}
	if _, err := h.super.Exec(ctx, "INSERT INTO organization (id, slug, name, status) VALUES ($1, $2, 'Other', 'active')",
		w.other, "o"+w.other.String()[24:]); err != nil {
		t.Fatal(err)
	}
	return w
}

// stepped is an administrator of org with a fresh step-up.
func stepped(org uuid.UUID, role principal.Role) context.Context {
	return principal.With(context.Background(), principal.Principal{
		Kind: principal.KindAdmin, ID: uuid.Must(uuid.NewV7()), Display: "alice", Role: role, OrganizationID: org,
		StepUpAt: time.Now(),
	})
}

func steppedPlatform() context.Context {
	return principal.With(context.Background(), principal.Principal{
		Kind: principal.KindPlatformAdmin, ID: uuid.Must(uuid.NewV7()), Display: "root", Role: principal.RolePlatform,
		StepUpAt: time.Now(),
	})
}

func webhookInput(name string) app.NotificationDestinationInput {
	u := "https://hooks.example.org/services/T000/B000/XXXX?token=abc"
	return app.NotificationDestinationInput{Type: outbound.TypeWebhook, Name: name, Enabled: true,
		FilterMode: outbound.FilterSecurity, URL: &u}
}

func wantProblem(t *testing.T, err error, want *problem.Error, what string) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("%s: err %v, want %s", what, err, want.Code)
	}
}

// TestNotificationDestinationCreate: a webhook destination stores the URL and the secret as ciphertexts under the
// organization's context, returns the secret once, starts at the newest event, and records the display URL only.
func TestNotificationDestinationCreate(t *testing.T) {
	w := newNotificationWorld(t, false)
	ctx := context.Background()
	d, secret, err := w.n.Create(stepped(w.org, principal.RoleOrgAdmin), app.ScopeOrg, webhookInput("SIEM"))
	if err != nil {
		t.Fatal(err)
	}
	if len(secret) != 43 {
		t.Fatalf("secret %q, want 43 characters", secret)
	}
	if d.URLDisplay == nil || *d.URLDisplay != "https://hooks.example.org/…" || d.State.Status != "active" || d.CreatedBy != "alice" {
		t.Fatalf("destination %+v", d)
	}
	var urlCT, secretCT, display string
	var startAtLatest bool
	var cursor int64
	if err := w.super.QueryRow(ctx, `SELECT d.url_ciphertext, d.secret_ciphertext, d.url_display, s.start_at_latest, s.cursor_commit_seq
		FROM notification_destination d JOIN notification_destination_state s ON s.destination_id = d.id WHERE d.id = $1`, d.ID).
		Scan(&urlCT, &secretCT, &display, &startAtLatest, &cursor); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(urlCT, "vault:v1:notification-wrap:"+w.org.String()+":url:") ||
		!strings.HasPrefix(secretCT, "vault:v1:notification-wrap:"+w.org.String()+":secret:") {
		t.Fatalf("ciphertexts %q %q, want notification-wrap under the organization's url and secret context", urlCT, secretCT)
	}
	if strings.Contains(urlCT+secretCT+display, "token") || strings.Contains(urlCT+secretCT, secret) {
		t.Fatal("a plaintext secret reached the database")
	}
	if !startAtLatest || cursor != 0 {
		t.Fatalf("state start_at_latest %t cursor %d, want the marker set and no cursor written", startAtLatest, cursor)
	}
	_, events := w.recorded(t, "corr-"+t.Name())
	if len(events) != 1 || events[0].Code != audit.CodeNotificationDestinationCreated || events[0].Outcome != audit.OutcomeSuccess {
		t.Fatalf("events %+v", events)
	}
	ev := events[0]
	if ev.Params["url_display"] != "https://hooks.example.org/…" || ev.Params["name"] != "SIEM" || ev.Target == nil ||
		ev.Target.ID != d.ID.String() {
		t.Fatalf("event params %v target %+v", ev.Params, ev.Target)
	}
	if _, ok := ev.Params["recipient_count"]; ok {
		t.Fatal("a webhook event names recipient_count")
	}
	for k, v := range ev.Params {
		if strings.Contains(fmt.Sprint(v), secret) || strings.Contains(fmt.Sprint(v), "token=") {
			t.Fatalf("param %s carries a secret", k)
		}
	}

	if _, _, err := w.n.Create(stepped(w.org, principal.RoleOrgAdmin), app.ScopeOrg, webhookInput("SIEM")); !errors.Is(err, problem.AlreadyExists) {
		t.Fatalf("duplicate name: %v", err)
	}
	_, _, err = w.n.Create(stepped(w.other, principal.RoleOrgAdmin), app.ScopeOrg, webhookInput("SIEM"))
	if err != nil {
		t.Fatalf("the same name in another organization: %v", err)
	}
}

// TestNotificationDestinationValidation covers plan M9 decision 9 and gate N5 with the production URL policy.
func TestNotificationDestinationValidation(t *testing.T) {
	w := newNotificationWorld(t, false)
	ctx := stepped(w.org, principal.RoleOrgAdmin)
	for _, raw := range []string{
		"http://hooks.example.org/x", "https://127.0.0.1/", "https://10.0.0.1/", "https://user:pw@hooks.example.org/",
		"https://hooks.example.org:80/", "https://intranet.example.org/", "https://[::1]/", "https://unknown.example.org/",
	} {
		in := webhookInput("bad url")
		in.URL = &raw
		_, _, err := w.n.Create(ctx, app.ScopeOrg, in)
		var p *problem.Error
		if !errors.As(err, &p) || p.Code != "invalid_request" || !strings.Contains(p.Detail, "invalid webhook URL") {
			t.Errorf("%s: %v, want invalid_request naming the URL rule", raw, err)
		}
		if p != nil && strings.Contains(p.Detail, raw) {
			t.Errorf("%s: the detail echoes the URL", raw)
		}
	}
	in := webhookInput("heartbeat")
	in.HeartbeatIntervalS = 30
	_, _, err := w.n.Create(ctx, app.ScopeOrg, in)
	var p *problem.Error
	if !errors.As(err, &p) || p.Code != "invalid_request" || !strings.Contains(p.Detail, "heartbeat_interval_s") {
		t.Errorf("heartbeat 30: %v", err)
	}
	in = webhookInput("custom")
	in.FilterMode, in.Codes = outbound.FilterCustom, []string{"admin.login", "no.such_code"}
	_, _, err = w.n.Create(ctx, app.ScopeOrg, in)
	wantProblem(t, err, problem.UnknownCode, "unregistered code")
	in.Codes = []string{"admin.login", "admin.login"}
	_, _, err = w.n.Create(ctx, app.ScopeOrg, in)
	wantProblem(t, err, problem.InvalidRequest, "duplicate code")
	in = webhookInput("no url")
	in.URL = nil
	_, _, err = w.n.Create(ctx, app.ScopeOrg, in)
	wantProblem(t, err, problem.InvalidRequest, "webhook without url")

	email := app.NotificationDestinationInput{Type: outbound.TypeEmail, Name: "secops", Enabled: true,
		FilterMode: outbound.FilterAll, Recipients: []string{"secops@example.org"}, EmailMinIntervalS: 300}
	_, _, err = w.n.Create(ctx, app.ScopeOrg, email)
	wantProblem(t, err, problem.EmailNotConfigured, "e-mail without SMTP")

	_, _, err = w.n.Create(principal.With(context.Background(), principal.Principal{Kind: principal.KindAdmin,
		ID: uuid.Must(uuid.NewV7()), Role: principal.RoleOrgAdmin, OrganizationID: w.org}), app.ScopeOrg, webhookInput("no step-up"))
	wantProblem(t, err, problem.StepUpRequired, "without step-up")
	_, _, err = w.n.Create(stepped(w.org, principal.RoleOrgOperator), app.ScopeOrg, webhookInput("operator"))
	wantProblem(t, err, problem.Forbidden, "operator")

	actions, _ := w.recorded(t, "corr-"+t.Name())
	denied := 0
	for _, a := range actions {
		if a.outcome != nil && *a.outcome == string(audit.OutcomeDenied) {
			denied++
		}
	}
	if len(actions) != 15 || denied != 2 {
		t.Fatalf("%d actions (%d denied), want one per attempt (15, 2 denied)", len(actions), denied)
	}
}

// TestNotificationDestinationEmail: with an SMTP relay an e-mail destination takes 1–20 plain addresses.
func TestNotificationDestinationEmail(t *testing.T) {
	w := newNotificationWorld(t, true)
	ctx := stepped(w.org, principal.RoleOrgAdmin)
	if email, err := w.n.Capabilities(ctx); err != nil || !email {
		t.Fatalf("capabilities %t %v", email, err)
	}
	in := app.NotificationDestinationInput{Type: outbound.TypeEmail, Name: "secops", Enabled: true,
		FilterMode: outbound.FilterAll, Recipients: []string{"a@example.org", "b@example.org"}, EmailMinIntervalS: 600}
	d, secret, err := w.n.Create(ctx, app.ScopeOrg, in)
	if err != nil || secret != "" || d.URLDisplay != nil || len(d.Recipients) != 2 || d.EmailMinIntervalS != 600 {
		t.Fatalf("e-mail destination %+v secret %q err %v", d, secret, err)
	}
	if _, err := w.n.RotateSecret(ctx, app.ScopeOrg, d.ID); !errors.Is(err, problem.InvalidState) {
		t.Fatalf("rotating an e-mail destination: %v", err)
	}
	many := make([]string, 21)
	for i := range many {
		many[i] = fmt.Sprintf("r%d@example.org", i)
	}
	in.Name, in.Recipients = "many", many
	_, _, err = w.n.Create(ctx, app.ScopeOrg, in)
	wantProblem(t, err, problem.InvalidRequest, "21 recipients")
	in.Recipients = []string{"Sec Ops <secops@example.org>"}
	_, _, err = w.n.Create(ctx, app.ScopeOrg, in)
	wantProblem(t, err, problem.InvalidRequest, "display name")

	// Without a relay an existing e-mail destination can still be renamed and disabled, but not enabled again.
	off := w.with(false)
	upd := app.NotificationDestinationInput{Name: "secops renamed", Enabled: true, FilterMode: outbound.FilterAll,
		Recipients: []string{"a@example.org"}, EmailMinIntervalS: 600}
	if got, err := off.Update(ctx, app.ScopeOrg, d.ID, upd); err != nil || got.Name != "secops renamed" {
		t.Fatalf("rename without SMTP: %+v %v", got, err)
	}
	upd.Enabled = false
	if got, err := off.Update(ctx, app.ScopeOrg, d.ID, upd); err != nil || got.Enabled {
		t.Fatalf("disable without SMTP: %+v %v", got, err)
	}
	upd.Enabled, upd.Cursor = true, app.CursorContinue
	_, err = off.Update(ctx, app.ScopeOrg, d.ID, upd)
	wantProblem(t, err, problem.EmailNotConfigured, "enabling without SMTP")
	if _, err := w.n.Update(ctx, app.ScopeOrg, d.ID, upd); err != nil {
		t.Fatalf("enabling with SMTP: %v", err)
	}
	_, events := w.recorded(t, "corr-"+t.Name())
	for _, ev := range events {
		if ev.Code == audit.CodeNotificationDestinationUpdated && ev.Outcome == audit.OutcomeSuccess &&
			(ev.Params["type"] != "email" || ev.Params["recipient_count"] != float64(1)) {
			t.Fatalf("e-mail update params %v", ev.Params)
		}
	}
}

// TestNotificationDestinationUpdate: the URL is kept without url and replaced with one, the type never changes, and
// enabling a disabled destination needs a cursor choice; skip sets the start_at_latest marker, continue does not.
func TestNotificationDestinationUpdate(t *testing.T) {
	w := newNotificationWorld(t, false)
	ctx := stepped(w.org, principal.RoleOrgAdmin)
	bg := context.Background()
	d, _, err := w.n.Create(ctx, app.ScopeOrg, webhookInput("hook"))
	if err != nil {
		t.Fatal(err)
	}
	urlCT := func() string {
		var s string
		if err := w.super.QueryRow(bg, "SELECT url_ciphertext FROM notification_destination WHERE id = $1", d.ID).Scan(&s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	before := urlCT()
	in := webhookInput("hook renamed")
	in.URL, in.Enabled = nil, false
	got, err := w.n.Update(ctx, app.ScopeOrg, d.ID, in)
	if err != nil || got.Name != "hook renamed" || got.Enabled || urlCT() != before || *got.URLDisplay != "https://hooks.example.org/…" {
		t.Fatalf("update without url: %+v %v", got, err)
	}
	other := "https://hooks.example.org/"
	in.URL = &other
	got, err = w.n.Update(ctx, app.ScopeOrg, d.ID, in)
	if err != nil || urlCT() == before || *got.URLDisplay != "https://hooks.example.org" {
		t.Fatalf("update with url: %+v %v", got, err)
	}
	bad := "https://10.0.0.1/"
	in.URL = &bad
	_, err = w.n.Update(ctx, app.ScopeOrg, d.ID, in)
	wantProblem(t, err, problem.InvalidRequest, "private URL on update")
	in.URL, in.Type = nil, outbound.TypeEmail
	_, err = w.n.Update(ctx, app.ScopeOrg, d.ID, in)
	wantProblem(t, err, problem.InvalidRequest, "type change")
	in.Type = ""

	if _, err := w.super.Exec(bg, "UPDATE notification_destination_state SET start_at_latest = false, cursor_commit_seq = 42 WHERE destination_id = $1", d.ID); err != nil {
		t.Fatal(err)
	}
	marker := func() (bool, int64) {
		var b bool
		var c int64
		if err := w.super.QueryRow(bg, "SELECT start_at_latest, cursor_commit_seq FROM notification_destination_state WHERE destination_id = $1", d.ID).Scan(&b, &c); err != nil {
			t.Fatal(err)
		}
		return b, c
	}
	in.Enabled = true
	_, err = w.n.Update(ctx, app.ScopeOrg, d.ID, in)
	wantProblem(t, err, problem.InvalidRequest, "enabling without cursor")
	in.Cursor = app.CursorContinue
	if _, err := w.n.Update(ctx, app.ScopeOrg, d.ID, in); err != nil {
		t.Fatal(err)
	}
	if b, c := marker(); b || c != 42 {
		t.Fatalf("continue: marker %t cursor %d, want unchanged", b, c)
	}
	in.Enabled, in.Cursor = false, ""
	if _, err := w.n.Update(ctx, app.ScopeOrg, d.ID, in); err != nil {
		t.Fatal(err)
	}
	in.Enabled, in.Cursor = true, app.CursorSkip
	if _, err := w.n.Update(ctx, app.ScopeOrg, d.ID, in); err != nil {
		t.Fatal(err)
	}
	if b, c := marker(); !b || c != 42 {
		t.Fatalf("skip: marker %t cursor %d, want the marker set and the cursor untouched by the api", b, c)
	}
	in.Cursor = app.CursorSkip
	_, err = w.n.Update(ctx, app.ScopeOrg, d.ID, in)
	wantProblem(t, err, problem.InvalidRequest, "cursor on an enabled destination")

	_, events := w.recorded(t, "corr-"+t.Name())
	var last audit.Event
	for _, ev := range events {
		if ev.Code == audit.CodeNotificationDestinationUpdated && ev.Outcome == audit.OutcomeSuccess {
			last = ev
		}
	}
	if last.Params["cursor"] != "skip" || fmt.Sprint(last.Params["changed"]) != "[enabled]" ||
		last.Params["type"] != "webhook" || last.Params["url_display"] != "https://hooks.example.org" {
		t.Fatalf("last update params %v, want the stored type and URL display of a PUT without type and url", last.Params)
	}
}

// TestNotificationDestinationIsolation: another organization's destination is not_found for every read and write,
// and the platform scope sees only nil-organization rows.
func TestNotificationDestinationIsolation(t *testing.T) {
	w := newNotificationWorld(t, false)
	a, _, err := w.n.Create(stepped(w.org, principal.RoleOrgAdmin), app.ScopeOrg, webhookInput("A hook"))
	if err != nil {
		t.Fatal(err)
	}
	b := stepped(w.other, principal.RoleOrgAdmin)
	if _, err := w.n.Get(b, app.ScopeOrg, a.ID); !errors.Is(err, problem.NotFound) {
		t.Errorf("get: %v", err)
	}
	if _, err := w.n.Update(b, app.ScopeOrg, a.ID, webhookInput("stolen")); !errors.Is(err, problem.NotFound) {
		t.Errorf("update: %v", err)
	}
	if _, err := w.n.RotateSecret(b, app.ScopeOrg, a.ID); !errors.Is(err, problem.NotFound) {
		t.Errorf("rotate: %v", err)
	}
	if _, err := w.n.Test(b, app.ScopeOrg, a.ID); !errors.Is(err, problem.NotFound) {
		t.Errorf("test: %v", err)
	}
	if _, err := w.n.ResolvePseudonym(b, a.ID, "u_0123456789abcdef01234567"); !errors.Is(err, problem.NotFound) {
		t.Errorf("resolve: %v", err)
	}
	if err := w.n.Delete(b, app.ScopeOrg, a.ID); !errors.Is(err, problem.NotFound) {
		t.Errorf("delete: %v", err)
	}
	list, err := w.n.List(b, app.ScopeOrg, app.NotificationQuery{Page: app.ListPage{Sort: "name", Limit: 25}})
	if err != nil || list.Count != 0 {
		t.Errorf("B lists %d destinations, %v", list.Count, err)
	}
	if _, err := w.n.Get(steppedPlatform(), app.ScopePlatform, a.ID); !errors.Is(err, problem.NotFound) {
		t.Errorf("platform get of an organization destination: %v", err)
	}
	if _, err := w.n.Get(stepped(w.org, principal.RoleOrgAdmin), app.ScopeOrg, a.ID); err != nil {
		t.Errorf("A reads its own destination: %v", err)
	}
}

// TestNotificationDestinationForeignKeyIsNotFound: a foreign key violation on a destination reference (another
// organization's destination since the composite keys of migration 00085) answers not_found.
func TestNotificationDestinationForeignKeyIsNotFound(t *testing.T) {
	w := newNotificationWorld(t, false)
	a, _, err := w.n.Create(stepped(w.org, principal.RoleOrgAdmin), app.ScopeOrg, webhookInput("A hook"))
	if err != nil {
		t.Fatal(err)
	}
	env := pgtest.SharedPaddock(t)
	orgPool, err := db.NewOrgPool(context.Background(), env.API, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(orgPool.Close)
	err = orgPool.InOrg(stepped(w.other, principal.RoleOrgAdmin), func(ctx context.Context, q *pgstore.Queries) error {
		return q.InsertNotificationTestDelivery(ctx, pgstore.InsertNotificationTestDeliveryParams{
			ID: uuid.Must(uuid.NewV7()), DestinationID: a.ID, OrganizationID: w.other, RequestedBy: nil,
		})
	})
	if !db.IsForeignKeyViolation(err) {
		t.Fatalf("insert naming another organization's destination: %v, want 23503", err)
	}
	if got := app.ForeignNotFound(err); !errors.Is(got, problem.NotFound) {
		t.Fatalf("mapped to %v, want not_found", got)
	}
}

// TestNotificationDestinationReads: auditors read the configuration, operators do not; lists filter and sort.
func TestNotificationDestinationReads(t *testing.T) {
	w := newNotificationWorld(t, false)
	admin := stepped(w.org, principal.RoleOrgAdmin)
	for _, name := range []string{"b hook", "a hook"} {
		if _, _, err := w.n.Create(admin, app.ScopeOrg, webhookInput(name)); err != nil {
			t.Fatal(err)
		}
	}
	off := webhookInput("c off")
	off.Enabled = false
	if _, _, err := w.n.Create(admin, app.ScopeOrg, off); err != nil {
		t.Fatal(err)
	}
	auditor := stepped(w.org, principal.RoleOrgAuditor)
	list, err := w.n.List(auditor, app.ScopeOrg, app.NotificationQuery{Page: app.ListPage{Sort: "name", Limit: 25}})
	if err != nil || list.Count != 3 || list.Items[0].Name != "a hook" || list.Items[2].Name != "c off" {
		t.Fatalf("auditor list %+v %v", list, err)
	}
	enabled := false
	list, err = w.n.List(auditor, app.ScopeOrg, app.NotificationQuery{Page: app.ListPage{Sort: "-name", Limit: 25}, Enabled: &enabled, Types: []string{"webhook"}})
	if err != nil || list.Count != 1 || list.Items[0].Name != "c off" {
		t.Fatalf("filtered list %+v %v", list, err)
	}
	if _, err := w.n.List(stepped(w.org, principal.RoleOrgOperator), app.ScopeOrg, app.NotificationQuery{Page: app.ListPage{Sort: "name", Limit: 25}}); !errors.Is(err, problem.Forbidden) {
		t.Fatalf("operator list: %v", err)
	}
	if _, err := w.n.Capabilities(stepped(w.org, principal.RoleOrgOperator)); !errors.Is(err, problem.Forbidden) {
		t.Fatalf("operator capabilities: %v", err)
	}
	if email, err := w.n.Capabilities(auditor); err != nil || email {
		t.Fatalf("capabilities without SMTP: %t %v", email, err)
	}
}

// TestNotificationDestinationPlatform: platform destinations live in the nil organization, only platform
// administrators manage them, and they never pseudonymize.
func TestNotificationDestinationPlatform(t *testing.T) {
	w := newNotificationWorld(t, false)
	d, secret, err := w.n.Create(steppedPlatform(), app.ScopePlatform, webhookInput("platform-"+uuid.NewString()[:8]))
	if err != nil || secret == "" {
		t.Fatalf("platform create: %v", err)
	}
	var org uuid.UUID
	var urlCT string
	if err := w.super.QueryRow(context.Background(), "SELECT organization_id, url_ciphertext FROM notification_destination WHERE id = $1", d.ID).Scan(&org, &urlCT); err != nil {
		t.Fatal(err)
	}
	if org != uuid.Nil || !strings.HasPrefix(urlCT, "vault:v1:notification-wrap:"+uuid.Nil.String()+":url:") {
		t.Fatalf("platform row organization %s ciphertext %q", org, urlCT)
	}
	if _, err := w.n.Get(stepped(w.org, principal.RoleOrgAdmin), app.ScopeOrg, d.ID); !errors.Is(err, problem.NotFound) {
		t.Errorf("an organization reads a platform destination: %v", err)
	}
	_, _, err = w.n.Create(stepped(w.org, principal.RoleOrgAdmin), app.ScopePlatform, webhookInput("from org"))
	wantProblem(t, err, problem.Forbidden, "organization session on the platform scope")
	if _, err := w.n.List(stepped(w.org, principal.RoleOrgAdmin), app.ScopePlatform, app.NotificationQuery{Page: app.ListPage{Sort: "name", Limit: 25}}); !errors.Is(err, problem.Forbidden) {
		t.Errorf("organization list of the platform scope: %v", err)
	}
	_, _, err = w.n.Create(steppedPlatform(), app.ScopeOrg, webhookInput("platform in org"))
	wantProblem(t, err, problem.NoOrganization, "platform session on the organization scope")
	in := webhookInput("pseudo")
	in.PseudonymizeUsers = true
	_, _, err = w.n.Create(steppedPlatform(), app.ScopePlatform, in)
	wantProblem(t, err, problem.InvalidRequest, "platform pseudonymization")

	in = webhookInput(d.Name)
	in.URL, in.HeartbeatIntervalS = nil, 300
	if got, err := w.n.Update(steppedPlatform(), app.ScopePlatform, d.ID, in); err != nil || got.HeartbeatIntervalS != 300 {
		t.Fatalf("platform update: %+v %v", got, err)
	}
	in.Enabled = false
	if _, err := w.n.Update(steppedPlatform(), app.ScopePlatform, d.ID, in); err != nil {
		t.Fatal(err)
	}
	in.Enabled, in.Cursor = true, app.CursorSkip
	if _, err := w.n.Update(steppedPlatform(), app.ScopePlatform, d.ID, in); err != nil {
		t.Fatalf("platform enable with skip: %v", err)
	}
	if newSecret, err := w.n.RotateSecret(steppedPlatform(), app.ScopePlatform, d.ID); err != nil || newSecret == secret {
		t.Fatalf("platform rotate: %v", err)
	}
	if id, err := w.n.Test(steppedPlatform(), app.ScopePlatform, d.ID); err != nil || id == uuid.Nil {
		t.Fatalf("platform test: %v", err)
	}
	if err := w.n.Delete(steppedPlatform(), app.ScopePlatform, d.ID); err != nil {
		t.Fatalf("platform delete: %v", err)
	}
	actions, _ := w.recorded(t, "corr-"+t.Name())
	for _, a := range actions {
		if a.outcome != nil && *a.outcome == "success" && a.org != uuid.Nil {
			t.Errorf("platform action %s recorded in organization %s", a.code, a.org)
		}
	}
}

// TestNotificationDestinationSecretTestAndDelete: rotation returns a new secret once, a test request inserts a
// fresh test delivery, deletion removes the destination with its state.
func TestNotificationDestinationSecretTestAndDelete(t *testing.T) {
	w := newNotificationWorld(t, false)
	ctx := stepped(w.org, principal.RoleOrgAdmin)
	bg := context.Background()
	d, secret, err := w.n.Create(ctx, app.ScopeOrg, webhookInput("hook"))
	if err != nil {
		t.Fatal(err)
	}
	rotated, err := w.n.RotateSecret(ctx, app.ScopeOrg, d.ID)
	if err != nil || rotated == secret || len(rotated) != 43 {
		t.Fatalf("rotate: %q %v", rotated, err)
	}
	deliveryID, err := w.n.Test(ctx, app.ScopeOrg, d.ID)
	if err != nil {
		t.Fatal(err)
	}
	var kind, requestedBy string
	var delivered *time.Time
	if err := w.super.QueryRow(bg, "SELECT kind, requested_by, delivered_at FROM notification_delivery WHERE id = $1 AND destination_id = $2",
		deliveryID, d.ID).Scan(&kind, &requestedBy, &delivered); err != nil {
		t.Fatal(err)
	}
	if kind != "test" || requestedBy != "alice" || delivered != nil {
		t.Fatalf("delivery %s %s %v", kind, requestedBy, delivered)
	}
	_, err = w.n.Test(ctx, app.ScopeOrg, d.ID)
	wantProblem(t, err, problem.InvalidState, "a second test while the first is pending")
	if _, err := w.super.Exec(bg, "UPDATE notification_delivery SET delivered_at = now(), attempts = 1 WHERE id = $1", deliveryID); err != nil {
		t.Fatal(err)
	}
	if _, err := w.n.Test(ctx, app.ScopeOrg, d.ID); err != nil {
		t.Fatalf("a test after the first was delivered: %v", err)
	}
	_, events := w.recorded(t, "corr-"+t.Name())
	for _, ev := range events {
		if ev.Code == audit.CodeNotificationTestRequested && ev.Params["destination_id"] != d.ID.String() {
			t.Fatalf("test params %v", ev.Params)
		}
		if ev.Code == audit.CodeNotificationDestinationSecretRotated && ev.Params["name"] != "hook" {
			t.Fatalf("rotation params %v", ev.Params)
		}
	}
	if err := w.n.Delete(ctx, app.ScopeOrg, d.ID); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := w.super.QueryRow(bg, "SELECT (SELECT count(*) FROM notification_destination WHERE id = $1) + (SELECT count(*) FROM notification_destination_state WHERE destination_id = $1)", d.ID).Scan(&n); err != nil || n != 0 {
		t.Fatalf("%d rows left, %v", n, err)
	}
	if err := w.n.Delete(ctx, app.ScopeOrg, d.ID); !errors.Is(err, problem.NotFound) {
		t.Fatalf("second delete: %v", err)
	}
}

// TestNotificationPseudonymLookup: the pseudonym key is created once as a wrapped data key, a lookup needs a key and
// a well-formed pseudonym, and a resolved lookup is shown once.
func TestNotificationPseudonymLookup(t *testing.T) {
	w := newNotificationWorld(t, false)
	ctx := stepped(w.org, principal.RoleOrgAdmin)
	bg := context.Background()
	plain, _, err := w.n.Create(ctx, app.ScopeOrg, webhookInput("plain"))
	if err != nil {
		t.Fatal(err)
	}
	const pseudonym = "u_0123456789abcdef01234567"
	_, err = w.n.ResolvePseudonym(ctx, plain.ID, pseudonym)
	wantProblem(t, err, problem.InvalidState, "no pseudonym key")
	in := webhookInput("pseudo")
	in.PseudonymizeUsers = true
	if _, _, err := w.n.Create(ctx, app.ScopeOrg, in); err != nil {
		t.Fatal(err)
	}
	in.Name = "pseudo 2"
	if _, _, err := w.n.Create(ctx, app.ScopeOrg, in); err != nil {
		t.Fatal(err)
	}
	var keyCT string
	if err := w.super.QueryRow(bg, "SELECT key_ciphertext FROM notification_pseudonym_key WHERE organization_id = $1", w.org).Scan(&keyCT); err != nil {
		t.Fatal(err)
	}
	if keyCT != "vault:v1:notification-pseudonym:"+w.org.String()+":pseudonym" {
		t.Fatalf("pseudonym key %q", keyCT)
	}
	datakeys := 0
	for _, c := range w.keys.calls {
		if strings.HasPrefix(c, "datakey") {
			datakeys++
		}
	}
	if datakeys != 1 {
		t.Fatalf("%d data keys created, want one per organization", datakeys)
	}
	_, err = w.n.ResolvePseudonym(ctx, plain.ID, "alice")
	wantProblem(t, err, problem.InvalidRequest, "malformed pseudonym")
	lookupID, err := w.n.ResolvePseudonym(ctx, plain.ID, pseudonym)
	if err != nil {
		t.Fatal(err)
	}
	_, err = w.n.ResolvePseudonym(ctx, plain.ID, "u_ffffffffffffffffffffffff")
	wantProblem(t, err, problem.InvalidState, "a second lookup while the first is pending")
	got, err := w.n.PseudonymLookup(ctx, plain.ID, lookupID)
	if err != nil || got.Resolved || got.Username != nil || got.Pseudonym != pseudonym {
		t.Fatalf("unresolved lookup %+v %v", got, err)
	}
	if _, err := w.n.PseudonymLookup(stepped(w.org, principal.RoleOrgAuditor), plain.ID, lookupID); !errors.Is(err, problem.Forbidden) {
		t.Fatalf("auditor lookup: %v", err)
	}
	if _, err := w.n.PseudonymLookup(stepped(w.other, principal.RoleOrgAdmin), plain.ID, lookupID); !errors.Is(err, problem.NotFound) {
		t.Fatalf("other organization lookup: %v", err)
	}
	if _, err := w.super.Exec(bg, "UPDATE notification_pseudonym_lookup SET resolved_username = 'jdoe', resolved_at = now() WHERE id = $1", lookupID); err != nil {
		t.Fatal(err)
	}
	// Of concurrent reads of a resolved lookup exactly one receives the user name; the others find it gone.
	const readers = 8
	results := make(chan error, readers)
	names := make(chan string, readers)
	var start sync.WaitGroup
	start.Add(1)
	for range readers {
		go func() {
			start.Wait()
			got, err := w.n.PseudonymLookup(ctx, plain.ID, lookupID)
			if err == nil && got.Resolved && got.Username != nil {
				names <- *got.Username
			}
			results <- err
		}()
	}
	start.Done()
	notFound := 0
	for range readers {
		if err := <-results; errors.Is(err, problem.NotFound) {
			notFound++
		} else if err != nil {
			t.Fatalf("concurrent read: %v", err)
		}
	}
	close(names)
	var got1 []string
	for n := range names {
		got1 = append(got1, n)
	}
	if len(got1) != 1 || got1[0] != "jdoe" || notFound != readers-1 {
		t.Fatalf("names %v, %d not found; want exactly one reader to get jdoe", got1, notFound)
	}
	if _, err := w.n.ResolvePseudonym(ctx, plain.ID, "u_ffffffffffffffffffffffff"); err != nil {
		t.Fatalf("a lookup after the first was resolved: %v", err)
	}
	_, events := w.recorded(t, "corr-"+t.Name())
	resolved := 0
	for _, ev := range events {
		if ev.Code == audit.CodeNotificationPseudonymResolved && ev.Outcome == audit.OutcomeSuccess {
			resolved++
			if (ev.Params["pseudonym"] != pseudonym && ev.Params["pseudonym"] != "u_ffffffffffffffffffffffff") || ev.Target == nil || ev.Target.Type != "organization" || ev.Target.ID != w.org.String() {
				t.Fatalf("resolve event %+v", ev)
			}
		}
	}
	if resolved != 2 {
		t.Fatalf("%d successful resolve events, want 2", resolved)
	}
	for _, ev := range events {
		if ev.Code == audit.CodeNotificationPseudonymResolved && ev.Outcome == audit.OutcomeFailure && ev.ErrorCode == "invalid_request" {
			if _, ok := ev.Params["pseudonym"]; ok {
				t.Fatalf("a malformed pseudonym was recorded: %v", ev.Params)
			}
		}
	}
}
