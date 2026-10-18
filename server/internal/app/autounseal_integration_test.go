package app_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/domain/autounseal"
	"github.com/phischl/paddock-mdm/server/internal/platform/bao"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/platform/httpx"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/problem"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/baotest"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
)

const (
	ackEN = "I understand and accept the risk"
	ackDE = "Ich verstehe und akzeptiere das Risiko"
)

type autoUnsealHarness struct {
	t     *testing.T
	uc    *app.AutoUnseal
	super *pgx.Conn
	admin principal.Principal
}

func newAutoUnsealHarness(t *testing.T, seal app.SealStatusReader) *autoUnsealHarness {
	t.Helper()
	env := pgtest.SharedPaddock(t)
	ctx := context.Background()
	orgPool, err := db.NewOrgPool(ctx, env.API, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(orgPool.Close)
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
	// The row is platform-wide: every test starts from and leaves the state of the migration.
	reset := func() {
		if _, err := super.Exec(context.Background(), `UPDATE openbao_auto_unseal SET state = 'disabled',
			disclaimer_version = NULL, acknowledgement = NULL, acknowledged_by = NULL, acknowledged_by_subject = NULL,
			acknowledged_at = NULL, disabled_by = NULL, disabled_at = NULL WHERE id = 1`); err != nil {
			t.Fatal(err)
		}
	}
	reset()
	t.Cleanup(reset)
	runner := app.NewActionRunner(orgPool, platform, httpx.RequestID)
	return &autoUnsealHarness{t: t, uc: app.NewAutoUnseal(runner, platform, seal), super: super,
		admin: principal.Principal{Kind: principal.KindPlatformAdmin, ID: uuid.Must(uuid.NewV7()), Subject: "sub-root",
			Display: "Root Admin", Role: principal.RolePlatform, StepUpAt: time.Now()}}
}

func (h *autoUnsealHarness) ctx(p principal.Principal) (context.Context, string) {
	id := uuid.NewString()
	return principal.With(httpx.WithRequestID(context.Background(), id), p), id
}

// event returns "code:outcome:error_code", the params and the actor display of the single action of requestID.
func (h *autoUnsealHarness) event(requestID string) (string, map[string]any, string) {
	h.t.Helper()
	rows, err := h.super.Query(context.Background(), `SELECT code || ':' || coalesce(outcome, status) || ':' ||
		coalesce(error_code, ''), params, actor->>'display' FROM action WHERE correlation_id = $1`, requestID)
	if err != nil {
		h.t.Fatal(err)
	}
	type ev struct {
		Event  string
		Params map[string]any
		Actor  string
	}
	out, err := pgx.CollectRows(rows, pgx.RowToStructByPos[ev])
	if err != nil {
		h.t.Fatal(err)
	}
	if len(out) != 1 {
		h.t.Fatalf("events for %s: %v, want exactly one", requestID, out)
	}
	return out[0].Event, out[0].Params, out[0].Actor
}

func (h *autoUnsealHarness) noEvent(requestID string) {
	h.t.Helper()
	var n int
	if err := h.super.QueryRow(context.Background(), "SELECT count(*) FROM action WHERE correlation_id = $1", requestID).Scan(&n); err != nil {
		h.t.Fatal(err)
	}
	if n != 0 {
		h.t.Fatalf("%d events for %s, want none", n, requestID)
	}
}

type fakeSealReader struct{ st bao.SealStatus }

func (f fakeSealReader) SealStatus(context.Context) (bao.SealStatus, error) { return f.st, nil }

func code(err error) string { return problem.From(err).Code }

// TestAutoUnsealEnable (plan M8u decision 4): a platform administrator with a step-up enables with either sentence;
// every other attempt is refused and audited.
func TestAutoUnsealEnable(t *testing.T) {
	h := newAutoUnsealHarness(t, fakeSealReader{bao.SealStatus{Reachable: true, Initialized: true, Type: "shamir", Threshold: 3, Shares: 5}})

	noStepUp := h.admin
	noStepUp.StepUpAt = time.Now().Add(-app.StepUpValidity - time.Minute)
	ctx, id := h.ctx(noStepUp)
	if _, err := h.uc.Enable(ctx, autounseal.DisclaimerVersion, ackEN); code(err) != "step_up_required" {
		t.Fatalf("without step-up: %v", err)
	}
	if ev, _, _ := h.event(id); ev != "platform.auto_unseal_enabled:denied:step_up_required" {
		t.Fatalf("event %s", ev)
	}

	org := principal.Principal{Kind: principal.KindAdmin, ID: uuid.Must(uuid.NewV7()), Display: "alice",
		Role: principal.RoleOrgAdmin, OrganizationID: uuid.Must(uuid.NewV7()), StepUpAt: time.Now()}
	ctx, id = h.ctx(org)
	if _, err := h.uc.Enable(ctx, autounseal.DisclaimerVersion, ackEN); code(err) != "forbidden" {
		t.Fatalf("org admin: %v", err)
	}
	if ev, _, _ := h.event(id); ev != "platform.auto_unseal_enabled:denied:forbidden" {
		t.Fatalf("event %s", ev)
	}

	ctx, id = h.ctx(h.admin)
	_, err := h.uc.Enable(ctx, "2000-01-01", ackEN)
	if p := problem.From(err); p.Code != "disclaimer_outdated" || p.Status != 409 {
		t.Fatalf("outdated: %v", err)
	}
	if ev, params, _ := h.event(id); ev != "platform.auto_unseal_enabled:failure:disclaimer_outdated" ||
		params["disclaimer_version"] != "2000-01-01" {
		t.Fatalf("event %s %v", ev, params)
	}

	ctx, id = h.ctx(h.admin)
	_, err = h.uc.Enable(ctx, autounseal.DisclaimerVersion, "I accept")
	if p := problem.From(err); p.Code != "invalid_request" || p.Detail != "acknowledgement does not match the disclaimer" {
		t.Fatalf("wrong sentence: %v", err)
	}
	if ev, _, _ := h.event(id); ev != "platform.auto_unseal_enabled:failure:invalid_request" {
		t.Fatalf("event %s", ev)
	}

	for _, ack := range []string{ackDE, ackEN} {
		ctx, id = h.ctx(h.admin)
		st, err := h.uc.Enable(ctx, autounseal.DisclaimerVersion, ack)
		if err != nil {
			t.Fatal(err)
		}
		s := st.Setting
		if s.State != autounseal.StateEnabled || s.AcknowledgedBy != "Root Admin" || s.AcknowledgedBySubject != "sub-root" ||
			s.Acknowledgement != ack || s.DisclaimerVersion != autounseal.DisclaimerVersion || s.AcknowledgedAt.IsZero() {
			t.Fatalf("setting = %+v", s)
		}
		if !st.Seal.Reachable || st.Seal.Threshold != 3 {
			t.Fatalf("seal = %+v", st.Seal)
		}
		ev, params, _ := h.event(id)
		if ev != "platform.auto_unseal_enabled:success:" || params["acknowledgement"] != ack ||
			params["disclaimer_version"] != autounseal.DisclaimerVersion || params["previous_state"] == nil {
			t.Fatalf("event %s %v", ev, params)
		}
		if ack == ackDE && params["previous_state"] != "disabled" {
			t.Fatalf("previous_state = %v, want disabled", params["previous_state"])
		}
	}
}

// TestAutoUnsealDisable: the portal and the CLI disable; the acknowledgement stays; both are audited with method.
func TestAutoUnsealDisable(t *testing.T) {
	h := newAutoUnsealHarness(t, nil)
	ctx, _ := h.ctx(h.admin)
	if _, err := h.uc.Enable(ctx, autounseal.DisclaimerVersion, ackEN); err != nil {
		t.Fatal(err)
	}

	noStepUp := h.admin
	noStepUp.StepUpAt = time.Time{}
	ctx, id := h.ctx(noStepUp)
	if _, err := h.uc.Disable(ctx); code(err) != "step_up_required" {
		t.Fatalf("without step-up: %v", err)
	}
	if ev, _, _ := h.event(id); ev != "platform.auto_unseal_disabled:denied:step_up_required" {
		t.Fatalf("event %s", ev)
	}

	ctx, id = h.ctx(h.admin)
	st, err := h.uc.Disable(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if s := st.Setting; s.State != autounseal.StateDisabled || s.DisabledBy != "Root Admin" || s.DisabledAt.IsZero() ||
		s.Acknowledgement != ackEN || s.AcknowledgedBy != "Root Admin" {
		t.Fatalf("setting = %+v", s)
	}
	if st.Seal.Reachable {
		t.Fatalf("without a seal reader the seal must be unreachable: %+v", st.Seal)
	}
	ev, params, _ := h.event(id)
	if ev != "platform.auto_unseal_disabled:success:" || params["previous_state"] != "enabled" || params["method"] != "portal" {
		t.Fatalf("event %s %v", ev, params)
	}

	id = uuid.NewString()
	s, err := h.uc.DisableCLI(httpx.WithRequestID(context.Background(), id))
	if err != nil {
		t.Fatal(err)
	}
	if s.State != autounseal.StateDisabled || s.DisabledBy != "paddock-server admin" {
		t.Fatalf("setting = %+v", s)
	}
	ev, params, actor := h.event(id)
	if ev != "platform.auto_unseal_disabled:success:" || params["method"] != "cli" || params["previous_state"] != "disabled" ||
		actor != "paddock-server admin" {
		t.Fatalf("event %s %v actor %q", ev, params, actor)
	}

	loaded, err := h.uc.Load(context.Background())
	if err != nil || loaded.State != autounseal.StateDisabled || loaded.Acknowledgement != ackEN {
		t.Fatalf("Load = %+v, %v", loaded, err)
	}
}

// TestAutoUnsealStatus: a read for platform administrators only, without an audit event; the seal status comes from
// OpenBao without a token.
func TestAutoUnsealStatus(t *testing.T) {
	b := baotest.Start(t)
	c, err := bao.New(b.Addr, "", "")
	if err != nil {
		t.Fatal(err)
	}
	h := newAutoUnsealHarness(t, c)

	org := principal.Principal{Kind: principal.KindAdmin, ID: uuid.Must(uuid.NewV7()), Display: "alice",
		Role: principal.RoleOrgAdmin, OrganizationID: uuid.Must(uuid.NewV7())}
	ctx, id := h.ctx(org)
	if _, err := h.uc.Status(ctx); code(err) != "forbidden" {
		t.Fatalf("org admin: %v", err)
	}
	h.noEvent(id)

	ctx, id = h.ctx(h.admin)
	st, err := h.uc.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if st.Setting.State != autounseal.StateDisabled || !st.Seal.Reachable || !st.Seal.Initialized || st.Seal.Sealed {
		t.Fatalf("status = %+v", st)
	}
	h.noEvent(id)
}
