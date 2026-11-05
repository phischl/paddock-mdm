package app_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/problem"
)

// sent marks a destination as having sent forward sequence numbers 1..n, with an optional pending batch, as the
// notifier would.
func (w notificationWorld) sent(t *testing.T, id uuid.UUID, n int64, pending bool) {
	t.Helper()
	bg := context.Background()
	var pendingID *uuid.UUID
	if pending {
		p := uuid.Must(uuid.NewV7())
		pendingID = &p
		if _, err := w.super.Exec(bg, `INSERT INTO notification_delivery (id, destination_id, organization_id, kind,
			forward_from, forward_to, event_count) SELECT $1, id, organization_id, 'events', $3, $3, 1
			FROM notification_destination WHERE id = $2`, p, id, n); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := w.super.Exec(bg, `UPDATE notification_destination_state SET forward_seq = $2, pending_delivery_id = $3,
		start_at_latest = false WHERE destination_id = $1`, id, n, pendingID); err != nil {
		t.Fatal(err)
	}
}

// replayDone ends a requested replay, as the notifier does after its last stored delivery.
func (w notificationWorld) replayDone(t *testing.T, id uuid.UUID) {
	t.Helper()
	if _, err := w.super.Exec(context.Background(), `UPDATE notification_destination_state SET replay_from = NULL
		WHERE destination_id = $1`, id); err != nil {
		t.Fatal(err)
	}
}

// skipPending marks a skip request the notifier has not resolved yet, as enabling with cursor skip does.
func (w notificationWorld) skipPending(t *testing.T, id uuid.UUID) {
	t.Helper()
	if _, err := w.super.Exec(context.Background(), `UPDATE notification_destination_state SET start_at_latest = true
		WHERE destination_id = $1`, id); err != nil {
		t.Fatal(err)
	}
}

func (w notificationWorld) replayFrom(t *testing.T, id uuid.UUID) *int64 {
	t.Helper()
	var from *int64
	if err := w.super.QueryRow(context.Background(), `SELECT replay_from FROM notification_destination_state
		WHERE destination_id = $1`, id).Scan(&from); err != nil {
		t.Fatal(err)
	}
	return from
}

// TestNotificationReplay: an administrator with a step-up sets replay_from for a number the destination has sent;
// numbers outside 1..forward_seq are refused with 400, a pending retry, a running replay and a pending skip with 409,
// every attempt is recorded as notification.replay_requested with the range, and the state shows the request.
func TestNotificationReplay(t *testing.T) {
	w := newNotificationWorld(t, false)
	ctx := stepped(w.org, principal.RoleOrgAdmin)
	d, _, err := w.n.Create(ctx, app.ScopeOrg, webhookInput("siem"))
	if err != nil {
		t.Fatal(err)
	}
	w.sent(t, d.ID, 5, false)
	for _, from := range []int64{0, -1, 6} {
		wantProblem(t, w.n.Replay(ctx, app.ScopeOrg, d.ID, from), problem.InvalidRequest, "out-of-range from_forward_seq")
	}
	if w.replayFrom(t, d.ID) != nil {
		t.Fatal("a refused request set replay_from")
	}
	if err := w.n.Replay(ctx, app.ScopeOrg, d.ID, 3); err != nil {
		t.Fatalf("replay: %v", err)
	}
	if from := w.replayFrom(t, d.ID); from == nil || *from != 3 {
		t.Fatalf("replay_from %v", from)
	}
	got, err := w.n.Get(ctx, app.ScopeOrg, d.ID)
	if err != nil || got.State.ReplayFrom == nil || *got.State.ReplayFrom != 3 || got.State.LastCheckpointDay != nil {
		t.Fatalf("state %+v (%v)", got.State, err)
	}
	wantProblem(t, w.n.Replay(ctx, app.ScopeOrg, d.ID, 5), problem.InvalidState, "replay while a replay runs")
	if from := w.replayFrom(t, d.ID); from == nil || *from != 3 {
		t.Fatalf("a refused request redirected the running replay: replay_from %v", from)
	}
	w.replayDone(t, d.ID)
	if err := w.n.Replay(ctx, app.ScopeOrg, d.ID, 5); err != nil {
		t.Fatalf("replay of the last number: %v", err)
	}

	w.replayDone(t, d.ID)
	w.skipPending(t, d.ID)
	err = w.n.Replay(ctx, app.ScopeOrg, d.ID, 1)
	wantProblem(t, err, problem.InvalidState, "replay while a skip is pending")
	if pe := (*problem.Error)(nil); !errors.As(err, &pe) || !strings.Contains(pe.Detail, "skip request is pending") {
		t.Fatalf("pending skip detail: %v", err)
	}
	if w.replayFrom(t, d.ID) != nil {
		t.Fatal("a request during a pending skip set replay_from")
	}
	w.sent(t, d.ID, 6, true)
	wantProblem(t, w.n.Replay(ctx, app.ScopeOrg, d.ID, 1), problem.InvalidState, "replay while a batch is pending")

	_, events := w.recorded(t, "corr-"+t.Name())
	var outcomes []audit.Outcome
	for _, ev := range events {
		if ev.Code != audit.CodeNotificationReplayRequested {
			continue
		}
		outcomes = append(outcomes, ev.Outcome)
		if ev.Target == nil || ev.Target.ID != d.ID.String() || ev.Params["destination"] != "siem" ||
			ev.Params["destination_id"] != d.ID.String() || ev.Params["from_forward_seq"] == nil ||
			ev.Params["to_forward_seq"] == nil {
			t.Fatalf("replay_requested %+v", ev)
		}
		if ev.Params["from_forward_seq"] == float64(3) && (ev.Outcome != audit.OutcomeSuccess || ev.Params["to_forward_seq"] != float64(5)) {
			t.Fatalf("successful replay_requested %+v", ev)
		}
	}
	if len(outcomes) != 8 || outcomes[0] != audit.OutcomeFailure || outcomes[3] != audit.OutcomeSuccess ||
		outcomes[4] != audit.OutcomeFailure || outcomes[5] != audit.OutcomeSuccess || outcomes[6] != audit.OutcomeFailure ||
		outcomes[7] != audit.OutcomeFailure {
		t.Fatalf("replay_requested outcomes %v", outcomes)
	}
}

// TestNotificationReplayAuthorization: only an organization administrator with a fresh step-up replays; an API token,
// an operator, an auditor and an administrator without a step-up are refused, another organization's destination is
// not found, and the platform twin serves platform destinations only.
func TestNotificationReplayAuthorization(t *testing.T) {
	w := newNotificationWorld(t, false)
	admin := stepped(w.org, principal.RoleOrgAdmin)
	d, _, err := w.n.Create(admin, app.ScopeOrg, webhookInput("siem"))
	if err != nil {
		t.Fatal(err)
	}
	w.sent(t, d.ID, 2, false)

	token := principal.With(context.Background(), principal.Principal{Kind: principal.KindAdmin, ID: uuid.Must(uuid.NewV7()),
		Role: principal.RoleOrgAdmin, OrganizationID: w.org, APITokenID: uuid.Must(uuid.NewV7()), APITokenName: "ci"})
	wantProblem(t, w.n.Replay(token, app.ScopeOrg, d.ID, 1), problem.StepUpRequired, "API token")
	noStepUp := principal.With(context.Background(), principal.Principal{Kind: principal.KindAdmin,
		ID: uuid.Must(uuid.NewV7()), Role: principal.RoleOrgAdmin, OrganizationID: w.org})
	wantProblem(t, w.n.Replay(noStepUp, app.ScopeOrg, d.ID, 1), problem.StepUpRequired, "without a step-up")
	for _, role := range []principal.Role{principal.RoleOrgOperator, principal.RoleOrgAuditor} {
		if err := w.n.Replay(stepped(w.org, role), app.ScopeOrg, d.ID, 1); !errors.Is(err, problem.Forbidden) {
			t.Errorf("%s: %v", role, err)
		}
	}
	wantProblem(t, w.n.Replay(stepped(w.other, principal.RoleOrgAdmin), app.ScopeOrg, d.ID, 1), problem.NotFound,
		"another organization")
	wantProblem(t, w.n.Replay(steppedPlatform(), app.ScopePlatform, d.ID, 1), problem.NotFound,
		"an organization destination on the platform scope")
	if w.replayFrom(t, d.ID) != nil {
		t.Fatal("a refused request set replay_from")
	}

	p, _, err := w.n.Create(steppedPlatform(), app.ScopePlatform, webhookInput("platform-"+uuid.NewString()[:8]))
	if err != nil {
		t.Fatal(err)
	}
	w.sent(t, p.ID, 4, false)
	wantProblem(t, w.n.Replay(admin, app.ScopePlatform, p.ID, 1), problem.Forbidden, "organization session on the platform scope")
	wantProblem(t, w.n.Replay(steppedPlatform(), app.ScopePlatform, p.ID, 5), problem.InvalidRequest, "platform out of range")
	if err := w.n.Replay(steppedPlatform(), app.ScopePlatform, p.ID, 2); err != nil {
		t.Fatalf("platform replay: %v", err)
	}
	if from := w.replayFrom(t, p.ID); from == nil || *from != 2 {
		t.Fatalf("platform replay_from %v", from)
	}
	if err := w.n.Delete(steppedPlatform(), app.ScopePlatform, p.ID); err != nil {
		t.Fatal(err)
	}
}

// TestNotificationReplayGrantGuards: the column grant lets the api roles write replay_from and nothing else, row level
// security confines that write to the caller's own destinations (decision 14a: a cross-organization update affects 0
// rows, a missing context fails), and the guarded update itself refuses a number the destination has not sent, a
// pending batch, a running replay and a pending skip, so the api cannot set replay_from around the use case.
func TestNotificationReplayGrantGuards(t *testing.T) {
	w := newNotificationWorld(t, false)
	d, _, err := w.n.Create(stepped(w.org, principal.RoleOrgAdmin), app.ScopeOrg, webhookInput("siem"))
	if err != nil {
		t.Fatal(err)
	}
	w.sent(t, d.ID, 3, false)
	bg := context.Background()
	as := func(role string, org *uuid.UUID, fn func(tx pgx.Tx) error) error {
		t.Helper()
		tx, err := w.super.Begin(bg)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(bg) }()
		if _, err := tx.Exec(bg, "SET LOCAL ROLE "+role); err != nil {
			t.Fatal(err)
		}
		if org != nil {
			if _, err := tx.Exec(bg, "SELECT set_config('paddock.org_id', $1, true)", org.String()); err != nil {
				t.Fatal(err)
			}
		}
		return fn(tx)
	}
	replay := func(role string, org *uuid.UUID, from int64) int64 {
		t.Helper()
		var rows int64
		if err := as(role, org, func(tx pgx.Tx) error {
			var err error
			rows, err = pgstore.New(tx).ReplayNotificationDestination(bg, pgstore.ReplayNotificationDestinationParams{
				DestinationID: d.ID, FromForwardSeq: from,
			})
			return err
		}); err != nil {
			t.Fatalf("%s replay: %v", role, err)
		}
		return rows
	}
	if got := replay("paddock_api", &w.other, 2); got != 0 {
		t.Errorf("cross-organization update affected %d rows", got)
	}
	if got := replay("paddock_platform", nil, 2); got != 0 {
		t.Errorf("platform role updated an organization destination: %d rows", got)
	}
	if err := as("paddock_api", nil, func(tx pgx.Tx) error {
		_, err := pgstore.New(tx).ReplayNotificationDestination(bg, pgstore.ReplayNotificationDestinationParams{
			DestinationID: d.ID, FromForwardSeq: 2,
		})
		return err
	}); err == nil {
		t.Error("replay without an organization context did not fail")
	}
	for _, col := range []string{"forward_seq = 9", "start_at_latest = true", "pending_delivery_id = NULL"} {
		if err := as("paddock_api", &w.org, func(tx pgx.Tx) error {
			_, err := tx.Exec(bg, "UPDATE notification_destination_state SET "+col+" WHERE destination_id = $1", d.ID)
			return err
		}); err == nil {
			t.Errorf("paddock_api wrote %s", col)
		}
	}
	if got := replay("paddock_api", &w.org, 4); got != 0 {
		t.Errorf("unsent number applied: %d rows", got)
	}
	if got := replay("paddock_api", &w.org, 0); got != 0 {
		t.Errorf("number 0 applied: %d rows", got)
	}
	if got := replay("paddock_api", &w.org, 2); got != 1 {
		t.Errorf("valid request: %d rows", got)
	}
	if from := w.replayFrom(t, d.ID); from != nil {
		t.Fatalf("rolled-back request left replay_from %d", *from)
	}
	if _, err := w.super.Exec(bg, `UPDATE notification_destination_state SET replay_from = 1 WHERE destination_id = $1`,
		d.ID); err != nil {
		t.Fatal(err)
	}
	if got := replay("paddock_api", &w.org, 2); got != 0 {
		t.Errorf("running replay redirected: %d rows", got)
	}
	w.replayDone(t, d.ID)
	w.skipPending(t, d.ID)
	if got := replay("paddock_api", &w.org, 2); got != 0 {
		t.Errorf("pending skip applied: %d rows", got)
	}
	w.sent(t, d.ID, 3, true)
	if got := replay("paddock_api", &w.org, 2); got != 0 {
		t.Errorf("pending batch applied: %d rows", got)
	}
}
