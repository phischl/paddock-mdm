package app_test

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/inventory"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
)

// TestAttentionAgentNotRunning (PDK-295, plan M8x decision 60, migration 00049): a reported failure of fleetd's
// policy paddock_agent_running is the attention kind agent_not_running of an active device, for its own organization
// only; it is not listed before the failure is reported or for a device that is not active, and it is gone once the
// policy passes again. Everything runs in one transaction that is rolled back; the reads run as paddock_api.
func TestAttentionAgentNotRunning(t *testing.T) {
	env := pgtest.SharedPaddock(t)
	ctx := context.Background()
	super, err := pgx.Connect(ctx, env.Super)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = super.Close(ctx) })
	tx, err := super.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := tx.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	org := func() uuid.UUID {
		id := uuid.Must(uuid.NewV7())
		exec("INSERT INTO organization (id, slug, name, status) VALUES ($1, $2, 'O', 'active')", id, "o"+id.String()[24:])
		return id
	}
	device := func(org uuid.UUID, hostname, state string) uuid.UUID {
		id := uuid.Must(uuid.NewV7())
		exec("INSERT INTO device (id, organization_id, hostname, state) VALUES ($1, $2, $3, $4)", id, org, hostname, state)
		return id
	}
	q := pgstore.New(tx)
	policy := func(org, dev uuid.UUID, passing bool) {
		t.Helper()
		if err := q.UpsertPolicyResult(ctx, pgstore.UpsertPolicyResultParams{DeviceID: dev, OrganizationID: org,
			PolicyKey: inventory.PolicyAgentRunning, Passing: passing}); err != nil {
			t.Fatal(err)
		}
	}
	reported := func(dev uuid.UUID) {
		t.Helper()
		if err := q.MarkAgentNotRunningReported(ctx, pgstore.MarkAgentNotRunningReportedParams{DeviceID: dev,
			PolicyKey: inventory.PolicyAgentRunning}); err != nil {
			t.Fatal(err)
		}
	}
	// listed returns the hostnames of acme's agent_not_running conditions as paddock_api in the asking organization.
	listed := func(asking uuid.UUID) []string {
		t.Helper()
		sp, err := tx.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = sp.Rollback(ctx) }()
		if _, err := sp.Exec(ctx, "SET LOCAL ROLE paddock_api"); err != nil {
			t.Fatal(err)
		}
		if _, err := sp.Exec(ctx, "SELECT set_config('paddock.org_id', $1, true)", asking.String()); err != nil {
			t.Fatal(err)
		}
		rows, err := pgstore.New(sp).ListAttention(ctx, pgstore.ListAttentionParams{Kinds: []string{"agent_not_running"}, Sort: "hostname", MaxRows: 100})
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, r := range rows {
			if r.ID != "agent_not_running:"+r.DeviceID.String() || r.Detail != "" {
				t.Errorf("row %+v", r)
			}
			out = append(out, r.Hostname)
		}
		return out
	}

	acme, globex := org(), org()
	stopped := device(acme, "stopped", "active")
	unreported := device(acme, "unreported", "active")
	retired := device(acme, "retired", "retired")
	other := device(globex, "other", "active")
	for _, d := range []struct{ org, dev uuid.UUID }{{acme, stopped}, {acme, unreported}, {acme, retired}, {globex, other}} {
		policy(d.org, d.dev, false)
	}
	reported(stopped)
	reported(retired)
	reported(other)

	if got := listed(acme); len(got) != 1 || got[0] != "stopped" {
		t.Fatalf("acme agent_not_running %v, want [stopped] (reported, active, own organization)", got)
	}
	if got := listed(globex); len(got) != 1 || got[0] != "other" {
		t.Fatalf("globex agent_not_running %v, want [other]", got)
	}

	// The policy passes again: alerted_at is cleared and the condition is gone.
	policy(acme, stopped, true)
	if got := listed(acme); len(got) != 0 {
		t.Fatalf("agent_not_running %v after the policy passed", got)
	}
	// A new failure is listed again only once it is reported.
	policy(acme, stopped, false)
	if got := listed(acme); len(got) != 0 {
		t.Fatalf("agent_not_running %v before the new failure was reported", got)
	}
	reported(stopped)
	if got := listed(acme); len(got) != 1 || got[0] != "stopped" {
		t.Fatalf("agent_not_running %v after the new report, want [stopped]", got)
	}
}
