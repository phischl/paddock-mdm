package app_test

import (
	"context"
	"errors"
	"testing"

	"github.com/phischl/paddock-mdm/server/internal/adapters/postgres/pgstore"
	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/domain/audit"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/problem"
)

// setOrgStatus moves h.org to status the way the offboarding does and refreshes the gate's status cache.
func (h harness) setOrgStatus(t *testing.T, status string) {
	t.Helper()
	ctx := context.Background()
	if _, err := h.super.Exec(ctx, `UPDATE organization SET status = $2,
		deleted_at = CASE WHEN $2 = 'deleted' THEN now() END,
		deletion_requested_at = CASE WHEN $2 IN ('deleting', 'deleted') THEN now() END,
		delete_after = CASE WHEN $2 IN ('deleting', 'deleted') THEN now() END WHERE id = $1`, h.org, status); err != nil {
		t.Fatal(err)
	}
	if err := h.orgPool.RefreshOrganizationStatus(ctx); err != nil {
		t.Fatal(err)
	}
}

// expectInactiveDenied asserts exactly one event for the attempt: organization.inactive_denied in the platform
// pseudo-organization, naming h.org, the attempted code and status; nothing in h.org.
func expectInactiveDenied(t *testing.T, h harness, attempted audit.Code, status string) {
	t.Helper()
	ev := expectOne(t, h, audit.OutcomeDenied, "organization_inactive")
	if ev.Code != audit.CodeOrganizationInactiveDenied || ev.OrganizationID != audit.PlatformOrganizationID ||
		ev.Params["organization_id"] != h.org.String() || ev.Params["attempted_code"] != string(attempted) ||
		ev.Params["status"] != status || ev.Actor.Type != audit.ActorAdmin {
		t.Fatalf("event %s in %s, params %v, actor %s; want organization.inactive_denied in the platform "+
			"pseudo-organization for %s, %s, %s, admin", ev.Code, ev.OrganizationID, ev.Params, ev.Actor.Type, h.org,
			attempted, status)
	}
	var inOrg int
	if err := h.super.QueryRow(context.Background(), "SELECT count(*) FROM action WHERE organization_id = $1", h.org).
		Scan(&inOrg); err != nil || inOrg != 0 {
		t.Fatalf("rows written into the %s organization: %d (%v)", status, inOrg, err)
	}
}

// TestRunTxInactiveOrganizationRecordsOneEvent (PDK-1113): an attempt in an organization that is deleting or deleted
// is recorded exactly once, whatever refuses it first: a denial before the gate (missing step-up, wrong role), the
// gate itself, or a failure after the gate let the transaction in. The organization's unavailability wins: the event
// is organization.inactive_denied in the platform pseudo-organization, and the caller gets organization_inactive.
func TestRunTxInactiveOrganizationRecordsOneEvent(t *testing.T) {
	stepUp := createSpec
	stepUp.RequiresStepUp = true
	for _, status := range []string{"deleting", "deleted"} {
		t.Run(status, func(t *testing.T) {
			cases := []struct {
				name string
				role principal.Role
				spec app.ActionSpec
				fn   func(t *testing.T, h harness) func(ctx context.Context, q *pgstore.Queries, rec app.Recorder) error
				// flip moves the organization only after the gate let the transaction in.
				flip bool
			}{
				{name: "step-up denial", role: principal.RoleOrgAdmin, spec: stepUp},
				{name: "role denial", role: principal.RoleOrgAuditor, spec: createSpec},
				{name: "gate refusal", role: principal.RoleOrgAdmin, spec: createSpec},
				{name: "failure after the gate", role: principal.RoleOrgAdmin, spec: createSpec, flip: true,
					fn: func(t *testing.T, h harness) func(ctx context.Context, q *pgstore.Queries, rec app.Recorder) error {
						return func(context.Context, *pgstore.Queries, app.Recorder) error {
							h.setOrgStatus(t, status)
							return problem.NameTaken
						}
					}},
			}
			for _, c := range cases {
				t.Run(c.name, func(t *testing.T) {
					h := newHarness(t)
					if !c.flip {
						h.setOrgStatus(t, status)
					}
					fn := createGroup("late")
					if c.fn != nil {
						fn = c.fn(t, h)
					}
					err := h.runner.RunTx(h.admin(c.role), app.ScopeOrg, c.spec, fn)
					if !errors.Is(err, problem.OrganizationInactive) {
						t.Fatalf("RunTx = %v, want organization_inactive", err)
					}
					expectInactiveDenied(t, h, audit.CodeDeviceGroupCreated, status)
				})
			}
		})
	}
}

// TestRecordRefusalInactiveOrganization (PDK-1113): a refusal that precedes the role and step-up checks (the MCP
// guard) in a deleting organization is recorded once, as organization.inactive_denied.
func TestRecordRefusalInactiveOrganization(t *testing.T) {
	h := newHarness(t)
	h.setOrgStatus(t, "deleting")
	err := h.runner.RecordRefusal(h.admin(principal.RoleOrgAdmin), app.ScopeOrg, createSpec, problem.MCPWriteNotEnabled)
	if !errors.Is(err, problem.OrganizationInactive) {
		t.Fatalf("RecordRefusal = %v, want organization_inactive", err)
	}
	expectInactiveDenied(t, h, audit.CodeDeviceGroupCreated, "deleting")
}

// TestRunExternalInactiveOrganizationRecordsOneEvent (PDK-1113): a step-up denial of an external action in a deleting
// organization is recorded once, as organization.inactive_denied; an organization that becomes deleting between the
// started record and its finish leaves exactly the started action, which the reaper finalizes as unknown, and no
// second event in the platform pseudo-organization.
func TestRunExternalInactiveOrganizationRecordsOneEvent(t *testing.T) {
	noop := func(context.Context, *pgstore.Queries, app.Recorder, error) error { return nil }
	t.Run("step-up denial", func(t *testing.T) {
		h := newHarness(t)
		h.setOrgStatus(t, "deleting")
		spec := createSpec
		spec.RequiresStepUp = true
		err := h.runner.RunExternal(h.admin(principal.RoleOrgAdmin), app.ScopeOrg, spec, createGroup("late"),
			func(context.Context) error { t.Fatal("external call for a denied attempt"); return nil }, noop)
		if !errors.Is(err, problem.OrganizationInactive) {
			t.Fatalf("RunExternal = %v, want organization_inactive", err)
		}
		expectInactiveDenied(t, h, audit.CodeDeviceGroupCreated, "deleting")
	})
	t.Run("unknown", func(t *testing.T) {
		h := newHarness(t)
		err := h.runner.RunExternal(h.admin(principal.RoleOrgAdmin), app.ScopeOrg, createSpec, createGroup("started"),
			func(context.Context) error { h.setOrgStatus(t, "deleting"); return nil }, noop)
		if !errors.Is(err, problem.OrganizationInactive) {
			t.Fatalf("RunExternal = %v, want organization_inactive", err)
		}
		actions, events := h.recorded(t, "corr-"+t.Name())
		if len(actions) != 1 || actions[0].org != h.org || actions[0].status != "started" || len(events) != 0 {
			t.Fatalf("actions %+v, %d outbox events; want only the started action in the organization", actions,
				len(events))
		}
	})
}

// TestRunExternalInPendingDeletionStepUpDenial (PDK-1113): a platform administrator's recovery export of a deleting
// organization without a step-up is recorded once, as organization.inactive_denied: the pending-deletion scope
// refuses the organization's own log.
func TestRunExternalInPendingDeletionStepUpDenial(t *testing.T) {
	h := newHarness(t)
	h.setOrgStatus(t, "deleting")
	err := h.runner.RunExternalInPendingDeletion(platformCtx(), h.org, true, app.SpecPlatformRecoveryExport,
		func(context.Context, *pgstore.Queries, app.Recorder) error {
			t.Fatal("prepare for a denied attempt")
			return nil
		},
		func(context.Context) error { return nil },
		func(context.Context, *pgstore.Queries, app.Recorder, error) error { return nil })
	if !errors.Is(err, problem.OrganizationInactive) {
		t.Fatalf("RunExternalInPendingDeletion = %v, want organization_inactive", err)
	}
	ev := expectOne(t, h, audit.OutcomeDenied, "organization_inactive")
	if ev.Code != audit.CodeOrganizationInactiveDenied || ev.OrganizationID != audit.PlatformOrganizationID ||
		ev.Params["organization_id"] != h.org.String() || ev.Params["status"] != "deleting" {
		t.Fatalf("event %s in %s, params %v", ev.Code, ev.OrganizationID, ev.Params)
	}
}

// TestRunTxRefusalInactiveOrganization (PDK-1113): RunTxRefusal records a role denial in a deleting organization, and
// a failure after the gate, once as organization.inactive_denied.
func TestRunTxRefusalInactiveOrganization(t *testing.T) {
	t.Run("role denial", func(t *testing.T) {
		h := newHarness(t)
		h.setOrgStatus(t, "deleting")
		err := h.runner.RunTxRefusal(h.admin(principal.RoleOrgAuditor), app.ScopeOrg, createSpec, problem.NameTaken,
			func(context.Context, *pgstore.Queries, app.Recorder) error {
				t.Fatal("fn for a denied attempt")
				return nil
			})
		if !errors.Is(err, problem.OrganizationInactive) {
			t.Fatalf("RunTxRefusal = %v, want organization_inactive", err)
		}
		expectInactiveDenied(t, h, audit.CodeDeviceGroupCreated, "deleting")
	})
	t.Run("failure after the gate", func(t *testing.T) {
		h := newHarness(t)
		err := h.runner.RunTxRefusal(h.admin(principal.RoleOrgAdmin), app.ScopeOrg, createSpec, problem.NameTaken,
			func(context.Context, *pgstore.Queries, app.Recorder) error {
				h.setOrgStatus(t, "deleting")
				return problem.UpstreamUnavailable
			})
		if !errors.Is(err, problem.OrganizationInactive) {
			t.Fatalf("RunTxRefusal = %v, want organization_inactive", err)
		}
		expectInactiveDenied(t, h, audit.CodeDeviceGroupCreated, "deleting")
	})
}

// TestRecordReadOnceInactiveOrganization (PDK-1113): RecordReadOnce records a role denial in a deleting organization,
// and a claim failing after the gate, once as organization.inactive_denied. A read the gate refuses before the switch
// was read records nothing, by RecordReadOnce's contract (PDK-139 round 3), and is refused with organization_inactive.
func TestRecordReadOnceInactiveOrganization(t *testing.T) {
	on := func(context.Context, *pgstore.Queries) (bool, error) { return true, nil }
	t.Run("role denial", func(t *testing.T) {
		h := newHarness(t)
		h.setOrgStatus(t, "deleting")
		_, err := h.runner.RecordReadOnce(h.admin(principal.RoleOrgAuditor), createSpec, on,
			func(context.Context, *pgstore.Queries, app.Recorder) (bool, error) {
				t.Fatal("claim for a denied read")
				return false, nil
			})
		if !errors.Is(err, problem.OrganizationInactive) {
			t.Fatalf("RecordReadOnce = %v, want organization_inactive", err)
		}
		expectInactiveDenied(t, h, audit.CodeDeviceGroupCreated, "deleting")
	})
	t.Run("failure after the gate", func(t *testing.T) {
		h := newHarness(t)
		_, err := h.runner.RecordReadOnce(h.admin(principal.RoleOrgAdmin), createSpec, on,
			func(context.Context, *pgstore.Queries, app.Recorder) (bool, error) {
				h.setOrgStatus(t, "deleting")
				return false, problem.UpstreamUnavailable
			})
		if !errors.Is(err, problem.OrganizationInactive) {
			t.Fatalf("RecordReadOnce = %v, want organization_inactive", err)
		}
		expectInactiveDenied(t, h, audit.CodeDeviceGroupCreated, "deleting")
	})
	t.Run("refused before the switch was read", func(t *testing.T) {
		h := newHarness(t)
		h.setOrgStatus(t, "deleting")
		_, err := h.runner.RecordReadOnce(h.admin(principal.RoleOrgAdmin), createSpec,
			func(context.Context, *pgstore.Queries) (bool, error) {
				t.Fatal("switch read past the gate")
				return false, nil
			},
			func(context.Context, *pgstore.Queries, app.Recorder) (bool, error) { return true, nil })
		if !errors.Is(err, problem.OrganizationInactive) {
			t.Fatalf("RecordReadOnce = %v, want organization_inactive", err)
		}
		if actions, events := h.recorded(t, "corr-"+t.Name()); len(actions)+len(events) != 0 {
			t.Fatalf("a read refused before the switch was read was recorded: %+v", actions)
		}
	})
}
