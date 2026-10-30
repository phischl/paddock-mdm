package app_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/pkg/protocol"
	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/domain/agentrelease"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/platform/httpx"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/problem"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
)

// operatorIn inserts an organization operator (or another role) of org and returns its context.
func (h releaseHarness) operatorIn(t *testing.T, org uuid.UUID, role principal.Role) context.Context {
	t.Helper()
	p := principal.Principal{Kind: principal.KindAdmin, ID: uuid.Must(uuid.NewV7()), Subject: uuid.NewString(), Display: "op", Role: role,
		OrganizationID: org, IP: "192.0.2.1"}
	if _, err := h.super.Exec(context.Background(), `INSERT INTO admin_account (id, organization_id, authentik_sub, username, display_name, role)
		VALUES ($1, $2, $3, $4, $4, $5)`, p.ID, org, p.Subject, "op-"+p.ID.String()[24:], string(role)); err != nil {
		t.Fatal(err)
	}
	return httpx.WithRequestID(principal.With(context.Background(), p), uuid.NewString())
}

// TestUpdateNow (plan M8d decisions 26 and 29): an operator requests the offered release for an active device older
// than it; the request is refused without an offer, for a device on the release, for an architecture without an
// artifact, for a device that is not active and for an auditor; the device's report of the version clears it, and
// the command round clears requests older than 24 hours.
func TestUpdateNow(t *testing.T) {
	h := newReleaseHarness(t, true)
	// Completed rollouts of other tests would still be offered.
	h.exec(t, "UPDATE agent_rollout SET status = 'halted' WHERE status IN ('running', 'completed')")
	org, dev := h.device(t)
	updates := app.NewAgentUpdates(h.runner, h.workerPool(t), evaluatedOffer{h})
	op := h.operatorIn(t, org, principal.RoleOrgOperator)
	if _, err := updates.RequestNow(op, dev); problem.From(err).Detail != "no agent release is being offered" {
		t.Fatalf("without a rollout: %v", err)
	}
	v := h.completedRollout(t, time.Now().Add(2*time.Minute))
	if _, err := updates.RequestNow(h.operatorIn(t, org, principal.RoleOrgAuditor), dev); !strings.Contains(err.Error(), "forbidden") {
		t.Fatalf("auditor: %v", err)
	}
	h.exec(t, "INSERT INTO device_status (device_id, organization_id, agent_version, arch) VALUES ($1, $2, $3, 'arm64')", dev, org, v)
	if _, err := updates.RequestNow(op, dev); problem.From(err).Detail != "the device already runs "+v {
		t.Fatalf("device on the release: %v", err)
	}
	h.exec(t, "UPDATE device_status SET agent_version = '0.9.0' WHERE device_id = $1", dev)
	if _, err := updates.RequestNow(op, dev); problem.From(err).Detail != "no artifact for arm64" {
		t.Fatalf("arch without an artifact: %v", err)
	}
	h.exec(t, "UPDATE device_status SET arch = 'amd64' WHERE device_id = $1", dev)
	d, err := updates.RequestNow(op, dev)
	if err != nil || d.AgentUpdateRequestedVersion == nil || *d.AgentUpdateRequestedVersion != v || d.AgentUpdateRequestedAt == nil {
		t.Fatalf("request: %+v, %v", d, err)
	}
	var params map[string]any
	var raw []byte
	if err := h.super.QueryRow(context.Background(), `SELECT payload -> 'params' FROM outbox WHERE payload ->> 'code' = 'device.agent_update_requested'
		AND payload -> 'target' ->> 'id' = $1 AND payload ->> 'outcome' = 'success'`, dev.String()).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	_ = json.Unmarshal(raw, &params)
	if params["version"] != v || params["from_version"] != "0.9.0" || params["hostname"] != "h" {
		t.Fatalf("params %v", params)
	}
	// The request recompiles the device, whose bundle then carries the supervisor package outside the wave (review 2
	// finding C).
	var recompiles int
	if err := h.super.QueryRow(context.Background(), `SELECT count(*) FROM outbox WHERE payload ->> 'scope' = 'device'
		AND payload ->> 'id' = $1`, dev.String()).Scan(&recompiles); err != nil || recompiles != 1 {
		t.Fatalf("%d device state changes (%v), want 1", recompiles, err)
	}

	// Another version's report leaves the request; the requested version's report clears it.
	report := func(seq int64, version string) {
		data, _ := json.Marshal(map[string]string{"version": version, "from_version": "0.9.0", "outcome": "updated"})
		if _, err := h.reports.RecordEvent(systemCtx(org), dev, protocol.Event{EventSeq: seq, Type: protocol.EventAgentUpdated, OccurredAt: time.Now(), Data: data}); err != nil {
			t.Fatal(err)
		}
	}
	report(1, "0.9.5")
	if h.requested(t, dev) == "" {
		t.Fatal("cleared by another version")
	}
	report(2, v)
	if r := h.requested(t, dev); r != "" {
		t.Fatalf("not cleared by the report: %s", r)
	}

	// Requests older than 24 hours end in the command round.
	h.exec(t, "UPDATE device SET agent_update_requested_version = $2, agent_update_requested_at = now() - interval '25 hours' WHERE id = $1", dev, v)
	cmds := app.NewDeviceCommands(nil, h.workerPool(t))
	if n, err := cmds.ExpireAgentUpdateRequests(systemCtx(org), time.Now()); err != nil || n != 1 || h.requested(t, dev) != "" {
		t.Fatalf("expired %d (%v)", n, err)
	}

	h.exec(t, "UPDATE device SET state = 'retired' WHERE id = $1", dev)
	if _, err := updates.RequestNow(op, dev); problem.From(err).Detail != "only active devices can be updated" {
		t.Fatalf("retired device: %v", err)
	}
	if _, err := updates.RequestNow(op, uuid.Must(uuid.NewV7())); problem.From(err).Code != "not_found" {
		t.Fatalf("unknown device: %v", err)
	}
}

// evaluatedOffer is the offer the worker's rollout round would write to ar:current.
type evaluatedOffer struct{ h releaseHarness }

func (e evaluatedOffer) Offer(context.Context) (agentrelease.Offer, bool, error) {
	o, err := e.h.releases.EvaluateRollouts(systemCtx(uuid.Nil), time.Now())
	if err != nil || o == nil {
		return agentrelease.Offer{}, false, err
	}
	return *o, true, nil
}

func (h releaseHarness) workerPool(t *testing.T) *db.OrgPool {
	t.Helper()
	pool, err := db.NewOrgPool(context.Background(), pgtest.SharedPaddock(t).Worker, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func (h releaseHarness) exec(t *testing.T, sql string, args ...any) {
	t.Helper()
	if _, err := h.super.Exec(context.Background(), sql, args...); err != nil {
		t.Fatal(err)
	}
}

func (h releaseHarness) requested(t *testing.T, dev uuid.UUID) string {
	t.Helper()
	var v *string
	if err := h.super.QueryRow(context.Background(), "SELECT agent_update_requested_version FROM device WHERE id = $1", dev).Scan(&v); err != nil {
		t.Fatal(err)
	}
	if v == nil {
		return ""
	}
	return *v
}

// TestUpdateNowFollowsTheSupervisor (review finding 5): under the manual policy only an open request lets a device
// upgrade paddock-supervisor and fleetd, so the request stays open after the agent's report while the device reports
// another supervisor and ends with the supervisor's result; a device on the release can be asked again while its
// supervisor is older or fleetd is outdated.
func TestUpdateNowFollowsTheSupervisor(t *testing.T) {
	h := newReleaseHarness(t, true)
	h.exec(t, "UPDATE agent_rollout SET status = 'halted' WHERE status IN ('running', 'completed')")
	org, dev := h.device(t)
	updates := app.NewAgentUpdates(h.runner, h.workerPool(t), evaluatedOffer{h})
	op := h.operatorIn(t, org, principal.RoleOrgOperator)
	v := h.completedRollout(t, time.Now().Add(2*time.Minute))
	h.exec(t, `INSERT INTO device_status (device_id, organization_id, agent_version, arch, health)
		VALUES ($1, $2, '0.9.0', 'amd64', '{"components": {"paddockd": "0.9.0", "paddock_supervisor": "0.9.0"}}')`, dev, org)
	if _, err := updates.RequestNow(op, dev); err != nil {
		t.Fatal(err)
	}
	report := func(seq int64, typ, outcome string) {
		data, _ := json.Marshal(map[string]string{"version": v, "from_version": "0.9.0", "outcome": outcome})
		if _, err := h.reports.RecordEvent(systemCtx(org), dev, protocol.Event{EventSeq: seq, Type: typ, OccurredAt: time.Now(), Data: data}); err != nil {
			t.Fatal(err)
		}
	}
	report(1, protocol.EventAgentUpdated, "updated")
	if h.requested(t, dev) != v {
		t.Fatal("the agent's report ended the request while the supervisor is outdated")
	}
	report(2, protocol.EventAgentSupervisorUpdated, protocol.SupervisorOutcomeUpdated)
	if r := h.requested(t, dev); r != "" {
		t.Fatalf("the supervisor's result did not end the request: %s", r)
	}

	h.exec(t, "UPDATE device_status SET agent_version = $2 WHERE device_id = $1", dev, v)
	if _, err := updates.RequestNow(op, dev); err != nil {
		t.Fatalf("device on the release with an older supervisor: %v", err)
	}
	h.exec(t, `UPDATE device_status SET health = jsonb_build_object('components', jsonb_build_object('paddock_supervisor', replace($2, '-', '~'))),
		components_outdated = '{fleetd}' WHERE device_id = $1`, dev, v)
	if _, err := updates.RequestNow(op, dev); err != nil {
		t.Fatalf("device on the release with an outdated fleetd: %v", err)
	}
	h.exec(t, "UPDATE device_status SET components_outdated = '{}' WHERE device_id = $1", dev)
	if _, err := updates.RequestNow(op, dev); problem.From(err).Detail != "the device already runs "+v {
		t.Fatalf("device fully current: %v", err)
	}
}
