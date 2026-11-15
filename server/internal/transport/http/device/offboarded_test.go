package device_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/pkg/command"
	"github.com/phischl/paddock-mdm/pkg/protocol"
	"github.com/phischl/paddock-mdm/server/internal/devicecache"
	"github.com/phischl/paddock-mdm/server/internal/ingest"
	"github.com/phischl/paddock-mdm/server/internal/platform/mq"
)

// TestOffboardedKeyGetsOnlyTheUninstall (plan M17 decision 15, amendment l point 3, PDK-1016): a device whose
// organization was deleted keeps its dk: (status offboarded), cmd: with the disarm and the uninstall, seq: and sd:. A
// check-in carries the disarm first and then the uninstall (amendment n): no other command, no bundle, no agent offer,
// no time ticket, and no heartbeat is published. The results of both are accepted (the agent starts its removal only
// after the uninstall's) but not published; the result of another command in cmd: is refused. An event batch is
// published only when it is exactly one agent.uninstalled; any other batch is answered 200 and dropped. Escrow upload
// and status, diagnostics, catalog icons and the result of another command are refused with 401 identity_revoked.
func TestOffboardedKeyGetsOnlyTheUninstall(t *testing.T) {
	e := newEnv(t, 0, 0)
	c := newClient(t)
	id := e.enrolled(c, devicecache.KeyOffboarded)
	ctx := context.Background()
	uninstall, lock, disarm := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	uninstallEnv, disarmEnv := commandEnvelope(t, uninstall, id, command.TypeUninstall), commandEnvelope(t, disarm, id, command.TypeDeleteSelfLock)
	for cmd, env := range map[uuid.UUID]json.RawMessage{uninstall: uninstallEnv, disarm: disarmEnv,
		lock: commandEnvelope(t, lock, id, command.TypeRotateAdminPassword)} {
		if err := e.cache.PutCommand(ctx, id, cmd, devicecache.Command{ExpiresAt: e.now.Add(365 * 24 * time.Hour), Envelope: env}); err != nil {
			t.Fatal(err)
		}
	}
	if err := e.cache.PutBundlePointer(ctx, id, devicecache.BundlePointer{Version: 3, SHA256: "s", ObjectKey: "k"}); err != nil {
		t.Fatal(err)
	}
	if err := e.cache.PutTimeTicket(ctx, e.org, []byte(`{"payload":"e30="}`)); err != nil {
		t.Fatal(err)
	}
	ct := base64.StdEncoding.EncodeToString(make([]byte, 512))
	refused := map[string]request{
		"escrow": {method: "POST", path: "/v1/escrow", device: id.String(), body: map[string]any{"escrow_id": uuid.NewString(),
			"kind": "admin_password", "generation": 1, "key_version": 1, "ciphertext": ct}},
		"escrow status": {method: "GET", path: "/v1/escrow/" + uuid.NewString(), device: id.String()},
		"diagnostics":   {method: "POST", path: "/v1/diagnostics", device: id.String(), body: diagnosticsBody(lock)},
		"catalog icon":  {method: "GET", path: "/v1/catalog/" + uuid.NewString() + "/icon", device: id.String()},
		"command result of an unknown command": {method: "POST", path: "/v1/commands/" + uuid.NewString() + "/result", device: id.String(),
			body: protocol.CommandResult{Status: "succeeded", Result: json.RawMessage(`{}`)}},
		"command result of another pending command": {method: "POST", path: "/v1/commands/" + lock.String() + "/result", device: id.String(),
			body: protocol.CommandResult{Status: "succeeded", Result: json.RawMessage(`{}`)}},
	}
	for name, rq := range refused {
		t.Run(name, func(t *testing.T) {
			e.expectProblem(e.send(c, rq), http.StatusUnauthorized, "identity_revoked")
		})
	}
	published := func() int { return len(e.pub.msgs[mq.ExchangeIngest]) }

	t.Run("check-in", func(t *testing.T) {
		before := published()
		r := e.send(c, request{method: "POST", path: "/v1/checkin", device: id.String(), body: checkinBody(0)})
		var out protocol.CheckinResponse
		if err := json.Unmarshal(r.body, &out); err != nil || r.status != http.StatusOK {
			t.Fatalf("checkin: %d %s", r.status, r.body)
		}
		if len(out.Commands) != 2 || string(out.Commands[0]) != string(disarmEnv) || string(out.Commands[1]) != string(uninstallEnv) || out.Bundle != nil ||
			out.AgentUpdate != nil || out.TimeTicket != nil || out.Seq == 0 {
			t.Fatalf("an offboarded device's check-in: %s", r.body)
		}
		if n := published() - before; n != 0 {
			t.Fatalf("an offboarded device's check-in published %d messages", n)
		}
	})

	t.Run("results of the disarm and the uninstall", func(t *testing.T) {
		before := published()
		post := func(cmd uuid.UUID, status string) result {
			return e.send(c, request{method: "POST", path: "/v1/commands/" + cmd.String() + "/result", device: id.String(),
				body: protocol.CommandResult{Status: status, Result: json.RawMessage(`{}`)}})
		}
		for _, cmd := range []uuid.UUID{disarm, uninstall} {
			for range 2 {
				if r := post(cmd, "succeeded"); r.status != http.StatusAccepted {
					t.Fatalf("result of %s: %d %s", cmd, r.status, r.body)
				}
			}
			e.expectProblem(post(cmd, "failed"), http.StatusConflict, "conflict")
		}
		if n := published() - before; n != 0 {
			t.Fatalf("the results published %d messages", n)
		}
	})

	t.Run("events", func(t *testing.T) {
		ev := func(seq int64, typ string) protocol.Event {
			return protocol.Event{EventSeq: seq, Type: typ, OccurredAt: e.now, Data: json.RawMessage(`{}`)}
		}
		send := func(events ...protocol.Event) result {
			return e.send(c, request{method: "POST", path: "/v1/events", device: id.String(), body: protocol.EventsRequest{Events: events}})
		}
		before := published()
		for name, batch := range map[string][]protocol.Event{
			"other events":                   {ev(1, "bundle.applied"), ev(2, "config.drift_corrected")},
			"agent.uninstalled with another": {ev(3, "bundle.applied"), ev(4, protocol.EventAgentUninstalled)},
			"one event of another type":      {ev(5, "bundle.applied")},
		} {
			if r := send(batch...); r.status != http.StatusOK {
				t.Fatalf("%s: %d %s, want 200", name, r.status, r.body)
			}
		}
		if n := published() - before; n != 0 {
			t.Fatalf("dropped batches published %d messages", n)
		}
		if r := send(ev(6, protocol.EventAgentUninstalled)); r.status != http.StatusAccepted {
			t.Fatalf("agent.uninstalled: %d %s", r.status, r.body)
		}
		var batch ingest.Events
		msg := e.pub.last(t)
		if err := json.Unmarshal(msg.Body, &batch); err != nil || msg.RoutingKey != "ingest.event."+e.org.String() ||
			batch.DeviceID != id || len(batch.Events) != 1 || batch.Events[0].Type != protocol.EventAgentUninstalled {
			t.Fatalf("published %s %+v", msg.RoutingKey, batch)
		}
	})
}
