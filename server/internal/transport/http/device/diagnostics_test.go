package device_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/pkg/command"
	"github.com/phischl/paddock-mdm/pkg/dsse"
	"github.com/phischl/paddock-mdm/pkg/protocol"
	"github.com/phischl/paddock-mdm/server/internal/devicecache"
	"github.com/phischl/paddock-mdm/server/internal/ingest"
)

// commandEnvelope is an envelope of a command of typ for device as the worker publishes it; the gateway reads its
// payload without verifying the signature.
func commandEnvelope(t *testing.T, id, device uuid.UUID, typ string) json.RawMessage {
	t.Helper()
	payload, err := command.Encode(command.Command{CommandID: id.String(), DeviceID: device.String(),
		OrganizationID: uuid.NewString(), Type: typ, IssuedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	env, err := dsse.New(command.PayloadType, payload, dsse.Signature{KeyID: "command-signing:v1", Sig: "AA=="}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	return env
}

func diagnosticsBody(cmd uuid.UUID) map[string]any {
	return map[string]any{"command_id": cmd.String(), "sha256": strings.Repeat("cd", 32), "size": 2345678,
		"nonce":       base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{2}, 12)),
		"wrapped_dek": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 512)), "key_version": 3}
}

// TestDiagnosticsAnnounce (plan M12 decisions 2 and 5): a collect_status command held for the device is answered with
// a presigned PUT bound to the announced size and published to the escrow ingest queue; a second announcement is 409
// already_uploaded; another command type, another device's command or a command not held for the device is 404; a
// size above 32 MiB is 413; malformed fields are 400.
func TestDiagnosticsAnnounce(t *testing.T) {
	e := newEnv(t, 0, 0)
	c, other := newClient(t), newClient(t)
	id, otherID := e.enrolled(c, "active"), e.enrolled(other, "active")
	ctx := context.Background()
	put := func(device, cmd uuid.UUID, typ string) {
		t.Helper()
		if err := e.cache.PutCommand(ctx, device, cmd, devicecache.Command{ExpiresAt: e.now.Add(time.Hour),
			Envelope: commandEnvelope(t, cmd, device, typ)}); err != nil {
			t.Fatal(err)
		}
	}
	announce := func(c client, device uuid.UUID, body any, skip bool) result {
		t.Helper()
		return e.send(c, request{method: "POST", path: "/v1/diagnostics", device: device.String(), body: body, skipReqCheck: skip})
	}
	cmd, install, othersCmd := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	put(id, cmd, command.TypeCollectStatus)
	put(id, install, command.TypeInstallNow)
	put(otherID, othersCmd, command.TypeCollectStatus)

	before := len(e.pub.msgs["paddock.ingest"])
	t.Run("not found", func(t *testing.T) {
		e.expectProblem(announce(c, id, diagnosticsBody(install), false), http.StatusNotFound, "not_found")
		e.expectProblem(announce(c, id, diagnosticsBody(othersCmd), false), http.StatusNotFound, "not_found")
		e.expectProblem(announce(other, otherID, diagnosticsBody(cmd), false), http.StatusNotFound, "not_found")
		e.expectProblem(announce(c, id, diagnosticsBody(uuid.Must(uuid.NewV7())), false), http.StatusNotFound, "not_found")
		expired := uuid.Must(uuid.NewV7())
		if err := e.cache.PutCommand(ctx, id, expired, devicecache.Command{ExpiresAt: e.now,
			Envelope: commandEnvelope(t, expired, id, command.TypeCollectStatus)}); err != nil {
			t.Fatal(err)
		}
		e.expectProblem(announce(c, id, diagnosticsBody(expired), false), http.StatusNotFound, "not_found")
		if len(e.pub.msgs["paddock.ingest"]) != before {
			t.Fatal("a refused announcement was published")
		}
	})

	t.Run("too large", func(t *testing.T) {
		body := diagnosticsBody(cmd)
		body["size"] = protocol.MaxDiagnosticsObject + 1
		e.expectProblem(announce(c, id, body, true), http.StatusRequestEntityTooLarge, "payload_too_large")
	})

	for name, mutate := range map[string]func(map[string]any){
		"command_id":  func(b map[string]any) { b["command_id"] = "collect" },
		"sha256":      func(b map[string]any) { b["sha256"] = strings.Repeat("CD", 32) },
		"short sha":   func(b map[string]any) { b["sha256"] = "cd" },
		"size":        func(b map[string]any) { b["size"] = 0 },
		"no size":     func(b map[string]any) { delete(b, "size") },
		"nonce":       func(b map[string]any) { b["nonce"] = base64.StdEncoding.EncodeToString(make([]byte, 16)) },
		"wrapped_dek": func(b map[string]any) { b["wrapped_dek"] = "%%%" },
		"no dek":      func(b map[string]any) { delete(b, "wrapped_dek") },
		"key_version": func(b map[string]any) { b["key_version"] = -1 },
	} {
		t.Run(name, func(t *testing.T) {
			body := diagnosticsBody(cmd)
			mutate(body)
			e.expectProblem(announce(c, id, body, true), http.StatusBadRequest, "invalid_request")
		})
	}

	r := announce(c, id, diagnosticsBody(cmd), false)
	var out protocol.DiagnosticsResponse
	key := "org/" + e.org.String() + "/devices/" + id.String() + "/diagnostics/" + cmd.String() + ".bin"
	if err := json.Unmarshal(r.body, &out); err != nil || r.status != http.StatusAccepted || out.DiagnosticsID != cmd.String() ||
		out.UploadURL != "https://bundles.test/paddock-escrow/"+key+"?X-Amz-Expires=600&size=2345678" {
		t.Fatalf("announce: %d %s", r.status, r.body)
	}
	msg := e.pub.last(t)
	var in ingest.DiagnosticsAnnounced
	if err := json.Unmarshal(msg.Body, &in); err != nil || msg.RoutingKey != "ingest.escrow."+e.org.String() ||
		msg.MessageID != "diagnostics:"+cmd.String() || in.DiagnosticsID != cmd || in.DeviceID != id || in.OrganizationID != e.org ||
		in.ObjectKey != key || in.SHA256 != strings.Repeat("cd", 32) || in.Size != 2345678 || len(in.Nonce) != 12 ||
		len(in.WrappedDEK) != 512 || in.KeyVersion != 3 || !in.ReceivedAt.Equal(e.now) {
		t.Fatalf("published %s %s %+v", msg.RoutingKey, msg.MessageID, in)
	}
	published := len(e.pub.msgs["paddock.ingest"])
	e.expectProblem(announce(c, id, diagnosticsBody(cmd), false), http.StatusConflict, "already_uploaded")
	if len(e.pub.msgs["paddock.ingest"]) != published {
		t.Fatal("a second announcement was published")
	}

	t.Run("agent without key_version", func(t *testing.T) {
		older := uuid.Must(uuid.NewV7())
		put(id, older, command.TypeCollectStatus)
		body := diagnosticsBody(older)
		delete(body, "key_version")
		if r := announce(c, id, body, false); r.status != http.StatusAccepted {
			t.Fatalf("announce: %d %s", r.status, r.body)
		}
		var in ingest.DiagnosticsAnnounced
		if err := json.Unmarshal(e.pub.last(t).Body, &in); err != nil || in.DiagnosticsID != older || in.KeyVersion != 0 {
			t.Fatalf("published %+v", in)
		}
	})
}

// TestDiagnosticsAnnounceRetryAfterFailedPublish: an announcement the broker refused (503) is not remembered, so the
// device's retry succeeds.
func TestDiagnosticsAnnounceRetryAfterFailedPublish(t *testing.T) {
	e := newEnv(t, 0, 0)
	c := newClient(t)
	id := e.enrolled(c, "active")
	cmd := uuid.Must(uuid.NewV7())
	if err := e.cache.PutCommand(context.Background(), id, cmd, devicecache.Command{ExpiresAt: e.now.Add(time.Hour),
		Envelope: commandEnvelope(t, cmd, id, command.TypeCollectStatus)}); err != nil {
		t.Fatal(err)
	}
	e.pub.nack = true
	e.expectProblem(e.send(c, request{method: "POST", path: "/v1/diagnostics", device: id.String(), body: diagnosticsBody(cmd)}),
		http.StatusServiceUnavailable, "backpressure")
	e.pub.nack = false
	if r := e.send(c, request{method: "POST", path: "/v1/diagnostics", device: id.String(), body: diagnosticsBody(cmd)}); r.status != http.StatusAccepted {
		t.Fatalf("retry: %d %s", r.status, r.body)
	}
}
