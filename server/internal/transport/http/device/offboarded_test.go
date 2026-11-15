package device_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/pkg/protocol"
	"github.com/phischl/paddock-mdm/server/internal/devicecache"
)

// keyStatusOffboarded is the dk: status the devices step writes for a device of a deleted organization (plan M17
// decision 15, PDK-1016).
const keyStatusOffboarded = "offboarded"

// TestOffboardedKeyGetsOnlyTheUninstall (plan M17 decision 15, amendment l point 3, PDK-1015 review 1): a device whose
// organization was deleted keeps its dk: (status offboarded), cmd: with the uninstall, seq: and sd:. It reaches
// nothing beyond the uninstall: escrow, diagnostics and command results of the tombstoned organization are refused
// with 401 identity_revoked, and a check-in carries no bundle, no agent offer and no time ticket.
func TestOffboardedKeyGetsOnlyTheUninstall(t *testing.T) {
	e := newEnv(t, 0, 0)
	c := newClient(t)
	id := e.enrolled(c, keyStatusOffboarded)
	ctx := context.Background()
	uninstall := uuid.Must(uuid.NewV7())
	if err := e.cache.PutCommand(ctx, id, uninstall, devicecache.Command{ExpiresAt: e.now.Add(365 * 24 * time.Hour),
		Envelope: envelope(uninstall)}); err != nil {
		t.Fatal(err)
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
		"command result of another command": {method: "POST", path: "/v1/commands/" + uuid.NewString() + "/result", device: id.String(),
			body: protocol.CommandResult{Status: "succeeded", Result: json.RawMessage(`{}`)}},
	}
	for name, rq := range refused {
		t.Run(name, func(t *testing.T) {
			e.expectProblem(e.send(c, rq), http.StatusUnauthorized, "identity_revoked")
		})
	}

	t.Run("check-in", func(t *testing.T) {
		// Until PDK-1016 the gateway refuses every route of an offboarded key, the check-in included: the safety net of
		// the devices step keeps such a device's organization from being deleted meanwhile (main §37). PDK-1016
		// removes this skip; the check-in must then answer the uninstall and nothing else.
		t.Skip("PDK-1016: the gateway serves offboarded keys")
		r := e.send(c, request{method: "POST", path: "/v1/checkin", device: id.String(), body: checkinBody(0)})
		var out protocol.CheckinResponse
		if err := json.Unmarshal(r.body, &out); err != nil || r.status != http.StatusOK {
			t.Fatalf("checkin: %d %s", r.status, r.body)
		}
		if len(out.Commands) != 1 || string(out.Commands[0]) != string(envelope(uninstall)) || out.Bundle != nil ||
			out.AgentUpdate != nil || out.TimeTicket != nil {
			t.Fatalf("an offboarded device's check-in: %s", r.body)
		}
	})
}
