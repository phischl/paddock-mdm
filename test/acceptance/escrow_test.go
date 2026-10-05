package acceptance

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/paddock-mdm/paddock/pkg/bundle"
	"github.com/paddock-mdm/paddock/pkg/escrow"
	"github.com/paddock-mdm/paddock/pkg/protocol"
	"github.com/paddock-mdm/paddock/test/acceptance/devicesim"
	"github.com/paddock-mdm/paddock/test/acceptance/internal/env"
)

// escrowUpload encrypts secret to the escrow-wrap key of b, uploads it as generation and waits for its final
// status.
func escrowUpload(t *testing.T, d *devicesim.Device, b *bundle.Bundle, generation int64, secret string) (string, string) {
	t.Helper()
	pub, err := escrow.ParsePublicKey(b.Keys.EscrowWrap.PublicKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	version, err := escrow.KeyVersion(b.Keys.EscrowWrap.KeyID)
	if err != nil {
		t.Fatal(err)
	}
	ct, err := escrow.Encrypt(pub, []byte(secret))
	if err != nil {
		t.Fatal(err)
	}
	id := uuid.Must(uuid.NewV7()).String()
	ctx := testContext(t, 2*time.Minute)
	res, err := d.Escrow(ctx, escrow.Request{EscrowID: id, Kind: escrow.KindAdminPassword, Generation: generation, KeyVersion: version, Ciphertext: ct})
	if err != nil || res.Status != http.StatusAccepted {
		t.Fatalf("upload: %v HTTP %d %s", err, res.Status, res.Body)
	}
	for deadline := time.Now().Add(30 * time.Second); ; time.Sleep(time.Second) {
		status, res, err := d.EscrowStatus(ctx, id)
		if err != nil || res.Status != http.StatusOK {
			t.Fatalf("status: %v HTTP %d %s", err, res.Status, res.Body)
		}
		if status != escrow.StatusPending {
			return id, status
		}
		if time.Now().After(deadline) {
			t.Fatalf("escrow %s still pending", id)
		}
	}
}

// TestEscrowEndpoints (plan M4a decision 12): a v2 bundle carries the escrow-wrap key; an upload encrypted to it is
// stored, a second upload of the same generation fails, and another device cannot read the status.
func TestEscrowEndpoints(t *testing.T) {
	alice := login(t, env.Alice)
	d := v2Device(t, alice, "", 1, 2)
	b := latestBundle(t, d, time.Minute, func(b *bundle.Bundle) bool { return b.Keys != nil && b.Keys.EscrowWrap != nil })
	id, status := escrowUpload(t, d, b, 1, "first-password")
	if status != escrow.StatusStored {
		t.Fatalf("first upload %s", status)
	}
	if _, status := escrowUpload(t, d, b, 1, "same-generation"); status != escrow.StatusFailed {
		t.Fatalf("second upload of generation 1: %s", status)
	}
	other := activeDevice(t, alice, "", "esc-other-"+uniqueSuffix())
	if _, res, err := other.EscrowStatus(testContext(t, time.Minute), id); err != nil || res.Status != http.StatusNotFound {
		t.Fatalf("status of another device's upload: %v HTTP %d", err, res.Status)
	}
}

// escrowedDevice enrolls a v2 device of alice's organization whose local administrator password generation 1 is
// escrowed and confirmed (local_admin.rotated), as an agent does it, and returns the device and the password.
func escrowedDevice(t *testing.T, alice *env.Portal) (*devicesim.Device, string) {
	t.Helper()
	d := v2Device(t, alice, "", 1, 2)
	b := latestBundle(t, d, time.Minute, func(b *bundle.Bundle) bool { return b.Keys != nil && b.Keys.EscrowWrap != nil })
	password := "escrowed-" + uniqueSuffix()
	if _, status := escrowUpload(t, d, b, 1, password); status != escrow.StatusStored {
		t.Fatalf("escrow upload %s", status)
	}
	data, _ := json.Marshal(protocol.LocalAdminRotated{Generation: 1})
	res, err := d.SendEvents(testContext(t, time.Minute), []protocol.Event{{EventSeq: 1, Type: protocol.EventLocalAdminRotated, OccurredAt: time.Now(), Data: data}})
	if err != nil || res.Status != http.StatusAccepted {
		t.Fatalf("rotated event: %v HTTP %d %s", err, res.Status, res.Body)
	}
	for deadline := time.Now().Add(30 * time.Second); ; time.Sleep(time.Second) {
		var state struct {
			Active *int `json:"active_generation"`
		}
		if err := call(t, alice, http.MethodGet, "/api/v1/devices/"+d.DeviceID+"/local-admin", nil).JSON(&state); err != nil {
			t.Fatal(err)
		}
		if state.Active != nil && *state.Active == 1 {
			return d, password
		}
		if time.Now().After(deadline) {
			t.Fatal("generation 1 not active")
		}
	}
}
