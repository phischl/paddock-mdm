package acceptance

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/pkg/bundle"
	"github.com/phischl/paddock-mdm/pkg/escrow"
	"github.com/phischl/paddock-mdm/test/acceptance/devicesim"
	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
)

// escrowWrap returns the escrow-wrap key of a bundle.
func escrowWrap(t *testing.T, b *bundle.Bundle) (pub *rsa.PublicKey, version int) {
	t.Helper()
	pub, err := escrow.ParsePublicKey(b.Keys.EscrowWrap.PublicKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	if version, err = escrow.KeyVersion(b.Keys.EscrowWrap.KeyID); err != nil {
		t.Fatal(err)
	}
	return pub, version
}

// waitEscrow polls an escrow until it is not pending, every 5 s like a device would (each device may send 30
// requests a minute).
func waitEscrow(t *testing.T, d *devicesim.Device, id string, timeout time.Duration) string {
	t.Helper()
	ctx := testContext(t, timeout+time.Minute)
	for deadline := time.Now().Add(timeout); ; time.Sleep(5 * time.Second) {
		status, res, err := d.EscrowStatus(ctx, id)
		if err != nil || res.Status != http.StatusOK {
			t.Fatalf("status: %v HTTP %d %s", err, res.Status, res.Body)
		}
		if status != escrow.StatusPending {
			return status
		}
		if time.Now().After(deadline) {
			t.Fatalf("escrow %s still pending", id)
		}
	}
}

// escrowHeader seals header for generation, announces it and uploads object (nil: the sealed object) to the
// presigned URL; it returns the escrow ID, the upload URL and the HTTP status of the upload.
func escrowHeader(t *testing.T, d *devicesim.Device, b *bundle.Bundle, generation int64, header, object []byte) (string, string, int) {
	t.Helper()
	pub, version := escrowWrap(t, b)
	id := uuid.Must(uuid.NewV7()).String()
	sealed, err := escrow.SealHeader(pub, header, id)
	if err != nil {
		t.Fatal(err)
	}
	if object == nil {
		object = sealed.Object
	}
	ctx := testContext(t, 2*time.Minute)
	res, err := d.Escrow(ctx, escrow.Request{EscrowID: id, Kind: escrow.KindLUKSHeader, Generation: generation, KeyVersion: version,
		WrappedDEK: sealed.WrappedDEK, Nonce: sealed.Nonce, SHA256: sealed.SHA256, Size: int64(len(sealed.Object))})
	var accepted escrow.Accepted
	if err != nil || res.Status != http.StatusAccepted || json.Unmarshal(res.Body, &accepted) != nil || accepted.UploadURL == "" {
		t.Fatalf("header escrow: %v HTTP %d %s", err, res.Status, res.Body)
	}
	status, err := d.Upload(ctx, accepted.UploadURL, object)
	if err != nil {
		t.Fatal(err)
	}
	return id, accepted.UploadURL, status
}

// testHeader is a stand-in for a LUKS header backup: 16 MiB, mostly zeros, with a random keyslot area.
func testHeader(t *testing.T) []byte {
	t.Helper()
	h := make([]byte, 16<<20)
	copy(h, "LUKS\xba\xbe\x00\x02")
	if _, err := rand.Read(h[32768 : 32768+258048]); err != nil {
		t.Fatal(err)
	}
	return h
}

// TestDiskEscrow (plan M4b decisions 10 and 13): a recovery key is stored like a secret; a sealed header uploaded to
// its presigned URL is stored once the worker found it with the announced size and SHA-256, a different object fails;
// the URL writes only the key the server chose, and generations must increase.
func TestDiskEscrow(t *testing.T) {
	alice := login(t, env.Alice)
	d := v2Device(t, alice, "", 1, 2)
	b := latestBundle(t, d, time.Minute, func(b *bundle.Bundle) bool { return b.Keys != nil && b.Keys.EscrowWrap != nil })
	pub, version := escrowWrap(t, b)
	ct, err := escrow.Encrypt(pub, []byte("recovery-key"))
	if err != nil {
		t.Fatal(err)
	}
	recoveryID := uuid.Must(uuid.NewV7()).String()
	res, err := d.Escrow(testContext(t, time.Minute), escrow.Request{EscrowID: recoveryID, Kind: escrow.KindLUKSRecoveryKey, Generation: 1,
		KeyVersion: version, Ciphertext: ct})
	if err != nil || res.Status != http.StatusAccepted {
		t.Fatalf("recovery key: %v HTTP %d %s", err, res.Status, res.Body)
	}
	if status := waitEscrow(t, d, recoveryID, 30*time.Second); status != escrow.StatusStored {
		t.Fatalf("recovery key %s", status)
	}

	header := testHeader(t)
	id, url, status := escrowHeader(t, d, b, 1, header, nil)
	if status != http.StatusOK || !strings.Contains(url, "/paddock-escrow/org/") || !strings.Contains(url, "/devices/"+d.DeviceID+"/luks-header/1.bin?") {
		t.Fatalf("upload to %s: HTTP %d", url, status)
	}
	if status := waitEscrow(t, d, id, time.Minute); status != escrow.StatusStored {
		t.Fatalf("header generation 1: %s", status)
	}
	// The signature fixes the key: the same URL for another generation is refused.
	other := strings.Replace(url, "/luks-header/1.bin?", "/luks-header/9.bin?", 1)
	if status, err := d.Upload(testContext(t, time.Minute), other, []byte("x")); err != nil || status != http.StatusForbidden {
		t.Fatalf("upload to another key: %v HTTP %d", err, status)
	}
	// An object that is not the announced one fails, and generations must increase.
	id, _, status = escrowHeader(t, d, b, 2, header, []byte("something else"))
	if status != http.StatusOK {
		t.Fatalf("upload: HTTP %d", status)
	}
	if status := waitEscrow(t, d, id, time.Minute); status != escrow.StatusFailed {
		t.Fatalf("mismatching header: %s", status)
	}
	id, _, _ = escrowHeader(t, d, b, 1, header, nil)
	if status := waitEscrow(t, d, id, time.Minute); status != escrow.StatusFailed {
		t.Fatalf("header generation 1 again: %s", status)
	}
}
