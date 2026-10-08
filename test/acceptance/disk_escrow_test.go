package acceptance

import (
	"bytes"
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
	return escrowVolumeHeader(t, d, b, "", generation, header, object)
}

// escrowVolumeHeader is escrowHeader for the LUKS volume with UUID volume ("": none, as before PDK-009).
func escrowVolumeHeader(t *testing.T, d *devicesim.Device, b *bundle.Bundle, volume string, generation int64, header, object []byte) (string, string, int) {
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
		Volume: volume, WrappedDEK: sealed.WrappedDEK, Nonce: sealed.Nonce, SHA256: sealed.SHA256, Size: int64(len(sealed.Object))})
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

// diskDevice enrolls a v2 device of alice's organization that escrowed recovery key generation 1 and header
// generation 1, as the luks reconciler does, and returns it with the key and the header.
func diskDevice(t *testing.T, alice *env.Portal) (*devicesim.Device, string, []byte) {
	t.Helper()
	d := v2Device(t, alice, "", 1, 2)
	b := latestBundle(t, d, time.Minute, func(b *bundle.Bundle) bool { return b.Keys != nil && b.Keys.EscrowWrap != nil })
	pub, version := escrowWrap(t, b)
	key := "recovery-" + uniqueSuffix()
	ct, err := escrow.Encrypt(pub, []byte(key))
	if err != nil {
		t.Fatal(err)
	}
	id := uuid.Must(uuid.NewV7()).String()
	res, err := d.Escrow(testContext(t, time.Minute), escrow.Request{EscrowID: id, Kind: escrow.KindLUKSRecoveryKey, Generation: 1,
		KeyVersion: version, Ciphertext: ct})
	if err != nil || res.Status != http.StatusAccepted || waitEscrow(t, d, id, 30*time.Second) != escrow.StatusStored {
		t.Fatalf("recovery key escrow: %v HTTP %d", err, res.Status)
	}
	header := testHeader(t)
	id, _, status := escrowHeader(t, d, b, 1, header, nil)
	if status != http.StatusOK || waitEscrow(t, d, id, time.Minute) != escrow.StatusStored {
		t.Fatalf("header escrow: HTTP %d", status)
	}
	return d, key, header
}

// TestDiskRecovery is gate D-ESC at the API (plan M4b decision 14, AC2): with a fresh step-up and the typed hostname
// an organization administrator gets the escrowed recovery key and the decrypted header, each reveal and download is
// audited exactly once, without step-up the request is refused and audited as denied, auditors see the state only.
func TestDiskRecovery(t *testing.T) {
	alice, bob := login(t, env.Alice), login(t, env.Bob)
	d, key, header := diskDevice(t, alice)
	hostname := getDevice(t, alice, d.DeviceID).Hostname
	path := "/api/v1/devices/" + d.DeviceID + "/disk"

	var disk struct {
		RecoveryKeys []struct {
			Generation int    `json:"generation"`
			Status     string `json:"status"`
		} `json:"recovery_keys"`
		Headers []struct {
			Generation int    `json:"generation"`
			Status     string `json:"status"`
		} `json:"headers"`
	}
	if err := call(t, bob, http.MethodGet, path, nil).JSON(&disk); err != nil || len(disk.RecoveryKeys) != 1 || len(disk.Headers) != 1 ||
		disk.Headers[0].Status != "stored" {
		t.Fatalf("disk state %+v %v", disk, err)
	}
	body := map[string]any{"confirm_hostname": hostname}
	res := call(t, alice, http.MethodPost, path+"/recovery-key", body)
	expectStatus(t, res, http.StatusForbidden, "step_up_required")
	expectOneEvent(t, alice, res.RequestID, "disk.recovery_key_revealed", "denied")

	stepUp(t, alice, env.Alice, true)
	res = call(t, alice, http.MethodPost, path+"/recovery-key", body)
	expectStatus(t, res, http.StatusOK, "")
	var revealed struct {
		Generation  int    `json:"generation"`
		RecoveryKey string `json:"recovery_key"`
	}
	if err := res.JSON(&revealed); err != nil || revealed.RecoveryKey != key || revealed.Generation != 1 {
		t.Fatalf("revealed generation %d (%v), key matches: %v", revealed.Generation, err, revealed.RecoveryKey == key)
	}
	ev := expectOneEvent(t, alice, res.RequestID, "disk.recovery_key_revealed", "success")
	if raw, _ := json.Marshal(ev); strings.Contains(string(raw), key) {
		t.Fatal("the audit event contains the recovery key")
	}

	res = call(t, alice, http.MethodPost, path+"/header", body)
	expectStatus(t, res, http.StatusOK, "")
	if !bytes.Equal(res.Body, header) || res.Header.Get("Content-Disposition") != "attachment; filename="+hostname+"-luks-header-1.img" {
		t.Fatalf("header: %d bytes, Content-Disposition %q", len(res.Body), res.Header.Get("Content-Disposition"))
	}
	expectOneEvent(t, alice, res.RequestID, "disk.header_downloaded", "success")

	res = call(t, bob, http.MethodPost, path+"/header", body)
	expectStatus(t, res, http.StatusForbidden, "forbidden")
}

// TestDiskEscrowVolumes is the acceptance check of the escrow schema of PDK-009 (decisions 1, 4 and 5): a header with
// a volume is stored below the volume's UUID; the root volume's header escrowed without a volume gets the root UUID
// with the first check-in that reports it; the disk card lists both volumes, and each header downloads on its own and
// is audited with its volume.
func TestDiskEscrowVolumes(t *testing.T) {
	alice := login(t, env.Alice)
	d := v2Device(t, alice, "", 1, 2)
	b := latestBundle(t, d, time.Minute, func(b *bundle.Bundle) bool { return b.Keys != nil && b.Keys.EscrowWrap != nil })
	root, data := uuid.NewString(), uuid.NewString()
	rootHeader, dataHeader := testHeader(t), testHeader(t)
	id, _, status := escrowHeader(t, d, b, 1, rootHeader, nil)
	if status != http.StatusOK || waitEscrow(t, d, id, time.Minute) != escrow.StatusStored {
		t.Fatalf("root header: HTTP %d", status)
	}
	id, url, status := escrowVolumeHeader(t, d, b, data, 2, dataHeader, nil)
	if status != http.StatusOK || !strings.Contains(url, "/devices/"+d.DeviceID+"/luks-header/"+data+"/2.bin?") {
		t.Fatalf("upload to %s: HTTP %d", url, status)
	}
	if status := waitEscrow(t, d, id, time.Minute); status != escrow.StatusStored {
		t.Fatalf("data header: %s", status)
	}
	d.Health = json.RawMessage(`{"disk":{"state":"compliant","luks_version":2,"tokens":["recovery","tpm2+pin"],"keyslots":2,"volumes":[` +
		`{"uuid":"` + root + `","device":"/dev/sda3","root":true,"luks_version":2,"tokens":["recovery","tpm2+pin"],"keyslots":2,"escrowed":true,"header_generation":1},` +
		`{"uuid":"` + data + `","device":"/dev/sdb1","luks_version":2,"tokens":["password"],"keyslots":1,"escrowed":true,"header_generation":2}]}}`)
	if _, res, err := d.Checkin(testContext(t, time.Minute)); err != nil || res.Status != http.StatusOK {
		t.Fatalf("check-in: %v HTTP %d", err, res.Status)
	}

	path := "/api/v1/devices/" + d.DeviceID + "/disk"
	var disk struct {
		Volumes []struct {
			UUID   string `json:"uuid"`
			Device string `json:"device"`
			Root   bool   `json:"root"`
		} `json:"volumes"`
		Headers []struct {
			Generation int    `json:"generation"`
			Volume     string `json:"volume"`
		} `json:"headers"`
	}
	for deadline := time.Now().Add(time.Minute); ; time.Sleep(2 * time.Second) {
		if err := call(t, alice, http.MethodGet, path, nil).JSON(&disk); err != nil {
			t.Fatal(err)
		}
		if len(disk.Headers) == 2 && disk.Headers[1].Volume == root {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the root header did not get the root volume: %+v", disk)
		}
	}
	if len(disk.Volumes) != 2 || !disk.Volumes[0].Root || disk.Volumes[1].UUID != data || disk.Headers[0].Volume != data {
		t.Fatalf("disk %+v", disk)
	}

	hostname := getDevice(t, alice, d.DeviceID).Hostname
	stepUp(t, alice, env.Alice, true)
	res := call(t, alice, http.MethodPost, path+"/header", map[string]any{"confirm_hostname": hostname, "volume": data})
	expectStatus(t, res, http.StatusOK, "")
	if !bytes.Equal(res.Body, dataHeader) || res.Header.Get("Content-Disposition") != "attachment; filename="+hostname+"-luks-header-"+data+"-2.img" {
		t.Fatalf("data header: %d bytes, Content-Disposition %q", len(res.Body), res.Header.Get("Content-Disposition"))
	}
	if ev := expectOneEvent(t, alice, res.RequestID, "disk.header_downloaded", "success"); ev.Params["volume"] != data {
		t.Fatalf("audit params %v", ev.Params)
	}
	res = call(t, alice, http.MethodPost, path+"/header", map[string]any{"confirm_hostname": hostname})
	expectStatus(t, res, http.StatusOK, "")
	if !bytes.Equal(res.Body, rootHeader) {
		t.Fatalf("root header by default: %d bytes", len(res.Body))
	}
}

// diskAuditCases are the A3 cases of the disk recovery (plan M4b decision 14); each case that needs a step-up signs
// in on its own, as a step-up changes the session it runs in.
func diskAuditCases(verb, code string) []auditCase {
	target := func(id string) string { return "/api/v1/devices/" + id + "/disk/" + verb }
	return []auditCase{
		{"success", func(t *testing.T, w *auditWorld) {
			alice := login(t, env.Alice)
			d, _, _ := diskDevice(t, alice)
			stepUp(t, alice, env.Alice, true)
			res := call(t, alice, http.MethodPost, target(d.DeviceID), map[string]any{"confirm_hostname": getDevice(t, alice, d.DeviceID).Hostname})
			expectStatus(t, res, http.StatusOK, "")
			expectOneEvent(t, w.alice, res.RequestID, code, "success")
		}},
		{"no step-up", func(t *testing.T, w *auditWorld) {
			res := call(t, login(t, env.Alice), http.MethodPost, target(activeID(t, w)), map[string]any{"confirm_hostname": "x"})
			expectStatus(t, res, http.StatusForbidden, "step_up_required")
			expectOneEvent(t, w.alice, res.RequestID, code, "denied")
		}},
		{"wrong role", func(t *testing.T, w *auditWorld) {
			res := call(t, w.bob, http.MethodPost, target(activeID(t, w)), map[string]any{"confirm_hostname": "x"})
			expectStatus(t, res, http.StatusForbidden, "forbidden")
			expectOneEvent(t, w.alice, res.RequestID, code, "denied")
		}},
		{"validation failure and not found", func(t *testing.T, w *auditWorld) {
			alice := login(t, env.Alice)
			stepUp(t, alice, env.Alice, true)
			res := call(t, alice, http.MethodPost, target(activeID(t, w)), map[string]any{"confirm_hostname": "not-the-hostname"})
			expectStatus(t, res, http.StatusBadRequest, "invalid_request")
			expectOneEvent(t, w.alice, res.RequestID, code, "failure")
			res = call(t, alice, http.MethodPost, target(uuid.NewString()), map[string]any{"confirm_hostname": "x"})
			expectStatus(t, res, http.StatusNotFound, "not_found")
			expectOneEvent(t, w.alice, res.RequestID, code, "failure")
		}},
		{"conflict", func(t *testing.T, w *auditWorld) {
			alice := login(t, env.Alice)
			id := activeID(t, w)
			stepUp(t, alice, env.Alice, true)
			res := call(t, alice, http.MethodPost, target(id), map[string]any{"confirm_hostname": getDevice(t, alice, id).Hostname})
			expectStatus(t, res, http.StatusConflict, "invalid_state")
			expectOneEvent(t, w.alice, res.RequestID, code, "failure")
		}},
	}
}

func init() {
	deviceAuditCases["POST /api/v1/devices/{id}/disk/recovery-key"] = diskAuditCases("recovery-key", "disk.recovery_key_revealed")
	deviceAuditCases["POST /api/v1/devices/{id}/disk/header"] = diskAuditCases("header", "disk.header_downloaded")
}
