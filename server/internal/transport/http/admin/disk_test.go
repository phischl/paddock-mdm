package admin_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/pkg/escrow"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin/adminapi"
)

// diskEscrow stands in for OpenBao (escrow-wrap) and the bucket paddock-escrow.
type diskEscrow struct {
	key     *rsa.PrivateKey
	mu      sync.Mutex
	objects map[string][]byte
}

func newDiskEscrow(t *testing.T) *diskEscrow {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatal(err)
	}
	return &diskEscrow{key: key, objects: map[string][]byte{}}
}

func (d *diskEscrow) Decrypt(_ context.Context, version int, ciphertext string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil || version != 1 {
		return nil, errors.New("decrypt failed")
	}
	return rsa.DecryptOAEP(sha256.New(), nil, d.key, raw, nil)
}

func (d *diskEscrow) GetIfExists(_ context.Context, key string) ([]byte, bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	data, ok := d.objects[key]
	return data, ok, nil
}

// recoveryKey escrows a recovery key generation as the worker stores it.
func (e *env) recoveryKey(org, device uuid.UUID, generation int, key string) {
	e.t.Helper()
	ct, err := escrow.Encrypt(&e.disk.key.PublicKey, []byte(key))
	if err != nil {
		e.t.Fatal(err)
	}
	raw, _ := base64.StdEncoding.DecodeString(ct)
	if _, err := e.super.Exec(context.Background(), `INSERT INTO escrow_secret (id, organization_id, device_id, kind, generation, status,
		ciphertext, key_version) VALUES ($1, $2, $3, 'luks_recovery_key', $4, 'stored', $5, 1)`, uuid.New(), org, device, generation, raw); err != nil {
		e.t.Fatal(err)
	}
}

// header seals and stores a header generation with status.
func (e *env) header(org, device uuid.UUID, generation int, status string, header []byte) {
	e.t.Helper()
	id := uuid.New()
	sealed, err := escrow.SealHeader(&e.disk.key.PublicKey, header, id.String())
	if err != nil {
		e.t.Fatal(err)
	}
	key := escrow.HeaderObjectKey(org.String(), device.String(), int64(generation))
	e.disk.mu.Lock()
	e.disk.objects[key] = sealed.Object
	e.disk.mu.Unlock()
	wrapped, _ := base64.StdEncoding.DecodeString(sealed.WrappedDEK)
	nonce, _ := base64.StdEncoding.DecodeString(sealed.Nonce)
	if _, err := e.super.Exec(context.Background(), `INSERT INTO escrow_secret (id, organization_id, device_id, kind, generation, status,
		key_version, object_key, wrapped_dek, nonce, sha256, size) VALUES ($1, $2, $3, 'luks_header', $4, $5, 1, $6, $7, $8, $9, $10)`,
		id, org, device, generation, status, key, wrapped, nonce, sealed.SHA256, len(sealed.Object)); err != nil {
		e.t.Fatal(err)
	}
}

// TestDeviceDisk (plan M4b decision 14): the disk state comes from the last check-in, the keyslot change from the
// last tamper event, the generations from the escrow; recovery key and header need an organization administrator, a
// fresh step-up and the typed hostname, and are audited without the secret.
func TestDeviceDisk(t *testing.T) {
	e := newEnv(t)
	alice := e.session(e.acme, principal.RoleOrgAdmin)
	auditor := e.session(e.acme, principal.RoleOrgAuditor)
	carol := e.steppedUp(e.session(e.globex, principal.RoleOrgAdmin), time.Now())
	device := e.insertDevice(e.acme, "lt-disk", "active")
	path := "/api/v1/devices/" + device.String() + "/disk"

	var empty adminapi.DiskEncryption
	e.do(call{method: "GET", path: path, cookie: auditor}).decode(t, &empty)
	if empty.State != nil || len(empty.Headers) != 0 || empty.LastKeyslotChange != nil {
		t.Fatalf("before a check-in: %+v", empty)
	}
	health := `{"status":"ok","disk":{"state":"compliant","luks_version":2,"tokens":["recovery","tpm2+pin"],"keyslots":2}}`
	change := `{"disk":{"type":"tamper.keyslot_changed","occurred_at":"2026-10-06T10:00:00Z","params":{"before":["recovery","tpm2+pin"],"after":["password","recovery","tpm2+pin"]}}}`
	if _, err := e.super.Exec(context.Background(), `INSERT INTO device_status (device_id, organization_id, last_contact_at, health, login_state)
		VALUES ($1, $2, now(), $3, $4)`, device, e.acme, health, change); err != nil {
		t.Fatal(err)
	}
	header := bytes.Repeat([]byte("LUKS header "), 4096)
	e.recoveryKey(e.acme, device, 1, "old-key")
	e.recoveryKey(e.acme, device, 2, "recovery-key-2")
	e.header(e.acme, device, 1, "stored", []byte("old header"))
	e.header(e.acme, device, 2, "stored", header)
	e.header(e.acme, device, 3, "pending", []byte("not uploaded yet"))

	var disk adminapi.DiskEncryption
	e.do(call{method: "GET", path: path, cookie: auditor}).decode(t, &disk)
	if disk.State == nil || *disk.State != "compliant" || disk.Keyslots != 2 || strings.Join(disk.Tokens, ",") != "recovery,tpm2+pin" ||
		len(disk.RecoveryKeys) != 2 || disk.RecoveryKeys[0].Generation != 2 || len(disk.Headers) != 3 || disk.Headers[0].Status != "pending" ||
		disk.LastKeyslotChange == nil || strings.Join(disk.LastKeyslotChange.After, ",") != "password,recovery,tpm2+pin" {
		raw, _ := json.Marshal(disk)
		t.Fatalf("disk %s", raw)
	}
	var list adminapi.DevicePage
	e.do(call{method: "GET", path: "/api/v1/devices?disk_state=compliant&q=lt-disk", cookie: auditor}).decode(t, &list)
	if list.Total != 1 || list.Items[0].DiskState == nil || *list.Items[0].DiskState != "compliant" {
		t.Fatalf("filtered list %+v", list)
	}
	e.do(call{method: "GET", path: "/api/v1/devices?disk_state=tpm_pin_missing&q=lt-disk", cookie: auditor}).decode(t, &list)
	if list.Total != 0 {
		t.Fatalf("filter tpm_pin_missing found %d", list.Total)
	}

	body := map[string]any{"confirm_hostname": "lt-disk"}
	res := e.do(call{method: "POST", path: path + "/recovery-key", cookie: alice, body: body})
	if res.status != http.StatusForbidden || res.problemCode(t) != "step_up_required" {
		t.Fatalf("without step-up: %d %s", res.status, res.body)
	}
	e.expectEvent(res, "disk.recovery_key_revealed:denied:step_up_required")
	fresh := e.steppedUp(alice, time.Now())
	if r := e.do(call{method: "POST", path: path + "/recovery-key", cookie: fresh, body: map[string]any{"confirm_hostname": "x"}}); r.status != http.StatusBadRequest {
		t.Fatalf("wrong hostname: %d", r.status)
	}
	if r := e.do(call{method: "POST", path: path + "/recovery-key", cookie: carol, body: body}); r.status != http.StatusNotFound {
		t.Fatalf("another organization: %d", r.status)
	}
	res = e.do(call{method: "POST", path: path + "/recovery-key", cookie: fresh, body: body})
	var key adminapi.DiskRecoveryKey
	res.decode(t, &key)
	if res.status != http.StatusOK || key.Generation != 2 || key.RecoveryKey != "recovery-key-2" {
		t.Fatalf("recovery key: %d %s", res.status, res.body)
	}
	e.expectEvent(res, "disk.recovery_key_revealed:success:")
	e.expectNoSecret(res, "recovery-key-2")

	res = e.do(call{method: "POST", path: path + "/header", cookie: fresh, body: body})
	if res.status != http.StatusOK || !bytes.Equal(res.body, header) || res.header.Get("Content-Type") != "application/octet-stream" ||
		res.header.Get("Content-Disposition") != `attachment; filename=lt-disk-luks-header-2.img` {
		t.Fatalf("header: %d %v %d bytes", res.status, res.header, len(res.body))
	}
	e.expectEvent(res, "disk.header_downloaded:success:")
	res = e.do(call{method: "POST", path: path + "/header", cookie: fresh, body: map[string]any{"confirm_hostname": "lt-disk", "generation": 1}})
	if res.status != http.StatusOK || string(res.body) != "old header" {
		t.Fatalf("header generation 1: %d %s", res.status, res.body)
	}
	if r := e.do(call{method: "POST", path: path + "/header", cookie: fresh, body: map[string]any{"confirm_hostname": "lt-disk", "generation": 3}}); r.status != http.StatusConflict {
		t.Fatalf("pending header: %d", r.status)
	}
	if r := e.do(call{method: "POST", path: path + "/header", cookie: e.steppedUp(auditor, time.Now()), body: body}); r.status != http.StatusForbidden {
		t.Fatalf("auditor: %d", r.status)
	}
}

// expectNoSecret fails if secret appears in the action rows of a request.
func (e *env) expectNoSecret(r result, secret string) {
	e.t.Helper()
	var n int
	if err := e.super.QueryRow(context.Background(), "SELECT count(*) FROM action WHERE correlation_id = $1 AND (params::text LIKE '%' || $2 || '%' OR target::text LIKE '%' || $2 || '%')",
		r.header.Get("X-Request-Id"), secret).Scan(&n); err != nil || n != 0 {
		e.t.Fatalf("secret in %d action rows (%v)", n, err)
	}
}
