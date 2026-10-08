package admin_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
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

// diskEscrow is the escrow-wrap key of the disk escrows and stands in for the bucket paddock-escrow.
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

// header seals and stores a header generation with status (of the root volume, before PDK-009: no volume).
func (e *env) header(org, device uuid.UUID, generation int, status string, header []byte) {
	e.t.Helper()
	e.volumeHeader(org, device, "", generation, status, header)
}

// volumeHeader seals and stores a header generation of volume ("" none) with status.
func (e *env) volumeHeader(org, device uuid.UUID, volume string, generation int, status string, header []byte) {
	e.t.Helper()
	id := uuid.New()
	sealed, err := escrow.SealHeader(&e.disk.key.PublicKey, header, id.String())
	if err != nil {
		e.t.Fatal(err)
	}
	key := escrow.HeaderObjectKey(org.String(), device.String(), volume, int64(generation))
	var vol *string
	if volume != "" {
		vol = &volume
	}
	e.disk.mu.Lock()
	e.disk.objects[key] = sealed.Object
	e.disk.mu.Unlock()
	wrapped, _ := base64.StdEncoding.DecodeString(sealed.WrappedDEK)
	nonce, _ := base64.StdEncoding.DecodeString(sealed.Nonce)
	if _, err := e.super.Exec(context.Background(), `INSERT INTO escrow_secret (id, organization_id, device_id, kind, generation, status,
		key_version, object_key, wrapped_dek, nonce, sha256, size, volume) VALUES ($1, $2, $3, 'luks_header', $4, $5, 1, $6, $7, $8, $9, $10, $11)`,
		id, org, device, generation, status, key, wrapped, nonce, sealed.SHA256, len(sealed.Object), vol); err != nil {
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

// TestDeviceDiskVolumes (PDK-009 decisions 1 and 5): the disk card lists every volume the device reports and the
// header generations of each; a download is per volume, the root volume's by default — including its headers
// escrowed before PDK-009 without a volume —, and audited with the volume.
func TestDeviceDiskVolumes(t *testing.T) {
	e := newEnv(t)
	alice := e.steppedUp(e.session(e.acme, principal.RoleOrgAdmin), time.Now())
	device := e.insertDevice(e.acme, "lt-vols", "active")
	path := "/api/v1/devices/" + device.String() + "/disk"
	const root, data = "0d8f4c62-0000-4000-8000-0000000000aa", "0d8f4c62-0000-4000-8000-0000000000bb"
	health := `{"disk":{"state":"compliant","luks_version":2,"tokens":["recovery","tpm2+pin"],"keyslots":2,"volumes":[` +
		`{"uuid":"` + root + `","device":"/dev/sda3","root":true,"luks_version":2,"tokens":["recovery","tpm2+pin"],"keyslots":2,"escrowed":true,"header_generation":2},` +
		`{"uuid":"` + data + `","device":"/dev/sdb1","luks_version":2,"tokens":["password"],"keyslots":1,"escrowed":true,"header_generation":3}],` +
		`"unresolved":["LABEL=backup"]}}`
	if _, err := e.super.Exec(context.Background(), `INSERT INTO device_status (device_id, organization_id, last_contact_at, health)
		VALUES ($1, $2, now(), $3)`, device, e.acme, health); err != nil {
		t.Fatal(err)
	}
	e.header(e.acme, device, 1, "stored", []byte("legacy root header"))
	e.volumeHeader(e.acme, device, data, 3, "stored", []byte("data header"))

	var disk adminapi.DiskEncryption
	e.do(call{method: "GET", path: path, cookie: alice}).decode(t, &disk)
	if len(disk.Volumes) != 2 || !disk.Volumes[0].Root || disk.Volumes[1].Uuid == nil || *disk.Volumes[1].Uuid != data ||
		disk.Volumes[1].Device != "/dev/sdb1" || !disk.Volumes[1].Escrowed || strings.Join(disk.Unresolved, ",") != "LABEL=backup" ||
		len(disk.Headers) != 2 || disk.Headers[0].Volume == nil || disk.Headers[0].Volume.String() != data || disk.Headers[1].Volume != nil {
		raw, _ := json.Marshal(disk)
		t.Fatalf("disk %s", raw)
	}

	// The root volume by default: its only header is the one without a volume.
	body := map[string]any{"confirm_hostname": "lt-vols"}
	res := e.do(call{method: "POST", path: path + "/header", cookie: alice, body: body})
	if res.status != http.StatusOK || string(res.body) != "legacy root header" ||
		res.header.Get("Content-Disposition") != `attachment; filename=lt-vols-luks-header-1.img` {
		t.Fatalf("root header: %d %s %v", res.status, res.body, res.header)
	}
	e.volumeHeader(e.acme, device, root, 2, "stored", []byte("root header 2"))
	res = e.do(call{method: "POST", path: path + "/header", cookie: alice, body: map[string]any{"confirm_hostname": "lt-vols", "volume": root}})
	if res.status != http.StatusOK || string(res.body) != "root header 2" {
		t.Fatalf("root header by volume: %d %s", res.status, res.body)
	}
	res = e.do(call{method: "POST", path: path + "/header", cookie: alice, body: map[string]any{"confirm_hostname": "lt-vols", "volume": data}})
	if res.status != http.StatusOK || string(res.body) != "data header" ||
		res.header.Get("Content-Disposition") != `attachment; filename=lt-vols-luks-header-`+data+`-3.img` {
		t.Fatalf("data header: %d %s %v", res.status, res.body, res.header)
	}
	e.expectEvent(res, "disk.header_downloaded:success:")
	var param string
	if err := e.super.QueryRow(context.Background(), "SELECT params->>'volume' FROM action WHERE correlation_id = $1",
		res.header.Get("X-Request-Id")).Scan(&param); err != nil || param != data {
		t.Fatalf("audit volume %q: %v", param, err)
	}
	// A generation of another volume, and a volume without headers, are not this volume's.
	for _, b := range []map[string]any{
		{"confirm_hostname": "lt-vols", "volume": data, "generation": 1},
		{"confirm_hostname": "lt-vols", "volume": "0d8f4c62-0000-4000-8000-0000000000cc"},
	} {
		if r := e.do(call{method: "POST", path: path + "/header", cookie: alice, body: b}); r.status != http.StatusConflict {
			t.Fatalf("%v: %d %s", b, r.status, r.body)
		}
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
