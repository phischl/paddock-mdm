package escrowreader_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/domain/organization"
	"github.com/phischl/paddock-mdm/server/internal/escrowreader"
	"github.com/phischl/paddock-mdm/server/internal/platform/bao"
	"github.com/phischl/paddock-mdm/server/internal/recoveryexport"
)

const exportPassphrase = "a passphrase of the requester"

// pending makes the deletion of organization i pending.
func (w *world) pending(i int) {
	w.exec(`UPDATE organization SET deletion_requested_at = now(), delete_after = now() + interval '30 days' WHERE id = $1`, w.orgs[i])
}

func (w *world) call(i int, scope, token string) app.RecoveryExportCall {
	return app.RecoveryExportCall{OrganizationID: w.orgs[i], Slug: "er-" + w.orgs[i].String()[:8],
		ExportedAt: time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC), Scope: scope, StepUpIDToken: token,
		LocalAdminUsername: "paddock-admin", Recipient: recoveryexport.RecipientPassphrase, Passphrase: exportPassphrase}
}

// export runs an export and returns the message, the counts and whether open was called.
func (w *world) export(call app.RecoveryExportCall) ([]byte, app.RecoveryExportCounts, bool, error) {
	var out bytes.Buffer
	opened := false
	counts, err := w.client.Export(context.Background(), call, func(app.RecoveryExportCounts) io.Writer {
		opened = true
		return &out
	})
	return out.Bytes(), counts, opened, err
}

func openExport(t *testing.T, msg []byte, keys openpgp.EntityList) []map[string]any {
	t.Helper()
	block, err := armor.Decode(bytes.NewReader(msg))
	if err != nil {
		t.Fatalf("armour: %v\n%s", err, msg)
	}
	md, err := openpgp.ReadMessage(block.Body, keys, func([]openpgp.Key, bool) ([]byte, error) {
		return []byte(exportPassphrase), nil
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := io.ReadAll(md.UnverifiedBody)
	if err != nil {
		t.Fatal(err)
	}
	var lines []map[string]any
	sc := bufio.NewScanner(bytes.NewReader(plain))
	for sc.Scan() {
		var m map[string]any
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			t.Fatalf("line %s: %v", sc.Bytes(), err)
		}
		lines = append(lines, m)
	}
	return lines
}

// TestExport: the escrow-reader exports exactly the non-retired devices with escrow of a pending organization, the
// newest recovery key per volume and the newest local administrator password, for an organization administrator or
// a platform administrator, counting one use of the step-up token; nothing of the secrets reaches a log.
func TestExport(t *testing.T) {
	var logs bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	w := newWorld(t)
	w.pending(0)
	// A retired device with escrow and an active device without escrow are left out.
	retired := uuid.New()
	w.exec(`INSERT INTO device (id, organization_id, hostname, state) VALUES ($1, $2, 'retired-host', 'retired')`, retired, w.orgs[0])
	w.exec(`INSERT INTO escrow_secret (id, organization_id, device_id, kind, generation, status, ciphertext, key_version)
		VALUES ($1, $2, $3, 'luks_recovery_key', 1, 'stored', 'retired-ct', 1)`, uuid.New(), w.orgs[0], retired)
	w.exec(`INSERT INTO device (id, organization_id, hostname, state) VALUES ($1, $2, 'bare-host', 'active')`, uuid.New(), w.orgs[0])
	// An older recovery key and an older, superseded password of the exported device.
	w.exec(`UPDATE escrow_secret SET generation = 2 WHERE id = ANY($1)`, []uuid.UUID{w.recovery[0], w.passwords[0]})
	w.exec(`INSERT INTO escrow_secret (id, organization_id, device_id, kind, generation, status, ciphertext, key_version)
		VALUES ($1, $2, $3, 'luks_recovery_key', 1, 'stored', 'old-key', 1), ($4, $2, $3, 'admin_password', 1, 'superseded', 'old-pw', 1)`,
		uuid.New(), w.orgs[0], w.devices[0], uuid.New())

	msg, counts, opened, err := w.export(w.call(0, app.RequesterOrganization, w.token(0, "org_admin")))
	if err != nil || !opened || counts != (app.RecoveryExportCounts{Devices: 1, Secrets: 2}) {
		t.Fatalf("export: %v opened %v counts %+v", err, opened, counts)
	}
	if bytes.Contains(msg, []byte("plain-")) || !bytes.HasSuffix(bytes.TrimSpace(msg), []byte("-----END PGP MESSAGE-----")) {
		t.Fatalf("not a complete encrypted message:\n%s", msg)
	}
	lines := openExport(t, msg, nil)
	if len(lines) != 2 || lines[0]["organization_id"] != w.orgs[0].String() || lines[0]["devices"] != float64(1) ||
		lines[0]["exported_at"] != "2026-11-14T12:00:00Z" {
		t.Fatalf("lines: %v", lines)
	}
	dev := lines[1]
	volumes, _ := dev["volumes"].([]any)
	admin, _ := dev["local_admin"].(map[string]any)
	if dev["device_id"] != w.devices[0].String() || dev["hostname"] != "host" || len(volumes) != 1 || admin == nil ||
		volumes[0].(map[string]any)["recovery_key"] != "plain-ct-luks_recovery_key" ||
		volumes[0].(map[string]any)["uuid"] != "" ||
		admin["username"] != "paddock-admin" || admin["password"] != "plain-ct-admin_password" {
		t.Fatalf("device line: %v", dev)
	}
	if w.proofs.uses["jti-"+w.token(0, "org_admin")] != 1 {
		t.Fatalf("uses: %v", w.proofs.uses)
	}
	if len(w.batches) != 1 || w.batches[0] != 2 {
		t.Fatalf("batches: %v", w.batches)
	}

	// A platform administrator, proven by the signed groups of its token.
	platformToken := w.token(0, "platform_admin")
	w.proofs.groups[platformToken] = []string{organization.PlatformAdminsGroup()}
	e, armored := newRecipientKey(t)
	call := w.call(0, app.RequesterPlatform, platformToken)
	call.Recipient, call.PublicKey, call.Passphrase = recoveryexport.RecipientPublicKey, armored, ""
	msg, _, _, err = w.export(call)
	if err != nil {
		t.Fatalf("platform export: %v", err)
	}
	if lines := openExport(t, msg, openpgp.EntityList{e}); len(lines) != 2 {
		t.Fatalf("platform lines: %v", lines)
	}

	for _, secret := range []string{"plain-", "ct-admin_password", exportPassphrase, w.token(0, "org_admin")} {
		if strings.Contains(logs.String(), secret) {
			t.Fatalf("a log line contains %q:\n%s", secret, logs.String())
		}
	}
}

func newRecipientKey(t *testing.T) (*openpgp.Entity, string) {
	t.Helper()
	e, err := openpgp.NewEntity("Requester", "", "requester@example.test", &packet.Config{Algorithm: packet.PubKeyAlgoEdDSA})
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	aw, err := armor.Encode(&buf, openpgp.PublicKeyType, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Serialize(aw); err != nil {
		t.Fatal(err)
	}
	_ = aw.Close()
	return e, buf.String()
}

// TestExportRefusals: no export for another role, a disabled administrator, an administrator of another organization,
// a platform token without the platform group, an organization without a pending deletion, or an exhausted token;
// open is never called and nothing is decrypted.
func TestExportRefusals(t *testing.T) {
	w := newWorld(t)
	w.pending(0)
	for name, tc := range map[string]struct {
		call app.RecoveryExportCall
		want error
	}{
		"operator":            {w.call(0, app.RequesterOrganization, w.token(0, "org_operator")), app.ErrEscrowRefused},
		"auditor":             {w.call(0, app.RequesterOrganization, w.token(0, "org_auditor")), app.ErrEscrowRefused},
		"disabled admin":      {w.call(0, app.RequesterOrganization, w.token(0, "disabled")), app.ErrEscrowRefused},
		"other org's admin":   {w.call(0, app.RequesterOrganization, w.token(1, "org_admin")), app.ErrEscrowRefused},
		"platform no group":   {w.call(0, app.RequesterPlatform, w.token(0, "platform_admin")), app.ErrEscrowRefused},
		"admin as platform":   {w.call(0, app.RequesterPlatform, w.token(0, "org_admin")), app.ErrEscrowRefused},
		"unknown token":       {w.call(0, app.RequesterOrganization, "forged"), app.ErrEscrowRefused},
		"not pending":         {w.call(1, app.RequesterOrganization, w.token(1, "org_admin")), app.ErrEscrowNotPending},
		"platform no pending": {w.call(1, app.RequesterPlatform, w.platformToken(1)), app.ErrEscrowNotPending},
	} {
		_, _, opened, err := w.export(tc.call)
		if !errors.Is(err, tc.want) || opened {
			t.Errorf("%s: %v opened %v, want %v", name, err, opened, tc.want)
		}
	}
	tok := w.token(0, "org_admin")
	for range 5 {
		if _, _, _, err := w.export(w.call(0, app.RequesterOrganization, tok)); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, opened, err := w.export(w.call(0, app.RequesterOrganization, tok)); !errors.Is(err, app.ErrEscrowRefused) || opened {
		t.Fatalf("sixth use of a token: %v", err)
	}
	// Five exports of one device with two secrets each; the refused sixth decrypted nothing.
	if len(w.used) != 10 {
		t.Fatalf("decryptions: %v", w.used)
	}
	bad := w.call(0, app.RequesterOrganization, w.token(0, "org_admin"))
	bad.Passphrase = "too short"
	if _, _, opened, err := w.export(bad); err == nil || opened {
		t.Fatalf("short passphrase: %v", err)
	}
	wrong := escrowreader.NewClient(w.srv.URL, "another secret")
	if _, err := wrong.Export(context.Background(), w.call(0, app.RequesterOrganization, w.token(0, "org_admin")),
		func(app.RecoveryExportCounts) io.Writer { t.Fatal("opened without the secret"); return nil }); err == nil {
		t.Fatal("export with another secret")
	}
}

func (w *world) platformToken(i int) string {
	tok := w.token(i, "platform_admin")
	w.proofs.groups[tok] = []string{organization.PlatformAdminsGroup()}
	return tok
}

// TestExportBatches: the secrets are decrypted in Transit batches of at most bao.MaxBatch, never one device split
// across two batches; the export streams from memory and writes no file (decision 24): the temporary directory is
// read-only and stays empty.
func TestExportBatches(t *testing.T) {
	tmp := t.TempDir()
	if err := os.Chmod(tmp, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(tmp, 0o700) })
	t.Setenv("TMPDIR", tmp)
	w := newWorld(t)
	w.pending(0)
	for range 130 {
		d := uuid.New()
		w.exec(`INSERT INTO device (id, organization_id, hostname, state) VALUES ($1, $2, $3, 'active')`, d, w.orgs[0], "h-"+d.String())
		w.exec(`INSERT INTO escrow_secret (id, organization_id, device_id, kind, generation, status, ciphertext, key_version)
			VALUES ($1, $2, $3, 'luks_recovery_key', 1, 'stored', 'k', 1), ($4, $2, $3, 'admin_password', 1, 'active', 'p', 1)`,
			uuid.New(), w.orgs[0], d, uuid.New())
	}
	msg, counts, _, err := w.export(w.call(0, app.RequesterOrganization, w.token(0, "org_admin")))
	if err != nil || counts.Devices != 131 || counts.Secrets != 262 {
		t.Fatalf("export: %v %+v", err, counts)
	}
	total := 0
	for _, n := range w.batches {
		if n > bao.MaxBatch || n%2 != 0 {
			t.Fatalf("batches: %v", w.batches)
		}
		total += n
	}
	if total != 262 || len(w.batches) < 2 {
		t.Fatalf("batches: %v", w.batches)
	}
	if lines := openExport(t, msg, nil); len(lines) != 132 {
		t.Fatalf("lines: %d", len(lines))
	}
	if entries, err := os.ReadDir(tmp); err != nil || len(entries) != 0 {
		t.Fatalf("files written during the export: %v %v", entries, err)
	}
}

// TestExportBodyMAC: an answer whose headers carry a valid MAC but whose body does not is refused, and the message
// handed on is never complete: its end stays held back.
func TestExportBodyMAC(t *testing.T) {
	body := "-----BEGIN PGP MESSAGE-----\n\n" + strings.Repeat("A", 4000) + "\n-----END PGP MESSAGE-----\n"
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		var req struct {
			Nonce string `json:"nonce"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		m := hmac.New(sha256.New, []byte(secret))
		m.Write([]byte("recovery-export\n" + req.Nonce + "\n" + strconv.Itoa(1) + "\n" + strconv.Itoa(2)))
		rw.Header().Set("Trailer", "X-Paddock-Escrow-Reader-Body-Mac")
		rw.Header().Set("X-Paddock-Export-Devices", "1")
		rw.Header().Set("X-Paddock-Export-Secrets", "2")
		rw.Header().Set("X-Paddock-Escrow-Reader-Mac", base64.StdEncoding.EncodeToString(m.Sum(nil)))
		_, _ = io.WriteString(rw, body)
		rw.Header().Set("X-Paddock-Escrow-Reader-Body-Mac", "forged")
	}))
	t.Cleanup(srv.Close)
	var out bytes.Buffer
	_, err := escrowreader.NewClient(srv.URL, secret).Export(context.Background(), app.RecoveryExportCall{},
		func(app.RecoveryExportCounts) io.Writer { return &out })
	if err == nil || strings.Contains(out.String(), "END PGP MESSAGE") || out.Len() != len(body)-1024 {
		t.Fatalf("forged body: %v, %d of %d bytes handed on", err, out.Len(), len(body))
	}
}

// slowKeys is plainKeys that takes delay per Transit batch.
type slowKeys struct {
	plainKeys
	delay time.Duration
}

func (k slowKeys) DecryptBatch(ctx context.Context, items []bao.VersionedCiphertext) ([][]byte, error) {
	time.Sleep(k.delay)
	return k.plainKeys.DecryptBatch(ctx, items)
}

// TestExportOutlastsWriteTimeout (review 1 finding 2): an export that streams longer than the server's write timeout
// still arrives complete, because the escrow-reader extends its write deadline for the export.
func TestExportOutlastsWriteTimeout(t *testing.T) {
	w := newWorld(t)
	w.pending(0)
	for range 260 {
		d := uuid.New()
		w.exec(`INSERT INTO device (id, organization_id, hostname, state) VALUES ($1, $2, $3, 'active')`, d, w.orgs[0], "s-"+d.String())
		w.exec(`INSERT INTO escrow_secret (id, organization_id, device_id, kind, generation, status, ciphertext, key_version)
			VALUES ($1, $2, $3, 'luks_recovery_key', 1, 'stored', 'k', 1)`, uuid.New(), w.orgs[0], d)
	}
	var used, batches []int
	srv := httptest.NewUnstartedServer(escrowreader.NewService(secret, w.pool, w.proofs, w.proofs,
		slowKeys{plainKeys{&used, &batches}, 400 * time.Millisecond}).Handler())
	srv.Config.WriteTimeout = 300 * time.Millisecond
	srv.Start()
	t.Cleanup(srv.Close)
	var out bytes.Buffer
	counts, err := escrowreader.NewClient(srv.URL, secret).Export(context.Background(),
		w.call(0, app.RequesterOrganization, w.token(0, "org_admin")), func(app.RecoveryExportCounts) io.Writer { return &out })
	if err != nil || counts.Devices != 261 || len(batches) < 2 {
		t.Fatalf("slow export: %v %+v, %d batches", err, counts, len(batches))
	}
	if lines := openExport(t, out.Bytes(), nil); len(lines) != 262 {
		t.Fatalf("lines: %d", len(lines))
	}
}
