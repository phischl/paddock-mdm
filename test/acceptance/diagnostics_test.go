package acceptance

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/pkg/bundle"
	"github.com/phischl/paddock-mdm/pkg/command"
	"github.com/phischl/paddock-mdm/pkg/dsse"
	"github.com/phischl/paddock-mdm/pkg/escrow"
	"github.com/phischl/paddock-mdm/pkg/protocol"
	"github.com/phischl/paddock-mdm/test/acceptance/devicesim"
	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
)

// diagnosticsBundle is the part of GET /api/v1/diagnostics/{id} the gates read.
type diagnosticsBundle struct {
	ID               string  `json:"id"`
	DeviceID         string  `json:"device_id"`
	State            string  `json:"state"`
	Reason           string  `json:"reason"`
	Size             *int64  `json:"size"`
	SHA256           *string `json:"sha256"`
	Files            *int    `json:"files"`
	NotifiedSessions *int    `json:"notified_sessions"`
	FailedReason     *string `json:"failed_reason"`
}

// diagnosticsDevice is an active device of p's organization that applied a bundle with the escrow-wrap key, which
// seals a diagnostics bundle.
func diagnosticsDevice(t *testing.T, p *env.Portal) (*devicesim.Device, *bundle.Bundle) {
	t.Helper()
	d := v2Device(t, p, "", 1, 2)
	return d, latestBundle(t, d, time.Minute, func(b *bundle.Bundle) bool { return b.Keys != nil && b.Keys.EscrowWrap != nil })
}

// getDiagnostics reads a bundle as p.
func getDiagnostics(t *testing.T, p *env.Portal, id string) diagnosticsBundle {
	t.Helper()
	res := call(t, p, http.MethodGet, "/api/v1/diagnostics/"+id, nil)
	expectStatus(t, res, http.StatusOK, "")
	var b diagnosticsBundle
	if err := res.JSON(&b); err != nil {
		t.Fatal(err)
	}
	return b
}

// waitDiagnostics polls a bundle every second until cond holds.
func waitDiagnostics(t *testing.T, p *env.Portal, id string, timeout time.Duration, cond func(diagnosticsBundle) bool) diagnosticsBundle {
	t.Helper()
	for deadline := time.Now().Add(timeout); ; time.Sleep(time.Second) {
		// The deadline is checked against the poll's start, as in expectOneEvent (PDK-551, PDK-561).
		polled := time.Now()
		b := getDiagnostics(t, p, id)
		if cond(b) {
			return b
		}
		if polled.After(deadline) {
			t.Fatalf("diagnostics bundle %s: condition not met within %s, last %+v", id, timeout, b)
		}
	}
}

// diagnosticsArchive is a tar.gz that holds only a manifest naming the bundle, a stand-in for the agent's archive.
func diagnosticsArchive(t *testing.T, id string) (archive, manifest []byte) {
	t.Helper()
	manifest, _ = json.Marshal(map[string]any{"schema": "paddock.diagnostics.v1", "request_id": id, "entries": []any{}})
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	if err := tw.WriteHeader(&tar.Header{Name: "manifest.json", Mode: 0o600, Size: int64(len(manifest)), Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(manifest); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes(), manifest
}

// archiveFile returns the named file of a tar.gz.
func archiveFile(t *testing.T, archive []byte, name string) []byte {
	t.Helper()
	zr, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(zr)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			t.Fatalf("archive has no %s", name)
		}
		if err != nil {
			t.Fatal(err)
		}
		if h.Name == name {
			data, err := io.ReadAll(tr)
			if err != nil {
				t.Fatal(err)
			}
			return data
		}
	}
}

// awaitCollectStatus checks in until the device receives the collect_status command of bundle id (the bundle ID is the
// command ID).
func awaitCollectStatus(t *testing.T, d *devicesim.Device, id string) {
	t.Helper()
	checkinUntil(t, d, 2*time.Minute, func(out protocol.CheckinResponse) bool {
		for _, raw := range out.Commands {
			_, payload, err := dsse.Decode(raw)
			if err != nil {
				continue
			}
			var c command.Command
			if json.Unmarshal(payload, &c) == nil && c.Type == command.TypeCollectStatus && c.CommandID == id {
				return true
			}
		}
		return false
	})
}

// sealedDiagnostics is a sealed archive announced to the gateway.
type sealedDiagnostics struct {
	object    []byte
	sha256    string // hex SHA-256 of object
	uploadURL string
}

// objectKey is the escrow-bucket key the presigned URL writes.
func (s sealedDiagnostics) objectKey(t *testing.T) string {
	t.Helper()
	u, err := url.Parse(s.uploadURL)
	if err != nil {
		t.Fatal(err)
	}
	key, ok := strings.CutPrefix(u.Path, "/paddock-escrow/")
	if !ok || !strings.Contains(key, "/diagnostics/") {
		t.Fatalf("upload URL %s is not below diagnostics/ of the escrow bucket", s.uploadURL)
	}
	return key
}

// announceDiagnostics seals archive as the agent does (ADR 0048 decision 3: a random key wrapped to the bundle's
// escrow-wrap key, the bundle ID as additional data) and announces it with the sealed size plus sizeDelta.
func announceDiagnostics(t *testing.T, d *devicesim.Device, b *bundle.Bundle, id string, archive []byte, sizeDelta int64) sealedDiagnostics {
	t.Helper()
	pub, version := escrowWrap(t, b)
	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		t.Fatal(err)
	}
	object, nonce, err := escrow.SealObject(dek, id, bytes.NewReader(archive))
	if err != nil {
		t.Fatal(err)
	}
	wrapped, err := escrow.Encrypt(pub, dek)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(object)
	s := sealedDiagnostics{object: object, sha256: hex.EncodeToString(sum[:])}
	res, err := d.Do(testContext(t, time.Minute), devicesim.Request{Method: http.MethodPost, Path: "/v1/diagnostics", Body: protocol.DiagnosticsRequest{
		CommandID: id, SHA256: s.sha256, Size: int64(len(object)) + sizeDelta,
		Nonce: base64.StdEncoding.EncodeToString(nonce), WrappedDEK: wrapped, KeyVersion: version,
	}})
	var answer protocol.DiagnosticsResponse
	if err != nil || res.Status != http.StatusAccepted || json.Unmarshal(res.Body, &answer) != nil || answer.UploadURL == "" {
		t.Fatalf("announce: %v HTTP %d %s", err, res.Status, res.Body)
	}
	s.uploadURL = answer.UploadURL
	return s
}

// reportDiagnostics posts the device's successful collect_status result.
func reportDiagnostics(t *testing.T, d *devicesim.Device, id string, archive []byte) {
	t.Helper()
	result, _ := json.Marshal(command.CollectStatusResult{Uploaded: true, Files: 1, Bytes: int64(len(archive))})
	if res, err := d.CommandResult(testContext(t, time.Minute), id, protocol.CommandSucceeded, result); err != nil || res.Status != http.StatusAccepted {
		t.Fatalf("result: %v HTTP %d %s", err, res.Status, res.Body)
	}
}

// uploadDiagnostics answers the collect_status command of bundle id like an agent: it seals archive, announces and
// uploads it and reports the result.
func uploadDiagnostics(t *testing.T, d *devicesim.Device, b *bundle.Bundle, id string, archive []byte) sealedDiagnostics {
	t.Helper()
	awaitCollectStatus(t, d, id)
	s := announceDiagnostics(t, d, b, id, archive, 0)
	if status, err := d.Upload(testContext(t, time.Minute), s.uploadURL, s.object); err != nil || status != http.StatusOK {
		t.Fatalf("upload: %v HTTP %d", err, status)
	}
	reportDiagnostics(t, d, id, archive)
	return s
}

// keepDiagnostics moves the end of a stored bundle's retention an hour ahead: the development stack counts retention
// days in seconds, so a stored bundle would be deleted about 7 s after the worker stored it, before the gate downloads
// it. The retention itself is gate D2.
func keepDiagnostics(t *testing.T, id string) {
	t.Helper()
	if got := paddockSQL(t, `WITH u AS (UPDATE device_diagnostics SET expires_at = now() + interval '1 hour'
		WHERE id = '`+id+`' AND state = 'stored' RETURNING id) SELECT id FROM u`); got != id {
		t.Fatalf("bundle %s was not stored any more when its retention was extended (%q)", id, got)
	}
}

// diagnosticsObjectGone fails unless the escrow bucket holds no version of key (listed with the api's credential,
// which lists below diagnostics/ only).
func diagnosticsObjectGone(t *testing.T, key string) {
	t.Helper()
	out, err := escrowAPICall(t, "list-object-versions", "--bucket", "paddock-escrow", "--prefix", key)
	if err != nil {
		t.Fatalf("list %s: %v %s", key, err, out)
	}
	if strings.Contains(out, `"Key"`) {
		t.Fatalf("the escrow bucket still holds %s: %s", key, out)
	}
}

// TestDiagnosticsFlow is gate D1 of plan M12 (ADR 0048): an API token of an operator requests a bundle with a reason
// (202) and a second request while it is pending is refused (409); the device receives collect_status, announces a
// sealed archive, uploads it and reports; the worker stores it with its files and hash, and both events are recorded;
// an operator's download needs a step-up and then returns the archive and records its hash; an API token never
// downloads, an auditor gets 403 on every endpoint, an operator cannot purge; an organization
// administrator's API token purges, which deletes the object and the download then answers 409; an object of another size than announced fails the bundle with
// size_mismatch.
func TestDiagnosticsFlow(t *testing.T) {
	alice, bob := login(t, env.Alice), login(t, env.Bob)
	operator := mfaTempUser(t, "diag-operator", env.RoleGroup("acme", "operators"))
	token := tokenPortal(t, createAPIToken(t, alice, env.Alice, "org_operator").Secret)
	d, b := diagnosticsDevice(t, alice)
	hostname := getDevice(t, alice, d.DeviceID).Hostname

	reason := "D1 logins fail since Monday " + uniqueSuffix()
	res := requestDiagnostics(t, token, d.DeviceID, reason)
	expectStatus(t, res, http.StatusAccepted, "")
	var requested diagnosticsBundle
	if err := res.JSON(&requested); err != nil || requested.State != "requested" || requested.Reason != reason || requested.DeviceID != d.DeviceID {
		t.Fatalf("requested bundle %+v (%v)", requested, err)
	}
	id := requested.ID
	if ev := expectOneEvent(t, alice, res.RequestID, "device.diagnostics_requested", "success"); ev.Params["reason"] != reason {
		t.Fatalf("device.diagnostics_requested params %v", ev.Params)
	}
	expectStatus(t, requestDiagnostics(t, alice, d.DeviceID, "a second request"), http.StatusConflict, "invalid_state")

	base := "/api/v1/diagnostics/" + id
	t.Run("auditor", func(t *testing.T) {
		for _, r := range []struct {
			method, path string
			body         any
		}{
			{http.MethodPost, "/api/v1/devices/" + d.DeviceID + "/diagnostics", map[string]string{"reason": "auditor"}},
			{http.MethodGet, "/api/v1/devices/" + d.DeviceID + "/diagnostics", nil},
			{http.MethodGet, "/api/v1/diagnostics", nil},
			{http.MethodGet, base, nil},
			{http.MethodGet, base + "/download", nil},
			{http.MethodPost, base + "/purge", nil},
		} {
			res := call(t, bob, r.method, r.path, r.body)
			expectStatus(t, res, http.StatusForbidden, "forbidden")
			if strings.Contains(string(res.Body), reason) {
				t.Fatalf("%s %s shows the auditor the bundle: %s", r.method, r.path, res.Body)
			}
		}
	})

	archive, manifest := diagnosticsArchive(t, id)
	sealed := uploadDiagnostics(t, d, b, id, archive)
	stored := waitDiagnostics(t, alice, id, 2*time.Minute, func(b diagnosticsBundle) bool { return b.State != "requested" && b.State != "uploaded" })
	if stored.State != "stored" {
		t.Fatalf("bundle %+v, want stored", stored)
	}
	keepDiagnostics(t, id)
	if stored.SHA256 == nil || *stored.SHA256 != sealed.sha256 || stored.Size == nil || *stored.Size != int64(len(sealed.object)) ||
		stored.Files == nil || *stored.Files != 1 {
		t.Fatalf("stored bundle %+v, want sha256 %s, size %d, 1 file", stored, sealed.sha256, len(sealed.object))
	}
	for deadline := time.Now().Add(time.Minute); eventCount(t, alice, "device.diagnostics_collected", d.DeviceID) != 1; time.Sleep(time.Second) {
		if time.Now().After(deadline) {
			t.Fatal("no single device.diagnostics_collected event of the device")
		}
	}

	t.Run("api token", func(t *testing.T) {
		res := call(t, token, http.MethodGet, "/api/v1/devices/"+d.DeviceID+"/diagnostics", nil)
		expectStatus(t, res, http.StatusOK, "")
		if !strings.Contains(string(res.Body), id) {
			t.Fatalf("the token's list lacks bundle %s: %s", id, res.Body)
		}
		expectStatus(t, call(t, token, http.MethodGet, base+"/download", nil), http.StatusForbidden, "step_up_required")
	})

	res = call(t, operator.Portal, http.MethodGet, base+"/download", nil)
	expectStatus(t, res, http.StatusForbidden, "step_up_required")
	expectOneEvent(t, alice, res.RequestID, "device.diagnostics_downloaded", "denied")
	expectStatus(t, call(t, operator.Portal, http.MethodPost, base+"/purge", nil), http.StatusForbidden, "forbidden")

	operator.stepUp(t)
	res = call(t, operator.Portal, http.MethodGet, base+"/download", nil)
	expectStatus(t, res, http.StatusOK, "")
	if !strings.Contains(res.Header.Get("Content-Disposition"), "paddock-diagnostics-"+hostname+"-"+id+".tar.gz") {
		t.Fatalf("Content-Disposition %q", res.Header.Get("Content-Disposition"))
	}
	if !bytes.Equal(res.Body, archive) || !bytes.Equal(archiveFile(t, res.Body, "manifest.json"), manifest) {
		t.Fatalf("downloaded %d bytes, want the sealed archive of %d bytes", len(res.Body), len(archive))
	}
	ev := expectOneEvent(t, alice, res.RequestID, "device.diagnostics_downloaded", "success")
	if ev.Params["sha256"] != sealed.sha256 {
		t.Fatalf("device.diagnostics_downloaded params %v, want sha256 %s", ev.Params, sealed.sha256)
	}
	if raw, _ := json.Marshal(ev); bytes.Contains(raw, manifest) {
		t.Fatal("the audit event holds the bundle's content")
	}

	adminToken := tokenPortal(t, createAPIToken(t, alice, env.Alice, "org_admin").Secret)
	res = call(t, adminToken, http.MethodPost, base+"/purge", nil)
	expectStatus(t, res, http.StatusOK, "")
	expectOneEvent(t, alice, res.RequestID, "device.diagnostics_purged", "success")
	if b := getDiagnostics(t, alice, id); b.State != "purged" {
		t.Fatalf("purged bundle %+v", b)
	}
	diagnosticsObjectGone(t, sealed.objectKey(t))
	operator.stepUp(t)
	expectStatus(t, call(t, operator.Portal, http.MethodGet, base+"/download", nil), http.StatusConflict, "invalid_state")

	t.Run("size mismatch", func(t *testing.T) {
		res := requestDiagnostics(t, alice, d.DeviceID, "D1 size mismatch")
		expectStatus(t, res, http.StatusAccepted, "")
		id := responseID(t, res).String()
		awaitCollectStatus(t, d, id)
		archive, _ := diagnosticsArchive(t, id)
		s := announceDiagnostics(t, d, b, id, archive, 1)
		// The presigned URL is bound to the announced size, so the device cannot put another; the object of the sealed
		// size is put with the bucket's root credential, as a tampered bucket would hold it.
		escrowPutRoot(t, s.objectKey(t), len(s.object))
		reportDiagnostics(t, d, id, archive)
		failed := waitDiagnostics(t, alice, id, 2*time.Minute, func(b diagnosticsBundle) bool { return b.State != "requested" && b.State != "uploaded" })
		if failed.State != "failed" || failed.FailedReason == nil || *failed.FailedReason != "size_mismatch" {
			t.Fatalf("bundle %+v, want failed with size_mismatch", failed)
		}
	})
}

// TestDiagnosticsRetention is gate D2 of plan M12 (ADR 0048 decision 5): the development stack counts retention days
// in seconds and runs the retention round every 15 s, so a stored bundle is expired within seconds: its object is
// deleted, its metadata (hash, size) stays, and retention.purged with store device_diagnostics is recorded. The gate
// runs in an organization of its own, so no other gate's bundle expires into the same event.
func TestDiagnosticsRetention(t *testing.T) {
	slug, org := gateOrganization(t)
	user, password := tempUser(t, "diag-retention", env.RoleGroup(slug, "admins"))
	admin, err := loginAs(t, user, password)
	if err != nil {
		t.Fatal(err)
	}
	d, b := diagnosticsDevice(t, admin)
	res := requestDiagnostics(t, admin, d.DeviceID, "D2 retention")
	expectStatus(t, res, http.StatusAccepted, "")
	id := responseID(t, res).String()
	archive, _ := diagnosticsArchive(t, id)
	sealed := uploadDiagnostics(t, d, b, id, archive)

	expired := waitDiagnostics(t, admin, id, 2*time.Minute, func(b diagnosticsBundle) bool {
		return b.State != "requested" && b.State != "uploaded" && b.State != "stored"
	})
	if expired.State != "expired" || expired.SHA256 == nil || *expired.SHA256 != sealed.sha256 {
		t.Fatalf("bundle %+v, want expired with sha256 %s", expired, sealed.sha256)
	}
	const where = "code = 'retention.purged' AND params->>'store' = $1"
	expectOneIndexEvent(t, auditIndex(t), org, where, "device_diagnostics", "retention.purged", "success", 90*time.Second)
	diagnosticsObjectGone(t, sealed.objectKey(t))
}
