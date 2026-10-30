package acceptance

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
	"github.com/phischl/paddock-mdm/test/acceptance/internal/stack"
)

// auditExport is the part of an evidence export the gate reads.
type auditExport struct {
	ID          string `json:"id"`
	Status      string `json:"status"`
	FromDay     string `json:"from_day"`
	ToDay       string `json:"to_day"`
	Purpose     string `json:"purpose"`
	RequestedBy struct {
		Type    string  `json:"type"`
		Display string  `json:"display"`
		IP      *string `json:"ip"`
		StepUp  bool    `json:"step_up"`
	} `json:"requested_by"`
	EventCount    *int64  `json:"event_count"`
	ObjectCount   *int    `json:"object_count"`
	Size          *int64  `json:"size"`
	PackageSHA256 *string `json:"package_sha256"`
	VerifyOK      *bool   `json:"verify_ok"`
	KeyVersion    *int    `json:"key_version"`
	ExpiresAt     *string `json:"expires_at"`
	Error         *string `json:"error"`
}

// TestAuditEvidenceExport covers the evidence export gates of plan M10 §9. E1 (PDK-142): an auditor of a fresh
// organization requests an export of a sealed day only after a step-up, every request is recorded as
// audit.export_requested, the refusals carry their problem codes, and another organization does not see the export.
// E2 (PDK-143): the audit writer builds the package without operator action; it holds exactly the events the
// organization had when its day was sealed (plan M10 amendment A7) and its chain verifies. E3 (PDK-144): the auditor downloads the ready package with the
// headers and checksum of plan M10 decision 35, a not-ready export is refused, another organization gets 404 and
// every attempt is recorded. E4 (PDK-146, PDK-147): `paddockctl audit verify-export` accepts the download against the
// fingerprint of the keys endpoint and rejects a package with a modified object or without its first manifest.
//
// Like TestAuditIntegrity it uses a fresh organization so the development-only `audit seal --day --org` can seal today
// without sealing other organizations' days early.
func TestAuditEvidenceExport(t *testing.T) {
	ctx := testContext(t, 10*time.Minute)
	root := login(t, env.PlatformAdmin)
	body := newOrg()
	res := call(t, root, http.MethodPost, "/api/platform/v1/organizations", body)
	expectStatus(t, res, http.StatusCreated, "")
	org := responseID(t, res)
	adminName, adminPW := tempUser(t, "export-admin", env.RoleGroup(body["slug"], "admins"))
	admin, err := loginAs(t, adminName, adminPW)
	if err != nil {
		t.Fatalf("login as the new organization's admin: %v", err)
	}
	createGroup(t, admin)
	waitForEvents(t, admin, 2) // admin.login + device_group.created
	today := time.Now().UTC().Format(time.DateOnly)
	tomorrow := time.Now().UTC().AddDate(0, 0, 1).Format(time.DateOnly)
	// Everything recorded after the seal is filed under tomorrow and is not in the package (amendment A7).
	sealedEvents := auditTotalSince(t, admin, today)
	if code, out, err := stack.PaddockServer(ctx, "audit", "seal", "--day", today, "--org", org.String()); err != nil || code != 0 {
		t.Fatalf("audit seal: exit %d, %v\n%s", code, err, out)
	}
	auditor := mfaTempUser(t, "export-auditor", env.RoleGroup(body["slug"], "auditors"))
	request := func(from, to, purpose string) env.Response {
		return call(t, auditor.Portal, http.MethodPost, "/api/v1/audit/exports",
			map[string]string{"from_day": from, "to_day": to, "purpose": purpose})
	}

	// E1: without a step-up the request is refused and recorded as denied.
	expectRefusal(t, auditor.Portal, request(today, today, "E1 without step-up"), http.StatusForbidden, "step_up_required", "audit.export_requested")

	// E1: with a step-up the auditor's request is pending and recorded with its range and purpose.
	auditor.stepUp(t)
	res = request(today, today, "E1 ISO 27001 surveillance audit")
	expectStatus(t, res, http.StatusAccepted, "")
	var first auditExport
	if err := res.JSON(&first); err != nil {
		t.Fatal(err)
	}
	if first.Status != "pending" || first.FromDay != today || first.ToDay != today || first.Purpose != "E1 ISO 27001 surveillance audit" ||
		first.RequestedBy.Type != "admin" || first.RequestedBy.IP != nil || !first.RequestedBy.StepUp {
		t.Fatalf("E1 export: %s", res.Body)
	}
	// The builder's audit.export_completed carries the request's correlation ID too, so events are counted per code.
	ev := expectOneEventOfCode(t, auditor.Portal, res.RequestID, "audit.export_requested", "success")
	firstRequest := res.RequestID
	if ev.Params["export_id"] != first.ID || ev.Params["from_day"] != today || ev.Params["to_day"] != today ||
		ev.Params["purpose"] != "E1 ISO 27001 surveillance audit" {
		t.Fatalf("E1 event params: %+v", ev.Params)
	}

	// E1 refusals: an unsealed day, too long a range, an empty purpose, an operator.
	auditor.stepUp(t)
	res = request(today, tomorrow, "E1 unsealed")
	expectStatus(t, res, http.StatusUnprocessableEntity, "day_not_sealed")
	expectOneEvent(t, auditor.Portal, res.RequestID, "audit.export_requested", "failure")
	res = request(time.Now().UTC().AddDate(0, 0, -401).Format(time.DateOnly), today, "E1 too long")
	expectStatus(t, res, http.StatusBadRequest, "range_too_large")
	res = request(today, today, "")
	expectStatus(t, res, http.StatusBadRequest, "invalid_request")
	operator := steppedUpTempUser(t, "export-operator", env.RoleGroup(body["slug"], "operators"))
	res = call(t, operator.Portal, http.MethodPost, "/api/v1/audit/exports",
		map[string]string{"from_day": today, "to_day": today, "purpose": "E1 operator"})
	expectRefusal(t, auditor.Portal, res, http.StatusForbidden, "forbidden", "audit.export_requested")

	// E2: the first export becomes ready within 60 s with the events of the sealed day and a verified chain.
	ready := waitForExport(t, auditor.Portal, first.ID, 60*time.Second)
	if ready.Status != "ready" || ready.EventCount == nil || *ready.EventCount != sealedEvents || ready.VerifyOK == nil ||
		!*ready.VerifyOK || ready.ObjectCount == nil || *ready.ObjectCount < 1 || ready.Size == nil || *ready.Size <= 0 ||
		ready.KeyVersion == nil || ready.ExpiresAt == nil || ready.Error != nil {
		t.Fatalf("E2 export (want event_count %d): %+v", sealedEvents, ready)
	}
	done := expectOneEventOfCode(t, auditor.Portal, firstRequest, "audit.export_completed", "success")
	if done.Params["export_id"] != first.ID || done.Params["events"] != float64(sealedEvents) ||
		done.Params["verify_ok"] != true || done.Params["size"] != float64(*ready.Size) ||
		done.Params["key_version"] != float64(*ready.KeyVersion) || len(fmt.Sprint(done.Params["package_sha256"])) != 64 {
		t.Fatalf("E2 event params: %+v", done.Params)
	}

	// E3 (PDK-148): the key version the package names is published with the fingerprint that the audit-writer CLI
	// prints from OpenBao; an operator may not read the list.
	res = call(t, auditor.Portal, http.MethodGet, "/api/v1/audit/keys", nil)
	expectStatus(t, res, http.StatusOK, "")
	var published struct {
		Keys []struct {
			KeyVersion  int    `json:"key_version"`
			PublicKey   string `json:"public_key"`
			Fingerprint string `json:"fingerprint"`
		} `json:"keys"`
	}
	if err := res.JSON(&published); err != nil {
		t.Fatal(err)
	}
	fingerprint := ""
	for _, k := range published.Keys {
		if k.KeyVersion == *ready.KeyVersion {
			fingerprint = k.Fingerprint
			if raw, err := base64.StdEncoding.DecodeString(k.PublicKey); err != nil || len(raw) != 32 || fingerprint != hex.EncodeToString(sha256Sum(raw)) {
				t.Fatalf("E3 key v%d: %+v (decode: %v)", k.KeyVersion, k, err)
			}
		}
	}
	if fingerprint == "" {
		t.Fatalf("E3 key v%d of the package is not published: %s", *ready.KeyVersion, res.Body)
	}
	code, out, err := stack.PaddockServer(ctx, "audit", "keys")
	if err != nil || code != 0 {
		t.Fatalf("E3 audit keys: exit %d, %v\n%s", code, err, out)
	}
	if want := fmt.Sprintf("audit-chain v%d %s", *ready.KeyVersion, fingerprint); !strings.Contains(out, want+"\n") {
		t.Fatalf("E3 audit keys prints %q, want a line %q", out, want)
	}
	expectStatus(t, call(t, operator.Portal, http.MethodGet, "/api/v1/audit/keys", nil), http.StatusForbidden, "forbidden")

	// E1: at most two exports are pending or running. The builder finishes a request within seconds, so the second
	// export is awaited and two running exports are held through the writer role for the refusal and finished
	// afterwards; exactly two are then open at the third request.
	auditor.stepUp(t)
	res = request(today, today, "E1 second")
	expectStatus(t, res, http.StatusAccepted, "")
	var second auditExport
	if err := res.JSON(&second); err != nil {
		t.Fatal(err)
	}
	waitForExport(t, auditor.Portal, second.ID, 60*time.Second)
	holdOpenExports(t, org, 2)
	auditor.stepUp(t)
	res = request(today, today, "E1 third")
	expectStatus(t, res, http.StatusConflict, "too_many_exports")
	expectOneEvent(t, auditor.Portal, res.RequestID, "audit.export_requested", "failure")
	finishOpenExports(t, org)

	// E1: the organization lists its exports; another organization's auditor finds none of them.
	res = call(t, auditor.Portal, http.MethodGet, "/api/v1/audit/exports?page_size=10", nil)
	expectStatus(t, res, http.StatusOK, "")
	var page struct {
		Items []auditExport `json:"items"`
		Total int           `json:"total"`
	}
	if err := res.JSON(&page); err != nil || page.Total != 4 {
		t.Fatalf("E1 list: %v %s", err, res.Body)
	}
	carol := login(t, env.Carol)
	expectStatus(t, call(t, carol, http.MethodGet, "/api/v1/audit/exports/"+first.ID, nil), http.StatusNotFound, "not_found")
	res = call(t, carol, http.MethodGet, "/api/v1/audit/exports?page_size=100", nil)
	expectStatus(t, res, http.StatusOK, "")
	if leaked := containsAny(res.Body, []string{first.ID, org.String()}); leaked != "" {
		t.Fatalf("E1 globex list contains %s: %s", leaked, res.Body)
	}

	// E3: the download is the package of the ready export: size, checksum and file name as announced, a tar with the
	// files of plan M10 §6.5, and one audit.export_downloaded event with the export's range, size and checksum.
	downloadPath := "/api/v1/audit/exports/" + first.ID + "/download"
	res = call(t, auditor.Portal, http.MethodGet, downloadPath, nil)
	expectStatus(t, res, http.StatusOK, "")
	sum := sha256.Sum256(res.Body)
	wantName := fmt.Sprintf(`attachment; filename="paddock-audit-export-%s-%s_%s-%s.tar"`, body["slug"], today, today, first.ID[:8])
	if res.Header.Get("Content-Type") != "application/x-tar" || res.Header.Get("Content-Length") != fmt.Sprint(*ready.Size) ||
		int64(len(res.Body)) != *ready.Size || res.Header.Get("Content-Disposition") != wantName ||
		res.Header.Get("X-Paddock-Package-SHA256") != hex.EncodeToString(sum[:]) ||
		ready.PackageSHA256 == nil || *ready.PackageSHA256 != hex.EncodeToString(sum[:]) {
		t.Fatalf("E3 download headers %v (%d bytes, export %+v)", res.Header, len(res.Body), ready)
	}
	members := readTarMembers(t, res.Body)
	files := map[string]bool{}
	for _, m := range members {
		files[m.name] = true
	}
	for _, name := range []string{"README.md", "events.jsonl", "export.json", "export.sig"} {
		if !files[name] {
			t.Fatalf("E3 package lacks %s: %v", name, files)
		}
	}
	// E3 (PDK-148): the fingerprint the keys endpoint publishes is the one the downloaded package names in export.json.
	var doc struct {
		Keys []struct {
			KeyVersion  int    `json:"key_version"`
			Fingerprint string `json:"fingerprint"`
		} `json:"keys"`
	}
	for _, m := range members {
		if m.name == "export.json" {
			if err := json.Unmarshal(m.body, &doc); err != nil {
				t.Fatalf("E3 export.json: %v", err)
			}
		}
	}
	inPackage := false
	for _, k := range doc.Keys {
		if k.KeyVersion == *ready.KeyVersion && k.Fingerprint == fingerprint {
			inPackage = true
		}
	}
	if !inPackage {
		t.Fatalf("E3 export.json keys[] %+v lack key v%d with fingerprint %s", doc.Keys, *ready.KeyVersion, fingerprint)
	}
	downloaded := expectOneEventOfCode(t, auditor.Portal, res.RequestID, "audit.export_downloaded", "success")
	if downloaded.Params["export_id"] != first.ID || downloaded.Params["from_day"] != today || downloaded.Params["to_day"] != today ||
		downloaded.Params["size"] != float64(*ready.Size) || downloaded.Params["package_sha256"] != hex.EncodeToString(sum[:]) {
		t.Fatalf("E3 event params: %+v", downloaded.Params)
	}

	// E3: an export that is not ready is refused with a recorded failure; another organization and an operator get no package.
	res = call(t, auditor.Portal, http.MethodGet, "/api/v1/audit/exports?status=failed&page_size=10", nil)
	expectStatus(t, res, http.StatusOK, "")
	var failed struct {
		Items []auditExport `json:"items"`
	}
	if err := res.JSON(&failed); err != nil || len(failed.Items) == 0 {
		t.Fatalf("E3 failed exports: %v %s", err, res.Body)
	}
	res = call(t, auditor.Portal, http.MethodGet, "/api/v1/audit/exports/"+failed.Items[0].ID+"/download", nil)
	expectStatus(t, res, http.StatusConflict, "export_not_ready")
	expectOneEventOfCode(t, auditor.Portal, res.RequestID, "audit.export_downloaded", "failure")
	expectStatus(t, call(t, carol, http.MethodGet, downloadPath, nil), http.StatusNotFound, "not_found")
	expectStatus(t, call(t, operatorUser(t).Portal, http.MethodGet, downloadPath, nil), http.StatusForbidden, "forbidden")

	// E4: an auditor verifies the downloaded package offline against the fingerprint of the keys endpoint; a package
	// with a flipped object byte or without its first manifest does not verify.
	ctl := newPaddockctl(t)
	dir := t.TempDir()
	write := func(name string, data []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	verify := func(file string) ctlResult {
		return ctl.run(t, "", "", "audit", "verify-export", file, "--fingerprint", fingerprint)
	}
	if r := verify(write("package.tar", res.Body)); r.code != 0 || !strings.HasPrefix(r.stdout, "OK ") ||
		!strings.Contains(r.stdout, "fingerprint "+fingerprint) {
		t.Fatalf("E4 verify-export of the download: exit %d\n%s%s", r.code, r.stdout, r.stderr)
	}
	flipped := false
	tampered := writeTarMembers(t, members, func(m tarMember) (tarMember, bool) {
		if !flipped && strings.HasPrefix(m.name, "objects/") && len(m.body) > 0 {
			flipped = true
			m.body = append([]byte{}, m.body...)
			m.body[len(m.body)/2] ^= 1
		}
		return m, true
	})
	if !flipped {
		t.Fatalf("E4 package has no object to modify: %v", files)
	}
	if r := verify(write("flipped.tar", tampered)); r.code != 1 || !strings.Contains(r.stdout, "SHA-256 mismatch") {
		t.Fatalf("E4 verify-export of a modified object: exit %d, want 1 with SHA-256 mismatch\n%s%s", r.code, r.stdout, r.stderr)
	}
	firstManifest := "manifests/" + today + ".json"
	removed := false
	noManifest := writeTarMembers(t, members, func(m tarMember) (tarMember, bool) {
		if m.name == firstManifest {
			removed = true
			return m, false
		}
		return m, true
	})
	if !removed {
		t.Fatalf("E4 package lacks %s: %v", firstManifest, files)
	}
	if r := verify(write("no-manifest.tar", noManifest)); r.code != 1 || !strings.Contains(r.stdout, "no manifest") {
		t.Fatalf("E4 verify-export without the first manifest: exit %d, want 1 with no manifest\n%s%s", r.code, r.stdout, r.stderr)
	}
}

type tarMember struct {
	name string
	body []byte
}

// readTarMembers returns the regular files of a tar archive in archive order.
func readTarMembers(t *testing.T, data []byte) []tarMember {
	t.Helper()
	var members []tarMember
	for r := tar.NewReader(bytes.NewReader(data)); ; {
		h, err := r.Next()
		if err == io.EOF {
			return members
		}
		if err != nil {
			t.Fatalf("tar: %v", err)
		}
		body, err := io.ReadAll(r)
		if err != nil {
			t.Fatalf("tar member %s: %v", h.Name, err)
		}
		members = append(members, tarMember{name: h.Name, body: body})
	}
}

// writeTarMembers builds a tar archive from members after edit decided for each whether it stays and with which body.
func writeTarMembers(t *testing.T, members []tarMember, edit func(tarMember) (tarMember, bool)) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := tar.NewWriter(&buf)
	for _, m := range members {
		m, keep := edit(m)
		if !keep {
			continue
		}
		if err := w.WriteHeader(&tar.Header{Name: m.name, Mode: 0o600, Size: int64(len(m.body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(m.body); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// auditTotalSince is the total the audit log lists for the viewer's organization from 00:00 UTC of day.
func auditTotalSince(t *testing.T, p *env.Portal, day string) int64 {
	t.Helper()
	res := call(t, p, http.MethodGet, "/api/v1/audit-events?page_size=10&from="+day+"T00:00:00Z", nil)
	expectStatus(t, res, http.StatusOK, "")
	var page struct {
		Total int64 `json:"total"`
	}
	if err := res.JSON(&page); err != nil {
		t.Fatal(err)
	}
	return page.Total
}

// waitForExport polls an export until it is no longer pending or running, or fails the test after timeout.
func waitForExport(t *testing.T, p *env.Portal, id string, timeout time.Duration) auditExport {
	t.Helper()
	for deadline := time.Now().Add(timeout); ; time.Sleep(time.Second) {
		res := call(t, p, http.MethodGet, "/api/v1/audit/exports/"+id, nil)
		expectStatus(t, res, http.StatusOK, "")
		var x auditExport
		if err := res.JSON(&x); err != nil {
			t.Fatal(err)
		}
		if x.Status != "pending" && x.Status != "running" {
			return x
		}
		if time.Now().After(deadline) {
			t.Fatalf("export %s still %s after %s", id, x.Status, timeout)
		}
	}
}

// expectOneEventOfCode is expectOneEvent for a correlation ID that more than one code shares: exactly one event of
// code, with outcome, exists for requestID, also after the settle delay.
func expectOneEventOfCode(t *testing.T, viewer *env.Portal, requestID, code, outcome string) env.AuditEvent {
	t.Helper()
	ctx := testContext(t, 2*time.Minute)
	from := time.Now().Add(-auditLookback)
	of := func() []env.AuditEvent {
		events, err := viewer.AuditEventsSince(ctx, code, from)
		if err != nil {
			t.Fatal(err)
		}
		return env.EventsFor(events, requestID)
	}
	var found []env.AuditEvent
	for deadline := time.Now().Add(auditPollTimeout); ; time.Sleep(500 * time.Millisecond) {
		if found = of(); len(found) > 0 || time.Now().After(deadline) {
			break
		}
	}
	check := func(when string) {
		if len(found) != 1 || found[0].Outcome != outcome {
			t.Fatalf("%s: %d %s events for request %s, want exactly 1 with outcome %s: %+v", when, len(found), code, requestID, outcome, found)
		}
	}
	check("after polling")
	time.Sleep(auditSettleDelay)
	found = of()
	check("5 s later")
	return found[0]
}

// holdOpenExports inserts n running exports of org through the audit writer role, which the builder never claims, so
// the open-export limit can be reached while the builder finishes requests within seconds; finishOpenExports ends
// them.
func holdOpenExports(t *testing.T, org uuid.UUID, n int) {
	t.Helper()
	dsn, err := stack.AuditWriterDSN()
	if err != nil {
		t.Fatal(err)
	}
	ctx := testContext(t, time.Minute)
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close(ctx) }()
	today := time.Now().UTC().Format(time.DateOnly)
	for i := range n {
		if _, err := conn.Exec(ctx, `INSERT INTO audit_export (id, organization_id, status, from_day, to_day, purpose,
			requested_by, correlation_id, started_at) VALUES ($1, $2, 'running', $3, $3, $4, '{"type":"system"}', $5, now())`,
			uuid.Must(uuid.NewV7()), org, today, fmt.Sprintf("held by the export gate %d", i+1), "gate-hold"); err != nil {
			t.Fatalf("hold an open export of %s: %v", org, err)
		}
	}
}

func sha256Sum(b []byte) []byte {
	sum := sha256.Sum256(b)
	return sum[:]
}
