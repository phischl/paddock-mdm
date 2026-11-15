package acceptance

import (
	"bufio"
	"bytes"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/pkg/escrow"
	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
	"github.com/phischl/paddock-mdm/test/acceptance/internal/stack"
)

// gpgHome runs gpg in a temporary GNUPGHOME. The gate fails, never skips, without gpg (plan M17 amendment b, tests).
type gpgHome struct {
	t    *testing.T
	bin  string
	home string
}

func newGPGHome(t *testing.T) *gpgHome {
	t.Helper()
	bin, err := exec.LookPath("gpg")
	if err != nil {
		t.Fatal("gate OF9 needs gpg on the test host (present on ubuntu-24.04 runners and the development host)")
	}
	home := t.TempDir()
	if err := os.Chmod(home, 0o700); err != nil {
		t.Fatal(err)
	}
	return &gpgHome{t: t, bin: bin, home: home}
}

func (g *gpgHome) run(args ...string) []byte {
	g.t.Helper()
	cmd := exec.Command(g.bin, append([]string{"--homedir", g.home, "--batch", "--yes", "--pinentry-mode", "loopback"}, args...)...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		g.t.Fatalf("gpg %s: %v\n%s", args[len(args)-1], err, stderr.String())
	}
	return out
}

// decrypt decrypts an export file and returns its JSON lines.
func (g *gpgHome) decrypt(body []byte, args ...string) []map[string]any {
	g.t.Helper()
	file := filepath.Join(g.t.TempDir(), "export.asc")
	if err := os.WriteFile(file, body, 0o600); err != nil {
		g.t.Fatal(err)
	}
	plain := g.run(append(args, "--decrypt", file)...)
	var lines []map[string]any
	sc := bufio.NewScanner(bytes.NewReader(plain))
	for sc.Scan() {
		var m map[string]any
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			g.t.Fatalf("export line: %v", err)
		}
		lines = append(lines, m)
	}
	return lines
}

// TestOrganizationRecoveryExport is gate OF9 (plan M17 amendment b; ADR 0052 amendment b): while the deletion of an
// organization is pending, its administrator exports every recovery key and local administrator password, encrypted
// to a gpg test key and to a passphrase; plain gpg decrypts both, the values equal the single reveals of the device,
// and each export is one organization.recovery_exported in the organization's log without a secret.
func TestOrganizationRecoveryExport(t *testing.T) {
	g := newGPGHome(t)
	slug, org := gateOrganization(t)
	admin := steppedUpTempUser(t, "of9-admin", env.RoleGroup(slug, "admins"))
	d, b, password := escrowedDevice(t, admin.Portal)
	pub, version := escrowWrap(t, b)
	key := "recovery-" + uniqueSuffix()
	ct, err := escrow.Encrypt(pub, []byte(key))
	if err != nil {
		t.Fatal(err)
	}
	keyID := uuid.Must(uuid.NewV7()).String()
	res, err := d.Escrow(testContext(t, time.Minute), escrow.Request{EscrowID: keyID, Kind: escrow.KindLUKSRecoveryKey, Generation: 1,
		KeyVersion: version, Ciphertext: ct})
	if err != nil || res.Status != http.StatusAccepted || waitEscrow(t, d, keyID, 30*time.Second) != escrow.StatusStored {
		t.Fatalf("recovery key escrow: %v HTTP %d", err, res.Status)
	}
	hostname := getDevice(t, admin.Portal, d.DeviceID).Hostname
	body := map[string]any{"recipient": "passphrase", "passphrase": "an OF9 gate passphrase " + uniqueSuffix()}

	admin.stepUp(t)
	exp := call(t, admin.Portal, http.MethodPost, "/api/v1/recovery-export", body)
	expectStatus(t, exp, http.StatusConflict, "invalid_state")
	expectOneEvent(t, admin.Portal, exp.RequestID, "organization.recovery_exported", "failure")

	root := login(t, env.PlatformAdmin)
	stepUp(t, root, env.PlatformAdmin, true)
	orgPath := "/api/platform/v1/organizations/" + org.String()
	expectStatus(t, call(t, root, http.MethodPost, orgPath+"/delete",
		map[string]any{"confirm_slug": slug, "reason": "gate OF9", "grace_days": 30}), http.StatusAccepted, "")
	t.Cleanup(func() { call(t, root, http.MethodPost, orgPath+"/cancel-deletion", nil) })

	g.run("--passphrase", "", "--quick-gen-key", "of9-"+uniqueSuffix()+"@gate.test", "default", "default", "never")
	publicKey := string(g.run("--armor", "--export"))

	admin.stepUp(t)
	exp = call(t, admin.Portal, http.MethodPost, "/api/v1/recovery-export", map[string]any{"recipient": "public_key", "public_key": publicKey})
	expectStatus(t, exp, http.StatusOK, "")
	if !strings.HasPrefix(exp.Header.Get("Content-Disposition"), "attachment; filename=paddock-recovery-"+slug+"-") {
		t.Fatalf("Content-Disposition %q", exp.Header.Get("Content-Disposition"))
	}
	ev := expectOneEvent(t, admin.Portal, exp.RequestID, "organization.recovery_exported", "success")
	if ev.Params["recipient"] != "public_key" || ev.Params["requester_scope"] != "organization" || ev.Params["devices"] != float64(1) ||
		ev.Params["secrets"] != float64(2) || ev.Params["key_fingerprint"] == nil {
		t.Fatalf("event params %v", ev.Params)
	}
	lines := g.decrypt(exp.Body)
	if len(lines) != 2 || lines[0]["organization_id"] != org.String() || lines[0]["slug"] != slug || lines[1]["device_id"] != d.DeviceID ||
		lines[1]["hostname"] != hostname {
		t.Fatalf("export: %d lines, header %v", len(lines), lines[0])
	}
	volumes, _ := lines[1]["volumes"].([]any)
	localAdmin, _ := lines[1]["local_admin"].(map[string]any)
	if len(volumes) != 1 || volumes[0].(map[string]any)["recovery_key"] != key || localAdmin == nil || localAdmin["password"] != password {
		t.Fatal("the export's secrets differ from the escrowed ones")
	}

	// The values equal the single reveals of the same device.
	revealed := call(t, admin.Portal, http.MethodPost, "/api/v1/devices/"+d.DeviceID+"/disk/recovery-key", map[string]any{"confirm_hostname": hostname})
	var rk struct {
		RecoveryKey string `json:"recovery_key"`
	}
	if err := revealed.JSON(&rk); err != nil || rk.RecoveryKey != volumes[0].(map[string]any)["recovery_key"] {
		t.Fatalf("reveal of the recovery key differs: %v", err)
	}
	revealed = call(t, admin.Portal, http.MethodPost, "/api/v1/devices/"+d.DeviceID+"/local-admin/reveal", map[string]any{"confirm_hostname": hostname})
	if !bytes.Contains(revealed.Body, []byte(localAdmin["password"].(string))) {
		t.Fatal("reveal of the local administrator password differs")
	}

	admin.stepUp(t)
	exp = call(t, admin.Portal, http.MethodPost, "/api/v1/recovery-export", body)
	expectStatus(t, exp, http.StatusOK, "")
	ev = expectOneEvent(t, admin.Portal, exp.RequestID, "organization.recovery_exported", "success")
	if raw, _ := json.Marshal(ev); bytes.Contains(raw, []byte(body["passphrase"].(string))) || bytes.Contains(raw, []byte(key)) ||
		bytes.Contains(raw, []byte(password)) {
		t.Fatal("the audit event carries a secret")
	}
	if lines := g.decrypt(exp.Body, "--passphrase", body["passphrase"].(string)); len(lines) != 2 {
		t.Fatalf("passphrase export: %d lines", len(lines))
	}
}

// recoveryExportAuditCases are the A3 cases of the recovery export. acme has no pending deletion, so a stepped-up
// request is the conflict case; the success of each path is gate OF9's, on an organization of its own.
func recoveryExportAuditCases(platform bool) []auditCase {
	body := map[string]any{"recipient": "passphrase", "passphrase": "an A3 gate passphrase"}
	target := func(w *auditWorld, org uuid.UUID) string {
		if platform {
			return "/api/platform/v1/organizations/" + org.String() + "/recovery-export"
		}
		return "/api/v1/recovery-export"
	}
	steppedUp := func(t *testing.T, w *auditWorld) *env.Portal {
		if platform {
			root := login(t, env.PlatformAdmin)
			stepUp(t, root, env.PlatformAdmin, true)
			return root
		}
		user := w.admins.take()
		admin := login(t, user)
		stepUp(t, admin, user, true)
		return admin
	}
	plain := env.Alice
	if platform {
		plain = env.PlatformAdmin
	}
	cases := []auditCase{
		{"no step-up", func(t *testing.T, w *auditWorld) {
			res := call(t, login(t, plain), http.MethodPost, target(w, w.acme), body)
			expectStatus(t, res, http.StatusForbidden, "step_up_required")
			expectOneEvent(t, w.alice, res.RequestID, "organization.recovery_exported", "denied")
		}},
		{"wrong role", func(t *testing.T, w *auditWorld) {
			p := w.bob
			if platform {
				p = w.alice
			}
			res := call(t, p, http.MethodPost, target(w, w.acme), body)
			expectStatus(t, res, http.StatusForbidden, "forbidden")
			expectOneEvent(t, w.alice, res.RequestID, "organization.recovery_exported", "denied")
		}},
		{"validation failure", func(t *testing.T, w *auditWorld) {
			// A body the binder refuses is recorded by the route's spec: in the platform log for the platform path.
			viewer := w.alice
			if platform {
				viewer = w.root
			}
			res := call(t, viewer, http.MethodPost, target(w, w.acme), map[string]any{"recipient": 5})
			expectStatus(t, res, http.StatusBadRequest, "invalid_request")
			expectOneEvent(t, viewer, res.RequestID, "organization.recovery_exported", "failure")
		}},
		{"conflict", func(t *testing.T, w *auditWorld) {
			res := call(t, steppedUp(t, w), http.MethodPost, target(w, w.acme), body)
			expectStatus(t, res, http.StatusConflict, "invalid_state")
			expectOneEvent(t, w.alice, res.RequestID, "organization.recovery_exported", "failure")
		}},
	}
	if platform {
		cases = append(cases, auditCase{"not found", func(t *testing.T, w *auditWorld) {
			res := call(t, steppedUp(t, w), http.MethodPost, target(w, uuid.New()), body)
			expectStatus(t, res, http.StatusNotFound, "not_found")
			expectOneEvent(t, w.root, res.RequestID, "organization.recovery_exported", "failure")
		}})
	}
	return cases
}

func init() {
	auditCases["POST /api/v1/recovery-export"] = recoveryExportAuditCases(false)
	auditCases["POST /api/platform/v1/organizations/{id}/recovery-export"] = recoveryExportAuditCases(true)
}

// foreignOrgBody is a recovery export request with a passphrase recipient that names another organization and one of
// its devices in every field a client could try (PDK-1073). The request schema has none of them.
func foreignOrgBody(org, slug, device string) map[string]any {
	return map[string]any{"recipient": "passphrase", "passphrase": "a PDK-1073 isolation passphrase " + uniqueSuffix(),
		"organization_id": org, "org_id": org, "organization": org, "slug": slug, "device_id": device,
		"device_ids": []string{device}, "devices": []string{device}}
}

// foreignOrgQuery names another organization and one of its devices as query parameters (PDK-1073).
func foreignOrgQuery(org, device string) url.Values {
	return url.Values{"organization_id": {org}, "org_id": {org}, "organization": {org}, "device_id": {device}}
}

// foreignOrgHeaders names another organization in the request headers a client could try (PDK-1073).
func foreignOrgHeaders(org string) map[string]string {
	return map[string]string{"X-Paddock-Organization": org, "X-Paddock-Org-Id": org, "X-Organization-Id": org, "X-Org-Id": org}
}

// recoveryExportOrg is an organization of TestRecoveryExportIsolation with one device whose recovery key and local
// administrator password are escrowed.
type recoveryExportOrg struct {
	slug          string
	id            uuid.UUID
	admin         *mfaUser
	device        string
	key, password string
}

// newRecoveryExportOrg creates the organization, its administrator (signed in, without a step-up) and its device.
func newRecoveryExportOrg(t *testing.T, prefix string) *recoveryExportOrg {
	t.Helper()
	slug, id := gateOrganization(t)
	admin := mfaTempUser(t, prefix, env.RoleGroup(slug, "admins"))
	admin.stepUp(t)
	d, b, password := escrowedDevice(t, admin.Portal)
	pub, version := escrowWrap(t, b)
	key := "recovery-" + uniqueSuffix()
	ct, err := escrow.Encrypt(pub, []byte(key))
	if err != nil {
		t.Fatal(err)
	}
	keyID := uuid.Must(uuid.NewV7()).String()
	res, err := d.Escrow(testContext(t, time.Minute), escrow.Request{EscrowID: keyID, Kind: escrow.KindLUKSRecoveryKey, Generation: 1,
		KeyVersion: version, Ciphertext: ct})
	if err != nil || res.Status != http.StatusAccepted || waitEscrow(t, d, keyID, 30*time.Second) != escrow.StatusStored {
		t.Fatalf("recovery key escrow: %v HTTP %d", err, res.Status)
	}
	return &recoveryExportOrg{slug: slug, id: id, admin: admin, device: d.DeviceID, key: key, password: password}
}

// secrets are the values of the organization that must never reach another organization's administrator.
func (o *recoveryExportOrg) secrets() []string {
	return []string{o.id.String(), o.slug, o.device, o.key, o.password}
}

// startDeletion puts the organization into its grace period and cancels the deletion when the test ends.
func (o *recoveryExportOrg) startDeletion(t *testing.T, root *env.Portal) {
	t.Helper()
	path := "/api/platform/v1/organizations/" + o.id.String()
	expectStatus(t, call(t, root, http.MethodPost, path+"/delete",
		map[string]any{"confirm_slug": o.slug, "reason": "PDK-1073 isolation", "grace_days": 30}), http.StatusAccepted, "")
	t.Cleanup(func() { call(t, root, http.MethodPost, path+"/cancel-deletion", nil) })
}

// exportWithHeaders is call for POST /api/v1/recovery-export in the administrator's session with extra headers.
func exportWithHeaders(t *testing.T, admin *mfaUser, path string, headers map[string]string, body any) env.Response {
	t.Helper()
	hc, err := env.HeaderClient(headers)
	if err != nil {
		t.Fatal(err)
	}
	hc.Jar = admin.Client.Jar
	res, err := env.Call(testContext(t, time.Minute), hc, http.MethodPost, stack.AdminURL()+path, body, true)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	return res
}

// TestRecoveryExportIsolation proves that POST /api/v1/recovery-export never exports another organization (PDK-1073,
// decisions alpha.11 §66). The export takes its organization from the principal only: the path has no parameter,
// the request schema no organization or device, and no header selects an organization. An administrator of a who
// names b (pending deletion, escrowed device) in the body, the query or the headers gets a's own answer, the same
// as for an unknown organization, and never b's key material; b's own path below /api/platform/v1 refuses a for its
// role before any lookup. Once a's deletion is pending too, a's export holds a's device only.
func TestRecoveryExportIsolation(t *testing.T) {
	g := newGPGHome(t)
	root := login(t, env.PlatformAdmin)
	stepUp(t, root, env.PlatformAdmin, true)
	a, b := newRecoveryExportOrg(t, "iso-a-admin"), newRecoveryExportOrg(t, "iso-b-admin")
	b.startDeletion(t, root)
	const export = "/api/v1/recovery-export"
	unknown, unknownDevice := uuid.NewString(), uuid.NewString()
	leaks := func(t *testing.T, res env.Response) {
		t.Helper()
		if leaked := containsAny(res.Body, b.secrets()); leaked != "" {
			t.Fatalf("the response carries %s of the other organization: %s", leaked, res.Body)
		}
	}

	// Without a step-up a is refused before anything else, whatever the request names.
	fresh := mfaTempUser(t, "iso-a-plain", env.RoleGroup(a.slug, "admins"))
	res := call(t, fresh.Portal, http.MethodPost, export+"?"+foreignOrgQuery(b.id.String(), b.device).Encode(),
		foreignOrgBody(b.id.String(), b.slug, b.device))
	expectStatus(t, res, http.StatusForbidden, "step_up_required")
	leaks(t, res)

	// a's deletion is not pending: every way of naming b answers a's own invalid_state, as an unknown organization
	// does, and the attempt is recorded in a's log with a as its target.
	a.admin.stepUp(t)
	cases := []struct {
		name    string
		path    string
		headers map[string]string
		body    func(org, slug, device string) any
	}{
		{"plain request", export, nil, func(string, string, string) any {
			return map[string]any{"recipient": "passphrase", "passphrase": "a PDK-1073 isolation passphrase " + uniqueSuffix()}
		}},
		{"body", export, nil, func(org, slug, device string) any { return foreignOrgBody(org, slug, device) }},
		{"query", export + "?" + foreignOrgQuery(b.id.String(), b.device).Encode(), nil, nil},
		{"headers", export, foreignOrgHeaders(b.id.String()), nil},
	}
	for _, c := range cases {
		t.Run("pending b, idle a, "+c.name, func(t *testing.T) {
			body := c.body
			if body == nil {
				body = cases[0].body
			}
			a.admin.stepUp(t)
			res := exportWithHeaders(t, a.admin, c.path, c.headers, body(b.id.String(), b.slug, b.device))
			expectStatus(t, res, http.StatusConflict, "invalid_state")
			leaks(t, res)
			ev := expectOneEvent(t, a.admin.Portal, res.RequestID, "organization.recovery_exported", "failure")
			if ev.Target == nil || ev.Target.ID != a.id.String() {
				t.Fatalf("event target %+v, want organization %s", ev.Target, a.id)
			}
			control := exportWithHeaders(t, a.admin, export, nil, body(unknown, "unknown-org", unknownDevice))
			if control.Status != res.Status || control.ProblemCode() != res.ProblemCode() {
				t.Fatalf("naming the other organization answers %d %s, naming an unknown one %d %s",
					res.Status, res.ProblemCode(), control.Status, control.ProblemCode())
			}
		})
	}

	// b's own path is the platform administrators': a is refused for the role, as for an unknown organization.
	t.Run("platform path of b", func(t *testing.T) {
		a.admin.stepUp(t)
		res := call(t, a.admin.Portal, http.MethodPost, "/api/platform/v1/organizations/"+b.id.String()+"/recovery-export", cases[0].body("", "", ""))
		expectStatus(t, res, http.StatusForbidden, "forbidden")
		leaks(t, res)
		control := call(t, a.admin.Portal, http.MethodPost, "/api/platform/v1/organizations/"+unknown+"/recovery-export", cases[0].body("", "", ""))
		expectStatus(t, control, http.StatusForbidden, "forbidden")
	})

	// With a's deletion pending, a request that names b everywhere exports a, and only a.
	t.Run("pending a and b", func(t *testing.T) {
		a.startDeletion(t, root)
		a.admin.stepUp(t)
		body := foreignOrgBody(b.id.String(), b.slug, b.device)
		res := exportWithHeaders(t, a.admin, export+"?"+foreignOrgQuery(b.id.String(), b.device).Encode(),
			foreignOrgHeaders(b.id.String()), body)
		expectStatus(t, res, http.StatusOK, "")
		leaks(t, res)
		ev := expectOneEvent(t, a.admin.Portal, res.RequestID, "organization.recovery_exported", "success")
		if ev.Target == nil || ev.Target.ID != a.id.String() || ev.Params["devices"] != float64(1) || ev.Params["secrets"] != float64(2) {
			t.Fatalf("event target %+v params %v, want organization %s with one device", ev.Target, ev.Params, a.id)
		}
		lines := g.decrypt(res.Body, "--passphrase", body["passphrase"].(string))
		if len(lines) != 2 || lines[0]["organization_id"] != a.id.String() || lines[0]["slug"] != a.slug || lines[1]["device_id"] != a.device {
			t.Fatalf("export of a: %v", lines)
		}
		plain, _ := json.Marshal(lines)
		if leaked := containsAny(plain, b.secrets()); leaked != "" {
			t.Fatalf("a's export carries %s of the other organization", leaked)
		}
		if !bytes.Contains(plain, []byte(a.key)) || !bytes.Contains(plain, []byte(a.password)) {
			t.Fatal("a's export lacks a's own secrets")
		}
	})

	// b's log has no export: nothing a sent was recorded, let alone run, as b's.
	events, err := b.admin.AuditEvents(testContext(t, time.Minute), "organization.recovery_exported")
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 0 {
		t.Fatalf("the other organization's log has %d recovery exports", len(events))
	}
}
