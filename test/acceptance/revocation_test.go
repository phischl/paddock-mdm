package acceptance

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/phischl/paddock-mdm/pkg/bundle"
	"github.com/phischl/paddock-mdm/pkg/protocol"
	"github.com/phischl/paddock-mdm/pkg/revocation"
	"github.com/phischl/paddock-mdm/test/acceptance/devicesim"
	"github.com/phischl/paddock-mdm/test/acceptance/internal/authflow"
	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
	"github.com/phischl/paddock-mdm/test/acceptance/internal/stack"
)

// The revocation gates (plan M4c R2, R3, R5) run in an organization of their own with temporary administrators:
// the limits of ADR 0014 count per administrator and organization over 24 h, and a gate that exceeds them on purpose
// must not freeze the dev users or exhaust acme for the other gates.

// gateAdmin is a temporary organization administrator with a TOTP authenticator, so it can step up.
type gateAdmin struct {
	portal             *env.Portal
	username, password string
	totp               *authflow.TOTP
}

// gateOrganization creates an organization and returns its slug and ID.
func gateOrganization(t *testing.T) (string, uuid.UUID) {
	t.Helper()
	root := login(t, env.PlatformAdmin)
	org := newOrg()
	res := call(t, root, http.MethodPost, "/api/platform/v1/organizations", org)
	expectStatus(t, res, http.StatusCreated, "")
	return org["slug"], responseID(t, res)
}

// newGateAdmin creates an administrator of slug with a TOTP authenticator (installed in Authentik's shell like
// make dev-seed does; the key travels on stdin) and signs it in.
func newGateAdmin(t *testing.T, slug string) *gateAdmin {
	t.Helper()
	username, password := tempUser(t, "revoke", env.RoleGroup(slug, "admins"))
	key := make([]byte, 20)
	_, _ = rand.Read(key)
	script := fmt.Sprintf("from authentik.core.models import User\nfrom authentik.stages.authenticator_totp.models import TOTPDevice\n"+
		"TOTPDevice.objects.create(user=User.objects.get(username=%q), name=\"paddock-gate\", key=%q, confirmed=True)\nprint(\"gate totp ok\")\n",
		username, hex.EncodeToString(key))
	out, err := stack.ComposeInput(testContext(t, 2*time.Minute), strings.NewReader(script), "exec", "-T", "authentik-worker", "ak", "shell")
	if err != nil || !strings.Contains(out, "gate totp ok") {
		t.Fatalf("TOTP authenticator of %s: %v %s", username, err, out)
	}
	p, err := loginAs(t, username, password)
	if err != nil {
		t.Fatal(err)
	}
	return &gateAdmin{portal: p, username: username, password: password,
		totp: &authflow.TOTP{Secret: base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(key)}}
}

// stepUp runs a step-up of the administrator's session. A step-up within Authentik's maximum auth age of the
// previous one may carry that login's auth_time, which Paddock refuses as too old; it is repeated once after the
// age has passed.
func (a *gateAdmin) stepUp(t *testing.T) {
	t.Helper()
	for attempt := 0; ; attempt++ {
		res, err := authflow.StepUp(testContext(t, 3*time.Minute), a.portal.Client, stack.AdminURL(), "/settings", a.username, a.password, a.totp, false)
		if err != nil {
			t.Fatalf("step-up of %s: %v", a.username, err)
		}
		if !strings.Contains(res.Final, "stepup=failed") {
			return
		}
		if attempt == 1 {
			t.Fatalf("step-up of %s returned to %s", a.username, res.Final)
		}
		time.Sleep(serverStepUp(t, a.portal).MaxAuthAge + time.Second)
	}
}

// revocationRequest is the part of a RevocationRequest the gates read.
type revocationRequest struct {
	ID        string          `json:"id"`
	Status    string          `json:"status"`
	Action    string          `json:"action"`
	Rejection string          `json:"rejection"`
	Result    json.RawMessage `json:"result"`
	Approvals []struct {
		Role string `json:"role"`
	} `json:"approvals"`
}

// revoke requests a Lock or Destroy of a device after a fresh step-up.
func (a *gateAdmin) revoke(t *testing.T, action string, d *devicesim.Device) revocationRequest {
	t.Helper()
	a.stepUp(t)
	res := call(t, a.portal, http.MethodPost, "/api/v1/devices/"+d.DeviceID+"/"+action,
		map[string]any{"confirm_hostname": getDevice(t, a.portal, d.DeviceID).Hostname, "reason": "gate " + action})
	expectStatus(t, res, http.StatusCreated, "")
	var r revocationRequest
	if err := res.JSON(&r); err != nil {
		t.Fatal(err)
	}
	return r
}

// waitRevocation polls the request list until the request is in one of the states.
func waitRevocation(t *testing.T, p *env.Portal, id string, timeout time.Duration, states ...string) revocationRequest {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		var page struct {
			Items []revocationRequest `json:"items"`
		}
		res := call(t, p, http.MethodGet, "/api/v1/revocation-requests?page_size=100", nil)
		expectStatus(t, res, http.StatusOK, "")
		if err := res.JSON(&page); err != nil {
			t.Fatal(err)
		}
		for _, r := range page.Items {
			if r.ID == id && (len(states) == 0 || containsString(states, r.Status)) {
				return r
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("revocation %s not in %v within %s: %+v", id, states, timeout, page.Items)
		}
		time.Sleep(time.Second)
	}
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// revocationEnvelope checks in until the device is handed a revocation token and returns it, verified with the
// revocation keys of the device's enrollment configuration (its pinned trust anchor).
func revocationEnvelope(t *testing.T, d *devicesim.Device, timeout time.Duration) (*revocation.Token, []byte) {
	t.Helper()
	keys := make([]revocation.Key, len(d.Config.RevocationKeys))
	for i, k := range d.Config.RevocationKeys {
		keys[i] = revocation.Key{KeyID: k.KeyID, PublicKey: k.PublicKey}
	}
	trust, err := revocation.TrustFromKeys(keys)
	if err != nil {
		t.Fatalf("enrollment configuration without revocation keys: %v", err)
	}
	var env []byte
	checkinUntil(t, d, timeout, func(out protocol.CheckinResponse) bool {
		for _, c := range out.Commands {
			if revocation.IsRevocation(c) {
				env = c
				return true
			}
		}
		return false
	})
	tok, err := revocation.Verify(env, trust, d.DeviceID, time.Now())
	if err != nil {
		t.Fatalf("revocation token: %v", err)
	}
	return tok, env
}

// ownerDB connects as paddock_owner: the gates that play a compromised api or database write with it.
func ownerDB(t *testing.T) *pgx.Conn {
	t.Helper()
	dsn, err := stack.PaddockOwnerDSN()
	if err != nil {
		t.Fatal(err)
	}
	conn, err := pgx.Connect(testContext(t, time.Minute), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close(context.Background()) })
	return conn
}

// TestRevocationLockAndDestroy is gate R2 and the server side of R1 (plan M4c decisions 7–10, AC1, AC2): a Lock is
// approved with its request, issued for the device only, confirmed by the device and keeps the escrow; a Destroy
// needs a second administrator — the requester cannot approve it — and its issuance deletes every escrowed header
// version and every recovery key and header row, after which the recovery endpoints answer 404.
func TestRevocationLockAndDestroy(t *testing.T) {
	slug, org := gateOrganization(t)
	a1, a2 := newGateAdmin(t, slug), newGateAdmin(t, slug)

	locked, _, _ := diskDevice(t, a1.portal)
	lock := a1.revoke(t, "lock", locked)
	if lock.Status != "approved" || len(lock.Approvals) != 1 {
		t.Fatalf("lock request %+v", lock)
	}
	tok, _ := revocationEnvelope(t, locked, 2*time.Minute)
	if tok.Action != revocation.ActionLock || tok.RequestID != lock.ID || tok.OrganizationID != org.String() {
		t.Fatalf("lock token %+v", tok)
	}
	waitRevocation(t, a1.portal, lock.ID, time.Minute, "delivered")
	confirmation, err := locked.CommandResult(testContext(t, time.Minute), tok.CommandID, protocol.CommandSucceeded,
		json.RawMessage(`{"erased":true,"slots_before":2,"slots_after":0}`))
	if err != nil || confirmation.Status != http.StatusAccepted {
		t.Fatalf("confirmation: %v HTTP %d %s", err, confirmation.Status, confirmation.Body)
	}
	confirmed := waitRevocation(t, a1.portal, lock.ID, time.Minute, "confirmed")
	if !strings.Contains(string(confirmed.Result), `"slots_after":0`) {
		t.Fatalf("confirmed result %s", confirmed.Result)
	}
	idx := auditIndex(t)
	expectOneIndexEvent(t, idx, org, "code = 'device.revocation_confirmed' AND params->>'request_id' = $1", lock.ID,
		"device.revocation_confirmed", "success", auditPollTimeout)
	// Lock keeps the escrow: the device stays restorable.
	var disk struct {
		RecoveryKeys []any `json:"recovery_keys"`
		Headers      []any `json:"headers"`
	}
	if err := call(t, a1.portal, http.MethodGet, "/api/v1/devices/"+locked.DeviceID+"/disk", nil).JSON(&disk); err != nil ||
		len(disk.RecoveryKeys) != 1 || len(disk.Headers) != 1 {
		t.Fatalf("escrow after a Lock %+v %v", disk, err)
	}

	destroyed, _, _ := diskDevice(t, a1.portal)
	hostname := getDevice(t, a1.portal, destroyed.DeviceID).Hostname
	headers := "org/" + org.String() + "/devices/" + destroyed.DeviceID + "/luks-header/"
	if n := escrowVersions(t, headers); n == 0 {
		t.Fatal("no escrowed header object before the Destroy")
	}
	destroy := a1.revoke(t, "destroy", destroyed)
	if destroy.Status != "requested" {
		t.Fatalf("destroy request %+v", destroy)
	}
	approve := "/api/v1/revocation-requests/" + destroy.ID + "/approve"
	a1.stepUp(t)
	res := call(t, a1.portal, http.MethodPost, approve, map[string]any{"confirm_hostname": hostname})
	expectStatus(t, res, http.StatusForbidden, "forbidden")
	expectOneEvent(t, a1.portal, res.RequestID, "revocation.approved", "denied")
	a2.stepUp(t)
	res = call(t, a2.portal, http.MethodPost, approve, map[string]any{"confirm_hostname": hostname})
	expectStatus(t, res, http.StatusOK, "")
	issued := waitRevocation(t, a1.portal, destroy.ID, 2*time.Minute, "issued", "delivered")
	if len(issued.Approvals) != 2 {
		t.Fatalf("approvals %+v", issued.Approvals)
	}
	expectOneIndexEvent(t, idx, org, "code = 'device.escrow_destroyed' AND params->>'request_id' = $1", destroy.ID,
		"device.escrow_destroyed", "success", auditPollTimeout)
	if err := call(t, a1.portal, http.MethodGet, "/api/v1/devices/"+destroyed.DeviceID+"/disk", nil).JSON(&disk); err != nil ||
		len(disk.RecoveryKeys) != 0 || len(disk.Headers) != 0 {
		t.Fatalf("escrow after a Destroy %+v %v", disk, err)
	}
	if n := escrowVersions(t, headers); n != 0 {
		t.Fatalf("%d header object versions after a Destroy", n)
	}
	a1.stepUp(t)
	for _, verb := range []string{"recovery-key", "header"} {
		res := call(t, a1.portal, http.MethodPost, "/api/v1/devices/"+destroyed.DeviceID+"/disk/"+verb, map[string]any{"confirm_hostname": hostname})
		expectStatus(t, res, http.StatusNotFound, "not_found")
	}
	tok, _ = revocationEnvelope(t, destroyed, time.Minute)
	if tok.Action != revocation.ActionDestroy {
		t.Fatalf("destroy token %+v", tok)
	}
}

// escrowVersions counts the object versions and delete markers below prefix in the escrow bucket, listed with the
// root credential from a container on the control-plane network (the bucket has no published port).
func escrowVersions(t *testing.T, prefix string) int {
	t.Helper()
	image, err := stack.Image("AWS_CLI_IMAGE")
	if err != nil {
		t.Fatal(err)
	}
	creds := mustSecret(t, "rustfs_root_user") + "\n" + mustSecret(t, "rustfs_root_password") + "\n"
	script := `read -r AWS_ACCESS_KEY_ID; read -r AWS_SECRET_ACCESS_KEY; export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY; ` +
		`aws --endpoint-url http://rustfs:9000 s3api list-object-versions --bucket paddock-escrow --prefix "$1" --output json`
	out, err := stack.Docker(testContext(t, 2*time.Minute), strings.NewReader(creds), "run", "--rm", "-i", "--network", "paddock_cp",
		"-e", "AWS_DEFAULT_REGION=us-east-1", "-e", "AWS_PAGER=", "--entrypoint", "sh", image, "-c", script, "sh", prefix)
	if err != nil {
		t.Fatalf("list object versions: %v %s", err, out)
	}
	if strings.TrimSpace(out) == "" {
		return 0
	}
	var versions struct {
		Versions      []any `json:"Versions"`
		DeleteMarkers []any `json:"DeleteMarkers"`
	}
	if err := json.Unmarshal([]byte(out), &versions); err != nil {
		t.Fatalf("list object versions: %v %s", err, out)
	}
	return len(versions.Versions) + len(versions.DeleteMarkers)
}

// TestRevocationLimits is gate R3 (ADR 0014, AC3): the fourth Lock within an hour of one administrator is rejected,
// audited as revocation.limit_exceeded and freezes the administrator for 24 h; the organization limit applies
// likewise; the issuer refuses approvals a compromised api or database forged — a token signed by another key, a
// stale auth_time and a token that proved another request.
func TestRevocationLimits(t *testing.T) {
	slug, org := gateOrganization(t)
	a1, a2 := newGateAdmin(t, slug), newGateAdmin(t, slug)
	idx := auditIndex(t)
	var first revocationRequest
	for i := range 3 {
		r := a1.revoke(t, "lock", activeDevice(t, a1.portal, "", "rv-"+uniqueSuffix()))
		waitRevocation(t, a1.portal, r.ID, time.Minute, "issued", "delivered")
		if i == 0 {
			first = r
		}
	}
	fourth := a1.revoke(t, "lock", activeDevice(t, a1.portal, "", "rv-"+uniqueSuffix()))
	if r := waitRevocation(t, a1.portal, fourth.ID, time.Minute, "rejected"); r.Rejection != "limit_admin_hour" {
		t.Fatalf("fourth lock %+v", r)
	}
	ev := expectOneIndexEvent(t, idx, org, "code = 'revocation.limit_exceeded' AND params->>'request_id' = $1", fourth.ID,
		"revocation.limit_exceeded", "denied", auditPollTimeout)
	if ev.Params["reason"] != "limit_admin_hour" || ev.Params["frozen_until"] == nil {
		t.Fatalf("limit event params %v", ev.Params)
	}
	// Frozen: the api refuses the administrator's next request at once.
	a1.stepUp(t)
	d := activeDevice(t, a1.portal, "", "rv-"+uniqueSuffix())
	res := call(t, a1.portal, http.MethodPost, "/api/v1/devices/"+d.DeviceID+"/lock",
		map[string]any{"confirm_hostname": getDevice(t, a1.portal, d.DeviceID).Hostname})
	expectStatus(t, res, http.StatusForbidden, "revocation_frozen")
	expectOneEvent(t, a1.portal, res.RequestID, "revocation.requested", "denied")

	db := ownerDB(t)
	ctx := testContext(t, 10*time.Minute)
	var a1ID string
	if err := db.QueryRow(ctx, "SELECT requested_by FROM revocation_request WHERE id = $1", first.ID).Scan(&a1ID); err != nil {
		t.Fatal(err)
	}

	// Forged approvals, written as a compromised database would: the issuer's round picks approved requests up.
	var realToken, realJTI, realSubject string
	var realApproved time.Time
	if err := db.QueryRow(ctx, `SELECT stepup_id_token, stepup_jti, subject, approved_at FROM revocation_approval WHERE request_id = $1`,
		first.ID).Scan(&realToken, &realJTI, &realSubject, &realApproved); err != nil {
		t.Fatal(err)
	}
	forge := func(token, jti string, approvedAt time.Time) string {
		dev := activeDevice(t, a1.portal, "", "rv-"+uniqueSuffix())
		id := uuid.Must(uuid.NewV7()).String()
		if _, err := db.Exec(ctx, `INSERT INTO revocation_request (id, organization_id, device_id, action, status, requested_by, approved_at)
			VALUES ($1, $2, $3, 'lock', 'approved', $4, $5)`, id, org, dev.DeviceID, a1ID, approvedAt); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(ctx, `INSERT INTO revocation_approval (request_id, organization_id, role, admin_id, subject, stepup_jti,
			stepup_id_token, approved_at) VALUES ($1, $2, 'requester', $3, $4, $5, $6, $7)`, id, org, a1ID, realSubject, jti, token, approvedAt); err != nil {
			t.Fatal(err)
		}
		return id
	}
	forged := forgedStepUpToken(t, realToken)
	cases := map[string]string{
		"token signed by another key": forge(forged, stepUpClaimString(t, forged, "jti"), time.Now()),
		// More than the step-up window (development: 30 s) after the token's authentication.
		"stale auth_time": forge(realToken, "stale-"+uniqueSuffix(), time.Now()),
	}
	// The token moved from the request it proved to another one: the database cannot tell (one row per jti), the
	// issuer remembers which request the token proved.
	if _, err := db.Exec(ctx, "DELETE FROM revocation_approval WHERE request_id = $1", first.ID); err != nil {
		t.Fatal(err)
	}
	cases["token that proved another request"] = forge(realToken, realJTI, realApproved)
	for name, id := range cases {
		r := waitRevocation(t, a1.portal, id, 3*time.Minute, "rejected", "issued")
		if r.Status != "rejected" || r.Rejection != "stepup_invalid" {
			t.Errorf("%s: %+v", name, r)
		}
		expectOneIndexEvent(t, idx, org, "code = 'revocation.issue_refused' AND params->>'request_id' = $1", id,
			"revocation.issue_refused", "denied", auditPollTimeout)
	}

	// Organization: 20 issued in 24 h (a1's 3 and 17 more), so a2's first Lock is the 21st.
	other := activeDevice(t, a1.portal, "", "rv-"+uniqueSuffix())
	if _, err := db.Exec(ctx, `INSERT INTO revocation_request (id, organization_id, device_id, action, status, requested_by, issued_at,
		expires_at, finished_at) SELECT gen_random_uuid(), $1, $2, 'lock', 'confirmed', $3, now() - interval '2 hours',
		now() + interval '28 days', now() - interval '1 hour' FROM generate_series(1, 17)`, org, other.DeviceID, a1ID); err != nil {
		t.Fatal(err)
	}
	r := a2.revoke(t, "lock", activeDevice(t, a2.portal, "", "rv-"+uniqueSuffix()))
	if r := waitRevocation(t, a2.portal, r.ID, time.Minute, "rejected"); r.Rejection != "limit_organization_day" {
		t.Fatalf("21st revocation of the organization %+v", r)
	}
}

// stepUpClaimString returns a string claim of an ID token without verifying it.
func stepUpClaimString(t *testing.T, raw, claim string) string {
	t.Helper()
	parts := strings.Split(raw, ".")
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}
	s, _ := claims[claim].(string)
	return s
}

// TestRevocationDisabled is gate R5 (plan M4c decision 1, AC5): with PADDOCK_REVOCATION_ENABLED=false the endpoints
// answer 403 revocation_disabled (audited as denied), the issuer refuses to sign and bundles say
// revocation.enabled=false.
func TestRevocationDisabled(t *testing.T) {
	ctx := testContext(t, 15*time.Minute)
	services := []string{"paddock-api", "paddock-compiler", "paddock-revocation-issuer"}
	recreate := func(env []string) {
		if _, err := stack.Compose(ctx, env, append([]string{"--profile", "paddock", "up", "-d", "--no-deps"}, services...)...); err != nil {
			t.Fatal(err)
		}
		if err := stack.WaitHealthy(ctx); err != nil {
			t.Fatal(err)
		}
	}
	slug, org := gateOrganization(t)
	a1 := newGateAdmin(t, slug)
	d := activeDevice(t, a1.portal, "", "rv-"+uniqueSuffix())
	d.SchemaVersions = []int{bundle.SchemaVersion, bundle.SchemaVersion2}
	if b := latestBundle(t, d, 2*time.Minute, func(b *bundle.Bundle) bool { return b.Revocation != nil }); !b.Revocation.Enabled {
		t.Fatal("revocation.enabled is false while the flag is on")
	}

	t.Cleanup(func() { recreate(nil) })
	recreate([]string{"PADDOCK_REVOCATION_ENABLED=false"})
	// Sign in again: the restarted api lost no sessions (cookies are sealed), but the gate wants a fresh step-up.
	a1.stepUp(t)
	hostname := getDevice(t, a1.portal, d.DeviceID).Hostname
	for _, path := range []string{"/api/v1/devices/" + d.DeviceID + "/lock", "/api/v1/devices/" + d.DeviceID + "/destroy"} {
		res := call(t, a1.portal, http.MethodPost, path, map[string]any{"confirm_hostname": hostname})
		expectStatus(t, res, http.StatusForbidden, "revocation_disabled")
		expectOneEvent(t, a1.portal, res.RequestID, "revocation.requested", "denied")
	}

	// The issuer refuses an approved request, even one with a valid-looking approval.
	db := ownerDB(t)
	var admin string
	if err := db.QueryRow(ctx, "SELECT id FROM admin_account WHERE organization_id = $1 LIMIT 1", org).Scan(&admin); err != nil {
		t.Fatal(err)
	}
	id := uuid.Must(uuid.NewV7()).String()
	if _, err := db.Exec(ctx, `INSERT INTO revocation_request (id, organization_id, device_id, action, status, requested_by, approved_at)
		VALUES ($1, $2, $3, 'lock', 'approved', $4, now())`, id, org, d.DeviceID, admin); err != nil {
		t.Fatal(err)
	}
	if r := waitRevocation(t, a1.portal, id, 3*time.Minute, "rejected", "issued"); r.Status != "rejected" || r.Rejection != "revocation_disabled" {
		t.Fatalf("issuer with the flag off: %+v", r)
	}
	if b := latestBundle(t, d, 3*time.Minute, func(b *bundle.Bundle) bool { return b.Revocation != nil && !b.Revocation.Enabled }); b == nil {
		t.Fatal("no bundle with revocation.enabled=false")
	}
}

// revocationRequestCases are the A3 cases of POST /api/v1/devices/{id}/<verb> (lock, destroy). Successful requests
// run in a gate organization, so the A3 gate never counts against the limits of the dev users.
func revocationRequestCases(verb string) []auditCase {
	const code = "revocation.requested"
	path := func(id string) string { return "/api/v1/devices/" + id + "/" + verb }
	return []auditCase{
		{"success", func(t *testing.T, _ *auditWorld) {
			slug, _ := gateOrganization(t)
			a := newGateAdmin(t, slug)
			d := activeDevice(t, a.portal, "", "a3-revoke-"+uniqueSuffix())
			a.stepUp(t)
			res := call(t, a.portal, http.MethodPost, path(d.DeviceID), map[string]any{"confirm_hostname": getDevice(t, a.portal, d.DeviceID).Hostname})
			expectStatus(t, res, http.StatusCreated, "")
			expectOneEvent(t, a.portal, res.RequestID, code, "success")
		}},
		{"no step-up", func(t *testing.T, w *auditWorld) {
			res := call(t, login(t, env.Alice), http.MethodPost, path(activeID(t, w)), map[string]any{"confirm_hostname": "x"})
			expectStatus(t, res, http.StatusForbidden, "step_up_required")
			expectOneEvent(t, w.alice, res.RequestID, code, "denied")
		}},
		{"wrong role", func(t *testing.T, w *auditWorld) {
			res := call(t, w.bob, http.MethodPost, path(activeID(t, w)), map[string]any{"confirm_hostname": "x"})
			expectStatus(t, res, http.StatusForbidden, "forbidden")
			expectOneEvent(t, w.alice, res.RequestID, code, "denied")
		}},
		{"not found", func(t *testing.T, w *auditWorld) {
			alice := login(t, env.Alice)
			stepUp(t, alice, env.Alice, true)
			res := call(t, alice, http.MethodPost, path(uuid.NewString()), map[string]any{"confirm_hostname": "x"})
			expectStatus(t, res, http.StatusNotFound, "not_found")
			expectOneEvent(t, w.alice, res.RequestID, code, "failure")
		}},
		{"validation failure", func(t *testing.T, w *auditWorld) {
			alice := login(t, env.Alice)
			id := activeID(t, w)
			stepUp(t, alice, env.Alice, true)
			res := call(t, alice, http.MethodPost, path(id), map[string]any{"confirm_hostname": "not-" + uniqueSuffix()})
			expectStatus(t, res, http.StatusBadRequest, "invalid_request")
			expectOneEvent(t, w.alice, res.RequestID, code, "failure")
		}},
	}
}

// pendingDestroy creates a gate organization with two administrators and a Destroy of the first that waits for its
// approval.
func pendingDestroy(t *testing.T) (a1, a2 *gateAdmin, id, hostname string) {
	t.Helper()
	slug, _ := gateOrganization(t)
	a1, a2 = newGateAdmin(t, slug), newGateAdmin(t, slug)
	d := activeDevice(t, a1.portal, "", "a3-destroy-"+uniqueSuffix())
	return a1, a2, a1.revoke(t, "destroy", d).ID, getDevice(t, a1.portal, d.DeviceID).Hostname
}

// revocationReviewCases are the A3 cases of POST /api/v1/revocation-requests/{id}/<verb> (approve, reject, cancel).
func revocationReviewCases(verb, code string) []auditCase {
	path := func(id string) string { return "/api/v1/revocation-requests/" + id + "/" + verb }
	// actor is who may run verb: the second administrator approves or rejects, the requester cancels.
	actor := func(a1, a2 *gateAdmin) *gateAdmin {
		if verb == "cancel" {
			return a1
		}
		return a2
	}
	return []auditCase{
		{"success", func(t *testing.T, _ *auditWorld) {
			a1, a2, id, hostname := pendingDestroy(t)
			a := actor(a1, a2)
			a.stepUp(t)
			res := call(t, a.portal, http.MethodPost, path(id), map[string]any{"confirm_hostname": hostname})
			expectStatus(t, res, http.StatusOK, "")
			expectOneEvent(t, a.portal, res.RequestID, code, "success")
		}},
		{"conflict", func(t *testing.T, _ *auditWorld) {
			a1, a2, id, hostname := pendingDestroy(t)
			a1.stepUp(t)
			expectStatus(t, call(t, a1.portal, http.MethodPost, "/api/v1/revocation-requests/"+id+"/cancel",
				map[string]any{"confirm_hostname": hostname}), http.StatusOK, "")
			a := actor(a1, a2)
			a.stepUp(t)
			res := call(t, a.portal, http.MethodPost, path(id), map[string]any{"confirm_hostname": hostname})
			expectStatus(t, res, http.StatusConflict, "invalid_state")
			expectOneEvent(t, a.portal, res.RequestID, code, "failure")
		}},
		{"no step-up", func(t *testing.T, w *auditWorld) {
			res := call(t, login(t, env.Alice), http.MethodPost, path(uuid.NewString()), map[string]any{"confirm_hostname": "x"})
			expectStatus(t, res, http.StatusForbidden, "step_up_required")
			expectOneEvent(t, w.alice, res.RequestID, code, "denied")
		}},
		{"wrong role", func(t *testing.T, w *auditWorld) {
			res := call(t, w.bob, http.MethodPost, path(uuid.NewString()), map[string]any{"confirm_hostname": "x"})
			expectStatus(t, res, http.StatusForbidden, "forbidden")
			expectOneEvent(t, w.alice, res.RequestID, code, "denied")
		}},
		{"not found", func(t *testing.T, w *auditWorld) {
			alice := login(t, env.Alice)
			stepUp(t, alice, env.Alice, true)
			res := call(t, alice, http.MethodPost, path(uuid.NewString()), map[string]any{"confirm_hostname": "x"})
			expectStatus(t, res, http.StatusNotFound, "not_found")
			expectOneEvent(t, w.alice, res.RequestID, code, "failure")
		}},
	}
}

func init() {
	deviceAuditCases["POST /api/v1/devices/{id}/lock"] = revocationRequestCases("lock")
	deviceAuditCases["POST /api/v1/devices/{id}/destroy"] = revocationRequestCases("destroy")
	deviceAuditCases["POST /api/v1/revocation-requests/{id}/approve"] = revocationReviewCases("approve", "revocation.approved")
	deviceAuditCases["POST /api/v1/revocation-requests/{id}/reject"] = revocationReviewCases("reject", "revocation.rejected")
	deviceAuditCases["POST /api/v1/revocation-requests/{id}/cancel"] = revocationReviewCases("cancel", "revocation.cancelled")
}

// dmsCases are the A3 cases of PUT /api/v1/settings/dms. They never turn acme's switch on: success turns it off (no
// step-up needed), and turning it on without a step-up is denied before anything changes.
func dmsCases() []auditCase {
	const path = "/api/v1/settings/dms"
	body := func(enabled bool, period int) map[string]any {
		return map[string]any{"enabled": enabled, "period_days": period, "warn_days": []int{3, 1}}
	}
	return []auditCase{
		{"success", func(t *testing.T, w *auditWorld) {
			res := call(t, w.alice, http.MethodPut, path, body(false, 30))
			expectStatus(t, res, http.StatusOK, "")
			expectOneEvent(t, w.alice, res.RequestID, "settings.dms_changed", "success")
		}},
		{"validation failure", func(t *testing.T, w *auditWorld) {
			res := call(t, w.alice, http.MethodPut, path, body(false, 400))
			expectStatus(t, res, http.StatusBadRequest, "invalid_request")
			expectOneEvent(t, w.alice, res.RequestID, "settings.dms_changed", "failure")
		}},
		{"no step-up", func(t *testing.T, w *auditWorld) {
			res := call(t, login(t, env.Alice), http.MethodPut, path, body(true, 30))
			expectStatus(t, res, http.StatusForbidden, "step_up_required")
			expectOneEvent(t, w.alice, res.RequestID, "settings.dms_changed", "denied")
		}},
		{"wrong role", func(t *testing.T, w *auditWorld) {
			res := call(t, w.bob, http.MethodPut, path, body(false, 30))
			expectStatus(t, res, http.StatusForbidden, "forbidden")
			expectOneEvent(t, w.alice, res.RequestID, "settings.dms_changed", "denied")
		}},
	}
}

func init() { deviceAuditCases["PUT /api/v1/settings/dms"] = dmsCases() }
