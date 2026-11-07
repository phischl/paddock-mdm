package acceptance

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/test/acceptance/internal/env"
	"github.com/phischl/paddock-mdm/test/acceptance/internal/stack"
)

// The backup gates (plan M15 §9 B1–B7) run against `make up BACKUP=1` after `make dev-seed BACKUP=1`. The backup key,
// the schedule and the restore plans are platform-wide singletons, so the gates are sequential top-level tests: no
// t.Parallel, and each gate brings the singleton into the state it starts from.

// TestBackupKeyConfirmation is gate B1: without an active key no backup runs; a generated key is shown once, refused
// with wrong characters (audited, discarded after three), and active after the right ones.
func TestBackupKeyConfirmation(t *testing.T) {
	requireBackupStack(t)
	start := time.Now()
	a := newBackupAdmin(t)
	idx := auditIndex(t)

	// API tokens are organization-scoped, so the platform route refuses them as forbidden before the step-up rule
	// would (PDK-730, TestBackupKeyEndpointsRefuseOthers); §9 B1's step_up_required is the step-up rule's own refusal.
	acme := adminUser(t, "bkey")
	res := postAPIToken(t, acme.Portal, apiTokenName("backup key"), "org_admin", 2*time.Hour)
	expectStatus(t, res, http.StatusCreated, "")
	var tok apiTokenCreated
	if err := res.JSON(&tok); err != nil {
		t.Fatal(err)
	}
	token := tokenPortal(t, tok.Secret)
	expectStatus(t, call(t, token, http.MethodGet, backupKeyPath, nil), http.StatusForbidden, "forbidden")
	expectStatus(t, call(t, token, http.MethodPost, backupKeyPath, nil), http.StatusForbidden, "forbidden")

	// No API leaves the active key: retiring it in the database is the state of an installation before its first
	// confirmation, which the role and the run request see the same way (no confirmed key).
	conn := ownerConn(t)
	ctx := testContext(t, time.Minute)
	if _, err := conn.Exec(ctx, `UPDATE backup_key SET state = 'retired', retired_at = now() WHERE state = 'confirmed'`); err != nil {
		t.Fatalf("retire the active key: %v", err)
	}
	if _, err := conn.Exec(ctx, `UPDATE backup_key SET state = 'discarded' WHERE state = 'unconfirmed'`); err != nil {
		t.Fatalf("discard the pending key: %v", err)
	}
	t.Run("no key, no backup", func(t *testing.T) {
		res := call(t, a.fresh(t), http.MethodPost, backupRunPath, map[string]any{"kinds": []string{"openbao"}})
		expectStatus(t, res, http.StatusConflict, "invalid_state")
		waitKeyConfirmedMetric(t, 0)
	})

	g, res := generateBackupKey(t, a)
	t.Run("generated key", func(t *testing.T) {
		raw, err := base64.StdEncoding.DecodeString(g.Key)
		if len(g.Key) != 44 || err != nil || len(raw) != 32 {
			t.Fatalf("key text of %d characters (%d bytes, %v), want 44 base64 characters of 32 bytes", len(g.Key), len(raw), err)
		}
		if len(g.Positions) != 6 || !slices.IsSorted(g.Positions) || len(slices.Compact(slices.Clone(g.Positions))) != 6 ||
			g.Positions[0] < 1 || g.Positions[5] > 44 {
			t.Fatalf("positions %v, want six distinct ascending positions in [1, 44]", g.Positions)
		}
		if g.Fingerprint != keyFingerprint(t, g.Key) || g.DownloadName == "" {
			t.Fatalf("fingerprint %q (want %q), download name %q", g.Fingerprint, keyFingerprint(t, g.Key), g.DownloadName)
		}
		if !strings.Contains(res.Header.Get("Cache-Control"), "no-store") {
			t.Fatalf("Cache-Control %q, want no-store", res.Header.Get("Cache-Control"))
		}
		ev := expectOneIndexEvent(t, idx, platformOrg, "correlation_id = $1", res.RequestID, "platform.backup_key_generated", "success", auditPollTimeout)
		if ev.Params["key_id"] != g.KeyID || ev.Params["fingerprint"] != g.Fingerprint {
			t.Fatalf("event params %v", ev.Params)
		}
		expectParamsWithout(t, ev, g.Key)
		expectStatus(t, call(t, a.fresh(t), http.MethodPost, backupKeyPath, nil), http.StatusConflict, "invalid_state")
		s, res := getBackupKeyStatus(t, a.Portal)
		if s.Pending == nil || s.Pending.KeyID != g.KeyID || s.Pending.State != "unconfirmed" || !slices.Equal(s.Pending.Positions, g.Positions) {
			t.Fatalf("pending key %+v, want %s unconfirmed with the positions %v", s.Pending, g.KeyID, g.Positions)
		}
		expectNoSecretIn(t, "GET /backup/key", res.Body, g.Key)
	})

	right := challengeAnswer(t, g.Key, g.Positions)
	t.Run("three wrong confirmations", func(t *testing.T) {
		for attempt := 1; attempt <= 3; attempt++ {
			res := confirmBackupKey(t, a, g.KeyID, wrongAnswer(right))
			expectStatus(t, res, http.StatusConflict, "backup_key_mismatch")
			detail := problemDetail(t, res)
			want := "attempts_left=" + strconv.Itoa(3-attempt)
			if attempt == 3 {
				want = "discarded"
			}
			if !strings.Contains(detail, want) {
				t.Fatalf("attempt %d: detail %q, want %q", attempt, detail, want)
			}
			ev := expectOneIndexEvent(t, idx, platformOrg, "correlation_id = $1", res.RequestID, "platform.backup_key_confirmed", "failure", auditPollTimeout)
			if ev.Params["attempts"] != float64(attempt) {
				t.Fatalf("attempt %d: event params %v", attempt, ev.Params)
			}
		}
		expectStatus(t, confirmBackupKey(t, a, g.KeyID, right), http.StatusConflict, "invalid_state")
		if s, _ := getBackupKeyStatus(t, a.Portal); s.Pending != nil || s.Active != nil {
			t.Fatalf("after three mismatches: active %+v, pending %+v; want neither", s.Active, s.Pending)
		}
	})

	t.Run("confirmed with the right characters", func(t *testing.T) {
		g, _ := generateBackupKey(t, a)
		res := confirmBackupKey(t, a, g.KeyID, challengeAnswer(t, g.Key, g.Positions))
		expectStatus(t, res, http.StatusOK, "")
		ev := expectOneIndexEvent(t, idx, platformOrg, "correlation_id = $1", res.RequestID, "platform.backup_key_confirmed", "success", auditPollTimeout)
		if ev.Params["key_id"] != g.KeyID || ev.Params["rotated_from"] != nil {
			t.Fatalf("event params %v, want key_id %s without rotated_from", ev.Params, g.KeyID)
		}
		expectParamsWithout(t, ev, g.Key)
		s, res := getBackupKeyStatus(t, a.Portal)
		if s.Active == nil || s.Active.KeyID != g.KeyID || s.Active.State != "confirmed" || s.Active.ConfirmedAt == nil || s.Active.Positions != nil {
			t.Fatalf("active key %+v, want %s confirmed without positions", s.Active, g.KeyID)
		}
		expectNoSecretIn(t, "GET /backup/key", res.Body, g.Key)
		overview := call(t, a.Portal, http.MethodGet, backupOverviewPath, nil)
		expectStatus(t, overview, http.StatusOK, "")
		expectNoSecretIn(t, "GET /backup", overview.Body, g.Key)
		waitKeyConfirmedMetric(t, 1)
	})
	expectSecretsNotLogged(t, start, knownBackupSecrets()...)
}

// TestBackupTargets is gate B2: local and S3 targets are created, listed by the list contract, updated without losing
// the stored secret and tested by the backup role; no secret appears in a response, an audit event or a log.
func TestBackupTargets(t *testing.T) {
	requireBackupStack(t)
	start := time.Now()
	a := newBackupAdmin(t)
	idx := auditIndex(t)
	access, secret := mustSecret(t, "backup_dev_target_access_key"), mustSecret(t, "backup_dev_target_secret_key")
	wrong := "wrong" + uniqueSuffix() + uniqueSuffix()
	for _, s := range []string{access, secret, wrong} {
		rememberBackupSecret(s)
	}
	secrets := []string{access, secret, wrong}
	suffix := uniqueSuffix()

	// The gate's targets stay disabled: the role tests every target, but mirrors only enabled ones, so B3's mirror
	// counts are not disturbed.
	s3Body := func(name, prefix, secretKey string) map[string]any {
		return map[string]any{"name": name, "type": "s3", "enabled": false, "s3": map[string]any{
			"endpoint": "http://audit-rustfs:9000", "bucket": devS3Bucket, "prefix": prefix, "access_key": access, "secret_key": secretKey}}
	}
	create := func(t *testing.T, body map[string]any) backupTarget {
		t.Helper()
		res := call(t, a.fresh(t), http.MethodPost, backupTargets, body)
		expectStatus(t, res, http.StatusCreated, "")
		expectNoSecretIn(t, "POST /backup/targets", res.Body, secrets...)
		var target backupTarget
		if err := res.JSON(&target); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			res := call(t, a.fresh(t), http.MethodDelete, backupTargets+"/"+target.ID, nil)
			if res.Status != http.StatusNoContent && res.Status != http.StatusNotFound {
				t.Errorf("delete backup target %s: HTTP %d %s", target.Name, res.Status, res.Body)
			}
		})
		ev := expectOneIndexEvent(t, idx, platformOrg, "correlation_id = $1", res.RequestID, "platform.backup_target_created", "success", auditPollTimeout)
		expectParamsWithout(t, ev, secrets...)
		return target
	}
	s3 := create(t, s3Body("b2 s3 "+suffix, "b2-"+suffix, secret))
	local := create(t, map[string]any{"name": "b2 local " + suffix, "type": "local", "enabled": false,
		"local": map[string]any{"path": "b2-" + suffix}})
	if s3.HostState != "n/a" || !s3.HasCredentials || local.HostState != "pending_host" || local.HostRevision != 1 {
		t.Fatalf("created targets: s3 %+v, local %+v", s3, local)
	}

	t.Run("list contract", func(t *testing.T) {
		names := func(p backupTargetPage) []string {
			var out []string
			for _, it := range p.Items {
				out = append(out, it.Name)
			}
			slices.Sort(out)
			return out
		}
		for _, c := range []struct {
			query url.Values
			want  []string
		}{
			{url.Values{"q": {suffix}}, []string{local.Name, s3.Name}},
			{url.Values{"q": {suffix}, "type": {"s3"}}, []string{s3.Name}},
			{url.Values{"q": {suffix}, "host_state": {"pending_host"}}, []string{local.Name}},
			{url.Values{"q": {suffix}, "enabled": {"false"}}, []string{local.Name, s3.Name}},
			{url.Values{"q": {suffix}, "enabled": {"true"}}, nil},
		} {
			page := listBackupTargets(t, a.Portal, c.query)
			if got := names(page); !slices.Equal(got, c.want) || page.Total != len(c.want) {
				t.Errorf("%s: %v (total %d), want %v", c.query.Encode(), got, page.Total, c.want)
			}
		}
		page := listBackupTargets(t, a.Portal, url.Values{"q": {suffix}, "sort": {"-name"}})
		if page.Sort != "-name" || len(page.Items) != 2 || page.Items[0].Name != s3.Name {
			t.Errorf("sort=-name: %q %v", page.Sort, names(page))
		}
		expectStatus(t, call(t, a.Portal, http.MethodGet, backupTargets+"?page_size=7", nil), http.StatusBadRequest, "invalid_request")
	})

	t.Run("update keeps the secret", func(t *testing.T) {
		body := s3Body(s3.Name, "b2-updated-"+suffix, "")
		delete(body["s3"].(map[string]any), "access_key")
		delete(body["s3"].(map[string]any), "secret_key")
		res := call(t, a.fresh(t), http.MethodPut, backupTargets+"/"+s3.ID, body)
		expectStatus(t, res, http.StatusOK, "")
		expectNoSecretIn(t, "PUT /backup/targets/{id}", res.Body, secrets...)
		var updated backupTarget
		if err := res.JSON(&updated); err != nil || !updated.HasCredentials || updated.Settings.S3 == nil ||
			updated.Settings.S3.Prefix != "b2-updated-"+suffix {
			t.Fatalf("updated target %s (%v)", res.Body, err)
		}
		ev := expectOneIndexEvent(t, idx, platformOrg, "correlation_id = $1", res.RequestID, "platform.backup_target_updated", "success", auditPollTimeout)
		expectParamsWithout(t, ev, secrets...)
	})

	// requestTest asks the backup role for a connection test and waits for the result of this request (plan M15
	// decision 11: within 60 s).
	requestTest := func(t *testing.T, target backupTarget) backupTarget {
		t.Helper()
		requested := time.Now()
		res := call(t, a.fresh(t), http.MethodPost, backupTargets+"/"+target.ID+"/test", nil)
		expectStatus(t, res, http.StatusAccepted, "")
		expectOneIndexEvent(t, idx, platformOrg, "correlation_id = $1", res.RequestID, "platform.backup_target_tested", "success", auditPollTimeout)
		return waitBackupTarget(t, a.Portal, target.ID, 60*time.Second, "a test result", func(b backupTarget) bool {
			return b.TestRequestedAt == nil && b.LastTestAt != nil && b.LastTestAt.After(requested.Add(-2*time.Second)) && b.LastTestOK != nil
		})
	}
	t.Run("S3 test with the kept secret", func(t *testing.T) {
		if got := requestTest(t, s3); !*got.LastTestOK || got.LastTestError != nil {
			t.Fatalf("test result ok %v, error %v; want ok", *got.LastTestOK, got.LastTestError)
		}
	})
	t.Run("S3 test with a wrong secret key", func(t *testing.T) {
		bad := create(t, s3Body("b2 wrong "+suffix, "b2-wrong-"+suffix, wrong))
		got := requestTest(t, bad)
		if *got.LastTestOK || got.LastTestError == nil || *got.LastTestError != "auth" {
			t.Fatalf("test result ok %v, error %v; want auth", *got.LastTestOK, got.LastTestError)
		}
	})
	t.Run("local test before the host step", func(t *testing.T) {
		got := requestTest(t, local)
		if *got.LastTestOK || got.LastTestError == nil || *got.LastTestError != "not_mounted" {
			t.Fatalf("test result ok %v, error %v; want not_mounted", *got.LastTestOK, got.LastTestError)
		}
	})

	t.Run("private S3 endpoint", func(t *testing.T) {
		body := s3Body("b2 private "+suffix, "b2-private-"+suffix, secret)
		body["s3"].(map[string]any)["endpoint"] = "https://10.255.255.1:9000"
		res := call(t, a.fresh(t), http.MethodPost, backupTargets, body)
		if apiAllowsPrivate(t) {
			expectStatus(t, res, http.StatusCreated, "")
			expectStatus(t, call(t, a.fresh(t), http.MethodDelete, backupTargets+"/"+responseID(t, res).String(), nil), http.StatusNoContent, "")
		} else {
			expectStatus(t, res, http.StatusBadRequest, "invalid_request")
		}
		// User information stays refused with the development flag as well.
		body["s3"].(map[string]any)["endpoint"] = "https://user:pass@backup.example.com"
		expectStatus(t, call(t, a.fresh(t), http.MethodPost, backupTargets, body), http.StatusBadRequest, "invalid_request")
	})

	t.Run("no secret in any response", func(t *testing.T) {
		for _, id := range []string{s3.ID, local.ID} {
			_, res := getBackupTarget(t, a.Portal, id)
			expectNoSecretIn(t, "GET /backup/targets/{id}", res.Body, secrets...)
		}
		for _, path := range []string{backupTargets + "?page_size=100", backupOverviewPath} {
			res := call(t, a.Portal, http.MethodGet, path, nil)
			expectStatus(t, res, http.StatusOK, "")
			expectNoSecretIn(t, "GET "+path, res.Body, secrets...)
		}
	})
	expectSecretsNotLogged(t, start, append(secrets, knownBackupSecrets()...)...)
}

// apiAllowsPrivate reports whether the running api has the development flag PADDOCK_OUTBOUND_DEV_ALLOW_PRIVATE, which
// admits private S3 endpoints (backupset.Policy).
func apiAllowsPrivate(t *testing.T) bool {
	t.Helper()
	ctx := testContext(t, time.Minute)
	ids, err := stack.Docker(ctx, nil, "ps", "-q", "--filter", "label=com.docker.compose.project="+stack.Project(),
		"--filter", "label=com.docker.compose.service=paddock-api", "--filter", "label=com.docker.compose.oneoff=False")
	if err != nil || strings.TrimSpace(ids) == "" {
		t.Fatalf("finding paddock-api: %v", err)
	}
	envs, err := stack.Docker(ctx, nil, "inspect", "-f", "{{range .Config.Env}}{{println .}}{{end}}", strings.Fields(ids)[0])
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(envs, "\n")
	return slices.Contains(lines, "PADDOCK_OUTBOUND_DEV_ALLOW_PRIVATE=true") && slices.Contains(lines, "PADDOCK_ENV=development")
}

// expectParamsWithout fails when an audit event's params hold one of secrets or a credential field.
func expectParamsWithout(t *testing.T, ev env.IndexEvent, secrets ...string) {
	t.Helper()
	raw, err := json.Marshal(ev.Params)
	if err != nil {
		t.Fatal(err)
	}
	expectNoSecretIn(t, "audit event "+ev.Code, raw, secrets...)
}

// TestBackupRuns is gate B3: `backup now` for every kind backs up OpenBao, Fleet and the escrow bucket within three
// minutes, mirrors them to both development targets and records one platform.backup_completed per run.
func TestBackupRuns(t *testing.T) {
	requireBackupStack(t)
	start := time.Now()
	a := newBackupAdmin(t)
	idx := auditIndex(t)
	key := ensureActiveBackupKey(t, a)
	s3t, local := devBackupTarget(t, a.Portal, devS3Target), devBackupTarget(t, a.Portal, devLocalTarget)
	if !s3t.Enabled || !local.Enabled || local.HostState != "mounted" {
		t.Fatalf("development targets not ready (run `make dev-seed BACKUP=1`): s3 %+v, local %+v", s3t, local)
	}
	mirrored := 0
	for _, it := range listBackupTargets(t, a.Portal, url.Values{}).Items {
		if it.Enabled && (it.HostState == "mounted" || it.HostState == "n/a") {
			mirrored++
		}
	}

	alice := login(t, env.Alice)
	d, _, _ := diskDevice(t, alice)
	header := "/devices/" + d.DeviceID + "/luks-header/1.bin"

	requested := time.Now()
	label := "b3 " + uniqueSuffix()
	runs, res := requestBackupRuns(t, a, nil, label)
	expectOneIndexEvent(t, idx, platformOrg, "correlation_id = $1", res.RequestID, "platform.backup_run_requested", "success", auditPollTimeout)
	ids := map[string]string{}
	for _, r := range runs {
		ids[r.Kind] = r.ID
	}
	kinds := []string{"openbao", "fleet", "escrow"}
	var wait []string
	for _, k := range append(slices.Clone(kinds), "postgres", "authentik") {
		if ids[k] == "" {
			t.Fatalf("no run of kind %s requested: %+v", k, runs)
		}
	}
	for _, k := range kinds {
		wait = append(wait, ids[k])
	}
	done := waitBackupRunsMirrored(t, a.Portal, wait, 3*time.Minute)
	for _, k := range kinds {
		r := done[ids[k]]
		if r.Outcome == nil || *r.Outcome != "succeeded" || r.Label != label {
			t.Errorf("run %s: outcome %v, error %v, label %q", k, r.Outcome, r.ErrorClass, r.Label)
		}
		for _, target := range []backupTarget{s3t, local} {
			if !slices.ContainsFunc(r.Targets, func(rt backupRunTarget) bool { return rt.TargetID == target.ID && rt.OK }) {
				t.Errorf("run %s: target %s not mirrored: %+v", k, target.Name, r.Targets)
			}
		}
		ev := expectOneIndexEvent(t, idx, platformOrg, "params->>'run_id' = $1", ids[k], "platform.backup_completed", "success", auditPollTimeout)
		if ev.Params["kind"] != k || ev.Params["label"] != label || ev.Params["targets_ok"] != float64(mirrored) ||
			ev.Params["targets_failed"] != float64(0) {
			t.Errorf("run %s: event params %v, want targets_ok %d and targets_failed 0", k, ev.Params, mirrored)
		}
	}
	if t.Failed() {
		t.FailNow()
	}

	for _, target := range []backupTarget{s3t, local} {
		waitBackupTarget(t, a.Portal, target.ID, time.Minute, "a success of every run kind after the request", func(b backupTarget) bool {
			for _, k := range kinds {
				if b.lastSuccess(k).Before(requested) {
					return false
				}
			}
			return true
		})
	}
	m := waitTargetManifest(t, devTargetS3(t), time.Minute, "the active key and the device's header", func(m backupManifest) bool {
		return m.KeyID == key.KeyID && slices.ContainsFunc(m.Contents.Escrow, func(f backupFile) bool {
			return strings.HasPrefix(f.Path, "escrow/org/") && strings.HasSuffix(f.Path, header) && f.Bytes > 0
		})
	})
	if m.Schema != "paddock.backup-set.v1" || len(m.Contents.OpenBao) == 0 || len(m.Contents.Fleet) == 0 {
		t.Fatalf("manifest %s: %d OpenBao snapshots, %d Fleet dumps", m.Schema, len(m.Contents.OpenBao), len(m.Contents.Fleet))
	}
	expectSecretsNotLogged(t, start, append(knownBackupSecrets(),
		mustSecret(t, "backup_dev_target_access_key"), mustSecret(t, "backup_dev_target_secret_key"))...)
}

// fullLabel matches a full backup label of `pgbackrest info` (local time of the pgBackRest container, UTC).
var fullLabel = regexp.MustCompile(`(\d{8}-\d{6})F\b`)

// newestFull returns the time of the newest full backup that `pgbackrest info` of service lists in the repository path
// of the key in its state volume, and that path; ok is false while the command fails (no stanza yet).
func newestFull(t *testing.T, service string) (time.Time, string, bool) {
	t.Helper()
	ctx := testContext(t, 2*time.Minute)
	path, err := stack.ComposeBackup(ctx, nil, "exec", "-T", service, "cat", "/var/lib/pgbackrest/repo-path")
	if err != nil {
		return time.Time{}, "", false
	}
	info, err := stack.ComposeBackup(ctx, nil, "exec", "-T", service, "paddock-pgbackrest", "info")
	if err != nil {
		return time.Time{}, strings.TrimSpace(path), false
	}
	var newest time.Time
	for _, m := range fullLabel.FindAllStringSubmatch(info, -1) {
		if at, err := time.Parse("20060102-150405", m[1]); err == nil && at.After(newest) {
			newest = at
		}
	}
	return newest, strings.TrimSpace(path), !newest.IsZero()
}

// TestBackupRotation is gate B4: a second confirmed key retires the first, pgBackRest takes a full backup in the new
// key's repository path within one full interval (120 s on the development stack), and the old path stays.
func TestBackupRotation(t *testing.T) {
	requireBackupStack(t)
	a := newBackupAdmin(t)
	idx := auditIndex(t)
	client := devTargetS3(t)
	old := ensureActiveBackupKey(t, a)
	oldPath := "pgbackrest/" + old.KeyID
	// The old path must hold a mirrored full of both stanzas first: only then does "the old set stays" mean something.
	waitTargetManifest(t, client, 8*time.Minute, "a full of both stanzas in the active key's path", func(m backupManifest) bool {
		return m.KeyID == old.KeyID && m.Contents.PgBackRest.Path == oldPath && !m.lastFull("paddock").IsZero() &&
			!m.lastFull("authentik").IsZero()
	})

	g, _ := generateBackupKey(t, a)
	res := confirmBackupKey(t, a, g.KeyID, challengeAnswer(t, g.Key, g.Positions))
	expectStatus(t, res, http.StatusOK, "")
	confirmed := time.Now()
	ev := expectOneIndexEvent(t, idx, platformOrg, "correlation_id = $1", res.RequestID, "platform.backup_key_confirmed", "success", auditPollTimeout)
	if ev.Params["rotated_from"] != old.KeyID {
		t.Fatalf("event params %v, want rotated_from %s", ev.Params, old.KeyID)
	}
	s, _ := getBackupKeyStatus(t, a.Portal)
	if s.Active == nil || s.Active.KeyID != g.KeyID || !slices.ContainsFunc(s.Retired, func(k backupKey) bool {
		return k.KeyID == old.KeyID && k.State == "retired" && k.RetiredAt != nil
	}) {
		t.Fatalf("after the rotation: active %+v, retired %+v", s.Active, s.Retired)
	}

	newPath := "pgbackrest/" + g.KeyID
	// A full backup started a little before the confirmation's response is still the rotation's (clock skew).
	after := confirmed.Add(-30 * time.Second)
	// Plan §9 B4 bounds the switch by one full interval (120 s on the development stack). On top of it: one backup-role
	// round (15 s) until the runtime names the new path, one pgbackrest loop pause (10 s) until switch_repo_path takes
	// the full at once, and the full plus its verify of the development databases (90 s). Both services switch in
	// parallel, so one deadline from the confirmation covers both.
	const (
		fullInterval = 120 * time.Second
		roleRound    = 15 * time.Second
		loopPause    = 10 * time.Second
		fullVerify   = 90 * time.Second
		bound        = fullInterval + roleRound + loopPause + fullVerify
	)
	deadline := confirmed.Add(bound)
	pending := map[string]bool{"pgbackrest": true, "pgbackrest-authentik": true}
	for len(pending) > 0 {
		for service := range pending {
			at, path, ok := newestFull(t, service)
			if ok && path == newPath && at.After(after) {
				t.Logf("%s: full backup of %s in %s, %s after the confirmation", service, at.Format(time.RFC3339), path,
					time.Since(confirmed).Round(time.Second))
				delete(pending, service)
				continue
			}
			if time.Now().After(deadline) {
				t.Fatalf("%s: no full backup in %s within %s of the confirmation (path %q, newest %s)", service, newPath,
					bound, path, at)
			}
		}
		if len(pending) > 0 {
			time.Sleep(time.Second)
		}
	}
	waitTargetManifest(t, client, 3*time.Minute, "the new key's path with a full of both stanzas", func(m backupManifest) bool {
		return m.KeyID == g.KeyID && m.Contents.PgBackRest.Path == newPath && m.lastFull("paddock").After(after) &&
			m.lastFull("authentik").After(after)
	})
	if n := targetObjects(t, client, oldPath+"/"); n == 0 {
		t.Fatalf("the S3 target lost the retired key's path %s before its expire", oldPath)
	}
}

// restorePlan is BackupRestorePlan of the admin API.
type restorePlan struct {
	ID          string    `json:"id"`
	Kind        string    `json:"kind"`
	Source      string    `json:"source"`
	State       string    `json:"state"`
	Components  []string  `json:"components"`
	CreatedAt   time.Time `json:"created_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	HostCommand string    `json:"host_command"`
}

// TestRestorePlan is gate B5: a restore plan needs the typed word, a successful backup of every chosen component and no
// other approved plan; it is approved with the host command and cancelled to expired.
func TestRestorePlan(t *testing.T) {
	requireBackupStack(t)
	a := newBackupAdmin(t)
	idx := auditIndex(t)
	ensureActiveBackupKey(t, a)
	runs, _ := requestBackupRuns(t, a, []string{"openbao"}, "b5")
	r := waitBackupRuns(t, a.Portal, []string{runs[0].ID}, 3*time.Minute)[runs[0].ID]
	if r.Outcome == nil || *r.Outcome != "succeeded" {
		t.Fatalf("OpenBao run: %+v", r)
	}

	// Only one plan may be approved: a plan an interrupted gate left behind is cancelled first.
	listPlans := func(state string) []restorePlan {
		res := call(t, a.Portal, http.MethodGet, restorePlans+"?page_size=100&state="+state, nil)
		expectStatus(t, res, http.StatusOK, "")
		var page struct{ Items []restorePlan }
		if err := res.JSON(&page); err != nil {
			t.Fatal(err)
		}
		return page.Items
	}
	if running := listPlans("running"); len(running) > 0 {
		t.Fatalf("restore plan %s is running; abandon it in the portal first", running[0].ID)
	}
	for _, p := range listPlans("approved") {
		expectStatus(t, call(t, a.fresh(t), http.MethodPost, restorePlans+"/"+p.ID+"/cancel", nil), http.StatusOK, "")
	}

	t.Run("typed word", func(t *testing.T) {
		for _, word := range []string{"", "Restore", "restore "} {
			expectStatus(t, call(t, a.fresh(t), http.MethodPost, restorePlans, restorePlanBody(word)), http.StatusBadRequest, "invalid_request")
		}
	})
	t.Run("component without a success", func(t *testing.T) {
		body := restorePlanBody("restore")
		body["kind"], body["at"] = "point_in_time", "2000-01-01T00:00:00Z"
		res := call(t, a.fresh(t), http.MethodPost, restorePlans, body)
		expectStatus(t, res, http.StatusConflict, "invalid_state")
		if d := problemDetail(t, res); !strings.Contains(d, "no successful openbao") {
			t.Fatalf("detail %q, want the missing kind", d)
		}
	})

	res := call(t, a.fresh(t), http.MethodPost, restorePlans, restorePlanBody("restore"))
	expectStatus(t, res, http.StatusCreated, "")
	var plan restorePlan
	if err := res.JSON(&plan); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		res := call(t, a.fresh(t), http.MethodPost, restorePlans+"/"+plan.ID+"/cancel", nil)
		if res.Status != http.StatusOK && res.Status != http.StatusConflict {
			t.Errorf("cancel restore plan %s: HTTP %d %s", plan.ID, res.Status, res.Body)
		}
	})
	if plan.State != "approved" || plan.Source != "repo" || plan.HostCommand != "./paddock restore --plan "+plan.ID ||
		!slices.Equal(plan.Components, []string{"openbao"}) || plan.ExpiresAt.Sub(plan.CreatedAt).Round(time.Minute) != 24*time.Hour {
		t.Fatalf("plan %+v", plan)
	}
	ev := expectOneIndexEvent(t, idx, platformOrg, "correlation_id = $1", res.RequestID, "platform.restore_planned", "success", auditPollTimeout)
	if ev.Params["plan_id"] != plan.ID {
		t.Fatalf("event params %v", ev.Params)
	}

	expectStatus(t, call(t, a.fresh(t), http.MethodPost, restorePlans, restorePlanBody("restore")), http.StatusConflict, "invalid_state")

	res = call(t, a.fresh(t), http.MethodPost, restorePlans+"/"+plan.ID+"/cancel", nil)
	expectStatus(t, res, http.StatusOK, "")
	expectOneIndexEvent(t, idx, platformOrg, "correlation_id = $1", res.RequestID, "platform.restore_cancelled", "success", auditPollTimeout)
	res = call(t, a.Portal, http.MethodGet, restorePlans+"/"+plan.ID, nil)
	expectStatus(t, res, http.StatusOK, "")
	if err := res.JSON(&plan); err != nil || plan.State != "expired" {
		t.Fatalf("cancelled plan %s (%v), want expired", res.Body, err)
	}
	expectStatus(t, call(t, a.fresh(t), http.MethodPost, restorePlans+"/"+plan.ID+"/cancel", nil), http.StatusConflict, "invalid_state")
	if !slices.ContainsFunc(listPlans("expired"), func(p restorePlan) bool { return p.ID == plan.ID }) {
		t.Fatalf("plan %s missing from the expired plans", plan.ID)
	}
}

// TestBackupLegacyKey is gate B6, the stack variant of plan M15 decision 9: an api started with
// PADDOCK_BACKUP_LEGACY_KEY_FILE over an empty key table imports the host key as legacy/unconfirmed, and no backup
// runs until it is confirmed. A one-off api container with the variable plays the upgraded installation; the key
// table is emptied for it and put back afterwards.
func TestBackupLegacyKey(t *testing.T) {
	if os.Getenv("PADDOCK_ACCEPTANCE_DISRUPTIVE") != "1" {
		t.Skip("empties the backup key table and starts a second api; set PADDOCK_ACCEPTANCE_DISRUPTIVE=1")
	}
	requireBackupStack(t)
	a := newBackupAdmin(t)
	idx := auditIndex(t)
	text := strings.TrimSpace(mustSecret(t, "backup_encryption_key"))
	rememberBackupSecret(text)
	start := time.Now()

	conn := ownerConn(t)
	ctx := testContext(t, time.Minute)
	rows, err := conn.Query(ctx, `SELECT row_to_json(k)::text FROM backup_key k`)
	if err != nil {
		t.Fatal(err)
	}
	var saved []string
	for rows.Next() {
		var row string
		if err := rows.Scan(&row); err != nil {
			t.Fatal(err)
		}
		saved = append(saved, row)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		if _, err := conn.Exec(ctx, `DELETE FROM backup_key`); err != nil {
			t.Errorf("empty the key table: %v", err)
			return
		}
		for _, row := range saved {
			if _, err := conn.Exec(ctx, `INSERT INTO backup_key SELECT * FROM json_populate_record(NULL::backup_key, $1::json)`, row); err != nil {
				t.Errorf("put back a backup key: %v", err)
			}
		}
	})
	if _, err := conn.Exec(ctx, `DELETE FROM backup_key`); err != nil {
		t.Fatal(err)
	}

	name := stack.Project() + "-b6-api-" + uniqueSuffix()
	// Registered after the table's restore, so it runs first: the one-off api is gone before the keys come back.
	t.Cleanup(func() {
		_, _ = stack.Docker(context.Background(), nil, "rm", "-f", name)
	})
	if out, err := stack.ComposeBackup(testContext(t, 3*time.Minute), nil, "--profile", "paddock", "run", "-d", "--no-deps",
		"--name", name, "-e", "PADDOCK_BACKUP_LEGACY_KEY_FILE=/run/secrets/backup_encryption_key", "paddock-api"); err != nil {
		t.Fatalf("start the one-off api: %v: %s", err, out)
	}

	const timeout = 2 * time.Minute
	deadline := time.Now().Add(timeout)
	var s backupKeyStatus
	for {
		s, _ = getBackupKeyStatus(t, a.Portal)
		if s.Pending != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no imported key within %s", timeout)
		}
		time.Sleep(time.Second)
	}
	p := s.Pending
	if p.KeyID != "legacy" || !p.Legacy || p.State != "unconfirmed" || p.Fingerprint != keyFingerprint(t, text) || len(p.Positions) != 6 || s.Active != nil {
		t.Fatalf("imported key %+v (active %+v), want legacy/unconfirmed with the host file's fingerprint", p, s.Active)
	}
	ev := expectOneIndexEvent(t, idx, platformOrg, "params->>'key_id' = $1 AND occurred_at >= "+fmtTime(start), "legacy",
		"platform.backup_key_generated", "success", auditPollTimeout)
	if ev.Params["legacy"] != true {
		t.Fatalf("event params %v, want legacy true", ev.Params)
	}
	expectParamsWithout(t, ev, text)

	res := call(t, a.fresh(t), http.MethodPost, backupRunPath, map[string]any{"kinds": []string{"openbao"}})
	expectStatus(t, res, http.StatusConflict, "invalid_state")
	waitKeyConfirmedMetric(t, 0)
	expectSecretsNotLogged(t, start, text)
}

// TestBackupIsolation is gate B7: every backup operation refuses organization administrators, with or without a step-up,
// and their API tokens with 403, without naming a platform backup object.
func TestBackupIsolation(t *testing.T) {
	doc := loadSpec(t)
	admin := adminUser(t, "bkiso")
	res := postAPIToken(t, admin.Portal, apiTokenName("backup isolation"), "org_admin", 2*time.Hour)
	expectStatus(t, res, http.StatusCreated, "")
	var tok apiTokenCreated
	if err := res.JSON(&tok); err != nil {
		t.Fatal(err)
	}
	callers := map[string]*env.Portal{"session": admin.Portal, "token": tokenPortal(t, tok.Secret)}

	root := login(t, env.PlatformAdmin)
	var ids []string
	for _, it := range listBackupTargets(t, root, url.Values{}).Items {
		ids = append(ids, it.ID)
	}
	targetID := uuid.NewString()
	if len(ids) > 0 {
		targetID = ids[0]
	}
	n := 0
	for path, item := range doc.Paths.Map() {
		if !strings.HasPrefix(path, "/api/platform/v1/backup") {
			continue
		}
		concrete := path
		switch {
		case strings.HasPrefix(path, backupKeyPath+"/"):
			concrete = strings.ReplaceAll(path, "{id}", missingBackupKey)
		case strings.HasPrefix(path, backupTargets+"/"):
			concrete = strings.ReplaceAll(path, "{id}", targetID)
		default:
			concrete = strings.ReplaceAll(path, "{id}", uuid.NewString())
		}
		for method := range item.Operations() {
			n++
			for who, p := range callers {
				t.Run(who+" "+method+" "+path, func(t *testing.T) {
					var body any
					if method != http.MethodGet {
						body = map[string]any{}
					}
					res := call(t, p, method, concrete, body)
					expectStatus(t, res, http.StatusForbidden, "forbidden")
					if id := containsAny(res.Body, ids); id != "" {
						t.Fatalf("the refusal names backup target %s: %s", id, res.Body)
					}
				})
			}
		}
	}
	if n < 22 {
		t.Fatalf("only %d backup operations in the contract", n)
	}
}
