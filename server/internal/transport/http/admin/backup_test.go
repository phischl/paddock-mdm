package admin_test

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/domain/backupset"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin"
	"github.com/phischl/paddock-mdm/server/internal/transport/http/admin/adminapi"
)

// countingWrap stands in for Transit backup-wrap; its ciphertext never holds the plaintext.
type countingWrap struct{ n atomic.Int64 }

func (w *countingWrap) EncryptPlatform(_ context.Context, key string, _ []byte) (string, error) {
	return fmt.Sprintf("vault:v1:%s-%d", key, w.n.Add(1)), nil
}

// Plaintext credentials sent by the tests: no response and no audit param may hold them.
const (
	apiSMBPass   = "smb-pass-aaaa"
	apiS3Access  = "s3-access-aaaa"
	apiS3Private = "s3-private-aaaa"
)

func newBackupEnv(t *testing.T) *env {
	t.Helper()
	ctx := context.Background()
	platform, err := db.NewPlatformPool(ctx, pgtest.SharedPaddock(t).Platform, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(platform.Close)
	e := newEnvWith(t, func(d *admin.Deps) {
		d.BackupTargets = app.NewBackupTargets(d.Runner, platform, &countingWrap{}, backupset.Policy{})
		d.BackupSchedule = app.NewBackupSchedule(d.Runner, platform)
		d.BackupRuns = app.NewBackupRuns(d.Runner, platform)
	})
	// The backup tables are platform-wide: start from and leave them empty.
	reset := func() {
		if _, err := e.super.Exec(context.Background(), `DELETE FROM backup_run; DELETE FROM backup_target_status;
			DELETE FROM backup_restore_plan; DELETE FROM backup_target; DELETE FROM backup_schedule; DELETE FROM backup_key`); err != nil {
			t.Fatal(err)
		}
	}
	reset()
	t.Cleanup(reset)
	return e
}

// noCredentials fails when a response body or the params of the request's audit event hold a credential.
func (e *env) noCredentials(r result) {
	e.t.Helper()
	var params string
	_ = e.super.QueryRow(context.Background(), "SELECT coalesce(string_agg(params::text, ' '), '') FROM action WHERE correlation_id = $1",
		r.header.Get("X-Request-Id")).Scan(&params)
	for _, s := range []string{apiSMBPass, apiS3Access, apiS3Private, "password", "secret_key", "access_key", "credentials_ciphertext"} {
		if strings.Contains(string(r.body), s) {
			e.t.Errorf("response %s holds %q", r.body, s)
		}
		if strings.Contains(params, s) {
			e.t.Errorf("audit params %s hold %q", params, s)
		}
	}
}

// TestBackupTargetEndpoints (PDK-731): create, read, update and delete over the contract; secrets never leave the
// server; invalid input names the field; every write is audited once.
func TestBackupTargetEndpoints(t *testing.T) {
	e := newBackupEnv(t)
	root := e.platformSession()
	su := e.steppedUp(root, time.Now())
	const base = "/api/platform/v1/backup/targets"

	s3 := map[string]any{"name": "offsite", "type": "s3", "enabled": true, "s3": map[string]any{
		"endpoint": "https://s3.example.org", "bucket": "paddock-backup", "access_key": apiS3Access, "secret_key": apiS3Private}}
	r := e.do(call{method: "POST", path: base, cookie: root, body: s3})
	if r.status != http.StatusForbidden || r.problemCode(t) != "step_up_required" {
		t.Fatalf("without step-up: %d %s", r.status, r.body)
	}
	e.expectEvent(r, "platform.backup_target_created:denied:step_up_required")

	r = e.do(call{method: "POST", path: base, cookie: su, body: s3})
	if r.status != http.StatusCreated {
		t.Fatalf("create s3: %d %s", r.status, r.body)
	}
	e.expectEvent(r, "platform.backup_target_created:success:")
	e.noCredentials(r)
	var created adminapi.BackupTarget
	r.decode(t, &created)
	if created.HostState != "n/a" || !created.HasCredentials || created.Settings.S3 == nil || created.Settings.S3.Region != "us-east-1" ||
		r.header.Get("Location") != base+"/"+created.Id.String() {
		t.Fatalf("created %+v location %s", created, r.header.Get("Location"))
	}

	for _, body := range []map[string]any{
		{"name": "local", "type": "local", "enabled": true, "local": map[string]any{"path": "/srv/backup"}},
		{"name": "nfs", "type": "nfs", "enabled": true, "nfs": map[string]any{"host": "nas.example.org", "export": "/export/backup"}},
		{"name": "smb", "type": "smb", "enabled": true, "smb": map[string]any{"host": "nas.example.org", "share": "backup$",
			"username": "svc", "password": apiSMBPass}},
	} {
		r = e.do(call{method: "POST", path: base, cookie: su, body: body})
		if r.status != http.StatusCreated {
			t.Fatalf("create %s: %d %s", body["type"], r.status, r.body)
		}
		e.noCredentials(r)
		var got adminapi.BackupTarget
		r.decode(t, &got)
		if got.HostState != "pending_host" || got.HostRevision != 1 {
			t.Fatalf("%s: %+v", body["type"], got)
		}
	}

	for _, tc := range []struct {
		body  map[string]any
		field string
	}{
		{map[string]any{"name": "x", "type": "smb", "enabled": true, "smb": map[string]any{"host": "nas", "share": "s", "username": "u"}}, "smb.password"},
		{map[string]any{"name": "x", "type": "nfs", "enabled": true, "nfs": map[string]any{"host": "nas", "export": "/e", "options": "soft"}}, "nfs.options"},
		{map[string]any{"name": "x", "type": "s3", "enabled": true, "s3": map[string]any{"endpoint": "http://s3.example.org",
			"bucket": "b-1", "access_key": "a", "secret_key": "s"}}, "s3.endpoint"},
		{map[string]any{"name": "x", "type": "local", "enabled": true}, "local.path"},
	} {
		r = e.do(call{method: "POST", path: base, cookie: su, body: tc.body})
		if r.status != http.StatusBadRequest || r.problemCode(t) != "invalid_request" || !strings.Contains(string(r.body), tc.field) {
			t.Errorf("%s: %d %s", tc.field, r.status, r.body)
		}
		e.expectEvent(r, "platform.backup_target_created:failure:invalid_request")
	}
	r = e.do(call{method: "POST", path: base, cookie: su, body: s3})
	if r.status != http.StatusConflict || r.problemCode(t) != "already_exists" {
		t.Fatalf("duplicate: %d %s", r.status, r.body)
	}

	r = e.do(call{method: "GET", path: base + "?sort=-name&type=s3&type=smb", cookie: root})
	e.noCredentials(r)
	var page adminapi.BackupTargetPage
	r.decode(t, &page)
	if r.status != http.StatusOK || page.Total != 2 || page.Items[0].Name != "smb" || page.Sort != "-name" {
		t.Fatalf("list: %d %s", r.status, r.body)
	}
	r = e.do(call{method: "GET", path: base + "?host_state=pending_host&q=lo", cookie: root})
	r.decode(t, &page)
	if page.Total != 1 || page.Items[0].Name != "local" {
		t.Fatalf("list by host state and search: %s", r.body)
	}

	keep := map[string]any{"name": "offsite", "type": "s3", "enabled": true, "s3": map[string]any{
		"endpoint": "https://s3.example.org", "bucket": "paddock-backup", "prefix": "site-a"}}
	r = e.do(call{method: "PUT", path: base + "/" + created.Id.String(), cookie: su, body: keep})
	if r.status != http.StatusOK {
		t.Fatalf("update: %d %s", r.status, r.body)
	}
	e.expectEvent(r, "platform.backup_target_updated:success:")
	var updated adminapi.BackupTarget
	r.decode(t, &updated)
	if !updated.HasCredentials || updated.Settings.S3.Prefix != "site-a" {
		t.Fatalf("updated %+v", updated)
	}

	for _, step := range []struct{ method, path, event string }{
		{"POST", "/test", "platform.backup_target_tested:success:"},
		{"POST", "/disable", "platform.backup_target_updated:success:"},
		{"POST", "/disable", "platform.backup_target_updated:failure:invalid_state"},
		{"POST", "/enable", "platform.backup_target_updated:success:"},
		{"DELETE", "", "platform.backup_target_deleted:success:"},
		{"GET", "", ""},
	} {
		r = e.do(call{method: step.method, path: base + "/" + created.Id.String() + step.path, cookie: su})
		if step.event == "" {
			if r.status != http.StatusNotFound {
				t.Fatalf("get after delete: %d", r.status)
			}
			continue
		}
		e.expectEvent(r, step.event)
	}
}

// TestBackupScheduleAndRuns (PDK-731): the schedule defaults and ranges, and no run without a confirmed key.
func TestBackupScheduleAndRuns(t *testing.T) {
	e := newBackupEnv(t)
	root := e.platformSession()
	su := e.steppedUp(root, time.Now())

	r := e.do(call{method: "GET", path: "/api/platform/v1/backup/schedule", cookie: root})
	var s adminapi.BackupSchedule
	r.decode(t, &s)
	if r.status != http.StatusOK || s.FullIntervalHours != 24 || s.EscrowIntervalHours != 1 || s.RetentionFull != 14 || s.UpdatedAt != nil {
		t.Fatalf("defaults: %d %s", r.status, r.body)
	}
	next := map[string]any{"full_interval_hours": 12, "openbao_interval_hours": 6, "fleet_interval_hours": 24,
		"escrow_interval_hours": 1, "retention_full": 14, "openbao_keep_days": 30, "fleet_keep_days": 400}
	r = e.do(call{method: "PUT", path: "/api/platform/v1/backup/schedule", cookie: su, body: next})
	if r.status != http.StatusBadRequest || !strings.Contains(string(r.body), "fleet_keep_days") {
		t.Fatalf("out of range: %d %s", r.status, r.body)
	}
	e.expectEvent(r, "platform.backup_schedule_changed:failure:invalid_request")
	next["fleet_keep_days"] = 30
	r = e.do(call{method: "PUT", path: "/api/platform/v1/backup/schedule", cookie: su, body: next})
	r.decode(t, &s)
	if r.status != http.StatusOK || s.FullIntervalHours != 12 || s.UpdatedBy == nil {
		t.Fatalf("put: %d %s", r.status, r.body)
	}
	e.expectEvent(r, "platform.backup_schedule_changed:success:")

	r = e.do(call{method: "POST", path: "/api/platform/v1/backup/run", cookie: su, body: map[string]any{}})
	if r.status != http.StatusConflict || r.problemCode(t) != "invalid_state" {
		t.Fatalf("run without a key: %d %s", r.status, r.body)
	}
	e.expectEvent(r, "platform.backup_run_requested:failure:invalid_state")
	if _, err := e.super.Exec(context.Background(), `INSERT INTO backup_key (key_id, state, ciphertext, fingerprint,
		challenge_positions, challenge_sha256, created_by) VALUES ('bk-20261104-0123abcd', 'confirmed', 'vault:v1:x',
		'0123456789abcdef', '{1,2,3,4,5,6}', '\x00', 'root')`); err != nil {
		t.Fatal(err)
	}
	r = e.do(call{method: "POST", path: "/api/platform/v1/backup/run", cookie: su,
		body: map[string]any{"kinds": []string{"openbao", "escrow"}, "label": "before upgrade"}})
	var runs []adminapi.BackupRun
	r.decode(t, &runs)
	if r.status != http.StatusAccepted || len(runs) != 2 || runs[0].State != "requested" || runs[1].Label != "before upgrade" {
		t.Fatalf("run: %d %s", r.status, r.body)
	}
	e.expectEvent(r, "platform.backup_run_requested:success:")
	r = e.do(call{method: "POST", path: "/api/platform/v1/backup/run", cookie: su, body: map[string]any{"kinds": nil}})
	if r.status != http.StatusAccepted {
		t.Fatalf("run every kind: %d %s", r.status, r.body)
	}

	r = e.do(call{method: "GET", path: "/api/platform/v1/backup/runs?kind=openbao", cookie: root})
	var page adminapi.BackupRunPage
	r.decode(t, &page)
	if r.status != http.StatusOK || page.Total != 2 || page.Sort != "-started_at" {
		t.Fatalf("runs: %d %s", r.status, r.body)
	}
	r = e.do(call{method: "GET", path: "/api/platform/v1/backup", cookie: root})
	var ov adminapi.BackupOverview
	r.decode(t, &ov)
	if r.status != http.StatusOK || ov.Key.Active == nil || ov.Repo.Path == nil || len(ov.LastRuns) != 5 || ov.Schedule.FullIntervalHours != 12 {
		t.Fatalf("overview: %d %s", r.status, r.body)
	}
	if strings.Contains(string(r.body), "vault:v1") || strings.Contains(string(r.body), "challenge") {
		t.Fatalf("the overview shows key material: %s", r.body)
	}
}

// TestBackupEndpointsRefuseOrganizations (PDK-731): organization sessions and API tokens are forbidden on every
// backup endpoint; refused writes are audited.
func TestBackupEndpointsRefuseOrganizations(t *testing.T) {
	e := newBackupEnv(t)
	alice := e.session(e.acme, principal.RoleOrgAdmin)
	token := e.createAPIToken("acme", alice, "ci", adminapi.ApiTokenRoleOrgAdmin)
	steppedAlice := e.steppedUp(alice, time.Now())
	const id = "0190f2a0-0000-7000-8000-000000000001"
	target := map[string]any{"name": "x", "type": "local", "enabled": true, "local": map[string]any{"path": "/srv"}}
	schedule := map[string]any{"full_interval_hours": 24, "openbao_interval_hours": 6, "fleet_interval_hours": 24,
		"escrow_interval_hours": 1, "retention_full": 14, "openbao_keep_days": 30, "fleet_keep_days": 30}
	for _, c := range []struct {
		method, path string
		body         any
		event        string
	}{
		{"GET", "/api/platform/v1/backup", nil, ""},
		{"GET", "/api/platform/v1/backup/schedule", nil, ""},
		{"PUT", "/api/platform/v1/backup/schedule", schedule, "platform.backup_schedule_changed"},
		{"GET", "/api/platform/v1/backup/targets", nil, ""},
		{"POST", "/api/platform/v1/backup/targets", target, "platform.backup_target_created"},
		{"GET", "/api/platform/v1/backup/targets/" + id, nil, ""},
		{"PUT", "/api/platform/v1/backup/targets/" + id, target, "platform.backup_target_updated"},
		{"DELETE", "/api/platform/v1/backup/targets/" + id, nil, "platform.backup_target_deleted"},
		{"POST", "/api/platform/v1/backup/targets/" + id + "/test", nil, "platform.backup_target_tested"},
		{"POST", "/api/platform/v1/backup/targets/" + id + "/enable", nil, "platform.backup_target_updated"},
		{"POST", "/api/platform/v1/backup/targets/" + id + "/disable", nil, "platform.backup_target_updated"},
		{"POST", "/api/platform/v1/backup/run", map[string]any{}, "platform.backup_run_requested"},
		{"GET", "/api/platform/v1/backup/runs", nil, ""},
	} {
		r := e.do(call{method: c.method, path: c.path, cookie: steppedAlice, body: c.body})
		if r.status != http.StatusForbidden {
			t.Errorf("session %s %s: %d %s", c.method, c.path, r.status, r.body)
		}
		if c.event != "" {
			e.expectEvent(r, c.event+":denied:forbidden")
		}
		r = e.do(call{method: c.method, path: c.path, headers: bearer(token.Secret), body: c.body})
		if r.status != http.StatusForbidden {
			t.Errorf("token %s %s: %d %s", c.method, c.path, r.status, r.body)
		}
		if c.event != "" {
			e.expectEvent(r, c.event+":denied:forbidden")
		}
	}
}
