package app_test

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/phischl/paddock-mdm/server/internal/app"
	"github.com/phischl/paddock-mdm/server/internal/domain/backupset"
	"github.com/phischl/paddock-mdm/server/internal/platform/db"
	"github.com/phischl/paddock-mdm/server/internal/principal"
	"github.com/phischl/paddock-mdm/server/internal/testsupport/pgtest"
)

// fakePlatformKeys stands in for Transit backup-wrap: the ciphertext counts the calls and never holds the plaintext.
type fakePlatformKeys struct {
	mu    sync.Mutex
	calls []string
}

func (k *fakePlatformKeys) EncryptPlatform(_ context.Context, key string, plaintext []byte) (string, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.calls = append(k.calls, key)
	return fmt.Sprintf("vault:v1:%s:%d:%d", key, len(k.calls), len(plaintext)), nil
}

type backupWorld struct {
	harness
	targets  *app.BackupTargets
	schedule *app.BackupSchedule
	runs     *app.BackupRuns
	keys     *fakePlatformKeys
}

// Plaintext credentials of the tests: every check scans responses and audit params for them.
const (
	smbPass   = "smb-pass-aaaa"
	s3Access  = "s3-access-aaaa"
	s3Private = "s3-private-aaaa"
)

func newBackupWorld(t *testing.T) backupWorld {
	t.Helper()
	h := newHarness(t)
	ctx := context.Background()
	platformPool, err := db.NewPlatformPool(ctx, pgtest.SharedPaddock(t).Platform, db.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(platformPool.Close)
	// The backup tables are platform-wide: every test starts from and leaves them empty.
	reset := func() {
		if _, err := h.super.Exec(context.Background(), `DELETE FROM backup_run; DELETE FROM backup_target_status;
			DELETE FROM backup_restore_plan; DELETE FROM backup_target; DELETE FROM backup_schedule; DELETE FROM backup_key`); err != nil {
			t.Fatal(err)
		}
	}
	reset()
	t.Cleanup(reset)
	keys := &fakePlatformKeys{}
	return backupWorld{
		harness: h, keys: keys,
		targets:  app.NewBackupTargets(h.runner, platformPool, keys, backupset.Policy{}),
		schedule: app.NewBackupSchedule(h.runner, platformPool),
		runs:     app.NewBackupRuns(h.runner, platformPool),
	}
}

func smbInput(name string) app.TargetInput {
	return app.TargetInput{Name: name, Type: backupset.TypeSMB, Enabled: true, SMB: backupset.SMB{
		Host: "nas.example.org", Share: "backup$", Path: "paddock", Username: "svc-backup", Password: smbPass,
		Options: "vers=3.1.1,seal"}}
}

func s3Input(name string) app.TargetInput {
	return app.TargetInput{Name: name, Type: backupset.TypeS3, Enabled: true, S3: backupset.S3{
		Endpoint: "https://s3.example.org", Bucket: "paddock-backup", AccessKey: s3Access, SecretKey: s3Private}}
}

// stored returns the credentials ciphertext, host state, host revision and whether deleted_at is set.
func (w backupWorld) stored(t *testing.T, id uuid.UUID) (*string, string, int, bool) {
	t.Helper()
	var ct *string
	var state string
	var rev int
	var deleted bool
	if err := w.super.QueryRow(context.Background(), `SELECT credentials_ciphertext, host_state, host_revision,
		deleted_at IS NOT NULL FROM backup_target WHERE id = $1`, id).Scan(&ct, &state, &rev, &deleted); err != nil {
		t.Fatal(err)
	}
	return ct, state, rev, deleted
}

// backupEvents returns code:outcome:error_code of the backup actions in order, and fails when any action's params
// hold a credential.
func (w backupWorld) backupEvents(t *testing.T) []string {
	t.Helper()
	rows, err := w.super.Query(context.Background(), `SELECT code || ':' || coalesce(outcome, status) || ':' ||
		coalesce(error_code, ''), params::text FROM action WHERE code LIKE 'platform.backup_%' AND correlation_id = $1
		ORDER BY started_at, id`, "corr-"+t.Name())
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var ev, params string
		if err := rows.Scan(&ev, &params); err != nil {
			t.Fatal(err)
		}
		for _, s := range []string{smbPass, s3Access, s3Private, "password", "secret_key", "access_key", "credentials_ciphertext"} {
			if strings.Contains(params, s) {
				t.Errorf("%s: params %s hold %q", ev, params, s)
			}
		}
		out = append(out, ev)
	}
	return out
}

// TestBackupTargetsCreate (plan M15 decision 10): every type is created with its host state; invalid input names the
// field; a duplicate name is already_exists; credentials are encrypted and never shown.
func TestBackupTargetsCreate(t *testing.T) {
	w := newBackupWorld(t)
	ctx := steppedPlatform()

	local, err := w.targets.Create(ctx, app.TargetInput{Name: "local", Type: backupset.TypeLocal, Enabled: true,
		Local: backupset.Local{Path: "/srv/backup"}})
	if err != nil || local.HostState != "pending_host" || local.HostRevision != 1 || local.HasCredentials ||
		local.Settings.Path != "/srv/backup" {
		t.Fatalf("local: %+v %v", local, err)
	}
	nfs, err := w.targets.Create(ctx, app.TargetInput{Name: "nfs", Type: backupset.TypeNFS, Enabled: false,
		NFS: backupset.NFS{Host: "10.0.0.5", Export: "/export/backup", Options: "vers=4.2,hard"}})
	if err != nil || nfs.HostState != "pending_host" || nfs.Enabled {
		t.Fatalf("nfs: %+v %v", nfs, err)
	}
	smb, err := w.targets.Create(ctx, smbInput("smb"))
	if err != nil || smb.HostState != "pending_host" || !smb.HasCredentials || smb.Settings.Username != "svc-backup" {
		t.Fatalf("smb: %+v %v", smb, err)
	}
	s3, err := w.targets.Create(ctx, s3Input("s3"))
	if err != nil || s3.HostState != "n/a" || !s3.HasCredentials || s3.Settings.Region != backupset.DefaultRegion {
		t.Fatalf("s3: %+v %v", s3, err)
	}
	if ct, _, _, _ := w.stored(t, s3.ID); ct == nil || !strings.HasPrefix(*ct, "vault:v1:backup-wrap:") {
		t.Fatalf("s3 ciphertext %v", ct)
	}
	if ct, _, _, _ := w.stored(t, local.ID); ct != nil {
		t.Fatalf("local target has credentials %q", *ct)
	}
	if fmt.Sprintf("%+v", []app.Target{local, nfs, smb, s3}) == "" ||
		strings.Contains(fmt.Sprintf("%+v", []app.Target{smb, s3}), smbPass) ||
		strings.Contains(fmt.Sprintf("%+v", s3), s3Access) || strings.Contains(fmt.Sprintf("%+v", s3), s3Private) {
		t.Fatal("a target shows a credential")
	}
	if len(w.keys.calls) != 2 {
		t.Fatalf("encryptions %v, want one per target with credentials", w.keys.calls)
	}

	for _, tc := range []struct {
		in    app.TargetInput
		field string
	}{
		{app.TargetInput{Name: "", Type: backupset.TypeLocal, Local: backupset.Local{Path: "/x"}}, "name"},
		{app.TargetInput{Name: "x", Type: "ftp"}, "type"},
		{app.TargetInput{Name: "x", Type: backupset.TypeLocal, Local: backupset.Local{Path: "relative"}}, "local.path"},
		{app.TargetInput{Name: "x", Type: backupset.TypeSMB, SMB: backupset.SMB{Host: "nas", Share: "s", Username: "u"}}, "smb.password"},
		{app.TargetInput{Name: "x", Type: backupset.TypeSMB, SMB: backupset.SMB{Host: "nas", Share: "s", Username: "u",
			Password: "p", Options: "uid=0"}}, "smb.options"},
		{app.TargetInput{Name: "x", Type: backupset.TypeNFS, NFS: backupset.NFS{Host: "nas", Export: "export"}}, "nfs.export"},
		{app.TargetInput{Name: "x", Type: backupset.TypeS3, S3: backupset.S3{Endpoint: "https://169.254.169.254",
			Bucket: "b-1", AccessKey: "a", SecretKey: "s"}}, "s3.endpoint"},
		{app.TargetInput{Name: "x", Type: backupset.TypeS3, S3: backupset.S3{Endpoint: "https://s3.example.org",
			Bucket: "b-1", AccessKey: "a"}}, "s3.secret_key"},
	} {
		_, err := w.targets.Create(ctx, tc.in)
		if code(err) != "invalid_request" || !strings.Contains(err.Error(), tc.field) {
			t.Errorf("%s: %v, want invalid_request naming %s", tc.field, err, tc.field)
		}
	}
	if _, err := w.targets.Create(ctx, s3Input("smb")); code(err) != "already_exists" {
		t.Fatalf("duplicate name: %v", err)
	}
	evs := w.backupEvents(t)
	if len(evs) != 13 || evs[0] != "platform.backup_target_created:success:" ||
		evs[12] != "platform.backup_target_created:failure:already_exists" {
		t.Fatalf("events %v", evs)
	}

	list, err := w.targets.List(ctx, app.TargetQuery{Page: app.ListPage{Sort: "name", Limit: 10},
		HostStates: []string{"pending_host"}})
	if err != nil || list.Count != 3 || list.Items[0].Name != "local" || list.Items[2].Name != "smb" {
		t.Fatalf("list by host state: %+v %v", list, err)
	}
	enabled := true
	list, err = w.targets.List(ctx, app.TargetQuery{Page: app.ListPage{Sort: "-name", Limit: 10},
		Types: []string{"nfs", "s3"}, Enabled: &enabled})
	if err != nil || list.Count != 1 || list.Items[0].Name != "s3" {
		t.Fatalf("list by type and enabled: %+v %v", list, err)
	}
}

// TestBackupTargetsUpdate (plan M15 decision 10): an update without a password keeps the credentials; a mount-relevant
// change raises the host revision and resets the host state; the type never changes.
func TestBackupTargetsUpdate(t *testing.T) {
	w := newBackupWorld(t)
	ctx := steppedPlatform()
	smb, err := w.targets.Create(ctx, smbInput("smb"))
	if err != nil {
		t.Fatal(err)
	}
	ctBefore, _, _, _ := w.stored(t, smb.ID)
	if _, err := w.super.Exec(context.Background(), "UPDATE backup_target SET host_state = 'mounted' WHERE id = $1", smb.ID); err != nil {
		t.Fatal(err)
	}

	rename := smbInput("smb-renamed")
	rename.SMB.Password = ""
	got, err := w.targets.Update(ctx, smb.ID, rename)
	if err != nil || got.Name != "smb-renamed" || !got.HasCredentials || got.HostRevision != 1 || got.HostState != "mounted" {
		t.Fatalf("rename: %+v %v", got, err)
	}
	if ct, _, _, _ := w.stored(t, smb.ID); *ct != *ctBefore {
		t.Fatal("an update without a password replaced the credentials")
	}

	moved := rename
	moved.SMB.Path = "other"
	got, err = w.targets.Update(ctx, smb.ID, moved)
	if err != nil || got.HostRevision != 2 || got.HostState != "pending_host" || !got.HasCredentials {
		t.Fatalf("settings change: %+v %v", got, err)
	}
	if ct, _, _, _ := w.stored(t, smb.ID); *ct != *ctBefore {
		t.Fatal("a settings change replaced the credentials")
	}

	newUser := moved
	newUser.SMB.Username = "other-user"
	if _, err := w.targets.Update(ctx, smb.ID, newUser); code(err) != "invalid_request" || !strings.Contains(err.Error(), "smb.password") {
		t.Fatalf("user name change without password: %v", err)
	}
	newUser.SMB.Password = "new-pass"
	got, err = w.targets.Update(ctx, smb.ID, newUser)
	if err != nil || got.HostRevision != 3 || got.Settings.Username != "other-user" {
		t.Fatalf("credentials change: %+v %v", got, err)
	}
	if ct, _, _, _ := w.stored(t, smb.ID); *ct == *ctBefore {
		t.Fatal("a new password did not replace the credentials")
	}

	// Stored credentials never follow a changed destination (review PDK-731 Major 1).
	newUser.SMB.Password = ""
	for field, change := range map[string]func(*backupset.SMB){
		"smb.host":     func(s *backupset.SMB) { s.Host = "nas.attacker.example" },
		"smb.share":    func(s *backupset.SMB) { s.Share = "other$" },
		"smb.domain":   func(s *backupset.SMB) { s.Domain = "OTHER" },
		"smb.username": func(s *backupset.SMB) { s.Username = "third-user" },
		"smb.options":  func(s *backupset.SMB) { s.Options = "vers=3.1.1,seal,ip=192.0.2.7" },
	} {
		redirect := newUser
		change(&redirect.SMB)
		_, err := w.targets.Update(ctx, smb.ID, redirect)
		if code(err) != "invalid_request" || !strings.Contains(err.Error(), "smb.password") || !strings.Contains(err.Error(), field) {
			t.Errorf("%s change without password: %v", field, err)
		}
	}
	if got, err := w.targets.Get(ctx, smb.ID); err != nil || got.HostRevision != 3 || got.Settings.Host != "nas.example.org" {
		t.Fatalf("a refused change was stored: %+v %v", got, err)
	}
	redirect := newUser
	redirect.SMB.Host, redirect.SMB.Password = "nas2.example.org", "third-pass"
	if got, err = w.targets.Update(ctx, smb.ID, redirect); err != nil || got.Settings.Host != "nas2.example.org" {
		t.Fatalf("host change with password: %+v %v", got, err)
	}

	asS3 := s3Input("smb-renamed")
	if _, err := w.targets.Update(ctx, smb.ID, asS3); code(err) != "invalid_request" {
		t.Fatalf("type change: %v", err)
	}

	s3, err := w.targets.Create(ctx, s3Input("s3"))
	if err != nil {
		t.Fatal(err)
	}
	keep := s3Input("s3")
	keep.S3.AccessKey, keep.S3.SecretKey, keep.S3.Prefix = "", "", "site-a"
	got, err = w.targets.Update(ctx, s3.ID, keep)
	if err != nil || got.HostState != "n/a" || got.HostRevision != 1 || !got.HasCredentials || got.Settings.Prefix != "site-a" {
		t.Fatalf("s3 update: %+v %v", got, err)
	}
	for field, change := range map[string]func(*backupset.S3){
		"s3.endpoint": func(s *backupset.S3) { s.Endpoint = "https://s3.attacker.example" },
		"s3.bucket":   func(s *backupset.S3) { s.Bucket = "other-bucket" },
		"s3.region":   func(s *backupset.S3) { s.Region = "eu-central-1" },
		"s3.ca_pem":   func(s *backupset.S3) { s.CAPEM = "-----BEGIN CERTIFICATE-----" },
	} {
		redirect := keep
		change(&redirect.S3)
		_, err := w.targets.Update(ctx, s3.ID, redirect)
		if code(err) != "invalid_request" || !strings.Contains(err.Error(), "s3.access_key") || !strings.Contains(err.Error(), field) {
			t.Errorf("%s change without key pair: %v", field, err)
		}
	}
	explicitRegion := keep
	explicitRegion.S3.Region = backupset.DefaultRegion
	if got, err = w.targets.Update(ctx, s3.ID, explicitRegion); err != nil || got.HostRevision != 1 {
		t.Fatalf("the default region spelled out is no destination change: %+v %v", got, err)
	}
	s3Moved := keep
	s3Moved.S3.Endpoint, s3Moved.S3.AccessKey, s3Moved.S3.SecretKey = "https://s3-2.example.org", "s3-access-bbbb", "s3-private-bbbb"
	if got, err = w.targets.Update(ctx, s3.ID, s3Moved); err != nil || got.Settings.Endpoint != "https://s3-2.example.org" {
		t.Fatalf("endpoint change with key pair: %+v %v", got, err)
	}
	keep.S3.Endpoint = s3Moved.S3.Endpoint
	half := keep
	half.S3.AccessKey = "only-access"
	if _, err := w.targets.Update(ctx, s3.ID, half); code(err) != "invalid_request" || !strings.Contains(err.Error(), "s3.secret_key") {
		t.Fatalf("half a key pair: %v", err)
	}
	if _, err := w.targets.Update(ctx, uuid.Must(uuid.NewV7()), keep); code(err) != "not_found" {
		t.Fatalf("unknown target: %v", err)
	}
	w.backupEvents(t)
}

// TestBackupTargetsLifecycle: enable, disable, test, delete (plan M15 decisions 10 and 11).
func TestBackupTargetsLifecycle(t *testing.T) {
	w := newBackupWorld(t)
	ctx := steppedPlatform()
	smb, err := w.targets.Create(ctx, smbInput("smb"))
	if err != nil {
		t.Fatal(err)
	}
	s3, err := w.targets.Create(ctx, s3Input("s3"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.targets.Enable(ctx, smb.ID); code(err) != "invalid_state" {
		t.Fatalf("enable an enabled target: %v", err)
	}
	if got, err := w.targets.Disable(ctx, smb.ID); err != nil || got.Enabled {
		t.Fatalf("disable: %+v %v", got, err)
	}
	if got, err := w.targets.Enable(ctx, smb.ID); err != nil || !got.Enabled {
		t.Fatalf("enable: %+v %v", got, err)
	}
	if got, err := w.targets.Test(ctx, s3.ID); err != nil || got.TestRequestedAt == nil {
		t.Fatalf("test: %+v %v", got, err)
	}

	if err := w.targets.Delete(ctx, smb.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, _, deleted := w.stored(t, smb.ID); !deleted {
		t.Fatal("a share target was not kept for the host step")
	}
	if _, err := w.targets.Get(ctx, smb.ID); code(err) != "not_found" {
		t.Fatalf("get a deleted target: %v", err)
	}
	if _, err := w.targets.Test(ctx, smb.ID); code(err) != "not_found" {
		t.Fatalf("test a deleted target: %v", err)
	}
	if _, err := w.targets.Create(ctx, smbInput("smb")); code(err) != "already_exists" {
		t.Fatalf("the name of a target waiting for removal: %v", err)
	}
	if err := w.targets.Delete(ctx, s3.ID); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := w.super.QueryRow(context.Background(), "SELECT count(*) FROM backup_target WHERE id = $1", s3.ID).Scan(&n); err != nil || n != 0 {
		t.Fatalf("an S3 target was kept: %d %v", n, err)
	}
	want := []string{
		"platform.backup_target_created:success:", "platform.backup_target_created:success:",
		"platform.backup_target_updated:failure:invalid_state", "platform.backup_target_updated:success:",
		"platform.backup_target_updated:success:", "platform.backup_target_tested:success:",
		"platform.backup_target_deleted:success:", "platform.backup_target_tested:failure:not_found",
		"platform.backup_target_created:failure:already_exists", "platform.backup_target_deleted:success:",
	}
	if got := w.backupEvents(t); strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("events %v, want %v", got, want)
	}
}

// TestBackupAuthorization: organization administrators are forbidden on every backup use case, platform writes
// without a step-up are denied.
func TestBackupAuthorization(t *testing.T) {
	w := newBackupWorld(t)
	org := stepped(w.org, principal.RoleOrgAdmin)
	id := uuid.Must(uuid.NewV7())
	for name, err := range map[string]error{
		"create":       func() error { _, err := w.targets.Create(org, s3Input("x")); return err }(),
		"list":         func() error { _, err := w.targets.List(org, app.TargetQuery{}); return err }(),
		"get":          func() error { _, err := w.targets.Get(org, id); return err }(),
		"update":       func() error { _, err := w.targets.Update(org, id, s3Input("x")); return err }(),
		"delete":       w.targets.Delete(org, id),
		"enable":       func() error { _, err := w.targets.Enable(org, id); return err }(),
		"test":         func() error { _, err := w.targets.Test(org, id); return err }(),
		"schedule get": func() error { _, err := w.schedule.Get(org); return err }(),
		"schedule put": func() error { _, err := w.schedule.Put(org, backupset.DefaultSchedule()); return err }(),
		"run":          func() error { _, err := w.runs.Request(org, nil, ""); return err }(),
		"runs":         func() error { _, err := w.runs.List(org, app.BackupRunQuery{}); return err }(),
		"overview":     func() error { _, err := w.runs.Overview(org); return err }(),
	} {
		if code(err) != "forbidden" {
			t.Errorf("%s by an organization administrator: %v", name, err)
		}
	}
	stale := principal.With(context.Background(), principal.Principal{Kind: principal.KindPlatformAdmin,
		ID: uuid.Must(uuid.NewV7()), Display: "root", Role: principal.RolePlatform, StepUpAt: time.Now().Add(-time.Hour)})
	if _, err := w.targets.Create(stale, s3Input("x")); code(err) != "step_up_required" {
		t.Fatalf("create without step-up: %v", err)
	}
	if _, err := w.runs.Request(stale, nil, ""); code(err) != "step_up_required" {
		t.Fatalf("run without step-up: %v", err)
	}
	if _, err := w.targets.List(stale, app.TargetQuery{Page: app.ListPage{Sort: "name", Limit: 10}}); err != nil {
		t.Fatalf("a read needs no step-up: %v", err)
	}
}

// TestBackupSchedule (plan M15 decision 12): the defaults without a row, the ranges, the audited change.
func TestBackupSchedule(t *testing.T) {
	w := newBackupWorld(t)
	ctx := steppedPlatform()
	got, err := w.schedule.Get(ctx)
	if err != nil || got.Schedule != backupset.DefaultSchedule() || got.UpdatedAt != nil {
		t.Fatalf("defaults: %+v %v", got, err)
	}
	bad := backupset.DefaultSchedule()
	bad.RetentionFull = 61
	if _, err := w.schedule.Put(ctx, bad); code(err) != "invalid_request" || !strings.Contains(err.Error(), "retention_full") {
		t.Fatalf("out of range: %v", err)
	}
	next := backupset.DefaultSchedule()
	next.FullIntervalHours, next.EscrowIntervalHours = 12, 2
	got, err = w.schedule.Put(ctx, next)
	if err != nil || got.Schedule != next || got.UpdatedBy == nil || *got.UpdatedBy != "root" {
		t.Fatalf("put: %+v %v", got, err)
	}
	if again, err := w.schedule.Get(ctx); err != nil || again.Schedule != next {
		t.Fatalf("get after put: %+v %v", again, err)
	}
	var params string
	if err := w.super.QueryRow(context.Background(), `SELECT params::text FROM action
		WHERE code = 'platform.backup_schedule_changed' AND outcome = 'success' AND correlation_id = $1`,
		"corr-"+t.Name()).Scan(&params); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{`"full_interval_hours": 12`, `"escrow_interval_hours": 2`, `"openbao_interval_hours": 6`,
		`"fleet_interval_hours": 24`, `"retention_full": 14`, `"openbao_keep_days": 30`, `"fleet_keep_days": 30`} {
		if !strings.Contains(params, f) {
			t.Errorf("params %s lack %s", params, f)
		}
	}
}

// TestBackupRuns (plan M15 decisions 13 and 14): no run without a confirmed key; a request inserts one requested run
// per kind; the list filters; the overview shows the key, the schedule, the targets and the newest runs.
func TestBackupRuns(t *testing.T) {
	w := newBackupWorld(t)
	ctx := steppedPlatform()
	if _, err := w.runs.Request(ctx, nil, "before key"); code(err) != "invalid_state" {
		t.Fatalf("without a key: %v", err)
	}
	if _, err := w.super.Exec(context.Background(), `INSERT INTO backup_key (key_id, state, ciphertext, fingerprint,
		challenge_positions, challenge_sha256, created_by) VALUES ('bk-20261104-0123abcd', 'confirmed', 'vault:v1:x',
		'0123456789abcdef', '{1,2,3,4,5,6}', '\x00', 'root'), ('bk-20261104-89abcdef', 'unconfirmed', 'vault:v1:y',
		'fedcba9876543210', '{1,2,3,4,5,6}', '\x00', 'root')`); err != nil {
		t.Fatal(err)
	}
	if _, err := w.runs.Request(ctx, []string{"postgres", "rogue-kind"}, ""); code(err) != "invalid_request" {
		t.Fatalf("unknown kind: %v", err)
	}
	var rejected string
	if err := w.super.QueryRow(context.Background(), `SELECT params::text FROM action WHERE code = 'platform.backup_run_requested'
		ORDER BY started_at DESC, id DESC LIMIT 1`).Scan(&rejected); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(rejected, "rogue-kind") || strings.Contains(rejected, "kinds") {
		t.Errorf("unvalidated kinds reached the audit params: %s", rejected)
	}
	if _, err := w.runs.Request(ctx, nil, strings.Repeat("l", 65)); code(err) != "invalid_request" {
		t.Fatalf("long label: %v", err)
	}
	all, err := w.runs.Request(ctx, nil, "")
	if err != nil || len(all) != 5 {
		t.Fatalf("all kinds: %+v %v", all, err)
	}
	for i, r := range all {
		if r.Kind != backupset.Kinds[i] || r.State != "requested" || r.RequestedBy == nil || *r.RequestedBy != "root" {
			t.Errorf("run %d: %+v", i, r)
		}
	}
	two, err := w.runs.Request(ctx, []string{"openbao", "openbao", "escrow"}, "before upgrade")
	if err != nil || len(two) != 2 || two[1].Label != "before upgrade" {
		t.Fatalf("two kinds: %+v %v", two, err)
	}
	var accepted string
	if err := w.super.QueryRow(context.Background(), `SELECT params::text FROM action WHERE code = 'platform.backup_run_requested'
		ORDER BY started_at DESC, id DESC LIMIT 1`).Scan(&accepted); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(accepted, `"kinds": ["openbao", "escrow"]`) {
		t.Errorf("validated kinds missing from the audit params: %s", accepted)
	}

	target, err := w.targets.Create(ctx, s3Input("s3"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.super.Exec(context.Background(), `UPDATE backup_run SET state = 'finished', outcome = 'succeeded',
		started_at = now() - interval '1 minute', finished_at = now(),
		targets = jsonb_build_array(jsonb_build_object('target_id', $1::text, 'ok', true)) WHERE id = $2`,
		target.ID, all[0].ID); err != nil {
		t.Fatal(err)
	}
	if _, err := w.super.Exec(context.Background(), `INSERT INTO backup_target_status (target_id, kind, last_success_at, bytes)
		VALUES ($1, 'postgres', now(), 42)`, target.ID); err != nil {
		t.Fatal(err)
	}
	tid := target.ID
	list, err := w.runs.List(ctx, app.BackupRunQuery{Page: app.ListPage{Sort: "-started_at", Limit: 10}, TargetID: &tid})
	if err != nil || list.Count != 1 || list.Items[0].Kind != "postgres" || len(list.Items[0].Targets) != 1 ||
		!list.Items[0].Targets[0].OK {
		t.Fatalf("by target: %+v %v", list, err)
	}
	list, err = w.runs.List(ctx, app.BackupRunQuery{Page: app.ListPage{Sort: "kind", Limit: 10}, Kinds: []string{"openbao"}})
	if err != nil || list.Count != 2 {
		t.Fatalf("by kind: %+v %v", list, err)
	}
	list, err = w.runs.List(ctx, app.BackupRunQuery{Page: app.ListPage{Sort: "-started_at", Limit: 10}})
	if err != nil || list.Count != 7 || list.Items[6].Kind != "postgres" {
		t.Fatalf("requested runs lead the default sort: %+v %v", list, err)
	}

	ov, err := w.runs.Overview(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if ov.Key.Active == nil || ov.Key.Active.KeyID != "bk-20261104-0123abcd" || ov.Key.Pending == nil ||
		len(ov.Key.Retired) != 0 {
		t.Fatalf("key status: %+v", ov.Key)
	}
	if ov.Repo.Path == nil || *ov.Repo.Path != "pgbackrest/bk-20261104-0123abcd" || ov.Repo.Stanzas[0].Name != "paddock" ||
		ov.Repo.Stanzas[0].LastFullAt == nil || ov.Repo.Stanzas[1].LastFullAt != nil {
		t.Fatalf("repo: %+v", ov.Repo)
	}
	if len(ov.Targets) != 1 || len(ov.Targets[0].Status) != 1 || ov.Targets[0].Status[0].Bytes != 42 {
		t.Fatalf("targets: %+v", ov.Targets)
	}
	if len(ov.LastRuns) != 5 || ov.Schedule.Schedule != backupset.DefaultSchedule() {
		t.Fatalf("last runs %+v schedule %+v", ov.LastRuns, ov.Schedule)
	}
	want := []string{"platform.backup_run_requested:failure:invalid_state",
		"platform.backup_run_requested:failure:invalid_request", "platform.backup_run_requested:failure:invalid_request",
		"platform.backup_run_requested:success:", "platform.backup_run_requested:success:",
		"platform.backup_target_created:success:"}
	if got := w.backupEvents(t); strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("events %v, want %v", got, want)
	}
}
