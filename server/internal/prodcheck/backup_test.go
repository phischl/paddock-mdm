package prodcheck_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/phischl/paddock-mdm/server/internal/prodcheck"
)

func backupCheck(t *testing.T, c prodcheck.Config, item string) (string, string) {
	t.Helper()
	return backupCheckAs(t, c, item, uint32(os.Getuid()))
}

func backupCheckAs(t *testing.T, c prodcheck.Config, item string, uid uint32) (string, string) {
	t.Helper()
	var out bytes.Buffer
	prodcheck.Write(&out, prodcheck.Run(context.Background(), c, prodcheck.Options{LocalRootUID: uid}))
	return itemBlock(t, out.String(), item)
}

func secrets(names ...string) []prodcheck.ServiceSecret {
	var out []prodcheck.ServiceSecret
	for _, n := range names {
		out = append(out, prodcheck.ServiceSecret{Source: n, Target: "/run/secrets/" + n})
	}
	return out
}

func backupHost() prodcheck.Config {
	repo := prodcheck.Volume{Type: "volume", Source: "backup-repo", Target: "/backup-repo"}
	return prodcheck.Config{Services: map[string]prodcheck.Service{
		"paddock-backup": {Environment: map[string]*string{}, Volumes: []prodcheck.Volume{repo},
			Secrets: secrets("db_paddock_backup_url", "db_paddock_platform_url", "approle_backup_role_id",
				"approle_backup_secret_id", "rustfs_escrow_backup_access_key", "rustfs_escrow_backup_secret_key")},
		"pgbackrest": {Environment: map[string]*string{}, Volumes: []prodcheck.Volume{repo}},
		"paddock-api": {Environment: map[string]*string{"PADDOCK_BACKUP_LEGACY_KEY_FILE": ptr("/run/secrets/backup_encryption_key")},
			Secrets: secrets("backup_encryption_key")},
		"paddock-worker": {Environment: map[string]*string{}, Secrets: secrets("db_paddock_worker_url")},
	}}
}

// TestBackupRoleChecks covers plan M15 decision 18: a host with backups passes with the backup role holding its
// secrets and the named repository volume; a missing role or secret, a leftover S3 setting or a bind-mounted
// repository fails.
func TestBackupRoleChecks(t *testing.T) {
	const role, repo = "backup: paddock-backup service present with its secrets", "backup: repo volume named"
	c := backupHost()
	for _, item := range []string{role, repo} {
		if status, detail := backupCheck(t, c, item); status != "PASS" {
			t.Errorf("%s: %s %s", item, status, detail)
		}
	}

	s := c.Services["paddock-backup"]
	s.Secrets = s.Secrets[1:]
	s.Environment["PADDOCK_BACKUP_S3_ENDPOINT"] = ptr("https://backup-s3.example.org")
	c.Services["paddock-backup"] = s
	status, detail := backupCheck(t, c, role)
	if status != "FAIL" || !strings.Contains(detail, "secret db_paddock_backup_url is not mounted") ||
		!strings.Contains(detail, "PADDOCK_BACKUP_S3_ENDPOINT is set") {
		t.Errorf("missing secret and S3 setting: %s\n%s", status, detail)
	}

	c = backupHost()
	delete(c.Services, "paddock-backup")
	if status, detail := backupCheck(t, c, role); status != "FAIL" || !strings.Contains(detail, "without paddock-backup") {
		t.Errorf("pgBackRest without the role: %s\n%s", status, detail)
	}

	c = backupHost()
	p := c.Services["pgbackrest"]
	p.Volumes = []prodcheck.Volume{{Type: "bind", Source: "/srv/backup", Target: "/backup-repo"}}
	c.Services["pgbackrest"] = p
	if status, detail := backupCheck(t, c, repo); status != "FAIL" || !strings.Contains(detail, "pgbackrest: /backup-repo") {
		t.Errorf("bind-mounted repository: %s\n%s", status, detail)
	}
}

// TestBackupSecretsConfined: the worker holds no backup secret or variable, the AppRole paddock-backup reaches only
// the backup role and the legacy key file only the api (plan M15 decisions 5, 9, 18).
func TestBackupSecretsConfined(t *testing.T) {
	const item = "backup: no S3 credentials or encryption key on the worker"
	if status, detail := backupCheck(t, backupHost(), item); status != "PASS" {
		t.Fatalf("clean host: %s %s", status, detail)
	}
	for name, mutate := range map[string]func(c prodcheck.Config) string{
		"worker with the old bucket credential": func(c prodcheck.Config) string {
			w := c.Services["paddock-worker"]
			w.Secrets = append(w.Secrets, secrets("backup_worker_access_key")...)
			c.Services["paddock-worker"] = w
			return "paddock-worker: holds the backup secret backup_worker_access_key"
		},
		"worker with the AppRole": func(c prodcheck.Config) string {
			w := c.Services["paddock-worker"]
			w.Secrets = append(w.Secrets, secrets("approle_backup_secret_id")...)
			c.Services["paddock-worker"] = w
			return "paddock-worker: holds the backup secret approle_backup_secret_id"
		},
		"worker with the encryption key variable": func(c prodcheck.Config) string {
			w := c.Services["paddock-worker"]
			w.Environment["PADDOCK_BACKUP_ENCRYPTION_KEY_FILE"] = ptr("/run/secrets/backup_encryption_key")
			c.Services["paddock-worker"] = w
			return "paddock-worker: PADDOCK_BACKUP_ENCRYPTION_KEY_FILE is set"
		},
		"worker with the escrow backup credential": func(c prodcheck.Config) string {
			w := c.Services["paddock-worker"]
			w.Secrets = append(w.Secrets, secrets("rustfs_escrow_backup_secret_key")...)
			c.Services["paddock-worker"] = w
			return "paddock-worker: holds the backup secret rustfs_escrow_backup_secret_key"
		},
		"legacy key file outside the api": func(c prodcheck.Config) string {
			b := c.Services["paddock-backup"]
			b.Environment["PADDOCK_BACKUP_LEGACY_KEY_FILE"] = ptr("/run/secrets/backup_encryption_key")
			b.Secrets = append(b.Secrets, secrets("backup_encryption_key")...)
			c.Services["paddock-backup"] = b
			return "paddock-backup: holds the backup secret backup_encryption_key"
		},
	} {
		t.Run(name, func(t *testing.T) {
			c := backupHost()
			want := mutate(c)
			status, detail := backupCheck(t, c, item)
			if status != "FAIL" || !strings.Contains(detail, want) {
				t.Errorf("%s: %s\n%s", name, status, detail)
			}
		})
	}
}

// TestBackupLocalRootCheck covers plan M15 decision 36: the root of local targets passes as a private directory, warns
// when missing and fails as a symlink, a file, a group-writable directory or a relative path.
func TestBackupLocalRootCheck(t *testing.T) {
	const item = "backup: local target root"
	dir := t.TempDir()
	good := filepath.Join(dir, "good")
	open := filepath.Join(dir, "open")
	file := filepath.Join(dir, "file")
	link := filepath.Join(dir, "link")
	for _, d := range []string{good, open} {
		if err := os.Mkdir(d, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(open, 0o770); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(good, link); err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		root, want string
	}{
		"private directory": {good, "PASS"},
		"missing":           {filepath.Join(dir, "missing"), "WARN"},
		"symlink":           {link, "FAIL"},
		"file":              {file, "FAIL"},
		"group writable":    {open, "FAIL"},
		"relative":          {"srv/backup", "FAIL"},
		"filesystem root":   {"/", "FAIL"},
		"first level":       {"/backup", "FAIL"},
	} {
		c := backupHost()
		c.Prod.BackupLocalRoot = tc.root
		status, detail := backupCheck(t, c, item)
		if status != tc.want {
			t.Errorf("%s: %s %q, want %s", name, status, detail, tc.want)
		}
	}
	c := backupHost()
	c.Prod.BackupLocalRoot = good
	if status, detail := backupCheckAs(t, c, item, uint32(os.Getuid())+1); status != "FAIL" {
		t.Errorf("a root of another owner: %s %q, want FAIL", status, detail)
	}
}

// TestBackupTargetRevisionsCheck covers plan M15 decision 22: online, the rendered targets file is compared with the
// database; a difference or an unreadable database warns and never fails, offline the item is absent.
func TestBackupTargetRevisionsCheck(t *testing.T) {
	const item = "backup: targets file matches the database revision"
	for name, tc := range map[string]struct {
		rev          prodcheck.BackupRevisions
		want, detail string
	}{
		"equal":               {prodcheck.BackupRevisions{File: "a=2 b=1", Database: "a=2 b=1"}, "PASS", ""},
		"no targets":          {prodcheck.BackupRevisions{File: "none", Database: "none"}, "PASS", ""},
		"newer in database":   {prodcheck.BackupRevisions{File: "a=1", Database: "a=2"}, "WARN", "run ./paddock backup-target apply, then ./paddock up"},
		"file missing":        {prodcheck.BackupRevisions{File: "none", Database: "a=1"}, "WARN", "the database a=1"},
		"database unreadable": {prodcheck.BackupRevisions{File: "a=1"}, "WARN", "could not read"},
	} {
		var out bytes.Buffer
		prodcheck.Write(&out, prodcheck.Run(context.Background(), backupHost(),
			prodcheck.Options{LocalRootUID: uint32(os.Getuid()), BackupRevisions: &tc.rev}))
		status, detail := itemBlock(t, out.String(), item)
		if status != tc.want || !strings.Contains(detail, tc.detail) {
			t.Errorf("%s: %s %q", name, status, detail)
		}
	}
	var out bytes.Buffer
	prodcheck.Write(&out, prodcheck.Run(context.Background(), backupHost(), prodcheck.Options{LocalRootUID: uint32(os.Getuid())}))
	if strings.Contains(out.String(), item) {
		t.Errorf("offline the item must be absent:\n%s", out.String())
	}
}
