package prodcheck_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/phischl/paddock-mdm/server/internal/prodcheck"
)

// TestUnmountedSecretReferenceFails is the regression of review 1 finding 1: compose.prod.yaml's `secrets: !override`
// dropped the backup secrets of paddock-worker while its environment still named them, and prod-check passed.
func TestUnmountedSecretReferenceFails(t *testing.T) {
	f := newFixture(t)
	f.cfg.Services["paddock-worker"] = prodcheck.Service{
		Environment: map[string]*string{
			"PADDOCK_ENV":                       ptr("production"),
			"PADDOCK_DB_WORKER_URL_FILE":        ptr("/run/secrets/db_paddock_api_url"),
			"PADDOCK_BACKUP_S3_ACCESS_KEY_FILE": ptr("/run/secrets/backup_worker_access_key"),
			"BAO_CACERT":                        ptr("/run/secrets/internal_ca_bundle"),
		},
		Secrets: []prodcheck.ServiceSecret{{Source: "db_paddock_api_url"}},
	}
	ok, out := run(t, f.cfg, prodcheck.Options{})
	if ok {
		t.Fatalf("expected FAIL:\n%s", out)
	}
	failLine(t, out, "paddock-worker: PADDOCK_BACKUP_S3_ACCESS_KEY_FILE names /run/secrets/backup_worker_access_key, which is not mounted")
	failLine(t, out, "paddock-worker: BAO_CACERT names /run/secrets/internal_ca_bundle, which is not mounted")
}

func TestUnmountedDSNRootCertFails(t *testing.T) {
	f := newFixture(t)
	api := f.cfg.Services["paddock-api"]
	api.Secrets = api.Secrets[:3]
	f.cfg.Services["paddock-api"] = api
	_, out := run(t, f.cfg, prodcheck.Options{})
	failLine(t, out, "the DSN of PADDOCK_AUDIT_DB_READER_URL_FILE names sslrootcert /run/secrets/internal_ca_bundle, which is not mounted")
}

func TestUnreadableDSNFails(t *testing.T) {
	f := newFixture(t)
	file := f.cfg.Secrets["db_paddock_audit_reader_url"].File
	if err := os.Remove(file); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(file, 0o700); err != nil {
		t.Fatal(err)
	}
	_, out := run(t, f.cfg, prodcheck.Options{})
	failLine(t, out, "PADDOCK_AUDIT_DB_READER_URL_FILE cannot be read")
}

func TestPublicPortsOnlyOnCaddy(t *testing.T) {
	f := newFixture(t)
	f.cfg.Services["postgres"] = prodcheck.Service{Ports: []prodcheck.Port{{Target: 5432, Published: "443"}}}
	_, out := run(t, f.cfg, prodcheck.Options{})
	failLine(t, out, `postgres: port 443 published on "0.0.0.0"`)
}

func TestWorldReadableFollowsSymlinks(t *testing.T) {
	f := newFixture(t)
	// The secret is a link from the private secrets directory to a file in a directory every user may enter.
	open := filepath.Join(f.dir, "open")
	if err := os.Mkdir(open, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{filepath.Dir(f.dir), f.dir} {
		if err := os.Chmod(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	target := filepath.Join(open, "api_url")
	if err := os.WriteFile(target, []byte("postgres://api:pw@postgres:5432/paddock"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := f.cfg.Secrets["db_paddock_api_url"].File
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	_, out := run(t, f.cfg, prodcheck.Options{})
	failLine(t, out, "db_paddock_api_url: readable by every user of the host")

	// A link that cannot be resolved is a finding, not a private file.
	if err := os.Remove(target); err != nil {
		t.Fatal(err)
	}
	_, out = run(t, f.cfg, prodcheck.Options{})
	failLine(t, out, "db_paddock_api_url: missing")
}
