package prodcheck_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/phischl/paddock-mdm/server/internal/prodcheck"
)

const interconnect = "10.0.0.1"

func ptr(s string) *string { return &s }

// fixture is a passing control-plane configuration with its secret files in a private directory.
type fixture struct {
	dir string
	cfg prodcheck.Config
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	dir := t.TempDir()
	secrets := filepath.Join(dir, "secrets")
	if err := os.Mkdir(secrets, 0o700); err != nil {
		t.Fatal(err)
	}
	write := func(name, content string, mode os.FileMode) string {
		p := filepath.Join(secrets, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), mode); err != nil {
			t.Fatal(err)
		}
		return p
	}
	caddyfile := filepath.Join(dir, "Caddyfile.prod")
	if err := os.WriteFile(caddyfile, []byte("{\n\temail {$PADDOCK_ACME_EMAIL}\n}\nadmin.{$PADDOCK_DOMAIN} {\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	f := &fixture{dir: dir}
	f.cfg = prodcheck.Config{
		Prod: prodcheck.Prod{InterconnectAddr: interconnect, RevocationAccepted: "no"},
		Secrets: map[string]prodcheck.Secret{
			"db_paddock_api_url":          {File: write("db_paddock_api_url", "postgres://api:pw@postgres:5432/paddock", 0o644)},
			"db_paddock_audit_reader_url": {File: write("db_paddock_audit_reader_url", "postgres://r:pw@10.0.0.2:5432/paddock_audit?sslmode=verify-full&sslrootcert=/run/secrets/internal_ca_bundle", 0o644)},
			"release_public_key":          {File: write("release-production/minisign.pub", "untrusted comment: prod\nRWQPROD\n", 0o644)},
			"internal_ca_bundle":          {File: write("internal-ca/bundle.crt", "-----BEGIN CERTIFICATE-----\n", 0o644)},
		},
		Services: map[string]prodcheck.Service{
			"caddy": {
				Environment: map[string]*string{"PADDOCK_ACME_EMAIL": ptr("ops@example.org")},
				Ports:       []prodcheck.Port{{Target: 443, Published: "443"}, {Target: 80, Published: "80"}},
				Volumes:     []prodcheck.Volume{{Type: "bind", Source: caddyfile, Target: "/etc/caddy/Caddyfile"}},
			},
			"postgres": {},
			"rabbitmq": {Ports: []prodcheck.Port{{HostIP: interconnect, Target: 5671, Published: "5671"}}},
			"paddock-api": {
				Environment: map[string]*string{
					"PADDOCK_ENV":                      ptr("production"),
					"PADDOCK_OPENBAO_ADDR":             ptr("https://openbao:8200"),
					"PADDOCK_DB_URL_FILE":              ptr("/run/secrets/db_paddock_api_url"),
					"PADDOCK_AUDIT_DB_READER_URL_FILE": ptr("/run/secrets/db_paddock_audit_reader_url"),
					"PADDOCK_RELEASE_PUBLIC_KEY_FILE":  ptr("/run/secrets/release_public_key"),
					"PADDOCK_REVOCATION_ENABLED":       ptr("false"),
					"PADDOCK_TEST_EXTERNAL_DELAY":      ptr(""),
				},
				Secrets: []prodcheck.ServiceSecret{
					{Source: "db_paddock_api_url"}, {Source: "db_paddock_audit_reader_url"}, {Source: "release_public_key"},
					{Source: "internal_ca_bundle", Target: "/run/secrets/internal_ca_bundle"},
				},
			},
		},
	}
	return f
}

func (f *fixture) service(name string) prodcheck.Service { return f.cfg.Services[name] }

func (f *fixture) setEnv(service, name, value string) {
	s := f.cfg.Services[service]
	s.Environment[name] = ptr(value)
	f.cfg.Services[service] = s
}

func run(t *testing.T, cfg prodcheck.Config, o prodcheck.Options) (bool, string) {
	t.Helper()
	if o.Host == "" {
		o.Host = prodcheck.HostControlPlane
	}
	var out bytes.Buffer
	ok := prodcheck.Write(&out, prodcheck.Run(context.Background(), cfg, o))
	return ok, out.String()
}

func failLine(t *testing.T, out, want string) {
	t.Helper()
	status := ""
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "PASS") || strings.HasPrefix(line, "FAIL") {
			status = line[:4]
		}
		if status == "FAIL" && strings.Contains(line, want) {
			return
		}
	}
	t.Fatalf("no FAIL line containing %q in\n%s", want, out)
}

func TestProductionConfigurationPasses(t *testing.T) {
	f := newFixture(t)
	ok, out := run(t, f.cfg, prodcheck.Options{ComposeFiles: []string{"compose.yaml", "compose.prod.yaml"}})
	if !ok {
		t.Fatalf("expected all PASS:\n%s", out)
	}
	if strings.Count(out, "PASS") != 10 {
		t.Fatalf("expected 10 items:\n%s", out)
	}
}

func TestDevelopmentVariableFailsNamingIt(t *testing.T) {
	for _, name := range []string{"PADDOCK_STEPUP_WINDOW", "PADDOCK_STEPUP_MAX_AUTH_AGE", "PADDOCK_STALENESS_UNIT",
		"PADDOCK_TEST_EXTERNAL_DELAY", "PADDOCK_REAPER_THRESHOLD", "PADDOCK_OSV_SYNC_INTERVAL"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			f.setEnv("paddock-api", name, "30s")
			ok, out := run(t, f.cfg, prodcheck.Options{})
			if ok {
				t.Fatal("expected FAIL")
			}
			failLine(t, out, "paddock-api: "+name)
		})
	}
}

func TestDevelopmentEnvAndOverlayFail(t *testing.T) {
	f := newFixture(t)
	f.setEnv("paddock-api", "PADDOCK_ENV", "development")
	f.cfg.Secrets["dev_alice_password"] = prodcheck.Secret{File: "/nonexistent"}
	_, out := run(t, f.cfg, prodcheck.Options{ComposeFiles: []string{"a/compose.yaml", "a/compose.dev.yaml"}})
	failLine(t, out, "paddock-api: PADDOCK_ENV=development")
	failLine(t, out, "compose.dev.yaml is part of the configuration")
	failLine(t, out, "development secret dev_alice_password")
}

func TestRevocationNeedsAcceptance(t *testing.T) {
	f := newFixture(t)
	f.setEnv("paddock-api", "PADDOCK_REVOCATION_ENABLED", "true")
	_, out := run(t, f.cfg, prodcheck.Options{})
	failLine(t, out, "PADDOCK_REVOCATION_ENABLED=true without PADDOCK_REVOCATION_ACCEPTED=yes")

	f.cfg.Prod.RevocationAccepted = "yes"
	if ok, out := run(t, f.cfg, prodcheck.Options{}); !ok {
		t.Fatalf("accepted revocation path must pass:\n%s", out)
	}
}

func TestSecretFiles(t *testing.T) {
	t.Run("missing", func(t *testing.T) {
		f := newFixture(t)
		if err := os.Remove(f.cfg.Secrets["db_paddock_api_url"].File); err != nil {
			t.Fatal(err)
		}
		_, out := run(t, f.cfg, prodcheck.Options{})
		failLine(t, out, "db_paddock_api_url: missing")
	})
	t.Run("empty counts as missing", func(t *testing.T) {
		f := newFixture(t)
		if err := os.WriteFile(f.cfg.Secrets["db_paddock_api_url"].File, nil, 0o644); err != nil {
			t.Fatal(err)
		}
		_, out := run(t, f.cfg, prodcheck.Options{})
		failLine(t, out, "db_paddock_api_url: empty")
	})
	t.Run("world-readable", func(t *testing.T) {
		f := newFixture(t)
		// t.TempDir's own directories are 0700, which would keep the file private.
		for _, d := range []string{filepath.Dir(f.dir), f.dir, filepath.Join(f.dir, "secrets")} {
			if err := os.Chmod(d, 0o755); err != nil {
				t.Fatal(err)
			}
		}
		_, out := run(t, f.cfg, prodcheck.Options{})
		failLine(t, out, "db_paddock_api_url: readable by every user of the host")
	})
	t.Run("private file in an open directory", func(t *testing.T) {
		f := newFixture(t)
		if err := os.Chmod(filepath.Join(f.dir, "secrets"), 0o755); err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"db_paddock_api_url", "db_paddock_audit_reader_url", "release_public_key"} {
			if err := os.Chmod(f.cfg.Secrets[name].File, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		if ok, out := run(t, f.cfg, prodcheck.Options{}); !ok {
			t.Fatalf("0600 files must pass:\n%s", out)
		}
	})
	t.Run("unused secrets are not checked", func(t *testing.T) {
		f := newFixture(t)
		f.cfg.Secrets["unused"] = prodcheck.Secret{File: "/nonexistent"}
		if ok, out := run(t, f.cfg, prodcheck.Options{}); !ok {
			t.Fatalf("unused secret must not fail:\n%s", out)
		}
	})
}

func TestPublishedPorts(t *testing.T) {
	cases := map[string]struct {
		port         prodcheck.Port
		interconnect string
		want         string
	}{
		"public port":           {prodcheck.Port{Target: 5432, Published: "5432"}, interconnect, `port 5432 published on "0.0.0.0"`},
		"loopback":              {prodcheck.Port{HostIP: "127.0.0.1", Target: 8200, Published: "8200"}, interconnect, `port 8200 published on "127.0.0.1"`},
		"no interconnect":       {prodcheck.Port{HostIP: interconnect, Target: 8200, Published: "8200"}, "", "port 8200"},
		"wildcard interconnect": {prodcheck.Port{HostIP: "0.0.0.0", Target: 8200, Published: "8200"}, "0.0.0.0", "is not a specific IP address"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			f.cfg.Prod.InterconnectAddr = tc.interconnect
			f.cfg.Services["openbao"] = prodcheck.Service{Ports: []prodcheck.Port{tc.port}}
			_, out := run(t, f.cfg, prodcheck.Options{})
			failLine(t, out, tc.want)
		})
	}
}

func TestCrossHostLinksNeedTLS(t *testing.T) {
	t.Run("plaintext AMQP on the interconnect", func(t *testing.T) {
		f := newFixture(t)
		f.cfg.Services["rabbitmq"] = prodcheck.Service{Ports: []prodcheck.Port{{HostIP: interconnect, Target: 5672, Published: "5672"}}}
		_, out := run(t, f.cfg, prodcheck.Options{})
		failLine(t, out, "rabbitmq: plaintext AMQP (5672) published")
	})
	t.Run("audit writer without amqps", func(t *testing.T) {
		f := newFixture(t)
		f.setEnv("paddock-api", "PADDOCK_AMQP_URL", "amqp://10.0.0.1:5672/paddock")
		_, out := run(t, f.cfg, prodcheck.Options{})
		failLine(t, out, "PADDOCK_AMQP_URL crosses hosts without amqps")
	})
	t.Run("local AMQP stays plain", func(t *testing.T) {
		f := newFixture(t)
		f.setEnv("paddock-api", "PADDOCK_AMQP_URL", "amqp://rabbitmq:5672/paddock")
		if ok, out := run(t, f.cfg, prodcheck.Options{}); !ok {
			t.Fatalf("local AMQP must pass:\n%s", out)
		}
	})
	t.Run("OpenBao without TLS", func(t *testing.T) {
		f := newFixture(t)
		f.setEnv("paddock-api", "PADDOCK_OPENBAO_ADDR", "http://openbao:8200")
		_, out := run(t, f.cfg, prodcheck.Options{})
		failLine(t, out, "PADDOCK_OPENBAO_ADDR is not https")
	})
	t.Run("audit reader without verify-full", func(t *testing.T) {
		f := newFixture(t)
		if err := os.WriteFile(f.cfg.Secrets["db_paddock_audit_reader_url"].File,
			[]byte("postgres://r:secretpw@10.0.0.2:5432/paddock_audit?sslmode=require"), 0o644); err != nil {
			t.Fatal(err)
		}
		_, out := run(t, f.cfg, prodcheck.Options{})
		failLine(t, out, "PADDOCK_AUDIT_DB_READER_URL_FILE crosses hosts without sslmode=verify-full")
		if strings.Contains(out, "secretpw") {
			t.Fatal("the DSN must never be printed")
		}
	})
}

func TestCaddy(t *testing.T) {
	f := newFixture(t)
	caddy := f.service("caddy")
	if err := os.WriteFile(caddy.Volumes[0].Source, []byte("admin.example.org {\n\ttls internal\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	caddy.Environment["PADDOCK_ACME_EMAIL"] = ptr("")
	_, out := run(t, f.cfg, prodcheck.Options{})
	failLine(t, out, "Caddyfile uses tls internal")
	failLine(t, out, "PADDOCK_ACME_EMAIL is not set")
}

func TestReleaseKeys(t *testing.T) {
	t.Run("secret key next to the public key", func(t *testing.T) {
		f := newFixture(t)
		pub := f.cfg.Secrets["release_public_key"].File
		if err := os.WriteFile(strings.TrimSuffix(pub, ".pub")+".key", []byte("secret"), 0o600); err != nil {
			t.Fatal(err)
		}
		_, out := run(t, f.cfg, prodcheck.Options{})
		failLine(t, out, "PADDOCK_RELEASE_PUBLIC_KEY_FILE: the secret key")
	})
	t.Run("same key as the development key", func(t *testing.T) {
		f := newFixture(t)
		dev := filepath.Join(f.dir, "dev-minisign.pub")
		if err := os.WriteFile(dev, []byte("untrusted comment: minisign public key DEV\nRWQPROD\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		_, out := run(t, f.cfg, prodcheck.Options{DevReleaseKeys: []string{dev}})
		failLine(t, out, "is the development release key")
	})
	t.Run("different development key", func(t *testing.T) {
		f := newFixture(t)
		dev := filepath.Join(f.dir, "dev-minisign.pub")
		if err := os.WriteFile(dev, []byte("untrusted comment: dev\nRWQDEV\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if ok, out := run(t, f.cfg, prodcheck.Options{DevReleaseKeys: []string{dev, "/nonexistent"}}); !ok {
			t.Fatalf("expected PASS:\n%s", out)
		}
	})
}

type lockReader struct {
	enabled bool
	mode    string
	days    int32
	err     error
}

func (l lockReader) DefaultRetention(context.Context) (bool, string, int32, error) {
	return l.enabled, l.mode, l.days, l.err
}

func TestAuditBucketObjectLock(t *testing.T) {
	cases := map[string]struct {
		reader prodcheck.ObjectLockReader
		want   string
	}{
		"offline":    {nil, "not checked (run with ONLINE=1)"},
		"error":      {lockReader{err: errors.New("AccessDenied")}, "AccessDenied"},
		"disabled":   {lockReader{}, "Object Lock is not enabled"},
		"governance": {lockReader{enabled: true, mode: "GOVERNANCE", days: 400}, "not COMPLIANCE"},
		"short":      {lockReader{enabled: true, mode: "COMPLIANCE", days: 30}, "less than 400"},
		"compliance": {lockReader{enabled: true, mode: "COMPLIANCE", days: 400}, ""},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			ok, out := run(t, prodcheck.Config{}, prodcheck.Options{Host: prodcheck.HostAudit, ObjectLock: tc.reader})
			if tc.want == "" {
				if !ok {
					t.Fatalf("expected PASS:\n%s", out)
				}
				return
			}
			failLine(t, out, tc.want)
		})
	}
	if _, out := run(t, prodcheck.Config{}, prodcheck.Options{}); strings.Contains(out, "Object Lock") {
		t.Fatalf("the control plane has no audit bucket item:\n%s", out)
	}
}

func TestParse(t *testing.T) {
	cfg, err := prodcheck.Parse(strings.NewReader(`{"services":{"api":{"environment":{"A":"1","B":null},
		"ports":[{"host_ip":"10.0.0.1","target":5671,"published":"5671","protocol":"tcp"}],
		"secrets":[{"source":"s"}]}},"secrets":{"s":{"name":"paddock_s","file":"/x"}},
		"x-paddock-prod":{"interconnect_addr":"10.0.0.1","revocation_accepted":"no"}}`))
	if err != nil {
		t.Fatal(err)
	}
	s := cfg.Services["api"]
	if *s.Environment["A"] != "1" || s.Environment["B"] != nil || s.Ports[0].Published != "5671" ||
		cfg.Secrets["s"].File != "/x" || cfg.Prod.InterconnectAddr != "10.0.0.1" {
		t.Fatalf("unexpected parse result: %+v", cfg)
	}
}
