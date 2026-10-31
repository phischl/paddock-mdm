package prodcheck_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strconv"
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
				Volumes: []prodcheck.Volume{
					{Type: "bind", Source: caddyfile, Target: "/etc/caddy/Caddyfile"},
					{Type: "bind", Source: filepath.Join(dir, "guards.caddy"), Target: "/etc/caddy/guards.caddy"},
					{Type: "bind", Source: filepath.Join(dir, "entrypoint.sh"), Target: "/paddock/entrypoint.sh"},
				},
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
					"PADDOCK_TRUSTED_PROXY_CIDRS":      ptr("10.0.0.0/8 172.16.0.0/12 fc00::/7 ::1/128"),
					"PADDOCK_IP_ALLOWLIST_BYPASS":      ptr("false"),
				},
				Secrets: []prodcheck.ServiceSecret{
					{Source: "db_paddock_api_url"}, {Source: "db_paddock_audit_reader_url"}, {Source: "release_public_key"},
					{Source: "internal_ca_bundle", Target: "/run/secrets/internal_ca_bundle"},
				},
			},
		},
	}
	harden(f.cfg)
	return f
}

// harden gives every service of cfg the settings of plan M8s decisions 34 and 35 and the log rotation of plan M10
// decision 40.
func harden(cfg prodcheck.Config) {
	for name, s := range cfg.Services {
		s.PidsLimit = 256
		s.Logging = prodcheck.Logging{Driver: "json-file", Options: map[string]string{"max-size": "50m", "max-file": "10"}}
		if strings.HasPrefix(name, "paddock-") || name == "caddy" || name == "caddy-ca-export" {
			s.CapDrop, s.SecurityOpt = []string{"ALL"}, []string{"no-new-privileges:true"}
		}
		if name == "caddy" {
			s.CapAdd = []string{"NET_BIND_SERVICE"}
		}
		cfg.Services[name] = s
	}
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
	if strings.Count(out, "PASS") != 17 {
		t.Fatalf("expected 17 items:\n%s", out)
	}
}

func TestDevelopmentVariableFailsNamingIt(t *testing.T) {
	for _, name := range []string{"PADDOCK_STEPUP_WINDOW", "PADDOCK_STEPUP_MAX_AUTH_AGE", "PADDOCK_STALENESS_UNIT",
		"PADDOCK_TEST_EXTERNAL_DELAY", "PADDOCK_REAPER_THRESHOLD", "PADDOCK_OSV_SYNC_INTERVAL", "PADDOCK_LOGIN_MFA_OPTIONAL",
		"PADDOCK_RETENTION_UNIT"} {
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

// TestUnrotatedContainerLogFailsNamingTheService: a service without max-size or with another log driver fails the
// item with its name, on every host (plan M10 decision 40, M10-11).
func TestUnrotatedContainerLogFailsNamingTheService(t *testing.T) {
	cases := map[string]struct {
		logging prodcheck.Logging
		want    string
	}{
		"no logging block":   {prodcheck.Logging{}, `caddy: logging driver "", want json-file`},
		"max-size unset":     {prodcheck.Logging{Driver: "json-file", Options: map[string]string{"max-file": "10"}}, "caddy: logging option max-size is unset"},
		"other driver":       {prodcheck.Logging{Driver: "local", Options: map[string]string{"max-size": "50m"}}, `caddy: logging driver "local", want json-file`},
		"empty max-size":     {prodcheck.Logging{Driver: "json-file", Options: map[string]string{"max-size": " "}}, "caddy: logging option max-size is unset"},
		"journald forwarder": {prodcheck.Logging{Driver: "journald"}, `caddy: logging driver "journald", want json-file`},
	}
	for name, tc := range cases {
		for _, host := range []string{prodcheck.HostControlPlane, prodcheck.HostAudit, prodcheck.HostLab} {
			t.Run(name+"/"+host, func(t *testing.T) {
				f := newFixture(t)
				s := f.service("caddy")
				s.Logging = tc.logging
				f.cfg.Services["caddy"] = s
				_, out := run(t, f.cfg, prodcheck.Options{Host: host})
				failLine(t, out, tc.want)
				if strings.Contains(out, "PASS  container logs are rotated") {
					t.Fatalf("item passed:\n%s", out)
				}
			})
		}
	}
	t.Run("rotated logs pass", func(t *testing.T) {
		_, out := run(t, newFixture(t).cfg, prodcheck.Options{})
		if !strings.Contains(out, "PASS  container logs are rotated") {
			t.Fatalf("item did not pass:\n%s", out)
		}
	})
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
		// Private to every user of the host, so the world-readable item passes; the Paddock images' user (uid 65532)
		// cannot read an operator's 0600 file either, which TestSecretFilesReadableByServices covers.
		_, out := run(t, f.cfg, prodcheck.Options{})
		if !strings.Contains(out, "PASS  secret files present, not empty and not world-readable") {
			t.Fatalf("0600 files must pass the world-readable item:\n%s", out)
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

// TestSecretFilesReadableByServices: a secret of a Paddock service that the image's user (uid 65532) cannot read fails
// with the file, its mode and owner and the chmod to run; 0644 passes (plan M8x decision 49, lab finding L4).
func TestSecretFilesReadableByServices(t *testing.T) {
	const item = "secret files readable by the Paddock services"
	f := newFixture(t)
	key := f.cfg.Secrets["release_public_key"].File
	if err := os.Chmod(key, 0o600); err != nil {
		t.Fatal(err)
	}
	ok, out := run(t, f.cfg, prodcheck.Options{})
	if ok {
		t.Fatalf("a 0600 release key passed:\n%s", out)
	}
	failItem(t, out, item, "release_public_key is not readable by the service user (uid 65532): "+key+" has mode 0600, owner uid "+
		strconv.Itoa(os.Getuid())+"; run chmod 644 "+key)
	if err := os.Chmod(key, 0o644); err != nil {
		t.Fatal(err)
	}
	if ok, out := run(t, f.cfg, prodcheck.Options{}); !ok || !strings.Contains(out, "PASS  "+item) {
		t.Fatalf("0644 must pass:\n%s", out)
	}
	// A missing file is a finding, not a pass.
	sec := f.cfg.Secrets["release_public_key"]
	sec.File = filepath.Join(f.dir, "gone.pub")
	f.cfg.Secrets["release_public_key"] = sec
	_, out = run(t, f.cfg, prodcheck.Options{})
	failItem(t, out, item, "release_public_key: cannot check")
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

// TestCaddyEdgeFiles: the guards and the entrypoint are mounted from next to the Caddyfile, and the Caddyfile does
// not configure the client address itself (plan M7a decision 24).
func TestCaddyEdgeFiles(t *testing.T) {
	f := newFixture(t)
	caddy := f.service("caddy")
	content := "{\n\tservers {\n\t\ttrusted_proxies static 10.0.0.0/8\n\t\tclient_ip_headers X-Forwarded-For\n\t}\n}\n"
	if err := os.WriteFile(caddy.Volumes[0].Source, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	caddy.Volumes = []prodcheck.Volume{caddy.Volumes[0], {Type: "bind", Source: "/elsewhere/guards.caddy", Target: "/etc/caddy/guards.caddy"}}
	f.cfg.Services["caddy"] = caddy
	_, out := run(t, f.cfg, prodcheck.Options{})
	failLine(t, out, "Caddyfile declares trusted_proxies itself")
	failLine(t, out, "Caddyfile declares client_ip_headers itself")
	failLine(t, out, "/etc/caddy/guards.caddy is mounted from /elsewhere/guards.caddy")
	failLine(t, out, "/paddock/entrypoint.sh is not mounted")
}

// TestEdgeClientAddress: every invalid edge combination of plan M7a decision 24 fails the item, the valid ones pass.
func TestEdgeClientAddress(t *testing.T) {
	cases := []struct {
		header, proxies, listener, want string
	}{
		{"X-Forwarded-For", "0.0.0.0/0", "", "0.0.0.0/0 trusts every address"},
		{"X-Forwarded-For", "10.0.0.0/8 ::/0", "", "::/0 trusts every address"},
		{"CF-Connecting-IP", "", "", "PADDOCK_EDGE_TRUSTED_PROXIES is empty"},
		{"none", "10.0.0.0/8", "", "PADDOCK_EDGE_CLIENT_IP_HEADER is none"},
		{"", "10.0.0.0/8", "", "PADDOCK_EDGE_CLIENT_IP_HEADER is none"},
		{"CF-Connecting-IP X-Forwarded-For", "10.0.0.0/8", "", "is not exactly one of"},
		{"X-Real-IP", "10.0.0.0/8", "", "is not exactly one of"},
		{"X-Forwarded-For", "10.0.0.0/33", "", "10.0.0.0/33 is not a CIDR"},
		{"none", "", ":8443", "PADDOCK_EDGE_SERVERS_LISTENER"},
		{"CF-Connecting-IP", "203.0.113.0/24", "", ""},
		{"X-Forwarded-For", "private_ranges 10.0.0.5 2001:db8::/32", "", ""},
		{"none", "", "", ""},
	}
	for _, tc := range cases {
		f := newFixture(t)
		f.setEnv("caddy", "PADDOCK_EDGE_CLIENT_IP_HEADER", tc.header)
		f.setEnv("caddy", "PADDOCK_EDGE_TRUSTED_PROXIES", tc.proxies)
		f.setEnv("caddy", "PADDOCK_EDGE_SERVERS_LISTENER", tc.listener)
		ok, out := run(t, f.cfg, prodcheck.Options{})
		if tc.want == "" {
			if !ok {
				t.Errorf("header %q proxies %q: expected PASS:\n%s", tc.header, tc.proxies, out)
			}
			continue
		}
		failLine(t, out, tc.want)
		if !strings.Contains(out, "FAIL  edge client address") {
			t.Errorf("header %q proxies %q: the item edge client address did not fail:\n%s", tc.header, tc.proxies, out)
		}
	}
}

// TestRoleTrustedProxies: an unparsable entry or a /0 in PADDOCK_TRUSTED_PROXY_CIDRS fails the item.
func TestRoleTrustedProxies(t *testing.T) {
	for value, want := range map[string]string{
		"10.0.0.0/8 0.0.0.0/0": "paddock-api: PADDOCK_TRUSTED_PROXY_CIDRS: 0.0.0.0/0 trusts every address",
		"::/0":                 "::/0 trusts every address",
		"10.0.0.1":             "10.0.0.1 is not a CIDR",
	} {
		f := newFixture(t)
		f.setEnv("paddock-api", "PADDOCK_TRUSTED_PROXY_CIDRS", value)
		_, out := run(t, f.cfg, prodcheck.Options{})
		failLine(t, out, want)
	}
}

// TestAllowlistBypass: the api's environment bypass of the IP allow list fails prod-check (plan M7a decision 22).
func TestAllowlistBypass(t *testing.T) {
	f := newFixture(t)
	f.setEnv("paddock-api", "PADDOCK_IP_ALLOWLIST_BYPASS", "true")
	_, out := run(t, f.cfg, prodcheck.Options{})
	failLine(t, out, "PADDOCK_IP_ALLOWLIST_BYPASS is true")
}

// TestRetentionInterval: a retention round below one minute fails, an operator's longer interval passes (plan M10
// amendment 2026-10-30).
func TestRetentionInterval(t *testing.T) {
	for value, suffix := range map[string]string{
		"15s":   " is not a duration between 1m0s and 24h0m0s",
		"59s":   "",
		"often": "",
		"24h1s": "",
		"48h":   "",
	} {
		want := "paddock-api: PADDOCK_RETENTION_INTERVAL" + "=" + value + suffix
		f := newFixture(t)
		f.setEnv("paddock-api", "PADDOCK_RETENTION_INTERVAL", value)
		ok, out := run(t, f.cfg, prodcheck.Options{})
		if ok {
			t.Fatalf("%s: expected FAIL:\n%s", value, out)
		}
		failLine(t, out, want)
	}
	for _, value := range []string{"1m", "12h", "24h"} {
		f := newFixture(t)
		f.setEnv("paddock-api", "PADDOCK_RETENTION_INTERVAL", value)
		if ok, out := run(t, f.cfg, prodcheck.Options{}); !ok {
			t.Fatalf("%s: expected all PASS:\n%s", value, out)
		}
	}
}

// TestAuditIndexRetention (ADR 0032 amendment 2026-10-31): prod-check fails where the worker would refuse to start, on
// an audit index retention that is missing (an .env from before the variable), no number, below the bucket default or
// below the WORM retention; the shipped value passes.
func TestAuditIndexRetention(t *testing.T) {
	withWorker := func(env map[string]*string) *fixture {
		f := newFixture(t)
		f.cfg.Services["paddock-worker"] = prodcheck.Service{Environment: env}
		harden(f.cfg)
		return f
	}
	for name, tc := range map[string]struct {
		index, worm string
		want        string
	}{
		"missing":          {"", "400", "PADDOCK_AUDIT_INDEX_RETENTION_DAYS is not set; add it to .env"},
		"no number":        {"four hundred", "400", "PADDOCK_AUDIT_INDEX_RETENTION_DAYS=four hundred is not a number of days of at least 400"},
		"below the bucket": {"399", "", "PADDOCK_AUDIT_INDEX_RETENTION_DAYS=399 is not a number of days of at least 400"},
		"below the WORM":   {"500", "730", "PADDOCK_AUDIT_INDEX_RETENTION_DAYS=500 is not a number of days of at least 730"},
		"WORM no number":   {"400", "x", "PADDOCK_AUDIT_RETENTION_DAYS=x is not a number of days"},
	} {
		f := withWorker(map[string]*string{"PADDOCK_AUDIT_INDEX_RETENTION_DAYS": ptr(tc.index), "PADDOCK_AUDIT_RETENTION_DAYS": ptr(tc.worm)})
		ok, out := run(t, f.cfg, prodcheck.Options{})
		if ok {
			t.Fatalf("%s: expected FAIL:\n%s", name, out)
		}
		failItem(t, out, "audit index retention of the retention round", tc.want)
	}
	for _, env := range []map[string]*string{
		{"PADDOCK_AUDIT_INDEX_RETENTION_DAYS": ptr("400"), "PADDOCK_AUDIT_RETENTION_DAYS": ptr("400")},
		{"PADDOCK_AUDIT_INDEX_RETENTION_DAYS": ptr("730"), "PADDOCK_AUDIT_RETENTION_DAYS": ptr("500")},
	} {
		if ok, out := run(t, withWorker(env).cfg, prodcheck.Options{}); !ok {
			t.Fatalf("%v: expected all PASS:\n%s", env, out)
		}
	}
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

const (
	labProxy     = "192.0.2.5"
	labDomain    = "paddock.example.org"
	labCaddyfile = "{\n\tauto_https off\n\thttp_port 80\n\t{$CADDY_SERVERS_BLOCK}\n}\n\nimport /etc/caddy/guards.caddy\n\n" +
		"(lab_snippet) {\n}\n\nhttp://admin.{$PADDOCK_DOMAIN} {\n\timport admin_site\n}\n\n" +
		"http://auth.{$PADDOCK_DOMAIN}, http://fleet.{$PADDOCK_DOMAIN} {\n\timport authentik_site\n}\n"
)

// labItems are the items of a lab host's offline checklist (plan M8a §6.2).
var labItems = []string{
	"compose.dev.yaml is not in the effective configuration",
	"PADDOCK_ENV=production in every service",
	"no development-only variables",
	"revocation path enabled only after its acceptance",
	"secret files present, not empty and not world-readable",
	"secret files readable by the Paddock services",
	"secrets the services reference are mounted",
	"openbao auto-unseal",
	"container logs are rotated",
	"only Caddy's HTTP port published, on the bind address",
	"links between the hosts use TLS",
	"container hardening",
	"Caddy: plain HTTP behind the TLS proxy",
	"edge client address",
	"lab: edge admin allow list",
	"lab: caddy has no hostname aliases",
	"lab: roles resolve the public names to the proxy",
	"role trusted proxies",
	"ip allow list bypass is off",
	"audit index retention of the retention round",
	"release public keys are production keys",
}

func labHosts() []string {
	var hosts []string
	for _, n := range []string{"admin", "auth", "device", "bundles", "fleet"} {
		hosts = append(hosts, n+"."+labDomain+"="+labProxy)
	}
	return hosts
}

// newLabFixture is a passing lab configuration (plan M8a decision 13): the production fixture with Caddy's one
// plain-HTTP port on the bind address, an http:// Caddyfile, no ACME e-mail, no aliases and the roles' extra hosts.
func newLabFixture(t *testing.T) *fixture {
	t.Helper()
	f := newFixture(t)
	f.cfg.Prod.LabProxyAddr = labProxy
	caddyfile := filepath.Join(f.dir, "Caddyfile.lab")
	if err := os.WriteFile(caddyfile, []byte(labCaddyfile), 0o644); err != nil {
		t.Fatal(err)
	}
	caddy := f.service("caddy")
	caddy.Volumes[0].Source = caddyfile
	caddy.Environment = map[string]*string{
		"PADDOCK_ACME_EMAIL":            ptr(""),
		"PADDOCK_EDGE_CLIENT_IP_HEADER": ptr("X-Forwarded-For"),
		"PADDOCK_EDGE_TRUSTED_PROXIES":  ptr(labProxy),
		"PADDOCK_ADMIN_ALLOWED_CIDRS":   ptr("192.0.2.0/24 private_ranges"),
	}
	caddy.Ports = []prodcheck.Port{{HostIP: interconnect, Target: 80, Published: "8080"}}
	caddy.Networks = map[string]prodcheck.ServiceNetwork{"cp": {}}
	f.cfg.Services["caddy"] = caddy
	f.cfg.Services["rabbitmq"] = prodcheck.Service{}
	api := f.service("paddock-api")
	api.Environment["PADDOCK_PUBLIC_ADMIN_URL"] = ptr("https://admin." + labDomain)
	api.ExtraHosts = labHosts()
	f.cfg.Services["paddock-api"] = api
	f.cfg.Services["paddock-escrow-reader"] = prodcheck.Service{ExtraHosts: labHosts()}
	f.cfg.Services["paddock-revocation-issuer"] = prodcheck.Service{ExtraHosts: labHosts()}
	f.cfg.Services["paddock-worker"] = prodcheck.Service{
		ExtraHosts: labHosts(),
		Environment: map[string]*string{"PADDOCK_TLS_PROBE_ADDR": ptr(labProxy + ":443"),
			"PADDOCK_AUDIT_RETENTION_DAYS": ptr("400"), "PADDOCK_AUDIT_INDEX_RETENTION_DAYS": ptr("400")},
	}
	harden(f.cfg)
	return f
}

func runLab(t *testing.T, cfg prodcheck.Config, reader prodcheck.ObjectLockReader) (bool, string) {
	t.Helper()
	return run(t, cfg, prodcheck.Options{Host: prodcheck.HostLab, ObjectLock: reader})
}

// failItem asserts that the item fails with a finding containing want.
func failItem(t *testing.T, out, item, want string) {
	t.Helper()
	in := false
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "PASS") || strings.HasPrefix(line, "FAIL") {
			in = line == "FAIL  "+item
			continue
		}
		if in && strings.Contains(line, want) {
			return
		}
	}
	t.Fatalf("item %q has no FAIL finding containing %q in\n%s", item, want, out)
}

func items(out string) []string {
	var names []string
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "PASS  ") || strings.HasPrefix(line, "FAIL  ") {
			names = append(names, line[6:])
		}
	}
	return names
}

// TestLabConfigurationPasses: the lab fixture passes exactly the items of plan M8a §6.2; the Object Lock item joins
// only online.
func TestLabConfigurationPasses(t *testing.T) {
	f := newLabFixture(t)
	ok, out := runLab(t, f.cfg, nil)
	if !ok {
		t.Fatalf("expected all PASS:\n%s", out)
	}
	if got := strings.Join(items(out), "\n"); got != strings.Join(labItems, "\n") {
		t.Fatalf("items:\n%s\nwant:\n%s", got, strings.Join(labItems, "\n"))
	}
	ok, out = runLab(t, f.cfg, lockReader{enabled: true, mode: "COMPLIANCE", days: 400})
	want := append(slices.Clone(labItems), "audit bucket has Object Lock COMPLIANCE")
	if !ok || strings.Join(items(out), "\n") != strings.Join(want, "\n") {
		t.Fatalf("online: expected every item of the lab and the Object Lock item to PASS:\n%s", out)
	}
	_, out = runLab(t, f.cfg, lockReader{enabled: true, mode: "COMPLIANCE", days: 30})
	failItem(t, out, "audit bucket has Object Lock COMPLIANCE", "less than 400")
}

// TestACMEEmailOnlyInProduction: an empty ACME e-mail passes in the lab and still fails in production.
func TestACMEEmailOnlyInProduction(t *testing.T) {
	f := newFixture(t)
	f.setEnv("caddy", "PADDOCK_ACME_EMAIL", "")
	_, out := run(t, f.cfg, prodcheck.Options{Host: prodcheck.HostControlPlane})
	failItem(t, out, "Caddy: public ACME certificates, edge guards and entrypoint mounted", "PADDOCK_ACME_EMAIL is not set")

	lab := newLabFixture(t)
	if v := lab.service("caddy").Environment["PADDOCK_ACME_EMAIL"]; v == nil || *v != "" {
		t.Fatal("the lab fixture must carry an empty ACME e-mail")
	}
	if ok, out := runLab(t, lab.cfg, nil); !ok || strings.Contains(out, "ACME") {
		t.Fatalf("expected the lab to pass without an ACME item:\n%s", out)
	}
}

// TestLabFindings: every new finding of plan M8a decision 12 fails its item.
func TestLabFindings(t *testing.T) {
	const (
		ports    = "only Caddy's HTTP port published, on the bind address"
		caddy    = "Caddy: plain HTTP behind the TLS proxy"
		edge     = "edge client address"
		admin    = "lab: edge admin allow list"
		aliases  = "lab: caddy has no hostname aliases"
		resolver = "lab: roles resolve the public names to the proxy"
	)
	writeCaddyfile := func(content string) func(*testing.T, *fixture) {
		return func(t *testing.T, f *fixture) {
			if err := os.WriteFile(f.service("caddy").Volumes[0].Source, []byte(content), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	setCaddyPorts := func(p ...prodcheck.Port) func(*testing.T, *fixture) {
		return func(_ *testing.T, f *fixture) {
			s := f.service("caddy")
			s.Ports = p
			f.cfg.Services["caddy"] = s
		}
	}
	setHosts := func(service string, hosts []string) func(*testing.T, *fixture) {
		return func(_ *testing.T, f *fixture) {
			s := f.service(service)
			s.ExtraHosts = hosts
			f.cfg.Services[service] = s
		}
	}
	setEnv := func(service, name, value string) func(*testing.T, *fixture) {
		return func(_ *testing.T, f *fixture) { f.setEnv(service, name, value) }
	}
	cases := map[string]struct {
		mutate     func(*testing.T, *fixture)
		item, want string
	}{
		"second caddy port": {setCaddyPorts(
			prodcheck.Port{HostIP: interconnect, Target: 80, Published: "8080"},
			prodcheck.Port{HostIP: interconnect, Target: 80, Published: "8081"},
		), ports, "caddy: publishes 2 ports, want exactly one"},
		"no caddy port": {setCaddyPorts(), ports, "caddy: publishes 0 ports, want exactly one"},
		"other service publishes": {func(_ *testing.T, f *fixture) {
			f.cfg.Services["rabbitmq"] = prodcheck.Service{Ports: []prodcheck.Port{{HostIP: interconnect, Target: 5671, Published: "5671"}}}
		}, ports, "rabbitmq: port 5671 published; the lab publishes nothing but Caddy"},
		"caddy on every address": {setCaddyPorts(prodcheck.Port{Target: 80, Published: "8080"}),
			ports, `caddy: port 8080 published on "0.0.0.0", not on the bind address`},
		"caddy to the TLS port": {setCaddyPorts(prodcheck.Port{HostIP: interconnect, Target: 443, Published: "8080"}),
			ports, "caddy: port 8080 forwards to 443"},
		"no bind address": {func(_ *testing.T, f *fixture) { f.cfg.Prod.InterconnectAddr = "" },
			ports, `PADDOCK_INTERCONNECT_ADDR "" is not a specific IP address`},
		"https site": {writeCaddyfile("{\n\tauto_https off\n}\nhttps://admin.{$PADDOCK_DOMAIN} {\n}\n"),
			caddy, `Caddyfile site "https://admin.{$PADDOCK_DOMAIN}" is not an http:// site`},
		"bare site": {writeCaddyfile("{\n\tauto_https off\n}\nhttp://auth.{$PADDOCK_DOMAIN}, admin.{$PADDOCK_DOMAIN} {\n}\n"),
			caddy, `Caddyfile site "admin.{$PADDOCK_DOMAIN}" is not an http:// site`},
		"https in a multi-line address list": {writeCaddyfile("{\n\tauto_https off\n}\nhttp://admin.{$PADDOCK_DOMAIN},\n\thttps://auth.{$PADDOCK_DOMAIN} {\n}\n"),
			caddy, `Caddyfile site "https://auth.{$PADDOCK_DOMAIN}" is not an http:// site`},
		"https site with a comment after the brace": {writeCaddyfile("{\n\tauto_https off\n}\nhttps://admin.{$PADDOCK_DOMAIN} { # portal\n}\n"),
			caddy, `Caddyfile site "https://admin.{$PADDOCK_DOMAIN}" is not an http:// site`},
		"indented https site": {writeCaddyfile("{\n\tauto_https off\n}\n  https://admin.{$PADDOCK_DOMAIN} {\n}\n"),
			caddy, `Caddyfile site "https://admin.{$PADDOCK_DOMAIN}" is not an http:// site`},
		"no auto_https off": {writeCaddyfile("{\n\tauto_https disable_redirects\n}\nhttp://admin.{$PADDOCK_DOMAIN} {\n}\n"),
			caddy, "Caddyfile does not set auto_https off"},
		"tls internal": {writeCaddyfile(labCaddyfile + "http://bundles.{$PADDOCK_DOMAIN} {\n\ttls internal\n}\n"),
			caddy, "Caddyfile uses tls internal"},
		"guards elsewhere": {func(_ *testing.T, f *fixture) {
			s := f.service("caddy")
			s.Volumes[1].Source = "/elsewhere/guards.caddy"
			f.cfg.Services["caddy"] = s
		}, caddy, "/etc/caddy/guards.caddy is mounted from /elsewhere/guards.caddy"},
		"CF-Connecting-IP": {setEnv("caddy", "PADDOCK_EDGE_CLIENT_IP_HEADER", "CF-Connecting-IP"),
			edge, "PADDOCK_EDGE_CLIENT_IP_HEADER must be X-Forwarded-For behind the lab proxy"},
		"private_ranges": {setEnv("caddy", "PADDOCK_EDGE_TRUSTED_PROXIES", "private_ranges"),
			edge, "PADDOCK_EDGE_TRUSTED_PROXIES: private_ranges trusts every LAN peer; name the proxy's address"},
		"no trusted proxies": {setEnv("caddy", "PADDOCK_EDGE_TRUSTED_PROXIES", ""),
			edge, "PADDOCK_EDGE_TRUSTED_PROXIES is empty: name the lab proxy's address"},
		"admin /0": {setEnv("caddy", "PADDOCK_ADMIN_ALLOWED_CIDRS", "192.0.2.0/24 ::/0"),
			admin, "PADDOCK_ADMIN_ALLOWED_CIDRS: ::/0 trusts every address"},
		"admin empty": {setEnv("caddy", "PADDOCK_ADMIN_ALLOWED_CIDRS", ""),
			admin, "PADDOCK_ADMIN_ALLOWED_CIDRS is empty"},
		"alias": {func(_ *testing.T, f *fixture) {
			s := f.service("caddy")
			s.Networks = map[string]prodcheck.ServiceNetwork{"cp": {Aliases: []string{"admin." + labDomain}}}
			f.cfg.Services["caddy"] = s
		}, aliases, "caddy: alias admin.paddock.example.org on network cp would short-circuit the proxy"},
		"missing extra host": {setHosts("paddock-escrow-reader", labHosts()[:4]),
			resolver, "paddock-escrow-reader: extra_hosts lacks fleet.paddock.example.org=192.0.2.5"},
		"extra host to another address": {setHosts("paddock-revocation-issuer", []string{"auth." + labDomain + "=192.0.2.99"}),
			resolver, "paddock-revocation-issuer: extra_hosts maps auth.paddock.example.org to 192.0.2.99, not to the proxy 192.0.2.5"},
		"conflicting extra host": {setHosts("paddock-api", append([]string{"admin." + labDomain + "=10.9.9.9"}, labHosts()...)),
			resolver, "paddock-api: extra_hosts maps admin.paddock.example.org to 10.9.9.9, not to the proxy 192.0.2.5"},
		"conflicting extra host in upper case": {setHosts("paddock-api", append([]string{"ADMIN." + labDomain + "=10.9.9.9"}, labHosts()...)),
			resolver, "paddock-api: extra_hosts maps admin.paddock.example.org to 10.9.9.9, not to the proxy 192.0.2.5"},
		"conflicting extra host with a trailing dot": {setHosts("paddock-api", append([]string{"admin." + labDomain + ".=10.9.9.9"}, labHosts()...)),
			resolver, "paddock-api: extra_hosts maps admin.paddock.example.org to 10.9.9.9, not to the proxy 192.0.2.5"},
		"lab network_mode host": {func(_ *testing.T, f *fixture) {
			s := f.service("paddock-worker")
			s.NetworkMode = "host"
			f.cfg.Services["paddock-worker"] = s
		}, ports, "paddock-worker: network_mode host exposes every port of the service on the host"},
		"wrong probe address": {setEnv("paddock-worker", "PADDOCK_TLS_PROBE_ADDR", "caddy:443"),
			resolver, `paddock-worker: PADDOCK_TLS_PROBE_ADDR is "caddy:443", not 192.0.2.5:443`},
		"unspecific proxy address": {func(_ *testing.T, f *fixture) { f.cfg.Prod.LabProxyAddr = "0.0.0.0" },
			resolver, `PADDOCK_LAB_PROXY_ADDR "0.0.0.0" is not a specific IP address`},
		"no proxy address": {func(_ *testing.T, f *fixture) { f.cfg.Prod.LabProxyAddr = "" },
			resolver, `PADDOCK_LAB_PROXY_ADDR "" is not a specific IP address`},
		"admin URL without admin.": {setEnv("paddock-api", "PADDOCK_PUBLIC_ADMIN_URL", "https://portal."+labDomain),
			resolver, `PADDOCK_PUBLIC_ADMIN_URL "https://portal.paddock.example.org" is not https://admin.<domain>`},
		"admin URL over http": {setEnv("paddock-api", "PADDOCK_PUBLIC_ADMIN_URL", "http://admin."+labDomain),
			resolver, `PADDOCK_PUBLIC_ADMIN_URL "http://admin.paddock.example.org" is not https://admin.<domain>`},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := newLabFixture(t)
			tc.mutate(t, f)
			ok, out := runLab(t, f.cfg, nil)
			if ok {
				t.Fatalf("expected FAIL:\n%s", out)
			}
			failItem(t, out, tc.item, tc.want)
		})
	}
}

// TestNetworkModeOnEveryHost: a service in the host's network namespace, or in a namespace the configuration does not
// describe, fails the ports item on every host; sharing a checked service's namespace and network_mode none pass
// (PDK-104).
func TestNetworkModeOnEveryHost(t *testing.T) {
	portItems := map[string]string{
		prodcheck.HostControlPlane: "only 80/443 published, other ports on the interconnect address only",
		prodcheck.HostAudit:        "only 80/443 published, other ports on the interconnect address only",
		prodcheck.HostLab:          "only Caddy's HTTP port published, on the bind address",
	}
	for host, item := range portItems {
		t.Run(host, func(t *testing.T) {
			for mode, want := range map[string]string{
				"host":            "postgres: network_mode host exposes every port of the service on the host",
				"container:other": "postgres: network_mode container:other shares a network namespace this check does not see",
				"service:missing": "postgres: network_mode service:missing shares a network namespace this check does not see",
				"service:caddy":   "",
				"none":            "",
			} {
				f := newLabFixture(t)
				f.cfg.Services["postgres"] = prodcheck.Service{NetworkMode: mode}
				_, out := run(t, f.cfg, prodcheck.Options{Host: host})
				if want == "" {
					if strings.Contains(out, "network_mode") {
						t.Errorf("network_mode %s: unexpected finding:\n%s", mode, out)
					}
					continue
				}
				failItem(t, out, item, want)
			}
		})
	}
}

// TestParseLabShapes:extra_hosts and service networks in the shape `docker compose config --format json` renders
// (plan M8a §2), including a network without options.
func TestParseLabShapes(t *testing.T) {
	cfg, err := prodcheck.Parse(strings.NewReader(`{"services":{
		"caddy":{"networks":{"cp":{"aliases":["admin.example.org","auth.example.org"]},"edge":null}},
		"paddock-api":{"extra_hosts":["admin.example.org=192.0.2.5","auth.example.org=192.0.2.5"],"networks":{"cp":{}}},
		"proxy":{"network_mode":"host"}},
		"x-paddock-prod":{"interconnect_addr":"192.0.2.10","revocation_accepted":"no","lab_proxy_addr":"192.0.2.5"}}`))
	if err != nil {
		t.Fatal(err)
	}
	caddy, api := cfg.Services["caddy"], cfg.Services["paddock-api"]
	if !slices.Equal(caddy.Networks["cp"].Aliases, []string{"admin.example.org", "auth.example.org"}) ||
		len(caddy.Networks["edge"].Aliases) != 0 || len(caddy.Networks) != 2 ||
		!slices.Equal(api.ExtraHosts, []string{"admin.example.org=192.0.2.5", "auth.example.org=192.0.2.5"}) ||
		cfg.Prod.LabProxyAddr != "192.0.2.5" || cfg.Services["proxy"].NetworkMode != "host" {
		t.Fatalf("unexpected parse result: %+v", cfg)
	}
}

// TestContainerHardeningFindings: each setting of plan M8s decision 36 fails the item, naming the service.
func TestContainerHardeningFindings(t *testing.T) {
	cases := map[string]struct {
		edit func(*fixture)
		want string
	}{
		"role keeps capabilities": {func(f *fixture) {
			s := f.service("paddock-api")
			s.CapDrop = nil
			f.cfg.Services["paddock-api"] = s
		}, "paddock-api: cap_drop is not [ALL]"},
		"role may gain privileges": {func(f *fixture) {
			s := f.service("paddock-api")
			s.SecurityOpt = []string{"label:disable"}
			f.cfg.Services["paddock-api"] = s
		}, "paddock-api: security_opt lacks no-new-privileges:true"},
		"role adds a capability": {func(f *fixture) {
			s := f.service("paddock-api")
			s.CapAdd = []string{"NET_ADMIN"}
			f.cfg.Services["paddock-api"] = s
		}, "paddock-api: cap_add [NET_ADMIN]"},
		"caddy adds more than the bind": {func(f *fixture) {
			s := f.service("caddy")
			s.CapAdd = []string{"NET_BIND_SERVICE", "SYS_ADMIN"}
			f.cfg.Services["caddy"] = s
		}, "caddy: cap_add [NET_BIND_SERVICE SYS_ADMIN], want [NET_BIND_SERVICE]"},
		"caddy keeps capabilities": {func(f *fixture) {
			s := f.service("caddy")
			s.CapDrop = []string{"NET_RAW"}
			f.cfg.Services["caddy"] = s
		}, "caddy: cap_drop is not [ALL]"},
		"third-party service without a process bound": {func(f *fixture) {
			s := f.service("postgres")
			s.PidsLimit = 0
			f.cfg.Services["postgres"] = s
		}, "postgres: no pids_limit"},
		"unbounded processes": {func(f *fixture) {
			s := f.service("rabbitmq")
			s.PidsLimit = -1
			f.cfg.Services["rabbitmq"] = s
		}, "rabbitmq: no pids_limit"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			tc.edit(f)
			_, out := run(t, f.cfg, prodcheck.Options{})
			failItem(t, out, "container hardening", tc.want)
		})
	}
	t.Run("a third-party service keeps its capabilities", func(t *testing.T) {
		f := newFixture(t)
		s := f.service("postgres")
		s.CapAdd = []string{"IPC_LOCK"}
		f.cfg.Services["postgres"] = s
		if ok, out := run(t, f.cfg, prodcheck.Options{}); !ok {
			t.Fatalf("expected all PASS:\n%s", out)
		}
	})
}

// TestAuthentikWebWorkersItem: the item fails unless authentik-server's AUTHENTIK_WEB__WORKERS is an integer of at least 1,
// since Authentik falls back to 2 workers on an unparsable value and serves no login with 0 (PDK-545).
func TestAuthentikWebWorkersItem(t *testing.T) {
	for _, c := range []struct {
		value string
		ok    bool
	}{{"4", true}, {"1", true}, {" 8 ", true}, {"0", false}, {"-1", false}, {"abc", false}, {"2.5", false}, {"", false}} {
		t.Run(c.value, func(t *testing.T) {
			f := newFixture(t)
			f.cfg.Services["authentik-server"] = prodcheck.Service{Environment: map[string]*string{"AUTHENTIK_WEB__WORKERS": ptr(c.value)}}
			var got *prodcheck.Result
			for _, r := range prodcheck.Run(context.Background(), f.cfg, prodcheck.Options{Host: prodcheck.HostControlPlane}) {
				if r.Item == "authentik web workers" {
					got = &r
				}
			}
			if got == nil {
				t.Fatal("no item authentik web workers")
			}
			if got.OK != c.ok {
				t.Fatalf("AUTHENTIK_WEB__WORKERS=%q: OK = %v, want %v (%s)", c.value, got.OK, c.ok, got.Detail)
			}
		})
	}
	t.Run("no authentik-server, no item", func(t *testing.T) {
		for _, r := range prodcheck.Run(context.Background(), newFixture(t).cfg, prodcheck.Options{Host: prodcheck.HostControlPlane}) {
			if r.Item == "authentik web workers" {
				t.Fatal("item present without authentik-server")
			}
		}
	})
}
