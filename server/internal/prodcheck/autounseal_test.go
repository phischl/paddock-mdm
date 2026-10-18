package prodcheck_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/phischl/paddock-mdm/server/internal/prodcheck"
)

const autoUnsealRisk = "automatic unseal is on: whoever controls this host or a copy of its disk, snapshots or .secrets/ can unseal OpenBao and use every key; the custodian threshold of ADR 0006 does not gate the unseal (residual risk RR-43)"

// withUnsealer adds the unsealer of compose.auto-unseal.yaml with its secret files (shares 0644 in the 0700
// secrets directory) and sets the switch.
func withUnsealer(t *testing.T, f *fixture, mode os.FileMode) string {
	t.Helper()
	secrets := filepath.Join(f.dir, "secrets")
	shares := filepath.Join(secrets, "openbao", "auto-unseal-shares")
	if err := os.MkdirAll(filepath.Dir(shares), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(shares, []byte("s1\ns2\ns3\n"), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(shares, mode); err != nil {
		t.Fatal(err)
	}
	url := filepath.Join(secrets, "db_paddock_unsealer_url")
	if err := os.WriteFile(url, []byte("postgres://paddock_unsealer:pw@postgres:5432/paddock"), 0o644); err != nil {
		t.Fatal(err)
	}
	f.cfg.Secrets["openbao_auto_unseal_shares"] = prodcheck.Secret{File: shares}
	f.cfg.Secrets["db_paddock_unsealer_url"] = prodcheck.Secret{File: url}
	f.cfg.Services["paddock-unsealer"] = prodcheck.Service{
		Environment: map[string]*string{
			"PADDOCK_ENV":                        ptr("production"),
			"PADDOCK_LOG_LEVEL":                  ptr("info"),
			"PADDOCK_OPS_ADDR":                   ptr(":9090"),
			"PADDOCK_DB_UNSEALER_URL_FILE":       ptr("/run/secrets/db_paddock_unsealer_url"),
			"PADDOCK_OPENBAO_ADDR":               ptr("https://openbao:8200"),
			"BAO_CACERT":                         ptr("/run/secrets/internal_ca_bundle"),
			"PADDOCK_OPENBAO_UNSEAL_SHARES_FILE": ptr("/run/secrets/openbao_auto_unseal_shares"),
		},
		Secrets: []prodcheck.ServiceSecret{
			{Source: "db_paddock_unsealer_url"}, {Source: "openbao_auto_unseal_shares"}, {Source: "internal_ca_bundle"},
		},
		CapDrop: []string{"ALL"}, SecurityOpt: []string{"no-new-privileges:true"}, PidsLimit: 256,
	}
	f.cfg.Prod.AutoUnseal = "yes"
	return shares
}

// itemBlock returns the status line and the detail lines of item.
func itemBlock(t *testing.T, out, item string) (status, detail string) {
	t.Helper()
	lines := strings.Split(out, "\n")
	for i, line := range lines {
		if len(line) > 6 && line[6:] == item {
			var d []string
			for _, l := range lines[i+1:] {
				if !strings.HasPrefix(l, "      - ") {
					break
				}
				d = append(d, strings.TrimPrefix(l, "      - "))
			}
			return line[:4], strings.Join(d, "\n")
		}
	}
	t.Fatalf("no item %q in\n%s", item, out)
	return "", ""
}

// TestAutoUnsealCheck covers plan M8u decision 20: a production control plane with automatic unseal passes with a
// warning naming RR-43 (exit code unchanged), a lab passes with the same detail, a host without it passes "off".
func TestAutoUnsealCheck(t *testing.T) {
	f := newFixture(t)
	ok, out := run(t, f.cfg, prodcheck.Options{})
	if status, detail := itemBlock(t, out, "openbao auto-unseal"); !ok || status != "PASS" || detail != "automatic unseal is off" {
		t.Fatalf("without automatic unseal: ok=%v %s %q\n%s", ok, status, detail, out)
	}

	withUnsealer(t, f, 0o644)
	ok, out = run(t, f.cfg, prodcheck.Options{})
	if status, detail := itemBlock(t, out, "openbao auto-unseal"); !ok || status != "WARN" || detail != autoUnsealRisk {
		t.Fatalf("control plane with automatic unseal: ok=%v %s %q\n%s", ok, status, detail, out)
	}
	if !strings.Contains(out, "WARN  openbao auto-unseal\n      - "+autoUnsealRisk+"\n") {
		t.Fatalf("the warning is not printed as WARN with its detail:\n%s", out)
	}

	lab := newLabFixture(t)
	withUnsealer(t, lab, 0o644)
	ok, out = runLab(t, lab.cfg, nil)
	if status, detail := itemBlock(t, out, "openbao auto-unseal"); !ok || status != "PASS" || detail != autoUnsealRisk {
		t.Fatalf("lab with automatic unseal: ok=%v %s %q\n%s", ok, status, detail, out)
	}
}

// TestWriteWarn: a warning prints WARN and never fails the checklist; a failure still does.
func TestWriteWarn(t *testing.T) {
	var out bytes.Buffer
	ok := prodcheck.Write(&out, []prodcheck.Result{
		{Item: "a", OK: true}, {Item: "b", OK: true, Warn: true, Detail: "careful"},
	})
	if !ok || out.String() != "PASS  a\nWARN  b\n      - careful\n" {
		t.Fatalf("Write = %v %q", ok, out.String())
	}
	out.Reset()
	if prodcheck.Write(&out, []prodcheck.Result{{Item: "b", OK: true, Warn: true}, {Item: "c", Detail: "x"}}) ||
		out.String() != "WARN  b\nFAIL  c\n      - x\n" {
		t.Fatalf("Write with a failure = %q", out.String())
	}
}

// TestAutoUnsealCheckFindings: every FAIL finding of decision 20, with its exact text.
func TestAutoUnsealCheckFindings(t *testing.T) {
	for _, tc := range []struct {
		name   string
		host   string
		edit   func(f *fixture)
		detail string
	}{
		{"overlay without the switch", prodcheck.HostControlPlane, func(f *fixture) { f.cfg.Prod.AutoUnseal = "no" },
			"paddock-unsealer is configured but PADDOCK_AUTO_UNSEAL is not yes"},
		{"switch without the overlay", prodcheck.HostControlPlane, func(f *fixture) { delete(f.cfg.Services, "paddock-unsealer") },
			"PADDOCK_AUTO_UNSEAL=yes but paddock-unsealer is not in the configuration"},
		{"switch on the audit host", prodcheck.HostAudit, func(f *fixture) { delete(f.cfg.Services, "paddock-unsealer") },
			"PADDOCK_AUTO_UNSEAL=yes on the audit host: there is no OpenBao here"},
		{"shares in another service", prodcheck.HostControlPlane, func(f *fixture) {
			s := f.cfg.Services["paddock-api"]
			s.Secrets = append(s.Secrets, prodcheck.ServiceSecret{Source: "openbao_auto_unseal_shares"})
			f.cfg.Services["paddock-api"] = s
		}, "paddock-api: mounts openbao_auto_unseal_shares"},
		{"an AppRole in the unsealer", prodcheck.HostControlPlane, func(f *fixture) { addUnsealerSecret(f, "approle_worker_role_id") },
			"paddock-unsealer: mounts approle_worker_role_id"},
		{"another database URL in the unsealer", prodcheck.HostControlPlane, func(f *fixture) { addUnsealerSecret(f, "db_paddock_platform_url") },
			"paddock-unsealer: mounts db_paddock_platform_url"},
		{"Valkey in the unsealer", prodcheck.HostControlPlane, func(f *fixture) { f.setEnv("paddock-unsealer", "PADDOCK_VALKEY_ADDR", "valkey:6379") },
			"paddock-unsealer: PADDOCK_VALKEY_ADDR is set"},
		{"an AppRole variable in the unsealer", prodcheck.HostControlPlane, func(f *fixture) {
			f.setEnv("paddock-unsealer", "PADDOCK_OPENBAO_ROLE_ID_FILE", "/run/secrets/approle_worker_role_id")
		}, "paddock-unsealer: PADDOCK_OPENBAO_ROLE_ID_FILE is set"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			withUnsealer(t, f, 0o644)
			tc.edit(f)
			ok, out := run(t, f.cfg, prodcheck.Options{Host: tc.host})
			status, detail := itemBlock(t, out, "openbao auto-unseal")
			if ok || status != "FAIL" || !strings.Contains("\n"+detail+"\n", "\n"+tc.detail+"\n") {
				t.Fatalf("ok=%v %s %q, want FAIL with %q\n%s", ok, status, detail, tc.detail, out)
			}
		})
	}
}

func addUnsealerSecret(f *fixture, name string) {
	f.cfg.Secrets[name] = prodcheck.Secret{File: f.cfg.Secrets["db_paddock_unsealer_url"].File}
	s := f.cfg.Services["paddock-unsealer"]
	s.Secrets = append(s.Secrets, prodcheck.ServiceSecret{Source: name})
	f.cfg.Services["paddock-unsealer"] = s
}

// TestAutoUnsealGenericItems: the generic items apply to the unsealer unchanged, and the shares file is checked like
// every secret file: 0644 in the 0700 directory passes both secret items, 0600 is unreadable by the service user,
// 0644 in a directory others may enter is readable by every user of the host, an empty file is refused.
func TestAutoUnsealGenericItems(t *testing.T) {
	const (
		present  = "secret files present, not empty and not world-readable"
		readable = "secret files readable by the Paddock services"
	)
	f := newFixture(t)
	withUnsealer(t, f, 0o644)
	_, out := run(t, f.cfg, prodcheck.Options{})
	for _, item := range []string{present, readable, "container hardening", "PADDOCK_ENV=production in every service"} {
		if status, _ := itemBlock(t, out, item); status != "PASS" {
			t.Fatalf("%s with the shares 0644 in the 0700 directory: %s\n%s", item, status, out)
		}
	}

	f = newFixture(t)
	withUnsealer(t, f, 0o600)
	_, out = run(t, f.cfg, prodcheck.Options{})
	failItem(t, out, readable, "paddock-unsealer: openbao_auto_unseal_shares is not readable by the service user")

	f = newFixture(t)
	shares := withUnsealer(t, f, 0o644)
	if err := os.WriteFile(shares, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	_, out = run(t, f.cfg, prodcheck.Options{})
	failItem(t, out, present, "openbao_auto_unseal_shares: empty")

	f = newFixture(t)
	withUnsealer(t, f, 0o644)
	f.setEnv("paddock-unsealer", "PADDOCK_ENV", "development")
	_, out = run(t, f.cfg, prodcheck.Options{})
	failItem(t, out, "PADDOCK_ENV=production in every service", "paddock-unsealer")

	f = newFixture(t)
	withUnsealer(t, f, 0o644)
	s := f.cfg.Services["paddock-unsealer"]
	s.CapDrop = nil
	f.cfg.Services["paddock-unsealer"] = s
	_, out = run(t, f.cfg, prodcheck.Options{})
	failItem(t, out, "container hardening", "paddock-unsealer")
}

// TestAutoUnsealSharesWorldReadable: the shares file 0644 in directories every user may enter is readable by every
// user of the host and fails like every secret file.
func TestAutoUnsealSharesWorldReadable(t *testing.T) {
	f := newFixture(t)
	shares := withUnsealer(t, f, 0o644)
	if err := os.Chmod(filepath.Join(f.dir, "secrets"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Dir(shares), 0o755); err != nil {
		t.Fatal(err)
	}
	// t.TempDir's own directories are private as well; open every one up to the system's temporary directory.
	d := f.dir
	for ; d != filepath.Clean(os.TempDir()) && d != "/"; d = filepath.Dir(d) {
		if err := os.Chmod(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for ; d != "/"; d = filepath.Dir(d) {
		if fi, err := os.Stat(d); err != nil || fi.Mode().Perm()&0o001 == 0 {
			t.Skipf("%s is private: a world-readable secret file cannot be set up below it", d)
		}
	}
	_, out := run(t, f.cfg, prodcheck.Options{})
	failItem(t, out, "secret files present, not empty and not world-readable", "openbao_auto_unseal_shares: readable by every user of the host")
}
