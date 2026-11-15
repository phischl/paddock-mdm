package prodcheck_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/phischl/paddock-mdm/server/internal/prodcheck"
)

// offboardVars are the organization deletion's secrets and the variables naming their files (plan M17 amendment k).
var offboardVars = map[string]string{
	"rustfs_bundles_offboard_access_key": "PADDOCK_OFFBOARD_BUNDLES_S3_ACCESS_KEY_FILE",
	"rustfs_bundles_offboard_secret_key": "PADDOCK_OFFBOARD_BUNDLES_S3_SECRET_KEY_FILE",
	"rustfs_escrow_offboard_access_key":  "PADDOCK_OFFBOARD_ESCROW_S3_ACCESS_KEY_FILE",
	"rustfs_escrow_offboard_secret_key":  "PADDOCK_OFFBOARD_ESCROW_S3_SECRET_KEY_FILE",
}

// withOffboardCredentials returns the worker s with the organization deletion's four secrets and variables, as the
// shipped Compose files configure it.
func withOffboardCredentials(s prodcheck.Service) prodcheck.Service {
	env := map[string]*string{}
	for k, v := range s.Environment {
		env[k] = v
	}
	s.Environment = env
	s.Secrets = append([]prodcheck.ServiceSecret(nil), s.Secrets...)
	for secret, v := range offboardVars {
		s.Secrets = append(s.Secrets, prodcheck.ServiceSecret{Source: secret, Target: "/run/secrets/" + secret})
		s.Environment[v] = ptr("/run/secrets/" + secret)
	}
	return s
}

// offboardWorker is withOffboardCredentials for a fixture: the four secret files exist, so the other items that read
// them pass as on a host after ./paddock secrets.
func (f *fixture) offboardWorker(t *testing.T, s prodcheck.Service) prodcheck.Service {
	t.Helper()
	for secret := range offboardVars {
		p := filepath.Join(f.dir, "secrets", secret)
		if err := os.WriteFile(p, []byte("k"), 0o644); err != nil {
			t.Fatal(err)
		}
		f.cfg.Secrets[secret] = prodcheck.Secret{File: p}
	}
	return withOffboardCredentials(s)
}

// TestOffboardCredentialsCheck: the full worker passes with all four credentials; a missing secret or variable fails,
// and so does any credential or variable on another service, the ingest workers above all (plan M17 amendment k).
func TestOffboardCredentialsCheck(t *testing.T) {
	const item = "offboarding: object-store credentials on paddock-worker only, and complete there"
	base := func() prodcheck.Config {
		return prodcheck.Config{Services: map[string]prodcheck.Service{
			"paddock-worker":        withOffboardCredentials(prodcheck.Service{Environment: map[string]*string{}}),
			"paddock-worker-ingest": {Environment: map[string]*string{}, Secrets: secrets("db_paddock_worker_url")},
		}}
	}
	check := func(c prodcheck.Config) (string, string) {
		t.Helper()
		var out strings.Builder
		prodcheck.Write(&out, prodcheck.Run(context.Background(), c, prodcheck.Options{}))
		return itemBlock(t, out.String(), item)
	}
	if status, detail := check(base()); status != "PASS" {
		t.Fatalf("shipped configuration: %s %s", status, detail)
	}
	for name, tc := range map[string]struct {
		change func(c prodcheck.Config)
		want   string
	}{
		"secret missing": {func(c prodcheck.Config) {
			w := c.Services["paddock-worker"]
			w.Secrets = w.Secrets[1:]
			c.Services["paddock-worker"] = w
		}, "paddock-worker: does not mount the secret"},
		"variable missing": {func(c prodcheck.Config) {
			delete(c.Services["paddock-worker"].Environment, "PADDOCK_OFFBOARD_ESCROW_S3_SECRET_KEY_FILE")
		}, `PADDOCK_OFFBOARD_ESCROW_S3_SECRET_KEY_FILE is ""`},
		"ingest worker holds a secret": {func(c prodcheck.Config) {
			s := c.Services["paddock-worker-ingest"]
			s.Secrets = append(s.Secrets, secrets("rustfs_escrow_offboard_access_key")...)
			c.Services["paddock-worker-ingest"] = s
		}, "paddock-worker-ingest: holds the organization deletion's secret rustfs_escrow_offboard_access_key"},
		"api names a variable": {func(c prodcheck.Config) {
			c.Services["paddock-api"] = prodcheck.Service{Environment: map[string]*string{
				"PADDOCK_OFFBOARD_BUNDLES_S3_ACCESS_KEY_FILE": ptr("/run/secrets/x")}}
		}, "paddock-api: PADDOCK_OFFBOARD_BUNDLES_S3_ACCESS_KEY_FILE is set"},
	} {
		c := base()
		tc.change(c)
		if status, detail := check(c); status != "FAIL" || !strings.Contains(detail, tc.want) {
			t.Errorf("%s: %s %q, want FAIL with %q", name, status, detail, tc.want)
		}
	}
}

// TestComposeOffboardCredentials renders the shipped Compose files (plan M17 amendment k point 2): on the control
// plane, the lab and the development stack the full worker holds the four credentials and names their files, and the
// ingest workers, like every other service, hold none.
func TestComposeOffboardCredentials(t *testing.T) {
	for name, tc := range map[string]struct {
		files   []string
		envFile string
	}{
		"production control plane": {prodFiles(t, "controlplane"), "prod.env.example"},
		"lab":                      {prodFiles(t, "lab"), "lab.env.example"},
		"development":              {libFiles(t, "DEV_FILES"), ".env.example"},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := renderConfig(t, tc.files, tc.envFile)
			if _, ok := cfg.Services["paddock-worker-ingest"]; !ok {
				t.Fatal("no paddock-worker-ingest to check")
			}
			for _, r := range prodcheck.Run(context.Background(), cfg, prodcheck.Options{}) {
				if strings.HasPrefix(r.Item, "offboarding:") && !r.OK {
					t.Errorf("%s:\n%s", r.Item, r.Detail)
				}
			}
			for _, s := range cfg.Services["paddock-worker-ingest"].Secrets {
				if strings.Contains(s.Source, "offboard") {
					t.Errorf("paddock-worker-ingest mounts %s", s.Source)
				}
			}
		})
	}
}
