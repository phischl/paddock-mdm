package prodcheck_test

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/phischl/paddock-mdm/server/internal/prodcheck"
)

const (
	valkeyACLItem   = "valkey: ACL entrypoint and default user off"
	valkeyUsersItem = "valkey: one user per role"
	valkeyDevItem   = "valkey: no development user"
	fleetRedisItem  = "fleet-redis: own configuration file"
)

var valkeyItems = []string{valkeyACLItem, valkeyUsersItem, valkeyDevItem, fleetRedisItem}

// itemResults runs every item over cfg and indexes the results by item.
func itemResults(cfg prodcheck.Config, host string) map[string]prodcheck.Result {
	m := map[string]prodcheck.Result{}
	for _, r := range prodcheck.Run(context.Background(), cfg, prodcheck.Options{Host: host}) {
		m[r.Item] = r
	}
	return m
}

// valkeyItem runs the checks and returns one of the Valkey items; it fails the test when the item did not run.
func valkeyItem(t *testing.T, cfg prodcheck.Config, item string) prodcheck.Result {
	t.Helper()
	r, ok := itemResults(cfg, prodcheck.HostControlPlane)[item]
	if !ok {
		t.Fatalf("no item %q", item)
	}
	return r
}

// TestValkeyACLItemsOnTheRealFileSets renders the production file sets (plan M12h §14.11): the four Valkey items pass
// there, and the development stack, which mounts the user acceptance, fails "no development user".
func TestValkeyACLItemsOnTheRealFileSets(t *testing.T) {
	cases := map[string]struct {
		files    []string
		envFiles []string
	}{
		"production control plane": {prodFiles(t, "controlplane"), []string{"prod.env.example"}},
		"lab":                      {prodFiles(t, "lab"), []string{"lab.env.example"}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			results := itemResults(renderConfig(t, tc.files, tc.envFiles...), prodcheck.HostControlPlane)
			for _, item := range valkeyItems {
				r, ok := results[item]
				if !ok || !r.OK {
					t.Errorf("%s: ran %v, ok %v:\n%s", item, ok, r.OK, r.Detail)
				}
			}
		})
	}
	t.Run("development", func(t *testing.T) {
		r := valkeyItem(t, renderConfig(t, libFiles(t, "DEV_FILES"), ".env.example"), valkeyDevItem)
		if r.OK || !strings.Contains(r.Detail, "valkey_acceptance_password") || !strings.Contains(r.Detail, "users.acl.dev.tmpl") {
			t.Fatalf("%s on the development stack: ok %v:\n%s", valkeyDevItem, r.OK, r.Detail)
		}
	})
	t.Run("audit host has no Valkey", func(t *testing.T) {
		results := itemResults(renderConfig(t, prodFiles(t, "audit"), "prod.env.example"), prodcheck.HostAudit)
		for _, item := range valkeyItems {
			if _, ok := results[item]; ok {
				t.Errorf("%s runs on the audit host", item)
			}
		}
	})
}

// TestValkeyACLItemsFindings mutates the rendered production control plane: each misconfiguration fails its item and
// names the cause.
func TestValkeyACLItemsFindings(t *testing.T) {
	base := func(t *testing.T) prodcheck.Config {
		return renderConfig(t, prodFiles(t, "controlplane"), "prod.env.example")
	}
	svc := func(cfg prodcheck.Config, name string, mutate func(*prodcheck.Service)) {
		s := cfg.Services[name]
		mutate(&s)
		cfg.Services[name] = s
	}
	cases := map[string]struct {
		mutate func(t *testing.T, cfg prodcheck.Config)
		item   string
		want   string
	}{
		"development template mounted": {func(_ *testing.T, cfg prodcheck.Config) {
			svc(cfg, "valkey", func(s *prodcheck.Service) {
				s.Volumes = append(s.Volumes, prodcheck.Volume{Type: "bind", Source: "/x/users.acl.dev.tmpl",
					Target: "/etc/valkey/users.acl.dev.tmpl"})
			})
		}, valkeyDevItem, "mounts /etc/valkey/users.acl.dev.tmpl"},
		"development secret mounted": {func(_ *testing.T, cfg prodcheck.Config) {
			svc(cfg, "valkey", func(s *prodcheck.Service) {
				s.Secrets = append(s.Secrets, prodcheck.ServiceSecret{Source: "valkey_acceptance_password"})
			})
		}, valkeyDevItem, "mounts valkey_acceptance_password"},
		"role without PADDOCK_VALKEY_USER": {func(_ *testing.T, cfg prodcheck.Config) {
			svc(cfg, "paddock-gateway", func(s *prodcheck.Service) { delete(s.Environment, "PADDOCK_VALKEY_USER") })
		}, valkeyUsersItem, `paddock-gateway: PADDOCK_VALKEY_USER is "", not "gateway"`},
		"role as another user": {func(_ *testing.T, cfg prodcheck.Config) {
			svc(cfg, "paddock-gateway", func(s *prodcheck.Service) {
				v := "worker"
				s.Environment["PADDOCK_VALKEY_USER"] = &v
			})
		}, valkeyUsersItem, `paddock-gateway: PADDOCK_VALKEY_USER is "worker", not "gateway"`},
		"role mounts another role's secret": {func(_ *testing.T, cfg prodcheck.Config) {
			svc(cfg, "paddock-gateway", func(s *prodcheck.Service) {
				s.Secrets = append(s.Secrets, prodcheck.ServiceSecret{Source: "valkey_worker_password"})
			})
		}, valkeyUsersItem, "paddock-gateway: mounts [valkey_gateway_password valkey_worker_password], want exactly valkey_gateway_password"},
		"leftover valkey_password": {func(_ *testing.T, cfg prodcheck.Config) {
			svc(cfg, "paddock-api", func(s *prodcheck.Service) {
				s.Secrets = append(s.Secrets, prodcheck.ServiceSecret{Source: "valkey_password"})
			})
		}, valkeyUsersItem, "paddock-api: mounts the retired secret valkey_password"},
		"leftover valkey_auth_conf": {func(_ *testing.T, cfg prodcheck.Config) {
			svc(cfg, "valkey", func(s *prodcheck.Service) {
				s.Secrets = append(s.Secrets, prodcheck.ServiceSecret{Source: "valkey_auth_conf"})
			})
		}, valkeyUsersItem, "valkey: mounts the retired secret valkey_auth_conf"},
		"valkey misses a role's secret": {func(_ *testing.T, cfg prodcheck.Config) {
			svc(cfg, "valkey", func(s *prodcheck.Service) {
				s.Secrets = slices.DeleteFunc(s.Secrets, func(x prodcheck.ServiceSecret) bool { return x.Source == "valkey_compiler_password" })
			})
		}, valkeyUsersItem, "valkey: mounts ["},
		"client without a user": {func(_ *testing.T, cfg prodcheck.Config) {
			svc(cfg, "paddock-notifier", func(s *prodcheck.Service) {
				v := "valkey:6379"
				s.Environment["PADDOCK_VALKEY_ADDR"] = &v
			})
		}, valkeyUsersItem, "paddock-notifier: connects to Valkey but has no Valkey user"},
		"fleet-redis on valkey.conf": {func(_ *testing.T, cfg prodcheck.Config) {
			svc(cfg, "fleet-redis", func(s *prodcheck.Service) {
				for i, v := range s.Volumes {
					if v.Target == "/etc/valkey/valkey.conf" {
						s.Volumes[i].Source = filepath.Join(filepath.Dir(v.Source), "valkey.conf")
					}
				}
			})
		}, fleetRedisItem, "/etc/valkey/valkey.conf is mounted from"},
		"plain valkey entrypoint": {func(_ *testing.T, cfg prodcheck.Config) {
			svc(cfg, "valkey", func(s *prodcheck.Service) { s.Entrypoint = nil })
		}, valkeyACLItem, "entrypoint is [], not /usr/local/bin/paddock-entrypoint.sh"},
		"no tmpfs": {func(_ *testing.T, cfg prodcheck.Config) {
			svc(cfg, "valkey", func(s *prodcheck.Service) { s.Tmpfs = nil })
		}, valkeyACLItem, "no tmpfs at /run/valkey"},
		"template without the default user off": {func(t *testing.T, cfg prodcheck.Config) {
			tmpl := filepath.Join(t.TempDir(), "users.acl.tmpl")
			if err := os.WriteFile(tmpl, []byte("user default on nopass ~* +@all\nuser default off\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			svc(cfg, "valkey", func(s *prodcheck.Service) {
				for i, v := range s.Volumes {
					if v.Target == "/etc/valkey/users.acl.tmpl" {
						s.Volumes[i].Source = tmpl
					}
				}
			})
		}, valkeyACLItem, `is "user default on nopass ~* +@all", not "user default off"`},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := base(t)
			tc.mutate(t, cfg)
			r := valkeyItem(t, cfg, tc.item)
			if r.OK || !strings.Contains(r.Detail, tc.want) {
				t.Fatalf("%s: ok %v, want a finding containing %q:\n%s", tc.item, r.OK, tc.want, r.Detail)
			}
		})
	}
}
