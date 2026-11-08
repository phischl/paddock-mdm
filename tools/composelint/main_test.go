package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// fixtureRender renders a set from testdata/rendered/<set>.json and lets mutate change it first.
func fixtureRender(t *testing.T, mutate func(set string, services map[string]map[string]any)) renderFunc {
	t.Helper()
	return func(_ context.Context, _ string, set hostSet) ([]byte, error) {
		data, err := os.ReadFile(filepath.Join("testdata", "rendered", set.Name+".json"))
		if err != nil {
			t.Fatalf("fixture for %s: %v", set.Name, err)
		}
		var cfg map[string]any
		if err := json.Unmarshal(data, &cfg); err != nil {
			t.Fatal(err)
		}
		services := map[string]map[string]any{}
		for name, svc := range cfg["services"].(map[string]any) {
			services[name] = svc.(map[string]any)
		}
		if mutate != nil {
			mutate(set.Name, services)
		}
		cfg["services"] = services
		return json.Marshal(cfg)
	}
}

// fixtureDir returns a Compose directory with the fixture lib.sh and the given exceptions file content.
func fixtureDir(t *testing.T, exceptions string) string {
	t.Helper()
	dir := t.TempDir()
	lib, err := os.ReadFile(filepath.Join("testdata", "lib.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "scripts"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "scripts", "lib.sh"), lib, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "hardening-exceptions.yaml"), []byte(exceptions), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func fixtureExceptions(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "exceptions.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func runFixture(t *testing.T, exceptions string, mutate func(string, map[string]map[string]any)) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"--compose-dir", fixtureDir(t, exceptions)}, &stdout, &stderr, fixtureRender(t, mutate))
	return code, stdout.String(), stderr.String()
}

func TestPassesWithExceptions(t *testing.T) {
	code, stdout, stderr := runFixture(t, fixtureExceptions(t), nil)
	if code != 0 {
		t.Fatalf("exit %d, stderr:\n%s", code, stderr)
	}
	if !strings.Contains(stdout, "5 services in 7 file sets") {
		t.Fatalf("stdout %q does not count every service and file set", stdout)
	}
}

// TestFindings removes or changes one setting in one host set at a time: every host set is checked on its own, and the
// report names the service, the problem and the set.
func TestFindings(t *testing.T) {
	cases := []struct {
		name    string
		set     string
		service string
		change  func(svc map[string]any)
		want    string
	}{
		{"cap_drop missing", "dev", "paddock-api", func(s map[string]any) { delete(s, "cap_drop") }, "paddock-api: cap_drop [] lacks ALL (dev)"},
		{"cap_drop without ALL", "controlplane", "paddock-api", func(s map[string]any) { s["cap_drop"] = []string{"NET_RAW"} }, "paddock-api: cap_drop [NET_RAW] lacks ALL (controlplane)"},
		{"no-new-privileges missing", "audit", "paddock-audit-writer", func(s map[string]any) { delete(s, "security_opt") }, "paddock-audit-writer: security_opt lacks no-new-privileges:true (audit)"},
		{"no-new-privileges false", "lab", "paddock-api", func(s map[string]any) { s["security_opt"] = []string{"no-new-privileges:false"} }, "paddock-api: security_opt lacks no-new-privileges:true (lab)"},
		{"pids_limit missing", "dev+backup", "paddock-api", func(s map[string]any) { delete(s, "pids_limit") }, "paddock-api: no pids_limit (dev+backup)"},
		{"pids_limit unlimited", "controlplane+optional", "paddock-api", func(s map[string]any) { s["pids_limit"] = -1 }, "paddock-api: no pids_limit (controlplane+optional)"},
		{"mem_limit missing", "lab+optional", "paddock-api", func(s map[string]any) { delete(s, "mem_limit") }, "paddock-api: no mem_limit or deploy.resources.limits.memory (lab+optional)"},
		{"deploy memory missing", "audit", "paddock-audit-writer", func(s map[string]any) { delete(s, "deploy") }, "paddock-audit-writer: no mem_limit or deploy.resources.limits.memory (audit)"},
		{"unlisted cap_add", "dev", "paddock-api", func(s map[string]any) { s["cap_add"] = []string{"NET_ADMIN"} }, "paddock-api: cap_add [NET_ADMIN] (dev)"},
		{"cap_add beyond the exception", "lab", "postgres", func(s map[string]any) {
			s["cap_add"] = []string{"CHOWN", "SETUID", "SETGID", "DAC_OVERRIDE", "FOWNER", "SYS_ADMIN"}
		}, "postgres: cap_add [CHOWN DAC_OVERRIDE FOWNER SETGID SETUID SYS_ADMIN] differs from the exception [CHOWN DAC_OVERRIDE FOWNER SETGID SETUID] (lab)"},
		{"cap_add short of the exception", "controlplane", "postgres", func(s map[string]any) { s["cap_add"] = []string{"CHOWN"} }, "postgres: cap_add [CHOWN] differs from the exception"},
		{"privileged", "dev", "paddock-api", func(s map[string]any) { s["privileged"] = true }, "paddock-api: privileged: true (cannot be excepted) (dev)"},
		{"privileged on an excepted service", "controlplane", "postgres", func(s map[string]any) { s["privileged"] = true }, "postgres: privileged: true (cannot be excepted) (controlplane)"},
		{"host pid", "audit", "paddock-audit-writer", func(s map[string]any) { s["pid"] = "host" }, "paddock-audit-writer: pid: host (cannot be excepted) (audit)"},
		{"host ipc", "lab", "paddock-api", func(s map[string]any) { s["ipc"] = "host" }, "paddock-api: ipc: host (cannot be excepted) (lab)"},
		{"seccomp unconfined", "dev", "paddock-api", func(s map[string]any) {
			s["security_opt"] = []string{"no-new-privileges:true", "seccomp:unconfined"}
		}, "paddock-api: security_opt seccomp:unconfined (cannot be excepted) (dev)"},
		{"apparmor unconfined", "dev", "paddock-api", func(s map[string]any) {
			s["security_opt"] = []string{"no-new-privileges:true", "apparmor=unconfined"}
		}, "paddock-api: security_opt apparmor=unconfined (cannot be excepted) (dev)"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, _, stderr := runFixture(t, fixtureExceptions(t), func(set string, services map[string]map[string]any) {
				if set == tc.set {
					tc.change(services[tc.service])
				}
			})
			if code != 1 {
				t.Fatalf("exit %d, want 1; stderr:\n%s", code, stderr)
			}
			if !strings.Contains(stderr, tc.want) {
				t.Fatalf("stderr does not contain %q:\n%s", tc.want, stderr)
			}
		})
	}
}

// valkeyCaps is the Valkey capability reference of decision A10-5 (plan M12h, amendment 2026-11-09): PDK-824 and PDK-825
// use the same four.
var valkeyCaps = []string{"CHOWN", "SETUID", "SETGID", "DAC_READ_SEARCH"}

func TestValkeyExceptionIsTheReferenceSet(t *testing.T) {
	exceptions, err := loadExceptions(filepath.Join("..", "..", "deploy", "compose", "hardening-exceptions.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"valkey", "fleet-redis"} {
		got := normCaps(exceptions[name][settingCapAdd].Value)
		if want := normCaps(valkeyCaps); !slices.Equal(got, want) {
			t.Fatalf("%s cap_add exception %v, want exactly %v", name, got, want)
		}
	}
}

// TestValkeyCapabilitiesArePinned puts valkey into every host set: the four capabilities pass, one more or one less
// fails in each set on its own.
func TestValkeyCapabilitiesArePinned(t *testing.T) {
	exceptions := fixtureExceptions(t) + "  valkey:\n    cap_add:\n      value: [" + strings.Join(valkeyCaps, ", ") + "]\n      reason: entrypoint chown\n"
	withValkey := func(caps func(set string) []string) func(string, map[string]map[string]any) {
		return func(set string, services map[string]map[string]any) {
			base, ok := services["paddock-api"]
			if !ok {
				base = services["paddock-audit-writer"]
			}
			svc := map[string]any{}
			for k, v := range base {
				svc[k] = v
			}
			svc["cap_add"] = caps(set)
			services["valkey"] = svc
		}
	}
	if code, _, stderr := runFixture(t, exceptions, withValkey(func(string) []string { return valkeyCaps })); code != 0 {
		t.Fatalf("exact set: exit %d; stderr:\n%s", code, stderr)
	}
	files, err := filepath.Glob(filepath.Join("testdata", "rendered", "*.json"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no rendered fixtures (%v)", err)
	}
	for _, f := range files {
		target := strings.TrimSuffix(filepath.Base(f), ".json")
		for name, caps := range map[string][]string{
			"extra":   append(slices.Clone(valkeyCaps), "DAC_OVERRIDE"),
			"missing": valkeyCaps[:3],
		} {
			t.Run(target+" "+name, func(t *testing.T) {
				code, _, stderr := runFixture(t, exceptions, withValkey(func(set string) []string {
					if set == target {
						return caps
					}
					return valkeyCaps
				}))
				if code != 1 || !strings.Contains(stderr, "valkey: cap_add") || !strings.Contains(stderr, "("+target+")") {
					t.Fatalf("exit %d, want 1 naming valkey and %s; stderr:\n%s", code, target, stderr)
				}
			})
		}
	}
}

func TestCapabilityNamesAreNormalized(t *testing.T) {
	code, _, stderr := runFixture(t, fixtureExceptions(t), func(_ string, services map[string]map[string]any) {
		if pg, ok := services["postgres"]; ok {
			pg["cap_add"] = []string{"CAP_FOWNER", "cap_dac_override", "CHOWN", "SETGID", "SETUID"}
			pg["cap_drop"] = []string{"cap_all"}
		}
	})
	if code != 0 {
		t.Fatalf("exit %d; stderr:\n%s", code, stderr)
	}
}

func TestStaleExceptions(t *testing.T) {
	cases := []struct {
		name   string
		extra  string
		mutate func(string, map[string]map[string]any)
		want   string
	}{
		{"service in no set", "  retired:\n    mem_limit:\n      reason: gone\n", nil, "exceptions: retired is in no file set; remove it"},
		{"setting now hardened", "  paddock-api:\n    mem_limit:\n      reason: pending\n", nil, "exceptions: paddock-api.mem_limit is no longer needed; remove it"},
		{"service hardened in every set", "", func(_ string, services map[string]map[string]any) {
			if b, ok := services["pgbackrest"]; ok {
				b["mem_limit"] = "1073741824"
			}
		}, "exceptions: pgbackrest.mem_limit is no longer needed; remove it"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, _, stderr := runFixture(t, fixtureExceptions(t)+tc.extra, tc.mutate)
			if code != 1 || !strings.Contains(stderr, tc.want) {
				t.Fatalf("exit %d, want 1 with %q; stderr:\n%s", code, tc.want, stderr)
			}
		})
	}
}

// TestExceptionNeededInOneSetOnly keeps an exception that a single host set needs.
func TestExceptionNeededInOneSetOnly(t *testing.T) {
	code, _, stderr := runFixture(t, fixtureExceptions(t), func(set string, services map[string]map[string]any) {
		if b, ok := services["pgbackrest"]; ok && set != "lab+optional" {
			b["mem_limit"] = "1073741824"
		}
	})
	if code != 0 {
		t.Fatalf("exit %d; stderr:\n%s", code, stderr)
	}
}

func TestInvalidExceptionsFile(t *testing.T) {
	cases := []struct {
		name, content, want string
	}{
		{"no reason", "services:\n  postgres:\n    cap_add:\n      value: [CHOWN]\n", "postgres.cap_add: no reason"},
		{"cap_add without value", "services:\n  postgres:\n    cap_add:\n      reason: r\n", "postgres.cap_add: value must list the exact capabilities"},
		{"value on another setting", "services:\n  x:\n    mem_limit:\n      value: [1g]\n      reason: r\n", "x.mem_limit: only cap_add takes a value"},
		{"unknown setting", "services:\n  x:\n    read_only:\n      reason: r\n", `x: unknown setting "read_only"`},
		{"isolation excepted", "services:\n  x:\n    isolation:\n      reason: r\n", "x.isolation: cannot be excepted"},
		{"unknown field", "services:\n  x:\n    mem_limit:\n      reason: r\n      until: PDK-1\n", "field until not found"},
		{"empty service", "services:\n  x: {}\n", "x: no excepted setting"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, _, stderr := runFixture(t, tc.content, nil)
			if code != 2 || !strings.Contains(stderr, tc.want) {
				t.Fatalf("exit %d, want 2 with %q; stderr:\n%s", code, tc.want, stderr)
			}
		})
	}
}

func TestRenderFailure(t *testing.T) {
	var stdout, stderr bytes.Buffer
	failing := func(context.Context, string, hostSet) ([]byte, error) { return nil, os.ErrNotExist }
	code := run(context.Background(), []string{"--compose-dir", fixtureDir(t, fixtureExceptions(t))}, &stdout, &stderr, failing)
	if code != 2 || !strings.Contains(stderr.String(), "render dev:") {
		t.Fatalf("exit %d; stderr:\n%s", code, stderr.String())
	}
}

func TestHostSetsFromFixture(t *testing.T) {
	sets, err := hostSets(filepath.Join("testdata", "lib.sh"))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, s := range sets {
		got[s.Name] = strings.Join(s.Files, " ")
	}
	want := map[string]string{
		"dev":                   "compose.yaml compose.audit.yaml compose.dev.yaml",
		"dev+backup":            "compose.yaml compose.audit.yaml compose.dev.yaml compose.backup.yaml",
		"controlplane":          "compose.yaml compose.prod.yaml",
		"controlplane+optional": "compose.yaml compose.prod.yaml compose.auto-unseal.yaml compose.backup-legacy-key.yaml",
		"audit":                 "compose.audit.yaml",
		"lab":                   "compose.yaml compose.audit.yaml compose.lab.yaml",
		"lab+optional":          "compose.yaml compose.audit.yaml compose.lab.yaml compose.auto-unseal.yaml compose.backup.yaml compose.backup-legacy-key.yaml",
	}
	if len(got) != len(want) {
		t.Fatalf("sets %v, want %v", got, want)
	}
	for name, files := range want {
		if got[name] != files {
			t.Errorf("%s: %q, want %q", name, got[name], files)
		}
	}
}

func TestHostSetsMissingVariable(t *testing.T) {
	lib := filepath.Join(t.TempDir(), "lib.sh")
	if err := os.WriteFile(lib, []byte("DEV_FILES=\"compose.yaml\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := hostSets(lib); err == nil || !strings.Contains(err.Error(), "DEV_BACKUP_FILES") {
		t.Fatalf("err %v, want the missing variable named", err)
	}
}

// TestRepositoryFileSets reads the real lib.sh: every file of every set exists, and the repository's exceptions file
// is valid, so a renamed Compose file or a broken entry fails here before docker compose runs.
func TestRepositoryFileSets(t *testing.T) {
	dir := filepath.Join("..", "..", "deploy", "compose")
	sets, err := hostSets(filepath.Join(dir, "scripts", "lib.sh"))
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range sets {
		for _, f := range s.Files {
			if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
				t.Errorf("%s: %v", s.Name, err)
			}
		}
	}
	if _, err := loadExceptions(filepath.Join(dir, "hardening-exceptions.yaml")); err != nil {
		t.Fatal(err)
	}
}
