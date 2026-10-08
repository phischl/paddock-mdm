package cfg_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/phischl/paddock-mdm/cli/internal/cfg"
)

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func write(t *testing.T, dir, name, content string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestPrecedenceFlagsOverEnvironmentOverFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "paddockctl"), 0o700); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(dir, "paddockctl"), "config.yaml", "url: https://file.test\ntoken_file: /file/token\nca_file: /file/ca.pem\n", 0o600)
	e := map[string]string{"XDG_CONFIG_HOME": dir}

	c, err := cfg.Resolve(cfg.Sources{Getenv: env(e)})
	if err != nil || c != (cfg.Config{URL: "https://file.test", TokenFile: "/file/token", CAFile: "/file/ca.pem"}) {
		t.Fatalf("file only: %+v, %v", c, err)
	}
	e["PADDOCK_URL"], e["PADDOCK_TOKEN_FILE"] = "https://env.test/", "/env/token"
	c, err = cfg.Resolve(cfg.Sources{Getenv: env(e)})
	if err != nil || c != (cfg.Config{URL: "https://env.test", TokenFile: "/env/token", CAFile: "/file/ca.pem"}) {
		t.Fatalf("environment over file: %+v, %v", c, err)
	}
	c, err = cfg.Resolve(cfg.Sources{URL: "https://flag.test", CAFile: "/flag/ca.pem", Getenv: env(e)})
	if err != nil || c != (cfg.Config{URL: "https://flag.test", TokenFile: "/env/token", CAFile: "/flag/ca.pem"}) {
		t.Fatalf("flags over environment: %+v, %v", c, err)
	}
}

func TestConfigFileErrors(t *testing.T) {
	dir := t.TempDir()
	e := env(map[string]string{"HOME": dir, "PADDOCK_URL": "https://x.test", "PADDOCK_TOKEN_FILE": "/t"})
	if _, err := cfg.Resolve(cfg.Sources{Getenv: e}); err != nil {
		t.Fatalf("a missing default config file is an error: %v", err)
	}
	var cerr *cfg.Error
	if _, err := cfg.Resolve(cfg.Sources{ConfigFile: filepath.Join(dir, "missing.yaml"), Getenv: e}); !errors.As(err, &cerr) {
		t.Fatalf("missing --config file: %v", err)
	}
	bad := write(t, dir, "bad.yaml", "url: https://x.test\ntoken: pdk_secret\n", 0o600)
	if _, err := cfg.Resolve(cfg.Sources{ConfigFile: bad, Getenv: e}); !errors.As(err, &cerr) {
		t.Fatalf("unknown key (a token in the config file): %v", err)
	}
	if _, err := cfg.Resolve(cfg.Sources{Getenv: env(map[string]string{"HOME": dir})}); !errors.As(err, &cerr) || !strings.Contains(err.Error(), "URL") {
		t.Fatalf("no URL: %v", err)
	}
	if _, err := cfg.Resolve(cfg.Sources{URL: "https://x.test", Getenv: env(map[string]string{"HOME": dir})}); !errors.As(err, &cerr) {
		t.Fatalf("no token file: %v", err)
	}
	for _, u := range []string{"ftp://x.test", "http://x.test", "http://127.0.0.1:8443", "HTTP://x.test", "admin.example.org"} {
		if _, err := cfg.Resolve(cfg.Sources{URL: u, TokenFile: "/t", Getenv: e}); !errors.As(err, &cerr) || !strings.Contains(err.Error(), "https://") {
			t.Errorf("URL %s: %v, want a refusal", u, err)
		}
	}
}

func TestReadToken(t *testing.T) {
	dir := t.TempDir()
	ok := write(t, dir, "token", "pdk_abc\n  \n", 0o600)
	if s, err := cfg.ReadToken(ok); err != nil || s != "pdk_abc" {
		t.Fatalf("ReadToken = %q, %v", s, err)
	}
	for _, mode := range []os.FileMode{0o644, 0o640, 0o604} {
		p := write(t, dir, "open-"+mode.String(), "pdk_abc", mode)
		var cerr *cfg.Error
		if _, err := cfg.ReadToken(p); !errors.As(err, &cerr) || !strings.Contains(err.Error(), "readable by others") ||
			strings.Contains(err.Error(), "pdk_abc") {
			t.Errorf("mode %v: %v", mode, err)
		}
	}
	if _, err := cfg.ReadToken(write(t, dir, "empty", "\n", 0o600)); err == nil {
		t.Error("an empty token file is accepted")
	}
	if _, err := cfg.ReadToken(filepath.Join(dir, "none")); err == nil {
		t.Error("a missing token file is accepted")
	}
}
