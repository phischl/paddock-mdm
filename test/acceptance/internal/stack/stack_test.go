package stack

import (
	"os"
	"path/filepath"
	"testing"
)

// checkout is a repository root with go.work and, unless env is empty, deploy/compose/.env; the test runs in it.
func checkout(t *testing.T, env string) {
	t.Helper()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "go.work"), []byte("go 1.27\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if env != "" {
		dir := filepath.Join(root, "deploy", "compose")
		if err := os.MkdirAll(dir, 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, ".env"), []byte(env), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Chdir(root)
}

func TestStackSettings(t *testing.T) {
	second := "PADDOCK_HTTPS_PORT=8443\nPADDOCK_PROJECT=paddock2\nPADDOCK_HTTPS_PORT=8543\nPADDOCK_DEV_POSTGRES_PORT=5532\n"
	for _, c := range []struct {
		name, env, envProject, project, port, admin, db string
	}{
		{"first stack without .env", "", "", "paddock", "8443", "https://admin.paddock.localhost:8443", "127.0.0.1:5432"},
		{"first stack .env", "PADDOCK_HTTPS_PORT=8443\n", "", "paddock", "8443", "https://admin.paddock.localhost:8443", "127.0.0.1:5432"},
		{"second stack .env, last line wins", second, "", "paddock2", "8543", "https://admin.paddock.localhost:8543", "127.0.0.1:5532"},
		{"environment wins over .env", second, "paddock9", "paddock9", "8543", "https://admin.paddock.localhost:8543", "127.0.0.1:5532"},
	} {
		t.Run(c.name, func(t *testing.T) {
			for _, v := range []string{"PADDOCK_PROJECT", "PADDOCK_HTTPS_PORT", "PADDOCK_DOMAIN", "PADDOCK_DEV_POSTGRES_PORT", "PADDOCK_TEST_ADMIN_URL"} {
				t.Setenv(v, "")
			}
			if c.envProject != "" {
				t.Setenv("PADDOCK_PROJECT", c.envProject)
			}
			checkout(t, c.env)
			if got := Project(); got != c.project {
				t.Errorf("Project() = %q, want %q", got, c.project)
			}
			if got := Network("cp"); got != c.project+"_cp" {
				t.Errorf("Network(cp) = %q, want %q", got, c.project+"_cp")
			}
			if got := HTTPSPort(); got != c.port {
				t.Errorf("HTTPSPort() = %q, want %q", got, c.port)
			}
			if got := AdminURL(); got != c.admin {
				t.Errorf("AdminURL() = %q, want %q", got, c.admin)
			}
			if got := loopback("PADDOCK_DEV_POSTGRES_PORT", "5432"); got != c.db {
				t.Errorf("PostgreSQL host = %q, want %q", got, c.db)
			}
		})
	}
}
