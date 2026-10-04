package buildinfo_test

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestAgentBinariesAreStatic builds the agent commands as `make agent` does and checks that they have no runtime
// dependencies (design contract 9, plan M2.2 decision 4). `go test` puts its own toolchain first on PATH.
func TestAgentBinariesAreStatic(t *testing.T) {
	for _, cmd := range []string{"paddockd", "paddock-supervisor"} {
		t.Run(cmd, func(t *testing.T) {
			bin := filepath.Join(t.TempDir(), cmd)
			build := exec.Command("go", "build", "-trimpath", "-o", bin, "../../cmd/"+cmd)
			build.Env = append(build.Environ(), "CGO_ENABLED=0", "GOOS=linux")
			if out, err := build.CombinedOutput(); err != nil {
				t.Fatalf("go build %s: %v\n%s", cmd, err, out)
			}

			out, err := exec.Command("file", bin).CombinedOutput()
			if err != nil {
				t.Fatalf("file %s: %v\n%s", cmd, err, out)
			}
			if !strings.Contains(string(out), "statically linked") {
				t.Errorf("file %s: want statically linked, got %s", cmd, out)
			}

			// ldd exits non-zero for a static binary; its message is what matters.
			out, _ = exec.Command("ldd", bin).CombinedOutput()
			if !strings.Contains(string(out), "not a dynamic executable") {
				t.Errorf("ldd %s: want not a dynamic executable, got %s", cmd, out)
			}
		})
	}
}
