package reconcile_test

import (
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/paddock-mdm/paddock/agent/internal/reconcile"
)

// TestPAMProfileMatchesTheVerifiedLines: the pam-auth-update profile of the paddock-agent package produces exactly
// the lines the login reconciler verifies (plan M3b decision 9).
func TestPAMProfileMatchesTheVerifiedLines(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	data, err := os.ReadFile(filepath.Join(filepath.Dir(file), "..", "..", "..", "packaging", "pam-configs", "paddock-deny"))
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	section := ""
	for _, line := range strings.Split(string(data), "\n") {
		switch {
		case strings.HasPrefix(line, "Auth:"):
			section = "auth"
		case strings.HasPrefix(line, "Account:"):
			section = "account"
		case strings.HasPrefix(line, "\t") && section != "":
			lines = append(lines, section+" "+strings.Join(strings.Fields(line), " "))
		default:
			section = ""
		}
	}
	if !slices.Equal(lines, []string{reconcile.DenyAuthLine, reconcile.DenyAccountLine}) {
		t.Fatalf("profile lines %q", lines)
	}
}
