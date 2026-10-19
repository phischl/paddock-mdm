package paths

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestUninstallHelperOffRun (ADR 0037 amendment 2026-10-19): the uninstall helper and its plan lie next to the
// removal's summary, not below /run, which initramfs-tools mounts noexec.
func TestUninstallHelperOffRun(t *testing.T) {
	l := Layout{Root: "/"}
	for _, p := range []string{l.UninstallBinary(), l.UninstallPlan()} {
		if strings.HasPrefix(p, "/run/") {
			t.Errorf("%s lies below /run", p)
		}
		if filepath.Dir(p) != "/root/paddock-uninstall" {
			t.Errorf("%s does not lie in /root/paddock-uninstall", p)
		}
	}
}
