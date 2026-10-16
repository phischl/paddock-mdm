package policy

import (
	"slices"
	"strings"
	"testing"
)

// FuzzClassify checks the invariants of plan M8s §6.2: Classify never panics, an ordinary or sensitive path is never
// covered by the denied catalog, and ValidatePath accepts exactly the paths that Classify does not deny.
func FuzzClassify(f *testing.F) {
	for _, v := range classifyVectors {
		f.Add(v.path, v.mode)
	}
	f.Add("/etc/systemd/system/sudo.service", "0644")
	f.Add("/etc//sudoers", "0644")
	f.Fuzz(func(t *testing.T, p, mode string) {
		tier, err := Classify(p, mode)
		if err == nil && tier != TierDenied {
			if slices.Contains(deniedFiles, p) || inDirs(p, deniedDirs) {
				t.Fatalf("Classify(%q) = %s inside the denied catalog", p, tier)
			}
			for _, prefix := range deniedPrefixes {
				if strings.HasPrefix(p, prefix) {
					t.Fatalf("Classify(%q) = %s below the denied prefix %s", p, tier, prefix)
				}
			}
		}
		t644, err644 := Classify(p, "0644")
		if (ValidatePath(p) == nil) != (err644 == nil && t644 != TierDenied) {
			t.Fatalf("ValidatePath(%q) disagrees with Classify: %q, %v", p, t644, err644)
		}
	})
}
