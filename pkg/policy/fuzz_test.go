package policy

import (
	"strings"
	"testing"
)

// FuzzClassify asserts the properties of plan M8s decision 7e without re-implementing the classification: the tier
// denied depends neither on the mode nor on the operator roots and agrees with the agent's ValidatePath; ordinary is
// never returned outside every operator root, below a root that ValidateOperatorRoot refuses, or with an execute bit.
func FuzzClassify(f *testing.F) {
	for _, v := range classifyVectors {
		f.Add(v.path, v.mode, testRoots[0])
		f.Add(v.path, v.mode, "/opt/myapp/")
	}
	f.Add("/etc/systemd/system/sudo.service", "0644", "/etc/systemd/")
	f.Add("/etc//sudoers", "0644", "/etc/")
	f.Fuzz(func(t *testing.T, p, mode, root string) {
		roots := []string{root}
		tier, err := Classify(p, mode, roots)
		if err != nil {
			return
		}
		if (tier == TierDenied) != (ValidatePath(p) != nil) {
			t.Fatalf("Classify(%q) = %s but ValidatePath = %v", p, tier, ValidatePath(p))
		}
		if plain, perr := Classify(p, "0644", nil); perr != nil || (plain == TierDenied) != (tier == TierDenied) {
			t.Fatalf("denied of %q depends on mode or roots: %s vs %s (%v)", p, tier, plain, perr)
		}
		if tier == TierOrdinary {
			if root == "" || !strings.HasPrefix(p, root) {
				t.Fatalf("Classify(%q) = ordinary outside the operator root %q", p, root)
			}
			if err := ValidateOperatorRoot(root); err != nil {
				t.Fatalf("Classify(%q) = ordinary below the refused root %q: %v", p, root, err)
			}
			if strings.ContainsAny(mode[1:], "1357") {
				t.Fatalf("Classify(%q, %q) = ordinary with an execute bit", p, mode)
			}
		}
	})
}
