package bundle

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestRefusedIntent(t *testing.T) {
	all := []string{"required", "uninstall", "hold", "forbid"}
	for _, tc := range []struct {
		pkg     string
		refused []string
		entry   bool
	}{
		{"paddock-agent", all, true}, {"paddock-supervisor", all, true}, {"paddock-revoke", all, true},
		{"fleet-osquery", all, true}, {"himmelblau", all, true}, {"pam-himmelblau", all, true},
		{"nss-himmelblau", all, true}, {"himmelblau-apparmor", all, true}, {"himmelblau-future-addon", all, true},
		{"sudo", []string{"forbid", "uninstall"}, false}, {"libpam-modules", []string{"forbid", "uninstall"}, false},
		{"cryptsetup", []string{"forbid", "uninstall"}, false}, {"tpm2-tools", []string{"forbid", "uninstall"}, false},
		{"dracut", []string{"forbid", "uninstall"}, false},
		{"initramfs-tools", []string{"required", "hold"}, false},
		{"nano", nil, false}, {"", nil, false},
		// apt reads these as regexes that select protected packages (review of PDK-412, PDK-705).
		{"himmelblau.", all, true}, {"paddock-agen.", all, true}, {"sud.", all, true}, {"paddoc+k-agent", all, true},
		{"initramfs-tool.", all, true}, {"CRYPTSETU.", all, true},
		{"sud++o", all, true}, {"paddock-agen++t", all, true}, {"himmelblau++", all, true}, {"paddock-agen.++", all, true},
		// Exact names with "." or "+" that select no protected package stay valid; g++ is an exemption.
		{"libstdc++6", nil, false}, {"python3.12", nil, false}, {"g++", nil, false},
	} {
		if EntryRefused(tc.pkg) != tc.entry {
			t.Errorf("EntryRefused(%q) = %v", tc.pkg, !tc.entry)
		}
		for _, intent := range all {
			if got := RefusedIntent(tc.pkg, intent); got != slices.Contains(tc.refused, intent) {
				t.Errorf("RefusedIntent(%q, %s) = %v", tc.pkg, intent, got)
			}
		}
	}
	for _, name := range slices.Concat(fullyProtected, removalProtected, conflictingResult) {
		if !ValidPackage(name) {
			t.Errorf("%s is not a valid package name", name)
		}
	}
}

// TestFullyProtected: the exact-name predicate for names apt printed covers only the fully protected tier and never
// reads a name as a pattern (plan M13a amendment 2026-11-03).
func TestFullyProtected(t *testing.T) {
	for _, name := range slices.Concat(fullyProtected, []string{"himmelblau-future-addon", "future-himmelblau"}) {
		if !FullyProtected(name) {
			t.Errorf("FullyProtected(%q) = false", name)
		}
	}
	for _, name := range slices.Concat(removalProtected, conflictingResult, []string{"nano", "", "himmelblau.", "sud.", "libstdc++6"}) {
		if FullyProtected(name) {
			t.Errorf("FullyProtected(%q) = true", name)
		}
	}
}

// TestAptPatternExemptions: every exemption is an exact name that the pattern emulation would refuse without its
// entry; an entry that is not needed must not be on the list (architect decision 2026-11-03).
func TestAptPatternExemptions(t *testing.T) {
	for _, name := range aptPatternExempt {
		if !ValidPackage(name) || !aptPatternMatches(name) {
			t.Errorf("exemption %q is not needed or not a package name", name)
		}
		if EntryRefused(name) {
			t.Errorf("exemption %q is refused", name)
		}
	}
}

// TestAgentDependenciesAreRemovalProtected: removing a dependency of paddock-agent removes the agent, so the
// dependencies listed in its package definition (the other Paddock packages are fully protected) must stay in the
// removal-protected list.
func TestAgentDependenciesAreRemovalProtected(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "packaging", "nfpm", "paddock-agent.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var depends []string
	in := false
	for _, line := range strings.Split(string(raw), "\n") {
		switch {
		case strings.HasPrefix(line, "depends:"):
			in = true
		case in && strings.HasPrefix(strings.TrimSpace(line), "- ") && strings.HasPrefix(line, " "):
			if name := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "- ")); !EntryRefused(name) {
				depends = append(depends, name)
			}
		case in && !strings.HasPrefix(line, " "):
			in = false
		}
	}
	slices.Sort(depends)
	if want := slices.Sorted(slices.Values(agentDepends)); !slices.Equal(depends, want) {
		t.Fatalf("Depends of paddock-agent without Paddock packages = %v, removal-protected list = %v", depends, want)
	}
	if !slices.Contains(removalProtected, "dracut") {
		t.Error("dracut (agent/internal/encrypt/prepare.go) is not removal-protected")
	}
}
