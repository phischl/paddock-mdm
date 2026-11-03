package bundle

import (
	"slices"
	"strings"
)

// Packages Paddock installs or depends on, in three tiers (architect decisions 2026-11-02, plan M13a amendment M3, Q1
// and Q2). The server refuses catalog entries and assignments by them, bundle.ValidateSoftware (PDK-410) and the
// agent's guard (PDK-412) are to refuse them as well (defence in depth); all use RefusedIntent and EntryRefused.
//
//   - Fully protected: Paddock's own packages and the Himmelblau login stack. Any intent would move, pin or remove them
//     outside the signed A/B update path or break the login (design contract 2 and 5, protected area 4), so no entry may
//     name them. Sources: packaging/nfpm/*.yaml (names), reconcile.FleetdPackage, reconcile.HimmelblauPackages
//     (agent/internal/reconcile/login.go) and agent/internal/uninstall/steps.go, which purges every himmelblau package
//     incl. himmelblau-apparmor.
//   - Removal protected: the dependencies of paddock-agent (packaging/nfpm/paddock-agent.yaml; apt-get remove of one of
//     them removes the agent; TestAgentDependenciesAreRemovalProtected keeps them equal) and dracut, which the agent
//     installs for the encrypted initramfs (agent/internal/encrypt/prepare.go). forbid and uninstall are refused;
//     required and hold are ordinary.
//   - Conflicting: initramfs-tools; installing it removes dracut, so required and hold are refused.
var (
	fullyProtected = []string{
		"fleet-osquery", "paddock-agent", "paddock-revoke", "paddock-supervisor",
		"himmelblau", "himmelblau-apparmor", "himmelblau-qr-greeter", "himmelblau-sshd-config", "nss-himmelblau",
		"pam-himmelblau",
	}
	agentDepends      = []string{"cryptsetup", "libpam-modules", "sudo", "tpm2-tools"}
	removalProtected  = append(slices.Clone(agentDepends), "dracut")
	conflictingResult = []string{"initramfs-tools"}
)

// EntryRefused reports whether no catalog entry may name pkg: it is fully protected, a Paddock package or any
// himmelblau package.
func EntryRefused(pkg string) bool {
	return slices.Contains(fullyProtected, pkg) || pkg == "himmelblau" || strings.HasPrefix(pkg, "himmelblau-") ||
		strings.HasSuffix(pkg, "-himmelblau")
}

// RefusedIntent reports whether an assignment with intent (required, uninstall, hold or forbid) must be refused for
// pkg: every intent for a fully protected package, forbid and uninstall for a removal-protected one, required and
// hold for a conflicting one.
func RefusedIntent(pkg, intent string) bool {
	switch {
	case EntryRefused(pkg):
		return true
	case slices.Contains(removalProtected, pkg):
		return intent == SoftwareForbid || intent == SoftwareUninstall
	case slices.Contains(conflictingResult, pkg):
		return intent == SoftwareRequired || intent == SoftwareHold
	}
	return false
}
