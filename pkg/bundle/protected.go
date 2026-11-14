package bundle

import (
	"regexp"
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
// himmelblau package, or apt would read it as a pattern that selects a protected package of any tier (aptPattern).
func EntryRefused(pkg string) bool {
	return FullyProtected(pkg) || aptPattern(pkg)
}

// FullyProtected reports whether pkg is a fully protected package by its exact name: Paddock's own packages and every
// himmelblau package. Unlike EntryRefused it does not read pkg as an apt pattern, so it suits names apt printed itself
// (the agent refuses a simulation that installs, upgrades or removes such a package, plan M13a amendment 2026-11-03).
func FullyProtected(pkg string) bool {
	return slices.Contains(fullyProtected, pkg) || pkg == "himmelblau" || strings.HasPrefix(pkg, "himmelblau-") ||
		strings.HasSuffix(pkg, "-himmelblau")
}

// aptPatternExempt are exact Debian package names that the archive really has and whose pattern reading would select a
// protected package (TestAptPatternExemptions proves each one needs its entry). They are safe: apt resolves an
// existing exact name before any regex fallback, and the agent passes a name to apt only after apt-cache pkgnames listed
// exactly that name (architect decision 2026-11-03). The list is closed: an entry needs the same proof.
//
//   - g++: the GNU C++ compiler metapackage (main); read as a pattern, "g+" selects every name containing "g".
var aptPatternExempt = []string{"g++"}

// aptPattern reports whether apt-get, given pkg as an argument, could select a protected package of any tier. apt
// matches a package of exactly that name first; without one it reads an argument with a regex character (of those a
// package name may contain, "." and "+") as an unanchored, case-insensitive POSIX extended regex, so "himmelblau."
// selects every himmelblau package and "sud." or "sud++o" selects sudo (reviews of PDK-412, folded PDK-705).
func aptPattern(pkg string) bool {
	return !slices.Contains(aptPatternExempt, pkg) && aptPatternMatches(pkg)
}

// aptPatternMatches emulates apt's POSIX ERE reading of pkg against the protected names: glibc accepts a run of "+"
// as one (Go's RE2 rejects "++"), "." is any character, the match is unanchored and ignores case. A pattern that does
// not compile counts as matching (fail closed).
func aptPatternMatches(pkg string) bool {
	if !strings.ContainsAny(pkg, ".+") {
		return false
	}
	for strings.Contains(pkg, "++") {
		pkg = strings.ReplaceAll(pkg, "++", "+")
	}
	re, err := regexp.Compile("(?i)" + pkg)
	if err != nil {
		return true
	}
	return slices.ContainsFunc(slices.Concat(fullyProtected, removalProtected, conflictingResult), re.MatchString)
}

// RefusedIntent reports whether an assignment with intent (required, uninstall, hold, forbid or available) must be
// refused for pkg: every intent for a fully protected package, forbid and uninstall for a removal-protected one,
// required, hold and available for a conflicting one (a user's install of an available package puts it on the device
// like a required one, as software.ValidateAssignmentTarget counts it).
func RefusedIntent(pkg, intent string) bool {
	switch {
	case EntryRefused(pkg):
		return true
	case slices.Contains(removalProtected, pkg):
		return intent == SoftwareForbid || intent == SoftwareUninstall
	case slices.Contains(conflictingResult, pkg):
		return intent == SoftwareRequired || intent == SoftwareHold || intent == SoftwareAvailable
	}
	return false
}
