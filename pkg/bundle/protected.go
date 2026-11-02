package bundle

import "slices"

// protectedPackages are the packages Paddock itself installs and depends on. A software assignment of any intent
// (forbid, uninstall, hold or a version pin through apt) would change them outside the signed A/B update path or
// remove the agent from the device, so the server refuses entries that name them and the agent refuses to apply them
// (defence in depth). Sources: packaging/nfpm/*.yaml (paddock-agent, paddock-supervisor, paddock-revoke and the
// dependencies of paddock-agent), reconcile.FleetdPackage (fleet-osquery), reconcile.HimmelblauPackages
// (agent/internal/reconcile/login.go) and the purge list of agent/internal/uninstall/steps.go.
var protectedPackages = []string{
	"cryptsetup", "fleet-osquery", "himmelblau", "himmelblau-qr-greeter", "himmelblau-sshd-config", "libpam-modules",
	"nss-himmelblau", "paddock-agent", "paddock-revoke", "paddock-supervisor", "pam-himmelblau", "sudo", "tpm2-tools",
}

// ProtectedPackages returns the closed list of packages a software assignment may never touch, sorted.
func ProtectedPackages() []string { return slices.Clone(protectedPackages) }

// IsProtectedPackage reports whether name is one of ProtectedPackages.
func IsProtectedPackage(name string) bool { return slices.Contains(protectedPackages, name) }
