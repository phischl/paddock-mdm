// Package paths is the file system layout of the agent on a device (plan M2b decision 6). Every path is resolved
// below Root, which is "/" on a device and a temporary directory in tests.
package paths

import "path/filepath"

// Layout resolves the agent's files below Root.
type Layout struct{ Root string }

// Default is the layout of an installed device.
var Default = Layout{Root: "/"}

// Join resolves an absolute device path below Root.
func (l Layout) Join(path string) string { return filepath.Join(l.Root, path) }

// AgentConfig is /etc/paddock/agent.yml.
func (l Layout) AgentConfig() string { return l.Join("/etc/paddock/agent.yml") }

// Trust is /etc/paddock/trust.json (the bundle keys of the enrollment configuration).
func (l Layout) Trust() string { return l.Join("/etc/paddock/trust.json") }

// IdentityKey is the device signing key (PKCS#8 PEM, 0600, directory 0700).
func (l Layout) IdentityKey() string { return l.Join("/var/lib/paddock/identity/sign.key") }

// State is state.json (enrollment, sequence numbers, applied bundle).
func (l Layout) State() string { return l.Join("/var/lib/paddock/state/state.json") }

// Managed is managed.json (files Paddock wrote, with their content hash).
func (l Layout) Managed() string { return l.Join("/var/lib/paddock/state/managed.json") }

// Bundle is the last applied, verified bundle envelope.
func (l Layout) Bundle() string { return l.Join("/var/lib/paddock/state/bundle.dsse") }

// UpdateResult is written by the supervisor after an update attempt.
func (l Layout) UpdateResult() string { return l.Join("/var/lib/paddock/state/update-result.json") }

// Probation is the supervisor's record of a running probation.
func (l Layout) Probation() string { return l.Join("/var/lib/paddock/state/probation.json") }

// Spool is the event spool.
func (l Layout) Spool() string { return l.Join("/var/lib/paddock/spool/events.jsonl") }

// Staging holds downloaded agent releases.
func (l Layout) Staging() string { return l.Join("/var/lib/paddock/staging") }

// UpdateRequest asks the supervisor to install a staged release.
func (l Layout) UpdateRequest() string { return l.Join("/var/lib/paddock/staging/request.json") }

// Packages holds downloaded Debian packages until dpkg installed them (fleetd, the supervisor).
func (l Layout) Packages() string { return l.Join("/var/lib/paddock/packages") }

// SupervisorUpgrade marks a running supervisor upgrade (plan M8d decision 31).
func (l Layout) SupervisorUpgrade() string {
	return l.Join("/var/lib/paddock/state/supervisor-upgrade.json")
}

// SupervisorUpgradeResult is written by `paddockd supervisor-upgrade` when it finished (plan M8d decision 31).
func (l Layout) SupervisorUpgradeResult() string {
	return l.Join("/var/lib/paddock/state/supervisor-upgrade-result.json")
}

// UninstallPlan is the plan of an accepted uninstall command; UninstallBinary the copy of paddockd that runs it, so
// that removing the paddock-agent package does not remove the running helper (plan M8d decision 39). Both lie next to
// the removal's summary on the root file system, not below /run: initramfs-tools mounts /run noexec, and systemd
// refuses to start a binary from there (ADR 0037 amendment 2026-10-19).
func (l Layout) UninstallPlan() string { return l.Join("/root/paddock-uninstall/plan.json") }

// UninstallBinary is the copy of paddockd the uninstall helper runs as.
func (l Layout) UninstallBinary() string { return l.Join("/root/paddock-uninstall/paddockd") }

// Socket is the health socket.
func (l Layout) Socket() string { return l.Join("/run/paddock/agent.sock") }

// LastCheckin is touched after every successful check-in.
func (l Layout) LastCheckin() string { return l.Join("/run/paddock/last-checkin") }

// LastCheckinFailed holds the time of the last check-in that did not reach the server (no answer, or 502–504 from the
// reverse proxy); the supervisor upgrade helper tells an unreachable server from a broken supervisor by it.
func (l Layout) LastCheckinFailed() string { return l.Join("/run/paddock/last-checkin-failed") }

// EnrollConfig is the enrollment configuration the Paddock autoinstall leaves for the first start of the agent
// (plan M4b decision 7).
func (l Layout) EnrollConfig() string { return l.Join("/etc/paddock/enroll.json") }

// EnrollLock serializes `paddockd enroll` and the agent's autoinstall enrollment (plan M11 amendment R6.5). It lives
// below the state directory, which both have, unlike /run/paddock, which exists only while the supervisor runs.
func (l Layout) EnrollLock() string { return l.Join("/var/lib/paddock/enroll.lock") }

// DiskSetupConfig holds the settings of the first-boot disk setup (plan M4b decision 4).
func (l Layout) DiskSetupConfig() string { return l.Join("/etc/paddock/disk-setup.json") }

// DiskSetupPending marks a first-boot disk setup that has not run yet (plan M4b decision 5).
func (l Layout) DiskSetupPending() string { return l.Join("/var/lib/paddock/disk-setup-pending") }

// InstallPassphrase is the temporary disk passphrase of the Paddock autoinstall (0600 root), removed once the
// recovery key and the header are escrowed (plan M4b decision 11).
func (l Layout) InstallPassphrase() string { return l.Join("/var/lib/paddock/install-passphrase") }

// HeaderBackupDir is the tmpfs directory LUKS header backups are written to before they are escrowed.
func (l Layout) HeaderBackupDir() string { return l.Join("/run/paddock") }

// Slots holds the A/B slots and the current symlink.
func (l Layout) Slots() string { return l.Join("/opt/paddock/agent") }

// RevokeTrust is /etc/paddock/revoke-trust.json, the revocation-signing keys pinned at enrollment (plan M4c
// decision 3); never replaced from a bundle.
func (l Layout) RevokeTrust() string { return l.Join("/etc/paddock/revoke-trust.json") }

// RevokeBinary is paddock-revoke, installed by its own package and never by the agent update (plan M4c decision 4).
func (l Layout) RevokeBinary() string { return l.Join("/opt/paddock/revoke/paddock-revoke") }

// RevokeEnabled is the marker the agent keeps while the bundle says revocation.enabled (plan M4c decision 1);
// paddock-revoke refuses to run without it.
func (l Layout) RevokeEnabled() string { return l.Join("/etc/paddock/revoke-enabled") }

// UpdatesResult is the result of the last regular update run, written by `paddockd updates run` for the agent (plan
// M5b decision 6).
func (l Layout) UpdatesResult() string { return l.Join("/var/lib/paddock/state/updates-result.json") }

// RebootRequired is the marker packages leave when the device needs a reboot (plan M5b decision 8).
func (l Layout) RebootRequired() string { return l.Join("/var/run/reboot-required") }

// UnattendedLog is the log of unattended-upgrades, the daily security updates.
func (l Layout) UnattendedLog() string {
	return l.Join("/var/log/unattended-upgrades/unattended-upgrades.log")
}

// EncryptDir holds the data files of an in-place encryption (plan M8e §6.3; 0700): plan.json, plan.env and, in dev
// builds, test-hooks. Nothing below it is ever executed (plan M8e decision 29).
func (l Layout) EncryptDir() string { return l.Join("/var/lib/paddock/encrypt") }

// EncryptPlan is the conversion plan the agent writes at preparation (plan M8e decision 13 step 2).
func (l Layout) EncryptPlan() string { return l.Join("/var/lib/paddock/encrypt/plan.json") }

// EncryptPlanEnv is the shell form of the plan the dracut module puts into the initrd (plan M8e decision 13 step 7).
func (l Layout) EncryptPlanEnv() string { return l.Join("/var/lib/paddock/encrypt/plan.env") }

// EncryptTestHooks marks a dev build's initrd for the test delays of the init script (plan M8e decision 19).
func (l Layout) EncryptTestHooks() string { return l.Join("/var/lib/paddock/encrypt/test-hooks") }

// EncryptProgress is the progress of the background reencryption, written by `paddockd encrypt-resume` (plan M8e
// decision 21).
func (l Layout) EncryptProgress() string { return l.Join("/var/lib/paddock/encrypt/progress.json") }

// EncryptResult is the outcome of the background reencryption, written by `paddockd encrypt-resume` when it ends
// (plan M8e decision 21).
func (l Layout) EncryptResult() string { return l.Join("/var/lib/paddock/encrypt/result.json") }

// EncryptBootResult is the result of the init step at the conversion boot (plan M8e decision 16): data the init
// script leaves on /run, never executed.
func (l Layout) EncryptBootResult() string { return l.Join("/run/paddock/encrypt-boot.env") }

// EncryptAbortRequest is the request `paddockd encrypt-abort` hands to the running agent (plan M8e decision 14 as
// corrected on 2026-10-21: the agent stays the only writer of its state and its spool).
func (l Layout) EncryptAbortRequest() string { return l.Join("/var/lib/paddock/encrypt-abort.request") }

// EncryptAbortResponse is the running agent's answer to EncryptAbortRequest.
func (l Layout) EncryptAbortResponse() string {
	return l.Join("/var/lib/paddock/encrypt-abort.response")
}
