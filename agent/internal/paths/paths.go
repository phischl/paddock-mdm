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

// Socket is the health socket.
func (l Layout) Socket() string { return l.Join("/run/paddock/agent.sock") }

// LastCheckin is touched after every successful check-in.
func (l Layout) LastCheckin() string { return l.Join("/run/paddock/last-checkin") }

// EnrollConfig is the enrollment configuration the Paddock autoinstall leaves for the first start of the agent
// (plan M4b decision 7).
func (l Layout) EnrollConfig() string { return l.Join("/etc/paddock/enroll.json") }

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

// RevokeEnabled is the marker the agent keeps while the bundle says revocation.enabled (plan M4c decision 1);
// paddock-revoke refuses to run without it.
func (l Layout) RevokeEnabled() string { return l.Join("/etc/paddock/revoke-enabled") }
