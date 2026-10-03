# Paddock – Product Concept

Oct 3, 2026 · @phizzl

Paddock is an open-source platform for managing Linux workstations centrally while users keep the local administrator rights they are granted. This document is the basis for technical architecture planning.

## Purpose and scope

**Paddock manages fleets of Linux workstations without taking local administrator rights away from their users.** Existing MDM products either do not support Linux meaningfully or assume a locked-down device. Paddock targets the opposite case: developer and power-user machines where `sudo` is part of the job.

**Target users:** organizations running Linux desktops and laptops, typically mobile and without an always-on VPN, that need central configuration, inventory, user lifecycle control, data revocation, and an audit trail suitable for ISO 27001.

**Initial requirements** come from a reference deployment of 30–100 devices, mostly Ubuntu LTS with a small Arch Linux share. The architecture must not be bound to that size.

**Out of scope for the first release:**

- Endpoint detection and response, threat hunting
- Network access control (802.1X, NAC)
- Mobile, Windows, and macOS devices
- Backup of user data on devices
- Command or session logging on devices
- SaaS mechanics: self-service sign-up, billing, custom subdomains

**The premise that shapes everything:** whoever holds root on a device can disable any agent and override any policy. Linux offers no hardware-anchored enforcement comparable to TPM-attested MDM on other platforms. Paddock therefore does not promise enforcement. It promises **enforcement in the normal case, plus reliable detection and evidence when someone deliberately circumvents it**. Organizational policy carries the consequences; Paddock makes violations visible and provable.

## Initial requirements

### Functional

| ID | Requirement |
| --- | --- |
| F1 | Roll out configuration centrally and continuously reconcile drift |
| F2 | Hold all users in Paddock; lock and unlock them centrally, with the lock taking effect on the device's local login |
| F3 | Allow users to log in offline after a first online login; offline behavior follows the login component (Himmelblau) as configured by Paddock |
| F4 | Inventory installed software and match it against known vulnerabilities |
| F5 | Revoke access to device data remotely, effective no later than the device's next contact |
| F6 | Enforce daily security updates and regular updates; allow packages to be held globally or installed immediately |
| F7 | Record every privileged action in a tamper-evident audit log suitable for ISO 27001 |
| F8 | Provide an administration portal; only administrators can sign in |
| F9 | Detect and report tampering with managed state |
| F10 | Serve multiple organizations from one installation with strict data isolation |
| F11 | Define permission profiles in Paddock and assign them globally, to groups, or to users; Paddock merges them into an effective profile and generates each user's `sudoers.d` entry, ranging from no privileges to full `sudo` |
| F12 | Track each device's last successful contact and flag devices that exceed a configurable staleness threshold |
| F13 | Distinguish local users and groups (managed in Paddock) from synced ones (owned by an upstream identity provider); synced attributes are read-only |
| F14 | Optional dead man's switch: a device that has not reached Paddock for a configurable number of days locks itself; disabled by default |
| F15 | Suspend all user logins on a specific device and lift the suspension again, without touching data or encryption |
| F16 | Create a managed local administrator account on every device with regular password rotation; Paddock administrators can reveal the current password and trigger rotation on demand |
| F17 | Devices check in every five minutes |

### Constraints

| ID | Constraint |
| --- | --- |
| C1 | Devices are mostly mobile and have no reliable VPN. All communication is initiated by the device (pull) |
| C2 | Devices must remain fully usable when Paddock is unreachable |
| C3 | Version 1 supports the distributions that Himmelblau supports, with Ubuntu LTS as the primary platform; Arch Linux is not supported in version 1 |
| C4 | Users can be granted local administrator rights up to full sudo, defined per user through permission profiles |
| C5 | Disk encryption (LUKS2) is a prerequisite on managed devices |
| C6 | The system must scale horizontally; no fixed target size is set |
| C7 | Source language is English; the UI must be localizable from the start |
| C8 | Self-hostable as a container stack; no mandatory dependency on a commercial license |
| C9 | Data minimization: collect only what the enabled features require |

## Design principles

These principles bind every component. A design that violates one needs an explicit, documented reason.

1. **Detection over enforcement.** Where root can circumvent a control, Paddock does not pretend otherwise. It protects state, detects deviation, and produces evidence.
2. **Device-initiated, publish and sync.** The server precomputes each device's desired state as a signed bundle. Devices fetch it; the server never pushes and never computes per request. Devices never access the configuration repository directly; Paddock compiles, signs, and serves the result itself.
3. **Asynchronous ingest.** Everything devices report (heartbeats, inventory, events) enters through a message queue and is processed asynchronously. No synchronous write path from device to database.
4. **Fail safe, not fail secure.** If Paddock is unreachable, devices keep working. No component locks, wipes, or blocks on its own initiative because a server is missing. The only exception is the optional dead man's switch (F14), disabled by default and documented as an exception.
5. **Organization isolation by construction.** Every entity carries an `organization_id`. Isolation is enforced in one layer, not in each query.
6. **Canonical audit.** Audit events are stored once, in English, with stable codes and structured parameters. They are never translated or rewritten; only their display is localized.
7. **Everything as code.** Configuration, policies, and infrastructure live in version control. The portal writes through the same path, not around it.
8. **Small trusted core.** Components that can destroy data or lock users out are minimal, separately signed, and subject to stricter review than everything else.
9. **Reuse before build.** Proven open-source components are integrated where they fit. Paddock builds only what nothing else provides safely.

## Architecture

&#91;embedded content: Paddock architecture: control plane and managed device\]

Devices never receive inbound connections. They authenticate against the identity service, fetch precomputed signed bundles, and push events into a queue that workers consume asynchronously. If the control plane is unavailable, devices keep working; only new configuration, reports, and commands are delayed.

### Components

| Component | Role | Built or reused |
| --- | --- | --- |
| Portal and API (paddock-server) | Administration, user and profile management, command issuing; the only place privileged actions originate | built |
| Workers and state compiler | Consume ingest events; compute and sign each device's desired state when inputs change | built |
| Bundle store | Serves signed bundles; cacheable at the edge | reused (object storage) |
| Ingest queue | Decouples device reports from processing | reused, technology per A8 |
| Identity | Authentication for devices (through Himmelblau) and administrators | bundled: Authentik |
| Fleet and osquery | Inventory, vulnerability matching, policy queries | reused, free core only |
| Audit pipeline | Normalizes events into a search index and WORM storage | reused |
| paddock-agent and supervisor | Applies bundles, executes commands, reports tampering, manages the login component, revokes data | built |

### Scalability model

No target size is fixed (C6); the architecture must scale horizontally from the start:

- **Ingest through a message queue.** Devices write only to the queue. Workers scale independently and process idempotently.
- **Publish and sync.** Desired state is computed when its inputs change (a profile edit, a policy change, a hold), not when a device asks. Devices fetch finished bundles; the read path is static and cacheable.
- **Precompute everything that can be precomputed.** Compliance views, dashboards, and per-organization summaries are materialized by workers, not calculated on page load.
- **Stateless API nodes.** Session and organization context come from tokens; any node can serve any request.

**Check-in interval: five minutes (F17).** This keeps login suspension, unlock, and revocation responsive. Publish and sync makes the interval cheap: an unchanged bundle is answered with a conditional response and no body, so the steady-state cost is one small authenticated request per device every five minutes. Every check-in carries random jitter, and failed check-ins back off, so a fleet never hits the server in lockstep after an outage.

The architect chooses concrete technologies (A8, A9).

### Secure bundle delivery

**Devices never pull from Git.** The configuration repository and the database are inputs to the state compiler; the only thing a device ever fetches is its own compiled, signed bundle.

- **Authenticated fetch.** The bundle endpoint requires the device's identity (A5, A6). Unauthenticated requests receive nothing.
- **Authorized per device.** A device can fetch only its own bundle, never another device's or another organization's.
- **Signed and verified.** Bundles are signed with a dedicated key (A3); the agent verifies the signature before applying anything.
- **Monotonic versions.** Every bundle carries an increasing version. The agent rejects bundles older than the one it last applied, which prevents replay and downgrade.
- **Minimal content.** A bundle contains only what that device needs. Secrets that must reach the device are encrypted for that device.
- **Edge caching only with preserved authorization**, for example short-lived signed URLs; a cache must never serve one device's bundle to another.

## Identity and user lifecycle

**Paddock holds every user; only administrators can sign in to Paddock itself.** Locking a user in Paddock must block that user's local login on every device, no later than the device's next contact.

### Source of truth

**Decided: Authentik is a mandatory, bundled component of Paddock.** It is the single source of truth for authentication – for administrators and for device logins.

- **Local users and groups** are created in Paddock but stored in Authentik. Paddock's user management is a simplified wrapper.
- **Synced users and groups** come from an upstream identity provider, with Authentik acting as broker (for example for Entra ID). Paddock displays and can lock them, but cannot change passwords or core attributes; those are owned upstream.
- **Device logins run through Himmelblau, which authenticates against Authentik via OIDC,** including MFA (see Login component).

Rationale: authentication, MFA, and federation are where self-built, AI-generated code carries the highest risk. Authentik already provides them.

Consequences:

- **No MFA during offline login.** Logins within the offline window use cached credentials; a second factor cannot be verified. This is unavoidable and must be documented for audits.
- **Authentik belongs to the trusted core.** Paddock pins its version, ships its updates with Paddock releases, and defines a response time for Authentik vulnerabilities.
- **Organization isolation extends into Authentik.** Users of one organization must never appear in another organization's login flows (A1).
- **Only Authentik's open-source core is used**, as with Fleet.

### Lock propagation

### Login component: Himmelblau

**Decided: Paddock does not own the login path.** Device login is delegated to Himmelblau, an open-source project that provides OIDC and Entra ID login for Linux with native MFA at the greeter, TPM-bound Hello PIN, and offline sign-in. Paddock configures and monitors it; it never adds its own login logic.

| Layer | Owner | Examples |
| --- | --- | --- |
| What applies | Paddock | Delivers `himmelblau.conf` in the signed bundle: identity provider, who may log in, MFA requirements, PIN rules, offline emergency access. Enforces device-wide login suspension through the allow list |
| Who exists and who is locked | Authentik | Users, groups, account locks – driven by Paddock's user management |
| How authentication works | Himmelblau | Login flow, MFA, Hello PIN, TPM binding, token cache |
| Whether everything still holds | Paddock | Himmelblau running, configuration unchanged, expected version – a protected area with tamper detection |

Two binding rules:

1. **No intervention beyond configuration.** What Himmelblau cannot do through its options is not added through patches, wrappers, or custom PAM modules. Otherwise the risky login code returns, spread across two projects.
2. **Missing features go upstream, never into a fork.** Maintaining a fork of a security-critical authentication project is exactly the burden this decision avoids.

**Offline behavior (F3) follows Himmelblau.** A minute-granular offline window enforced by Paddock was dropped: it would have required a custom PAM module, the highest-risk component in the original design. Protection against locked users working offline comes from device-wide suspension (F15), Lock, and the optional dead man's switch.

**Proof of concept gate.** Before further development builds on this decision, a time-boxed PoC on the test VMs must show:

1. Authentik works as Himmelblau's OIDC provider, including MFA.
2. A lock in Paddock takes effect on device login through Authentik.
3. The agent can enforce device-wide suspension through Himmelblau's allow list.
4. Hello PIN works in OIDC mode against Authentik, which requires the Himmelblau client in Authentik to allow refresh tokens.

If the PoC fails, the fallback is SSSD against Authentik with day-granular offline validity – still without any custom login code.

Himmelblau is licensed GPLv3+. Paddock ships it as a separate package and never incorporates its code, which keeps Paddock's MIT license unaffected.

#### Login configuration decisions

| Setting | Decision |
| --- | --- |
| Entra ID users | Always authenticate through Authentik; Himmelblau runs in OIDC mode. One source of truth for authentication; no Microsoft 365 single sign-on on the device |
| Hello PIN for daily login | Configurable per organization |
| Intune registration by Himmelblau | Configurable per organization in principle, but tied to Himmelblau's direct Entra mode, which Paddock does not use. Effectively unavailable in version 1 |
| Offline emergency access for MFA users | Configurable per organization, with a duration; disabled by default. Himmelblau's documentation warns that it allows password-only login when the identity provider is unreachable – an attacker who blocks that access can bypass MFA. The portal shows this warning when it is enabled |
| sudo ownership | Architect decision (A13) |
| Boot PIN and login PIN | Architect decision after a UX test (A14) |

### Lock propagation

| Situation | Expected behavior |
| --- | --- |
| Device online, user locked | Login fails at the next authentication against Authentik |
| Device offline, user locked | Offline sign-in remains possible as far as Himmelblau's offline mechanisms allow |
| Device comes online | Lock takes effect at the next online authentication |
| Exposure must end immediately | Device-wide suspension (F15), then Lock if needed |

A lock withdraws access, not data: a local root user can bypass PAM. Data protection comes from disk encryption and data revocation (see Device controls).

### Device-wide login suspension

**An administrator can suspend all logins on one device and lift the suspension again.** This is the light, reversible response when it is unclear whether a device is lost: no keyslots are touched, no data is at risk, and unsuspending restores normal operation immediately.

- Suspension takes effect at the device's next check-in, within the five-minute interval.
- Active user sessions are terminated; new logins are denied for all directory users, enforced through the login component's allow list.
- **The managed local administrator account stays usable**, so an operator with the device in hand can still recover it.
- Suspension withdraws access, not data. If the device is confirmed lost, escalate to Lock.

Response levels at a glance: **suspend logins** (unclear) → **Lock** (lost, reversible) → **Destroy** (final).

### Managed local administrator account

**Every device gets a local administrator account whose password Paddock rotates regularly.** It works offline, independent of Authentik, and serves as the break-glass path.

- **Rotation interval** is configurable per organization.
- **Reveal:** a Paddock administrator can display the current password. Every reveal requires step-up authentication and produces an audit event.
- **After a reveal** the administrator either waits for the next scheduled rotation or triggers rotation immediately. An optional organization policy rotates automatically a set time after each reveal.
- **Rotation must never leave a device with an unknown password.** The agent generates the new password, sends it to Paddock encrypted, and applies it only after Paddock has confirmed storage. If confirmation fails, the old password stays valid.
- **Escrowed passwords fall under A3**, with the same protection as signing keys.
- **Local administrator logins are audit events**, reported at the next check-in.
- The account is a protected area: unexpected changes to it are tamper events.

## Local admin model

**Users can keep full `sudo`. Paddock adds a tripwire with evidence, not a security boundary.** Circumvention is possible, for example by installing a root service. The model's value is that circumvention must be deliberate, becomes visible, and can be acted on under the operator's acceptable-use policy. Operators must document it that way in their ISMS.

**No command denylist in `sudoers`.** A denylist is defeated by `sudo bash` and creates a false impression of enforcement. Paddock protects state and detects deviation instead.

### Permission profiles

**Privileges are assigned per user through profiles defined in Paddock.** Paddock generates the user's `sudoers.d` file from the assigned profile and ships it in the device's state bundle. Full `sudo` is one profile among others, not the default for everyone.

| Profile class | Meaning | Enforceable |
| --- | --- | --- |
| None | No `sudo` | yes |
| Restricted | Explicit allowlist of commands | yes, if no listed command is root-equivalent |
| Full | Unrestricted `sudo` | detection model applies |

**Root-equivalent commands collapse a restricted profile into full root.** Package installation (maintainer scripts run as root), membership in the `docker` group, `systemctl edit`, and any editor or pager with a shell escape all grant full control. The portal must flag such commands when an administrator adds them to a restricted profile, and the profile must then be treated as full for detection purposes. An allowlist is enforceable; a denylist never is.

**Generation must never break `sudo`.** A malformed `sudoers` file can disable `sudo` on the device entirely. Generated files are validated (`visudo -c`) before activation, written atomically, and rolled back on failure. Profile changes are audit events.

Open point for the architect: whether profiles can be overridden per device or device group, for example full rights on a personal laptop but restricted rights on a shared lab machine.

#### Assignment and effective profile

Profiles can be assigned at three levels. The effective profile is computed in a fixed order: global profiles first, then group profiles merged in, then user profiles.

| Order | Level | Applies to |
| --- | --- | --- |
| 1 | Global | Every user in the organization |
| 2 | Group | Every member of the group |
| 3 | User | One user |

**Merge rules** (confirmed):

- **Command allowlists are unioned** across all levels. A union is order-independent, so membership in several groups yields a deterministic result.
- **Profile class takes the highest value** (None < Restricted < Full). A single Full assignment anywhere makes the effective profile Full.
- **Scalar settings are overridden by the later level** – user over group over global – for example password prompting or the credential timestamp timeout. In case of doubt the user level wins. Between several groups at the same level, the most restrictive value wins.
- **A lower level cannot remove a right granted above it.** With union semantics, a user profile can only add. If a right must be withdrawn from one user, that is modeled by removing the user from the group, never by a deny entry – deny entries in `sudoers` are not enforceable.

Consequences for the system:

- The state compiler recomputes the effective profile whenever a profile, an assignment, or a group membership changes, and republishes the affected bundles.
- The portal shows the effective profile with its derivation: for every granted command, which assignment granted it.
- A group membership change is a privilege change and produces an audit event with the effective class before and after.
- Root-equivalent commands are evaluated on the effective profile, not on individual profiles, because two harmless profiles can combine into full root.

Open point for the architect: whether groups are managed in Paddock or sourced from the identity provider.

### Three layers

| Layer | Mechanism | Effect |
| --- | --- | --- |
| 1 – Friction | `sudoers` rules against the obvious cases | Prevents accidental disabling, not intent |
| 2 – Notice | `sudo` lecture referencing the operator's policy and logging | Removes "I didn't know"; the key element legally |
| 3 – Detection | Frequent policy checks: agent running, log shipper running, hashes of protected files, LUKS keyslot count, heartbeat present | Every deviation raises an alert and an audit event; this is the actual control system |

### Protected areas

Hard protection is reserved for changes with irreversible or external consequences:

1. `/etc/sudoers*` and files managed by Paddock's configuration
2. LUKS keyslots and headers
3. The agent, `fleetd`, the configuration timer, and the log shipper
4. Identity configuration: Himmelblau, PAM, NSS

### Explicitly allowed

Installing and removing packages, managing services, Docker and virtualization, loading kernel modules, network configuration, adding package sources, shaping development environments freely.

Paddock ships this allowed/protected split as a documented default that operators can reference in their own acceptable-use policy. A model with broad freedom and four clear protected areas is accepted by technical teams; a restrictive allowlist invites workarounds and undermines the trust the detection model depends on.

## The agent

**`paddock-agent` is an action executor, not an inventory agent.** It applies desired state, executes commands, reports tampering, and manages the login component's configuration. Inventory, vulnerability matching, and policy evaluation stay with osquery and Fleet.

| Agent responsibilities | Not the agent's job |
| --- | --- |
| Fetch and apply the device's signed state bundle | Inventory software |
| Execute portal commands | Evaluate vulnerabilities |
| Report tamper events | Define policies |
| Execute the data revocation path | User interaction or UI |
| Manage the login component's configuration | Persist logs locally beyond shipping |
| Update itself with self-test and rollback |  |

### Why a design contract

The agent is the riskiest component in the system: root-privileged, self-updating, deployed to devices without physical access, and largely AI-generated. A broken update without working rollback loses manageability of the entire fleet. A defect in the revocation path destroys the wrong device's data.

Self-update also has a bootstrap problem: the component performing an update cannot reliably replace itself if it crashes while doing so.

### Design contract (binding)

1. **Supervisor and agent are separate.** A minimal supervisor (systemd unit plus watchdog) starts, monitors, and replaces the agent. The agent never replaces itself in-process. The supervisor is simple enough to need no updates.
2. **A/B installation.** New versions install alongside the current one; switching and rollback both flip one symlink.
3. **Self-test before switch.** The new version must pass defined checks (start, server connection, signature verification, readable configuration, health endpoint) before it becomes active.
4. **Watchdog with automatic rollback.** If the new version does not report healthy within a fixed window, the supervisor reverts and emits an audit event.
5. **Signed artifacts.** Updates are signed and verified before installation. The public key belongs to the supervisor, not the agent.
6. **Staged rollout.** Every update rolls out in waves with an automatic stop at a defined failure rate. Never all devices at once.
7. **Isolated revocation path.** Data revocation is a separately signed module. It requires a short-lived, device-bound token and is never changed through the same channel as the agent core.
8. **Fail safe.** If the server is unreachable, the device works normally. The agent never locks, wipes, or blocks on its own initiative – except through the dead man's switch, if an organization enables it.
9. **Static binary.** No runtime dependencies (for example Go), which avoids library breakage, especially on rolling-release distributions.
10. **Two-person rule for the revocation path.** Every change to that code requires review by a second person and a passed test on real hardware.

## Device controls

### Last contact and device health

**Paddock records every device's last successful contact.** Every authenticated check-in – heartbeat or bundle fetch – updates it. Unauthenticated or rejected requests never do.

In line with asynchronous ingest, heartbeats enter the queue and workers materialize the last-contact state; there is no synchronous database write per heartbeat.

The portal shows per device: last contact, the bundle version last applied, the agent version, and policy status. Staleness thresholds are configurable per organization, with at least a warning and a critical level. Crossing a threshold is an alert and an audit event: a device that goes silent is either offline, reinstalled, or tampered with, and all three need a reaction.

### Data revocation

A forced remote wipe does not exist on Linux: the device must be online and the agent running. F5 is met with three staged measures.

| Stage | Measure | Takes effect | Needs agent |
| --- | --- | --- | --- |
| 1 | Lock the user | after the offline window, even without any connection | no |
| 2 | Erase the LUKS keyslots | after an automatic reboot triggered by the agent with a short delay | yes |
| 3 | Record the outcome | immediately | yes |

Stage 3 is routinely forgotten and is what matters for audits and breach notifications: proof that revocation took effect, or a documented finding that the device never came back online.

**Revocation sequence.** Erasing keyslots does not make data unreadable on a running system: the volume key stays in kernel memory until the machine restarts. The agent therefore forces the reboot itself and does not wait for the user. The order matters:

1. Terminate all user sessions, so nobody keeps working on the decrypted volume.
2. Erase the keyslots and verify the erasure.
3. Send the confirmation and wait for the server's acknowledgment, bounded by a timeout. After the reboot the device can no longer boot, so a confirmation not sent now never arrives.
4. Reboot.

The delay between erasure and reboot exists only to deliver the confirmation. It must stay as short as possible: a user with root who notices the sequence could copy data off during that window. Unsaved work is lost; operators must state this in their policy.

#### Two revocation actions: Lock and Destroy

Paddock offers two distinct actions with different approval thresholds. Most revocations are triggered by loss or departure, and lost devices often reappear; a reversible action removes the hesitation to act quickly.

| Action | Effect | Reversible | Approval |
| --- | --- | --- | --- |
| **Lock** | Keyslots erased, forced reboot; the operator can restore the device from the escrowed LUKS header | yes, by the operator with physical access | one administrator with step-up authentication |
| **Destroy** | Keyslots erased, forced reboot, escrowed header deleted; data is cryptographically unrecoverable | no | two-person approval |

**Header escrow happens before it is needed.** The agent escrows the LUKS header at enrollment and again after every keyslot change, not at revocation time. Revocation must not depend on a successful upload in the critical moment, and a keyslot change is already reported as a tamper event.

**What Destroy achieves without the device – and what it does not.** Two cases must be kept apart:

- **Locked, then lost:** the keyslots on the device are already erased; the hardware alone no longer yields the data. The only remaining path is the escrowed header. Destroying it server-side closes that path, even if the device never returns. Operators can define a policy such as: locked devices not recovered within a set period are destroyed automatically.
- **Lost before any revocation reached it:** the keyslots are intact. Destroy changes nothing for the device; it only removes the escrow copy. Protection then rests entirely on the encryption at rest (see Keyslot policy). This is the critical case, and the reason keyslot hygiene matters more than any remote action.

#### Optional dead man's switch

**A device that has not reached Paddock for a configurable number of days locks itself.** Disabled by default; enabled and configured per organization. This is a deliberate, documented exception to the fail-safe principle.

**It triggers Lock, never Destroy.** Destroy requires two-person approval, which an agent deciding alone on the device cannot obtain. Combined with the server-side auto-destroy policy, a self-locked device that never returns still ends up destroyed after a further period.

**What it protects against – honestly scoped.** The agent can only act on a running device. A thief without the PIN never boots it, so the switch does nothing there; encryption does. Its value lies in two cases: a device stolen while suspended, with the volume key still in memory, and a device deliberately kept offline by someone who still has access. A user with root can disable the switch; that is covered by the detection model, not by the switch.

Requirements:

- **Time basis is the last authenticated server contact**, anchored to a server-signed timestamp and measured with monotonic time, so that changing the local clock neither defers nor triggers the lock.
- **Staged warnings** to the logged-in user before the lock, for example three days and one day ahead, asking them to connect.
- **The period must be at least the offline login window** (F3); the portal enforces this.
- **The lock follows the regular revocation sequence**, but the confirmation cannot reach the server. Paddock therefore marks a device that stays silent past the period as presumed self-locked.
- **Platform outage risk.** If Paddock itself is down longer than the configured period, every device with the switch enabled locks. Operators must choose a period well above any realistic outage; the portal warns against short periods.

**The escrowed header is a high-value secret.** Together with the hardware it grants access to the data. Escrowed headers and recovery keys fall under A3 with the same protection as signing keys.

Revocation destroys local data irrecoverably. Paddock does not back up devices. Operators must state this in their policy and should treat local home directories as volatile. Paddock can report home directory size as an early indicator if local data starts accumulating.

### Disk encryption

LUKS2 is a prerequisite. Paddock supports these unlock modes:

| Mode | Convenience | Protection on theft | Recommendation |
| --- | --- | --- | --- |
| Passphrase | low | full | supported |
| **TPM2 + PIN** | high | full; TPM lockout slows brute force | **default** |
| TPM2 without PIN | maximum | only until the login screen | not supported |
| Network-bound (Clevis/Tang) | high, centrally revocable | full | not supported: needs a reachable server at boot, which conflicts with C1 and C2 |

Recovery keys and LUKS header backups are escrowed with the operator (see Data revocation). Enrollment is automated.

**Keyslot policy.** A device lost before it receives a revocation is protected only by its encryption. Paddock therefore enforces:

- **No low-entropy keyslots.** No user-chosen passphrase slot remains after enrollment; a weak passphrase is the one keyslot an attacker can brute-force offline with the disk removed.
- **TPM2 + PIN as the only interactive unlock.** The TPM's dictionary-attack lockout limits PIN guessing to the device itself.
- **High-entropy recovery key**, generated by Paddock and stored only in escrow.
- **Keyslot inventory as a policy check.** An unexpected keyslot is a tamper event (see Local admin model).

### Patch management

Security updates install daily; regular updates follow a schedule. Both are enforced. `unattended-upgrades` alone is insufficient because it cannot hold packages centrally.

- **Global hold:** pinning (`/etc/apt/preferences.d/`, `IgnorePkg` in `pacman.conf`) is part of the device's state bundle. A change reaches every device with its next sync.
- **Immediate install:** a command that bypasses the schedule for named packages.
- **Optional later stage:** snapshot-based repository mirrors (for example aptly or Pulp) for wave-based rollouts.

Arch Linux is not supported in version 1 (C3).

## Multi-organization and internationalization

Both are design decisions, not features. Retrofitted, they touch every table, every API path, and every string.

### Multi-organization

**Paddock scopes organizations itself.** Fleet stays a data source without knowledge of organizations. Fleet's team feature is a premium capability and would force a commercial license on every Paddock user; one Fleet instance per organization scales operations linearly and was rejected.

**Term: `organization`.** Authentik uses the same word, so documentation always qualifies it: "Paddock organization" or "Authentik organization".

Minimum requirements:

1. **`organization_id` on every entity**, including audit events, enrollment tokens, and agent identities.
2. **Enforced in the repository layer.** The context comes from the authenticated token and is applied centrally. A per-query parameter that one query can forget is the most likely defect in generated code.
3. **Enrollment is bound to one organization.** A device never changes organization; it re-enrolls.
4. **Negative tests as an acceptance gate.** Accessing another organization's resource returns 404, not 403, verified automatically across all API paths.
5. **Audit storage is partitioned by organization.** The organization ID is part of the object path, so per-organization export and deletion are possible.
6. **Retention is configurable per organization**, within the limits the WORM storage allows.

Not in scope: self-service sign-up, billing, cross-organization roles, custom subdomains. The boundary is data isolation; everything beyond it can be added later without changing the data model.

### Internationalization

- English is the source language for code, commits, documentation, API, and UI strings.
- **Audit events are never translated** (principle 6).
- ICU MessageFormat, because of plural and gender forms.
- No concatenated strings; every sentence is one message with parameters.
- Language is a property of the user account, not of the organization or the browser alone.
- The agent and CLI stay English-only: their output ends up in logs, tickets, and search engines.
- Dates, times, and numbers are stored in UTC and formatted only in the frontend.
- German is the first target language, added once the UI stabilizes.

## Audit log and privacy by design

### Audit log

**Two storage paths: a search index for queries and alerting, and object storage with WORM lock for evidence.** A search index alone is insufficient because administrators can delete from it. The reference stack uses Loki and MinIO with Object Lock; the architect may substitute equivalents.

ISO 27001 prescribes no format. The relevant controls are A.8.15 (logging), A.8.16 (monitoring), A.8.17 (clock synchronization), and A.5.33 (protection of records):

| Requirement | Implementation |
| --- | --- |
| Completeness | Every privileged action from every source, normalized through one pipeline |
| Integrity | WORM storage in compliance mode; daily signed hash chain over each day's objects |
| Time | NTP enforced on devices, UTC everywhere, clock drift monitored as a policy |
| Access | Role-based read access; no delete permission for any operating account |
| Retention | Configurable per organization; automatic deletion afterwards |

**Separation of duties.** The audit store must not share an administrative domain with the systems it records. Separate credentials, separate host, and at least one replica outside the primary failure domain.

**Not iterable:** Object Lock is enabled at bucket creation, and compliance-mode retention cannot be shortened later. The deployment must get this right on the first production bucket.

**Limit of evidence.** On devices with local root, device-side logs are not tamper-proof at the source. Paddock narrows the window (near-real-time shipping), makes gaps visible (a missing heartbeat or log gap is itself an audit event), and keeps server-side records out of users' reach. This is the residual risk operators record in their ISMS.

### Privacy by design

Paddock collects only what enabled features need. No command logging on devices.

| Source | Events |
| --- | --- |
| Portal | Who triggered which privileged action on which device or account, with outcome |
| Identity | Login success and failure, MFA, lock, role change |
| Inventory | Enrollment, policy status, installed software, heartbeat |
| Configuration | Commits and merges to the configuration repository |
| Agent | Tamper events only: service stopped, protected file changed, clock drift, keyslot change |

**Never collected:** executed commands, process lists, network connections, browser or application data, keystrokes, screen content, location.

The negative list is part of the product documentation, not an internal note. It is what lets operators pass a privacy review and what keeps teams from seeing the inventory as covert surveillance.

Software inventory covers all installed packages, because private and business software cannot be distinguished technically. Making unauthorized installations visible is an intended purpose; operators must declare it in their policy.

## Decisions for the architect

These decisions are deliberately delegated. Each comes with the criteria a solution must meet, not with a solution.

| ID | Decision | Acceptance criteria |
| --- | --- | --- |
| A1 | **User source of truth and device authentication** – Authentik is bundled (decided); open: how Paddock organizations map to Authentik, shared instance or one per organization | No user of one organization is visible in another organization's login flows; meets F2, F3, and F13; works without an upstream identity provider; only Authentik's open-source core is used |
| A2 | **Himmelblau proof of concept** for the login component | The four PoC criteria in Login component are met; otherwise fall back to SSSD with day-granular offline validity, still without custom login code |
| A3 | **Signing key management** for agent updates, state bundles, and revocation tokens, plus escrowed LUKS headers and recovery keys | Keys never on the application server in plaintext; rotation and revocation defined; compromise of one key type does not compromise the others; works self-hosted without a commercial service |
| A4 | **Mass-revocation protection** if the portal or an admin account is compromised | A single compromised session cannot revoke more than a defined number of devices; step-up authentication for destructive actions; destructive actions are rate-limited and alerted |
| A5 | **Agent–server protocol** | Device-initiated only; mutual authentication; replay protection; idempotent commands; works through restrictive proxies |
| A6 | **Agent identity lifecycle** | Identity issued at enrollment, bound to one organization, rotatable, revocable; a cloned disk image is detectable |
| A7 | **Server–agent version compatibility** | Defined support window; an outdated agent degrades predictably, never silently; server upgrades never strand the fleet |
| A8 | **Message queue and async processing** | Horizontal scaling of ingest and workers; backpressure; at-least-once delivery with idempotent consumers; no synchronous device-to-database writes |
| A9 | **State compilation and distribution** (publish and sync) | Per-device bundles precomputed and signed; recomputed on change, not per request; cacheable at the edge; devices fetch only deltas or changed bundles |
| A10 | **Depth of Fleet integration** | Fleet replaceable in principle; Paddock's data model does not leak Fleet concepts; no dependency on Fleet premium features |
| A11 | **Backup and restore of the Paddock server** | Restore procedure tested; recovery point and time objectives stated; audit store excluded from routine restore paths |
| A12 | **Platform observability** | Metrics, health checks, and tracing separate from the audit log |
| A13 | **sudo ownership** between Paddock's permission profiles and Himmelblau's group-based sudo | Exactly one system determines a user's effective sudo rights; every granted right appears in the effective profile shown in the portal; behavior defined for users in a sudo-granting group without a Paddock profile |
| A14 | **Boot PIN and login PIN** (TPM2 + PIN for LUKS, Hello PIN for login) | Decided after a UX test with real users; the security properties of the chosen combination are documented; if both models are viable, offered per organization |

### Open technical questions

- **Break-glass access:** resolved by the managed local administrator account (see Identity and user lifecycle).
- **Enrollment:** autoinstall image, one-time token, who may enroll. This is the trust anchor of the whole system.
- **Silent disappearance:** a user reinstalls the OS and the device vanishes. Detection works only through absence; a reaction rule is needed.
- **Permanently offline devices:** lost or stolen hardware that never returns; the reporting and closing process.
- **Hardware reissue:** re-enrollment, re-encryption, deletion evidence.
- **Interference with third-party VPNs:** agent and sync must not disrupt user-managed VPN connections.
- **Platform outage behavior:** which commands are queued, which expire.
- **Shared devices:** device-to-person assignment affects audit attribution and revocation decisions.

## Development, testing, and acceptance

**Development is fully AI-assisted; humans review and accept.** This lowers build cost sharply but leaves review and operating cost unchanged. The acceptance gates below are therefore the actual quality assurance, not a formality.

### Environment

The stack runs as Docker Compose, identical for development and production. Test clients are reproducible VMs (Ubuntu LTS and Arch) defined as code. VirtualBox provides no real TPM, so TPM2 unlock and the revocation path are tested on real hardware; a hypervisor with an emulated TPM is an acceptable intermediate step.

### Acceptance gates

| Gate | Criterion |
| --- | --- |
| Configuration | Idempotent: a second run changes nothing, on all supported distributions |
| Identity | A lock in Paddock blocks the next online login through Authentik and Himmelblau, measured |
| Login suspension | Suspend and unsuspend take effect within one check-in interval; the local administrator account stays usable |
| Local administrator | Rotation never leaves a device with an unknown password, including when confirmation fails; every reveal is audited |
| Organization isolation | Cross-organization access returns 404 on every API path, tested automatically |
| Effective profile | Identical inputs produce an identical `sudoers.d` file regardless of evaluation order; generated files always pass validation |
| Agent update | A broken update is rolled back by the watchdog, demonstrated |
| Agent outage | Server unreachable: device works normally, no lock or block. With the dead man's switch enabled, the lock occurs only after the configured period and only after the warnings |
| Revocation | Lock: real device locked and restored from the escrowed header. Destroy: real device unrecoverable, escrowed header deleted, two-person approval recorded. Confirmation reaches the server before the forced reboot |
| Mass revocation | Exceeding the defined limit from one session is blocked and alerted |
| Audit | An event in WORM storage cannot be deleted, even with admin credentials; organization ID in the object path |
| Portal | Every privileged action produces exactly one audit event, including negative tests for duplicate and missing events on failure |
| Scalability | Ingest sustains a defined event rate with horizontal workers; no synchronous device-to-database path; five-minute check-ins with jitter do not produce load spikes |

The portal gate addresses the typical weakness of generated audit code: events are written on success and silently lost on failure.

### Repository layout

```
paddock/
├── CLAUDE.md               # binding rules for AI-assisted development
├── docs/
│   ├── concept.md          # this document
│   ├── architecture.md
│   ├── adr/                # one record per directional decision
│   ├── operations/
│   └── compliance/         # event schema, residual risks
├── server/                 # paddock-server: API and portal
├── agent/                  # paddock-agent, static binary
│   └── internal/
│       ├── supervisor/     # update, watchdog, rollback
│       └── revoke/         # separately signed; CODEOWNERS two-person rule
├── cli/                    # paddockctl
├── ansible/roles/          # generic roles only
├── deploy/compose/
└── test/
    ├── vms/                # reproducible test clients
    └── acceptance/         # the gates above as executable tests
```

Operator-specific configuration (inventories, policies, pinning) lives in a separate private repository, never in the product repository. Otherwise the first public release leaks it into Git history.

`CLAUDE.md` contains only the binding rules, written as instructions: the agent design contract, the protected areas, organization isolation, the never-translate rule for audit events, the acceptance gates as definition of done, and the two-person rule for the revocation path.

## Risks

| Risk | Impact | Mitigation |
| --- | --- | --- |
| Broken agent update without working rollback | Loss of manageability across the fleet | A/B installation, supervisor watchdog, staged rollout with automatic stop |
| Defect in the revocation path | Irreversible data loss on the wrong device | Separately signed module, device-bound token, two-person rule, real-hardware tests |
| Compromised portal or admin account | Mass revocation | Rate limits, step-up authentication, alerting (A4) |
| Signing key or escrow compromise | Malicious updates or revocations; escrowed headers expose data of seized devices | Key separation by purpose, rotation, keys never in plaintext on the server (A3) |
| Defect in the login path (offline window, PAM) | Users locked out of their own devices | No custom login code; login delegated to Himmelblau; managed local administrator as break-glass |
| Malformed generated `sudoers` | `sudo` unusable on the device | Validation before activation, atomic write, rollback |
| Restricted profile contains a root-equivalent command | False sense of restriction | Portal flags such commands; profile treated as full |
| User disables agent or logging | Gap in evidence | Heartbeat alerting, tamper events; documented residual risk |
| Missing organization filter in a query | Cross-organization data leak | Isolation enforced in the repository layer; automated negative tests |
| Revocation destroys unsaved work | Data loss, liability | Documented in operator policy; home directory size as early indicator |
| Forced updates break developer setups | Productivity and acceptance loss | Pilot groups, fast hold process, documented rollback |
| Scope creep from cheap AI-generated features | The product turns into an unmaintainable full platform | Written feature catalog and scope limits; reject against them |
| Dependency on Fleet changes license or direction | Core inventory capability at risk | Fleet kept replaceable in principle (A10) |

## Licensing, naming, and rejected alternatives

### License

**Paddock is released under the MIT license.** It allows any use, including commercial hosting, with minimal obligations. MIT contains no explicit patent grant; organizations with strict legal review sometimes ask about this.

Dependencies must be license-compatible with MIT distribution. Fleet ships its free core under MIT alongside a separately licensed commercial code area; Paddock must use only the free core (see A10).

### Naming

**Working title: Paddock** – a large enclosure with room to roam and a clear boundary. Renaming before the first public release costs almost nothing; afterwards it costs every inbound link. Trademark and namespace checks (GitHub, package registries, container registries, domain) are pending; the GitHub organization should be reserved early regardless.

| Component | Name |
| --- | --- |
| API and portal | `paddock-server` |
| Device agent | `paddock-agent` (daemon `paddockd`) |
| Command-line tool | `paddockctl` |
| Configuration file | `paddock.yml` |

### Rejected alternatives

| Alternative | Reason for rejection |
| --- | --- |
| Ubuntu Landscape | Strong for pure Ubuntu fleets, but licensed per machine through a commercial subscription and without Arch support |
| Commercial SaaS MDM with Linux support | Per-user pricing, closed source, and limited Linux depth; contradicts self-hosting and open source |
| Built-in Linux support of large MDM suites | Limited to compliance checks and scripts on selected distributions; no inventory, no revocation |
| Rudder, Uyuni, Puppet | Viable pull models, but each is another heavyweight platform without the identity, revocation, and audit features Paddock needs |
| Fleet teams for organization isolation | Premium feature; would force a commercial license on every Paddock user |
| Fully custom inventory agent | Buildable, but osquery tables, distribution compatibility, and vulnerability data would need permanent maintenance; Fleet provides them |
