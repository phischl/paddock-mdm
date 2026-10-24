# 0042 — Software catalog and self-service: package sources, the `software` bundle section, the local self-service channel
Status: Proposed (architect, 2026-10-24; plan `docs/plans/M13a-software-catalog.md`; M13b and M13c outlined there)

## Context

Organizations want to manage the software of their Linux workplaces the way the Intune Company Portal does it on
Windows: some applications are installed because of the device's assignment, others are offered and installed by the
user on demand; updates and removals travel the same way. Today Paddock holds or releases operating-system updates
(`updates` section, plan M5b: `package_hold`, `apt-mark hold`, `/etc/apt/preferences.d/50paddock`,
unattended-upgrades blacklist) and manages exactly one third-party APT source, the identity component
(`agent/internal/reconcile/login.go`: `/etc/apt/keyrings/himmelblau.gpg`,
`/etc/apt/sources.list.d/paddock-himmelblau.list`, a scoped `apt-get update`, ADR 0019). Every other software change
is manual work on each device. Users keep local administrator rights, so the catalog corrects and reports deviations
rather than preventing them (CLAUDE.md design contract 8, RR-01).

The maintainer decided on 2026-10-20 (ticket PDK-355):

1. the self-service interface is a desktop app on the device that Paddock installs and updates; it talks to the local
   agent, and the agent carries out every request (the pull model stays);
2. APT for system software and Flatpak for desktop apps; no Snap; own `.deb` packages come from the customer's own
   APT repository added as a source;
3. targets: device groups first; user groups and users in a later phase;
4. "lock" means both: hold a version, and forbid a package (removed if present, reported);
5. a required app a user removes locally is reinstalled and the event reported; no hard block;
6. no approval workflow for now;
7. a catalog shared across organizations is low priority.

Constraints from the existing architecture:

- A bundle is the signed desired state of one device (ADR 0005). New capabilities are **optional top-level sections**
  (`updates`, `disk`, `hostname`), never new entries in `resources[]`, because an agent rejects a bundle with a
  resource type it does not know (architecture §11.3 amendment 2026-10-08, ADR 0013).
- The gateway rejects a whole event batch with 400 `unknown_event_type` when one event type is outside
  `protocol.EventTypes`; a newer agent must not send a type an older server does not know (ADR 0024).
- `/etc/apt/` is a **denied** path tier for managed files (ADR 0034 decision 2, `pkg/policy`): no `file` resource
  may write there. A dedicated reconciler with its own validation is the only way Paddock writes below `/etc/apt/`
  (the login reconciler is the precedent).
- Every privileged action goes through `app.ActionRunner`, with exactly one audit event per attempt; codes come from
  the closed registry; API tokens never satisfy a step-up (ADR 0034 decision 3).
- Protected areas are re-verified; a change is a tamper event (architecture §11.6; the `updates` files use the
  drift-pass comparison against the last applied spec and emit `tamper.protected_file_changed`).
- The uninstall (ADR 0037, `agent/internal/uninstall/steps.go`) removes what Paddock wrote by a stated rule per path.

## Options

### A. Package sources and trust

- **A1 — One shared keyring for every Paddock source (`/etc/apt/trusted.gpg.d/paddock.gpg`).** + One file. − Every
  key then signs every source, including the distribution's: a compromised vendor key can replace `libc6`. Rejected.
- **A2 — One deb822 `.sources` file per source with `Signed-By:` pointing at a per-source binary keyring
  `/etc/apt/keyrings/paddock-<slug>.gpg`; HTTPS only; the key's fingerprint is part of the signed bundle and of the
  audit event; the agent compares the fingerprint of the key it writes with the bundle's.** + The key is scoped to
  its source by apt itself; same layout as the identity component; the keyring is a blob the agent can hash and
  compare; `apt-key` is not used anywhere. − Two files per source. **Chosen.**
- **A3 — deb822 with the armored key inline in `Signed-By:`.** + One file. − apt ≥ 2.4 only, an indented armored
  block in a configuration file is harder to compare byte-wise and to inspect by hand, and it deviates from the
  existing himmelblau layout and uninstall path list. Not chosen; nothing prevents a later switch.
- **Who computes the fingerprint.** The server has no `gpg`; the device has one. (i) `golang.org/x/crypto/openpgp`
  is deprecated and frozen and would become a direct import of a module that is only indirect today; (ii)
  `github.com/ProtonMail/go-crypto` is a new dependency; (iii) a minimal RFC 4880 reader for the public-key packet
  (armor decode with CRC-24, packet header, v4 fingerprint = SHA-1 over the key packet) in `pkg/openpgpkey`, shared
  by server and agent, stdlib only, refusing v3, v5 and v6 keys and anything that is not a public key. **(iii) is
   chosen**; (i) and (ii) stay an open question for the maintainer (plan §12).
- **Step-up.** Adding, changing or deleting a source or its key is root-equivalent: whoever controls a source key
  ships code that runs as root at install time. Create, update and delete of a source require the `org_admin` role
  and a fresh WebAuthn step-up (`ActionSpec.RequiresStepUp`), which excludes API tokens (ADR 0034 decision 3). The
  administrator enters the fingerprint they verified out of band **and** uploads the key; the server refuses a key
  whose computed fingerprint differs (422 `fingerprint_mismatch`), so a key pasted from the wrong page never becomes
  a trust anchor. The server never contacts a source: it validates syntax only (pull model; the server has no
  outbound role for this).

### B. Desired state and intents

- **B1 — A new `resources[]` type.** Rejected (ADR 0013, §11.3 amendment 2026-10-08).
- **B2 — An optional top-level section `software` (schema v2) with `sources[]` and `packages[]`, mapped by the
  agent to one internal resource `software` applied right after `updates`.** + Older agents ignore the section; a
  device without assignments has no section; one reconciler owns `/etc/apt/sources.list.d/paddock-*.sources`,
  `/etc/apt/keyrings/paddock-*.gpg` and `/etc/apt/preferences.d/51paddock-software`. **Chosen.**
- **Intents** of an assignment (catalog entry × device group, or organization-wide): `required` (installed and kept
  installed; update rule `latest` or `pinned` with a version), `uninstall` (removed if present), `hold` (lock variant
  1: the installed version, or a given version, is held; nothing is installed), `forbid` (lock variant 2: removed if
  present and an apt pin `Pin-Priority: -1` prevents installation through apt). Several assignments for one package
  on one device are merged by severity `forbid > uninstall > required > hold`; a `hold` with a version turns a
  `required latest` into `required` pinned at that version; two pinned versions take the lexicographically smallest
  and report a conflict, as `updates.Merge` does for holds.

### C. Ownership of holds between the `software` and the `updates` reconciler

- **C1 — Both reconcilers call `apt-mark` and write pin files, each with its own record.** − Two owners of one
  apt state; a package in both records is unheld by whichever runs last. Rejected.
- **C2 — The `updates` reconciler stays the only owner of `apt-mark hold`, of the pin file
  `/etc/apt/preferences.d/50paddock` and of the unattended-upgrades blacklist. The compiler feeds it from two
  sources: `package_hold` rows (as today) and software assignments with the intent `hold` or `required pinned`,
  merged by `updates.Merge`. The `software` reconciler never calls `apt-mark` and never writes `50paddock`; it owns
  installs, removals, the forbid pins (`51paddock-software`, priority −1) and the source files.** + One owner per
  file and per apt command; the existing gates U1 stay valid; `apt-get install pkg=version` by the software
  reconciler and the pin by the updates reconciler agree by construction. **Chosen.**

### D. Status and events

- **D1 — One device event per status change of every package.** − Every check-in could carry hundreds of events;
  the audit trail is not a status store.
- **D2 — Changes are events (installed, reinstalled, removed, apply failed) and the status per app × device travels
  in the check-in health as `health.software` (`digest` always; `items` when the digest changed since the last
  successful check-in and at least once per 24 h), stored by `RecordStatus` in `device_software_status`.**
  + Reuses the health channel (`health.disk` is the precedent), bounded size, one row per app × device. − After a
  restore from backup the status can lag up to 24 h (RR-79). **Chosen.**
- **Event compatibility (ADR 0024).** The agent emits the new event types `software.installed`,
  `software.reinstalled`, `software.removed` and `software.apply_failed` only while applying a bundle that carries
  the `software` section. Only a server that knows the section renders it, and that server knows the event types.
  No upgrade-order rule is needed beyond "the server first", which is the usual order.

### E. The local self-service channel (M13b; decided now because the bundle and the agent must leave room for it)

- **E1 — The desktop app runs privileged (polkit action, pkexec) and calls apt itself.** − A second executor beside
  the agent; a polkit policy is a protected area of its own; the app would need the signed bundle. Rejected
  (maintainer decision 1: the agent is the executor).
- **E2 — The desktop app talks to `paddockd` over a second unix socket `/run/paddock/selfservice.sock` (mode 0666,
  JSON over HTTP as the health socket); the agent authenticates the caller with `SO_PEERCRED` (UID, PID), resolves
  the UID to the account (`getent passwd <uid>`; UIDs in Himmelblau's `idmap_range` 200000–999999999 are directory
  users, below 60000 local accounts, RR-07) and authorizes every request against the signed bundle: a user may list,
  install, update and remove only the apps with the intent `available` whose audience names them (device-wide, or
  their UPN among the entry's audience), and may remove only what self-service installed; `required`, `hold`,
  `forbid` and `uninstall` entries are visible as read-only state and never changeable (`403 required_by_policy`).
  UID 0 has no special rights on this socket. One operation runs at a time per device; the agent executes it as root
  through the same code path as the reconciler (APT) or, for Flatpak user scope, in the user's context
  (`systemd-run --uid`), always agent-initiated; every operation is one device event (`software.self_service`).**
  + No polkit, no second executor, kernel-authenticated caller, policy from the signed bundle, works offline for
  listing. − The app must be installed and updated by Paddock itself (a catalog entry of the `required` kind that
  Paddock ships). **Chosen.** The socket path is reserved now; M13a does not create it.

### F. User and user-group targets on multi-user devices (M13b)

- **F1 — The agent resolves membership at login time through NSS groups.** − Himmelblau's NSS answers any name
  (RR-07); group membership on the device is a cache; offline behaviour undefined. Rejected.
- **F2 — The compiler resolves user and user-group targets through the device–owner relation (`device_owner`, plan
  M8d): a `required`, `uninstall`, `hold` or `forbid` assignment targeted at users applies to a device when one of
  its owners is targeted; an `available` assignment targeted at users is rendered into the device's bundle with the
  audience (the targeted owners' UPNs), and the agent authorizes the caller against that list. Devices without
  owners receive no user-targeted entries; administrators target such devices by device group.** + One source of
  truth (the server), deterministic bundles, offline-safe, auditable. − A user who signs in to a device they do not
  own sees only device-targeted apps. **Chosen.**

### G. Locally removed required apps

- **G1 — Block the removal (dpkg hook, `apt-mark hold`, immutable attribute).** − A local administrator removes any
  block; the user experience is a fight. Rejected (maintainer decision 5).
- **G2 — Reinstall and report: the reconciler records the packages it installed (`/var/lib/paddock/state/
  software-installed`); a recorded `required` package that is not installed is reinstalled at the next pass and the
  device reports `software.reinstalled` (audit `device.software_reinstalled`). A first installation reports
  `software.installed`. Nothing blocks the user.** **Chosen.**

### H. Fail safe on the device

- **H1 — Apply the cached bundle without conditions (as the other reconcilers).** − A device cut off from the
  server would still remove software from a stale policy; ticket PDK-355 requires that nothing is removed while the
  server is unreachable.
- **H2 — Installs and reinstalls proceed whenever the repository is reachable; every removal (`uninstall`, `forbid`,
  and the downgrade of a pinned package) requires a successful check-in within the last 15 minutes
  (`/run/paddock/last-checkin`); otherwise the removal is deferred, planned again at the next pass and reported in
  the status as `deferred_offline`. A dpkg lock held by another process (`DPkg::Lock::Timeout=60` exceeded) ends
  the pass with the status `dpkg_locked`, retried at the next drift pass; an interrupted dpkg run is finished with
  `dpkg --configure -a` before anything else. Every install or removal is simulated first (`apt-get -s`); when the
  simulation would remove any package other than the targets, the operation is refused and reported as
  `would_remove_dependents` — Paddock removes nothing but what the policy names.** **Chosen.**

## Decision

1. **Sources (A2).** Table `software_source` (organization-scoped, RLS): `slug` (immutable, `^[a-z0-9][a-z0-9-]{1,40}$`,
   unique per organization), `name`, `uris` (HTTPS only), `suites`, `components`, `architectures` (optional),
   `signing_key` (ASCII-armored OpenPGP public key), `fingerprint` (40 hex characters, computed by
   `pkg/openpgpkey` and equal to the administrator's typed value). On the device: `/etc/apt/sources.list.d/
   paddock-<slug>.sources` (deb822, `Signed-By: /etc/apt/keyrings/paddock-<slug>.gpg`) and the binary keyring. Never
   `/etc/apt/trusted.gpg.d/`, never `apt-key`. Create, update and delete: `org_admin`, step-up required, audit
   params carry `fingerprint` (and `old_fingerprint` on a key change). The server validates syntax and the
   fingerprint, nothing else.
2. **Bundle (B2).** `pkg/bundle.Bundle` gains the optional section `software *SoftwareSpec` (schema v2). The agent
   maps it to the internal resource `software` (`bundle.TypeSoftware`), applied after `updates`:
   `hostname → time → file → systemd_unit → updates → software → login → sudo`. A device without any software
   assignment and without a source in use has no section.
3. **Holds (C2).** The `updates` reconciler is the single owner of `apt-mark hold`, `50paddock` and the
   unattended-upgrades blacklist; the compiler merges `package_hold` rows and the `hold`/`required pinned`
   assignments into `updates.holds`. The `software` reconciler owns installs, removals, `51paddock-software` and the
   source files.
4. **Status and events (D2).** Device events `software.installed`, `software.reinstalled`, `software.removed`,
   `software.apply_failed`; audit codes `device.software_installed`, `device.software_reinstalled`,
   `device.software_removed`, `device.software_apply_failed`; status in `health.software` and the table
   `device_software_status`. The events are emitted only while a bundle with the section is applied (ADR 0024).
5. **Self-service channel (E2).** `/run/paddock/selfservice.sock`, `SO_PEERCRED`, policy from the signed bundle, the
   agent as the only executor, `software.self_service` as the event. Delivered in M13b.
6. **User targets (F2).** Resolved by the compiler through `device_owner`. Delivered in M13b.
7. **Reinstall and report (G2).** Recorded installs; reinstall plus `software.reinstalled`.
8. **Fail safe (H2).** Removals need a check-in within 15 minutes; dpkg lock means retry; interrupted dpkg runs are
   repaired first; a simulation guards every operation.
9. **Protected areas.** `/etc/apt/sources.list.d/paddock-*.sources`, `/etc/apt/keyrings/paddock-*.gpg` and
   `/etc/apt/preferences.d/51paddock-software` are protected: a file that differs from the last applied spec is
   restored at the next drift pass and reported as `tamper.protected_file_changed` (the mechanism of the `updates`
   files); a file matching the Paddock prefix that the spec does not name is removed and reported the same way
   (a rogue source must not pass as Paddock's). `/etc/apt/sources.list.d/paddock-himmelblau.list` and
   `/etc/apt/keyrings/himmelblau.gpg` keep their owner (the login reconciler). Flatpak remotes Paddock manages (M13b)
   join the list with the same rule. Architecture §11.6 gains item 5.
10. **Uninstall (ADR 0037).** Both modes, `leave` and `reset`, remove the Paddock-managed sources, keyrings and
    `51paddock-software`, because a trust anchor nobody manages must not outlive Paddock; both modes keep every
    installed application and release the holds (the existing step). The state record `software-installed` goes
    with `/var/lib/paddock`.
11. **Roles.** Sources: `org_admin` with step-up. Catalog entries, assignments and icons: `RolesWrite` (`org_admin`,
    `org_operator`), no step-up — an operator chooses only from sources an administrator trusted, which is the same
    privilege `install_now` has today. Reading: `RolesRead`.
12. **Not decided here (M13c).** Approval workflow, update waves through ADR 0033's rollout, maintenance windows,
    packages stored in Paddock, the patch compliance report, the platform-wide catalog, the declarative sections for
    software (`PUT /api/v1/config`) — M13a does not record change sets for software writes because software is not
    one of ADR 0033's eight sections.

## Consequences

- + The maintainer's seven decisions have a binding place; sources are scoped trust anchors; one owner per apt file;
  older agents are not affected by the new section; the status store is bounded; the device never removes software
  from a stale policy.
- − Two files per source and a hand-written OpenPGP reader (small, fuzzed, refusing everything but v4 public keys);
  a 24 h status lag after a restore; a user on a device they do not own sees only device-targeted apps.
- Residual risks (plan §6.7): RR-74 source key root-equivalence, RR-75 maintainer scripts as root, RR-76 Flathub as
  an external trust anchor, RR-77 local root bypasses apt pins, RR-78 refused operations that would remove
  dependents, RR-79 status lag, RR-80 pinned versions that vanish from a repository.
- Follow-ups: architecture amendments to §11.3 (reconciler table and apply order), §11.5 (protected-file check
  covers the new paths), §11.6 (item 5), §12.5 (software catalog paragraph), §16 (new tables); the runbook
  `docs/operations/software.md`; M13b (self-service app, Flatpak, user targets) and M13c as outlined in the plan.
