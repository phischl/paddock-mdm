# 0037 — Device lifecycle: agent update policy, update now, supervisor updates, uninstall, owners, login history, hardware facts, staleness per device group
Status: Accepted (architect, 2026-10-17; plan `docs/plans/M8d-device-lifecycle.md`)

## Context

The first lab installation (v0.1.0-alpha.3, `.claude/roadmap/lab-findings.md` L12, L27, L32–L35) showed that a
device has a beginning in Paddock (autoinstall or adoption, M11) but no managed end, and that an administrator
cannot say who a device belongs to, what hardware it is, who signed in on it, or when its agent will be updated.

Facts about the code that bound the design (checked 2026-10-17, `main` at `ecfaad0`):

- **Agent releases are platform objects.** A platform administrator publishes a release and starts a rollout
  (`agent_rollout`, waves `{1,10,50,100}`, 24 h per wave, automatic halt). After the last wave the release is the
  *current release* and the gateway offers it to **every** active device of **every** organization that runs another
  version (`agentrelease.Offer.For`, `transport/http/device/handlers.go::agentUpdate`, Valkey `ar:current`). The
  agent stages the offer and the supervisor installs it into the inactive A/B slot (design contract 2–4, ADR 0024).
  There is no per-organization choice and no way to make one device update now: a device outside the current wave
  waits for the wave.
- **The supervisor has no update path.** `paddock-supervisor` is a Debian package (`packaging/nfpm/paddock-supervisor.yaml`)
  installed by the autoinstall or by hand; `docs/architecture.md` §11.2 says "the supervisor's own update happens only
  through the distribution package (apt)", but there is no Paddock apt repository (plan M4b non-goal). fleetd
  (`fleet-osquery`) is already installed and updated by the agent from the bundle's `inventory.package` of the newest
  published release (plan M5a decision 3, `agent/internal/reconcile/inventory.go`). `paddock-revoke` is installed
  only by its package (plan M4c decision 4) and never by the agent.
- **No uninstall.** `device.retired` revokes the identity keys; the device keeps running the agent, which gets 401
  `identity_revoked` and stops (architecture §6.5). Everything Paddock put on the device stays: the packages, the
  managed local administrator with its last escrowed password, Himmelblau and its PAM/NSS configuration, the deny
  list, `/etc/sudoers.d/paddock-u-*`, the unattended-upgrades configuration, the update timer, the notice files,
  fleetd. `agent-prerm.sh` and `supervisor-postrm.sh` deliberately keep `/var/lib/paddock` and `/etc/paddock`.
- **Device identity keys are files** (`agent/internal/identity`, `key_protection = file`); the TPM holds the LUKS
  TPM2 token's sealed key (plan M4b, `systemd-cryptenroll --tpm2-pcrs=7`) and nothing else of Paddock's.
- **`device_user_seen`** records the last login per user and device (plan M3a decision 10, `app.SeenWindow` 365 days)
  from `session.login`, which the agent sends at most once per user and 24 hours (`agent/internal/agent/sessions.go`).
  It is not a history and ADR 0032 fixes its retention because user locks depend on it.
- **Hardware facts stay in Fleet.** `docs/compliance/privacy.md`: "Serial numbers, hardware details, disk space and
  uptime stay in Fleet; Paddock does not copy them." The Fleet host detail carries `hardware_vendor`, `hardware_model`,
  `hardware_serial`, `cpu_brand`, `cpu_physical_cores`, `memory`, `gigs_total_disk_space`; the adapter
  (`server/internal/adapters/fleet/hosts.go`) reads none of them.
- **Staleness thresholds are per organization** (`organization_update_settings.staleness_warning_h` 24,
  `staleness_critical_h` 168; `app.Staleness.Evaluate`). A laptop fleet with the defaults is "presumed lost" after a
  week of holidays.
- Milestones M9 (notifications), M10 (retention, `organization_privacy_settings`, `retention.purged`) and M11
  (adoption, report-only, change sets) are planned (ADRs 0032, 0033) but not implemented. This ADR builds on the
  code as it is and names the touch points with those plans.

Binding rules: design contract 1 (supervisor and agent separate; the supervisor is simple enough to need no
updates), 5 (signed artifacts), 6 (staged rollout, never all devices at once), 8 (fail safe), 10 (two-person rule for
the revocation path); CLAUDE.md (RLS, `ActionRunner`, ADR 0018 lists and dialogs); ADR 0013 (additive protocol
changes); ADR 0024 (no new event type that an older server could receive from a newer agent).

## Options

### A. Agent update policy

- **A1 — Keep the platform-wide behaviour; add nothing.** − An organization cannot opt out of automatic agent
  updates (change management, works council agreements on maintenance windows), and nothing moves one device now.
- **A2 — Per-organization policy in the gateway's offer decision (Valkey per organization).** + Decided where the
  offer is made. − The gateway knows the device's organization but not its device groups; a per-group policy needs
  a per-device cache entry that the worker must recompute on every group change, outside the compiler's
  dependency index.
- **A3 — Per-organization policy with optional per-device-group override, rendered by the compiler into the
  bundle (`agent.update_policy`), honoured by the agent; the gateway keeps offering.** + The compiler already
  resolves device groups per device and recompiles on every group and settings change; the bundle is signed, so
  the policy reaches the device with the same integrity as everything else; an agent that does not know the field
  behaves as today (`automatic`). − A device on `manual` is still counted as *offered* in the current-release
  failure window (it never reports, so it never counts as failed; the window statistic is slightly diluted).
  **Chosen.**

Rollouts stay platform objects: `automatic` means "a device takes every release the platform administrator rolls
out, in its wave"; it does not start rollouts on publish (contract 6 keeps the human decision to roll out).

### B. Update now

- **B1 — A signed command `update_now` that carries the artifact.** − Commands are 16 KiB envelopes; the artifact is
  delivered through a presigned URL that expires in 120 s; the command would only tell the agent to ask.
- **B2 — A per-device request recorded in the device row and mirrored to Valkey (`au:<device_id>`); the gateway's
  offer skips the wave for that device and marks the offer `requested`; the agent stages a requested offer regardless
  of its policy and of an earlier failure of the same version.** + Reuses the whole signed update path (artifact
  signature, self-test, probation, rollback, reports); the request expires after 24 h; audited once. − One more
  Valkey key, rebuilt from PostgreSQL by the cache sync like the others. **Chosen.** A halted rollout is never
  offered, not even on request (the release failed; contract 4 and 6).

### C. Supervisor and fleetd updates

- **C1 — Supervisor updates only through a Paddock apt repository.** + Matches architecture §11.2 as written. − The
  repository does not exist (M4b non-goal, M7b distribution decided on packages in the artifact bucket); it would be
  a new component with its own signing, mirroring and proxy questions.
- **C2 — The agent installs a new `paddock-supervisor` package in-process (`dpkg -i`).** − The package's postinst
  restarts `paddock-supervisor.service`, whose cgroup contains the agent and therefore dpkg: dpkg is killed half-way.
- **C3 — The agent downloads the supervisor package of the current release from the bundle (SHA-256 in the signed
  bundle, as for fleetd), stages it, and hands the installation to a transient systemd unit outside the supervisor's
  cgroup (`systemd-run`), run by the agent binary of the current slot (`paddockd supervisor-upgrade`). The helper
  keeps a copy of the installed supervisor binary and unit file, installs the package, waits up to 10 minutes for
  the agent's next check-in mark, and restores the copy when it does not come. The agent reports the outcome as one
  event. The package is shipped only for the *current release* and only installed by an agent of that same release
  (agent first, supervisor second), only under the policy `automatic` or an update-now request, and only when the
  package version is newer (`dpkg --compare-versions`).** + No new component; the staged rollout of the agent gates
  the supervisor rollout; a broken supervisor is rolled back by the helper; contract 1 holds because the supervisor
  still never updates *itself* and still decides alone which agent runs. − The rollback restores the binary, not the
  dpkg database (the version dpkg shows may be the new one until the next successful upgrade); the helper and its
  10-minute check are new agent code. **Chosen.** fleetd keeps its existing path (plan M5a) and now also honours the
  policy. `paddock-revoke` is never installed or updated by the agent (contract 7 and 10; unchanged).

### D. Uninstall from the portal

- **D1 — "Retire" only (status quo).** − The device keeps every Paddock artifact and a stale local administrator.
- **D2 — One uninstall that removes everything Paddock touched.** − Removing Himmelblau on a device whose only
  accounts are directory users, or the managed local administrator on a device with no other administrator, leaves a
  device nobody can use (contract 8); clearing a TPM that holds the disk's unlock key leaves a disk only the recovery
  key opens.
- **D3 — Two modes, both signed commands with step-up, typed hostname and audit; never automatic; preconditions
  checked on the server from the last report and again on the device at execution time; a detached helper outside
  the supervisor's cgroup performs the removal, sends one final signed event and only then deletes the identity.**
  - `leave` ("leave the device as it is"): removes the Paddock packages, state and keys, Paddock's sudoers files,
    the deny list, the unattended-upgrades and update-timer configuration, the notice files and fleetd. Keeps every
    local account including the managed local administrator (its last escrowed password stays revealable for the
    retired device), the sudo memberships of break-glass accounts, Himmelblau with its configuration and packages
    (directory logins keep working against Authentik as long as the organization's application exists), the managed
    files, the disk encryption with every keyslot, and all user data.
  - `reset` ("reset the system"): everything of `leave` plus: removes Himmelblau and its configuration and credential
    cache (home directories of directory users stay), removes the managed files that are unchanged on the device,
    removes the managed local administrator **unless it is the last local administrator** (then it is kept and the
    result says so), and optionally requests a TPM clear — refused on the device while any LUKS volume carries a
    TPM2 token, because the disk would then open with the recovery key only.
  + Fail safe by construction; the device ends `retired` through its own final report; a device that never reports
    stays visible as *uninstall pending*; a request can be cancelled until it was delivered. − Two more device
    columns, one command type, one new event type, a helper that must survive the removal of its own package (it
    runs from a copy in `/run`). **Chosen.**
- **Escrow after uninstall.** The escrowed recovery key, headers and the last administrator password stay with the
  retired device (ADR 0032 matrix: "until a Destroy or until the device row is deleted"). `reset` does not delete
  them: after a reset the disk is still encrypted and the kept administrator's password is still the escrowed one;
  an organization that wants the data unrecoverable uses Destroy (two-person rule), not uninstall.

### E. Device owners

- **E1 — Reuse the login assignment as "owner".** − A shared device is assigned to a group; ownership is an asset
  relation (who is responsible), not a login right.
- **E2 — A separate relation `device_owner` (one or more users per device), informational: shown on the device,
  searchable, a filter of the device list, listed on the user; no effect on logins, sudo or revocation.** + Matches
  Entra ID's owner concept the maintainer asked for; a deleted user leaves the relation by cascade. **Chosen.**

### F. Login history

- **F1 — Derive it from the audit log.** − `session.login` is deliberately not audited (volume, privacy).
- **F2 — Extend `device_user_seen` with a history.** − Its retention is fixed by code because locks depend on it;
  mixing a configurable history into it would weaken that guarantee.
- **F3 — A separate, optional store `device_login_event` (device, username, time), off by default, enabled per
  organization with a privacy notice, with its own retention (7–365 days, default 90), purged by the worker and
  audited as a deletion; disabling deletes every row at once. With the history on, the bundle asks the agent to
  report every session, not once per user and day; the event stays `session.login` with the same data.** + The lock
  guarantee is untouched; the organization decides; the retention is documented in ADR 0032's matrix. − One more
  worker round until M10's retention round exists (it folds in then). **Chosen.**

### G. Hardware facts

- **G1 — Keep them in Fleet.** − The administrator cannot answer "which laptop is this" without a port forward to
  Fleet's UI.
- **G2 — Copy vendor, model, serial number, CPU model and core count, memory size and total disk size into
  `device_inventory_ref`; not free disk space, not uptime, not network addresses.** + Asset data an organization
  needs for inventory and theft reports (Art. 6(1)(f) GDPR); purged with the inventory of retired devices (ADR 0032,
  M10). − `privacy.md` changes; the serial number identifies a person's laptop indirectly. **Chosen.**

### H. Staleness per device group

- **H1 — Per-device thresholds.** − Unmanageable for a fleet.
- **H2 — Optional thresholds per device group; a device in several groups takes the most lenient value per level;
  the organization's value is the fallback.** + A laptop group with 120 h / 840 h and a workstation group with the
  organization's 24 h / 168 h; lenient wins because a false "presumed lost" leads to drastic actions (Lock). − A device
  in a laptop group and a server group is alerted late (documented residual risk). **Chosen.** The organization's
  defaults stay 24 / 168; the group form offers the laptop preset (5 days / 35 days).

## Decision

1. **Agent update policy** (option A3): `organization_update_settings.agent_update_policy` (`automatic` default,
   `manual`) and `device_group.agent_update_policy` (nullable override; a device in several groups with different
   overrides takes `manual`). The compiler renders `agent.update_policy` into every v2 bundle. The agent stages an
   offered release only when the policy is `automatic` or the offer is `requested`; it installs the supervisor and
   fleetd packages under the same rule. Rollouts stay platform-wide and wave-based.
2. **Update now** (option B2): `POST /api/v1/devices/{id}/update-agent` (roles `org_admin`, `org_operator`, no
   step-up, audited `device.agent_update_requested`), recorded in `device.agent_update_requested_version/at`,
   mirrored by the worker's cache sync to Valkey `au:<device_id>` (TTL 24 h), honoured by the gateway's offer
   (`protocol.AgentUpdate.Requested`, wave skipped, halted rollouts never offered) and by the agent (policy and an
   earlier failure of the same version ignored once). Cleared by the device's report for that version or after 24 h.
3. **Supervisor updates** (option C3): the bundle's `agent.supervisor_packages` (per architecture) carries the
   `paddock-supervisor` package of the current release; the agent installs it through `paddockd supervisor-upgrade`
   in a transient unit with a 10-minute check-in guard and a binary rollback; reported as the event
   `agent.supervisor_updated` with the outcomes `updated`, `install_failed`, `rolled_back` (audit codes
   `device.supervisor_updated`, `device.supervisor_update_failed`). The supervisor never updates itself; the agent
   never updates `paddock-revoke`.
4. **Uninstall** (option D3): `POST /api/v1/devices/{id}/uninstall` (`org_admin`, step-up, typed hostname, reason,
   `mode: leave|reset`, `clear_tpm`, `keep_local_admin`), command type `uninstall` (lifetime 7 days), cancel until
   delivered, final event `agent.uninstalled`, automatic retirement with `device.retired` param `reason: uninstalled`,
   attention kind `uninstall_pending`. Preconditions: device `active`, no open revocation request, no open uninstall;
   `clear_tpm` refused while the last report shows a TPM2 keyslot on any volume (409 `tpm_in_use_by_disk`) and again
   on the device at execution time. The managed local administrator is never removed when it is the last local
   administrator. User data is never deleted. The revocation path (`agent/internal/revoke/`, `agent/cmd/paddock-revoke/`,
   `pkg/revocation`) is not changed; the helper removes the `paddock-revoke` package through apt like any package.
5. **Owners** (option E2): table `device_owner`, `PUT /api/v1/devices/{id}/owners`, audited `device.owners_changed`;
   `DeviceDetail.owners`; device list filter `owner_id` and search by owner username; `GET /api/v1/users/{id}/devices`.
6. **Login history** (option F3): `organization_login_settings.login_history_enabled` (default false),
   `login_history_days` (7–365, default 90); table `device_login_event`; bundle `login.report_every_session`;
   `GET /api/v1/devices/{id}/logins` (list contract); worker purge audited `retention.purged` (store
   `device_login_event`); disabling deletes all rows in the same audited action. ADR 0032's matrix gains the store
   (amendment of the same date).
7. **Hardware facts** (option G2): `ports.HostInventory.Hardware`, columns on `device_inventory_ref`, shown on the
   device page and searchable; `privacy.md` names them and their retention.
8. **Staleness per device group** (option H2): `device_group.staleness_warning_h`, `staleness_critical_h` (both or
   none, critical > warning); the worker resolves per device (maximum per level over the device's groups, else the
   organization); the audit params name the source.
9. **Protocol** (ADR 0013): every change is additive. The new event types `agent.supervisor_updated` and
   `agent.uninstalled` are only ever emitted in response to a bundle section or a command that only a server of this
   release issues, so an older server never receives them (the ADR 0024 constraint is met without a discriminator).
   The heartbeat gains `arch`; `device_status` gains `arch`.

## Consequences

+ An organization controls when its devices take agent releases, an administrator can move one device at once,
  the supervisor and fleetd follow the agent in the same waves, and a device can leave Paddock cleanly in two
  well-defined ways that never strand the device or its user. Owners, hardware facts, login history and realistic
  staleness thresholds make the device page answer the questions the lab asked.
− The agent gains two detached helpers (supervisor upgrade, uninstall) that run outside the supervisor's control;
  both are bounded, report once and are covered by VM gates. `privacy.md` grows by two data classes (hardware facts,
  login history). The `manual` policy lets devices fall outside the support window until someone requests an
  update (attention `agent_outdated` stays visible). Uninstall never deletes escrow; Destroy remains the only
  way to make data unrecoverable.
Follow-ups: plan `docs/plans/M8d-device-lifecycle.md` (PDK-220 … PDK-234); the setup wizard (M8g, PDK-200) surfaces
the unlock mode default, the staleness presets and the update policy; M10's retention round absorbs the login-history
purge; M9 may notify on `device.uninstalled` and `device.supervisor_update_failed` through the audit index.

## Amendment 2026-10-17 — component versions per device, upstream version watch

Two maintainer requests of the same day extend this decision.

**I. Component versions and targets.** The device page shows no version of Himmelblau, fleetd, `paddock-supervisor`
or `paddock-revoke`, and nothing says which version the organization expects. M8b (PDK-105) removed the architecture
row "Himmelblau version and config hash (`tamper.login_component_changed`)" as unbuilt; nothing exists to reuse beyond
`reconcile.OS.PackageVersion` (dpkg), the health report, `paddock_current_agent_version()` and
`device_inventory_ref.fleetd_version` (Fleet's view, hourly).

- Options: (a) tamper events per component — rejected: a version is a fact, not a tampering, and the login reconciler
  already enforces the Himmelblau pin by installing it. (b) Compare in SQL against a floating target — rejected: Debian
  and SemVer comparisons do not belong in SQL. (c) **Chosen:** the agent reports installed versions in its health
  (`components`: `paddockd`, `paddock_supervisor`, `paddock_revoke`, `himmelblau`, `fleetd`); the server keeps one
  platform table `component_target (component, version, source, updated_at)` written by the compiler at start
  (`himmelblau` ← `PADDOCK_HIMMELBLAU_VERSION`) and by the worker's rollout round (`paddockd`, `paddock_supervisor`,
  `paddock_revoke`, `fleetd` ← the current release's artifacts and packages); the worker's heartbeat materialization
  compares in Go and stores `device_status.components_outdated` (names); the api reads the targets through the
  `SECURITY DEFINER` function `paddock_component_targets()` and answers `Device.components` with installed, expected and
  status; the device list filters on `components_outdated`; the platform page shows the targets. Single source of
  truth for the Himmelblau target stays the compiler's environment variable; the api never reads it.

**II. Upstream version watch.** Dependabot covers Go modules, npm and GitHub Actions, not the images pinned by tag
and digest in `deploy/compose/versions.env`, the Himmelblau apt pin, the fleetd build version (`FLEETCTL_IMAGE`) or
the Fleet NVD release URLs. Himmelblau sat at 4.0.4 while 4.0.6 was out (PDK-207 bumps it).

- **Renovate** (rejected): a hosted or self-hosted bot that reads `versions.env` with a custom regex manager; it is a
  new external dependency with write access to the repository, which `CLAUDE.md` forbids without a decision; its
  digest pinning and grouping would duplicate what a small tool does.
- **A bump PR per outdated pin** (rejected): resolving the new digest is mechanical, but every pin carries a gate a
  person must run before merging (RustFS: WORM gate; Authentik: I2; Fleet: F0–F4; Caddy/Postgres: restore drill), so
  a weekly bot PR would either sit open or be merged untested; it also needs a token with write access.
- **One issue per outdated tool, updated in place** (chosen): a weekly GitHub Actions job runs a Go tool under
  `tools/upstreamwatch/` (standard library only; `gh api` for GitHub releases and issues; plain HTTPS for registry tag
  lists and the Himmelblau index). It compares every pin with upstream, classifies patch/minor/major, and opens one
  issue per tool (label `upstream`, stable title `upstream: <tool> <pinned> → <latest>`), edits the existing issue
  when the latest moves on, and closes it when the pin catches up. A patch release is visible as an issue within
  seven days of its publication; `workflow_dispatch` runs it at once. The tool is also `make upstream-check` for a
  local run. No repository write token: `issues: write` only.

Consequences: + Administrators see per device which component is behind and what the platform expects; the
maintainer learns of every upstream patch within a week without a new dependency. − One more platform table and
health field; the watch depends on anonymous registry tag listings (Docker Hub, ghcr.io, gcr.io, mcr.microsoft.com)
staying available. Tickets PDK-235, PDK-236, PDK-237.

## Amendment 2026-10-18 — supervisor package in waves, retry after an unreachable server

The M8d review (PDK-234, review 1, findings 6 and 11; PDK-326) found two conflicts of decision 3 with the design
contract. The maintainer's architect decision of the same day:

**I. Waves (contract 6).** As written, the supervisor package went to every device of a release in the same compile
once its rollout completed — no waves, no failure stop. Now the package follows the wave plan of its release's agent
rollout: the bundle carries it for a device only once the rollout's current wave reached the device's bucket (the
gate of the agent offer, `agentrelease.Eligible`), only while the rollout is `running` or `completed`, never while it
is `halted`. `paddock_supervisor_packages()` returns the current rollout's status and waves (migration 00062, a new
forward migration rather than a change of 00059). A `device.supervisor_update_failed` for a local-health failure
(`install_failed`, `rolled_back`) counts toward the rollout's failure threshold exactly like a failed agent update
(`agent_update_report` outcome `supervisor_failed`, counted once per device in the rollout, current-release and
evaluation statistics), so enough supervisor failures halt the rollout and stop both the agent and the supervisor
offer. `rolled_back_unreachable` (II) never counts: a server outage is no defect of the release (review 2 finding B).

**II. Fail safe (contract 8).** As written, a server outage longer than the helper's 10-minute check-in wait rolled a
healthy supervisor back and `failed_supervisor_version` blocked that version for good. Now the helper reports the
outcome `rolled_back_unreachable` when the new supervisor kept one process for the hold time and the agent's
check-ins after the installation failed to reach the server (`/run/paddock/last-checkin-failed`: no answer or 502–504).
The agent then retries the version no earlier than 24 hours after the rollback and marks it failed after 3 such
rollbacks (`state.supervisor_retry`). Only local health failures — `dpkg` or the backup failed, the helper died, the
supervisor did not stay up, or the agent did not check in although the server was reachable — mark the version failed
for good. The rollback itself stays: the helper cannot tell whether the new supervisor would have worked.

**III. Update now and the supervisor (decision 2, review finding 5).** Under the manual policy only an open update-now
request lets a device upgrade `paddock-supervisor` and fleetd, but the request ended with the agent's report. Now the
request stays open after `agent.updated` while the device's last health report names another `paddock_supervisor`
than the requested version (the component target follows only completed rollouts, so it is no reference here) or
`components_outdated` names `fleetd`, and ends with `agent.supervisor_updated` (any outcome) or after 24 hours; the
gateway marks the device's own version `requested` for a device on the release while the request is open (the agent
never stages its own version); `RequestNow` accepts a device on the release under the same condition. An open
update-now request for the rollout's release (unexpired) lifts the wave gate of I for that device's supervisor
package, as it does for the agent offer; never while the rollout is halted. The request recompiles the device (review
2 finding C).

**IV. Lock and Destroy before an uninstall (review 2 finding D, replaces PDK-327's refusal).** Lock and Destroy are
never blocked by an uninstall. The revocation request cancels an uninstall without a removal report in its own
transaction — a `pending` or `delivered` command is withdrawn like a cancel (result claimed as `cancelled`, command
cancelled, removed from `cmd:<device_id>` after the commit), a command the device already answered stays — and records
`device.uninstall_cancelled` (reason `revocation`) next to `revocation.requested`, each once (`Recorder.Also`). When
the device had received the command, the response (`uninstall_cancelled: after_delivery`) and the portal warn that
`paddock-revoke` may already be gone. The revocation path itself is unchanged.

Consequences: + No supervisor change reaches every device at once, and a server outage no longer blocks a supervisor
version for good. − A supervisor wave follows the compiler's reconcile interval rather than the gateway's offer; a
device whose server stays unreachable retries for up to three days.
