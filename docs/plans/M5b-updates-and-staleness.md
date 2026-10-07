# Implementierungsplan: M5b — Update management and staleness alerts

Status: Ready for implementation (after M5a) · 2026-10-07 · Author: architect
Basis: architecture v1.7 §12.1 (last contact, staleness), §12.5 (patch management), §11.4 (commands); concept F6,
F12, "Patch management", "Silent disappearance"; M4a (commands), M4b.1 (bounded apt/dpkg path), ADR 0018

Binding language: **MUST** / **MUST NOT** / **SHOULD** / **MAY**.

## 1. Goal
Organizations enforce daily security updates and scheduled regular updates on all devices, hold packages globally or
per device group, and install named packages immediately. Devices that go silent are flagged at a warning and a
critical level, audited, and listed on an "attention" page together with other conditions that need an admin.

## 2. Context
- Architecture §12.5 (binding, quoted): daily security updates via `unattended-upgrades` restricted to the security
  pocket, blacklist from holds, run at `security_daily_at` with up to 60 min random delay; regular updates via
  `paddock-updates.timer` → `paddockd updates run` (`apt-get update && apt-get -y -o Dpkg::Options::=--force-confold
  dist-upgrade`, honouring holds), reported as `updates.run`; holds via `apt-mark hold` (no version) or an
  apt-preferences pin (version); `install_now` command; holds win over immediate install (409 `package_on_hold`);
  reboot required is reported, Paddock never reboots for updates.
- Architecture §12.1: last-contact materialization exists (`device_status.last_contact_at`); thresholds
  `staleness_warning_h` (default 24) and `staleness_critical_h` (default 168); crossing a level → alert + audit;
  returning resets with an event; critical → `presumed_lost` on the attention list (admin chooses Retire, Lock, Keep).
- M4b.1: every apt/dpkg run of the agent goes through a bounded path (15 min, process-group kill, back-off).

## 3. Binding decisions

### 3.1 Policy and holds (server)
1. **Organization update settings** (`organization_update_settings`, defaults): `security_daily_at` (`03:00`, local
   device time), `regular_schedule` (systemd `OnCalendar` expression, default `Sat 04:00`; validated server-side with a
   small parser for the subset `[Mon..Sun[,…]] HH:MM`; anything else → 422 `invalid_schedule`),
   `regular_updates_enabled` (true), `max_random_delay_min` (60). API `GET/PUT /api/v1/settings/updates` (org_admin;
   audit `settings.updates_changed`).
2. **Holds** `package_hold(id, organization_id, device_group_id nullable, package, version nullable, reason ≤ 500,
   created_by, created_at)`, unique `(organization_id, device_group_id, package)`. Package names validated
   (`^[a-z0-9][a-z0-9+.-]+$`), versions (`^[A-Za-z0-9.+:~-]+$`). API list contract `GET /api/v1/package-holds`
   (search package; filter device_group_id), `POST`, `PATCH`, `DELETE` (org_admin, operator; audit
   `package_hold.created|updated|deleted`); state change → recompile affected devices.
3. **Immediate install** `POST /api/v1/devices/{id}/install-now {packages: [..≤ 20]}` and
   `POST /api/v1/device-groups/{id}/install-now` (fan-out, one command per device; max 500 devices per call →
   422 `too_many_devices`) (admin, operator; audit `device.install_now_requested`): command type `install_now` (TTL
   24 h). A package held for the device → 409 `package_on_hold` naming the package; no command is created.

### 3.2 Bundle and agent
4. Bundle schema v2, additive resource `updates` (id `updates`):
   `{security_daily_at, regular_schedule, regular_updates_enabled, max_random_delay_min, holds: [{package, version|null}]}`
   (holds merged per device: organization-wide plus the device's groups; same package with different versions in two
   groups → the lexicographically smallest version wins and the device detail shows the conflict).
5. **Agent `updates` reconciler** (apply order: after `file`/`systemd_unit`, before `login`):
   - writes `/etc/apt/apt.conf.d/52paddock-unattended` (`Unattended-Upgrade::Allowed-Origins` = `${distro_id}:${distro_codename}-security`,
     `Unattended-Upgrade::Package-Blacklist` = held packages, `Unattended-Upgrade::Automatic-Reboot "false"`) and a
     drop-in `/etc/systemd/system/apt-daily-upgrade.timer.d/50-paddock.conf` (`OnCalendar=` reset + `security_daily_at`,
     `RandomizedDelaySec=max_random_delay_min`), `apt-daily.timer` enabled; protected paths (drift restored);
   - holds: `apt-mark hold/unhold` for versionless holds, `/etc/apt/preferences.d/50paddock` with
     `Pin: version <v>` + `Pin-Priority: 1001` for versioned holds; holds it did not set are left alone;
   - `paddock-updates.timer` + `paddock-updates.service` (`ExecStart=/opt/paddock/agent/current/paddockd updates run`)
     with `OnCalendar=regular_schedule`, `RandomizedDelaySec`, `Persistent=true`; disabled when
     `regular_updates_enabled=false`.
6. `paddockd updates run`: `apt-get update`, then `dist-upgrade` with `--force-confold`, `DEBIAN_FRONTEND=noninteractive`,
   through the bounded path with a **60 min** limit for this operation (the 15 min default stays for everything else);
   result event `updates.run {kind: regular|security, started_at, finished_at, upgraded: n, held_back: [..≤50],
   reboot_required: bool, result: ok|failed|timeout, error?}`. For security runs the agent reads the
   unattended-upgrades log after `apt-daily-upgrade.service` finished (`systemd` `OnSuccess=`-less approach: the agent
   checks the unit's `ActiveExitTimestamp` each drift pass) and emits `updates.run {kind: security}` once per run.
7. `install_now` command handler: install the named packages (`apt-get install --only-upgrade` for installed ones,
   plain install otherwise) via the bounded path; result `{installed: [...], failed: [...], reboot_required}`.
8. `reboot_required` (presence of `/var/run/reboot-required`) is part of every check-in health; never acted on.

### 3.3 Staleness and attention
9. **Settings** `staleness_warning_h` (1–720, default 24), `staleness_critical_h` (> warning, ≤ 2160, default 168) in
   the update settings resource. Dev-only override of the unit (minutes) via `PADDOCK_STALENESS_UNIT=minute`, honoured
   only with `PADDOCK_ENV=development` (production start fails otherwise) — for gate U4.
10. **Worker job** every 5 minutes per organization: for active devices compute level from `last_contact_at`;
    transitions write `device_alert(id, organization_id, device_id, kind stale_warning|stale_critical, raised_at,
    cleared_at)` and audit `device.stale_warning|device.stale_critical|device.stale_cleared` (system actor), exactly once
    per transition. Critical sets `device.presumed_lost=true`; a contact clears it.
11. **Attention list** `GET /api/v1/attention` (list contract; filters kind): one row per open condition — stale
    warning/critical, presumed lost, quarantined (clone suspected), disk not compliant, agent outdated
    (`agent_outdated`), login/sudo apply failed (latest event), revocation pending/expired. Read-only aggregation over
    existing state. Portal page *Attention* (default landing page for org admins when it has entries) and a count badge
    in the navigation. Actions link to the existing device actions (retire, lock, release quarantine).

### 3.4 Portal
12. Settings → Updates (schedule fields with validation messages, staleness thresholds); *Package holds* page
    (DataList, create/edit dialogs, delete via ConfirmDialog); device detail: *Updates* card (last security run, last
    regular run, reboot required, held packages incl. conflicts, *Install now* dialog); device-group detail: *Install
    now* for the group.

## 4. Non-goals
Repository mirrors/snapshots (aptly, Pulp), wave-based package rollouts, automatic reboots, maintenance windows per
device, Arch/pacman, notifications by e-mail or chat (alerts are in the portal and the audit log; a webhook is a later
milestone), Ubuntu Pro/ESM origins.

## 5. Steps
1. Server: settings, holds, install-now, bundle `updates`, audit codes, isolation/list/A3 coverage. Commit.
2. Agent: `updates` reconciler, `updates run`, `install_now`, health `reboot_required`; unit tests on the fake system.
   Commit.
3. Staleness job, alerts, attention list. Commit.
4. Portal. Commit.
5. Gates (both VMs in parallel where VM-based):
   - **U1 holds:** a versionless and a versioned hold appear as `apt-mark showhold` / pin; unattended-upgrades blacklist
     contains them; removing the hold reverts both;
   - **U2 install now:** a package not installed gets installed within one check-in; held package → 409 and no command;
   - **U3 scheduled runs:** dev schedule a few minutes ahead → `paddock-updates.service` runs, `updates.run` arrives with
     counts; an older package version installed by the test is upgraded unless held; `reboot_required` reported when
     the test creates `/var/run/reboot-required`;
   - **U4 staleness (acceptance, devicesim, minute unit):** silent device → warning then critical alert and audit events
     once each, appears on the attention list as presumed lost; one check-in clears it with `device.stale_cleared`;
   - existing gates via the regression.
6. Regression from reset. Commit fixes if needed.

## 6. Acceptance criteria
| # | Given / When / Then | Req. | Observed by |
| --- | --- | --- | --- |
| AC1 | Given the organization's update settings, then every device installs security updates daily and regular updates on schedule, and the portal shows the last runs | F6 | Org admin |
| AC2 | Given a hold, then no device upgrades that package, and an immediate install of it is refused | F6 | Org admin |
| AC3 | Given an immediate install, then the package is installed within one check-in interval | F6 | Org admin |
| AC4 | Given a device that stops contacting Paddock, then a warning and later a critical alert appear with audit events, and the device is listed on the attention page | F12 | Org admin, auditor |

## 7. Stop conditions
`unattended-upgrades` cannot be restricted to the security pocket with a blacklist on one of the releases; the timer
drop-in cannot override `apt-daily-upgrade.timer`; M0 §11 S2/S6/S7/S8.
