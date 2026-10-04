# Implementierungsplan: M3b — Identity and privileges, agent side

Status: Ready for implementation · 2026-10-04 · Author: architect
Basis: `docs/architecture.md` v1.6 §9.3–9.5, §10, §11; ADR 0008, 0019; PoC M1 (`docs/poc/M1-report.md`,
`test/poc/m1/checks/*` as reference for how each behaviour was observed); M3a (bundle schema v2, `pkg/sudoers`)

Binding language: **MUST** / **MUST NOT** / **SHOULD** / **MAY**.

## 1. Goal

A device running the M3b agent installs and configures Himmelblau from its signed bundle, admits exactly the users its
allow list names, blocks locked users locally (login, offline login and screen unlock) and locks or terminates their
sessions, terminates directory sessions when logins are suspended, writes sudoers files that grant exactly each
user's effective profile, and keeps the privileged local groups clean — verified on both test VMs with real GNOME/GDM.

## 2. Context

- M3a delivers bundle schema v2 to agents that report `schema_versions` containing 2: resources `login`
  (`provider`, `himmelblau{oidc_issuer_url, app_id, domain, pam_allow_groups[], enable_hello, hello_pin_min_length}`,
  `suspended`, `locked_users[]`, `session_action`, `break_glass_accounts[]`) and `sudo` (`lecture_text`,
  `entries[{username, class, root_equivalent, commands[], require_password, timestamp_timeout_min, lecture,
  profile_digest}]`, `privileged_groups[]`, `sudoers_d_allowlist[]`, `break_glass_accounts[]`). `pkg/sudoers` has
  `Render(entry, uid)` and `FileName(username)`; `pkg/bundle` has `SchemaVersion2` and `VerifyVersions`.
- PoC M1 facts (binding): Himmelblau 4.0.4 from `https://packages.himmelblau-idm.org/stable/<version>/deb/ubuntu$VERSION_ID/`
  signed with key fingerprint `E87F D8D4 63A5 E481 4B9C DBA9 0CC0 D400 2C42 5E03`; install with
  `-o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold`; packages `himmelblau`, `pam-himmelblau`,
  `nss-himmelblau`, `himmelblau-qr-greeter`, `himmelblau-sshd-config` (upstream installer selection); after writing the
  config `systemctl reset-failed` + restart `himmelblaud himmelblaud-tasks`; `pam_allow_groups` read only at daemon
  start, empty value denies all, missing line allows all; the GNOME lock screen ignores account-phase results; a
  `pam_listfile` deny check in the **auth** phase (before `pam_himmelblau`) blocks login, offline login and unlock and is
  fail safe with `onerr=succeed`; `local_groups = users` adds directory users to `users` only.
- Test VMs: start from `base-installed`; the PoC scripts show how to trust the Caddy CA, set `/etc/hosts`, drive GDM
  (keyboard + screenshot), run `pamtester`, approve device codes through the Authentik flow executor, enroll a Hello
  PIN. They may be **read and copied**, not changed.

## 3. Binding decisions

### 3.0 M3a review follow-ups (step 0)
1. **Isolation fix — upstream groups:** `GET /api/v1/upstream-groups` and the import endpoint MUST only list/accept
   Authentik groups (not starting with `paddock.`) that have **at least one member who is a member of
   `paddock.<slug>`**. Any other group → not listed / 404 on import. Extend gate A2 with a globex-only upstream group
   that acme must not see. CHANGELOG `Security`.
2. **Acceptance runtime:** A3 cases run in parallel (`t.Parallel`, bounded by `PADDOCK_ACCEPTANCE_PARALLEL`, default 8);
   the `make acceptance` timeout returns to 30 minutes. No assertion or polling limit changes.
3. **Supervisor test flake:** `agent/internal/supervisor` tests use an injected clock / explicit synchronization instead
   of a 500 ms real-time probation; `go test -count=20 -race ./agent/internal/supervisor/...` green.

### 3.1 Agent: schema and events
4. The agent reports `schema_versions: [1, 2]` and verifies with `bundle.VerifyVersions(…, []int{1,2})`. Unknown
   resource types in a bundle → `bundle.rejected {reason: "unknown_resource_type"}` (no partial apply).
5. New device event types (closed enum, server maps them to audit codes `device.<type>` except `session.login`, which
   only updates `device_user_seen` per M3a decision 10): `session.login {username}`, `login.applied {changed}`,
   `login.apply_failed {stage, message}`, `user.lock_applied {username, sessions_locked, sessions_terminated}`,
   `logins.suspension_applied {sessions_terminated}`, `sudo.apply_failed {username, message}`,
   `sudo.user_unresolved {username}`, `tamper.sudo_group_member {group, username, removed}`,
   `tamper.sudoers_d_file {file, quarantined_as}`, `tamper.sudoers_changed {sha256_before, sha256_after}`.
   Payloads contain usernames and file names only — no process, command or session content.

### 3.2 `login` reconciler (apply order after `time`, `file`, `systemd_unit`: `login` → `sudo` → `privileged_groups`)
6. **Package:** if `himmelblau` is not installed (or a different version than the bundle's
   `himmelblau.package_version`), the agent writes `/etc/apt/keyrings/himmelblau.gpg` from the key embedded in the
   agent binary (fingerprint above, verified at build time by a test) and
   `/etc/apt/sources.list.d/paddock-himmelblau.list`, then `apt-get update` (only that source) and installs the five
   packages with the PoC dpkg options, non-interactive (`DEBIAN_FRONTEND=noninteractive`). M3a's `login` resource gets
   one more field `package_version` (server config `PADDOCK_HIMMELBLAU_VERSION`, default `4.0.4`) — a server-side change
   in this plan, bundle schema stays v2 (additive field, agents ignore unknown fields).
7. **Config:** render `/etc/himmelblau/himmelblau.conf` exactly as the PoC (`oidc_issuer_url`, `app_id`, `domain`,
   `pam_allow_groups = <comma-separated>` — line **always present**, empty when suspended, `allow_console_password_only
   = false`, `enable_hello`, `hello_pin_min_length`, `local_groups = users`); no `debug`. Atomic write; on change:
   `systemctl reset-failed himmelblaud himmelblaud-tasks` + restart both, wait until active (≤ 30 s). The file is a
   protected path for drift detection (drift → restore + `config.drift_corrected`).
8. **Deny list:** `/etc/paddock/login-deny` (0644 root) contains, for every entry of `locked_users` not listed in
   `break_glass_accounts`, the UPN and the short name (part before `@`) — but a short name is omitted if it equals a
   local account in `/etc/passwd` with UID < 60000 (a local account must never be denied by a directory lock).
   Atomic write; file absent when the list is empty.
9. **PAM profile** shipped in the `paddock-agent` package as `/usr/share/pam-configs/paddock-deny`, enabled by
   `pam-auth-update --package --enable paddock-deny` in postinst and removed (`--remove paddock-deny`) in prerm.
   **Required result** (binding; the profile fields that achieve it are a freedom):
   - `/etc/pam.d/common-auth` contains
     `auth requisite pam_listfile.so item=user sense=deny file=/etc/paddock/login-deny onerr=succeed`
     **before** the `pam_himmelblau.so` line, and the jump offsets pam-auth-update writes for the following primary
     modules remain correct (a normal password login of the break-glass account and a Himmelblau login both work);
   - `/etc/pam.d/common-account` contains
     `account required pam_listfile.so item=user sense=deny file=/etc/paddock/login-deny onerr=succeed`.
   Achieve this only through the pam-auth-update profile (typically a higher `Priority` than Himmelblau's profile and
   the appropriate `Auth-Type`/`Auth-Initial`/`Account-Type` fields). If it cannot be achieved that way, **stop (S1)** —
   never edit `common-*` directly. The agent verifies at every apply that both lines exist and the auth line precedes
   `pam_himmelblau.so`; deviation → `login.apply_failed {stage:"pam"}` and `tamper.protected_file_changed`.
10. **Sessions:** after the deny list or allow list changed:
    - for each user newly in `locked_users`: their sessions (logind, D-Bus `org.freedesktop.login1`) are locked
      (`LockSession`) if `session_action = lock_screen`, or terminated (`TerminateUser`) if `terminate`; event
      `user.lock_applied`.
    - when `suspended` becomes true: terminate the sessions of all **directory users** (UID ≥ 60000 or not present in
      `/etc/passwd`, and not in `break_glass_accounts`); event `logins.suspension_applied`.
11. **Session tracking:** the agent subscribes to logind `SessionNew` and emits `session.login {username}` once per
    user per 24 h (state in `state.json`) — no session IDs, TTYs or remote hosts.

### 3.3 `sudo` reconciler
12. For each entry: resolve the UID with `getent passwd <username>` (NSS, so Himmelblau answers online and from cache);
    not resolvable → skip, event `sudo.user_unresolved` (retried every drift pass). Render with
    `pkg/sudoers.Render(entry, uid)`; write per architecture §10.3 apply procedure (rollback copy, dot-temp file,
    `visudo -cf`, rename, `visudo -c`, restore on failure → `sudo.apply_failed`). Write
    `/etc/paddock/sudo_lecture` from `lecture_text`. Files `paddock-u-*` without a current entry are removed.
13. Files in `/etc/sudoers.d/` that are neither `paddock-u-*` nor in `sudoers_d_allowlist` are moved to
    `/var/lib/paddock/quarantine/sudoers.d/<name>.<unix-time>` (mode 0600) and reported (`tamper.sudoers_d_file`).
14. `/etc/sudoers`: the agent records its SHA-256 at the first apply after M3b; on change it reports
    `tamper.sudoers_changed` and checks that `@includedir /etc/sudoers.d` (or `#includedir`) is still present and
    `visudo -c` passes — **it does not rewrite `/etc/sudoers`** (detection over enforcement; distribution updates may
    change it). Missing includedir → `sudo.apply_failed`.

### 3.4 Privileged local groups
15. For each group in `privileged_groups` that exists locally: every member not in `break_glass_accounts` is removed
    (`gpasswd -d`), event `tamper.sudo_group_member {removed:true}`. Directory users added through Himmelblau's
    `local_groups` are covered the same way. Groups that do not exist are ignored.

### 3.5 Packaging and server
16. `paddock-agent` package: adds the PAM profile (decision 9) and depends on `libpam-modules` (for `pam_listfile`),
    `sudo`; postinst/prerm call `pam-auth-update` non-interactively.
17. Server: `login.package_version` (decision 6); audit code mapping for decision 5 events; device detail shows the
    last `login.*`/`sudo.*` status per device (from the latest events, no new tables beyond what is needed — MAY add
    `device_status.login_state jsonb`).

## 4. Non-goals
Managed local admin account (M4), step-up, LUKS/TPM, offline emergency access, SSSD, Arch, changing Himmelblau
upstream, Hello PIN policy beyond min length.

## 5. Affected files
`agent/internal/reconcile/{login,sudo,groups}.go` (+ tests on the fake system), `agent/internal/sessions/` (logind),
`agent/internal/agent` (schema versions, apply order, events), `agent/internal/reconcile/system.go` (new port methods:
`AptInstall`, `Getent`, `Gpasswd`, `Logind…`, `Visudo` — fakeable), `packaging/nfpm/paddock-agent.yaml`,
`packaging/pam-configs/paddock-deny`, `packaging/scripts/*`, embedded Himmelblau key `agent/internal/reconcile/himmelblau.gpg`,
server: compiler `login.package_version`, worker event mapping, portal device detail; `test/system/identity_test.go`;
`test/acceptance` (A2 extension); `CHANGELOG.md`; `docs/operations/device-login.md` (operator view: first login via
code/QR on a second device, Hello PIN, lock behaviour, suspension, break-glass accounts).

## 6. System gates (both VMs, real GDM; start from `base-installed`, restore at the end)

| ID | Gate | Content |
| --- | --- | --- |
| L1 | Login | agent installs Himmelblau from the bundle; allowed user logs in at GDM via device code (approved through the Authentik flow executor with TOTP) and enrolls a Hello PIN; a globex user and a user outside the login assignment are refused; `session.login` reaches `device_user_seen` |
| L2 | **Identity gate (concept)** | lock in Paddock → the next online login fails; with the device online, within one check-in (triggered by a link toggle) the user's GNOME session is on the lock screen and the **real** unlock with the PIN is refused (screenshot + `LockedHint`); offline login with the cached PIN is refused; unlock in Paddock restores login (device code + new PIN); `user.lock_applied` audit event |
| L3 | **Login suspension gate (concept)** | suspend → within one check-in directory sessions are terminated and directory logins refused; break-glass account `paddock` logs in at the console and via SSH; resume restores logins |
| L4 | Fail safe | deny file deleted locally → logins work (until the agent restores it at the next drift pass, which it MUST); Himmelblau daemon stopped → local accounts still log in |
| L5 | PAM order | `common-auth` has the deny line before `pam_himmelblau`; manual removal of the profile → agent reports and the next package reconfigure restores it (`dpkg-reconfigure paddock-agent` documented; the agent does not edit PAM files) |
| P3 | **Effective profile on the device** | user with restricted profile: `sudo -l` lists exactly the effective commands and nothing else; full profile: `sudo -l` shows `(ALL) ALL`-equivalent root access; none: "not allowed"; a local account with the same short name gets nothing; profile change reaches the device in one check-in |
| P4 | Sudoers hygiene | a manually created `/etc/sudoers.d/evil` is quarantined with a tamper event; a directory user manually added to `sudo` is removed with a tamper event; break-glass `paddock` stays in `sudo` with its `90-paddock` file untouched; a broken entry (forced through a test-only bundle) never breaks `sudo` (`visudo -c` stays green, `sudo.apply_failed` reported) |
| S1–S2 | regression | M2b gates S1 and S2 still pass with the v2 agent |

## 7. Steps
0. §3.0 follow-ups (three commits).
1. Schema v2 support, event types, server mapping, `package_version`. Commit `feat(agent): bundle schema v2 and identity events`.
2. `login` reconciler + sessions + session tracking (unit tests on the fake system incl. allow-list line always
   present, restart on change only, deny-list name rules). Commit `feat(agent): login reconciler`.
3. PAM profile + packaging; verify on a VM manually that `pam-auth-update` places the line correctly (record the
   resulting `common-auth` in the commit message body). Commit `build(agent): deny-list PAM profile`.
4. `sudo` + privileged-group reconcilers (unit tests incl. visudo failure path with a fake visudo). Commit
   `feat(agent): sudo and privileged group reconcilers`.
5. System gates L1–L5, P3, P4 (reuse PoC techniques by copying helpers into `test/system`). Commit
   `test(system): identity and privilege gates`.
6. Regression from reset: `make dev-secrets up dev-seed acceptance e2e deb system-test VM=all`; VMs off at `base-installed`.

## 8. Acceptance criteria
| # | Given / When / Then | Req. | Observed by |
| --- | --- | --- | --- |
| AC1 | Given a locked user with an open GNOME session, when the device next checks in, then the session is locked and cannot be unlocked, and offline login is refused | F2 | User at device; org admin (audit) |
| AC2 | Given a suspended device, then directory sessions end and only break-glass accounts can log in | F15 | User / operator at device |
| AC3 | Given a user's effective profile, then `sudo -l` on the device shows exactly those rights | F11, A13 | User at device |
| AC4 | Given someone adds a sudoers file or a sudo-group member manually, then it is undone and reported | §10.1, F9 | Org admin (audit) |
| AC5 | Given the deny file or the Himmelblau daemon is missing, then local break-glass logins still work | Fail safe | Operator at device |

## 9. Freedoms
Internal agent structure, how logind is accessed (D-Bus preferred, `loginctl` acceptable), test helper design,
portal presentation of login/sudo status.

## 10. Stop conditions
S1: `pam-auth-update` cannot place the deny line before `pam_himmelblau` (decision 9); S2: a gate needs custom PAM code
or a Himmelblau patch; S3: Himmelblau 4.0.4 is not installable on one of the VMs from the official repository;
S4: GDM unlock behaves differently from PoC C5c with the auth-phase deny line; plus M0 §11 S2/S6/S7/S8.

## 11. Risks
| # | Item | Default |
| --- | --- | --- |
| R1 | apt operations from the agent can collide with unattended-upgrades (dpkg lock) | Retry with back-off up to 10 min; report `login.apply_failed {stage:"apt"}` |
| R2 | UID-based sudoers needs the user resolvable | Unresolvable users get no sudo until they logged in once; documented |
| R3 | System gates with GDM automation are slow and brittle | Reuse PoC helpers; screenshots stored as evidence on failure |
