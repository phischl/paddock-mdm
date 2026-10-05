# Implementierungsplan: M4a — Commands, step-up authentication, managed local administrator, login notice

Status: Ready for implementation · 2026-10-05 · Author: architect
Basis: `docs/architecture.md` v1.6 §6.8, §9.6, §11.4, §12.2, §13; concept F16, "Local admin model / Three layers"
(layer 2 notice); ADR 0006, 0014 (step-up), 0018; M3b (break-glass list, sudo-rs residual risk)

Binding language: **MUST** / **MUST NOT** / **SHOULD** / **MAY**. M4 is split into **M4a** (this plan),
**M4b** (LUKS: TPM2+PIN, recovery key, header escrow, keyslot inventory) and **M4c** (revocation: revocation issuer,
`paddock-revoke`, Lock/Destroy, mass-revocation limits, dead man's switch).

## 1. Goal

Paddock can send signed, expiring, idempotent commands to devices; security-relevant portal actions require a fresh
MFA step-up; every device has a managed local administrator account whose password Paddock rotates without ever
leaving an unknown password and which an org admin can reveal (step-up, audited); and every device shows the
organization's legal notice at the login screen, on TTYs and for SSH — closing the notice gap on `sudo-rs` devices.

## 2. Context

- Built: device check-in (`/v1/checkin`) with Valkey caches, ingest via RabbitMQ, compiler with bundle schema v1/v2
  (`login`, `sudo` resources; `sudo.break_glass_accounts` from the organization setting), agent reconcilers incl.
  privileged-group policy, ActionRunner, OpenBao Transit (`audit-chain`, `bundle-signing`), BFF session (cookie with
  `sub, pid, kind, role, org, …`), `ConfirmDialog` with typed confirmation.
- Not built yet: commands (architecture §11.4 describes them), escrow endpoints (`/v1/escrow`, `/v1/escrow/{id}` in
  §6.8), step-up (§9.6), managed local admin (§12.2), `command-signing` and `escrow-wrap` keys (§13.1).
- Architecture §12.2 rotation sequence (quoted essentials, binding): agent generates the password (24 chars, ≥ 144 bit),
  encrypts it to `escrow_wrap_public` (RSA-OAEP-256), uploads to `/v1/escrow`, polls `/v1/escrow/{id}` every 30 s up to
  15 min, applies it with `chpasswd` **only after `stored`**, then reports `local_admin.rotated`; the server keeps
  generations n and n+1 until the device confirms; on timeout the old password stays valid
  (`local_admin.rotation_failed`).

## 3. Binding decisions

### 3.1 Commands
1. **Entity** `device_command(id uuid, organization_id, device_id, type, params jsonb, status
   pending|delivered|succeeded|failed|expired|cancelled, issued_by uuid null, issued_at, expires_at, delivered_at,
   finished_at, result jsonb)`; RLS like all device tables. Types in M4a: `rotate_admin_password` (TTL 7 d). The type
   registry is a closed enum in `pkg/command`.
2. **Envelope:** DSSE, payload type `application/vnd.paddock.command.v1+json`, payload
   `{command_id, device_id, organization_id, type, params, issued_at, expires_at}` canonical JSON (RFC 8785), signed by
   OpenBao Transit key `command-signing` (Ed25519, non-exportable) — signing happens in the **worker** (AppRole
   `paddock-worker` gets `update` on `transit/sign/command-signing`), triggered by an outbox `command.issued` message.
   The signed envelope is stored in Valkey `cmd:<device_id>` (hash field = command_id), removed on result or expiry.
3. **Delivery:** the check-in response gains `commands: [<envelope>…]` (device API additive change). The agent verifies
   signature against the command keys from its bundle (decision 5), device/org match, `expires_at` > now (device clock,
   ±5 min tolerance), and that `command_id` was not executed before (`state.json`, kept 60 days). Then it executes and
   posts `POST /v1/commands/{id}/result {status: succeeded|failed, result}` (202, idempotent; second post with the same
   status → 202, different status → 409). Worker updates the row and removes the Valkey field. Expiry: worker marks
   `expired` every minute and removes the field; the portal shows the state.
4. **Device API contract** (`api/openapi/device.yaml`, additive): check-in response `commands`, new
   `POST /v1/commands/{command_id}/result`, `POST /v1/escrow`, `GET /v1/escrow/{escrow_id}` (§3.3).
5. **Trust for commands and escrow:** bundle schema v2 gets a top-level object
   `keys: {command_signing: [{key_id, public_key}], escrow_wrap: {key_id, public_key_pem}}` (additive; M3b agents
   ignore it — verify with a test that an M3b-built agent still accepts such a bundle). Key rotation: all active
   versions of `command-signing` are listed; `escrow_wrap` carries the latest version.

### 3.2 Step-up authentication
6. **Flow** `paddock-stepup` (blueprint `paddock-stepup.yaml`): identification (pre-filled from the session's login
   hint), password, authenticator validation (WebAuthn or TOTP) with `not_configured_action: deny`. Portal OIDC client
   `paddock-portal` gets a second authorization path: `GET /api/auth/stepup?return_to=` → authorize with
   `prompt=login`, `max_age=0`, the flow via Authentik's per-request flow override if available, otherwise a second
   OAuth provider/application `paddock-portal-stepup` bound to `paddock-stepup` (same client policy). Callback
   `/api/auth/stepup/callback` validates: same `sub` as the session, `auth_time` ≤ 60 s old, nonce/state. On success the
   session cookie gets `stepup_at` (unix) and `stepup_jti`; step-up is valid for **300 s**.
7. **Enforcement:** use cases declare `RequiresStepUp: true` in their `ActionSpec`; the runner records outcome `denied`
   with `error_code = step_up_required` (HTTP 403 problem `step_up_required`) when `now - stepup_at > 300 s`. Audit
   actor `step_up: true` when satisfied. M4a uses it for: local-admin reveal; changing a permission profile to class
   `full`; assigning a `full` profile (replacing M3a's typed-confirmation-only rule — typed confirmation stays too).
   The portal handles `step_up_required` by redirecting through the step-up flow and retrying the action once.
8. Dev users get TOTP devices with known secrets from the dev blueprint so acceptance tests can complete step-up via
   the flow executor (`authflow` helper).

### 3.3 Escrow (shared with M4b)
9. **Key** `escrow-wrap` (Transit `rsa-4096`, non-exportable). Compiler AppRole: `read` on `transit/keys/escrow-wrap`
   (public key for bundles). New AppRole `paddock-escrow-reader` used **only** by the `api` role's reveal use case:
   `update` on `transit/decrypt/escrow-wrap`. The api uses this AppRole only inside the reveal use case after step-up;
   all other api code uses its normal AppRole (two OpenBao clients in the api process, separated by package).
10. **Device-side encryption:** `RSA-OAEP` with SHA-256 (Go stdlib) to the PEM public key from the bundle;
    ciphertext base64. Verify in an integration test that OpenBao Transit decrypts it (`padding_scheme=oaep`,
    hash SHA-256 — if Transit's OAEP hash differs, stop: S1).
11. **Entity** `escrow_secret(id uuid = escrow_id from device, organization_id, device_id, kind admin_password,
    generation int, status stored|active|superseded|failed, ciphertext bytea, key_version int, created_at,
    activated_at)`; unique `(device_id, kind, generation)`.
12. **Endpoints:** `POST /v1/escrow {escrow_id, kind, generation, key_version, ciphertext}` → gateway publishes
    `ingest.escrow.<org>` → 202. Worker: insert (idempotent on `escrow_id`), set Valkey `esc:<escrow_id>` = `stored`
    (TTL 1 d); invalid generation (≤ active) → `failed`. `GET /v1/escrow/{id}` → `{status: pending|stored|failed}`
    from Valkey (`pending` when absent). Max ciphertext 4 KiB in M4a.

### 3.4 Managed local administrator
13. **Settings** (organization login settings, extended): `local_admin_username` (default `paddock-admin`, regex
    `^[a-z_][a-z0-9_-]{0,31}$`, **immutable once any device has an `active` generation** → 409 `setting_locked`),
    `local_admin_rotation_days` (1–365, default 30), `rotate_after_reveal_hours` (null or 1–168, default null).
14. **Bundle:** the `login` resource gains `local_admin: {username, rotation_days}`; the compiler adds the username to
    `login.break_glass_accounts` and `sudo.break_glass_accounts` automatically (it is never in a deny list, never
    removed from `sudo`).
15. **Agent reconciler `local_admin`** (order: after `sudo`, before `privileged_groups`): ensure the account exists
    (`useradd -m -s /bin/bash -G sudo <name>` — on systems without `sudo` group use `wheel`), home 0700; if it has no
    active generation yet, its password is locked (`passwd -l`) and a rotation starts immediately. Rotation triggers:
    no generation; `now - last_rotation ≥ rotation_days`; command `rotate_admin_password`. Rotation protocol exactly as
    architecture §12.2; the generation number is `last + 1`; the plaintext lives only in memory and is zeroed after
    `chpasswd`. After `chpasswd` the agent records the SHA-256 of the `/etc/shadow` hash field; any other change of that
    field, the shell, the group membership or a disabled/locked state → `tamper.local_admin_changed {field}` and the
    next rotation restores it (detection + repair, no other enforcement).
16. **Login audit:** the agent follows the journal for `pam_unix(*:session): session opened for user <name>` and emits
    `local_admin.login {service, at}` (service = PAM service name only; no TTY, no remote host).
17. **Admin API** (all audited):
    - `GET /api/v1/devices/{id}/local-admin` → `{username, active_generation, pending_generation, last_rotated_at,
      last_rotation_error}` (admin, operator, auditor).
    - `POST /api/v1/devices/{id}/local-admin/reveal` (org_admin, **step-up**, body `{confirm_hostname}` must equal the
      hostname) → `200 {passwords: [{generation, state: active|pending, password}]}` with `Cache-Control: no-store`;
      audit `local_admin.revealed {generations}`; if `rotate_after_reveal_hours` is set, a `rotate_admin_password`
      command is scheduled with `not_before = now + hours` (add `not_before` to `device_command`; the worker publishes
      it to Valkey only when due).
    - `POST /api/v1/devices/{id}/local-admin/rotate` (admin, operator) → command; audit `local_admin.rotation_requested`.
18. **Events → audit:** `local_admin.rotated {generation}` → server sets generation active, previous superseded;
    `local_admin.rotation_failed {generation, reason}`; `local_admin.login`; `tamper.local_admin_changed`. Ciphertexts
    and passwords never appear in events, logs or audit params.

### 3.5 Login notice (concept layer 2)
19. Organization setting `notice_text` (≤ 2000 characters, plain text, default English text referencing the
    acceptable-use policy and logging). Bundle `login.notice`. Agent writes: GDM banner via
    `/etc/dconf/db/gdm.d/90-paddock-notice` (`banner-message-enable=true`, `banner-message-text`) + `dconf update`;
    `/etc/issue.d/90-paddock.issue` (TTY); `/etc/paddock/notice` + `/etc/ssh/sshd_config.d/90-paddock-banner.conf`
    (`Banner /etc/paddock/notice`) + `systemctl reload ssh` (only if sshd is installed). All four files are
    protected paths (drift → restore). Empty `notice_text` removes them. The sudo lecture remains as in M3
    (Classic only); the architecture's residual risk for `sudo-rs` is closed by this notice — the architect updates the
    architecture after acceptance.

### 3.6 Portal
20. Device detail: *Local administrator* card (state, generations, last rotation/error, actions *Reveal* — step-up,
    then `ConfirmDialog` with typed hostname, the password shown in a dialog with copy button and auto-hide after 60 s,
    nothing stored in Pinia or the URL — and *Rotate now*), *Commands* list (`DataList`: type, status, issued, expires).
    Settings: local admin and notice fields. Step-up redirect handling for `step_up_required`.

## 4. Non-goals
LUKS (M4b); revocation, approvals by a second admin, revocation key (M4c); `install_now`, `collect_status` (M5);
WebAuthn enrollment UX in Authentik beyond what the flow provides; password policy for the local admin beyond
decision 15.

## 5. Affected files
`pkg/command/`, `pkg/bundle` (keys), migrations `00010_commands_escrow_local_admin.sql`, server domain/app/worker/gateway
for commands and escrow, BFF step-up, blueprints `paddock-stepup.yaml` (+ dev TOTP seeds), OpenBao bootstrap (keys,
AppRoles), compiler (keys, local admin, notice, break-glass injection), agent (`commands`, `escrow`, reconcilers
`local_admin`, `notice`, journal follower), portal, OpenAPI (admin, device), `test/acceptance`, `test/system`,
`docs/operations/local-admin.md`, CHANGELOG. Off-limits: as before.

## 6. Gates

| ID | Gate | Content |
| --- | --- | --- |
| C1 | Commands (acceptance, devicesim) | issued command appears in the next check-in, signature verifies with bundle keys; result → `succeeded`; duplicate result idempotent; expired command never delivered and marked `expired`; forged/other-device envelope rejected by `pkg/command.Verify`; isolation: org A cannot issue to org B device (404) |
| U1 | Step-up | reveal without step-up → 403 `step_up_required` + one `denied` audit event; with step-up older than 300 s → 403; with fresh step-up → 200; step-up for a different `sub` rejected; `full` profile assignment requires step-up |
| LA1 | **Local administrator gate (concept)** on both VMs | account exists after enrollment with a rotated, escrowed password; reveal returns it and SSH/console login with it works (`local_admin.login` audit event); *Rotate now* → new generation, old password stops working; **confirmation failure**: worker stopped during rotation → after 15 min the old password still works and reveal still returns it (generation n active, n+1 never applied), `local_admin.rotation_failed`; after the worker is back the next rotation succeeds; every reveal produces exactly one audit event |
| LA2 | Tamper | `passwd paddock-admin` locally → `tamper.local_admin_changed` and the next rotation restores a known password; `gpasswd -d paddock-admin sudo` → reported and restored |
| N1 | Notice on both VMs | GDM shows the banner (screenshot), `/etc/issue.d` content on TTY, SSH banner on connect; text change propagates within one check-in; removal cleans up |
| A2/A3/list/E | existing | new endpoints covered; e2e: reveal flow with step-up (TOTP via helper) and auto-hide |

## 7. Steps
0. **M3.1 review follow-ups** (one commit each, `make lint test` green):
   a) Usernames anywhere (API validation, `pkg/sudoers`, agent) MUST NOT start with `-`; every external command that
      takes a user-supplied name gets `--` before it (`getent passwd -- <name>`, `gpasswd -d -- …` where supported,
      otherwise reject). Test with `-x@acme.test`. CHANGELOG `Security`.
   b) The portal's audit code list is generated from `server/internal/domain/audit/codes.go` by `make gen`
      (`server/web/src/lib/auditCodes.gen.ts`), never maintained by hand; English display messages exist for every
      code (lint check: every generated code has an `audit.<code>` key in `en.json`).
   c) The agent writes an empty `/etc/paddock/login-deny` whenever the PAM profile is enabled, also on devices
      without a `login` resource.
   d) `TestDeviceSecurity/timestamp_5m1s`: use 5 min 10 s (still outside the window, robust against second truncation
      and latency); the boundary itself stays covered by the gateway unit test.
   e) `test/system`: after restoring `base-installed`, stop and mask `apt-daily.timer`, `apt-daily-upgrade.timer` and
      `unattended-upgrades.service` in the guest for the duration of the test (test harness only — devices in
      production keep their timers; update control is M5).
1. Commands end to end (server, device API, agent execution framework with a no-op test command behind a test build
   tag) + C1. Commit `feat(commands): signed device commands`.
2. Step-up + U1. Commit `feat(auth): step-up authentication`.
3. Escrow keys and endpoints + integration test decision 10. Commit `feat(escrow): escrow endpoints and wrap key`.
4. Local admin: settings, compiler, agent reconciler, reveal/rotate API, events. Commit `feat(local-admin): managed local administrator`.
5. Notice. Commit `feat(agent): login notice`.
6. Portal. Commit `feat(web): local administrator, commands, step-up`.
7. Gates LA1, LA2, N1, e2e; regression from reset incl. `system-test VM=all`. Commit `test: M4a gates`.

## 8. Acceptance criteria
| # | Given / When / Then | Req. | Observed by |
| --- | --- | --- | --- |
| AC1 | Given any device, then its local admin password is known to Paddock at all times, including when a rotation confirmation fails | F16, concept gate | Org admin (reveal) |
| AC2 | Given an org admin without a fresh MFA step-up, then reveal is refused and audited | ADR 0014, F16 | Org admin, auditor |
| AC3 | Given a reveal, then exactly one audit event exists and, if configured, a rotation follows after the set time | F16, F7 | Auditor |
| AC4 | Given the organization's notice text, then users see it at GDM, TTY and SSH login | Concept layer 2 | User at device |
| AC5 | Given a command, then it executes at most once, only on its device, and never after expiry | A5, §11.4 | Org admin (portal) |

## 9. Freedoms
Internal structure, journal-follow implementation (`journalctl -f -o json` vs. sd-journal file reading without cgo),
portal layout, test helpers.

## 10. Stop conditions
S1 Transit OAEP parameters incompatible with Go's RSA-OAEP-SHA256; S2 Authentik cannot force a fresh MFA re-auth for
an existing session or does not provide `auth_time`; S3 a design-contract rule would be violated; plus M0 §11
S2/S6/S7/S8.

## 11. Risks
| # | Item | Default |
| --- | --- | --- |
| R1 | Agent-driven rotation timer and offline devices | Rotation only when the server is reachable; overdue state shown in the portal |
| R2 | `useradd -G sudo` gives full sudo to the local admin | Intended (break-glass); documented; all its logins are audited |
| R3 | dconf banner differs between GNOME versions | N1 runs on both releases |
