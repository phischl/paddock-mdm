# Implementierungsplan: M4c — Revocation: Lock, Destroy, mass-revocation protection, dead man's switch

Status: Ready for implementation (after M4b) · 2026-10-05 · Author: architect
Basis: architecture v1.7 §12.3 (revocation sequence), §12.6 (dead man's switch), §13 (keys); ADR 0006, 0014; concept
"Data revocation", "Two revocation actions: Lock and Destroy", "Optional dead man's switch", design contract 7, 8, 10;
M4a (commands, step-up), M4b (escrowed recovery key and header)

Binding language: **MUST** / **MUST NOT** / **SHOULD** / **MAY**.

> **Acceptance is two-stage (product-owner decision 2026-10-05).** This plan is implemented and tested on VMs, but the
> revocation path is **disabled by a feature flag** until (1) a second person has reviewed every change under
> `agent/internal/revoke/` and `agent/cmd/paddock-revoke/` and (2) the hardware protocol in
> `docs/operations/revocation-acceptance.md` has passed on a real laptop. The coding agent MUST NOT mark M4c accepted
> and MUST NOT enable the flag anywhere except in development and test configuration.

## 1. Goal

An org admin can **Lock** a device (keyslots erased, forced reboot, restorable from the escrowed header) with step-up,
and two org admins can **Destroy** a device (Lock + escrow deleted, cryptographically unrecoverable). The confirmation
reaches the server before the reboot. A compromised admin session cannot revoke more than the configured number of
devices. Organizations can enable a dead man's switch that locks devices which have not reached Paddock for a
configured period.

## 2. Context

- Architecture §12.3 sequence (binding): request (step-up) → for Destroy a second approval by a different subject with
  step-up → revocation-issuer verifies step-up proofs against Authentik's JWKS, distinct subjects and rate limits → signs
  a device-bound revocation command → delivered with the check-in → `paddockd` hands it to `paddock-revoke` →
  verify → terminate user sessions → erase all keyslots and verify → POST confirmation, wait ≤ 20 s for the 202 →
  forced reboot. The 202 is returned only after the RabbitMQ publisher confirm (quorum queue).
- ADR 0014 limits (binding): per admin 3 per hour and 10 per 24 h; per organization 20 per 24 h (configurable downwards
  only; upwards only by a platform admin, audited); exceeding blocks, alerts, audits and freezes the admin's
  revocations for 24 h; `paddock-revoke` itself refuses more than one revocation per 24 h.
- M4a: commands (DSSE, `cmd:<device>` in Valkey, `/v1/commands/{id}/result`), step-up (`stepup_at`, `stepup_jti` in the
  session), `RequiresStepUp` in `ActionSpec`. M4b: escrowed `luks_recovery_key` and `luks_header` generations.

## 3. Binding decisions

### 3.1 Feature flag
1. Server env `PADDOCK_REVOCATION_ENABLED` (default `false`; `compose.dev.yaml` and test configurations set `true`).
   When false: revocation and DMS endpoints return 403 problem `revocation_disabled` (audited as `denied`), the
   revocation-issuer refuses to sign, the portal shows "Revocation is not enabled on this installation (pending
   acceptance)". `paddock-revoke` additionally checks a device-side marker `/etc/paddock/revoke-enabled` written by the
   agent only when the bundle says `revocation.enabled = true` (compiler sets it from the flag).

### 3.2 Keys and trust
2. OpenBao Transit key `revocation-signing` (Ed25519, non-exportable); AppRole `paddock-revocation-issuer` only
   (`update` on its sign path, `read` on the key). No other role can sign with it.
3. **Device trust anchor for revocation:** the revocation public keys are delivered in the **enrollment config**
   (field `revocation_keys`, added by the api when the token is created) and pinned by the agent at enrollment in
   `/etc/paddock/revoke-trust.json` (0644, protected path). They are **not** taken from bundles (a compromised bundle
   key must not be able to swap the revocation key). Rotation: a `revocation_key_rotation` command signed by a
   currently trusted revocation key that carries the new key. For devices enrolled before M4c the agent pins the keys
   once from the first bundle that carries `revocation.keys` and reports `revocation.trust_pinned_tofu` (documented
   trust-on-first-use for pre-M4c devices).
4. **Revoke module release key:** `paddock-revoke` is its own Debian package `paddock-revoke` (binary
   `/opt/paddock/revoke/paddock-revoke`), built and published like the agent packages but **never** delivered through
   the agent update channel (design contract 7). Installed by the autoinstall and as a dependency-free package;
   updates only via package installation. CODEOWNERS entry for `agent/internal/revoke/` and `agent/cmd/paddock-revoke/`
   with two required reviewers (placeholder `@paddock-mdm/revocation-reviewers`).

### 3.3 Server: requests, approvals, issuer
5. **Entities:** `revocation_request(id, organization_id, device_id, action lock|destroy|self_lock, status
   requested|approved|issued|delivered|confirmed|failed|rejected|cancelled|expired, requested_by, requested_at,
   reason text (≤ 500), issued_at, confirmed_at, result jsonb)` and `revocation_approval(request_id, organization_id,
   admin_id, subject, stepup_id_token text, approved_at, role requester|approver)`. The raw step-up ID token is stored
   (needed for the issuer's verification); it is never returned by any API and is deleted 30 days after the request
   reaches a final state.
6. **M4a extension:** the step-up callback keeps the raw ID token server-side (Valkey `stepup:<jti>`, TTL 300 s) so a
   revocation use case can attach it; the session still only carries `stepup_at`/`stepup_jti`.
7. **API** (org_admin only; every call step-up + typed hostname; audited):
   `POST /api/v1/devices/{id}/lock {reason}` → request + requester approval → status `approved` → outbox to
   `paddock.revocation`.
   `POST /api/v1/devices/{id}/destroy {reason}` → request `requested` (requester approval).
   `POST /api/v1/revocation-requests/{id}/approve` → second approval; MUST be a different `admin_id` and `subject` →
   `approved` → outbox. `POST …/{id}/reject`, `POST …/{id}/cancel` (requester, before issuance).
   `GET /api/v1/revocation-requests` (list contract; filters status, action, device_id).
8. **Revocation issuer** (`paddock-server serve revocation-issuer`, single active consumer on `revocation.approved`,
   own DB role `paddock_revocation` with access to revocation tables, `device` (read) and `escrow_secret` (delete for
   Destroy) only): for each approved request: verify every approval's ID token (signature via Authentik JWKS, `iss`,
   `aud` = portal client, `sub` = stored subject, `auth_time` ≤ 300 s before `approved_at`, not reused: one token per
   approval); Destroy requires two distinct subjects; check limits (ADR 0014; counting per requesting admin and per
   organization over sliding windows, including requests issued in the last 24 h); then sign the revocation command
   (DSSE `application/vnd.paddock.revocation.v1+json`, payload `{command_id, device_id, organization_id, action,
   issued_at, expires_at (+30 d), request_id}`) and put it into `cmd:<device_id>`; status `issued`. Limit exceeded →
   `rejected`, audit `revocation.limit_exceeded` (outcome denied), alert, and a 24 h freeze row for the admin.
9. **Destroy server side:** at issuance the issuer deletes all `luks_header` objects (escrow bucket, all versions) and
   all `luks_recovery_key`/`luks_header` rows of the device (crypto-shredding), in the same transaction as the status
   change (object deletion first; failure → `failed`, retried). Audit `device.escrow_destroyed`. Lock keeps the escrow.
10. **Results:** the device's confirmation (`/v1/commands/{id}/result`) moves the request to `confirmed` with
    `{erased: true, slots_before, slots_after: 0}`; audit `device.revocation_confirmed`. Requests issued but never
    confirmed are shown as `pending` with elapsed time (concept stage 3); after `expires_at` → `expired` (the token on the
    device would be refused anyway).

### 3.4 Device: `paddock-revoke`
11. Invocation by `paddockd`: `paddock-revoke execute` with the DSSE envelope on stdin; `paddockd` never interprets
    revocation payloads itself. `paddock-revoke`: verify signature against `/etc/paddock/revoke-trust.json`,
    `device_id` = enrolled identity, `expires_at` > now, `command_id` not executed (state
    `/var/lib/paddock/revoke/state.json`), no other revocation in the last 24 h, `/etc/paddock/revoke-enabled` present.
    Any failure → exit code ≠ 0 and a `revocation.refused {reason}` event via `paddockd`.
12. **Sequence** (binding, architecture §12.3): (1) terminate all user sessions (`loginctl terminate-user` for every
    non-system user); (2) `cryptsetup luksErase --batch-mode <root device>` (all keyslots), then verify with
    `luksDump --dump-json-metadata` that no keyslot remains; (3) POST the confirmation **itself** (signed with the device
    key; it links `pkg/protocol`) and wait up to 20 s for 202; (4) `systemctl reboot --force --force` regardless of the
    confirmation outcome. Between (2) and (4) nothing else runs. For `self_lock` the same sequence.
13. **Test target override:** only in binaries built with build tag `paddock_revoke_testtarget`, the root device can be
    overridden by `/etc/paddock/revoke-test-target` (a secondary LUKS disk in test VMs) and the reboot replaced by
    writing `/run/paddock/revoke-would-reboot`. Release packaging MUST NOT use this tag (a test asserts the release
    binary rejects the override file).

### 3.5 Dead man's switch
14. **Time tickets:** compiler issues per organization every 10 min `{organization_id, issued_at}` signed with Transit
    key `time-ticket` (Ed25519; AppRole compiler), Valkey `tt:<org>`, returned in every check-in (`time_ticket`). Public
    keys in the bundle (`keys.time_ticket`).
15. **Organization settings** `dms_enabled` (default false), `dms_period_days` (min = Himmelblau offline window rule:
    the portal enforces ≥ 7 and warns below 30), `dms_warn_days` (default `[3, 1]`). Enabling requires step-up and
    produces audit `settings.dms_changed`. When enabled, the issuer creates one `self_lock` revocation token per active
    device (no approvals needed; rate limits do not apply; the token payload contains `period_days`) and delivers it as
    a command that the agent stores (not executes) in `/var/lib/paddock/revoke/self-lock.dsse`. Disabling deletes the
    tokens server-side and sends a command telling the agent to delete its copy.
16. **Agent:** accumulates uptime since the last accepted ticket (`CLOCK_BOOTTIME` deltas, persisted every 60 s);
    warnings at `period − warn_days` via `notify-send` to graphical sessions (`systemd-run --machine=<user>@ --user`)
    and `/etc/issue.d/80-paddock-dms.issue`; at `elapsed ≥ period` invokes `paddock-revoke execute` with the stored
    self-lock token and `--elapsed-seconds <n>`; `paddock-revoke` additionally checks `elapsed ≥ period_days` from the
    token. A fresh ticket resets the counter and removes warnings.
17. Server: devices silent for longer than `dms_period_days` while DMS is enabled are shown as `presumed_self_locked`
    (worker, every 5 min; audit once).

### 3.6 Portal
18. Device detail: *Lock* and *Destroy* actions (step-up, `ConfirmDialog` with typed hostname, reason field; Destroy
    explains the two-person rule), revocation status timeline. *Revocation requests* page (`DataList`, approve/reject
    with step-up and typed hostname). Settings: DMS with period warning text ("If Paddock is unreachable for longer
    than this period, every device with the switch enabled locks itself").

## 4. Non-goals
Automatic destroy after a lock period; remote wipe of data beyond keyslots; revocation of unmanaged (non-Paddock-
installed) devices beyond keyslot erasure; enabling the flag in production configuration.

## 5. Affected files
Server: migration `00012_revocation.sql`, domain `revocation`, issuer role, API, compiler (time tickets, revocation
bundle section), worker (expiry, presumed self-locked), BFF step-up token retention. Agent: `cmd/paddock-revoke`,
`internal/revoke` (two-person rule!), `paddockd` hand-off, DMS counter, warnings. Packaging `paddock-revoke`. CODEOWNERS.
Portal. Tests. Docs: `docs/operations/revocation.md` (operator guide incl. Lock restore with the escrowed header and
recovery key), `docs/operations/revocation-acceptance.md` (hardware protocol, below). CHANGELOG (flagged features).

## 6. Gates (VMs and acceptance; all with the flag enabled in test configuration)

| ID | Gate | Content |
| --- | --- | --- |
| R1 | Lock on a VM | test VM with a secondary LUKS disk as test target (`paddock_revoke_testtarget` build): Lock → sessions terminated, all keyslots of the target erased, confirmation stored **before** the would-reboot marker appears (timestamps), request `confirmed`; restore: header from the escrow API + recovery key re-open the target |
| R2 | Destroy | two different admins with step-up; escrow rows and header objects deleted before issuance completes; restore impossible (API returns 404 for header/recovery key); single admin cannot approve their own request; same subject with two admin accounts rejected |
| R3 | Mass revocation gate (concept) | fourth Lock within an hour by the same admin → rejected, `revocation.limit_exceeded`, alert, admin frozen 24 h; organization limit analogous; issuer refuses a forged approval (ID token signed by another key, stale `auth_time`, reused token) |
| R4 | Device refusals | expired token, wrong device, untrusted key, second revocation within 24 h, missing `revoke-enabled` marker → refused with event, no keyslot touched; release-built `paddock-revoke` ignores the test-target file |
| R5 | Flag off | with `PADDOCK_REVOCATION_ENABLED=false`: endpoints 403 `revocation_disabled` (audited), issuer refuses, bundle `revocation.enabled=false`, `paddock-revoke` refuses |
| R6 | Dead man's switch (agent outage gate, concept) | period shortened via test build tag `paddock_dev` (minutes instead of days): with the stack stopped the device warns at the configured lead times and locks only after the period; wall-clock changes neither defer nor trigger; with DMS disabled nothing happens for 3× the period |
| A2/A3/list/E | existing | all new endpoints; e2e for Lock dialog with typed hostname and the approval page |

## 7. Hardware acceptance protocol (`docs/operations/revocation-acceptance.md`, executed by the product owner)
The document MUST contain step-by-step instructions with expected results for: installing a real laptop with the
Paddock autoinstall (TPM2+PIN); Lock → reboot → device asks for the PIN and does not unlock; restoring the header from the
escrow and unlocking with the recovery key from a live USB; Destroy (two admins) → device unrecoverable, escrow gone;
dead man's switch with a 1-day test period; a second-person review checklist for `agent/internal/revoke/` (what to
verify: the sequence order, no network calls before erase except the trust checks, no code path that erases without
a verified token, the 24 h limit, the test-target build tag excluded from release builds). Only after both are signed
off does the architect plan enabling the flag.

## 8. Steps
1. Keys, trust anchor (enrollment config + agent pinning), packaging `paddock-revoke`, CODEOWNERS.
2. Server requests/approvals/issuer/limits/Destroy shredding + R2, R3, R5 (acceptance).
3. `paddock-revoke` + `paddockd` hand-off + R4 (unit + VM).
4. R1 on both VMs (secondary disk added and removed by the test harness using `VBoxManage`, from `base-installed`).
5. DMS (tickets, settings, agent counter, warnings, self-lock token) + R6.
6. Portal + e2e. 7. Docs incl. hardware protocol. 8. Regression from reset (all gates incl. system tests).
One commit per step.

## 9. Acceptance criteria (stage 1 — VM; stage 2 — product owner, hardware)
| # | Given / When / Then | Req. | Observed by |
| --- | --- | --- | --- |
| AC1 | Given a Lock, then the device's keyslots are erased, the confirmation is stored before the reboot, and the device can be restored from the escrow | F5 | Org admin |
| AC2 | Given a Destroy approved by two admins, then the escrow is gone and the device's data is unrecoverable | F5 | Org admin, auditor |
| AC3 | Given a compromised admin session, then it cannot revoke more devices than the limits allow, and the attempt is blocked and alerted | A4, concept gate | Platform operator, auditor |
| AC4 | Given the dead man's switch, then a device locks only after the period and only after the warnings; without it nothing happens | F14, concept gate | User at device |
| AC5 | Given the feature flag is off, then no revocation can be issued or executed | product-owner decision | Platform operator |

## 10. Freedoms
Internal structure outside the binding sequence, portal layout, test harness details.

## 11. Stop conditions
S1 a step would let `paddockd` (not `paddock-revoke`) erase keyslots; S2 Authentik ID tokens lack `auth_time` or a
verifiable signature; S3 the confirmation cannot be sent before reboot without changing the sequence; S4 any need to
enable the flag outside dev/test; plus M0 §11 S2/S6/S7/S8.

## 12. Risks
| # | Item | Default |
| --- | --- | --- |
| R1 | TOFU pinning for pre-M4c devices | Documented, reported per device; re-enrollment removes it |
| R2 | Platform outage longer than DMS period locks all DMS devices | Portal warning; minimum period; concept risk accepted by operators |
| R3 | A user with root disables DMS or `paddock-revoke` | Detection model (tamper events, heartbeat absence) — documented |
