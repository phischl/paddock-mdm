# Implementierungsplan: M4b.1 — Findings from the trusted-core review

Status: Ready for implementation (after M4b) · 2026-10-06 · Author: architect
Basis: review page "Paddock Review-Paket" (2026-10-06), product-owner decision 2026-10-06: implement all four
recommendations; architecture v1.7 §9.2 (lock), §12.2/§12.4 (escrow), §11.2 (supervisor), §13 (keys); ADR 0007, 0014

Binding language: **MUST** / **MUST NOT** / **SHOULD** / **MAY**.

## 1. Goal
Close four findings: a lock no longer reactivates users deactivated elsewhere; the agent removes only the keyslot it
means to remove; escrowed secrets can only be decrypted with a fresh MFA proof verified outside the api process; agent
releases are bound to their version and downgrades are refused.

## 2. Findings (quoted from the review)
1. `LockUser` (server/internal/adapters/authentik/users.go:98–123) toggles `is_active` false → true unconditionally;
   a user deactivated before (upstream source or Authentik admin) is active afterwards. `UnlockUser` activates
   unconditionally.
2. `luks.Wipe` uses `systemd-cryptenroll --wipe-slot=password|recovery`, which removes **all** slots of that type,
   although the reconciler promises to remove only slots it created (agent/internal/reconcile/luks.go:152, :253).
3. The AppRole `paddock-escrow-reader` is loaded in the `api` process; code execution in the api container yields
   decryption of every escrowed secret without step-up.
4. The supervisor verifies the release signature over the binary only; the version comes from the unsigned
   `request.json`, so an older signed release can be installed as a downgrade.

## 3. Binding decisions

### 3.1 Lock keeps the previous activation state (finding 1)
1. `LockUser` reads the user's `is_active` first. If it was `false`, it only adds the user to `.locked` and revokes
   tokens/sessions by the toggle **without** the final reactivation (the user stays inactive). If it was `true`, the
   toggle runs as today. The previous value is returned to the use case and stored in `app_user.lock_reactivate`
   (new boolean column, migration).
2. `UnlockUser` removes the `.locked` membership and sets `is_active=true` **only** if `lock_reactivate` is true and the
   user is currently inactive because of an interrupted lock (`lock_incomplete`). A user deactivated elsewhere stays
   inactive. Tests: four combinations (active/inactive before lock × complete/interrupted lock) + unlock.

### 3.2 Remove exactly the intended keyslot (finding 2)
3. `luks.Wipe` is replaced by `luks.WipeSlot(device, keyFile, slot int)` (`cryptsetup luksKillSlot --key-file <keyFile>
   <device> <slot>`, never `--wipe-slot=<type>`). The reconciler records, at the time it creates something, the slot
   numbers it owns: the install passphrase slot is the slot that `cryptsetup luksOpen --test-passphrase
   --key-file <install-passphrase>` reports (`--verbose` prints the slot), recorded once before the first change; the
   recovery slot is the slot added by `EnrollRecovery` (diff of the token list before/after). Only recorded slots are
   ever killed. A slot that is not recorded but has the same type → `tamper.keyslot_changed`, never removed.
4. The comment in luks.go becomes true as written; tests with a fake `cryptsetup` cover: an extra user passphrase slot
   and an extra recovery slot survive both the recovery replacement and the passphrase removal.

### 3.3 Escrow decryption outside the api (finding 3)
5. New role `paddock-server serve escrow-reader` (own Compose service, own container, internal network `escrow` shared
   only with `paddock-api`, no published port). It holds the AppRole `paddock-escrow-reader`; the `api` no longer gets
   that credential (remove its secret files from the api service). The api's AppRole loses nothing else.
6. Interface (internal HTTP on the `escrow` network, mutual authentication by a shared bearer secret from a Docker
   secret file, rotated with `make dev-secrets`; production documented): `POST /internal/v1/decrypt` body
   `{organization_id, device_id, escrow_ids: [], stepup_id_token, purpose: "local_admin_reveal"|"disk_recovery_key"|"disk_header"}`.
   The escrow-reader MUST, before decrypting:
   - verify `stepup_id_token` against Authentik's JWKS (`iss`, `aud` = portal client, `exp`), `auth_time` within the
     effective step-up window (same rule and dev override as the api), and that the token's `sub` belongs to an
     `org_admin` of `organization_id` (own DB role `paddock_escrow_reader`: `SELECT` on `admin_account`,
     `escrow_secret`, `device` only; reads inside `InOrg` with the organization from the request and **re-checks** that
     every escrow row belongs to `device_id` and that organization);
   - refuse a token whose `jti` was used for more than 5 decrypt calls (Valkey counter, TTL = token lifetime).
   It returns plaintexts; it never logs them. Audit stays in the api's `ActionRunner` (the api records the outcome,
   including refusals by the escrow-reader as `denied`).
7. Step-up ID token retention (brought forward from plan M4c decision 6): the BFF stores the raw step-up ID token in
   Valkey `stepup:<jti>` (TTL = step-up window) at the step-up callback; reveal/recovery use cases fetch it by the
   session's `stepup_jti` and pass it to the escrow-reader. The session cookie still carries only `stepup_at`/`stepup_jti`.
8. Shared package `server/internal/stepupproof` (JWKS fetch with caching, claim checks) — M4c's revocation-issuer
   will reuse it.
9. Architecture amendment (done by the architect): escrow-reader role in §3.2/§13.

### 3.4 Version-bound releases (finding 4)
10. Release signing (`make agent-release`, docs/operations/agent-releases.md): the minisign **trusted comment** is
    `paddock-agent version=<semver> arch=<amd64|arm64>`.
11. Supervisor: after signature verification it parses the trusted comment (minisign verifies it as part of the
    signature) and requires `version` = requested version and `arch` = `runtime.GOARCH`; and it refuses a version lower
    than or equal to the currently active one (`semver` comparison in ≤ 40 lines, no new dependency), except when the
    active version is marked failed. Outcome `signature_invalid` resp. new outcome `downgrade_refused`
    (event `agent.update_failed {reason}`). Supervisor stays ≤ 600 non-test lines.
12. Server upload (`PUT …/artifacts/{arch}`) verifies the same trusted-comment fields (422 `release_signature_mismatch`).

## 4. Non-goals
Other changes to lock semantics, LUKS policy, escrow kinds or rollout logic; M4c work beyond decision 7/8.

## 5. Steps
1. Finding 1 + tests (adapter with recorded fixtures, acceptance I2 extended). Commit `fix(authentik): lock keeps the previous activation state`.
2. Finding 2 + tests (fake cryptsetup) + system gate D-24/D-TAMP rerun on paddock-u2604 with an extra user passphrase slot. Commit `fix(agent): remove only the keyslots the agent created`.
3. Finding 3: role, network, interface, step-up token retention, `stepupproof`, api changes, acceptance: reveal works; a forged/stale/foreign-org step-up token is refused by the escrow-reader even if the api is bypassed (test calls the internal endpoint directly from a container on the `escrow` network); the api container has no escrow-reader secret (`docker compose config`). Commit `feat(escrow): decryption in a separate escrow-reader role`.
4. Finding 4 + supervisor unit tests (downgrade, wrong version/arch in comment, missing comment) + gate S4 rerun on one VM. Commit `fix(agent): version-bound releases, no downgrades`.
5. Regression from reset: acceptance, e2e, `system-test VM=all T='TestAgentGates|TestLocalAdminGates|TestDiskGates'`.

## 6. Acceptance criteria
| # | Given / When / Then | Observed by |
| --- | --- | --- |
| AC1 | Given a user deactivated in Authentik, when an admin locks and unlocks them in Paddock, then they stay deactivated | Org admin |
| AC2 | Given an additional passphrase keyslot added by an operator, then the agent never removes it and reports it | Operator |
| AC3 | Given code execution in the api container, then no escrowed secret can be decrypted without a fresh MFA step-up of an org admin of that organization | Platform operator, auditor |
| AC4 | Given an older signed agent release, then the supervisor refuses to install it | Platform operator |

## 7. Stop conditions
`cryptsetup` cannot report the slot of a key file non-interactively; Authentik ID tokens lack `auth_time`; supervisor
exceeds 600 lines; M0 §11 S2/S6/S7/S8.
