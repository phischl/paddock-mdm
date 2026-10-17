# 0019 — Login component: Himmelblau in OIDC mode against Authentik (A2)
Status: Accepted (product owner, 2026-10-04)

## Context
The concept delegates device login to Himmelblau and requires a time-boxed PoC (items 1–4, plus item 5 from
architecture §9.5) before building on it; fallback is SSSD against Authentik with day-granular offline validity.
PoC M1 (`docs/poc/M1-report.md`, Himmelblau 4.0.4, Authentik 2026.8.3, Ubuntu 24.04.5 and 26.04.1) results:

| Criterion | Result (both releases) |
| --- | --- |
| C1 OIDC + MFA verified by Authentik | PASS (needs a `groups` claim on scope `profile`, names without `:`) |
| C2 lock via Authentik | PASS — only with revocation of refresh tokens/sessions (group alone does not stop PIN logins) |
| C3 suspension via allow list | PASS — `pam_allow_groups`, daemon restart required |
| C4 Hello PIN | PASS — PIN unsealing key TPM-bound via systemd-creds |
| C5a offline login refused after allow-list removal | PASS |
| C5b screen unlock refused via allow list | FAIL — GNOME lock screen ignores account-phase results |
| C5c `pam_listfile` | account phase PARTIAL; auth phase closes the gap (diagnostic) |
| C6 no sudo from the login component | PASS |

## Options
- **Himmelblau 4.x, OIDC mode, configuration only, plus a standard `pam_listfile` deny list in the auth and account
  phase.** + Meets all gate criteria; MFA and federation stay in Authentik; Hello PIN; offline. − First login (and
  after lock/unlock or three wrong PINs) uses the **device authorization grant**: code/QR on the greeter, approval
  with MFA on a second device; password + TOTP directly at the greeter is not possible with Authentik.
  Several upstream rough edges (7 issues listed in the report).
- **SSSD against Authentik (fallback).** + Familiar; password at the greeter. − No MFA at the greeter with Authentik,
  day-granular offline cache, no Hello PIN; not evaluated further because Himmelblau passed.

## Decision
Himmelblau 4.x (pinned, official repository, verified key fingerprint) in OIDC mode, configured exclusively through
`himmelblau.conf`. Binding details are in architecture §9.2–9.5: dot-separated group names (`paddock.<slug>…`), groups
claim on scope `profile` of the device provider, device provider with authorization code + refresh token + device
code grants, device-code flow with **mandatory** MFA, `allow_console_password_only = false`, explicit
`pam_allow_groups` line with daemon restart on change, lock = group **and** token revocation, local deny list via a
`pam-auth-update` profile in the auth and account phase, sessions of a suspended device are terminated.

## Consequences
+ No custom login code; concept rules 1 and 2 hold.
− Users need a second device (phone) for the first login and after a lock/unlock; operators must communicate this.
− M0 code must be migrated from `paddock:<slug>:<role>` to `paddock.<slug>.<role>` group names (plan M0.3).
Follow-ups: file the upstream issues from the report; re-test TPM lockout and SSH/TTY deny-list paths on real hardware
and in M3/M4 acceptance tests.

## Amendment 2026-10-17 (M8x, lab findings L26, L29)
- **Hello PIN past the access token (interim mitigation, agent-side).** Himmelblau 4.0.x (generic OIDC, identical
  in 4.0.6 and `main`) re-seals the refresh token with the Hello key at every PIN login, but its cached-user refresh
  (`unix_user_get`, run by any NSS lookup once the user's cache entry is older than `cache_timeout`, default 300 s)
  rotates the token in memory only; Authentik revokes the old one, the next PIN login or unlock presents the stale
  sealed token, gets `invalid_grant` and deletes the Hello key. No Authentik setting avoids it: a
  `refresh_token_threshold` above zero omits the refresh token from the response and Himmelblau then denies every
  PIN login. Decision: the agent renders `cache_timeout = 2592000` (30 days, equal to the device provider's
  `refresh_token_validity`) into `himmelblau.conf`, so the background refresh can only run when the sealed token has
  expired anyway; every PIN authentication re-seals the token and resets the cache expiry. Costs accepted:
  Himmelblau's cached NSS attributes of a signed-in user refresh online at the next PIN authentication or after 30
  days; a locked user (tokens revoked) leaves Himmelblau's NSS cache until the next login. Paddock's lock, suspension
  and allow list do not depend on that cache. Rejected: `enable_hello = false` as the default (device code and
  phone at every unlock; stays available per organization), a per-organization cache setting (the value follows
  from the token validity), accepting the failure. The two 30-day figures move together. Residual (RR-40): after 30
  days without a PIN authentication, after a lock, after three wrong PINs, and on agents older than 0.1.0-alpha.4
  the user signs in with the device code again and sets a new PIN. The constant is removed once an upstream
  release re-seals rotated tokens (issue draft in the maintainer's notes).
- **Device code lifetime** is `access_code_validity: minutes=10` on the device provider (Authentik's default of one
  minute was too short to approve the sign-in and set the PIN).
- **Pinned version** becomes 4.0.6 (second device flow after an expired code, synthetic lookups no longer cached),
  subject to green identity and local-administrator gates on both VMs; otherwise 4.0.4 stays.
- The system gate L6 (unlock with the PIN after more than the access-token lifetime) guards this behaviour.
- **Himmelblau never manages the sudo group (lab finding L37, PDK-294).** Himmelblau's local-group task runs at every
  authentication and, by default, every 300 s for every cached account; with `sudo_groups` unset it removes every
  account from `local_sudo_group` (default `sudo`), which fought the agent's local administrator and the break-glass
  accounts on the lab device. Decision: the agent renders `local_sudo_group = paddock-no-sudo` (a group that never
  exists, so the removal is a silent no-op) and `local_groups_reconcile_interval = 0`, never `sudo_groups`;
  `local_groups = users` stays. Paddock alone owns sudo (ADR 0008); Himmelblau's sudo mapping is never used.
