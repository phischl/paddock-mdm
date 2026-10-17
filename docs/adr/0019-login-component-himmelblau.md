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
- **Refresh tokens are not rotated during their life.** Himmelblau 4.0.x seals the refresh token with the Hello key
  once, at PIN enrolment, and refreshes cached users from an in-memory copy; Authentik's default
  `refresh_token_threshold = seconds=0` renews (and revokes) the refresh token at every refresh, so the sealed
  token was revoked ten minutes after every login and the next PIN login deleted the Hello key. The device
  provider sets `refresh_token_threshold: days=1` (renewal only within the last day of the 30-day validity).
  Residual: once per refresh-token lifetime the user signs in with the device code again and sets a new PIN (RR-40)
  until Himmelblau re-seals a renewed token (upstream issue filed by PDK-206).
- **Device code lifetime** is `access_code_validity: minutes=10` on the device provider (Authentik's default of one
  minute was too short to approve the sign-in and set the PIN).
- **Pinned version** becomes 4.0.6 (second device flow after an expired code, synthetic lookups no longer cached),
  subject to green identity and local-administrator gates on both VMs; otherwise 4.0.4 stays.
- The system gate L6 (unlock with the PIN after more than the access-token lifetime) guards this behaviour.
