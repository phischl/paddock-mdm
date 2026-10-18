# 0007 — Mapping Paddock organizations to Authentik (A1)
Status: Proposed

## Context
Authentik is bundled and the single source of authentication. A1: no user of one organization visible in another
organization's login flows; meets F2, F3, F13; works without upstream IdP; open-source core only.

## Options
- **One shared Authentik; per organization a group tree, a device-login application with policy binding, a login flow.**
  + One instance to operate; open-source features only. − Isolation enforced by Paddock-managed configuration;
  Authentik superusers see all organizations.
- **One Authentik per organization.** + Hard isolation. − Linear operational cost (rejected for Fleet for the same reason).
- **Authentik enterprise multi-tenancy.** − Not part of the open-source core.

## Decision
Shared instance. Per organization: groups `paddock.<slug>`, `.locked`, `.admins`, `.operators`, `.auditors`,
`.g.<group>` (amended 2026-10-04: `.` instead of `:` because Himmelblau drops claim values containing `:`, ADR 0019); OIDC application `paddock-device-<slug>` with expression policy "member of `paddock.<slug>` and not
of `.locked`"; flow `paddock-<slug>-login` with enumeration prevention and MFA; upstream sources bound to that flow.
One portal application for all admins. Lock = membership in `.locked` **and** revocation of sessions and refresh tokens (both mandatory; PoC M1 C2). Usernames
`local@verified-domain` for local users. The adapter reconciles these objects every 10 minutes.

Authentik is only one of two lock paths: the agent additionally blocks a locked user locally at the device's next
check-in and locks the user's sessions (architecture §9.5), so a lock does not depend on the offline window of
cached credentials once the device has had contact.

## Consequences
+ Lock survives upstream attribute sync; no per-organization infrastructure.
− Authentik admin accounts are platform-level and must be restricted to platform operators and audited.
Depends on A2 PoC (refresh tokens for Hello PIN).

## Amendment 2026-10-04 (M3a, live findings against Authentik 2026.8.3)
- **Token revocation on lock:** Authentik exposes other users' tokens only to superusers. Instead of a superuser service
  account (least privilege), the lock adds the user to `paddock.<slug>.locked` and then toggles `is_active` false → true;
  Authentik's deactivation signals delete all of the user's access, refresh and device tokens and sessions. The lock
  itself remains the group membership. This relies on Authentik behaviour: Authentik upgrades require the lock gate
  (I2) to pass. An interrupted lock is reported as incomplete and can be retried idempotently.
- **MFA on every device-login path:** the device providers use a Paddock authorization flow with a mandatory MFA stage,
  because the QR/`?code=` path otherwise authenticates through the brand's default flow.
- **Claim hygiene:** device providers do not use Authentik's managed `profile` mapping (it emits all groups); a Paddock
  mapping emits the profile claims and only the organization's `paddock.<slug>…` groups.

## Amendment 2026-10-16 (ADR 0034)
- The step-up provider `paddock-portal-stepup` emits the Paddock groups claim (`io.paddock/scope-groups`) explicitly;
  the step-up callback resolves the role from it with the login's resolution and refuses a step-up whose role or
  organization differs from the session (the account's sessions are revoked and `admin_account` updated).
- The worker reconciles `admin_account` against the organization's role groups and `is_active` every identity sync
  interval; a removed, demoted or deactivated administrator loses every session.
- The step-up flow `paddock-stepup` validates with WebAuthn only in the shipped blueprint; TOTP for the step-up
  exists in the development blueprint alone.

## Amendment 2026-10-17 (M8x, lab finding)
- **Second factor on every portal path.** ~~The portal requests its authorization with `prompt=login`, so every
  portal sign-in runs `paddock-admin-login` (password and second factor) and an existing Authentik session never
  satisfies it.~~ Replaced the same day (CI of PR #82): the portal login sends **no** `prompt` — Authentik's
  `prompt=login` handling (`last_login_uid`, never cleared) let a later step-up pass without running its flow (ADR
  0034 amendment). An existing Authentik session satisfies the portal sign-in only if its ID token carries `mfa` in
  `amr`, which the brand's authentication flow and the default-flow MFA stage below guarantee; the portal callback
  refuses every token without it. PDK-190 (ending the Authentik session on *end all sessions*) is therefore open
  again.
- **Brand and default flow.** The worker keeps the default brand's `flow_authentication` at `paddock-admin-login`
  next to the recovery and device-code flows; the portal blueprint binds a Paddock validation stage
  (`paddock-default-login-mfa`, configure when missing, 5-minute threshold) at order 31 of Authentik's
  `default-authentication-flow`, so a password-only session cannot be created through Authentik's own interfaces.
  The development blueprint skips that stage like the login stage.
- **Device provider tokens** (ADR 0019 amendment): `access_code_validity: minutes=10`; `refresh_token_threshold`
  stays at Authentik's default `seconds=0` (a threshold above zero makes Himmelblau deny every PIN login).

## Amendment 2026-10-18 (M8f, ADR 0034 amendment)
- **Step-up authenticator classes.** The step-up provider `paddock-portal-stepup` carries the Paddock mapping
  `io.paddock/scope-stepup-mfa` (scope `paddock_stepup`), which reads the session's login event and emits
  `paddock_mfa_classes`; the api requires the WebAuthn device class in it.
- **Portal login enrols WebAuthn after an existing factor** (`paddock-admin-login-mfa`: `[webauthn, totp]`,
  configure with the WebAuthn setup stage; `paddock-admin-login-webauthn`: `[webauthn]`, configure with the WebAuthn
  setup stage, bound with the policy `paddock-admin-login-webauthn-missing`); the default-flow and device-login stages
  are unchanged.
- **Service account** `paddock-service` holds `authentik_core.view_authenticatedsession` and
  `authentik_core.delete_authenticatedsession`: *End all sessions* deletes the authenticated sessions of every portal
  user (`core/authenticated_sessions/bulk_delete`).
