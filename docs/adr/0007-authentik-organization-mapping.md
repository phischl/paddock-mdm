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

