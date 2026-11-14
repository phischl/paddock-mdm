# 0053 — Second-factor enrolment of administrators only through a one-time enrolment link
Status: Accepted (architect, 2026-11-14; maintainer decisions Q11 of 2026-11-09 and §3.3 of 2026-11-14; plan
`docs/plans/M12h-2-supply-chain-and-mfa-enrolment.md`)

## Context

Every portal sign-in requires a second factor (architecture §9.6, amendments 2026-10-17 to 2026-10-29). An account
**without** an authenticator is asked to enrol one in the sign-in itself: the stages `paddock-admin-login-mfa` and
`paddock-admin-login-webauthn` of `deploy/compose/authentik/blueprints/paddock-portal.yaml` and
`paddock-default-login-mfa` on Authentik's default authentication flow run with `not_configured_action: configure`.
Whoever knows the password of an administrator who has not signed in yet therefore enrols their own passkey and owns
the account (trust on first use; roadmap finding AU-3, plan M12h §13). The maintainer accepted "MFA enrolment by
invitation" for alpha.11 (Q11) and decided on 2026-11-14 that existing administrators without a second factor set one
up at their next sign-in, announced in the changelog and by a portal banner.

Paddock already creates one-time Authentik links for local users: `POST /api/v3/core/users/<pk>/recovery/` (valid
24 h) opens the brand's recovery flow `paddock-recovery` with the user restored from the link token (plan M3a
decision 18, `adapters/authentik/users.go::RecoveryLink`).

## Options

- **A — Authentik invitation stage (`authentik_stages_invitation`).** + Built for invitations. − Designed for
  enrolment flows that create users; binding an invitation to an existing user needs a custom expression on
  `fixed_data`; a second link mechanism next to the recovery link.
- **B — Extend the existing one-time link: the recovery flow `paddock-recovery` enrols the authenticators after the
  password (or alone, when the account already has a usable password); the sign-in stages deny accounts without an
  authenticator, except accounts marked for a one-time enrolment at sign-in.** + One link mechanism, already
  audited and already restricted to a link token; the user is bound by the token; no new Authentik object type.
  − The recovery flow gains stages; the link is a bearer secret for 24 h. **Chosen.**
- **C — Keep enrolment at first sign-in, add an e-mail confirmation.** − Paddock sends no e-mail; does not remove
  trust on first use when the mailbox is shared.

## Decision

1. **Enrolment link.** `POST /api/v1/users/{id}/enrolment-link` (organization administrator, step-up, for a user of
   the own organization; audited as `user.enrolment_link_created`) and the host command `paddock-server admin
   enrolment-link --username <name>` (the operator, for platform administrator accounts, which are managed in
   Authentik directly; audited as `platform.enrolment_link_created` in the platform pseudo-organization) return a
   one-time link valid 24 hours. The link is shown once and never stored, logged or put into audit params.
2. **The flow.** `paddock-recovery` runs: link-token policy (unchanged) → password prompt, bound with a policy that
   skips it when the account has a usable password → WebAuthn enrolment (`default-authenticator-webauthn-setup`),
   required → TOTP enrolment, optional → end. A link opened by an account that already has a WebAuthn device ends
   without changing anything.
3. **Sign-in.** `paddock-admin-login-mfa`, `paddock-admin-login-webauthn` and `paddock-default-login-mfa` switch to
   `not_configured_action: deny`. Each gets a sibling stage with `configure` that runs only for an account with the
   Authentik attribute `paddock_mfa_enrol_at_login: true` (policy `paddock-mfa-enrol-at-login`). A denied sign-in
   shows Authentik's denial; the portal's `/login-denied` names the reason `mfa_enrolment_required` when the callback
   receives it.
4. **Existing administrators (maintainer decision 2026-11-14).** The worker's admin-accounts round sets
   `paddock_mfa_enrol_at_login: true` once on every account that is a direct member of a portal role group and has
   neither a WebAuthn nor a TOTP device at the first round after the upgrade (marker
   `platform_mfa_enrolment.seeded_at`), and removes the attribute from every account that has a WebAuthn
   device. Accounts created later never get the attribute and need an enrolment link.
5. **Scope.** Portal administrators (platform administrators and the role groups of every organization). The device
   login flow `paddock-device-login` keeps `configure` for device users in this decision.
6. **Announcement.** The release's changelog fragment carries an `Upgrade:` line; the portal shows a dismissible
   banner to platform and organization administrators for 30 days after the upgrade with the count of administrators
   who still have to enrol.

## Consequences

- + A password alone never enrols a factor for a new administrator account; the gap is closed without a new
  dependency or a new Authentik object type.
- + Existing administrators are not locked out (decision 4).
- − Onboarding a new administrator needs a second person (or the platform administrator) to create the link and pass
  it on out of band; a lost link means a new link.
- − The link is a 24-hour bearer secret; it is handled like the existing local-user links (shown once, never stored).
- − Device users still enrol at their first device login (decision 5); residual risk RR-139 until a later decision.
- Follow-up: ADR 0007 and ADR 0034 amendments (pointer); `TestIdentityLockAuthentik`-style acceptance gates for the
  denied and the grandfathered path.
