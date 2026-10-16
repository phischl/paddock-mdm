# Step-up authentication

Security-relevant portal actions require a fresh MFA authentication of the administrator, at most 300 s old
(architecture §9.6, plan M4a decisions 6 and 7):

| Action | When |
| --- | --- |
| `PATCH /api/v1/permission-profiles/{id}` | the class changes to `full` |
| `POST /api/v1/profile-assignments` | the profile has class `full` |
| `POST /api/platform/v1/sessions/end-all` | always (platform administrators) |

Without a fresh step-up such a request answers 403 `step_up_required` and records one audit event with outcome
`denied`; a permitted action records the actor with `step_up: true`. The portal sends the administrator through the
step-up and repeats the action once.

## How it works

- The Authentik blueprint `paddock-stepup.yaml` (applied automatically) creates the flow `paddock-stepup`
  (identification, password, authenticator validation with WebAuthn only — an administrator without a WebAuthn
  authenticator is refused, a TOTP authenticator does not count —, login) and the OIDC application `paddock-portal-stepup`, which uses that flow, the
  portal's client secret and the portal's access policy. Authentik has no per-request flow override, hence the
  second application.
- `GET /api/auth/stepup?return_to=` sends the administrator to `paddock-portal-stepup` with `prompt=login`,
  `max_age=60` and the session's username as `login_hint` (the flow skips the identification stage).
- `GET /api/auth/stepup/callback` accepts the ID token only for the same user (`sub`), with `auth_time` at most
  60 s old and MFA in `amr`, and then stores the time and the token ID in the session cookie. Otherwise the session
  stays as it was and the browser returns with `stepup=failed`.
- The callback also requires that the token's `groups` grant the session's role in the session's organization (the
  step-up provider carries the Paddock groups mapping). When they grant another role or none in it, the step-up is
  refused, the account takes the role from the identity provider (or is disabled when it has none there), every
  portal session of it ends and `admin.sessions_revoked` is recorded with reason `step_up_role_mismatch`; the
  administrator signs in again with the current role. A token without `groups`, or a platform session whose groups
  name an organization, is only refused.

`max_age` is 60, not 0: Authentik ignores `max_age=0` and forces a new login for `prompt=login` only once per
Authentik login, so a second step-up would otherwise receive a token of the first one. With `max_age=60`, a step-up
within 60 s of the previous one reuses it (its `auth_time` is still accepted), any later one authenticates again.
After a step-up that was refused because another account authenticated, Authentik keeps that account's login; the
next step-up asks for credentials again once it is older than 60 s.

## Configuration

`paddock-api` needs `PADDOCK_OIDC_STEPUP_ISSUER`, the issuer of `paddock-portal-stepup`
(`https://auth.<domain>/application/o/paddock-portal-stepup/`); `PADDOCK_OIDC_STEPUP_CLIENT_ID` defaults to
`paddock-portal-stepup`. The api is not ready until both OIDC providers are discovered.

## Before upgrading to WebAuthn-only step-up

Earlier versions also accepted a TOTP code at the step-up. Before the upgrade, every administrator enrols a WebAuthn
authenticator (security key or platform authenticator) in Authentik's user settings,
`https://auth.<domain>/if/user/` → MFA devices. After the upgrade an administrator with a TOTP authenticator only
cannot complete a step-up, and so cannot reveal keys, lock or destroy devices, create API tokens or grant
root-equivalent rights, until a WebAuthn authenticator exists. The portal login keeps accepting TOTP.

## Development stack

In the development stack `make dev-seed` gives the test users TOTP authenticators whose keys are in
`deploy/compose/.secrets/dev_<user>_totp_key` (hex), so the acceptance gates can complete step-ups. Authentik's
blueprint format cannot set an authenticator's key, so the seeder writes them through Authentik's shell. Because the
shipped flow validates WebAuthn only, the development blueprint `authentik/dev/paddock-dev.yaml` (mounted by
`compose.dev.yaml` only) skips the WebAuthn stage at order 30 with the policy `paddock-dev-skip-stepup-webauthn` and
binds `paddock-dev-stepup-mfa` (WebAuthn or TOTP) at order 31. Production carries neither.
