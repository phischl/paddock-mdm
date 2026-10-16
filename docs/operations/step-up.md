# Step-up authentication

Security-relevant portal actions require a fresh MFA authentication of the administrator, at most 300 s old
(architecture §9.6, plan M4a decisions 6 and 7):

| Action | When |
| --- | --- |
| `POST /api/v1/permission-profiles` | the profile is effectively Full |
| `PATCH /api/v1/permission-profiles/{id}` | the profile is effectively Full afterwards and was not before, or its class or commands change |
| `POST /api/v1/profile-assignments` | the profile is effectively Full |
| `PATCH /api/v1/profile-assignments/{id}` | the profile is effectively Full |
| `POST /api/v1/managed-files` | the path is sensitive (organization administrators only; other roles get 403 `forbidden`) |
| `PATCH /api/v1/managed-files/{id}` | the path is sensitive afterwards, or the file was on a sensitive path and any field changes |
| `POST /api/v1/user-groups/{id}/members` | the new member gains root on a device through the group's assignments |
| `POST /api/v1/enrollment-tokens` | a device enrolled into the token's device group would give a user root |
| `POST /api/v1/devices/{id}/approve`, `…/release-quarantine` | the device's device groups give a user root once it is active |
| `PUT /api/v1/devices/{id}/groups` | a user gains root on the device through the assignments of its new device groups |
| `PUT /api/v1/config` (`paddockctl apply`) | the document creates or changes a profile, an assignment or a managed file as above |
| `POST /api/platform/v1/sessions/end-all` | always (platform administrators) |

Since the amendment of 2026-10-16 (plan M8s decisions 7g–7k) the rule follows the effect of a change: a change that
gives any user root on a device or device group where the user did not have it before needs an organization
administrator with a fresh step-up (operators get 403 `forbidden`), also when no single profile is effectively Full
but the merged commands of several profiles form a root-equivalent pair (a writer and the file it writes and runs).
Membership that arrives from the upstream directory is not gated. Changes that can grant root take a per-organization
lock, so two of them never complete a combination unseen.

A profile is *effectively Full* when its class is `full` or when it is restricted and one of its commands hands out
root on its own or in combination (the catalog of `domain/privilege/rootequiv.go`, shown as "Full (effective)" in
the portal; ADR 0034 decision 1). A rename or a change of the password, lecture or timeout settings of such a
profile needs no step-up.

Without a fresh step-up such a request answers 403 `step_up_required` and records one audit event with outcome
`denied`; a permitted action records the actor with `step_up: true`. The portal sends the administrator through the
step-up and repeats the action once.

Managed-file paths have three tiers (ADR 0034 decision 2 and its amendment of 2026-10-16, catalog in `pkg/policy`):
*denied* paths are refused with 422 `path_not_allowed`, and existing definitions on them are no longer shipped to
devices; a path below an **operator root** of the organization is *ordinary* and stays with the `org_operator` role
without a step-up, unless it has an execute bit, a script or shared-object suffix (`.so`, `.so.*`, `.py`, `.pth`,
`.sh`, `.pl`, `.rb`, `.lua`, `.js`) or a `.d` directory component; every other path is *sensitive* and needs the
rule above. Operator roots are empty by default and are set in the portal (Configuration → Operator roots), with
`PUT /api/v1/settings/managed-files` or in the `settings.managed_files` section of a declarative document, always by
an organization administrator with a step-up (`settings.managed_files_changed`). A root is a directory such as
`/etc/myapp/` or `/opt/vendor/`; the never-operator directories (package managers, boot loader, interpreters, shells,
display managers, audit, MAC frameworks, firewall, network connections, trust anchors, PAM, identity, Paddock) are
refused. Changing the roots never changes existing definitions; the security review lists files whose tier rose.
Deleting a definition never needs a step-up.

| Action | When |
| --- | --- |
| `PUT /api/v1/settings/managed-files` | always (organization administrators only) |

An API token cannot complete a step-up (ADR 0034 decision 3): a request made with a token that needs one answers 403
`step_up_required` with the detail `this change needs an interactive administrator: API tokens cannot complete a
step-up`. A pipeline applies such changes in a second, interactive step.

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
