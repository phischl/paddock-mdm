# Step-up authentication

Security-relevant portal actions require a fresh MFA authentication of the administrator, at most 300 s old
(architecture §9.6, plan M4a decisions 6 and 7).

**Root grants.** Every change that would give a user root on a device in effect, on its own or in combination with
other grants, needs an organization administrator with a fresh step-up; operators get 403 `forbidden` (ADR 0034
decision 1 and its amendment of 2026-10-16, plan M8s decisions 7g–7k and 7g-quater to 7g-sexies). Paddock measures
root in *root witnesses*: a root-equivalent command, a pair of a writer and the file it writes and runs, or class
Full. A profile is *effectively Full* when its class is `full` or when it is restricted and one of its commands
hands out root on its own or in combination (the catalog of `domain/privilege/rootequiv.go`, shown as "Full
(effective)" in the portal). The requests and when they need the step-up:

| Action | When |
| --- | --- |
| `POST /api/v1/permission-profiles` | the profile is effectively Full |
| `PATCH /api/v1/permission-profiles/{id}` | the profile is effectively Full afterwards and was not before, or its class or commands change; or the change gives anyone a new witness (below) |
| `POST /api/v1/profile-assignments` | the profile is effectively Full, or the assignment gives anyone a new witness |
| `PATCH /api/v1/profile-assignments/{id}` | the profile is effectively Full, or the new scope gives anyone a new witness |
| `PUT /api/v1/config` (`paddockctl apply`) | the document creates or changes a profile or an assignment as above, or a managed file as below |
| `POST /api/v1/user-groups/{id}/members` | the new member gains a witness through the group's assignments |
| `PUT /api/v1/devices/{id}/groups` | a user gains a witness on the device through its new device groups |
| `POST /api/v1/devices/{id}/approve`, `…/release-quarantine` | the device's device groups give a user a witness once it is active |
| `POST /api/v1/enrollment-tokens` | a device enrolled into the token's device group would give a user a witness |
| `POST /api/v1/users` | the new user would receive a witness through grants to everyone |

*Gives anyone a new witness* means either of two checks: the profiles assigned anywhere in the organization
together gain a witness, whoever they are assigned to; or a real user, a future user (no groups, or a member of a
group an assignment names) or a device (every device in any state, and a future device in each device group that
an assignment or a usable auto-approve token names) gains one, also a user who already has Full. A rename or a
change of the password, lecture or timeout settings of an effectively Full profile needs no step-up. A device that
an auto-approve enrollment token would activate into such a grant is enrolled pending instead and waits for an
approval with a step-up (`device.enrolled` records `auto_approve_withheld: root_grant`). Membership that arrives
from the upstream directory, including the members an imported group mirrors, is not gated (residual risk RR-39).
Changes that can grant root take a per-organization lock, so two of them never complete a combination unseen.

Without a fresh step-up such a request answers 403 `step_up_required` and records one audit event with outcome
`denied`; a permitted action records the actor with `step_up: true`. The portal sends the administrator through the
step-up and repeats the action once.

**Managed files.** Paths have three tiers (ADR 0034 decision 2 and its amendment of 2026-10-16, catalog in
`pkg/policy`): *denied* paths are refused with 422 `path_not_allowed`, and existing definitions on them are no longer
shipped to devices; a path below an **operator root** of the organization is *ordinary* and stays with the
`org_operator` role without a step-up, unless it has an execute bit, a script, bytecode, archive or shared-object
suffix (`.so`, `.so.*`, `.py`, `.pyc`, `.pth`, `.sh`, `.bash`, `.zsh`, `.pl`, `.pm`, `.rb`, `.lua`, `.js`, `.mjs`,
`.cjs`, `.php`, `.jar`) or a `.d` directory component; every other path is *sensitive* and needs an organization
administrator with a fresh step-up:

| Action | When |
| --- | --- |
| `POST /api/v1/managed-files` | the path is sensitive (organization administrators only; other roles get 403 `forbidden`) |
| `PATCH /api/v1/managed-files/{id}` | the path is sensitive afterwards, or the file was on a sensitive path and any field changes |

Operator roots are empty by default and are set in the portal (Configuration → Operator roots), with
`PUT /api/v1/settings/managed-files` or in the `settings.managed_files` section of a declarative document, always by
an organization administrator with a step-up (`settings.managed_files_changed`). A root is a directory such as
`/etc/myapp/` or `/opt/vendor/`; the never-operator directories (package managers, boot loader, interpreters,
shells, display managers, audit, MAC frameworks, firewall, network connections and clients, directory and
authentication clients, trust anchors, PAM, identity, service environments, container runtimes, new-user skeletons,
Paddock) are refused below `/etc/` and `/usr/local/etc/` alike. An operator root is a trust decision (residual risk
RR-37). Changing the roots never changes existing definitions; the security review lists files whose tier rose.
Deleting a definition never needs a step-up.

These actions always need a fresh step-up, whatever their content:

| Action | Who |
| --- | --- |
| `POST /api/v1/devices/{id}/local-admin/reveal` | organization administrators |
| `POST /api/v1/devices/{id}/disk/recovery-key`, `POST /api/v1/devices/{id}/disk/header` | organization administrators |
| `POST /api/v1/devices/{id}/lock`, `POST /api/v1/devices/{id}/destroy` | organization administrators |
| `POST /api/v1/revocation-requests/{id}/approve`, `…/reject`, `…/cancel` | organization administrators |
| `POST /api/v1/permission-profiles/{id}/confirm-root-grant` | organization administrators (security review) |
| `POST /api/v1/managed-files/{id}/confirm-sensitive` | organization administrators (security review) |
| `PUT /api/v1/settings/dms` | organization administrators, when the dead man's switch is enabled |
| `POST /api/v1/api-tokens` | organization administrators and operators |
| `POST`, `PATCH`, `DELETE /api/platform/v1/ip-allowlist…` | platform administrators |
| `POST /api/platform/v1/sessions/end-all` | platform administrators |
| `PUT /api/v1/settings/managed-files` | organization administrators (operator roots) |

**API tokens** (ADR 0034 decision 3): a request authenticated with an API token never satisfies a step-up. Such a
request is refused with 403 `step_up_required` and the detail `this change needs an interactive administrator: API
tokens cannot complete a step-up`, recorded as one denied audit event. The GitOps flow is two-step: CI applies
everything else; an administrator applies root-equivalent changes from the portal (`docs/operations/paddockctl.md`).

**Factor.** The shipped step-up flow accepts WebAuthn authenticators only (security key or platform authenticator).
Every administrator, including every new one, enrols a WebAuthn authenticator in Authentik's user settings
(`https://auth.<domain>/if/user/` → MFA devices) before the first step-up. The portal login's MFA stage still offers
TOTP enrolment: an administrator who enrolled only TOTP can sign in but cannot complete a step-up. Paddock checks
`mfa` in the token's `amr`, which does not tell WebAuthn from TOTP; only the Authentik stage enforces the factor
(residual risk RR-38).

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

The portal shows how long the last step-up stays valid: a chip *Confirmed until …* in the app bar and the line
*Identity confirmed until …* in the user menu (*No current identity confirmation* otherwise), from
`step_up_valid_until` of `GET /api/v1/me`; both disappear when the window ends.

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
