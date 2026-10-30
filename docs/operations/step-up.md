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
| `POST /api/platform/v1/sessions/end-all` (also ends every portal user's Authentik sessions) | platform administrators |
| `PUT /api/v1/settings/managed-files` | organization administrators (operator roots) |

**API tokens** (ADR 0034 decision 3): a request authenticated with an API token never satisfies a step-up. Such a
request is refused with 403 `step_up_required` and the detail `this change needs an interactive administrator: API
tokens cannot complete a step-up`, recorded as one denied audit event. The GitOps flow is two-step: CI applies
everything else; an administrator applies root-equivalent changes from the portal (`docs/operations/paddockctl.md`).

**Factor.** The shipped step-up flow accepts WebAuthn authenticators only (security key or platform authenticator).
The portal sign-in requires a passkey: the api accepts a sign-in of any portal role (platform administrator,
organization administrator, operator, auditor) only when the login validated a WebAuthn authenticator (claim
`paddock_mfa_classes` of the portal's ID token, emitted by the mapping `io.paddock/scope-login-mfa` under the scope
`paddock_mfa`), and refuses every other sign-in, a role switch included, with `/login-denied?reason=passkey_required`
and one denied `admin.login` event (error code `passkey_required`; ADR 0034 amendment 2026-10-29). Three stages of the
flow `paddock-admin-login` give every administrator such a login:

- Order 30, `paddock-admin-login-mfa`: the administrator proves an existing authenticator (WebAuthn or TOTP). Authentik
  counts one of the account's recovery codes as the TOTP factor and accepts it here as well. Only an account with no
  WebAuthn or TOTP authenticator enrols a WebAuthn authenticator here, after the password (residual risk RR-62).
- Order 31, `paddock-admin-login-webauthn`: runs only for an account without a WebAuthn device (policy
  `paddock-admin-login-webauthn-missing`) that is a direct member of a portal role group, `paddock.platform.admins`
  or an organization's `admins`, `operators` or `auditors` group (policy
  `paddock-admin-login-webauthn-administrator`, ADR 0034 amendment 2026-10-29): the flow is also the brand's
  sign-in of the device-code page, where end users are not asked to enrol a passkey. An administrator with TOTP only has just proven the TOTP code or entered a
  recovery code and enrols a WebAuthn authenticator now; the password alone never enrols a key for an account with
  TOTP or WebAuthn, but the password and one recovery code do (RR-62: keep administrators' recovery codes in custody).
- Order 32, `paddock-admin-login-webauthn-confirm`: validates WebAuthn only and runs for members of the same groups
  when no WebAuthn authenticator was validated earlier in this sign-in (policy
  `paddock-admin-login-webauthn-unconfirmed`). Authentik records no authenticator for an enrolment, so an administrator
  who has just enrolled at order 30 or 31, or proved TOTP at order 30 although a passkey exists, confirms the passkey
  here once. An administrator who used the passkey at order 30 is not asked again.

A TOTP authenticator stays usable for Authentik's own interfaces and the device login. An administrator who reaches
the portal through an existing Authentik session whose login validated no passkey (Authentik's default sign-in with
TOTP, or a device-code sign-in) never passes these stages: the portal refuses the sign-in with `passkey_required`, and
the denial page offers *Sign out of the identity provider* (Authentik's default invalidation flow). Signing in again
through the portal then runs `paddock-admin-login` and enrols or confirms the passkey. Paddock checks the
authenticator classes the step-up validated (claim `paddock_mfa_classes` of the step-up token, emitted by the mapping
`io.paddock/scope-stepup-mfa`) and refuses every step-up without a WebAuthn authenticator; `amr` alone does not tell
WebAuthn from TOTP (residual risk RR-38). The api logs a refused class list as "step-up rejected … the step-up did not
validate the required authenticator class" with the classes, never the token.

## How it works

- The Authentik blueprint `paddock-stepup.yaml` (applied automatically) creates the flow `paddock-stepup`
  (identification, password, authenticator validation with WebAuthn only — an administrator without a WebAuthn
  authenticator is refused, a TOTP authenticator does not count —, login) and the OIDC application `paddock-portal-stepup`, which uses that flow, the
  portal's client secret and the portal's access policy. Authentik has no per-request flow override, hence the
  second application.
- `GET /api/auth/stepup?return_to=` sends the administrator to `paddock-portal-stepup` with `prompt=login`,
  `max_age=20` and the session's username as `login_hint` (the flow skips the identification stage).
- `GET /api/auth/stepup/callback` accepts the ID token only for the same user (`sub`), with `auth_time` at most
  20 s old and not earlier than the step-up's start, and MFA in `amr`, and then stores the time and the token ID in
  the session cookie. It also requires the class `authentik_stages_authenticator_webauthn.webauthndevice` in the
  token's `paddock_mfa_classes` (the api requests the scope `paddock_stepup` from the step-up provider). Otherwise the
  session stays as it was and the browser returns with `stepup=failed`. Both
  checks compare Authentik's `auth_time` with the api's clock, so the hosts of `paddock-api` and Authentik must keep
  their clocks in sync (NTP): an api clock ahead of Authentik's refuses step-ups, one behind it accepts older logins.
- The callback also requires that the token's `groups` grant the session's role in the session's organization (the
  step-up provider carries the Paddock groups mapping). When they grant another role or none in it, the step-up is
  refused, the account takes the role from the identity provider (or is disabled when it has none there), every
  portal session of it ends and `admin.sessions_revoked` is recorded with reason `step_up_role_mismatch`; the
  administrator signs in again with the current role. A token without `groups`, or a platform session whose groups
  name an organization, is only refused.
- A role switch (user menu) is a new sign-in: the new session starts without a step-up.

The portal shows how long the last step-up stays valid: a chip *Confirmed until …* in the app bar and the line
*Identity confirmed until …* in the user menu (*No current identity confirmation* otherwise), from
`step_up_valid_until` of `GET /api/v1/me`; both disappear when the window ends.

`max_age` is 20, not 0: Authentik ignores `max_age=0` and forces a new login for `prompt=login` only once per
Authentik login, so a second step-up would otherwise receive a token of the first one. With `max_age=20`, any step-up
more than 20 s after the previous Authentik login authenticates again; within 20 s Authentik may hand out the earlier
login, whose `auth_time` predates the step-up, so the callback refuses it and the administrator waits 20 seconds
and tries again. 20 s stays below the 30 s for which the escrow-reader and the revocation-issuer accept a step-up, so
a step-up that is too old for them is always old enough for Authentik to authenticate again.
After a step-up that was refused because another account authenticated, Authentik keeps that account's login; the
next step-up asks for credentials again once it is older than 20 s.

## Configuration

`paddock-api` needs `PADDOCK_OIDC_STEPUP_ISSUER`, the issuer of `paddock-portal-stepup`
(`https://auth.<domain>/application/o/paddock-portal-stepup/`); `PADDOCK_OIDC_STEPUP_CLIENT_ID` defaults to
`paddock-portal-stepup`. The api is not ready until both OIDC providers are discovered.

## Before upgrading to WebAuthn-only step-up

Earlier versions also accepted a TOTP code at the step-up and at the portal sign-in. Every administrator needs a
browser or device with a WebAuthn authenticator (security key, or a platform authenticator such as Windows Hello,
Touch ID, Android, or a phone through the browser's QR code). The portal sign-in now enrols a WebAuthn authenticator
when the administrator has none, after the administrator proved an existing TOTP authenticator or entered one of
its recovery codes (section *Factor*); a
TOTP authenticator stays usable for Authentik's own interfaces and the device login. No enrolment before the upgrade
is required.

### Checking the portal sign-in factor (lab)

The development stack skips both portal sign-in stages, so these cases are checked on a lab installation after the
upgrade, each in a private browser window:

1. An administrator with a TOTP authenticator only signs in through the portal: Authentik asks for the password, then
   for the TOTP code, then for the WebAuthn enrolment; after the enrolment the portal opens and a step-up succeeds.
2. The same kind of account (TOTP only, a second test administrator), with the password but a wrong TOTP code:
   Authentik refuses the code and never offers a WebAuthn enrolment. An unused recovery code of the same account in
   place of the TOTP code is accepted (Authentik counts it as the TOTP factor) and leads to the WebAuthn enrolment;
   the enrolment appears in Authentik's event log (*Events* → `model_created`, WebAuthn device). Regenerate the
   account's recovery codes afterwards.
3. An administrator with a WebAuthn authenticator signs in: Authentik asks for the password and once for the
   authenticator, then the portal opens.
4. A new administrator without any authenticator signs in: Authentik asks for the password and then for the WebAuthn
   enrolment once; the enrolment appears in Authentik's event log (*Events* → `model_created`, WebAuthn device).
5. Authentik's own sign-in (`https://auth.<domain>/if/user/`, flow `default-authentication-flow`). Paddock's stage
   `paddock-default-login-mfa` at order 31 is skipped by the policy `paddock-default-login-mfa-missing` only when
   Authentik's stage at order 30 has validated a TOTP or WebAuthn device in the same sign-in:
   1. A user with TOTP signs in with the TOTP code: Authentik asks for the code once, then the user interface opens.
   2. A user with WebAuthn signs in with the WebAuthn authenticator: Authentik asks for it once, then the user
      interface opens.
   3. A user with TOTP and recovery codes chooses a recovery code at order 30: Authentik then asks again at order 31
      (TOTP code or WebAuthn authenticator) and offers no enrolment. Authentik also accepts a second, unused recovery
      code there, because it counts a recovery code as the TOTP factor. The sign-in therefore finishes only after a
      second factor of the user's own devices, recovery codes included; the password and a single recovery code are
      not enough (a used code is spent). Whoever holds the password and two recovery codes gets a session and can
      enrol a passkey in the user settings (RR-62).
   4. A user without TOTP or WebAuthn (no device, or recovery codes only) is asked to enrol one (WebAuthn or TOTP)
      after the password and any factor order 30 asks for.

## Development stack

In the development stack `make dev-seed` gives the test users TOTP authenticators whose keys are in
`deploy/compose/.secrets/dev_<user>_totp_key` (hex), so the acceptance gates can complete step-ups. Authentik's
blueprint format cannot set an authenticator's key, so the seeder writes them through Authentik's shell. Because the
shipped flow validates WebAuthn only, the development blueprint `authentik/dev/paddock-dev.yaml` (mounted by
`compose.dev.yaml` only) skips the WebAuthn stage at order 30 with the policy `paddock-dev-skip-stepup-webauthn` and
binds `paddock-dev-stepup-mfa` (WebAuthn or TOTP) at order 31. It also skips the portal sign-in stages
(`paddock-admin-login` orders 30, 31 and 32) with the policy `paddock-dev-skip-mfa`; the bindings at orders 31 and 32
evaluate their policies in mode *all*, so the skip wins over the shipped policies. `compose.dev.yaml` sets
`PADDOCK_LOGIN_MFA_OPTIONAL=true`, so the api accepts the development users' sign-ins without a second factor or a
passkey. Production carries neither. `compose.dev.yaml` sets
`PADDOCK_STEPUP_MFA_CLASS=authentik_stages_authenticator_totp.totpdevice` on `paddock-api`, so the api accepts the
development users' TOTP step-ups; the variable is development-only and fails `./paddock check` and the api's start in
production.
