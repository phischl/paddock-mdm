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
| `POST /api/v1/users` | the new user receives root through grants to everyone |
| `PUT /api/v1/devices/{id}/groups` | a user gains root on the device through the assignments of its new device groups |
| `PUT /api/v1/config` (`paddockctl apply`) | the document creates or changes a profile, an assignment or a managed file as above |

Since the amendment of 2026-10-16 (plan M8s decisions 7g–7k and 7g-quater) the rule follows the effect of a change,
measured in *root witnesses*: a root-equivalent command, a pair of a writer and the file it writes and runs, or class
Full. A change to a profile, an assignment or an enrollment token's device group needs an organization administrator
with a fresh step-up (operators get 403 `forbidden`) when the profiles assigned anywhere in the organization together
gain a witness, whoever they are assigned to, or when a real user gains one (giving an approved combination to more
users); a change of Paddock group membership, device groups, approval or
quarantine release needs it when a real user gains a witness on a device, also a user who already has Full. A device that an auto-approve enrollment token
would activate into such a grant is enrolled pending instead and waits for an approval with a step-up. Membership
that arrives from the upstream directory is not gated. Changes that can grant root take a per-organization lock, so
two of them never complete a combination unseen.

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
  (identification, password, authenticator validation with WebAuthn or TOTP — an administrator without an
  authenticator is refused —, login) and the OIDC application `paddock-portal-stepup`, which uses that flow, the
  portal's client secret and the portal's access policy. Authentik has no per-request flow override, hence the
  second application.
- `GET /api/auth/stepup?return_to=` sends the administrator to `paddock-portal-stepup` with `prompt=login`,
  `max_age=60` and the session's username as `login_hint` (the flow skips the identification stage).
- `GET /api/auth/stepup/callback` accepts the ID token only for the same user (`sub`), with `auth_time` at most
  60 s old and MFA in `amr`, and then stores the time and the token ID in the session cookie. Otherwise the session
  stays as it was and the browser returns with `stepup=failed`.

`max_age` is 60, not 0: Authentik ignores `max_age=0` and forces a new login for `prompt=login` only once per
Authentik login, so a second step-up would otherwise receive a token of the first one. With `max_age=60`, a step-up
within 60 s of the previous one reuses it (its `auth_time` is still accepted), any later one authenticates again.
After a step-up that was refused because another account authenticated, Authentik keeps that account's login; the
next step-up asks for credentials again once it is older than 60 s.

## Configuration

`paddock-api` needs `PADDOCK_OIDC_STEPUP_ISSUER`, the issuer of `paddock-portal-stepup`
(`https://auth.<domain>/application/o/paddock-portal-stepup/`); `PADDOCK_OIDC_STEPUP_CLIENT_ID` defaults to
`paddock-portal-stepup`. The api is not ready until both OIDC providers are discovered.

In the development stack `make dev-seed` gives the test users TOTP authenticators whose keys are in
`deploy/compose/.secrets/dev_<user>_totp_key` (hex), so the acceptance gates can complete step-ups. Authentik's
blueprint format cannot set an authenticator's key, so the seeder writes them through Authentik's shell.
