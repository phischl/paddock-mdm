# 0034 — Privilege step-up on the effective class, managed-file path tiers and revocable sessions
Status: Accepted (2026-10-16)

## Context

Paddock asks for a fresh MFA step-up before an administrator hands out root (architecture §9.6, plan M4a decision 7).
Today the check keys on the *label* of a permission profile (`class = full`), although the domain already computes
an *effective* class: a restricted profile whose commands are root-equivalent is reported as Full
(`privilege.Effective`, `ReportedClass`). Managed files (plan M2a decision 8) are admitted everywhere below `/etc/`,
`/usr/local/etc/` and `/opt/` except a short list of protected paths, with the operator role and no step-up, although
many of those paths run code as root or change identity, boot or loader configuration. API tokens carry the operator
role and can use both. Portal sessions are stateless cookies: logout only clears the browser, and a lost role stays
in force until the session expires. The step-up flow accepts TOTP, while the architecture says WebAuthn.

These are policy decisions that several milestones build on (M10 instruments sessions, M11 classifies configuration
changes). They are decided here, once, and implemented by plan M8s.

## Options

### A. Where the step-up keys on
- **A1 — Class label (status quo).** + No change. − The effective class is already computed and shown as a
  warning, but not enforced; a restricted profile with a shell is Full in effect.
- **A2 — Effective class.** + One rule for both label and content; the catalog in
  `domain/privilege/rootequiv.go` stays the single source of truth. − Adding a root-equivalent command to an
  already root-equivalent profile needs a step-up too (intended: it is a grant to everyone the profile is assigned
  to). **Chosen.**

### B. Managed-file path policy
- **B1 — Keep the deny list, extend it.** + Small change. − A deny list over `/etc/` keeps missing paths; the last
  review found a dozen.
- **B2 — Three tiers with an allow list of roots.** Denied (D): paths that bypass a protected area or Paddock itself.
  Sensitive (S): root-equivalent but legitimate management tasks; organization administrator with step-up.
  Ordinary (O): application configuration; operator. Everything not matched by an allow list of roots is denied.
  + Explicit; reviewable; the agent keeps its defence-in-depth check on D. − Existing definitions on D paths stop
  being shipped and must be reviewed. **Chosen.**
- **B3 — Two tiers (ordinary, sensitive) without outright denial.** − Paths such as the loader configuration or the
  initramfs have no legitimate management use in Paddock and would only ever circumvent a protected area.

### C. API tokens and step-up classes
- **C1 — Tokens may perform Full and tier-S changes after a one-time confirmation at creation.** − A long-lived
  credential would replace MFA.
- **C2 — Tokens are refused for every change that needs a step-up.** + A token cannot complete a step-up by
  construction; the rule is simple and stable. − GitOps pipelines need an interactive second step for root-equivalent
  changes. **Chosen.** A short-lived, step-up-bound session token for `paddockctl` is a later feature and needs its
  own decision.

### D. Session lifecycle
- **D1 — Stateless cookie, shorter lifetimes.** + No new state. − Logout and deactivation still do not end a
  session; only the window shrinks.
- **D2 — Server-side session records in Valkey.** The cookie keeps its AEAD payload and gains a session ID; the api
  looks the record up on every request. Logout deletes it; a role change, a deactivation or a step-up role mismatch
  deletes every record of the account; a platform action ends every session. + Immediate effect; one round trip to
  a store the api already uses. − Sessions depend on Valkey (fail closed with 503 for the portal; devices are not
  affected). **Chosen.**
- **D3 — Account re-validation against PostgreSQL on every request, no store.** + No Valkey dependency. − Does not
  end a session on logout or for a copied cookie; `admin_account` is only written at login.

### E. Role check at the step-up
- **E1 — Subject, `auth_time` and `amr` only (status quo).** − An administrator removed from the admin group can
  still complete a step-up while the session lives.
- **E2 — Re-resolve the role from the step-up ID token's `groups` claim** with the same resolution as at login and
  refuse on any difference. + Every high-risk action is bounded by a group check that is at most 5 minutes old.
  **Chosen.** The step-up provider gets the Paddock `groups` scope mapping explicitly; a token without the claim is
  refused.

### F. Step-up factor (AU-2)
- **F1 — Keep TOTP in the step-up flow, amend the architecture.** + No migration for administrators. − TOTP can be
  relayed in real time; the step-up gates Destroy, reveals and token creation.
- **F2 — WebAuthn only in the shipped blueprint; the development stack adds a TOTP stage through the development
  blueprint that only `compose.dev.yaml` mounts.** + Matches the architecture; production carries no switch; the
  acceptance gates keep their scripted TOTP. − Administrators who enrolled only TOTP must enrol a WebAuthn
  authenticator before the upgrade (migration note). **Chosen; in scope of M8s.**

### G. Existing data
- **G1 — Forced re-confirmation:** withdraw unconfirmed root grants and stop shipping tier-S files until confirmed.
  − Fail-unsafe for a fix release; breaks users' work.
- **G2 — Review without withdrawal.** Existing root-equivalent profiles and tier-S files keep working and are listed
  for review until an organization administrator confirms them with a step-up. Files on tier-D paths are no longer
  shipped; the agent keeps the file on the device and stops tracking it. **Chosen.**

## Decision

1. **Step-up on the effective class.** A profile *needs a step-up* when `privilege.RequiresStepUp(p)` is true:
   its class is `full`, or its class is `restricted` and `RootEquivalentCommands(p.Commands)` is not empty. The
   check applies when such a profile is created; when a profile becomes one, or already is one and its class or
   command list changes; when such a profile is assigned, and when the scope of such an assignment changes. The
   declarative path (`PUT /api/v1/config`, `paddockctl apply`) applies the same rule. Audit events of these actions
   carry `effective_class`.
2. **Managed-file path tiers.** `pkg/policy` classifies every path and mode into denied, sensitive or ordinary from
   one catalog (plan M8s §6.2 lists it). The server refuses denied paths (422 `path_not_allowed`), requires the
   `org_admin` role and a step-up for sensitive paths, and keeps `RolesWrite` for ordinary paths. The agent refuses
   only denied paths and never deletes a file on a denied path, not even one it wrote. Any file with an execute bit
   is sensitive wherever it lies; a file directly in `/etc/` and any `/etc/*.d/` directory not in the catalog is
   sensitive by default. Audit events of managed files carry `tier`.
3. **API tokens.** A request authenticated with an API token never satisfies a step-up. Such a request is refused
   with 403 `step_up_required` and the detail `this change needs an interactive administrator: API tokens cannot
   complete a step-up`, recorded as one denied audit event. The GitOps flow is two-step: CI applies everything
   else; an administrator applies root-equivalent changes from the portal.
4. **Server-side sessions.** The api keeps one record per session in Valkey (`sess:<sid>`, TTL = remaining
   absolute lifetime) and a set per account (`acct-sess:<account_id>`). The session cookie (payload version 2)
   carries `sid`. Every request looks the record up; a missing record is 401; a Valkey error is 503
   `session_store_unavailable`. Logout deletes the record. A step-up role mismatch, a role change or a deactivation
   found by the worker deletes every record of the account and records `admin.sessions_revoked`. A platform
   administrator ends every session with `POST /api/platform/v1/sessions/end-all` (step-up required, recorded as
   `platform.sessions_ended`), implemented as a generation counter every record is compared with. The absolute
   lifetime stays 8 h, the idle timeout 30 min.
5. **Role at the step-up.** The step-up callback resolves the role from the ID token's `groups` claim with the
   login's `ResolveRole`. A different role or organization, or a missing claim, refuses the step-up, writes the
   resolved role (or marks the account disabled) to `admin_account`, and revokes the account's sessions. The
   escrow-reader's existing `admin_account` check then refuses decryptions as well.
6. **WebAuthn-only step-up.** `paddock-stepup.yaml` validates with `device_classes: [webauthn]`. The development
   blueprint (`deploy/compose/authentik/dev/`, mounted by `compose.dev.yaml` only) adds a second validation stage
   with TOTP for the dev users and skips the WebAuthn stage with an always-false policy, the pattern the portal
   login already uses in development.
7. **Existing data.** Migration `00045` adds `root_grant_confirmed_at/by` to `permission_profile` and
   `sensitive_confirmed_at/by` to `managed_file`; a step-up-confirmed create or update sets them. Unconfirmed rows
   are listed by `GET /api/v1/security-review` and shown on the overview; `POST …/confirm-root-grant` and
   `POST …/confirm-sensitive` (organization administrator, step-up) confirm them. Nothing is withdrawn from devices.
   `paddock-server admin security-review` records one `organization.security_review_required` event per organization
   with the counts, so that the review has a start in the audit trail.
8. **Compatibility (ADR 0013).** The bundle format does not change. An agent older than M8s keeps the looser path
   check and deletes an unchanged file that left the bundle; the server enforces first, so the only effect of the
   rollout window is on devices whose definitions were on denied paths, and those are listed for review.

## Consequences

- Positive: the step-up rule follows what a profile *does*; the path catalog is explicit and tested by property
  tests; a stolen cookie or a lost role ends with the next request; the step-up factor matches the architecture.
- Negative: the portal depends on Valkey (devices do not); administrators with only TOTP must enrol WebAuthn before
  the upgrade; GitOps users apply root-equivalent changes interactively; existing definitions on denied paths stop
  being shipped and need a manual clean-up on devices.
- Follow-up: M11 (configuration apply, revert, staged rollout) MUST treat a revert of a step-up change as a
  step-up change; a step-up-bound short-lived token for `paddockctl` needs a separate decision; the Valkey ACL
  split per role (AZ-4) narrows who can write `sess:*` and is planned for the later hardening milestone; the
  automated monthly session-key rotation (CK-1) stays a manual runbook until then.
- Amended documents: architecture §9.6; plan M4a decision 7; plan M2a decision 8; ADR 0003 (Valkey holds session
  records); ADR 0007 (step-up provider emits the Paddock groups claim; WebAuthn-only step-up); ADR 0013 (agent-side
  policy tightening during a rollout).

## Amendment 2026-10-16 — operator roots instead of an ordinary tier by default

The review of the implementation showed that "ordinary unless catalogued" (decision 2) keeps missing root-equivalent
paths below `/etc/`, `/usr/local/etc/` and `/opt/` (package-manager, boot-loader, interpreter, shell, display-manager
and audit plug-in configuration, shared objects and scripts of vendor software). A deny or sensitive catalog over
those roots can never be complete. Decision 2 is therefore narrowed:

- **Sensitive is the default.** Every path that is not denied is *sensitive* (organization administrator with a
  fresh step-up) unless it lies below an **operator root**.
- **Operator roots** are a per-organization list of directory prefixes, empty by default, set only by an
  organization administrator with a fresh step-up (audited, never through an API token). A root MUST be a directory
  below `/etc/<name>/`, `/usr/local/etc/<name>/` or `/opt/<name>/`, MUST NOT be or contain a denied or catalogued
  sensitive path, and MUST NOT be one of the never-operator directories of the plan (package managers, boot loader,
  interpreters, login shells, display managers, audit, MAC frameworks, firewall, network connections, trust
  anchors, PAM and identity configuration).
- **Below an operator root** a file is *ordinary* (operator, no step-up) unless it has an execute bit, a script or
  shared-object suffix, or a `.d` directory component; those stay *sensitive*.
- The agent is unchanged: it enforces *denied* only. Existing definitions keep working on devices; only who may
  change them narrows (fail safe).

The upgrade order becomes binding: agents first, then the server. A pre-M8s agent removes a file that leaves its
bundle, so a server that stops shipping denied files must not reach devices before their agents know `left_denied_file`.

## Amendment 2026-10-17 (M8x, lab finding L9 / PDK-202) — second factor at login
The login callback applies the step-up's rule to the sign-in itself: an ID token whose `amr` lacks `mfa` is refused
(`admin.login` denied, error code `mfa_required`); an existing Authentik session satisfies the portal sign-in only
with such a token (the brand's authentication flow and the default-flow MFA stage of ADR 0007 make every session
carry one). The development stack, whose login flow skips the validation stage, sets
`PADDOCK_LOGIN_MFA_OPTIONAL=true` for the api; the variable is refused outside `PADDOCK_ENV=development` and is a
production-check finding like `PADDOCK_STEPUP_*`. The portal exposes `step_up_valid_until` in `GET /api/v1/me` so
that an administrator sees how long the current step-up satisfies privileged actions.

## Amendment 2026-10-17 (M8x, CI of PR #82) — step-up `auth_time` must not precede the step-up start
The portal login briefly requested `prompt=login`. Authentik 2026.8.3 honours `prompt=login` through the session
key `authentik/providers/oauth2/last_login_uid` (`authorize.py` 540–560) and never clears it: after a forced
re-login, the next step-up's `prompt=login` found the stale key and a login event younger than `max_age`, and
Authentik issued the step-up token for that login event without running `paddock-stepup` — a silent step-up pass
within 60 s of a portal login that skipped the WebAuthn-only factor (and a login flow that ran twice on a fresh
browser). Decisions: (A) the portal login sends no `prompt` (ADR 0007 amendment of the same date); (B) the step-up
callback refuses an ID token whose `auth_time` is missing or earlier than the step-up start, compared in whole
seconds (`auth_time >= started_at`), next to the existing subject, `max_age` and `amr` checks. (B) holds whatever
Authentik does with `prompt`: a token for a login event older than the step-up start never satisfies a step-up.

## Amendment 2026-10-18 (M8f) — step-up factor proven in Paddock, `max_age` 20 s, WebAuthn-only portal login, end-all ends Authentik sessions
Context (Authentik 2026.8.3 sources, plan M8f §2): the ID token's `amr` says `mfa` for WebAuthn and TOTP alike; a
held authorize URL of a started step-up can be satisfied by a later TOTP sign-in through any Authentik flow reachable
by slug (`last_login_uid` set by the first pass, `auth_time` after the start), so decision 6 was enforced by the
Authentik stage alone (RR-38). `max_age=60` collided with the 30 s window of the escrow-reader and the
revocation-issuer: a repeated step-up between 30 s and 60 s after the previous one was refused. New administrators
could enrol TOTP at the portal login and were refused at every step-up (PDK-181). After *end all sessions* a live
Authentik session signed in again without a prompt (PDK-190).

Decisions:
1. **Factor claim.** The step-up provider carries the Paddock mapping `io.paddock/scope-stepup-mfa` (scope
   `paddock_stepup`), which emits `paddock_mfa_classes`: the `<app>.<model_name>` of every authenticator the
   session's login event validated (`auth_method_args.mfa_devices`, the same event Authentik uses for `amr`). The
   step-up callback refuses a token whose claim is missing or does not contain
   `authentik_stages_authenticator_webauthn.webauthndevice`. The development stack sets the required class to the TOTP
   device through `PADDOCK_STEPUP_MFA_CLASS` (development only, a production-check finding). Options weighed: binding
   the token to the step-up *flow* (the login event does not record the flow; an expression policy would have to
   mutate the plan context — fragile); `ak_user_has_authenticator` (says the user *has* a WebAuthn device, not that it
   was *used*); keeping the Authentik-only enforcement (status quo, RR-38). Chosen: the factor used, read from the login
   event. The escrow-reader and the revocation-issuer keep verifying `amr` on the proof token; they receive it only
   after the api accepted the step-up.
2. **`max_age` is 20 s** (`StepUpMaxAuthAge`): below the shortest consumer window (30 s), so a step-up that is too old
   for the escrow-reader is always old enough for Authentik to run `paddock-stepup` again; 10 s remain for clock skew.
3. **WebAuthn enrolment at the portal login, after an existing factor.** Stage A, `paddock-admin-login-mfa` at
   order 30, validates `[webauthn, totp]` and configures only the WebAuthn setup stage, which Authentik runs only for
   an account without any authenticator of these classes. Stage B, `paddock-admin-login-webauthn` at order 31,
   validates `[webauthn]` and configures the WebAuthn setup; an expression policy on its binding
   (`re_evaluate_policies`, mode *all*) runs it only for an account without a WebAuthn device. An administrator with
   TOTP only therefore proves TOTP and then enrols WebAuthn; the password alone never enrols a key for an account with
   an authenticator. A `last_auth_threshold` on stage B was rejected: Authentik binds the MFA cookie to the stage that
   set it (`check_mfa_cookie`), so it would ask a WebAuthn administrator twice. The first enrolment of an account with
   no authenticator still follows the password alone (RR-62). The default-flow stage (every Authentik user) and the
   device-login stages keep both classes. The pre-upgrade enrolment note of decision 6 is superseded by the enrolment
   at sign-in.
   *Note 2026-10-18 (M8f Review 3, B3): recovery codes count as a second factor; decided by the maintainer
   2026-10-18 (option a).* Authentik accepts one of the account's recovery codes wherever it asks for a TOTP code, so
   "proves TOTP" in this decision includes entering a recovery code: the password and one recovery code of a TOTP-only
   administrator enrol WebAuthn in stage B. No deny stage enforces the factor class; RR-62 names the risk and the
   custody of administrators' recovery codes.
4. **End all sessions** (decision 4) also deletes the identity provider's authenticated sessions of every portal user
   (platform administrators and the three role groups of every organization) through Authentik's
   `core/authenticated_sessions/bulk_delete`, inside the same audited action, run as its external part
   (`ActionRunner.RunExternal`: the started action is committed before Valkey and Authentik are called, so a crash
   leaves an action the reaper records as `unknown`; the Authentik part has 80 s, below the 120 s HTTP write timeout);
   the service account gains the two session
   permissions. A single account's revocation (role change, step-up mismatch, deactivation) stays Paddock-only: the
   account signs in again with its current role, and a deactivation already ended everything in Authentik.

Consequences: RR-38 is reworded (the factor now depends on Authentik's login event, not on its stage alone); RR-62
(WebAuthn-capable browser needed) and RR-66 (end-all scope) are added; `docs/operations/step-up.md` and the upgrade
runbook change; plan M8f implements (PDK-297, PDK-299, PDK-181, PDK-190).
