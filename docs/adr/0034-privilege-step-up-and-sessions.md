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
  initramfs have no legitimate management use in Paddock and would only ever be a bypass.

### C. API tokens and step-up classes
- **C1 — Tokens may perform Full and tier-S changes after a one-time confirmation at creation.** − Re-opens the
  bypass: a long-lived credential replaces MFA.
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
