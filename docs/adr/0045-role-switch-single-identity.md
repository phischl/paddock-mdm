# 0045 — One identity with the platform role and one organization role: active role per session, explicit switch
Status: Accepted (architect, 2026-10-26; maintainer decision of 2026-10-26: PDK-201 ships in 0.1.0-alpha.6)

## Context

`organization.ResolveRole` (ADR 0007, plan M0 §6.7) maps the `groups` claim of an ID token to exactly one portal
role and denies an identity that is a member of `paddock.platform.admins` **and** of an organization role group
(`/login-denied?reason=platform_and_organization`). The maintainer's real-world setup is one central identity
(Entra ID through Authentik) that must administer the platform and one organization; the workaround — a second,
local Authentik account — bypasses central identity management, which is the opposite of what Paddock promises
(architecture §9.1). The maintainer decided on 2026-10-26 that the role switch (PDK-201) ships in 0.1.0-alpha.6
with the smallest scope that solves this.

Facts about the code that bound the design (checked 2026-10-26, `main` at `313ac96a`):

- `admin_account.authentik_sub` and `platform_admin.authentik_sub` are each `UNIQUE` (`00001_init.sql`): one identity
  has at most one organization account (in one organization) and at most one platform-administrator row. The two
  rows have different IDs and live in different pools (`paddock_platform` vs. the RLS-governed organization pool).
- A portal session is one cookie (`admin.Session`: `sid, sub, pid, kind, role, org, …`) plus one record in Valkey
  (`sessions.Record{AccountID, Kind, Role, Org, Gen, CreatedAt}` under `sess:<sid>`, in the set
  `acct-sess:<account_id>`; ADR 0034 decision 4). `Session.Validate` refuses a cookie whose `kind` and `org`
  disagree; `recordMatches` refuses a record whose account, role or organization differs from the cookie. The
  principal of a request is built from the cookie alone (`Session.Principal`), so a request carries exactly one
  `Kind`, one `Role` and one `OrganizationID`; `RequireOrg`/`RequirePlatform` and the pools follow from `Kind`.
- The login callback (`bff.callback`) resolves the role, calls `app.Accounts.Login` (which upserts the account row and
  records `admin.login` in the new role's scope) and opens the session record inside the login's transaction.
  Authentik's redirect to `/api/auth/callback` is a cross-site navigation: the `SameSite=Strict` session cookie is
  **not** sent with it; only the `paddock_login` cookie (`SameSite=Lax`, path `/api/auth`) is. The step-up uses the
  same trick and carries the session in its own cookie.
- The step-up callback re-resolves the role from the step-up token's `groups` claim and refuses a role that differs
  from the session's (ADR 0034 decision 5, `checkStepUpRole`); a mismatch of an organization session also rewrites or
  disables the account and ends every session of it (`Accounts.StepUpMismatch`).
- The worker reconciles organization accounts against the organization's three role groups and platform
  administrators against `paddock.platform.admins` separately (`AdminAccounts.Reconcile`, `ReconcilePlatform`,
  PDK-111/PDK-185): the organization round only ever sees the organization's groups, the platform round only the
  platform group. Neither calls `ResolveRole` with a mixed group list.
- ADR 0044 (MCP, 0.1.0-alpha.7, not implemented yet) resolves the role at `POST /api/auth/mcp/session` with the same
  `ResolveRole` and keeps one `sessions.Record` per MCP login; it requires "one role per session" from PDK-201.
- The portal shows the role in the user menu (`App.vue`, `roleLabel`) and names a refused sign-in's reason on
  `/login-denied` (`LoginDenied.vue`, keys `loginDenied.<reason>`).

## Options

### A. Which role combinations one identity may hold
- **A1 — platform role plus exactly one organization role** (the organization part follows today's rule: exactly
  one role group of exactly one organization). + Matches the database (`authentik_sub` unique per table), the two
  pools and the two worker rounds; no migration; the only new combination is the one the maintainer needs.
  **Chosen.**
- **A2 — several organizations per identity.** − `admin_account.authentik_sub` would have to become unique per
  organization (migration of a protected invariant), every `GetAdminAccountBySubject` call site and the worker's
  account reconciliation would change, and the MCP login would need an organization choice too. No requirement
  asks for it. **Rejected for alpha.6; the denial `multiple_organizations` stays.**

### B. How the active role is chosen at sign-in
- **B1 — picker page after the login callback.** + Explicit from the first sign-in. − A pending-login state (the
  resolved groups) must be kept in a sealed cookie between the callback and the choice, a new page and a new
  endpoint are needed, and every automation (acceptance helpers, `paddockctl mcp login`) must learn the extra step.
- **B2 — default role plus an explicit switch.** The sign-in lands in the **organization role**; the user menu
  offers *Switch to platform administration* (and back). + One mechanism for both directions; a sign-in of a
  two-role identity differs from today's organization sign-in only by the menu entry; the default is the
  least-reaching role for Paddock's purpose (the organization role sees one organization, the platform role sees
  every organization's existence, releases and the installation's sessions). − The platform role needs one more
  click after sign-in. **Chosen.**

### C. How the switch works
- **C1 — re-issue the cookie with the other role, same session.** − Re-uses a session that was opened for another
  account row and another pool; the step-up state and the record would have to be rewritten; "one role per session"
  (ADR 0044) would hold only by convention.
- **C2 — a new sign-in through Authentik that ends the previous session.** `POST /api/auth/switch` (CSRF-protected
  like logout) seals the current session and the chosen role into the `paddock_login` cookie and answers the
  authorization URL; the callback runs the normal login for the chosen role and, inside the login's transaction,
  deletes the previous session's record. + The new session is a fresh login by construction: new `sid`, new record,
  no step-up (`StepUpAt` zero), the other account row, the other pool; the previous session is gone before the
  `admin.login` event commits; Authentik re-validates the identity (an existing Authentik session satisfies it only
  with `mfa` in `amr`, ADR 0007 amendment 2026-10-17). − One Authentik round trip per switch (sub-second with a live
  Authentik session). **Chosen.**
- **C3 — require a step-up for the switch itself.** − The switch grants nothing the identity does not already hold
  in Authentik, and every privileged action of the new session needs its own fresh step-up anyway (C2). Rejected.

### D. Audit of a switch
- **D1 — `admin.login` of the new session with `previous_role`.** One event per switch, recorded where every login
  is recorded (the new role's scope), with the role that was left. + Exactly one event, no new code. **Chosen.**
- **D2 — a new code `admin.role_switched` next to `admin.login`.** − Two events for one action, or a login that is
  not recorded as a login.

### E. MCP sessions (ADR 0044)
- **E1 — the MCP login chooses the role once, at `paddockctl mcp login`; default organization; platform only with
  `--platform`.** The session carries that one role for its whole life (renewals repeat the choice); switching
  means `paddockctl mcp login` again. + Fits ADR 0044 A2 unchanged (one record, one role); the safe default is the
  organization role; an assistant can never widen its own scope — the choice is made by the human on the command
  line before any tool runs. **Chosen.**
- **E2 — a switch tool or `alternate_role` for MCP sessions.** − A prompt-injected "switch to platform" is exactly
  the scope widening ADR 0044 §H forbids. Rejected.

## Decision

1. **Allowed combinations.** An identity holds either one platform role, or one organization role (one role group of
   one organization), or **both** — the platform role plus exactly one organization role. `multiple_organizations`
   and `multiple_roles` stay denials, also when the identity is a platform administrator in addition (fail closed:
   an identity whose organization part is ambiguous gets no role at all, not even the platform role).
   `platform_and_organization` is no longer a denial reason.
2. **Resolution.** `ResolveRole` returns, for a two-role identity, a resolution with `Choices =
   [platform, organization]` that a caller **must narrow** with `RoleResolution.Active(choice)` before using it; a
   `LoginRole` that still names both roles is refused by `Accounts.Login` with an error (never a session).
3. **Sign-in default and switch.** The portal sign-in of a two-role identity lands in the **organization role**. The
   session remembers the other role (`alt_role`, `alt_slug` in the cookie payload) and `GET /api/v1/me` answers it
   as `alternate_role`; the user menu offers the switch. The switch is `POST /api/auth/switch` → authorization URL →
   `GET /api/auth/callback`: a **new session** (new `sid`, new record, the other account row, no step-up), the
   **previous session's record deleted inside the login's transaction** (a copy of the old cookie answers 401 from
   then on), and **one audit event**: the `admin.login` of the new session with the param `previous_role`. A switch
   whose chosen role the fresh `groups` claim no longer grants is refused with `/login-denied?reason=role_not_granted`
   and one `admin.login` denied event; the previous session is left untouched.
4. **One role per request, always.** Nothing changes in how a request is authorised: the principal is built from one
   session cookie with one `Kind`, one `Role` and one `OrganizationID`; a platform session uses the platform pool
   only, an organization session the organization pool under RLS only. The two account rows of a two-role identity
   are two accounts with two session sets; revoking one (worker, step-up mismatch) never touches the other.
5. **Session model (ADR 0034 decision 4).** `sessions.Record` is unchanged. The cookie payload (version 2) gains the
   optional fields `alt_role` and `alt_slug`; a cookie without them is a single-role session. The step-up callback
   refreshes them from the step-up token's groups, so the menu follows the identity provider at every step-up.
6. **Step-up role check (ADR 0034 decision 5).** The step-up callback narrows the step-up token's resolution to the
   session's role (`Active(platform)` for a platform session, `Active(organization)` for an organization session)
   and compares as before. A two-role identity therefore steps up in either session; an identity that lost the
   session's role is refused as today, and an organization session whose organization part changed still rewrites
   or disables the account and ends its sessions.
7. **MCP (ADR 0044).** `POST /api/auth/mcp/session` takes `role: "platform" | "organization"` (default
   `organization`), narrows with `Active` exactly like the portal callback, and refuses a role the groups do not grant
   with 403 `forbidden`, detail `role_not_granted`, one `admin.login` denied event. `paddockctl mcp login --platform`
   sends `role: platform`; the session file stores the choice and every renewal repeats it. An MCP session has no
   `alternate_role` (`GET /api/v1/me` answers `null`) and no switch; `paddockctl mcp login` again chooses anew.
8. **Worker and role-membership audit (PDK-111, PDK-185).** No change: the organization round and the platform round
   keep reconciling their own group memberships, and the role-membership audit records each group's grants and
   revocations as before. A regression test pins that `ResolveRole` with an organization's groups plus the platform
   group still yields the organization role for the organization round.
9. **Devices and API tokens** keep one role; an API token is created in an organization session and is unaffected
   by a switch of its creator (it acts with its own stored role and organization).

## Specification (binding for PDK-201 and PDK-450)

### Domain — `server/internal/domain/organization/role.go`

```go
// RoleChoice names the role an identity with the platform role and an organization role acts in (ADR 0045).
type RoleChoice string

const (
	ChoicePlatform     RoleChoice = "platform"
	ChoiceOrganization RoleChoice = "organization"
)

// Denial reasons of ResolveRole (DenialPlatformAndOrganization is removed).
const (
	DenialNoRole                DenialReason = "no_role"
	DenialMultipleOrganizations DenialReason = "multiple_organizations"
	DenialMultipleRoles         DenialReason = "multiple_roles"
	// DenialRoleNotGranted: the caller asked for a RoleChoice the groups do not grant (switch, MCP login).
	DenialRoleNotGranted DenialReason = "role_not_granted"
)

type RoleResolution struct {
	Platform bool
	Slug     string
	Role     principal.Role
	Denied   bool
	Slugs    []string
	Reason   DenialReason
	// Choices is set for an identity in paddock.platform.admins and exactly one organization role group:
	// [ChoicePlatform, ChoiceOrganization]. Platform is then true and Slug and Role name the organization role.
	// A resolution with Choices MUST be narrowed with Active before it is used.
	Choices []RoleChoice
}

// Active narrows the resolution to one role. A denied resolution is never active. A single-role resolution is
// active for c == "" and for the choice that names its role (ChoicePlatform for a platform resolution,
// ChoiceOrganization for an organization resolution). A two-role resolution is active for either of its Choices
// and never for c == "". The result has no Choices; Slugs is kept.
func (r RoleResolution) Active(c RoleChoice) (RoleResolution, bool)

// Alternate returns the role and organization slug an identity may switch to from active (a resolution narrowed
// with Active): ("platform_admin", "") from an organization session, (<organization role>, <slug>) from a platform
// session, ("", "") for a single-role identity.
func (r RoleResolution) Alternate(active RoleChoice) (role principal.Role, slug string)
```

`ResolveRole` results (`Slugs` as today):

| groups | result |
| --- | --- |
| `paddock.platform.admins` | `{Platform: true, Role: platform_admin}` |
| `paddock.acme.admins` | `{Slug: acme, Role: org_admin, Slugs: [acme]}` |
| `paddock.platform.admins`, `paddock.acme.admins` | `{Platform: true, Slug: acme, Role: org_admin, Slugs: [acme], Choices: [platform, organization]}` |
| `paddock.platform.admins`, `paddock.acme.admins`, `paddock.globex.admins` | `{Denied: true, Slugs: [acme, globex], Reason: multiple_organizations}` |
| `paddock.platform.admins`, `paddock.acme.admins`, `paddock.acme.auditors` | `{Denied: true, Slugs: [acme], Reason: multiple_roles}` |

`Active` on the two-role result: `Active(platform)` → `{Platform: true, Role: platform_admin, Slugs: [acme]}`,
`Active(organization)` → `{Slug: acme, Role: org_admin, Slugs: [acme]}`, `Active("")` → `ok == false`.
`Active` on `{Slug: acme, Role: org_admin, Slugs: [acme]}`: `Active("")` and `Active(organization)` → itself,
`Active(platform)` → `ok == false`. `Active` on a denied resolution → `ok == false` for every `c`.

### Login use case — `server/internal/app/accounts.go`

```go
type LoginIdentity struct {
	Subject, Username, Name, IP string
	OpenSession func(ctx context.Context, p principal.Principal) error
	// PreviousRole is the role of the session a switch ends (ADR 0045 decision 3); "" for a plain sign-in. It is
	// recorded as the admin.login param previous_role.
	PreviousRole principal.Role
}

// ErrAmbiguousRole: Login was called with a LoginRole that names the platform role and an organization role.
var ErrAmbiguousRole = errors.New("app: login role names more than one role")
```

`Login` returns `ErrAmbiguousRole` when `role.Platform && role.Slug != ""` (before any audit event), and sets the
param `previous_role` on `admin.login` (organization and platform path alike) when `id.PreviousRole != ""`.
`StepUpMismatch` computes `newRole` from `res.Active(organization.ChoiceOrganization)` instead of
`!res.Denied && !res.Platform && res.Role != ""`.

### Audit registry — `server/internal/domain/audit/codes.go`

`CodeAdminLogin.Params` gains `previous_role`; `Note` gains: "previous_role is the role of the session a role
switch ended (ADR 0045); absent for a plain sign-in." No new code.

### Session cookie — `server/internal/transport/http/admin/session.go`

```go
type Session struct {
	// … existing fields unchanged …
	// AltRole and AltSlug name the role the identity may switch to (ADR 0045 decision 3): platform_admin and "" from
	// an organization session, the organization role and its slug from a platform session; empty for a single-role
	// identity.
	AltRole string `json:"alt_role,omitempty"`
	AltSlug string `json:"alt_slug,omitempty"`
}
```

`sessionVersion` stays 2. The session middleware puts `AltRole`/`AltSlug` into the request context under the
package-private key `alternateRoleKey{}` (next to `stepUpClassesKey{}`); `GetMe` and `UpdateMe` read it through
`h.alternateRole(ctx) *adminapi.MeAlternateRole`. The principal is unchanged.

### BFF — `server/internal/transport/http/admin/bff.go`

```go
type loginState struct {
	State, Verifier, Nonce, ReturnTo string
	Exp int64
	// Choice is the role the callback activates (ADR 0045): "" for a plain sign-in (organization by default).
	Choice organization.RoleChoice `json:"choice,omitempty"`
	// Switch is the session a switch ends; nil for a plain sign-in.
	Switch *Session `json:"switch,omitempty"`
}
```

`POST /api/auth/switch` (handler `bff.switchRole`, registered like logout: `noStore(s.csrf(...))`, outside the
session middleware, inside the IP guard): body `{"role": "platform" | "organization", "return_to": "/"}`.

| condition | answer |
| --- | --- |
| no valid session cookie | 401 `unauthenticated` |
| session record missing or not current | 401 `unauthenticated` (cookie cleared); store error → 503 `session_store_unavailable` |
| `role` is not the session's alternate (`AltRole` empty, or `role` names the active side) | 400 `invalid_request`, detail `role is not available for this session` |
| `return_to` not a relative path | 400 `invalid_request` |
| OIDC provider not discovered | 502 `upstream_unavailable` |
| otherwise | 200 `{"authorize_url": "<Authentik authorize URL>"}` and `Set-Cookie: paddock_login=<sealed loginState{Choice, Switch: &sess}>` |

`GET /api/auth/callback`, after the MFA check:

```
res := organization.ResolveRole(claims.Groups)
if res.Denied                       → existing path (reason res.Reason)
choice := st.Choice
switching := st.Switch != nil && st.Switch.Sub == claims.Subject
if !switching { choice = "" ; st.Switch = nil }          // a state of another user is a plain sign-in
if choice == "" && len(res.Choices) > 0 { choice = organization.ChoiceOrganization }
active, ok := res.Active(choice)
if !ok                              → recordDenied(…, res.Slugs, DenialRoleNotGranted); /login-denied?reason=role_not_granted
openSession := create sess:<sid> for p; if switching { delete sess:<st.Switch.SID> of st.Switch.PID } ; error fails the login
Login(ctx, LoginIdentity{…, OpenSession, PreviousRole: st.Switch.Role if switching}, LoginRole from active)
sess := NewSession(p, sid, locale, now); sess.AltRole, sess.AltSlug = res.Alternate(choice)
```

`checkStepUpRole` (`stepup.go`): `choice := ChoiceOrganization` (`ChoicePlatform` for a platform session);
`active, ok := res.Active(choice)`; `match := ok && (platform || (active.Role == sess.Role && orgOf(active.Slug) ==
sess.Org))`; on match the callback sets `sess.AltRole, sess.AltSlug = res.Alternate(choice)` before re-sealing; on
mismatch the existing paths run unchanged (`StepUpMismatch(ctx, sess.PID, sess.Org, res)` for an organization
session; refusal only for a platform session).

### Contract — `api/openapi/admin.yaml`

```yaml
  /api/auth/switch:
    post:
      operationId: switchRole
      tags: [auth]
      summary: Start the switch to the session's alternate role (ADR 0045).
      parameters: [ { $ref: "#/components/parameters/Csrf" } ]
      requestBody:
        required: true
        content:
          application/json:
            schema: { $ref: "#/components/schemas/RoleSwitch" }
      responses:
        "200":
          description: Navigate the browser to authorize_url; the callback opens the new session and ends this one.
          content:
            application/json:
              schema:
                type: object
                required: [authorize_url]
                properties: { authorize_url: { type: string, format: uri } }
        "400": { $ref: "#/components/responses/Problem" }
        "401": { $ref: "#/components/responses/Problem" }
        "502": { $ref: "#/components/responses/Problem" }
        "503": { $ref: "#/components/responses/Problem" }
components:
  schemas:
    RoleSwitch:
      type: object
      required: [role]
      properties:
        role: { type: string, enum: [platform, organization] }
        return_to: { type: string, description: Relative path to return to after the switch; default /. }
    MeAlternateRole:
      type: object
      required: [role]
      properties:
        role: { type: string, enum: [org_admin, org_operator, org_auditor, platform_admin] }
        organization_slug: { type: string, description: Set when role is an organization role. }
    Me:
      required: [ …existing…, alternate_role ]
      properties:
        alternate_role:
          allOf: [ { $ref: "#/components/schemas/MeAlternateRole" } ]
          nullable: true
          description: The role this identity may switch to (ADR 0045); null for a single-role identity, API tokens and MCP sessions.
```

The description of `GET /api/auth/callback` names the switch (previous session ended, `admin.login` with
`previous_role`, `role_not_granted`).

### Portal — `server/web/src`

- `stores/session.ts`: `alternateRole` (computed from `me.alternate_role`) and
  `switchRole(role: 'platform' | 'organization'): Promise<void>` → `api.POST('/api/auth/switch', {params: {header:
  {'X-Paddock-CSRF': '1'}}, body: {role}})` → `window.location.assign(data.authorize_url)`; on a problem answer the
  function rejects and the caller shows an inline alert.
- `App.vue` user menu: a `v-list-item` with `data-testid="switch-role"` above *Sign out*, rendered only when
  `alternateRole` is set, titled `app.switchRole` with the alternate role's label (`roles.<role>`) and, for an
  organization role, the slug; click opens a `ConfirmDialog` (`title` `app.switchRoleConfirmTitle`, `message`
  `app.switchRoleConfirmMessage` — names that the current session ends and privileged actions need a new step-up,
  `confirmLabel` `app.switchRoleConfirm`, not destructive, no typed text); confirm calls `session.switchRole`.
- `LoginDenied.vue` keys: `loginDenied.role_not_granted` added, `loginDenied.platform_and_organization` removed
  (`en.json`, `de.json`, `loginDenied.test.ts`).

### Residual risks (`docs/compliance/residual-risks.md`, section "Login and identity")

| ID | Risk | Mitigation in Paddock | Record in the ISMS |
| --- | --- | --- | --- |
| RR-91 | **One identity now spans both scopes.** A compromised two-role identity reaches the platform and its organization; before ADR 0045 that needed two accounts. | MFA at every sign-in; a fresh WebAuthn step-up per privileged action in every session; one role per session, a switch is a new sign-in through Authentik and one `admin.login` event with `previous_role`; the worker revokes each role on its own. | Which identities hold both roles; review `admin.login` events with `previous_role`. |
| RR-92 | **The alternate role is a snapshot.** The menu offers the switch from the groups seen at sign-in or at the last step-up; a role removed in Authentik meanwhile is still offered until the switch re-resolves the groups and refuses it (`role_not_granted`); no access results. | The switch always re-resolves the `groups` claim; the step-up refreshes the snapshot. | None. |
| RR-93 | **A switch is recorded in the scope it enters.** The `admin.login` of the new session (with `previous_role`) is recorded in the new role's scope: an organization auditor sees the identity's departure to the platform only through the next organization sign-in. | `previous_role` on the event; platform administrators see both scopes' events. | Whether the ISMS needs a departure event per scope (then a follow-up decision). |

## Consequences

- + One central identity administers the platform and its organization; no local accounts; the switch is a sign-in
  and inherits every login guarantee (MFA in `amr`, role from the fresh `groups` claim, audit, session record).
- + No migration, no new dependency, no change to `sessions.Record`, to the pools, to RLS, to the worker rounds or to
  the API-token model.
- − One Authentik round trip per switch; the platform role needs a click after sign-in.
- − The denial text `platform_and_organization` and its acceptance case are removed; the acceptance gate A4 gains a
  two-role case and a switch case.
- Follow-ups: PDK-201 (server, contract, acceptance gate, docs) and PDK-450 (portal) implement this ADR; PDK-436 and
  PDK-439 (M14) implement decision 7; architecture §9.6 amendment (text in PDK-201); ADR 0007, ADR 0034 and
  ADR 0044 carry dated cross-references.
