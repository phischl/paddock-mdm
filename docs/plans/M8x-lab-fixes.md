# Implementierungsplan: M8x — Fixes from the first lab test (release 0.1.0-alpha.4)

Status: Ready for implementation · 2026-10-17 · Author: architect
Basis: lab test of 2026-10-17 against v0.1.0-alpha.3 (findings L1–L29 of the maintainer's lab log); ADR 0007
(Authentik mapping, amended 2026-10-17), ADR 0008 (sudo ownership, amended 2026-10-17), ADR 0018 (lists and dialogs,
amended 2026-10-17), ADR 0019 (Himmelblau, amended 2026-10-17), ADR 0034 (step-up and sessions, amended
2026-10-17); plan M8s (step-up, sessions, blueprints); plan M11 §3.2 and §3.11 (report-only adoption, PDK-160/161);
plan M3a decision 1 (domains), plan M4a decisions 14–20 (break-glass accounts, local administrator); PoC M1 report.

Binding language: **MUST** / **MUST NOT** / **SHOULD** / **MAY**.

Public repository: the commit messages, pull requests and CHANGELOG lines of PDK-203 (portal login) describe the
change as a policy change ("every portal sign-in runs Paddock's login flow and must carry a second factor"), not as a
bypass. The release commit moves that line into `### Security` (plan M8s §13 rule).

## 1. Goal

After M8x a portal sign-in always runs Paddock's own login flow and is refused without a second factor; an agent
never removes the last administrator of a device; a Hello PIN keeps working past the access-token lifetime and the
device code gives a user ten minutes; a platform administrator sets an organization's domains in the portal; and the
sixteen smaller findings of the lab (loading states, readable errors, hints, German terms, bundle checks) are fixed.

## 2. Context (verified in the code on 2026-10-17, `main` at `ecfaad0`)

- **Portal login (PDK-202 / L9).** `server/internal/transport/http/admin/bff.go::login` (line 144) builds the
  authorize URL without `prompt`; an existing Authentik session therefore satisfies the authorize request without
  running `paddock-admin-login`. `callback` (line 190) decodes `idClaims` (`sub`, `preferred_username`, `name`,
  `email`, `groups`) and never reads `amr`; `stepup.go::checkStepUp` (line 239) already requires `mfa` in `amr`.
  `deploy/compose/authentik/blueprints/paddock-portal.yaml` defines the flow `paddock-admin-login` (stages at 10, 20,
  30 = `paddock-admin-login-mfa` with `not_configured_action: configure`, 100) and never touches the brand or
  `default-authentication-flow`. The default brand's flows are set by the worker, not by a blueprint
  (`server/internal/adapters/authentik/brand.go::EnsureBrandFlows`, fields `flow_recovery`, `flow_device_code`; the
  device blueprint's header explains the race with the default brand). The development blueprint
  `deploy/compose/authentik/dev/paddock-dev.yaml` skips the MFA stage of `paddock-admin-login` with an always-false
  policy on the binding at order 30; the acceptance and e2e helpers (`test/acceptance/internal/authflow`,
  `server/web/e2e/auth.ts::login`) run the flow with username and password only. Development-only switches are
  loaded with `config.LoadDevStepUp` (refused outside `PADDOCK_ENV=development`) and listed in
  `server/internal/prodcheck/prodcheck.go::devOnly`. The login unit test `login_test.go` uses `newFakeStepUpIdP`
  (`stepup_test.go`) whose claims the test sets.
- **Privileged groups (L15).** `agent/internal/reconcile/groups.go::groupMembers` lists the members of `sudo`,
  `admin`, `wheel` that are not in `spec.BreakGlassAccounts`; `cleanGroups` removes every one of them with
  `gpasswd -d` and emits `tamper.sudo_group_member {group, username, removed}`. The compiler
  (`server/internal/compiler/v2.go::renderV2`) renders the sudo resource for every device and adds
  `local_admin_username` to the break-glass list, but the login resource (which creates the local administrator) only
  for an organization with a primary domain. A device of an organization without a domain, whose administrator set no
  break-glass account, therefore loses every sudo member at the first apply and gets no administrator. M11 (ADR 0033,
  PDK-160/161, not merged) makes the first apply of an adopted device report-only; it does not cover enforced devices.
- **Device login tokens (L26, L29).** `server/internal/adapters/authentik/devicelogin.go::ensureDeviceLogin` PUTs
  the device provider with `access_token_validity: minutes=10`, `refresh_token_validity: days=30` and no
  `access_code_validity` (Authentik default `minutes=1`, which is the device code's lifetime:
  `device_backchannel.py` sets `expires = now + access_code_validity`). Authentik 2026.8.3 renews the refresh token
  at every refresh and revokes the old one (`views/token.py::create_refresh_response`, default
  `refresh_token_threshold = seconds=0`); a threshold above zero is **not** a fix: Authentik then omits
  `refresh_token` from the refresh response until the token nears expiry, and Himmelblau 4.0.4–4.0.6 denies every
  PIN login without one ("Authentication incomplete", `openidconnect.rs` 3322–3330). The mechanism, verified in the
  lab against Authentik's refresh-token primary keys and in the Himmelblau source (4.0.4, 4.0.6 and `main` are
  identical for generic OIDC; evidence in the maintainer's upstream note): every successful PIN login exchanges
  the sealed refresh token and **re-seals the new one** with the Hello key; the cached-user refresh in
  `unix_user_get` runs when the user's cache entry has expired (`cache_timeout`, default 300 s, reset by every
  `set_cache_usertoken`, which every successful PAM authentication calls) and is triggered by any NSS lookup of the
  user (`get_usertoken` → `refresh_usertoken`); that refresh rotates the token, keeps the new one in memory only,
  and Authentik revokes the old one; the next PIN login or unlock prefers the stale sealed token, gets
  `invalid_grant` (Authentik event `suspicious_request` "Revoked refresh token was used"), deletes the Hello key
  and demands the device code and a new PIN. The session itself never ends; Authentik revokes no token family. No
  Authentik setting changes this; Himmelblau's Okta provider on `main` handles the rotation correctly, the generic
  OIDC provider does not. A PIN login therefore fails whenever more than `cache_timeout` passed since the user's
  last successful PIN authentication while the device was online and anything looked the user up. Himmelblau
  4.0.6 (2026-10-15) resets the MFA polling state after a completed poll (PoC M1 upstream issue 4, `PAM_SYSTEM_ERR`
  after an expired device code) and stops caching synthetic user lookups. The pin `PADDOCK_HIMMELBLAU_VERSION`
  defaults to `4.0.4` (`server/cmd/paddock-server/compiler.go:36`); the repository serves `4.0.6` for `ubuntu24.04`
  and `ubuntu26.04`. The agent renders `himmelblau.conf` in `agent/internal/reconcile/login.go::renderHimmelblauConf`
  with fixed lines (`idmap_range`, `local_groups`) next to the bundle's values; `cache_timeout` is not set, so the
  default 300 s applies. `cache_timeout` also bounds Himmelblau's negative cache (`set_nxcache`) and the group cache.
  Paddock's user lock does not depend on it: the agent writes the deny list and locks or ends sessions itself, and
  Authentik revokes the user's tokens; the allow list (`pam_allow_groups`) is evaluated in the account phase after
  an online authentication refreshed the user's claims.
- **Organizations (L16).** `PATCH /api/platform/v1/organizations/{id}` (`OrganizationDomainsUpdate`, audited
  `organization.domains_changed`) exists; `OrganizationCreate` has `slug` and `name` only;
  `server/web/src/views/Organizations.vue` has a create dialog without domains and no edit dialog;
  `organization.ValidateDomains` accepts at most 20 names matching
  `^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$`, each ≤ 253 characters, no duplicates.
  `MeOrganization` has `id`, `slug`, `name` (no domains).
- **Portal.** No submit button binds `:loading` except `InstallNowDialog.vue` and `PlatformSessions.vue` (`busy`);
  22 forms and views have a `type="submit"` button. `App.vue` renders the organization name in
  `<span class="org-name" data-testid="org-name">` without ellipsis or tooltip. `LoginDenied.vue` shows
  `loginDenied.<reason>` for `not_authorized` and `login_failed`; `app.Accounts.Login` records `admin.login` denied
  with `reason: not_authorized` for every denial of `organization.ResolveRole` (platform plus organization role,
  several organizations, no role). `LocalAdminCard.vue` shows `devices.localAdmin.none` ("none yet") while
  `active_generation` is null even when `pending_generation` is set. `ProfileForm.vue` has no hint on the
  `requirePassword` switch and no root-equivalence feedback before submit (the catalog is
  `server/internal/domain/privilege/rootequiv.go`, server-side only). `ManagedFiles.vue` has no pointer to
  `/settings/managed-files`; the German catalog uses "Operator-Wurzel(n)" eight times (`de.json` lines 83, 353,
  1000–1007) and the glossary row 54. `pkg/policy.wellFormed` accepts non-ASCII path characters. `Me.step_up` is
  development-only (`MeStepUp`); `handlers.go::GetMe` fills it when `stepUpTiming != nil`. `Users.vue` validates
  `name@domain` for local users only; synced users keep their Authentik username.
- **Key store (L6).** `admin.Keyring.Seal` returns `admin: no session key loaded` when OpenBao was sealed at the
  api's start; `bff.login` answers that error with `httpx.WriteProblem` (500 `internal`) on a browser navigation.
  `/readyz` says `not ready: session keys not loaded`; `paddock-server healthcheck` prints only `readyz: 503
  Service Unavailable`; `deploy/compose/scripts/wait-healthy.sh` prints `still waiting for: paddock-api (unhealthy)`.
- **Bundle (L4, L5).** `prodcheck.checkSecretFiles` refuses world-readable secrets and never checks that a secret is
  readable by the Paddock images' user (`USER nonroot`, uid 65532, `deploy/compose/Dockerfile`); a 0600 release
  public key passes and the roles fail with `permission denied`. Compose bind-mounts each secret file by path, so
  only the file's own mode and owner matter (the 0700 `.secrets/` directory is fine; `gen-prod-secrets.sh` writes
  files with umask 077). `./paddock agent-release` mounts `<dir>` read-only into `paddock-api` (uid 65532) without
  checking that the directory is readable.
- **Tests.** Acceptance: `TestLoginGate` (`login_test.go`), `TestAuthentikBrandFlows` (`authentik_brand_test.go`,
  helper `env.Authentik.BrandFlowMismatches`), `TestIdentityAuthentikProvisioning` (reads the device provider),
  `TestStepUpFactor` (reads flow bindings through `ak.Get`). System gates on the VMs: `TestIdentityGates`
  (`test/system/identity_test.go`: `gdmLogin`, `pamLogin`, `w.Key(keySpace...)`, `w.Type(pin)`,
  `loginctl show-session <id> -p LockedHint`, `authentikSQL`, `paddockSQL`, `forgeBundle`), one subtest per VM
  (`forEachVM`). Portal component tests in `server/web/src/__tests__/`, e2e in `server/web/e2e/` (`mobile.spec.ts`
  at 390 px, `german.spec.ts`). Prodcheck blueprint content tests: `compose_test.go::TestStepUpBlueprintWebAuthnOnly`.
  Residual risks end at RR-39.

## 3. Binding decisions

### 3.1 Portal login requires a second factor on every Authentik path (PDK-203; closes PDK-202)

1. ~~`bff.login` MUST add `oauth2.SetAuthURLParam("prompt", "login")` to `oauth.AuthCodeURL(...)`. Every portal
   sign-in runs the provider's authentication flow `paddock-admin-login`; an existing Authentik session never
   satisfies it. (This also removes the symptom of PDK-190: after *end all sessions* the browser is prompted again.)~~
   **Replaced 2026-10-17 (architect, CI of PR #82):** `bff.login` MUST NOT send `prompt=login`. Authentik 2026.8.3
   honours `prompt=login` through the session key `authentik/providers/oauth2/last_login_uid` (`authorize.py`
   540–560), which it never clears: after a forced re-login the next step-up's `prompt=login` finds the stale key and
   a login event younger than `max_age`, and Authentik issues the step-up token for that login event without running
   `paddock-stepup` — a silent step-up pass within 60 s of a portal login that skips the WebAuthn-only factor; on a
   fresh browser the login flow also ran twice. The rule becomes: an existing Authentik session MAY satisfy the
   portal sign-in only if its ID token carries `mfa` in `amr`, which the brand's authentication flow (decision 4) and
   the default-flow MFA stage (decision 5) guarantee for every session Authentik can create, and the callback
   (decision 2) refuses every token without it. Consequence: the symptom of PDK-190 returns (after *end all
   sessions* a browser with a live Authentik session signs in again without a prompt, with a second factor already in
   that session); PDK-190 is relevant again and stays open.
1a. **Defensive step-up check (architect, 2026-10-17).** `stepup.go::checkStepUp` MUST refuse a step-up ID token
   whose `auth_time` is missing or earlier than the step-up start (`st.StartedAt`, unix seconds, compared in whole
   seconds: `auth_time >= started_at`), in addition to the existing subject, `max_age` and `amr` checks; the refusal
   is `stepup=failed` as today. The step-up start is recorded in the step-up state cookie when `/api/auth/stepup`
   begins. This holds whatever Authentik does with `prompt`: a token for an older login event can never satisfy a
   step-up. Unit test: a token with `auth_time = started_at - 1` → refused; `= started_at` → accepted; absent →
   refused. Acceptance: `TestStepUp` passes; a new case starts a step-up and completes it with the executor in
   under a second (equal-second boundary).
2. `idClaims` MUST gain `AMR []string \`json:"amr"\``. After the nonce and subject checks and before
   `ResolveRole`, the callback MUST refuse a token whose `AMR` does not contain `"mfa"` unless
   `bff.loginMFAOptional` is true: it calls `b.accounts.RecordLoginFailure(ctx, ip, username,
   app.ReasonMFARequired, errMFARequired)` and `denied(w, r, app.ReasonMFARequired)`.

   ```go
   // server/internal/app/accounts.go
   ReasonMFARequired = "mfa_required" // the ID token carried no second factor (amr without "mfa")
   // server/internal/transport/http/admin/bff.go
   var errMFARequired = &problem.Error{Code: app.ReasonMFARequired, Status: http.StatusForbidden}
   ```

   `RecordLoginFailure` MUST become `RecordLoginFailure(ctx context.Context, ip, username, reason string, cause
   error)`; a non-empty `username` is the anonymous actor's `Display`. Existing callers pass `""`. The event is one
   `admin.login` with outcome `denied`, error code `mfa_required`, params `reason: mfa_required`.
3. Development switch: `config.LoadDevLoginMFAOptional(l *Loader, c Common) bool` reads
   `PADDOCK_LOGIN_MFA_OPTIONAL` (`true` or `false`; any value outside `PADDOCK_ENV=development` is
   `l.Invalid(name, "only allowed with PADDOCK_ENV=development")`, exactly the `LoadDevStepUp` pattern).
   `admin.Deps` gains `LoginMFAOptional bool`; `cmd/paddock-server/api.go` passes it; `prodcheck.devOnly` gains
   `"PADDOCK_LOGIN_MFA_OPTIONAL"`; `deploy/compose/compose.dev.yaml` sets `PADDOCK_LOGIN_MFA_OPTIONAL: "true"` on
   `paddock-api` next to `PADDOCK_STEPUP_WINDOW`. No production file sets it.
4. `authentik.EnsureBrandFlows` MUST also keep the brand's `flow_authentication` at the flow `paddock-admin-login`
   (blueprint `paddock-portal.yaml`): the `brand` struct gains `FlowAuthentication string
   \`json:"flow_authentication"\``, the comparison and the PATCH cover the three fields, the log line names all
   three. `brand_test.go` covers a brand whose `flow_authentication` is another flow (patched) and one that already
   matches (no PATCH). `env.Authentik.BrandFlowMismatches` gains the pair `{"flow_authentication",
   "paddock-admin-login"}`.
5. `paddock-portal.yaml` MUST gain, after the `mfa-binding` entry:

   ```yaml
   # Second factor on Authentik's default authentication flow as well (lab finding of 2026-10-17): a user without an
   # authenticator must enrol one; a user who just validated one in the stage at order 30 is not asked twice.
   - model: authentik_stages_authenticator_validate.authenticatorvalidatestage
     id: default-flow-mfa
     identifiers:
       name: paddock-default-login-mfa
     attrs:
       device_classes: [webauthn, totp]
       not_configured_action: configure
       last_auth_threshold: minutes=5
       configuration_stages:
         - !Find [authentik_stages_authenticator_webauthn.authenticatorwebauthnstage, [name, default-authenticator-webauthn-setup]]
         - !Find [authentik_stages_authenticator_totp.authenticatortotpstage, [name, default-authenticator-totp-setup]]
   - model: authentik_flows.flowstagebinding
     id: default-flow-mfa-binding
     identifiers:
       target: !Find [authentik_flows.flow, [slug, default-authentication-flow]]
       stage: !KeyOf default-flow-mfa
       order: 31
     attrs:
       evaluate_on_plan: true
       re_evaluate_policies: true
   ```

   Order 31 lies behind Authentik's own `default-authentication-mfa-validation` binding at order 30 (which skips
   users without an authenticator). `paddock-dev.yaml` MUST bind the existing policy `paddock-dev-skip-mfa` to that
   binding too (a second `authentik_policies.policybinding` entry whose `target` is `!Find
   [authentik_flows.flowstagebinding, [target, !Find [authentik_flows.flow, [slug, default-authentication-flow]]],
   [order, 31]]`), so that the development users without authenticators keep working.
6. `LoginDenied.vue` MUST show `loginDenied.mfa_required` (§6.6) and keep the *Sign in again* link, which now works
   because of decision 1.
7. Tests: (a) `compose_test.go::TestPortalBlueprintBindsMFAOnTheDefaultFlow`: `paddock-portal.yaml` contains
   `name: paddock-default-login-mfa`, `slug, default-authentication-flow` and `order: 31`; `paddock-dev.yaml`
   contains `[order, 31]`. (b) `login_test.go::TestLoginRefusesATokenWithoutMFA`: with `LoginMFAOptional: false` and
   `idp.claims` without `amr` → 302 to `/login-denied?reason=mfa_required`, no session cookie, no session record,
   exactly one row in `action` with code `admin.login`, outcome `denied`, error code `mfa_required`; with `amr:
   ["pwd","mfa"]` → 302 to `/` with the cookie; with `LoginMFAOptional: true` and no `amr` → success. (c)
   (replaced 2026-10-17) `login_test.go::TestLoginStartsWithoutPrompt`: the `Location` of `GET /api/auth/login`
   contains no `prompt` parameter; `stepup_test.go` covers the `auth_time >= started_at` rule of decision 1a. (d)
   Acceptance `TestAuthentikBrandFlows` passes with the third field; new `TestLoginMFAPath` (`login_test.go`): the
   flow `default-authentication-flow` has a binding at order 31 whose stage is named `paddock-default-login-mfa`
   with `not_configured_action == "configure"`, and `GET /api/auth/login` redirects to a URL without `prompt`.
8. Documents: `docs/operations/install.md` §12 and `docs/operations/upgrade.md` *Before you start*: "After this
   upgrade every Authentik sign-in — the portal, Authentik's own user and admin interfaces (`akadmin` included) and
   the device approval page — asks for a second factor and enrols one when missing." `docs/operations/device-login.md`
   *Authentik brand flows*: the worker also keeps the brand's authentication flow at `paddock-admin-login`.
   CHANGELOG `### Changed`: "Every portal sign-in now runs Paddock's own login flow and is refused without a second
   factor; the default brand's authentication flow and Authentik's default authentication flow ask for a second
   factor as well."

### 3.2 Never remove the last administrator (PDK-204; agent) — ADR 0008 amendment 2026-10-17

9. `agent/internal/reconcile/groups.go` MUST become:

   ```go
   // privilegedGroup is one privileged local group as found on the device.
   type privilegedGroup struct {
       Foreign       []string // members that are no break-glass account, in getent order
       HasBreakGlass bool     // at least one break-glass account is a member
   }
   // groupMembers returns every privileged group that exists on the device.
   func (s *Sudo) groupMembers(ctx context.Context, spec bundle.SudoSpec) (map[string]privilegedGroup, error)
   // cleanGroups removes the foreign members of every group that has a break-glass member and keeps every member of
   // a group without one (never the last administrator, ADR 0008 amendment 2026-10-17); each kept member is reported
   // once per daemon run as tamper.sudo_group_member with removed=false and reason last_admin.
   func (s *Sudo) cleanGroups(ctx context.Context, groups map[string]privilegedGroup) (bool, error)
   ```

   A group without a break-glass member is never changed; `gpasswd` is not called for it. `Sudo` gains
   `kept map[string]bool` (key `group + "/" + username`) so that drift passes do not repeat the event while the
   state is unchanged; the key is deleted when the member disappears or the group gains a break-glass member.
   `sudoPlan.changes()` MUST list `keep <user> in <group> (last administrator)` for kept members and keep
   `remove <user> from <group>` for the others. The error joined into `errorResult` is unchanged (a kept member is no
   error).
10. `pkg/protocol.TamperSudoGroupMember` MUST gain `Reason string \`json:"reason,omitempty"\`` with
    `const SudoGroupMemberKeptLastAdmin = "last_admin"` (additive device protocol change, ADR 0013: older servers
    store the unknown param). The registry description of `device.tamper_sudo_group_member` becomes: "A device found
    a member of a privileged local group (sudo, admin, wheel) that is not a break-glass account and removed it, or
    kept it because no break-glass account is a member of that group (reason last_admin) (actor: the device)."
    `make gen` regenerates `docs/compliance/audit-codes.md`.
11. Tests: `sudo_test.go` with `fakesys`: (a) group `sudo` = `groot,paddock-admin`, break-glass `paddock-admin` →
    `gpasswd -d groot sudo`, event `removed: true`, no reason; (b) group `sudo` = `groot`, break-glass
    `paddock-admin` (not a member) → no `gpasswd`, event `removed: false, reason: last_admin`, result `OK`; a second
    apply emits no second event; after `paddock-admin` joins the group the next apply removes `groot`; (c) a name
    starting with `-` is still refused as today. System gate `gateP4` (`identity_test.go`) MUST gain the case: with
    `forgeBundle` emptying `BreakGlassAccounts`, a member `systest-<suffix>` added to `sudo` stays a member after the
    apply, `getent group sudo` still lists `paddock` and `paddock-admin`, and `device.tamper_sudo_group_member`
    with `removed=false` and `reason=last_admin` arrives; after the forged bundle is withdrawn the member is removed.
12. Coordination with M11: PDK-161's report-only apply plans without applying; the guard of decision 9 applies to
    every enforced apply, so M11 needs no change; PDK-160's consequence sentence of the *Enable enforcement* dialog
    MUST read "… remove unexpected members of privileged groups (never the last administrator) …" when PDK-160 is
    implemented (note added to the PDK-160 ticket by PDK-204).

### 3.3 Break-glass guidance before enrolment (PDK-205; portal and settings texts)

13. `MeOrganization` MUST gain `domains` (`string[]`, required); `Accounts.GetMe`/`toMe` fill it from the
    organization row (`GetOrganization` inside the same `InOrg`). Platform administrators keep `organization: null`.
14. `EnrollmentTokens.vue` create dialog MUST show, above `EnrollmentTokenForm`, one `v-alert variant="tonal"`:
    `type="warning"` with `tokens.noDomainWarning` when `me.organization.domains` is empty, else `type="info"` with
    `tokens.breakGlassHint` (§6.6; `{username}` is `local_admin_username` from `GET /api/v1/settings/login`,
    loaded once when the dialog opens through `lib/loginSettings.ts`). Both end with a `router-link` to
    `/settings/login` labelled `tokens.breakGlassLink`. `loginSettings.breakGlassHint` becomes the §6.6 text.
15. Tests: component test `enrollmentTokens.test.ts` (new) for both alerts; acceptance `TestMe` (or the existing
    `overview_test.go` me check) asserts `organization.domains` equals the acme domains.

### 3.4 Device code lifetime (PDK-206) and the Hello PIN past the access token (PDK-292) — ADR 0019 amendment 2026-10-17

16. `ensureDeviceLogin` MUST set `"access_code_validity": "minutes=10"` on the device provider (unchanged:
    `access_token_validity: minutes=10`, `refresh_token_validity: days=30`) and MUST set
    `"refresh_token_threshold": "seconds=0"` explicitly, Authentik's default, so that the reconciliation every 10
    minutes resets a value changed by hand: a threshold above zero makes Himmelblau deny every PIN login (§2). The
    reconciliation converges existing providers. `adapter_test.go::TestDeviceLoginSettings` and the acceptance gate
    `TestIdentityAuthentikProvisioning` MUST assert both values; the fake test also asserts that a threshold set by
    hand is reset to `seconds=0`.
16a. **Interim mitigation (PDK-292, agent).** Until Himmelblau re-seals a rotated refresh token upstream, the agent
    MUST render `cache_timeout = 2592000` (30 days, the device provider's `refresh_token_validity`) into
    `himmelblau.conf` in `renderHimmelblauConf`, as a fixed line after `idmap_range`, with the constant

    ```go
    // himmelblauCacheTimeout keeps Himmelblau's cached-user refresh from rotating the refresh token behind the Hello
    // PIN: Himmelblau 4.0.x re-seals the token only at a PIN login and presents the sealed one at the next, so a
    // background rotation deletes the Hello key (ADR 0019 amendment 2026-10-17). Equal to the provider's refresh
    // token validity (server/internal/adapters/authentik/devicelogin.go): the refresh can then only run when the
    // sealed token has expired anyway. Remove when the upstream fix is pinned.
    const himmelblauCacheTimeout = 2592000
    ```

    Rationale and the alternatives weighed: (a) a larger `cache_timeout` — chosen; with the value equal to the
    refresh-token validity the background refresh can never revoke a sealed token that is still valid, because every
    PIN authentication re-seals the token and resets the cache expiry; the cost is that Himmelblau's cached NSS
    attributes (display name, shell, groups of `id`) of a user with an open session are refreshed online only at the
    user's next PIN authentication or after 30 days instead of 300 s, and that a user whose refresh failed with
    `invalid_grant` (a Paddock lock revokes the tokens) stays in Himmelblau's negative cache for up to 30 days or a
    daemon restart, so `getent passwd` of a **locked** user answers nothing until the user signs in again (the agent
    reports `device.sudo_user_unresolved` for such a user; a lock already removes the user's sudo entry). Paddock's
    lock, suspension and allow list do not depend on the cache (§2), and a login's auth phase refreshes the claims
    online before the account phase checks them, so no access decision becomes stale. (b) `enable_hello = false`
    — rejected as the default: every login and every screen unlock would need the device code and the phone;
    organizations that prefer it already have the setting *Login & privileges → Hello PIN* (`hello_enabled`).
    (c) a per-organization setting for the cache timeout — rejected: the value follows from the provider's token
    validity, nothing varies per organization, and a setting would outlive the workaround. (d) accept and document
    only — rejected: a PIN that fails after every lunch break is the device finding with the highest priority.
    The residual that stays (RR-40): a user who did not authenticate with the PIN for 30 days (refresh token
    expired) signs in with the device code again and sets a new PIN; the same after a lock, three wrong PINs, or a
    stale sealed token on devices whose agent is older than this release (the mitigation is agent-side: update the
    agents first).
17. Documents: `docs/operations/device-login.md` new section *Tokens of the device login* (binding content): the
    device code lives ten minutes; the access token ten minutes; the refresh token 30 days, renewed at every PIN
    authentication; Himmelblau refreshes a cached user's attributes online at the next PIN authentication or after
    30 days (`cache_timeout`, set by the agent because Himmelblau 4.0.x would otherwise rotate the refresh token
    behind the PIN and the next PIN login would fail); once per 30 days without a PIN authentication (or earlier
    after a lock, three wrong PINs or a long offline period) the user signs in with the device code again and sets a
    new PIN. The upstream issue (draft in the maintainer's notes; the maintainer posts it after a 4.0.6
    reproduction) is linked there once posted. `docs/compliance/residual-risks.md` **RR-40** "Hello PIN re-enrolment
    after 30 days without a PIN authentication, and on agents older than 0.1.0-alpha.4" with the mitigation of 16a.
    `test/system/login.go` `pamOpts.approve` comment: "the attempt fails once the code expires, about 10 minutes" (the
    gates' negative cases run into their own 3-minute timeout, which stays).

### 3.5 System gate for the PIN past the access-token lifetime, Himmelblau 4.0.6, login messages (PDK-207)

18. `TestIdentityGates` MUST gain `L6 PIN past the access-token lifetime` (`gateL6`), run directly after `L1 login`
    on each VM: (a) record `t0`; assert that `/etc/himmelblau/himmelblau.conf` contains the line
    `cache_timeout = 2592000`; (b) for eleven minutes, every 60 s run `id <dave>` and `getent passwd <dave>` in
    the guest (with the default `cache_timeout` of 300 s they would trigger Himmelblau's cached-user refresh and the
    rotation; the gate proves they no longer do); (c) `sudo loginctl lock-session <seat0 session ID>`, wait until
    `LockedHint=yes` (60 s); `w.Shot("20-locked")`; `w.Key(keySpace...)`, 3 s, `w.Type(dave.pin)`, wait until
    `LockedHint=no` within 60 s, `w.Shot("21-unlocked")`; (d) `pamLogin(dave, false, time.Minute) == 0`;
    (e) `authentikSQL("SELECT count(*) FROM authentik_events_event WHERE action = 'suspicious_request' AND created >
    '<t0>'")` is `0`. A failure of (a), (c), (d) or (e) fails the gate. The eleven minutes run in parallel on both
    VMs. The gate is expected to fail without PDK-292 (that run is recorded once in the result document as the
    reproduction) and to pass with it, on 4.0.4 and on 4.0.6.
19. `PADDOCK_HIMMELBLAU_VERSION` default MUST become `4.0.6` (`compiler.go:36` and the error text, `.env.example`
    comments, `docs/operations/device-login.md`, `docs/architecture.md` §9.3 if it names the version, CHANGELOG
    `### Changed`). Order inside the ticket: gate L6 first against 4.0.4 (with PDK-292 merged it passes); then the
    bump; then `make system-test VM=all T='TestIdentityGates|TestLocalAdminGates|TestNoticeGate'`. If any gate
    regresses with 4.0.6 (stop condition S4), the default stays `4.0.4` and the ticket reports the gate.
20. `docs/operations/device-login.md` MUST gain the table *Messages at the login screen* (L19) with these rows:
    `PAM_SYSTEM_ERR` after a device code expired at the greeter (Himmelblau before 4.0.6 could not start a second
    device flow; type the username again; fixed in 4.0.6); `Sorry, password authentication didn't work` on the
    GNOME lock screen (GNOME's text for any refused PIN; locked user, wrong PIN or expired session); `Your session
    has expired. Please sign in again.` (the refresh token was revoked or expired: sign in with the device code and
    set a new PIN); `Failed to authenticate with Hello PIN.` (wrong PIN; after three the device code is required);
    `authenticated user … does not match requested user` (the Authentik username is not `name@domain`, L18).
    Paddock cannot change these texts: the greeter and lock screen show PAM's and GNOME's messages.

### 3.6 Organization domains in the portal (PDK-208)

21. `Organizations.vue` create dialog MUST gain a `v-textarea id="org-domains"` (label `organizations.domains`, hint
    `organizations.domainsHint`, rows 2). Submit: `createOrganization(slug, name)`; when the organization was created
    (201 or 200) and the textarea names at least one domain, `updateOrganizationDomains(id, domains)`; a failed
    PATCH keeps the dialog open with the problem text and `organizations.createdWithoutDomains` as a second alert
    line; the list reloads in every case. Two audit events (`organization.created`, `organization.domains_changed`)
    are intended: the API contract does not change.
22. The list MUST gain the column `domains` (`organizations.domains`, not sortable, the names joined with `, `,
    ellipsis) and a per-row button `organizations.editDomains` (`data-testid="org-domains-<slug>"`, visible to
    platform administrators) opening the dialog `organizations.editDomainsTitle` (`{name}`) with the same textarea
    prefilled; *Save* PATCHes and closes on success.
23. `lib/organizations.ts` gains `updateOrganizationDomains(id: string, domains: string[]): Promise<string | null>`
    (PATCH with `X-Paddock-CSRF`). `lib/validation.ts` gains `validateDomains(text: string): string` returning `''`
    or the message key `validation.domainsInvalid`: lines are trimmed and lower-cased, empty lines dropped; invalid
    when more than 20, a duplicate, a name longer than 253 characters or not matching
    `^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$` (the server's rule, repeated for
    the form; the server stays authoritative and answers 400 `invalid_request` / 409 `domain_taken`).
24. Tests: component test `organizations.test.ts` (new): create with domains → POST then PATCH with the
    lower-cased list; create without → no PATCH; PATCH failure → dialog open with both texts; edit dialog PATCH.
    e2e `organizations.spec.ts` (new, platform admin): create `e2e-<suffix>` with domain `e2e-<suffix>.test`, the row
    shows the domain; edit to two domains, the row shows both. Acceptance: unchanged (the API has gates).

### 3.7 Loading state on every submitting button (PDK-209) — ADR 0018 amendment 2026-10-17

25. New composable `server/web/src/composables/usePending.ts`:

    ```ts
    /** One in-flight request per caller: run ignores a second call while the first is pending. */
    export function usePending(): { pending: Ref<boolean>; run<T>(fn: () => Promise<T>): Promise<T | undefined> }
    ```

26. Every `v-btn` of `type="submit"` and every `v-btn` whose click handler calls the API (the 22 files of §5 plus
    `InstallNowDialog.vue`, `PlatformSessions.vue`, `LocalAdminCard.vue`, `DeviceOverview.vue`, `IpAllowlist.vue`,
    `AgentReleaseDetail.vue`, `RevocationRequests.vue`, `SecurityReview.vue`, `UserDetail.vue`, `Users.vue`,
    `UserGroupDetail.vue`, `DeviceGroupDetail.vue`, `PackageHolds.vue`, `ManagedUnits.vue`, `Attention.vue`) MUST
    bind `:loading="pending"` and `:disabled="pending"` to the `pending` of the component that runs the request. The
    form components `ProfileForm`, `ManagedFileForm`, `EnrollmentTokenForm`, `DeviceGroupForm`, `ApiTokenForm`,
    `IpAllowlistEntryForm`, `ManagedUnitForm`, `PackageHoldForm` gain the prop `pending?: boolean` (default
    `false`) and bind it on their submit button; their hosts pass `usePending().pending`. `ConfirmDialog` is
    unchanged: it closes on confirm and the button that opened it shows the loading state while the request runs.
    `InstallNowDialog.vue` and `PlatformSessions.vue` keep their behaviour and rename `busy` to `pending`.
27. Tests: `pending.test.ts` (new: a second `run` while pending resolves `undefined` and does not call `fn`);
    `permissionProfiles.test.ts` and `managedFiles.test.ts` gain a case: while the create request is unresolved the
    submit button has the `disabled` attribute and contains an element with `role="progressbar"`; after it resolves
    the button is enabled again. e2e `portal.spec.ts` gains one check on the organization create button (platform
    admin): after the click the button is disabled until the dialog closes.

### 3.8 Readable "key store sealed" (PDK-210)

28. `app.ReasonKeyStoreSealed = "key_store_sealed"`. `bff.login` and `bff.callback` MUST, as their first check,
    answer `denied(w, r, app.ReasonKeyStoreSealed)` when `!b.keys.Ready()` (no audit event: no identity is
    known and the condition is operational). `LoginDenied.vue` shows `loginDenied.key_store_sealed` (§6.6).
29. `api.go` readiness error MUST read `session keys not loaded: OpenBao is sealed or unreachable
    (docs/operations/openbao.md section 2)`. `main.go::runHealthcheck` MUST include the first 200 bytes of the
    response body in its error (`readyz: 503 Service Unavailable: not ready: session keys not loaded: …`).
    `wait-healthy.sh` MUST, on timeout, print for every pending service with health `unhealthy` the last health
    log line: `docker inspect --format '{{range .State.Health.Log}}{{.Output}}{{end}}' <container> | tail -n 1`
    (container names from `compose ps -a --format '{{.Service}}|{{.Name}}'`).
30. `docs/operations/openbao.md` *What stops while OpenBao is sealed*, row *Portal login and sessions*: "the sign-in
    page shows *The server's key store is sealed* until OpenBao is unsealed; `./paddock up` names the reason in its
    timeout line". Tests: `login_test.go::TestLoginNamesASealedKeyStore` (empty keyring → 302 to
    `/login-denied?reason=key_store_sealed`); `main_test.go` or `ops` test for the body in the healthcheck error.

### 3.9 Login denied with the reason (PDK-211)

31. `organization.RoleResolution` MUST gain `Reason DenialReason` with

    ```go
    type DenialReason string
    const (
        DenialNoRole                  DenialReason = "no_role"                   // no Paddock role group
        DenialMultipleOrganizations   DenialReason = "multiple_organizations"    // role groups of several organizations
        DenialPlatformAndOrganization DenialReason = "platform_and_organization" // platform admins plus an organization role
    )
    ```

    set in the `default` branch of `ResolveRole` (`platform && matches > 0` → platform_and_organization;
    `matches > 1` → multiple_organizations; else no_role) and empty when a role is granted. `app.LoginRole` gains
    `DenialReason string`; `Accounts.Login` passes it to `recordDenied`, which adds the audit param
    `denial_reason`; an unknown or inactive organization records `denial_reason: organization_inactive`.
    `ErrLoginDenied` stays; the bff redirects to `/login-denied?reason=<denial reason>` (it has `res.Reason`; for the
    inactive-organization case the bff uses `organization_inactive`, which `Login` reports through a new error
    `ErrOrganizationInactive = problem.Forbidden.WithDetail("organization_inactive")`). The registry entry
    `admin.login` gains the param `denial_reason`.
32. `LoginDenied.vue` texts for `no_role`, `multiple_organizations`, `platform_and_organization`,
    `organization_inactive` (§6.6); `not_authorized` stays as the fallback. The warning "when a platform admin is
    added to an organization group" cannot be shown by the portal: role groups are managed in Authentik, not in
    Paddock (the portal manages `paddock.<slug>.g.<group>` only); the getting-started guide of M8g carries it.
33. Tests: `role_test.go` for the three reasons; acceptance `TestLoginGate` subtests assert the `reason` query of
    `Portal.Final` (`no_role` for the first case, `multiple_organizations` for the third) and the audit param through
    `expectOneEvent`; a new subtest "platform admin with an organization role" (temp user in
    `paddock.platform.admins` and `paddock.acme.admins`) → `platform_and_organization`.

### 3.10 App bar organization name and step-up freshness (PDK-212; closes PDK-191)

34. `App.vue`: the `org-name` span MUST get `:title="session.me.organization.name"` and be the activator of a
    `v-tooltip` (`:text` the name, `location="bottom"`, `open-on-click`, `open-on-hover`); CSS
    `.org-name { display: inline-block; max-width: 45vw; overflow: hidden; text-overflow: ellipsis; white-space:
    nowrap; vertical-align: bottom; }`. `mobile.spec.ts` MUST assert that the `org-name` element lies inside the
    viewport, has `title` equal to the organization name and `text-overflow: ellipsis` computed.
35. `Me` MUST gain `step_up_valid_until` (`date-time`, nullable, required): `p.StepUpAt + window` when
    `StepUpAt` is set and that instant is in the future, else `null`; `handlers` gets `stepUpWindow time.Duration`
    from `runner.StepUpWindow()` (production value 300 s). The development-only `step_up` object is unchanged.
    `App.vue` user menu (`data-testid="user-menu"`) MUST show a line `app.stepUpValidUntil` with the local time
    while valid, else `app.stepUpNone`; the app bar shows a `v-chip size="small" data-testid="stepup-chip"` with
    `app.stepUpChip` while valid (desktop only); a 1 s ticker hides both at expiry. `session.ts` keeps `me` as is
    (the step-up callback is a full navigation, so `me` is refetched).
36. Tests: acceptance `stepup_test.go`: `GET /api/v1/me` before a step-up → `step_up_valid_until: null`; after →
    within `[now, now+300 s]`. Component test `session.test.ts` for the chip and the menu line.

### 3.11 Texts: local administrator state, sudo scope, password switch (PDK-213)

37. `LocalAdminCard.vue` *Active password* row MUST show: the generation number; or, when `active_generation` is
    null and `pending_generation` is set, `devices.localAdmin.pendingConfirmation` (`{generation}`); or
    `devices.localAdmin.none`. `localAdmin.test.ts` covers the three states.
38. `PermissionProfiles.vue` MUST show the intro paragraph `profiles.intro` under the heading; the assignment dialog
    of `PermissionProfileDetail.vue` the hint `profiles.assignHint`; `DeviceAccess.vue`'s
    `devices.login.assignmentHint` becomes the §6.6 text.
39. `ProfileForm.vue` `requirePassword` switch MUST get `:hint="t('profiles.requirePasswordHint')"` and
    `persistent-hint`.

### 3.12 Root equivalence before submit (PDK-214)

40. New read-only endpoint (tag `privileges`, roles `RolesRead`, no `x-paddock-audit`, not in `privileged`):

    ```yaml
    GET /api/v1/permission-profiles/root-equivalence
      operationId: previewRootEquivalence
      parameters: class (PrivilegeClass, required), command (string, repeatable, maxItems 100, each maxLength 1024)
      200 RootEquivalence:
        required: [effective_class, root_equivalent_commands, witnesses]
        effective_class: PrivilegeClass
        root_equivalent_commands: string[]   # privilege.RootEquivalentCommands of the normalized commands
        witnesses: string[]                  # privilege.RootWitnesses(class, commands): "ALL", "cmd:<c>", "pair:<writer>|<command>"
      400 invalid_request · 401 · 403 forbidden
    ```

    The handler calls `privilege.NormalizeProfile`, `EffectiveClass`, `RootEquivalentCommands`, `RootWitnesses`
    only (no database, no audit). `lib/profiles.ts` gains `previewRootEquivalence(cls, commands)`.
41. `ProfileForm.vue` MUST call it 300 ms after the last change of class or commands (class `restricted` with at
    least one command, or class `full`) and show `v-alert type="warning" variant="tonal"
    data-testid="root-equivalent-preview"`: for `full` the text `profiles.fullPreview`; for a restricted profile
    with witnesses `profiles.rootEquivalentPreview` (`{commands}` = `root_equivalent_commands` joined with `, `)
    followed by one line `profiles.rootEquivalentPair` per `pair:` witness; nothing when there is no witness. A
    failed call shows nothing (the server enforces on submit).
42. Tests: handler unit test (`/usr/bin/apt update` → `effective_class: full`, witnesses `cmd:/usr/bin/apt
    update`; `/usr/bin/tee /opt/x` + `/opt/x` → pair; `/usr/bin/systemctl restart nginx.service` → restricted, none);
    `TestOpenAPISpec` unchanged; component test in `permissionProfiles.test.ts` with a mocked endpoint.

### 3.13 Managed files: non-ASCII paths, link to the shared directories, German term (PDK-215)

43. `ManagedFileForm.vue` MUST show `v-alert type="info" variant="tonal" data-testid="path-non-ascii"` with
    `managed.files.pathNonAscii` while `/[^\x20-\x7e]/.test(form.path)`; submit stays possible.
44. `ManagedFiles.vue` MUST show, under the heading, the paragraph `managed.files.operatorRootsHint` with a
    `router-link to="/settings/managed-files"` labelled `managed.files.operatorRootsLink`.
45. German term: every "Operator-Wurzel"/"Operator-Wurzeln" in `de.json` (lines 83, 353, 1000–1007) MUST become
    the §6.6 texts ("Freigegebene Verzeichnisse", page title "Freigegebene Verzeichnisse für Operatoren"); the
    glossary row 54 becomes `| Operator root (managed files) | Freigegebenes Verzeichnis (für Operatoren) | Directory
    below which operators manage files without a step-up. |`; `german.spec.ts` asserts the navigation entry
    "Freigegebene Verzeichnisse". English texts are unchanged.

### 3.14 Directory users without an organization domain (PDK-216)

46. `User` MUST gain `domain_match` (`boolean`, required): the part after the last `@` of `username` equals one
    of the organization's domains. `domain/user` gains `func DomainMatch(username string, domains []string) bool`;
    `Users.List` and `Users.Get` read the organization row once (`GetOrganization` in the same transaction) and set
    it for every item. The list filter set is unchanged.
47. `Users.vue` MUST show a `StatusChip` (`status="warning"`, label `users.noDomain`) after the username when
    `!item.domain_match`, and the banner `v-alert type="warning"` `users.orgNoDomains` above the list when
    `me.organization.domains` is empty. `UserDetail.vue` MUST show `v-alert type="warning"` `users.noDomainDetail`
    (`{username}`, `{domains}`) when `!user.domain_match`.
48. Tests: acceptance `identity_sync_test.go`: a temp Authentik user `lab<suffix>` (no `@`) in `paddock.acme`
    syncs with `domain_match: false`; `dave@acme.test` has `true`. Component test `identity.test.ts` for chip,
    banner and detail alert.

### 3.15 Bundle: readable release keys and release directory (PDK-217; closes PDK-188)

49. `prodcheck` MUST gain the item `secret files readable by the Paddock services`
    (`checkSecretFilesReadableByServices`, appended directly after `checkSecretFiles` for every host): for every
    service whose name starts with `paddock-` and every secret it references (`Service.Secrets`, source file
    `c.Secrets[source].File`), `os.Stat` the file; it passes when `mode&0o004 != 0`, or the owner uid is `65532`
    and `mode&0o400 != 0`; otherwise the finding `<service>: <secret> is not readable by the service user (uid
    65532): <file> has mode <%04o>, owner uid <uid>; run chmod 644 <file>`. A stat error is a finding. Third-party
    services are not checked (their images run with other users). Test `TestSecretFilesReadableByServices` with
    `t.TempDir()` files of mode 0600 (finding) and 0644 (pass).
50. `deploy/bundle/paddock` `agent-release` MUST, before `compose run`, check
    `find "$release_dir" \( -type d ! -perm -o=rx \) -o \( -type f ! -perm -o=r \)`; when it prints anything,
    `die "the release directory must be readable by the paddock-api service (uid 65532): run 'chmod -R a+rX
    $release_dir' — not readable: <first five paths>"`. `deploy/bundle/bundle_test.sh` gains a case with a 0700
    directory (exit 1, message contains `chmod -R a+rX`).
51. Documents: `install.md` §4 and `lab-install.md` step 7 add `chmod 644 .secrets/release-production/*.pub`;
    `install.md` §10, `lab-install.md` §6 and `agent-releases.md` state that `<dir>` and its files must be
    world-readable (`chmod -R a+rX <dir>`); `lab-install.md` §8 lists the new check item.

### 3.16 Documents and residual risks (PDK-218); regression and release (PDK-219)

52. PDK-218 MUST update: `device-login.md` (*Break-glass accounts and sudo*: the last-administrator rule and the
    advice "add existing local administrators as break-glass accounts before enrolment"; the two new sections of
    decisions 17 and 20; *Authentik brand flows*), `local-admin.md` (the pending-confirmation wording), `lab-install.md`
    §6 (domains first, break-glass before the first device, second-factor note), `install.md` §9 (same) and §12,
    `upgrade.md`, `openbao.md`, `step-up.md` (freshness indicator), `docs/architecture.md` with one dated amendment
    block `Amendment 2026-10-17 (M8x)` in §9.2 (brand authentication flow, default-flow MFA, `prompt=login`), §9.6
    (`amr` check), §10.1 (never the last administrator), §9.3 (Himmelblau 4.0.6, token settings);
    `docs/compliance/residual-risks.md` RR-40; `docs/compliance/glossary-de.md`; the CHANGELOG lines of every
    ticket are reviewed for operator language.
53. PDK-219 runs the full regression (`make lint test`, `make acceptance`, `make e2e`, `make system-test VM=all`,
    `make bundle-test`, `make scan-secrets`, `make gen` without diff) and prepares `0.1.0-alpha.4` as the
    `0.1.0-alpha.3` release commit did (`ed315b9`): version strings, CHANGELOG release heading, the PDK-203 line
    moved to `### Security` with the advisory link the maintainer provides (open point O2).

### 3.17 Amendment 2026-10-17 — Himmelblau must never manage the sudo group (PDK-294, lab finding L37)

Context (verified in the Himmelblau 4.0.4 and 4.0.6 sources; the lab's `auth.log` of device groot-XPS-13-9300): the
agent renders `local_groups = users` (plan M3b decision 7, PoC M1) and nothing else about groups. Himmelblau then
runs two things. (1) At every authentication the daemon submits `TaskRequest::LocalGroups(account, is_sudoer)`
(`daemon.rs` 852), unconditionally; the task (`tasks_daemon.rs` 637–660) adds the account to every `local_groups`
group with `gpasswd -a` and, unless `local_groups` contains `local_sudo_group` (default `sudo`), removes the
account from `local_sudo_group` when `is_sudoer` is false (`remove_user_from_group`: `getent group <group>` first,
`gpasswd -d` only for a member; a group that does not exist makes it a silent no-op at trace level). `is_sudoer` is
true only for members of an Entra group listed in `sudo_groups`, which Paddock never renders, so every account is
removed from `sudo`. (2) `reconcile_local_groups_periodically` (`daemon.rs` 381, every
`local_groups_reconcile_interval` seconds, default 300, `0` disables it) runs the same task for every row of
`get_unexpired_nssaccounts()` — Himmelblau's own sqlite `account_t` with `expiry > now`, **not** `/etc/passwd`. On
4.0.4 a synthetic NSS lookup of any name was cached as an account (`UserTokenState::Update`), so local accounts the
agent, GDM or AccountsService looked up (`paddock-admin`, `debian-gdm`, `groot`) became "accounts" and were removed
from `sudo` every five minutes while their cache entry was unexpired; `groot` was removed once and not again because
nobody looked him up afterwards and his entry expired after 300 s, while `paddock-admin` is looked up continuously.
4.0.6 caches synthetic lookups no longer (`LookupOnly`), but directory users stay affected and the login-time task
stays. With PDK-292's `cache_timeout` of 30 days every cached entry stays unexpired for 30 days, which would make the
periodic removal permanent on 4.0.4 — PDK-294 ships in the same release. Both `local_sudo_group` and
`local_groups_reconcile_interval` exist in 4.0.4 and 4.0.6 (`config.rs` tests at 1893 and 2226).

54. `renderHimmelblauConf` MUST render, after `local_groups = users` and before `idmap_range`:

    ```
    local_sudo_group = paddock-no-sudo
    local_groups_reconcile_interval = 0
    ```

    with the constants `himmelblauNoSudoGroup = "paddock-no-sudo"` (a group the agent never creates; Himmelblau's
    removal from it is a no-op because `getent group paddock-no-sudo` fails, and an addition to it never happens
    because `sudo_groups` is never rendered) and the why-comment: Paddock alone owns sudo (ADR 0008); Himmelblau's
    local-group task would remove every account from `sudo` and its periodic reconciliation did so every five minutes
    on the lab device. `sudo_groups` MUST NOT be rendered, ever; a unit test asserts its absence. `local_groups =
    users` stays (plan M3b decision 7: directory users join `users` once at login; removing the line would change the
    groups of new users silently and gains nothing once the periodic task is off).
55. No new drift alert: `himmelblau.conf` is compared byte-for-byte at every apply and drift pass and rewritten
    (`login.go` `fileIs`, then `restart`), and `/etc/himmelblau/` is a protected area whose change is reported as
    `device.tamper_protected_file_changed`; a locally added `sudo_groups` line is therefore reverted and reported
    already. The unit test of decision 54 covers the renderer; the existing drift test covers the revert.
56. Gate: PDK-294 extends `gateL6` (PDK-207, decision 18) with: in (a) the two configuration lines are present; (f)
    `getent group sudo` and `getent group users` captured before the eleven minutes equal the capture after them;
    (g) `sudo journalctl --since "<t0>" -o cat` contains no line matching `removed by root from group sudo`; (h)
    `paddockSQL` counts zero `device.tamper_local_admin_changed` events for the device since `t0`. The local
    administrator gate `TestLocalAdminGates` LA2 stays as the positive test of the repair path.
57. Documents: `docs/operations/device-login.md` *What the agent sets up* step 2 lists the two lines and the reason;
    `docs/architecture.md` §9.3 gets the lines in the `Amendment 2026-10-17 (M8x)` block of PDK-218; ADR 0019
    amendment (done); CHANGELOG `### Fixed`: "The login component no longer removes accounts from the sudo group or
    re-adds them to local groups every five minutes; Paddock alone manages sudo." An upstream note to Himmelblau
    ("LocalGroups task removes every account from local_sudo_group when sudo_groups is unset") is drafted by the
    implementer in the maintainer's notes, not posted.

### 3.18 Amendment 2026-10-17 — Contact state "Online" only within three check-ins (PDK-295, lab finding L36)

Context (verified): `paddock_device_contact(state, last_contact_at, presumed_lost_at, open_alert_kind)`
(migration `00043`, `IMMUTABLE`, inlined into `device.sql` lines 18, 27, 58, 70 and `overview.sql` line 19) answers
`ok` for every active device without a staleness alert, whatever `last_contact_at` is; the alerts come from the
worker's `Staleness.Evaluate` at the organization's thresholds (24 h warning, 168 h critical). The portal shows `ok`
as "Online" (`devices.contact.ok`, `status.ts` → `ok`), the device header's state chip too (`e2e devices.spec.ts:74`
expects `Online|Never contacted`), and the overview KPI "Online" counts `contact = 'ok'`. The agent checks in about
every 5 minutes; `app.AgentSilence` is 15 minutes (`inventory.go:19`), the window after which fleetd's policy
`paddock_agent_running` failing is recorded as `device.tamper_agent_not_running` and marked in
`inventory_policy_result.alerted_at` (cleared when the policy passes again). That open finding appears nowhere but
the audit log: `AttentionKind` has no kind for it (`admin.yaml` 4760, view `attention_condition` of `00039`).

58. New contact value **`unseen`**: an active device with `last_contact_at < now - 15 minutes` and no staleness
    alert and not presumed lost. Migration `000NN_device_contact_unseen.sql` (the next free number at implementation
    time; stop condition S12) MUST replace the function with

    ```sql
    CREATE FUNCTION paddock_device_contact(state text, last_contact_at timestamptz, presumed_lost_at timestamptz,
                                           open_alert_kind text, at timestamptz)
    RETURNS text LANGUAGE sql IMMUTABLE PARALLEL SAFE AS $$
      SELECT CASE
        WHEN state <> 'active' THEN CASE WHEN last_contact_at IS NULL THEN 'never' ELSE 'ok' END
        WHEN presumed_lost_at IS NOT NULL THEN 'presumed_lost'
        WHEN open_alert_kind = 'stale_critical' THEN 'stale_critical'
        WHEN open_alert_kind = 'stale_warning' THEN 'stale_warning'
        WHEN last_contact_at IS NULL THEN 'never'
        WHEN last_contact_at < at - interval '15 minutes' THEN 'unseen'
        ELSE 'ok'
      END
    $$;
    ```

    (`DROP FUNCTION` of the four-argument form first; `IMMUTABLE` stays valid because `at` is a parameter.) Every
    consumer passes `now()` as `at` (`device.sql` 18, 27, 58, 70; `overview.sql` 19). The 15 minutes are the one
    figure of `app.AgentSilence` (three check-ins); the migration's comment names it, and `inventory.go` gets the
    comment that the SQL literal mirrors the constant (stop condition S13 if either changes alone). Per-group
    staleness thresholds (M8d, PDK-222) keep driving the alerts; the `unseen` boundary is independent of them, and
    PDK-222's note "contact-state SQL function unchanged" now means "the five-argument function of PDK-295".
59. API and portal: `DeviceContact` enum gains `unseen` (description: "no check-in for more than 15 minutes, below
    the staleness warning threshold"); `deviceContacts` in `lib/devices.ts` gains it (filter option);
    `status.ts::deviceStatus` maps `unseen` to `{ status: 'warn', label: 'devices.contact.unseen' }`; `Overview.devices`
    gains `no_recent_contact` (integer, required; `overview.sql` FILTER `c.contact = 'unseen'`); the overview KPI
    "Silent" value becomes `silent + no_recent_contact` and its link includes `unseen`
    (`devices({ contact: ['unseen', 'stale_warning', 'stale_critical'] })`); the KPI "Online" keeps `contact = ok`.
    e2e `devices.spec.ts:74` accepts `Online|No recent contact|Never contacted` (devicesim devices check in once).
60. Attention kind **`agent_not_running`**: migration of decision 58 also replaces the view `attention_condition`
    (whole, as `00040` did) with the branch

    ```sql
    UNION ALL
    SELECT 'agent_not_running', d.id, d.hostname, r.alerted_at, '', 'agent_not_running:' || d.id::text
    FROM inventory_policy_result r JOIN device d ON d.id = r.device_id
    WHERE d.state = 'active' AND r.policy_key = 'paddock_agent_running' AND NOT r.passing AND r.alerted_at IS NOT NULL
    ```

    (the literal equals `inventory.PolicyAgentRunning`); `AttentionKind` enum, `attention.go` kinds list and the
    portal keys `attention.kinds.agent_not_running` / `attention.action.agent_not_running` are added exactly as
    `agent_rollback_pending` was; the device row's `AttentionChips` and the device header show it without further
    change. `inventory.sql` MUST clear `alerted_at` when the policy passes again if it does not already (verify
    `UpsertPolicyResult`; stop condition S14 if the pass path never resets it).
61. Texts (verbatim):

    | Key | English | German |
    | --- | --- | --- |
    | `devices.contact.unseen` | No recent contact | Kein aktueller Kontakt |
    | `devices.contactHint` | Online: a check-in within the last 15 minutes. No recent contact: none for more than 15 minutes, below the silence threshold of the organization. | Online: ein Check-in innerhalb der letzten 15 Minuten. Kein aktueller Kontakt: seit mehr als 15 Minuten keiner, unterhalb der Stille-Schwelle der Organisation. |
    | `attention.kinds.agent_not_running` | Agent not running | Agent läuft nicht |
    | `attention.action.agent_not_running` | Open device | Gerät öffnen |
    | `overview.kpi.silentNote` (existing note of the Silent KPI, reworded) | {count, number} without contact for more than 15 minutes, {critical, number} critical | {count, number} seit mehr als 15 Minuten ohne Kontakt, {critical, number} kritisch |

    `devices.contactHint` is shown as the hint of the contact filter (`contactFilter.hint`) and in the device header's
    state chip tooltip. If the existing Silent KPI note key differs from `overview.kpi.silentNote`, the implementer
    rewords the existing key and records its name.
62. Tests: migration integration test (an active device with `last_contact_at = now() - 16 min` → `unseen`; 14 min →
    `ok`; a retired device → `ok`; with an open `stale_warning` alert → `stale_warning`); acceptance `TestOverview`
    maps `unseen` to `no_recent_contact`; acceptance `TestAttention` (or the existing attention gate) inserts an
    `inventory_policy_result` failure with `alerted_at` for a devicesim device and expects kind `agent_not_running`
    with `GET /api/v1/attention?kind=agent_not_running`; component test `status.test.ts` for the mapping;
    `TestIsolation` fixtures unchanged. Documents: `docs/operations/monitoring.md` (or the document that explains
    staleness) gets the three-tier wording; the lab test plan step "Agent stoppen" expects "No recent contact" after
    15 minutes and the attention item after fleetd's next report; CHANGELOG `### Changed`.

### 3.19 Amendment 2026-10-17 — Denial reason for two roles in one organization (PDK-296, follow-up of PDK-211)

63. `organization.ResolveRole` MUST distinguish `DenialMultipleRoles DenialReason = "multiple_roles"` (several role
    groups of **one** organization, `len(res.Slugs) == 1 && matches > 1`) from `multiple_organizations`
    (`len(res.Slugs) > 1`); `platform_and_organization` keeps precedence when `platform` is set. Texts:
    `loginDenied.multiple_roles` EN "Your account holds several roles in one organization (administrator, operator
    or auditor). Ask your administrator to keep exactly one of the memberships." / DE "Ihr Konto hat mehrere Rollen in
    einer Organisation (Administrator, Operator oder Auditor). Bitten Sie Ihren Administrator, genau eine der
    Mitgliedschaften zu behalten." `role_test.go` case "two roles in one organization"; `TestLoginGate` subtest; the
    `admin.login` param documentation lists the fifth value.

## 4. Non-goals

- Any change to `agent/internal/revoke/`, `agent/cmd/paddock-revoke/`, `pkg/revocation/`.
- The bundle schema, the device API version. Migrations: only `00049_device_contact_unseen.sql` of §3.18 (PDK-295);
  no other M8x ticket adds one.
- Ending Authentik sessions on *end all sessions* (PDK-190 stays open; decision 1 removes its symptom).
- WebAuthn-only login (PDK-181), the role switch (PDK-201), the getting-started wizard and guide (M8g), the
  one-liner install (L11), hardware facts (L12), auto-unseal (M8u), device lifecycle (M8d).
- Report-only adoption (M11, PDK-160/161): referenced, not implemented.
- An English rename of "operator roots".
- Changing `refresh_token_validity` (30 days stays; open point O1) or setting `refresh_token_threshold` to any value
  other than `seconds=0` (breaks Himmelblau's PIN login, §2).
- Patching or forking Himmelblau; `enable_hello = false` as the default (the per-organization setting stays).

## 5. Affected files

| Path | Action | Purpose |
| --- | --- | --- |
| `docs/plans/M8x-lab-fixes.md` | new (this plan) | — |
| `docs/adr/0007-…`, `0008-…`, `0018-…`, `0019-…`, `0034-…` | amended (done) | dated amendments 2026-10-17 |
| `server/internal/transport/http/admin/{bff,server}.go`, `login_test.go` | change | §3.1, §3.8, §3.9 |
| `server/internal/app/accounts.go` | change | reasons, `RecordLoginFailure` signature, `ErrOrganizationInactive` |
| `server/internal/config/config.go`, `server/cmd/paddock-server/{api,main}.go` | change | dev switch, readiness text, healthcheck body |
| `server/internal/prodcheck/prodcheck.go`, `compose_test.go`, `prodcheck_test.go` | change | `devOnly`, readable-secrets item, blueprint test |
| `server/internal/adapters/authentik/{brand,devicelogin}.go`, `brand_test.go`, `adapter_test.go` | change | brand authentication flow, provider token settings |
| `deploy/compose/authentik/blueprints/paddock-portal.yaml`, `deploy/compose/authentik/dev/paddock-dev.yaml` | change | default-flow MFA stage and dev skip |
| `deploy/compose/compose.dev.yaml` | change | `PADDOCK_LOGIN_MFA_OPTIONAL` |
| `deploy/compose/scripts/wait-healthy.sh`, `deploy/bundle/paddock`, `deploy/bundle/bundle_test.sh` | change | §3.8, §3.15 |
| `agent/internal/reconcile/{groups,sudo}.go`, `sudo_test.go`; `pkg/protocol/types.go` | change | §3.2 |
| `server/internal/domain/audit/codes.go`, `docs/compliance/audit-codes.md` (gen), `server/web/src/lib/auditCodes.gen.ts` (gen) | change | descriptions and params |
| `server/internal/domain/organization/role.go`, `role_test.go`; `server/internal/domain/user/user.go` | change | denial reasons; `DomainMatch` |
| `server/internal/app/users.go`, `server/internal/transport/http/admin/{handlers,handlers_identity}.go` | change | `domain_match`, `MeOrganization.domains`, `step_up_valid_until`, root-equivalence handler |
| `api/openapi/admin.yaml`, generated Go/TS | change | §6.1 |
| `server/cmd/paddock-server/compiler.go` | change | Himmelblau 4.0.6 |
| `agent/internal/reconcile/login.go`, `login_test.go` | change | `cache_timeout` line (PDK-292); `local_sudo_group`, `local_groups_reconcile_interval` lines (PDK-294) |
| `server/migrations/paddock/00049_device_contact_unseen.sql` (new), `queries/{device,overview,inventory}.sql`, `server/internal/app/attention.go`, `api/openapi/admin.yaml`, `server/web/src/lib/{devices,status,overview}.ts`, locales, `server/web/e2e/devices.spec.ts` | new/change | §3.18 (PDK-295) |
| `server/internal/domain/organization/role.go`, `role_test.go`, locales | change | §3.19 (PDK-296) |
| `server/web/src/composables/usePending.ts` (new), the 22 submit sites and the action views of decision 26 | new/change | §3.7 |
| `server/web/src/views/{Organizations,LoginDenied,PermissionProfiles,PermissionProfileDetail,ManagedFiles,Users,UserDetail,EnrollmentTokens,DeviceAccess}.vue`, `App.vue` | change | §3.3–§3.14 |
| `server/web/src/components/{ProfileForm,ManagedFileForm,LocalAdminCard,EnrollmentTokenForm,…}.vue` | change | hints, previews, states |
| `server/web/src/lib/{organizations,validation,profiles,loginSettings}.ts`, `stores/session.ts` | change | §3.6, §3.10, §3.12 |
| `server/web/src/locales/{en,de}.json`, `docs/compliance/glossary-de.md` | change | §6.6 |
| `server/web/src/__tests__/{organizations,enrollmentTokens,pending}.test.ts` (new), `{permissionProfiles,managedFiles,localAdmin,identity,session}.test.ts` | new/change | §8 |
| `server/web/e2e/{organizations}.spec.ts` (new), `{mobile,german,portal}.spec.ts` | new/change | §8 |
| `test/acceptance/{login,authentik_brand,identity_authentik,identity_sync,stepup,overview}_test.go`, `internal/env/env.go` | change | §9 |
| `test/system/identity_test.go`, `test/system/login.go` | change | gate L6, P4 case, comment |
| `docs/operations/{device-login,local-admin,lab-install,install,upgrade,openbao,step-up,agent-releases}.md`, `docs/architecture.md`, `docs/compliance/residual-risks.md`, `CHANGELOG.md` | change | §3.16 |

MUST NOT be touched: `agent/internal/revoke/`, `agent/cmd/paddock-revoke/`, `pkg/revocation/`, `pkg/bundle`,
`api/openapi/device.yaml` (the protocol change of decision 10 is a Go struct field of `pkg/protocol` and the audit
param registry; the device API document lists report events by name only — if it documents the payload fields, add
`reason` there as an optional field), `server/migrations/paddock/00001…00048` (PDK-295 adds `00049`),
`deploy/compose/compose.prod.yaml`,
`deploy/compose/compose.lab.yaml`, `deploy/compose/authentik/blueprints/paddock-stepup.yaml`, `paddock-device.yaml`,
`paddock-recovery.yaml`, `docs/adr/0001…0033` except the amended ones, files of plans M8b–M11.

## 6. Interfaces and formats

### 6.1 Admin API (`api/openapi/admin.yaml`)

```yaml
MeOrganization: + domains (string[], required)
Me:             + step_up_valid_until (date-time, nullable, required)
User:           + domain_match (boolean, required)
GET /api/v1/permission-profiles/root-equivalence   decision 40 (tag privileges, roles RolesRead, no audit)
RootEquivalence: {effective_class: PrivilegeClass, root_equivalent_commands: string[], witnesses: string[]}
```

`OrganizationCreate` is unchanged. No new problem code. One migration, `00049_device_contact_unseen.sql` (§3.18).

### 6.2 Device protocol (`pkg/protocol`)

```go
TamperSudoGroupMember struct { Group, Username string; Removed bool; Reason string `json:"reason,omitempty"` }
const SudoGroupMemberKeptLastAdmin = "last_admin"
```

### 6.3 Go signatures (new or changed)

```go
// server/internal/app
const ReasonMFARequired = "mfa_required"; const ReasonKeyStoreSealed = "key_store_sealed"
var ErrOrganizationInactive = problem.Forbidden.WithDetail("organization_inactive")
func (a *Accounts) RecordLoginFailure(ctx context.Context, ip, username, reason string, cause error)
type LoginRole struct { Platform bool; Slug string; Role principal.Role; Denied bool; Slugs []string; DenialReason string }

// server/internal/config
func LoadDevLoginMFAOptional(l *Loader, c Common) bool

// server/internal/transport/http/admin
type Deps struct { …; LoginMFAOptional bool }

// server/internal/domain/organization
type DenialReason string
type RoleResolution struct { …; Reason DenialReason }

// server/internal/domain/user
func DomainMatch(username string, domains []string) bool

// server/internal/adapters/authentik
type brand struct { UUID, FlowRecovery, FlowDeviceCode, FlowAuthentication string }

// agent/internal/reconcile
type privilegedGroup struct { Foreign []string; HasBreakGlass bool }
func (s *Sudo) groupMembers(ctx context.Context, spec bundle.SudoSpec) (map[string]privilegedGroup, error)
func (s *Sudo) cleanGroups(ctx context.Context, groups map[string]privilegedGroup) (bool, error)

// server/internal/prodcheck
func checkSecretFilesReadableByServices(c Config) Result   // item "secret files readable by the Paddock services"
```

### 6.4 Authentik objects

| Object | Setting | Value |
| --- | --- | --- |
| device provider `paddock-device-<slug>` | `access_code_validity` | `minutes=10` |
| device provider | `refresh_token_threshold` | `seconds=0` (Authentik default; MUST stay: any other value breaks the PIN login) |
| `himmelblau.conf` (agent) | `cache_timeout` | `2592000` (= `refresh_token_validity: days=30`) |
| default brand | `flow_authentication` | flow `paddock-admin-login` (worker, every 10 min) |
| flow `default-authentication-flow` | binding order 31 | stage `paddock-default-login-mfa` (configure, threshold 5 min) |
| portal authorize request | `prompt` | none (replaced 2026-10-17: `prompt=login` broke the step-up, decision 1) |
| step-up callback | `auth_time` | `>= step-up start` in whole seconds, missing refused (decision 1a) |

### 6.5 Audit registry changes

| Code | Change |
| --- | --- |
| `admin.login` | params + `denial_reason`; error code `mfa_required` for the new denial |
| `device.tamper_sudo_group_member` | description of decision 10; payload param `reason` |

### 6.6 UI texts (verbatim; English `en.json` / German `de.json`)

| Key | English | German |
| --- | --- | --- |
| `loginDenied.mfa_required` | Your sign-in did not include a second factor. Sign in again: the portal asks for your password and your authenticator. | Ihre Anmeldung enthielt keinen zweiten Faktor. Melden Sie sich erneut an: Das Portal fragt nach Ihrem Passwort und Ihrem Authenticator. |
| `loginDenied.key_store_sealed` | The server's key store is sealed, so the portal cannot start sessions. An operator must unseal OpenBao (docs/operations/openbao.md, section 2). Devices keep working. | Der Schlüsselspeicher des Servers ist versiegelt, deshalb kann das Portal keine Sitzungen starten. Ein Operator muss OpenBao entsiegeln (docs/operations/openbao.md, Abschnitt 2). Geräte arbeiten weiter. |
| `loginDenied.no_role` | Your account is not in any Paddock role group. Ask your administrator to add you to exactly one of the groups paddock.<organization>.admins, .operators or .auditors. | Ihr Konto ist in keiner Paddock-Rollengruppe. Bitten Sie Ihren Administrator, Sie genau einer der Gruppen paddock.<Organisation>.admins, .operators oder .auditors hinzuzufügen. |
| `loginDenied.multiple_organizations` | Your account holds roles in several organizations. One account belongs to exactly one organization; ask your administrator to remove the other memberships or to create separate accounts. | Ihr Konto hat Rollen in mehreren Organisationen. Ein Konto gehört zu genau einer Organisation; bitten Sie Ihren Administrator, die übrigen Mitgliedschaften zu entfernen oder getrennte Konten anzulegen. |
| `loginDenied.platform_and_organization` | This account holds platform and organization roles. By design one account is either a platform administrator or a member of one organization: use separate accounts, or ask your administrator to remove one of the memberships. | Dieses Konto hat Plattform- und Organisationsrollen. Ein Konto ist entweder Plattformadministrator oder Mitglied einer Organisation: Verwenden Sie getrennte Konten, oder bitten Sie Ihren Administrator, eine der Mitgliedschaften zu entfernen. |
| `loginDenied.organization_inactive` | Your organization is not active. Ask a platform administrator. | Ihre Organisation ist nicht aktiv. Wenden Sie sich an einen Plattformadministrator. |
| `tokens.noDomainWarning` | This organization has no domain: its devices get no login management and no managed local administrator. Add the existing local administrator accounts of a device as break-glass accounts before you enroll it. Without a break-glass account in the sudo group, the agent keeps the present members and reports them; it removes them once a break-glass account or the managed local administrator is a member. | Diese Organisation hat keine Domain: Ihre Geräte erhalten keine Anmeldeverwaltung und keinen verwalteten lokalen Administrator. Tragen Sie die vorhandenen lokalen Administratorkonten eines Geräts als Notfallkonten ein, bevor Sie es registrieren. Ohne Notfallkonto in der Gruppe sudo behält der Agent die vorhandenen Mitglieder und meldet sie; er entfernt sie, sobald ein Notfallkonto oder der verwaltete lokale Administrator Mitglied ist. |
| `tokens.breakGlassHint` | Devices enrolled with this token keep only the managed local administrator ({username}) and the break-glass accounts in the sudo group; every other member is removed at the first apply and reported. Add the existing local administrators of a device as break-glass accounts before you enroll it. | Mit diesem Token registrierte Geräte behalten nur den verwalteten lokalen Administrator ({username}) und die Notfallkonten in der Gruppe sudo; jedes andere Mitglied wird beim ersten Anwenden entfernt und gemeldet. Tragen Sie die vorhandenen lokalen Administratoren eines Geräts als Notfallkonten ein, bevor Sie es registrieren. |
| `tokens.breakGlassLink` | Break-glass accounts | Notfallkonten |
| `loginSettings.breakGlassHint` | Local accounts, one per line, that Paddock never restricts: never denied by a lock, never ended by a suspension, never removed from sudo. Add the existing local administrators of a device before you enroll it; a sudo group without a break-glass account keeps its members. | Lokale Konten, eines pro Zeile, die Paddock nie einschränkt: nie durch eine Sperre abgewiesen, nie durch eine Aussetzung beendet, nie aus sudo entfernt. Tragen Sie die vorhandenen lokalen Administratoren eines Geräts ein, bevor Sie es registrieren; eine sudo-Gruppe ohne Notfallkonto behält ihre Mitglieder. |
| `organizations.domains` | Domains (one per line) | Domains (eine pro Zeile) |
| `organizations.domainsHint` | Lowercase DNS names of the organization's users, for example example.org; the first is the primary domain of the device login. Without a domain, login management, the login component and the managed local administrator stay off. | DNS-Namen der Benutzer der Organisation in Kleinbuchstaben, zum Beispiel example.org; die erste ist die primäre Domain der Geräteanmeldung. Ohne Domain bleiben Anmeldeverwaltung, Anmeldekomponente und verwalteter lokaler Administrator aus. |
| `organizations.editDomains` | Domains | Domains |
| `organizations.editDomainsTitle` | Domains of {name} | Domains von {name} |
| `organizations.createdWithoutDomains` | The organization was created, but its domains were not saved. Save them with "Domains" in the list. | Die Organisation wurde angelegt, ihre Domains wurden aber nicht gespeichert. Speichern Sie sie über „Domains“ in der Liste. |
| `validation.domainsInvalid` | Enter lowercase DNS names, one per line, at most 20 without duplicates. | Geben Sie DNS-Namen in Kleinbuchstaben ein, einen pro Zeile, höchstens 20 ohne Dopplungen. |
| `app.stepUpValidUntil` | Identity confirmed until {time} | Identität bestätigt bis {time} |
| `app.stepUpNone` | No current identity confirmation | Keine aktuelle Identitätsbestätigung |
| `app.stepUpChip` | Confirmed until {time} | Bestätigt bis {time} |
| `devices.localAdmin.pendingConfirmation` | none confirmed yet — password {generation, number} is stored and waits for the device's confirmation at its next check-in (within about 5 minutes) | noch keines bestätigt — Passwort {generation, number} ist gespeichert und wartet auf die Bestätigung des Geräts beim nächsten Check-in (innerhalb von etwa 5 Minuten) |
| `profiles.intro` | Permission profiles grant sudo rights to directory users who sign in on devices through the login component. They never apply to local accounts such as break-glass accounts or the managed local administrator. Which directory users may sign in on a device is set on the device's Access tab. | Berechtigungsprofile gewähren Verzeichnisbenutzern sudo-Rechte, die sich über die Anmeldekomponente an Geräten anmelden. Für lokale Konten wie Notfallkonten oder den verwalteten lokalen Administrator gelten sie nie. Welche Verzeichnisbenutzer sich an einem Gerät anmelden dürfen, legen Sie im Reiter „Zugang“ des Geräts fest. |
| `profiles.assignHint` | Assignments target directory users and user groups; local accounts of the device are never affected. | Zuweisungen gelten für Verzeichnisbenutzer und Benutzergruppen; lokale Konten des Geräts sind nie betroffen. |
| `devices.login.assignmentHint` | Only these directory users and groups can sign in on this device; permission profiles apply to them only, never to local accounts. | Nur diese Verzeichnisbenutzer und Gruppen können sich an diesem Gerät anmelden; Berechtigungsprofile gelten nur für sie, nie für lokale Konten. |
| `profiles.requirePasswordHint` | When on, sudo asks the user to authenticate before the first command of a session and again after the timeout; when off, the commands run without a prompt. Keep it on except for profiles whose commands must run unattended. | Wenn aktiv, verlangt sudo vor dem ersten Befehl einer Sitzung und nach Ablauf des Timeouts eine Authentifizierung; wenn inaktiv, laufen die Befehle ohne Abfrage. Lassen Sie die Option aktiv, außer für Profile, deren Befehle unbeaufsichtigt laufen müssen. |
| `profiles.fullPreview` | Class full grants root for every command. Saving needs an organization administrator with a fresh identity confirmation (step-up). | Die Klasse „vollständig“ gewährt root für jeden Befehl. Zum Speichern braucht es einen Organisationsadministrator mit frischer Identitätsbestätigung. |
| `profiles.rootEquivalentPreview` | This profile grants root in effect through {commands}. Saving needs an organization administrator with a fresh identity confirmation (step-up). | Dieses Profil gewährt faktisch root durch {commands}. Zum Speichern braucht es einen Organisationsadministrator mit frischer Identitätsbestätigung. |
| `profiles.rootEquivalentPair` | {writer} together with {command}: the first writes what the second runs. | {writer} zusammen mit {command}: Der erste schreibt, was der zweite ausführt. |
| `managed.files.pathNonAscii` | The path contains characters outside ASCII. The device writes it as given; make sure the program that reads the file expects this name. | Der Pfad enthält Zeichen außerhalb von ASCII. Das Gerät schreibt ihn unverändert; stellen Sie sicher, dass das Programm, das die Datei liest, diesen Namen erwartet. |
| `managed.files.operatorRootsHint` | Operators create and change files only below the operator roots; every other path needs an organization administrator with a step-up. | Operatoren legen Dateien nur unterhalb der freigegebenen Verzeichnisse an und ändern sie dort; jeder andere Pfad erfordert einen Organisationsadministrator mit Identitätsbestätigung. |
| `managed.files.operatorRootsLink` | Configure operator roots | Freigegebene Verzeichnisse festlegen |
| `nav.operatorRoots` | Operator roots (unchanged) | Freigegebene Verzeichnisse |
| `managedFiles.roots.title` | (unchanged) | Freigegebene Verzeichnisse für Operatoren |
| `managedFiles.roots.label` | (unchanged) | Freigegebene Verzeichnisse (eines pro Zeile) |
| `managedFiles.roots.confirmTitle` | (unchanged) | Freigegebene Verzeichnisse ändern |
| `managedFiles.roots.confirm` | (unchanged) | {count, plural, one {# freigegebenes Verzeichnis} other {# freigegebene Verzeichnisse}} speichern? Anschließend bestätigen Sie Ihre Identität. |
| `managedFiles.roots.saved` | (unchanged) | Die freigegebenen Verzeichnisse wurden gespeichert. |
| `managedFiles.roots.intro`, `.hint`, `.warning` | (unchanged) | the existing sentences with „Operator-Wurzel(n)“ replaced by „freigegebene(s) Verzeichnis(se)“ and „unterhalb einer Wurzel“ by „unterhalb eines freigegebenen Verzeichnisses“ |
| `audit.settings.managed_files_changed` | (unchanged) | {actor} hat die freigegebenen Verzeichnisse für Operatoren der verwalteten Dateien geändert |
| `users.noDomain` | No organization domain | Keine Organisationsdomain |
| `users.noDomainDetail` | The username {username} does not end with one of the organization's domains ({domains}). The user cannot sign in on devices: the login component accepts name@domain only. Rename the user in the identity source, or let a platform administrator add the domain to the organization. | Der Benutzername {username} endet nicht auf eine der Domains der Organisation ({domains}). Der Benutzer kann sich nicht an Geräten anmelden: Die Anmeldekomponente akzeptiert nur name@domain. Benennen Sie den Benutzer in der Identitätsquelle um, oder lassen Sie einen Plattformadministrator die Domain der Organisation hinzufügen. |
| `users.orgNoDomains` | This organization has no domain yet. Local users cannot be created and no user can sign in on devices until a platform administrator adds one under Platform → Organizations. | Diese Organisation hat noch keine Domain. Lokale Benutzer können nicht angelegt werden und niemand kann sich an Geräten anmelden, bis ein Plattformadministrator unter Plattform → Organisationen eine hinzufügt. |

The German glossary (`docs/compliance/glossary-de.md`) gains the terms Notfallkonto (break-glass account, already
in use), Anmeldekomponente (login component) and Freigegebenes Verzeichnis (operator root) where missing.

## 7. Host and operator notes (binding figures for the documents)

- After the upgrade every Authentik sign-in asks for a second factor; `akadmin` enrols one at its next login.
- A Hello PIN now outlives the access token on devices with an agent of this release (update the agents first);
  after 30 days without a PIN authentication a device-code sign-in with a new PIN is expected (RR-40).
- `cache_timeout` and `refresh_token_validity` are one figure (30 days) in two places (agent constant, device
  provider); they move together.
- The device code at the login screen is valid for 10 minutes.
- Release public keys: `chmod 644`; release directories for `./paddock agent-release`: `chmod -R a+rX`.
- A device whose sudo group has no break-glass member keeps its members and reports them; configure break-glass
  accounts (and a domain) before the first enrolment.

## 8. Steps (tickets, in order)

1. **PDK-203 — Portal login requires a second factor on every Authentik path** (§3.1, closes PDK-202). Verify:
   `go test ./server/internal/transport/http/admin/ ./server/internal/adapters/authentik/ ./server/internal/prodcheck/
   ./server/internal/config/`; `make down V=1 dev-secrets up dev-seed acceptance T='TestLogin|TestAuthentikBrandFlows|TestStepUp'`;
   `make e2e`.
2. **PDK-204 — Never remove the last administrator** (§3.2). Verify: `go test ./agent/... ./pkg/...`; `make gen`
   no diff; `make system-test VM=all T=TestIdentityGates` (P4 case).
3. **PDK-205 — Break-glass guidance before enrolment** (§3.3). Verify: `make typecheck`; `make web`; acceptance me
   check.
4. **PDK-206 — Device code lifetime** (§3.4 decisions 16–17). Verify: `go test ./server/internal/adapters/authentik/`;
   `make acceptance T=TestIdentityAuthentikProvisioning`.
4a. **PDK-292 — Agent renders `cache_timeout`** (§3.4 decision 16a). Verify: `go test ./agent/...`; the L6 gate of
   PDK-207 once it exists (PDK-207 runs it against this change).
5. **PDK-207 — System gate L6, Himmelblau 4.0.6, login messages** (§3.5). Verify: `make system-test VM=all
   T='TestIdentityGates|TestLocalAdminGates|TestNoticeGate'` on both VMs.
6. **PDK-208 — Organization domains in the portal** (§3.6). Verify: `make web`; `make e2e`.
7. **PDK-209 — Loading state on every submitting button** (§3.7). Verify: `make web`; `make e2e`.
8. **PDK-210 — Readable "key store sealed"** (§3.8). Verify: `go test ./server/...`; `make bundle-test`.
9. **PDK-211 — Login denied with the reason** (§3.9). Verify: `go test ./server/internal/domain/organization/
   ./server/internal/app/ ./server/internal/transport/http/admin/`; `make acceptance T=TestLoginGate`.
10. **PDK-212 — App bar organization name, step-up freshness** (§3.10, closes PDK-191). Verify: `make web`;
    `make e2e`; `make acceptance T=TestStepUp`.
11. **PDK-213 — Local administrator state, sudo scope, password switch texts** (§3.11). Verify: `make web`.
12. **PDK-214 — Root equivalence before submit** (§3.12). Verify: `go test ./server/internal/transport/http/admin/`;
    `make gen` no diff; `make web`.
13. **PDK-215 — Managed files: non-ASCII, link, German term** (§3.13). Verify: `make web`; `make e2e` (german).
14. **PDK-216 — Directory users without an organization domain** (§3.14). Verify: `go test ./server/...`;
    `make acceptance T=TestIdentitySync`; `make web`.
15. **PDK-217 — Bundle: readable release keys and release directory** (§3.15, closes PDK-188). Verify: `go test
    ./server/internal/prodcheck/`; `make bundle-test`.
16. **PDK-218 — Documents and residual risks** (§3.16). Verify: `make lint`; links resolve.
17. **PDK-219 — Regression and release 0.1.0-alpha.4** (§3.16). Verify: every command of decision 53 green.
18. **PDK-294 — Himmelblau must never manage the sudo group** (§3.17, amendment). Verify: `go test ./agent/...`;
    `make system-test VM=all T='TestIdentityGates|TestLocalAdminGates'` (gate L6 with (f)–(h)). Depends on
    PDK-207 (gate L6 exists) and ships with PDK-292; PDK-219 runs after it.
19. **PDK-295 — Contact state "Online" only within three check-ins; attention kind agent_not_running** (§3.18,
    amendment). Verify: `go test ./server/...` (migration test); `make gen` no diff; `make acceptance
    T='TestOverview|TestAttention|TestDevices'`; `make e2e` (devices); `make web`. Depends on no M8x ticket; PDK-219
    runs after it.
20. **PDK-296 — Denial reason for two roles in one organization** (§3.19, amendment). Verify: `go test
    ./server/internal/domain/organization/ ./server/internal/app/`; `make acceptance T=TestLoginGate`. Depends on
    PDK-211.

PDK-203 first; PDK-204, PDK-206, PDK-292 and PDK-208 MAY run in parallel after it. PDK-205 depends on PDK-204
(texts name its rule); PDK-207 on PDK-206 and PDK-292; PDK-212 on PDK-209 (the chip uses no pending state, but both
touch `App.vue`);
PDK-213, PDK-214, PDK-215, PDK-216 MAY run in parallel after PDK-209; PDK-218 after every other ticket but PDK-219.

## 9. Acceptance criteria (positive and negative per role)

Roles: **A** = org_admin (`env.Alice` or a temp admin), **U** = org_auditor (`env.Bob`), **P** = platform admin,
**D** = a device (VM), **O** = operator of the bundle host, **S** = a user signing in on a device.

| # | Given / When / Then | Role sees |
| --- | --- | --- |
| S1 | `GET /api/auth/login` → the `Location` contains no `prompt` (replaced 2026-10-17); a step-up token with `auth_time` before the step-up start is refused (unit); the default brand's `flow_authentication` is `paddock-admin-login`; `default-authentication-flow` has the binding at order 31 to `paddock-default-login-mfa` with `not_configured_action: configure`. | P (Authentik API) |
| S2 | (unit) An ID token without `mfa` in `amr` → `/login-denied?reason=mfa_required`, no cookie, one `admin.login` denied `mfa_required`; with `mfa` → session; with the development switch → session. `PADDOCK_LOGIN_MFA_OPTIONAL` in a production configuration fails `./paddock check` (`no development-only variables`). | A, O |
| S3 | (VM, P4) A foreign member of `sudo` on a device whose bundle names no break-glass account stays a member; `device.tamper_sudo_group_member` arrives with `removed=false`, `reason=last_admin`; with a break-glass member present the foreign member is removed. | D, A (audit) |
| S4 | The device provider of acme has `access_code_validity: minutes=10` and `refresh_token_threshold: seconds=0`; the agent's `himmelblau.conf` on a VM contains `cache_timeout = 2592000` and `renderHimmelblauConf` emits it (unit test). | P (Authentik API), D |
| S5 | (VM, L6) After eleven minutes of cached-user lookups the locked GNOME session unlocks with the PIN, a PAM PIN login succeeds, and Authentik recorded no `suspicious_request` since the login; the same gate fails on an agent without PDK-292 (recorded once as the reproduction). | S, D |
| S6 | P creates an organization with a domain in the portal → the row shows the domain and the audit log has `organization.created` and `organization.domains_changed`; P edits the domains of a row → PATCH, row updated; a domain of another organization → the dialog shows the `domain_taken` text. | P |
| S7 | While a create request is in flight, the submit button is disabled and shows a progress indicator (component tests for profiles and managed files; e2e for organizations). | A, P |
| S8 | (unit) With an empty keyring `GET /api/auth/login` redirects to `/login-denied?reason=key_store_sealed`; the page shows the OpenBao text. `paddock-server healthcheck` against a sealed api prints `session keys not loaded: OpenBao is sealed or unreachable`. | A, O |
| S9 | A user in `paddock.platform.admins` and `paddock.acme.admins` → `/login-denied?reason=platform_and_organization`, event param `denial_reason=platform_and_organization`; no role → `no_role`; two organizations → `multiple_organizations`. | S (portal), U (audit) |
| S10 | At 390 px the organization name is inside the viewport with `text-overflow: ellipsis` and `title` equal to the full name. | A (phone) |
| S11 | `GET /api/v1/me` has `step_up_valid_until: null` before and a time within 300 s after a step-up; the user menu shows "Identity confirmed until …" after a step-up. | A |
| S12 | A device with `active_generation: null` and `pending_generation: 1` shows "none confirmed yet — password 1 is stored …". | A |
| S13 | `GET /api/v1/permission-profiles/root-equivalence?class=restricted&command=/usr/bin/apt%20update` → `effective_class: full`, witnesses `["cmd:/usr/bin/apt update"]`; U may call it; the form shows the warning 300 ms after typing the command, before submit. | A, U |
| S14 | A path `/etc/myapp/konfiguration-ä.conf` shows the non-ASCII hint and can still be submitted; the managed files page links to `/settings/managed-files`; the German navigation shows "Freigegebene Verzeichnisse" and `de.json` contains no "Operator-Wurzel". | A |
| S15 | A synced user without `@` has `domain_match: false` and the chip "No organization domain"; `dave@acme.test` has `true`; the Users page of an organization without domains shows the banner. | A |
| S16 | A 0600 release public key owned by uid 1000 fails `./paddock check` with the item `secret files readable by the Paddock services` naming the file; `chmod 644` makes it pass; `./paddock agent-release 1.0.0 <0700 dir>` exits 1 naming `chmod -R a+rX`. | O |
| S17 | The full regression of decision 53 is green on `main` before the release commit. | all |
| S18 | (VM, L6 extended) `himmelblau.conf` carries `local_sudo_group = paddock-no-sudo` and `local_groups_reconcile_interval = 0`; `getent group sudo` is identical before and after the eleven minutes; the journal has no "removed by root from group sudo"; no `device.tamper_local_admin_changed` since the login; `renderHimmelblauConf` never emits `sudo_groups` (unit). | D, A (audit) |
| S19 | A devicesim device whose last check-in is 16 minutes old lists with `contact: unseen` ("No recent contact"), is counted in `overview.devices.no_recent_contact` and in the Silent KPI; 14 minutes old → `ok`; an open `paddock_agent_running` failure with `alerted_at` lists as attention kind `agent_not_running` and shows on the device row. | A, U |
| S20 | A user in `paddock.acme.admins` and `paddock.acme.auditors` → `/login-denied?reason=multiple_roles`, event param `denial_reason=multiple_roles`. | S, U |

## 10. Freedoms

Helper names inside the use cases and components; the layout of the domains textarea and the row action within the
design system; whether `usePending` lives in one file per composable or next to `useConfirm.ts`; the split of the
new acceptance assertions into files (test names of §9 are binding); the exact wording of log lines and of the
upstream issue; the fixture layout of the new prodcheck test; how `gateL6` structures its eleven-minute loop
(`Until` or a ticker); the CSS of the step-up chip; whether `previewRootEquivalence` debounces with a composable or
`setTimeout`.

## 11. Stop conditions

- S1: Authentik's blueprint importer rejects the binding at order 31 on `default-authentication-flow` or the
  `last_auth_threshold` attribute (report the importer log; do not bind at order 30 and do not remove `configure`).
- S2: (withdrawn 2026-10-17 with decision 1; `prompt=login` is removed.) Instead: the step-up start cannot be
  carried in the step-up state cookie, or Authentik's step-up token has no `auth_time` (report; do not relax
  decision 1a).
- S3: Authentik 2026.8.3 refuses `access_code_validity: minutes=10` in the provider PUT (report the response; never
  set `refresh_token_threshold` above zero as a substitute).
- S4: a system gate regresses with Himmelblau 4.0.6 (sudo UID resolution before the first login, local administrator,
  notice): keep `4.0.4` as the default, keep gate L6, report.
- S5: gate L6 fails with PDK-292 merged (the sealed token is still rejected, or Himmelblau refuses
  `cache_timeout = 2592000`): report the Himmelblau log lines, the rendered configuration and Authentik's events; do
  not weaken the gate and do not lower the value below 86400 without reporting.
- S6: the organization row is not readable inside `InOrg` for `MeOrganization.domains` or `User.domain_match`
  (report the RLS policy; do not read with the platform pool).
- S7: `TestOpenAPISpec` or the privileged-route table refuses a `GET` without `x-paddock-audit` (report; do not add an
  audit code for a read).
- S8: a Vuetify button cannot expose a `role="progressbar"` child while loading (report; the test then asserts the
  `disabled` attribute and `aria-busy`).
- S9: a change seems necessary in `agent/internal/revoke/`, `agent/cmd/paddock-revoke/`, `pkg/revocation/`,
  `pkg/bundle`, `api/openapi/device.yaml` beyond the documentation note of §5, or a migration.
- S10: a new Go module, npm package or container image seems necessary (none is expected).
- S11: `wait-healthy.sh` cannot obtain container names from `compose ps --format` on the pinned Compose version
  (report the output; fall back to printing the service name only).
- S12: the next migration number collides with an unmerged plan (M11 `00049_adoption.sql`, M8d device-group
  policies): take the next free number on `main` at implementation time and report it; never renumber a merged file.
- S13: `app.AgentSilence` and the SQL literal of decision 58 differ when PDK-295 starts (report; change both).
- S14: `inventory_policy_result.alerted_at` is never reset when the policy passes again (report; the attention kind
  would never clear — fix the pass path in the same ticket only if it is a one-line `UPDATE`, else stop).
- S15: Himmelblau logs an error (not trace or debug) for `local_sudo_group = paddock-no-sudo` on the VMs (report the
  line; do not create the group).

## 12. Risks and open points

- ~~**`prompt=login` on every portal sign-in** costs one password-plus-factor per portal session (8 h).~~
  Withdrawn 2026-10-17: `prompt=login` is not sent (decision 1). **Authentik's `prompt=login` quirk**
  (`last_login_uid` never cleared) would have let a step-up pass silently within 60 s of a login; decision 1a's
  `auth_time >= step-up start` check guards the step-up independently of Authentik's prompt handling. A live
  Authentik session (with its second factor) signs in to the portal again after *end all sessions* until PDK-190 ends
  the Authentik session too.
- **Second factor on Authentik's own interfaces.** `akadmin` and every administrator enrol at the next login; a
  user without a phone cannot sign in anywhere. The upgrade note says it; the development stack skips the stage.
- **Authentik upgrade** may re-apply its default blueprints: the Paddock stage at order 31 is a separate object and
  survives; the worker keeps the brand's authentication flow every 10 minutes.
- **Himmelblau 4.0.6** changes synthetic-user caching; the system gates decide (S4).
- **PIN re-enrolment after 30 days without a PIN authentication** (RR-40) until Himmelblau re-seals a rotated
  refresh token; the maintainer posts the upstream issue after a 4.0.6 reproduction. Devices with an older agent
  keep failing after every background refresh until the agent is updated (agents first).
- **Stale cached attributes for 30 days.** Himmelblau's NSS cache of a signed-in user (name, shell, `id` groups)
  refreshes at the next PIN authentication; a locked user disappears from `getent passwd` until the next login.
  No access decision depends on it (§2); documented in `device-login.md`.
- **Two audit events for a create with domains** (`organization.created`, `organization.domains_changed`): accepted
  and documented; the M8g wizard may later ask for an atomic create (own decision).
- **Last-administrator guard delays hygiene** on devices without any break-glass member: the members are reported,
  and the attention/audit trail shows them; administrators configure break-glass accounts to let the cleanup run.
- O1 (open, default chosen): raise `refresh_token_validity` (and with it `cache_timeout`) above 30 days to make
  the re-enrolment rarer? Default: no; both stay 30 days (ADR 0019 setting).
- O2 (open): the advisory ID for the PDK-203 security line of the release commit; the maintainer provides it to
  PDK-219 or the line stays in `### Changed`.
- O3 (open, default chosen): the German navigation label is "Freigegebene Verzeichnisse" (short) with the page
  title "Freigegebene Verzeichnisse für Operatoren" (the maintainer's suggestion). Default: both as stated.
- O4 (open): the lab items L21, L22 and L23 are not in the lab log table (only in the maintainer's brief); the texts
  of §6.6 follow the brief. Default: implement as specified.
