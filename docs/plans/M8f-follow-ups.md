# Implementierungsplan: M8f — Follow-ups after the alpha.4 lab fixes (step-up binding, sessions, transport trust, test budgets)

Status: Ready for implementation · 2026-10-18 · Author: architect
Basis: the follow-up tickets PDK-180, PDK-181, PDK-187, PDK-189, PDK-190, PDK-290, PDK-291, PDK-293, PDK-297, PDK-298,
PDK-299, PDK-300, PDK-301; ADR 0034 (step-up and sessions, amended 2026-10-18 by this plan), ADR 0007 (Authentik
mapping, amended 2026-10-18), ADR 0024 (failed rollback, amended 2026-10-18), ADR 0032 (retention, amended 2026-10-18),
ADR 0040 (transport trust, new); plans M8x (lab fixes, merged in `c10a839`), M8u (auto-unseal) and M8d (device
lifecycle), which are implemented next to this plan and ship in the same release; the Authentik 2026.8.3 sources read
from the pinned image (`deploy/compose/versions.env`).

Binding language: **MUST** / **MUST NOT** / **SHOULD** / **MAY**.

Public repository: commit messages, pull requests and CHANGELOG lines describe policy and behaviour ("a step-up proves
a WebAuthn authenticator", "ending all sessions also signs administrators out of the identity provider"), never an
attack sequence. The sequence of §2 (PDK-297) stays in this plan and the ticket.

## 1. Goal

After M8f a step-up proves a WebAuthn authenticator inside Paddock, not only inside Authentik; a repeated step-up no
longer has to wait a minute; new administrators enrol a WebAuthn authenticator at their first portal sign-in; *End all
sessions* also ends the administrators' Authentik sessions; a device that keeps checking in but stays behind its
configuration for an hour appears on the attention page, and the dead man's switch says that a blocked connection can
trigger it; public portal pages speak the browser's language; `./paddock logs` prints no token values; the
acceptance suite has a budget again; the system-test helpers fail the subtest that called them; a probation release is
rolled back exactly once; and the Playwright image cannot drift from the npm package unnoticed. Two tickets are
decided and deferred (PDK-180, PDK-187).

## 2. Context (verified on 2026-10-18 in `main` at `c10a839` and in the Authentik 2026.8.3 image)

- **Step-up (PDK-297, PDK-299).** `server/internal/transport/http/admin/stepup.go`: `StepUpMaxAuthAge = 60 s`
  (`Deps.StepUpMaxAuthAge` shortens it in development: `compose.dev.yaml` sets `PADDOCK_STEPUP_MAX_AUTH_AGE: 15s`,
  `PADDOCK_STEPUP_WINDOW: 30s`); `stepUpStart` sends `prompt=login`, `max_age=<seconds>`, `login_hint`;
  `stepUpClaims{Subject, AuthTime, AMR, JTI, Groups}`; `checkStepUp(c, sess, started, now, maxAuthAge)` checks
  subject, `|now − auth_time| ≤ maxAuthAge`, `auth_time ≥ started`, `mfa ∈ amr`; `checkStepUpRole` resolves the role.
  The step-up provider (`deploy/compose/authentik/blueprints/paddock-stepup.yaml`) has the mappings `scope-openid`,
  `scope-profile`, `io.paddock/scope-groups`; the api's `OIDC` config (`bff.go:91`) requests `openid profile email
  groups` for both providers. The escrow-reader and the revocation-issuer accept a step-up proof whose `auth_time` is
  at most `app.StepUpValidity` (300 s) old in production and `PADDOCK_STEPUP_WINDOW` (30 s) in development
  (`server/cmd/paddock-server/{escrowreader,revocationissuer}.go`); the api's own window is the same 300 s. Portal
  text `problems.step_up_failed` says "wait a minute".
  Authentik 2026.8.3 (`providers/oauth2/views/authorize.py` 525–560): `get()` loads the session's login event; with
  `max_age` it re-authenticates when `now − login_event.created > max_age` (strictly greater, whole seconds from the
  query) and sets `authentik/providers/oauth2/last_login_uid`; with `prompt=login` it re-authenticates only when that
  key is absent or equals the current login event's pk; the key is never cleared. `providers/oauth2/id_token.py`
  `IDToken.new` (105–121): `auth_event = get_login_event(token.session)`, `amr` gets `pwd` for `method == "password"`,
  `user` for `auth_webauthn_pwl`, `sc` for `certificate` in the method args, `mfa` when `mfa_devices` is in the method
  args — **no class of the device**. `stages/authenticator_validate/stage.py` 150–156 appends the validated device
  (model instance) to `plan.context["auth_method_args"]["mfa_devices"]`; the login event's context is sanitized by
  `events/utils.py::model_to_dict` into `{app, model_name, pk, name}`, so the event holds
  `{"app": "authentik_stages_authenticator_webauthn", "model_name": "webauthndevice", …}` for a WebAuthn validation and
  `{"app": "authentik_stages_authenticator_totp", "model_name": "totpdevice", …}` for TOTP.
  `providers/oauth2/views/userinfo.py::get_claims` (67–84) evaluates every `ScopeMapping` of the provider whose
  `scope_name` is in the token's scopes with `user`, `request`, `provider` and **`token`** in the expression context;
  `events/signals.py::get_login_event(request_or_session)` accepts an `AuthenticatedSession` (63–73);
  `lib/expression/evaluator.py` runs expressions with `exec` and shipped blueprints import Authentik modules in
  expressions (`/blueprints/default/flow-oobe.yaml`), so a mapping may `from authentik.events.signals import
  get_login_event`.
  Consequence verified on paper (the ticket's sequence, simplified): hold the authorize URL of a started step-up
  (`Started = t0`), sign in through any Authentik flow reachable by slug that accepts TOTP (for example
  `/if/flow/default-authentication-flow/`, whose Authentik stage at order 30 validates TOTP and whose Paddock stage at
  order 31 accepts TOTP by design for every Authentik user) at `t1 > t0` in the same browser, then open the held URL
  within `max_age`: the login event is the TOTP login (`auth_time = t1 ≥ t0`, `mfa ∈ amr`), `last_login_uid` was set by
  the first pass and differs from the new event, so Authentik issues the code without running `paddock-stepup`.
  `auth_time ≥ started` holds; Paddock cannot tell the factor. A holder of password and TOTP without the WebAuthn
  authenticator passes the step-up. Not reproduced in a browser yet (PDK-297 reproduces it first).
- **Login factor (PDK-181).** `paddock-portal.yaml` stage `paddock-admin-login-mfa`: `device_classes: [webauthn,
  totp]`, `not_configured_action: configure`, configuration stages WebAuthn setup and TOTP setup. The default-flow
  stage `paddock-default-login-mfa` (order 31 of `default-authentication-flow`, every Authentik user) has the same
  settings plus `last_auth_threshold: minutes=5`. The device-login stages (`paddock-device.yaml`) accept both classes.
  Authentik's validate stage with `not_configured_action: configure` sends a user without a device of an allowed class
  to the configuration stage, directly when there is exactly one (`stage.py` 281–315). The development blueprint skips
  the stage at order 30 of `paddock-admin-login` and the stage at order 31 of the default flow. Tests:
  `server/internal/prodcheck/compose_test.go::TestStepUpBlueprintWebAuthnOnly`, `TestPortalBlueprintBindsMFAOnTheDefaultFlow`;
  acceptance `test/acceptance/stepup_test.go::TestStepUpFactor` reads validate stages through `env.NewAuthentik()`
  (`ak.Get("/stages/authenticator/validate/<pk>/")`). Runbooks: `docs/operations/step-up.md` (*Factor*, *Before
  upgrading to WebAuthn-only step-up*), `install.md` lines 274–313, `upgrade.md` line 12; residual risk RR-38.
- **Sessions (PDK-190).** `server/internal/app/sessions.go`: `Sessions{runner, store SessionEnder}`; `EndAll` and
  `EndAllCLI` run `store.EndAll` inside `runner.RunTx(ctx, ScopePlatform, spec, …)` and record `generation`;
  `handlers_sessions.go::EndAllSessions`; `server/cmd/paddock-server/admin.go` command `end-sessions` loads the Valkey
  configuration only. `bff.logout` returns Authentik's `end_session_endpoint` for the user's own browser. The Authentik
  adapter (`server/internal/adapters/authentik/`) is constructed in `api.go:154` (`authentik.New(url, token)`);
  `Client.RoleGroupUsers(ctx, groupName) ([]ports.IdentityUser, error)` lists a role group (`IdentityUser.PK` is
  Authentik's integer user pk as a string); the service role `paddock-service` in `paddock-portal.yaml` has 29
  permissions and none on sessions. Authentik 2026.8.3 `core/api/authenticated_sessions.py`:
  `DELETE /api/v3/core/authenticated_sessions/bulk_delete/?user_pks=<int>&user_pks=<int>` (permission
  `authentik_core.delete_authenticatedsession`, response `{"deleted": n}`), `GET /api/v3/core/authenticated_sessions/?user__username=<name>`
  (permission `authentik_core.view_authenticatedsession`); `core/signals.py` 124–127 deletes the Django `Session`
  when an `AuthenticatedSession` is deleted, so the browser is signed out. Acceptance `TestSessionsEndAll`
  (`sessions_test.go`, behind `PADDOCK_ACCEPTANCE_DISRUPTIVE=1`, own CI step); `env.NewAuthentik()` uses the bootstrap
  token.
- **Transport (PDK-293).** Verified: bundles and commands are DSSE-signed with trust anchors from
  `/etc/paddock/trust.json` (`agent/internal/config/config.go::LoadTrust`), bundle versions are monotonic, device
  requests are signed, the check-in response carries the organization's signed time ticket and signed commands; the
  bundle pointer of the response is unsigned (the bundle itself is signed). fleetd runs with the system CA store
  (`agent/internal/reconcile/inventory.go:39`, `/etc/ssl/certs/ca-certificates.crt`), Himmelblau too; neither pins.
  The server stores `device_status.applied_bundle_version` and `last_contact_at` (migration `00003`, query
  `device_status.sql`), the newest compiled bundle per device is `bundle(device_id, version, created_at)`; the
  attention view `attention_condition` (last recreated in `00049_device_contact_unseen.sql`, kinds in
  `api/openapi/admin.yaml` `AttentionKind` line 4805, portal `lib/status.ts` and `lib/updates.ts:161`, texts
  `attention.kinds.*` and `attention.action.*`) has no kind for a device that stays behind its bundle. Integration
  tests query the view directly (`server/internal/app/agentreleases_integration_test.go:384`); the acceptance suite has
  no SQL access to the paddock database (only the audit index). DMS texts: `dms.warning`, `dms.confirm.message`
  (`en.json` 1313–1329, `de.json` 1314–1326). Architecture §6.1 says "TLS protects metadata"; §12.6 describes the DMS.
- **Agent update (PDK-300).** `agent/internal/supervisor/supervisor.go::rollback` (350–375): on a durable flip back it
  calls `s.restartChild()` (the previous agent starts) **before** `s.conclude(p, outcomeRolledBack)`, which writes the
  probation log and the result (`probation.go::conclude` → `report` → `finishAt`: `cleanup(version)` removes
  `request.json`, syncs the staging directory, then writes `update-result.json`). The agent (`agent/internal/agent/
  agent.go` 342–349) reads the result at every successful check-in before it handles the response's offer
  (`reportUpdate` sets `state.FailedUpdateVersion`; `handleUpdate` skips that version and anything while
  `update.Pending`). The server offers the current release at every check-in to every device whose agent is older
  (`agentrelease.Offer.For`). A restarted agent that checks in before the result exists therefore gets the offer, stages
  the same release again and signals the supervisor, whose `onRequest` accepts it (`probation` and `rolledBack` are
  nil after a durable rollback): a second install, probation and rollback. The window is the time `conclude` needs
  (two fsyncs and a file write); the lab host's disk was under pressure that day. Development probation is 2 min
  (`paddock_dev`), the broken-probation build crashes, three crashes end the probation at once (`onExit`), which fits
  the 64 s between the two rollbacks. `supervisor_test.go` runs a fake with shell-script agents (`script(version,
  selfTest, run)`, `good()` writes the check-in mark, `stageAfterCheckin`, `waitResult`, injected clock).
  System gate `test/system/agent_test.go::gateS4` subtest `probation failure` waits for one `device.agent_rolled_back`.
- **System tests (PDK-298).** `test/system/stack.go`: `Stack{t, root, alice, composeFiles}`; `Login`, `StepUp`,
  `Call`, `DeleteOnCleanup`, `RevokeOnCleanup`, `cleanupCall`, `OperatorRoot`, `ID`, `Events`, `Make`, `Release`,
  `BuildAgent`, `Rollout` all report through `s.t`; `InstallRelease(t)` and `Until(t, …)` already take `t`.
  `forEachVM` (`agent_test.go` 37–53) creates one Stack per VM subtest and the gates run deeper subtests
  (`t.Run("S4 …", func(t) { d.Bind(t); … })`), so a Stack failure inside a gate panics with "subtest may have called
  FailNow on a parent test". 70 call sites in ten `_test.go` files.
- **Acceptance budget (PDK-189).** `Makefile`: `ACCEPTANCE_TIMEOUT ?= 75m`, comment "suite ~55 min since M6";
  `.github/workflows/ci.yml` job `acceptance`: `timeout-minutes: 130`, `ACCEPTANCE_TIMEOUT: 90m`, steps `make up`
  (7–8 min), `make dev-seed`, `make acceptance`, the disruptive step, `make e2e` (6–8 min). Measured: run 39099247774
  (PR #82) `make acceptance` 76 min 10 s; run 39105651986 (`main` after the merge) **82 min 2 s** of 90 (9 % headroom).
  75 top-level gates in 50 files; only `audit_once_test.go` uses `t.Parallel` (inside the gate). 90 step-up calls;
  `env.Portal.StepUp` waits out the development `max_age` (`awaitStepUpMaxAge`, up to 17 s) and the TOTP helper never
  reuses a 30 s time step. The four session gates `TestSessionsDeactivation`, `TestSessionsRoleChange`,
  `TestSessionsPlatformAdminRemoved`, `TestAPITokenCreatorInactive` each wait up to 70 s for the worker round, one after
  another, on independent temporary users.
- **Portal language (PDK-301).** `server/web/src/i18n.ts::createPortalI18n()` starts with `locale: 'en'`;
  `applyLocale(locale)` switches the shared instance and `document.documentElement.lang`; `stores/session.ts:24` calls
  it with `me.locale` once `GET /api/v1/me` answered; `index.html` has `lang="en"`; `router.ts` marks `/login-denied`
  `meta.public`; tests `__tests__/i18n.test.ts`, `__tests__/loginDenied.test.ts` (mounts with `createPortalI18n()`),
  e2e `german.spec.ts`.
- **Playwright (PDK-290).** `server/web/package.json` `@playwright/test: 1.64.0`; `versions.env`
  `PLAYWRIGHT_IMAGE=mcr.microsoft.com/playwright:v1.64.0-noble@sha256:…`; `Makefile` target `e2e` runs the image;
  `.github/dependabot.yml` groups npm minor/patch updates and ignores only TypeScript majors;
  `docs/operations/local-dev.md` documents `versions.env` in *Files and services* and has no Playwright note.
- **Authentik log (PDK-291).** `providers/oauth2/token/refresh_token.py:40` (pinned image) and upstream `main`
  (read 2026-10-18): `self.logger.warning("Refresh token is revoked", token=raw_token)`, also "Refresh token does not
  exist" and "Refresh token is expired" with `token=raw_token`. Not fixed upstream. `./paddock logs`
  (`deploy/bundle/paddock` line 141) and `make logs` print `compose logs` unfiltered; `deploy/compose/scripts/lib.sh`
  holds shared shell functions and `deploy/bundle/bundle_test.sh` tests them (`expect`, `fail`, `pass`).
- **Retention (PDK-180).** No retention round exists yet (M10, PDK-137 is in the backlog); the tables
  `organization_role_member`, `platform_role_member`, `device_event_dropped`, `device_event_gap` do not exist yet (M8b,
  PDK-106–110 in the backlog). `action`, `device_command`, `device_alert`, `revocation_request`,
  `revocation_approval` exist (`00001`, `00011`, `00026`, `00020`).
- **Auto-approve root approval (PDK-187).** `server/internal/app/rootgrant.go::requireTokenGroups` gates the
  creation of a token (assigned witnesses and `newDeviceGains`); `enrollments.go::Enroll` (74–93) withholds the
  automatic approval when `newDeviceGains(before, token groups)` and records `auto_approve_withheld: root_grant`.
  `enrollment_token` (migration `00003`) has no approval columns. M11 (ADR 0033, PDK-154) wraps every configuration
  write into change sets with before-states.
- **Numbering.** Migrations: last on `main` `00049_device_contact_unseen.sql` (M8x). Plan M8u names
  `00049_openbao_auto_unseal.sql` — that number is taken; M8u takes the next free number at implementation time.
  M8d adds eight with `<next>` numbering. Residual risks: M8u RR-43, M8d RR-44–55, M8e RR-56–61; **M8f reserves
  RR-62 to RR-66**; the next free number after M8f is RR-67. (M8b's reservation RR-40–42 collides with M8x's RR-40;
  M8b renumbers when it is planned for implementation.) ADRs: 0036 is a gap, 0039 is the last; this plan adds 0040.

## 3. Binding decisions

### 3.1 Step-up `max_age` below the shortest consumer window (PDK-299) — ADR 0034 amendment 2026-10-18

1. `StepUpMaxAuthAge` MUST become `20 * time.Second`. Rationale: the escrow-reader and the revocation-issuer accept
   a step-up for 30 s; with `max_age` ≤ 30 s every moment at which the previous step-up is too old for them is also old
   enough for Authentik to run `paddock-stepup` again, so a repeated step-up is never refused for being too early; 20 s
   leaves 10 s for the clock skew the callback tolerates (`|now − auth_time| ≤ 20 s`). The development value stays
   `PADDOCK_STEPUP_MAX_AUTH_AGE: 15s` (`compose.dev.yaml`; every helper reads it from `GET /api/v1/me`).
2. Texts: `problems.step_up_failed` EN "The identity confirmation failed. Try again with your own account. If you
   confirmed your identity less than 20 seconds ago, wait 20 seconds first." / DE "Die Identitätsbestätigung ist
   fehlgeschlagen. Versuchen Sie es erneut mit Ihrem eigenen Konto. Haben Sie Ihre Identität vor weniger als
   20 Sekunden bestätigt, warten Sie zuerst 20 Sekunden."
3. Documents: `docs/operations/step-up.md` (*How it works*: `max_age=20`; the paragraph "`max_age` is 60, not 0"
   becomes "`max_age` is 20, not 0 … within 20 s Authentik may hand out the earlier login …"; the sentence "wait a
   minute" everywhere becomes "wait 20 seconds"), `docs/operations/local-dev.md` (*Development-only shortcuts*:
   "default 20s; the dev stack sets 15s"), `docs/architecture.md` §9.6 amendment block of this plan (decision 20),
   CHANGELOG `### Changed`: "A repeated identity confirmation (step-up) is possible 20 seconds after the previous one
   instead of a minute; the step-up asks the identity provider to authenticate again after 20 seconds."
4. Tests: `stepup_test.go` boundary cases unchanged (they use the injected `maxAuthAge`); one new case asserts the
   constant is 20 s and that the authorize URL carries `max_age=20` with the production `Deps`. The acceptance helper
   needs no change. `test/system/stack.go` `stepUpRetryAfter` stays 20 s (development value 15 s).

### 3.2 The step-up proves a WebAuthn authenticator inside Paddock (PDK-297) — ADR 0034 amendment 2026-10-18, ADR 0007 amendment

5. Reproduction first. PDK-297 MUST reproduce the sequence of §2 against the development stack with the acceptance
   executor (gate `TestStepUpHeldAuthorizeURL`, decision 11) before the fix and record the outcome in the result
   document. If it does not reproduce (the held URL re-runs `paddock-stepup`), stop condition S3 applies: the fix is
   implemented all the same as defence in depth (ADR 0034 decision 6 is otherwise enforced by Authentik alone, RR-38),
   but the ticket reports the finding.
6. `paddock-stepup.yaml` MUST gain, before the provider, the scope mapping

   ```yaml
   # The step-up proves a WebAuthn authenticator (ADR 0034 decision 6). Authentik's amr says only "mfa", for WebAuthn and
   # TOTP alike; this mapping names the classes of the authenticators the session's login validated, from the login
   # event Authentik itself uses for amr (providers/oauth2/id_token.py), so that the api can refuse any other factor.
   - model: authentik_providers_oauth2.scopemapping
     id: scope-stepup-mfa
     identifiers:
       managed: io.paddock/scope-stepup-mfa
     attrs:
       name: "Paddock: step-up authenticator classes"
       scope_name: paddock_stepup
       description: Authenticator classes of the step-up
       expression: |
         from authentik.events.signals import get_login_event
         classes = []
         event = get_login_event(token.session) if token and token.session else None
         if event:
             for device in (event.context.get("auth_method_args") or {}).get("mfa_devices") or []:
                 if isinstance(device, dict) and device.get("app") and device.get("model_name"):
                     classes.append(f"{device['app']}.{device['model_name']}")
         return {"paddock_mfa_classes": classes}
   ```

   and the provider's `property_mappings` MUST list `!KeyOf scope-stepup-mfa` after the groups mapping. The mapping
   always emits the claim (an empty list when the login validated no authenticator), so a token without the claim
   means the mapping is missing and is refused (fail closed).
7. The api's step-up OIDC configuration MUST request the scope: `OIDC` (`bff.go`) gains the field `Scopes []string`
   in its config; the login provider keeps `openid profile email groups`; the step-up provider gets `openid profile
   groups paddock_stepup`. `stepUpClaims` gains `MFAClasses []string \`json:"paddock_mfa_classes"\``.
8. `checkStepUp` MUST gain the parameter `requiredClass string` and refuse the token unless `MFAClasses` contains
   it (`errors.New("the step-up did not validate the required authenticator class")`); a nil or empty list is refused.
   The production value is the constant `StepUpWebAuthnClass = "authentik_stages_authenticator_webauthn.webauthndevice"`
   (`stepup.go`). The check runs after the `amr` check; the refusal is `stepup=failed` as every other refusal, logged
   at warn level with the classes the token carried (class names only, never the token).
9. Development switch: `config.DevStepUp` gains `MFAClass string` from `PADDOCK_STEPUP_MFA_CLASS` (the same
   development-only rule as the two durations: any value outside `PADDOCK_ENV=development` is
   `l.Invalid(name, "only allowed with PADDOCK_ENV=development")`; the value MUST match `^[a-z0-9_]+\.[a-z0-9_]+$`);
   `admin.Deps` gains `StepUpMFAClass string` (empty = `StepUpWebAuthnClass`); `prodcheck.devOnly` gains
   `"PADDOCK_STEPUP_MFA_CLASS"`; `compose.dev.yaml` sets `PADDOCK_STEPUP_MFA_CLASS:
   authentik_stages_authenticator_totp.totpdevice` on `paddock-api` next to `PADDOCK_STEPUP_MAX_AUTH_AGE`. The
   escrow-reader and the revocation-issuer verify the proof token with `stepupproof` and keep checking `amr` only;
   they trust the api's step-up record (the token reaches them only after the api accepted it), so they are unchanged.
10. The development-only `Me.step_up` object (`MeStepUp`, `handlers.go::GetMe`) MUST gain `mfa_classes`
    (`string[]`, the classes of the session's last step-up; the session cookie gains `StepUpClasses []string
    \`json:"stepup_classes,omitempty"\`` set in `stepUpCallback` next to `StepUpJTI`). Production sessions carry
    the field too (it is small); the API exposes it in development only, as the rest of `step_up`.
11. Tests. Unit (`stepup_test.go`): claim absent → refused; `["authentik_stages_authenticator_totp.totpdevice"]`
    with required WebAuthn → refused; `["…webauthndevice"]` → accepted; both classes → accepted; with
    `Deps.StepUpMFAClass = "…totpdevice"` the TOTP token → accepted. Blueprint content
    (`compose_test.go::TestStepUpBlueprintEmitsMFAClasses`): `paddock-stepup.yaml` contains `managed:
    io.paddock/scope-stepup-mfa`, `scope_name: paddock_stepup`, `paddock_mfa_classes` and `!KeyOf scope-stepup-mfa`.
    Acceptance (`stepup_test.go`): `TestStepUpFactorClaim` — after a step-up of `env.Alice`, `GET /api/v1/me`
    `step_up.mfa_classes` equals `["authentik_stages_authenticator_totp.totpdevice"]`; `TestStepUpHeldAuthorizeURL`
    — start a step-up for a temporary administrator (`steppedUpTempUser` pattern) and keep its `Location` without
    following it; in the same cookie jar run the flow `https://auth.<domain>/if/flow/default-authentication-flow/`
    with password and TOTP through the executor (`authflow.runFlow` with the flow URL; the development blueprint
    skips Paddock's stage at order 31, Authentik's own stage at order 30 validates the seeded TOTP); then follow the
    held URL: the gate records in `t.Logf` whether the callback returned without `stepup=failed` and asserts, when it
    did, that `me.step_up.at` lies after the recorded step-up start and `mfa_classes` names the TOTP class — the
    reproduction (decision 5). With the production class the same token is refused (unit test); the lab verification
    of PDK-297 (ticket) exercises the refusal with a real TOTP-only and a WebAuthn administrator.
12. Documents: `docs/operations/step-up.md` *Factor*: "Paddock checks the authenticator classes the step-up validated
    (claim `paddock_mfa_classes` of the step-up token, emitted by the mapping `io.paddock/scope-stepup-mfa`) and refuses
    every step-up without a WebAuthn authenticator; `amr` alone does not tell WebAuthn from TOTP." *Development stack*:
    the variable `PADDOCK_STEPUP_MFA_CLASS` and its value. `docs/operations/local-dev.md` lists the variable with the
    other two. `docs/compliance/residual-risks.md` RR-38 MUST be reworded (§6.7). CHANGELOG `### Security`: "A step-up
    (identity confirmation) now proves a WebAuthn authenticator to Paddock itself: the identity provider names the
    authenticator classes it validated and the portal refuses any other factor." Architecture §9.6 amendment block
    (decision 20).

### 3.3 WebAuthn-only enrolment and validation at the portal login (PDK-181) — ADR 0034 amendment 2026-10-18

13. `paddock-portal.yaml` stage `paddock-admin-login-mfa` MUST become

    ```yaml
    attrs:
      # WebAuthn only, enrolled at the first portal sign-in when missing (ADR 0034 amendment 2026-10-18): the step-up
      # accepts WebAuthn only, so an administrator who could sign in with TOTP alone would be refused at every step-up.
      device_classes: [webauthn]
      not_configured_action: configure
      configuration_stages:
        - !Find [authentik_stages_authenticator_webauthn.authenticatorwebauthnstage, [name, default-authenticator-webauthn-setup]]
    ```

    An administrator with a TOTP authenticator only is sent to the WebAuthn setup at the next portal sign-in and then
    signs in; nobody is locked out and the pre-upgrade enrolment of ADR 0034 decision 6 is no longer required. The
    default-flow stage `paddock-default-login-mfa` and the device-login stages are unchanged (they serve every
    Authentik user, not only administrators). The development blueprint is unchanged (it skips the stage).
14. Tests: `compose_test.go::TestPortalBlueprintLoginWebAuthnOnly` — the `paddock-admin-login-mfa` block contains
    `device_classes: [webauthn]` and exactly one `configuration_stages` entry (the WebAuthn setup) and
    `not_configured_action: configure`; `paddock-default-login-mfa` keeps `[webauthn, totp]`. Acceptance
    `TestStepUpFactor` MUST gain the stage `paddock-admin-login-mfa`: `device_classes == ["webauthn"]`,
    `not_configured_action == "configure"`, `configuration_stages` has one entry.
15. Documents: `docs/operations/step-up.md` *Factor* and *Before upgrading to WebAuthn-only step-up* ("The portal
    sign-in now enrols a WebAuthn authenticator when the administrator has none and accepts no other factor; a TOTP
    authenticator stays usable for Authentik's own interfaces and the device login"), `install.md` lines 274–313
    (the four steps: step 1 becomes "every administrator needs a browser or device with a WebAuthn authenticator
    (security key, or a platform authenticator such as Windows Hello, Touch ID, Android, or a phone through the
    browser's QR code); the portal asks for the enrolment at the first sign-in"), `upgrade.md` line 12,
    `lab-install.md` where it names the enrolment, `docs/compliance/residual-risks.md` RR-62 (§6.7) and RR-38
    reworded. CHANGELOG `### Changed`: "The portal sign-in accepts a WebAuthn authenticator only and enrols one at the
    first sign-in when the administrator has none; TOTP stays usable for the identity provider's own interfaces and
    the device login."

### 3.4 End all sessions ends the administrators' Authentik sessions too (PDK-190) — ADR 0034 amendment 2026-10-18, ADR 0007 amendment

16. `app.Sessions` MUST gain two dependencies and end the Authentik sessions inside the same action:

    ```go
    // IdentitySessionEnder ends the identity provider's browser sessions of users (Authentik authenticated sessions).
    type IdentitySessionEnder interface {
        EndUserSessions(ctx context.Context, userPKs []string) (int, error)
    }
    // PortalUserLister lists the identity provider's users who hold a portal role: the platform admins group and the
    // three role groups of every organization (ports.UserDirectory.RoleGroupUsers for each).
    type PortalUserLister interface {
        PortalUsers(ctx context.Context) ([]ports.IdentityUser, error)
    }
    func NewSessions(runner *ActionRunner, store SessionEnder, users PortalUserLister, identity IdentitySessionEnder) *Sessions
    ```

    `endAll` keeps `store.EndAll` first (unchanged), then lists the portal users, then calls `EndUserSessions` with
    their pks in chunks of 50, and records the params `generation`, `identity_users` (count of listed users) and
    `identity_sessions_ended` (sum of `deleted`). An error of the listing or of a chunk returns the error: the action
    records `failure` with the detail, the Paddock sessions are ended already (as RR-35 states for a failed commit),
    the HTTP answer is 502 `upstream_unavailable` with detail `the identity provider's sessions could not be ended;
    end all sessions again`. The portal users come from `PortalUsers`: `paddock.platform.admins` plus, for every
    organization slug of `ListOrganizations` (platform pool), the three groups of `organization.RoleGroup`;
    `ports.ErrGroupNotFound` for a missing group is skipped (an organization whose groups are not provisioned yet).
17. `authentik.Client` MUST gain `EndUserSessions(ctx, userPKs []string) (int, error)`: one
    `DELETE /api/v3/core/authenticated_sessions/bulk_delete/?user_pks=<pk>&…` per call (the caller chunks), decoding
    `{"deleted": n}`; the pks are validated as integers before the call. `PortalUsers` is implemented in `app`
    (`sessions.go`) over `ports.UserDirectory.RoleGroupUsers` and a `ListOrganizations` query of the platform pool;
    no new port for it. The service role `paddock-service` (`paddock-portal.yaml`) MUST gain
    `authentik_core.view_authenticatedsession` and `authentik_core.delete_authenticatedsession` (Authentik applies the
    blueprint at start; an existing installation gets the permissions at the next Authentik start, which the upgrade
    runbook names).
18. Wiring: `api.go` passes the existing Authentik client and a platform-pool lister; `admin.go` command
    `end-sessions` MUST load `config.LoadAuthentik` (URL and token file) next to the Valkey configuration and use the
    same `NewSessions`. The handler and the OpenAPI operation are unchanged in shape; the description of
    `POST /api/platform/v1/sessions/end-all` MUST say "ends every portal session and every identity-provider browser
    session of every portal user (platform administrators and organization role members); device logins and API
    tokens are not affected". The audit registry description of `platform.sessions_ended` MUST name the two params.
19. Portal texts (`sessions.*`): `summary` EN "Ends every portal session of the installation, including your own, and
    signs every portal user out of the identity provider (Authentik). Every administrator signs in again with password
    and authenticator; API tokens and device logins keep working." / DE "Beendet jede Portalsitzung der Installation,
    auch Ihre eigene, und meldet jeden Portalbenutzer beim Identitätsanbieter (Authentik) ab. Jeder Administrator
    meldet sich mit Passwort und Authenticator neu an; API-Token und Geräteanmeldungen arbeiten weiter."
    `confirmMessage` EN "Every administrator, you included, is signed out of the portal and of the identity provider
    at the next request. Type END to confirm." / DE "Jeder Administrator, Sie eingeschlossen, wird bei der nächsten
    Anfrage vom Portal und vom Identitätsanbieter abgemeldet. Geben Sie END ein, um zu bestätigen."
    `PlatformSessions.vue` is otherwise unchanged (the response shape is unchanged).
20. Tests: `sessions_test.go` (app, unit with fakes): the identity ender receives every pk once in chunks of 50 (test
    with 120 users → three calls), the params are recorded, a failing chunk → error and outcome `failure`;
    `authentik/adapter_test.go` with the fake server: the request path and query, the decoded count, a 403 → error.
    Acceptance `TestSessionsEndAll` MUST gain: before the call, `ak.Get("/core/authenticated_sessions/?user__username=alice%40acme.test")`
    has at least one result (alice signed in through the flow); after the call it has none for `alice@acme.test` and
    for the platform admin; the success event's params `identity_sessions_ended ≥ 2` and `identity_users ≥ 5`. The
    e2e suite is unchanged. Documents: `docs/operations/step-up.md` (the end-all row), `docs/operations/upgrade.md`
    (Authentik start applies the two permissions), architecture §9.6 amendment block (decision 20 below is the
    architecture amendment; this is the sessions paragraph), RR-35 gains the sentence "*End all sessions* also ends the
    identity provider's browser sessions of every portal user; the identity provider's sessions of a single account
    stay when only that account's Paddock sessions are revoked (role change, step-up mismatch), because the account
    simply signs in again with its current role", RR-66 (§6.7). CHANGELOG `### Changed`: "*End all sessions* now also
    signs every portal user out of the identity provider, so a stolen browser session cannot sign in again without
    password and authenticator."

### 3.5 Public pages follow the browser language (PDK-301)

21. `i18n.ts` MUST gain

    ```ts
    /** The portal locale a browser asks for: the first of languages whose primary subtag is a portal locale, else en. */
    export function browserLocale(languages: readonly string[]): PortalLocale
    export function createPortalI18n(initial: PortalLocale = 'en')
    ```

    The shared instance is created with `browserLocale(navigator.languages ?? [navigator.language])` and `main.ts`
    sets `document.documentElement.lang` to that locale before mounting (`applyLocale(i18n.global.locale.value)`).
    `session.ts` keeps calling `applyLocale(me.locale)` once `GET /api/v1/me` answered, so the stored language wins as
    soon as it is known; nothing else changes.
22. Tests: `i18n.test.ts`: `browserLocale(['de-DE', 'en'])` → `de`; `['fr-FR', 'de-CH']` → `de`; `['fr-FR']` → `en`;
    `[]` → `en`; `['EN-us']` → `en` (case-insensitive). `loginDenied.test.ts`: mounted with `createPortalI18n('de')`
    the message for `mfa_required` is the German text of plan M8x §6.6. e2e `public.spec.ts` (new): with
    `test.use({ locale: 'de-DE' })` and no session, `/login-denied?reason=mfa_required` shows "Ihre Anmeldung enthielt
    keinen zweiten Faktor." and `html[lang="de"]`; then `login(page, 'alice@acme.test', …)` (alice's stored language is
    English in the seed) → the overview heading is "Overview" and `html[lang="en"]`. CHANGELOG `### Fixed`: "Public
    portal pages such as the sign-in refusal use the browser's language (German or English) before a session exists."

### 3.6 Transport trust: freeze detection and the dead man's switch text (PDK-293) — ADR 0040

23. New attention kind **`config_behind`**: an active device that keeps checking in but applies an older bundle than
    its newest one for more than an hour. Migration `<next>_attention_config_behind.sql` (the next free number on
    `main` at implementation time, after M8u's and M8d's; stop condition S7) MUST recreate the view
    `attention_condition` as the latest migration on `main` defines it plus the branch

    ```sql
    UNION ALL
    SELECT 'config_behind', d.id, d.hostname, b.created_at,
      coalesce(s.applied_bundle_version, 0)::text || ' < ' || b.version::text, 'config_behind:' || d.id::text
    FROM device d JOIN device_status s ON s.device_id = d.id
    JOIN LATERAL (SELECT version, created_at FROM bundle WHERE bundle.device_id = d.id ORDER BY version DESC LIMIT 1) b ON true
    WHERE d.state = 'active'
      AND b.created_at < now() - interval '1 hour'
      AND s.last_contact_at > b.created_at + interval '1 hour'
      AND coalesce(s.applied_bundle_version, 0) < b.version
    ```

    The device had an hour and at least one check-in after that hour to learn of and apply the bundle; a device that
    stopped checking in is the staleness alert's business, not this kind's. `AttentionKind` gains `config_behind`
    (`detail`: "config_behind: applied and newest bundle version as `<applied> < <newest>`"; `since`: when the newest
    bundle was compiled); `lib/updates.ts` kinds list and `lib/status.ts` (`warn`) gain it; texts
    `attention.kinds.config_behind` EN "Configuration behind" / DE "Konfiguration im Rückstand",
    `attention.action.config_behind` EN "Open device" / DE "Gerät öffnen". No audit event (a derived condition, as
    `agent_outdated` and `disk_not_compliant`).
24. Tests: integration (`server/internal/app/attention_integration_test.go`, new, the harness of
    `agentreleases_integration_test.go`): a device with a bundle row `created_at = now() − 2 h`, `applied_bundle_version
    = version − 1`, `last_contact_at = now()` → one row of kind `config_behind` with detail `<v-1> < <v>` visible to its
    organization only; `applied = version` → none; `last_contact_at = created_at + 30 min` → none; `created_at = now()
    − 30 min` → none; a retired device → none. Acceptance `TestAttentionKinds` (or the existing attention gate):
    `GET /api/v1/attention?kind=config_behind` answers 200 with an empty list for acme (the filter accepts the kind);
    `TestOpenAPISpec` passes; component test `status.test.ts` for the mapping.
25. Dead man's switch texts: `dms.warning` EN "If Paddock is unreachable for longer than this period, every device
    with the switch enabled locks itself. This includes a device whose connection to Paddock is blocked on purpose: an
    attacker who keeps the device from reaching Paddock can trigger the lock." / DE "Ist Paddock länger als diese
    Frist nicht erreichbar, sperrt sich jedes Gerät mit eingeschaltetem Schalter selbst. Das gilt auch für ein Gerät,
    dessen Verbindung zu Paddock absichtlich blockiert wird: Ein Angreifer, der das Gerät von Paddock fernhält, kann
    die Sperre auslösen." `dms.confirm.message` EN "Every device of the organization locks itself after {days, plural,
    one {# day} other {# days}} of uptime without reaching Paddock, also when Paddock itself is down or the device's
    connection is blocked on purpose. A locked device must be restored with its escrowed header and recovery key." /
    DE "Jedes Gerät der Organisation sperrt sich nach {days, plural, one {# Tag} other {# Tagen}} Betriebszeit ohne
    Kontakt zu Paddock selbst, auch wenn Paddock selbst ausgefallen ist oder die Verbindung des Geräts absichtlich
    blockiert wird. Ein gesperrtes Gerät muss mit seinem hinterlegten Header und dem Wiederherstellungsschlüssel
    wiederhergestellt werden."
26. Documents: `docs/architecture.md` §6.1 gains the dated block `Amendment 2026-10-18 (M8f, ADR 0040) — what TLS
    protects` with the verbatim content of ADR 0040 §Decision 1–4 (what the connection does and does not protect, no
    pinning, server-side freeze detection, the DMS note); §12.6 adds the sentence "A blocked connection triggers the
    switch like an outage; the portal says so at the setting." `docs/operations/monitoring.md` (or `capacity.md` if
    monitoring has no attention section — the implementer names the document) lists the kind with the one-hour rule.
    `docs/compliance/residual-risks.md` RR-64 and RR-65 (§6.7). CHANGELOG `### Added`: "The attention page lists a
    device that keeps checking in but has not applied its newest configuration for more than an hour (kind
    *Configuration behind*)." and `### Changed`: "The dead man's switch setting says that a blocked connection
    triggers the lock like an outage."
27. Deferred by ADR 0040 (not in M8f): certificate or SPKI pinning for the device gateway, Himmelblau and fleetd;
    encryption of health and inventory reports to a server key; signing of the bundle pointer in the check-in
    response. The ADR records the options and the trigger for revisiting.

### 3.7 `./paddock logs` prints no token values; Authentik's refresh-token log (PDK-291)

28. `deploy/compose/scripts/lib.sh` MUST gain

    ```sh
    # redact_tokens replaces the value of every token=<value> field in a log stream: Authentik 2026.8.3 logs the raw
    # refresh token of a refused refresh ("Refresh token is revoked", providers/oauth2/token/refresh_token.py), and
    # Paddock's rule is that no secret is ever printed (RR-63).
    redact_tokens() { sed -E 's/(token=)[A-Za-z0-9._~+\/=-]+/\1<redacted>/g'; }
    ```

    `./paddock logs` (`deploy/bundle/paddock`) and `make logs` MUST pipe `compose logs` through it (the bundle sources
    `lib.sh` already; the Makefile target runs `. deploy/compose/scripts/lib.sh && … | redact_tokens`).
    `deploy/bundle/bundle_test.sh` gains a case: `printf 'x Refresh token is revoked token=fake.token-value_x=\n' |
    redact_tokens` prints `token=<redacted>` and nothing of the value; a line without `token=` is unchanged.
29. Upstream: the implementer drafts the issue "Refresh-token endpoint logs the raw refresh token on refused refreshes"
    (file, line, the three log calls, the proposal to log the token's pk or a hash) in the maintainer's notes; the
    maintainer posts it (open point O1). No Authentik configuration change: the message is a warning and the logger
    cannot be silenced without losing the signal.
30. Documents: `docs/operations/device-login.md` *Tokens of the device login* gains "Authentik's server log prints
    the raw refresh token when a revoked, expired or unknown token is presented; `./paddock logs` redacts `token=`
    values, `docker compose logs` does not. Treat the Authentik container log as confidential and keep its retention
    short (Docker rotation of plan M10)." `docs/compliance/residual-risks.md` RR-63 (§6.7). CHANGELOG `### Fixed`:
    "`./paddock logs` and `make logs` redact token values that the identity provider prints for refused token
    refreshes."

### 3.8 A probation release is rolled back exactly once (PDK-300) — ADR 0024 amendment 2026-10-18

31. `supervisor.rollback` MUST, on a durable flip back, call `s.conclude(p, outcomeRolledBack)` **before**
    `s.restartChild()`, so that `update-result.json` exists and `request.json` is gone before the previous agent can
    start and check in. The non-durable path (`RollingBack`, result waits for `confirmRollback`) and the pending path
    (`keepRollbackPending`, the new agent keeps running) are unchanged: in both, `request.json` still exists while the
    previous agent is not running, or the running agent is the offered version. `finishAt`'s SIGHUP goes to the child
    that is running at that time or to none; the restarted agent checks in at start anyway (PDK-035). The
    `rollbackPending` retry path (`retryFlipBack` → `restartChild` → `confirmRollback` → `conclude`) MUST get the same
    order: `confirmRollback` concludes before `retryFlipBack` restarts the child when the flip succeeded on a retry
    (restructure `retryFlipBack` to return the flip's success and let `confirmRollback` restart the child after
    `conclude`).
32. Regression test (`supervisor_test.go::TestRollbackWritesTheResultBeforeTheOldAgentStarts`): slot A runs a script
    whose `run` branch first records whether the result file exists (`[ -e <result> ] && : > <dir>/result-seen-at-start`)
    and then behaves as `good()`; stage 1.1.0 with a script that exits at once (three exits end the probation); wait for
    the `rolled_back` result; assert `result-seen-at-start` exists, exactly one result was written (the fake's
    `waitResult` sees one `at`), and `request.json` is gone. The test fails on `main` (the previous agent starts before
    the result exists at least on the first restart) and passes with decision 31.
33. System gate `gateS4` subtest `probation failure` MUST additionally wait 3 minutes after the first
    `device.agent_rolled_back` and assert that the device has exactly one `device.agent_rolled_back` event for that
    version (`s.Events("device.agent_rolled_back", deviceID)` filtered by `version`) and that `agent_update_report` for
    the version shows one report (through the release detail's `failed` count staying 1 for that device, read with
    `Stack.Rollout`/release detail). Documents: `docs/operations/agent-releases.md` *On the device*: "The supervisor
    writes the result before it restarts the previous agent, so the restarted agent never stages the release it just
    rolled back from." CHANGELOG `### Fixed`: "A release that failed its probation is rolled back exactly once; the
    restarted agent no longer re-installs it before the rollback is recorded."

### 3.9 System-test Stack helpers fail the calling subtest (PDK-298)

34. Every `Stack` method that reports a failure MUST take `t *testing.T` as its first parameter and use it for
    `Helper`, `Fatal*`, `Error*`, `Log*`, `TempDir` and `Cleanup`; the field `Stack.t` is removed:

    ```go
    func newStack(t *testing.T) *Stack                       // signs alice in with t; keeps root, alice, composeFiles
    func (s *Stack) Login(t *testing.T)
    func (s *Stack) StepUp(t *testing.T)
    func (s *Stack) Call(t *testing.T, method, path string, body any, status int) portal.Response
    func (s *Stack) DeleteOnCleanup(t *testing.T, path string)
    func (s *Stack) RevokeOnCleanup(t *testing.T, tokenID string)
    func (s *Stack) cleanupCall(t *testing.T, method, path string, ok ...int)
    func (s *Stack) OperatorRoot(t *testing.T, root string)
    func (s *Stack) ID(t *testing.T, res portal.Response) string
    func (s *Stack) Events(t *testing.T, code, deviceID string) []portal.AuditEvent
    func (s *Stack) Make(t *testing.T, args ...string)
    func (s *Stack) Release(t *testing.T, version string, tags []string, flags ...string) string
    func (s *Stack) BuildAgent(t *testing.T, version string, tags []string) string
    func (s *Stack) Rollout(t *testing.T, version string) string
    func (s *Stack) InstallRelease(t *testing.T) string      // unchanged
    ```

    `s.alice` stays a shared field (a `*portal.Session` is safe for concurrent requests; `Login` replaces it under a
    `sync.Mutex` added to Stack). Every call site (70 in `agent_test.go`, `autoinstall_test.go`, `disk_test.go`,
    `identity_test.go`, `inventory_test.go`, `localadmin_test.go`, `notice_test.go`, `revoke_test.go`,
    `rollout_test.go`, `updates_test.go`) passes the innermost `t`. If M8d's system gates (PDK-230, PDK-247) landed
    first, their call sites are updated too (stop condition S9 if more than those files are affected).
35. Verification: `go vet ./test/system/...` and `GOTOOLCHAIN=auto go test -count=1 -run '^$' ./test/system/...`
    compile; `withBackup`'s unit test stays; one new unit test `TestStackHelpersTakeTheCallersT` asserts, with a
    `testing.T` of a subtest and a `Stack` whose `alice` is a stub, that `Call` with an unreachable path fails the
    subtest and not the parent (run the subtest and read its `Failed()`); `make system-test VM=all
    T=TestNoticeGate` on one VM pair as the smoke run.

### 3.10 Acceptance suite budget (PDK-189)

36. Budgets: `Makefile` `ACCEPTANCE_TIMEOUT ?= 120m` with the comment "Guard against hangs; the suite takes ~85 min on
    a development machine and ~82 min on a GitHub runner since M8x (measured 2026-10-18). Keep at least 20 % headroom
    when gates are added."; `.github/workflows/ci.yml` job `acceptance`: `ACCEPTANCE_TIMEOUT: 120m`, `timeout-minutes:
    180` (`make up` 8 min + acceptance 120 min + disruptive 1 min + e2e 10 min + logs).
37. The four session gates `TestSessionsDeactivation`, `TestSessionsRoleChange`, `TestSessionsPlatformAdminRemoved`
    and `TestAPITokenCreatorInactive` MUST call `t.Parallel()` as their first statement (each uses its own temporary
    user and waits for the same worker round; Go runs them together after the sequential gates). No other gate is
    made parallel in this ticket; the measurement of decision 38 names the candidates for a later ticket.
38. Measurement: PDK-189 runs `make acceptance` once with `go test -json` output captured
    (`GOFLAGS=-json` is not used; the implementer adds `-v` and parses `--- PASS: Test… (…s)`) and records the top
    15 gates by duration and the total in the result document; the Makefile comment of decision 36 carries the total.
    Acceptance criteria: the CI step `make acceptance` of the ticket's PR finishes within 80 % of `ACCEPTANCE_TIMEOUT`;
    a local run finishes within 80 % of the default. No gate is removed or weakened; `audit_once_test.go` is unchanged.

### 3.11 The Playwright image follows the npm package (PDK-290)

39. `.github/dependabot.yml` npm block MUST gain

    ```yaml
      - dependency-name: "@playwright/test"
        # Moves only together with PLAYWRIGHT_IMAGE in deploy/compose/versions.env (make e2e refuses a mismatch).
    ```

    under `ignore` (all update types). `Makefile` MUST gain the target `e2e-check-playwright` as a prerequisite of
    `e2e`: it reads the version from `server/web/package.json` (`sed -n 's/.*"@playwright\/test": "\([^"]*\)".*/\1/p'`)
    and from `PLAYWRIGHT_IMAGE` (the text between `playwright:v` and `-`), and exits 1 with `@playwright/test
    <npm> in server/web/package.json does not match PLAYWRIGHT_IMAGE v<image> in deploy/compose/versions.env; bump both
    together` when they differ, else prints nothing. Verify by editing one side temporarily (documented in the
    result), and `make e2e-check-playwright` on `main` prints nothing and exits 0.
40. `docs/operations/local-dev.md` *Files and services* gains the row/paragraph: "`@playwright/test`
    (`server/web/package.json`) and `PLAYWRIGHT_IMAGE` (`versions.env`) are one version: the image ships the browsers
    of exactly that package. Dependabot ignores the package; bump both by hand and run `make e2e`." CHANGELOG: no
    operator-visible change (developer tooling), no line.

### 3.12 Deferred with a decision: retention of the remaining tables (PDK-180) — ADR 0032 amendment 2026-10-18

41. Decided now, implemented after M10's retention round exists (PDK-137) and the M8b tables exist (PDK-106,
    PDK-108): the periods and purge of the remaining tables are fixed in ADR 0032's amendment of 2026-10-18 (`action`,
    `device_command`, `device_alert` (cleared rows), `revocation_request` with `revocation_approval` (finished rows),
    `organization_role_member`, `platform_role_member`, `device_event_dropped`, `device_event_gap`: all
    `PADDOCK_AUDIT_INDEX_RETENTION_DAYS` after their last change, purged by the worker's retention round per
    organization in batches of 1 000 with `retention.purged` per store; `revocation_request` rows of a device whose
    request is not finished are never purged). PDK-180 becomes a full ticket that depends on PDK-137 and stays in the
    backlog; no code in M8f.

### 3.13 Deferred with a decision: recorded root approval for auto-approve tokens (PDK-187)

42. Design accepted, implementation deferred until after M11 (PDK-154 change sets, PDK-156 rollout settings): a token
    created or confirmed by an organization administrator with a step-up MAY carry `root_grant_approved_witnesses
    text[]`, `root_grant_approved_at`, `root_grant_approved_by` (the witnesses of
    `requireTokenGroups`' `inGroups` at that moment); `Enroll` activates the device when
    `privilege.NewWitnesses(approved, current inGroups)` is empty and withholds otherwise (`auto_approve_withheld:
    root_grant`); any change that grows the witness set voids the approval by construction. Reasons for the deferral:
    priority low, one migration while M8d's eight are in flight, and M11 wraps every configuration write into change
    sets whose before-state capture would have to cover the new columns, so an implementation now would be redone.
    The ticket records the design; no code in M8f.

## 4. Non-goals

- Any change to `agent/internal/revoke/`, `agent/cmd/paddock-revoke/`, `pkg/revocation/`, `pkg/bundle`,
  `api/openapi/device.yaml`, the device API path version.
- The step-up factor of the development stack (TOTP stays), the dev blueprint's skips, `paddock-default-login-mfa` and
  the device-login stages (PDK-181 touches the administrator login only).
- Ending Authentik sessions for single-account revocations (role change, step-up mismatch, deactivation).
- Certificate or SPKI pinning, report encryption, a signed bundle pointer (ADR 0040 defers them).
- Parallelizing gates other than the four of decision 37; changing `PADDOCK_STEPUP_MAX_AUTH_AGE` or
  `PADDOCK_IDENTITY_SYNC_INTERVAL` in the development stack.
- Server-side suppression of an agent release offer after a rollback (M8d decisions 27–28 own `Offer.For` and
  `handleUpdate`).
- A new Go module, npm package or container image.
- Implementing PDK-180 and PDK-187 (decided, deferred).

## 5. Affected files

| Path | Action | Purpose |
| --- | --- | --- |
| `docs/plans/M8f-follow-ups.md` | new (this plan) | — |
| `docs/adr/0034-…`, `0007-…`, `0024-…`, `0032-…` | amended (done) | dated amendments 2026-10-18 |
| `docs/adr/0040-transport-trust.md` | new (done) | §3.6 |
| `server/internal/transport/http/admin/{stepup,bff,handlers}.go`, `stepup_test.go` | change | §3.1, §3.2 |
| `server/internal/config/config.go`, `server/cmd/paddock-server/{api,admin}.go`, `server/internal/prodcheck/prodcheck.go`, `compose_test.go` | change | §3.2, §3.3, §3.4 |
| `deploy/compose/authentik/blueprints/paddock-stepup.yaml`, `paddock-portal.yaml` | change | §3.2, §3.3, §3.4 |
| `deploy/compose/compose.dev.yaml` | change | `PADDOCK_STEPUP_MFA_CLASS` |
| `server/internal/app/sessions.go`, `sessions_test.go`; `server/internal/adapters/authentik/{users,authentik}.go`, `adapter_test.go` | change | §3.4 |
| `api/openapi/admin.yaml`, generated Go/TS; `server/internal/domain/audit/codes.go`, generated docs | change | §3.4 description, §3.6 kind |
| `server/migrations/paddock/<next>_attention_config_behind.sql` (new), `server/internal/app/attention_integration_test.go` (new) | new | §3.6 |
| `server/web/src/{i18n,main}.ts`, `lib/{status,updates}.ts`, `locales/{en,de}.json`, `__tests__/{i18n,loginDenied,status}.test.ts`, `e2e/public.spec.ts` (new) | change/new | §3.1, §3.4, §3.5, §3.6 |
| `agent/internal/supervisor/supervisor.go`, `supervisor_test.go` | change | §3.8 |
| `test/system/stack.go` and the ten `_test.go` files, `test/system/agent_test.go` (S4) | change | §3.8, §3.9 |
| `test/acceptance/{stepup,sessions,login,attention}_test.go` (`attention` only if the kinds gate lives there), `internal/authflow/authflow.go` (flow-URL entry for the held-URL gate) | change | §3.2, §3.3, §3.4, §3.6 |
| `Makefile`, `.github/workflows/ci.yml`, `.github/dependabot.yml` | change | §3.7, §3.10, §3.11 |
| `deploy/compose/scripts/lib.sh`, `deploy/bundle/paddock`, `deploy/bundle/bundle_test.sh` | change | §3.7 |
| `docs/operations/{step-up,local-dev,install,upgrade,lab-install,device-login,agent-releases,monitoring}.md`, `docs/architecture.md`, `docs/compliance/residual-risks.md`, `CHANGELOG.md` | change | per section |

MUST NOT be touched: `agent/internal/revoke/`, `agent/cmd/paddock-revoke/`, `pkg/revocation/`, `pkg/bundle`,
`api/openapi/device.yaml`, every existing migration, `deploy/compose/compose.prod.yaml`, `compose.lab.yaml`,
`deploy/compose/authentik/blueprints/paddock-device.yaml`, `paddock-recovery.yaml`, `deploy/compose/authentik/dev/
paddock-dev.yaml`, `agent/internal/agent/updates.go` (M8d), `server/internal/domain/agentrelease/` (M8d),
`docs/adr/` other than through the architect, files of plans M8u, M8d, M8e, M9–M11 and their tickets.

Coordination with M8u and M8d (implemented in parallel): **migrations** — M8u's `00049` is taken by M8x; M8u and
M8d take the next free numbers at implementation time; M8f's one migration (§3.6) comes after both and copies the
view from the latest migration on `main` (M8d's `uninstall` migration recreates it too; the later one carries every
branch — stop condition S7). **CHANGELOG** — every ticket adds its own line under `[Unreleased]`; the release commit
consolidates. **i18n** — M8f adds or changes only the keys named in §6.6; M8d's keys are in other sections. **Shared
files** — `paddock-portal.yaml` (M8f only), `stepup.go` (M8f only), `supervisor.go` (M8f; M8d adds the new package
`agent/internal/supervisorpkg` and `paddock-supervisor/main.go`), `test/system/stack.go` (PDK-298 SHOULD land before
M8d's PDK-230; whichever lands second adapts the call sites), `ci.yml` (M8u adds a disruptive step; M8f changes two
numbers), `residual-risks.md` (ranges above), `attention_condition` (above).

## 6. Interfaces and formats

### 6.1 Admin API (`api/openapi/admin.yaml`)

```yaml
AttentionKind: + config_behind         # §3.6; detail "<applied> < <newest>", since = newest bundle compiled
POST /api/platform/v1/sessions/end-all  # description names the identity-provider sessions (§3.4); shape unchanged
Me.step_up (development only): + mfa_classes (string[])   # §3.2 decision 10
```

### 6.2 Go signatures (new or changed)

```go
// server/internal/transport/http/admin
const StepUpMaxAuthAge = 20 * time.Second
const StepUpWebAuthnClass = "authentik_stages_authenticator_webauthn.webauthndevice"
type stepUpClaims struct { Subject string; AuthTime int64; AMR []string; JTI string; Groups []string; MFAClasses []string `json:"paddock_mfa_classes"` }
func checkStepUp(c stepUpClaims, sess Session, started int64, now time.Time, maxAuthAge time.Duration, requiredClass string) error
type Deps struct { …; StepUpMFAClass string }
type Session struct { …; StepUpClasses []string `json:"stepup_classes,omitempty"` }
type OIDCConfig struct { …; Scopes []string }

// server/internal/config
type DevStepUp struct { Window, MaxAuthAge time.Duration; MFAClass string }

// server/internal/app
type IdentitySessionEnder interface { EndUserSessions(ctx context.Context, userPKs []string) (int, error) }
type PortalUserLister interface { PortalUsers(ctx context.Context) ([]ports.IdentityUser, error) }
func NewSessions(runner *ActionRunner, store SessionEnder, users PortalUserLister, identity IdentitySessionEnder) *Sessions

// server/internal/adapters/authentik
func (c *Client) EndUserSessions(ctx context.Context, userPKs []string) (int, error)

// server/web/src/i18n.ts
export function browserLocale(languages: readonly string[]): PortalLocale
export function createPortalI18n(initial: PortalLocale = 'en')

// test/system (see §3.9 for the full list)
func (s *Stack) Call(t *testing.T, method, path string, body any, status int) portal.Response
```

### 6.3 Authentik objects

| Object | Setting | Value |
| --- | --- | --- |
| scope mapping `io.paddock/scope-stepup-mfa` | `scope_name` | `paddock_stepup`; claim `paddock_mfa_classes: ["<app>.<model_name>", …]` |
| provider `paddock-portal-stepup` | `property_mappings` | + the mapping; the api requests `openid profile groups paddock_stepup` |
| step-up authorize request | `max_age` | `20` (development: `PADDOCK_STEPUP_MAX_AUTH_AGE`) |
| stage `paddock-admin-login-mfa` | `device_classes` / `configuration_stages` | `[webauthn]` / WebAuthn setup only |
| role `paddock-service` | permissions | + `authentik_core.view_authenticatedsession`, `authentik_core.delete_authenticatedsession` |
| end-all | API call | `DELETE /api/v3/core/authenticated_sessions/bulk_delete/?user_pks=…` per 50 users |

### 6.4 Environment

| Variable | Role | Rule |
| --- | --- | --- |
| `PADDOCK_STEPUP_MFA_CLASS` | api | development only (`prodcheck.devOnly`); `compose.dev.yaml`: `authentik_stages_authenticator_totp.totpdevice` |
| `ACCEPTANCE_TIMEOUT` | Makefile / CI | `120m` |

### 6.5 Audit registry changes

| Code | Change |
| --- | --- |
| `platform.sessions_ended` | params + `identity_users`, `identity_sessions_ended`; description names the identity-provider sessions |

### 6.6 UI texts (verbatim; English `en.json` / German `de.json`)

| Key | English | German |
| --- | --- | --- |
| `problems.step_up_failed` | The identity confirmation failed. Try again with your own account. If you confirmed your identity less than 20 seconds ago, wait 20 seconds first. | Die Identitätsbestätigung ist fehlgeschlagen. Versuchen Sie es erneut mit Ihrem eigenen Konto. Haben Sie Ihre Identität vor weniger als 20 Sekunden bestätigt, warten Sie zuerst 20 Sekunden. |
| `sessions.summary` | Ends every portal session of the installation, including your own, and signs every portal user out of the identity provider (Authentik). Every administrator signs in again with password and authenticator; API tokens and device logins keep working. | Beendet jede Portalsitzung der Installation, auch Ihre eigene, und meldet jeden Portalbenutzer beim Identitätsanbieter (Authentik) ab. Jeder Administrator meldet sich mit Passwort und Authenticator neu an; API-Token und Geräteanmeldungen arbeiten weiter. |
| `sessions.confirmMessage` | Every administrator, you included, is signed out of the portal and of the identity provider at the next request. Type END to confirm. | Jeder Administrator, Sie eingeschlossen, wird bei der nächsten Anfrage vom Portal und vom Identitätsanbieter abgemeldet. Geben Sie END ein, um zu bestätigen. |
| `attention.kinds.config_behind` | Configuration behind | Konfiguration im Rückstand |
| `attention.action.config_behind` | Open device | Gerät öffnen |
| `dms.warning` | If Paddock is unreachable for longer than this period, every device with the switch enabled locks itself. This includes a device whose connection to Paddock is blocked on purpose: an attacker who keeps the device from reaching Paddock can trigger the lock. | Ist Paddock länger als diese Frist nicht erreichbar, sperrt sich jedes Gerät mit eingeschaltetem Schalter selbst. Das gilt auch für ein Gerät, dessen Verbindung zu Paddock absichtlich blockiert wird: Ein Angreifer, der das Gerät von Paddock fernhält, kann die Sperre auslösen. |
| `dms.confirm.message` | Every device of the organization locks itself after {days, plural, one {# day} other {# days}} of uptime without reaching Paddock, also when Paddock itself is down or the device's connection is blocked on purpose. A locked device must be restored with its escrowed header and recovery key. | Jedes Gerät der Organisation sperrt sich nach {days, plural, one {# Tag} other {# Tagen}} Betriebszeit ohne Kontakt zu Paddock selbst, auch wenn Paddock selbst ausgefallen ist oder die Verbindung des Geräts absichtlich blockiert wird. Ein gesperrtes Gerät muss mit seinem hinterlegten Header und dem Wiederherstellungsschlüssel wiederhergestellt werden. |

No other key changes. The German glossary is unchanged.

### 6.7 Residual risks (`docs/compliance/residual-risks.md`; M8f reserves RR-62 to RR-66)

| ID | Risk | Mitigation in Paddock | Record in the ISMS |
| --- | --- | --- | --- |
| RR-38 (reworded) | **The step-up factor depends on the identity provider's login event.** Paddock refuses a step-up whose token does not name a WebAuthn authenticator in `paddock_mfa_classes`; that claim is computed by a Paddock-managed mapping from the login event Authentik keeps for the session. An Authentik administrator who changes the mapping, the step-up stage or the login event's content can make TOTP pass again. | The blueprints `paddock-stepup.yaml` and `paddock-portal.yaml` are applied on every Authentik start and restore the mapping and the stages; a token without the claim is refused; the portal sign-in enrols and accepts WebAuthn only; Authentik's admin actions are logged by Authentik. | Restrict Authentik administration; review Authentik's event log for changes to the step-up flow and the Paddock mappings. |
| RR-62 | **Portal sign-in needs a WebAuthn authenticator.** An administrator whose browser or device has no WebAuthn authenticator (no security key, no platform authenticator, no phone the browser can use) cannot sign in to the portal; TOTP is not accepted there. | The portal login enrols a WebAuthn authenticator at the first sign-in; Authentik's own interfaces and the device login keep accepting TOTP, so the administrator can still manage authenticators in Authentik. | Issue security keys or approve platform authenticators for every administrator; keep one platform administrator's key in custody. |
| RR-63 | **Authentik logs refused refresh tokens.** Authentik 2026.8.3 prints the raw refresh token when a revoked, expired or unknown token is presented; a revoked token cannot be used again, but whoever reads the container log sees it. | `./paddock logs` and `make logs` redact `token=` values; the upstream issue is pending. | Treat Authentik's container log as confidential; limit who runs `docker compose logs`; keep the log retention short. |
| RR-64 | **TLS alone protects the confidentiality of reports and of the enrollment token, and the login component and fleetd trust the system CA store.** Health and inventory reports are signed, not encrypted; the enrollment token travels in the enrollment configuration; Himmelblau (OIDC to Authentik) and fleetd (to Fleet) verify TLS against the system CA store and pin nothing. An attacker with a certificate the device trusts (an interception CA on the device, a compromised CA) can read reports, capture an enrollment token and phish the device login. Integrity and the revocation path do not depend on TLS (ADR 0040). | Bundles, commands, time tickets and device requests are signed end-to-end with keys from the enrollment configuration; tokens expire, have maximum uses and need approval unless auto-approve is set; the device login needs a second factor. Pinning and report encryption are deferred (ADR 0040). | Decide whether devices may carry interception CAs; revisit pinning when a customer requires it. |
| RR-65 | **A withheld configuration is visible after an hour, and a blocked connection can trigger the dead man's switch.** An attacker who proxies a device's connection can withhold newer bundles (for example a revoked sudo right) for up to an hour before the device appears as *Configuration behind*; blocking the connection entirely makes the device stale and, with the dead man's switch enabled, locks it after the period. | The attention kind `config_behind` (one hour after the newest bundle, with a check-in after that hour); staleness alerts; the dead man's switch setting states the consequence. | React to *Configuration behind* and staleness; choose the switch period with blocking in mind. |
| RR-66 | **End all sessions does not end device logins or sessions outside the portal roles.** It ends Paddock sessions and the identity provider's browser sessions of platform administrators and organization role members; device-login refresh tokens (Hello PIN) and sessions of users without a portal role stay. A single account's Paddock session revocation (role change, step-up mismatch) leaves its identity-provider session, because the account signs in again with its current role. | Lock (user) revokes a user's device tokens; account deactivation in the identity provider ends everything. | Use *End all sessions* for portal incidents and the user lock for device incidents. |

## 7. Host and operator notes (binding figures for the documents)

- A repeated step-up works 20 s after the previous one; the escrow-reader and the revocation-issuer accept a step-up
  for 30 s, the portal for 300 s.
- Every portal administrator signs in with a WebAuthn authenticator; the portal enrols one at the first sign-in.
- *End all sessions* signs every portal user out of Authentik; after the upgrade, Authentik's next start grants the
  service account the two session permissions (restart Authentik once).
- A device that keeps checking in but applies an older bundle for more than an hour is *Configuration behind*.
- `./paddock logs` redacts `token=` values; `docker compose logs` does not.
- The acceptance suite's budget is 120 minutes; the suite takes about 85.

## 8. Steps (tickets, in order)

1. **PDK-299 — Step-up `max_age` 20 s** (§3.1). Verify: `go test ./server/internal/transport/http/admin/`; `make
   acceptance T='TestStepUp'`; `make e2e`.
2. **PDK-297 — Step-up proves a WebAuthn authenticator** (§3.2). Depends on PDK-299 (same file). Verify: `go test
   ./server/internal/transport/http/admin/ ./server/internal/config/ ./server/internal/prodcheck/`; `make down V=1
   dev-secrets up dev-seed acceptance T='TestStepUp'`; `make e2e`; lab verification (ticket).
3. **PDK-181 — WebAuthn-only portal login** (§3.3). Verify: `go test ./server/internal/prodcheck/`; `make up` (blueprint
   applies) and `make acceptance T=TestStepUpFactor`; lab verification with a TOTP-only administrator (ticket).
4. **PDK-190 — End all sessions ends Authentik sessions** (§3.4). Verify: `go test ./server/internal/app/
   ./server/internal/adapters/authentik/`; `make gen` no diff; `PADDOCK_ACCEPTANCE_DISRUPTIVE=1 make acceptance
   T=TestSessionsEndAll`.
5. **PDK-301 — Public pages follow the browser language** (§3.5). Verify: `make web`; `make e2e`.
6. **PDK-293 — Transport trust: `config_behind`, DMS text, ADR 0040 documents** (§3.6). Verify: `go test
   ./server/...` (integration test with the database); `make gen` no diff; `make acceptance T='TestAttention|TestOpenAPI'`;
   `make web`.
7. **PDK-291 — Logs redact tokens** (§3.7). Verify: `make bundle-test`; `./paddock logs` on the lab prints
   `token=<redacted>` for an Authentik refresh warning (ticket).
8. **PDK-300 — Rollback exactly once** (§3.8). Verify: `go test -race ./agent/internal/supervisor/`; `make system-test
   VM=all T=TestAgentGates`.
9. **PDK-298 — Stack helpers take the caller's t** (§3.9). Verify: `go vet ./test/system/...`; `go test -run '^$'
   ./test/system/...`; `make system-test VM=all T=TestNoticeGate`.
10. **PDK-189 — Acceptance budget** (§3.10). Last of the acceptance-touching tickets. Verify: `make acceptance`
    (full) locally and in CI; the measurement in the result document.
11. **PDK-290 — Playwright image follows npm** (§3.11). Independent. Verify: `make e2e-check-playwright`; `make e2e`.
12. **PDK-180**, **PDK-187**: no implementation (§3.12, §3.13); the tickets stay in the backlog with their blockers.

PDK-299 first; PDK-297 after it; PDK-181, PDK-190, PDK-301, PDK-293, PDK-291, PDK-300, PDK-298, PDK-290 MAY run in
parallel after PDK-297 (PDK-181 and PDK-190 both edit `paddock-portal.yaml` in different blocks); PDK-189 last. The
release's full regression (`make lint test`, `make acceptance`, `make e2e`, `make system-test VM=all`, `make
bundle-test`, `make scan-secrets`, `make gen` without diff) is run by the release ticket of M8u/M8d, which ships this
batch; every M8f ticket runs its named gates.

## 9. Acceptance criteria (positive and negative per role)

Roles: **A** = org_admin (`env.Alice` or a temp admin), **P** = platform admin, **D** = a device (VM or devicesim),
**O** = operator of the bundle host, **S** = a user at the sign-in page, **Dev** = developer running the suites.

| # | Given / When / Then | Role sees |
| --- | --- | --- |
| S1 | A steps up at t=0 and again at t=25 s → the second step-up runs `paddock-stepup` and succeeds; `GET /api/auth/stepup` redirects with `max_age=20` (production `Deps`); a repeated step-up within 15 s in development is refused with `stepup=failed` and the portal text says "wait 20 seconds". | A |
| S2 | (unit) A step-up token without `paddock_mfa_classes`, or with the TOTP class only, is refused with the production class; with the WebAuthn class it is accepted. (acceptance, development) after a step-up `me.step_up.mfa_classes == ["authentik_stages_authenticator_totp.totpdevice"]`; `TestStepUpHeldAuthorizeURL` records whether the held authorize URL passed and, if so, that its `auth_time` is after the start (reproduction). (lab) a TOTP-only administrator who runs the held-URL sequence is refused; a WebAuthn administrator's step-up passes. | A, Dev |
| S3 | `PADDOCK_STEPUP_MFA_CLASS` in a production configuration fails `./paddock check` (`no development-only variables`). | O |
| S4 | The stage `paddock-admin-login-mfa` has `device_classes == ["webauthn"]` and one configuration stage; (lab) an administrator with a TOTP authenticator only is sent to the WebAuthn setup at the portal sign-in and signs in afterwards; a WebAuthn administrator signs in as before; the development users sign in unchanged. | S, P (Authentik API) |
| S5 | P ends all sessions with a step-up → alice's and P's Authentik authenticated sessions are gone (`core/authenticated_sessions/?user__username=`), every portal session is 401, the event `platform.sessions_ended` has `identity_sessions_ended ≥ 2` and `identity_users ≥ 5`; with the Authentik API unreachable the action records `failure`, the response is 502 `upstream_unavailable`, and every portal session is still 401. | P, A |
| S6 | With `navigator.languages = ['de-DE']` and no session, `/login-denied?reason=mfa_required` is German and `html[lang="de"]`; with `['fr-FR']` English; alice (stored `en`) sees English after sign-in in a `de-DE` browser. | S, A |
| S7 | (integration) A device with its newest bundle compiled 2 h ago, `applied = newest − 1` and a check-in now lists as `config_behind` with detail `<n−1> < <n>` for its organization only; applied = newest, or a bundle 30 min old, or a last contact 30 min after the compile → not listed. `GET /api/v1/attention?kind=config_behind` → 200. The DMS settings page shows the blocked-connection sentence and the confirmation dialog too. | A |
| S8 | `printf 'x token=fake.token-value_x=\n' \| redact_tokens` → `x token=<redacted>`; `./paddock logs` on the lab shows `token=<redacted>` in Authentik's refresh warning. | O |
| S9 | (unit) After a probation that fails by crashes the result file exists before the previous agent's script starts and exactly one result is written; (VM, S4) exactly one `device.agent_rolled_back` for the probation release within 3 minutes after the first. | D, A (audit) |
| S10 | A `Stack.Call` that fails inside a gate subtest fails that subtest and the remaining gates of the VM run; `go vet ./test/system/...` passes. | Dev |
| S11 | `make acceptance` locally finishes within 96 min (80 % of 120) with every gate green; the CI step `make acceptance` finishes within 96 min; the Makefile comment names the measured duration; the four session gates run in parallel. | Dev |
| S12 | With `@playwright/test` at 1.64.0 and `PLAYWRIGHT_IMAGE` at v1.63.0, `make e2e` stops before `docker run` with the message naming both files; with equal versions it runs; Dependabot's npm block ignores `@playwright/test`. | Dev |
| S13 | ADR 0032's amendment lists the period and purge of every remaining table; PDK-180 and PDK-187 are full tickets in the backlog with their blockers named. | architect |

## 10. Freedoms

Helper names inside the use cases and tests; the layout of the `PortalUsers` listing (sequential per group); whether
the held-URL gate lives in `stepup_test.go` or `sessions_test.go`; the fixture layout of the attention integration
test; the exact wording of log lines and of the upstream issue draft; how `e2e-check-playwright` parses the tag
(`sed` or shell parameter expansion) as long as the message is as specified; whether `redact_tokens` lives in `lib.sh`
or a new `logs.sh` sourced by both callers; the Go structure of `retryFlipBack`/`confirmRollback` as long as the
result precedes the restart; how the system-gate S4 counts the events (audit query or release detail).

## 11. Stop conditions

- S1: Authentik's blueprint importer rejects the scope mapping (the expression, the `managed` identifier or
  `scope_name`) or the token endpoint reports a mapping evaluation error (Authentik event `configuration_error`):
  report the importer or event text; do not relax decision 8 (the claim stays required).
- S2: the claim arrives but never names the class (`mfa_devices` entries are not dicts with `app` and `model_name` in
  2026.8.3's login event): report the event's `auth_method_args` content; do not derive the class from
  `ak_user_has_authenticator` or any per-user property (the factor *used* is what counts).
- S3: the held-URL sequence does not reproduce (the held URL re-runs `paddock-stepup`): implement decision 8 all the
  same and report the observation in the result document; do not drop the gate.
- S4: Authentik's validate stage with `device_classes: [webauthn]` and `configure` refuses the WebAuthn setup stage
  (importer error or the sign-in loops): report; do not restore TOTP in `paddock-admin-login-mfa` and do not switch to
  `deny`.
- S5: `bulk_delete` is missing in the pinned Authentik (404) or needs a permission the service account cannot be
  granted by blueprint: report; the fallback is one `DELETE /core/authenticated_sessions/<uuid>/` per listed session
  (`view_authenticatedsession` and `delete_authenticatedsession`), still inside the action.
- S6: the Authentik client is not available to the `end-sessions` CLI role without a new secret in the role's
  environment: report; do not add a token to a new location (use the api's existing `PADDOCK_AUTHENTIK_*` variables).
- S7: the next migration number or the `attention_condition` definition on `main` differs from what this plan and
  M8d assume (M8d's `uninstall` migration landed, or not): take the next free number, copy the view from the latest
  migration on `main` and add the branch; report the number; never renumber a merged file.
- S8: `supervisor_test.go`'s fake cannot observe the result file from the child script (sandbox or path): report; do not
  weaken the assertion to "one result" alone.
- S9: more than the ten listed `_test.go` files (plus M8d's) call Stack helpers, or a helper is called from a
  goroutine without a `t`: report the sites; do not keep a shared `t`.
- S10: the acceptance suite exceeds 96 min with decisions 36–37: report the measurement; do not raise the budget
  further without the architect and do not remove or skip a gate.
- S11: `node` would be needed to parse `package.json` in the Makefile: report; use `sed` as specified.
- S12: a new Go module, npm package or container image seems necessary (none is expected).
- S13: a change seems necessary in `agent/internal/revoke/`, `agent/cmd/paddock-revoke/`, `pkg/revocation/`,
  `pkg/bundle`, `api/openapi/device.yaml`, `paddock-dev.yaml`, `paddock-device.yaml`, or in M8d's files
  (`updates.go`, `agentrelease/`).

## 12. Risks and open points

- **The step-up claim depends on Authentik internals** (`get_login_event`, the login event's `auth_method_args`,
  the sanitized device dicts). An Authentik upgrade can change them; the acceptance gate `TestStepUpFactorClaim`
  and the lab verification catch it (fail closed: the step-up stops working rather than accepting TOTP). The upgrade
  rule for Authentik (`versions.env` comment) gains "and TestStepUpFactorClaim".
- **WebAuthn-only portal login locks out an administrator without an authenticator** (RR-62); the platform
  administrator's key is in custody; Authentik's own interface still accepts TOTP for authenticator management.
- **End-all and a slow or failing Authentik**: the action takes one listing per role group and one delete per 50
  users; a failure leaves Paddock sessions ended and reports failure (RR-35 pattern); the operator repeats.
- **`config_behind` on devices whose apply fails for other reasons** (a failing managed unit): intended — the kind
  means "not on the newest configuration"; M11's apply status (PDK-151/152) will name the cause; M11 keeps the kind.
- **Raising the acceptance budget hides growth**: the Makefile comment carries the measured total and the 20 % rule;
  the measurement names the next parallelization candidates.
- **Supervisor reorder and the SIGHUP**: `finishAt` signals the running child; after the reorder that child is the
  crashed release (or none); the restarted agent checks in at start, so nothing is lost (PDK-035 rule).
- O1 (open, default chosen): the maintainer posts the Authentik upstream issue (PDK-291); default: drafted, not
  posted, RR-63 recorded.
- O2 (open, default chosen): should `PADDOCK_STEPUP_MAX_AUTH_AGE` in development drop below 15 s to shorten the
  acceptance waits? Default: no (PDK-189 measures first; a later ticket may change it with the helpers).
- O3 (open, default chosen): the German term for `config_behind` is "Konfiguration im Rückstand"; alternative
  "Konfiguration veraltet". Default: as stated.
- O4 (open, default chosen): M8b's residual-risk reservation RR-40–42 collides with M8x's RR-40; default: M8b
  renumbers when it is planned, M8f keeps RR-62–66.
