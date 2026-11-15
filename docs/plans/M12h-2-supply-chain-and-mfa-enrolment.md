# Implementation plan: M12h-2 — Renovate, OpenSSF Scorecard and second-factor enrolment by link

Status: accepted (architect arch-a11, 2026-11-14), release 0.1.0-alpha.11. Decision records: ADR 0053 (Accepted),
ADR 0054 (Accepted). Binding language: **MUST** / **MUST NOT** / **SHOULD** / **MAY**. Tickets: PDK-1023 to PDK-1027.

## 1. Goal

Patch-level dependency updates reach `main` without a person when CI is green, the repository's supply-chain posture
is measured weekly against a published target, and no new administrator account can get a second factor enrolled by
whoever learns its password first.

## 2. Context

- M12h §13 outlined M12h-2 (Authentik controls, portal headers, parsers, database and secrets, supply chain). The
  maintainer scoped alpha.11 to **Renovate, OpenSSF Scorecard and MFA enrolment** (Q11, `decisions-alpha11.md` §2.3).
  The other outline items stay outline (Non-goals).
- Dependency updates today: `.github/dependabot.yml` (gomod in `/pkg`, `/server`, `/agent`, `/test/acceptance`,
  `/test/system`; npm in `/server/web` with `typescript` majors and `@playwright/test` ignored; github-actions; docker
  in `/deploy/compose`), and the upstream watch (`tools/upstreamwatch`, `.github/workflows/upstream-watch.yml`, `make
  upstream-check`) for `deploy/compose/versions.env`, the compiler's Himmelblau default, fleetd and the Fleet NVD
  URLs (ADR 0037 II).
- `main` ruleset: pull request, code-owner review (`.github/CODEOWNERS` covers `/.github/`, `/Makefile`,
  `/deploy/compose/versions.env`, …), required CI. CI on PRs: `lint`, `test`, `secrets`, `trivy`, `web`; on PRs to
  `main` also `acceptance` (shards, disruptive/e2e) and CodeQL.
- Second factor: `deploy/compose/authentik/blueprints/paddock-portal.yaml` stages `paddock-admin-login-mfa`,
  `paddock-admin-login-webauthn` (both `configure`), `paddock-admin-login-webauthn-confirm` (`deny`) and
  `paddock-default-login-mfa` (`configure`) on Authentik's default flow; one-time links: `paddock-recovery.yaml` and
  `adapters/authentik/users.go::RecoveryLink` (24 h).
- ADR 0053 and ADR 0054 (Accepted) carry the decisions; this plan makes them executable.

## 3. Binding decisions

### Requirements

| ID | Requirement | Acceptance (who sees it) |
| --- | --- | --- |
| SC-R1 | Renovate opens one weekly group PR for all patch and digest updates and merges it on fully green CI; minor and major updates are single PRs. | The maintainer sees merged `patch-weekly` PRs without action and open minor/major PRs. |
| SC-R2 | Every pin the upstream watch covers is covered by Renovate before the watch is removed. | The maintainer sees every pin in Renovate's dependency dashboard issue. |
| SC-R3 | OpenSSF Scorecard runs weekly and on pushes to `main`, publishes results and fails no build. | Anyone sees the Scorecard badge and results on the repository's security tab. |
| MFA-R1 | A new administrator account cannot enrol a second factor in the sign-in; it enrols through a one-time link. | A new administrator signing in without a factor sees a denial; with the link the administrator enrols and then signs in. |
| MFA-R2 | Administrators existing at the upgrade without a factor enrol at their next sign-in. | Such an administrator sees the enrolment step at the next sign-in, then the portal. |
| MFA-R3 | The change is announced. | Every administrator sees a banner for 30 days after the upgrade; the operator reads an `Upgrade:` line in the release notes. |

### Decisions

1. **Renovate runtime (ADR 0054 decision 1).** Workflow `.github/workflows/renovate.yml`: triggers `schedule`
   `cron: "0 4 * * 1"` and `workflow_dispatch`; `permissions: {}` at workflow level, job `contents: read`; token from
   `actions/create-github-app-token` with `secrets.RENOVATE_APP_ID` and `secrets.RENOVATE_APP_PRIVATE_KEY`; runs
   `renovatebot/github-action` pinned by commit SHA with `renovate-version` pinned to an image digest
   (`ghcr.io/renovatebot/renovate@sha256:…`); `RENOVATE_REPOSITORIES: phischl/paddock-mdm`; checkout with
   `persist-credentials: false`. The App permissions: contents write, pull requests write, issues write, workflows
   write, checks read, metadata read. The App is created by the maintainer (§12).
2. **Configuration** `renovate.json5` at the repository root:
   - `extends: ["config:recommended", ":dependencyDashboard", ":semanticCommits", "helpers:pinGitHubActionDigests"]`,
     `baseBranches: ["main"]`, `timezone: "UTC"`, `schedule: ["before 6am on monday"]`, `prConcurrentLimit: 10`,
     `labels: ["dependencies"]`, `commitMessagePrefix` per Conventional Commits (`build(deps):`).
   - `packageRules` (in this order):
     1. `matchUpdateTypes: ["patch", "digest", "pin", "pinDigest"]` → `groupName: "patch-weekly"`, `automerge: true`,
        `automergeType: "pr"`, `platformAutomerge: true`.
     2. `matchUpdateTypes: ["minor", "major"]` → `automerge: false`, no group.
     3. `matchPackageNames` (docker): `postgres`, `ghcr.io/goauthentik/server`, `openbao/openbao`, `rustfs/rustfs`,
        `fleetdm/fleet`, `fleetdm/fleetctl`, and the Himmelblau custom dependency → `automerge: false`,
        `groupName: null`, label `gated-pin` (ADR 0054 decision 2).
     4. `matchPackageNames: ["@playwright/test", "mcr.microsoft.com/playwright"]` → `groupName: "playwright"`,
        `automerge: false`.
     5. `matchPackageNames: ["typescript"]`, `matchUpdateTypes: ["major"]` → `enabled: false`.
   - `customManagers` (`customType: "regex"`):
     - `deploy/compose/versions.env`: `^(?<depName>[A-Z0-9_]+)_IMAGE=(?<packageName>[^:@\s]+):(?<currentValue>[^@\s]+)@(?<currentDigest>sha256:[a-f0-9]{64})$`,
       `datasourceTemplate: "docker"`.
     - The compiler's Himmelblau default (the file and constant that `tools/upstreamwatch/himmelblau.go` reads), with
       `datasourceTemplate: "deb"`, `registryUrlTemplate` = the Himmelblau repository URL that `upstreamwatch` uses.
     - `FLEET_CPE_DATABASE_URL` / `FLEET_CPE_TRANSLATIONS_URL` in `versions.env`: `datasourceTemplate:
       "github-releases"`, `depNameTemplate: "fleetdm/nvd"`, both URLs in one dependency.
     - `GITLEAKS_DEFAULT_CONFIG_*` are not managed (they follow `GITLEAKS_IMAGE` by an existing make target; the
       `gitleaks` PR fails `make scan-secrets-check` until regenerated, which is intended).
   - Go toolchain: the gomod manager updates `toolchain` lines; `go-version` in workflows is matched by a regex
     manager on `go-version: "(?<currentValue>[0-9.]+)"` with `datasourceTemplate: "golang-version"` and grouped with
     `GO_BUILD_IMAGE` in group `go-toolchain` (never automerged: a toolchain bump touches `go.work`, every `go.mod` and
     every workflow together, PDK-727 practice).
3. **Coverage check (SC-R2).** `tools/renovatecheck` (Go, standard library) reads `deploy/compose/versions.env` and
   the list of pins that `tools/upstreamwatch/pins.go` knows, and fails when one of them is not matched by a
   `customManagers` pattern of `renovate.json5` (JSON5 parsed by stripping comments and trailing commas; the file
   MUST stay within that subset). It runs in `make lint`.
4. **Removal (ADR 0054 decision 5).** After the first scheduled Renovate run on `main` whose dashboard lists every
   pin, a separate ticket removes the `version-updates` of `.github/dependabot.yml` (the file is deleted; security
   alerts are a repository setting), `tools/upstreamwatch`, `upstream-watch.yml`, `make upstream-check` and the
   `upstream` label documentation, and rewrites ADR 0037 II's operator text in `docs/operations/local-dev.md`.
   `tools/renovatecheck` then reads its pin list from `versions.env` and the compiler default only.
5. **Scorecard.** Workflow `.github/workflows/scorecard.yml`: triggers `push` to `main`, `schedule`
   `cron: "30 5 * * 1"`, `branch_protection_rule`, `workflow_dispatch`; `permissions: read-all` at workflow level;
   job permissions `security-events: write`, `id-token: write`; `ossf/scorecard-action` pinned by SHA with
   `publish_results: true`; SARIF uploaded with `github/codeql-action/upload-sarif` (already used by CodeQL, same
   pinned SHA). It never fails a build. README gains the Scorecard badge.
6. **Scorecard targets.** Overall score ≥ 7.0 within alpha.11 and ≥ 8.0 by the first beta. Checks with a binding
   target of 10 in alpha.11: `Token-Permissions`, `Pinned-Dependencies`, `Dangerous-Workflow`, `Binary-Artifacts`,
   `Dependency-Update-Tool`, `Security-Policy`, `License`, `SAST`. Checks accepted below 10 with a recorded reason in
   `docs/operations/supply-chain.md`: `Code-Review` (solo maintainer, admin merges), `Contributors`, `Maintained`,
   `CII-Best-Practices` (not registered), `Fuzzing` (M12h-2 parser fuzzing is outline only), `Signed-Releases`
   (minisign signatures are not detected by Scorecard). Every finding of a target-10 check is fixed in PDK-1025.
7. **MFA enrolment (ADR 0053).** Exactly as decided there; the binding object names:
   - stages: `paddock-admin-login-mfa` and `paddock-admin-login-webauthn` get `not_configured_action: deny`; new
     sibling stages `paddock-admin-login-mfa-enrol` and `paddock-admin-login-webauthn-enrol` with `configure`, bound
     at the same orders with policy `paddock-mfa-enrol-at-login` (expression:
     `return bool(request.user.attributes.get("paddock_mfa_enrol_at_login"))`); the deny stages bound with the
     negated policy `paddock-mfa-enrol-at-login-absent`. Same pair for `paddock-default-login-mfa`
     (`paddock-default-login-mfa-enrol`).
   - recovery flow `paddock-recovery`: the password prompt stage binding gets policy
     `paddock-recovery-password-missing` (`return not request.user.has_usable_password()`); new bindings after it:
     `default-authenticator-webauthn-setup` (required) with policy `paddock-recovery-webauthn-missing`, and
     `default-authenticator-totp-setup` with `re_evaluate_policies: true` and a policy that skips it when a TOTP
     device exists. The flow's title becomes "Set up your sign-in".
   - The flow change applies to local-user password links too: a new local user who opens the link now sets a
     password and enrols a passkey in one go (intended).
   - `RecoveryLink` keeps its 24 h validity; the new use cases call it.
   - Worker: `Identity.adminAccounts` gains `seedMFAEnrolAtLogin` (once, guarded by
     `platform_mfa_enrolment.seeded_at`) and `clearMFAEnrolAtLogin` (every round, for accounts with a
     WebAuthn device). New adapter methods `SetUserAttribute(ctx, pk, key string, value any) error`,
     `UserAuthenticators(ctx, pks []string) (map[string]ports.Authenticators, error)` (one listing per authenticator
     type: `GET /api/v3/authenticators/admin/webauthn/?user=…` and `…/totp/`).
   - API: `POST /api/v1/users/{id}/enrolment-link` → 201 `{ "link": string, "expires_at": date-time }`;
     `x-paddock-step-up: true`; roles `org_admin`; 404 `not_found`; 409 `invalid_state` for a disabled user; 502
     `upstream_unavailable`. Audit `user.enrolment_link_created` (params `username`; never the link). Host command
     `paddock-server admin enrolment-link --username <name>` for platform administrator accounts (refuses a user who
     is not a direct member of `paddock.platform.admins`), audit `platform.enrolment_link_created` in the platform
     pseudo-organization. `/login-denied?reason=mfa_enrolment_required` is added to the reasons.
   - Portal: on the user detail an action "Create sign-in setup link" (step-up, shows the link once in a dialog with
     copy, never again); a banner component on every page for platform and organization administrators for 30 days
     after `platform_mfa_enrolment.seeded_at`, text from i18n, with the count of accounts still marked
     (`GET /api/v1/me` gains `mfa_enrolment_notice: {until: date-time, pending: int} | null`; the count is per
     organization for organization administrators and platform-wide for platform administrators).
8. **Changelog.** PDK-1026 adds `changelog.d/PDK-1026.changed.md` with an `Upgrade:` line naming the behaviour.

## 4. Non-goals

- The rest of the M12h §13 outline (reputation policy, Trusted Types, Permissions-Policy, fuzz targets, runtime
  OpenAPI validation, SECURITY DEFINER lint, role-matrix gate, log redaction, key rotation jobs, SLSA provenance,
  SBOMs, `npm ci --ignore-scripts`). They stay outline for a later release.
- No change to the device login flow's MFA (`paddock-device-authentication`): device users keep enrolment at first
  device login (ADR 0053 decision 5).
- No e-mail delivery of links.
- No change of the `main` ruleset by an agent: the bypass actor is set by the maintainer (§12).
- No removal of Dependabot security alerts.

## 5. Affected files

| Path | Action | Purpose |
| --- | --- | --- |
| `renovate.json5` | new | configuration |
| `.github/workflows/renovate.yml` | new | runtime |
| `tools/renovatecheck/` | new | coverage check |
| `Makefile` | change | `renovate-check` in `lint`; later remove `upstream-check` |
| `.github/dependabot.yml`, `tools/upstreamwatch/`, `.github/workflows/upstream-watch.yml` | delete (PDK-1024) | replaced |
| `.github/workflows/scorecard.yml` | new | Scorecard |
| `.github/workflows/*.yml` | change | Scorecard target-10 findings (token permissions, pins) |
| `SECURITY.md`, `README.md` | change | policy check, badge |
| `docs/operations/supply-chain.md` | new | Renovate policy, Scorecard targets and accepted checks |
| `docs/operations/local-dev.md` | change | dependency updates section |
| `deploy/compose/authentik/blueprints/paddock-portal.yaml`, `paddock-recovery.yaml` | change | ADR 0053 |
| `server/internal/adapters/authentik/users.go`, `ports/identity.go` | change | attribute and authenticator methods |
| `server/internal/worker/identity.go` | change | seed and clear |
| `server/internal/app/users.go`, `app/enrolmentlinks.go` | change/new | use cases |
| `server/internal/domain/audit/codes.go` (+ generated docs) | change | two codes |
| `server/cmd/paddock-server/admin.go` | change | host command |
| `api/openapi/admin.yaml` | change | endpoint, `Me` field, denial reason |
| `server/web/src/...` | change | action, dialog, banner, i18n |
| `test/acceptance/mfa_enrolment_test.go` | new | gates MF1–MF4 |
| `changelog.d/PDK-1026.changed.md` | new | `Upgrade:` line |

**MUST NOT be touched:** `paddock-device.yaml`, `paddock-stepup.yaml`, `paddock-mcp.yaml`, the release workflow's
signing steps, branch rulesets.

## 6. Interfaces and data model

```yaml
/api/v1/users/{id}/enrolment-link:
  post:
    operationId: createUserEnrolmentLink
    x-paddock-step-up: true
    x-paddock-audit: user.enrolment_link_created
    description: "Roles: org_admin. A one-time sign-in setup link (24 h): password if missing, passkey, optional TOTP (ADR 0053)."
    parameters: [Csrf]
    responses:
      "201": { content: { application/json: { schema: { type: object, required: [link, expires_at],
               properties: { link: { type: string, format: uri }, expires_at: { type: string, format: date-time } } } } } }
      "401", "403" (forbidden | step_up_required), "404" (not_found), "409" (invalid_state), "502" (upstream_unavailable)
Me.mfa_enrolment_notice: { type: object, nullable: true, required: [until, pending],
  properties: { until: date-time, pending: integer } }
```

```sql
-- paddock migration; single-row platform table like platform_mcp_settings (RLS enabled+forced, policy for
-- paddock_platform only)
CREATE TABLE platform_mfa_enrolment (
  id        boolean PRIMARY KEY DEFAULT true CHECK (id),
  seeded_at timestamptz NOT NULL
);
```

```go
// server/internal/ports/identity.go
type Authenticators struct{ WebAuthn, TOTP bool }
// adapter (authentik.Client) gains:
func (c *Client) SetUserAttribute(ctx context.Context, pk, key string, value any) error
func (c *Client) UserAuthenticators(ctx context.Context, pks []string) (map[string]ports.Authenticators, error)
```

## 7. Implementation steps

1. **PDK-1023 Renovate.** Do: decisions 1–3; `docs/operations/supply-chain.md` "Dependency updates". Result:
   the workflow exists; `make lint` runs `renovate-check`; Renovate's config validator passes. Check: `make lint`;
   `npx --yes renovate-config-validator renovate.json5` in the `NODE_IMAGE` container (no repository dependency);
   after the maintainer created the App: `workflow_dispatch` run produces the dashboard issue.
2. **PDK-1025 Scorecard.** Do: decision 5; run once; fix target-10 findings (decision 6) in workflows and files;
   record accepted checks. Result: results on the security tab. Check: workflow run green; score recorded in
   `supply-chain.md`.
3. **PDK-1026 MFA flows and worker.** Do: blueprint changes, adapter methods, seed/clear, changelog. Result: new
   accounts denied without factor, marked accounts enrol. Check: acceptance MF1, MF2, MF4.
4. **PDK-1027 MFA link API, host command, portal.** Do: endpoint, host command, audit codes, portal action and
   banner. Check: acceptance MF3, component tests, `frontend-verify`.
5. **PDK-1024 removal.** Only after step 1 ran on `main` and the dashboard lists every pin. Do: decision 4.
   Check: `make lint test`; `git grep -n upstreamwatch` returns only history documents (plans, ADRs).

## 8. Tests

- `tools/renovatecheck`: unit tests with a fixture `versions.env` where one pin is unmatched → exit 1 naming it; all
  matched → exit 0; JSON5 comments and trailing commas parsed.
- Acceptance (`test/acceptance/mfa_enrolment_test.go`, against Authentik of the dev stack, with
  `PADDOCK_LOGIN_MFA_OPTIONAL` off for these tests as in the existing MFA gates):
  - MF1: a new user in `paddock.<slug>.admins` without a factor and without the attribute → the portal sign-in ends
    at a denial; `admin.login` denied with reason `mfa_enrolment_required`.
  - MF2: the same user with `paddock_mfa_enrol_at_login: true` → the sign-in offers enrolment; after a virtual
    WebAuthn enrolment the portal session exists; the next worker round removes the attribute.
  - MF3: `POST /api/v1/users/{id}/enrolment-link` without step-up → 403 `step_up_required`; with step-up → 201;
    the link opens `paddock-recovery`, enrols a passkey, and the user then signs in; the link used twice → Authentik
    refuses; the audit event has no `link` param; an `org_operator` → 403.
  - MF4: seeding: a user existing before the first round without a factor gets the attribute exactly once; a user
    created after the seed marker never gets it.
- Existing gates MUST stay green: `TestIdentityLockAuthentik`, the step-up gates, `TestSessions*`, e2e login specs.

## 9. Acceptance criteria

- SC-R1 — Given Renovate runs on Monday; when only patch and digest updates are available and CI is fully green;
  then the maintainer sees one merged `patch-weekly` PR (or, until the bypass is set, one green PR a maintainer
  merges); a minor update appears as its own open PR.
- SC-R2 — Given the dashboard issue; then the maintainer sees every pin of `versions.env`, the Himmelblau default and
  the Fleet NVD release listed; `make lint` fails when a new `*_IMAGE` line is not matched.
- SC-R3 — Given a push to `main`; then anyone sees Scorecard results on the security tab and the README badge; the
  overall score is ≥ 7.0 and the target-10 checks score 10.
- MFA-R1 — Given a new administrator without a factor; when the administrator signs in; then the administrator sees a
  denial naming the missing setup; with a link created by an organization administrator the administrator enrols and
  signs in.
- MFA-R2 — Given an administrator who existed without a factor before the upgrade; when the administrator signs in;
  then the administrator sees the enrolment step and afterwards the portal.
- MFA-R3 — Given the upgrade; then every administrator sees the banner for 30 days, and the release notes carry the
  `Upgrade:` line.

## 10. Degrees of freedom

- Renovate options not named in decision 2 (`rebaseWhen`, `dependencyDashboardTitle`, commit body).
- The order of Scorecard fixes and which workflow files they touch, within decision 6.
- Banner design within the portal design system (ADR 0023).

## 11. Stop conditions

- Renovate's `deb` datasource cannot read the Himmelblau repository: stop; report; keep `upstreamwatch` for that pin
  only (decision 4 then removes everything else).
- Authentik 2026.8 cannot bind a policy to a stage binding that decides on a user attribute before identification is
  complete, or `has_usable_password()` is unavailable in expression policies.
- Any Scorecard fix requires a new action or tool beyond `ossf/scorecard-action` and `actions/create-github-app-token`.
- A target-10 check cannot reach 10 without changing the release signing.

## 12. Risks and open points

- **Maintainer actions (not agents):** create the GitHub App "paddock-renovate" with the permissions of decision 1,
  install it on the repository, store `RENOVATE_APP_ID` and `RENOVATE_APP_PRIVATE_KEY`; add the App as bypass actor
  of the code-owner review rule of `main` for automerge (ADR 0054 decision 4). Until then a maintainer merges the
  green group PR.
- New CI components: `renovatebot/github-action` with the Renovate image, `actions/create-github-app-token`,
  `ossf/scorecard-action`. Approved with Q11 (Renovate, Scorecard); listed for the maintainer in the alpha.11 questions.
- **RR-139 (new):** device users still enrol their factor at first device login (ADR 0053 decision 5).
- Automerge risk: a patch that passes CI but breaks a path CI does not cover reaches `main`; the gated pins are
  excluded and the release regression still runs before every tag.

## Amendment 2026-11-14 b — Renovate without App and automerge (maintainer decision; ADR 0054 amendment b)

Binding; where it contradicts the sections above (decisions 1, 2.1, 4; SC-R1; §11; §12 maintainer actions), it wins.

- **Runtime (replaces decision 1).** `.github/workflows/renovate.yml`: `schedule` `cron: "0 4 * * 1"` and
  `workflow_dispatch`; workflow-level `permissions: {}`; job permissions `contents: write`, `pull-requests: write`,
  `issues: write`; `renovatebot/github-action` pinned by SHA with the Renovate image pinned by digest; `token:
  ${{ secrets.GITHUB_TOKEN }}`; `RENOVATE_REPOSITORIES: phischl/paddock-mdm`; `persist-credentials: false`. No
  `actions/create-github-app-token`, no App, no new secret.
- **Configuration (amends decision 2).** Rule 1 becomes `groupName: "patch-weekly"`, `automerge: false`; no rule sets
  `automerge: true`; `platformAutomerge` is not set. `enabledManagers` excludes `github-actions` (and the
  `helpers:pinGitHubActionDigests` preset is dropped). Labels: `dependencies`; the group PR additionally `patch-weekly`.
- **Dependabot (amends decision 4).** `.github/dependabot.yml` keeps only the `github-actions` block; PDK-1024 removes the
  other blocks, `tools/upstreamwatch`, `upstream-watch.yml` and `make upstream-check`.
- **CI trigger.** Open choice (A) dispatch or (B) close/reopen, ADR 0054 amendment b point 4; recommendation (B). With (B)
  `docs/operations/supply-chain.md` documents: before merging a Renovate PR, close and reopen it (`gh pr close <n> &&
  gh pr reopen <n>`) and merge after every required check is green. With (A) PDK-1023 adds the dispatch step and the
  `workflow_dispatch` handling in `ci.yml`, with a test run on one Renovate branch.
- **SC-R1 (replaces).** Given Renovate runs on Monday with patch and digest updates available; then the maintainer sees
  one open `patch-weekly` PR and one PR per minor or major update; after CI is triggered (A or B) and fully green, a
  maintainer merges it; nothing merges itself.
- **Maintainer action (replaces §12 first bullet).** Enable the repository setting "Allow GitHub Actions to create and
  approve pull requests". New CI component: `renovatebot/github-action` with the Renovate image (approved with Q11).
- **Stop condition (added).** The repository setting is not enabled when PDK-1023 runs its first dispatch: stop and
  report; do not work around it with another token.

## Amendment 2026-11-14 c — MFA enrolment: administrators only, TOTP-only administrators, the denial reason (architect decision for PDK-1026; ADR 0053 amendment c)

Binding; where it contradicts decision 7, §8 MF1/MF4 or §9 MFA-R1, it wins.

1. **The deny applies to administrators only.** `paddock-admin-login` is the default brand's authentication flow, so
   the device-code page runs it for every device user (blueprint comment of stage B, PDK-498). "Administrator" is the
   existing policy `paddock-admin-login-webauthn-administrator`: a direct member of `paddock.platform.admins` or of
   `paddock.<slug>.admins|operators|auditors`. Decision 4's seed MUST use exactly this predicate. Bindings, with all
   object names of decision 7 unchanged:
   - Stage A `paddock-admin-login-mfa` (deny): `paddock-mfa-enrol-at-login-absent` AND `…-webauthn-administrator`
     (policy engine mode `all`).
   - Stage A sibling `paddock-admin-login-mfa-enrol` (configure): `paddock-mfa-enrol-at-login` OR NOT
     `…-webauthn-administrator`. NOT is the binding's `negate: true` on a second binding of the administrator
     policy; engine mode `any`. Device users therefore keep today's enrolment (ADR 0053 decision 5, RR-139).
   - Stage B `paddock-admin-login-webauthn` (deny): `…-webauthn-missing` AND `…-webauthn-administrator` AND
     `paddock-mfa-enrol-at-login-absent`.
   - Stage B sibling `paddock-admin-login-webauthn-enrol` (configure): `…-webauthn-missing` AND
     `…-webauthn-administrator` AND `paddock-mfa-enrol-at-login`.
   - `paddock-default-login-mfa` and `paddock-default-login-mfa-enrol`: the same pair as stage A.
   Test (acceptance, added to MF1): a new device user without a factor completes `/device` enrolment through the
   brand flow as before; a new administrator without a factor is denied.
2. **Seed every administrator without a WebAuthn device.** Decision 4's seed sets `paddock_mfa_enrol_at_login: true` on
   every administrator (point 1 predicate) without a WebAuthn device at the first round after the upgrade, including
   accounts that have only TOTP. Reason: stage B now denies an administrator without WebAuthn, so seeding only accounts
   with neither factor would lock TOTP-only administrators out. Stage A still demands their TOTP (configure acts only
   when no device exists, so it validates the existing TOTP). The removal rule is unchanged: the attribute is cleared
   once the account has a WebAuthn device. MF4 gains a case: a TOTP-only administrator existing before the seed gets
   the attribute, proves TOTP, enrols a passkey, and the next round clears the attribute.
3. **The denial reason.** Authentik's deny ends on Authentik's own access-denied page; no callback reaches Paddock,
   so no `admin.login` event is recorded for it (an Authentik decision, not a Paddock action). Binding:
   - `mfa_enrolment_required` joins the closed `/login-denied` reason set (API enum, en/de i18n).
   - The OIDC callback uses it in place of `passkey_required`/`mfa_required` when `UserAuthenticators` reports no
     WebAuthn device for the account. This is reached only when Authentik let such an account through, for example
     with `PADDOCK_LOGIN_MFA_OPTIONAL`.
   - MF1 asserts the Authentik denial (the flow executor answers with the access-denied component), that no portal
     session exists, and that no `admin.login` success event is recorded.
   - MFA-R1 reads "sees Authentik's denial".
   - The Authentik-side denial is visible in Authentik's event log (`login_failed`), which is shipped like every
     Authentik event.

Tickets: points 1–3 PDK-1026 (blueprint, worker seed, callback, gates MF1/MF4); the reason enum and i18n of point 3
belong to PDK-1026 as well. PDK-1027 is unchanged except that its portal texts use the reason key of point 3.

## Amendment 2026-11-14 d — the link flow without TOTP, audit of the sign-in marking, lab-only gates (architect decision for PDK-1026; ADR 0053 amendment d)

Binding; where it contradicts decision 7 or amendment c, it wins.

1. **No TOTP stage in the link flow.** Authentik's TOTP setup stage cannot be skipped. An "optional" TOTP would need an
   extra choice stage, and a mandatory TOTP would add a second enrolment to every link, including local users' password
   links, for little gain: portal sign-in and step-up accept only WebAuthn, so a TOTP device does not restore access
   after a lost passkey (that needs a new link). `paddock-recovery` therefore runs: link-token policy → password prompt
   (only when the password is missing) → WebAuthn setup (required) → end. The binding of
   `default-authenticator-totp-setup` and the policy `paddock-recovery-totp-missing` are removed from the blueprint.
   Accounts that want TOTP add it through Authentik's user settings, as before. MF3 asserts that the link flow shows no
   TOTP stage.
2. **The marking is audited.** Setting or clearing `paddock_mfa_enrol_at_login` changes an administrator's sign-in
   requirement, so it is a privileged system action. It goes through `ActionRunner` as the system actor in the
   platform pseudo-organization, with two new closed codes:
   - `platform.mfa_enrol_marks_seeded`: params `marked` (int), `totp_only` (int), `organizations` (int); outcomes
     success and failure.
   - `platform.mfa_enrol_marks_cleared`: params `cleared` (int); outcomes success and failure.

   An event is recorded per round only when the round wrote at least one attribute. A failure after a partial write
   is recorded as failure with the count written so far. A round that writes nothing records nothing, so an Authentik
   outage does not fill the log. No usernames go into the params; Authentik's own event log holds the per-account
   `model_updated` entries. Both codes are ≤ 32 characters (MSGID as is), have en/de messages, and are Wazuh
   informational. Tests: the seed records exactly one event with the counts; a second round records none; a clearing
   round records `cleared`; an injected failure after one write records failure with `marked: 1`.
3. **Device listing without `?user=`.** Authentik 2026.8.5 ignores the filter. The adapter lists every WebAuthn and
   every TOTP device (paged) and matches by `user.pk`. This is accepted: `Seed` runs once, `Clear` costs nothing when
   nothing is marked, and the callback lookup runs only on a factor denial of an account with a portal role.
   Follow-up PDK-1042 bounds the callback lookup if lab measurements show a cost.
4. **Lab-only gates get their own ticket.** The MF1 denial page and the MF2 real passkey enrolment cannot run on the
   dev stack, because its blueprint skips MFA. They become ticket PDK-1042, "MFA enrolment lab gate", which must be
   green before the alpha.11 release tag and runs as part of the release regression on the lab. PDK-1026 is done when
   its dev-stack gates are green and PDK-1042 exists.

### Correction 2026-11-14 to amendment d point 3

Amendment d point 3 is wrong and is replaced. In Authentik 2026.8.5, `GET /api/v3/authenticators/admin/all/?user=<pk>`
does filter by user. The adapter's `UserAuthenticators` uses that endpoint, one request per account, and decision 7's
per-type listings are replaced by it. The PDK-1042 measurement of the callback lookup stays.

## Amendment 2026-11-14 e — administrators set up their second factor only through the setup link, in every sign-in flow (architect decision; ADR 0053 amendment e)

Binding; it replaces the §4 non-goal "No change to the device login flow's MFA".

1. **One rule for every shipped sign-in flow.** Every Authentik flow that Paddock ships, the device login flows
   included, applies the deny/enrol pair of amendment c to every stage that can set up a second factor. An
   administrator who is neither marked (amendment c point 2) nor already has a factor sets one up only through the
   setup link. The technical binding list is in ticket PDK-1047.
2. **Device users** keep setting up their factor at their first device sign-in (decision 5, RR-139). **Administrators
   who approve a device sign-in** prove a factor they already have.
3. **Tests (both required).** A blueprint test fails when any stage in a production blueprint that can set up a factor
   lacks the pair. An acceptance regression gate on the dev stack (attribute `paddock_dev_enforce_mfa`) proves that an
   administrator without a factor cannot set one up in any device sign-in flow, and that a device user still can. The
   lab repeats the administrator case (PDK-1042).
4. **Releases.** PDK-1047 implements this. It blocks the alpha.11 release tag. No alpha.10 hotfix: alpha.10 does not
   have the setup-link model at all, and alpha.11 introduces it.

## Amendment 2026-11-15 f — older setup links, synced accounts, the banner (architect decision after the PDK-1027 review)

Binding; where it contradicts decision 7 or the amendments above, it wins.

1. **A new setup link replaces older ones.** Only the newest setup or password link of an account may work. Creating a
   link first deletes the account's unexpired recovery tokens in Authentik, then issues the new one; the audit event
   (`user.enrolment_link_created`, `platform.enrolment_link_created`, and the existing local-user link) gains the param
   `previous_links_revoked` (int). If the deletion fails, no new link is issued (502 `upstream_unavailable`). Granting
   a portal role does not revoke links: roles are granted in Authentik or the upstream source, not by Paddock. Ticket
   **PDK-1052** (follow-up; PDK-1027 ships as it is, with its current help text, which PDK-1052 then shortens to "a new
   link ends every older one").
2. **Synced accounts get links, never a local password.** Administrators usually come from the organization's
   identity source, so `POST /api/v1/users/{id}/enrolment-link` accepts synced users; only disabled users are refused
   (as planned). The link flow MUST NOT set an Authentik password for an account Paddock does not manage: the password
   prompt runs only when the account has `paddock_managed: true` **and** no usable password. A synced account's link
   therefore only sets up the passkey. Blueprint change and an acceptance case (a synced user's link shows no password
   prompt) in **PDK-1052**.
3. **Banner audience and wording: accepted as implemented.** All portal roles (organization administrator, operator,
   auditor, platform administrator) see it during the 30 days. With nothing pending it shows the announcement without a
   count. Reusing the setup-link wording is correct; the denial reason key stays for the denial page only.
4. **No organization-issued link for a platform administrator.** When the account is a direct member of
   `paddock.platform.admins` (an identity with both roles, ADR 0045), `POST /api/v1/users/{id}/enrolment-link` answers
   409 `invalid_state` with the detail "platform administrators receive their setup link from the host operator" and
   records the attempt as a failure. Reason: an organization administrator must not control how a platform account gets
   its second factor; the host command stays the only path for platform administrators. In **PDK-1027**, with an
   acceptance case.

### Addendum 2026-11-15 to amendment f point 2 — hand-created platform administrators (architect decision after PDK-1052 review 1)

Binding; it refines point 2. The problem: the operator creates the first platform administrators by hand in Authentik
(install §9 step 1). Those accounts carry no `paddock_managed`, so since point 2 their setup link only enrolled a
passkey. A hand-created account without a password could then never sign in to the portal, because the sign-in asks
for the password first.

1. **The host command marks the account (main's option b, with a dedicated attribute).**
   - `paddock-server admin enrolment-link --username <name>` sets the Authentik attribute
     `paddock_password_by_link: true` on the account before it issues the link.
   - Exception: the account has an upstream source connection (Authentik's user source connections list an entry for
     it). Then the command sets nothing, issues a passkey-only link, and prints that the password stays with the
     upstream source.
   - The command's audit event `platform.enrolment_link_created` gains the param `password_allowed` (boolean).
   - *Rejected:* setting `paddock_managed` itself. That attribute means "Paddock created this account" and drives the
     identity sync's managed/synced distinction (`ports.IdentityUser.Managed`); reusing it would change how other
     rounds treat the account.
2. **The flow rule.** The password prompt of `paddock-recovery` runs when the account has no usable password **and**
   either `paddock_managed` or `paddock_password_by_link` is true. The attribute stays on the account; a later link
   with an existing password still skips the prompt, because it is then usable.
3. **The portal endpoint is unchanged.** `POST /api/v1/users/{id}/enrolment-link`:
   - accounts Paddock created get a password prompt;
   - synced accounts get the passkey only;
   - platform administrators are refused (point 4).

   It never sets `paddock_password_by_link`.
4. **Wording.** Texts, help and documents say "an account Paddock created" (or "a Paddock-managed account") where
   they said "local user", wherever the meaning is `paddock_managed`.
5. **install.md §9 step 1** gains one sentence: create the platform administrator in Authentik without a password and
   without an authenticator, add it to `paddock.platform.admins`, then run `./paddock compose run --rm --no-deps paddock-worker admin
   enrolment-link --username <name>` (the pattern of the other `admin` host commands) and hand over the link; it sets
   the password and the passkey.
6. **Tests (PDK-1052):**
   - the host command on a hand-created account without a password sets the attribute, and the link shows the password
     prompt and then the passkey setup;
   - the same command on an account with a source connection sets nothing, and the link shows no password prompt;
   - the portal endpoint never sets the attribute;
   - the audit param `password_allowed` matches each case.

### Addendum 2026-11-15 b to amendment f — hand-created organization administrators (architect decision; ticket PDK-1055)

Binding; it refines the addendum above for organization accounts.

1. **Supported sources of an organization administrator.** An organization administrator either comes from the
   organization's identity source, or is created in Paddock (portal *Users* → create, which sets `paddock_managed`) and
   then added to a role group. Both kinds already get a working link from the portal: the source account gets the
   passkey only, the Paddock-created account gets password and passkey. An account created by hand in Authentik is
   outside that model. `docs/operations/getting-started.md` step 3 and `install.md` §9 say so.
2. **Operator path for a hand-created account.** `paddock-server admin enrolment-link --username <name>` also accepts
   an account that is a direct member of an organization's `admins`, `operators` or `auditors` group, not only of
   `paddock.platform.admins`. Everything else is as in the addendum above: it marks `paddock_password_by_link: true`
   unless the account has an upstream source connection, and the link then sets the password and the passkey.
   - The event `platform.enrolment_link_created` gains `organization_id` (the account's organization, or none for a
     platform administrator).
   - The event is recorded in the platform pseudo-organization: the operator acts on the host, outside any
     organization.
   - The command refuses an account that is in no portal role group.
3. **The portal stays unchanged.** It never marks accounts. An organization administrator must not be able to give a
   local password to an account Paddock did not create; that remains an operator decision on the host.
4. **Priority: alpha.11**, small (one command check, one audit param, documentation). Risk medium, Sonnet. Tests:
   - a hand-created organization admin without a password gets a link with password and passkey through the host
     command;
   - an account in no role group is refused;
   - the portal endpoint still never sets the attribute.
