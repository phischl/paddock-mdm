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
