# 0054 — Renovate replaces Dependabot version updates and the upstream watch
Status: Accepted (architect, 2026-11-14; maintainer decisions Q11 of 2026-11-09 and §3.4 of 2026-11-14; plan
`docs/plans/M12h-2-supply-chain-and-mfa-enrolment.md`). Supersedes the "Upstream version watch" part (II) of ADR 0037.

## Context

Two mechanisms keep dependencies current today:

- **Dependabot version updates** (`.github/dependabot.yml`): Go modules in five directories, npm in `server/web`,
  GitHub Actions and the Compose directory, weekly, grouped minor+patch.
- **The upstream watch** (ADR 0037 II, `tools/upstreamwatch`, workflow `upstream-watch.yml`): one issue per outdated
  pin that Dependabot cannot see: the images pinned by tag and digest in `deploy/compose/versions.env`, the compiler's
  Himmelblau default, the fleetd build and the Fleet NVD release URLs. Issues, not pull requests, because every pin
  carried a gate a person had to run before merging.

In practice the maintainers bundle the issues into one bump PR within days. Patch
bumps cost a person's time every week, and Dependabot and the watch disagree on grouping and timing. ADR 0037 rejected
Renovate because it was a new dependency with write access that nobody had approved; the maintainer has approved it
(Q11) and decided on 2026-11-14: patch-level updates including image digests are grouped weekly and merged
automatically once CI is fully green; minor and major updates arrive as pull requests for review.

Dependabot **security alerts** are a separate GitHub feature (the dependency graph) and are not part of this decision.

## Options

- **A — Keep Dependabot and the watch.** − The weekly manual bundle stays; no automerge for the pins the watch covers.
- **B — Mend's hosted Renovate GitHub App.** + No workflow to maintain. − A third party holds a permanent
  installation token with contents and pull-request write access; its runtime and version are outside the
  repository's control.
- **C — Self-hosted Renovate in a GitHub Actions workflow, authenticated as a GitHub App owned by the maintainer, the
  action pinned by commit SHA and the Renovate image pinned by digest.** + The token is minted per run
  (`actions/create-github-app-token`) and expires after an hour; the configuration and version are reviewed in the
  repository; covers every manager in one place (gomod, npm, github-actions, docker digests, custom regex managers for
  `versions.env`, the Himmelblau pin and the Fleet NVD URL). − One new workflow, one GitHub App and its private key
  as a repository secret; the maintainer creates the App. **Chosen.**

## Decision

1. Renovate runs self-hosted (option C) from `.github/workflows/renovate.yml`, weekly (Monday 04:00 UTC) and on
   `workflow_dispatch`, with the configuration in `renovate.json5` at the repository root, against `main`.
2. **Grouping and merging.** One group `patch-weekly` for every `patch` and `digest` update across all managers:
   automerge through GitHub's native auto-merge once every required check is green. One pull request per dependency
   for `minor` and `major`, never automerged, labelled `dependencies`. Updates of `postgres`, `goauthentik/server`,
   `openbao/openbao`, `rustfs/rustfs`, `fleetdm/fleet`, `fleetdm/fleetctl` and the Himmelblau pin are never
   automerged, whatever their level: each carries a gate (restore drill, I2, the WORM gate, F0–F4, the identity VM
   gates) that CI does not run.
3. The `@playwright/test` package and `PLAYWRIGHT_IMAGE` move in one group; TypeScript majors stay ignored (as in
   Dependabot today).
4. **Automerge and the main ruleset.** `main` requires a pull request with a code-owner review. Automerge of the
   `patch-weekly` group needs the Renovate App as a bypass actor of that review rule, set by the maintainer; until it
   is set the group pull request is merged by a maintainer after green CI (the current practice).
5. Dependabot version updates (`.github/dependabot.yml`), `tools/upstreamwatch`, `upstream-watch.yml` and the
   `make upstream-check` target are removed once Renovate's dependency dashboard lists every pin that the watch
   covers (coverage test in the plan). Dependabot security alerts stay on.

## Consequences

- + Patch-level upkeep needs no person when CI is green; one tool, one dashboard, one grouping.
- + Every pin of `versions.env` becomes a pull request with a resolved digest instead of an issue.
- − A GitHub App with write access exists (least privilege: contents, pull requests, issues, workflows read-only is
  not enough because Renovate updates workflow pins: `workflows: write`); its key is a repository secret and must be
  rotated like other secrets.
- − Automerge trusts CI. CI runs lint, unit and integration tests, the secret scan, trivy and the web build on every
  pull request, and acceptance only on pull requests to `main` — the Renovate group targets `main`, so acceptance
  runs too. Pins with gates outside CI are excluded (decision 2).
- Re-evaluate when CI coverage changes or a bad automerged patch reaches a release.

## Amendment 2026-11-14 b — no GitHub App, no automerge (maintainer decision)

Status of this amendment: **Accepted** except point 4, which is **Proposed** (open design choice, recommendation given).

The maintainer decided: no GitHub App, no bypass of the code-owner review rule, no automerge. Renovate only opens
grouped pull requests; a maintainer merges them within days once CI is fully green. This replaces decisions 1, 2
(automerge parts) and 4, and changes decision 5.

**Constraints of the workflow token (`GITHUB_TOKEN`)**, which is all Renovate gets now:

- Events caused by `GITHUB_TOKEN` start no workflow run, except `workflow_dispatch` and `repository_dispatch`
  (GitHub Actions documentation, "Triggering a workflow from a workflow"). A pull request Renovate opens or updates
  therefore runs **no** `pull_request` CI on its own.
- `GITHUB_TOKEN` cannot be granted the `workflows` permission, so it cannot push changes to `.github/workflows/`:
  Renovate cannot update the SHA pins of GitHub Actions.
- Creating pull requests with `GITHUB_TOKEN` requires the repository setting "Allow GitHub Actions to create and approve
  pull requests" (a setting, not an App or a secret; set by the maintainer).

**Decisions.**

1. Renovate runs from `.github/workflows/renovate.yml` with `GITHUB_TOKEN` (`contents: write`, `pull-requests: write`,
   `issues: write` for the dependency dashboard), weekly and on `workflow_dispatch`. No App, no new secret.
2. Grouping without automerge: one group `patch-weekly` (patch and digest), one PR per minor or major update, the gated
   pins of decision 2 always separate; `automerge: false` everywhere.
3. The `github-actions` ecosystem stays with **Dependabot version updates** (its pull requests trigger CI and it may
   update workflow files); `.github/dependabot.yml` keeps exactly that block. Renovate's `github-actions` manager is
   disabled. Decision 5 accordingly removes only the other Dependabot blocks and the upstream watch.
4. **CI for Renovate's pull requests — open, for the orchestrating maintainer to choose:**
   - **(A) Dispatch CI from the Renovate workflow.** `ci.yml` gains `workflow_dispatch` (input `base`, default `main`)
     and treats a dispatch like a pull request to `base` in its pull-request-only steps; the Renovate workflow, after
     its run, dispatches `ci.yml` once for every open `renovate/*` branch whose head commit has no CI run yet. The check
     runs attach to the head commit and satisfy the required checks. + Fully automatic, no secret. − `ci.yml` gains a
     trigger and an event-dependent branch in several jobs; a later push by Renovate to an open branch needs the next
     Renovate run to be dispatched again.
   - **(B) Close and reopen.** The maintainer (with a personal token) closes and reopens each Renovate pull request
     before merging; `reopened` is a `pull_request` event by a user and runs the full CI. + No workflow change. − A
     manual step per pull request (merging is manual anyway).
   - (C) A personal access token or App for Renovate — excluded by the maintainer.
   **Recommendation: (B) for alpha.11** (no change to the CI workflow that guards every pull request, and the merge is a
   manual step anyway); revisit (A) if Renovate's volume makes the extra step costly. PDK-1023 implements decisions 1–3
   and whichever of (A) or (B) is chosen; until the choice it implements (B), which needs no code.
