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
