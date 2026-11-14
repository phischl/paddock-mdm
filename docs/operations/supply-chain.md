# Supply chain

## Dependency updates

Renovate (`.github/workflows/renovate.yml`, configuration `renovate.json5`) runs every Monday at 04:00 UTC and on
demand (`workflow_dispatch`). It keeps the dependency dashboard issue, opens one `patch-weekly` pull request with all
patch and digest updates, and one pull request per minor or major update. Nothing merges itself: automerge is off
everywhere. GitHub Actions stay with Dependabot.

Pins with a gate a person runs before merging carry the label `gated-pin` (see `deploy/compose/versions.env`).

### Merging a Renovate pull request

Pull requests that the workflow opens with `GITHUB_TOKEN` do not start the CI workflows. Before merging one:

1. Close and reopen it: `gh pr close <number> && gh pr reopen <number>`.
2. Wait until every required check is green on the head commit.
3. Merge it.

### Precondition

The repository setting "Allow GitHub Actions to create and approve pull requests" must be enabled. Without it the
workflow cannot open pull requests and fails; do not work around it with another token.

### Coverage check

`make renovate-check` (part of `make lint`) fails when a line of `deploy/compose/versions.env` or the compiler's
Himmelblau default is not matched by a `customManagers` pattern of `renovate.json5`. `renovate.json5` must stay within
JSON with comments and trailing commas (quoted keys), because the check parses it that way. The `GITLEAKS_DEFAULT_CONFIG_*`
lines are intentionally unmanaged: they follow `GITLEAKS_IMAGE` through `make scan-secrets-check`.
