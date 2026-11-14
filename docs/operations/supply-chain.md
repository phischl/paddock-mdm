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

## OpenSSF Scorecard

The workflow `.github/workflows/scorecard.yml` runs the OpenSSF Scorecard on every push to `main`, weekly (Monday
05:30 UTC), when a branch protection rule changes and on demand. It publishes the result (the README badge and
`scorecard.dev`) and uploads it to the repository's security tab (Security, Code scanning). It never fails a build.
Both actions are pinned by commit SHA; Renovate keeps the pins current.

### Targets (plan M12h-2 decision 6)

- Overall score: at least 7.0 in 0.1.0-alpha.11, at least 8.0 by the first beta.
- Binding score 10 for `Token-Permissions`, `Pinned-Dependencies`, `Dangerous-Workflow`, `Binary-Artifacts`,
  `Dependency-Update-Tool`, `Security-Policy`, `License` and `SAST`. A finding in one of these checks is fixed, not
  accepted.

### Accepted checks below 10

| Check                | Reason |
| -------------------- | ------ |
| `Code-Review`        | Solo maintainer; pull requests are merged by the maintainer with administrator rights. |
| `Contributors`       | The project has a single contributing organization. |
| `Maintained`         | Scores low while the repository is young. |
| `CII-Best-Practices` | The project is not registered for the OpenSSF Best Practices badge. |
| `Fuzzing`            | Parser fuzzing is outline only (M12h-2 non-goal). |
| `Signed-Releases`    | Releases are signed with minisign, which Scorecard does not detect. |

### Recorded score

| Date | Overall | Target-10 checks | Note |
| ---- | ------- | ---------------- | ---- |
| open | open    | open             | Filled in by the maintainer after the first run on `main`: the workflow cannot run before the merge. |

The workflow files were reviewed against the target-10 checks before the first run: every workflow declares
`permissions` at the top, every action is pinned by commit SHA and no workflow downloads or installs unpinned
