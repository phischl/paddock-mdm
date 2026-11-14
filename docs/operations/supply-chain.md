# Supply-chain posture

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
dependencies. Findings of the first run are fixed under PDK-1025 follow-up before the score is recorded.
