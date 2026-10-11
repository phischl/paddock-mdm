# Secret scan

The CI job `secrets` runs gitleaks on every pull request and on every push to `main`. Locally, `make scan-secrets`
scans the history of the current branch and `make scan-secrets-diff` the files changed since `origin/main`.

## What a pull request is scanned with

- `make scan-secrets` scans the pull request's own commits, merge commits included (`--remerge-diff`, PDK-057).
- `make scan-secrets-diff` scans the final content of every file the pull request changes.
- Both read `.gitleaks.toml` and `.gitleaksignore` from the pull request's merge base (`GITLEAKS_CONFIG_REF`, PDK-065).
  A pull request that changes either file is scanned with the base's version. An allowlist for a new false positive
  therefore lands in its own pull request first, and the pull request with the flagged content follows once it is
  merged.
- A `.gitleaksignore` in the scanned tree is never loaded, inline `gitleaks:allow` comments are ignored, and a
  `.gitleaks.toml` that extends another file (`[extend] path`) fails the scan; `useDefault` alone is allowed.

## What the scan relies on

A pull request runs its own `.github/workflows/ci.yml`, `Makefile` and scripts. It can therefore change how it is
scanned, or skip the scan, and no setting inside the repository prevents that. The scan's integrity rests on code
review of `.github/`, the `Makefile` and `deploy/compose/scripts/`.

`.github/CODEOWNERS` names a reviewer for these paths and for `.gitleaks.toml` and `.gitleaksignore`. GitHub enforces
code owners only once branch protection (or a ruleset) on `main` requires a review from code owners; that is a setting
of the maintainer. Recommended for `main`:

- require a pull request with an approving review from code owners;
- require the status checks `secrets` (and the other CI jobs) to pass before merging.

Until those settings are on, a reviewer has to check every change to the paths above by hand.
