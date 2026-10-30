# Testing strategy

Which tests and gates run where, what to do when one of them fails without a code cause, and how to read the timing
of the acceptance shards in a CI log. The workflows are `.github/workflows/ci.yml`, `bundle-smoke.yml` and
`release.yml`; the targets are in the `Makefile`. Running the stack and the gates locally is described in
`docs/operations/local-dev.md`.

## 1. Which gates run where

Changes reach `main` in clusters: a pull request for a single change targets a cluster branch and gets the fast
checks; the cluster branch then reaches `main` in one pull request, which runs the full acceptance suite once. A
public repository has a queue of 20 GitHub runners, which cannot run the acceptance stacks for every pull request.

### Per pull request (`ci.yml` and `bundle-smoke.yml`)

| Job | What it runs | When |
|---|---|---|
| `lint` | `make lint`: golangci-lint and `go vet`, the OpenAPI contract test, `make lint-tidy` (every workspace module must be tidy: `go mod tidy -diff`), govulncheck for all modules, the build stages of the server and compiler images (arm64 cross-compiled as well), ESLint and vue-tsc for the portal, the Prometheus and Caddy configuration checks, the license gate, the supervisor's line budget, shellcheck and the changelog fragment check | every pull request, push to `main` and the weekly schedule |
| `test` | `make test` (Go unit and integration tests with Docker test containers, the shell script tests, portal unit tests), then `make fuzz` (every fuzz test of `pkg/` for 30 s) | as `lint` |
| `secrets` | gitleaks: on a pull request over its own commits and, as a second view, over the final content of every changed file and every added blob (`make scan-secrets`, `make scan-secrets-diff`); otherwise over the full history | as `lint` |
| `trivy` | `make scan-fs` and `make scan-images` (vulnerabilities in dependencies and images) | as `lint`; the weekly schedule catches new CVEs in unchanged dependencies |
| `web` | `make web` (the portal build) | as `lint` |
| `acceptance (shard 1)` … `acceptance (shard 4)` | each shard on its own stack: `make dev-secrets`, `make up`, `make dev-seed`, then `make acceptance SHARD=i/4` | pull requests to `main`, pushes to `main`, the schedule; after `lint`, `test`, `web`, `secrets` and `trivy` passed |
| `acceptance (disruptive, e2e)` | on its own stack: the disruptive gates (`PADDOCK_ACCEPTANCE_DISRUPTIVE=1 make acceptance T='TestSessionsEndAll\|TestAutoUnsealRestart'`, which end every portal session and restart OpenBao and therefore run alone), then `make e2e` (Playwright) | as the shards, in parallel with them |
| `acceptance` | summary job: green only if every shard and the disruptive/e2e job are green; a skipped prerequisite fails it | as the shards |
| `bundle-smoke` | builds the images and the operator bundle from the pull request's code and installs it with the smoke scripts (default profile, then the lab profile behind Nginx); nothing is pushed or signed | only pull requests that change `deploy/**`, the `Makefile`, `.dockerignore` or the workflow itself (path filter) |
| `edge` | release images (pushed to ghcr.io and signed keylessly), SBOMs, operator bundle, checksums, then the smoke test of the edge bundle and of its lab profile | pushes to `main` only, after `acceptance` |

CodeQL (GitHub's default setup) scans pull requests to `main` and `main` itself.

**Required checks.** The ruleset of `main` requires the `acceptance` summary job, not the shard jobs. The number of
shards can therefore change in `ci.yml` alone, without a change to the ruleset.

`bundle-smoke` is deliberately **not** a required check. Because of its path filter it does not run at all on a pull
request that changes only Go code or the portal, and GitHub keeps a required check that never reports in the
"expected" state, which would block such a pull request forever. Treat a red `bundle-smoke` as blocking anyway when it
runs.

### Per cluster of changes (before the cluster's pull request to `main`)

One full regression on a local development stack (`docs/operations/local-dev.md`):

1. `make acceptance`, either serially in one run (180-minute timeout) or shard by shard
   (`make acceptance SHARD=i/4` for i = 1 … 4 against the same stack);
2. the disruptive gates and `make e2e`, as in the CI job above;
3. the agent system tests on the VirtualBox VMs: `make system-test VM=all` (both VMs in parallel; the VMs are set up
   with the scripts in `test/vms/`).

Run these **one after another, never in parallel**: system gate S3 takes the stack down for ten minutes to prove
that devices keep working while the server is unreachable, which would fail every acceptance gate running at the
same time.

### Per release

Everything of a cluster, on the release candidate, plus:

- the release workflow (`release.yml`, started by a `v*` tag): `build` (images, agent packages, SBOMs, operator
  bundle, checksums, keyless signatures), `smoke` (installs the release bundle on both hosts and checks them, without
  a registry login, which proves the images are publicly pullable), `sign` (agent release key, after the
  maintainer's approval) and `publish`;
- an installation of the release bundle on a lab host (`docs/operations/lab-install.md`) with real devices.

## 2. Flake policy

A test or CI step that fails and passes again without a code change is a flake. A rerun that turns green hides it,
and a hidden flake becomes a failure that nobody trusts. Therefore:

1. **Two failures without a code cause make a priority issue, immediately.** A test or CI step that fails twice
   without a code cause gets an issue at once, prioritized before new work.
2. **No rerun without an issue reference.** Whoever reruns a failed job notes it on the pull request with the issue
   number that tracks the failure. A rerun with no issue behind it is not done.
3. **No automatic retries**, neither in CI (retry actions, rerun loops) nor in tests (retry wrappers around
   assertions). Retries mask real failures, including the intermittent ones that matter most.
4. **A flaky test is fixed, or its cause removed; it is never skipped or weakened** to make it pass. Waiting for a
   condition that the system really reaches asynchronously is a fix; a longer sleep or a looser assertion is not.

Infrastructure flakes count too: a Go module proxy timeout, a registry pull that fails, a runner that runs out of
disk. They get an issue and a structural fix (a cache, a pinned digest, a local mirror), not a retry.

## 3. How to read shard timing

### Where the numbers are

A shard job log consists of these steps:

| Step | What it is |
|---|---|
| `make dev-secrets`, `make up`, `make dev-seed` | setup of the shard's stack, **not** gate time. Together ~7–9 min per job (measured on PR #227, 2026-10-29) |
| `make acceptance SHARD=i/4` | the gates. The first line, `acceptance shard i/4: -run '<regex>'`, names the gates of this shard |
| `compose logs`, `Fleet log` | only on failure |

Inside the `make acceptance` step, two kinds of lines carry timing:

- `--- PASS: TestName (123.45s)` (or `--- FAIL`): the duration of one top-level test. Indented lines below it are its
  subtests.
- `ok  	github.com/.../test/acceptance	1925.312s`: the wall time of the whole package in this shard.

The timestamps GitHub prints in front of each log line are **no** guide to per-test timing. `make acceptance` runs
`go test -v` over several packages (`./test/acceptance/...`), and with more than one package `go test` buffers each
package's output and prints it when the package is done; the lines of a 30-minute package all arrive within the same
second. Only the `(Ns)` durations and the package's `ok … Ns` line are measurements.

### Tests with parallel subtests under-report

A test whose subtests call `t.Parallel()` reports only its sequential part. Go pauses parallel subtests until the
parent's function returns, prints the parent's `--- PASS` duration at that point, and only then runs the subtests.
The parent's real cost is therefore not in its own line. Compute it as the package time of its shard minus the sum of
the `--- PASS` durations of the other top-level tests in that shard.

Example: `TestAuditExactlyOnce` checks about 180 delivery cases in parallel. Its `--- PASS` line says ~400 s; package
time minus the other tests of its shard gives ~1730 s, which is what it really costs. It is the reason a fifth shard
would save only a few minutes: no shard can be shorter than this one test.

### What normal looks like

With four shards (PR #227, 2026-10-29) each shard runs ~32 min of gates, and a shard job takes 39–43 min including
the setup above. Before, with three shards, the jobs took ~45, ~72 and ~45 min: one shard carried far more than the
others. The overall acceptance stage is as long as its slowest shard, so **compare the shards with each other**, not
with a fixed number.

### Refreshing `test/acceptance/shard-weights.txt`

`make acceptance SHARD=i/n` assigns every gate to exactly one shard with a greedy balance over the measured durations
in `test/acceptance/shard-weights.txt` (`test/acceptance/cmd/acceptanceshard`). A gate missing from the file still
runs, with a default weight of 60 s, so the file only affects the balance, never the coverage.

Refresh it when a shard's gate time drifts more than a few minutes away from the others in recent green runs on
`main`, typically after gates were added or became noticeably slower:

1. Take several recent green CI runs (the current file uses the median of eight).
2. For every top-level test, collect its `--- PASS: TestName (Ns)` duration from the shard logs and take the median.
3. For tests with parallel subtests, use the package time minus the other tests of that shard instead (see above).
4. Write one line per test, `<seconds> <test> [group]`. Tests that share a group run in parallel with each other and
   stay in one shard; the group weighs as much as its slowest member. Update the header's source line (date and run
   IDs).
5. Check the partition locally; it needs no stack:

   ```sh
   go test -list '.*' ./test/acceptance/... \
     | go run ./test/acceptance/cmd/acceptanceshard -verify 4 -weights test/acceptance/shard-weights.txt
   ```

   It prints that every test is selected by exactly one shard; `-shard i/4` instead of `-verify 4` prints the
   `-run` regex of shard i.

The next run on `main` shows whether the shards are even again.
