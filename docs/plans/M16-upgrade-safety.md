# Implementierungsplan: M16 — Upgrade safety (tested upgrade path, pre-upgrade checks, restore drill)

Status: Ready for implementation · 2026-11-04 · Author: architect
Basis: ADR 0047 (upgrade guarantee; **Accepted 2026-11-04**, the maintainer set the first guaranteed pair to
0.1.0-alpha.8 → alpha.9);
ADR 0013 with the amendment of 2026-11-04 (support window per release until 0.1.0); ADR 0022 (bundle, images,
keyless signing); ADR 0005 / 0024 (additive bundle and event formats); ADR 0046 and plan M15 (`./paddock backup
now`, `./paddock restore`, the local target); plan M7b decisions 16, 25, 27–28 (host script, smoke test, upgrade
and rollback runbook); roadmap "Continuous track → Upgrade safety" (F-29).

Binding language: **MUST** / **MUST NOT** / **SHOULD** / **MAY**.

This plan is written against `main` at `80984bde` (0.1.0-alpha.8). Tickets: PDK-740 to PDK-746 (§8). Milestone
number M16. The restore drill of this plan uses M15's commands: PDK-744 depends on PDK-734 and PDK-733.

## 1. Goal

An operator upgrades an installation from release N to N+1 with `./paddock upgrade-check` (tells them what will
happen and what is missing, changes nothing) and `./paddock upgrade` (does exactly what the runbook described, with
a labelled backup first), and goes back with `./paddock rollback`; a maintainer cannot cut a release whose upgrade
from the previous release, whose rollback and whose restore from a backup have not passed in CI; a device with an
agent of the two previous releases keeps working against the new server, and the check refuses an upgrade that
would strand more.

## 2. Context (verified in the code on 2026-11-04, `main` at `80984bde`)

- **Bundle and host script**: `deploy/bundle/build.sh` builds `paddock-deploy-<version>.tar.gz` (the Compose
  files, scripts, `versions.env`, `VERSION`, `SHA256SUMS`, `README.md`, `.env.example`); `deploy/bundle/paddock`
  with `migrate-from <old dir>` (copies `.env` and `.secrets/`, refuses when they exist), `pull`, `check`
  (prod-check in a one-off container), `up` (waits for health, 15 min for a sealed OpenBao), `down`; `versions.env`
  pins every image by tag and digest; `PADDOCK_IMAGE` is the release image.
- **Release pipeline**: `.github/workflows/release.yml` jobs `build`, `smoke` (`deploy/bundle/ci/smoke.sh
  <tarball> --agent-artifacts <dir>`: two Compose projects `paddock-cp` and `paddock-audit` on one runner, the CI
  overlay `compose.ci.yaml`, steps 1–10 with `probe`/`expect_status`, `assert-hardening.sh`, a pgBackRest backup,
  the agent release upload), `sign` (environment `release`), `publish` (GitHub release with the tarball,
  `.sigstore.json`, agent artifacts). `ci.yml` job `edge` builds and smoke-tests an edge bundle on `main`;
  `acceptance-e2e` runs for PRs to `main` and `main` only (PDK-526).
- **Migrations**: `server/internal/platform/migrate/migrate.go` (`goose.NewProvider`, `Paddock`, `Audit`),
  embedded in `server/migrations/migrations.go`; forward-only; `paddock-migrate` service runs `migrate paddock +
  provision rabbitmq` before the roles start. `CHANGELOG.md` release sections carry `Schema: migrations …`.
- **Upgrade runbook**: `docs/operations/upgrade.md` (before you start, upgrade per host, rollback by schema line,
  per-release notes; alpha.7 = fresh installation). Residual risk RR-36 (offline devices during an agent-first
  order).
- **Agent window**: `pkg/protocol.CheckinRequest.SchemaVersions`; the compiler renders the newest common schema;
  the 426 `agent_unsupported` answer of ADR 0013 is **not implemented** (no such code in `server/internal`);
  `protocol.CheckinResponse.AgentUpdate` carries the update pointer; `device_status.agent_version` and
  `component_versions` are known per device; the attention kind `agent_outdated` appears in integration tests
  (the implementer verifies the attention view); `test/acceptance/component_versions_test.go`.
- **devicesim**: `test/acceptance/cmd/devicesim` (enroll, check-in, events) built from the repository.
- **Fixtures**: `pkg/bundle/testdata/`, `pkg/protocol/testdata/` hold current-schema examples; nothing is
  version-tagged.
- **Secrets and roles**: `gen-prod-secrets.sh <host>` is idempotent (writes missing files only);
  `openbao-configure.sh` is idempotent with `BAO_TOKEN`; new database roles were manual steps in M9 (`CREATE ROLE
  paddock_notifier`), documented in `upgrade.md`.
- **Release checks**: `make release-check` (`Makefile` target `release-check`: version, changelog section,
  pins), `make changelog-check`.

## 3. Binding decisions

### 3.1 The compatibility contract in code (PDK-740)

1. `make lint-migrations-frozen` (new Makefile target, part of `make lint`) MUST run
   `tools/migrationsfrozen` (new, `go run ./tools/migrationsfrozen --since <tag>`): it resolves the previous
   release tag (`git describe --tags --abbrev=0 --match 'v*' --exclude "$CURRENT"` or `PADDOCK_PREVIOUS_TAG`),
   lists `server/migrations/paddock/*.sql` and `server/migrations/audit/*.sql` at that tag, and fails when any
   of those files differs or is missing in the working tree, printing the file names. In CI the checkout uses
   `fetch-depth: 0`. The lint passes when no `v*` tag exists (a fresh fork).
2. **Previous-release fixtures.** `pkg/compat/testdata/<release>/` (new, release = `0.1.0-alpha.8` first) holds,
   per release, `bundle-schema-<n>.json` (one signed bundle per schema version the release's agent accepts, as
   the release's compiler rendered it for the acceptance organization), `checkin.json` and `events.json` (the
   release's devicesim request bodies), `commands.json` (one signed command per registered type). `make
   compat-fixtures RELEASE=<v>` (new target) regenerates the files for the current tree (run by the maintainer at
   release time; the release checklist of `docs/operations/testing-strategy.md` gains the step). `pkg/compat/
   compat_test.go` `TestPreviousReleaseFixtures` MUST, for every release directory: `bundle.Verify` + `VerifyVersions`
   accept every bundle (with the fixture's public key); the gateway's decoders (`ingest` types) accept the
   check-in and the events with `DisallowUnknownFields` off (unknown fields from a newer release are ignored by
   an older server, so the reverse direction is a devicesim test in CI, decision 12); `command.Verify` accepts
   the commands. A release directory older than two releases is deleted by `make compat-fixtures` (the window).
3. **Release notes contract.** `make release-check` MUST additionally require, in the release's `CHANGELOG.md`
   section, the lines `Schema: …` (exists), `Upgrade: from <previous release>: automatic` or `Upgrade: from
   <previous>: steps: <text>`, and `Agents: supports <N-2>, <N-1>, <N>`; `make changelog` writes the three
   lines from `changelog.d/_release.md` (new fragment kind `release`, one per release, written by the maintainer).

### 3.2 Server-side upgrade report (PDK-741)

4. `paddock-server admin upgrade-check --target-version <v> [--json]` (platform scope, system actor, read-only)
   MUST print a report with the items: `migrations` (the database's applied version vs the binary's embedded
   highest; FAIL when the database is ahead of the binary — a downgrade), `agents` (count and list of active
   devices whose `agent_version` is outside the window of ADR 0013's amendment for `--target-version`: FAIL when
   more than 1 % or more than 5, WARN otherwise with the list; the window is computed from the release list the
   binary carries: `buildinfo.ReleaseSequence()` — a generated ordered list of release versions, `make gen` from
   the `v*` tags plus the current version), `backups` (M15: an active key, every enabled target with a success of
   every kind within 26 h, the escrow kind within 3 h: FAIL on a missing key, WARN on stale), `openbao` (sealed
   state; auto-unseal on or off: INFO), `pending` (open restore plan, running agent rollout, halted configuration
   rollout: WARN), `sessions` (platform administrators signed in: INFO). Exit code 0 when no FAIL, 1 otherwise,
   2 on usage. The report is also `GET /api/platform/v1/upgrade-check?target_version=…` (platform admin, read,
   no audit) for the portal's *Platform → Upgrade* information card (PDK-746 adds the card).
4a. **Out-of-window agents degrade predictably** (ADR 0013 amendment 2026-11-04, replacing the 426 answer that was
   never built): the gateway accepts a check-in whose `agent_version` is outside the window and answers it with
   `AgentUpdate` (the newest published release the device is eligible for, regardless of waves) and **no** bundle
   pointer and **no** commands; the worker's `RecordStatus` marks the device `agent_outdated` (attention kind; the
   implementer adds the kind to the attention view exactly as `agent_rollback_pending` was added if it is absent)
   and the device's events are still accepted. The window is `buildinfo.Window()`; a `device_status.agent_version`
   older than every known release counts as outside. An agent of the previous release handles this response today
   (it updates and reports). PDK-741 implements it; gate C5 proves it.

### 3.3 Host commands (PDK-742, PDK-743)

5. `./paddock upgrade-check <old dir>` (new; runs in B's directory before `migrate-from`; read-only) MUST print a
   PASS/WARN/FAIL table and exit 0/1/2 as decision 4, with the items in this order:
   1. `old bundle verified` — `<old dir>/paddock verify` passes (FAIL otherwise);
   2. `versions adjacent` — `<old dir>/VERSION` is the release directly before this bundle's `VERSION` in
      `buildinfo.ReleaseSequence()` (FAIL when older: *upgrade through <list> first*; FAIL when newer or equal);
   3. `release notes` — the `Upgrade:` line of this release is printed (`automatic` or the steps); the
      `Agents:` line;
   4. `env` — every key of this bundle's `.env.example` that is absent from `<old dir>/.env` and has no default in
      the Compose files (`compose config` with the old `.env` fails with the `:?` message) is listed as FAIL with
      the example's comment; keys present in the old `.env` but unknown to this bundle are WARN;
   5. `secrets` — every secret file this bundle's Compose files reference that `<old dir>/.secrets/` lacks is
      listed (INFO: `./paddock secrets` will generate it; FAIL for secrets that cannot be generated: the release
      keys, the OpenBao AppRole files);
   6. `disk` — free space on the Docker data root ≥ the sum of the new images' sizes × 2 plus 2 GiB (`docker
      manifest inspect` sizes from `versions.env`; WARN when the manifest cannot be read offline);
   7. `images pullable` — `docker manifest inspect` of every image of this host (WARN offline);
   8. `server report` — decision 4 through the **old** stack (`<old dir>/paddock compose run --rm --no-deps
      paddock-worker admin upgrade-check --target-version <new>`; the old binary knows the command from this
      release on; for the first guaranteed pair, alpha.8 → alpha.9, the item runs the new image against the old
      stack's database: `./paddock compose … run --rm --no-deps --entrypoint paddock-server paddock-worker admin
      upgrade-check` with `PADDOCK_IMAGE` of the new `versions.env` — the schema is read-only for the check);
   9. `openbao unseal path` — `PADDOCK_AUTO_UNSEAL=yes` with the shares file present, or a WARN that three
      custodians must be available during `./paddock up`;
   10. `running stack healthy` — `<old dir>/paddock ps` shows every service healthy (WARN otherwise);
   `--json` prints `{items: [{name, status, detail}], exit}`. The command never writes.
6. `./paddock upgrade <old dir> [--yes] [--allow-unsupported-agents] [--skip-backup]` MUST: run decision 5 and
   stop on FAIL (`--allow-unsupported-agents` turns the agent FAIL into WARN; nothing else is overridable);
   print the plan (the steps below with the versions) and ask for `yes` on the terminal unless `--yes`; then
   `migrate-from <old dir>`; `./paddock secrets` (generates missing secrets only); `pull`; `check` (every item
   PASS, else stop before anything changed on the running stack — the old stack is still up); on the control
   plane and lab: `<old dir>/paddock backup now --label pre-upgrade-<new version> --wait` (M15; `--skip-backup`
   is refused on the control plane unless the release notes say `Schema: unchanged` — the flag exists for the
   audit host, which has no backup role); `up` (this directory; Compose recreates the containers with the new
   images, `paddock-migrate` runs); on the control plane with `BAO_TOKEN` set: `openbao-configure.sh` (idempotent;
   without the token: print the manual step when this release's notes list OpenBao changes); post-checks: `ps`
   healthy, `paddock-server admin upgrade-check --target-version <new>` on the new stack shows `migrations` at
   the binary's version, `check --online` on the audit host and lab; print *Keep <old dir> until the next
   upgrade: it is the rollback*. Every step prints its command. The command is idempotent after a failure:
   re-running continues at the first incomplete step (a marker file `.upgrade-state` in the new directory,
   deleted at the end).
7. `./paddock rollback <old dir> [--yes]` MUST: read this directory's release notes line `Schema:`; `down` here;
   when `Schema: unchanged`: `<old dir>/paddock up`; when `Schema: migrations …` (control plane, lab): restore the
   set labelled `pre-upgrade-<this version>` from the **local** target through M15's `restore.sh`
   (`restore_run fresh <backup-repo volume path> --only postgres --only openbao --only fleet --only escrow`, with
   the key from `.secrets/backup_encryption_key` of the old directory — the legacy file — or, when the
   installation already runs on a portal key, the operator is prompted for it), then `<old dir>/paddock up`;
   Fleet's dump is restored when `FLEET_IMAGE` differs between the two `versions.env`. The audit host rolls back
   with `down` + old `up` only: audit migrations within a guaranteed pair are additive (ADR 0047 decision 2), so
   the old writer inserts into a superset schema; `TestPreviousReleaseFixtures` (decision 2) gains the case
   *the previous release's writer insert statement runs on the current audit schema* (`pgtest`, the statement
   text kept in the fixture directory). The command asks for `yes` and prints *every change after <backup time>
   is lost*.

### 3.4 Idempotent provisioning (PDK-745)

8. `paddock-server migrate paddock` MUST, after the migrations, run `provision roles`: for every database role
   of the control plane (`paddock_api`, `paddock_worker`, `paddock_compiler`, `paddock_platform`,
   `paddock_notifier`, `paddock_backup`, `paddock_escrow_reader`, `paddock_revocation_issuer`,
   `paddock_outbox_relay`, `paddock_audit_reader` on the audit database) whose password file
   `PADDOCK_DB_<ROLE>_PASSWORD_FILE` is mounted into `paddock-migrate`: `CREATE ROLE … LOGIN` when absent, then
   always `ALTER ROLE … PASSWORD` (idempotent, cheap, no comparison needed); the password travels as a bound
   parameter, never in a logged statement. Grants stay in the migrations. `compose.yaml` mounts the password
   secrets into `paddock-migrate`. The manual `CREATE ROLE` steps leave `upgrade.md`.
   *Amendment 2026-11-04 (PDK-745):* the mechanism is not `provision roles` inside `paddock-server migrate`
   (`paddock_owner` stays `NOCREATEROLE`, `paddock-migrate` gets no superuser credential). The one-shot service
   `db-provision` (`audit-db-provision` for the audit database) uses the postgres image already in the stack, mounts the
   superuser password file read-only into that service only, and runs the single idempotent script
   `deploy/compose/postgres/provision-roles.sh` (also the initdb hook, one source of truth): `CREATE ROLE` guarded by
   an existence check, `ALTER ROLE … PASSWORD` from the `*_FILE` secrets on every run, role-level grants
   (CONNECT/USAGE); a role without a mounted secret file is skipped with a message. `paddock-migrate` and
   `paddock-audit-migrate` depend on it with `service_completed_successfully`. The role names are those of the
   existing roles (`paddock_revocation`, `paddock_relay`), not the list above.
9. `openbao-configure.sh` MUST stay idempotent for every key, policy and AppRole it creates (it is today); `./paddock
   upgrade` calls it when `BAO_TOKEN` is set. `gen-prod-secrets.sh` MUST print the names of the files it created
   (it does) and `./paddock upgrade` shows them.

### 3.5 CI (PDK-744)

10. `deploy/bundle/ci/upgrade.sh <previous tarball> <candidate tarball> [--agent-artifacts <dir>] [--work <dir>]`
    (new; shares `lib-smoke.sh`, extracted from `smoke.sh`: `step`, `probe`, `expect_status`, the two-host
    install) MUST: install the previous release as `smoke.sh` does (both hosts, CI overlay, its agent artifacts
    from the previous GitHub release); **seed** through the admin API with a platform session (the smoke test's
    first administrator; `deploy/bundle/ci/seed.sh` new): one organization, one enrollment token, one devicesim
    device enrolled with the **previous release's devicesim** (built from the previous tag's checkout into
    `<work>/devicesim-prev`), one escrowed admin password of that device, one managed file, one notification
    destination (webhook to the smoke test's sink), one API token; record the device ID, the bundle version and
    the audit event count; then `./paddock upgrade-check` on both hosts (expect exit 0 or 1 with only the known
    WARNs: `openbao unseal path`), `./paddock upgrade` with `--yes` on the control plane then the audit host;
    **probe**: every seeded object exists with the same IDs (`GET` each), the previous devicesim checks in
    against the new server and receives a bundle with a higher version containing the managed file, its events
    are accepted (`POST /v1/events` 202), the audit event count only grew and `TestAuditChain`'s verification
    endpoint reports the chain intact, the escrowed password is revealed with a step-up (the smoke test's
    WebAuthn helper), the new devicesim (candidate) enrolls too; `assert-hardening.sh`; then the **restore
    drill**: `./paddock backup now --label ci --wait` (local target of the CI overlay), `./paddock down
    --volumes` on the control plane, `./paddock secrets`, `./paddock restore --from <local target path> --at
    <time after the seed>` with the CI key, probes again (the seeded objects, a check-in of the previous
    devicesim); then **rollback**: `./paddock rollback <previous dir> --yes` → the previous stack is healthy and
    the seeded objects exist (the pre-upgrade set). Exit codes and logs as `smoke.sh`.
11. `release.yml` MUST gain the job `upgrade` (`needs: build`, after `smoke`, `timeout-minutes: 60`): downloads
    the previous release's tarball, `.sigstore.json` and agent artifacts with `gh release download
    v<prev>` (previous = the newest `v*` tag below the candidate), verifies the tarball with cosign as
    `install.md` §3 does, runs `upgrade.sh`. `ci.yml` MUST gain the same job gated like `acceptance-e2e` (PRs to
    `main`, `main`) with the candidate bundle built from the tree (`make release-bundle RELEASE_VERSION=ci-<sha>
    RELEASE_CHANNEL=edge` as `edge` does, images from the PR's `make image`), and `edge` keeps its smoke test.
    The `sign` and `publish` jobs `need` `upgrade`.
12. The job is the gate of ADR 0047 decision 5: `docs/operations/testing-strategy.md` lists it next to the
    acceptance shards; a flake follows the project's flake rule (ticket, no re-run without one).

### 3.6 Documents (PDK-746)

13. `docs/operations/upgrade.md` MUST be rewritten around the three commands: *Before you start* (the guarantee,
    the release notes lines, what the check reads), *Upgrade* (`upgrade-check`, `upgrade`, what each step does,
    the OpenBao custodians, the agent order), *Rollback* (`rollback`, what is lost), *Per release* (one
    subsection per release from alpha.8 on; the older notes move to an *Archive* section), *Upstream version
    watch* unchanged. `docs/architecture.md` §21 gains the amendment (window per release, the commands, the CI
    job); `docs/operations/testing-strategy.md` the job and the fixture step; `docs/compliance/residual-risks.md`
    RR-105 to RR-107 (§6.4); `README.md` the one-line upgrade; `CHANGELOG.md` template lines; the portal card
    *Upgrade* on `/platform` (reads decision 4's endpoint; shows the window, the agents outside it, the backup
    state; no action).

## 4. Non-goals

- No automatic upgrade (no self-update of the bundle, no scheduler); no upgrade across two releases in one step
  (the check refuses; the operator upgrades twice).
- No Kubernetes; no migration tool for stateful image majors (its own ADR when needed).
- No down migrations.
- No change to the agent, the supervisor or the revocation path; the agent's own A/B update is unchanged.
- No portal action for upgrades (information card only).

## 5. Affected files

| Path | Action | Purpose |
| --- | --- | --- |
| `tools/migrationsfrozen/main.go` (+ `_test.go`), `Makefile` (`lint-migrations-frozen`, `compat-fixtures`, `release-check`) | new / change | decisions 1–3 |
| `pkg/compat/compat_test.go`, `pkg/compat/testdata/0.1.0-alpha.8/*` | new | decision 2 |
| `server/internal/buildinfo/releases.gen.go`, `tools/releaseseq/main.go` | new | `ReleaseSequence()` |
| `server/cmd/paddock-server/admin.go`, `server/internal/app/upgradecheck.go` (+ tests) | change / new | decision 4 |
| `api/openapi/admin.yaml`, `server/internal/transport/http/admin/handlers_platform.go` | change | `GET /api/platform/v1/upgrade-check` |
| `deploy/bundle/paddock`, `deploy/bundle/README.md`, `deploy/bundle/bundle_test.sh` | change | `upgrade-check`, `upgrade`, `rollback` |
| `deploy/compose/scripts/upgrade-check.sh`, `upgrade.sh`, `rollback.sh` (+ `_test.sh`) | new | decisions 5–7 (sourced by the host script) |
| `server/cmd/paddock-server/main.go` (`provision roles`), `server/internal/platform/db/provision.go` | change / new | decision 8 |
| `deploy/compose/compose.yaml` (`paddock-migrate` secrets) | change | decision 8 |
| `deploy/bundle/ci/upgrade.sh`, `seed.sh`, `lib-smoke.sh`, `smoke.sh` | new / change | decision 10 |
| `.github/workflows/release.yml`, `ci.yml` | change | decision 11 |
| `changelog.d/_release.md` (template), `Makefile` (`changelog`) | change | decision 3 |
| `docs/operations/upgrade.md`, `testing-strategy.md`, `docs/architecture.md`, `docs/compliance/residual-risks.md`, `README.md`, `server/web/src/views/PlatformOverview.vue` (or the platform landing view), `locales/*` | change | decision 13 |

Not to be touched: `agent/`, `server/migrations/` (no new migration in M16), the revocation path, ADRs other than
0047 and the 0013 amendment.

## 6. Interfaces

### 6.1 Host commands

```
./paddock upgrade-check <old dir> [--json]
./paddock upgrade <old dir> [--yes] [--allow-unsupported-agents] [--skip-backup]
./paddock rollback <old dir> [--yes]
paddock-server admin upgrade-check --target-version <v> [--json]
```

Report item JSON: `{"name": "agents", "status": "FAIL", "detail": "7 of 120 active devices run 0.1.0-alpha.6
(window: alpha.7, alpha.8, alpha.9): lt-01, lt-02, …"}`.

### 6.2 Admin API

```
GET /api/platform/v1/upgrade-check?target_version=<v>   → 200 UpgradeCheck {generated_at, target_version, items: [{name, status (PASS|WARN|FAIL|INFO), detail}], window: [versions], agents_outside: [{device_id, hostname, agent_version}]}; 400 unknown version
```

### 6.3 Release notes lines (`CHANGELOG.md`, every release section)

```
Schema: migrations 00100–00104 (control-plane database); audit unchanged
Upgrade: from 0.1.0-alpha.8: automatic
Agents: supports 0.1.0-alpha.7, 0.1.0-alpha.8, 0.1.0-alpha.9
```

### 6.4 Residual risks (RR-105 to RR-107)

| ID | Risk | Mitigation | ISMS record |
| --- | --- | --- | --- |
| RR-105 | **The CI runner is one machine with both hosts.** Timing, DNS and network differences of a real two-host installation are not exercised. | The lab's upgrade before every release (maintainer checklist); the smoke probes through Caddy. | The operator's own staging upgrade. |
| RR-106 | **Devices offline during an upgrade** return with an agent that may be outside the window after two more releases. | 426 with the update pointer; `agent_outdated` in the portal; the check lists them before. | Offline-device policy. |
| RR-107 | **A rollback after a schema change loses every change since the pre-upgrade backup.** | The command says so and asks; the labelled set is kept; the audit domain keeps its evidence. | Change freeze during upgrades. |

## 7. Steps (tickets, in order)

1. **PDK-740 — Migrations-frozen lint, previous-release fixtures, release notes contract.** Decisions 1–3.
   Verify: `make lint` runs the lint (it must see 99 + 10 files at the alpha.8 tag); `go test ./pkg/compat/`;
   `make release-check` fails on a section without the lines.
2. **PDK-741 — `admin upgrade-check` and the platform endpoint.** Decision 4; `ReleaseSequence()`. Depends on
   PDK-729 (M15 tables) for the `backups` item (the item reports `n/a` when the tables are absent, so PDK-741 MAY
   run before PDK-729 lands). Verify: integration tests per item with seeded devices and versions.
3. **PDK-745 — Idempotent role provisioning in the migrate step.** Decisions 8–9. Independent of the others.
   Verify: a cluster without `paddock_notifier` gets it; a second run changes nothing; `TestProdcheck` sees the
   secrets on `paddock-migrate`.
4. **PDK-742 — `./paddock upgrade-check`.** Decision 5. Depends on PDK-741. Verify: `upgrade-check_test.sh` with
   two fixture bundle directories (env diff, adjacency, secrets).
5. **PDK-743 — `./paddock upgrade` and `./paddock rollback`.** Decisions 6–7. Depends on PDK-742, PDK-733 and
   PDK-734 (M15 backup now / restore). Verify: `upgrade_test.sh` with a fake `paddock` of the old directory;
   the CI job of step 6 is the real verification.
6. **PDK-744 — CI job `upgrade` with seed, probes, restore drill and rollback.** Decisions 10–12. Depends on
   PDK-743. Verify: the job is green on the PR (the previous release = alpha.8, the candidate = the PR's bundle).
7. **PDK-746 — Documents, platform card, residual risks.** Decision 13; §6.4. Depends on PDK-744.

PDK-740, PDK-741 and PDK-745 MAY run in parallel.

## 8. Tests and gates

- **Unit:** `migrationsfrozen` (a changed file, a missing file, no tag); `ReleaseSequence` order and window
  computation (`Window(target) [3]string`); `upgradecheck` item evaluation table (percent and absolute
  thresholds, the `n/a` cases); `provision roles` SQL generation (no password on a command line or in a log).
- **Shell:** `upgrade-check_test.sh`, `upgrade_test.sh`, `rollback_test.sh` with fixtures under
  `deploy/bundle/ci/testdata/` (two bundle directories with `VERSION`, `.env.example`, `versions.env`); the state
  marker resume.
- **Integration:** `admin upgrade-check` items against `pgtest`-seeded devices.
- **CI gate:** the `upgrade` job (decision 10) — this is the definition of done of the milestone; it must be green
  with alpha.8 as the previous release before PDK-746 closes.
- **Acceptance:** `TestUpgradeCheckEndpoint` (platform admin reads the report; organization roles 403; an unknown
  version 400).
- Never weakened: `smoke.sh`, `TestAgentGates`, `TestDeviceProtocol`.

## 9. Acceptance criteria

- **C1 (ADR 0047 decision 1; maintainer):** Given the alpha.8 release and a candidate bundle, when `release.yml`
  runs, then the `upgrade` job installs alpha.8, upgrades, probes, restores and rolls back, and `sign` waits for it.
- **C2 (decision 3; operator):** Given an installation of N and the bundle of N+1, when the operator runs
  `./paddock upgrade-check ../N`, then they see every missing `.env` key, every secret to be generated, the agents
  outside the window, the backup state and the unseal path, and nothing has changed.
- **C3 (decision 3; operator):** When they run `./paddock upgrade ../N`, then a backup labelled `pre-upgrade-N+1`
  exists before the first container changes, the stack comes up on N+1, and the old directory is named as the
  rollback.
- **C4 (decision 3; operator):** When they run `./paddock rollback ../N` after a schema change, then N runs on the
  pre-upgrade data and the command told them what was lost.
- **C5 (ADR 0013 amendment; operator, device user):** Given devices with agents of N−2, N−1 and N, then all three
  check in against N+1 and receive bundles; an agent of N−3 gets 426 and the portal shows `agent_outdated`; the
  check refused the upgrade while more than 1 % (or 5) ran N−3 unless overridden.
- **C6 (decision 1; maintainer):** Given a changed historical migration file, then `make lint` fails naming it.
- **C7 (decision 3; maintainer):** Given a release section without the three lines, then `make release-check` fails.

## 10. Stop conditions

- The previous release's artifacts are not downloadable in CI (deleted release, GHCR visibility): report; do not
  build the previous release from source instead.
- `smoke.sh` cannot be split into `lib-smoke.sh` without changing its behaviour: report with the blocking step;
  do not duplicate it.
- The alpha.8 database cannot be read by the alpha.9 `admin upgrade-check` because of a schema the check needs:
  report; add the `n/a` branch, never a migration in the check.
- Any change seems necessary in `agent/`, the revocation path, an existing migration, or an ADR other than 0047
  and the 0013 amendment; any new Go module, npm package or container image.

## 11. Risks and open points

- **R1 — The job's duration** (two installations, a restore, a rollback: ~25–35 min on the GitHub runner).
  Countermeasure: `timeout-minutes: 60`; it runs only for PRs to `main` and tags.
- **R2 — Previous devicesim build** needs the previous tag's Go toolchain; `GOTOOLCHAIN=auto` handles it.
- **R3 — alpha.8 → alpha.9 runs the new binary's check against the old database** (decision 5 item 8): read-only
  queries on tables that exist in both; the item is `n/a` for anything newer.
Decisions taken on 2026-11-04 (binding for this plan):

- **Open restore plan or running rollout at upgrade time**: `./paddock upgrade` prints a **WARN only**; the
  operator decides (architect lead).
- **Pre-upgrade sets**: labelled `pre-upgrade-*` sets are exempt from the schedule's expire; the **latest two**
  are kept, older ones expire with the next label (architect lead; PDK-732 implements the exemption in the
  backup role's expire step).
- **First guaranteed pair**: **0.1.0-alpha.8 → alpha.9** (maintainer). PDK-744's job runs with alpha.8 as the
  previous release and `sign` depends on it from the alpha.9 release on; `pkg/compat/testdata/` starts at alpha.8.
- **Maintenance bundle of alpha.9 checked against ADR 0047 decision 2** (2026-11-04): OpenBao 2.7.1 → 2.7.2
  (patch, Raft data compatible), Himmelblau 4.0.8 (device package rolled out by the compiler, no server data),
  Fleet v4.93.2 → v4.94.0 (minor; Fleet migrates its MySQL at start — the rollback restores the Fleet dump when
  `FLEET_IMAGE` differs, decision 7, and the release's `Upgrade:` line stays `automatic`), aws-cli 2.39.3 (the
  sidecar M15 removes), Node 26.13.0 and the Go/npm patches (build-time only), NVD data (development stacks
  only): none of them breaks the guarantee.

## 12. Freedoms

- The internal layout of `lib-smoke.sh`, the seed script's data beyond the listed objects, the JSON shape of the
  shell report beyond `{items, exit}`, the Makefile target names beyond those listed, the wording of the terminal
  prompts, the platform card's layout, and whether `ReleaseSequence()` is generated at build time from tags or
  maintained as a checked-in list regenerated by `make gen` (the test asserts it contains the current version).

## Amendment 2026-11-04 (alpha.9 decisions)

Architect-lead decisions of 2026-11-04 for this plan (binding; the sections above stay as written and are read with
these changes).

### §5 — one read-only grant migration (PDK-741), approved 2026-11-04

§5's "no new migration in M16" and §10's "never a migration in the check" get one exception: **one read-only grant
migration, approved 2026-11-04**. `goose_db_version` belongs to the migration owner, so the platform role cannot
read the applied version that decision 4's `migrations` item compares. `server/migrations/paddock/00102_upgrade_check_grant.sql`
contains exactly `GRANT SELECT ON goose_db_version TO paddock_platform` and nothing else; a SECURITY DEFINER function
was rejected (it needs owner, pinned `search_path`, `REVOKE ALL FROM PUBLIC` and a scoped EXECUTE, all of which a
plain grant does without). The check probes the privilege (`has_table_privilege`) before it reads, so a database of
the previous release, which lacks the grant, reports `migrations` PASS ("predates migration 00102") instead of
aborting the transaction. sqlc learns the table from `server/internal/adapters/postgres/schema/goose_db_version.sql`,
a declaration that is never applied (goose creates the table itself).

### Decision 4a — safety commands reach out-of-window agents (PDK-765)

Decision 4a's "no commands" is narrowed by ADR 0013 amendment 2026-11-04 (2): an agent outside the window still
receives its pending safety commands, reported as delivered: the revocation tokens (Lock, Destroy, dead man's switch;
DSSE payload type `application/vnd.paddock.revocation.v1+json`) and `delete_self_lock`, which disarms the dead man's
switch after the organization turned it off. The gateway selects them before the 20-command cap. The bundle pointer
and every other command of the `pkg/command` registry stay withheld. All supported releases understand these commands
(no per-type minimum agent version exists); the `volumes` extension stays bound to the device's
`revoke_capabilities`.

Delivery is not effect: a delivered Lock or Destroy takes effect only if the device's last applied bundle enabled
revocation (the agent keeps `/etc/paddock/revoke-enabled` from the bundle); otherwise the device answers
`revocation.refused{reason: disabled}`. An old agent stays lockable only if revocation was enabled before it left the
window. Likewise, the time-ticket keys arrive with the bundle, so after a `time-ticket` key rotation an out-of-window
agent with an armed dead man's switch rejects the tickets and counts down while it still checks in. Whether a
server-side option should let the revocation switch (and the time-ticket keys) reach out-of-window agents is open:
PDK-772. Server-side delivery only; the revocation path on the device is unchanged. PDK-741 implements it
(`TestCheckinOutsideWindow`).

### Decision 2 — how the previous-release fixtures are built (PDK-740)

The fixtures of `pkg/compat/testdata/<release>/` deviate from decision 2's wording, and every future fixture release
follows this approach:

- **Bundles** are built and signed with `pkg/bundle` (one per schema version the release's agent accepts) from a
  fixture key derived from a public seed, not taken from the release's compiler rendering for the acceptance
  organization. The agent module verifies them with its own accepted list (`apply.SchemaVersions`).
- **Check-in and events** are decoded with the `pkg/protocol` types (unknown fields ignored) plus the closed event-type
  set, not with the gateway's decoders.
- **Events** carry empty data (`data: {}`), one event per type of `protocol.EventTypes`.

### Migration numbers (decision 10 of 2026-11-04)

Migrations are numbered in landing order, not by plan. The alpha.9 numbers known on 2026-11-04 are 00100 (M15
backups), 00101 (syslog destinations), 00102 (this plan's grant), 00103 (device diagnostics) and 00104 (access review
grants); the example in §6.3 follows them. A plan's label for a migration is corrected at the next touch of that plan.

## Amendment 2026-11-06 — `./paddock upgrade` and `./paddock rollback` as implemented (PDK-743, review 1)

Binding refinements of decisions 6 and 7; where they differ, this amendment wins.

1. **Rollback restores a point in time, not the labelled set as such.** `./paddock upgrade` records, in
   `.upgrade-state`, the timestamp `up-started=<RFC 3339 UTC>` immediately before its first `./paddock up`. A
   rollback after a schema change restores PostgreSQL with `--at <up-started>` from the local repository; the
   OpenBao snapshot and the Fleet dump are the newest at or before that time, which the labelled
   `pre-upgrade-<version>` run guarantees to exist (M15 decision 23 step 1 checks it). Everything written between
   the labelled backup and the first container change is therefore kept; everything after `up-started` is lost
   (RR-107 unchanged).
2. **The old release's `restore.sh` is an interface between releases.** `rollback.sh` of release N+1 sources
   `<old dir>/scripts/restore.sh` of release N and calls its functions, so a rollback runs the restore logic of
   the release whose data it restores. The following names are frozen for every guaranteed pair (ADR 0047
   decision 2 gains this item): functions `restore_trap_set`, `restore_trap_reset`, `set_opts`, `read_set`,
   `key_fingerprint`, `prompt_key`, `normalize_at`, `preflight`, `confirm`, `flush_wal`, `stop_writers`, `run`,
   `cleanup`, `die`; variables `RESTORE_SOURCE`, `RESTORE_SOURCE_LABEL`, `RESTORE_AT`, `RESTORE_ONLY`,
   `RESTORE_SET`, `RESTORE_KEY_FILE`, `RESTORE_KEY_PATH`. A change to a frozen name is a breaking change of the
   upgrade guarantee and needs this plan's next amendment; `rollback_test.sh` holds the contract test (it sources
   the shipped `restore.sh` and asserts every name is defined). `make lint-migrations-frozen`'s companion check
   (`tools/migrationsfrozen --restore-interface`) compares the list against the previous tag's `restore.sh`.
3. **Checks before `down`.** `./paddock rollback` runs, in this order and before anything stops: the key check
   (`key_fingerprint` against the set's manifest), the old release's `preflight` (schema versions, stanzas, the
   oldest backup at or before `up-started`, the OpenBao snapshot and the Fleet dump), and the terminal
   confirmation `restore`; only then `./paddock down`. `restore_run` repeats its own preflight after `down` and
   receives `restore` on stdin from the rollback script (no second prompt). A failure before `down` leaves the
   running stack untouched.
4. **Additional rules.** `--skip-backup` is refused when `FLEET_IMAGE` differs between the two `versions.env`
   (a Fleet migration needs the dump). A lab host without backups (`PADDOCK_LAB_BACKUP=no`) must pass
   `--skip-backup` for an upgrade whose release notes say `Schema: migrations …` or that changes `FLEET_IMAGE`,
   and the command prints that a rollback will then be `down` + old `up` only, with the data loss that implies.
   On the audit host and the lab, `rollback` stops `paddock-audit-writer` before `down` when the `Schema:` line
   names audit migrations or is missing (an unknown schema state is treated as changed).
5. **One rollback per upgrade attempt.** `./paddock upgrade` writes `.upgrade-rollback` with
   `attempt=<16 hex>`, `from=<N>`, `to=<N+1>`; `.upgrade-state` carries `attempt=` and `up-started=`. `rollback`
   uses the record only when both versions match the two directories and either no `.upgrade-state` exists
   (completed upgrade — the main case) or its `attempt` equals the record's. After a successful rollback the
   record is renamed `.upgrade-rollback.rolled-back-<attempt>` and the state gains `rolled-back=<RFC 3339>`; a
   second rollback of the same attempt is refused with the file named. A new `./paddock upgrade` starts a new
   attempt.

Consequences: §6.1 gains no flag; `docs/operations/upgrade.md` (PDK-746) documents the point-in-time semantics,
the pre-`down` checks, the lab rule and the one-rollback rule; RR-107 keeps its text (the loss window ends at
`up-started`).

## Amendment 2026-11-06 — the pair 0.1.0-alpha.8 → 0.1.0-alpha.9 (PDK-840; decisions-alpha9 items 46 and 49)

0.1.0-alpha.8 has none of what decisions 6 and 7 rely on. It has no `backup now --label`, no M15 tables or key, no
local repository and no `restore.sh`. It is still the first guaranteed pair, so that pair gets a legacy path. The
path lives in `deploy/compose/scripts/legacy-alpha8.sh`, which both commands source.

1. **Detection.** The path applies when the old directory's `VERSION` is exactly `0.1.0-alpha.8`, the release
   sequence that `upgrade-check` already checks. It never probes the old bundle for features. Every other old
   release without `backup now` is still refused.
2. **Pre-upgrade backup (upgrade step `backup`, before `up`).** The upgrade runs alpha.8's runbook step 3 through
   `<old>/paddock compose`, which uses alpha.8's Compose files and images, while alpha.8 still runs:
   - `run --rm --no-deps -T pgbackrest backup --start-fast`, then the same for `pgbackrest-authentik`;
   - `paddock-worker backup openbao`;
   - `fleet-backup once`.

   It reads the backup labels, the snapshot key and the dump name from what those commands print. Then it checks
   them in the bucket:
   - the newest backup of each stanza (`pgbackrest info`) is the new one;
   - the snapshot exists;
   - the dump exists, waiting up to 5 minutes for `fleet-backup-upload`. The upgrade does not upload the dump
     itself, because that would race with the running service.

   The bucket is read through a one-off of alpha.8's AWS CLI service, with the pgBackRest credential (the one that
   alpha.8 grants `s3:GetObject` on `openbao/` and `fleet/`) mounted as read-only files.
   `.upgrade-rollback` gains `method=legacy-0.1.0-alpha.8`, `legacy-paddock`, `legacy-authentik`, `legacy-openbao`,
   `legacy-fleet` and `legacy-at` (the time the backup completed). These fields are bound to the attempt like the
   rest of the record (amendment 2026-11-06 item 5).

   **The fence (upgrade step `up`, before the record).** alpha.8's restore stages every WAL segment the bucket holds,
   and alpha.8's pgBackRest would otherwise keep pushing from the shared spool while alpha.9's `up` migrates. So right
   before the rollback point is recorded, the upgrade runs `<old>/paddock compose stop pgbackrest
   pgbackrest-authentik`, then `run --rm --no-deps -T pgbackrest flush` and the same for `pgbackrest-authentik`. The
   bucket's archive then ends before alpha.9 touches a database; WAL written after that reaches alpha.9's local
   repository only. A failed stop or flush starts alpha.8's pgBackRest again, writes no record and does not run `up`;
   the next run repeats the fence. After the fence, when nothing new can reach the bucket, the upgrade checks that the
   newest backup of both stanzas is still the one recorded by the step `backup`: alpha.8's pgBackRest takes a full
   backup on its own once the last is 24 h old, for example while a stopped run waits, and alpha.8's restore always
   restores the newest. On a mismatch (or an unreadable `info`) it starts alpha.8's pgBackRest again, removes the step
   `backup` and its `legacy-*` lines from `.upgrade-state`, writes no record and does not run `up`; the next run takes
   the backup again. Every failure before `up` (fence, this check, the record write) says that `up` did not run and
   alpha.8 runs unchanged, and leaves alpha.8's pgBackRest running. The record's `at` is the time right after the fence.
3. **Rollback.** Instead of the old `restore.sh`, `rollback.sh` runs alpha.8's `docs/operations/restore.md` steps
   2–6 through `<old>/paddock compose`.
   - **Before anything stops**, in this order:
     - the record names a valid legacy backup;
     - the old directory names the same Compose project as this one (`PADDOCK_PROJECT` of the environment, else of
       each `.env`, default `paddock`), because the volumes of this project are deleted and alpha.8 starts in its own;
     - alpha.8's key and pgBackRest credential files exist;
     - the newest backup of each stanza is the recorded one (alpha.8's `restore` always takes the newest);
     - the recorded snapshot and, when `FLEET_IMAGE` changed, the dump are downloaded into a private work directory
       and decrypt with the key.
   - **Then:**
     - `./paddock down`;
     - both PostgreSQL clusters are restored by alpha.8's `pgbackrest restore` to the newest WAL alpha.8 archived.
       The fence of item 2 ends that archive before `up`, and 0.1.0-alpha.9 archives into its local repository;
     - the recovery is awaited;
     - the snapshot is restored into a fresh OpenBao with one temporary share (`openbao-restore.sh`), and the restored
       OpenBao is unsealed by the custodians or the automatic unseal;
     - when Fleet changed, Fleet's database is dropped and loaded from the dump;
     - step 5's restore commands run in their binding order;
     - pgBackRest starts, then `<old>/paddock up`.
   - **pgBackRest starts last, not in step 3.** With its fresh state it takes a full backup at once, which would make
     a repeated rollback refuse after a later failure.
   - **The loss window.** It starts at `legacy-at` at the latest, not at `up-started`: the restore reaches the WAL
     that alpha.8 archived until the fence. The plan says so.
   - **Escrow.** The escrow bucket is not part of alpha.8's restore and is not restored.
4. **Volumes and OpenBao (item 49).** The legacy rollback deletes and recreates exactly these volumes:
   `postgres-data`, `authentik-postgres-data`, both `pgbackrest-spool-*`, both `pgbackrest-state-*` and
   `openbao-data`.
   - The spools and the states go, so that WAL left behind by alpha.9 never reaches alpha.8's stanza.
   - Fleet's volume is kept: its database is dropped instead.
   - Only the OpenBao whose volume was just emptied is initialized, and only after it reports
     `"initialized": false`.
5. **Removal.** `legacy-alpha8.sh` and its call sites in `upgrade.sh`, `rollback.sh` and `paddock` are removed once
   0.1.0-alpha.8 leaves the support window (ADR 0013 amendment: its own release plus two).
6. **Proof.** PDK-744's CI job proves the pair end to end, including the rollback. The legacy rollback is never run
   against a development stack that holds lab-linked secrets.
