# Implementation plan: M19 — alpha.10 follow-ups, residual risks and small items

Status: accepted (architect arch-a11, 2026-11-14), release 0.1.0-alpha.11. Binding language: **MUST** / **MUST NOT**
/ **SHOULD** / **MAY**. New tickets: PDK-1031 to PDK-1035; decided existing tickets: PDK-1011, PDK-962, PDK-971,
PDK-1003, PDK-811d; listed existing tickets: PDK-814, PDK-818, PDK-828, PDK-829, PDK-966, PDK-1007, PDK-1012.

## 1. Goal

The worker can be scaled for the ingest requirement without exhausting PostgreSQL, a restore or rollback finds the
database schema in force at its point, a paused recovery fails within minutes instead of half an hour, the device test
run is observable and splittable, and four accepted residual risks (RR-131, RR-134, RR-135, RR-136) are closed.

## 2. Context

Each item quotes its own context. Common facts:

- **Connection budget** (`docs/operations/capacity.md` "PostgreSQL connection budget", decisions-alpha10 §63):
  PostgreSQL default `max_connections` 100, 97 usable; long-running roles at most 81 (api 12, worker 30 = organization 8
  + platform 8 + leader locks 12 + readiness 2, notifier 10, compiler 8, backup 7, escrow-reader 4, revocation-issuer
  4, outbox-relay 4, unsealer 2). Raising `max_connections` was reverted in alpha.10 (4e52cd04): a backup or WAL
  written with a higher value cannot be restored or replayed on a server that starts with a lower one ("hot standby is
  not possible because of insufficient parameter settings"; recovery pauses; database stays read-only).
- **Architecture N2** (§2.3): "sustains 5 000 events/s with 3 worker replicas"; measured 2026-10-09 with
  `--scale paddock-worker=3` before the pools grew.
- **Restore** (`deploy/compose/scripts/restore.sh`): waits for `pg_is_in_recovery() = f` up to
  `RESTORE_RECOVERY_TIMEOUT` (1800 s, line ~445). **Rollback** (`deploy/compose/scripts/rollback.sh`): since
  alpha.10 overrides the old bundle's `schema.*` with the schema recorded by `./paddock upgrade` in
  `.upgrade-rollback` (decisions-alpha10 §62).
- **Manifest** (`server/internal/domain/backupset/manifest.go`): schema `paddock.backup-set.v1`, field
  `schema_versions map[string]int` (newest only); `Parse` uses `json.Unmarshal` without `DisallowUnknownFields`, so
  an additive field is ignored by alpha.10 readers. `paddock-server backup manifest --at` prints
  `schema.<name>=<n>` lines (`server/cmd/paddock-server/restore.go::printSetInfo`). Migrations are applied by goose
  (`goose_db_version`, columns `version_id`, `is_applied`, `tstamp`).
- **Backup leadership** (`server/internal/platform/db/db.go::PlatformPool.Lead`, decisions-alpha10 §50 M1): one
  dedicated connection holds `pg_try_advisory_lock`; a ping every check interval detects a lost connection; RR-134
  names the ~10 s window in which a process that lost the lock can still write.

## 3. Binding decisions

### D1 Worker replicas and the connection budget (architecture N2; PDK-1031, PDK-1032)

Options: (a) raise `max_connections` — breaks restore and rollback onto a lower setting (proven in alpha.10);
(b) a connection pooler (PgBouncer) — a new container image, and transaction pooling breaks the session advisory locks
the worker and the backup role rely on; (c) shrink pools further — the readiness and leader-lock starvation of
PDK-1010 returns; (d) **an ingest-only worker mode for additional replicas, plus a configurable `max_connections`
that every restore path honours from the backup itself, raised by default only one release later.** Chosen: (d).

1. `paddock-server serve worker` reads `PADDOCK_WORKER_MODE` = `full` (default) | `ingest`. In `ingest` mode the
   process runs only the queue consumers (enroll, heartbeat, event, command issued, command result, escrow) and opens
   only: organization pool 8, platform pool 2, readiness 1 (no lock pool, no leader-lock rounds). Its readiness
   reports `mode=ingest`. Compose gains the service `paddock-worker-ingest` (same image, `deploy.replicas: 0` by
   default, `PADDOCK_WORKER_MODE=ingest`); scaling for N2 is `--scale paddock-worker-ingest=2`.
2. The postgres service starts with `-c max_connections=${PADDOCK_PG_MAX_CONNECTIONS:-100}`. alpha.11 keeps the
   default 100.
3. `restore.sh` reads `max_connections setting` from `pg_controldata` of the restored data directory before the
   first start of the restored cluster and starts it with `max(PADDOCK_PG_MAX_CONNECTIONS, that value)`, logging
   both; the same for the audit database. A rollback from alpha.11 to alpha.10 with `PADDOCK_PG_MAX_CONNECTIONS` >
   100 is refused by alpha.11's `rollback.sh` with the message: lower it to 100, run `./paddock backup now`, then roll
   back to a point after that backup.
4. `./paddock check` computes the budget: sum of the long-running roles' maximum connections × their configured
   replicas (`docker compose config`), and FAILs when it exceeds `PADDOCK_PG_MAX_CONNECTIONS − 3 − 12` (12 = pgBackRest
   and `paddock-migrate` headroom), WARNs within 5 of it. The per-role maxima live in one table in
   `deploy/bundle/paddock` and a test compares it with the `MaxConns` values in `server/cmd/paddock-server/*.go`.
5. **N2 amended:** "5 000 events/s with one worker and two ingest workers (`paddock-worker-ingest=2`) at
   `PADDOCK_PG_MAX_CONNECTIONS=150`." alpha.12 MAY raise the default to 150 (its rollback target alpha.11 restores
   it per decision 3); that is a later decision. The N2 load test is re-run in PDK-1031 and recorded in
   `capacity.md`.

### D2 Schema history in the backup manifest (PDK-1011)

1. Additive manifest field (schema stays `paddock.backup-set.v1`):
   `schema_history: [{"since": RFC3339, "versions": {"paddock": int, "audit": int}}]`, sorted ascending by `since`,
   at most 64 entries. `schema_versions` stays and equals the last entry's `versions`.
2. The backup role appends an entry when the current `schema_versions` differ from the last entry. `since` = the
   `tstamp` of the newest applied `goose_db_version` row of each database whose version changed (the earliest of
   them when both changed). If `tstamp` cannot be read, `since` = the previous manifest's `generated_at`
   (earlier, therefore conservative: an old restorer refuses rather than accepts). A manifest without
   `schema_history` (written by alpha.10) is migrated by writing one entry with `since` = the oldest restorable point
   of the set (`oldest.<stanza>` minimum) and the current versions.
3. `backup manifest --at <t>` prints `schema.<name>` from the last entry with `since <= t`; when `t` is earlier than
   every entry it prints the first entry's versions and the additional line `schema.exact=false`; otherwise
   `schema.exact=true`. Without `--at` it prints the newest, as today.
4. alpha.11's restore preflight refuses `schema.exact=false` with an actionable message. alpha.10 readers ignore the
   field and keep their behaviour; alpha.11's `rollback.sh` keeps the record-and-override (decisions-alpha10 §62) for
   rollbacks to alpha.10. The override is removed in alpha.12, whose rollback target alpha.11 reads the history.
5. ADR 0046 gets an amendment with D2 (done in this plan's PR).

### D3 Fail fast on paused recovery (PDK-1033)

The recovery wait in `restore.sh` additionally queries `SELECT pg_get_wal_replay_pause_state()` each poll. When it
returns `paused` on two consecutive polls (≥ 10 s apart), the restore stops at once with exit 1 and prints: the pause
state, the last 20 lines of the database log containing `insufficient parameter settings` or `recovery has paused`,
and, when found, the parameter name with the hint to set `PADDOCK_PG_MAX_CONNECTIONS` (D1) and rerun the restore.
The 1800 s timeout stays for every other case.

### D4 Device test run: streaming and splitting (PDK-962)

1. Streaming: `make system-test` runs `go test -json` and pipes it through `test/cmd/testlive` (new, standard library):
   prints each `output` action line immediately, prefixed with the test name for parallel subtests, prints the
   standard `--- PASS/FAIL` lines, and keeps the zero-test guard of `test/require-tests.sh` (exit 1 when no test ran);
   the raw JSON is written to `bin/system-test/<suite>-<UTC timestamp>.json`.
2. Splitting: `test/system/suites.txt` maps suite names to `-run` regexes and timeouts: `identity`, `localadmin`,
   `software` (incl. self-service), `disk` (disk, encrypt, unlock mode), `revoke` (revoke, DMS), `lifecycle`
   (uninstall, supervisor update, update now, update policy, rollout, updates), `misc` (everything else). A
   completeness test fails when a top-level `Test*` of `test/system` matches no suite or more than one.
   `make system-test VM=all SUITE=<name>` runs one suite; `SUITE=all` runs them one after another, each with its own
   `-timeout`, continuing after a failed suite, and prints a summary table at the end. `T=` stays and excludes
   `SUITE`.
3. Every deliberate wait longer than 60 s logs its reason and duration before it starts (helper
   `vm.WaitLogged(t, reason, d)`).

### D5 RR-134 lease fence (PDK-1034)

1. Platform table `backup_leader(id boolean PRIMARY KEY DEFAULT true CHECK (id), epoch bigint NOT NULL,
   holder text NOT NULL, acquired_at timestamptz NOT NULL)`.
2. Right after `Lead` acquires the advisory lock, the backup role runs `UPDATE backup_leader SET epoch = epoch + 1,
   holder = $1, acquired_at = now() RETURNING epoch` and keeps the epoch in the lead context.
3. Every database write of the backup role (run state, target state, key confirmation effects, restore plans, the
   `mirrored` marker, audit actions it records) runs in a transaction that first executes
   `SELECT epoch FROM backup_leader FOR SHARE` and aborts with `ErrFenced` when the value differs from its own.
   `ErrFenced` is handled like `ErrLeadershipLost`: cancel all lanes and rounds, record nothing further.
4. Object-store writes are not fenced (unchanged RR-134 reasoning: they are idempotent). RR-134 is reworded to that
   remaining window and marked mitigated.

### D6 Release package control fields (PDK-1003; ADR 0043 amendment 2026-11-11 b "follow-up")

One shared check `server/internal/debcontrol.Read(r io.ReaderAt, size int64) (Fields, error)` (standard library `ar` parsing by
hand, `archive/tar`, `compress/gzip`, and `github.com/klauspost/compress/zstd`, already a dependency) reading
`Package`, `Version`, `Architecture` from `control.tar.gz`, `control.tar.zst` or `control.tar`; any other member
compression (`.xz`) is refused with `unsupported_control_compression`. Used by the upload, the host publish and the
GitHub import; refusal reasons `package_name_mismatch`, `package_version_mismatch`, `package_arch_mismatch`;
`Version` compared after mapping the release's `-` pre-release separator to `~`; fleet-osquery's `Version` compared
with the stored `package_version`. RR-136 closes.

### D7 Unread request bodies (PDK-971)

Per-route handling through a role-side marker, not a global close:

1. A shared middleware in `server/internal/platform/httpx` wraps the request body of every POST, PUT, PATCH and
   DELETE of every role; when the handler writes a 2xx or 3xx status and the body was not read to EOF (Content-Length
   > bytes read, or a chunked body without EOF), it sets the response header `X-Paddock-Body-Unread: 1` before the
   status is written.
2. `deploy/compose/caddy/guards.caddy` `(close_unread_body)`: the `@role_answer` branch also matches the response
   header `X-Paddock-Body-Unread` on HTTP/1.x, sets `Connection: close` and removes the header from the answer.
3. `docs/operations/capacity.md` "Request limits" reverts to the plain 60 s bound; RR-131 closes.
4. An acceptance gate sends `POST /api/auth/logout` with `X-Paddock-CSRF: 1`, no cookie and a body at 1 byte/s and
   asserts the connection ends within 70 s.

### D8 Software request withdrawal ordering (PDK-811d)

1. `software_request` gains `reported_seq bigint` (the device event's sequence number of the `software.request`
   that opened it; NULL for rows opened before the migration).
2. New table `software_request_withdrawal(organization_id uuid NOT NULL, device_id uuid NOT NULL, catalog_entry_id
   uuid NOT NULL, username text NOT NULL, event_seq bigint NOT NULL, received_at timestamptz NOT NULL DEFAULT now(),
   PRIMARY KEY (organization_id, device_id, catalog_entry_id, username))` with the tenant RLS policy; one row per key
   holding the highest withdrawal `event_seq`; registered in `offboarding_table` (M17).
3. `software.request` with seq `r`: opens a request only if no withdrawal row with `event_seq > r` exists for the
   key. `software.request_withdrawn` with seq `w`: upserts the withdrawal row with `greatest(event_seq, w)` and closes
   the open request of the key only if its `reported_seq < w` or `reported_seq IS NULL`.
4. Audit: the registry Description of `device.software_request_withdrawn` becomes "The device reported that a user
   withdrew a software request"; new param `closed` (boolean). Withdrawal rows follow the request retention of ADR
   0032 (same period after `received_at`). RR-135 closes.

### D9 PDK-990 residual (no work left)

Checked on `main` at `f6d59cb9`: plan M5a amendment 2026-11-11 b, P3, already records the second accepted duplicate
(an updates run without the cross-process lock may report a record twice, never lose it), and RR-133 already names
the wall-clock false positive of P2. Nothing remains for alpha.11; no ticket.

### D10 Rollout loop cancel guard (PDK-1035)

`worker.Rollouts.Run`: when `Round` returns an error and `ctx.Err() != nil`, return `nil` without logging the
warning. The same guard for every worker loop of the same shape that logs a round error before checking `ctx.Done()`
(listed by the implementer in the result document).

### Existing tickets (scope unchanged; scheduled in alpha.11)

PDK-814 patch SLA report, PDK-818 review, PDK-828 diagnostics search, PDK-829 session gate flakes, PDK-966 jsdom 31,
PDK-1007 leftover `.bundle-seq.replaced.*` removal as root, PDK-1012 DMS gate rendezvous deadlock.

## 4. Non-goals

- No PgBouncer or other new container image; no change of the default `max_connections` in alpha.11.
- No new manifest schema version; no re-verification of stored release packages (PDK-1003 scope).
- No change of what the system gates test (D4).
- No fencing of object-store writes (D5.4).
- No change under `agent/internal/revoke/` or `agent/cmd/paddock-revoke/`.

## 5. Affected files

| Path | Action | Purpose |
| --- | --- | --- |
| `server/cmd/paddock-server/worker.go` | change | D1.1 mode |
| `deploy/compose/compose.yaml`, `compose.prod.yaml`, `prod.env.example` | change | D1.1, D1.2 |
| `deploy/compose/scripts/restore.sh`, `rollback.sh` | change | D1.3, D3 |
| `deploy/bundle/paddock`, `deploy/bundle/bundle_test.sh`, `rollback_test.sh` | change | D1.3, D1.4 |
| `docs/operations/capacity.md`, `restore.md`, `upgrade.md` | change | D1, D3 |
| `docs/architecture.md` §2.3 | change (amendment, done in this PR) | N2 |
| `server/internal/domain/backupset/manifest.go`, `server/internal/backuprole/*.go`, `server/cmd/paddock-server/restore.go` | change | D2 |
| `test/cmd/testlive/`, `test/system/suites.txt`, `test/system/suites_test.go`, `Makefile` | new/change | D4 |
| `server/migrations/paddock/<next>_backup_leader.sql`, `server/internal/backuprole/*.go` | new/change | D5 |
| `server/internal/debcontrol/`, `server/internal/app/agentreleases.go`, `releaseimport.go`, host publish | new/change | D6 |
| `server/internal/platform/httpx/`, `deploy/compose/caddy/guards.caddy`, `test/acceptance/edge_limits_test.go` | change | D7 |
| `server/migrations/paddock/<next>_software_request_order.sql`, `server/internal/app/softwarerequests.go`, `domain/audit/codes.go` | change | D8 |
| `server/internal/worker/rollouts.go` (+ same-shape loops) | change | D10 |
| `docs/compliance/residual-risks.md` | change | RR-131, 133, 134, 135, 136 |

## 6. Interfaces and data model

```json
// manifest.json (additive)
"schema_history": [
  {"since": "2026-11-13T09:12:44Z", "versions": {"audit": 10, "paddock": 125}}
]
```

```text
# backup manifest --at <t> (additional line)
schema.exact=true|false
```

```go
// server/internal/debcontrol (server module only: klauspost/compress is a dependency of server, not of pkg)
type Fields struct{ Package, Version, Architecture string }
var ErrUnsupportedCompression = errors.New("debcontrol: unsupported control compression")
func Read(r io.ReaderAt, size int64) (Fields, error)

// server/internal/backuprole
var ErrFenced = errors.New("backuprole: leadership epoch changed")
```

```sql
CREATE TABLE backup_leader (id boolean PRIMARY KEY DEFAULT true CHECK (id), epoch bigint NOT NULL,
  holder text NOT NULL, acquired_at timestamptz NOT NULL);
INSERT INTO backup_leader VALUES (true, 0, '', now());
ALTER TABLE software_request ADD COLUMN reported_seq bigint;
CREATE TABLE software_request_withdrawal (...);  -- D8.2
```

## 7. Implementation steps

1. **PDK-1035** (D10). Check: unit test: cancelled context → no warning logged.
2. **PDK-1033** (D3). Check: `bash deploy/bundle/rollback_test.sh` and a restore test case with a stubbed `psql`
   answering `paused` → exit within two polls.
3. **PDK-1011** (D2). Check: unit tests of §8; `backup manifest --at` on a set with two history entries.
4. **PDK-1032** (D1.2–D1.4). Check: `bundle_test.sh` budget cases; restore drill with `PADDOCK_PG_MAX_CONNECTIONS=150`
   restored onto a configuration of 100 → starts with 150, no pause.
5. **PDK-1031** (D1.1, D1.5). Check: `make load-test SCENARIO=ingest` with `paddock-worker-ingest=2` at 150; figures
   in `capacity.md`.
6. **PDK-1034** (D5). Check: §8.
7. **PDK-1003** (D6), **PDK-971** (D7), **PDK-811d** (D8), **PDK-962** (D4) in any order.

## 8. Tests

- D1: worker in `ingest` mode starts no round and opens no lock pool (pool stats in a test); `./paddock check`
  FAIL/WARN/OK cases; the maxima table matches the code (test); restore with a control-file value above the
  configured value.
- D2: append on change only; `since` from `tstamp`; fallback to previous `generated_at`; migration of a history-less
  manifest; `--at` before, between and after entries; `exact=false` refused by the preflight; an alpha.10-format
  reader (`json.Unmarshal` into the alpha.10 struct copied into the test) still parses the new manifest.
- D3: stubbed pause → fast failure with the parameter hint; not paused → unchanged behaviour.
- D4: suites completeness test; `testlive` passes through output, fails on zero tests, keeps go test's exit code.
- D5: two processes: the second takes the lock after the first's connection is killed; the first's next write fails
  with `ErrFenced` and records nothing; the epoch increments per acquisition.
- D6: per path (upload, host publish, import) a package with a wrong `Package`, `Version`, `Architecture`, and an
  `.xz` control member → refused with the reason; fleet-osquery version mismatch refused; valid packages accepted.
- D7: middleware sets the header only for unread bodies on 2xx/3xx; Caddy acceptance gate of D7.4.
- D8: withdrawal processed before request → request never opens; A, B, W processed A, B, W and A, W, B → final
  state matches the device's order; `closed` param true/false.

## 9. Acceptance criteria

- D1 — Given `paddock-worker-ingest=2` and `PADDOCK_PG_MAX_CONNECTIONS=150`; when the ingest load test runs; then the
  operator sees 5 000 events/s with lag < 60 s in `capacity.md`, and `./paddock check` reports the budget OK; with
  `paddock-worker=3` at 100 it reports FAIL.
- D2 — Given an upgrade from alpha.11 to a release with a newer schema; when the operator runs `./paddock restore
  --at` a point before the upgrade with the alpha.11 bundle; then the preflight sees the alpha.11 schema and passes
  without a rollback record.
- D3 — Given a restore onto a lower `max_connections`; then the operator sees a failure naming the parameter within
  one minute.
- D4 — Given `make system-test VM=all SUITE=identity`; then the developer sees each test's output while it runs and
  only the identity suite executes.
- D5 — Given a backup role whose lock session was killed; then the platform administrator sees no write of the old
  process after the new one leads (no duplicate failure entry).
- D6 — Given a release upload with the supervisor package stored as `paddock-agent`; then the platform administrator
  sees it refused with `package_name_mismatch`.
- D7 — Given a slow body on `POST /api/auth/logout`; then the connection ends within 70 s.
- D8 — Given a withdrawal processed before its request; then the organization administrator sees no open request.

## 10. Degrees of freedom

- Internal structure of `testlive`, `debcontrol`, the middleware; suite assignment of tests within D4.2's names.
- Whether `./paddock check` reads replica counts from `docker compose config --format json` or `ps`.

## 11. Stop conditions

- The postgres service cannot take `-c` arguments (configuration only by a mounted file): stop and report.
- `pg_controldata` is not available in the image used by `restore.sh` at that point.
- A worker queue consumer needs a leader lock (D1.1 then not possible).
- A release package in the existing release store uses an `.xz` control member (D6 would refuse a real release).
- Device events of `software.request` carry no sequence number reachable by the worker (D8).
- Any change that would touch the revocation path.

## 12. Risks and open points

- D1 leaves the default at 100 in alpha.11, so N2 needs an explicit operator setting until alpha.12.
- D2 relies on `goose_db_version.tstamp` being the apply time (goose sets it on insert); the fallback is conservative.
- D5 adds one row lock per backup write transaction; the backup role writes rarely.
- PDK-1010 is fixed on `main` (lock pool and readiness connections, alpha.10) but its ticket file is still in
  `todo/`; its ticket is closed without further work.
