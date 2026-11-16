# Capacity

Measured load figures of the device control plane against the non-functional requirements N1 and N2 (architecture
§2.3, plan M6b decision 1). Size a production control plane from these figures and re-measure on your own hardware
with the same scenarios before a large rollout.

> **Never run the load test against a production installation.** It runs only on a dedicated test stack. It enrolls
> thousands of devices into a real organization, and an `ingest` run writes millions of audit events into WORM
> objects that nobody can delete before their retention ends. `make load-identities` and `make load-test` refuse when
> the running gateway has `PADDOCK_ENV=production` or the checkout carries production markers (the checks of the
> restore drill: `PADDOCK_ENV=development` in `deploy/compose/.env`, no production secrets, no production overlay),
> and `test/load/cmd/identities` requires an explicit `--server`.

| Requirement | Target |
| --- | --- |
| N1 check-in | 1 000 check-ins/s against **one** gateway replica, p99 latency < 200 ms, error rate < 0.1 % |
| N2 ingest | 5 000 device events/s with one worker and two ingest workers (`PADDOCK_WORKER_INGEST_REPLICAS=2`) at `PADDOCK_PG_MAX_CONNECTIONS=150`, consumer lag of `ingest.event` < 60 s (architecture §2.3, amendment 2026-11-14) |

## Results

Measured on 2026-10-09 on the reference machine below, with the whole development stack (`make up BACKUP=1`, with
the observability profile), the k6 load generator and 10 000 load devices on the same host. A production control
plane spreads these roles over more hardware; treat the figures as a lower bound of one gateway and three workers.

**Reference machine:** a laptop with an Intel Core Ultra 7 155H (16 cores, 22 threads, up to 4.8 GHz), 62 GiB RAM and
an NVMe SSD (SanDisk PC SN8000S, 1 TB), Ubuntu with Docker. **Paddock commit:** `5687d78` (branch
`M6-integration`, with the fixes below).

| Scenario | Reference machine | Rate | p99 | Error rate | Lag (max) | Result |
| --- | --- | --- | --- | --- | --- | --- |
| `checkin` | Core Ultra 7 155H, 62 GiB | 1 000 check-ins/s held for 5 min (300 001 requests), 1 gateway | 10.3 ms (median 2.2 ms, max 112 ms) | 0.00 % | – | met |
| `ingest` | Core Ultra 7 155H, 62 GiB | 5 000 events/s for 60 s (6 000 batches of 50), 3 workers | 9.0 ms (request) | 0.00 % | 0.03 s (backlog ≤ 2 messages) | met |

`checkin`: `RATE=1000 VUS=400 WARMUP=1m DURATION=5m`. `ingest`: `EVENTS_PER_S=5000 BATCH=50 VUS=200 DURATION=60s
DRAIN=2m` with `--scale paddock-worker=3`; the run is limited to 60 s by architect decision (each run writes its
events into the WORM audit bucket for good). The audit pipeline behind it (`audit.writer`) peaked at about 61 000
queued messages and drained within a minute after the run.

The first runs missed both targets and found two hot spots, fixed before the figures above:

- **Gateway:** every check-in waits for its publisher confirm, and the gateway published over one broker channel
  that handled one batch at a time: about 800 check-ins/s at a p99 of 786 ms. It now publishes over a pool of 16
  connections.
- **Worker:** `ingest.event` was consumed one message at a time with one transaction per event: about 1 000
  events/s with three workers, a backlog of 2 500 messages and a lag of about 75 s. A worker now handles 8 messages at a
  time and records the events of one message in one transaction.

## Attention list and overview

The kind `config_behind` (plan M8f, ADR 0040) lists an active device whose newest bundle was compiled more than an
hour ago, which checked in after that hour and still applies an older bundle. It adds one lookup of the newest bundle
per active device through the primary key `bundle(device_id, version)`; the measurements below predate it.

Measured on 2026-10-12 on the same reference machine and development stack, with one organization of **10 103 active
devices** enrolled with `make load-identities` (10 000 load devices and 103 that never checked in). The load
devices checked in once each, with agent versions mixed against the current release `0.3.1791801809-probation`:
4 000 on it, 3 000 older (`0.2.0`, `0.1.9`, `0.0.0-load`), 2 000 newer (`9.0.0`, `10.1.0`) and 1 000 with no
semantic version (`dev-build`). The development stack counts staleness in minutes, so the 10 000 devices were also
`stale_warning` during the measurement. The attention list had 14 000 conditions: 10 000 `stale_warning` and 4 000
`agent_outdated`. Target: attention list p95 ≤ 200 ms at 10 000 devices.

**Before (Paddock `2db58c9`), HTTP:** 50 sequential requests per row with a portal session through the edge (Caddy).
A request runs the list query and its count.

| Request | p50 | p95 | p99 |
| --- | --- | --- | --- |
| `GET /api/v1/attention` (defaults) | 635 ms | 765 ms | 797 ms |
| `GET /api/v1/attention?page_size=25` | 662 ms | 771 ms | 776 ms |
| `GET /api/v1/attention?page_size=100` | 658 ms | 764 ms | 819 ms |
| `GET /api/v1/attention?page_size=25&kind=agent_outdated` | 1 247 ms | 1 492 ms | 1 507 ms |
| `GET /api/v1/attention?page_size=100&kind=agent_outdated` | 1 265 ms | 1 442 ms | 1 469 ms |
| `GET /api/v1/attention/devices?page_size=25` | 1 406 ms | 1 654 ms | 1 692 ms |
| `GET /api/v1/attention/devices?page_size=100` | 1 383 ms | 1 558 ms | 1 618 ms |
| `GET /api/v1/attention/devices?page_size=25&kind=agent_outdated` | 2 647 ms | 2 989 ms | 3 047 ms |
| `GET /api/v1/overview` | 3 129 ms | 3 419 ms | 3 456 ms |

**Cause.** The `agent_outdated` branch of the view `attention_condition` and the overview's agent counters joined a
derived table with the current release's version key. The planner flattened it, so the SECURITY DEFINER lookup
`paddock_current_agent_version()` ran once per active device. That cost 358 ms per 10 000 calls, against 1 ms for a
single call. `EXPLAIN (ANALYZE, BUFFERS)` of the default list: 507 ms and 171 818 shared buffer hits, 490 ms of them
in that branch. Migration `00042` evaluates the key once per query (an InitPlan).

**Before and after, database:** `EXPLAIN ANALYZE` medians of 5 runs as the API role in the organization's scope,
read-only. These are query execution times, not HTTP latencies. The after figures come from the view of migration
`00042` on the same data. The HTTP figures after the change (p50, p95 and p99 as in the table above) are still to be
measured once the change is merged and deployed to the development stack (PDK-091).

| Query (endpoint) | Before | After |
| --- | --- | --- |
| `ListAttention` defaults, 25 (`/attention`) | 614 ms | 119 ms |
| `CountAttention` defaults | 14 ms | 15 ms |
| `ListAttention`, 100 | 604 ms | 83 ms |
| `ListAttention` `kind=agent_outdated`, 25 | 609 ms | 65 ms |
| `CountAttention` `kind=agent_outdated` | 592 ms | 61 ms |
| `ListAttentionDevices`, 25 (`/attention/devices`) | 617 ms | 119 ms |
| `CountAttentionDevices` | 686 ms | 75 ms |
| `ListAttentionDevices` `kind=agent_outdated`, 25 | 1 813 ms | 225 ms |
| `CountAttentionDevices` `kind=agent_outdated` | 666 ms | 63 ms |
| `OverviewAttention` (`/overview`) | 615 ms | 74 ms |
| `OverviewUpdates` (`/overview`) | 2 226 ms | 151 ms |
| `OverviewDevices` (`/overview`, unchanged) | 385 ms | 385 ms |

After the change, the default list takes 118 ms with 2 542 shared buffer hits. The query time of an
`/api/v1/attention` request is the sum of its list and count medians: 134 ms with the defaults (page size 25), 98 ms
with page size 100, and 126 ms with `kind=agent_outdated` and page size 25. These are `EXPLAIN ANALYZE` medians of
query execution time, not the HTTP p95 the target refers to. Whether the target is met is decided by the HTTP
measurement after the change (PDK-091).

**Remaining hot spots:** none known at the query level. The per-device version key was closed by PDK-090 and the
device contact state by PDK-089 (both below). Over HTTP, `/api/v1/attention/devices` stayed above the 200 ms target
once the fleet was stale (see "After PDK-027/089/090, HTTP" below); PDK-094 cut its query time to a third ("After
PDK-094" below). Its HTTP figures after that change are still to be measured.

**After PDK-089.** Measured on 2026-10-12 on the same machine and development stack with a new load organization of
**10 000 active devices**, enrolled with `make load-identities` and checked in once each with
`make load-test SCENARIO=checkin`. Because the stack counts staleness in minutes, every device had an open
`stale_warning` during the measurement. `paddock_device_contact()` (migration 00038) ran two `EXISTS` probes on
`device_alert` per device. A SQL function with a subquery is never inlined, so every row started a sub-executor.
Migration `00043` (ADR 0028) makes it an inlinable `CASE` over the device's columns and the kind of its open alert,
which the queries join (`device_alert_open_idx` allows at most one open alert per device).

`EXPLAIN (ANALYZE, BUFFERS)` medians of 5 runs as the API role in the organization's scope. Before and after ran in
one rolled-back transaction with a single snapshot; the "after" function and queries were created inside that
transaction. These are query execution times, not HTTP latencies:

| Query (endpoint) | Before | After |
| --- | --- | --- |
| `OverviewDevices` (`/overview`) | 405 ms | 13 ms |
| `ListDevices` `state=active&contact=stale_warning`, 25 (`/devices`) | 109 ms | 16 ms |
| `CountDevices` with the same filter | 92 ms | 10 ms |

`OverviewDevices` reads 1 225 shared buffers instead of 300 970. The plan has no function call (`EXPLAIN (VERBOSE)`
shows the inlined `CASE`). The buckets are identical before and after (10 000 active, 10 000 `silent`), and so are
the list (25 rows) and the count (10 000). On the same fleet before the devices went stale (no open alerts), the
medians were 414 ms to 11 ms, 89 ms to 8 ms and 96 ms to 5 ms. The HTTP figures of `GET /api/v1/overview` after this
change are measured with those of PDK-027 once both are merged and deployed (PDK-091).

**After PDK-090.** Measured on 2026-10-12 on the same machine and development stack. The fleet had the PDK-027 shape
against the current release `0.3.1791801809-probation`: **10 000 active devices**, 4 000 on it, 3 000 older (`0.2.0`,
`0.1.9`, `0.0.0-load`), 2 000 newer (`9.0.0`, `10.1.0`) and 1 000 with no semantic version (`dev-build`), each with an
open `stale_warning`, so the attention list had 14 000 conditions. Unlike the earlier runs, the fleet was not enrolled
through the API: it was inserted into a new organization inside the measuring transaction, which was rolled back, so
the shared database kept no devices and the unmerged migration never reached it. Before, `paddock_version_key()`
(PL/pgSQL, migration 00039) ran once per device row in the `agent_outdated` branch of `attention_condition` and three
times per row in `OverviewUpdates`. Migration `00044` (ADR 0028) stores the key per device as the generated column
`device_status.agent_version_key`, computed when a device checks in, and both queries compare that column. The only
remaining call computes the current release's key, once per query.

`EXPLAIN (ANALYZE, BUFFERS)` medians of 5 runs as the API role in the organization's scope. Before is the view of
migration `00042`. After is migration `00044`, applied in the same transaction on the same data. These are query
execution times, not HTTP latencies:

| Query (endpoint) | Before | After |
| --- | --- | --- |
| `ListAttentionDevices` `kind=agent_outdated`, 25 (`/attention/devices`) | 278 ms | 160 ms |
| `CountAttentionDevices` `kind=agent_outdated` | 66 ms | 15 ms |
| `OverviewUpdates` (`/overview`) | 151 ms | 7 ms |
| `OverviewAttention` (`/overview`) | 68 ms | 23 ms |

The query time of `/api/v1/attention/devices?page_size=25&kind=agent_outdated` (list plus count) drops from 344 ms to
174 ms. The results are identical before and after: the same 25 devices on the first page, 4 000 matching devices, the
buckets 4 000 on current, 4 000 outdated, 2 000 ahead and 0 unknown, and 14 000 conditions on 10 000 devices. After the
migration, `agent_version_key` equals `paddock_version_key(agent_version)` for every device in the database (dev seed
and fleet). Of the remaining list time, about 90 ms is spent in the view's alert branch (the 10 000 open `stale_warning`
alerts) under the kind filter; no function runs per device row any more. The HTTP figures after this change are measured
with those of PDK-027 and PDK-089 once all three are merged and deployed (PDK-091).

**After PDK-027/089/090, HTTP.** Measured on 2026-10-13 on the same machine with the development stack on Paddock
`c0aff7e` (migrations up to `00044`). A new load organization of **10 000 active devices**, enrolled with
`make load-identities`, checked in once each with the PDK-027 version mix against the current release
`0.3.1791801809-probation`: 4 000 on it, 3 000 older, 2 000 newer and 1 000 with no semantic version. 50 sequential
requests per row after 3 warm-up requests, with a portal session of an organization administrator through the edge
(Caddy). "Fresh" was measured right after the check-ins: no open alerts, 4 000 `agent_outdated` conditions. "Stale"
was measured 25 minutes later, when the development stack's minute-based staleness had opened a `stale_warning` for
every device: 14 000 conditions on 10 000 devices.

| Request | Fresh p50 | Fresh p95 | Fresh p99 | Stale p50 | Stale p95 | Stale p99 |
| --- | --- | --- | --- | --- | --- | --- |
| `GET /api/v1/attention` (defaults) | 104 ms | 131 ms | 136 ms | 89 ms | 98 ms | 105 ms |
| `GET /api/v1/attention?page_size=100` | 90 ms | 101 ms | 104 ms | 91 ms | 101 ms | 104 ms |
| `GET /api/v1/attention?kind=agent_outdated` | 67 ms | 74 ms | 75 ms | 88 ms | 108 ms | 138 ms |
| `GET /api/v1/attention/devices?page_size=25` | 114 ms | 151 ms | 170 ms | 158 ms | **202 ms** | 224 ms |
| `GET /api/v1/attention/devices?page_size=25&kind=agent_outdated` | 118 ms | 162 ms | 176 ms | 203 ms | **236 ms** |
312 ms |
| `GET /api/v1/overview` | 46 ms | 56 ms | 58 ms | 57 ms | 64 ms | 73 ms |

The attention list meets the target (p95 ≤ 200 ms at 10 000 devices) in every variant, and so does the overview,
which drops from 3.4 s to 64 ms p95. Two requests miss it once the fleet is stale: the device view of the attention
list, `/api/v1/attention/devices`, at 202 ms p95 without and 236 ms p95 with `kind=agent_outdated`. A repeated stale
run confirmed both (209 ms and 243 ms p95). Its query time is dominated by the view's alert branch over the 10 000
open alerts (PDK-090 above). The miss is tracked in PDK-094.

**After PDK-094.** Measured on 2026-10-13 on the same machine and development stack (migrations up to `00044`). The
fleet had the PDK-090 shape and was inserted the same way, into a new organization inside the measuring transaction,
which was rolled back: **10 000 active devices** in the PDK-027 version mix, each with an open `stale_warning`, 14 000
conditions. Cause: pgx reuses prepared statements, and after five executions of a statement PostgreSQL runs its
generic plan, which it did for both queries of the device view (checked with `EXPLAIN EXECUTE` after six executions).
Both queries filtered the view `attention_condition` with optional filters (`$1 IS NULL OR hostname ILIKE $1`, the
same for `kind` and `device_id`), which PostgreSQL pushes into every branch of the view. In a generic plan it cannot
drop them and estimates almost no matching rows, so it probes the view's tables once per device instead of joining
them. The list also read the view a second time, once per condition row, for the `kind` filter (a correlated
`EXISTS`), and joined `device` and `device_status` for all 10 000 groups before cutting the page. The rewrite (no
migration) reads the view once as a `MATERIALIZED` CTE, applies the filters to its rows (`kind` as
`bool_or(kind = ANY(kinds))` per device), and joins `device` and `device_status` after the page is cut.

`EXPLAIN (ANALYZE, BUFFERS)` medians of 5 runs (after a warm-up run) as the API role in the organization's scope.
Before is the query text of `c0aff7e`, after the rewritten one, both on the same data in the same transaction. These
are query execution times, not HTTP latencies:

| Query (endpoint) | Before, generic plan | After, generic plan | Before, custom plan | After, custom plan |
| --- | --- | --- | --- | --- |
| `ListAttentionDevices`, 25 (`/attention/devices`) | 178 ms | 57 ms | 94 ms | 59 ms |
| `CountAttentionDevices` | 93 ms | 30 ms | 31 ms | 28 ms |
| `ListAttentionDevices` `kind=agent_outdated`, 25 | 273 ms | 53 ms | 181 ms | 54 ms |
| `CountAttentionDevices` `kind=agent_outdated` | 64 ms | 26 ms | 13 ms | 26 ms |
| `ListAttentionDevices` `device_id` (device page) | 7 ms | 28 ms | 1 ms | 34 ms |
| `CountAttentionDevices` `device_id` | 7 ms | 21 ms | 1 ms | 28 ms |

With the generic plan, which a reused statement runs, the query time of `/api/v1/attention/devices?page_size=25`
(list plus count) drops from 271 ms to 87 ms, and with `kind=agent_outdated` from 337 ms to 79 ms. The plan no longer
depends on the plan cache mode. Timed without `EXPLAIN` (40 executions per query after 5 warm-ups, `psql` `\timing`;
the sums of the list's and the count's p50 and p95), list plus count take 81 ms p50 and 97 ms p95 instead of 231 ms
and 266 ms, and with `kind=agent_outdated` 72 ms p50 and 79 ms p95 instead of 276 ms and 342 ms. The device page's conditions (`device_id`) now read the whole view as well, about
50 ms instead of 15 ms at this fleet size. Results are identical before and after for ten parameter sets (sorts, pages
including the last, `q`, one and two kinds, a kind without matches, `device_id`). The test
`TestAttentionDevicesGenericPlan` pins the plan property: in the generic plan, `device_alert` is scanned by one node and
no table scan refers to a query parameter. The HTTP figures after this change are still to be measured once it is
merged and deployed.

*Note, 2026-11-16 (PDK-1079, ADR 0055):* the organization pools now plan every execution, so they no longer run
generic plans and the trap described above no longer applies to them (see Query planning). The rewrite stays as
defence in depth, and `TestAttentionDevicesGenericPlan` still pins its plan property.

## Query planning

Since PDK-1079 (ADR 0055) the pools that open organization transactions run pgx's `QueryExecModeCacheDescribe`: pgx
caches only a statement's description and sends every execution as an unnamed statement, so PostgreSQL plans it with
the real parameter values and the organization of the transaction. A reused plan built for another organization was
catastrophic before: a statement prepared by pgx's default statement cache keeps a generic plan, and a statement
without parameters (the organization comes from `paddock.org_id`, not from a parameter) never gets a custom plan. On
the development stack (PostgreSQL 18.6, one organization of 70 000 devices next to about 400 small ones), a plan built
for a small organization took more than 5 s for the large one in the attention list and count, the outdated-schema
and the config rollout device lists, and 300 to 430 ms instead of 0.03 to 0.06 ms in the event-gap lookups; 29 more
queries were 150 to 1 700 times slower in one direction or the other.

Pool modes (`db.openPool`; pinned by `TestPoolQueryExecModes`):

| Pool | Roles | Mode |
| --- | --- | --- |
| `OrgPool` (incl. `NotifierPool`) | api, worker incl. ingest, compiler, notifier, escrow-reader, revocation-issuer, the `paddock-server admin` commands (the gateway opens no PostgreSQL pool) | per execution (`CacheDescribe`), `jit = off` |
| `OrgPool.WithStatementCache()` view (same connections) | worker `ingest.heartbeat` and `ingest.event` consumers, full and ingest mode | listed statements `CacheStatement`, all others per execution; `jit = off` |
| `PlatformPool` and its lock pool | platform endpoints, leader locks | statement cache |
| `AuditReader`, `AuditWriterPool` | audit reader and writer | statement cache |
| `RelayPool`, `UnsealerPool`, `BackupPool` | outbox relay, unsealer, backup and restore | statement cache |
| health pools (`Options.HealthConn`) | readiness pings | statement cache |
| migrations | `paddock-server migrate` (own connection) | unchanged |

Planning cost, measured read-only on the development stack for PDK-1079: median 0.11 ms per query, p99 3.9 ms,
maximum 5.6 ms. The round trips are unchanged (one per query), so plan M17 amendment j's "no extra statement per
transaction" still holds. `TestOrganizationPoolPlansPerExecution` seeds 70 000 devices and bounds each of the former
catastrophic queries to 1 s in the large organization after six runs in a small one on the same connection.

Ingest CPU per event with and without per-execution planning (N2 method, ADR 0055 decision 3): +28 % CPU seconds per
1 000 events (median, postgres +36 %; two pairs, +32 % and +24 %), far above the 5 % budget. This led to the
statement-cache view below.

The heartbeat and event ingest keeps cached statements (ADR 0055 amendment 2026-11-15 (2), PDK-1079b): planning its
short, keyed statements per execution cost about 30 % more CPU per event in the first N2 measurement. The worker's
`ingest.heartbeat` and `ingest.event` consumers run on `OrgPool.WithStatementCache()`, a view of the worker's
organization pool with the same connections, role, offboarding gate and `jit = off`; it adds no connection. The view
runs a statement as a named, cached one only if its sqlc name is on the closed allow list `ingestStatementCached`
(`server/internal/platform/db/statementcache.go`): `device` by `id`, `device_status` by `device_id`, the device-keyed
queries of `device_event_seen`, `device_event_gap` and `device_event_dropped`, `InsertAction`, `FinishAction`,
`InsertOutbox` and plain inserts. Every other statement, also on the view, is planned per execution. Migration 00158
replaced the organization-only indexes of the three event tables by `(organization_id, device_id)`, so a generic plan
that takes the organization index still reads only one device's rows (7 000 shared buffers before, 13 after, for
`MaxDeviceEventSeenBefore` at 70 000 devices). `TestIngestViewGenericPlans` forces generic plans and bounds every
listed read and write, and the two event-gap lookups, to 100 shared buffers in a 70 000-device organization.

Ingest CPU per event with the statement-cache view (N2 method, ADR 0055 amendment 2 decision 12, series 1 and 2;
5 000 events/s offered, two ingest workers, 150 connections):

- Series 1, view against the build without per-execution planning: +0.7 % (median of three alternating pairs, 1.715
  against 1.703 CPU seconds per 1 000 events; pairs −15.1 %, +6.5 %, −1.0 %). Within the 5 % budget.
- Series 2a, the `(organization_id, device_id)` event-table indexes of migration 00158 against the organization-only
  ones: −20.7 % (postgres −31.5 %). The composite indexes are cheaper.
- Series 2b, `outbox_org_idx` (PDK-1068) present against absent: median +10.3 %, but the pairs range from −35 % to
  +55 % with a mean of +5.9 % and the present variant always ran second on a host whose load drifted, so the
  measurement does not separate the index's cost from noise. The index stays for the offboarding database step; a
  re-measurement with randomized order on a quiet host follows (decisions recorded with the release).

The organization pools also open their connections with `jit = off` (connection runtime parameter, no statement per
transaction; ADR 0055 amendment 2026-11-15, PDK-1081); the other pools keep the server's default. At 70 000 active
devices that all have a status row, the attention view's plan costs about 630 000, above PostgreSQL's
`jit_above_cost` (100 000) and `jit_optimize_above_cost`/`jit_inline_above_cost` (500 000). With JIT, every execution
spent about 2.3 s compiling (2.7 s in total, 0.3 to 0.4 s without JIT), whatever the plan cache does, and the worker's
findings loop would pay it in every round. The organization roles run short, index-driven queries where compilation
does not pay off. `TestOrganizationPoolPlansPerExecution` runs with that data and the production pool configuration,
and `TestPoolQueryExecModes` asserts `jit = off` on the organization pools and the default on the others.

## Authentik web workers

Every portal login, step-up, device login and every call of the worker's identity rounds is a request to
`authentik-server`. Its Python web server (Gunicorn with Uvicorn workers, Authentik 2026.8) runs
`AUTHENTIK_WEB__WORKERS` processes; Paddock sets it from `PADDOCK_AUTHENTIK_WEB_WORKERS` in `.env`, **default 4**
(Authentik's own default is 2), in the development, production and lab stacks alike.

- **CPU:** a worker process serves its requests concurrently, but Python executes in it on at most one core at a time.
  The workers are therefore the number of cores Authentik can use for its requests. Under more simultaneous requests
  every request of a worker slows down instead of being refused: with 2 workers, 24 parallel login loops on the
  reference machine reached p50 17 s and p99 33 s per login, and 5 of 600 logins exceeded the client's 30 s timeout
  (PDK-545). 8 parallel loops stayed below 6.5 s.
- **Memory:** measured on the development stack (`docker stats`, `/proc/<pid>/smaps_rollup`), each worker process holds
  about 220–240 MiB proportional set size, of which about 190 MiB are private; `authentik-server` with 2 workers uses
  650–710 MiB. Four workers add about 0.5 GiB, about 1.2 GiB in total.
- **Sizing:** one worker per core you give Authentik. The default of 4 matches the minimum of 4 vCPU of the control
  plane (`install.md`) and of the lab (`lab-install.md`); the workers only use a core while they serve requests. On a
  larger host with many simultaneous logins (shift start, a large device rollout) raise it with the cores and plan
  about 250 MiB RAM per worker (raise `PADDOCK_AUTHENTIK_SERVER_MEM_LIMIT` with it, section "Memory limits"). Apply a
  change with `./paddock up` (it recreates `authentik-server`).
- `./paddock check` fails the item `authentik web workers` unless the value is an integer of at least 1: Authentik
  falls back to 2 workers on a value it cannot parse and serves no login with 0.
- Authentik's API throttle for anonymous requests counts in a cache of each worker process, so its per-address ceiling
  is the configured rate times the workers; 4 workers double it compared with Authentik's default. The device login
  throttle (`PADDOCK_DEVICE_LOGIN_THROTTLE`) counts in PostgreSQL and does not change with the workers.
- `AUTHENTIK_WEB__THREADS` is not set: Authentik's Uvicorn workers ignore Gunicorn's thread setting, so it does not
  change the capacity. Authentik's HTTP timeouts (`web.timeout_http_*`) stay at their defaults; their sum (215 s) only
  bounds a request in Authentik's Rust front end and is not what clients run into.

## Audit index commit sequence backfill

Audit migration `00010_commit_seq` (PDK-120) gives every event of the audit index a per-organization `commit_seq`
and numbers the existing rows in one transaction that locks `audit_event`. The new audit writer starts only after
the migration (`depends_on` `paddock-audit-migrate` in `compose.audit.yaml`), but during `./paddock up` the previous
writer keeps running until compose replaces it: its transactions wait for the migration's lock and then fail, and the
queue redelivers their events. The queue dead-letters an event after 20 deliveries (`dlq.audit.writer`), so a long
backfill is not guaranteed to be absorbed. The upgrade procedure therefore stops the running audit writer before
`./paddock up` whenever audit migrations are pending (`docs/operations/upgrade.md`, *Upgrade*, the step `audit-writer-stop`), so that new
events wait in the queue instead.

A fresh installation, including the move to 0.1.0-alpha.7 (`docs/operations/upgrade.md`), applies the migration to an
empty index and needs none of this.

- **Measured:** 1 000 000 synthetic events (50 organizations, 12 monthly partitions, typical row size) took
  **1 min 26 s** for the whole migration (column, backfill, `NOT NULL`, index, `audit_org_seq`). Measured on
  2026-10-31 on the development host against PostgreSQL 18.6 in a test container with the repository's audit roles
  and migrations, while the host ran other test suites (load average 16–39 on 22 cores); an idle host is faster.
- **Planning figure:** about 1.5 min per million events in the index. Count the events before an upgrade with
  `SELECT count(*) FROM audit_event` on `paddock_audit`.

## Identity rounds

The worker reconciles the identity provider every 10 minutes (`IdentitySync.Reconcile`: `EnsureOrganization` per
active organization, plus the device login groups) and the admin accounts every 5 minutes. Every call is a request to
`authentik-server` and a burst of queries on `authentik-postgres`, also while nobody uses the portal. The cost grows
with the number of organizations, so it is measured at **250 organizations** (PDK-1020) and again after every change
of the rounds (PDK-1021 repeats it with the same procedure).

### Procedure

Run it on a development stack only (`make load-orgs` refuses a stack with production markers, like `make
load-identities`), with the worker as the only load: no portal sessions, no load test, no other Paddock stack on the
host. Record the commit (`git rev-parse --short HEAD` of the image's checkout) and the hardware next to the figures.

1. **Seed.** Log in to the portal as the platform admin, copy the value of the `paddock_session` cookie (browser
   developer tools) into `bin/load/platform-session` (a file inside the checkout, mode 0600), then

   ```sh
   make load-orgs COOKIE_FILE=bin/load/platform-session N=250
   ```

   creates the organizations `load-001` … `load-250` through `POST /api/platform/v1/organizations`
   (`test/load/cmd/orgseed`). It is repeatable: organizations that exist are counted, not recreated. The session
   expires; use a fresh cookie for a second run. Sign out of the portal afterwards so the window below has no activity.
   `orgseed` creates no devices: the platform principal cannot act inside an organization, and a login assignment
   needs a device of that organization. The figures therefore measure `EnsureOrganization` and the admin-account
   round, not the per-device group calls (see "Limits of the baseline").
2. **Settle.** Wait until the worker log shows a finished reconcile round (`docker logs <paddock-worker>` ends with
   the last `authentik organization ensured` line of an organization and stays quiet) so that the first round after
   the seeding (which creates groups) is not part of the window.
3. **Measure 10 minutes without portal activity.** Note the start time `T0` (UTC, `date -u +%Y-%m-%dT%H:%M:%SZ`),
   start `docker stats --format '{{.Name}} {{.CPUPerc}}' <authentik-postgres>` in a second shell, sampling every 2 s
   into a file (`while sleep 2; do docker stats --no-stream --format '{{.CPUPerc}}' <authentik-postgres>; done >
   bin/load/pg-cpu.txt`), and wait 10 minutes. The window covers one reconcile round and two admin-accounts rounds.
4. **Count the requests by path.** There is no Paddock metric for Authentik requests; Authentik's access log names
   every API request with its path:

   ```sh
   docker logs <authentik-server> --since <T0> --until <T0+10m> 2>&1 | grep '"paddock-service"' \
     | grep -o '"event": "/api/v3/[a-z_/]*' | sort | uniq -c | sort -rn
   ```

   Sum the counts for the total. (`grep '"paddock-service"'` keeps the requests of Paddock's service account.)
5. **CPU average.** `awk '{ sub("%",""); s+=$1; n++ } END { printf "%.1f%%\n", s/n }' bin/load/pg-cpu.txt` (percent of
   one core).
6. **Round duration.** In the worker log, the time between the first and the last `authentik organization ensured`
   line of the reconcile round inside the window.
7. **Repeat** steps 2–6 once; the two runs must agree within 10 %. Record the mean.

### Cleanup

Offboard the organizations `load-001` … `load-250` through organization offboarding (M17) after the measurement,
with a grace period of 0 (development and test stacks only). Never run the measurement on a stack whose data must be
kept and that cannot be offboarded: use a separate scratch stack instead, and remove it afterwards.

### Baseline at 250 organizations

PLACEHOLDER (PDK-1020, measurement still open): the lead fills this table after running the procedure above.

| Item | Baseline (current code) | After PDK-1021 |
| --- | --- | --- |
| Commit | _tbd_ | _tbd_ |
| Hardware | _tbd_ | _tbd_ |
| Authentik requests in 10 min, total | _tbd_ | _tbd_ |
| of which per path (`/api/v3/...`) | _tbd_ | _tbd_ |
| `authentik-postgres` CPU average | _tbd_ | _tbd_ |
| Reconcile round duration | _tbd_ | _tbd_ |

### Limits of the baseline

Organizations without devices do not exercise `DeviceLoginGroups`; with devices the round costs 14 + 1 requests per
organization instead of 14 (PDK-570), so the baseline is a lower bound of the real cost.

## Backup repository

The local backup repository (volume `backup-repo` of the control-plane host, `docs/operations/backup.md`) is the one
backup storage that lives on the host itself, so size its disk (plan M15 §12 decision 7; accepted: the reference host
has about 260 GB free). A full set is roughly:

- `retention_full` (default 14) full backups of both PostgreSQL databases, plus the WAL they need;
- the OpenBao snapshots and Fleet dumps of their keep days (default 30 days each, at the default intervals about 120
  snapshots and 30 dumps);
- the escrowed LUKS headers (small objects, one per device generation);
- during and after a key rotation, the previous key's repository until its retention has passed: a second full set.

Measure the size of one full backup with `./paddock compose run --rm --no-deps pgbackrest info` and multiply it by
`retention_full`. `PaddockBackupRepoFull` fires below 10 % free space; a full volume stops pgBackRest and the backup
role. Every backup target holds another copy of the same set, so size those disks the same way. The figures of
`docs/operations/backup.md` ("What is backed up") are the defaults the sizing assumes.

## Memory limits

Every container of the stack gets a memory limit (ADR 0051 decision 4, plan M12h §3.4), so that a runaway or attacked
service cannot starve the host that also runs OpenBao. When a container reaches its limit, the kernel's OOM killer
kills the largest process inside it, which is not necessarily the container's main process (RR-120):

- PostgreSQL (`postgres`, `authentik-postgres`, `audit-postgres`): usually a backend process is killed. The postmaster
  terminates the other connections, runs crash recovery and accepts connections again; the container keeps running and
  its restart count does not change. Clients see dropped connections and failed transactions.
- Valkey (`valkey`, `fleet-redis`): the killed process may be the child of a background save or AOF rewrite. The
  server keeps running and retries later; after a failed background save it refuses writes until a save succeeds
  (`stop-writes-on-bgsave-error`, on by default), and `INFO persistence` shows `rdb_last_bgsave_status:err` or
  `aof_last_bgrewrite_status:err`. If the server itself is killed, Docker restarts the container and the restart
  count rises.

Neither a Paddock alert nor the restart count reliably shows such a kill (`PaddockRoleDown` covers only the Paddock
roles). The evidence is `docker inspect --format '{{.State.OOMKilled}}' <container>` (set when the container's main
process was killed), the `oom_kill` counter in the container's cgroup `memory.events`
(`docker exec <container> cat /sys/fs/cgroup/memory.events`), and the kernel log (`journalctl -k | grep -i oom`).

The limits are set from the measured working set with headroom and can be raised per installation in `.env`; apply a
change with `./paddock up` (it recreates the container). The table grows with each hardened service group; services
without a limit yet are listed in `deploy/compose/hardening-exceptions.yaml`.

| Service | Host | Default limit | `.env` variable | Snapshot (development stack, 2026-11-09) |
| --- | --- | --- | --- | --- |
| `postgres` | control plane | 2 GiB | `PADDOCK_POSTGRES_MEM_LIMIT` | 190–245 MiB |
| `authentik-postgres` | control plane | 1 GiB | `PADDOCK_AUTHENTIK_POSTGRES_MEM_LIMIT` | 210–215 MiB |
| `audit-postgres` | audit | 1 GiB | `PADDOCK_AUDIT_POSTGRES_MEM_LIMIT` | 50–75 MiB |
| `valkey` | control plane | 512 MiB | `PADDOCK_VALKEY_MEM_LIMIT` | 6–12 MiB |
| `fleet-redis` | control plane | 512 MiB | `PADDOCK_FLEET_REDIS_MEM_LIMIT` | 4–5 MiB |
| `fleet-mysql` | control plane | 2 GiB | `PADDOCK_FLEET_MYSQL_MEM_LIMIT` | 645–655 MiB |
| `rabbitmq` | control plane | 1 GiB | `PADDOCK_RABBITMQ_MEM_LIMIT` | 155–170 MiB |
| `openbao` | control plane | 1 GiB | `PADDOCK_OPENBAO_MEM_LIMIT` | 30–45 MiB; 137 MiB peak |
| `rustfs` | control plane | 2 GiB | `PADDOCK_RUSTFS_MEM_LIMIT` | 240–350 MiB |
| `audit-rustfs` | audit | 4 GiB | `PADDOCK_AUDIT_RUSTFS_MEM_LIMIT` | 2.0–2.7 GiB after many acceptance runs; 90 MiB on a fresh volume |
| `fleet` | control plane | 3 GiB | `PADDOCK_FLEET_MEM_LIMIT` | 90–120 MiB; 810 MiB during a vulnerability run |
| `prometheus` | control plane | 1 GiB | `PADDOCK_PROMETHEUS_MEM_LIMIT` | 60–65 MiB |
| `authentik-server` | control plane | 2 GiB | `PADDOCK_AUTHENTIK_SERVER_MEM_LIMIT` | 860 MiB–1.05 GiB idle with 4 web workers; 1.1 GiB peak at the first start |
| `authentik-worker` | control plane | 1 GiB | `PADDOCK_AUTHENTIK_WORKER_MEM_LIMIT` | 265–330 MiB; 370 MiB peak at the first start |
| `paddock-worker-ingest` | control plane | 1 GiB per replica | `PADDOCK_WORKER_INGEST_MEM_LIMIT` | not measured yet (no replica by default) |

The snapshot is the resident memory (`docker stats`) of two idle development stacks after their acceptance runs, not
a peak under load. PostgreSQL's page cache does not count against the limit beyond what the kernel can reclaim, so a
larger database grows into the host's page cache instead; raise `PADDOCK_POSTGRES_MEM_LIMIT` when you raise
`shared_buffers` or the number of connections. Valkey holds sessions, device keys, nonces and counters only; a limit
reached there points to a leak, not to a larger installation.

The vulnerability figure for `fleet` is the cgroup peak (`memory.peak`, page cache included) of one run of
`fleet vuln_processing` that downloaded every feed into an empty volume (850 MiB on disk), measured on a scratch stack
without enrolled hosts; matching the software of many hosts adds to it, hence the headroom. RabbitMQ does not see its
container limit by itself: `rabbitmq.conf` passes `PADDOCK_RABBITMQ_MEM_LIMIT` as its total memory, so its memory
alarm blocks publishers at 60 % of the limit (the healthcheck `check_local_alarms` then fails) before the kernel would
kill the broker. The alarm reads the suffixes as decimal units (`1g` = 10⁹ bytes), slightly below Docker's binary
ones. The limit must be a whole number with an optional unit (`1536m`, not `1.5g`): RabbitMQ ignores any other value
with a log warning only and sizes the alarm from the host's RAM, so `prod-check` rejects it.

`authentik-server` grows with its web workers (section "Authentik web workers"): about 250 MiB per worker on top of
about 0.5 GiB. The default of 2 GiB fits the default of 4 workers with headroom for simultaneous logins; raise
`PADDOCK_AUTHENTIK_SERVER_MEM_LIMIT` by 256 MiB for every worker you add with `PADDOCK_AUTHENTIK_WEB_WORKERS`. The
peaks are the cgroup's `memory.peak` of a scratch project's first start, which applies every blueprint.

RustFS's resident memory grows with the objects it serves: 90 MiB on a fresh volume, 2.0–2.7 GiB on the
development stack's `audit-rustfs` after many acceptance runs (anonymous memory; its cgroup's `memory.peak`, page
cache included, reached 7.4 GiB, which the kernel reclaims below the limit). When an object store is killed at its
limit, clients see failed uploads and the audit writer retries; raise `PADDOCK_AUDIT_RUSTFS_MEM_LIMIT` (or
`PADDOCK_RUSTFS_MEM_LIMIT`) and the host's RAM together. OpenBao holds its keys and the Raft index in memory and stays
small.

## PostgreSQL connection budget

Every Paddock role opens its own connection pools, and every connection counts against the database's
`max_connections`, PostgreSQL's default of 100, of which it keeps 3 for the superuser
(`superuser_reserved_connections`): 97 for the roles. The pools open connections only on demand and close them after 5
minutes idle, so the figures below are the most a role can hold at once, not what it holds at rest. Every pool has a
fixed size; none grows with the host's CPUs.

Control-plane database (`postgres`):

| Role | Pools | Maximum connections |
| --- | --- | --- |
| `paddock-api` | organization 8, platform 4 | 12 |
| `paddock-worker` | organization 8, platform 8, leader locks 12, readiness 2 | 30 |
| `paddock-worker-ingest` (per replica, none by default) | organization 8, platform 2, readiness 1 | 11 |
| `paddock-notifier` | notifier 8, platform 2 | 10 |
| `paddock-compiler` | 8 | 8 |
| `paddock-backup` | backup 4, platform 3 | 7 |
| `paddock-escrow-reader` | 4 | 4 |
| `paddock-revocation-issuer` | 4 | 4 |
| `paddock-outbox-relay` | 4 | 4 |
| `paddock-unsealer` (automatic unseal only) | 2 | 2 |
| operator commands (`paddock-server admin`, `agent-release`, `backup now`, `restore`, …) | 2–4 each | 4 |

Together the long-running roles of one control plane hold at most **81** connections, 85 while an operator command
runs (operator commands run one at a time), which leaves 12 for pgBackRest and `paddock-migrate`: at the default 100
the budget of `./paddock check` (below) is used up exactly. The worker runs 20
rounds that each hold a leader lock connection for their whole duration (the organization deletion round of M17 is
the 20th; it adds no pool and no connection); with 12 lock connections a round that finds
them all taken waits for one, while its queries and the readiness check keep pools of their own. At many
organizations up to 9 rounds run for minutes (identity, inventory, osv, staleness, findings, retention), so a short
round such as commands or escrow waits only when they all run at once. A further api replica adds 12 and uses up the
spare. A further full worker replica (`--scale paddock-worker=N`) adds up to 30 and does not fit: the budget then
holds only while not every pool is full at once, and otherwise roles fail with `too many clients already`, and it
would run every round a second time for nothing, since a leader lock lets only one replica run each.

For more ingest throughput (N2) add ingest workers instead: set `PADDOCK_WORKER_INGEST_REPLICAS=2` in the bundle's
`.env` (the service `paddock-worker-ingest` declares `deploy.replicas: ${PADDOCK_WORKER_INGEST_REPLICAS:-0}`, so
`./paddock up`, upgrades and restores keep the number). An ingest worker (`PADDOCK_WORKER_MODE=ingest`) runs only
the queue consumers (enrollment, heartbeats, events, issued commands, command results, escrow), no round and no
leader lock, holds at most 11 connections and does not receive the Authentik, Fleet or bundle-bucket credentials
(it shares the worker's OpenBao login); its `/readyz` answers
`ready mode=ingest`. Two of them add 22 connections, 103 in all, which exceeds the default of 100: they need
`PADDOCK_PG_MAX_CONNECTIONS=150` (see the restore and rollback notes of that setting before raising it).

Raise `max_connections` only through `PADDOCK_PG_MAX_CONNECTIONS` in `.env` (default 100; both databases start with
`-c max_connections=${PADDOCK_PG_MAX_CONNECTIONS:-100}`), never with a `-c` of your own or a mounted configuration
file. PostgreSQL writes the value into its WAL and into every backup, and a database restored onto a server that starts
with a lower value pauses its recovery and stays read-only ("hot standby is not possible because of insufficient
parameter settings"). Therefore:

- **Restores start with the backup's value.** `./paddock restore` (and the rollback's restore from 0.1.0-alpha.11 on)
  reads `max_connections` from the restored cluster's control file (`pg_controldata`) before its first start and starts
  it with the larger of that value and `PADDOCK_PG_MAX_CONNECTIONS`, logging both. The next `./paddock up` starts the
  recovered database with the configured value again; set `PADDOCK_PG_MAX_CONNECTIONS` to the logged value to keep it.
- **No rollback to 0.1.0-alpha.10 above 100.** That release starts PostgreSQL with 100 whatever `.env` says; alpha.11's
  `./paddock rollback` refuses it while `PADDOCK_PG_MAX_CONNECTIONS` is above 100: set it to 100 (or remove it) in
  `.env` and run `./paddock rollback` again. The rollback restores the pre-upgrade backup, which the previous release
  took at its own setting.

`./paddock check` computes the budget from the effective configuration (`docker compose config`, which resolves the
replicas of `.env`): each long-running role's maximum from the table above times its replicas, against
`max_connections` less 3 for the superuser, 12 for pgBackRest and `paddock-migrate` and 4 for one operator command
(81 at the default 100). The item `postgres: connection budget` FAILs (and the check exits 1) above that and WARNs with
fewer than 5 connections to spare: the default configuration warns with 79 of 81, with the automatic unseal 81 of 81;
both are accurate and exit 0. The maxima live in one table in
`deploy/bundle/paddock` (`PG_ROLE_MAX_CONNS`); a test compares it with the pools in `server/cmd/paddock-server`.

The audit database (`audit-postgres`) keeps the same default: the api's audit reader (8), the audit writer (8 per
replica), the notifier's audit reader (2) and an operator command (`paddock-server audit …` 8, the restore's escrow
check 2) together hold at most 28.

## Request limits

The fixed limits that bound one request (ADR 0051 decisions 3 and 6, architecture §4.1). They are sized above every
legitimate request; a request beyond them is refused, not queued.

| Limit | Value | Where | Beyond it |
| --- | --- | --- | --- |
| Request body, `admin.` | 2 MiB; 256.5 MiB for the platform uploads (a stored package of at most 256 MiB with its multipart framing) | Caddy | 413 from the edge |
| Request body, `auth.`, `device.`, `bundles.` | 1 MiB (`bundles.`: 33 MiB for an escrowed LUKS header) | Caddy | 413 from the edge |
| Request body, `fleet.` | 64 MiB | Caddy | 413 from the edge |
| Reading a request (api, gateway, escrow-reader) | headers 10 s, whole request 60 s | Go server | connection closed; a body sent at 1 byte/s ends after 60 s |
| Writing a response (api, gateway, escrow-reader) | 120 s; 30 min for agent release and package uploads; the audit export download 60 s per write, in total max(10 min, size at 64 KiB/s), at most 24 h | Go server | connection closed |
| Idle keep-alive connection | 120 s | Go server | connection closed |
| Requests per minute | `PADDOCK_RATELIMIT_*`, `PADDOCK_DEVICE_PER_IP_LIMIT` (`install.md` section 4) | api, gateway | 429 `rate_limited` |

A 128 MiB agent artifact over a link of 1 Mbit/s takes about 17 minutes and fits the 30-minute upload deadline; on a
slower link upload from a host closer to the control plane. An audit export download breaks off when the client
accepts no data for 60 s or reads slower than 64 KiB/s on average (at least 10 minutes are always allowed, at most
24 hours); the client detects the short body against `Content-Length` and `X-Paddock-Package-SHA256` and downloads
again.

## Method

The load generator is k6 (`K6_IMAGE` in `deploy/compose/versions.env`, a tool only, never shipped). It runs as a
container on the Compose networks `paddock_edge` and `paddock_data` (the ingest scenario reads Prometheus there) and
talks to one gateway replica directly
(`http://paddock-gateway:8081`), without the edge (Caddy) in front: N1 is the cost of the gateway node. Each device
signs its requests exactly like the agent (architecture §6.3, ECDSA P-256 with k6's WebCrypto; the P1363 signature
is converted to ASN.1 DER) and sends its own address in `X-Paddock-Client-IP`, so the per-IP limit of the gateway (300
per minute) sees a fleet instead of one load generator. The gateway honours that header only from the addresses in
`PADDOCK_TRUSTED_PROXY_CIDRS`; the development stack's gateway trusts the edge subnet, production Caddy alone. The per-key limit (30 per minute) is respected by spreading the
rate over enough devices: 10 000 devices check in every 10 s at 1 000/s.

1. **Identities.** Create auto-approving enrollment tokens in a dedicated organization (at most 1 000 devices per
   token, so 10 tokens for 10 000 devices) and save each token's enrollment configuration as JSON:
   `make load-enrol-configs ORG=load-enrol TOKENS=10 USES=1000` creates the organization if it is missing and writes
   `bin/load/token-1.json …` (git-ignored; it signs in like `make dev-seed` and refuses production like
   `load-identities`). Then

   ```sh
   make load-identities CONFIGS='bin/load/token-1.json … bin/load/token-10.json' COUNT=10000
   ```

   enrolls the devices through the real enrollment API (`test/load/cmd/identities`) and writes their IDs and keys to
   `bin/load/identities.json`. The gateway tracks a sequence number per device that only the device knows, so
   identities are used by **one** run: enroll new ones for the next run (otherwise the devices are quarantined as
   suspected clones). Retire the load devices of the organization afterwards.
2. **Check-in (N1).**

   ```sh
   make load-test SCENARIO=checkin RATE=1000 VUS=400 WARMUP=1m DURATION=5m
   ```

   ramps to `RATE` during `WARMUP`, then holds it for `DURATION`; thresholds apply to the held phase only. Devices
   report the bundle they were offered as applied, so the held phase measures steady-state check-ins.
3. **Ingest (N2).** Set `PADDOCK_PG_MAX_CONNECTIONS=150` and `PADDOCK_WORKER_INGEST_REPLICAS=2` in
   `deploy/compose/.env` and start the stack again (two ingest workers; each answers `ready mode=ingest`, for example
   `docker compose … exec prometheus wget -qO- http://worker-ingest-ops:9090/readyz`), start the observability profile
   (`make up` does) and run

   ```sh
   make load-test SCENARIO=ingest EVENTS_PER_S=5000 BATCH=50 VUS=200 DURATION=5m DRAIN=2m
   ```

   Devices send `config.drift_corrected` events in batches of `BATCH` (one queue message per batch). The scenario
   reads the backlog of `ingest.event` (and, for information, `audit.writer`) from Prometheus every 5 s and records
   the lag as backlog divided by the consumption rate, derived over at least one scrape interval (15 s,
   `SCRAPE_INTERVAL_S`): two samples of the same scrape show no change although the queue moved. Every device event
   becomes an audit event: an ingest run writes millions of objects into the WORM audit bucket, which cannot be
   deleted before their retention ends. Run it only on a stack whose audit bucket may keep them.

k6 writes its summary to `bin/load/<scenario>-summary.json`; copy the figures into the table above together with
the hardware (CPU model and cores, RAM, disk) and the Paddock commit.
