# 0055 — Per-execution query planning on the organization pools
Status: Accepted (architect, 2026-11-16; approved by main, main §69; implementation PDK-1079)

## Context

Every Paddock role reaches PostgreSQL through pgx pools in `server/internal/platform/db`. pgx's default execution mode
is `QueryExecModeCacheStatement`: each statement is prepared once per pooled connection and then run as a prepared
statement. Two PostgreSQL behaviours make that unstable under row-level security, where one table holds organizations
of very different sizes:

- The planner folds `current_setting('paddock.org_id')` of the RLS policy into its estimates. A **generic** plan is
  therefore costed for whichever organization the connection served when the plan was built.
- A prepared statement **without parameters** never gets a custom plan, whatever `plan_cache_mode` says: PostgreSQL's
  `choose_custom_plan` returns false when there are no parameters. 103 of Paddock's organization queries have none,
  because the organization comes from the session, not from a parameter. Statements with parameters switch to the
  generic plan after five executions.

PDK-1079 measured this read-only on the devstack (PostgreSQL 18.6, one organization with 70 000 devices and about 400
small ones), over 369 queries:
- **Five are catastrophic** when a plan built for a small organization serves the large one:
  - the attention list and count (API dashboard, more than 5 s, timeout);
  - `ListAttentionConditionKeys` (worker findings loop, about 91 s at 70 000 devices);
  - `ListDevicesWithOutdatedSchema` (compiler, timeout);
  - `ListConfigRolloutDevices` (timeout);
  - `MaxDeviceEventSeenBefore` and `ListDeviceEventSeenAbove` (heartbeat and event-gap paths, 5 000–8 500 times
    slower).
- **29 degrade** by 200 to 1 600 times, in both directions.

Earlier fixes (PDK-094, PDK-1071) rewrote single queries.

## Options

- **A — `plan_cache_mode = force_custom_plan`** on the organization roles. + One setting. − It does not reach the 103
  statements without parameters, which include several of the catastrophic ones.
- **B — Rewrite each affected query** (as PDK-094 and PDK-1071 did). + Targeted. − More than 30 queries today, and every
  new query can regress the same way; nothing enforces it.
- **C — `QueryExecModeExec`** (no preparation, text parameters). + A custom plan every time. − pgx then infers parameter
  types without a description, which is fragile with sqlc's typed parameters (uuid, arrays, enums).
- **D — `QueryExecModeCacheDescribe` on the organization pools.** pgx caches only the statement *description*, which
  keeps sqlc's parameter types exact. Every execution sends an unnamed Parse+Bind+Execute in the same single round trip,
  so PostgreSQL plans it with the real parameter values and the current organization, statements without parameters
  included. + It fixes the whole class, including future queries, with one setting in one place. − It plans every
  execution: PDK-1079 measured a median of 0.11 ms, p99 3.9 ms, maximum 5.6 ms. **Chosen.**

## Decision

1. **Organization pools plan per execution.** `db.NewOrgPool` (and every pool that opens organization transactions:
   `InOrg`, `InOrgSnapshot`, `InPendingDeletionOrg`, `InOrgOffboarding`) sets
   `ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeCacheDescribe` in `db.openPool`. This covers the organization
   pools of api, gateway, worker (the ingest workers included), compiler, notifier, escrow-reader and
   revocation-issuer.
2. **The other pools keep the statement cache.** They run no organization-dependent plans: the platform pool and the
   leader-lock connections, the audit writer and audit reader pools, the outbox relay, the backup and restore pools,
   and migrations. Their queries are either cross-organization by design, keyed by primary keys, or on tables without
   organization RLS. Moving them would add planning cost without a benefit. A pool that later starts running
   organization-scoped queries MUST move to the organization mode with it.
3. **The ingest hot path plans per execution too.** Heartbeat and event ingest run in the worker's organization pool,
   and two of the catastrophic queries are on that path (`MaxDeviceEventSeenBefore`, `ListDeviceEventSeenAbove`), so it
   cannot stay on the statement cache. The cost is measured with the N2 method (worker plus postgres CPU per event,
   alternating A/B pairs; method of M17 amendment i). If CPU per event rises by more than 5 %, the decision goes back to
   the architect before merge; the fallback is to keep those two queries' rewrites and move only the ingest consumers'
   pool back.
4. **Defence in depth stays.** The query rewrites of PDK-094 and PDK-1071 remain.
5. **Regression test (main's condition).** An integration test runs each of the catastrophic queries six times in a
   small organization on one pooled connection, then once in the 70 000-device organization on the same connection,
   and asserts a time bound: 1 s per query, with the dataset seeded set-based. Further tests:
   - a test asserts each pool's execution mode, organization pools against the others, so a new pool cannot silently
     take the wrong one;
   - an `EXPLAIN`-based check after six executions shows a custom plan for a statement without parameters.

## Consequences

- + Plans follow the organization actually being queried. The class of "small organization planned, large
  organization served" is closed for current and future queries.
- + Round trips are unchanged: one per query, as before. M17 amendment j's rule ("no extra statement per transaction")
  still holds: describe mode adds no statement, only planning work inside the same message exchange.
- + Unnamed statements also suit a transaction-pooling proxy, should one ever be needed (M19 D1 rejected one for
  now).
- − Planning on every execution: about 0.1 ms per query at the median. The N2 measurement decides whether that is
  acceptable on the ingest path (decision 3).
- Follow-up in `docs/operations/capacity.md`:
  - The PDK-094 section ("After PDK-094") gains a dated note that organization pools plan per execution since this
    ADR, so the generic-plan trap it describes no longer applies to them, and that its rewrite stays as defence.
  - A new short section "Query planning" gives the measured planning cost, which pools use which mode, and the N2
    result.
- Re-evaluate if PostgreSQL gains a way to re-plan generic plans per RLS context, or if planning cost becomes visible
  in N1/N2.

## Amendment 2026-11-15 — JIT compilation is off on the organization pools (PDK-1081; main §72)

### Finding

The PDK-1079 regression test seeds 70 000 active devices in one organization, each with a `device_status` row. With
that data the attention view's plan costs about 630 000, above PostgreSQL's JIT thresholds (`jit_above_cost` 100 000,
`jit_optimize_above_cost` and `jit_inline_above_cost` 500 000). Every execution then spends about 2.3 s compiling: 2.7 s
in total, against 0.3–0.4 s without JIT. This is independent of plan caching, so per-execution planning (decision 1)
does not help; it would hit every planning mode. The worker's findings loop of a large organization would pay it in
every round.

### Options

- **A — `jit = off` on the organization pools.** + The standard setting for OLTP workloads; the organization roles run
  short, index-driven queries where compilation never pays off. One setting in one place, covering future queries.
  − A future organization query that genuinely benefits from JIT would not get it. **Chosen.**
- **B — Raise the JIT thresholds.** + Keeps JIT for very expensive plans. − The threshold is a guess that moves with
  data size; the next large organization crosses it again.
- **C — Only make the attention view cheaper.** + Fixes the cause for this query. − Leaves every other expensive
  organization query exposed; it stays planned as a later improvement (0.1.0-alpha.12), not as the fix.

### Decision

6. **Organization pools open their connections with `jit = off`.** It applies to the same pools as decision 1:
   `db.NewOrgPool` and `db.NewNotifierPool` (the organization pools of api, gateway, worker, compiler, notifier,
   escrow-reader and revocation-issuer).
   - It is set as a connection runtime parameter in `ConnConfig.RuntimeParams`, the same way as the planned
     `transaction_timeout` of M17 amendment r. It costs no statement per transaction, so M17 amendment j's rule
     ("no extra statement per transaction") still holds.
   - The other pools keep PostgreSQL's default: the platform, audit and backup pools may run analytical scans where
     JIT can help. The rule of decision 2 applies here too: a pool that starts running organization-scoped queries
     MUST take `jit = off` with the organization mode.
7. **Proof.** A regression test seeds status rows for all 70 000 devices and asserts that the attention view stays
   under 1 s on an organization pool. The pool-mode test of decision 5 also asserts `jit = off` on the organization
   pools and the default on the others.

### Consequences

- + The attention view and the findings loop no longer pay seconds of compilation per execution at the target scale.
- − Should an organization query ever need JIT, it must be a deliberate exception via an architect decision.
- Follow-up: the "Query planning" section in `docs/operations/capacity.md` (see Consequences above) also states that
  the organization pools run with `jit = off`, and why.
- A cheaper attention view is a later improvement (0.1.0-alpha.12).

## Amendment 2026-11-15 (2) — The heartbeat and event ingest keeps cached statements (main §76)

Status of this amendment: Accepted (architect, 2026-11-15; approved by main, main §77); it replaces decision 3. Decisions 1, 2 and 4 to 7 stay.

### Finding

The N2 ingest measurement of decision 3 (5 000 events/s, one full worker and two ingest workers, worker plus postgres
CPU per 1 000 events, A = the integration head without this ADR, B = with decisions 1 and 6) came out far above the 5 %
limit: median +28.3 % (postgres +35.8 %, workers +9.3 %); the clean pair +31.6 % (postgres +40.9 %), the second pair
+24.2 %. Transactions per event were unchanged. The cost is planning: the event path runs a handful of short, keyed
statements per event, and planning each of them is a large share of their total cost.

Checked in the code:
- The gateway opens no PostgreSQL pool; it publishes to RabbitMQ. All database work of the ingest happens in the
  worker's queue consumers.
- `ingest.heartbeat` and `ingest.event` are consumed by the full worker and by every ingest worker
  (`PADDOCK_WORKER_MODE=ingest`), so at N2 the full worker carries about a third of the events. Both reach the database
  through the worker's single organization pool and its `ActionRunner` (`app.DeviceReports`, `app.DeviceCommands`,
  `app.ActionRunner`).
- Of the catastrophic queries only `MaxDeviceEventSeenBefore` is on that path (heartbeat). `ListDeviceEventSeenAbove`
  runs only in the event-gap round.
- The cause of both is not the SQL but an index. `EXPLAIN` of the generic plan, built in a 43-row organization and
  executed in the 3 million-row one, reads the whole organization through `device_event_seen_org_idx`
  (`organization_id` only, migration 00145 of M17 amendment q): 30 000 buffers, 3 014 900 rows removed by the filter,
  380–510 ms, where the primary key `(device_id, event_seq)` needs a few buffers. Every query on that table carries the
  RLS predicate on `organization_id`, so a rewrite of the SQL cannot take that path away from the planner.
- The connection budget is used up exactly at `max_connections` 100 (81 for the long-running roles,
  `docs/operations/capacity.md`). A further pool in the full worker would break `./paddock check`.

### Options

- **A — Statement cache for the whole ingest worker role only.** + One pool option. − The full worker still runs a
  third of the events per execution, so the measured cost stays well above 5 %.
- **B — A separate pool for the ingest consumers in every worker.** + Clear boundary. − Adds connections to the full
  worker, which the budget does not have; resizing the existing pool starves the rounds (PDK-1010).
- **C — Statement cache by default, per-execution planning only for a named list of heavy queries.** + Cheapest
  everywhere. − Inverts the guarantee of decision 1: a new heavy query is unsafe until someone lists it.
- **D — A statement-cache view of the organization pool for the heartbeat and event consumers, plus organization
  indexes that cannot capture device-keyed lookups.** The view shares the pool's connections, role, organization gate
  and `jit = off`; only the execution mode of its statements differs. + No extra connection; per-execution planning
  stays the default for everything else, including future queries; the root cause of the two event-gap queries is
  removed for every mode. − Two execution modes on one pool; the queries on the view need a review list. **Chosen.**

### Decision

8. **Statement-cache view.** `(*db.OrgPool).WithStatementCache() *db.OrgPool` returns a view of the same pool. Its
   transactions (`InOrg`, `InOrgSnapshot`, `InOrgOffboarding`, `InPendingDeletionOrg`) hand the `pgstore.Queries` a
   wrapper of the transaction that passes `pgx.QueryExecModeCacheStatement` as the first query argument of every
   `Exec`, `Query` and `QueryRow`, and its `set_config` of the organization runs the same way (the gate's rare batch with a stale status cache keeps the pool's mode). pgx keeps the statement
   and the description cache side by side on each connection, so the view and the per-execution default share
   connections safely. `Close` of a view does nothing; only the pool that was opened closes.
9. **Who uses the view.** The worker's `ingest.heartbeat` and `ingest.event` consumers, in the full and in the ingest
   mode, through their own `ActionRunner`, `DeviceReports` and `DeviceCommands` on the view. Every other consumer, every
   round, and every other role keep per-execution planning (decision 1). Decision 3 is replaced by this.
10. **Organization indexes that keep the device key.** Migration 00158 replaces the single-column organization indexes
    of `device_event_seen`, `device_event_gap` and `device_event_dropped` (00143–00145) by indexes on
    `(organization_id, device_id)`, built and dropped concurrently. The organization deletion keeps an index led by
    `organization_id` (M17 amendment q), and a plan that takes the organization index now still reads only one
    device's rows. The SQL of `MaxDeviceEventSeenBefore` and `ListDeviceEventSeenAbove` stays as it is.
11. **Review list for the view.** A test keeps a closed list of the `pgstore` queries the view's code calls. A query
    may join the list only if every table it touches is reached by its primary key or by a device key that every
    index led by `organization_id` on that table contains. A new call fails the test until it is reviewed and listed.
12. **Proof.**
    - A plan test on a connection with `plan_cache_mode = force_generic_plan` runs every listed query that reads or
      writes a device-keyed table, plus `ListDeviceEventSeenAbove` and `CountDeviceEventSeenInRanges` of the event-gap
      round, six times in a small organization and then once in a 70 000-device organization through the view, and
      asserts at most 100 shared buffers for the large-organization execution. Without migration 00158 it fails for
      `MaxDeviceEventSeenBefore` and `ListDeviceEventSeenAbove`.
    - The pool-mode test of decision 5 also asserts that the view runs statements cached and still with `jit = off`.
    - N2 re-measurement (method of main §16): three clean alternating A/B pairs against A = the integration head
      7e23f0ca, CPU seconds per event of worker plus postgres, median of B at most 5 % above A. Migration 00158 is
      applied before the series, so A and B run on the same schema. The cost of the new indexes is measured in the
      second series together with the pending `outbox` index series of PDK-1068: organization-only against
      `(organization_id, device_id)` indexes, at most 5 %.

### Consequences

- + The ingest hot path costs what it cost before ADR 0055; plan stability stays the default for all other queries.
- + Device-keyed lookups on the event tables are safe in every planning mode, also in the event-gap round.
- − The heartbeat and event path keeps generic plans. Its review list (decision 11) is the guard; a heavy query on that
  path must not be added without an architect decision.
- − The composite indexes are larger than the organization-only ones; the second N2 series decides whether that is
  acceptable.
- Follow-up: the "Query planning" section of `docs/operations/capacity.md` names the view, its consumers and both N2
  results.

### Clarification 2026-11-15 (within main §77): the view caches only listed statements

Before implementation started, the call graph of the two consumers turned out to reach far more queries than the four
files decision 11 named: device transitions and tamper findings (clone quarantine, uninstall retirement), disk
conversion and configuration status events, and the software-request handling of request events. Several of them
touch tables whose organization-led indexes lack the lookup key, so they fail the rule of decision 11:
- `device_group_member`, `user_group_member` and `device_identity_key` have organization-only indexes;
- `device_owner` has `(organization_id, user_id)`, `app_user` has `(organization_id, created_at)`;
- `software_request`, `device_command`, `device_resource_status`, `device_bundle_report`, `escrow_secret` and
  `device_software_status` have organization-led indexes without the device key.

Decisions 8 and 11 are therefore made precise, so that the guarantee holds by construction, not by a closed file list:

- **8 (precise).** The view runs a `pgstore` statement with `pgx.QueryExecModeCacheStatement` only if its sqlc name
  (the `-- name:` line that starts each generated SQL text) is on an allow list in `server/internal/platform/db`.
  Every other statement on the view runs in the pool's mode, per execution. The view's own `set_config` stays cached.
  An unlisted or newly reached query is thus planned per execution, which is safe; it can only cost CPU, which N2
  shows.
- **11 (precise).** The allow list replaces the call-graph registry; nothing has to follow the call graph. A name may
  be listed only if it passes the rule of decision 11, or it is a plain `INSERT … VALUES` without a subquery. The first
  list holds the common heartbeat and event path:
  - lookups and updates of `device` by `id` and of `device_status` by `device_id`;
  - the queries on `device_event_seen`, `device_event_gap` and `device_event_dropped` (after migration 00158);
  - `InsertAction`, `FinishAction`, `InsertOutbox`;
  - plain inserts.
  Software-request handling, disk conversion, configuration status, device transitions, tamper findings, device
  commands, escrow and software status stay unlisted and run per execution. They only run for their own event types,
  and adding indexes for them would grow 00158 for little benefit. No index is added beyond decision 10.
- **12 (precise).** The plan test covers every listed name that reads or updates a table (not the plain inserts).
  Further tests check that every listed name exists among the generated queries, and that on the view a listed
  statement is cached while an unlisted one is not.

## Amendment 2026-11-16 (3) — The view's admission rule holds under worst-case statistics (main §89)

Status of this amendment: Accepted (architect, 2026-11-16; approved by main, main §90). It replaces decision 11 and its clarification, and makes
decisions 8 and 12 precise. Decisions 9 and 10 stay. Implementation: PDK-1079d, as a fix forward on the integration
head (no revert of PDK-1079b, main §89).

### Finding

Decision 11 admitted a statement to the view if it reached each table "by its primary key or by a device key that
every index led by `organization_id` on that table contains". The primary-key half of that rule is unsound:

- A generic plan is costed with the organization that is active when the plan is built: the planner evaluates
  `current_setting('paddock.org_id')` of the RLS predicate for its selectivity estimate.
- If the `ANALYZE` sample holds no row of a small organization, `organization_id` gets `n_distinct = 1` and the large
  organization as its only most common value. The small organization's estimate then clamps to one row, and any index
  led by `organization_id` costs no more than the primary key. The generic plan built in the small organization takes
  that index and, executed in the large organization, reads all of the large organization's rows in it.
- Measured on PostgreSQL 18.6 (PDK-1079c, 70 000-device organization next to a 5-device one):
  - over 120 repeated `ANALYZE` runs the generic plan flipped to an organization index **7 times**; with a sample of
    30 000 rows an organization of 5 devices is missed in about 6 % of the runs, one of 1 device nearly always;
  - with the statistics forced to that worst case (`ANALYZE` while the small organization's rows are absent), **14 of
    the 23** listed reads and updates fail the 100-buffer bound of decision 12: the 7 `device` statements by `id`
    (about 1 330 buffers via `device_org_state_idx`), the 6 `device_status` statements by `device_id` (about 2 316 via
    `device_status_disk_state_idx`) and `CloseOpenDeviceEventGaps` (1 069 via `device_event_gap_org_reported_idx`,
    which migration 00158 did not touch);
  - safe under the same worst case: the statements on `device_event_seen` and `device_event_dropped`, the inserts and
    the upserts that conflict on a unique key;
  - with `plan_cache_mode = auto`, as in production, a connection adopted the bad generic plan on the sixth
    execution.
- `FinishAction` (on `action` by `id`) passed only because the test did not analyze `action` under the worst case;
  `action` has `action_org_idx (organization_id)`, so it falls under the same failure.

The N2 numbers this rests on: per-execution planning of everything costs +28 % CPU per event; the view as merged
+0.7 % (series 1). The 14 failing statements are on the heartbeat path; the event path is mostly inserts.

### Options

- **1 — Strict rule: the view caches only statements whose plan cannot be captured.** A name stays on the list only
  if it is an insert, or every table it reads or updates has no index led by `organization_id` that lacks the lookup
  key as its second column. `device`, `device_status`, `CloseOpenDeviceEventGaps` and `FinishAction` leave the list
  and run per execution. + Sound by a static property of the schema; no new mechanism. − The heartbeat's device and
  status lookups pay planning again; estimated between +5 % and +15 % CPU per event (4 of about 7 cached statements
  of each heartbeat move back; the event path is unchanged).
- **1 + extension — replace the organization indexes of `device` and `device_status` by variants that contain the
  key, as 00158 did.** Rejected. Those indexes exist for their second column: `device_org_hostname_idx`,
  `device_org_enrolled_idx`, `device_org_state_idx`, `device_org_name_key`, `device_status_org_contact_idx` and
  `device_status_disk_state_idx` serve the portal lists, the attention view and the rounds by sorting or filtering
  within an organization. With the key in second place (`(organization_id, id, …)`) they are unique per row and can no
  longer serve that sort or filter, which brings back the timeouts ADR 0055 removed. The partial indexes
  (`device_org_uninstall_idx`, `device_org_config_mode_idx`, `device_status_org_outdated_idx`,
  `device_event_gap_org_reported_idx`) serve rounds the same way. No variant both keeps their purpose and contains the
  key.
- **2 — Cached statements with `plan_cache_mode = force_custom_plan`.** The organization pools' connections get the
  parameter `plan_cache_mode = force_custom_plan`, next to `jit = off`. It only acts on named prepared statements:
  the pool's own unnamed statements (describe mode) are planned per execution anyway, and a statement without
  parameters keeps its single plan in either mode. So it reaches exactly the view's cached statements: they keep
  parse, analysis and rewrite cached and get a custom plan, costed for the current organization and the real
  parameters, on every execution. No statement is added per transaction. + Sound for every listed statement with a
  parameter, including `device` and `device_status`; the list can stay as merged. − Planning per execution for all
  cached statements, the safe ones too; the saving over option 1 is only parse and analysis, so its cost may equal or
  exceed option 1's. Setting it per transaction instead (`set_config('plan_cache_mode', …, true)` in the view's
  existing `set_config` statement) would be equally free but adds a second mode switch to maintain; the connection
  parameter is chosen.
- **3 — Other mechanisms, judged for soundness:**
  - a higher statistics target on `organization_id`: lowers the chance of a missed organization, does not remove it,
    and fails the worst-case test; not sound;
  - extended statistics: they model correlation between columns, not a missed value in the sample; not sound;
  - an `n_distinct` override: the most common value list still holds only the large organization, so the small
    organization's estimate still clamps to one row; not sound;
  - making the organization indexes partial: they stay led by `organization_id`, so the plan can still take them;
    not sound;
  - an explicit `organization_id = $n` parameter or cast tricks in the SQL: the RLS predicate is added regardless and
    is still estimated with the folded `current_setting`; not sound;
  - planner hints (`pg_hint_plan`): a new extension in the database image, against the dependency rule; rejected.

### Decision

11. **Admission rule (replaces decision 11 and its clarification).** A sqlc name may be on the allow list of the view
    only if one of these holds, each checked mechanically by a test:
    - **(a) insert:** its SQL is an `INSERT … VALUES` without `SELECT` in its text, optionally with
      `ON CONFLICT (<columns of a unique index>) DO UPDATE | DO NOTHING`;
    - **(b) device-keyed:** its SQL compares `device_id` with a parameter, and every table in its plan has no index
      whose first column is `organization_id` unless that index's second column is `device_id` (an expression in
      second place does not count);
    - **(c) custom-planned (only if decision 13 is in force):** its SQL has at least one parameter.

    Primary-key access alone is **not** a reason for admission. No name may be added that is not on the list as merged
    in PDK-1079b; a name leaves the list only through this rule or a main decision (main §88).
12. **Proof (makes decision 12 precise).**
    - `TestIngestViewGenericPlans` analyzes, before the measured runs, **every** table with an `organization_id`
      column with the small organization's rows absent (the deterministic worst case of PDK-1079c, extended from six
      tables to all organization tables), and asserts at most 100 shared buffers in the large organization for every
      listed name that reads or updates a table. Under option 1 it runs with `plan_cache_mode = force_generic_plan`;
      once decision 13 is in force, with the pool's own setting.
    - A static test checks rules (a), (b) and (c) for every listed name against the SQL text of
      `server/internal/adapters/postgres/queries/*.sql` and, for (b), against `pg_index` of the migrated schema.
13. **Order of paths, decided by N2.**
    - **Path 1 first:** the list shrinks to the names that pass (a) or (b). N2 (main §16 method, three clean
      alternating pairs, A = the integration head with the list as merged, B = A plus path 1): median CPU per event of
      B at most 5 % above A → path 1 is final.
    - **Path 2 if path 1 exceeds 5 %:** organization pools get `plan_cache_mode = force_custom_plan` as a connection
      parameter, and the list returns to the names of PDK-1079b, each passing (a), (b) or (c). N2 again against the
      same A. The cheaper path within 5 % is final; if neither is within 5 %, main decides with both numbers.
    - Path 1 is merged to the integration branch as soon as its tests are green, before N2: it removes the unsound
      plans, and costs only CPU.

### Consequences

- + The view's guarantee no longer depends on the `ANALYZE` sample; the test checks the worst case on every run.
- + No migration and no new dependency.
- − The heartbeat may cost more CPU than series 1 showed; N2 decides between path 1 and path 2, and main between
  them and the budget if neither fits.
- − A new organization index led by `organization_id` without `device_id` second on `device_event_seen` or
  `device_event_dropped` fails the static test and takes their statements off the list; that is intended.
- Follow-up: the "Query planning" section of `docs/operations/capacity.md` names the final path and its N2 result.

## Amendment 2026-11-16 (4) — Organization foreign keys reference narrow key tables (main §92)

Status of this amendment: Proposed (architect, 2026-11-16). It adds decisions 14 to 16. Implementation: PDK-1095.

### Finding

The same estimate failure as in amendment 3 hits PostgreSQL's own foreign-key checks, which no execution mode of
Paddock controls:

- 53 foreign keys reference ten parents by `(organization_id, id)`: `device` (29), `device_group` (10), `app_user`,
  `software_catalog_entry` (4 each), `notification_destination` (3), `user_group` (2), `permission_profile`,
  `config_rollout`, `software_source`, `notification_delivery` (1 each). Every child insert runs
  `SELECT 1 FROM ONLY <parent> x WHERE organization_id = $1 AND id = $2 FOR KEY SHARE OF x`.
- Every one of the ten parents has further indexes led by `organization_id` (list order, sorting, names, rounds).
- PDK-1091 (PostgreSQL 18.6): 100 000 one-device organizations analyzed (`n_distinct(organization_id) = -1`), then an
  organization of 10 000 devices below the autoanalyze threshold. The check takes `device_org_state_idx` and reads
  all 10 000 devices for every checked row, in the custom and in the generic plan. A young install hits the same
  while its first large organization enrolls.
- Reproduced by the architect on the same version with the four device indexes on `(organization_id, …)`: the check
  took `device_org_name_key`, not `device_org_state_idx` (2 064 buffers, 9 999 rows removed by the filter); 2 000
  child inserts took 300 ms. Under these statistics every candidate is estimated at one row, so the planner's choice
  between them is decided by index size, and any index led by `organization_id` can win. The same check against a
  table whose only index is `(organization_id, id)` read 5 buffers; 2 000 child inserts took 13.5 ms.

### Options

- **i — Append `id` to every index led by `organization_id` on the parents.** − Not possible for the unique keys
  (`device_org_name_key`, `*_organization_id_name_key`, `*_slug_key`): with `id` appended they no longer enforce
  uniqueness. − For a high-cardinality middle column (hostname, name, dates) the check becomes a PostgreSQL 18 skip
  scan that probes every distinct value of the organization, which is the scan it should avoid. Rejected.
- **ii — Foreign keys on `(id)` alone.** + The check uses the primary key. − The database no longer guarantees that a
  child row and its parent belong to the same organization; the check bypasses row-level security, so a
  cross-organization `id` would be accepted. A trigger replacing that guarantee would query the parent under
  row-level security and face the same index choice. Rejected (organization isolation).
- **iii — Narrow key tables.** Each parent gets a key table that holds only `(organization_id, id)`; the children
  reference the key table instead of the parent. All of its indexes contain `id`, which is unique, so every plan the
  planner can choose for the check reads at most one row, whatever the statistics. The composite guarantee stays.
  + Sound by construction, checkable on the schema. − Ten tables, two triggers each, 53 foreign keys moved; one
  extra row written per parent insert. **Chosen.**
- Statistics measures (higher target, `n_distinct` override, `ANALYZE` after enrolment) are rejected for the reasons
  of amendment 3 option 3; a statistics target of 0 on `organization_id` would make every check sound but take away
  the per-organization estimates the portal and the rounds rely on (decision 1).

### Decision

14. **Key tables.** For each of the ten parents `<p>` a table `<p>_org_key`:
    - columns `organization_id uuid NOT NULL`, `id uuid NOT NULL`; `PRIMARY KEY (organization_id, id)`,
      `UNIQUE (id)`; no other index;
    - `ENABLE` and `FORCE ROW LEVEL SECURITY` with the same policies and grants as `<p>`, registered in
      `offboarding_table` after `<p>` and after all its children;
    - `<p>` gets `FOREIGN KEY (organization_id, id) REFERENCES <p>_org_key DEFERRABLE INITIALLY DEFERRED`, so every
      parent row has its key and its organization cannot change. `UNIQUE (id)` keeps a second key with the same `id`
      in another organization out, so a child cannot point across organizations;
    - an `AFTER INSERT … FOR EACH ROW` trigger on `<p>` inserts the key (`ON CONFLICT DO NOTHING`); an
      `AFTER DELETE … FOR EACH STATEMENT` trigger with a transition table deletes the keys of the deleted rows. The
      delete actions of the children (cascade or no action) move unchanged to the key table.
15. **Children reference the key table.** Each of the 53 foreign keys is re-created against `<p>_org_key` with the
    same columns and the same `ON DELETE` action, then the old one is dropped. Migration `00160` runs without a
    transaction and can be re-run: key tables and triggers first, then the backfill, then per foreign key `ADD … NOT
    VALID`, `VALIDATE`, `DROP` of the old one.
16. **Rule and proof.** A static test asserts on the migrated schema: every foreign key whose columns include
    `organization_id` references a table whose indexes are all unique and all contain the referenced `id` column.
    A worst-case test reproduces PDK-1091 (one-row organizations analyzed, then a large organization unanalyzed) and
    asserts at most 10 shared buffers for the check query on `device_org_key`, in the custom and in the generic plan.

### Consequences

- + Foreign-key checks of child inserts cost one index lookup in every statistics state; the heartbeat and event
  inserts, the uninstall commands of an offboarding request and the identity sync are no longer quadratic.
- + The organization guarantee of the composite keys stays in the database.
- − One extra insert per parent insert, one extra statement per parent delete statement.
- − Not covered: the checks of a parent delete look up the children by `(organization_id, <parent>_id)`, and many
  children have indexes led by `organization_id` without that column. Offboarding deletes children before parents,
  so the ranges scanned are empty; single deletions in a live organization scan that organization's child rows once
  per deleted parent. The offboarding gates measure it; a change needs a further decision.
