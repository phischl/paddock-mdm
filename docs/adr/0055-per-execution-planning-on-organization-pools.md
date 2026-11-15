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
