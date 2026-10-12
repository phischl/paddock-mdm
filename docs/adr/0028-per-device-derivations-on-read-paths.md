# 0028 — Per-device derived values on read paths: stored key, joined alert, inlinable functions
Status: Accepted (2026-10-12)

## Context
PDK-027 measured the attention list and the overview with 10 103 active devices (`docs/operations/capacity.md`,
"Attention list and overview"). After migration 00042 (the current release's key is evaluated once per query) two
per-device costs remain, both function calls that PostgreSQL executes once per row:

- `paddock_version_key(agent_version)` (migration 00039, PL/pgSQL): about 48 ms per pass over 10 000 devices. The
  `agent_outdated` branch of `attention_condition` evaluates it once per device, `OverviewUpdates` three times per
  device (151 ms). `GET /api/v1/attention/devices?kind=agent_outdated` reads the view twice and takes about 290 ms of
  query time; the target is 200 ms (PDK-090).
- `paddock_device_contact(state, last_contact_at, presumed_lost_at, device_id)` (migration 00038, SQL with two
  `EXISTS` probes on `device_alert`): `OverviewDevices` takes 385 ms at 10 000 devices, the device list's `contact`
  column and filter pay the same per row (PDK-089). A SQL function whose body contains a subquery is never inlined,
  so every call starts a sub-executor.

Constraints: `agent_release.version_key` is a stored generated column of the same function (00039) and the keys of
releases and devices must stay comparable; a server test keeps the key's order equal to `pkg/semver.Compare`. The
staleness record is `device_alert` (plan M5b §3.3 decision 10): the worker opens and clears alerts, at most one open
alert per device, enforced by the unique partial index `device_alert_open_idx (device_id) WHERE cleared_at IS NULL`
(00026). Row level security applies to every organization table (ADR 0002); `paddock_device_contact` was SECURITY
INVOKER for that reason. The contact state has one definition shared by the device list, its filter, the device
detail and the overview (00038).

Probe on 2026-10-12 against the pinned `postgres:17.11` image, scratch database, 10 000 rows with the PDK-027 fleet
shape, run as a role under RLS, median of 7 (`EXPLAIN`-free wall clock of the statement):

| Query shape | Status quo | Candidate | Result |
| --- | --- | --- | --- |
| `OverviewUpdates` (three key evaluations per row) | PL/pgSQL 151 ms | inlinable SQL function | 1 431 ms |
| same | | stored generated column | 3.4 ms |
| same | | key once per distinct version (`GROUP BY` subquery, join) | 8.8 ms |
| `agent_outdated` branch (one evaluation per row) | PL/pgSQL 47 ms | stored generated column | 2.9 ms |
| `OverviewDevices` (9 500 open alerts, 20 000 cleared) | two `EXISTS` per row 345 ms | `LEFT JOIN` open alert + inlinable `CASE` | 16 ms |
| same | | correlated scalar subquery per row | 206 ms |
| device list, `contact` filter, first page | 86 ms | `LEFT JOIN` open alert + inlinable `CASE` | 22 ms |
| device count, `contact` filter | 109 ms | same | 13 ms |

The inlinable version key was verified: PostgreSQL inlines a `LANGUAGE sql` function only when its body is a single
`SELECT` of one expression without `FROM`, subqueries, aggregates or set-returning functions, the function is not
`STRICT` when the body is non-strict (`CASE`, `COALESCE`), not `SECURITY DEFINER`, has no `SET` clause, and an
argument used more than once in the body is cheap (a column or constant). Mapping a variable number of dot-separated
identifiers therefore cannot use `unnest` and `string_agg`; the only inlinable form is a chain of `regexp_replace`
calls over the whole list (a 20-alternative regular expression for the `uint64` bound). It inlines, produces
byte-identical keys on the test vector, and is ten times slower than the PL/pgSQL loop, because the regular expression
work is repeated for every filter that names the key.

## Options
- **PDK-090 A: stored generated column `device_status.agent_version_key`** — `GENERATED ALWAYS AS
  (paddock_version_key(agent_version)) STORED`, `COLLATE "C"`, the pattern of `agent_release.version_key`.
  + 3 ms instead of 151 ms; the comparison is a plain column compare; one source for the key (the function) and one
  evaluation per check-in (about 5 µs). − A data-model change with a table rewrite of `device_status` (one row per
  device, seconds at most) during the migration.
- **PDK-090 B: inlinable SQL `paddock_version_key`** — no data-model change. − Only possible as a regular-expression
  pipeline nobody can read, and ten times slower than today (1 431 ms). Rejected by measurement.
- **PDK-090 C: key once per distinct version** — a `GROUP BY agent_version` subquery joined to every consumer.
  + No data-model change, 8.8 ms. − Three view branches and the overview each carry an extra scan and join, and the
  gain depends on the planner never flattening the subquery; less simple than A for the same result.
- **PDK-089 A: materialized contact flag on `device_status`** — written by the staleness worker. − A second record of
  staleness next to `device_alert` that can disagree with it; changes the worker, which the ticket excludes.
- **PDK-089 B: index change only** — the probes already use `device_alert_open_idx`; the cost is the sub-executor per
  call, not the index. Rejected by measurement (the correlated subquery without a sub-executor still takes 206 ms).
- **PDK-089 C: join the open alert, inlinable `CASE` function** — every consumer `LEFT JOIN`s the device's open alert
  (at most one, by `device_alert_open_idx`) and passes its `kind` to a pure `CASE` function. + 16 ms, identical
  buckets, RLS applies to the joined table directly, the contact definition stays one function. − Four queries gain a
  join; the join relies on the uniqueness of the open alert.

## Decision
1. **Rule.** A value derived per device that a list, a count or the overview reads is never computed by a function
   call that PostgreSQL cannot inline. A pure function of the row's own columns is a stored generated column
   (`agent_release.version_key`, `device_status.agent_version_key`). A value that depends on other rows is produced
   by a join or a set-based subquery in the query and an inlinable `LANGUAGE sql` function over the joined columns
   (single expression, no subquery, non-`STRICT`, no `SET`, not `SECURITY DEFINER`).
2. **PDK-090.** `device_status` gains `agent_version_key text COLLATE "C" GENERATED ALWAYS AS
   (paddock_version_key(agent_version)) STORED` (NULL while `agent_version` is NULL or no semantic version).
   `attention_condition` (`agent_outdated` branch) and `OverviewUpdates` compare `s.agent_version_key` with the
   current release's key; `paddock_version_key` stays PL/pgSQL and is no longer called per device row anywhere.
3. **PDK-089.** `paddock_device_contact(state text, last_contact_at timestamptz, presumed_lost_at timestamptz,
   open_alert_kind text)` replaces the uuid-taking function: `LANGUAGE sql IMMUTABLE PARALLEL SAFE`, not `STRICT`,
   the same `CASE` with `open_alert_kind = 'stale_critical'` and `open_alert_kind = 'stale_warning'` in place of the
   two `EXISTS`. Every consumer (`ListDevices`, `CountDevices`, `DeviceContact`, `OverviewDevices`) joins
   `LEFT JOIN device_alert open_alert ON open_alert.device_id = device.id AND open_alert.cleared_at IS NULL` and
   passes `open_alert.kind`. The join relies on `device_alert_open_idx` (unique open alert per device); that index is
   part of the contract of `device_alert` and is never dropped or relaxed.

## Consequences
+ `OverviewUpdates` drops from 151 ms to a few ms, `OverviewDevices` from 385 ms to about 16 ms, the device list's
  `contact` column and filter by a factor of four; `/api/v1/overview` can reach the 200 ms target at 10 000 devices.
+ The contact state and the version key keep one definition each; RLS is unchanged (the joined `device_alert` is a
  table with `FORCE ROW LEVEL SECURITY`).
− Migration of PDK-090 rewrites `device_status` under `ACCESS EXCLUSIVE`; acceptable for one row per device.
− A future `device_alert` with several open alerts per device would duplicate device rows in the four queries; the
  unique partial index prevents it, and a test pins it.
Follow-ups: PDK-089 (migration 00043) and then PDK-090 (migration 00044) after PDK-027 is merged, each re-measured on
the 10 000-device load fleet and recorded in `docs/operations/capacity.md`.
