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
| N2 ingest | 5 000 device events/s with 3 worker replicas, consumer lag of `ingest.event` < 60 s |

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

**Remaining hot spots:** none open. The per-device version key was closed by PDK-090 and the device contact state by
PDK-089 (both below).

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
174 ms. The results are identical before and after: the same 25 devices on the first page, 4 000 matching devices,
the buckets 4 000 on current, 4 000 outdated, 2 000 ahead and 0 unknown, and 14 000 conditions on 10 000 devices. After
the migration, `agent_version_key` equals `paddock_version_key(agent_version)` for every device in the database (dev
seed and fleet). Of the remaining list time, about 90 ms is spent in the view's alert branch (the 10 000 open
`stale_warning` alerts) under the kind filter; no function runs per device row any more. The HTTP figures after this change are
measured with those of PDK-027 and PDK-089 once all three are merged and deployed (PDK-091).

## Method

The load generator is k6 (`K6_IMAGE` in `deploy/compose/versions.env`, a tool only, never shipped). It runs as a
container on the Compose network `paddock_cp` and talks to one gateway replica directly
(`http://paddock-gateway:8081`), without the edge (Caddy) in front: N1 is the cost of the gateway node. Each device
signs its requests exactly like the agent (architecture §6.3, ECDSA P-256 with k6's WebCrypto; the P1363 signature
is converted to ASN.1 DER) and sends its own address in `X-Paddock-Client-IP`, so the per-IP limit of the gateway (300
per minute) sees a fleet instead of one load generator. The gateway honours that header only from the addresses in
`PADDOCK_TRUSTED_PROXY_CIDRS`; the development stack trusts the private ranges, which include the Compose network. The per-key limit (30 per minute) is respected by spreading the
rate over enough devices: 10 000 devices check in every 10 s at 1 000/s.

1. **Identities.** Create auto-approving enrollment tokens in a dedicated organization (at most 1 000 devices per
   token, so 10 tokens for 10 000 devices) and save each token's enrollment configuration as JSON. Then

   ```sh
   make load-identities CONFIGS='token-1.json … token-10.json' COUNT=10000
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
3. **Ingest (N2).** Scale the workers to 3 replicas (`docker compose … up -d --scale paddock-worker=3`), start the
   observability profile (`make up` does) and run

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
