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

**Not measured yet.** The scenarios below are ready; the figures are filled in from the first run on the reference
machine (hardware, Paddock commit, k6 summary).

| Scenario | Reference machine | Rate | p99 | Error rate | Lag (max) | Result |
| --- | --- | --- | --- | --- | --- | --- |
| `checkin` | – | – | – | – | – | pending |
| `ingest` | – | – | – | – | – | pending |

## Method

The load generator is k6 (`K6_IMAGE` in `deploy/compose/versions.env`, a tool only, never shipped). It runs as a
container on the Compose network `paddock_cp` and talks to one gateway replica directly
(`http://paddock-gateway:8081`), without the edge (Caddy) in front: N1 is the cost of the gateway node. Each device
signs its requests exactly like the agent (architecture §6.3, ECDSA P-256 with k6's WebCrypto; the P1363 signature
is converted to ASN.1 DER) and sends its own `X-Forwarded-For` address, so the per-IP limit of the gateway (300 per
minute) sees a fleet instead of one load generator. The per-key limit (30 per minute) is respected by spreading the
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
   the lag as backlog divided by the consumption rate. Every device event becomes an audit event: an ingest run
   writes millions of objects into the WORM audit bucket, which cannot be deleted before their retention ends. Run
   it only on a stack whose audit bucket may keep them.

k6 writes its summary to `bin/load/<scenario>-summary.json`; copy the figures into the table above together with
the hardware (CPU model and cores, RAM, disk) and the Paddock commit.
