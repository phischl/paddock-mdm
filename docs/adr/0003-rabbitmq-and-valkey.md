# 0003 — RabbitMQ for ingest and internal events, Valkey for hot read paths (A8)
Status: Accepted (product owner, 2026-10-03) — supersedes the earlier proposal "NATS JetStream"

## Context
Principle 3: everything devices report enters through a queue; no synchronous device-to-database writes.
A8 requires horizontal scaling, backpressure, at-least-once delivery with idempotent consumers. The check-in path
needs fast reads (bundle pointer, pending commands, time ticket) and a write-once nonce store without touching
PostgreSQL. The product owner requires that a later move to the cloud can use **managed services that map 1:1**.

## Options
- **RabbitMQ + Valkey.** + RabbitMQ (MPL-2.0) maps 1:1 to Amazon MQ for RabbitMQ; Valkey (BSD-3-Clause) maps 1:1 to
  ElastiCache for Valkey. Very widely known, mature tooling, quorum queues (Raft) for durability, publisher confirms,
  dead-lettering, delivery limits, single active consumer. − Two components instead of one; no broker-side
  deduplication; no built-in KV.
- **NATS JetStream (earlier proposal).** + One component for queue and KV, broker-side deduplication. − No equivalent
  managed AWS service; self-operated in the cloud.
- **Kafka / Redpanda.** + Throughput; Amazon MSK exists. − Heavy for the target size; Redpanda not OSI-licensed.
- **AWS-native SQS/SNS + DynamoDB.** − No self-hosted equivalent; contradicts C8.

## Decision
- **RabbitMQ 4.x** with **quorum queues only** and **no plugins** beyond management, so the topology runs unchanged
  on Amazon MQ. Exchanges `paddock.ingest`, `paddock.state`, `paddock.audit`, `paddock.external`,
  `paddock.revocation`, `paddock.dlx`; routing keys carry the organization (`<kind>.<...>.<org>`). Ordering for state
  compilation through 16 publisher-computed partition queues with single active consumer. Retries via
  requeue/dead-letter queues, not via the delayed-message plugin. Topology is code (`paddock-server provision rabbitmq`).
- Publishers use **publisher confirms**; consumers ack after commit. Every message carries AMQP `message_id` (natural
  key); every consumer is idempotent (`ON CONFLICT DO NOTHING`), because RabbitMQ does not deduplicate.
- **Valkey 8.x** as cache and coordination store (device key cache, nonces, bundle pointers, pending commands, time
  tickets, locks), core commands only, no modules. Never a source of truth; rebuildable from PostgreSQL except nonces.
  Introduced with the device gateway (M2), not in M0.
- Server-side writes that must emit events use a transactional outbox in PostgreSQL relayed to RabbitMQ.

## Consequences
+ Cloud migration path: Amazon MQ for RabbitMQ and ElastiCache for Valkey without code changes (connection strings,
  TLS `amqps://` / `rediss://`).
+ Broad operational know-how available.
− Idempotency is entirely the consumers' responsibility; every consumer needs a duplicate-delivery test.
− Two stateful components to operate (3-node RabbitMQ cluster, Valkey primary + replica with Sentinel).
− Plugin restrictions must be checked against Amazon MQ's supported feature list on every RabbitMQ upgrade.

## Amendment 2026-10-16 (ADR 0034)
Valkey additionally holds the server-side half of portal sessions (`sess:<sid>`, `acct-sess:<account_id>`,
`sess-gen`), written and read by the `api` role and revoked by the `worker`. These keys are state the portal
depends on (503 `session_store_unavailable` while Valkey is unreachable), not a cache: `appendonly yes` and no
`maxmemory` stay mandatory, and `paddock-server admin rebuild-cache` does not touch them. Devices are unaffected.

## Amendment 2026-10-29 (plan M6d)
From release 0.1.0-alpha.7 the majors are **RabbitMQ 4.4** (Erlang/OTP 29, Khepri metadata store, quorum queues as
before) and **Valkey 9** for both the control plane's store and Fleet's Redis (one image pin, plan
`docs/plans/M6d-upstream-majors.md`, decisions 7–8). The topology, the plugin restriction (management and
Prometheus only), publisher confirms, consumer idempotency and the Valkey configuration are unchanged. Neither
component is backed up (ADR 0016), and the release ships no upgrade path: both start on empty volumes (fresh
installation; maintainer decision 2026-10-29). The 4.4 line writes a classic-queue message store that 4.3 cannot
read, which matters only to a rollback this project does not offer. The Amazon MQ feature check of the consequences
above applies to every future RabbitMQ bump as before.
