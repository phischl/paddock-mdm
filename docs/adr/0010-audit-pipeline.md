# 0010 — Audit pipeline and storage
Status: Proposed

## Context
F7 and the audit section: two storage paths (query index + WORM evidence), signed daily hash chain, separation of
duties, partitioning by organization, exactly one event per privileged action including failures. Reference stack
names Loki + MinIO; equivalents are allowed. MinIO is no longer maintained; the object store is chosen in ADR 0017.

## Options
- **Outbox → RabbitMQ → audit-writer → PostgreSQL index (separate DB, separate host) + S3 Object Lock COMPLIANCE.**
  + Typed queries, RLS reuse, fewer components. − Index scaling needs partitioning (monthly).
- **Loki index + MinIO.** + Log tooling. − Weak structured queries for the portal; another component.
- **OpenSearch index.** + Powerful search. − Heavy to operate.

## Decision
First option. Events `paddock.audit.v1` with stable English codes from a closed registry. Privileged use cases write
an `action` row and the outbox record in the same transaction; failures are recorded by a deferred handler; stuck
actions are finalized as `outcome=unknown`. Objects `org/<org>/YYYY/MM/DD/HH-<seq>.jsonl.zst`, dated by **recording** day (amended 2026-10-03: late events are covered by the manifest of the day they are recorded); daily per-organization
manifest chained and signed with `audit-chain`. Audit domain on a separate host with separate credentials and an
offsite replica. Optional SIEM forwarding.

## Consequences
+ The portal gate (exactly one event, also on failure) is structurally supported.
− Production audit bucket must be created correctly once (Object Lock cannot be added later).
