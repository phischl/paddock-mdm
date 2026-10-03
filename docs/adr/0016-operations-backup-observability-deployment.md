# 0016 — Operations: backup (A11), observability (A12), deployment
Status: Proposed

## Context
A11: tested restore, stated RPO/RTO, audit store excluded from routine restore. A12: metrics, health, tracing separate
from audit. C8: self-hostable as container stack. Decided by the product owner: Compose now, Kubernetes later.

## Options
- Backup: **pgBackRest (MIT)** vs. `pg_dump` only (no PITR) vs. WAL-G (Apache-2.0, comparable; pgBackRest chosen for its restore verification tooling).
- Observability: **OpenTelemetry + Prometheus** vs. vendor agents (rejected: commercial dependency).
- Deployment: **Compose v1, 12-factor roles** vs. Compose + Helm in v1 (higher cost now).

## Decision
pgBackRest with WAL archiving (RPO 5 min, RTO 4 h), OpenBao Raft snapshots, escrow bucket replication, bundles
recomputed instead of restored, RabbitMQ and Valkey not backed up (Valkey rebuilt from PostgreSQL), audit store excluded. Restore runbook bumps `bundle_seq`.
Quarterly restore drill. Prometheus metrics, OTLP traces, slog JSON logs, `/healthz` + `/readyz`. Docker Compose
with two hosts (control plane, audit domain); no Compose-only behaviour that would block Kubernetes later.

## Consequences
+ Clear recovery objectives. − Two-host minimum for production to satisfy separation of duties.
