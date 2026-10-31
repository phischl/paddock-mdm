# 0016 — Operations: backup (A11), observability (A12), deployment
Status: Accepted (architect, 2026-10-29; implemented by plans M6a and M6d)

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

## Amendment 2026-10-29 (plan M6d, decision 6)
The backup design above is implemented as plan M6a describes (pgBackRest with WAL archive and daily verified full
backups per stanza, OpenBao snapshots, Fleet dumps, quarterly restore drill) and the status moves to Accepted. One
rule is added: a pgBackRest stanza follows the cluster it backs up. When the stanza already exists in the repository
for another cluster (a different PostgreSQL major or system identifier — a fresh installation into a kept backup
bucket), the backup service runs `stanza-upgrade` instead of failing; the older backup sets stay in the repository
until retention expires them and are not restorable into the new cluster. A PostgreSQL major upgrade is a fresh
installation without a product upgrade path (maintainer decision 2026-10-29); pgBackRest's own PostgreSQL support
is verified against the sources before each major (`PG_CONTROL_VERSION`, `XLOG_PAGE_MAGIC`), not assumed from the
package's label.

## Amendment 2026-10-30 (plan M6d, decision 6 revised)
The rule of the amendment of 2026-10-29 that the backup service runs `stanza-upgrade` when the repository holds the
stanza for another cluster is withdrawn. The backup service refuses such a stanza and logs it; the operator runs
`stanza-upgrade` once by hand (`run.sh stanza-upgrade`) when a bucket is kept on purpose. Reason: an automatic
upgrade lets the service back up a freshly initialised, empty cluster on a rebuilt host, and a disaster restore then
restores that newest, empty set; it also breaks the archiving of a second installation that shares the bucket. The
rest of the 2026-10-29 amendment (status Accepted, the backup design, PostgreSQL majors as fresh installations,
verifying pgBackRest against the sources) stands.
