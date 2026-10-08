# Implementierungsplan: M6a — Production deployment, backup and restore, monitoring

Status: Ready for implementation (after M4c.1) · 2026-10-07 · Author: architect
Basis: architecture v1.7 §4 (deployment topology, two hosts), §13.2 (OpenBao), §19 (observability, A12),
§20 (backup and restore, A11); ADR 0016, 0017; concept C8, "Audit log" (separation of duties, WORM)

Binding language: **MUST** / **MUST NOT** / **SHOULD** / **MAY**.

## 1. Goal
An operator can install Paddock in production on two hosts (control plane, audit domain) from documented steps, with
public TLS, no development weakening, backups with stated RPO/RTO and a tested restore, and metrics with alert rules.

## 2. Binding decisions

### 2.1 Production overlays
1. `deploy/compose/compose.prod.yaml` (control-plane host) and `deploy/compose/compose.audit.prod.yaml` (audit host):
   Caddy with automatic HTTPS from a public ACME CA (`PADDOCK_ACME_EMAIL`, real domains `admin.`, `auth.`, `device.`,
   `bundles.`, `fleet.` under `PADDOCK_DOMAIN`), no `tls internal`, no host port mappings other than 443/80 (ACME
   HTTP-01), no dev blueprints, `PADDOCK_ENV=production`, OpenBao with TLS on its internal listener (self-signed CA
   generated at install, mounted read-only into clients), RabbitMQ with `amqps` internally optional (documented), RustFS
   and Postgres not published.
2. `make prod-check` (and `paddock-server prod-check` used by it) refuses when: any dev-only variable is set
   (`PADDOCK_STEPUP_WINDOW`, `PADDOCK_STEPUP_MAX_AUTH_AGE`, `PADDOCK_STALENESS_UNIT`, `PADDOCK_REVOCATION_ENABLED=true`
   without `PADDOCK_REVOCATION_ACCEPTED=yes`, test delay hooks), a required secret file is missing or world-readable,
   the audit bucket lacks Object Lock COMPLIANCE, the dev release public key is configured, or `compose.dev.yaml` is in
   the effective config. Output is a checklist with PASS/FAIL per item; exit 1 on any FAIL.
3. Install guide `docs/operations/install.md`: host requirements, DNS, secrets generation (`make prod-secrets`, which
   never prints secrets), OpenBao production init with 5 custodians (existing runbook), audit bucket creation
   (existing runbook), first platform admin, first organization, enrollment of the first device, upgrade procedure,
   and a section "Residual risks you must record in your ISMS" linking `docs/compliance/residual-risks.md` (M6b).

### 2.2 Backup and restore (A11)
4. Container `pgbackrest` (image built from `debian:13.7-slim` + `pgbackrest` package — Debian package, approved;
   pinned base) with stanzas for `paddock` and `authentik` Postgres: continuous WAL archive + daily full to an S3
   endpoint (`PADDOCK_BACKUP_S3_*`, MUST be outside the control-plane host; the dev stack uses the audit host's RustFS
   with a separate bucket `paddock-backup` without Object Lock). Retention 14 full backups.
5. OpenBao: `paddock-server backup openbao` takes a Raft snapshot via the OpenBao API (AppRole `paddock-backup` with
   `read` on `sys/storage/raft/snapshot` only), encrypts it with AES-256-GCM (Go standard library) using the key file
   `backup_encryption_key` (32 bytes, secret file), uploads to the backup bucket; scheduled every 6 h by the
   worker scheduler and after key operations (key creation/rotation events).
6. Fleet MySQL: daily `mysqldump` from a sidecar job to the backup bucket (rebuildable data; RPO 24 h).
7. Restore runbook `docs/operations/restore.md` and command `make restore-drill`: on the dev stack, take a backup, wipe
   Postgres volumes, restore with pgBackRest (point in time = latest), restore OpenBao snapshot into a fresh OpenBao and
   unseal with the dev shares, run `paddockctl admin bump-bundle-seq --by 1000000` and `paddockctl admin rebuild-cache`,
   `paddockctl admin recompile --all`, then run the acceptance subset `TestDeviceProtocol|TestLoginGate|TestAuditChain|
   TestOrganizationIsolation`. Measured RTO is written to the runbook. The audit store is not part of the restore.
   Amendment 2026-10-08 (architect): `paddockctl admin …` → `paddock-server admin …` (plan M6c decisions 20–23; item 9
   of the amendment below).

### 2.3 Monitoring (A12)
8. Compose profile `observability` (prod and dev): Prometheus (image `prom/prometheus`, pinned — approved) scraping
   every role's `/metrics` on the internal network, plus rule file `deploy/compose/prometheus/alerts.yml` with alerts:
   role down, RabbitMQ DLQ depth > 0 (critical for `dlq.audit.writer`), audit writer lag > 10 min, compile latency p95
   > 30 s, gateway 5xx rate, OpenBao sealed, OSV data stale (M5c), backup older than 26 h, certificate expiry < 14 d.
   Alertmanager is **not** bundled; the docs show how to point Prometheus at an existing Alertmanager. Grafana not
   bundled.
9. Metrics added where missing for the alerts above (backup age, OpenBao seal status, cert expiry from Caddy's metrics).

## 3. Non-goals
Kubernetes/Helm; HA RabbitMQ/Postgres clustering automation (documented as operator topology, not automated);
Alertmanager/Grafana bundling; multi-region.

## 4. Steps
1. Prod overlays + `prod-check` + install guide skeleton. Gate P-1: `make prod-check` on the prod overlay with generated
   prod secrets passes; with any dev variable added it fails naming the item.
2. pgBackRest + OpenBao snapshot + Fleet dump. Gate P-2: backups appear in the backup bucket; `pgbackrest info` lists
   them.
3. Restore drill. Gate P-3: `make restore-drill` green; RTO recorded.
4. Observability profile + alerts + missing metrics. Gate P-4: `promtool check rules` passes; with the stack running
   all targets are up; stopping the audit writer fires its alert in Prometheus within 15 min (test reads the
   Prometheus API).
5. Regression (acceptance, e2e; system tests not needed — no agent change). One commit per step.

## 5. Acceptance criteria
| # | Given / When / Then | Req. | Observed by |
| --- | --- | --- | --- |
| AC1 | Given the install guide, then an operator installs Paddock on two hosts with public TLS and `prod-check` passes | C8 | Platform operator |
| AC2 | Given a lost control-plane database, then the restore runbook brings Paddock back within the stated RTO and devices accept new bundles | A11 | Platform operator |
| AC3 | Given a failing role or a growing audit DLQ, then a Prometheus alert fires | A12 | Platform operator |

## 6. Stop conditions
pgBackRest cannot archive to the S3 endpoint (RustFS) — then report; any need to weaken a production default; M0 §11
S2/S6/S7/S8.

## Amendment 2026-10-08 (architect)
Decided on the implementer's questions during PDK-005; binding for steps 1–4.

1. **Links between the hosts (decision 1).** The audit host reaches RabbitMQ and OpenBao on the control plane, the
   control plane reaches the audit PostgreSQL (read-only role). These endpoints are published only on
   `${PADDOCK_INTERCONNECT_ADDR}`, the host's address on a private interconnect the operator provides (VPN or private
   network), never on `0.0.0.0`. Every link between the hosts MUST use TLS: `amqps` on 5671 only (no 5672 on the
   interconnect), PostgreSQL `sslmode=verify-full` for the audit reader, OpenBao over TLS. Each host generates its own
   internal CA at install (`make prod-secrets HOST=…`); the CA certificates (public) are exchanged, so each side
   trusts both (`internal-ca/bundle.crt`) and no CA key leaves its host. `prod-check` FAILs on a plaintext cross-host
   link and on any published port other than 80/443 that is not bound to `${PADDOCK_INTERCONNECT_ADDR}`.
2. **Audit bucket check (decision 2).** Runs on the audit host with `make prod-check HOST=audit ONLINE=1`, using the
   writer credential, which gains the read-only permission `s3:GetBucketObjectLockConfiguration`. Offline the item is
   "not checked" and reported as FAIL on the audit host; the control plane has no such item.
3. **Development release key (decision 2).** FAIL when the matching minisign secret key (`<name>.key`) lies next to
   the configured public key, and when the configured key equals a key `make dev-release-key` produced
   (`.secrets/release/*.pub`) if that file is known on the host. Production public keys live in
   `.secrets/release-production/`.
4. **Secret files (decision 2).** World-readable means any user of the host can read the file: it has the read bit
   for others and every directory above it lets others pass (a 0644 file in the 0700 secrets directory is private).
   An empty secret file counts as missing.
5. The production settings template is `deploy/compose/prod.env.example`; `make prod-check` runs from source in the
   pinned Go image, so production hosts need no Go toolchain.
6. **Backups (decisions 4–6), as implemented in step 2.** pgBackRest speaks TLS only and cannot run inside the
   PostgreSQL image, so: `archive_command` copies each WAL file into a spool volume (the path contains "pgbackrest",
   which pgBackRest's own check requires) and one `pgbackrest` container per database (`pgbackrest`,
   `pgbackrest-authentik`; pgBackRest needs the data directory at the path the server reports) pushes it every 2 s and
   takes the daily full. `restore` stages the archived WAL next to the data directory for PostgreSQL's
   `restore_command`. The repository, the OpenBao snapshots and the Fleet dumps are encrypted with
   `backup_encryption_key` before they leave the host. The development stack reaches the audit host's RustFS through
   the Caddy TLS proxy `backup-s3-tls` (`compose.backup.dev.yaml`, `make up BACKUP=1`). The Fleet dump is uploaded by a
   second container in the pinned AWS CLI image, because the MySQL image's curl cannot sign S3 uploads. The worker's
   backup credential may write below `openbao/` and list the bucket. OpenBao key operations are manual `bao` CLI
   operations outside Paddock, so "after key operations" is a runbook step (`paddock-server backup openbao`,
   `docs/operations/openbao.md` section 5) besides the 6-hourly snapshot.
7. **Missing metrics (decision 9), as implemented in step 4.** Caddy exports no certificate metrics, so the worker
   probes the public hostnames over TLS through Caddy on the internal network (`PADDOCK_TLS_PROBE_HOSTS`, production
   only) and exports `paddock_tls_certificate_expiry_timestamp_seconds{host}` and `paddock_tls_probe_success{host}`.
   The worker exports `paddock_openbao_sealed` and `paddock_openbao_reachable` from OpenBao's unauthenticated
   `sys/health`, and `paddock_backup_last_success_timestamp_seconds{kind}` from the newest object of each kind in the
   backup bucket (0 before the first, so that a kind that never ran alerts too).
8. **Prometheus per host (decision 8).** The control plane's Prometheus scrapes the roles and RabbitMQ (plugin
   `rabbitmq_prometheus`, bundled with the image); the audit host runs its own (`prometheus-audit`) for the audit
   writer, because no further port crosses the interconnect. The control plane watches the audit queue
   (`PaddockAuditWriterLag`: `audit.writer` not drained for 10 minutes; `PaddockAuditWriterNotConsuming`). Each role is
   one static target, so that a stopped role stays a target with `up == 0`. `make lint-prometheus` (part of
   `make lint`) runs `promtool check config`, `check rules` and the rule tests.
9. **Restore commands (decision 7).** Amendment 2026-10-08 (architect): `paddockctl admin …` → `paddock-server admin …`
   (plan M6c decisions 20–23). Order, each as `docker compose … run --rm --no-deps paddock-worker admin …`: stop
   `paddock-compiler` → `bump-bundle-seq --by 1000000` → start the compiler → `rebuild-cache` → `recompile --all`
   (plan M6c §5). The OpenBao snapshot is decrypted to stdout (`paddock-server backup decrypt <in> -`) straight into
   the fresh OpenBao container, which after `raft snapshot restore -force` is sealed with the original barrier and is
   unsealed with the original shares (verified on a throwaway OpenBao). `make restore-drill` requires the development
   stack with backups (`make up BACKUP=1`).
