# Monitoring

Metrics and alert rules of Paddock (plan M6a, architecture §19, A12). Observability is separate from the audit log.
Every role serves `/healthz`, `/readyz` and `/metrics` on its ops port 9090 on the internal network only.

## Prometheus

The Compose profile `observability` runs Prometheus (pinned `PROMETHEUS_IMAGE`) with the rules of
`deploy/compose/prometheus/alerts.yml`:

| Host | Service | Scrapes |
| --- | --- | --- |
| Control plane | `prometheus` (`compose.yaml`) | every Paddock role, RabbitMQ's queue metrics (plugin `rabbitmq_prometheus`, port 15692) — `prometheus/scrape/controlplane.yml` |
| Audit host | `prometheus-audit` (`compose.audit.prod.yaml`) | the audit writer — `prometheus/scrape/audit.yml` |
| Development | `prometheus`, published on `127.0.0.1:9091` | both |

```sh
./paddock up      # control plane and audit host: starts the profiles paddock and observability
                  # (docs/operations/install.md)
```

Prometheus is not published in production. Reach it through an SSH tunnel, for example
`ssh -L 9090:<container address>:9090 <host>`, or let your own Prometheus federate from it. Grafana is not bundled.

### Sending alerts

Alertmanager is not bundled. Point Prometheus at your existing Alertmanager: copy `prometheus/prometheus.yml`, add

```yaml
alerting:
  alertmanagers:
    - static_configs:
        - targets: ["alertmanager.example.org:9093"]
```

and mount the copy instead of the original (an override file for the `prometheus` service with
`volumes: - ./prometheus/prometheus.local.yml:/etc/prometheus/prometheus.yml:ro`). Without an Alertmanager the alerts
are visible in Prometheus' UI and API (`/api/v1/alerts`) only.

## Alerts

| Alert | Fires when | Severity |
| --- | --- | --- |
| `PaddockRoleDown` | a role (or RabbitMQ) cannot be scraped for 2 minutes | critical |
| `PaddockAuditDLQ` | `dlq.audit.writer` holds messages: audit events that are not in the audit log | critical |
| `PaddockDLQ` | any other `dlq.*` queue holds messages | warning |
| `PaddockAuditWriterLag` | `audit.writer` has not drained for 10 minutes (lag > 10 min) | critical |
| `PaddockAuditWriterNotConsuming` | `audit.writer` has no consumer for 5 minutes (visible on the control plane) | critical |
| `PaddockAuditChainBroken` | the last nightly chain verification found a broken or unreadable audit chain of at least one organization (`docs/operations/audit-bucket.md` section 3) | critical |
| `PaddockAuditVerifyStale` | no nightly chain verification has finished for 36 hours, for one hour | warning |
| `PaddockAuditIndexPurgeStale` | no complete audit index purge (01:15 UTC) has finished for 48 hours, for one hour; a purge with a failed or timed-out partition is not complete (`docs/operations/audit-bucket.md` section 4) | warning |
| `PaddockAuditWriterTransactionSlow` | the audit writer's transaction p95 is above 5 s for 5 minutes (see [Attributing a slow audit writer](#attributing-a-slow-audit-writer)) | warning |
| `PaddockCompileLatencyHigh` | bundle compilation p95 above 30 s for 10 minutes | warning |
| `PaddockGateway5xx` | more than 5 % of the device API's responses are 5xx for 10 minutes | warning |
| `PaddockOpenBaoSealed` | OpenBao is sealed (`docs/operations/openbao.md` section 2) | critical |
| `PaddockOpenBaoUnreachable` | the worker cannot reach OpenBao for 5 minutes | critical |
| `PaddockAutoUnsealWithdrawn` | automatic unseal was disabled in the portal, but the unsealer has reported shares on the host for an hour: run `./paddock auto-unseal disable` there (`docs/operations/openbao.md` section 6) | warning |
| `PaddockAutoUnsealerDown` | automatic unseal is enabled, but the unsealer has not reported for 10 minutes: OpenBao stays sealed after the next restart until it runs or three custodians unseal it | warning |
| `PaddockOSVStale` | Ubuntu's vulnerability data has not been updated for 3 days (`docs/operations/vulnerability-data.md`) | warning |
| `PaddockIPAllowlistBypassed` | an api runs with `PADDOCK_IP_ALLOWLIST_BYPASS=true` for 15 minutes: the application IP allow list is not enforced (`docs/operations/ip-allowlist.md`) | warning |
| `PaddockRoleDirectoryRefused` | the admin-accounts round has refused one or more organizations in every round for 15 minutes (two refusals five minutes apart do not fire it): every role group listing is empty and the Authentik service token cannot be shown to see the directory (a role group unreadable by name, or no user other than service accounts visible). Role changes are not recorded and administrator accounts are not followed. The worker logs `the identity provider's directory looked empty to the service token in consecutive rounds` with the `organization_id` of each; check the permissions of the `paddock-service` role in Authentik (`deploy/compose/authentik/blueprints/paddock-portal.yaml`) | warning |
| `PaddockBackupStale` | the newest backup of a kind (postgres, authentik, openbao, fleet) is older than 26 hours (`docs/operations/restore.md`) | critical |
| `PaddockWALArchiveLag` | the newest archived WAL segment of a database (stanza `paddock` or `authentik`) is older than 15 minutes for 10 minutes: the RPO of minutes no longer holds (check the `pgbackrest` containers and their spool volumes) | critical |
| `PaddockCertificateExpiry` | a public certificate expires within 14 days | warning |
| `PaddockCertificateProbeFailing` | the certificate of a public hostname cannot be read or does not verify (expired, untrusted, wrong name) for an hour | warning |
| `PaddockBackupAgeMissing` | the worker exports the age of fewer backup kinds than `paddock_backup_kinds` for an hour (e.g. listing the bucket fails from the start) | critical |
| `PaddockWALArchiveLagMissing` | the worker exports the WAL archive age of fewer stanzas than `paddock_backup_wal_stanzas` for 30 minutes | critical |
| `PaddockOpenBaoHealthMissing` | the worker is up but exports no `paddock_openbao_reachable` for an hour | critical |
| `PaddockCertificateExpiryMissing` | fewer certificate expiries than `paddock_tls_probe_hosts` for an hour | warning |
| `PaddockRetentionPurgeStale` | the retention round has not purged a store (`device_login_event`, `device_user_seen`, `retired_inventory`) in every organization for 48 hours, for an hour: personal data is kept beyond its retention period (ADR 0032); the worker logs `retention round failed` with the failing organization and store | critical |
| `PaddockRetentionPurgeMissing` | the worker exports the last success of fewer stores than `paddock_retention_stores` for an hour (e.g. a pass fails from the start) | warning |

On a lab host (`docs/operations/lab-install.md`) the probe dials your TLS proxy (`PADDOCK_LAB_PROXY_ADDR:443`), so
`PaddockCertificateExpiry` and `PaddockCertificateProbeFailing` watch the proxy's certificate.

`make lint-prometheus` checks the configuration and the rules with `promtool` and runs the rule tests of
`prometheus/alerts_test.yml`.

## Metrics Paddock adds for the alerts

| Metric | Exported by |
| --- | --- |
| `paddock_backup_last_success_timestamp_seconds{kind}`, `paddock_backup_kinds` | worker: last-modified time of the newest object of each kind in the backup bucket, 0 before the first; a kind that cannot be listed keeps its last value, the others are still exported |
| `paddock_backup_wal_last_archived_timestamp_seconds{stanza}`, `paddock_backup_wal_stanzas` | worker, every 5 minutes: last-modified time of the newest segment below `pgbackrest/archive/<stanza>/`, 0 before the first. It never lists the whole archive: it takes the newest archive ID, lists the WAL directories from the newest one seen before (`StartAfter`; a new timeline sorts after it) and the segments of the newest directory only, at most 10 pages of 1000 entries per listing. The alert assumes a database that writes continuously (PostgreSQL switches the segment every 60 s only after activity); a stanza that cannot be listed keeps its last value |
| `paddock_openbao_sealed`, `paddock_openbao_reachable` | worker: OpenBao's `sys/health` every 30 s |
| `paddock_auto_unseal_enabled`, `paddock_auto_unseal_shares_present`, `paddock_auto_unseal_unsealer_up` | worker, every 30 s (ADR 0035): the automatic-unseal setting, whether a running unsealer (reported within the last 60 s) reports shares on the host, and whether it reported within the last 60 s |
| `paddock_unsealer_shares_present`, `paddock_unsealer_setting_enabled`, `paddock_unsealer_unseals_total{result}` | unsealer (only where automatic unseal is enabled; job `paddock-unsealer`): the shares file holds three valid lines, the setting it last read, and its unseal attempts by `success` and `failure` |
| `paddock_tls_certificate_expiry_timestamp_seconds{host}`, `paddock_tls_probe_success{host}`, `paddock_tls_probe_hosts` | worker: TLS handshake with Caddy for each name of `PADDOCK_TLS_PROBE_HOSTS` every 15 minutes, verified against the system trust store like a client (production; Caddy exports no certificate metrics). An expired, untrusted or wrong-name certificate reads `paddock_tls_probe_success` 0 |
| `paddock_osv_stale`, `paddock_osv_last_success_timestamp_seconds` | worker (M5c) |
| `paddock_retention_last_success_timestamp_seconds{store}`, `paddock_retention_deleted_total{store}`, `paddock_retention_stores` | worker (M10), every `PADDOCK_RETENTION_INTERVAL` (Go duration, default `6h`, between `1m` and `24h` unless `PADDOCK_ENV=development`; `paddock prodcheck` fails on any other value): end of the last retention round in which the store's pass succeeded in every organization (not exported before the first), the rows deleted per store (including the committed batches of a failed pass; for `retired_inventory` the retired devices whose inventory was purged, neither a device that failed nor one whose host is still kept for a device of the same hardware with nothing else left to purge counted), and the number of stores the round purges (3: `device_login_event`, `device_user_seen`, `retired_inventory`) |
| `paddock_identity_directory_refusals_total` | worker: organization rounds of admin-accounts refused because every role group listing was empty and the directory probe did not show that the service token sees the directory (PDK-424); counted once per refused organization round |
| `paddock_ip_allowlist_entries`, `paddock_ip_allowlist_enabled`, `paddock_ip_allowlist_bypass`, `paddock_ip_allowlist_denied_total`, `paddock_ip_allowlist_reload_errors_total`, `paddock_ip_allowlist_last_reload_timestamp_seconds` | api (M7a): the cached IP allow list of each replica, the break-glass bypass, denied requests (exact count; the audit log aggregates them) and the reloads from PostgreSQL |
| `paddock_audit_writer_transaction_seconds{result}` | audit writer: duration of each writer transaction, one per organization of a batch, from acquiring the connection to commit (`committed`) or rollback (`rolled_back`, e.g. a failed put or `transaction_timeout`); it includes the WORM put of the transaction |
| `paddock_audit_worm_put_seconds{object,result}` | audit writer: duration of each WORM put (`PutLocked`) to the audit bucket; `object` is `events` (inside the writer transaction) or `manifest` (the daily seal), `result` is `ok` or `error` |
| `paddock_audit_verify_runs_total{trigger,result}` | audit writer: chain verification runs by `trigger` (`nightly`, `sample`, `cli`) and `result`. `ok` and `failed` are read from `audit_verification_run` at every scrape, so they count the runs of every process, `paddock-server audit verify` included, and survive restarts; they are omitted while the audit database cannot be read. `error` (the verification could not run) and `record_error` (the run could not be recorded) count this process's runs only |
| `paddock_audit_verify_failed_organizations` | audit writer: organizations whose nightly verification (window or sample day) failed or could not run in the last cycle |
| `paddock_audit_verify_last_run_timestamp_seconds` | audit writer: end of the last nightly cycle; at start the end of the last recorded nightly run, or the start time |
| `paddock_audit_index_purge_last_success_timestamp_seconds` | audit writer: end of the last index purge in which no partition failed or hit the lock timeout; at start the start time |
| `paddock_audit_index_partitions_dropped_total` | audit writer: monthly audit index partitions dropped by the nightly purge of this process |

Both histograms use the buckets 5 ms to 41 s and carry no organization or other identifying labels.

### Attributing a slow audit writer

A writer transaction is the database work plus one WORM put of `object="events"`. When transactions are slow
(`PaddockAuditWriterTransactionSlow`, or messages sit unacked in `audit.writer`), compare the two on the audit host's
Prometheus over the same window:

```promql
histogram_quantile(0.95, sum by (le) (rate(paddock_audit_writer_transaction_seconds_bucket[5m])))
histogram_quantile(0.95, sum by (le) (rate(paddock_audit_worm_put_seconds_bucket{object="events"}[5m])))
```

If the put accounts for most of the transaction, the WORM store (audit-rustfs) is slow; if the transaction is slow
while the put stays fast, the time is spent in audit-postgres (connection, partition DDL, index inserts, commit).
A `result="rolled_back"` transaction near `transaction_timeout` (5 minutes) is a stall the writer gave up on.
