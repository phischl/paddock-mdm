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
pc --profile paddock --profile observability up -d     # control plane (pc: docs/operations/install.md)
pa --profile paddock --profile observability up -d     # audit host
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
| `PaddockCompileLatencyHigh` | bundle compilation p95 above 30 s for 10 minutes | warning |
| `PaddockGateway5xx` | more than 5 % of the device API's responses are 5xx for 10 minutes | warning |
| `PaddockOpenBaoSealed` | OpenBao is sealed (`docs/operations/openbao.md` section 2) | critical |
| `PaddockOpenBaoUnreachable` | the worker cannot reach OpenBao for 5 minutes | critical |
| `PaddockOSVStale` | Ubuntu's vulnerability data has not been updated for 3 days (`docs/operations/vulnerability-data.md`) | warning |
| `PaddockBackupStale` | the newest backup of a kind (postgres, authentik, openbao, fleet) is older than 26 hours (`docs/operations/restore.md`) | critical |
| `PaddockCertificateExpiry` | a public certificate expires within 14 days | warning |
| `PaddockCertificateProbeFailing` | the certificate of a public hostname cannot be read for an hour | warning |

`make lint-prometheus` checks the configuration and the rules with `promtool` and runs the rule tests of
`prometheus/alerts_test.yml`.

## Metrics Paddock adds for the alerts

| Metric | Exported by |
| --- | --- |
| `paddock_backup_last_success_timestamp_seconds{kind}` | worker: last-modified time of the newest object of each kind in the backup bucket, 0 before the first |
| `paddock_openbao_sealed`, `paddock_openbao_reachable` | worker: OpenBao's `sys/health` every 30 s |
| `paddock_tls_certificate_expiry_timestamp_seconds{host}`, `paddock_tls_probe_success{host}` | worker: TLS handshake with Caddy for each name of `PADDOCK_TLS_PROBE_HOSTS` every 15 minutes (production; Caddy exports no certificate metrics) |
| `paddock_osv_stale`, `paddock_osv_last_success_timestamp_seconds` | worker (M5c) |
