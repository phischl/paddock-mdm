# Retention schedule

How long Paddock keeps each store, on which legal basis, and which job deletes it with which evidence (ADR 0032
decision 1 and its amendments 2026-10-17 and 2026-10-18; plan M10). The schedule answers GDPR Art. 5(1)(e) (storage
limitation) and ISO/IEC 27001:2022 A.5.33, A.5.34 and A.8.10 ([iso27001-mapping.md](iso27001-mapping.md)). What
Paddock collects in the first place: [privacy.md](privacy.md).

## Retention matrix

Periods are in days unless stated; "WORM retention" is `PADDOCK_AUDIT_RETENTION_DAYS` (≥ 400). "Purge" names the
job that deletes and the audit event that proves it. "Now" means configurable per organization in this milestone.

| Store | Data class | Content (personal data) | Retention | Legal basis (GDPR) | Purge (role, event) | Configurable |
| --- | --- | --- | --- | --- | --- | --- |
| WORM bucket `paddock-audit`: objects, manifests | Evidence | Audit events: actor display name, IP, step-up; usernames, hostnames; never secrets | WORM retention from recording day; Object Lock COMPLIANCE; expiry by the operator's lifecycle rule | Art. 6(1)(c) with A.5.33/A.8.15 duties, Art. 6(1)(f); Art. 17(3)(b) and (e): erasure requests are answered by **restriction**, not deletion | Never by Paddock (lifecycle rule of the operator) | Platform-wide now; per-organization extend-only **later** |
| Audit index `paddock_audit.audit_event` (monthly partitions by `occurred_at`) | Evidence (copy) | Same as WORM | `PADDOCK_AUDIT_INDEX_RETENTION_DAYS` (default = WORM retention; must be ≥ it); a partition is dropped only when **every** event in it was recorded more than that many days ago | As above | Audit writer, nightly 00:45 UTC; `retention.purged` (store `audit_index`, platform pseudo-organization) | Platform-wide |
| `paddock_audit.audit_object`, `audit_manifest`, `audit_signing_key` | Evidence metadata | Object keys, hashes, signatures; no personal data | Unlimited (the chain index) | — | None | — |
| Audit evidence exports (`audit_export`, `audit_export_chunk`) | Evidence (derived copy) | Package with events, objects, manifests; requester identity, purpose | 7 days after `ready`; failed and expired rows keep metadata (no package) for the WORM retention | Art. 6(1)(c)/(f) (A.5.28 evidence collection) | Audit writer, nightly; `retention.purged` (store `audit_exports`) | — |
| `device_user_seen` | Employee login trace | Username, device, last login | **365 days** after the last login = `app.SeenWindow`; deletion is per row | Art. 6(1)(f): lock coverage of cached credentials (plan M3a decision 10); Art. 32 | Worker, every 6 h; `retention.purged` (store `device_user_seen`, per organization, only when rows were deleted) | Fixed by code |
| `device_login_event` (ADR 0037 decision 6) | Employee login history | Username, device, time of every session start | `login_history_days` (7–365, default 90) after the login; **off by default** (`login_history_enabled`); disabling deletes every row at once | Art. 6(1)(f) with the organization's works council agreement; Art. 88 | Worker, every 6 h; `retention.purged` (store `device_login_event`, per organization, only when rows were deleted); until M10's retention round exists, its own round with the same lock pattern | **Now** (`settings.login`) |
| Inventory of **retired** devices: `device_inventory_ref`, `installed_software`, `vulnerability_finding`, `inventory_policy_result`, and the host in Fleet | Device data of a person's laptop | Packages, CVEs, OS version, Fleet host | `retired_inventory_days` after retirement (default 30, 1–365) | Art. 6(1)(f), Art. 5(1)(c) | Worker, every 6 h; `device.inventory_purged` per device (target: the device) | **Now** (`settings.privacy`) |
| Hardware facts in `device_inventory_ref` (ADR 0037 decision 7) | Device data (asset) | Vendor, model, serial number, CPU, memory size, disk size | As the inventory of the device: while active, and `retired_inventory_days` after retirement (same row as the inventory reference) | Art. 6(1)(f) (asset management, theft reports) | The inventory purge of retired devices (M10, `device.inventory_purged`) | With `retired_inventory_days` |
| Inventory of active and quarantined devices | Device data | As above | While the device is active; replaced by every sync round ("what the host no longer reports is deleted") | Art. 6(1)(f) (A.8.8) | Sync round | — |
| Device record (`device`, `device_status`, `device_identity_key`, `bundle`, `device_event_seen`, `device_group_member`, `device_login_assignment`) | Device data | Hostname, hardware UUID, machine ID, state, applied versions | Lifetime of the organization; a retired device stays as the anchor of its audit trail | Art. 6(1)(c)/(f) | None in this milestone | — |
| Escrowed secrets (`escrow_secret`, bucket `paddock-escrow`) of retired devices | Secrets | Encrypted recovery keys, LUKS headers, admin passwords | Until a Destroy (`device.escrow_destroyed`) or until the device row is deleted | Art. 6(1)(f): data recovery of a device the organization still owns | None in this milestone (open question 1 of the plan) | — |
| `device_command` (finished rows: `done`, `failed`, `expired`, `cancelled`) | Operational history | Actor references, hostnames, reasons | `PADDOCK_AUDIT_INDEX_RETENTION_DAYS` after `finished_at` | Art. 6(1)(f) (A.8.9, A.8.32) | Worker; `retention.purged` (store `device_command`) | — |
| `device_alert` (cleared rows) | Operational history | Actor references, hostnames, reasons | `PADDOCK_AUDIT_INDEX_RETENTION_DAYS` after `cleared_at`; open alerts never | Art. 6(1)(f) (A.8.9, A.8.32) | Worker; `retention.purged` (store `device_alert`) | — |
| `revocation_request` with its `revocation_approval` rows (finished: `completed`, `rejected`, `cancelled`, `expired`, `failed`) | Operational history | Actor references, hostnames, reasons | `PADDOCK_AUDIT_INDEX_RETENTION_DAYS` after `finished_at`; unfinished requests never | Art. 6(1)(f) (A.8.9, A.8.32) | Worker; `retention.purged` (store `revocation_request`) | — |
| `change_set` (metadata and plan) | Operational history | Actor references, hostnames, reasons | WORM retention (they explain audit events and feed M11 revert) | Art. 6(1)(f) (A.8.9, A.8.32) | None in this milestone; follow-up ticket | — |
| `change_set.before` (M11, ADR 0033: managed file contents before a change) | Configuration history (may hold personal data of the file contents) | Full managed file contents | **90 days** after `applied_at`; then the column is set to NULL and `before_purged_at` stamped; the change set itself stays | Art. 6(1)(f) (A.8.32 revert) | Worker, every 6 h; `retention.purged` (store `change_set_before`, per organization) | Fixed by code |
| `device_bundle_report`, `device_resource_status` (M11) | Apply status per device | Resource IDs, error messages (may name local users and paths) | Current state only: replaced by the device's next report; rows of a retired device stay with the device record | Art. 6(1)(f) (A.8.9) | None (overwritten); retired devices: follow-up with the device record | — |
| `organization_role_member`, `platform_role_member` (M8b, ADR 0030: snapshots of portal role groups) | Administrator data | Account identities per role | `PADDOCK_AUDIT_INDEX_RETENTION_DAYS` after the snapshot's `taken_at`, keeping the newest snapshot of every group | Art. 6(1)(c)/(f) (A.5.18) | Worker; `retention.purged` (store `role_member_snapshot`) | — |
| `device_event_dropped`, `device_event_gap` (M8b) | Evidence metadata | Device IDs, sequence ranges; no names | `PADDOCK_AUDIT_INDEX_RETENTION_DAYS` after `recorded_at` | Art. 6(1)(f) | Worker; `retention.purged` (store `device_event_gap`) | — |
| `paddock_audit.audit_verification_run` (M8b) | Evidence metadata | Verification results per range; no personal data | Unlimited (part of the chain's evidence) | — | None | — |
| `action` (control-plane origin of audit events) | Evidence (origin copy) | As audit events | `PADDOCK_AUDIT_INDEX_RETENTION_DAYS` after `occurred_at` (never ahead of the audit index) | As audit events | Worker retention round, per organization, batches of 1 000; `retention.purged` (store `action`) | — |
| `outbox` | Transport | Audit payloads, state changes | 7 days after publication (existing) | — | Outbox relay (existing, not audited: transport only) | — |
| `read_audit_window` | Coalescing keys of read-access events | Actor ID, code, target ID, window | 48 hours | Art. 6(1)(f) | Worker, every 6 h; `retention.purged` (store `read_audit_window`) | — |
| Administrator accounts (`admin_account`), API tokens (`api_token`) | Administrator data | Name, display, role, token hash and metadata | Account: follows Authentik (synced); token: until revoked or expired, then kept as metadata for `api_token.use_denied` | Art. 6(1)(b)/(f) | None (operator removes the person in Authentik; the audit trail keeps the name) | — |
| Organization settings, profiles, groups, managed files/units | Configuration | Usernames in profiles and groups | Lifetime of the organization | Art. 6(1)(f) | None | — |
| Authentik database | Identity | Accounts, groups, sessions, Authentik events | Authentik's own settings | Operator's processing | Operator | — |
| Fleet MySQL | Device data | Hosts, software, policies; hosts of **retired** devices | Active hosts: as the inventory; retired hosts: deleted by the inventory purge (same job, same event, `fleet_host_deleted`) | Art. 6(1)(f) | Worker | — |
| RabbitMQ | Transport | Audit events in flight, device messages | Until consumed; quorum queues capped at 256 MiB; dead-letter queues until the operator acts | — | — | — |
| Valkey | Cache | Device keys, sequence numbers, step-up windows | Rebuilt from PostgreSQL; TTLs per key | — | — | — |
| Container logs (Caddy access log, `slog` of the roles) | Operational | Client IPs, hostnames, usernames in messages; never secrets | Docker `json-file` rotation: 50 MiB × 10 files per container (`x-paddock-logging` anchor, this milestone) | Art. 6(1)(f) | Docker | Operator may shorten |
| Prometheus | Metrics | No organization or person labels | 30 days (existing) | — | Prometheus | — |
| Backups (pgBackRest, OpenBao snapshots, Fleet dumps, backup bucket) | Copies of the above | Everything above except WORM | 14 full backups (14 days) plus WAL; bucket noncurrent versions and `openbao/`, `fleet/` objects 30 days (`docs/operations/restore.md`) | Art. 6(1)(c)/(f), Art. 32 | Backup lifecycle (existing) | Operator |

The per-organization settings are *Privacy settings* (`GET`/`PUT /api/v1/settings/privacy`, section
`settings.privacy` of `paddock.yml`: `retired_inventory_days`, `audit_search_recorded`, `inventory_view_recorded`)
and *Login & privileges* → *Login history* (`settings.login`). Every other period is platform-wide or fixed by code.
The periods of `action`, `device_command`, `device_alert`, `revocation_request`, the role-group snapshots and the
device event gaps equal the audit index retention (≥ the WORM retention): these rows explain audit events and must
not disappear while the index still shows them (ADR 0032 amendment 2026-10-18).

## Deletion evidence

Every purge leaves an audit event in the same WORM chain as every other event, recorded as a system action:

- **`retention.purged`**: one event per run, organization and store when at least one row was deleted (or when the
  purge failed). Parameters: `store` (`device_login_event`, `device_user_seen`, `read_audit_window`, `audit_index`,
  `audit_exports`, and the stores of ADR 0032 amendment 2026-10-18: `action`, `device_command`, `device_alert`,
  `revocation_request`, `role_member_snapshot`, `device_event_gap`), `deleted` (number of rows), `cutoff` (RFC 3339;
  rows older than it were deleted) and, for the audit index, `partition` (one event per dropped partition, recorded in the
  platform pseudo-organization); an expired export carries `export_id` and is recorded in its organization.
- **`device.inventory_purged`**: one event per retired device whose inventory was deleted, in Paddock and in Fleet
  (target: the device; parameters `hostname`, `retired_at`, `software`, `findings`, `policy_results`,
  `fleet_host_deleted`). A `failure` with `upstream_unavailable` leaves the Paddock rows in place; the device is
  retried in the next round.

List them in the portal (*Audit log*, filter by code) or through the admin API:

```
GET /api/v1/audit-events?code=retention.purged
GET /api/v1/audit-events?code=device.inventory_purged
```

The meaning and parameters of both codes are in [audit-codes.md](audit-codes.md). Keep the events with your ISMS
records as evidence for A.8.10 (information deletion).

## Deletion lag

A purged row survives in backups for up to 30 days (dump and version expiry, `docs/operations/restore.md`) and in the
audit index copy of the event that proves its deletion. State this lag in your privacy notice; it is accepted as
residual risk RR-94 ([residual-risks.md](residual-risks.md)). If you keep backups longer than 30 days, the lag grows
accordingly; document the value you chose.

## Erasure requests

- **Audit evidence** (WORM bucket, audit index, `action`, evidence exports) is not erased on request. Art. 17(3)(b)
  (legal obligation) and (e) (establishment, exercise or defence of legal claims) apply; the request is answered by
  **restriction**: the events stay until their retention ends, and only the organization's administrators and
  auditors can read them. Object Lock COMPLIANCE makes earlier deletion technically impossible.
- **Stores with a period** are deleted by their job when the period ends. An organization shortens the inventory of
  retired devices with `retired_inventory_days` and deletes the login history at once by switching it off.
  `device_user_seen` is fixed at 365 days because a shorter period would weaken user locks on devices that cache the
  user's credentials (ADR 0032).
- **Administrator accounts** follow Authentik: remove the person there; the audit trail keeps the name.

Record each request, the stores it concerns and the answer in your ISMS.

## What is not purged yet

These rows of the matrix still read "None in this milestone"; their data stays for the period named in the matrix
until a later decision adds a purge:

- the device record (`device`, `device_status`, `device_identity_key`, `bundle`, `device_event_seen`,
  `device_group_member`, `device_login_assignment`): the anchor of a retired device's audit trail;
- escrowed secrets of retired devices (`escrow_secret`, bucket `paddock-escrow`): until a Destroy or until the device
  row is deleted;
- `change_set` (metadata and plan);
- `device_bundle_report` and `device_resource_status` of retired devices: they stay with the device record;
- administrator accounts and API tokens (`admin_account`, `api_token`): they follow Authentik;
- the chain metadata (`audit_object`, `audit_manifest`, `audit_signing_key`, `audit_verification_run`): unlimited by
  design.

The periods of `action`, `device_command`, `device_alert`, `revocation_request` with its approvals, the role-group
snapshots and the device event gaps are decided (ADR 0032 amendment 2026-10-18); their purge is implemented by
PDK-180 in the worker's retention round. The purge of `change_set.before` joins the same round with the M11 change
that creates the column.
