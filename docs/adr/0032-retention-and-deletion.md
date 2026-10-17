# 0032 — Retention and deletion
Status: Accepted (architect, 2026-10-15)

## Context

Paddock stores personal data in several places: audit events with administrator names and client addresses
(index and WORM store), login traces of employees (`device_user_seen`), the software inventory of devices that are
personal laptops, administrator accounts, escrowed secrets, backups and logs. Today only the WORM store has a
retention (`PADDOCK_AUDIT_RETENTION_DAYS`, at least 400 days, platform-wide) and only the outbox is purged
(published rows after 7 days). The concept and `docs/architecture.md` §14.4 promise per-organization retention and
automatic deletion that the code does not deliver (roadmap finding G5, auditor items AUD-07 and AUD-10/11).

GDPR Art. 5(1)(e) (storage limitation), Art. 17 (erasure) and Art. 25 (data protection by design) require a
retention schedule per data class with a legal basis, and deletion that actually runs and leaves evidence
(ISO/IEC 27001:2022 A.5.33, A.5.34, A.8.10). Two constraints shape the decision:

- **Object Lock retention can never be shortened.** Audit objects and manifests are COMPLIANCE-locked for
  `PADDOCK_AUDIT_RETENTION_DAYS`; Paddock itself never deletes audit objects; expiry is a lifecycle rule the operator
  adds once the period is final (`docs/operations/audit-bucket.md`). Every index purge must run **after**, never
  ahead of, the WORM retention, otherwise the portal hides what is still evidence.
- **`device_user_seen` is not only a convenience.** `app.SeenWindow` (365 days, plan M3a decision 10) makes a user
  who logged in on a device within that window an *affected user* of a lock on that device, because Himmelblau
  caches credentials. Purging earlier would weaken user locks. The auditor's suggestion of 90 days is therefore
  rejected; the retention is bound to the constant.

Related: ADR 0002 (RLS, scheduler role iterates organizations), ADR 0010 (audit pipeline, recording day),
ADR 0017 (object store), ADR 0030 (M8b: evidence integrity, `audit_verification_run`, role-group snapshots),
ADR 0033 (M11: safe configuration changes, `change_set.before`). Plan: `docs/plans/M10-evidence-privacy.md`.

## Options

**Where the retention lives**

- **A. Platform-wide settings only (environment variables).** + Simple, one truth. − Different organizations have
  different contractual periods; the works council of one organization cannot shorten the inventory retention of
  its own devices.
- **B. Per-organization settings for every period, including WORM.** + Matches the concept. − Per-object WORM
  retention needs per-object `PutObjectRetention` at write time and extend-only semantics in the portal; the first
  production customers do not need it yet; it doubles the surface of this milestone.
- **C. Platform-wide for evidence (WORM, index), per organization for the stores that are purely the
  organization's business (retired-device inventory, read-access recording), fixed by code where a security
  property depends on it (`device_user_seen`).** + Honest about what can be configured today; small surface;
  per-organization WORM retention stays open as a later, extend-only setting. − The concept's "retention per
  organization" is only partly true until the later step.

**Who purges**

- **A. One cron job with the platform role across all tables.** + Simple. − Bypasses RLS for organization data;
  the audit index lives in another database on another host.
- **B. The worker purges control-plane tables organization by organization through `OrgPool.InOrg`; the audit
  writer purges the audit index and the exports on the audit host.** + RLS-safe, separation of duties kept (the
  control plane never gets delete rights in the audit domain), each role already has the credentials it needs.
  − Two jobs, two metrics.
- **C. PostgreSQL-side jobs (pg_cron).** − New dependency, no audit event.

**How a purge is audited**

- **A. Not audited; counts in logs only.** − No deletion evidence (A.8.10, A.5.33 "disposed").
- **B. One audit event per purge run and store with the counts, as a system action; per device for the inventory
  of retired devices.** + Deletion evidence in the same WORM chain as everything else; per-device traceability where
  a person is affected. − The audit writer must be able to record its own events (it has no `ActionRunner`).

**Evidence export placement**

- **A. The api role builds and serves the package.** − Needs a WORM read credential and the `audit-chain`
  signing key in the control plane; signing a package with the chain key outside the audit domain weakens the
  separation of duties.
- **B. The audit writer builds and signs the package in the audit domain; the api only stores the request and
  streams the result from the audit index database.** + No new credential, no new network path, the chain key
  never leaves the audit domain, large ranges run on the audit host. − The reader role gets `INSERT` on one request
  table and the package travels through PostgreSQL in chunks.

## Decision

### 1. Retention matrix

Periods are in days unless stated; "WORM retention" is `PADDOCK_AUDIT_RETENTION_DAYS` (≥ 400). "Purge" names the
job that deletes and the audit event that proves it. "Now" means configurable per organization in this milestone.

| Store | Data class | Content (personal data) | Retention | Legal basis (GDPR) | Purge (role, event) | Configurable |
| --- | --- | --- | --- | --- | --- | --- |
| WORM bucket `paddock-audit`: objects, manifests | Evidence | Audit events: actor display name, IP, step-up; usernames, hostnames; never secrets | WORM retention from recording day; Object Lock COMPLIANCE; expiry by the operator's lifecycle rule | Art. 6(1)(c) with A.5.33/A.8.15 duties, Art. 6(1)(f); Art. 17(3)(b) and (e): erasure requests are answered by **restriction**, not deletion | Never by Paddock (lifecycle rule of the operator) | Platform-wide now; per-organization extend-only **later** |
| Audit index `paddock_audit.audit_event` (monthly partitions by `occurred_at`) | Evidence (copy) | Same as WORM | `PADDOCK_AUDIT_INDEX_RETENTION_DAYS` (default = WORM retention; must be ≥ it); a partition is dropped only when **every** event in it was recorded more than that many days ago | As above | Audit writer, nightly 00:45 UTC; `retention.purged` (store `audit_index`, platform pseudo-organization) | Platform-wide |
| `paddock_audit.audit_object`, `audit_manifest`, `audit_signing_key` | Evidence metadata | Object keys, hashes, signatures; no personal data | Unlimited (the chain index) | — | None | — |
| Audit evidence exports (`audit_export`, `audit_export_chunk`) | Evidence (derived copy) | Package with events, objects, manifests; requester identity, purpose | 7 days after `ready`; failed and expired rows keep metadata (no package) for the WORM retention | Art. 6(1)(c)/(f) (A.5.28 evidence collection) | Audit writer, nightly; `retention.purged` (store `audit_exports`) | — |
| `device_user_seen` | Employee login trace | Username, device, last login | **365 days** after the last login = `app.SeenWindow`; deletion is per row | Art. 6(1)(f): lock coverage of cached credentials (plan M3a decision 10); Art. 32 | Worker, every 6 h; `retention.purged` (store `device_user_seen`, per organization, only when rows were deleted) | Fixed by code |
| Inventory of **retired** devices: `device_inventory_ref`, `installed_software`, `vulnerability_finding`, `inventory_policy_result`, and the host in Fleet | Device data of a person's laptop | Packages, CVEs, OS version, Fleet host | `retired_inventory_days` after retirement (default 30, 1–365) | Art. 6(1)(f), Art. 5(1)(c) | Worker, every 6 h; `device.inventory_purged` per device (target: the device) | **Now** (`settings.privacy`) |
| Inventory of active and quarantined devices | Device data | As above | While the device is active; replaced by every sync round ("what the host no longer reports is deleted") | Art. 6(1)(f) (A.8.8) | Sync round | — |
| Device record (`device`, `device_status`, `device_identity_key`, `bundle`, `device_event_seen`, `device_group_member`, `device_login_assignment`) | Device data | Hostname, hardware UUID, machine ID, state, applied versions | Lifetime of the organization; a retired device stays as the anchor of its audit trail | Art. 6(1)(c)/(f) | None in this milestone | — |
| Escrowed secrets (`escrow_secret`, bucket `paddock-escrow`) of retired devices | Secrets | Encrypted recovery keys, LUKS headers, admin passwords | Until a Destroy (`device.escrow_destroyed`) or until the device row is deleted | Art. 6(1)(f): data recovery of a device the organization still owns | None in this milestone (open question 1 of the plan) | — |
| `device_command`, `device_alert`, `revocation_request` and approvals, `change_set` (metadata and plan) | Operational history | Actor references, hostnames, reasons | WORM retention (they explain audit events and feed M11 revert) | Art. 6(1)(f) (A.8.9, A.8.32) | None in this milestone; follow-up ticket | — |
| `change_set.before` (M11, ADR 0033: managed file contents before a change) | Configuration history (may hold personal data of the file contents) | Full managed file contents | **90 days** after `applied_at`; then the column is set to NULL and `before_purged_at` stamped; the change set itself stays | Art. 6(1)(f) (A.8.32 revert) | Worker, every 6 h; `retention.purged` (store `change_set_before`, per organization) | Fixed by code |
| `device_bundle_report`, `device_resource_status` (M11) | Apply status per device | Resource IDs, error messages (may name local users and paths) | Current state only: replaced by the device's next report; rows of a retired device stay with the device record | Art. 6(1)(f) (A.8.9) | None (overwritten); retired devices: follow-up with the device record | — |
| `organization_role_member`, `platform_role_member` (M8b, ADR 0030: snapshots of portal role groups) | Administrator data | Account identities per role | WORM retention (the diff events reference them) | Art. 6(1)(c)/(f) (A.5.18) | None in this milestone; follow-up ticket | — |
| `device_event_dropped`, `device_event_gap` (M8b) | Evidence metadata | Device IDs, sequence ranges; no names | WORM retention | Art. 6(1)(f) | None in this milestone; follow-up ticket | — |
| `paddock_audit.audit_verification_run` (M8b) | Evidence metadata | Verification results per range; no personal data | Unlimited (part of the chain's evidence) | — | None | — |
| `action` (control-plane origin of audit events) | Evidence (origin copy) | As audit events | WORM retention | As audit events | None in this milestone; follow-up ticket | — |
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

**Deletion lag.** A purged row survives in backups for up to 30 days (dump and version expiry) and in the audit
index copy of the event that proves its deletion. The privacy documents state this lag; it is accepted
(residual risk RR-35).

### 2. Per-organization settings

`organization_privacy_settings` (`GET`/`PUT /api/v1/settings/privacy`, section `settings.privacy` of
`paddock.yml`, audited as `settings.privacy_changed`, role `org_admin`): `retired_inventory_days` (1–365, default
30), `audit_search_recorded` (default false), `inventory_view_recorded` (default false). Everything else in the
matrix is platform-wide or fixed by code. **Per-organization WORM retention** (extend-only, per object at write
time, step-up, audited) is a later decision; `docs/architecture.md` §14.4 is amended to say so.

### 3. Purge jobs

- The **worker** runs a retention round every `PADDOCK_RETENTION_INTERVAL` (default 6 h, leader lock) that iterates
  the organizations (`OrgPool.OrganizationIDs`) and deletes inside `OrgPool.InOrg` in batches of at most 1 000 rows
  per statement: `device_user_seen` rows older than `app.SeenWindow`, `read_audit_window` rows older than 48 h, and
  the inventory of devices retired longer than `retired_inventory_days` ago (plus the host in Fleet through a new
  `ports.InventoryAdmin.DeleteHost`), and the before-states of change sets older than 90 days (`change_set.before`
  of M11, set to NULL with `before_purged_at`). Every deletion is recorded through `app.ActionRunner` with a system
  principal: `retention.purged` per organization and store when at least one row was deleted (or on failure), and
  `device.inventory_purged` per device. In development `PADDOCK_RETENTION_UNIT=seconds` counts days as seconds
  (gate speed), refused by `prod-check` like `PADDOCK_STALENESS_UNIT`.
- The **audit writer** drops index partitions nightly at 00:45 UTC through the `SECURITY DEFINER` function
  `audit_purge_partition` (owner-executed like `audit_ensure_partition`; the writer role keeps no `DELETE` on
  `audit_event`) and expires exports; it records `retention.purged` through the audit writer's own event recorder
  (`auditwriter.Recorder`, ADR 0030 / M8b), which writes one system event through the normal writer path (index and
  WORM), in the platform pseudo-organization for the index, in the organization for its exports.
- Purges never touch the WORM bucket, `audit_object`, `audit_manifest` or the revocation path.

### 4. Read-access recording (AUD-10)

Reads of sensitive views are recorded through `ActionRunner.RecordReadOnce`: the first read per actor and window
records one event, later reads in the window record nothing (`read_audit_window` claim with
`ON CONFLICT DO NOTHING` in the action transaction). Always recorded: `audit.export_requested` (step-up),
`audit.export_downloaded`. Recorded only when the organization switched it on: `audit.searched` (per actor and
clock hour; filters, never results or the search text) and `device.inventory_viewed` (per actor, device and UTC
day). Escrow reveals and header downloads stay audited as today. The default is off so that the works council
agreement, not the tool, decides whether administrators are monitored.

### 5. Evidence export (AUD-01, G6)

`POST /api/v1/audit/exports` (roles `org_admin`, `org_auditor`, step-up, audited) requests a package for a range of
**sealed recording days**; the audit writer builds it in the audit domain: the raw WORM objects and signed daily
manifests of the range, `events.jsonl` reproduced from the objects, the verifier's report for the range plus the
nightly verification runs of M8b (`audit_verification_run`, ADR 0030) that covered it, the `audit-chain` public
keys, and `export.json` signed with `audit-chain`. The package is stored in 8 MiB chunks in the audit index
database (`audit_export_chunk`), streamed by the api (`GET /api/v1/audit/exports/{id}/download`, audited) and
expires after 7 days. The offline verifier is `paddockctl audit verify-export`; it needs no Paddock access. The
`paddock_audit_reader` role receives `INSERT` on `audit_export` and `SELECT` on `audit_manifest`, `audit_object`,
`audit_signing_key`, `audit_export` and `audit_export_chunk` (all organization-scoped tables under RLS); it keeps
no `UPDATE` or `DELETE` anywhere.

### 6. Dependencies

The `cli` module adds `github.com/klauspost/compress` (v1.20.1, the version the `server` module already pins;
BSD-3-Clause/MIT/Apache-2.0, in the license allow list) for zstd decoding in the offline verifier, and the
workspace module `github.com/phischl/paddock-mdm/pkg` for the shared export types (`pkg/auditevidence`). `pkg`
keeps its import allow list (standard library and `jcs` only). No other dependency.

## Consequences

- Positive: a retention schedule with legal basis and deletion evidence exists for every store; the two purge jobs
  are RLS-safe and keep the audit domain separate; `device_user_seen` keeps the lock guarantee; the auditor obtains
  verifiable evidence without a platform operator; read access becomes auditable where a works council wants it.
- Negative: deletion lag in backups (RR-35); the reader role is no longer read-only in the strict sense (one
  insert table); exports of several gigabytes travel through PostgreSQL; purges of `action`, commands, alerts,
  change sets and escrow of retired devices are documented as "not yet" and need follow-up tickets; the concept's
  "retention per organization" is only true for the organization's own stores until per-organization WORM
  retention exists.
- Follow-ups: per-organization WORM retention (extend-only); purge of `action` and operational history after the
  WORM retention; escrow of retired devices (open question 1 of the plan); on-device self-information file
  (`/usr/share/doc/paddock/what-is-collected`, AUD-11 e); legal hold (AUD-18) would suspend the purges per
  organization. Re-evaluate when the first customer's contractual period differs from 400 days or when an
  erasure request cannot be answered by restriction.

## Amendment 2026-10-17 (ADR 0037, plan M8d) — login history and hardware facts

Two rows join the retention matrix of decision 1:

| Store | Data class | Content (personal data) | Retention | Legal basis (GDPR) | Purge (role, event) | Configurable |
| --- | --- | --- | --- | --- | --- | --- |
| `device_login_event` (ADR 0037 decision 6) | Employee login history | Username, device, time of every session start | `login_history_days` (7–365, default 90) after the login; **off by default** (`login_history_enabled`); disabling deletes every row at once | Art. 6(1)(f) with the organization's works council agreement; Art. 88 | Worker, every 6 h; `retention.purged` (store `device_login_event`, per organization, only when rows were deleted); until M10's retention round exists, its own round with the same lock pattern | **Now** (`settings.login`) |
| Hardware facts in `device_inventory_ref` (ADR 0037 decision 7) | Device data (asset) | Vendor, model, serial number, CPU, memory size, disk size | As the inventory of the device: while active, and `retired_inventory_days` after retirement (same row as the inventory reference) | Art. 6(1)(f) (asset management, theft reports) | The inventory purge of retired devices (M10, `device.inventory_purged`) | With `retired_inventory_days` |

`device_user_seen` is unchanged (fixed 365 days, lock coverage). An uninstall (ADR 0037 decision 4) retires the
device; the escrowed secrets of the retired device stay as in the row "Escrowed secrets of retired devices".
