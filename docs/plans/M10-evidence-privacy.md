# Implementierungsplan: M10 — Evidence and privacy (retention, purge jobs, privacy pack, evidence export, read-access audit)

Status: Ready for implementation · 2026-10-16 · Author: architect
Basis: ADR 0032 (retention and deletion; accepted), ADR 0010 (audit pipeline, recording day), ADR 0002 (RLS,
scheduler iterates organizations), ADR 0017 (object store), ADR 0018 (lists and dialogs); roadmap M10 (AUD-01,
AUD-07, AUD-10, AUD-11, G5, G6; sysadmin F-24 partly); plan M3a decision 10 (`app.SeenWindow`), plan M5a decisions
6–7 (inventory tables), plan M5b decision 10 (staleness round as the pattern of a worker round), plan M6c (paddockctl).

Binding language: **MUST** / **MUST NOT** / **SHOULD** / **MAY**.

Parallel plans: M8b (document corrections G1–G6, event gap, nightly chain verification with an auditor-visible status,
role-group audit, clock drift), M9 (notifications, finding handling, cursor feed; ADR 0031), M11 (safe configuration
changes; ADR 0033). This plan's steps 1–7 (PDK-135 to PDK-141) depend on none of them. Steps 8–14 (the evidence
export) reuse `auditwriter.Verifier` as it exists today; where M8b adds a nightly verification status, the export's
`verification` block of §6.5 is the per-range result of the same verifier plus M8b's nightly runs of the range
(`audit_verification_run`, PDK-109). The audit writer's own events (purge, export) are recorded through M8b's
`auditwriter.Recorder` (PDK-109: event first, then row; params capped at 50 × 500 characters) — this plan adds no
second mechanism; PDK-140 and PDK-143 therefore start after PDK-109 is merged. The order of `events.jsonl` (§6.5)
is the evidence order (manifest day, object key, line order); M9's `commit_seq` (PDK-120) is an index column that the
stored event JSON does not carry, so the package does not contain it — an auditor reconciles the feed and the package
by `event_id`.

## 1. Goal

After this milestone every store of Paddock has a documented retention with a legal basis (`docs/compliance/retention.md`),
the worker and the audit writer delete what has expired and leave an audit event as deletion evidence
(`device_user_seen`, inventory and Fleet hosts of retired devices, audit index partitions, evidence exports,
read-access windows), an organization administrator can configure the organization's privacy settings
(`/api/v1/settings/privacy`), the works council and the data protection officer receive four English templates under
`docs/compliance/privacy-pack/`, an `org_auditor` can request, download and offline-verify a signed evidence package
for a range of sealed days without a platform operator (`POST /api/v1/audit/exports`, `paddockctl audit verify-export`),
and reads of the audit log and of a device's inventory are recorded as audit events when the organization switches it
on.

## 2. Context

- The audit writer (`server/internal/auditwriter/`) writes events per organization as `org/<org>/YYYY/MM/DD/HH-<event_id>.jsonl.zst`
  (zstd-compressed JSON lines, one `audit.Event` per line, `encodeObject`/`DecodeObject` in `writer.go`), indexes them
  in `paddock_audit.audit_event` (partitioned monthly by `occurred_at`; `audit_ensure_partition` is a `SECURITY DEFINER`
  function run by `paddock_audit_writer`) and seals every recording day at 00:15 UTC (`sealer.go`: `Manifest`,
  `ManifestFile`, `CanonicalManifest`, `ManifestKey`, signed with the OpenBao Transit key `audit-chain`;
  `bao.Client.Sign` returns `Signature{Value: "vault:v<N>:<base64>", KeyVersion}`; `bao.Client.PublicKeys(ctx, key)`
  returns `map[int][]byte` raw ed25519 keys). `verify.go` (`Verifier.Verify(ctx, org, from, to) (*Report, error)`)
  checks the chain and every object hash for a range of days; `paddock-server audit verify` runs it in the
  audit-writer container. The writer's object store credential may `PutObject`, `PutObjectRetention`, `GetObject`,
  `ListBucket` on `paddock-audit`.
- The audit database roles (`deploy/compose/audit-postgres/init/10-roles.sh`): `audit_owner` (migrations),
  `paddock_audit_writer` (`SELECT, INSERT` on the three tables, `EXECUTE audit_ensure_partition`), `paddock_audit_reader`
  (`SELECT` on `audit_event` under the `reader` RLS policy; no grants on `audit_object`, `audit_manifest`). The api
  reaches the audit index through `db.AuditReader.InOrg` (`PADDOCK_AUDIT_DB_READER_URL_FILE`), the audit writer through
  `db.AuditWriterPool` (`InWriter`, `InWriterWithTimeout`, `WithSession`).
- `app.ActionRunner` (`server/internal/app/action.go`): `RunTx`, `RunTxRefusal`, `RunExternal`, `RecordOnce`
  (system principals only), `RecordOnceBatch`, `RecordOnceRefusal`, `RecordRejected`; `ActionSpec{Code, AllowedRoles,
  Target, Params, Actor, RequiresStepUp, CorrelationID}`; `Recorder{SetTarget, SetParam, SetOrganization, …}`. Role
  sets in `app.go`: `RolesRead` (admin, operator, auditor), `RolesWrite`, `RolesAdmin`, `RolesAudit` (admin, auditor),
  `RolesPlatform`. `app.RequireOrg(ctx, roles)` guards reads outside the runner.
- The worker round pattern: `server/internal/worker/staleness.go` (`NewStaleness`, `Run` with a ticker, `Round` under
  `PlatformPool.WithLeaderLock(sys, key, fn)`, `pool.OrganizationIDs`, `systemContext(ctx, org, correlation)` per
  organization). Jobs are wired in `server/cmd/paddock-server/worker.go` (`runAll(ctx, …, dms.Run, staleness.Run, …)`).
  The inventory round (`worker/inventory.go`, `app.NewInventorySync`) uses the port `ports.Inventory`
  (`server/internal/ports/inventory.go`), implemented by `adapters/fleet.Client` (`hosts.go`: `do(ctx, method, path,
  in, out)`).
- `device_user_seen` (migration `00007_identity.sql`): `(organization_id, device_id, username, last_seen_at)`,
  upserted by `app/devicereports.go` from `session.login` events, read by `app/identity.go` `LoadIdentity` with
  `SeenWindow = 365 * 24 * time.Hour`. Grants: `paddock_worker` has `SELECT, INSERT, UPDATE` (no `DELETE`).
- Inventory tables (migration `00024_inventory.sql`): `device_inventory_ref` (`external_id` = Fleet host ID),
  `installed_software`, `vulnerability_finding`, `inventory_policy_result`; `paddock_worker` has `SELECT, INSERT,
  UPDATE, DELETE`, RLS `tenant` policy. A retired device keeps its last inventory; nothing deletes its Fleet host.
- Settings pattern: `organization_update_settings` (migration `00025_updates.sql`, default row per organization by
  trigger as in `organization_login_settings_default`), `GET`/`PUT /api/v1/settings/updates` (`x-paddock-audit:
  settings.updates_changed`, `app.SpecUpdateSettings`, `handlers_updates.go`, portal `views/UpdateSettings.vue`,
  route `/settings/updates`, nav group `organization` in `web/src/lib/navigation.ts`), section `settings.updates` of
  `api/schema/paddock.v1.json` and the declarative apply (`app/config*.go`).
- Audit list: `app/auditlog.go` (`AuditLog.List`, `AuditQuery`, 92-day cap), handler `admin/handlers.go`
  `ListAuditEvents`, portal `views/Audit.vue` with `components/AuditEventList.vue`. Inventory lists:
  `admin/handlers_inventory.go` (`ListDeviceSoftware`, `ListDeviceVulnerabilities`).
- Audit codes: closed registry `server/internal/domain/audit/codes.go` (`Definition{Code, Description, Params,
  Outcomes, Emitted, Note}`, `adminOutcomes`); `make gen` renders `docs/compliance/audit-codes.md`; the portal
  localizes `audit.<code>` in `web/src/locales/en.json` and `de.json`.
- Acceptance: every `/api/v1` operation needs a fixture in `test/acceptance/isolation_fixtures.go` (gate
  `TestOrganizationIsolation` fails otherwise); every collection `GET` is checked by `TestListContract`
  (`x-paddock-list`); `stack.PaddockServer(ctx, args…)` runs `paddock-server` in the audit-writer container;
  `env.Bob` is the acme **auditor**, `env.Alice` an acme admin, `env.Carol` a globex admin; `tempUser(t, name,
  env.RoleGroup(slug, "auditors"))` creates an auditor; `devicesim.Device.SendEvents` reports device events;
  `test/acceptance/fleethost.go` registers a simulated Fleet host; `TestPaddockctl` runs `bin/paddockctl` from
  `PADDOCK_ACCEPTANCE_PADDOCKCTL`.
- `pkg/` keeps an import allow list (standard library and `github.com/gowebpki/jcs`; `pkg/imports_test.go`);
  `pkg/canonicaljson` has `Transform(doc []byte) ([]byte, error)` and `Marshal(v any) ([]byte, error)`. The `cli`
  module (`cli/go.mod`) depends on `github.com/oasdiff/yaml` only; `cli/internal/cmd/cmd.go` dispatches
  subcommands (`dispatch`), exit codes 0/1/2/3 (`docs/operations/paddockctl.md`).
- `prodcheck` refuses development-only variables listed in `server/internal/prodcheck/prodcheck.go` line 124
  (`PADDOCK_STALENESS_UNIT`, …). `compose.dev.yaml` sets them for the development stack.

## 3. Binding decisions

### 3.0 Cross-plan rules

- **Migration numbers.** M8b uses control-plane `00045` and audit `00004`; M11 uses control-plane `00045`–`00049`.
  Every migration of this plan is written as `NNNNN_<name>.sql`: the implementer takes the **next free number** of
  the directory at the time of the ticket (`ls server/migrations/paddock | tail -1`) and never renumbers an existing
  file. The order of creation within this plan is fixed: paddock `privacy_settings` → `retention_grants` →
  `read_audit_window` → `change_set_before_purge`; audit `index_purge` → `audit_exports`. A migration MUST NOT be
  merged while a lower-numbered migration of another plan is still open on `main` with the same number (rebase and
  take the next number).
- **M8b (ADR 0030, `docs/plans/M8b-evidence-integrity.md`)** adds `audit_verification_run` and reader policies on
  `audit_manifest`, the endpoints `GET /api/v1/audit/integrity`, `/api/v1/audit/verification-runs`,
  `/api/v1/audit/manifests`, and the tables `organization_role_member`, `platform_role_member`,
  `device_event_dropped`, `device_event_gap`. This plan's export (§6.5) carries the nightly verification runs of the
  range from `audit_verification_run` (decision 32) and creates the reader policy on `audit_object` only when it is
  missing (§6.2 `DO` block); the policy on `audit_manifest` comes from M8b. The retention of M8b's tables is in ADR
  0032 §1 (kept for the WORM retention; no purge in this milestone).
- **M11 (ADR 0033, `docs/plans/M11-safe-config.md`)** adds `change_set.before` (managed file contents before a
  change), `change_set.before_purged_at` (the worker holds `UPDATE` on `change_set`), `device_bundle_report` and
  `device_resource_status`. This plan owns their periods (ADR 0032 §1) and the purge of `change_set.before`
  (decision 15a): when M11's columns do not exist yet at the time of PDK-137, PDK-137 ships without the
  `change_set.before` pass and PDK-147 adds it (stop condition: never add the columns from this plan).

### 3.1 Retention documents (PDK-135)

1. `docs/compliance/retention.md` (new) MUST contain: the retention matrix of ADR 0032 §1 verbatim as a table (same
   columns), a section "Deletion evidence" naming the codes `retention.purged` (params `store`, `deleted`, `cutoff`,
   `partition`) and `device.inventory_purged`, how to list them (`GET /api/v1/audit-events?code=retention.purged`),
   a section "Deletion lag" (backups up to 30 days, RR-35), a section "Erasure requests" (restriction instead of
   deletion for WORM evidence, Art. 17(3)(b)/(e)), and a section "What is not purged yet" listing the rows of the
   matrix whose purge column says "None in this milestone".
2. `docs/compliance/privacy.md` MUST change: the sentence "reading it is not audited" (inventory) becomes "reading
   it is recorded as `device.inventory_viewed` when the organization switches *Record inventory views* on
   (`/api/v1/settings/privacy`), coalesced per administrator, device and day"; the `session.login` row's "Stored"
   cell gains "kept 365 days after the last login (ADR 0032)"; the fleetd section gains "Inventory of a retired device
   is deleted, in Paddock and in Fleet, `retired_inventory_days` after retirement (default 30)"; the Administrators
   section gains "Searches of the audit log are recorded as `audit.searched` when the organization switches it on;
   evidence exports are always recorded (`audit.export_requested`, `audit.export_downloaded`)" and the retention
   pointer `docs/compliance/retention.md`.
3. `docs/compliance/iso27001-mapping.md` MUST gain the rows **A.5.28 Collection of evidence** (feature: signed
   evidence package per range of sealed days, offline verifier `paddockctl audit verify-export`; evidence:
   `audit.export_*` events, the package's `export.json`; duty: record the `audit-chain` key fingerprint from the
   *Evidence exports* page in the ISMS and hand it to the auditor out of band), **A.5.34 Privacy and protection of
   PII** (feature: negative list, retention matrix, purge jobs with deletion evidence, privacy settings, read-access
   recording, privacy pack; evidence: `retention.md`, `retention.purged`, `device.inventory_purged`,
   `settings.privacy_changed`; duty: complete the privacy pack, decide the read-access switches with the works
   council) and **A.8.10 Information deletion** (feature: the purge jobs; evidence: the deletion events; duty: add the
   WORM lifecycle rule, set `retired_inventory_days`, keep backup expiry at 30 days or document a different value).
   The A.5.33 row's duty cell MUST add "set `PADDOCK_AUDIT_INDEX_RETENTION_DAYS` if the index is to outlive the
   bucket's lifecycle rule".
4. `docs/compliance/residual-risks.md` MUST gain, in section "Control plane and audit domain": `RR-35` **Deletion
   lag in backups** (purged rows survive in backups up to 30 days; mitigation: encrypted backups, expiry; duty:
   state the lag in the privacy notice), `RR-36` **Evidence export is an egress of personal data** (a package holds
   every event of the range with names and addresses; mitigation: step-up, purpose field, audited request and every
   download, 7-day expiry; duty: handle packages as confidential, hand over through an agreed channel) and `RR-37`
   **Index purge equals WORM expiry** (the index is purged when the WORM retention has lapsed, so the portal can show
   nothing the bucket no longer holds; mitigation: `PADDOCK_AUDIT_INDEX_RETENTION_DAYS` may be longer; duty: align the
   lifecycle rule with it).
5. `docs/compliance/README.md` MUST list `retention.md` and `privacy-pack/` (one row each). `docs/operations/audit-bucket.md`
   section 3 MUST gain two bullets: the nightly index purge (`PADDOCK_AUDIT_INDEX_RETENTION_DAYS`, `paddock-server
   audit purge --dry-run`) and the evidence exports (built on the audit host, 7-day expiry, never in the bucket).
6. `docs/architecture.md` MUST gain an appended block `> **Amendment 2026-10-16 (M10, ADR 0032):**` at the end of
   §14.4 stating: one platform-wide WORM retention today, per-organization retention planned (extend-only); the audit
   index is purged by partition after `PADDOCK_AUDIT_INDEX_RETENTION_DAYS`; exports are built by the audit writer and
   stored in the index database; and at the end of §16.1 listing the new tables `organization_privacy_settings`,
   `read_audit_window` (paddock) and `audit_export`, `audit_export_chunk`, `audit_signing_key` (paddock_audit). No
   other line of `docs/architecture.md` changes in this milestone (M8b corrects G5/G6 wording).

### 3.2 Privacy settings (PDK-136)

7. Migration `server/migrations/paddock/NNNNN_privacy_settings.sql` MUST be §6.1 verbatim.
8. `GET`/`PUT /api/v1/settings/privacy` per §6.3 (`PrivacySettings`, `PrivacySettingsUpdate`); `PUT` is
   `x-paddock-audit: settings.privacy_changed`, role `org_admin` (`app.SpecPrivacySettings = ActionSpec{Code:
   audit.CodeSettingsPrivacyChanged, AllowedRoles: RolesAdmin}`), no step-up; `GET` roles `org_admin`, `org_operator`,
   `org_auditor`. Validation: `retired_inventory_days` outside 1–365 → `400 invalid_request`. The event params are
   the three new values.
9. `api/schema/paddock.v1.json` MUST gain `settings.privacy` (`$defs/privacySettings`: the three fields, all required
   when present, same constraints) and the declarative apply MUST treat it exactly like `settings.updates` (plan
   lines `~ settings.privacy retired_inventory_days: 30 -> 14`; `paddockctl get config` exports it).
10. Portal: view `web/src/views/PrivacySettings.vue`, route `/settings/privacy` (name `privacy-settings`), nav item
    `{ to: '/settings/privacy', label: 'nav.privacySettings', icon: 'shield', visible: orgReader }` after
    `nav.updateSettings` in group `organization`; a form with a number field and two switches, help text per field
    from the i18n catalog, save through the generated client, success snackbar, inline error; read-only for
    operators and auditors. Keys in `en.json` and `de.json`.

### 3.3 Worker retention round (PDK-137, PDK-138)

11. Migration `NNNNN_retention_grants.sql` MUST be exactly: the header comment, `-- +goose Up`, `GRANT DELETE ON
    device_user_seen TO paddock_worker;`, `-- +goose Down`.
12. `app.Retention` (new file `server/internal/app/retention.go`) and `worker.Retention` (new file
    `server/internal/worker/retention.go`) per §6.6. The round runs at start and every `PADDOCK_RETENTION_INTERVAL`
    (`config.Loader.Duration`, default `6h`) under the leader lock `retentionLockKey = 0x7061646420726574`, iterates
    `pool.OrganizationIDs`, and for every organization calls, in this order, `PurgeUserSeen`, `PurgeReadWindows`
    (PDK-139; a no-op until the table exists is NOT allowed — PDK-139 adds the call), `PurgeRetiredInventory`
    (PDK-138). A failing organization does not stop the others (`errors.Join`).
13. `PurgeUserSeen` deletes rows with `last_seen_at < now − app.SeenWindow` in batches of at most 1 000 rows
    (`DELETE … WHERE ctid IN (SELECT ctid FROM device_user_seen WHERE last_seen_at < @cutoff LIMIT 1000)` as query
    `DeleteExpiredDeviceUserSeen :execrows` in `queries/login.sql`), repeating until a batch deletes fewer than 1 000.
    It records exactly one `retention.purged` event per organization and round **only when** the total is > 0 or a
    batch failed (`RunTx` with `ScopeOrg`, the deletion batches inside `fn`; a failure after some batches records
    `failure` with `deleted` = the rows of the batches that committed — every batch runs in its own `RunTx`? No:
    **all batches of one organization run inside one `RunTx`** so that the event and the deletion commit together;
    the 1 000-row batching limits lock scope, not transactions). Params: `store: "device_user_seen"`, `deleted`,
    `cutoff` (RFC 3339).
14. Development unit: `PADDOCK_RETENTION_UNIT` (`days` default, `seconds` allowed only with
    `PADDOCK_ENV=development`; the loader MUST `Invalid` any other value and `seconds` outside development). With
    `seconds`, every period of the round (`SeenWindow`, `retired_inventory_days`, the 48 h window) counts days as
    seconds. `compose.dev.yaml` MUST set `PADDOCK_RETENTION_UNIT: ${PADDOCK_RETENTION_UNIT:-seconds}` and
    `PADDOCK_RETENTION_INTERVAL: ${PADDOCK_RETENTION_INTERVAL:-15s}` on `paddock-worker`; `prodcheck.go` line 124
    MUST list `PADDOCK_RETENTION_UNIT` among the development-only variables; `prod.env.example` and
    `lab.env.example` do not mention it.
15. Metrics (worker): `paddock_retention_last_success_timestamp_seconds{store}` (set after each successful store
    pass over all organizations; stores `device_user_seen`, `read_audit_window`, `retired_inventory`),
    `paddock_retention_deleted_total{store}`, `paddock_retention_stores` (constant 3). Alert
    `PaddockRetentionPurgeStale` (critical): any store's last success older than 48 h for 1 h, plus the
    `…Missing` pattern (`count(paddock_retention_last_success_timestamp_seconds) < paddock_retention_stores` for 1 h,
    warning). `docs/operations/monitoring.md` tables gain both and the metrics row.
15a. `PurgeChangeSetBefore` (decision 12's round, fourth pass; PDK-137 or PDK-147 per §3.0): per organization,
    `UPDATE change_set SET before = NULL, before_purged_at = now() WHERE before IS NOT NULL AND before_purged_at IS
    NULL AND applied_at < now − ChangeSetBeforeRetention` in batches of 1 000 (`PurgeChangeSetBefore :execrows` in
    `queries/change_set.sql`); `ChangeSetBeforeRetention = 90 * 24 * time.Hour` (ADR 0032 §1: before-states hold
    full managed file contents and serve M11 revert; 90 days covers a quarter of change control). One
    `retention.purged` with `store: "change_set_before"` per organization and round when > 0. The migration
    `NNNNN_change_set_before_purge.sql` of this plan contains only `GRANT UPDATE (before, before_purged_at) ON
    change_set TO paddock_worker;` **when** M11's migration did not grant it already (the implementer checks; if M11
    granted `UPDATE` on the table, this migration is not created). Store `change_set_before` is the fourth value of
    `paddock_retention_stores` (then constant 4).
16. `PurgeRetiredInventory` (PDK-138): per organization, read `retired_inventory_days` from
    `organization_privacy_settings`; select devices `state = 'retired' AND state_changed_at < now − days` that still
    have a `device_inventory_ref` row or any `installed_software`, `vulnerability_finding`, `inventory_policy_result`
    row (query `ListRetiredDevicesWithInventory :many` in `queries/inventory.sql`, at most 100 per round per
    organization). For every device, one `RunExternal` with `ScopeOrg`, spec `device.inventory_purged`, target the
    device: `prepare` locks the device row and reads the counts and the `external_id`; `external` calls
    `InventoryAdmin.DeleteHost(ctx, ref)` when a ref exists (a 404 from Fleet counts as deleted); `finalize` deletes the
    four tables' rows of the device and sets params `hostname`, `retired_at`, `software`, `findings`,
    `policy_results`, `fleet_host_deleted` (bool). When `DeleteHost` fails, finalize MUST NOT delete the Paddock rows
    (the event records `failure` with `error_code: upstream_unavailable`; the device is retried next round).
17. `ports.InventoryAdmin` and `fleet.Client.DeleteHost` per §6.6; `DELETE /api/v1/fleet/hosts/{id}`; a 404 returns
    nil. The fake inventory of `adapters/fleet/fake_test.go` and `worker/inventory_test.go` gains `DeleteHost`.

### 3.4 Read-access recording (PDK-139)

18. Migration `NNNNN_read_audit_window.sql` MUST be §6.1 verbatim. `ActionRunner.RecordReadOnce` per §6.6:
    authorization as in `RunTx` (denied is recorded), then one `OrgPool.InOrg` transaction in which `claim` runs
    first; `claim` returns `false` when the window key already existed, and then **nothing** is inserted into
    `action` or `outbox`; `true` records the event with outcome `success` in the same transaction. A `claim` error
    rolls back and records `failure` as `RunTx` does.
19. `app.ReadAudit` per §6.6. `AuditSearched` reads `organization_privacy_settings.audit_search_recorded` inside the
    claim transaction (query `GetPrivacySettings :one`); when false it returns `false, nil` without recording; the
    window key is `(actor key, "audit.searched", "", now.UTC().Truncate(time.Hour))`; params: `from`, `to` (RFC 3339
    of the effective range), `codes`, `outcomes`, `actor_types` (arrays, omitted when empty), `target_id` (omitted when
    nil), `q_used` (bool), `window_start`. The actor key is `principal.ID` (account ID; for an API token the token ID).
    `InventoryViewed` checks `inventory_view_recorded`; key `(actor key, "device.inventory_viewed", device ID,
    dayOf(now))`; params `hostname`, `view` (`software` or `vulnerabilities`), `window_start`; target the device.
20. Handlers: `ListAuditEvents` MUST call `h.readAudit.AuditSearched(ctx, query)` **before** `h.audit.List` and return
    its error (a denied role is recorded and refused); `ListDeviceSoftware` and `ListDeviceVulnerabilities` call
    `InventoryViewed` before the list. `GET /api/v1/devices/{id}/audit` does not exist; the device audit tab uses
    `target_id`, which `AuditSearched` records.
21. `PurgeReadWindows` (decision 12) deletes `read_audit_window` rows with `window_start < now − 48 h` in one
    statement per organization; `retention.purged` with `store: "read_audit_window"` only when > 0.

### 3.5 Audit index purge (PDK-140)

22. Audit migration `server/migrations/audit/NNNNN_index_purge.sql` MUST be §6.2 verbatim (function
    `audit_purge_partition`). `auditwriter.Purger` per §6.6: `Run(ctx, now, dryRun)` lists the partitions of
    `audit_event` (`SELECT inhrelid::regclass::text FROM pg_inherits WHERE inhparent = 'audit_event'::regclass` as
    query `ListAuditPartitions :many`), parses the month from the name `audit_event_YYYY_MM`, computes
    `cutoff = now − indexRetentionDays` and, for every partition whose month end is before `cutoff`, calls
    `audit_purge_partition(month, cutoff)` in its own `InWriter` transaction (`SET LOCAL lock_timeout = '5s'` first;
    a lock timeout is reported as `Reason: "lock_timeout"` and retried next night). In dry-run mode it only reports.
    For every **dropped** partition it records `retention.purged` through `RecordSelf` in the platform
    pseudo-organization (`audit.PlatformOrganizationID`) with params `store: "audit_index"`, `partition`,
    `deleted` (events), `cutoff`; a failed drop records `failure` with `error_code: "purge_failed"`. "Records" means
    `auditwriter.Recorder.Record` of M8b (PDK-109) with a one-event report; `RecordSelf` below is the name of the thin
    helper the purger and the exporter call, implemented on top of that recorder (not a second write path).
23. `PADDOCK_AUDIT_INDEX_RETENTION_DAYS` (`loadAuditDeps`): default `PADDOCK_AUDIT_RETENTION_DAYS`; a value below it
    is `Invalid`. `RunDaily` of the purger fires at 01:15 UTC (`PurgeDelay = 75 * time.Minute`, same loop shape as
    `Sealer.RunDaily`; after the seal at 00:15 and M8b's nightly verification at 00:45); `serveAuditWriter` adds it to `runAll`. CLI: `paddock-server audit purge [--dry-run]` prints
    one line per partition `DROP audit_event_2025_01: 12345 events` / `KEEP audit_event_2026_09: <reason>` and
    `nothing to purge` when no partition qualifies; exit 1 when a drop failed.
24. `RecordSelf(ctx, rec *Recorder, ev audit.Event) error` (file `selfevent.go`) fills `Schema`, `EventID` (`uuid.NewV7`),
    `OccurredAt` (now), `Source: audit.SourceSystem`, `Actor{Type: audit.ActorSystem, Display: "audit-writer"}` when
    empty, validates (`Validate`) and hands the event to M8b's `auditwriter.Recorder` (PDK-109), which writes it
    through `WriteBatch`. It MUST NOT be called inside an `InWriter` transaction. If PDK-109 is not merged when
    PDK-140 starts: stop (§12).
25. Metrics (audit writer): `paddock_audit_index_purge_last_success_timestamp_seconds`,
    `paddock_audit_index_partitions_dropped_total`; alert `PaddockAuditIndexPurgeStale` (warning, > 48 h for 1 h);
    `monitoring.md` rows.

### 3.6 Privacy pack (PDK-141)

26. Four files under `docs/compliance/privacy-pack/`, English, each starting with the banner
    `> Template. Not legal advice. Complete the fields in [brackets] and have your data protection officer and works
    council review the result. Facts about Paddock in this document are taken from docs/compliance/privacy.md and
    docs/compliance/retention.md as of <version>.`:
    - `transparency-notice.md` (GDPR Art. 13 employee notice): controller `[Organization]`, DPO contact, purposes
      (device management, security, evidence), the data categories per the `privacy.md` tables, the negative list
      verbatim, recipients (platform operator `[Operator]`, Fleet as a component, SIEM/SOC `[if configured]`), retention
      per the matrix (numbers, not prose), rights (access, rectification, restriction instead of erasure for evidence),
      the fact that reads of inventory and audit log are `[recorded | not recorded]` per the organization's setting,
      the dead man's switch `[enabled: period | disabled]`, and a "How to see what Paddock knows about you" paragraph
      (ask the administrator for the device page and the audit events with your username).
    - `record-of-processing.md` (Art. 30(1) input): one table per processing activity — *Device management*,
      *Identity and login*, *Privileged access (sudo)*, *Disk encryption and escrow*, *Inventory and vulnerabilities*,
      *Audit trail*, *Administrator access* — with columns purpose, data subjects, data categories, recipients,
      third-country transfer (`[none unless the operator hosts abroad]`), retention (matrix values), TOMs (pointer
      to `iso27001-mapping.md` rows), legal basis.
    - `dpia-input.md` (Art. 35 input): threshold assessment (systematic monitoring of employees → DPIA likely
      required), the risk list from the employee's perspective (RR-01, RR-06, RR-15, RR-20, RR-35, RR-36, and
      "behaviour evaluation through audit search" with the mitigation `audit_search_recorded`), likelihood/severity
      columns left as `[ ]`, mitigations from Paddock (negative list, coalesced read events, purge jobs, step-up,
      two administrators for Destroy) and the residual risks the organization accepts `[ ]`.
    - `works-council-annex.md` (BetrVG §87(1) Nr. 6 annex): exhaustive list of data and evaluations (every table of
      `privacy.md` plus the portal pages that show per-person data), permitted purposes, an explicit prohibition of
      performance and behaviour evaluation, roles with access (`org_admin`, `org_operator`, `org_auditor`,
      platform operator with what they cannot see), the configurable switches (`audit_search_recorded`,
      `inventory_view_recorded`, dead man's switch, `retired_inventory_days`) with the agreed values `[ ]`, deletion
      periods (matrix), the change procedure (a new data category or a changed switch = annex change; Paddock records
      `settings.privacy_changed`), and the employee's information rights.
27. `docs/compliance/README.md` MUST describe the pack as "templates the operator completes; not legal advice".

### 3.7 Evidence export: data model and request API (PDK-142)

28. Audit migration `NNNNN_audit_exports.sql` MUST be §6.2 verbatim. OpenAPI per §6.3 (`/api/v1/audit/exports`
    `GET` list contract and `POST`, `/api/v1/audit/exports/{id}` `GET`). Problem codes (`server/internal/problem/problem.go`):
    `DayNotSealed = &Error{Code: "day_not_sealed", Status: 422}`, `TooManyExports = &Error{Code:
    "too_many_exports", Status: 409}`, `ExportNotReady = &Error{Code: "export_not_ready", Status: 409}`.
29. `app.AuditExports` per §6.6. `Request` runs `runner.RunExternal(ctx, ScopeOrg, spec, prepare, external, finalize)`
    with `spec = SpecAuditExportRequest` (`Code: audit.CodeAuditExportRequested, AllowedRoles: RolesAudit,
    RequiresStepUp: true`): `prepare` validates (`from_day ≤ to_day` else `400 invalid_request`; `to_day − from_day`
    ≤ 400 days else `400 range_too_large`; `purpose` 1–500 characters after trimming else `400 invalid_request`) and
    sets params `export_id` (a new UUIDv7), `from_day`, `to_day`, `purpose`; `external` runs one
    `reader.InOrg` transaction on the audit database: `to_day` has a manifest (`GetAuditManifest`) else
    `422 day_not_sealed`; `from_day` has a manifest **or** is before the organization's first manifest day
    (`FirstAuditManifestDay :one`) — no: `from_day` MUST have a manifest else `422 day_not_sealed` (a range before
    the first sealed day is not evidence); pending+running exports of the organization < 3
    (`CountOpenAuditExports :one`) else `409 too_many_exports`; then `InsertAuditExport` with status `pending`,
    `requested_by` = the principal as `audit.Actor` without `IP`, `correlation_id` = the action's correlation ID;
    `finalize` does nothing but keep the params. A validation error in `external` is a `problem.Error` and is
    recorded as `denied`/`failure` per the runner's rules. `Get` and `List` run under `RequireOrg(ctx, RolesAudit)`
    through `reader.InOrg`; `List` follows ADR 0018 (`listing.Parse` with the spec `auditExportList`; sort allow list
    `requested_at`, `status`, `from_day`, `to_day`; search over `purpose` and `requested_by->>'display'`; filter
    `status` repeatable).
30. Fixtures: `isolation_fixtures.go` gains the three operations (a pending export of acme as the fixture object);
    `list_contract_test.go` needs no parent for `/api/v1/audit/exports`. The handler file is
    `admin/handlers_auditexports.go`.

### 3.8 Export builder in the audit writer (PDK-143)

31. `auditwriter.Exporter` per §6.6, started by `serveAuditWriter` (`exporter.Run`). `Run` polls every
    `PADDOCK_AUDIT_EXPORT_POLL_INTERVAL` (`Duration`, default `30s`; `compose.dev.yaml` sets `2s`): claims the oldest
    pending export (`ClaimPendingAuditExport :one`: `UPDATE audit_export SET status='running', started_at=now()
    WHERE id = (SELECT id FROM audit_export WHERE status='pending' ORDER BY requested_at LIMIT 1 FOR UPDATE SKIP
    LOCKED) RETURNING *`) and calls `Build`. Then `Expire(ctx, now)` (decision 34).
32. `Build(ctx, export)` MUST produce the package of §6.5 in this order and streaming: (1) list the manifests of
    `[from_day, to_day]` from the index (`ListAuditManifests`); a day without a manifest fails the build
    (`error: "day <d>: no manifest"`); (2) run `Verifier.Verify(ctx, org, from_day, to_day)`; the build continues when
    the report has problems (they go into `export.json.verification.problems`; `verify_ok` is false) — the auditor must
    see a broken chain, not an error; (2a) read M8b's `audit_verification_run` rows of the organization whose verified
    range overlaps `[from_day, to_day]` (`ListAuditVerificationRunsOverlapping :many`, newest first, at most 100) and
    put them into `export.json.verification.runs` (§6.5 `Run`: `run_id`, `started_at`, `from_day`, `to_day`, `ok`,
    `problems`); when the table does not exist yet (M8b not merged), `runs` is `[]` and the ticket reports it; (3) open a temp file (`os.CreateTemp` in `os.TempDir()`, removed in a `defer`)
    for `events.jsonl`; (4) write the tar through `chunkWriter` (8 MiB rows, each `InsertAuditExportChunk` in its own
    `InWriterWithTimeout(ctx, 2*time.Minute)` transaction, running SHA-256 over the whole stream): `README.md`
    (§6.5 text verbatim), then for every day in order `manifests/<day>.json` = the stored manifest object bytes
    verbatim (`store.Get(ManifestKey)`), then for every object of the day's manifest in key order
    `objects/<key without "org/<org>/">` = the stored bytes verbatim (hash checked against the manifest entry; a
    mismatch is added to `verification.problems` as `"<day>: object <key> was modified (SHA-256 mismatch)"` and the
    object is still included), each object decoded (`DecodeObject` is NOT used: the raw decompressed bytes are
    appended to the temp file so that `events.jsonl` is byte-identical to the concatenation) while counting lines;
    then `events.jsonl` from the temp file; then `export.json` (canonical bytes of §6.5, built from everything
    collected); then `export.sig` (§6.5). (5) `UpdateAuditExportReady` sets status `ready`, `ready_at`, `expires_at =
    ready_at + ExportTTL`, `event_count`, `object_count`, `size`, `package_sha256`, `verify_ok`, `verify_problems`,
    `signature`, `key_version`. Any error: delete the chunks, status `failed`, `error` = the message (at most 500
    characters, no secrets). (6) `RecordSelf` of `audit.export_completed` in the export's organization: outcome
    `success` or `failure`, target `{type: "audit_export", id}`, params `export_id`, `from_day`, `to_day`, `days`,
    `objects`, `events`, `size`, `package_sha256` (hex), `verify_ok`, `key_version`, `error` (failure only),
    `error_code: "export_failed"` on failure; `CorrelationID` = the export's `correlation_id`.
33. The signature: `signer.Sign(ctx, SigningKey, sum[:])` where `sum = sha256(canonical export.json)`; the keys
    embedded in `export.json` are `keys(ctx)` (`bao.PublicKeys(ctx, "audit-chain")`), all versions.
34. `Expire(ctx, now)`: exports with status `ready` and `expires_at < now` → delete their chunks
    (`DeleteAuditExportChunks`), status `expired`; exports `running` with `started_at < now − 2 h` → status `failed`,
    `error: "exporter restarted"`, chunks deleted. For every expired export one `RecordSelf` of `retention.purged` in
    the export's organization with params `store: "audit_exports"`, `deleted: 1`, `export_id`, `cutoff`. Metrics:
    `paddock_audit_export_total{result}` (`ready`, `failed`, `expired`), `paddock_audit_export_pending_age_seconds`
    (age of the oldest pending export, 0 when none), `paddock_audit_export_build_seconds` (histogram). Alerts:
    `PaddockAuditExportFailed` (warning: `increase(paddock_audit_export_total{result="failed"}[1h]) > 0`),
    `PaddockAuditExportStuck` (warning: pending age > 3 600 s for 10 min).

### 3.9 Download, signing keys, portal (PDK-144, PDK-148, PDK-145)

35. `GET /api/v1/audit/exports/{id}/download` (§6.3): roles `org_admin`, `org_auditor`; `404 not_found` for an
    unknown or foreign export; `409 export_not_ready` unless status is `ready`; records `audit.export_downloaded`
    (`RunTx`, `ScopeOrg`, params `export_id`, `from_day`, `to_day`, `size`, `package_sha256`) **before** streaming;
    then streams the chunks in `seq` order inside one `reader.InOrg` transaction with `Content-Type:
    application/x-tar`, `Content-Length: <size>`, `Content-Disposition: attachment; filename="<name>"` where
    `<name> = paddock-audit-export-<organization slug>-<from_day>_<to_day>-<first 8 hex of id>.tar`, and
    `X-Paddock-Package-SHA256: <hex>`. The handler returns the generated strict-server response type for a binary
    body (`io.Reader` + `ContentLength`); the implementer verifies the generated name after `make gen`.
36. `audit_signing_key` upkeep (PDK-148): after every successful `Sign` in `sealDay` and in `Build`, the audit writer
    calls `EnsureAuditSigningKey(key_version, public_key)` (`INSERT … ON CONFLICT DO NOTHING`) with the key from
    `bao.PublicKeys` (cached per process for 10 minutes). `GET /api/v1/audit/keys` (§6.3) returns every row
    with `fingerprint` = lowercase hex SHA-256 of the raw 32-byte public key; roles `org_admin`, `org_auditor`.
    `paddock-server audit keys` prints `audit-chain v<N> <fingerprint>` per version from OpenBao (the ISB's
    out-of-band copy).
37. Portal (PDK-145): view `web/src/views/AuditExports.vue`, route `/audit/exports` (name `audit-exports`), nav
    item `{ to: '/audit/exports', label: 'nav.auditExports', icon: 'file-check', visible: (a) => a.canReadAudit }`
    directly after `nav.auditIntegrity` (M8b, PDK-110; after `nav.audit` if that item does not exist yet); a button
    *Evidence exports* in the toolbar of `views/Audit.vue` linking there, and a link on `views/AuditIntegrity.vue` when
    it exists. The
    page: a `DataList` (columns requested, range, status chip, purpose, requested by, size, chain status
    (`verify_ok`: *intact* / *problems* with the problems in a tooltip or expandable row), actions: *Download* when
    ready — an anchor to the download URL, which the browser fetches with the session cookie); a *New export* dialog
    (from/to date fields, default range the last 365 days ending yesterday, purpose text field, explanatory text that
    the request needs a step-up and is recorded) that starts the step-up exactly as `DiskEncryptionCard.vue` does
    (`startStepUp`/`resumeStepUp` of `web/src/lib/stepUp`) and posts after returning; a card *Signing keys* listing
    `key_version` and `fingerprint` from `/api/v1/audit/keys` with the text "Compare with the fingerprint your
    ISMS recorded". Errors `day_not_sealed`, `too_many_exports`, `range_too_large`, `step_up_required` as inline
    alerts with their own messages. Keys in `en.json` and `de.json`; audit code messages for the eight new codes in
    both catalogs. Playwright spec `web/e2e/auditExports.spec.ts`: as Bob (auditor) the page lists exports, the
    *New export* dialog validates the range, the keys card shows at least one fingerprint; creating an export with
    step-up is exercised when the e2e step-up helper of `revocation.spec.ts` supports Bob, otherwise the spec asserts
    the dialog and the step-up redirect start only.

### 3.10 Offline verifier (PDK-146)

38. `pkg/auditevidence` (new package, standard library + `pkg/canonicaljson` only) per §6.7: the types of
    `export.json` and of a manifest file, `Fingerprint`, `VerifySignature`, `ExportDigest`, `ManifestDigest`. The
    server's exporter MUST use these types for `export.json` (the server keeps its own `auditwriter.Manifest` types
    for sealing; the JSON of both is identical, enforced by `TestManifestTypesAgree` in `auditwriter` that marshals
    one manifest through both and compares the bytes).
39. `paddockctl audit verify-export <file> [--fingerprint <hex>] [-o text|json]` in `cli/internal/evidence/`
    (verification) and `cli/internal/cmd/commands.go` (`runAuditVerifyExport`): no configuration or token is read
    (`dispatch` MUST NOT call `connect` for it). It reads the tar twice (pass 1: `export.json`, `export.sig`;
    pass 2: everything else), and checks in this order, collecting problems (never stopping at the first):
    1. `export.json` parses, `schema == "paddock.audit-export.v1"`; `export.sig` parses; the signature verifies with
       `keys[key_version]` over `sha256(canonical export.json)` (`VerifySignature`); when `--fingerprint` is given it
       equals `Fingerprint(keys[key_version])` (problem `signing key fingerprint differs from --fingerprint`).
    2. For every day from `from_day` to `to_day`: member `manifests/<day>.json` exists, parses as a manifest file,
       `ManifestDigest` equals `days[].manifest_sha256`, its signature verifies with the embedded keys, the manifest's
       `organization_id`, `day` and `schema` match, `prev_manifest_sha256` equals the previous day's digest (the first
       day's value is reported as `chain anchor` and not checked), and `days[]` has no extra or missing day.
    3. Every object of every manifest exists as `objects/<key without prefix>` with the manifest's `sha256`; no
       member under `objects/` is unlisted; `objects[]` of `export.json` equals the union.
    4. `events.jsonl` has the SHA-256 `events_sha256` and is byte-identical to the concatenation of the zstd-decoded
       objects in manifest order; `event_count` equals its line count; every line parses as JSON with
       `organization_id == organization_id` and `schema == "paddock.audit.v1"`.
    5. `verification.ok` and `verification.runs` are reported (`chain verified by the server: yes/no`, `nightly runs:
       <n>, with problems: <m>`, problems listed) but a server-side problem is not a verifier problem.
    Exit 0 and `OK <organization_id> <from>..<to>: <days> days, <objects> objects, <events> events; signed with
    audit-chain v<N> (fingerprint <hex>); chain anchor <prev hash or "none">` on success; exit 1 and `FAIL <problem>`
    lines plus the summary on problems; exit 2 on usage errors or an unreadable file. `-o json`: `{ok, organization_id,
    from_day, to_day, days, objects, events, key_version, fingerprint, chain_anchor, server_verification: {ok,
    problems}, problems}`. `cli/go.mod` adds `github.com/klauspost/compress v1.20.1` and
    `github.com/phischl/paddock-mdm/pkg` (ADR 0032 §6). `docs/operations/paddockctl.md` gains the command row and a
    section "Verifying an evidence package" (the five checks, the fingerprint handshake, the exit codes).

### 3.11 Container log rotation (PDK-149)

40. `deploy/compose/compose.yaml` MUST define `x-paddock-logging: &paddock-logging { driver: json-file, options:
    { max-size: "50m", max-file: "10" } }` and every service in `compose.yaml`, `compose.audit.yaml` and
    `compose.backup.yaml` MUST carry `logging: *paddock-logging` (overlays that already define `logging` for a
    service: none today). `prodcheck` gains the item `container logs are rotated` (FAIL for any service whose rendered
    `logging.driver` is not `json-file` or whose `max-size` is unset; `Service` gains `Logging struct{Driver string;
    Options map[string]string}` from the rendered JSON). `docs/operations/install.md` gets one paragraph "Logs" (what
    the roles log, that Caddy's access log holds client addresses, the rotation values, and that a central log system
    is the operator's choice) and `restore.md` one sentence on the deletion lag (ADR 0032). `compose_test.go` asserts
    every service of every host's file set has the logging block.

## 4. Non-goals

- No change to the WORM bucket, its policy, Object Lock, `PADDOCK_AUDIT_RETENTION_DAYS` semantics or
  `rustfs-audit-bootstrap.sh`; Paddock still never deletes audit objects.
- No per-organization WORM retention; no legal hold; no purge of `action`, `device_command`, `device_alert`,
  `change_set`, `revocation_request`, escrow of retired devices, `admin_account`, `api_token` (ADR 0032 follow-ups).
- No SIEM forward, no cursor feed, no notification on purge or export (M9); no nightly verification status page
  (M8b); no corrections of G1–G6 wording in `docs/architecture.md` beyond decision 6 (M8b).
- No filtering of the export by code or actor; no CSV; no export of inventory or device lists (F-24 later).
- No change to the agent, the device protocol, `agent/internal/revoke/`, `agent/cmd/paddock-revoke/`, the
  supervisor, Fleet's settings (`settings.go` `wanted()`), the OpenBao policies, the audit database roles script.
- No German versions of the privacy pack; no on-device self-information file.
- No API-token creation for `org_auditor` (open point 3).

## 5. Affected files

| Path | Action | Purpose |
| --- | --- | --- |
| `docs/adr/0032-retention-and-deletion.md` | new (done) | the decision |
| `docs/compliance/retention.md`, `docs/compliance/privacy-pack/{transparency-notice,record-of-processing,dpia-input,works-council-annex}.md` | new | decisions 1, 26 |
| `docs/compliance/privacy.md`, `iso27001-mapping.md`, `residual-risks.md`, `README.md`, `audit-codes.md` (generated) | change | decisions 2–5, 27 |
| `docs/operations/audit-bucket.md`, `monitoring.md`, `paddockctl.md`, `install.md`, `restore.md`, `local-dev.md` | change | decisions 5, 15, 25, 34, 39, 40 |
| `docs/architecture.md` | change (amendment blocks only) | decision 6 |
| `server/migrations/paddock/NNNNN_privacy_settings.sql`, `NNNNN_retention_grants.sql`, `NNNNN_read_audit_window.sql`, `NNNNN_change_set_before_purge.sql` (only if M11 did not grant the update) | new | §6.1, decision 15a |
| `server/migrations/audit/NNNNN_index_purge.sql`, `NNNNN_audit_exports.sql` | new | §6.2 |
| `api/openapi/admin.yaml`, `api/schema/paddock.v1.json` | change | §6.3, decision 9 |
| `server/internal/domain/audit/codes.go` | change | §6.4 |
| `server/internal/problem/problem.go` | change | decision 28 |
| `server/internal/app/{privacy,retention,readaudit,auditexports}.go`, `action.go` (`RecordReadOnce`), `config*.go` (settings.privacy) | new/change | §6.6 |
| `server/internal/adapters/postgres/queries/{privacy,login,inventory,readaudit,change_set}.sql` | new/change | queries named in §6.6 and decision 15a |
| `server/internal/adapters/auditpg/queries/audit.sql` (+ `export.sql`) | change/new | queries named in §6.6 |
| `server/internal/ports/inventory.go`, `server/internal/adapters/fleet/hosts.go` | change | `InventoryAdmin`, `DeleteHost` |
| `server/internal/worker/retention.go` | new | decision 12 |
| `server/internal/auditwriter/{purger,exporter,selfevent}.go`, `sealer.go` (key upkeep) | new/change | decisions 22–24, 31–36 |
| `server/cmd/paddock-server/{worker,auditwriter}.go` | change | wiring, `audit purge`, `audit keys` |
| `server/internal/transport/http/admin/{handlers_privacy,handlers_auditexports,handlers_evidence}.go`, `handlers.go`, `handlers_inventory.go` | new/change | decisions 8, 20, 29, 35, 36 |
| `server/internal/prodcheck/prodcheck.go`, `compose_test.go` | change | decisions 14, 40 |
| `deploy/compose/compose.yaml`, `compose.audit.yaml`, `compose.backup.yaml`, `compose.dev.yaml` | change | decisions 14, 31, 40 |
| `deploy/compose/prometheus/alerts.yml`, `alerts_test.yml` | change | decisions 15, 25, 34 |
| `pkg/auditevidence/*.go` | new | §6.7 |
| `cli/internal/evidence/*.go`, `cli/internal/cmd/{cmd,commands}.go`, `cli/go.mod`, `cli/go.sum` | new/change | decision 39 |
| `server/web/src/views/{PrivacySettings,AuditExports}.vue`, `router.ts`, `lib/navigation.ts`, `locales/{en,de}.json`, `views/Audit.vue`, `web/e2e/auditExports.spec.ts` | new/change | decisions 10, 37 |
| `test/acceptance/{retention_test.go,readaudit_test.go,audit_export_test.go}`, `isolation_fixtures.go` | new/change | §8 |
| `CHANGELOG.md` | change | every ticket |

Not to be touched: `agent/`, `pkg/` except the new package, `deploy/compose/scripts/rustfs-audit-bootstrap.sh`,
`deploy/compose/audit-postgres/init/`, `deploy/compose/openbao/`, `server/internal/auditwriter/verify.go` (read
only; the exporter calls it), `server/internal/adapters/fleet/settings.go`, every ADR but 0032, `docs/reqirements/`,
`docs/architecture.md` outside the two amendment blocks, the existing migrations.

## 6. Interfaces and formats

### 6.1 Migrations, database `paddock`

```sql
-- server/migrations/paddock/NNNNN_privacy_settings.sql
-- Privacy settings of an organization (ADR 0032 §2, plan M10 decision 7). Forward-only: there is no Down migration.
-- +goose Up
CREATE TABLE organization_privacy_settings (
  organization_id uuid PRIMARY KEY REFERENCES organization(id),
  retired_inventory_days int NOT NULL DEFAULT 30 CHECK (retired_inventory_days BETWEEN 1 AND 365),
  audit_search_recorded boolean NOT NULL DEFAULT false,
  inventory_view_recorded boolean NOT NULL DEFAULT false,
  updated_at timestamptz NOT NULL DEFAULT now(),
  updated_by uuid
);
INSERT INTO organization_privacy_settings (organization_id) SELECT id FROM organization;
-- +goose StatementBegin
CREATE FUNCTION organization_privacy_settings_default() RETURNS trigger
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  INSERT INTO organization_privacy_settings (organization_id) VALUES (NEW.id) ON CONFLICT DO NOTHING;
  RETURN NULL;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION organization_privacy_settings_default() FROM PUBLIC;
CREATE TRIGGER organization_privacy_settings_default AFTER INSERT ON organization
  FOR EACH ROW EXECUTE FUNCTION organization_privacy_settings_default();
ALTER TABLE organization_privacy_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE organization_privacy_settings FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON organization_privacy_settings TO paddock_api, paddock_worker
  USING (organization_id = current_setting('paddock.org_id')::uuid)
  WITH CHECK (organization_id = current_setting('paddock.org_id')::uuid);
GRANT SELECT, INSERT, UPDATE ON organization_privacy_settings TO paddock_api;
GRANT SELECT ON organization_privacy_settings TO paddock_worker;
-- +goose Down
```

```sql
-- server/migrations/paddock/NNNNN_read_audit_window.sql
-- Coalescing keys of read-access audit events (ADR 0032 §4, plan M10 decision 18). Forward-only.
-- +goose Up
CREATE TABLE read_audit_window (
  organization_id uuid NOT NULL REFERENCES organization(id),
  actor_id text NOT NULL,
  code text NOT NULL,
  target_id text NOT NULL DEFAULT '',
  window_start timestamptz NOT NULL,
  PRIMARY KEY (organization_id, actor_id, code, target_id, window_start)
);
CREATE INDEX read_audit_window_start_idx ON read_audit_window (organization_id, window_start);
ALTER TABLE read_audit_window ENABLE ROW LEVEL SECURITY;
ALTER TABLE read_audit_window FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON read_audit_window TO paddock_api, paddock_worker
  USING (organization_id = current_setting('paddock.org_id')::uuid)
  WITH CHECK (organization_id = current_setting('paddock.org_id')::uuid);
GRANT SELECT, INSERT ON read_audit_window TO paddock_api;
GRANT SELECT, DELETE ON read_audit_window TO paddock_worker;
-- +goose Down
```

### 6.2 Migrations, database `paddock_audit`

```sql
-- server/migrations/audit/NNNNN_index_purge.sql
-- Index purge (ADR 0032 §3, plan M10 decision 22): drops one monthly partition of audit_event once every event in it
-- was recorded before the cutoff. Owner-executed like audit_ensure_partition; the writer keeps no DELETE grant.
-- Forward-only: there is no Down migration.
-- +goose Up
-- +goose StatementBegin
CREATE FUNCTION audit_purge_partition(p_month date, p_cutoff timestamptz)
  RETURNS TABLE (dropped boolean, events bigint, reason text)
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  start_ts date := date_trunc('month', p_month)::date;
  end_ts   date := (date_trunc('month', p_month) + interval '1 month')::date;
  part     text := format('audit_event_%s', to_char(start_ts, 'YYYY_MM'));
  n        bigint;
  newest   timestamptz;
BEGIN
  IF to_regclass(part) IS NULL THEN
    RETURN QUERY SELECT false, 0::bigint, 'no such partition'; RETURN;
  END IF;
  IF end_ts::timestamptz > p_cutoff THEN
    RETURN QUERY SELECT false, 0::bigint, 'month not past the cutoff'; RETURN;
  END IF;
  EXECUTE format('SELECT count(*), max(recorded_at) FROM %I', part) INTO n, newest;
  IF newest IS NOT NULL AND newest >= p_cutoff THEN
    RETURN QUERY SELECT false, n, 'late events still within retention'; RETURN;
  END IF;
  EXECUTE format('ALTER TABLE audit_event DETACH PARTITION %I', part);
  EXECUTE format('DROP TABLE %I', part);
  RETURN QUERY SELECT true, n, 'dropped';
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION audit_purge_partition(date, timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION audit_purge_partition(date, timestamptz) TO paddock_audit_writer;
-- +goose Down
```

```sql
-- server/migrations/audit/NNNNN_audit_exports.sql
-- Evidence exports and the published signing keys (ADR 0032 §5, plan M10 decisions 28–36). The reader role may
-- insert export requests and read manifests, objects and exports of its organization; it keeps no UPDATE or DELETE.
-- Forward-only: there is no Down migration.
-- +goose Up
CREATE TABLE audit_export (
  id uuid PRIMARY KEY,
  organization_id uuid NOT NULL,
  status text NOT NULL CHECK (status IN ('pending','running','ready','failed','expired')),
  from_day date NOT NULL,
  to_day date NOT NULL CHECK (to_day >= from_day),
  purpose text NOT NULL CHECK (char_length(purpose) BETWEEN 1 AND 500),
  requested_by jsonb NOT NULL,
  requested_at timestamptz NOT NULL DEFAULT now(),
  started_at timestamptz,
  ready_at timestamptz,
  expires_at timestamptz,
  event_count bigint,
  object_count int,
  size bigint,
  package_sha256 bytea,
  verify_ok boolean,
  verify_problems jsonb,
  signature text,
  key_version int,
  error text,
  correlation_id text NOT NULL
);
CREATE INDEX audit_export_org_requested_idx ON audit_export (organization_id, requested_at DESC);
CREATE INDEX audit_export_pending_idx ON audit_export (requested_at) WHERE status = 'pending';
CREATE INDEX audit_export_expiry_idx ON audit_export (expires_at) WHERE status = 'ready';

CREATE TABLE audit_export_chunk (
  export_id uuid NOT NULL REFERENCES audit_export(id) ON DELETE CASCADE,
  organization_id uuid NOT NULL,
  seq int NOT NULL,
  data bytea NOT NULL,
  PRIMARY KEY (export_id, seq)
);
ALTER TABLE audit_export_chunk ALTER COLUMN data SET STORAGE EXTERNAL;

CREATE TABLE audit_signing_key (
  key_version int PRIMARY KEY,
  public_key bytea NOT NULL CHECK (octet_length(public_key) = 32),
  first_seen_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE audit_export ENABLE ROW LEVEL SECURITY; ALTER TABLE audit_export FORCE ROW LEVEL SECURITY;
CREATE POLICY reader ON audit_export TO paddock_audit_reader
  USING (organization_id = current_setting('paddock.org_id')::uuid)
  WITH CHECK (organization_id = current_setting('paddock.org_id')::uuid);
CREATE POLICY writer ON audit_export TO paddock_audit_writer USING (true) WITH CHECK (true);
ALTER TABLE audit_export_chunk ENABLE ROW LEVEL SECURITY; ALTER TABLE audit_export_chunk FORCE ROW LEVEL SECURITY;
CREATE POLICY reader ON audit_export_chunk TO paddock_audit_reader
  USING (organization_id = current_setting('paddock.org_id')::uuid);
CREATE POLICY writer ON audit_export_chunk TO paddock_audit_writer USING (true) WITH CHECK (true);
-- The reader policies on audit_manifest (and audit_verification_run) come from M8b (ADR 0030). audit_object gets its
-- reader policy here unless an earlier migration created one under the same name.
-- +goose StatementBegin
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'audit_object' AND policyname = 'reader') THEN
    CREATE POLICY reader ON audit_object TO paddock_audit_reader
      USING (organization_id = current_setting('paddock.org_id')::uuid);
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'audit_manifest' AND policyname = 'reader') THEN
    CREATE POLICY reader ON audit_manifest TO paddock_audit_reader
      USING (organization_id = current_setting('paddock.org_id')::uuid);
  END IF;
END $$;
-- +goose StatementEnd

GRANT SELECT, INSERT ON audit_export TO paddock_audit_reader;
GRANT SELECT ON audit_export_chunk, audit_object, audit_manifest, audit_signing_key TO paddock_audit_reader;
GRANT SELECT, INSERT, UPDATE, DELETE ON audit_export, audit_export_chunk TO paddock_audit_writer;
GRANT SELECT, INSERT ON audit_signing_key TO paddock_audit_writer;
-- +goose Down
```

### 6.3 OpenAPI (`api/openapi/admin.yaml`, additions)

```yaml
  /api/v1/settings/privacy:
    get:
      operationId: getPrivacySettings
      tags: [settings]
      description: "Roles: org_admin, org_operator, org_auditor. The privacy settings (ADR 0032 §2); the defaults until changed."
      responses:
        "200": { description: The privacy settings., content: { application/json: { schema: { $ref: "#/components/schemas/PrivacySettings" } } } }
        "401": { $ref: "#/components/responses/Problem" }
        "403": { $ref: "#/components/responses/Problem" }
    put:
      operationId: updatePrivacySettings
      tags: [settings]
      description: |
        Roles: org_admin. Replaces the privacy settings: retired_inventory_days (1–365; the inventory of a retired
        device, in Paddock and in Fleet, is deleted that many days after retirement), audit_search_recorded (searches
        of the audit log are recorded as audit.searched, once per administrator and hour) and
        inventory_view_recorded (views of a device's software and vulnerabilities are recorded as
        device.inventory_viewed, once per administrator, device and day). 400 invalid_request for a value out of range.
      x-paddock-audit: settings.privacy_changed
      parameters: [ { $ref: "#/components/parameters/Csrf" } ]
      requestBody: { required: true, content: { application/json: { schema: { $ref: "#/components/schemas/PrivacySettingsUpdate" } } } }
      responses:
        "200": { description: Updated., content: { application/json: { schema: { $ref: "#/components/schemas/PrivacySettings" } } } }
        "400": { $ref: "#/components/responses/Problem" }
        "401": { $ref: "#/components/responses/Problem" }
        "403": { $ref: "#/components/responses/Problem" }

  /api/v1/audit/exports:
    get:
      operationId: listAuditExports
      tags: [audit]
      description: "Roles: org_admin, org_auditor. The organization's evidence exports (ADR 0032 §5)."
      x-paddock-list:
        sort: [requested_at, status, from_day, to_day]
        default_sort: -requested_at
        search: [purpose, requested_by.display]
        filters: [status]
      parameters:
        - $ref: "#/components/parameters/Page"
        - $ref: "#/components/parameters/PageSize"
        - $ref: "#/components/parameters/AuditExportSort"
        - $ref: "#/components/parameters/Search"
        - name: status
          in: query
          description: Repeatable.
          style: form
          explode: true
          schema: { type: array, items: { $ref: "#/components/schemas/AuditExportStatus" } }
      responses:
        "200": { description: One page of exports., content: { application/json: { schema: { $ref: "#/components/schemas/AuditExportPage" } } } }
        "400": { $ref: "#/components/responses/Problem" }
        "401": { $ref: "#/components/responses/Problem" }
        "403": { $ref: "#/components/responses/Problem" }
    post:
      operationId: createAuditExport
      tags: [audit]
      description: |
        Roles: org_admin, org_auditor, with a step-up within the last 300 s (403 step_up_required). Requests a signed
        evidence package for the recording days from_day..to_day (both sealed: 422 day_not_sealed otherwise; at most
        400 days: 400 range_too_large; from_day after to_day or an empty purpose: 400 invalid_request). At most two
        exports of the organization may be pending or running (409 too_many_exports). The audit writer builds the
        package on the audit host; it is ready within minutes for small ranges and expires 7 days after it is ready.
        Recorded as audit.export_requested; every download as audit.export_downloaded.
      x-paddock-audit: audit.export_requested
      parameters: [ { $ref: "#/components/parameters/Csrf" } ]
      requestBody: { required: true, content: { application/json: { schema: { $ref: "#/components/schemas/AuditExportCreate" } } } }
      responses:
        "202": { description: The pending export., content: { application/json: { schema: { $ref: "#/components/schemas/AuditExport" } } } }
        "400": { $ref: "#/components/responses/Problem" }
        "401": { $ref: "#/components/responses/Problem" }
        "403": { $ref: "#/components/responses/Problem" }
        "409": { $ref: "#/components/responses/Problem" }
        "422": { $ref: "#/components/responses/Problem" }

  /api/v1/audit/exports/{id}:
    parameters: [ { $ref: "#/components/parameters/Id" } ]
    get:
      operationId: getAuditExport
      tags: [audit]
      description: "Roles: org_admin, org_auditor."
      responses:
        "200": { description: The export., content: { application/json: { schema: { $ref: "#/components/schemas/AuditExport" } } } }
        "401": { $ref: "#/components/responses/Problem" }
        "403": { $ref: "#/components/responses/Problem" }
        "404": { $ref: "#/components/responses/Problem" }

  /api/v1/audit/exports/{id}/download:
    parameters: [ { $ref: "#/components/parameters/Id" } ]
    get:
      operationId: downloadAuditExport
      tags: [audit]
      description: |
        Roles: org_admin, org_auditor. Streams the package (a tar archive, docs/operations/paddockctl.md "Verifying an
        evidence package") of a ready export; 409 export_not_ready otherwise. Recorded as audit.export_downloaded.
        The response carries Content-Length, Content-Disposition and X-Paddock-Package-SHA256.
      x-paddock-audit: audit.export_downloaded
      responses:
        "200":
          description: The package.
          headers:
            Content-Disposition: { schema: { type: string } }
            X-Paddock-Package-SHA256: { schema: { type: string } }
          content:
            application/x-tar: { schema: { type: string, format: binary } }
        "401": { $ref: "#/components/responses/Problem" }
        "403": { $ref: "#/components/responses/Problem" }
        "404": { $ref: "#/components/responses/Problem" }
        "409": { $ref: "#/components/responses/Problem" }

  /api/v1/audit/keys:
    get:
      operationId: listAuditEvidenceKeys
      tags: [audit]
      description: "Roles: org_admin, org_auditor. The public keys the audit chain and the evidence packages are signed with, by key version, with their SHA-256 fingerprints."
      responses:
        "200": { description: The keys., content: { application/json: { schema: { $ref: "#/components/schemas/AuditEvidenceKeys" } } } }
        "401": { $ref: "#/components/responses/Problem" }
        "403": { $ref: "#/components/responses/Problem" }

  # components/parameters
    AuditExportSort:
      name: sort
      in: query
      schema: { type: string, enum: [requested_at, -requested_at, status, -status, from_day, -from_day, to_day, -to_day] }

  # components/schemas
    PrivacySettings:
      type: object
      required: [retired_inventory_days, audit_search_recorded, inventory_view_recorded, updated_at]
      properties:
        retired_inventory_days: { type: integer, minimum: 1, maximum: 365 }
        audit_search_recorded: { type: boolean }
        inventory_view_recorded: { type: boolean }
        updated_at: { type: string, format: date-time }
    PrivacySettingsUpdate:
      type: object
      required: [retired_inventory_days, audit_search_recorded, inventory_view_recorded]
      properties:
        retired_inventory_days: { type: integer, minimum: 1, maximum: 365 }
        audit_search_recorded: { type: boolean }
        inventory_view_recorded: { type: boolean }
    AuditExportStatus: { type: string, enum: [pending, running, ready, failed, expired] }
    AuditExportCreate:
      type: object
      required: [from_day, to_day, purpose]
      properties:
        from_day: { type: string, format: date }
        to_day: { type: string, format: date }
        purpose: { type: string, minLength: 1, maxLength: 500 }
    AuditExport:
      type: object
      required: [id, status, from_day, to_day, purpose, requested_by, requested_at, ready_at, expires_at, event_count, object_count, size, package_sha256, verify_ok, verify_problems, key_version, error]
      properties:
        id: { type: string, format: uuid }
        status: { $ref: "#/components/schemas/AuditExportStatus" }
        from_day: { type: string, format: date }
        to_day: { type: string, format: date }
        purpose: { type: string }
        requested_by: { $ref: "#/components/schemas/AuditActor" }
        requested_at: { type: string, format: date-time }
        ready_at: { type: string, format: date-time, nullable: true }
        expires_at: { type: string, format: date-time, nullable: true }
        event_count: { type: integer, format: int64, nullable: true }
        object_count: { type: integer, nullable: true }
        size: { type: integer, format: int64, nullable: true }
        package_sha256: { type: string, nullable: true, description: Lowercase hex. }
        verify_ok: { type: boolean, nullable: true }
        verify_problems: { type: array, items: { type: string } }
        key_version: { type: integer, nullable: true }
        error: { type: string, nullable: true }
    AuditExportPage:
      type: object
      required: [items, page, page_size, total, total_capped, sort]
      properties:
        items: { type: array, items: { $ref: "#/components/schemas/AuditExport" } }
        page: { type: integer }
        page_size: { type: integer }
        total: { type: integer }
        total_capped: { type: boolean }
        sort: { type: string }
    AuditEvidenceKey:
      type: object
      required: [key_version, public_key, fingerprint, first_seen_at]
      properties:
        key_version: { type: integer }
        public_key: { type: string, description: Base64 of the raw 32-byte ed25519 public key. }
        fingerprint: { type: string, description: Lowercase hex SHA-256 of the raw public key. }
        first_seen_at: { type: string, format: date-time }
    AuditEvidenceKeys:
      type: object
      required: [keys]
      properties:
        keys: { type: array, items: { $ref: "#/components/schemas/AuditEvidenceKey" } }
```

`AuditActor` is the existing schema (`type`, `id`, `display`, `ip`, `step_up`); `requested_by` carries no `ip`.

### 6.4 Audit codes (`server/internal/domain/audit/codes.go`, registry entries)

```go
CodeSettingsPrivacyChanged   Code = "settings.privacy_changed"
CodeRetentionPurged          Code = "retention.purged"
CodeDeviceInventoryPurged    Code = "device.inventory_purged"
CodeAuditSearched            Code = "audit.searched"
CodeDeviceInventoryViewed    Code = "device.inventory_viewed"
CodeAuditExportRequested     Code = "audit.export_requested"
CodeAuditExportCompleted     Code = "audit.export_completed"
CodeAuditExportDownloaded    Code = "audit.export_downloaded"

CodeSettingsPrivacyChanged: {Emitted: true,
  Description: "An organization administrator changed the privacy settings: the inventory retention of retired devices and whether audit searches and inventory views are recorded (ADR 0032).",
  Params: []string{"retired_inventory_days", "audit_search_recorded", "inventory_view_recorded"}, Outcomes: adminOutcomes},
CodeRetentionPurged: {Emitted: true,
  Description: "A retention job deleted expired rows of one store (actor: system). store is device_user_seen, read_audit_window (recorded in the organization, only when rows were deleted), audit_index (one event per dropped partition, platform pseudo-organization) or audit_exports (one event per expired export, in its organization).",
  Params: []string{"store", "deleted", "cutoff", "partition", "export_id"}, Outcomes: []Outcome{OutcomeSuccess, OutcomeFailure},
  Note: "Deletion evidence (ISO/IEC 27001 A.8.10); docs/compliance/retention.md."},
CodeDeviceInventoryPurged: {Emitted: true,
  Description: "The retention job deleted the inventory of a retired device in Paddock and its host in Fleet, retired_inventory_days after retirement (actor: system). failure with upstream_unavailable leaves the Paddock rows in place; the device is retried next round.",
  Params: []string{"hostname", "retired_at", "software", "findings", "policy_results", "fleet_host_deleted"}, Outcomes: []Outcome{OutcomeSuccess, OutcomeFailure}},
CodeAuditSearched: {Emitted: true,
  Description: "An administrator, auditor or API token searched the audit log; recorded once per actor and clock hour and only while the organization's audit_search_recorded setting is on. Filters are recorded, never results or the search text.",
  Params: []string{"from", "to", "codes", "outcomes", "actor_types", "target_id", "q_used", "window_start"}, Outcomes: []Outcome{OutcomeSuccess, OutcomeDenied}},
CodeDeviceInventoryViewed: {Emitted: true,
  Description: "An organization member viewed the software or vulnerabilities of a device; recorded once per actor, device and UTC day and only while inventory_view_recorded is on. view is the first view of the day.",
  Params: []string{"hostname", "view", "window_start"}, Outcomes: []Outcome{OutcomeSuccess, OutcomeDenied}},
CodeAuditExportRequested: {Emitted: true,
  Description: "An organization administrator or auditor requested a signed evidence package for a range of sealed recording days after a step-up; denied with step_up_required without one.",
  Params: []string{"export_id", "from_day", "to_day", "purpose"}, Outcomes: adminOutcomes},
CodeAuditExportCompleted: {Emitted: true,
  Description: "The audit writer finished building an evidence package (actor: system). verify_ok tells whether the chain of the range verified; a package with problems is still delivered so that the auditor sees them. failure carries the error and error_code export_failed.",
  Params: []string{"export_id", "from_day", "to_day", "days", "objects", "events", "size", "package_sha256", "verify_ok", "key_version", "error"}, Outcomes: []Outcome{OutcomeSuccess, OutcomeFailure}},
CodeAuditExportDownloaded: {Emitted: true,
  Description: "An organization administrator or auditor downloaded an evidence package; every download is recorded.",
  Params: []string{"export_id", "from_day", "to_day", "size", "package_sha256"}, Outcomes: adminOutcomes},
```

### 6.5 The evidence package

Tar archive (POSIX ustar/PAX as `archive/tar` writes it; no compression of the archive itself), members in this order:

```
README.md
manifests/<YYYY-MM-DD>.json          one per day, from_day..to_day, the stored ManifestFile bytes verbatim
objects/<YYYY>/<MM>/<DD>/<HH>-<event_id>.jsonl.zst   every object of every manifest, key order, bytes verbatim
events.jsonl                         the zstd-decoded objects concatenated in manifest order (days ascending, keys ascending)
export.json                          canonical JSON (RFC 8785) of the Export below
export.sig                           {"signature":"vault:v<N>:<base64>","key_version":<N>}  (JSON, not canonicalized)
```

`export.json` (schema `paddock.audit-export.v1`, `pkg/auditevidence.Export`):

```json
{
  "schema": "paddock.audit-export.v1",
  "export_id": "<uuid>",
  "organization_id": "<uuid>",
  "organization_slug": "acme",
  "from_day": "2026-01-01",
  "to_day": "2026-03-31",
  "requested_by": {"type": "admin", "id": "<uuid>", "display": "bob@acme.test"},
  "requested_at": "2026-04-02T07:00:00Z",
  "created_at": "2026-04-02T07:01:12Z",
  "purpose": "ISO 27001 surveillance audit 2026",
  "generator": "paddock-server <version>",
  "days": [{"day": "2026-01-01", "manifest_key": "org/<org>/manifests/2026-01-01.json", "manifest_sha256": "<hex>", "object_count": 3, "event_count": 120}],
  "objects": [{"key": "org/<org>/2026/01/01/08-<id>.jsonl.zst", "path": "objects/2026/01/01/08-<id>.jsonl.zst", "sha256": "<hex>", "event_count": 40}],
  "event_count": 120,
  "events_sha256": "<hex>",
  "readme_sha256": "<hex SHA-256 of the README.md member>",
  "chain_anchor": "<hex of the first day's prev_manifest_sha256, or null>",
  "verification": {"ok": true, "problems": [], "verified_at": "2026-04-02T07:00:40Z", "verifier": "paddock-server <version>",
                   "runs": [{"run_id": "<uuid>", "started_at": "2026-04-01T02:00:00Z", "from_day": "2026-03-31", "to_day": "2026-03-31", "ok": true, "problems": []}]},
  "keys": [{"key_version": 1, "public_key": "<base64>", "fingerprint": "<hex>"}]
}
```

`README.md` (verbatim, `<…>` replaced by the export's values):

```
# Paddock audit evidence package

Organization <slug> (<organization_id>), recording days <from_day> to <to_day>, requested by <display> on
<requested_at> for: <purpose>. Built by <generator> on <created_at>. Package ID <export_id>.

What is inside: manifests/ holds the signed daily manifests of the audit chain (one per recording day), objects/
holds every audit object those manifests list, byte for byte as stored in the WORM bucket, events.jsonl holds the
decoded events of those objects in recording order, export.json describes the package and export.sig is its
signature with the audit-chain key (version <key_version>, SHA-256 fingerprint <fingerprint>).

How to verify without access to Paddock: install paddockctl (https://github.com/phischl/paddock-mdm/releases) and run

    paddockctl audit verify-export <this file> --fingerprint <fingerprint recorded by your ISMS>

It checks the package signature, every manifest signature and link, every object hash, that events.jsonl equals the
objects, and prints OK or the list of problems. The manifest of the first day links to the manifest of the day
before (chain anchor <chain_anchor>); verify consecutive packages against each other to extend the chain.

Server-side verification at build time: <ok: "no problems" | the problems, one per line>. Nightly verification runs
that covered days of this range (from the audit writer's verification log): <count> runs, <count> with problems.

This package contains personal data (names and addresses of administrators, user names, host names). Handle it
according to your organization's rules for audit evidence and delete it when the audit is closed.
```

### 6.6 Go signatures

```go
// server/internal/app/action.go
// RecordReadOnce records a read of sensitive data at most once per window: authorization as in RunTx (a denied role
// is recorded as denied), then claim runs inside the organization transaction; it returns false when the window key
// existed, and then nothing is recorded (no action, no outbox row). true records outcome success in the same
// transaction. A claim error rolls back and is recorded as failure.
func (r *ActionRunner) RecordReadOnce(ctx context.Context, spec ActionSpec,
	claim func(ctx context.Context, q *pgstore.Queries, rec Recorder) (bool, error)) (bool, error)

// server/internal/app/privacy.go
type PrivacySettings struct { RetiredInventoryDays int; AuditSearchRecorded, InventoryViewRecorded bool; UpdatedAt time.Time }
var SpecPrivacySettings = ActionSpec{Code: audit.CodeSettingsPrivacyChanged, AllowedRoles: RolesAdmin}
type Privacy struct{ runner *ActionRunner; org *db.OrgPool }
func NewPrivacy(runner *ActionRunner, org *db.OrgPool) *Privacy
func (p *Privacy) Get(ctx context.Context) (PrivacySettings, error)                       // RequireOrg(RolesRead)
func (p *Privacy) Update(ctx context.Context, s PrivacySettings) (PrivacySettings, error) // RunTx, ScopeOrg

// server/internal/app/readaudit.go
var SpecAuditSearched = ActionSpec{Code: audit.CodeAuditSearched, AllowedRoles: RolesAudit}
var SpecInventoryViewed = ActionSpec{Code: audit.CodeDeviceInventoryViewed, AllowedRoles: RolesRead}
type ReadAudit struct{ runner *ActionRunner; now func() time.Time }
func NewReadAudit(runner *ActionRunner) *ReadAudit
func (r *ReadAudit) AuditSearched(ctx context.Context, q AuditQuery) (recorded bool, err error)
func (r *ReadAudit) InventoryViewed(ctx context.Context, deviceID uuid.UUID, view string) (recorded bool, err error)

// server/internal/app/retention.go
type RetentionUnit time.Duration // time.Hour*24 or, in development, time.Second
var SpecRetentionPurged = ActionSpec{Code: audit.CodeRetentionPurged}            // system principal only
var SpecDeviceInventoryPurged = ActionSpec{Code: audit.CodeDeviceInventoryPurged} // system principal only
type Retention struct{ runner *ActionRunner; org *db.OrgPool; inventory ports.InventoryAdmin; unit RetentionUnit }
func NewRetention(runner *ActionRunner, org *db.OrgPool, inventory ports.InventoryAdmin, unit RetentionUnit) *Retention
const ReadWindowRetention = 48 * time.Hour
func (r *Retention) PurgeUserSeen(ctx context.Context, now time.Time) (deleted int64, err error)
func (r *Retention) PurgeReadWindows(ctx context.Context, now time.Time) (deleted int64, err error)
func (r *Retention) PurgeRetiredInventory(ctx context.Context, now time.Time) (devices int, err error)

// server/internal/worker/retention.go
const RetentionInterval = 6 * time.Hour
const retentionLockKey = 0x7061646420726574
type Retention struct{ app *app.Retention; pool *db.OrgPool; platform *db.PlatformPool; interval time.Duration; now func() time.Time }
func NewRetention(a *app.Retention, pool *db.OrgPool, platform *db.PlatformPool, interval time.Duration) *Retention
func (r *Retention) Run(ctx context.Context) error
func (r *Retention) Round(ctx context.Context) error

// server/internal/ports/inventory.go
// InventoryAdmin deletes hosts from the inventory system (retention of retired devices, ADR 0032).
type InventoryAdmin interface {
	// DeleteHost removes a host; a host that no longer exists is not an error.
	DeleteHost(ctx context.Context, ref HostRef) error
}
// server/internal/adapters/fleet/hosts.go
func (c *Client) DeleteHost(ctx context.Context, ref ports.HostRef) error // DELETE /api/v1/fleet/hosts/{id}; 404 → nil

// server/internal/auditwriter/selfevent.go (on top of M8b's auditwriter.Recorder, PDK-109)
func RecordSelf(ctx context.Context, rec *Recorder, ev audit.Event) error

// server/internal/auditwriter/purger.go
const PurgeDelay = 75 * time.Minute
type PurgedPartition struct { Name string; Month time.Time; Events int64; Dropped bool; Reason string }
type PurgeReport struct { Cutoff time.Time; Partitions []PurgedPartition }
type Purger struct{ pool *db.AuditWriterPool; writer *Writer; retentionDays int; now func() time.Time }
func NewPurger(pool *db.AuditWriterPool, writer *Writer, indexRetentionDays int) *Purger
func (p *Purger) Run(ctx context.Context, now time.Time, dryRun bool) (PurgeReport, error)
func (p *Purger) RunDaily(ctx context.Context)

// server/internal/auditwriter/exporter.go
const ExportSchema = "paddock.audit-export.v1"
const ExportChunkSize = 8 << 20
const ExportTTL = 7 * 24 * time.Hour
const ExportStuckAfter = 2 * time.Hour
type Exporter struct{ pool *db.AuditWriterPool; writer *Writer; store ObjectStore; signer Signer; keys PublicKeys; verifier *Verifier; version string; poll time.Duration; now func() time.Time }
func NewExporter(pool *db.AuditWriterPool, writer *Writer, store ObjectStore, signer Signer, keys PublicKeys, verifier *Verifier, version string, poll time.Duration) *Exporter
func (e *Exporter) Run(ctx context.Context) error
func (e *Exporter) Build(ctx context.Context, export auditstore.AuditExport) error
func (e *Exporter) Expire(ctx context.Context, now time.Time) (expired int, err error)

// server/internal/app/auditexports.go
var SpecAuditExportRequest = ActionSpec{Code: audit.CodeAuditExportRequested, AllowedRoles: RolesAudit, RequiresStepUp: true}
var SpecAuditExportDownload = ActionSpec{Code: audit.CodeAuditExportDownloaded, AllowedRoles: RolesAudit}
const MaxExportDays = 400
const MaxOpenExports = 2
type AuditExportRequest struct { FromDay, ToDay time.Time; Purpose string }
type AuditExports struct{ runner *ActionRunner; reader *db.AuditReader; org *db.OrgPool; now func() time.Time }
func NewAuditExports(runner *ActionRunner, reader *db.AuditReader, org *db.OrgPool) *AuditExports
func (a *AuditExports) Request(ctx context.Context, req AuditExportRequest) (auditstore.AuditExport, error)
func (a *AuditExports) Get(ctx context.Context, id uuid.UUID) (auditstore.AuditExport, error)
func (a *AuditExports) List(ctx context.Context, q AuditExportQuery) (AuditExportListed, error)
type AuditExportQuery struct { Statuses []string; Page ListPage }
type AuditExportListed struct { Items []auditstore.AuditExport; Count int }
// Download records audit.export_downloaded, then calls stream once per chunk in seq order inside one reader transaction.
func (a *AuditExports) Download(ctx context.Context, id uuid.UUID, stream func(chunk []byte) error) (auditstore.AuditExport, error)
func (a *AuditExports) Keys(ctx context.Context) ([]auditstore.AuditSigningKey, error)

// auditpg queries (server/internal/adapters/auditpg/queries/export.sql), names fixed:
// InsertAuditExport, GetAuditExport, ListAuditExports, CountAuditExports, CountOpenAuditExports,
// ClaimPendingAuditExport, UpdateAuditExportReady, UpdateAuditExportFailed, UpdateAuditExportExpired,
// ListExpiredAuditExports, ListStuckAuditExports, InsertAuditExportChunk, GetAuditExportChunk,
// DeleteAuditExportChunks, EnsureAuditSigningKey, ListAuditSigningKeys, OldestPendingAuditExportAge.
// audit.sql additions: ListAuditPartitions, PurgeAuditPartition (SELECT * FROM audit_purge_partition(@month, @cutoff)).
// pgstore queries: GetPrivacySettings, UpsertPrivacySettings (privacy.sql); DeleteExpiredDeviceUserSeen (login.sql);
// ListRetiredDevicesWithInventory, CountDeviceInventory, DeleteDeviceInventory (inventory.sql);
// ClaimReadAuditWindow (INSERT … ON CONFLICT DO NOTHING RETURNING true), DeleteExpiredReadAuditWindows (readaudit.sql).
```

### 6.7 `pkg/auditevidence`

```go
// Package auditevidence defines the evidence package (export.json) and the manifest file of the audit chain as the
// offline verifier and the server share them (plan M10 §6.5). Standard library and pkg/canonicaljson only.
package auditevidence

const ExportSchema = "paddock.audit-export.v1"
const ManifestSchema = "paddock.audit-manifest.v1"
const EventSchema = "paddock.audit.v1"

type Actor struct { Type string `json:"type"`; ID string `json:"id,omitempty"`; Display string `json:"display,omitempty"` }
type Day struct { Day string `json:"day"`; ManifestKey string `json:"manifest_key"`; ManifestSHA256 string `json:"manifest_sha256"`; ObjectCount int `json:"object_count"`; EventCount int `json:"event_count"` }
type Object struct { Key string `json:"key"`; Path string `json:"path"`; SHA256 string `json:"sha256"`; EventCount int `json:"event_count"` }
type Run struct { RunID string `json:"run_id"`; StartedAt time.Time `json:"started_at"`; FromDay string `json:"from_day"`; ToDay string `json:"to_day"`; OK bool `json:"ok"`; Problems []string `json:"problems"` }
type Verification struct { OK bool `json:"ok"`; Problems []string `json:"problems"`; VerifiedAt time.Time `json:"verified_at"`; Verifier string `json:"verifier"`; Runs []Run `json:"runs"` }
type Key struct { KeyVersion int `json:"key_version"`; PublicKey []byte `json:"public_key"`; Fingerprint string `json:"fingerprint"` }
type Export struct {
	Schema string `json:"schema"`; ExportID string `json:"export_id"`; OrganizationID string `json:"organization_id"`
	OrganizationSlug string `json:"organization_slug"`; FromDay string `json:"from_day"`; ToDay string `json:"to_day"`
	RequestedBy Actor `json:"requested_by"`; RequestedAt time.Time `json:"requested_at"`; CreatedAt time.Time `json:"created_at"`
	Purpose string `json:"purpose"`; Generator string `json:"generator"`; Days []Day `json:"days"`; Objects []Object `json:"objects"`
	EventCount int `json:"event_count"`; EventsSHA256 string `json:"events_sha256"`; ChainAnchor *string `json:"chain_anchor"`
	Verification Verification `json:"verification"`; Keys []Key `json:"keys"`
}
type Signature struct { Signature string `json:"signature"`; KeyVersion int `json:"key_version"` }
type ManifestObject struct { Key string `json:"key"`; SHA256 string `json:"sha256"`; EventCount int `json:"event_count"` }
type Manifest struct { Schema string `json:"schema"`; OrganizationID string `json:"organization_id"`; Day string `json:"day"`; Objects []ManifestObject `json:"objects"`; PrevManifestSHA256 *string `json:"prev_manifest_sha256"` }
type ManifestFile struct { Manifest json.RawMessage `json:"manifest"`; Signature string `json:"signature"`; KeyVersion int `json:"key_version"` }

func Fingerprint(pub []byte) string                                                   // lowercase hex sha256
func VerifySignature(keys map[int][]byte, version int, sig string, message []byte) bool // "vault:v<N>:<base64>", ed25519
func ExportDigest(canonical []byte) [32]byte                                           // sha256 of the canonical bytes
func ManifestDigest(file ManifestFile) ([]byte, [32]byte, error)                        // canonical bytes and sha256 of file.Manifest
func ObjectPath(organizationID, key string) (string, error)                             // "org/<org>/…" → "objects/…"; error for a foreign prefix
```

## 7. Development stack

`compose.dev.yaml`: `paddock-worker` gets `PADDOCK_RETENTION_UNIT: ${PADDOCK_RETENTION_UNIT:-seconds}` and
`PADDOCK_RETENTION_INTERVAL: ${PADDOCK_RETENTION_INTERVAL:-15s}`; `paddock-audit-writer` gets
`PADDOCK_AUDIT_EXPORT_POLL_INTERVAL: ${PADDOCK_AUDIT_EXPORT_POLL_INTERVAL:-2s}`. `docs/operations/local-dev.md`
lists them next to `PADDOCK_STALENESS_UNIT`.

## 8. Steps (tickets, in order)

1. **PDK-135 — Retention schedule and compliance documents.** Decisions 1–6. Verify: `make scan-secrets` green; every
   table of `retention.md` matches ADR 0032 §1 (reviewer reads).
2. **PDK-136 — Privacy settings (API, schema, portal).** Decisions 7–10, §6.1 (privacy_settings), §6.3 (settings), §6.4
   (`settings.privacy_changed`). Verify: `make gen` no diff; `go test ./server/...`; gate `TestDeclarativeConfig`
   (settings.privacy round-trips) and `TestListContract`, `TestOrganizationIsolation` green; browser check of
   `/settings/privacy` (skill `frontend-verify`).
3. **PDK-137 — Worker retention round: `device_user_seen`.** Decisions 11–15, `retention.purged`. Gate R1. Verify:
   `make acceptance T=TestRetentionUserSeen`; `make lint-prometheus`.
4. **PDK-138 — Retired-device inventory purge with Fleet host deletion.** Decisions 16–17,
   `device.inventory_purged`. Gate R2.
5. **PDK-139 — Read-access recording.** Decisions 18–21, §6.1 (read_audit_window), `audit.searched`, `device.inventory_viewed`.
   Gate R3.
6. **PDK-140 — Audit index purge.** Decisions 22–25, §6.2 (index_purge), `RecordSelf`, `audit purge`. Integration test
   `TestPurgerDropsExpiredPartition` in `auditwriter` (Docker PostgreSQL as the existing writer tests use); gate R4.
7. **PDK-141 — Privacy and works-council pack.** Decisions 26–27.
8. **PDK-142 — Evidence export: data model and request API.** Decisions 28–30, §6.2 (audit_exports), §6.3, codes
   `audit.export_requested`. Gates `TestListContract`, `TestOrganizationIsolation`, E1 (request, refusals).
9. **PDK-143 — Evidence export: builder in the audit writer.** Decisions 31–34, §6.5, §6.7 types, `audit.export_completed`,
   `retention.purged` (store `audit_exports`). Gate E2 (ready within the poll interval, counts match).
10. **PDK-144 — Evidence export: download.** Decision 35, `audit.export_downloaded`. Gate E3 (download, sha256, headers).
11. **PDK-148 — Signing keys: publication and CLI.** Decision 36. Gate E3 extended (keys endpoint returns the key
    version the package names).
12. **PDK-145 — Portal: evidence exports page.** Decision 37. Playwright `auditExports.spec.ts`; browser check.
13. **PDK-146 — `paddockctl audit verify-export`.** Decisions 38–39. Unit tests with a generated package (§8 tests);
    gate E4 (verifier accepts the downloaded package, rejects a modified one).
14. **PDK-147 — Evidence export: acceptance gate and documentation.** Gates E1–E4 as one file `audit_export_test.go`
    where the earlier tickets left stubs; `audit-bucket.md`, `paddockctl.md`, `iso27001-mapping.md` A.5.28 row
    cross-checked; `CHANGELOG.md` consolidated under one "Evidence export" entry.
15. **PDK-149 — Container log rotation.** Decision 40. Verify: `make bundle-test`, `make test`
    (`compose_test.go`), `./paddock check` of a local bundle passes the new item.

PDK-141 MAY run at any time after PDK-135. PDK-139 MAY run in parallel with PDK-137/138 once PDK-136 is merged.
PDK-149 MAY run at any time. PDK-148 MAY run in parallel with PDK-144. Everything else is sequential as listed.

## 9. Tests

- Unit (Go): `app.Retention` with a fake `InventoryAdmin` (success, Fleet 404, Fleet 500 → no Paddock deletion,
  batching over 2 500 rows); `app.ReadAudit` coalescing (second call in the window records nothing; next window
  records; setting off records nothing; denied role recorded as denied); `ActionRunner.RecordReadOnce` (claim false →
  no action row, no outbox row); `auditwriter.Purger` (`Run` dry-run reporting, lock timeout reason, month-boundary
  cases: a partition whose month ends exactly at the cutoff is kept); `auditwriter.Exporter` with the in-memory store
  of `export_test.go`: package member order, byte identity of objects and manifests, `events.jsonl` equals the
  concatenation, `export.json` canonical and signed, a modified object yields a `verification.problems` entry and
  `verify_ok=false` but status `ready`, a missing manifest fails the build, chunk boundaries at exactly 8 MiB, expiry
  and stuck handling; `pkg/auditevidence` (`VerifySignature` with a known key, `ManifestDigest` equals the server's
  `CanonicalManifest`, `ObjectPath` refuses a foreign prefix); `cli/internal/evidence` with a package built by a test
  helper (OK; each of the five check groups failing in turn: bad signature, wrong fingerprint, missing manifest, broken
  link, modified object, extra object, events.jsonl mismatch, wrong organization in a line); `prodcheck` logging item.
- Integration (Docker PostgreSQL): the three paddock and the two audit migrations of this plan apply on the previous schema;
  `audit_purge_partition` drops a backdated partition and keeps one with a late event (`recorded_at` set through the
  writer's test clock); RLS of `audit_export*` (reader of organization A cannot see B's export; reader cannot update).
- Acceptance (`test/acceptance/`), new gates:
  - **R1 `TestRetentionUserSeen`** (`retention_test.go`): a simulated device of acme reports `session.login` for
    user `retention-<rand>`; after at most 365 s + two rounds (`PADDOCK_RETENTION_UNIT=seconds`), an audit event
    `retention.purged` with `store=device_user_seen`, `deleted ≥ 1` exists for acme; globex has none from this run.
  - **R2 `TestRetentionRetiredInventory`**: enroll a simulated device, register its Fleet host (`fleethost.go`), wait
    for `installed_software` to be listed (`GET /api/v1/devices/{id}/software` ≥ 1 item), set
    `retired_inventory_days=1`, retire the device; within 90 s `device.inventory_purged` (outcome success,
    `fleet_host_deleted=true`) exists with the device as target, the software list is empty, and the Fleet admin API
    (`stack.FleetAdminURL()`) no longer lists the host.
  - **R3 `TestReadAccessAudit`** (`readaudit_test.go`): with the switches off, Alice lists audit events and device
    software → no `audit.searched`, no `device.inventory_viewed` within 10 s; with both on, two searches within the
    hour → exactly one `audit.searched` (params without `q`), two views of the same device → exactly one
    `device.inventory_viewed`; Bob (auditor) searching → one event with actor type `admin`; Carol sees none of them.
  - **R4 `TestAuditIndexPurge`**: `stack.PaddockServer(ctx, "audit", "purge", "--dry-run")` exits 0 and prints
    `nothing to purge` or `KEEP` lines only (no partition of the development stack is older than 400 days).
  - **E1–E4 `TestAuditEvidenceExport`** (`audit_export_test.go`): a fresh organization with an auditor (`tempUser`,
    role group `auditors`) and activity; `audit seal --day <today> --org <id>` (development-only, as `TestAuditChain`);
    E1: `POST /api/v1/audit/exports` without step-up → 403 `step_up_required` and an `audit.export_requested` denied
    event; with step-up: 202, status `pending`, `audit.export_requested` success; a range ending tomorrow → 422
    `day_not_sealed`; a third open export → 409 `too_many_exports`; Carol's `GET /api/v1/audit/exports/{id}` → 404.
    E2: status `ready` within 60 s; `event_count` equals the number of events the audit log lists for the organization
    with `from=<day 00:00Z>`; `verify_ok=true`; `audit.export_completed` success exists. E3: the download returns
    `application/x-tar`, `Content-Length == size`, `X-Paddock-Package-SHA256 == package_sha256`, the body's SHA-256
    matches, `audit.export_downloaded` exists; `GET /api/v1/audit/keys` lists `key_version` of the export
    with a fingerprint equal to `export.json.keys[]`. E4: `paddockctl audit verify-export <file> --fingerprint <fp>`
    exits 0 with `OK`; a copy with one byte of one object flipped exits 1 with `SHA-256 mismatch`; a copy with the
    first manifest removed exits 1 with `no manifest`.
- Playwright: `auditExports.spec.ts` (decision 37); `accessibility.spec.ts` gains the two new pages.

## 10. Acceptance criteria

- **M10-1 (data protection officer):** Given `docs/compliance/retention.md`, when the DPO asks for the retention and
  legal basis of any store, then the matrix names it, and every "purge" cell names a job that exists and an audit code
  that `audit-codes.md` lists. (PDK-135)
- **M10-2 (organization administrator):** Given the portal, when the administrator opens *Privacy settings*, changes
  `retired_inventory_days` to 14 and saves, then the API returns the new value, `settings.privacy_changed` appears in
  the audit log with the three values, and `paddockctl get config` shows `settings.privacy.retired_inventory_days: 14`.
  (PDK-136)
- **M10-3 (auditor):** Given a device whose user logged in more than 365 days ago (seconds in development), when the
  retention round runs, then the row is gone and `retention.purged` (store `device_user_seen`) proves it; a user who
  logged in within 365 days stays an affected user of a lock. (PDK-137, gate R1)
- **M10-4 (auditor, works council):** Given a device retired longer than `retired_inventory_days` ago, when the round
  runs, then its software, vulnerabilities and policy results are gone from the portal and the host is gone from Fleet,
  and `device.inventory_purged` names the device and the counts. (PDK-138, gate R2)
- **M10-5 (works council):** Given `audit_search_recorded` and `inventory_view_recorded` on, when an administrator
  searches the audit log or opens a device's software twice within the window, then exactly one `audit.searched` and
  one `device.inventory_viewed` exist; given them off, none. (PDK-139, gate R3)
- **M10-6 (platform operator):** Given an index partition whose newest event was recorded more than
  `PADDOCK_AUDIT_INDEX_RETENTION_DAYS` ago, when the nightly purge runs, then the partition is dropped and
  `retention.purged` (store `audit_index`, the partition name, the event count) exists in the platform
  pseudo-organization; a partition with a later event is kept with the reason. (PDK-140)
- **M10-7 (DPO, works council):** Given the four templates, when the operator fills the bracketed fields, then no
  fact about Paddock has to be looked up elsewhere (every data category, retention value and switch is in the
  template). (PDK-141)
- **M10-8 (auditor):** Given the auditor role without any platform access, when the auditor requests an export for a
  range of sealed days after a step-up, then the export becomes `ready` without operator action, the download is a
  tar with the members of §6.5, and `paddockctl audit verify-export` prints `OK` with the key fingerprint that the
  *Evidence exports* page shows. (PDK-142 to PDK-148, gates E1–E4)
- **M10-9 (auditor):** Given a package whose object or manifest was altered after download, when verified offline,
  then the verifier exits 1 naming the member; given a package whose chain was already broken on the server, then the
  package is still delivered with `verify_ok=false` and the problems in `export.json`. (PDK-143, PDK-146)
- **M10-10 (security):** Given Carol (globex), when she requests, lists, gets or downloads acme's export, then 404
  `not_found`; given an operator role, then 403 `forbidden`; given an auditor without step-up, then 403
  `step_up_required` and a denied event. (PDK-142, PDK-144)
- **M10-11 (operator):** Given a production bundle, when `./paddock check` runs, then it fails if any service's logs
  are not rotated or if `PADDOCK_RETENTION_UNIT` is set. (PDK-137, PDK-149)

## 11. Freedoms

- Internal structure of the purge queries (ctid batching vs. a key-range loop) as long as no statement touches more
  than 1 000 rows; helper names; the shape of the chunk writer; whether the exporter keeps the temp file in memory
  below 64 MiB; the tooltip vs. expandable row for verification problems; icon names from `PdIconSet.ts`; the exact
  English of help texts and the German translations; the sqlc file split (`export.sql` vs. appending to `audit.sql`);
  whether `ReadAudit` caches the privacy settings within one request; test fixture builders.

## 12. Stop conditions

- M8b's `auditwriter.Recorder` (PDK-109) is not merged when PDK-140 or PDK-143 starts: stop; do not add a second
  self-event write path.
- `ALTER TABLE … DETACH PARTITION` or `DROP TABLE` inside the `SECURITY DEFINER` function fails on the pinned
  PostgreSQL with a permission error: report; do not grant `DELETE` or ownership to the writer role.
- The generated strict-server type for a binary `application/x-tar` response does not stream (buffers the body):
  report; do not switch the download to a presigned URL or a new bucket.
- The acceptance step-up helper cannot act for an auditor account: report with the failing step; do not weaken
  `RequiresStepUp`.
- `klauspost/compress` v1.20.1 cannot be added to `cli/go.mod` without changing the server's version: report.
- Any need to change `verify.go`, `rustfs-audit-bootstrap.sh`, the audit roles script, the OpenBao policies, Fleet's
  `wanted()` settings, the agent, or any table of the revocation path.
- M9's `commit_seq` (PDK-120) turns out to be part of the stored event JSON (it must not be): report before PDK-143,
  because `events.jsonl` must stay byte-identical to the WORM objects.
- A partition drop would delete events whose WORM objects are still locked (cutoff earlier than the WORM retention
  because `PADDOCK_AUDIT_INDEX_RETENTION_DAYS` was accepted below `PADDOCK_AUDIT_RETENTION_DAYS`): this is a loader bug;
  stop and fix the validation, never the function.

## 13. Risks and open points

- **Open 1 — escrow of retired devices** (default chosen: keep until Destroy; ADR 0032 follow-up). The orchestrator
  decides whether a per-organization "destroy escrow N days after retirement" is wanted; it would need the revocation
  issuer's deletion path and is not in M10.
- **Open 2 — `action` and operational history purge** (default: not in M10; follow-up ticket stub to be created by
  the orchestrator after M10, named in `retention.md` "What is not purged yet").
- **Open 3 — API tokens for `org_auditor`** (default: no). Without them, `paddockctl` cannot download a package; the
  portal download suffices for M10 and the verifier needs no token.
- **Open 4 — M8b's `/audit/integrity` page (`AuditIntegrity.vue`, PDK-110) vs. this plan's `/audit/exports`**
  (default: separate pages; the exports nav item follows `nav.auditIntegrity`; PDK-145 adds a link from the
  integrity page to the exports page when the page exists).
- **Open 5 — M9 event order:** resolved (evidence order in the package, `commit_seq` index-only).
- **Risk — large packages:** a year of a 300-device fleet is a few GB through PostgreSQL chunks. Mitigation: chunked
  transactions, `MaxExportDays = 400`, `MaxOpenExports = 2`, 7-day expiry, metrics and the stuck alert. If the audit
  index database grows beyond the operator's disk, the operator shortens ranges; a bucket-based path is a later ADR.
- **Risk — partition drop locks the writer:** `lock_timeout 5s` and the 00:45 UTC slot; a timeout is retried next night.
- **Risk — Fleet host deletion of a re-enrolled device:** a reinstalled device enrolls as a new device with the same
  hardware UUID; the old retired device's host is the same Fleet host. Mitigation: `DeleteHost` only when the ref's
  `external_id` is not referenced by any active device (`CountInventoryRefsByExternalID` guard inside `prepare`); when
  referenced, the Paddock rows of the retired device are deleted and `fleet_host_deleted=false` is recorded.
- **Risk — read-access recording floods:** coalescing per hour/day bounds it to one event per actor and window; the
  switches default to off.
- **Risk — doc conflicts with M8b:** both touch `privacy.md`, `iso27001-mapping.md`, `residual-risks.md`. Mitigation:
  M10 adds rows and sections; it does not rewrite existing rows except the cells named in decisions 2–4.

## Amendment 2026-10-29 (refresh against main for alpha.7)

Checked against `origin/main` at `dbdebe9b` and the open cluster branches `origin/cluster/server-security` and
`origin/cluster/mcp` (both reach main before this plan's tickets start; neither adds a migration, an audit code
this plan uses, or a residual-risk number). Decided text above is not rewritten; where this amendment and a
decision above differ, this amendment wins. Numbers refer to the decisions of §3.

### A1. What main already has (do not build twice)

- **M8b is merged** (ADR 0030; `audit_verification_run` in `server/migrations/audit/00004_verification.sql`,
  `auditwriter.Recorder` in `server/internal/auditwriter/verification.go`, `auditwriter.Nightly` in `nightly.go`,
  `GET /api/v1/audit/integrity`, `/audit/verification-runs`, `/audit/manifests`, portal `views/AuditIntegrity.vue`
  at `/audit/integrity`, nav item `nav.auditIntegrity`). The preamble's "PDK-109 must be merged" and the first stop
  condition of §12 are satisfied; decision 32 step (2a) is **unconditional** (`runs` is never `[]` for lack of the
  table). Open point 4 is resolved as its default: separate pages, the exports item follows `nav.auditIntegrity`.
- **`auditwriter.Recorder` is verification-specific.** Its only method is `Record(ctx, org, trigger, from, to,
  started, report)`; it builds one `audit.Event` and hands it to `Writer.WriteBatch`. Decisions 22, 24, 32 and 34
  therefore read: `RecordSelf(ctx context.Context, w *Writer, ev audit.Event) error` (file
  `server/internal/auditwriter/selfevent.go`) fills `Schema`, `EventID` (`uuid.NewV7`), `OccurredAt` (now),
  `Source: audit.SourceSystem`, `Actor{Type: audit.ActorSystem, ID: "audit-writer", Display: "audit-writer"}` when
  empty, validates with `Validate` and calls `w.WriteBatch(ctx, []audit.Event{ev})` — exactly the path
  `Recorder.Record` uses (index row, WORM object, partition ensured, sealed-day guard). This is the "one mechanism"
  of the preamble; `verificationEvent` in `verification.go` is the pattern to copy. `RecordSelf` MUST NOT be called
  inside an `InWriter` transaction (unchanged).
- **Decision 14 is done** (M8d): `config.RetentionUnit(l, common)` in `server/internal/config/config.go` reads
  `PADDOCK_RETENTION_UNIT` (`days` | `seconds`, seconds only in development); `prodcheck.go` lists it in `devOnly`
  (now line 134, not 124); `compose.dev.yaml` sets `PADDOCK_RETENTION_UNIT: ${PADDOCK_RETENTION_UNIT:-seconds}` on
  `paddock-worker`. PDK-137 adds only `PADDOCK_RETENTION_INTERVAL` and the `local-dev.md` rows.
- **`retention.purged` is registered** (`codes.go` `CodeRetentionPurged`, store `device_login_event` from M8d) and
  localized (`audit.retention.purged` in `en.json`/`de.json`). PDK-137 adds no registry entry for it; PDK-180
  extends its `Description` with its store names.
- **A retention round exists** for the login history: `server/internal/worker/loginhistory.go` (`LoginHistory`,
  `LoginHistoryInterval = 6h`, lock key `0x70616464206c6f67`, 15 s interval when the unit is seconds) calling
  `app.LoginHistory.Purge(ctx, now)` per organization. ADR 0032 amendment 2026-10-17 made it provisional "until
  M10's retention round exists". See A3.
- **Sealed days are final** (ADR 0010 amendment 2026-10-25, PDK-422, audit migrations `00005`/`00006`): the writer
  files an object under the first unsealed day, a sealed day receives no further objects. Consequence for the export:
  the manifests of `[from_day, to_day]` list every object the package will ever hold; events recorded after the
  seal of `to_day` (including the `audit.export_requested` of the request itself) are filed under a later day and are
  **not** in the package. Gate E2 is adjusted in A7.
- **M9 and M11 are not implemented** (plans only; no `commit_seq`, no `change_set.before`). The stop condition on
  `commit_seq` is moot; decision 15a is removed from this milestone (A3).
- **ADR 0044 (MCP) is merged** on `cluster/mcp` and reaches main first: the principal carries `Channel`
  (`principal.ChannelMCP`), the runner records source `mcp`, and ADR 0044 §G states that once PDK-139 lands, MCP
  reads of sensitive views are recorded by the same handler calls. See A5.
- **ADR 0045 (role switch) is merged**: one principal per session, `principal.ID` is the account ID for every
  organization role; nothing in this plan changes. The actor key of decision 19 stays `principal.ID`.
- **PDK-518**: `CHANGELOG.md` is no longer edited by tickets. Every operator-, user- or integrator-visible change adds
  `changelog.d/<ticket-id>.<section>.md` (`added` | `changed` | `fixed` | …; Keep a Changelog bullets, English);
  `make changelog-check` (part of `make lint`) validates it. Every row "`CHANGELOG.md`" in §5 and §8 reads
  `changelog.d/<ticket>.<section>.md`. PDK-147 does not consolidate entries (the release assembles fragments).
- **PDK-526**: ticket pull requests go into a cluster branch (`cluster/evidence-privacy`, A9) and run only lint,
  test, web, secrets and trivy in CI; the acceptance stage runs on the cluster's pull request to main. Every
  acceptance gate a ticket names is therefore run by the implementer locally (`make acceptance T=<gate>` on the
  development stack assigned to the cluster) before the ticket's review — **only the ticket's own named gates,
  never a full local acceptance run**; the full run happens once in CI on the cluster's pull request to main.
- **`cli/go.mod` on `cluster/mcp`** already requires `github.com/phischl/paddock-mdm/pkg v0.0.0` with
  `replace … => ../pkg`. PDK-146 adds only `github.com/klauspost/compress` at **the version `server/go.mod` pins at
  ticket start** (today v1.20.3, not v1.20.1); the stop condition of §12 reads "cannot be added at the server's
  version".

### A2. Migration numbers (reserved by main's registry)

| Migration (plan name) | Ticket | File |
| --- | --- | --- |
| `privacy_settings` (§6.1) | PDK-136 | `server/migrations/paddock/00074_privacy_settings.sql` |
| `retention_grants` (decision 11) | PDK-137 | `server/migrations/paddock/00075_retention_grants.sql` |
| `read_audit_window` (§6.1) | PDK-139 | `server/migrations/paddock/00079_read_audit_window.sql` |
| `index_purge` (§6.2) | PDK-140 | `server/migrations/audit/00007_index_purge.sql` |
| `audit_exports` (§6.2) | PDK-142 | `server/migrations/audit/00008_audit_exports.sql` |

Reserved: paddock `00074`–`00076` (2026-10-30: `read_audit_window` is `00079`, see the PDK-583 round 3
amendment), audit `00007`–`00008`. `change_set_before_purge` is **not** created (A3). The
"next free number" rule of §3.0 is replaced by these fixed numbers; a ticket that finds its number taken stops
(§12). In `00008_audit_exports.sql` the `DO` block stays as written: `audit_manifest` already has the `reader`
policy from `00004`, `audit_object` has none and gets it here together with its `SELECT` grant.

### A3. Retention round: one round, four passes (decisions 11–16, 21, 15a)

- `worker.Retention` (`server/internal/worker/retention.go`, §6.6) **replaces** `worker.LoginHistory`:
  `server/internal/worker/loginhistory.go` is deleted in PDK-137, `app.LoginHistory` and its `Purge` are unchanged.
  `Round` iterates `pool.OrganizationIDs` under `WithLeaderLock(sys, retentionLockKey, …)` with
  `retentionLockKey = 0x7061646420726574` and calls per organization, in this order, each in its own `RunTx`:
  1. `app.LoginHistory.Purge(ctx, now)` (existing; store `device_login_event`) — PDK-137
  2. `app.Retention.PurgeUserSeen(ctx, now)` (store `device_user_seen`) — PDK-137
  3. `app.Retention.PurgeRetiredInventory(ctx, now)` (per device, `device.inventory_purged`) — PDK-138
  4. `app.Retention.PurgeReadWindows(ctx, now)` (store `read_audit_window`) — PDK-139
  PDK-180 appends its stores after pass 4. A pass that does not exist yet is not called (no stubs). The constructor
  is `NewRetention(a *app.Retention, history *app.LoginHistory, pool *db.OrgPool, platform *db.PlatformPool,
  interval time.Duration) *Retention`; `app.Retention` is constructed with `unit = config.RetentionUnit(l, common)`
  (type `time.Duration`; the `RetentionUnit` type of §6.6 is dropped, `app.Retention.unit time.Duration`, as
  `app.LoginHistory.day`).
- Interval: `PADDOCK_RETENTION_INTERVAL` (`config.Loader.Duration`, default `worker.RetentionInterval = 6h`). When the
  unit is seconds and the variable is unset, the interval is 15 s (today's development behaviour of the login
  history round, which gate `TestLoginHistory` relies on). `compose.dev.yaml` sets
  `PADDOCK_RETENTION_INTERVAL: ${PADDOCK_RETENTION_INTERVAL:-15s}` on `paddock-worker`.
- Metrics (decision 15): `paddock_retention_last_success_timestamp_seconds{store}` and
  `paddock_retention_deleted_total{store}` for the stores `device_login_event`, `device_user_seen` (PDK-137),
  `retired_inventory` (PDK-138), `read_audit_window` (PDK-139); `paddock_retention_stores` is 2 after PDK-137, 3
  after PDK-138, 4 after PDK-139; PDK-180 adds its stores to the constant.
- Decision 15a (`change_set.before`) leaves this milestone: the column does not exist and is introduced by plan M11.
  The M11 ticket that creates `change_set.before` adds pass `PurgeChangeSetBefore` to this round (same shape as pass
  2, store `change_set_before`, 90 days) and the `UPDATE` grant in its own migration. PDK-137 and PDK-147 do not
  check for the column any more.
- `PurgeUserSeen` runs its batches inside one `RunTx` per organization as decision 13 finally states (the "every
  batch its own RunTx?" aside is not a choice).

### A4. Residual-risk numbers (decision 4)

`docs/compliance/residual-risks.md` on main ends at **RR-93**. The three risks of decision 4 are **RR-94** (deletion
lag in backups), **RR-95** (evidence export is an egress of personal data), **RR-96** (index purge equals WORM
expiry), appended to section "Control plane and audit domain". Every "RR-35", "RR-36", "RR-37" of decisions 1, 4, 26
and §13 of this plan reads RR-94, RR-95, RR-96. ADR 0032 §1 ("residual risk RR-35") needs a one-line amendment by the
architect (reported; not part of a ticket). The DPIA input of decision 26 lists RR-01, RR-06, RR-15, RR-20, RR-94,
RR-95.

### A5. Read-access recording and MCP (decisions 18–20)

- The actor key of the window is `principal.ID` for portal **and MCP sessions** (same account, ADR 0044) and
  `principal.APITokenID` for API-token principals (`principal.APITokenID != uuid.Nil`).
- An MCP-session read with the switch on records `audit.searched` / `device.inventory_viewed` with source `mcp`
  and actor `client` through the unchanged runner; no MCP-specific code in `ReadAudit`. Unit test in
  `server/internal/app`: a principal with `Channel: principal.ChannelMCP` records once per window like a portal
  principal and shares the window with the same account's portal session.
- `ListAuditEvents` is `func (h *handlers) ListAuditEvents` in `server/internal/transport/http/admin/handlers.go`
  (receiver `handlers`, lower case; the same for `handlers_inventory.go`). `GET /api/v1/devices/{id}/audit` does not
  exist (confirmed); the device audit tab filters by `target_id`.

### A6. Export builder details (decisions 29, 31–36)

- `ListAuditVerificationRunsOverlapping :many` in `server/internal/adapters/auditpg/queries/audit.sql`:
  `SELECT * FROM audit_verification_run WHERE organization_id = @organization_id AND from_day <= @to_day AND
  to_day >= @from_day ORDER BY started_at DESC LIMIT 100`.
- `Verifier.Verify` returns `*Report{Days, Objects, Problems}`; `verification.ok = report.OK()`.
- The generated strict-server response type of the download is whatever `make gen` names for
  `application/x-tar` (pattern: `DownloadDeviceHeader200ApplicationoctetStreamResponse{Body, ContentLength}` in
  `handlers_disk.go`); the stop condition on buffering stands.
- `requested_by` is the principal as `audit.Actor` without `IP`; the `Client` field (MCP) is kept when set.
- Export requests from an MCP session are refused by the runner's step-up rule (`checkStepUp` refuses
  `Channel == mcp`) with 403 `step_up_required` and a denied event — no exception for exports.

### A7. Gates (§8–§10)

- **E2** reads: let `n0` be `total` of `GET /api/v1/audit-events?from=<today 00:00Z>&page_size=10` for the fresh
  organization after `waitForEvents` settled and **before** `audit seal`; the export of `[today, today]` becomes
  `ready` within 60 s with `event_count == n0` and `verify_ok == true`. Events recorded after the seal (the request's
  own `audit.export_requested`, the `audit.export_completed`) are filed under the next unsealed day and are not in
  the package; the gate MUST NOT "wait for them".
- **R1** keeps `TestLoginHistory` green (same round, same 15 s development interval).
- **E1–E4** use `tempUser(t, "export-auditor", env.RoleGroup(slug, "auditors"))` and `stepUp(t, portal, user,
  true)` of `test/acceptance/helpers.go` (works for temporary users; `TestAuditIntegrity` is the pattern). The §12
  stop condition "step-up helper cannot act for an auditor" is void.
- Playwright (decision 37): `web/e2e/auditIntegrity.spec.ts` (temporary auditor, `loginWithPassword`) and
  `auth.ts::stepUp(page, start, username, passwordFile, totpKeyFile)` are the patterns; when the temporary user of
  `auth.ts::tempUser` carries no TOTP key, the spec asserts the dialog and the redirect start only (fallback of
  decision 37 unchanged).
- Every ticket runs only its own named acceptance gates locally (`make acceptance T=…`, on the cluster's assigned
  stack) because CI does not run them on cluster pull requests; the full acceptance run is the cluster PR's CI
  (A1, PDK-526).

### A8. Documents (decisions 1–6, 26, 39, 40)

- `docs/compliance/retention.md` carries ADR 0032 §1 **plus** the rows of its amendments 2026-10-17 (login history,
  hardware facts) and 2026-10-18 (PDK-180 periods) as one table; "What is not purged yet" lists only the rows whose
  purge still reads "None in this milestone" after both amendments (device record, escrow of retired devices,
  `device_bundle_report`/`device_resource_status`, `admin_account`/`api_token`, chain metadata) and names PDK-180
  for the rows the amendment decided.
- `docs/architecture.md` amendment blocks (decision 6) are dated `> **Amendment 2026-10-29 (M10, ADR 0032):**`
  and appended after the existing `Amendment 2026-10-15 (M8b)` block at the end of §14.4 and after the
  `Amendment 2026-10-18 (M8h)` block at the end of §16.1. The plan is the architect decision CLAUDE.md requires.
- `docs/operations/local-dev.md`: PDK-137 adds `PADDOCK_RETENTION_UNIT` and `PADDOCK_RETENTION_INTERVAL`, PDK-143
  adds `PADDOCK_AUDIT_EXPORT_POLL_INTERVAL`, each as a row of the development-only list (section "Only active with
  `PADDOCK_ENV=development`").
- `docs/operations/paddockctl.md`: the command row joins the table under "## Commands"; the section "Verifying an
  evidence package" follows "## Restore commands".

### A9. Cluster cut and order

One cluster branch `cluster/evidence-privacy` from main (after `cluster/server-security` and `cluster/mcp` merged).
Three lanes; a lane is serial, lanes run in parallel in separate worktrees:

| Lane | Tickets (serial) | Starts |
| --- | --- | --- |
| Docs | PDK-135 → PDK-141 | at once |
| Worker | PDK-136 → PDK-137 → PDK-138 → PDK-139 → PDK-180 | at once |
| Audit writer and export | PDK-140 → PDK-142 → PDK-143 → {PDK-144 ∥ PDK-148 ∥ PDK-146} → PDK-145 → PDK-147 | at once |
| Deploy | PDK-149 | at once, independent |

Shared append-only files (`codes.go`, `en.json`/`de.json`, `admin.yaml`, `isolation_fixtures.go`,
`monitoring.md`, `alerts.yml`, `alerts_test.yml`) collide between the worker and the export lane; the second
ticket to merge rebases onto the cluster head. PDK-145 needs PDK-144 and PDK-148 merged (download link, keys card);
PDK-146 needs PDK-143 (`pkg/auditevidence`); PDK-147 is last. The heavy local gate at the cluster's end, on the
long-lived development stack, covers only what CI does not: `make e2e` (whole suite incl. `auditExports.spec.ts`
and `accessibility.spec.ts`), skill `frontend-verify` for `/settings/privacy` and `/audit/exports` as admin and
auditor, and one targeted rerun `make acceptance T='TestRetention|TestReadAccessAudit|TestAuditIndexPurge|
TestAuditEvidenceExport|TestLoginHistory'`. No VM system test (nothing on the agent changes), no disruptive gate.

### A10. Stop conditions added

- A migration number of A2 is already taken on the cluster head or main.
- `worker.LoginHistory` is referenced by code outside `server/cmd/paddock-server/worker.go` and
  `server/internal/worker/` (PDK-137 deletes it).
- A residual-risk number RR-94 to RR-96 exists on main when PDK-135 starts.
- `audit.Actor` or `audit.Event` gained a field that changes the stored event JSON of existing objects
  (`events.jsonl` must stay byte-identical to the WORM objects).

### Amendment 2026-10-30 (PDK-137, retention batching)

Architect decision after the external review of PDK-137; it changes A3 and A8 where they differ.

- **One transaction per batch (changes A3 "each in its own `RunTx`").** A pass deletes its expired rows in batches of
  1 000 rows, each batch in its own transaction, so a long backlog never holds the row locks of every expired row of an
  organization at once and the devices' login upserts do not wait for the purge. The pass still records exactly one
  `retention.purged` event per organization, store and round, through `app.ActionRunner.RunExternal`: transaction 1
  records the started action, the batches run as the "external" step, transaction 2 finishes the action with
  `deleted` = the rows of the committed batches. A failing batch rolls back alone; the batches before it stay deleted
  and the event has outcome failure with their number (never a number of rows that were not deleted). A crash between
  the transactions leaves a started action that the reaper records as outcome unknown. The helper is
  `app.purgeBatches`; `app.LoginHistory.Purge` and `app.Retention.PurgeUserSeen` use it. The cheap pre-check outside
  the action stays, so an organization without expired rows records nothing.
- **Index.** Migration `00075` also creates `device_user_seen_org_last_seen_idx ON device_user_seen (organization_id,
  last_seen_at)`, so every batch finds its rows through the index instead of rescanning the table (the RLS policy adds
  the organization). `device_login_event` already has `device_login_event_org_at_idx (organization_id, at)` (00054).
- **Lock key during a rolling upgrade.** The round holds `retentionLockKey` and, nested, the key of the replaced login
  history round (`0x70616464206c6f67`, "padd log"); while a worker of an earlier version holds that key, the round
  purges nothing in that run. The legacy key can be dropped once no release before PDK-137 can run next to a newer
  worker.
- **`PADDOCK_RETENTION_INTERVAL` is an operator setting (changes A8).** It is honoured in production, with a minimum of
  1 minute unless `PADDOCK_ENV=development` (`config.RetentionInterval`, a shorter value stops the start naming the
  variable); `paddock prodcheck` fails on a value below 1 minute. Development keeps the 15 s default when the unit is
  seconds. The variable is not in the development-only list of `docs/operations/local-dev.md`; it is documented with
  the worker's retention metrics in `docs/operations/monitoring.md`. `PADDOCK_RETENTION_UNIT` stays development-only.
- **Residual race (open for the architect).** Between the pre-check and the first batch a login can refresh the only
  expired rows; the pass then records a success event with `deleted` 0, which is truthful. Moving the check into the
  action's transaction does not remove it: an action that has started always records its event, and ending an action
  without recording it would need a new `ActionRunner` step outside its one-event-per-attempt contract.

### Amendment 2026-10-30 (PDK-137 fix round 2, pass budget and locks)

Architect decision after the second external review of PDK-137; it changes the amendment above where they differ.

- **Time budget per pass.** A pass stops after the batch during which 5 minutes (`app.retentionPassBudget`) have
  elapsed, comfortably below the outbox reaper's threshold (`outbox.DefaultReaperThreshold`, 10 minutes), and finishes
  its action cleanly with outcome success and `deleted` = the rows committed so far; the rows left over follow in the
  next round, with their own event. So every pass still records exactly one `retention.purged` event per organization,
  store and round, now possibly with a partial count, and a large backlog (e.g. after lowering `login_history_days`)
  never ends as an `unknown` action without `deleted`. Supersedes stub PDK-564.
- **Lock timeout per batch.** Every batch sets `lock_timeout` to 30 seconds (`app.retentionLockTimeout`) for its own
  transaction. A batch blocked longer by a row lock rolls back alone and ends the pass like an elapsed budget (outcome
  success, the rows committed so far), so a blocked `DELETE` cannot hold a pass past the reaper's threshold.
- **Both lock keys on one connection.** The round takes `retentionLockKey` and the legacy login history key on the same
  connection (`db.PlatformPool.WithLeaderLocks`), instead of nesting a second `WithLeaderLock` that needed a second
  pool connection without a timeout. When another session holds either key, the round purges nothing and the key it
  got is released again.
- **Upper bound of `PADDOCK_RETENTION_INTERVAL`.** Outside development the interval is at most 24 hours (besides the
  1 minute minimum): `config.RetentionInterval` rejects a longer one naming the variable, and `paddock prodcheck` fails
  on it. `docs/operations/install.md` lists the item.
- **Residual race.** The architect accepts the pre-check race of the amendment above as an open point; no
  `ActionRunner` extension.

### Amendment 2026-10-30 (PDK-140, audit index purge)

Architect decisions on reviews 1 and 2 of PDK-140. They amend decision 22 and the `audit_purge_partition` text of
§6.2; audit migration `00007_index_purge.sql` implements them and is the binding text from now on.

1. **Retention floor in the database, cutoff from the database's clock (review 2).** The function is
   `audit_purge_partition(p_month date, p_days integer)` and returns `(dropped, events, reason, cutoff, relid)`. It
   takes the index retention in days, not a cutoff, and computes `cutoff = now() - make_interval(days => p_days)` from
   the database's clock, so the writer's clock never decides what is dropped and a writer clock running ahead cannot
   trip the floor. It raises an exception (SQLSTATE `22023`) when `p_days` is `NULL` or below 400 (the check is
   `p_days < 400`), before it looks at any partition. The 400 days are hardcoded: they are a safety net under the Go
   checks (`Purger.Run`, `loadAuditDeps`) at the privilege boundary, not configuration, so a `paddock_audit_writer`
   session calling the function directly cannot drop events within the WORM retention. A Go test asserts that the
   function's floor equals `auditwriter.MinRetentionDays`; EXECUTE is granted only to `paddock_audit_writer`, the
   role that purges. `Purger.Run(ctx, dryRun)` takes no clock: it reads the report's cutoff for listing the due
   partitions from the database (`PurgeCutoff`, the same `now() - days`), and each `retention.purged` records the
   cutoff its own purge transaction returned (a failed drop, which returns none, records the report's cutoff). This
   supersedes stub PDK-565.
2. **Pinned search path and time zone (review 2).** The function is `SET search_path = pg_catalog, public, pg_temp`
   and qualifies every name with `public.` (also in the `format` calls: `public.%I`), so no temporary table can shadow
   a partition, as in audit migration `00006`. It is also `SET TimeZone = 'UTC'`, so the month boundary
   (`end_ts::timestamptz`) and the day arithmetic of the cutoff are the same in a caller session with another
   `TimeZone`; a test calls it under `Etc/GMT+12`, `Pacific/Kiritimati` and `Europe/Berlin`.
3. **Lock before the count (ratified deviation from §6.2 verbatim).** The function takes
   `LOCK TABLE ONLY public.audit_event, public.<partition> IN ACCESS EXCLUSIVE MODE` before it counts and drops.
   Without it, an event committed between the count and the `DETACH` would be dropped although it was recorded within
   the retention. A regression test pins this.
4. **Scan under the lock, with a sizing note.** `recorded_at` has no index on the partitions (audit migrations
   `00001`–`00006`), so the cheap locked re-check of an unlocked pre-read is not available, and `00007` creates no new
   index. The `count(*)`/`max(recorded_at)` scan stays under the lock (option a). Sizing: while it runs, every insert
   and read of `audit_event` waits. `lock_timeout` (5 s) bounds only the wait for the lock; the scan itself is bounded
   by the writer transaction timeout. A monthly partition whose sequential scan approaches that timeout fails as
   `purge_failed` every night and raises `PaddockAuditIndexPurgeStale`; operators with such volumes need an index on
   `recorded_at` first (a later audit migration, architect decision).
5. **Unknown commit outcome and the no-partition race.** When a drop's transaction ends with an error or is cancelled
   after the function reported the drop, the purger checks in a new session whether the dropped relation still
   exists, by the OID the function returned (`relid`, taken before the drop), not by the partition's name (review 2):
   the writer may already have created a partition of the same name again for a late event, and a partition someone
   else dropped before the purge transaction is no drop of the purge. If the relation is gone, it records
   `retention.purged` success without `deleted`, since the count was lost with the result. Without a function result
   that reported the drop, no `COMMIT` was sent, so the failure path applies. A writer
   transaction whose insert finds no partition (SQLSTATE `23514`, the purge dropped the month after
   `ensurePartitions`) is retried like the sealed-day refusal (`PA422`), and the retry creates the partition again.

`audit_ensure_partition` keeps its `search_path` weakness for now; it is fixed in audit migration `00009` (PDK-558),
not here.

### Amendment 2026-10-30 (PDK-138, retired inventory)

Architect decision after the external review of PDK-138; it changes decisions 16 and 17 and §13 "re-enrolled device"
where they differ.

- **Platform-scoped existence check before a Fleet host is deleted.** One Fleet serves every organization, and the
  organization scope of the retention pass cannot see another organization's re-enrolment of the same hardware. New
  decision: retention may use a platform-scoped existence check, read-only, boolean only. Before `DeleteHost` the
  device's action asks `db.PlatformPool.FleetHostInUse` (function `paddock_fleet_host_in_use`, migration 00076,
  `SECURITY DEFINER`, executable by `paddock_platform` only) whether, in any organization and other than the retired
  device itself, an inventory reference names the same Fleet host or an active or quarantined device has the retired
  device's hardware UUID (case-insensitive; also a device whose first inventory sync is still pending and has no
  reference yet). The answer is yes or no; no rows, organization IDs or device IDs of other organizations reach the
  caller, the logs or the audit. On yes the host stays in Fleet (`fleet_host_deleted` false) and the retired device's
  Paddock rows are purged as for re-enrolled hardware. When the check fails, the device fails closed: no Fleet call, no
  Paddock row deleted, a failure event. It replaces the organization-scoped reference count. Supersedes stub PDK-575.
- **No head-of-line blocking.** A failing device is recorded as its own `device.inventory_purged` failure event (target
  the device) and the pass goes on with the next device, within the pass budget and the 100-device limit. A pass with
  failed devices ends partial: its error counts them (`n of m devices failed`), the store's last success is not set,
  and `PaddockRetentionPurgeStale` stays the fallback alert.
- **A 404 counts as "already gone" only with Fleet's error body.** `DeleteHost` treats a 404 as a deleted host only
  when the body is Fleet's JSON error (`{"message": ..., "errors": [...]}`); any other 404 (a proxy, a wrong base URL)
  is a failure, so no deletion is recorded and the Paddock rows stay.
- **Return value and metric.** `PurgeRetiredInventory(ctx, now) (devices int, err error)` as in §6.6: the number of
  devices whose inventory it purged. `paddock_retention_deleted_total{store="retired_inventory"}` therefore counts
  purged devices, not rows; the other stores keep counting rows.

### Amendment 2026-10-30 (PDK-138, review 2 of the retired inventory)

Architect decisions on the external review after fix round 1 of PDK-138. They amend the amendment above where they
differ.

- **Migration number.** The function is in `00076_fleet_host_in_use.sql`; 00079 belongs to PDK-139 (renumbered 2026-10-30, see the PDK-583 round 3 amendment), 00077 is PDK-496.
- **Tri-state instead of "boolean only".** `paddock_fleet_host_in_use` returns `text`: `'ref'`, `'hardware'` or
  `'none'`, still never another organization's rows or IDs (`db.FleetHostUsedByRef`, `FleetHostUsedByHardware`,
  `FleetHostUnused`; any other answer fails closed). `'ref'`: another device of any organization references the host;
  the host stays and the retired device's Paddock rows are purged. `'hardware'`: no reference, but an active,
  quarantined or **pending** device with the same hardware UUID (case-insensitive) has no inventory reference yet; the
  host stays and so does the retired device's `device_inventory_ref` row, while its software, findings and policy
  results are purged, so later rounds list the device again and decide once that device has synced (its reference
  then names the same host, `'ref'`, or another one, `'none'`) or is gone. `'none'`: the host is deleted. The event
  records the answer in the new parameter `fleet_host_in_use` (absent when the device had no host or the check did
  not run); `fleet_host_deleted` stays false for `'ref'` and `'hardware'`.
- **Hardening.** The function is `SET search_path = pg_catalog, public, pg_temp` and qualifies its tables with
  `public.`; a test asserts that `paddock_worker` and `paddock_api` get permission denied and `paddock_platform` may
  execute it.
- **Paging within the pass.** The 100-device limit is the page size of one listing, not a cap of the pass: after a
  page the pass lists the next one after the last listed `(state_changed_at, id)` (kept in memory, no new column) until
  the budget elapses or no device is left, so devices behind ones that keep failing are reached in the same pass.
  Every round still starts at the head; with a budget that never gets past failing devices at the head, the tail can
  still starve across rounds (`PaddockRetentionPurgeStale` stays the alert).
- **Fleet breaker per round.** After three consecutive `upstream_unavailable` failures of the Fleet deletion, the
  round (state `app.RetentionRound`, created per round and passed into every organization's pass, no globals) starts
  no further retired-inventory device in any organization. Instead of one event per skipped device, each organization
  with due devices that the round skips gets one `retention.purged` failure (`store` `retired_inventory`,
  `upstream_unavailable`); the skipped devices keep all their rows. A successful Fleet deletion resets the count.

### Amendment 2026-10-30 (PDK-142)

Architect decisions on the review of PDK-142 (stubs PDK-580 and PDK-581, folded into PDK-142). Audit migration
`00008_audit_exports.sql` was not yet on `main` and implements them; it is the binding text from now on.

1. **Reader inserts only pending requests (§6.2 corrected).** The `reader` policy on `audit_export` pins the status and
   the builder's columns on insert, so no SQL path running as `paddock_audit_reader` can insert an export that looks
   built or verified. The §6.2 text of that policy reads:

   ```sql
   CREATE POLICY reader ON audit_export TO paddock_audit_reader
     USING (organization_id = current_setting('paddock.org_id')::uuid)
     WITH CHECK (organization_id = current_setting('paddock.org_id')::uuid AND status = 'pending'
       AND started_at IS NULL AND ready_at IS NULL AND expires_at IS NULL AND event_count IS NULL
       AND object_count IS NULL AND size IS NULL AND package_sha256 IS NULL AND verify_ok IS NULL
       AND verify_problems IS NULL AND signature IS NULL AND key_version IS NULL AND error IS NULL);
   ```

   A test asserts that the reader cannot insert a row with another status or with any builder column set.
2. **Decision 29: `InOrgWrite` ratified.** `external` runs the checks and `InsertAuditExport` in one
   `reader.InOrgWrite` transaction (read-write, same organization context and RLS as `reader.InOrg`), since a
   `READ ONLY` transaction cannot insert. `Get`, `List` and the download keep `reader.InOrg`. `docs/architecture.md`
   §4.1 carries a dated note that the reader also inserts pending export requests.
3. **Purpose characters (decision 29).** Besides C0 controls other than tab, newline and carriage return, `prepare`
   refuses C1 controls (U+0080–U+009F) and bidi controls (U+202A–U+202E, U+2066–U+2069) in `purpose` with
   `400 invalid_request` before any parameter is set, because the evidence package and the portal show the purpose to
   auditors. Tab, newline and carriage return stay allowed.

### Amendment 2026-10-30 (PDK-143: no organization slug in the export)

Architect decision during PDK-143. The audit domain has no source for an organization slug: `audit_export` has no
slug column, the audit database has no organization table, and the audit writer has no access to the `paddock`
database. Where this amendment and §6.5, §6.7 or decision 32 differ, this amendment wins.

1. **`export.json` has no `organization_slug`.** The field is removed from the §6.5 example and from
   `pkg/auditevidence.Export` (§6.7); it is not written as an empty string. A signed evidence file carries only what
   the audit domain can vouch for, and a slug can change while the organization ID cannot.
2. **The README names the organization by its ID only.** Its first sentence reads "Organization
   `<organization_id>`, recording days `<from_day>` to `<to_day>`, …"; the rest of the §6.5 text is unchanged.
3. **No migration, no change to the request API.** A slug snapshot taken at request time (an `audit_export` column
   filled by PDK-142's request path) would need an audit migration and is not part of this milestone; it is recorded
   as a low-priority follow-up stub.
4. **The README is not covered by the signature.** `export.sig` signs `export.json` only; the offline verifier
   (PDK-146) treats `README.md` as informational and takes every fact from `export.json`.
5. **Objects the builder does not decode** (review of PDK-143). An object whose SHA-256 differs from its manifest
   entry, or whose decompressed size exceeds 256 MiB, is still packed verbatim under `objects/` but contributes no
   lines to `events.jsonl` and has `event_count` 0; the problem is in `verification.problems` (the mismatch text of
   decision 32, or `"<day>: object <key> cannot be decoded"`) and `verify_ok` is false. The offline verifier reports
   such an object's hash or decode problem and builds the expected `events.jsonl` without it.

### Amendment 2026-10-30 (PDK-583, review leftovers of the retired inventory)

Architect decisions on the non-blocking findings of PDK-138's third review. They amend the amendment above where they
differ.

- **Breaker counts only transient Fleet failures.** `ports.InventoryAdmin.DeleteHost` classifies its errors: Fleet
  failing or unreachable (5xx, timeout, connection error, and statuses that concern Fleet or the way to it rather than
  the host: 401, 403, a 404 without Fleet's own error body, 408, 429) is `upstream_unavailable`; Fleet refusing
  this one host or an invalid host reference is `invalid_state`. Round 2 below narrows the refusal and covers
  redirects. Both fail the device with one
  `device.inventory_purged` failure event and keep its rows. Only `upstream_unavailable` counts toward the round's
  breaker; a refusal neither counts nor resets the count, a successful deletion resets it. Permanently refused hosts at
  the head of one organization therefore no longer skip the retired inventory of every organization.
- **A persisting `'hardware'` answer records no event.** (Replaced by round 2 below: the derived "unchanged" check
  missed a first sight and a change from a failure.) Before starting a device's action, the pass reads the
  device's remaining inventory; when nothing but the host reference is left and the host check answers `'hardware'`,
  the pass starts no action and only logs. The round that purged the other rows recorded the answer; the next event
  follows when the answer changes to `'ref'` or `'none'` and the reference is deleted. No new column: "unchanged" is
  derived from the remaining rows, since `'hardware'` is the only answer that leaves the reference without other
  rows. A device that had nothing but the reference when it was first listed records no event until the answer
  changes, because nothing is deleted. The check is read-only and fail-safe (an error starts the action, which
  re-checks under the row lock and records the outcome), so the one-event-per-attempt rule holds: a skipped device is
  no attempt. `paddock_retention_deleted_total{store="retired_inventory"}` therefore counts only devices whose rows
  were deleted.
- Open, not decided: x3 (two Fleet hosts of the same hardware) and x4 (no event for a pass-level failure). Both are
  decided in round 2 below.

### Amendment 2026-10-30 (PDK-583 round 2, review 1 of the leftovers)

Architect decisions on review 1 of PDK-583. They amend the amendment above where they differ.

- **B1: only Fleet's own refusal is `invalid_state`.** A 4xx is Fleet's refusal of this one host only when it carries
  Fleet's JSON error body (`{"message": ..., "errors": [...]}`, the same check that makes a 404 "already gone") and
  is not 401, 403, 404, 408 or 429. Any other 4xx (a proxy or ingress in front of Fleet answering 405, 407, 421, or 400
  without Fleet's body) fails every host alike and is `upstream_unavailable`, so it trips the breaker.
- **Redirects (PDK-586, folded in).** The Fleet client does not follow redirects (`CheckRedirect` returns
  `http.ErrUseLastResponse`): Go would turn a redirected DELETE into a GET whose 200 reads as a deleted host. Every 3xx
  is `upstream_unavailable`.
- **A canceled context** (shutdown) is neither `upstream_unavailable` nor `invalid_state` and does not count toward
  the breaker.
- **x3: a host still checking in is kept.** When the host check answers `'none'`, the device's action first reads
  Fleet's last check-in of the host (`ports.InventoryAdmin.HostSeenAt`, the host detail without software). A host
  seen **after the device's retirement and within 7 retention days of now** is still in use, by fleetd still running
  on the retired machine or by a successor without a reference of its own. It is kept with the retired device's
  reference like `'hardware'`; the other Paddock rows go. The event records `fleet_host_kept` `seen_recently` and
  `fleet_host_seen_at`. A host seen only before the retirement or longer ago, never seen, or no longer known is
  deleted, so gate R2 (host seen just before the retirement) stays deterministic. A failing lookup fails closed: no
  deletion, all rows kept, one failure event; an `upstream_unavailable` lookup failure counts toward the breaker like a
  failed deletion. The 7 days are retention days (`PADDOCK_RETENTION_UNIT`).
- **M1: the kept answer is persisted.** Paddock migration 00078 adds `retention_inventory_hold` (`device_id` primary
  key referencing `device` with `ON DELETE CASCADE`, `organization_id`, `last_answer` `'hardware'` or
  `'seen_recently'`, `unchanged_rounds`, `last_event_at`; ENABLE and FORCE row level security, the organization policy
  without `missing_ok`, granted to `paddock_worker` only). A successful action that keeps the host stores its answer
  (`fleet_host_kept`) with zero rounds. Before a listed device's action, the pass compares: when the device has a held
  answer, nothing but the host reference is left and the current answer (the host check and, on `'none'`, the
  check-in lookup) equals the held one, the pass starts no action, counts the unchanged round and logs. Otherwise it
  drops the held answer and the action runs, so every change of answer records one event: a first sight, a change from
  a failure or `'none'` to a kept answer, between `'hardware'` and `'seen_recently'`, and from a kept answer to the
  host's deletion. An action that fails therefore leaves no held answer, and the next kept answer is recorded again.
  A skip is no attempt and starts no action, so the one-event-per-attempt rule holds. The row goes when the answer
  changes and with the device.
- **Bound: one notice after 30 unchanged rounds.** The round that reaches 30 unchanged rounds of a held answer
  records one `device.inventory_host_kept` success event (new code; `fleet_host_kept`, `rounds`) in the same
  transaction as the count, and deletes nothing. Later unchanged rounds record no further notice; a change of answer
  starts over. It is a notice in the audit trail, no alert.
- **x4: a pass-level failure records one event.** A failure loading the organization's privacy settings or listing
  the first page of its retired devices records one `retention.purged` failure (`store` `retired_inventory`) for the
  organization and round, through `RunTx` like the breaker skip.

### Amendment 2026-10-30 (PDK-583 round 3, review 2 of the leftovers)

Decisions on review 2 of PDK-583. They amend M1, x3 and the bound above where they differ.

- **The held answer is consistent with the last event.** A device's action never runs while the device has a held
  answer: before the action the pass drops the held answer in a transaction of its own, also when it could not read
  it, and when the drop fails the device is skipped this round and the pass fails (no action, no event). The action
  sets the held answer, or drops it on a failure or when nothing is kept, in the transaction that records its outcome.
  A held answer therefore always belongs to the last event of the device.
- **The held answer belongs to one retirement.** `retention_inventory_hold.retired_at` (migration 00078) stores the
  device's `state_changed_at` with the answer. When it differs from the listed device's (reactivated and retired
  again), the answer counts as changed: the action runs, records its event and starts the count over.
- **A lookup blip neither records an event nor restarts the count.** The comparison's host check and check-in lookup
  run under the same bound as the action's Fleet step (`fleetDeleteTimeout`). When the check-in lookup of a held
  device fails with `upstream_unavailable`, the device keeps its held answer and its count, is skipped this round
  without an action or event, the pass fails (the worker logs it and the store's last success does not advance) and the
  failure counts toward the round's Fleet breaker like a failed lookup in an action. Any other failure of the
  comparison lets the action run; it checks again and records the outcome.
- **The breaker is reset only by a deleted host.** A successful lookup does not reset it, so a proxy that answers
  reads but fails every deletion still trips it.
- **`paddock_retention_deleted_total{store="retired_inventory"}` counts a device only when rows or its Fleet host were
  deleted**; a first sight or changed kept answer of a device with nothing but its host reference left counts nothing.
- **`HostSeenAt` fails closed on a foreign answer.** A 200 without a host object (or host id) or without `seen_time`
  is `upstream_unavailable`: Fleet always sends both, and a host that never checked in carries Fleet's zero time. Only
  Fleet's own 404 reads as a host that is gone.
- **`device.inventory_host_kept` declares `failure`**: a notice that cannot be recorded fails with the count and is
  retried the next round.
- **Migration numbers (renumbered 2026-10-30).** The hold table is paddock migration 00078; PDK-139 moves to 00079, so
  the cluster leaves no gap of its own even if PDK-139 lands last (goose refuses missing versions). This supersedes the
  "00078 belongs to PDK-139" note of the PDK-138 amendment; §6.1's table names 00079 for `read_audit_window`. Merge
  order to main: 00076 (PDK-138), 00077 (PDK-496), 00078 (PDK-583), 00079 (PDK-139); the next migration merged into
  the cluster takes the next free number.
- **Architect-confirmed (2026-10-30).** Two choices of this round are confirmed by the architect: a check-in lookup
  blip skips the device without an event, counts toward the breaker and leaves the stale alert as the safety net (no
  deletion on uncertainty); the breaker resets only after a real deletion, because a successful lookup proves nothing
  about DELETE. Scattered timeouts that trip the breaker stop the deletions of that round and the next round retries;
  a windowed count is decided in PDK-589.

### Amendment 2026-10-31 (PDK-605: README covered by export.json; decision 35 as built)

Architect decisions 2026-10-30 (PDK-143 amendment items 4-5, PDK-144 decision 35), implemented in PDK-605, which
folds in PDK-599. Where this amendment and §3.9 decision 35, §6.5 or the amendment "PDK-143: no organization slug in
the export" differ, this amendment wins.

1. **Item 4 of the PDK-143 amendment is replaced: the README is covered by the signature.** `export.json` gains
   `readme_sha256` (lowercase hex SHA-256 of the `README.md` member bytes; §6.5 example updated). `export.sig` signs
   `export.json`, so a README altered in transit fails `paddockctl audit verify-export`: a mismatch, a missing README
   or an `export.json` without the field is a problem (`verify_ok=false`). This is not circular: the README holds
   only values of `export.json` that exist before signing, never the hash of `export.json` or of the signature. It
   also names the signing key version and fingerprint, which the signer decides; the exporter renders the README for
   the newest published key before signing and renders and signs once more if the signer used another version.
2. **Decision 32/§6.5 override stays as written in the PDK-143 amendment item 5** (an object that is modified or
   cannot be decoded is packed verbatim without events and sets `verify_ok=false`).
3. **Decision 35 as built.** The download reads each chunk in its own short `reader.InOrg` transaction (by primary
   key), so a slow client holds no audit-reader connection between chunks; the export row is looked up before the
   action's `RunTx` and reused for the headers, with no second readiness check after the event. The transfer has
   write deadline 60 s per piece and an overall cap of `max(10 min, size / 64 KiB/s)`, itself capped at 24 h so a huge
   recorded size cannot overflow the duration. `size <= 0` counts as not ready.
4. **A chunk that goes missing mid-stream aborts the stream.** The use case returns an error, the handler ends the
   body short of `Content-Length` without appending a problem body, and no second event is recorded (one event per
   attempt, recorded before the first byte). The final size and SHA-256 check stays. Covered by
   `TestAuditExportDownloadChunkRemovedMidStream`.
5. **HEAD is refused with 405 (`Allow: GET`)** before the use case and audited as one rejected request, because
   net/http would otherwise run the download for a body that is never sent.

### Amendment 2026-10-30 (PDK-139 round 2, read-access recording)

Architect decisions after review 1 of PDK-139. Where this amendment and decisions 18–21, §6.4 or §6.6 differ, this
amendment wins.

1. **Accepted deviations.** (1) Both codes declare success, failure and denied (decision 18 emits failure).
   (2) The development retention unit never purges a key younger than 24 hours; production keeps 48 hours.
   (3) `PurgeReadWindows` deletes in batches of 1 000 like every other pass. (5) A denied role is recorded whatever
   the switch, because authorization precedes the switch.
2. **Deviation (4) changed: refused reads are recorded.** With the switch on, every authenticated attempt records
   exactly one event. A refused read records `failure` with the problem code as reason: a range the list refuses
   (`invalid_request` for from ≥ to, `range_too_large` beyond 92 days), handler input errors (`invalid_request`,
   `page_out_of_range`) and a missing or foreign device (`not_found`, target the requested device ID, as for other
   refused actions). A failure claims no window (the transaction rolls back). With the switch off nothing changes:
   no event, the list refuses as before. Input the OpenAPI request validator rejects never reaches the handler and
   records nothing.
3. **(a) Cancellation.** `RecordReadOnce` reads the switch in its own step (`enabled`) before `claim`. A
   `context.Canceled` before that step has read the switch records nothing; after it, the normal rules apply (switch
   off: nothing; switch on: a claim error is recorded as failure with reason `canceled`).
4. **(b) Foreign target IDs.** `audit.searched` records `target_id` only when it names a device of the caller's
   organization (RLS-visible `GetDevice` in the claim transaction); otherwise `target_id` is omitted and
   `target_id_used: true` is recorded (registry param). The isolation gate's globex `target_id` therefore never
   enters acme's trail. Other object types (users, groups) are recorded as `target_id_used` only.
5. **(c) Window key of `audit.searched` (amends decisions 19 and 20).** The key is `(actor key, "audit.searched",
   filter hash, now.UTC().Truncate(time.Hour))`; the filter hash (SHA-256, hex, stored in the key's `target_id`
   column) covers the normalized filters as recorded: the requested `from`/`to` (empty for a default end, so a default
   range keeps its key within the hour), the registered codes and `codes_unknown`, outcomes and actor types (sorted,
   without duplicates), the resolved `target_id` or `target_id_used`, and `q_used`. The search text never enters the
   hash, so event counts cannot tell two texts apart. `device.inventory_viewed` keeps `(actor key, device ID, UTC
   day)`. The list and the recording resolve default range ends against one clock (`AuditQuery.Now`).

### Amendment 2026-10-31 (PDK-139 round 3, read-access recording)

Architect decisions after review 2 of PDK-139 and the external review. Where this amendment and the amendment of
2026-10-30 (PDK-139 round 2) differ, this amendment wins.

1. **The switch unknown → no event and no data (replaces round 2 item 3 before the switch).** Any error before
   `enabled` has read the switch — a cancellation, a passed deadline, a failed pool acquire, `BEGIN` or `set_config`,
   a database error of the settings read — records nothing and is returned: the read itself fails with an error
   response, and the list is not served.
2. **The switch off → nothing, whatever fails afterwards.** Once the switch was read as off, `RecordReadOnce` never
   records, also when the commit fails or the request is canceled after the switch read; the error is returned
   unrecorded.
3. **Target of a refused inventory view (amends round 2 item 2).** `device.inventory_viewed` sets the device as target
   only after `GetDevice` resolved it within the caller's organization. Input errors, a missing or foreign device and a
   failed lookup record `target_id_used: true` (registry param of `device.inventory_viewed`) and no device ID, so
   another organization's device ID never enters this organization's trail.
4. **One range, millisecond-truncated.** `AuditQuery.effectiveRange` truncates `from` and `to` to the millisecond of
   audit timestamps once, so the recorded range, its filter hash and the list search identical bounds.
5. **Registry notes.** The notes of `audit.searched` and `device.inventory_viewed` name every emitted failure reason
   (`invalid_request`, `page_out_of_range`, `range_too_large`, `not_found`, `canceled`, `internal`) and that an
   unreadable switch records nothing.
6. **Transparency notice.** The notice and the portal hints say that only the first access per window is recorded.
7. **Failure events are not coalesced.** Each refused read with the switch on records one failure event; the DPIA
   input says so. A follow-up coalesces failures per actor, problem code and hour.
8. **Accepted (R2-m2).** (i) Input the OpenAPI request validator rejects never reaches the handler and records nothing.
   (ii) Only devices resolve a `target_id` of `audit.searched`; users, groups and other object types are recorded as
   `target_id_used` only.
9. **The search text stays out of the filter hash** because it can contain personal data (a searched employee's name):
   neither the event nor its window key may tell two texts apart.

### Amendment 2026-10-31 (PDK-606, CVE device-list view)

Architect decision (d) of PDK-139 round 2, with the window of round 3.

1. **New code `vulnerability.devices_viewed`** (registry, outcomes success, failure, denied; params `cve`,
   `device_count`, `window_start`). It is recorded by `GET /api/v1/vulnerabilities/{cve}/devices` through
   `RecordReadOnce` before the list, while `inventory_view_recorded` is on. The switch off records nothing, an
   unreadable switch records nothing and fails the read (round 3 item 1), a refused read (malformed CVE, listing
   error, CVE without finding in the organization → `not_found`) is a failure with its problem code, a role outside
   the read roles is denied. Authorization is that of the list (`RolesRead`), so recording does not change who may read.
2. **Window `(actor, cve, UTC clock hour)`** in `read_audit_window`: the CVE is stored in the key's `target_id` column;
   no migration. The CVE is a public identifier that matched the CVE pattern. The search text `q`, paging and sort are
   not part of the key and never recorded.
3. **`device_count` is the number of distinct devices of the caller's organization** (active or quarantined) with a
   finding of the CVE, counted in the claim transaction under row-level security (query
   `CountDevicesWithVulnerability`) and only after the switch was read as on. It is the devices, not the finding
   rows the list pages over, and no device ID or name enters the event.
4. **Failure events stay uncoalesced** as for the other read codes (round 3 item 7).
5. The privacy pack (transparency notice, works-council annex, DPIA input, `privacy.md`) and the portal hint name the
   new event.

### Amendment 2026-10-31 (PDK-608: export builder hardening)

Implemented in PDK-608, which folds in PDK-595 and PDK-596. Where this amendment and decisions 31, 32 or 34 differ,
this amendment wins. No migration and no change to the API, the events or the package format.

1. **Expiry runs in its own loop (decision 31).** `Run` calls `Expire` every poll interval in a loop of its own, next
   to the pending-age loop, instead of after the claim/build loop, so a hung build delays neither expiry nor the stuck
   check. `Expire` deletes the chunks of failed and expired exports first, then expires and fails as in decision 34,
   so an error in those passes cannot skip the sweep.
2. **A build is bounded by `ExportStuckAfter` (decision 32).** The whole build, including every object-store read,
   runs under a deadline of 2 h; when it passes, the export fails with `error: "the build took longer than 2h0m0s: …"`
   and one failure event, unless the stuck check failed it first (then its event is the only one). The deadline counts
   from the start of the build, the stuck check from `started_at`, so the stuck check usually fails a hung export
   first; the bound then mainly ends the hung build and frees its goroutine.
3. **Chunks are inserted only while the export is running (decision 32 step 4).** `InsertAuditExportChunk` inserts
   only when the export is `running`, read under a share lock in the same statement, so it either waits for a stuck
   check in flight or sees its result. An insert that inserts nothing fails the build like `errNotRunning`: no
   further reads, no event (the stuck check recorded the outcome).
4. **The status read after a failed ready update is final (decision 32 steps 5–6).** It reads under the row lock
   (`GetAuditExportLocked`, `FOR UPDATE`, 30 s, outliving a shutdown), so a COMMIT still in flight is waited out.
   When it fails or still sees `running`, the build reads once more after `failRunning` matched no row; a `ready`
   export then takes the success path. When the first read failed, the build also reads once more before it gives
   up on a shutdown or on a failed `failRunning`. Every export that a build marked ready ends with exactly one
   `audit.export_completed` success event, unless no status read succeeds at all, in which case the export stays
   ready with its chunks.
5. **A failure or expiry whose COMMIT outcome is lost records its event exactly once (decisions 32 and 34).** The
   update of `failRunning` (build and stuck check) and the expiry update return the row's `xmin`, the id of the
   writing transaction. Only when the transaction's statements all succeeded and its COMMIT returned an error is the
   outcome unknown; then the caller reads the export under the row lock (as in item 4, `GetAuditExportLocked` also
   returns `xmin`) and records its one failure or `retention.purged` event only if the visible version carries its own
   `xmin`. A caller whose update matched no row, or whose transaction failed before the COMMIT, never reads and never
   records. So a rollback of this caller's write followed by another replica's identical write (same status, same
   `exporter restarted`) does not record twice. A failed read is retried once; if both reads fail the export stays
   `failed`/`expired` without its event (neither list query sees it again) and the pass reports the error.
6. **The exporter's writes are bounded on the client side** by the writer transaction timeout plus 30 s:
   `markReady`, `failRunning`, the expiry update, every chunk delete (also the ones that outlive a shutdown) and the
   list queries of `Expire`. A hung connection or a lost acknowledgement cannot block the build or the stuck check
   beyond that bound; the locked status reads of items 4 and 5 have their own bound of 30 s.
7. **A failing expiry or stuck-check failure does not stop the pass.** `Expire` records the error, continues with the
   next due export, then runs the stuck check, which likewise continues with the next stuck export; the pass returns
   all errors joined.

### Amendment 2026-10-31 (PDK-593: export temp file and size limits)

Architect decision 2026-10-31 (PDK-593, with finding L3 of the PDK-143 external review), implemented in PDK-593.
Where this amendment and decision 32 differ, this amendment wins. No migration and no change to the API or the
package format; `audit.export_completed` gains the param `reason`.

1. **TMPDIR on a volume (decision 32 step 3).** `paddock-audit-writer` keeps `read_only: true`, but its `/tmp` is the
   named volume `audit-writer-tmp` instead of a tmpfs (`TMPDIR=/tmp`, `compose.audit.yaml`, used by the development
   stack, the audit host and the lab), so a large export uses disk, not the host's memory. The temp file of
   `events.jsonl` is unlinked right after `os.CreateTemp` and used through its open handle, so a writer killed during a
   build leaves nothing on the volume.
2. **`PADDOCK_AUDIT_EXPORT_MAX_BYTES`** (`paddock-audit-writer`, default `4294967296` = 4 GiB, a positive integer,
   otherwise the role refuses to start) bounds `events.jsonl` while it is written to the temp file and the whole
   package while it is written to the chunks. Exceeding either fails the build: status `failed`, `error` =
   `"export_too_large: events.jsonl exceeds PADDOCK_AUDIT_EXPORT_MAX_BYTES (<n> bytes)"` (or `the package exceeds …`),
   the chunks already stored deleted, exactly one `audit.export_completed` failure event with `error_code:
   "export_failed"` and the registered param `reason: "export_too_large"`.
3. **Object-store reads are bounded and streamed (L3; decisions 32 step 4 and the verifier of M8b).** Every manifest and
   object read of the exporter and of `Verifier` goes through `ObjectStore.Open` and `io.LimitReader` with the per-object
   limit `MaxObjectSize` (256 MiB, equal to the decode limit) and is hashed while it streams; a larger object is an
   error (`"… unreadable: larger than the per-object read limit (<n> bytes)"`): the build fails, the verifier reports
   it as a problem. The verifier hashes objects without buffering them. The first pass of the build buffers one object
   (at most the limit) because it decodes only bytes whose hash matched; the second pass streams each object straight
   into the tar with the size read in the first pass, and an object whose hash then differs fails the build (`"day <d>:
   object <key> changed during the build"`).
