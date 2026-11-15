# Implementation plan: M17 — Organization offboarding and identity-round performance

Status: accepted (architect arch-a11, 2026-11-14), release 0.1.0-alpha.11. Decision record: ADR 0052 (Accepted).
Binding language: **MUST** / **MUST NOT** / **SHOULD** / **MAY**. Tickets: PDK-1013 to PDK-1022 and PDK-946.

## 1. Goal

A platform administrator can delete an organization: its devices remove Paddock and keep working, every piece of the
organization's data is deleted after a grace period, and its audit evidence stays readable for platform administrators
until the WORM retention ends. Development stacks and acceptance gates use the same path to remove test organizations,
and the identity rounds of the worker no longer cost Authentik a request burst per organization every ten minutes.

## 2. Context

- **No deletion exists** (PDK-946 result, decision A10-23). `api/openapi/admin.yaml` has `listOrganizations`,
  `createOrganization`, `getOrganization`, `updateOrganization` (domains). `organization.status` is
  `provisioning|active|provisioning_failed|suspended` (`server/migrations/paddock/00001_init.sql`; `suspended` is
  never set by any code). Gate runs leave about 12 organizations per acceptance run; devstack held 376 on 2026-11-13.
- **Isolation** (architecture §5, CLAUDE.md): 74 tables with `organization_id`, `ENABLE` + `FORCE ROW LEVEL
  SECURITY`, policy on `current_setting('paddock.org_id')::uuid`; the only path into organization data is
  `db.OrgPool.InOrg(ctx, fn)` with the organization from the principal; platform scope is the separate pool/role
  `paddock_platform`; SQL only in `server/internal/platform/db` and the sqlc store. No foreign key to `organization`
  cascades.
- **Authentik objects per organization** (architecture §9.2, `server/internal/adapters/authentik/authentik.go`,
  `devicelogin.go`, `users.go`): groups `paddock.<slug>` and every `paddock.<slug>.*`; users created by Paddock
  (path `paddock/<slug>`, attribute `paddock_managed`); scope mapping `paddock-device-groups-<slug>`; OAuth provider
  and application `paddock-device-<slug>`; expression policy `paddock-device-<slug>-access` and its binding.
- **Object keys**: bundles bucket `org/<org>/devices/<dev>/bundles/*`, `org/<org>/icons/*`
  (`server/internal/compiler/compiler.go`), `apt/<org>/` (ADR 0050); escrow bucket
  `org/<org>/devices/<dev>/luks-header/*` and `.../diagnostics/*` (`pkg/escrow/escrow.go`); audit WORM bucket
  `org/<org>/...` (never deleted by Paddock, ADR 0032).
- **OpenBao has no per-organization path** (`server/internal/platform/bao/bao.go`, `testsupport/baotest`): the
  Transit keys are platform-wide; organization secrets are ciphertexts in PostgreSQL or object storage. Nothing in
  OpenBao is deleted by offboarding.
- **Valkey** (`server/internal/devicecache`): per device `dk:<key_id>`, `cmd:<dev>`, `cres:<cmd>`, `seq:<dev>`,
  `sd:<dev>`, `bp:<dev>`, `hb:<dev>`, `au:<dev>`, `diag:<cmd>`, `esc:<id>`, `nonce:<dev>:*`; per organization
  `tt:<org>`; sessions `sess:*`.
- **Uninstall** (ADR 0037 D3, `server/internal/app/uninstall.go::Uninstalls.Request`, `pkg/command` type `uninstall`
  default lifetime 7 days, `command.Verify` enforces no maximum lifetime): mode `leave` removes Paddock and keeps local
  accounts, Himmelblau, disk encryption and user data; the device's final event `agent.uninstalled` retires it.
- **Audit** (ADR 0010, 0030, 0032): the audit writer verifies every organization with audit data nightly and writes
  `audit.chain_verified` into its log; index retention ≥ WORM retention ≥ 400 days; the evidence export reads WORM
  objects through `audit_object`/`audit_manifest` (`server/internal/auditwriter/exporter.go`).
- **Identity rounds** (PDK-570, done in alpha.10): `IdentitySync.Reconcile` calls `EnsureOrganization(ctx, slug)` for
  every active organization every reconcile interval (10 min): 14 Authentik requests per organization
  (`TestIdentityRoundRequestCounts`: 200 organizations → 2 800 of 3 000 reconcile requests). The only input of
  `EnsureOrganization` is the slug plus the adapter code. At about 250 organizations `authentik-postgres` CPU stays
  high while nobody uses the stack (`decisions-alpha11.md` §2.1).
- ADRs: 0052 (Accepted, this milestone), 0032 (retention), 0037 (uninstall), 0007 (Authentik mapping), 0034
  (step-up), 0018 (lists and dialogs), 0013 (additive protocol).

## 3. Binding decisions

### Requirements

| ID | Requirement | Acceptance (who sees it) |
| --- | --- | --- |
| OFB-1 | A platform administrator requests the deletion of an organization with a step-up, the typed slug, a reason and a grace period; the request is cancellable until the grace period ends. | The platform administrator sees the organization as "deletion pending" with its date in the organization list and detail. |
| OFB-2 | Every active device of the organization receives an uninstall (`leave`) when the deletion is requested. | The organization administrator sees *uninstall pending* on every device; the device user keeps working after the removal. |
| OFB-3 | A device that has not reported its removal when the deletion runs removes Paddock at its next contact, for up to 365 days. | The platform administrator sees `platform.offboarded_device_uninstalled` in the platform audit log. |
| OFB-4 | After the grace period every datum of the organization outside the audit evidence is deleted: database rows, Authentik objects, Fleet hosts, objects, Valkey keys. | The platform administrator sees status `deleted` and the event `organization.deleted` with the counts per store. |
| OFB-5 | The organization's audit evidence stays until its retention ends and is readable only by platform administrators; an evidence export can be produced for auditors. | The platform administrator reads the deleted organization's audit log and downloads a verifiable export package. |
| OFB-6 | Each step is audited; a failing step is retried and visible. | The platform administrator sees the current step and the last error code on the organization. |
| OFB-7 | Organization administrators are warned during the grace period. | Every organization administrator sees a banner with the deletion date and what to secure. |
| OFB-8 | Acceptance gates delete the organizations they create; a dev-only `make` target deletes leftovers. | A developer sees no `Gate gate-…` organization after a full acceptance run. |
| IRP-1 | The reconcile round calls `EnsureOrganization` only for organizations whose desired Authentik state may have changed or whose last full check is older than 6 h, spread evenly. | The operator sees at 250 organizations ≤ 20 % of the baseline Authentik requests per reconcile interval (measurement ticket). |

### Decisions

1. **Lifecycle (ADR 0052 decision 1).** Pending = `status = 'active' AND delete_after IS NOT NULL`. Status values
   `deleting` and `deleted` are added; `suspended` stays untouched. Only `active` and `provisioning_failed`
   organizations can be deleted. A `provisioning_failed` organization has no devices and no data beyond its row and
   possibly Authentik objects; the same steps apply. Reason: the organization must stay usable during the grace
   period, and every existing `status = 'active'` check keeps working unchanged.
2. **Grace period.** `grace_days` is an integer 7–90 in production; 0–90 when the api runs with
   `PADDOCK_ENV=development` (gates, dev pruning). The portal proposes 30. Reason: production deletions need time for
   devices and administrators; gates need immediate deletion.
3. **Uninstall on request (ADR 0052 decision 2).** The deletion request issues `uninstall` `leave` with reason
   `organization_offboarding` to every `active` device in the same action, through a new use case method
   `Uninstalls.RequestForOffboarding(ctx, deviceID, expiresAt)` that skips the hostname confirmation and the
   per-device step-up, records **no** per-device `device.uninstall_requested` event, and is callable only from
   `Organizations.RequestDeletion`. The command's `expires_at` = `delete_after + 365 days`. A device with an open
   uninstall or an open revocation request is skipped and counted. Reason: one stepped-up platform action stands for
   all devices; per-device events would flood the organization's log that is about to close.
4. **Cancel.** `CancelDeletion` clears the deletion columns and calls the existing `Uninstalls.Cancel` for every
   device whose offboarding uninstall is not yet delivered; delivered ones run to completion (documented).
5. **Worker job.** A new round `worker.Offboarding` under leader lock `offboardingLockKey`, interval 1 min. It
   moves due organizations (`delete_after <= now()`) to `deleting` and runs the steps of decision 6 for every
   `deleting` organization, one step per organization per round, resuming from `organization.offboarding_step`.
6. **Steps, in this order** (constant `offboarding.Steps`): `sessions`, `devices`, `outbox`, `authentik`, `fleet`,
   `objects`, `valkey`, `audit_final`, `database`, `tombstone`. Each step is idempotent; a step that fails stores
   `offboarding_error_code` and is retried next round; the step records `organization.deletion_step_failed` only when
   the error code differs from the stored one. A completed step records `organization.deletion_step_completed`.
7. **Database deletion (ADR 0052 decision 4).** `paddock_offboard_delete_batch(max_rows int) RETURNS bigint`,
   `SECURITY DEFINER`, owner `paddock_owner`, `SET search_path = pg_catalog, public`, `EXECUTE` granted to
   `paddock_worker` only. It reads the organization from `current_setting('paddock.org_id')::uuid` (no parameter),
   raises `insufficient_privilege` unless that organization's status is `deleting`, deletes at most `max_rows` rows
   from the first registered table (by `delete_order`) that still has rows of the organization, and returns the
   number deleted (0 = nothing left in any table). The worker calls it inside `InOrg` with `max_rows = 1000` until it
   returns 0. Registry: `offboarding_table(table_name text PRIMARY KEY, delete_order int NOT NULL UNIQUE)`.
8. **Registry completeness is enforced by a test**: every table in schema `public` with a column `organization_id`
   (except `offboarding_table` itself) is in the registry, and for every foreign key between two registered tables the
   referencing table has a lower `delete_order` than the referenced one. Every future migration that adds such a
   table MUST insert it into the registry (documented in `docs/architecture.md` §16.2 conventions).
9. **Outbox before deletion.** Step `outbox` completes only when the organization has no unpublished `outbox` row;
   it never deletes unpublished rows. Reason: no audit event of the organization may be lost.
10. **Authentik step.** New port method `IdentityProvider.DeleteOrganization(ctx, slug) (ports.OrgIdentityDeletion,
    error)` deleting, missing objects ignored: the access policy binding and policy, the application, the provider,
    the scope mapping, every group whose name is `paddock.<slug>` or starts with `paddock.<slug>.`, and every user with
    path `paddock/<slug>` and attribute `paddock_managed: true`. Synced users are not deleted.
11. **Fleet step.** For every device of the organization with a `device_inventory_ref`, delete the Fleet host unless
    `PlatformPool.FleetHostInUse` reports another device using it (existing rule of `device.inventory_purged`).
12. **Objects step.** Delete every object with prefix `org/<org>/` in the bundles bucket, `apt/<org>/` in the bundles
    bucket and `org/<org>/` in the escrow bucket, listing and deleting in pages of 1000. The audit bucket MUST NOT be
    touched: the objects adapter used here MUST NOT be constructed with the audit bucket.
13. **Valkey step.** For every device ID of the organization delete `cmd:`, `seq:`, `sd:`, `bp:`, `hb:`, `au:`
    and every `dk:<key_id>` of its keys; delete `tt:<org>`. Keys of devices that move to `offboarded_device`
    (decision 15) are rewritten, not deleted. The worker's Valkey ACL user (ADR 0051) MUST already permit these
    commands; if it does not, the ticket stops (stop condition).
14. **Sessions step.** End every portal and MCP session of the organization's administrators (existing
    `Sessions.EndForOrganization` path of "end all sessions" restricted to one organization; if no such restriction
    exists, add `Sessions.EndOrganization(ctx, org)`), and revoke every API token of the organization.
15. **Offboarded devices (ADR 0052 decision 2).** Step `devices` writes one row per device whose uninstall has not
    been reported (`device.uninstalled_at IS NULL` and state not `retired`/`rejected`) into the platform table
    `offboarded_device` and sets its cached key (`dk:<key_id>`) to status `offboarded`. The gateway, for a key with
    status `offboarded`: answers a check-in with the stored uninstall command only (no bundle pointer, no agent offer,
    no time ticket); accepts an event batch only if it contains exactly one event of type `agent.uninstalled` (other
    events: 200 with the batch dropped, so the agent does not retry endlessly); answers every other device route 401
    `identity_revoked`. The worker, on `agent.uninstalled` from an offboarded device, deletes the row and its Valkey
    keys and records `platform.offboarded_device_uninstalled` (params `device_id`, `organization_id`). The retention
    round deletes rows older than 365 days after `offboarded_at` with `retention.purged` (store `offboarded_device`).
16. **Final verification (ADR 0052 decision 6).** Step `audit_final` publishes the message `audit.organization_retire`
    (routing key `audit.platform.<org>`) and waits for `audit_org_retired.final_verified_at` of that organization. The
    audit writer, on that message: runs a full verification of the organization's chain, writes `audit.chain_verified`
    (or `audit.chain_verification_failed`) with param `final: true`, inserts `audit_org_retired(organization_id,
    retired_at, final_verified_at, final_outcome)`, and from then on skips the organization in the nightly
    verification and refuses to write further events of it (an event arriving later is written to the platform
    pseudo-organization as `audit.event_after_retirement` with the original code; never dropped). A failed final
    verification does not block the deletion; it is visible as the outcome.
17. **Tombstone.** Step `tombstone`: `status = 'deleted'`, `deleted_at = now()`, all `idp_*` columns cleared, records
    `organization.deleted` (params: `slug`, `devices_offboarded`, `rows_deleted`, `objects_deleted`,
    `authentik_objects_deleted`, `fleet_hosts_deleted`). `slug` uniqueness becomes a partial unique index
    `WHERE status <> 'deleted'`; domains are deleted with the database step.
18. **Retained evidence access (ADR 0052 decision 7).** `db.AuditReader.InDeletedOrg(ctx, orgID, fn)` exists in
    `server/internal/platform/db` and is the only function that sets `paddock.org_id` from an argument. It refuses
    (returns `ErrNotDeleted`) unless the principal is a platform administrator and `PlatformPool` confirms
    `organization.status = 'deleted'`. It is used only by `app.DeletedOrgAudit`.
19. **Audit codes** (closed registry `server/internal/domain/audit/codes.go`, all in the platform pseudo-organization
    except `audit.chain_verified`): `organization.deletion_requested` (params `slug`, `reason`, `grace_days`,
    `delete_after`, `uninstalls_issued`, `uninstalls_skipped`; step-up), `organization.deletion_cancelled` (`slug`,
    `uninstalls_cancelled`), `organization.deletion_step_completed` (`slug`, `step`, `count`),
    `organization.deletion_step_failed` (`slug`, `step`, `error_code`), `organization.deleted` (decision 17),
    `platform.offboarded_device_uninstalled`, `platform.deleted_organization_audit_read` (the read record of decision
    18), `audit.event_after_retirement`. `audit.chain_verified` gains the param `final`.
20. **Identity rounds (IRP-1).** `organization` gains `idp_ensured_at timestamptz` and `idp_ensure_revision text`.
    `authentik.EnsureRevision` is a string constant in `server/internal/adapters/authentik/authentik.go`, changed by
    every commit that changes what `EnsureOrganization` creates or corrects (the test of §8 pins it to a hash of the
    desired-object description). `IdentitySync.Reconcile` calls `EnsureOrganization` only when
    `idp_ensure_revision <> EnsureRevision` OR `idp_ensured_at IS NULL` OR `now() - idp_ensured_at >= 6h + jitter`,
    where `jitter` = (first 8 bytes of the organization ID as uint64 mod 3600) seconds, so the full checks of many
    organizations spread over an hour. A successful ensure writes both columns. Organization creation, a domain change
    and any Authentik error of the organization in a round clear `idp_ensured_at`, forcing an ensure next round.
    No pacing sleep is added. Reason: pacing alone spreads load but does not reduce it; the cache removes ~95 % of
    the requests while drift is still repaired within 6–7 h and at once after any known change.

## 4. Non-goals

- No Lock, Destroy, wipe or self-lock token as part of offboarding (agent contract 8, maintainer decision).
- No change of the WORM bucket, its retention, `audit_object`, `audit_manifest` or the index retention.
- No editing of backup sets; no new backup kind.
- No platform auditor role; no organization-scoped access to a deleted organization.
- No suspend operation; `suspended` stays unused.
- No change to `EnsureOrganization`'s Authentik calls themselves, the sync interval or Authentik worker sizing.
- No change under `agent/internal/revoke/` or `agent/cmd/paddock-revoke/`.
- No agent change: the offboarded-device path uses the existing check-in, command and event protocol.

## 5. Affected files

| Path | Action | Purpose |
| --- | --- | --- |
| `server/migrations/paddock/<next>_organization_offboarding.sql` | new | status values, deletion and `idp_*` columns, partial slug index, `offboarding_table` + rows, `paddock_offboard_delete_batch`, `offboarded_device`, grants |
| `server/migrations/audit/<next>_org_retired.sql` | new | `audit_org_retired` |
| `server/internal/adapters/postgres/queries/*.sql`, `pgstore/` (generated) | change | queries for the above |
| `server/internal/platform/db/db.go`, `db/auditreader.go` | change | `InDeletedOrg`, `ErrNotDeleted` |
| `server/internal/platform/db/offboarding_registry_integration_test.go` | new | registry completeness and order test |
| `server/internal/domain/organization/organization.go` | change | `StatusDeleting`, `StatusDeleted`, grace bounds |
| `server/internal/domain/offboarding/` | new | `Steps`, step names, error codes |
| `server/internal/domain/audit/codes.go`, `docs/compliance/audit-codes.md`, portal `auditCodes.gen.ts` (generated) | change | codes of decision 19 |
| `server/internal/app/organizations.go` | change | `RequestDeletion`, `CancelDeletion` |
| `server/internal/app/offboarding.go` | new | step implementations |
| `server/internal/app/uninstall.go` | change | `RequestForOffboarding` |
| `server/internal/app/deletedorgaudit.go` | new | read and export for deleted organizations |
| `server/internal/app/identitysync.go` | change | ensure cache (decision 20) |
| `server/internal/ports/identity.go`, `adapters/authentik/*.go` | change | `DeleteOrganization`, `EnsureRevision` |
| `server/internal/worker/offboarding.go` | new | round |
| `server/internal/worker/reports.go` | change | `agent.uninstalled` of offboarded devices |
| `server/internal/worker/retention.go` | change | purge `offboarded_device` |
| `server/internal/worker/cachesync.go` | change | rebuild offboarded keys and commands |
| `server/internal/devicecache/devicecache.go` | change | key status `offboarded` |
| `server/internal/transport/http/device/*.go` | change | gateway behaviour of decision 15 |
| `server/internal/auditwriter/*.go` | change | retire message, final verification, skip retired |
| `server/internal/transport/http/admin/*.go` | change | endpoints of §6 |
| `server/cmd/paddock-server/worker.go` | change | wire the round |
| `api/openapi/admin.yaml` | change | endpoints and schemas of §6 |
| `server/web/src/views/platform/Organization*.vue`, banner component, i18n | change/new | portal |
| `test/acceptance/organization_offboarding_test.go` | new | gates OF1–OF8 |
| `test/acceptance/audit_once_test.go` (`newOrg`) | change | `t.Cleanup` deletion (PDK-946) |
| `test/system/offboarding_test.go` | new | VM gate OS1 |
| `Makefile` | change | `dev-prune-gate-orgs` |
| `docs/compliance/retention.md`, `privacy.md`, `residual-risks.md`, `iso27001-mapping.md` | change | §9 records |
| `docs/operations/organization-offboarding.md` | new | runbook incl. restore-before-deletion |
| `docs/architecture.md` | change | amendment notes (done in the plan PR) |

**MUST NOT be touched:** `agent/` (all), `pkg/command` verification rules, the WORM bucket configuration
(`deploy/compose/scripts/*audit-bucket*`), `server/migrations/*` already merged, ADRs other than via amendment.

## 6. Interfaces and data model

```sql
-- paddock migration (number = next free at implementation time)
ALTER TABLE organization DROP CONSTRAINT organization_status_check;
ALTER TABLE organization ADD CONSTRAINT organization_status_check
  CHECK (status IN ('provisioning','active','provisioning_failed','suspended','deleting','deleted'));
ALTER TABLE organization
  ADD COLUMN deletion_requested_at timestamptz,
  ADD COLUMN deletion_requested_by text,          -- actor display of the platform administrator
  ADD COLUMN deletion_reason       text CHECK (char_length(deletion_reason) BETWEEN 2 AND 500),
  ADD COLUMN delete_after          timestamptz,
  ADD COLUMN offboarding_step      text,          -- one of offboarding.Steps; NULL before deleting
  ADD COLUMN offboarding_error_code text,
  ADD COLUMN deleted_at            timestamptz,
  ADD COLUMN idp_ensured_at        timestamptz,
  ADD COLUMN idp_ensure_revision   text,
  ADD CONSTRAINT organization_deletion_consistent CHECK (
    (delete_after IS NULL) = (deletion_requested_at IS NULL) AND
    (status <> 'deleted' OR deleted_at IS NOT NULL));
-- slug: replace the column UNIQUE with
CREATE UNIQUE INDEX organization_slug_live ON organization (slug) WHERE status <> 'deleted';

CREATE TABLE offboarding_table (
  table_name   text PRIMARY KEY,
  delete_order int  NOT NULL UNIQUE
);  -- no RLS: no organization data; SELECT for paddock_worker only

CREATE TABLE offboarded_device (
  device_id        uuid PRIMARY KEY,
  organization_id  uuid NOT NULL REFERENCES organization(id),  -- the tombstone
  keys             jsonb NOT NULL,      -- [{"key_id": "...", "public_key": "<base64 SPKI DER>"}]
  command_id       uuid NOT NULL,
  command_envelope bytea NOT NULL,      -- the signed uninstall envelope
  offboarded_at    timestamptz NOT NULL DEFAULT now()
);  -- platform table like organization: RLS enabled+forced, policy for paddock_platform only

CREATE FUNCTION paddock_offboard_delete_batch(max_rows int) RETURNS bigint
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$ ... $$;
REVOKE ALL ON FUNCTION paddock_offboard_delete_batch(int) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION paddock_offboard_delete_batch(int) TO paddock_worker;
```

```sql
-- audit migration
CREATE TABLE audit_org_retired (
  organization_id   uuid PRIMARY KEY,
  retired_at        timestamptz NOT NULL DEFAULT now(),
  final_verified_at timestamptz,
  final_outcome     text CHECK (final_outcome IN ('verified','failed'))
);
```

```yaml
# api/openapi/admin.yaml (additions)
/api/platform/v1/organizations/{id}/delete:
  post:
    operationId: deleteOrganization
    x-paddock-step-up: true
    x-paddock-audit: organization.deletion_requested
    description: "Roles: platform_admin. Starts the deletion (ADR 0052)."
    requestBody: { $ref: OrganizationDeleteRequest }
    responses:
      "202": Organization                # status active, deletion set
      "400": Problem invalid_request     # confirm_slug mismatch, reason length, grace_days range
      "401": Problem
      "403": Problem forbidden | step_up_required
      "404": Problem not_found
      "409": Problem invalid_state       # deletion already requested, status deleting/deleted/provisioning/suspended
/api/platform/v1/organizations/{id}/cancel-deletion:
  post:
    operationId: cancelOrganizationDeletion
    x-paddock-audit: organization.deletion_cancelled
    responses: { "200": Organization, "401", "403", "404", "409": invalid_state }   # not pending
/api/platform/v1/organizations/{id}/audit-events:
  get:   # list contract, same sort/filters/q as /api/v1/audit-events; 404 not_found unless status deleted
/api/platform/v1/organizations/{id}/audit-exports:
  get:   # list contract as /api/v1/audit/exports
  post:  # body and 202 as /api/v1/audit/exports; x-paddock-step-up: true
/api/platform/v1/organizations/{id}/audit-exports/{export_id}/download:
  get:   # as /api/v1/audit/exports/{id}/download

OrganizationDeleteRequest:
  type: object
  required: [confirm_slug, reason, grace_days]
  additionalProperties: false
  properties:
    confirm_slug: { type: string }
    reason: { type: string, minLength: 2, maxLength: 500 }
    grace_days: { type: integer, minimum: 0, maximum: 90 }   # 7..90 outside development, checked by the server
OrganizationStatus: enum [provisioning, active, provisioning_failed, suspended, deleting, deleted]
Organization.deletion:      # nullable
  type: object
  required: [requested_at, requested_by, reason, delete_after, step, last_error_code, deleted_at,
             uninstalls_issued, uninstalls_skipped]
  properties:
    requested_at: date-time
    requested_by: string
    reason: string
    delete_after: date-time
    step: { type: string, nullable: true, enum: [sessions, devices, outbox, authentik, fleet, objects, valkey, audit_final, database, tombstone] }
    last_error_code: { type: string, nullable: true }
    deleted_at: { type: string, format: date-time, nullable: true }
    uninstalls_issued: integer
    uninstalls_skipped: integer
Me.organization_deletion:   # GET /api/v1/me, nullable: { delete_after: date-time }
```

`listOrganizations`: the `status` filter accepts the two new values; with no `status` filter the list excludes
`deleted` (documented in the `x-paddock-list` description).

```go
// server/internal/ports/identity.go
type OrgIdentityDeletion struct{ Groups, Users, Applications, Providers, Policies, Mappings int }
// IdentityProvider gains:
DeleteOrganization(ctx context.Context, slug string) (OrgIdentityDeletion, error)

// server/internal/app/organizations.go
type DeletionInput struct { ConfirmSlug, Reason string; GraceDays int }
func (o *Organizations) RequestDeletion(ctx context.Context, id uuid.UUID, in DeletionInput) (pgstore.Organization, error)
func (o *Organizations) CancelDeletion(ctx context.Context, id uuid.UUID) (pgstore.Organization, error)

// server/internal/app/uninstall.go
func (u *Uninstalls) RequestForOffboarding(ctx context.Context, deviceID uuid.UUID, expiresAt time.Time) (issued bool, err error)

// server/internal/app/offboarding.go
type Offboarding struct{ /* constructor-injected: runner, org, platform pools, idp, inventory, objects, cache, mq */ }
func (o *Offboarding) Advance(ctx context.Context, org uuid.UUID) (done bool, err error) // runs the next step

// server/internal/platform/db
var ErrNotDeleted = errors.New("db: organization is not deleted")
func (r *AuditReader) InDeletedOrg(ctx context.Context, platform *PlatformPool, org uuid.UUID,
    fn func(ctx context.Context, q *auditstore.Queries) error) error
```

Error codes stored in `offboarding_error_code`: `authentik_unavailable`, `fleet_unavailable`,
`object_store_unavailable`, `valkey_unavailable`, `outbox_pending`, `audit_writer_pending`, `database_error`.

## 7. Implementation steps

1. **PDK-1013 data model.** Do: paddock migration of §6 including registry rows for all 74 tables and the function;
   audit migration; sqlc queries; registry test of decision 8; function test (refuses for non-`deleting`, deletes in
   order and batches, returns 0 at the end, does not touch another organization). Result: schema in place, no
   behaviour change. Check: `GOTOOLCHAIN=auto go test -count=1 ./server/internal/platform/db/... ./server/migrations/...`.
2. **PDK-1014 API and state machine.** Do: domain statuses, `RequestDeletion` (incl. uninstalls of decision 3),
   `CancelDeletion`, OpenAPI, handlers, audit codes, `Me.organization_deletion`. Result: deletion can be requested
   and cancelled; nothing is deleted yet. Check: integration tests of §8.2; `make gen` without diff.
3. **PDK-1015 worker job.** Do: `Offboarding.Advance`, all steps except `audit_final` (stubbed to complete at once
   behind a constructor option used only until PDK-1017 lands), round wiring, Authentik `DeleteOrganization`.
   Result: a due organization ends `deleted`. Check: integration tests of §8.3.
4. **PDK-1016 offboarded devices.** Do: step `devices`, gateway behaviour, worker handling, cache sync, retention.
   Result: an offboarded device uninstalls at its next contact. Check: §8.4.
5. **PDK-1017 audit retirement and retained evidence.** Do: audit writer retire message and final verification,
   skip in nightly verification, `InDeletedOrg`, read and export endpoints, host command `paddock-server audit
   deletions --since <RFC3339>` (prints one line per `organization.deleted` event of the platform pseudo-organization
   read from WORM objects: `occurred_at`, `organization_id`, `slug`); remove the stub of step 3. Check: §8.5.
6. **PDK-1018 portal.** Do: delete dialog (`ConfirmDialog` with typed slug, reason, grace days with default 30),
   cancel action, deletion column/filter, detail with step and error, org-admin banner, deleted-organization audit
   view and export using `DataList`. Check: component tests, `make e2e` spec `organization-offboarding.spec.ts`,
   Skill `frontend-verify`.
7. **PDK-946 acceptance cleanup.** Do: `newOrg()` registers `t.Cleanup` that requests deletion with
   `grace_days: 0` (development stack) and waits up to 5 min for `deleted`; `make dev-prune-gate-orgs` deletes every
   organization whose name starts with `Gate gate-` through the API, refusing unless the api reports
   `PADDOCK_ENV=development`. Check: acceptance gate OF8.
8. **PDK-1019 documents.** Do: §9 compliance records and the runbook. Check: review.
9. **PDK-1020 identity-round measurement.** Do: `test/load/cmd/orgseed` (standard library) creates N
   organizations with one device login assignment each through the admin API on a development stack (refuses as
   `make load-identities` does); a documented procedure measures for 10 minutes without portal activity: Authentik
   requests by path (access log as in PDK-570's result), `authentik-postgres` CPU (`docker stats` averages), round
   duration. Baseline at 250 organizations on the current code. Result: numbers in
   `docs/operations/capacity.md` "Identity rounds". Check: the table exists with the commit and hardware.
10. **PDK-1021 ensure cache.** Do: decision 20; then repeat PDK-1020's measurement and record before/after.
    Check: unit tests of §8.6; measured requests ≤ 20 % of baseline.
11. **PDK-1022 VM gate.** Do: `test/system/offboarding_test.go` gate OS1 (§8.7). Check: `make system-test
    VM=all T=TestOffboarding`.

Order: 1 → 2 → 3 → (4, 5 in either order) → 6 → 7 → 8; 9 → 10 independent of 1–8; 11 after 4.

## 8. Tests

1. Unit/integration, data model: registry completeness and FK order (decision 8); function refuses for `active`,
   deletes only the context organization (a second organization's rows survive), batches of `max_rows`.
2. API: 202 with uninstalls issued for 2 active devices and 1 skipped (open revocation); 400 for slug mismatch,
   reason of 1 and 501 characters, `grace_days` 6 and 91 (production) and 0 accepted in development; 403 without
   step-up and for an organization role; 404 for an unknown ID; 409 when already pending and for `deleting`;
   cancel: 200 and undelivered uninstalls cancelled, 409 when not pending; exactly one audit event per attempt
   including denials.
3. Worker: steps run in order and resume after a simulated crash between steps; `outbox` waits while an unpublished
   row exists; Authentik errors set `authentik_unavailable` once, a repeated identical error records no second event;
   objects of another organization and the audit bucket are untouched (fake object store asserts no call with the
   audit bucket); Valkey keys of another organization survive.
4. Offboarded devices: check-in answers only the uninstall; an event batch with `agent.uninstalled` deletes the row
   and keys and records the platform event; any other route 401 `identity_revoked`; retention deletes a 366-day-old
   row; the cache sync rebuilds `dk:` and `cmd:` of offboarded rows after a Valkey flush.
5. Audit: the retire message leads to one `audit.chain_verified` with `final: true` and a row in
   `audit_org_retired`; the nightly verification skips it; a late event lands as `audit.event_after_retirement` in
   the platform pseudo-organization; `InDeletedOrg` refuses an organization that is `active` (ErrNotDeleted → 404)
   and an organization principal; the export of a deleted organization verifies with `paddockctl audit verify`.
6. Identity: ensure skipped when revision and time match; called when revision differs, after 6 h + jitter, after a
   domain change, after an error; jitter is deterministic per organization ID and within [0, 3600) s;
   `TestIdentityRoundRequestCounts` gains a steady-state case: 200 organizations, second round → ≤ 10 % of the first.
7. Acceptance gates (`test/acceptance/organization_offboarding_test.go`): OF1 request + cancel; OF2 request with a
   simulated device (`bin/devicesim`) → uninstall command visible to the device; OF3 grace 0 → `deleted` within 5 min,
   Authentik has no `paddock.<slug>` group and no `paddock-device-<slug>` application; OF4 the organization's admin API
   token gets 401; OF5 platform administrator reads the deleted organization's audit log and creates an export; an
   organization administrator token of another organization gets 404 on those paths; OF6 a simulated device that
   never reported checks in after deletion, gets the uninstall, reports `agent.uninstalled`, and the platform event
   exists; OF7 slug reuse: creating an organization with the deleted slug succeeds; OF8 a full acceptance run leaves
   no `Gate gate-…` organization in a status other than `deleted`.
8. System gate OS1 (`TestOffboarding`, both VMs): an enrolled VM in a fresh organization; request deletion with
   grace 0; the VM removes Paddock (no `paddock-agent` package, no `/etc/sudoers.d/paddock-*`), the local
   administrator still logs in, LUKS still unlocks at reboot, home directories exist; a second VM switched off during
   the request is started after `deleted` and uninstalls at its next contact.

## 9. Acceptance criteria

- OFB-1 — Given an active organization; when a platform administrator requests its deletion with a step-up, the
  correct slug, a reason and 30 days; then the platform administrator sees it as "deletion pending" with the date, and
  `organization.deletion_requested` is in the platform audit log.
- OFB-2 — Given two active devices; when the deletion is requested; then the organization administrator sees both as
  *uninstall pending*, and after the removal the device user still signs in with a local account (OS1).
- OFB-3 — Given a device that was offline during the grace period; when it checks in after `deleted`; then it removes
  Paddock, and the platform administrator sees `platform.offboarded_device_uninstalled`.
- OFB-4 — Given an organization with devices, escrow, packages and Authentik objects; when the grace period ends;
  then the platform administrator sees `deleted` and `organization.deleted` with counts, and gates OF3/OF4 find no
  remains.
- OFB-5 — Given a deleted organization; when a platform administrator opens its audit log and requests an export;
  then the platform administrator sees the events up to `audit.chain_verified` (`final: true`) and downloads a package
  that verifies offline; an organization administrator gets 404.
- OFB-6 — Given Authentik is unreachable during the deletion; then the platform administrator sees step `authentik`
  with error code `authentik_unavailable`, and the deletion continues once Authentik is back.
- OFB-7 — Given a pending deletion; when an organization administrator opens the portal; then the organization
  administrator sees a banner with the date and the advice to secure recovery keys and local administrator passwords
  now.
- OFB-8 — Given a full acceptance run; then the developer sees no `Gate gate-…` organization outside status
  `deleted`.
- IRP-1 — Given 250 organizations on a development stack; when two reconcile intervals without portal activity are
  measured; then the operator finds at most 20 % of the baseline requests in `capacity.md`.

## 10. Degrees of freedom

- Internal helper names, file split inside `server/internal/app/offboarding*.go`, the Vue component structure.
- The `delete_order` values (any order the FK test accepts).
- Whether the objects step deletes with per-object `DELETE` or a multi-object delete call of the existing adapter.
- The exact banner wording (i18n keys required, English and German).

## 11. Stop conditions

- A table with `organization_id` cannot be deleted by the function because of a non-organization FK into it from a
  platform table other than `organization` (for example a platform table referencing a device): stop and report.
- The worker's Valkey ACL user lacks a command or key pattern of decision 13 or 15.
- The audit writer cannot run a full verification of one organization within its existing limits.
- Authentik refuses deleting a group with children in one call and requires a different order than decision 10.
- Any need to change agent code, `pkg/command` verification or the revocation path.
- Any need for a new dependency.

## 12. Risks and open points

- **RR-137 (new):** after deletion, directory logins on the organization's devices stop and recovery keys and
  escrowed passwords are gone. Mitigation: grace period, banner, `leave` keeps local accounts. The operator records
  acceptance.
- **RR-138 (new):** backup sets keep the organization's data until their retention ends; a restore to a point
  before the deletion resurrects it. Runbook: after such a restore, read `organization.deleted` events after the
  restore point with the new host command `paddock-server audit deletions --since <RFC3339>` (PDK-1017; it reads the
  platform pseudo-organization's WORM objects, which a restore does not roll back) and repeat each deletion with
  `grace_days` at the minimum.
- Leader change during a step: steps are idempotent; the checkpoint is written after completion.
- `offboarded_device` holds signed uninstall envelopes valid for a year: they act only on their device and only
  remove Paddock (the action the organization was told about).
- Open: grace-period bounds 7–90 days with default 30 (maintainer question, default applied).

## Amendment 2026-11-14 b — encrypted recovery export (maintainer decision; ADR 0052 amendment b; ticket PDK-1036)

Binding; where it contradicts the sections above, it wins.

### Requirement

| ID | Requirement | Acceptance (who sees it) |
| --- | --- | --- |
| OFB-9 | During the grace period an organization administrator or the platform administrator exports all LUKS recovery keys and local administrator passwords of the organization, encrypted to a public key or passphrase they supply. | The requester downloads one OpenPGP file that `gpg --decrypt` opens with their key or passphrase; the organization's audit log shows one `organization.recovery_exported`. |

### Decisions

21. **Endpoints.** `POST /api/v1/recovery-export` (role `org_admin`) and
    `POST /api/platform/v1/organizations/{id}/recovery-export` (role `platform_admin`); both `x-paddock-step-up: true`,
    `x-paddock-audit: organization.recovery_exported`, CSRF header. Available only while the organization's deletion is
    pending; otherwise 409 `invalid_state`. 409 `export_limit` after five successful exports of the organization since
    `deletion_requested_at`. 404 `not_found` for an unknown organization (platform path).
22. **Request body** `RecoveryExportRequest`: `{ "recipient": "public_key" | "passphrase", "public_key": string
    (ASCII-armoured OpenPGP public key, required for public_key, at most 16 KiB, must contain an encryption-capable
    key), "passphrase": string (required for passphrase, 16–1024 characters) }`; `additionalProperties: false`. The body
    is never logged; the passphrase never enters audit params, problem details or metrics.
23. **Response** `200`, `Content-Type: application/pgp-encrypted`, `Content-Disposition: attachment;
    filename="paddock-recovery-<slug>-<UTC yyyymmddThhmmssZ>.asc"`, body = one ASCII-armoured OpenPGP message
    (`github.com/ProtonMail/go-crypto/openpgp`: `Encrypt` to the given entity, or `SymmetricallyEncrypt` with S2K
    `argon2`, cipher AES-256). Plaintext inside the message: JSON Lines, one object per device:
    `{"device_id": uuid, "hostname": string, "volumes": [{"uuid": string, "recovery_key": string}],
    "local_admin": {"username": string, "password": string} | null}`, first line a header object
    `{"organization_id": uuid, "slug": string, "exported_at": RFC3339, "devices": int}`.
24. **Flow.** The api checks role, step-up and state, then forwards to the escrow-reader exactly like a reveal (step-up
    token by `jti`, one use counted in `stepup-uses:*`). The escrow-reader reads the organization's escrow rows (newest
    recovery key per volume, newest local administrator password) of non-retired devices, decrypts them through Transit
    in batches of at most `bao.MaxBatch`, and writes the JSON Lines into the OpenPGP writer that streams into the
    response. Nothing is buffered to disk; the plaintext lives only in process memory per batch and is zeroed after use.
    The platform path enters the organization context through `db.OrgPool.InPendingDeletionOrg(ctx, platform, org, fn)`
    (same shape and checks as `InDeletedOrg`, but requires `status = 'active' AND delete_after IS NOT NULL`).
25. **Audit.** One `organization.recovery_exported` per attempt in the organization's log (success, failure, denial);
    params `recipient`, `key_fingerprint` (public_key only), `devices`, `secrets`, `requester_scope`
    (`organization` | `platform`). A failure after streaming began is recorded as failure; the client receives a
    truncated message that OpenPGP's integrity check rejects.
26. **Portal.** The banner of OFB-7 links to a dialog (organization administrator; platform administrator on the
    organization detail) that asks for the recipient type and the key or passphrase (twice, with a strength hint) and
    starts the download after the step-up. The dialog states that the file is the only remaining copy after the deletion.
27. **RR-137** is reworded to "only if no export was taken" (PDK-1019).

### Tests

- Integration (escrow-reader and api): an organization with three devices (one retired, one without escrow) → the
  export holds exactly one device line with its volumes and password; decrypted in the test with the private key and
  with the passphrase; a wrong passphrase fails; without step-up 403 `step_up_required`; `org_operator` 403; not pending
  409 `invalid_state`; the sixth export 409 `export_limit`; exactly one audit event per attempt and no secret, no
  passphrase in any recorded param or log line (log capture asserts); the platform path refused for an organization of
  another status (404 or 409 as specified).
- Acceptance gate OF9: request deletion (grace 30), export with a test key generated by `gpg --batch --quick-gen-key` in a temporary
  `GNUPGHOME`, decrypt with `gpg --batch --decrypt` (the gate fails, never skips, when `gpg` is missing; it is present on
  the `ubuntu-24.04` runners and the development host), compare with single reveals of the same device.

### Step

12. **PDK-1036** after PDK-1014 (needs the pending state), before PDK-1018 (the portal dialog is part of PDK-1036; the
    banner link in PDK-1018 points to it).

## Amendment 2026-11-14 c — gaps found while implementing PDK-1013 (architect decisions)

Binding; where it contradicts the sections above, it wins.

1. **Uninstall counts are columns.** PDK-1014's migration adds `organization.deletion_uninstalls_issued int` and
   `organization.deletion_uninstalls_skipped int` (both NULL while no deletion was requested, set by
   `RequestDeletion`, cleared by `CancelDeletion`, kept on the tombstone). They are not derived from `device_command`,
   whose rows the database step deletes.
2. **Outbox check through a definer function, no grant.** `paddock_worker` gets no `SELECT` on `outbox`. PDK-1015's
   migration adds `paddock_offboard_outbox_pending() RETURNS bigint` (`SECURITY DEFINER`, owner `paddock_owner`, same
   `search_path` convention as `paddock_offboard_delete_batch`, `EXECUTE` for `paddock_worker` only): it counts the
   unpublished outbox rows of the organization in `current_setting('paddock.org_id')::uuid` and raises
   `insufficient_privilege` unless that organization's status is `deleting`. Step `outbox` completes when it returns 0.
3. **Platform pool wiring is part of PDK-1015.** The round uses the worker's existing `PlatformPool` (organization
   status transitions, `offboarded_device`) and takes its leader lock from the existing lock pool (12 connections). It
   adds no pool and no connection to the budget of M19 D1; it is one more lock-holding round (19 → 20), which PDK-1015
   records in `docs/operations/capacity.md` "PostgreSQL connection budget". The round holds its lock only while it runs
   one step per organization.
4. **Accepted implementation details of PDK-1013:** `offboarded_device` is not in `offboarding_table` (its rows outlive
   the organization by decision 15); the registry test of decision 8 excludes exactly `offboarding_table` and
   `offboarded_device`. The definer function's `search_path` ends with `pg_temp` (convention of migrations 00034 and
   00076). `max_rows` is limited to 1–10000; a reference loop in the registry order raises.

## Amendment 2026-11-14 d — no writer survives `deleting` (architect decision after PDK-1013 review 2; ticket PDK-1038)

Binding; where it contradicts the sections above, it wins. **Decision: both a status gate and a lock (option c).** The
gate stops new transactions once `deleting` is committed; the lock covers transactions that entered before that commit
and are still running when the job finishes.

1. **Gate in the database.** New function `paddock_org_enter() RETURNS void` (`SECURITY DEFINER`, owner
   `paddock_owner`, the `search_path` convention of `paddock_offboard_delete_batch`, `EXECUTE` for every
   organization-scoped application role). It reads `current_setting('paddock.org_id')::uuid`, takes
   `pg_advisory_xact_lock_shared(<offboarding lock key of that organization>)` and raises SQLSTATE `PD001`
   (`organization_unavailable`) when the organization's status is `deleting` or `deleted`.
   `db.OrgPool.InOrg` and `InOrgSnapshot` call it right after `SET LOCAL paddock.org_id` in every transaction. The lock
   key is computed in one place (`db.OffboardingLockKey(org)`, the same derivation in SQL and Go, covered by a test).
2. **Bypass for the job only.** `db.OrgPool.InOrgOffboarding(ctx, org, fn)` sets the context and skips
   `paddock_org_enter`; it is used only by `app.Offboarding` (a test fails when another package calls it, by scanning
   imports and call sites under `server/internal`).
3. **Final pass under an exclusive lock.** New function `paddock_offboard_finalize() RETURNS void` (definer, `EXECUTE`
   for `paddock_worker` only), called by step `tombstone` inside `InOrgOffboarding`: it takes
   `pg_advisory_xact_lock(<same key>)` (waits for every transaction that entered before `deleting`), counts the
   organization's rows in every registered table, raises `40001` when any remain (the step then returns to `database`
   and retries next round), and otherwise sets the tombstone (`status = 'deleted'`, `deleted_at`) in the same
   transaction. Decision 17's status change therefore happens in this function, not through the platform pool; the
   `organization.deleted` event is recorded after it commits.
4. **Error mapping.** `PD001` maps to `problem` 403 `organization_inactive` in the api (the existing denial reason of
   the sign-in) and the MCP surface; the gateway answers 401 `identity_revoked` (offboarded devices are served by
   decision 15 from the platform table, never through `InOrg`); worker consumers acknowledge and drop the message with
   one `Info` log line and the counter `paddock_worker_dropped_total{reason="organization_unavailable"}`; rounds skip
   the organization.
5. **Cost.** One extra statement per organization transaction. PDK-1038 measures check-in and ingest throughput before
   and after with the existing load scenarios at a reduced rate and records it in its result document; a regression of
   more than 5 % stops the ticket.
6. **Ownership and order.** PDK-1038 owns points 1–5 (migration, `db` changes, mapping, tests). PDK-1015 depends on it
   and calls `InOrgOffboarding` and `paddock_offboard_finalize`.
7. **Tests.** A transaction that entered before `deleting` and inserts after the delete loop finished makes
   `finalize` wait and then raise `40001`; the next round deletes the row and finalizes. After `deleting` is committed,
   `InOrg` of every role fails with `PD001`. `InOrgOffboarding` is used only by `app.Offboarding`.

## Amendment 2026-11-14 e — offboarding uninstalls: marker, set-based issue and cancel, locks, gaps of the grace period (architect decision after PDK-1014 review 1; ADR 0052 amendment e)

Binding; where it contradicts the sections above (decisions 3, 4, 15, §6 signatures), it wins.

### Deviations of PDK-1014 (review 1, Major 3)

1. **Marker column: accepted.** `device.uninstall_reason text CHECK (uninstall_reason IN ('organization_offboarding'))`
   with `CHECK (uninstall_reason IS NULL OR uninstall_requested_at IS NOT NULL)` is the only marker of an offboarding
   uninstall. Every query that sets or clears an uninstall request (`SetDeviceUninstall`, `ClearDeviceUninstall`,
   `EndFailedUninstall`, `SetDeviceOffboardingUninstall`) MUST set the column in the same statement. Code MUST NOT
   identify offboarding uninstalls through `device_command.issued_by IS NULL`. Reason: `issued_by` is NULL for every
   non-administrator issuer (`app/commands.go::queueCommandID`), lives on the command instead of the device's request
   state that Cancel, Lock and step `devices` read, and needs a join; an explicit, constrained column states the
   meaning where it is used. The agent decodes uninstall params with `DisallowUnknownFields` and MUST NOT change, so the
   reason cannot travel in the command.
2. **Set-based, unexported methods: accepted; they replace the §6 signature.**
   ```go
   // server/internal/app/uninstall.go — callable only from Organizations.RequestDeletion / CancelDeletion
   func (u *Uninstalls) requestForOffboarding(ctx context.Context, expiresAt time.Time) (issued, skipped int, err error)
   func (u *Uninstalls) cancelForOffboarding(ctx context.Context) (cancelled int, err error)
   ```
   `Uninstalls.RequestForOffboarding(ctx, deviceID, expiresAt) (issued bool, err error)` of §6 MUST NOT be added.
   Reason: one transaction for all devices means a failed request leaves no device with an uninstall.
3. **Cancel without `Uninstalls.Cancel`: accepted.** `CancelDeletion` records exactly one event,
   `organization.deletion_cancelled` (param `uninstalls_cancelled`), and MUST NOT record `device.uninstall_cancelled`
   or any other per-device event. It reuses `withdrawUninstallCommand` for the result claim. Decision 4's wording
   "calls the existing `Uninstalls.Cancel`" is replaced by this rule.

### Locks and duration (review 1, Majors 1 and 2)

4. **Lock strength.** `LockOrganization`, the device selection of `requestForOffboarding` and the device selection of
   `cancelForOffboarding` MUST use `FOR NO KEY UPDATE` (devices `ORDER BY id`). `FOR UPDATE` MUST NOT be used in these
   queries. Reason: foreign-key checks take `FOR KEY SHARE`; `FOR UPDATE` would stall every insert that references the
   organization or its devices, and the cancel's two-connection hold could wait in a cycle PostgreSQL cannot detect.
5. **Set-based request.** Inside one organization transaction `requestForOffboarding` runs a constant number of SQL
   statements, independent of the device count (at most five): lock the active devices; one
   `INSERT INTO device_command … SELECT … FROM device WHERE state = 'active' AND NOT (uninstall_requested_at IS NOT NULL
   AND uninstalled_at IS NULL) AND NOT EXISTS (open Lock/Destroy, the condition of DeviceHasOpenRevocation) RETURNING id,
   device_id`; one `UPDATE device … FROM` the returned rows setting the request with `uninstall_reason =
   'organization_offboarding'`; `skipped` = locked active devices minus issued. Per-device statements MUST NOT be used.
6. **Set-based cancel with a budget.** `cancelForOffboarding` reads the open offboarding uninstalls with their command
   status in one statement (`device JOIN device_command`, `FOR NO KEY UPDATE OF device`). Per command in status
   `pending` it calls the Valkey result claim (`withdrawUninstallCommand` logic; one call per command is allowed, it is a
   cache round trip, not SQL). The command cancellation of all withdrawn, `failed` and `expired` commands is one
   `UPDATE device_command … WHERE id = ANY(@ids)`, the clearing of their devices one `UPDATE device … WHERE id =
   ANY(@ids)`. `delivered` and `succeeded` commands stay. `CancelDeletion` MUST bound the call with
   `context.WithTimeout(ctx, DeletionRequestBudget)` (2 min); on timeout the whole cancel rolls back, the deletion stays
   pending, the action records failure, and the result claims are released (existing `releaseOn`).
7. **Measurement, binding targets.** A test `TestOrganizationDeletionTenThousandDevices` in
   `server/internal/app/organizations_deletion_integration_test.go` (skipped with `-short`) seeds one organization with
   10 000 active devices (set-based insert) and measures `RequestDeletion` and `CancelDeletion` end to end. On the
   development host, measured without a parallel suite: request ≤ **5 s**, cancel ≤ **20 s**. The test asserts the
   loose ceilings request ≤ 30 s and cancel ≤ 60 s (CI headroom) and logs both durations; the result document records
   the development-host numbers. A development-host number above its target is a stop condition (report, do not tune
   the test).

### Gaps during the grace period (review 1 Minor 4, PDK-1039)

8. **The organization administrator cannot withdraw an offboarding uninstall.** `Uninstalls.Cancel` (and so
   `POST /api/v1/devices/{id}/uninstall/cancel`, MCP included) answers 409 `invalid_state` with detail "the uninstall
   belongs to the organization's deletion; only cancelling the deletion withdraws it" when `uninstall_reason =
   'organization_offboarding'`; the attempt records `device.uninstall_cancelled` with outcome failure (runner rule).
   `Uninstalls.Request` keeps its rules: while an offboarding uninstall is open it refuses (409), and when that
   uninstall's report is overdue (`UninstallReportTimeout`) an organization administrator MAY replace it with an own
   request, whose `uninstall_reason` is NULL.
9. **Lock and Destroy still take precedence.** `Revocations.Request` keeps cancelling an open uninstall, the offboarding
   one included (review 2 finding D of M8d: the removal purges `paddock-revoke`). The deletion request never triggers a
   revocation (maintainer decision §3.1); an administrator's own Lock or Destroy stays possible during the grace period.
10. **Every device gets its leave at step `devices` at the latest.** Step `devices` (PDK-1016) runs in one
    `InOrgOffboarding` transaction that first takes `pg_advisory_xact_lock(db.OffboardingLockKey(org))` (exclusive;
    every transaction that entered before `deleting` has ended, amendment d), then, for every device with
    `uninstalled_at IS NULL` and `state NOT IN ('retired','rejected')`:
    - it keeps the device's open uninstall (any mode, any reason) when its command status is `pending`, `delivered` or
      `succeeded`;
    - otherwise (no open uninstall; command `failed`, `expired` or `cancelled`) it issues a fresh `uninstall` `leave`
      as the system, set-based as in point 5, with `uninstall_reason = 'organization_offboarding'` and `expires_at =
      now() + OffboardedDeviceRetention`, regardless of an open Lock or Destroy (that revocation cannot be served once
      the organization is gone; the agent's own `revocationWindow` still refuses an uninstall right after a
      revocation);
    - it signs each kept or issued command with `commandsign.Sign(ctx, signer, app.Payload(cmd))` and writes the
      `offboarded_device` row with that envelope.

    This covers devices enrolled or approved during the grace period, devices whose offboarding uninstall a Lock or
    Destroy cancelled, devices skipped at the request whose own uninstall ended later, refused (`conversion_pending`,
    `revocation_pending`) and expired commands, and `pending`/`quarantined` devices. The step's
    `organization.deletion_step_completed` gains the param `uninstalls_reissued` (registered by PDK-1014). The function
    is `func (u *Uninstalls) reissueForOffboarding(ctx context.Context, q *pgstore.Queries, expiresAt time.Time)
    (reissued int, err error)` and is called only by `app.Offboarding`.
11. **No enrollment refusal during the grace period.** A pending deletion does not refuse enrollment or approval; such
    devices receive their leave through point 10. Once the status is `deleting`, amendment d's gate refuses enrollment
    (gateway 401 `identity_revoked`); PDK-1038 proves it with a test.
12. **The organization administrator sees why.** `DeviceUninstall` (admin API) gains the required, nullable property
    `reason: { type: string, enum: [organization_offboarding], nullable: true }`. The portal (PDK-1018) labels such an
    uninstall "Removal for the organization's deletion" (en/de) and offers no cancel action for it.

### Failure after the uninstalls went out (review 1 Minor 5)

13. **Documented, plus the count in the failure event.** If `RequestDeletion`'s finalize transaction fails after
    `requestForOffboarding` committed, the action records failure while the uninstalls are live and the deletion stays
    pending with NULL counts (never started; cancellable after `DeletionRequestStale`). This stays as designed. Binding:
    finalize MUST set `uninstalls_issued` and `uninstalls_skipped` on the recorder before the statement that can fail,
    so the failure event states how many devices were told to leave (test with an injected finalize failure); the
    runbook (PDK-1019) states the recovery: wait 10 minutes, cancel (withdraws the undelivered uninstalls), request
    again.

### Residual risk (PDK-1019 records it)

14. A device whose in-place encryption is unfinished or whose revocation was just handed to `paddock-revoke` when the
    organization is deleted refuses the leave; after the deletion its result route answers 401, so it keeps an inert
    Paddock agent until reinstalled. The user keeps working (contract 8). The banner and the runbook ask administrators
    to finish in-place encryptions during the grace period.

### Assignment

| Item | Ticket |
| --- | --- |
| Points 1–7, 8, 12 (API), 13, registration of `uninstalls_reissued` | PDK-1014 fix round |
| Point 10 | PDK-1016 |
| Point 11 (enrollment refused while `deleting`) | PDK-1038 |
| Point 12 (portal) | PDK-1018 |
| Points 13 (runbook), 14 | PDK-1019 |

PDK-1015 is unchanged. PDK-1039 is decided by points 8–12 and carries no implementation of its own.

## Amendment 2026-11-14 f — denials of a deleting organization, dropped device messages, the bypass signature (architect decision after PDK-1038 review 1)

Binding; where it contradicts amendment d, it wins.

1. **Where the denial of an inactive organization is recorded.** When an organization-scoped action fails with
   `PD001` (`problem.OrganizationInactive`), `ActionRunner` MUST NOT write into that organization (the gate refuses it,
   and a row written after the delete loop would make `paddock_offboard_finalize` raise 40001). It records the
   attempt's one event in the **platform pseudo-organization** (`audit.PlatformOrganizationID`, platform scope) with
   the new code `organization.inactive_denied`, outcome `denied`. Params: `organization_id` (the refused
   organization), `attempted_code` (the action's own code), `status` (`deleting` or `deleted`). Actor and target are
   kept from the attempt. The attempt's own code is not recorded in addition. This is the analogue of
   `audit.event_after_retirement` (decision 16). It is readable where every platform pseudo-organization event is
   read: the platform administrator's audit log. Nothing has to be read from the deleted organization's retained log
   for it. Registry: closed code, MSGID ≤ 32 characters as is (28), portal message `audit.organization.inactive_denied`
   (en/de), Wazuh informational. Test: a POST of an organization administrator against a `deleting` organization gets
   403 `organization_inactive` and yields exactly one `denied` `organization.inactive_denied` event in the platform
   pseudo-organization, and none in the organization.
2. **Device messages between `deleting` and step `devices`: accepted residual risk, no reconciliation.** Amendment d
   point 4 stays: worker consumers drop them. Consequence: a device whose `agent.uninstalled`, command result or
   delivery mark arrives in this window (about one round, `devices` is the second step) still gets an
   `offboarded_device` row. That row holds no personal data, is never used again by a device that has left, and is
   purged after 365 days. Its count in `organization.deleted` (`devices_offboarded`) is an upper bound, and no
   `platform.offboarded_device_uninstalled` is recorded for it. PDK-1016 MUST NOT add a reconciliation for it.
   PDK-1019 records it as a residual risk.
3. **Bypass signature: `db.OrgPool.InOrgOffboarding(ctx, fn)` confirmed.** It takes the organization from the
   principal in `ctx`, like `InOrg`; amendment d's `(ctx, org, fn)` is replaced. `app.Offboarding` builds that system
   principal from the organization it loaded through `PlatformPool` (the pattern of `offboardingContext` of PDK-1014).
4. **Status check order.** In `paddock_org_enter` the check after `pg_advisory_xact_lock_shared` is mandatory. The
   check before the lock is kept: it stops new transactions of a deleting organization from queueing behind a waiting
   finalize. It MAY only be dropped together with a non-queueing finalize (`pg_try_advisory_xact_lock`, 40001 when not
   granted).

Assignment: points 1, 3 and 4 PDK-1038 (fix round); point 2 PDK-1019 (residual risk), PDK-1016 (no reconciliation).

### Correction 2026-11-14 to amendment f point 1 (PDK-1038 fix round)

`organization.inactive_denied` is **not** classified as Wazuh informational. It has only the outcome `denied`, and the
classification test rejects informational codes that never succeed. The generic denied rule (level ≥ 7) covers it,
which fits: a refused request against an organization being deleted is worth an analyst's look. "Wazuh informational"
in point 1 is struck.

## Amendment 2026-11-14 g — recovery export: S2K that GnuPG 2.4 opens, and the pending-deletion entry point (architect decision for PDK-1036; ADR 0052 amendment g)

Binding; where it contradicts amendment b decisions 22–24, it wins.

1. **Passphrase S2K.** GnuPG 2.4.4 (Ubuntu 24.04, the gate runners) rejects Argon2 (`unknown S2K mode 4`), and "opens
   with plain `gpg --decrypt`" is the maintainer's requirement (`decisions-alpha11.md` §4.3). The passphrase export
   therefore uses S2K **iterated and salted, SHA-256, count 65011712 (the maximum)**, cipher AES-256, with integrity
   protection (SEIPD v1, MDC), which every GnuPG 2.2+ opens. Decision 23's `argon2` is replaced.
2. **Longer minimum passphrase.** Iterated S2K is far cheaper to brute-force than Argon2, so the passphrase minimum
   rises from 16 to **20 characters** (maximum stays 1024). Decision 22 and its test change: 19 characters → 400
   `invalid_request`, 20 accepted.
3. **Public key is the recommended recipient.** The portal dialog preselects `public_key`, and its passphrase option
   states that a generated passphrase of at least 20 characters is needed. Both recipient types stay allowed.
4. **Argon2 later.** PDK-1044 becomes the follow-up: switch to Argon2 once the gate runners and the documented
   operator platforms ship GnuPG ≥ 2.5. It is not in alpha.11.
5. **State names (confirmed).** *Deletion pending* = `status IN ('active','provisioning_failed') AND delete_after IS
   NOT NULL` (the grace period; the organization works normally). *Deleting* = status `deleting`, set by the worker
   once `delete_after` has passed, while the steps run. The export is available only while the deletion is pending;
   amendment d's gate refuses only `deleting` and `deleted`, so it does not block the export.
6. **`InPendingDeletionOrg` calls `paddock_org_enter`.** Like `InOrg`, it calls `paddock_org_enter()` right after
   `SET LOCAL paddock.org_id`, and it MUST NOT use the `InOrgOffboarding` bypass. Reason: the shared offboarding lock
   makes `paddock_offboard_finalize` wait for a running export. When the worker moves the organization to `deleting`
   between the platform check and the transaction, the export fails closed with `PD001`. That maps to 403
   `organization_inactive`, and the attempt is recorded as `organization.inactive_denied` in the platform
   pseudo-organization (amendment f point 1). Test: an organization moved to `deleting` before the export's
   transaction yields 403 `organization_inactive` and no export bytes.

## Amendment 2026-11-14 h — no recovery export may straddle the start of the deletion (architect decision after PDK-1036 review 2)

Binding; where it contradicts amendments b or g, it wins.

1. **Cutoff, chosen over the alternatives.** An export is allowed only while `delete_after > now() + 20 minutes`
   (constant `RecoveryExportCutoff = exportTimeout (15 min) + 5 min margin`, defined once in the app layer and used by
   the escrow-reader). `now()` is the database's clock, in the reservation (tx1) and in the escrow-reader's pending
   check, the same clock the worker uses for `delete_after <= now()`. Otherwise the answer is 409 `invalid_state` with
   detail "the recovery export closes 20 minutes before the deletion starts". The escrow-reader's 15-minute stream
   deadline is a hard limit. Because the worker moves an organization to `deleting` only once `delete_after <= now()`,
   an export's tx2 always commits while the deletion is still pending, and its `organization.recovery_exported` event
   reaches the organization's log.
   - *Rejected:* recording the final event in the platform pseudo-organization. The organization's own log is where
     the auditor of that organization expects a secret disclosure, and the started `action` row would still be deleted.
   - *Rejected:* letting the move to `deleting` wait on the advisory lock. The window between the stream and tx2 holds
     no lock, so the race stays, and the worker round would block for up to 15 minutes under its leader lock.
2. **Inactive organizations on the platform path (review 2 finding 1, confirmed).** When the platform check finds
   `deleting` or `deleted`, `db.InPendingDeletionOrg` returns `db.OrganizationUnavailable(org, status)` (PD001
   semantics: 403 `organization_inactive`, `organization.inactive_denied` in the platform pseudo-organization), never
   `ErrNotPendingDeletion`. The platform-pool fallback stays only for organizations that are neither pending nor
   inactive.
3. **What administrators see.** `Organization.deletion` and `Me.organization_deletion` gain the required property
   `recovery_export_until: date-time` (= `delete_after − 20 minutes`, computed by the server). The banner and both
   export dialogs show "Recovery export available until <time>". After that time the action is disabled, with the text
   "The recovery export closed 20 minutes before the deletion." A deletion with grace 0 (development only) therefore
   has no export window. Gate OF9 uses grace 30 and is unaffected.
4. **Tests.** Reservation with `delete_after = now() + 19 min` → 409; with `now() + 21 min` → allowed; the
   escrow-reader's own check refuses the same 19-minute case; the platform path for a `deleting` organization → 403
   `organization_inactive`; portal component test for the disabled state.

## Amendment 2026-11-14 i — a cheaper writer gate (architect decision after the PDK-1038 load measurement)

Binding; where it contradicts amendments d, f, g or h, it wins. ADR 0052 is unchanged: it requires that every
organization transaction passes the offboarding gate and fails closed once the deletion has started; it does not
prescribe the mechanism.

### Why

The N2 ingest scenario (5 000 events/s offered, 2 ingest workers), with the gate of amendment d against no gate,
alternating, measured CPU seconds per event (worker plus postgres containers): **+9.1 %** median, B higher in both
pairs (+12.6 %, +6.0 %), postgres +5.5 %, workers +16.6 %. The stop condition is 5 %. The benchmark of the gate put
its server-side cost at 17–20 µs per transaction: about 4.6 µs for the advisory lock and its key function, about
2.8 µs for each of the two status reads, and the rest for calling a PL/pgSQL `SECURITY DEFINER` function with a
`SET search_path` clause (function-manager wrapper, GUC save and restore, no inlining).

### Candidates (cost relative to amendment d's gate)

| Candidate | Keeps guarantees 1–4 | Expected server cost per transaction | Verdict |
|---|---|---|---|
| a. Fold `set_config`, status check and lock into one definer statement | yes | ~15–18 µs; the definer and `SET` overhead stays (the implementer measured this variant: no change within the noise) | rejected |
| b. Drop the pre-lock check, non-queueing finalize, function unchanged | yes | ~14–17 µs (saves one status read) | rejected alone, adopted as a part of e |
| c. Status cached per connection or in the process, invalidated on change | no | — | rejected: the invalidation is asynchronous, so the read after the lock would no longer be fresh; a per-transaction cache saves nothing (one call per transaction) |
| d. Gate only write transactions | no | ~0 on ingest (every ingest transaction writes) | rejected: `InOrg` does not know whether `fn` writes, the measured path would not get cheaper, and reads of a deleting organization would no longer get 403 `organization_inactive` |
| e. Plain-SQL gate in `db`: lock and `set_config` in one statement, one plain status read after it, refusal in Go; finalize with a try-lock | yes | ~6–8 µs (lock without key function ~4 µs, primary-key read under RLS ~2–3 µs, no PL/pgSQL, no definer) | **chosen** |

### Decision (candidate e)

1. **Gate statements.** `db.enterOrg(ctx, tx, org)` sends one pgx batch (one round trip) with exactly two plain SQL
   statements and no function of Paddock's own:

   ```sql
   -- statement 1: context and shared lock; $2 = db.OffboardingLockKey(org)
   SELECT set_config('paddock.org_id', $1, true), pg_advisory_xact_lock_shared($2::bigint);
   -- statement 2: status after the lock, in its own statement (READ COMMITTED takes a new snapshot)
   SELECT status FROM organization WHERE id = $1::uuid;
   ```

   When statement 2 returns `deleting` or `deleted`, `enterOrg` returns `db.OrganizationUnavailable(org, status)`
   (wraps `problem.OrganizationInactive`); `inTx` then rolls back and `fn` never runs. No row (the organization does
   not exist) passes, as in amendment d; RLS still applies.
2. **No pre-lock status check.** Amendment f point 4 allows dropping it together with a non-queueing finalize; point 3
   provides that. The check after the lock stays mandatory: a transaction whose lock had to wait for a finalize that
   holds the lock sees `deleted` in statement 2.
3. **`paddock_org_enter()` is removed** (never merged). `InOrg`, `InOrgSnapshot` and `InPendingDeletionOrg` (amendment
   g point 6) call `enterOrg`; `InOrgOffboarding` keeps calling `setOrg` only. The refusal no longer carries SQLSTATE
   `PD001`: `IsOrganizationUnavailable(err)` and `OrganizationUnavailableStatus(err)` recognise the typed error of
   `db.OrganizationUnavailable`. The mapping of amendment d point 4 (api and MCP 403 `organization_inactive`, gateway
   401 `identity_revoked`, worker drop and `paddock_worker_dropped_total{reason="organization_unavailable"}`) and the
   audit of amendment f point 1 (`organization.inactive_denied` in the platform pseudo-organization, params
   `organization_id`, `attempted_code`, `status`) are unchanged.
4. **Non-queueing finalize.** `paddock_offboard_finalize()` takes `pg_try_advisory_xact_lock(paddock_offboarding_lock_key(org))`.
   When it is not granted, the function raises SQLSTATE `55P03` (`lock_not_available`) and writes nothing; otherwise
   it continues as in amendment d point 3 (row lock, status `deleting` required, `EXISTS` per registered table with
   `40001` when rows remain, tombstone in the same transaction). Finalize therefore never waits, so no transaction
   queues behind a waiting finalize and no wait cycle can form through a nested `InOrg`. Guarantee 2 becomes: finalize
   never commits while a transaction that entered the organization is still open.
5. **PDK-1015 reaction.** `55P03` from finalize keeps the job in step `tombstone` and retries next round, without
   returning to `database`; `40001` returns to `database` as before. Each `55P03` increments
   `paddock_offboarding_finalize_busy_total`.
6. **Status read for every organization role.** Statement 2 runs as the pool's own role. `paddock_api`,
   `paddock_worker`, `paddock_compiler` and `paddock_notifier` can already read their own organization row. The
   migration grants them their own organization's ID and status, nothing else:

   ```sql
   GRANT SELECT (id, status) ON organization TO paddock_escrow_reader, paddock_revocation;
   CREATE POLICY org_gate_self ON organization FOR SELECT TO paddock_escrow_reader, paddock_revocation
     USING (id = current_setting('paddock.org_id')::uuid);
   ```
7. **Migration content.** `paddock_offboarding_lock_key(uuid)` (used by finalize; `TestOffboardingLockKey` keeps Go
   and SQL equal), `paddock_offboard_finalize()` per point 4, `paddock_organization_ids()` skipping `deleting` and
   `deleted` (amendment d point 4, unchanged), and the grants and policy of point 6. No `paddock_org_enter`.

### Migration numbers and merge order

Goose rejects a migration whose number lies below the highest applied one, so numbers ascend in merge order:

| Ticket | Migration | Merge order |
|---|---|---|
| PDK-1026 | `00131_platform_mfa_enrolment.sql` (renumbered from 00132) | 1 |
| PDK-1038 | `00132_offboarding_writer_gate.sql` (renumbered from 00131, content per point 7) | 2 |
| PDK-1036 | `00133_recovery_export.sql` (unchanged) | 3, rebased on PDK-1038 |
| PDK-1015 | next free number at its merge | after PDK-1038 and PDK-1036 |

PDK-1026 and the tickets stacked on it do not wait for PDK-1038. PDK-1036 waits for PDK-1038: it uses
`problem.OrganizationInactive`, `db.OrganizationUnavailable`, the `organization.inactive_denied` code and the
`ActionRunner` denial path that PDK-1038 introduces, so it cannot ship with a guarded gate call. Any further ticket
that adds a migration and merges after PDK-1036 takes 00134 or higher.

### Development stack

The development stack's `paddock` database has amendment d's 00131 applied. It is repaired in place, without
resetting the `postgres-data` volume (shared with the audit and Authentik databases) and without touching OpenBao, as
the PostgreSQL superuser in database `paddock`:

```sql
BEGIN;
DROP FUNCTION paddock_org_enter();
DROP FUNCTION paddock_offboard_finalize();
DROP FUNCTION paddock_offboarding_lock_key(uuid);
CREATE OR REPLACE FUNCTION paddock_organization_ids() RETURNS SETOF uuid
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS
  $$ SELECT id FROM organization ORDER BY id $$;
DELETE FROM goose_db_version WHERE version_id = 131;
COMMIT;
```

Precondition: `SELECT max(version_id) FROM goose_db_version` returns 131. The body of `paddock_organization_ids` is
the one of migration 00003. No organization, device or key row changes, so the audit database, Authentik and the
escrow keys in OpenBao stay consistent. The next deployment applies 00131 (PDK-1026) and, from the PDK-1038 image,
00132. No other ticket uses this repair; it is not part of any migration.

### Re-measurement (decides the stop condition of amendment d point 5)

- Method: the N2 ingest scenario, CPU seconds per event, worker plus postgres containers over the run window, median
  A against B. At least 2 strictly alternating A/B pairs with CPU data; a run starts only when the one-minute load is
  below 8; a run whose throughput deviates by more than 10 % from its variant, or whose p99 is at least 1.5× the
  variant median, is repeated. No VMs and no test suites in parallel.
- A: the cluster branch with PDK-1026 merged (migrations up to 00131). B: the PDK-1038 branch rebased on it (00132).
  If PDK-1026 is not merged yet, A is the PDK-1026 branch and B is PDK-1038 rebased on it; B MUST NOT run on a base
  without 00131, otherwise 00131 can never be applied afterwards.
- Report per container (postgres, each worker) as well as the total; the decision uses the total.
- **Expected:** postgres about +2 %, total about +3 to +4 %.
- **Result ≤ 5 %:** PDK-1038 goes ahead. **Above 5 %:** PDK-1038 stops again and goes back to the architect with the
  per-container figures; it is not accepted, and no gate variant is tried without a new decision.

### Tests (replace the PD001 assertions of PDK-1038)

- `TestOrgEnterGate`: for every role of point 6 and for `InOrg`, `InOrgSnapshot` and `InPendingDeletionOrg`, an
  organization in `deleting` and in `deleted` is refused with `IsOrganizationUnavailable` and the right status before
  `fn` runs; other organizations are unaffected. A role whose status read returns no row for its own organization
  fails this test, because it would pass the gate.
- `TestOffboardFinalize`: an open `InOrg` transaction of the organization makes finalize raise `55P03` at once, without
  waiting; after it commits a late row, the next finalize raises `40001`; after the delete, finalize writes the
  tombstone. While finalize holds the lock, a new `InOrg` waits only until finalize ends and is then refused with
  status `deleted`. The 40-writer no-deadlock test stays.
- A migration test: `paddock_org_enter` does not exist; `paddock_escrow_reader` and `paddock_revocation` read `id` and
  `status` of their own organization only (another organization: no row; another column: permission denied).
- `BenchmarkInOrgGate` stays and reports the new gate against `InOrgOffboarding`.

### Correction 2026-11-14 to amendment i point 4 (PDK-1038 fix round 2)

Point 4's pure try-lock is replaced. A test with 16 continuous writers of the deleting organization made it fail 50 of
50 times: every refused writer holds the shared lock for one round trip, so one of them almost always holds it and
finalize starves. Keeping the try-lock would need a status read before the lock in every transaction, which point 2
removed for cost.

- `paddock_offboard_finalize()` carries the function clause `SET lock_timeout = '1s'` and takes
  `pg_advisory_xact_lock(paddock_offboarding_lock_key(org))`. When the lock is not granted within 1 s, PostgreSQL
  raises `55P03` and nothing is written. PDK-1015's reaction is still point 5.
- While finalize waits, new transactions of that organization only queue behind it, for at most 1 s, and are then
  refused (status `deleted`) or pass (finalize timed out). Other organizations are unaffected. A wait cycle through a
  nested `InOrg` of the same organization is broken after 1 s. Guarantee 2 is unchanged.
- The test asserts that finalize succeeds within 3 attempts under 16 continuous writers. The hot-path gate (points 1–3)
  is unchanged.
