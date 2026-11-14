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
