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

## Amendment 2026-11-15 j — a gate without per-transaction database cost; the budget question (architect decision after the PDK-1038 v3 measurement)

Binding; where it contradicts amendments d, f or i, it wins. ADR 0052 is unchanged (amendment i, "Why").

### The v3 measurement decides nothing

The v3 series (A `500ab352`, B `f97efbdf`) gave +12.0 % CPU per event, but:

- its two pairs disagree by a factor of ten (+22.9 % and +2.3 %);
- valkey and rustfs were OOM-looping during the whole series, and one A run dropped 65 events with a backlog of 250;
- +12.9 % in postgres contradicts the gate's measured server cost (6–8 µs per transaction): at 5 000 events/s that
  much would need far more organization transactions per event than the ingest path opens.

So the series is not evidence for or against v3. No decision is taken on it, and v3 is not re-measured: the design
below removes the per-transaction database work, so v3's cost no longer matters.

### (a) Answer to the coordinator: a gate with no per-transaction database work (candidate k, **chosen**)

The guarantee stays the one of amendment i: once the deletion has started, no organization transaction can write
anything that survives the tombstone, and every refused request gets 403 `organization_inactive`.

1. **Status cache per process.** Every process that opens organization transactions keeps an in-memory set of
   inactive organizations (`deleting`, `deleted`). It loads the set by calling the new definer function
   `paddock_inactive_organizations()` (returns `id`, `status`, and the database's `now()`; `EXECUTE` for every
   organization role). It re-reads it **every second** on the existing pool, so no extra connection is needed.
   - *Rejected:* `LISTEN`/`NOTIFY`. It would cost one held connection per process against the M19 D1 budget, and a
     notification lost across a reconnect would need the same polling as a safety net anyway.
2. **The gate is a memory check.** `enterOrg` first checks the set. It refuses an inactive organization with
   `db.OrganizationUnavailable(org, status)`, exactly as in amendment i point 3.
   - **Fail closed on a stale cache:** if the last successful refresh is older than **5 s** on the process's monotonic
     clock, `enterOrg` falls back to amendment i's statement 2 (one status read). That read needs no advisory lock,
     because point 4 does not rely on locks.
   - With a fresh cache, the transaction runs no SQL of its own: the cost is one map lookup.
3. **No advisory locks.** `pg_advisory_xact_lock_shared` in `enterOrg` and the advisory lock in finalize are removed.
   `db.OffboardingLockKey` and `paddock_offboarding_lock_key` are removed with them.
4. **Finalize waits for quiescence and then checks; it never starves.** Step `tombstone` calls
   `paddock_offboard_finalize()` (definer, `EXECUTE` for `paddock_worker` only). It runs in this order:
   - It locks the organization row, requires status `deleting`, and reads `deleting_since`. That is a new column, set
     in the same statement that sets `deleting`.
   - It refuses with SQLSTATE `55P03` while any backend of an organization role (`paddock_api`, `paddock_gateway`,
     `paddock_worker`, `paddock_compiler`, `paddock_notifier`, `paddock_escrow_reader`, `paddock_revocation`) has an
     open transaction whose `xact_start` is earlier than `deleting_since + 6 s`. Those are the 5 s staleness bound of
     point 2 plus 1 s of margin, all on the database's clock, read from `pg_stat_activity`.
   - It runs the `EXISTS` check per registered table and raises `40001` when rows remain.
   - It writes the tombstone.

   Every transaction that could still have seen the organization as active started before that instant, and the set of
   such transactions only shrinks. Finalize therefore succeeds once they have ended, however much new traffic there
   is: unlike amendment i's lock, it cannot starve. A straggler's row is caught by the `EXISTS` check (40001), so the
   job goes back to step `database`.
   - The owner `paddock_owner` gets `pg_read_all_stats` in the migration, so the function can read other roles'
     `xact_start`. If the hosting refuses that grant: stop condition.
5. **PDK-1015's reaction is unchanged.** On `55P03` it stays in step `tombstone` and retries next round; on `40001` it
   returns to `database`.
   - New: the job records `organization.deletion_step_failed` with `error_code: finalize_waiting` only when it has
     waited longer than **1 h**. A transaction open for an hour is an anomaly an operator must see.
   - The counter `paddock_offboarding_finalize_busy_total` stays.
6. **Expected cost and the re-measurement.** About 0 % per transaction. The poll adds 1 query per second per process,
   independent of load. One re-measurement on a cleaned devstack (main's precondition: valkey and rustfs stable, load
   devices removed):
   - 3 strictly alternating A/B pairs, otherwise amendment i's method;
   - additionally, per run, the `xact_commit` delta of the `paddock` database divided by the events, so that an
     implausible result is visible as such.
   - Budget: the existing 5 %. A result above it goes back to the architect with the figures, as before.
7. **Tests.** They replace amendment i's.
   - `TestOrgEnterGate`: the refusal from the cache; the stale-cache fallback (the poller is stopped for 6 s, then the
     status read refuses); other organizations are unaffected.
   - `TestOffboardFinalize`:
     - an open transaction whose `xact_start` lies before the cutoff → `55P03`;
     - a transaction started after the cutoff that was refused by the cache does not block;
     - a straggler's row → `40001`, the next delete loop removes it, then the tombstone is written;
     - 16 continuous writers of the organization plus 16 of another organization do not stop finalize from succeeding
       within 3 rounds after the stragglers end.
   - A migration test: `paddock_inactive_organizations()` reveals only IDs and status.
   - `BenchmarkInOrgGate` reports the cache path against `InOrgOffboarding`.

### (b) Answer to the coordinator: is the 5 % budget calibrated correctly?

The 5 % is a performance guard set in amendment d without a cost model. The requirement it guards is N2: 5 000
events/s with a lag below 60 s. N2 was met by every v1 and v3 run, and B's p99 was lower. Deletion correctness
(nothing survives the tombstone) is non-negotiable and must not be traded for CPU.

In the architect's view the budget is therefore stricter than the requirement needs. A gate costing around 10 % CPU
at peak ingest, with N2 met, would be acceptable on correctness grounds. **The budget is not changed here:** changing
it is the maintainer's decision, raised through the coordinator. Candidate k is meant to make that question moot. If it
lands within 5 %, nothing needs deciding; if not, the figures and this assessment go to the maintainer.

### Tickets and order

- **PDK-1038 v4** implements points 1–7 on top of v3. v3's exported surface stays unchanged: `enterOrg`,
  `db.OrganizationUnavailable`, `IsOrganizationUnavailable`, `problem.OrganizationInactive`, the denial audit of
  amendment f, and `InOrgOffboarding`. Migration `00132` is not merged yet, so its content changes in place: remove the
  lock key function, add `deleting_since`, `paddock_inactive_organizations()`, the new finalize and the
  `pg_read_all_stats` grant.
- **PDK-1036** rebases onto PDK-1038 v3 now. It uses only the unchanged surface, so v4 causes no further conflicts.
  Merge order stays as in amendment i: 1038 → 1036.
- **PDK-1015** may be built stacked on PDK-1038 v3 now. It needs only the `finalize_waiting` event of point 5. It
  merges after 1038 and 1036. Then **PDK-1016 and PDK-1017**, in either order.

### Addendum 2026-11-15 to amendment j — the quiescence wait without a statistics grant (after main's objection)

Binding. It replaces amendment j point 4's quiescence bullet and its `pg_read_all_stats` grant, and the "55P03" wording
of points 4 and 5. Everything else in amendment j stays: the status cache, the fail-closed fallback and the removal of
the advisory locks are independent of this addendum and proceed unchanged.

**Isolation is the criterion.** A role with `pg_read_all_stats` can read every session's query text, including other
organizations' sessions. No Paddock role gets it. A non-login role holding it is not needed either (see the decision).

**The transaction-ID variant is disproven (PDK-1038 v4, PostgreSQL 18.6).** PostgreSQL assigns a transaction ID only
at a transaction's first write, and `pg_snapshot_xmin` sees only transactions that have one. A gated transaction that
reads first and writes later is therefore invisible. Reproduced: W began and selected; the deletion start got ID 754;
finalize saw xmin 756 > 754 while W was open; W then got ID 756 and inserted a row that survived the tombstone. Forcing
an ID in the gate would spend an ID on every read transaction and bring back per-transaction cost. Rejected, as is
making `paddock_owner` a member of the organization roles: it would still see their query text.

**Decision: wait on virtual transaction IDs, as `CREATE INDEX CONCURRENTLY` does.** Every open transaction, including a
read-only one, holds an exclusive lock on its own virtual transaction ID (`pg_locks.locktype = 'virtualxid'`).
`pg_locks` and the `pid`, `usename` and `datname` columns of `pg_stat_activity` are readable by every role without a
grant; query text, state and timestamps of other roles are not exposed. Nothing new becomes visible.

1. **The cutoff is taken after the commit.** The worker commits the status `deleting`. In a new transaction it then
   stores `organization.deleting_committed_at = now()`, replacing `deleting_since` of amendment j. The cutoff is
   `deleting_committed_at + 6 s`: the 5 s cache staleness bound plus 1 s of margin, counted from a moment at which the
   status was certainly visible.
2. **`paddock_offboard_quiesce() RETURNS boolean`** (`SECURITY DEFINER`, owner `paddock_owner`, `EXECUTE` for
   `paddock_worker` only, context organization, status `deleting` required):
   - It captures the wait set **only when the database's `now()` is at or after the cutoff**
     (`deleting_committed_at + 6 s`). Before that it returns `false` and stores nothing.
     Reason: a set captured earlier would miss a transaction that starts between the capture and the cutoff, because
     that transaction's cache can still say `active`.
   - At the first call after the cutoff it stores the **wait set** in `organization.offboarding_wait_vxids text[]` and
     `offboarding_wait_taken_at` and commits. The wait set is every `virtualxid` lock held by a backend whose `usename`
     is an organization role (amendment j point 4) and whose `datname` is the current database, excluding its own
     backend. Taken at or after the cutoff, it is a superset of every transaction that could still have passed the gate
     on a stale cache.
   - On later calls it returns `true` once none of the stored virtual IDs is still present in `pg_locks`, otherwise
     `false`. The set is never taken again for the same deletion.
3. **`paddock_offboard_finalize()`** requires a stored wait set and that `quiesce` returns `true` in the same
   transaction. It then runs the `EXISTS` check per registered table (`40001` when rows remain) and writes the
   tombstone, clearing the wait columns. It no longer raises `55P03`.
4. **PDK-1015's reaction (replaces amendment j point 5's first sentence).** In step `tombstone`, each round calls
   `quiesce`. On `false` it stays in the step. On `true` it calls `finalize`. On `40001` it returns to `database`; the
   stored wait set stays and is not needed again, because new transactions are refused by the gate.
5. **The 1 h alert and the counter live in PDK-1015's job**, the only caller.
   - `organization.deletion_step_failed` with `error_code: finalize_waiting` is recorded once, when `quiesce` has
     returned `false` for more than 1 h after the wait set was taken.
   - `paddock_offboarding_finalize_busy_total` counts the `false` answers.
   - PDK-1038 delivers the two functions, the columns and their tests; it has no job and no alert.
6. **Edge cases.**

   | Case | Effect on the wait |
   | --- | --- |
   | Transaction-ID wraparound, hot standby | Not relevant: virtual IDs are per server and never wrap within a server's lifetime in a way that matters here; Paddock runs one primary, and a standby cannot write. |
   | Prepared transactions | Not used (`max_prepared_transactions` 0). If two-phase commit is ever enabled, `quiesce` MUST also wait on `pg_prepared_xacts` (noted in the migration header). |
   | Autovacuum, pgBackRest, `paddock-migrate`, superuser sessions | Not in the set: their `usename` is not an organization role. |
   | A long-running transaction of an organization role, of any organization, open at the cutoff | Waited for until it ends; it is in the set by construction. More than 1 h raises the alert. The operator finds it in `pg_stat_activity` as the database superuser; the remedy is `pg_terminate_backend` (runbook, PDK-1019). |
   | An idle pool connection, not in a transaction | Not in the set: a session outside a transaction holds no virtual-ID lock. pgx pool connections between transactions are of this kind. |
   | Backup and monitoring sessions (pgBackRest, Prometheus exporters, `psql` as the superuser) | Not in the set: excluded by the `usename` filter on organization roles. |
   | An idle-in-transaction pool connection | Possible only through a bug or a hung `fn`, since pgx never hands back an open transaction. Same as the previous row. |
   | A backend reusing a PID | Harmless: a virtual ID includes the backend's local transaction counter, so a new transaction on the same PID has a different virtual ID. |
7. **Tests** (they replace the ones of the earlier text of this addendum):
   - The reproduction above: W begins and reads before the status change and writes after the delete loop. `quiesce`
     returns `false` until W ends; then `finalize` raises `40001`; the next delete loop and `finalize` write the
     tombstone.
   - `quiesce` called before the cutoff stores no wait set and returns `false`. Test the boundary with the
     database's `now()` just below and just at the cutoff.
   - A read-only transaction open at the cutoff blocks `quiesce`.
   - Cache staleness (amendment j point 2) is measured on the **process's monotonic clock**, never on wall time or on
     the database's clock. The 5 s bound therefore holds as an elapsed duration whatever the drift between the process
     and the database, and stays below the 6 s margin of the cutoff. The cache takes an injectable monotonic clock. A
     test advances it past 5 s without a successful refresh and asserts the fallback status read. A second test moves
     the wall clock (not the monotonic one) and asserts that nothing changes.
   - Sessions of a non-organization role do not block.
   - The wait set survives a failed `finalize` and is not re-taken.
   - Application roles still see `<insufficient privilege>` for other sessions' query text: no grant was added.

## Amendment 2026-11-15 k — the offboarding job's object-store and Valkey rights (architect decision after the PDK-1015 stop; main's guidance; ticket PDK-1054)

Binding. It resolves the two stop conditions PDK-1015 hit (decisions 12 and 13), and where it contradicts those
decisions it wins.

### Object store (decision 12)

1. **A dedicated offboarding credential, used only by the offboarding step.** The worker policies stay as they are:
   `paddock-bundles-worker` and `paddock-escrow-worker` are not widened. The revocation-issuer's escrow-destroy
   credential is never used, read or changed (agent contract 7: the revocation path stays separate). Offboarding is not
   a revocation (`decisions-alpha11.md` §3); it deletes what remains of an organization that is being deleted.
   `deploy/compose/scripts/rustfs-bundles-bootstrap.sh` creates two users with these policies:
   - `paddock-bundles-offboard` on the bundles bucket (unversioned):
     - `s3:ListBucket` with condition `s3:prefix` limited to `org/` and `apt/`;
     - `s3:DeleteObject` on `arn:aws:s3:::<bundles>/org/*` and `arn:aws:s3:::<bundles>/apt/*`.
   - `paddock-escrow-offboard` on the escrow bucket (versioned):
     - `s3:ListBucket` and `s3:ListBucketVersions` with `s3:prefix` limited to `org/`;
     - `s3:DeleteObject` and `s3:DeleteObjectVersion` on `arn:aws:s3:::<escrow>/org/*/devices/*/luks-header/*` and
       `arn:aws:s3:::<escrow>/org/*/devices/*/diagnostics/*`;
     - no `GetObject` on either bucket.
2. **Secrets.** `rustfs_bundles_offboard_access_key`, `rustfs_bundles_offboard_secret_key`,
   `rustfs_escrow_offboard_access_key`, `rustfs_escrow_offboard_secret_key` are Docker secrets of `paddock-worker` only
   (not of `paddock-worker-ingest`). They are read through `PADDOCK_OFFBOARD_BUNDLES_S3_ACCESS_KEY_FILE`,
   `…_SECRET_KEY_FILE`, `PADDOCK_OFFBOARD_ESCROW_S3_ACCESS_KEY_FILE` and `…_SECRET_KEY_FILE`. The worker builds two
   object-store clients from them and hands them **only** to `app.Offboarding` (constructor injection). A test fails
   when another package receives them. Without the files, the step `objects` fails with `object_store_unavailable`
   (fail closed) and the rest of the worker runs.
3. **Generation and upgrade, without anyone reading `.secrets`.**
   - `make dev-secrets` (`gen-dev-secrets`) and the bundle's secret generation (`gen-prod-secrets`) create the four
     files when missing, with the same generator and file modes as the other RustFS user keys.
   - `./paddock up` and `./paddock upgrade` run the bootstrap. It is idempotent and creates the two users and policies
     on existing installations.
   - `./paddock upgrade` generates missing secret files before `up`, as it does for earlier added secrets.
   - `./paddock check` fails when the files or the RustFS users are missing.
   - Changelog fragment: an `Upgrade:` line saying that the upgrade adds two object-store users for organization
     deletion, with no operator action.
4. **Residual risk (added to PDK-1019's register work as RR-140).**
   - A compromised worker process can permanently delete escrowed LUKS header copies and diagnostics of any
     organization. Object-store policies cannot test whether an organization is being deleted.
   - It cannot read them: there is no `GetObject`.
   - Mitigation: the backup set keeps copies of escrow objects until their retention ends (ADR 0046; restore with
     `backup restore-escrow`). Each deletion by the step is counted in `organization.deletion_step_completed`
     (`count`). The credential is mounted only in the full worker.

### Valkey (decision 13)

5. **The worker needs `bp:` and `tt:` only to delete them.** The worker user in `deploy/compose/valkey/users.acl.tmpl`
   gains `%W~bp:* %W~tt:*`: write-only key patterns, which cover `DEL` and give no read. No new command is needed
   (`+del` is already granted).
6. **ADR 0051 amendment (in this PR).** ADR 0051's decision text listed `~bp:*` in full for the worker, which the
   template never had. The amendment records the worker's actual key list as in the template, plus the write-only
   `%W~bp:* %W~tt:*`, so ADR and template agree. AZ-4 is unchanged: the gateway still cannot write `bp:*` or `tt:*`.

### Ticket

7. **Prerequisite ticket PDK-1054** ("offboarding infrastructure: object-store users, Valkey ACL, secrets, wiring",
   high risk, Opus) carries points 1–6, its changelog fragment and its tests. PDK-1015 depends on it and uses the two
   clients and the ACL. The non-blocking findings of the PDK-1015 stop stand as the implementer described them:
   session revocation per administrator account, child groups before the parent, the outbox function in the next free
   migration.

### Addendum 2026-11-15 to amendment k — what PDK-1054 established (architect record after its review; main's decisions)

Binding; it refines amendment k.

1. **Approved deviations of PDK-1054.**
   - The bootstrap's `--add-missing` mode runs during `./paddock upgrade` and creates only what is missing.
   - A list probe at the end of the bootstrap, with the new offboard credentials, replaces an online user check.
   - `--add-missing` also removes an explicit, closed list of policies known to be obsolete. Today that list is only
     `paddock-escrow-read`, and it is removed only after checking that the api user still holds
     `paddock-escrow-api`. Main decided that removing that stale escrow read right is a security gain.
   - Any further entry on that list needs an architect decision.
2. **Valkey: delete only, not write-only.** Amendment k point 5 is corrected.
   - A bare `%W~` pattern would also allow `SET`, `HSET` and `PEXPIREAT` on those keys.
   - The worker user therefore gets a separate selector: `(%W~bp:* %W~tt:* -@all +del)`. Inside that selector the
     worker can only `DEL` `bp:*` and `tt:*`; it cannot read or write them.
   - The ADR 0051 amendment of 2026-11-15 is corrected to the same wording.
3. **Error code `object_retained` (decides PDK-1054a).** The closed set of `offboarding_error_code` values in §6 gains
   `object_retained`.
   - **When it is set:** the step `objects` sets it when an object version is kept by Object Lock retention or a legal
     hold. Neither the bundles bucket nor the escrow bucket has Object Lock by default, so this happens only when an
     operator added retention.
   - **Every other failure:** missing credentials included, it stays `object_store_unavailable`.
   - **No false progress:** the step does not count retained versions as deleted and does not complete. It retries
     every round, and records `organization.deletion_step_failed` once per code, as for every step.
   - **Where it is exposed:** `Organization.deletion.last_error_code` is a free string in the API (no enum), so the API
     contract does not change. The portal (PDK-1018) gains the i18n key `offboarding.error.object_retained` (en/de).
   - **Runbook:** PDK-1019's runbook names the remedy: let the retention expire, or remove the hold; the deletion then
     continues by itself.
   - PDK-1015 stores and records the code that `Offboarding.DeleteObjects` returns.

### Addendum 2026-11-15 b to amendment k — no orphaned offboarding users after a rollback (architect decision; ticket PDK-1054d)

Binding; it refines amendment k points 2 and 3.

**Finding.** After a rollback, the next upgrade copies the old `.secrets`, which lack the four offboarding key files.
New keys are then generated, `--add-missing` creates new users, and the delete-capable users of the first attempt are
left behind with live credentials.

**Decision: both of main's directions.** (a) closes the known path, and (b) makes the rule hold whatever path leads
there: a lost or restored `.secrets`, or keys regenerated by hand.

1. **(a) Rollback keeps the offboarding key files.** `rollback.sh` carries the four `rustfs_*_offboard_*` files from the
   current `.secrets` into the restored one. They are additive: the older release neither mounts nor reads them. The
   next upgrade therefore finds them and reuses the existing users.
2. **(b) `--add-missing` reconciles the two offboarding policies.**
   - Rule: for each of the closed policy names `paddock-bundles-offboard` and `paddock-escrow-offboard`, exactly one
     user may hold it, and its access key MUST equal the current key file.
   - Any other user attached to one of these two policies loses it. Users are found by policy name, from the closed
     list, never by a name pattern. *(Corrected 2026-11-15, PDK-1054f.)*
     - If the offboarding policy is the user's only policy, the user is deleted.
     - If the user also holds any other policy, only the offboarding policy is detached and the user is kept, with a
       printed warning. No Paddock path creates such a user, but one made by hand must not lose its other rights.
   - The cleanup runs **after** the current user exists and its list probe has succeeded, never before. Each removal or
     detachment is printed with its access key ID, never the secret. *(Corrected 2026-11-15, PDK-1054f: this matches
     main's amendment and the implementation ed545a96.)*
   - Users of every other policy are never touched.
   - Test (`bundle_test.sh`/bootstrap test against RustFS):
     - a stale user with the offboard policy is removed;
     - the current one is kept;
     - a user with an unrelated policy is untouched;
     - running it twice changes nothing.
3. **`./paddock check`** fails when one of the two policies is held by more than one user or by a key that does not
   match the files.
4. PDK-1054e (an upgrade path for changed policy statements) stays outside this addendum and is scheduled later, as
   main decided.

## Amendment 2026-11-15 l — shared Fleet hosts, the full Valkey key list, offboarded devices' keys (architect decision after PDK-1015; tickets PDK-1058, PDK-1059)

Binding; where it contradicts decisions 11 and 13 or amendment k, it wins.

1. **Fleet hosts shared inside the deleting organization (PDK-1058, alpha.11, medium, Sonnet).**
   - **Problem:** decision 11's check `PlatformPool.FleetHostInUse(device, host)` excludes only the device it is asked
     about. Two devices of the deleting organization on one host (a re-enrolled machine) therefore keep the host
     forever.
   - **New check:** the fleet step uses a new check, `PlatformPool.FleetHostInUseOutside(ctx, org, host)`. It is backed
     by a definer function `paddock_fleet_host_in_use_outside(org uuid, host text)` with the same grants and output as
     `paddock_fleet_host_in_use` (00076). It ignores **every** device of the given organization, both for the
     inventory reference and for the `hardware` answer.
   - **Outcome:** a host is deleted when no device of another organization uses it, and kept (reported as now) when
     one does.
   - **Unchanged:** the retention round's rule for retired devices.
   - **Tests:**
     - two devices of the deleting organization on host A → A is deleted;
     - a device of another organization also on host B → B is kept;
     - an active device of the deleting organization without an inventory reference does not block.
2. **The full Valkey key list (PDK-1059, alpha.11, low, Sonnet).** Before the `database` step, the `valkey` step reads
   from the organization's rows, and then deletes, besides decision 13's per-device keys and `tt:<org>`:
   - `et:<sha256>` of every enrollment token of the organization;
   - `enr:<id>` of its enrollments;
   - `esc:<id>` of its escrow records.

   All three are already in the worker's Valkey ACL, so no ACL change is needed. Keys outside the worker's ACL are
   **not** added to it; they all carry a TTL and expire by themselves:
   - `nonce:<device>:*`: 10 minutes;
   - `diag:<command>`: 24 hours;
   - `cres:<command>`: 30 days (`devicecache.ResultTTL`).

   They hold IDs and a status, no personal data. `retention.md` (PDK-1019) records these bounds, and OFB-4 is read with
   them.
3. **Keys of offboarded devices stay (main's decision).** For a device that gets an `offboarded_device` row
   (decision 15), the `valkey` step deletes only `bp:<device>`, `hb:<device>` and `au:<device>`. It keeps:
   - `dk:<key_id>`, rewritten with status `offboarded`;
   - `cmd:<device>`, which holds the uninstall command;
   - `seq:<device>` and `sd:<device>`, which the gateway's request check needs;
   - `nonce:<device>:*`.

   The worker deletes those keys only on the device's final `agent.uninstalled` or at the 365-day purge (decision 15).
   The **acceptance gate OF6** (decision 15, §8.7) MUST run its check-in **after** the tombstone, so it proves that an
   uninstall at the first contact after finalize works.
4. **Order.** PDK-1058 and PDK-1059 are small follow-ups to PDK-1015. They merge after it and before the alpha.11
   release regression.

## Amendment 2026-11-15 m — devices still pending approval, kept uninstalls that would expire, PDK-1016's contract details (architect decision; tickets PDK-1061, PDK-1062; main reviews)

**Approved by the maintainer as §47 (2026-11-15)**, including point 1's narrowing to devices that were ever approved.

Binding; where it contradicts decision 15 or amendments e and l, it wins.

### 1. Devices still pending approval (PDK-1061, alpha.11, medium, Sonnet)

**The leave cannot reach them.** The agent verifies every command with the command-signing keys from its signed
bundle (`agent/internal/commands/commands.go`: without `keys.CommandSigning` it returns `ErrNoKeys`). A device that was
never approved has never received a bundle, so it cannot verify an uninstall, whatever the gateway answers. Answering
`active` on the enrollment status would only move it to a check-in it cannot act on. An agent change is out of scope.

**Decision.**
- Step `devices` does not hand over devices in state `pending`: they get no `offboarded_device` row and no uninstall.
- The deletion request (`RequestDeletion`) changes nothing about them. When the deletion runs, they are deleted with
  the organization. Their enrollment status answers `pending` until the deletion's `valkey` step removes
  `enr:<device id>` (or its 7-day TTL ends), then 404 `not_found`. The agent's `waitActive` logs a warning on the 404 and
  keeps polling every 5 minutes (`MaxPoll`), harmless and inert, until its packages are removed. *(Corrected
  2026-11-15: an earlier text said "answers `rejected`" and "stops polling".)*
- Such a device never had anything applied except the Paddock packages: no bundle, no login, no sudo, no disk
  configuration. Contract 8 holds.
- PDK-1019 records the residual risk RR-141: an unapproved device keeps the inert Paddock packages and needs `apt purge
  paddock-agent paddock-supervisor` by hand. The grace-period banner (OFB-7) counts pending devices and tells
  administrators to approve and then delete them, or to remove the packages. The count comes from the required integer
  `devices_pending` in `MeOrganizationDeletion` (`GET /api/v1/me`, an additive admin API change). The api fills it
  with a count of the organization's devices in state `pending` inside `InOrg`. Only organization roles see it; the
  platform view has no count. *(Added 2026-11-15, PDK-1061.)*
- `organization.deleted` gains the param `devices_pending_dropped`.
- This narrows the maintainer's promise "every device receives an uninstall" to every device that was ever approved;
  the maintainer approved it (§47).

### 2. Kept uninstalls that would expire (PDK-1062, alpha.11, medium; folded into PDK-1016's fix round)

- Step `devices` already keeps an open uninstall whose command is `pending`, `delivered` or `succeeded`
  (amendment e point 10).
- New: a kept command in status `pending` (the device has not fetched it) whose `expires_at` is earlier than
  `now() + OffboardedDeviceRetention` is replaced in the same transaction:
  - the old command is cancelled;
  - a new `uninstall` with **the same mode and params** gets `expires_at = now() + OffboardedDeviceRetention`, is
    signed, and becomes the device's open uninstall and the `offboarded_device` envelope.
  - The mode is kept, so an administrator's `reset` stays a `reset`.
- `delivered` and `succeeded` commands stay unchanged: the device already holds them.
- No reissue on contact is needed: every handed-over device now holds or will fetch a command valid for the whole
  retention.
- **Threshold (main, §40).** A kept `pending` command is renewed only when its `expires_at` lies **more than 30 days**
  before `now() + OffboardedDeviceRetention`. The deletion's own leave, which is always only minutes short of the
  365 days, is therefore never re-issued, and no device gets two leaves. An administrator's uninstall with 7 days left
  is always renewed.
- Tests:
  - a kept administrator `reset` with 7 days left is replaced by a `reset` valid for 365 days;
  - the deletion's own leave (expiring 364 days and 23 hours from now) is kept as it is;
  - a delivered command is untouched.

### 3. PDK-1016's deviations, accepted (main reviews the contract changes)

1. **`api/openapi/device.yaml` documents 200 for `POST /v1/events` of an offboarded device.** This is decision 15's
   rule ("other events: 200 with the batch dropped"), now written into the public device contract. It is additive:
   older agents already treat 200 as delivered.
2. **The uninstall's own command result is accepted with 202 and not published.** The agent waits for that result
   before it removes itself, so a 401 there would stall the removal. There is no organization to record it in; the
   final `agent.uninstalled` event remains the record (`platform.offboarded_device_uninstalled`).
3. **A check-in after the removal report gets 401 `invalid_signature`, not `identity_revoked`.** Amendment l point 3
   deletes `dk:` at the final event. The device has removed Paddock at that point, and any 401 ends its loop. The
   device contract documents both 401 reasons for an offboarded identity.

### 4. The offboarding system gate is mandatory for alpha.11 (main)

PDK-1022 (gate OS1, including amendment n's dead man's switch case) MUST be green on both VMs before the alpha.11 tag.

## Amendment 2026-11-15 n — no dead man's switch lock on an offboarded device (architect decision after PDK-1016 review, minor 5; contract 8)

Binding; it refines decision 15 and amendment m point 2.

**Finding.** The hand-over replaces a device's whole `cmd:` hash with the uninstall, which drops a pending
`delete_self_lock` (the disarm of the dead man's switch). An offboarded device receives no time tickets (`tt:<org>` is
deleted, decision 13). A device whose leave is refused or fails therefore keeps an armed self-lock and can lock itself.
That contradicts agent contract 8 and the maintainer's promise that devices of a deleted organization keep working
(§3).

**Options.**
- (a) Keep a pending disarm next to the uninstall. − It covers only devices that already had one pending.
- (b) Disarm every handed-over device as part of the hand-over. + It does not depend on what was pending, and it uses
  the existing command, signed with command-signing by the worker. It is not the revocation path: the agent's
  `deleteSelfLock` lives in `agent/internal/agent`, not in `paddock-revoke`.
- (c) Keep serving time tickets to offboarded devices until they report the uninstall. − It needs a compiler or ticket
  path for an organization that no longer exists, and it keeps the switch armed for up to a year.

**Decision: (b), and the hand-over never drops a command.**
1. Step `devices` issues, in the same set-based transaction and **before** the uninstall (UUIDv7 order makes the gateway
   deliver it first), one `delete_self_lock` per handed-over device with `expires_at = now() +
   OffboardedDeviceRetention`.
   - It is issued for every handed-over device, whether or not its organization had the switch enabled: on a device
     without a self-lock the command succeeds with `deleted: false`.
   - Unlike decision 3's uninstalls, it is recorded only as a count: `organization.deletion_step_completed` for step
     `devices` gains `disarms_issued`.
2. `offboarded_device` holds both envelopes (`command_envelopes jsonb` replaces the single `command_id`/
   `command_envelope` before PDK-1016 merges; the migration is not merged yet). The cache **merges** them into `cmd:`;
   it never replaces the whole hash. A pending `delete_self_lock` already in `cmd:` is kept.
3. The gateway's offboarded check-in (decision 15) answers with both commands. It accepts the command results of both
   with 202 without publishing them, as amendment m point 3.2 does for the uninstall.
4. Order of effects on the device: the disarm runs first, so a later refused or failed uninstall leaves a device that
   can no longer lock itself. Contract 8 holds in every case.
5. **Tests (PDK-1016 fix round):**
   - a device with an armed self-lock and a refused uninstall (the agent's `revocationWindow`) runs the disarm, keeps
     working, and never locks;
   - an existing pending `delete_self_lock` survives the hand-over;
   - `cmd:` holds both commands after the cache sync rebuild;
   - the system gate OS1 gains a case with the dead man's switch enabled before the deletion: the VM that was off
     during the deletion comes back, disarms, uninstalls, and never locks.

Priority: alpha.11, folded into PDK-1016's fix round. The device contract note on both 401 reasons (amendment m point
3.3) belongs to the same fix round.

## Amendment 2026-11-15 o — the hand-over to the audit domain and its acknowledgement (architect decision after the PDK-1017 stop; main's constraint)

Binding; it replaces decision 16's transport and the step `audit_final`'s wait. The audit domain stays isolated, as
main required: the worker gets no connection to the audit database, and audit migration 00011's grants and
`TestOffboardingGrants` stay as they are. Options (1a) and (1b) of the PDK-1017 stop are rejected for that reason, and
(1c) is rejected because it would let the tombstone come before the final verification (ADR 0052 decision 6).

### Forward: the request goes through `ActionRunner` and the outbox

1. Step `audit_final` records one system action through `ActionRunner` in the **platform pseudo-organization**
   (platform scope, as every step event):
   - code `organization.audit_retirement_requested`;
   - params `organization_id` and `slug`;
   - nothing else.

   It is a valid `audit.Event` and reaches the audit writer through the outbox (routing key `audit.platform.<platform
   org>`), like every platform event. No new outbox writer and no new message type are introduced.
2. The audit writer writes that event as usual. **After** writing it, it intercepts this one code and starts the final
   verification of `params.organization_id`, as decision 16 describes:
   - full chain verification;
   - one `audit.chain_verified` (or `audit.chain_verification_failed`) with `final: true` in the organization's log;
   - a row in `audit_org_retired`;
   - then it refuses further events of that organization, writing them to the platform pseudo-organization as
     `audit.event_after_retirement`.
3. Events of the organization still in flight in the audit queue when the request arrives are not lost. Decision 16's
   rule writes them to the platform pseudo-organization with their original code. The step `outbox` has already
   drained the organization's outbox, so only messages published but not yet consumed can arrive late.

### Back: the audit writer acknowledges on its own channel

4. New RabbitMQ exchange `paddock.offboarding` (topic), provisioned in `deploy/compose/rabbitmq/definitions.json.tmpl`.
   - User `audit_writer` gets `write` on `^paddock\.offboarding$` only.
   - Queue `worker.offboarding` is bound to it with routing key `audit_retired.*`; user `worker` gets `read` on it.
   - No other permission changes.
5. After the row in `audit_org_retired` is committed, the writer publishes, with publisher confirms, the message
   `{"organization_id": uuid, "final_outcome": "verified"|"failed", "final_verified_at": RFC3339}` with routing key
   `audit_retired.<organization_id>`.
   - It is not an audit event and carries no personal data.
   - Until the broker confirms, the writer records `audit_org_retired.ack_published_at = NULL` (new column, audit
     migration 00012) and republishes at start and every 5 minutes. The worker handles repeats idempotently.
6. The worker consumes `worker.offboarding` and, through `PlatformPool`, sets `organization.audit_final_verified_at` and
   `organization.audit_final_outcome`. These are new columns, written only while the status is `deleting`. Step
   `audit_final` completes when `audit_final_verified_at` is set; until then it waits.
   - The step records `organization.deletion_step_failed` with `error_code: audit_writer_pending` only after more than
     1 h of waiting (one event).
   - A `failed` outcome does not block the deletion (decision 16) and is carried into `organization.deleted` as param
     `audit_final_outcome`.

### The sealer stops after the final day (question 3)

7. The sealer seals a retired organization up to and including the day of its final `audit.chain_verified` and then
   never again. That day's manifest gains the additive field `"retired": true`, and the nightly verification and the
   evidence-export verifier (`pkg/auditevidence`, `paddockctl audit verify`) accept that no manifest follows a
   `retired` manifest. Older verifiers ignore the field and verify the days they are given, so the export format stays
   compatible.

### Ticket and tests

8. All of this is in **PDK-1017** (high, Opus), including the RabbitMQ definitions, audit migration 00012 and the
   control migration for the two `organization` columns. Required tests:
   - the request event leads to exactly one final verification and one acknowledgement;
   - a lost confirm leads to a republish, and the worker applies it once;
   - the worker never opens an audit-database connection (a wiring test asserts that no audit DSN is read);
   - the writer's RabbitMQ user can publish only to `paddock.offboarding`, and the worker can read only its queue;
   - the sealer writes no manifest for a retired organization after the final day;
   - an export spanning the retirement verifies offline, and a forged manifest after a `retired` one is rejected.

**Main reviews this amendment before it merges:** it adds a channel from the audit domain to the worker (acknowledgement
only) and an additive manifest field.

## Amendment 2026-11-15 p — the deletion advances several steps per round (architect decision after PDK-946's review; ticket PDK-946c)

Binding; it replaces decision 5's "one step per organization per round".

**Finding.** The round runs once a minute and advances each organization by one step, so the ten steps take 9–10
minutes. The plan's gates (OF3, OF6, OF8, §7 step 7) assume about 5 minutes.

**Options.** (a) A faster tick or more steps per round only under `PADDOCK_ENV=development`. Rejected: the gates would
then prove a schedule that production never runs, and development switches belong in configuration only for reasons
that cannot hold in production. (b) Longer gate waits. Rejected alone: a ten-minute deletion is slow for operators too,
and it would also be the time a production deletion holds its intermediate states.

**Decision (production behaviour, no development switch).**
1. In one round, the worker advances an organization step after step while the previous step completed.
2. It stops for that organization when one of these happens:
   - a step has to wait (`outbox` pending, `quiesce` false, the audit acknowledgement missing);
   - a step fails;
   - the round's budget is used up (point 2a).

   2a. **Confirmed by main (§43): one shared budget per round.** `OffboardingRoundBudget` (45 s, below the 1-minute
   interval) is shared by all organizations in the round, not granted per organization. The round makes passes over
   the `deleting` organizations ordered by least recently advanced: each pass gives every organization one step, and
   passes repeat until no organization can advance or the budget is used up. One large organization therefore cannot
   starve the others.
3. Each completed step is still committed and recorded on its own (`organization.deletion_step_completed`), so a crash
   resumes at the next step exactly as before. An organization the budget did not reach continues next round.
3a. **Confirmed by main (§43): leadership through `db.PlatformPool.Lead`.** The offboarding round holds its leader lock
   with `Lead` (the backup role's mechanism, decisions-alpha10 §50). When the lock's connection is lost, the running
   step's context is cancelled before any further write, and the step is resumed by the next leader. The other
   `WithLeaderLock` users of the worker are unchanged.
4. Expected duration of a grace-0 deletion of a small gate organization, end to end: 2–4 rounds. The waits that span
   rounds are the quiescence cutoff of 6 s, the audit writer's final verification and acknowledgement (amendment o),
   and the outbox drain.

**Gates.**
- OF3, OF6 and OF8 and the per-gate cleanup wait at most **5 minutes**, as planned.
- The implementing ticket records the measured duration of OF3 on the development stack in its result document.
- If OF3 exceeds 5 minutes after this change, that is a stop condition (report the slow step), not a reason to raise
  the timeout.
- PDK-1022's 10-minute wait on the VMs may stay: it includes device check-ins.

**Ticket:** PDK-946c (alpha.11, medium, Sonnet) implements points 1–3 in `server/internal/worker/offboarding.go` with a
test:
- a deletion with no waits finishes in one round;
- a step that waits stops the organization for that round;
- two organizations share the budget in least-recently-advanced passes, and the budget hands over to the next round;
- a crash between two steps of one round resumes at the next step;
- losing the lead cancels the running step and writes nothing further.

## Addendum 2026-11-15 to decision 10 — the Authentik rights for deleting an organization's objects (main's decision §56)

Binding; it completes decision 10, which named the objects to delete but not the rights needed to delete them.

1. **Rights.** The Authentik role of Paddock's service account (`paddock-service`, set by the blueprint) gains
   `delete_policybinding`, `delete_application`, `delete_oauth2provider`, `delete_expressionpolicy` and
   `delete_scopemapping`. Without them the `authentik` step got 403 against a live Authentik.
2. **Why this is a small step.**
   - The role already holds `add_*` and `change_*` on exactly these object types, and `delete_group` and `delete_user`.
   - The maintainer decided that offboarding removes the organization's Authentik objects (§3).
   - No other right is added. The adapter deletes only objects named after the organization's slug (decision 10's
     list).
3. **Residual risk.** A stolen service token could now also delete any organization's device login application,
   provider, policy and mappings. That breaks device sign-in, an availability loss rather than a disclosure. The same
   token could already change those objects and delete groups and users, so the exposure grows only slightly.
   - PDK-1019 records this as a sentence in RR-140, next to the object-store risk of amendment k.
   - The worker's identity rounds (`EnsureOrganization`) recreate deleted objects of a live organization within one
     full check (decision 20: at most 6 h plus jitter, or at once after an Authentik error).
4. **Rule for every new Authentik write path.** It needs:
   - a live test against the pinned Authentik with the service account's own token (`TestLiveAuthentik`; here it runs
     `DeleteOrganization`);
   - a static test that maps each object kind the adapter writes or deletes to the right the blueprint grants.

   A fake alone does not prove rights.

## Amendment 2026-11-16 q — organization indexes for the deletion, and a database step that respects the round budget (architect decision; main §59, alpha.11 blocker)

Binding; it refines decision 7, the addendum to decision 8 (registry test) and amendment p.

**Finding (devstack, integration head 40a50255).** Several registry tables have no index that leads with
`organization_id`, so every `EXISTS (… organization_id = $1)` of `paddock_offboard_delete_batch` and
`paddock_offboard_finalize` scans the whole table:

| Table | Rows | Measured cost of one EXISTS (seq scan) |
| --- | --- | --- |
| `outbox` | 7.3 M, 7 GB | 4.4 s |
| `action` | 7.06 M (only the partial `action_org_finished_idx WHERE status = 'finished'`) | 2.3 s |
| `device_event_seen` | 1.86 M | not measured |
| `bundle` | 254 k | not measured |
| `device_identity_key` | 73 k | not measured |
| `admin_account`, `revocation_approval` | small | not measured |

That comes to about 13 s per call and (tables with rows + 1) calls per organization. In addition, the `database` step
is one unbounded `Advance`, so one large organization holds the whole round (against amendment p's shared budget).
OF3 and OF5 miss the 5 minutes, and at the target scale (70 000 devices, 7-day outbox retention, a growing `action`
table) they would miss it in production too.

### Indexes

1. **One concurrent index per table that lacks one.** For every registered table without a valid, non-partial index
   whose first key column is `organization_id`, a migration adds `CREATE INDEX CONCURRENTLY <table>_org_idx ON <table>
   (organization_id)`.
   - **One migration file per index**, marked `-- +goose NO TRANSACTION`. `CREATE INDEX CONCURRENTLY` cannot run
     inside a transaction, and one file per index keeps each step small and individually resumable.
   - Each file contains exactly two statements, in this order: `DROP INDEX CONCURRENTLY IF EXISTS <table>_org_idx;`
     then `CREATE INDEX CONCURRENTLY <table>_org_idx ON <table> (organization_id);`.
   - **Failed or INVALID index:** a concurrent build that fails leaves an INVALID index, and goose does not record the
     version. The re-run therefore drops the leftover and builds it again. A valid index never exists before its own
     migration, so the drop removes only a failed attempt.
   - Stop condition: if goose 3.29 sends the two statements of a NO TRANSACTION file in one `Exec` (an implicit
     transaction, which `CONCURRENTLY` rejects), split into one statement per file and report.
   - The table list is computed at implementation time from the registry and `pg_index` on a database with all
     migrations, not copied from the finding above. `action` gets a full index next to its partial one.
2. **Upgrade.** The indexes are built while the database serves no writes from Paddock roles, or with them; both are
   correct because the build is concurrent.
   - The changelog fragment carries an `Upgrade:` line: on large installations the first start after the upgrade can
     take several minutes longer, mostly for `outbox` and `action`. The line names the devstack figure measured in
     step 4, and states that the upgrade must not be interrupted. If it is, a re-run completes it.
   - `docs/operations/upgrade.md` gets the same note.
   - No ADR conflict: the indexes are additive (ADR 0047), and frozen migrations are not changed.
3. **Ingest cost of the `outbox` index.** One more B-tree entry per audit event. The implementer records CPU per event
   and p99 of one N2 ingest run in the result document, as information. A rise above 5 % goes to the architect before
   merge (amendment j's budget).

### Registry test (extends decision 8)

4. A database test fails when any table in `offboarding_table` lacks a **valid, non-partial** index whose **first key
   column** is `organization_id` (`pg_index.indisvalid`, `indpred IS NULL`, `indkey[0]` = the column's `attnum`). New
   organization tables therefore cannot regress. `offboarded_device` stays outside the registry (amendment c).

### The database step inside the round budget (refines amendment p, §42 fairness)

5. A new function `paddock_offboard_delete_batch_from(max_rows int, from_order int) RETURNS TABLE (deleted bigint,
   at_order int)` (same owner, grants and status check as `paddock_offboard_delete_batch`, which stays for
   compatibility).
   - It starts at the first registered table with `delete_order >= from_order` and returns the number deleted and the
     `delete_order` it worked on.
   - `deleted = 0` with `at_order = NULL` means nothing is left.
6. The `database` step keeps its position in the new column `organization.offboarding_db_order int` (NULL = start). It
   calls the function batch by batch (1 000 rows) and **checks the round's shared budget between batches**. When the
   budget is spent, it stores the position and yields; the step stays current and continues in the next pass or round
   from that position.
   - A later straggler row in an earlier table is still found: `paddock_offboard_finalize` re-checks every table and
     raises `40001`, after which the step restarts from position NULL.
7. `paddock_offboard_finalize`'s pass over all tables uses the new indexes; it needs no change.

### Proof (main)

8. On the devstack **as it is**, with its load data and without deleting any of it, the implementer re-runs OF3 and OF5
   after the migrations and records per run:
   - the end-to-end duration;
   - the duration per step;
   - the number of database batches;
   - the time of the index builds during the upgrade.

   Both MUST finish within amendment p's 5 minutes. A run above that is a stop condition: report the slow step; do not
   raise the timeout.
9. **Tests:**
   - the registry index test (point 4);
   - the function with `from_order` (resume in the middle, empty tail, a straggler in an earlier table caught by
     finalize);
   - the database step yields at the budget and resumes at its position;
   - two organizations share the budget fairly while one has a large `database` step;
   - a migration test that runs the index files twice after a simulated failed build leaves exactly one valid index.

Ticket: the implementer named by the lead on `alpha11-offboarding-integration` (high, Opus).

## Amendment 2026-11-16 r — organization transactions are short and bounded (architect decision; main §64, alpha.11 blocker)

Binding; it refines amendment j's quiescence wait and amendment p's 5-minute bound. OF3's bound stays at 5 minutes.

**Finding (devstack at 863030ce, 70 000 load devices in one organization).**
- Step `devices` waited about 8 minutes in `paddock_offboard_quiesce`. The wait set holds every open organization-role
  transaction in the database, and two of them ran for minutes:
  - `CacheSync.Reconcile` (worker, one `InOrg` transaction per organization every 60 s) sat more than 7.5 minutes on
    `ListCachedDeviceKeys` at 79 % CPU. The same query runs ad hoc in 0.2–0.3 s, which suggests a bad cached generic
    plan on the pooled connection (unconfirmed).
  - The compiler's `compileOrg` (`InOrgSnapshot`) held 1–2 minutes.
- Without such a collision a deletion takes about 2 minutes.

### Definition of "short", and the bound

1. **Target.** Every organization-role transaction finishes within **10 s** at the target scale (70 000 devices in one
   organization). This is measured, not assumed (point 8).
2. **Hard cap.** Every connection of an organization pool (`OrgPool`, the org pools of api, gateway, worker, compiler,
   notifier, escrow-reader and revocation-issuer) starts with `transaction_timeout = 45s`.
   - It is set as a connection runtime parameter: new field `db.Options.TransactionTimeout`, written into
     `ConnConfig.RuntimeParams` like `application_name`.
   - So it costs no statement per transaction (amendment j's rule). PostgreSQL 18.6 (pinned) supports it; it exists
     since 17.
   - A transaction that needs a different bound sets it itself with `SET LOCAL`, as `InWriterWithTimeout` does. That
     is allowed only lower, never higher, for organization pools.
3. **Why 45 s fits the 5 minutes.**
   - Worst case from the `deleting` commit: up to 66 s until the wait set is captured (one round plus the 6 s cutoff);
     at most 45 s until every captured transaction has ended; up to 60 s until the next pass sees it.
   - That is about 2.9 minutes for the wait, plus the measured steps around it.
   - The gate measurement (point 8) must confirm the total stays under 5 minutes.
4. **Exceptions (no organization-role cap).** These pools do not get `TransactionTimeout`, and none of them is in
   quiescence's role filter:
   - the platform pool and role (`paddock_platform`), including the leader-lock connections;
   - `paddock-migrate` (owner);
   - the backup role and restore (`paddock_backup`, pgBackRest, `paddock-server backup …`);
   - the audit database pools (the audit writer keeps its own 5-minute bound);
   - the outbox relay's pool, which is not an organization role.

   The offboarding job's own `InOrgOffboarding` delete batches **keep** the cap: they are bounded batches of 1 000 rows
   (amendment q).

### How a timeout surfaces (no silent data loss)

5. PostgreSQL ends the session and rolls the transaction back, so nothing is written partially. `db` maps the error
   (SQLSTATE `25P04`, transaction timeout, and the connection loss that follows) to `db.ErrTransactionTimeout`.
   - **api, gateway:** 503 `transaction_timeout` with `Retry-After: 5`. An `ActionRunner` attempt records its one event
     with outcome failure and reason `transaction_timeout`.
   - **worker consumers:** the message is not acknowledged and is redelivered (at-least-once, idempotent consumers).
   - **rounds:** log at `Error` and retry next round.
   - **all:** counter `paddock_db_transaction_timeout_total{role, op}` (`op` = the use case or round name) and an alert
     `PaddockDBTransactionTimeout` (rate > 0 over 15 minutes, warning), with a runbook line in
     `docs/operations/capacity.md`.

### Root fixes

6. **`CacheSync.Reconcile`.**
   - Find and record the cause of the 7.5-minute query, with `auto_explain` (allowed on the devstack, never in
     production configuration) and `EXPLAIN (GENERIC_PLAN)`.
   - If it is the generic plan, the query gets a plan that does not degrade: rewrite it, or force a custom plan for
     that statement. The pool-wide `plan_cache_mode` stays unchanged.
   - The reconcile reads **keyset-paginated batches** (by device ID, 2 000 rows), each in its own short `InOrg`
     transaction. The Valkey writes happen **outside** the transaction, after it committed. A device that changes
     between batches is caught by the next reconcile or by the regular cache writes.
7. **`compileOrg` keeps a consistent snapshot, but only for reading.**
   - The compiler reads its inputs in one `InOrgSnapshot` transaction that MUST stay within the 10 s target at 70 000
     devices.
   - It then **closes** the transaction and computes the bundles outside it. It writes the results in batches of short
     transactions, each guarded by the bundle sequence (a write applies only if the device's `bundle_seq` still matches
     what was read, the existing conditional-stamp rule).
   - A conflict leaves that device for the next compile. *(Superseded by the note of 2026-11-16 below.)*
   - **Note 2026-11-16 (PDK-1072 review).** Leaving a conflicted device is not safe: an older snapshot can commit
     first (`TestStaleConcurrentCommitIsRecompiled`), and the newer inputs would then be lost.
     - **Rule:** a device whose guarded write conflicts is recompiled from a **fresh snapshot**, as a device-scope
       compile event without force, for at most 3 rounds. If it still conflicts after that, the compile fails and the
       consumer requeues the batch (at-least-once). Nothing is skipped silently.
     - **The bundle upload stays inside the guarded commit transaction.** The row lock protects the versioned object key
       from an overwrite race.
     - **Bound:** the upload is limited to about 5 s (`UploadTimeout`). A guarded commit transaction covers the uploads
       of so few devices that it stays within the 10 s target of point 1, even when every upload in it takes the full
       timeout; the 45 s cap still applies.
     - **Test:** a commit whose uploads all hit the timeout ends within the target and requeues; it does not hold the
       transaction open.
   - If reading the inputs alone exceeds 10 s at 70 000 devices: stop condition, report the figures. The architect
     then decides on a paged consistent read (an exported snapshot) instead.

### Proof and tests

8. **On the devstack as it is (with the 70 000 load devices):**
   - the longest organization-role transaction per role over 30 minutes, from `pg_stat_activity` sampling;
   - OF3 and OF5 end to end and per step.

   All organization-role transactions must stay ≤ 10 s, and OF3 and OF5 ≤ 5 minutes. Exceeding either is a stop
   condition.
9. **Tests:**
   - a pool with `TransactionTimeout` ends a deliberately long transaction with `db.ErrTransactionTimeout`, and nothing
     is written;
   - the api maps it to 503 with `Retry-After`;
   - a consumer redelivers;
   - `CacheSync.Reconcile` pages through 70 000 seeded devices with no transaction over 10 s (integration, skipped with
     `-short`);
   - `compileOrg`'s read transaction stays under 10 s for 70 000 devices, and a concurrent change makes the guarded
     write skip that device;
   - a test asserts which pools carry the timeout and which do not (point 4).

**ADR check.** No conflict. ADR 0052 and amendment j are unchanged: there is still no per-transaction statement, and
the wait now has a bound. ADR 0005 (bundle compilation) does not prescribe how long the compiler's read transaction
lasts. The existing guarantee that each organization's inputs come from one snapshot (`InOrgSnapshot`) is kept, and
only the computation moves outside it.

Ticket: the lead's Opus implementer on `alpha11-offboarding-integration`. Points 6 and 7 MAY be split into two tickets,
but both must land before OF3 is re-measured.

## Amendment 2026-11-16 s — every large step yields, and the caches a deletion leaves stay affordable (architect decision; main §79/§80, alpha.11 blocker)

Status: Accepted (approved by main, §81).

Binding; it refines amendment p (round, passes, budget), amendment q point 6 (the database step's yield) and decision
15 (offboarded devices in Valkey), and corrects the Valkey line of `docs/operations/capacity.md`. OF3's bound stays at
5 minutes.

**Finding (devstack, §62 step 4, image of integration 7e23f0ca).** A 3-device organization was deleted next to one
with 110 000 devices; both requests were sent at the same second with grace 0.

| Organization | Request to tombstone | Own work | Longest wait |
| --- | --- | --- | --- |
| small (3 devices) | 48 min 55 s (bound 5 min) | about 10 s | `valkey` 16.8 min, `audit_final` 28.0 min |
| large (110 000 devices) | 69 min 49 s (no bound) | — | `objects` 44.7 min, `database` 20.8 min |

- The round advances organizations in passes, but only the `database` step yields (amendment q). The `objects` step
  deleted one object per `DeleteObject` request, about 40 per second, and held the round for 44.7 minutes. The
  `devices` step (174.5 s, signing about 1.6 s per 1 000 devices) delayed the small organization by 2 minutes in the
  same way.
- **Why `audit_final` waited 28 minutes.** The audit writer was not the cause.
  - The small organization's `organization.audit_retirement_requested` was recorded only at about 22:38:45. The
    writer acknowledged it within seconds. The large organization's own `audit_final`, with 8.18 M events, took
    16.8 s.
  - The large `objects` step failed once at 22:10:48 (RustFS was OOM-killed). The next round gave the small
    organization exactly one step (`valkey`). Then it ran the large `objects` step again, for another 26.9 minutes.
  - The retry was not delayed. `worker.Offboarding.advance` computes the backoff from the time the failed attempt
    *started*: 21:54:03 + 1 min, which was already in the past.
  - Point 1 removes the long step and point 2 the backoff defect. Together they cover the 28 minutes.
- **Valkey** (512 MiB limit, AOF on, no `maxmemory`) was OOM-killed 23 times. The cause:
  - Every offboarded device keeps about 2.3 KB (`cmd:` with two signed envelopes 1 720 B, `dk:` 520 B, `seq:` 64 B),
    so 110 000 devices hold about 253 MB.
  - The cache sync rewrites every entry every 60 s, unchanged or not. `app.OffboardedDevices.Restore` does it for
    every offboarded device (`HSET` per command, `DEL`+`HSET` per key), `CacheSync.Reconcile` for every live key.
  - That grows the AOF by hundreds of MB per minute and triggers rewrites. The rewrite's fork, with copy-on-write
    under the same write load, crosses the container limit.
  - The resets broke other organizations' rounds and gateway check-ins.
  - In addition, `Restore` loads all 110 000 records in one transaction every minute (worker 60 → 550 MiB).
- **RustFS** (2 GiB) was OOM-looping before the deletion started. It reached 2 GiB about 2 minutes after each restart,
  from its own scanner over 110 000 bundle objects (330 000 directories). It stopped once about half of them were
  purged.
- **Log flood.** Within one second of the `deleting` commit:
  - 74 920 × `attention finding not materialized` (one per open condition of a round that had already listed the
    organization);
  - 48 561 × `device cache update failed` (one per change notification of the organization's devices).

### 1. Every step whose work grows with the organization yields (refines amendments p and q)

1. **One slice for all steps.** `app.OffboardingDatabaseSlice` is renamed `app.OffboardingStepSlice` (5 s, unchanged).
   A step call that is **resumable** stops after a unit of work once `now ≥ min(deadline, call start +
   OffboardingStepSlice)`. It stores its progress and returns the yield (point 1.7). With a zero deadline (`Advance`)
   it runs to the end.
   - Every call completes **at least one unit**, so every call progresses.
   - Resumable steps: `devices`, `fleet`, `objects`, `valkey`, `database`.
   - Not resumable, because their work does not grow with the number of devices: `sessions` (administrator accounts),
     `outbox` (one count), `authentik` (the organization's fixed set of objects), `audit_final` (one claim),
     `tombstone`. `fleet` is added beyond main's list: with real Fleet hosts it makes one HTTP request per host and
     would starve the round exactly like `objects` did.
2. **Progress and cursor.** Migration `00159_organization_offboarding_progress.sql`, transactional. It adds:
   - `organization.offboarding_cursor text NULL`: the resume position of the current step. Its meaning depends on the
     step (point 1.3). NULL means the step has not started.
   - `organization.offboarding_failures_recorded text[] NOT NULL DEFAULT '{}'` (point 3).
   - It backfills `offboarding_failures_recorded = ARRAY[offboarding_error_code]` for every organization with a
     non-NULL `offboarding_error_code`.

   Query changes:
   - New query `SaveOrganizationOffboardingProgress` (section 8) adds `@added` to
     `offboarding_counts[@step]`, sets `offboarding_cursor`, and clears `offboarding_error_code`. It applies only while
     the organization is `deleting` at `@step`, like `SaveOrganizationOffboardingDatabaseBatch`, which stays for the
     database step.
   - `CompleteOrganizationOffboardingStep` also sets `offboarding_cursor = NULL`.

   The migration number follows PDK-1079b's `00158`. If `00159` is taken when the ticket starts, that is a stop
   condition.
3. **The units and the resume of each step.**

   | Step | Unit | Cursor | Resume |
   | --- | --- | --- | --- |
   | `devices` | first call: quiesce + `OffboardReissueUninstalls` (one transaction, unchanged); then one page of 500 handed devices: commands, keys, cancelled uninstalls (one `InOrgOffboarding` transaction), `commandsign.SignAll`, `PutOffboardedDevice`, `DeleteCommand` of the cancelled ones, `InsertOffboardedDevices` | NULL before the reissue; after it the last handed device ID of the page (`00000000-0000-0000-0000-000000000000` right after the reissue) | the quiesce and the reissue run only while the cursor is NULL; pages continue with `id > cursor` |
   | `fleet` | one page of 200 distinct Fleet hosts, `external_id > cursor`, ordered by `external_id` | the last `external_id` of the page | continues after it; a host is listed once, because `DISTINCT ON (external_id)` keeps every reference of a host on one page |
   | `objects` | one listing page (at most 1 000 keys or versions) and **one `DeleteObjects` request** for it | none | re-listing: every call lists the three prefixes from their start again (point 1.4) |
   | `valkey` | one page of 2 000 devices with their key IDs: `ListPresentOffboardedDevices` for the page, then `devicecache.DeleteOrganization(ctx, org, page, OffboardOrgKeys{})`; the call that reads a page shorter than 2 000 also reads the token hashes and escrow IDs and passes them | the last device ID of the page | continues with `id > cursor` |
   | `database` | one `paddock_offboard_delete_batch_from` batch (unchanged, amendment q) | `offboarding_db_order` (unchanged) | unchanged |

   - Each unit's count is stored with `SaveOrganizationOffboardingProgress` right after the unit, before the slice
     check. A crash therefore loses neither the count nor the position.
   - The step completes (`complete`) when a call reaches the end: a page shorter than its size, or every listing
     done. The final unit's count goes with the completion.
4. **`objects`: `DeleteObjects` in batches of 1 000, resumed by listing again (no stored cursor).**
   - `objectstore.Store.PurgeObjects(ctx, prefix, until)` (unversioned bundles bucket) and `PurgeVersions(ctx, prefix,
     until)` (versioned escrow bucket):
     - list pages of at most 1 000 entries from the start of the prefix;
     - send one `DeleteObjects` with `Quiet: true` per page, keys only, or key and `VersionId`;
     - read the per-key errors of the response;
     - return `Purge{Deleted, Retained, Done}`.
   - A per-key error that `retainedKeyError(code, message)` classifies as Object Lock is recorded in `Retained`. It
     uses the codes and message words of `retainedError`. Any other per-key error, or an error of the whole request,
     ends the call with that error.
   - Each S3 request gets its own 30 s timeout (`objectstore.PurgeRequestTimeout`).
   - **Yield rule:** the call returns `Done = false` after a page only if it has **deleted at least one entry in this
     call** and `until` has passed. A call that meets only retained entries therefore lists to the end, and the step
     terminates.
   - **Why no cursor:** deleted entries vanish from the listing, so listing from the start continues exactly where the
     last call stopped. Only retained entries are listed again: one failed entry per call, and only in the escrow
     bucket, where Object Lock is a misconfiguration that already fails the step with `object_retained`. A persisted
     marker would add a column and a stale-marker case (an object written behind the marker by a straggler) for no
     gain.
   - The step calls the three purges in order (`org/<id>/` and `apt/<id>/` of bundles, `org/<id>/` of escrow) with
     the same `until`. When one returns `Done = false`, the step stores its count and yields. The next call starts
     again at the first prefix: an emptied prefix costs one list request.
   - When all three are done: `object_retained` if any were retained, otherwise the step completes.
   - The old one-object-per-request loops are removed.
   - Rights: S3 authorizes `DeleteObjects` per key with `s3:DeleteObject` (and `s3:DeleteObjectVersion` for a
     version). The offboard policies of amendment k already grant both. **If RustFS 1.0.4 refuses `DeleteObjects` for
     the offboard users, or the SDK's request checksum: stop and report. Do not widen a policy.**
5. **Errors.**
   - A unit that fails returns the step's error code as before: `object_store_unavailable`, `valkey_unavailable`,
     `signing_unavailable`, `fleet_unavailable` or `database_error`. The count of the call's earlier units is already
     stored.
   - The backoff and retry are unchanged. Progress clears `offboarding_error_code` (and with it the
     `paddock_offboarding_step_failing` gauge), as the database step already does.
6. **Fairness.**
   - The round's passes stay as in amendment p 2a. A yielding organization stays in the pass list, like the database
     step's yield.
   - One large organization therefore costs every other organization at most one slice (5 s plus one unit, bounded
     by the 30 s S3 timeout) per pass.
7. **The yield reaches the worker as a value, not as `nil`.**
   - New exported error type `app.OffboardingYield{Step string}`. Every resumable step returns it on a yield, which
     replaces `errDatabaseYield`.
   - `worker.Offboarding.advance` treats it like a completed step: the organization stays in the pass, and its
     retries are cleared. It also counts `paddock_offboarding_step_yields_total{step}`.

### 2. Two defects of the round (worker)

1. **Backoff from the end of the attempt.** In `advance`, `r.next = o.now().Add(delay)` is taken **after**
   `AdvanceWithin` returned, not from the time before the call.
2. **`audit_final` is polled, not spun.**
   - Today the pending acknowledgement returns `(false, nil)`. The organization stays in every pass and is re-read in
     a tight loop until the budget ends, against amendment p point 2.
   - New exported sentinel `app.ErrOffboardingPolling`, returned while the acknowledgement is missing.
   - The worker keeps such an organization in the round, but skips it in a pass until `offboardingPollInterval`
     (2 s) has passed since its last poll.
   - When a pass advanced no organization and only polling organizations remain, the round sleeps until the earliest
     poll is due or the deadline, whichever comes first. The sleep is context-aware and injectable for tests.
   - The acknowledgement is therefore seen within about 2 s, as today, without the hot loop.
3. **Overrun visibility.**
   - Counter `paddock_offboarding_round_overruns_total`: rounds that took longer than 120 s (`2 × OffboardingInterval`).
   - Alert `PaddockOrganizationDeletionRoundOverrun`: `increase(paddock_offboarding_round_overruns_total[30m]) > 0`,
     severity warning, with a `promtool` test.
   - After point 1 a round lasts at most the budget plus one slice plus one unit. An overrun means a step stopped
     yielding.

### 3. At most one failure event per code per deletion (main §32)

- `fail` records `organization.deletion_step_failed` only when the code is **not** in
  `offboarding_failures_recorded`. In the same transaction it appends the code.
- The comparison with the stored `offboarding_error_code` no longer decides whether an event is recorded. The stored
  code is still written, for the gauge and the portal.
- This also closes today's gaps:
  - a code that comes back after progress cleared it (the database step since §61);
  - a sequence A → B → A.
- The rule is per code, not per step and code (confirmed by main, §81). The step of a later failure with an
  already-recorded code is visible in the gauge `paddock_offboarding_step_failing{step,error_code}` and on the
  organization, not as a second event.

### 4. Valkey: no rewrite of unchanged entries, bounded memory, a sizing rule

1. **Compare before write in the periodic reconcile.** New type `devicecache.Syncer` with:
   - `SyncDeviceKeys(ctx, []DeviceKeyEntry) (written int, err error)`;
   - `SyncOffboardedDevices(ctx, []OffboardedDevice) (written int, err error)`.

   Per batch of at most 500 entries, it:
   - pipelines `SET seq:<device> <last> NX`. A failed NX writes nothing to the AOF, which keeps `RestoreSeq`'s
     semantics.
   - pipelines `HGETALL` of the `dk:` (and, for offboarded devices, `cmd:`) keys;
   - writes only what differs:
     - `dk:` with the existing `putHash` (DEL+HSET in MULTI) when its field map differs from the wanted one;
     - `cmd:` with `HSET` of exactly the fields that are missing or differ. It never removes a field (amendment n
       point 2).

   `CacheSync.Reconcile` (live keys) and `OffboardedDevices.Restore` use the Syncer. The change-notification path
   (`CacheSync.Changed`) and the deletion's `devices` step keep their unconditional writes: they write one changed
   entry each.
   - **Why read-compare and not a process-local fingerprint:** other paths write `dk:` too (enrolment, the `devices`
     step, notifications). A fingerprint that misses one of them could skip a needed write, and a stale `active` key
     is a security defect. Reading costs about 300 B per live key per minute, and nothing is written to the AOF.
   - **ACL (main §81):** `+hgetall` is **not** added to the worker's root permissions. The worker's user gains a
     read-only selector: `(%R~dk:* %R~cmd:* -@all +hgetall)`.
     - Within the selector the worker may run `HGETALL` on `dk:` and `cmd:` keys only.
     - Every other key and every other command stays as before. `HGETALL` on any other key is refused with NOPERM.
     - The worker already writes these keys from PostgreSQL, so it sees no data it could not already reconstruct.
     - ADR 0051's amendment of 2026-11-16 records the selector.
     - A running devstack needs `docker compose up -d --force-recreate valkey` (the ACL is rendered at start, §58).
     - An upgrade recreates the container.
2. **`Restore` pages and runs less often.**
   - It reads `offboarded_device` in keyset pages of 1 000 rows, each in its own platform transaction (new query
     `ListOffboardedDevicesPage(after_device uuid, max_rows int)` in a new query file `offboarded_device.sql`).
   - It runs at most every **15 minutes** (`worker.OffboardedRestoreInterval`) instead of with every 60-s reconcile,
     and at the first reconcile after the worker starts.
   - An offboarded device only fetches its uninstall, which is valid for 365 days, so after a Valkey data loss it
     waits at most 15 minutes longer.
3. **Counter** `paddock_device_cache_reconcile_writes_total{kind="device_key"|"offboarded_device"}`. In the steady
   state it stays flat. That is how the operator and the gate see that nothing is rewritten.
4. **`maxmemory` with `noeviction`.**
   - Without `maxmemory` the kernel kills Valkey, and every client loses reads and writes until the AOF is loaded
     again.
   - **Eviction is not acceptable.** An evicted `seq:` or `nonce:` weakens replay protection, and an evicted `dk:` or
     `cmd:` turns into 503s that look like outages.
   - So: `maxmemory-policy noeviction` in `valkey.conf`. `deploy/compose/valkey/entrypoint.sh` reads the cgroup limit
     (`/sys/fs/cgroup/memory.max`). If it is a number, the entrypoint passes `--maxmemory <60 % of it in bytes>` to
     `valkey-server`. If it is `max`, the entrypoint sets no maxmemory and prints one line saying so.
   - At the limit Valkey refuses writes that need memory and keeps serving reads and `DEL`, so the deletion's
     `valkey` step and the uninstall reports still free memory. The 40 % above it is the AOF rewrite's copy-on-write
     headroom.
   - This mirrors RabbitMQ's memory alarm at 60 % of its limit (`docs/operations/capacity.md`).
5. **Default and sizing rule.**
   - `PADDOCK_VALKEY_MEM_LIMIT` defaults to **1g** instead of 512m (`compose.yaml`, `prod.env.example`,
     `lab.env.example`, changelog `Upgrade:` line).
   - Rule in `docs/operations/capacity.md`: `PADDOCK_VALKEY_MEM_LIMIT ≥ 2 × (64 MiB + live devices × 2.0 KB +
     offboarded devices × 2.3 KB)`.
     - Measured: 220 MiB for 110 000 live devices, +175 MiB after their hand-over.
     - Offboarded devices count for 365 days after their organization's deletion.
     - Example: 70 000 live plus 70 000 offboarded devices need 716 MiB, so the 1 GiB default fits.
   - The sentence "a limit reached there points to a leak, not to a larger installation" is replaced.
6. **`./paddock check --online` warns.**
   - New item `valkey: memory headroom`. It reads the container's usage and limit with `docker stats --no-stream`
     (no Valkey credential, no ACL change).
   - PASS at ≤ 50 % of the limit.
   - WARN above, with the usage, the limit and the rule of point 5.
   - "not checked" WARN when the listing fails.
   - The parsing lives in `deploy/compose/scripts/valkey-headroom.sh` with a shell test.

### 5. RustFS sizing (docs only)

`docs/operations/capacity.md` (memory limits) gains:
- **1 GiB of `PADDOCK_RUSTFS_MEM_LIMIT` per 20 000 objects in the control plane's object store, at least 2 GiB.**
  Each managed device keeps one bundle object, plus its escrow objects (one LUKS header per encrypted disk,
  diagnostics while retained).
- The number comes from the §62 measurement on RustFS 1.0.4:
  - 2 GiB looped at 110 000 bundle objects (330 000 directories), from RustFS's own scanner (`walk_dir`);
  - it stayed below the limit from about 55 000 objects on;
  - 20 000 per GiB leaves headroom.
- Example: 70 000 devices with one LUKS header each need 140 000 objects, so 7 GiB.
- The default stays 2 GiB (about 40 000 objects). No scanner tuning in alpha.11 (open point 2).

### 6. Rounds skip organizations that start deleting (log flood)

1. `app.Findings.Materialize`: the first write that fails with `db.IsOrganizationUnavailable(err)` ends the
   organization's materialization at once. It returns that error once, with no per-finding `WARN`.
2. `worker.CacheSync`:
   - In the listener, a `Changed` error with `db.IsOrganizationUnavailable(err)` is not logged at `WARN`. It is
     logged once per organization per process, at `Info`: "device cache changes of a deleting organization are
     skipped; the deletion removes its keys".
   - In `ReconcileAll`, an organization that fails with it is skipped without a `WARN`.
3. Other rounds already log one line per organization. They are unchanged.

### 7. Proof: OF3 next to a large organization (gate OF3L)

1. New acceptance test `TestOrganizationDeletedWithinFiveMinutesNextToLargeOrganization`. It runs only when
   `PADDOCK_OF3_LARGE_ORG` names a seeded organization (slug), and skips otherwise. CI does not run it; the lead runs
   it on the devstack. It:
   - checks the precondition: the admin device list of the large organization reports `total ≥ 10000` or
     `total_capped = true`;
   - creates a small organization with the existing helpers `gateOrganization` and `activeDeviceWith` (3 active
     devices);
   - sends both deletions with grace 0 in parallel;
   - asserts that the small organization reaches `deleted` within **5 minutes**, client-side and server-side
     (`requested_at` to `deleted_at`);
   - then waits up to 60 minutes for the large organization's tombstone (the 1-hour alert's bound) and asserts
     `objects_deleted ≥ 10000` in its `organization.deleted` event, read from the audit index (the seed had real
     bundles);
   - logs the per-step durations of both organizations from their `organization.deletion_step_completed` events,
     read from the audit index like OF5 does (`expectOneIndexEvent`).
2. **Seeding with the existing load tooling** (on a development stack only; the load guard refuses otherwise):
   ```
   make load-enrol-configs ORG=of3-large TOKENS=20 USES=1000
   make load-identities CONFIGS="$(ls bin/load/token-*.json | tr '\n' ' ')" COUNT=20000
   ```
   - 20 000 devices, twice main's minimum: at 10 000 the old code delayed the small organization by only about
     4 minutes, too close to the bound to discriminate.
   - The devices are approved automatically by their tokens. The compiler writes their bundles. The gate's
     `objects_deleted` assertion proves this.
   - `make load-test` is not needed.
3. **Recorded in the result document:**
   - both organizations' per-step durations;
   - the duration of `OffboardReissueUninstalls` for 20 000 devices. Above 10 s (amendment r's target) is a stop
     condition.
   - Valkey and RustFS restart counts during the run, which must be 0.
   - the growth of Valkey's incremental AOF file (`/data/appendonlydir/*.incr.aof`) over 10 idle minutes after the
     run, before and after section 4.

### 8. Interfaces (binding)

```sql
-- migration 00159_organization_offboarding_progress.sql (transactional)
ALTER TABLE organization
  ADD COLUMN offboarding_cursor text,
  ADD COLUMN offboarding_failures_recorded text[] NOT NULL DEFAULT '{}';
UPDATE organization SET offboarding_failures_recorded = ARRAY[offboarding_error_code]
WHERE offboarding_error_code IS NOT NULL;

-- organization.sql
-- name: SaveOrganizationOffboardingProgress :exec
UPDATE organization
SET offboarding_error_code = NULL,
    offboarding_counts = offboarding_counts || jsonb_build_object(@step::text,
      coalesce((offboarding_counts ->> @step::text)::bigint, 0) + @added::bigint),
    offboarding_cursor = sqlc.narg(cursor)::text
WHERE id = @id AND status = 'deleting' AND offboarding_step = @step;

-- name: MarkOrganizationOffboardingFailureRecorded :execrows
UPDATE organization SET offboarding_failures_recorded = array_append(offboarding_failures_recorded, @code::text)
WHERE id = @id AND NOT (@code::text = ANY(offboarding_failures_recorded));
-- CompleteOrganizationOffboardingStep: additionally SET offboarding_cursor = NULL.

-- offboarding.sql (organization context, InOrgOffboarding)
-- name: ListOffboardingHandedDevicesPage :many
SELECT id FROM device WHERE uninstalled_at IS NULL AND state NOT IN ('pending', 'retired', 'rejected')
  AND id > @after_device::uuid ORDER BY id LIMIT @max_devices;
-- name: ListOffboardingInventoryRefsPage :many
SELECT DISTINCT ON (external_id) external_id, device_id FROM device_inventory_ref
WHERE external_id <> '' AND external_id > @after_external_id::text ORDER BY external_id, device_id LIMIT @max_hosts;
-- name: ListOffboardingDeviceKeysPage :many
SELECT d.id AS device_id, coalesce(k.key_id, '')::text AS key_id
FROM (SELECT id FROM device WHERE id > @after_device::uuid ORDER BY id LIMIT @max_devices) d
LEFT JOIN device_identity_key k ON k.device_id = d.id ORDER BY d.id, k.key_id;

-- offboarded_device.sql (new file, platform pool; PDK-1088)
-- name: ListOffboardedDevicesPage :many
SELECT * FROM offboarded_device WHERE device_id > @after_device::uuid ORDER BY device_id LIMIT @max_rows;
```

```go
// app
const OffboardingStepSlice = 5 * time.Second // replaces OffboardingDatabaseSlice
type OffboardingYield struct{ Step string } // Error() "offboarding: step <step> yields at its slice"
var ErrOffboardingPolling = errors.New("offboarding: the step waits for an acknowledgement and is polled again")
const (
    offboardingDevicePage = 500
    offboardingFleetPage  = 200
    offboardingValkeyPage = 2000
)
type OffboardingBundles interface {
    PurgeObjects(ctx context.Context, prefix string, until time.Time) (objectstore.Purge, error)
}
type OffboardingEscrow interface {
    PurgeVersions(ctx context.Context, prefix string, until time.Time) (objectstore.Purge, error)
}
func (o *Offboarding) DeleteObjects(ctx context.Context, org uuid.UUID, until time.Time) (int, error)

// objectstore
const PurgeBatch = 1000
const PurgeRequestTimeout = 30 * time.Second
type Purge struct {
    Deleted  int
    Retained []string
    Done     bool // the listing reached its end in this call
}
// until zero: no bound. Done=false only after a page that deleted at least one entry in this call once until passed.
func (s *Store) PurgeObjects(ctx context.Context, prefix string, until time.Time) (Purge, error)
func (s *Store) PurgeVersions(ctx context.Context, prefix string, until time.Time) (Purge, error)

// worker
const offboardingPollInterval = 2 * time.Second
const OffboardedRestoreInterval = 15 * time.Minute // PDK-1088
// metrics: paddock_offboarding_step_yields_total{step} (counter), paddock_offboarding_round_overruns_total (counter),
// paddock_device_cache_reconcile_writes_total{kind} (counter, PDK-1088)

// devicecache (PDK-1088)
type DeviceKeyEntry struct {
    KeyID   string
    Key     DeviceKey
    LastSeq int64
}
type Syncer struct{ /* unexported */ }
func NewSyncer(c *Cache) *Syncer
func (s *Syncer) SyncDeviceKeys(ctx context.Context, entries []DeviceKeyEntry) (written int, err error)
func (s *Syncer) SyncOffboardedDevices(ctx context.Context, devices []OffboardedDevice) (written int, err error)
```

### Tickets and order

- **PDK-1087** (sections 1–3, 7; high, Opus) and **PDK-1088** (sections 4–6; high, Opus) run **in parallel** on
  `alpha11-offboarding-integration`. They share no file.
- PDK-1087 merges after PDK-1079b (migration order).
- OF3L counts after both are merged; the lead re-runs it there.

**ADR check.**
- ADR 0052 is unchanged: steps, order and idempotency stay.
- ADR 0051 amendment 2026-11-16 (Accepted, main §81) records the worker's read-only `HGETALL` selector, and the
  Valkey memory policy of section 4 points 4–5: `maxmemory` at 60 % with `noeviction`, the sizing rule and the 1g
  default. These bind every future Valkey user beyond M17.

## Amendment 2026-11-16 t — no Valkey peak during a deletion, no fixed two-minute wait, bundle versions that are never pruned, the size of a deletion request (architect decision; main §94)

Status: Accepted (approved by main, main §96).

Binding once accepted. It refines amendment s point 4 (Valkey sizing), amendment j's addendum point 4 (how the job
reacts to `paddock_offboard_quiesce` returning `false`) and amendment s point 5 (RustFS sizing). ADRs 0051 and 0052 are
unchanged: the Valkey memory policy, the sizing rule's formula, the steps, their order and their idempotency stay.

**Evidence (devstack, §87 step 5, image of integration 10bbc671).** `load-n2` (218 034 devices) and a 3-device
organization were deleted in parallel with grace 0.

| Measurement | Value |
| --- | --- |
| small organization, request to tombstone | 2 min 31 s server-side (bound 5 min: met) |
| small organization, step `devices` | 119.9 s (step 4 on 7e23f0ca: 120.0 s); its reissue took 3 ms |
| large organization, request to tombstone | 75 min 49 s |
| delete request of the large organization (202) | 27.3 s (step 4: 9.2 s for 110 000 devices) |
| Valkey (2g, `maxmemory` 1 228.8 MiB) | 640 MiB → 1 004 MiB in the step `devices` (+218 009 keys); the step `valkey` deleted 436 299 keys 50 min later; 986 MiB at the end |
| RustFS (2g) | 29 OOM kills during the run; still looping afterwards with 201 395 objects in `paddock-bundles`, 195 457 of them below one organization (`acme`: 195 451 bundle rows for 2 845 devices, about 69 versions per device, created 2026-11-03 to 2026-11-15) |

### 1. The step `devices` frees each page's live Valkey entries before it writes the page's offboarded ones (alpha.11)

**Cause (code of 10bbc671).**
- `Offboarding.handOver` writes, per handed device, `cmd:<device>` with two signed envelopes (about 1 720 B) and
  rewrites `dk:<key>` with status `offboarded` (same size as before). `seq:<device>` already exists.
- The live entries the device no longer needs, `bp:`, `enr:`, `hb:` and `au:`, stay until the step `valkey`.
  `devicecache.DeleteOrganization` deletes them there, for every device of the organization.
- Between the two steps run `outbox`, `authentik`, `fleet` and `objects`. For `load-n2` that was 51 minutes, during
  which both sets were held: +364 MiB RSS for 218 034 devices. At the briefed 1g the step could not have written the
  offboarded entries at all (`maxmemory` 614.4 MiB, `noeviction`).

**What still needs the live entries after a device's hand-over: nothing.**
- The gateway serves a device whose `dk:` has status `offboarded` its commands only. `checkin` returns before
  `bundleRef` (no `bp:` read), records no heartbeat (no `hb:`) and offers no agent update (no `au:`).
  `authenticateDevice`, used by `catalogIcon` (the other `bp:` reader), refuses an offboarded key.
- `enrollStatus` with an existing `enr:` answers `rejected` for a device whose `dk:` is `offboarded`, and 404
  `not_found` once `enr:` is gone. A device in neither case reaches its uninstall through the enrollment status
  (amendment m point 1), so deleting `enr:` earlier changes no outcome. The step `valkey` deletes it today anyway.
- No step after `devices` reads them. `objects` lists object-store prefixes, and `valkey` deletes what is left.
- No writer re-creates them after the step's quiesce: the compiler's and the worker's organization transactions are
  refused for a deleting organization, and their reconciles skip it (amendment s point 6).
- A late writer, such as a compiler that committed before the quiesce and writes `bp:` after it, is still covered:
  the step `valkey` stays unchanged and deletes whatever exists.

**Decision.**
1. New method `devicecache.Cache.DeleteHandedDeviceKeys(ctx, devices []uuid.UUID) (int64, error)`. It deletes
   `hb:`, `au:` and `enr:` of every given device in DEL calls of at most `deleteChunk` (500) keys. It deletes `bp:` in
   **separate** DEL calls of at most 500 keys: the worker may delete `bp:` only through its delete-only selector
   `(%W~bp:* %W~tt:* -@all +del)`, and Valkey allows a DEL only when one selector or the root permissions cover every
   key of it. It returns how many keys existed.
   - `DeleteOrganization` keeps its behaviour and its key list. The code that builds and sends the two DEL groups
     MAY be shared between both methods.
   - No ACL change.
2. `app.OffboardingCache` gains `DeleteHandedDeviceKeys(ctx context.Context, devices []uuid.UUID) (int64, error)`.
3. `Offboarding.handOver` calls it with **every device ID of the page** returned by `ListOffboardingHandedDevicesPage`.
   - It runs right after the page's `InOrgOffboarding` transaction, **before** `commandsign.SignAll` and before any
     `PutOffboardedDevice`. Freeing first means the page's new entries can use the memory just freed, and the step
     still progresses while Valkey is at its `maxmemory`: `noeviction` refuses writes that need memory but serves
     `DEL`.
   - It also runs when the page has no commands (`len(cmds) == 0`).
   - An error fails the step with `valkey_unavailable`, like `PutOffboardedDevice`. The page is repeated: deleting
     missing keys is a no-op.
   - The deleted count is **not** added to any step count. The step `valkey`'s count, which reports what it deleted,
     becomes smaller for the same organization.
4. Order inside one device's hand-over during the window: a check-in that still sees the `active` key between the
   delete and the `dk:` rewrite gets no bundle reference and no agent update for that one check-in. That is harmless:
   the organization is `deleting`, and its devices get nothing new anyway.
5. **Sizing.** With point 3, a device of a deleting organization moves from about 2.0 KB (live) to about 2.3 KB
   (offboarded) per page of 500 devices. The peak is that difference plus one page, not the sum of both sets. The
   rule of ADR 0051's amendment of 2026-11-16 stays as it is. `docs/operations/capacity.md` gains one sentence:
   **"Count the devices of an organization from the moment its deletion runs as offboarded devices."**
   `./paddock check --online` and `valkey-headroom.sh` are unchanged.
6. **The devstack stays at 2g.** It holds about 330 000 offboarded devices (load-enrol and load-n2, 365-day
   retention) and 3 400 live ones. By the rule that is 2 × (64 MiB + 3 400 × 2.0 KB + 330 000 × 2.3 KB) ≈ 1.6 GiB.
   - `docs/operations/local-dev.md`, section "Valkey", gains a paragraph: a development stack that kept the
     offboarded devices of a load-seeded organization's deletion needs `PADDOCK_VALKEY_MEM_LIMIT` by the rule of
     `docs/operations/capacity.md`. It is set in `deploy/compose/.env` (example `PADDOCK_VALKEY_MEM_LIMIT=2g`) and
     applied with `docker compose up -d --force-recreate valkey`. A shell export is lost at the next `make up`.
   - The default in `compose.yaml` stays 1g. The lead sets 2g in the devstack's `.env`, which is untracked.

### 2. A waiting step is polled within the round, not once a minute (alpha.11)

**Cause (code of 10bbc671).** The 120 s are two round intervals (`worker.OffboardingInterval` = 1 min). They are not
load, not the reissue and not the uninstall issue.
- Call 1, round *n*: `paddock_offboard_quiesce` finds `deleting_committed_at` NULL, stores `clock_timestamp()` and
  returns `false`. `Offboarding.devices` returns `ErrOffboardingWaiting`, and `worker.Offboarding.advance` answers
  `stepStop`: the organization takes no further step **in this round**.
- Call 2, round *n+1* (60 s later, past the 6 s cutoff): it takes the wait set and checks it in the same statement.
  Any organization-role transaction open at that instant (check-ins, other rounds) is in the set and still open
  microseconds later, so the answer is `false` almost always on a busy stack.
- Call 3, round *n+2*: the set has ended, so the reissue and the hand-over run. That is 2 × 60 s ≈ 119.9 s, for
  every organization size. The same reaction applies to the tombstone, where the wait set already exists and the
  answer usually comes at once.

**Decision.**
1. `worker.Offboarding.advance` answers `ErrOffboardingWaiting` with **`stepPolling`** instead of `stepStop`. It still
   clears the organization's retries, as today.
   - The organization stays in the round and is asked again after `offboardingPollInterval` (2 s), exactly like a
     pending `audit_final` (amendment s point 2.2).
   - When only polling organizations remain, the round sleeps in `awaitPoll` until the earliest poll is due or the
     budget ends.
2. `paddock_offboarding_finalize_busy_total` is incremented **at most once per organization per round**: on the first
   `ErrOffboardingWaiting` of that organization in the round. Its help text and `docs/operations/monitoring.md` keep
   the meaning "rounds in which the step `devices` or the tombstone waited". This replaces amendment j's "counts the
   `false` answers".
3. Nothing else changes:
   - the function `paddock_offboard_quiesce`, the 6 s cutoff (the gate's 5 s staleness bound plus 1 s) and the
     wait-set semantics;
   - `FinalizeWaitAlert` (1 h) and `finalize_waiting`, recorded once;
   - the round budget, the slice and the backoff of failing steps.
4. Expected effect: the step `devices` of a small organization takes about 8–12 s (cutoff 6 s, then one or two polls
   2 s apart) instead of 120 s. The OF3 bound stays 5 minutes.
5. Cost: one short `InOrgOffboarding` transaction (the row lock `FOR NO KEY UPDATE` on the organization row plus a
   `pg_locks` scan) and one `GetOrganization` read per poll, at most every 2 s per waiting organization. A waiting
   step that waits behind a long transaction (RR-145) is polled every 2 s for the length of that wait. That is
   accepted: it is the same cost as `audit_final`'s polling.
6. Doc comments that say "asks again next round" (`ErrOffboardingWaiting`, `Offboarding.devices`,
   `Offboarding.tombstone` in `server/internal/app/offboarding_job.go`) are corrected to "asked again after the
   round's poll interval". The runbook row `finalize_waiting` in `docs/operations/organization-offboarding.md` says
   "The step continues within seconds" instead of "in the next round".

### 3. Bundle versions are never pruned (alpha.11: operator command and documentation; alpha.12: automatic pruning)

**Cause (code of 10bbc671).**
- `compiler.Compiler.commit` writes every bundle version to its own key
  `org/<org>/devices/<device>/bundles/<version>.dsse` (`compiler.ObjectKey`) and inserts a `bundle` row.
- Nothing deletes a superseded object. Only an organization's deletion (step `objects`) removes them.
- Every recompile therefore adds one object per device: a platform change, an agent update, a rollout, a key change.
  On the devstack that was about 69 per device in 12 days.
- RustFS's resident memory grows with the number of objects (amendment s point 5: 1 GiB per 20 000), so every
  installation runs into the RustFS limit over time.
- Amendment s point 5's premise, "each managed device keeps one bundle object", is wrong.

**What devices and agents need.**
- The gateway presigns only the newest version (`bp:<device>`, never moved back) with `BundleURLTTL` = 120 s. An
  agent may still be downloading the previous version for up to 120 s after a newer one was published. On a 404 the
  agent keeps its applied state and fetches the newest version at its next check-in (fail safe).
- No server path reads an older version's object. The portal's bundle history (`ListDeviceBundles`), the rollouts
  and the apply reports use the `bundle` **rows**, which stay.
- A restore does not back up the bundles bucket. It raises the bundle sequence and recompiles every device
  (`docs/operations/restore.md`, "Bundle sequence"). Version numbers are therefore **not contiguous**: pruning MUST
  NOT compute keys as `version − n`.
- **WORM:** `paddock-bundles` has neither versioning nor Object Lock (`rustfs-bundles-bootstrap.sh`). Only
  `paddock-escrow` is versioned, and only the audit store is WORM. Nothing blocks a delete.

**Options.**

| Option | For | Against |
| --- | --- | --- |
| A. Bucket lifecycle (`Expiration`, `NoncurrentVersionExpiration`) on RustFS 1.0.4 | No code in the hot path; RustFS documents AWS-compatible lifecycle rules, and the development backup target already uses `NoncurrentVersionExpiration` | Not applicable: every version is its own **current** key in an **unversioned** bucket, so there are no noncurrent versions. An age rule (`Expiration.Days`) would also delete the newest bundle of a device whose configuration did not change. S3 lifecycle cannot express "keep the newest N keys below a prefix". It runs in RustFS's scanner, the component that OOMs. Rejected. |
| A'. One key per device in a versioned bucket, plus `NoncurrentVersionExpiration` with `NewerNoncurrentVersions` | Lifecycle then fits | Changes the object-key contract (architecture §7.1), the presigned URLs (version IDs), the step `objects` (versions) and the bootstrap. RustFS does not document `NewerNoncurrentVersions`. Rejected for alpha.11 and alpha.12. |
| B. The compiler deletes the superseded objects after a publish, keeping the newest two (current and previous) | Bounded at two objects per device; uses the `bundle` rows, so the versions need not be contiguous; no scanner | Adds a delete to the compile path, which is load-measured. Needs `s3:DeleteObject` for the compiler on `org/*/devices/*/bundles/*`, a grant that `./paddock upgrade` (`bootstrap buckets --add-missing`) cannot add to an existing user today, so it needs a new attach helper. The backlog of existing installations needs a catch-up. Not small. |
| C. An operator command that prunes on demand, keeping the newest N per device | Small; no server change; works on every existing installation now; fixes the devstack | Manual; the operator must run it. |

**Decision.**
1. **alpha.11: option C**, as `./paddock bundles prune [--keep N] [--yes]` (control plane or lab host). The script is
   `deploy/compose/scripts/bundles-prune.sh`, run with the bucket's root credential and the pinned `AWS_CLI_IMAGE`,
   like `rustfs-bundles-bootstrap.sh`.
   - It lists `org/` of `PADDOCK_BUNDLES_S3_BUCKET` (default `paddock-bundles`) and considers only keys matching
     `^org/[0-9a-f-]{36}/devices/[0-9a-f-]{36}/bundles/[0-9]+\.dsse$`. Icons (`org/<org>/icons/`) and packages
     (`apt/`) are never touched.
   - Per device directory it keeps the `N` highest version numbers (numeric order, `--keep` default 2, minimum 2;
     `--keep 1` is refused with exit 2).
   - It also keeps every object whose `LastModified` lies less than 10 minutes in the past: a version published while
     the command runs, and an in-flight download, are never removed.
   - Without `--yes` it deletes nothing and prints `would delete <n> of <m> bundle objects of <d> devices (keeping the
     newest <N> per device)`. With `--yes` it deletes in `delete-objects` requests of at most 1 000 keys with
     `Quiet: true`, and prints `deleted <n> of <m> bundle objects of <d> devices`.
   - Any per-key error in a response ends the run with exit 1 and the number deleted so far. A rerun continues: the
     selection is computed again from a fresh listing.
   - It never reads object contents and never prints a credential.
   - It is not an audited action: it removes derived, reproducible artifacts on the operator's own host (like
     `docker image prune`), the `bundle` rows and the history in the portal stay, and the server's audited actions
     are not involved. The runbook says so.
2. **Documentation (alpha.11).**
   - `docs/operations/capacity.md`, RustFS paragraph: the objects to count are **every stored bundle version**, not one
     per device, plus the escrow objects. The paragraph says that versions accumulate with every recompile until
     pruned, how to count them (the command's dry run prints the number), and that `./paddock bundles prune --yes`
     after large recompiles keeps the store at two objects per device.
   - Residual risk **RR-146** in `docs/compliance/residual-risks.md`, section "Application hardening (M12h)", next to
     RR-120:
     - **Risk:** bundle versions accumulate in the control plane's object store until an operator prunes them, and
       the store's memory grows with them until it hits its limit.
     - **Mitigation:** `./paddock bundles prune`, the sizing rule in `capacity.md`, automatic pruning planned for
       0.1.0-alpha.12.
     - **Record in the ISMS:** run the prune after large recompiles and in the monthly capacity review.
   - The command in the usage text of `./paddock`.
3. **alpha.12: option B**, planned in a separate amendment (ticket stub PDK-1100). It binds now only as a direction:
   - the compiler deletes, after a successful publish, the objects of the device's versions older than the newest two
     `bundle` rows;
   - a dedicated grant `s3:DeleteObject` on `org/*/devices/*/bundles/*` only;
   - an upgrade path that attaches it to an existing compiler user;
   - a bounded catch-up for the existing backlog;
   - a load measurement of the compile path.
   If it needs a migration, it takes the next free number when that ticket starts (00161 or later).

### 4. Uninstalls issued inside the deletion request (alpha.11: documented limit; alpha.12: asynchronous)

**Cause (code of 10bbc671).** `Organizations.RequestDeletion` issues the uninstall to every active device in the
request (`RunExternal`, bounded by `DeletionRequestBudget` = 2 min), before it answers 202. The duration grows with the
devices, and faster than linearly: 9.2 s for 110 000 devices, 27.3 s for 218 034. The server's `WriteTimeout` is
120 s. A proxy or client with a 30–60 s timeout in front of it gives up first. When the request context ends, the
external phase is cancelled and the request is withdrawn as a whole (`CancelOrganizationDeletion`).

**Decision.**
1. **alpha.11: documentation only.** `docs/operations/capacity.md` gains the section "Organization deletion", stating:
   - the request issues every device's uninstall before it answers;
   - measured: 9.2 s for 110 000 devices, 27.3 s for 218 034;
   - **supported up to about 250 000 devices per organization**;
   - above that, or behind a proxy whose read timeout is below 60 s, raise the proxy's read timeout to at least 120 s
     for `/api/platform/` (the bundled Caddy has no response timeout; `nginx/paddock.conf.example` sets 300 s);
   - a request that timed out at the client is either complete or withdrawn as a whole: read the organization's
     status before you repeat it;
   - the deletion steps themselves have no such limit, because they yield (amendment s point 1).
2. **alpha.12: asynchronous issue** (ticket stub PDK-1101). The request records the deletion as pending and answers
   202 at once. The worker issues the uninstalls in set-based pages (amendment e) before the grace period can end, and
   the grace period does not start counting before every uninstall is issued. Planned in a separate amendment. It
   changes ADR 0052 decision 2's "the request issues the leave", so it needs an ADR 0052 amendment.

### 5. Tickets and order

| Ticket | Points | alpha | Branch base | Files (exclusive) |
| --- | --- | --- | --- | --- |
| PDK-1097 | 1, 4.1 | 11 | `alpha11-offboarding-integration` | `server/internal/devicecache/offboarding.go`, `server/internal/devicecache/offboarding_test.go`, `server/internal/app/offboarding_job.go`, `server/internal/app/offboarding_job_integration_test.go`, `server/internal/app/offboarding_devices_integration_test.go`, `docs/operations/capacity.md`, `docs/operations/local-dev.md`, `changelog.d/PDK-1097.fixed.md` |
| PDK-1098 | 2 (without point 2.6's Go comments) | 11 | `alpha11-offboarding-integration` | `server/internal/worker/offboarding.go`, `server/internal/worker/offboarding_test.go`, `docs/operations/monitoring.md`, `docs/operations/organization-offboarding.md`, `changelog.d/PDK-1098.fixed.md` |
| PDK-1099 | 3.1, 3.2 | 11 | `alpha11-offboarding-integration`, after PDK-1097 merged (`capacity.md`) | `deploy/compose/scripts/bundles-prune.sh`, `deploy/compose/scripts/bundles-prune_test.sh`, `deploy/bundle/paddock`, `deploy/bundle/build.sh`, `Makefile`, `docs/operations/capacity.md`, `docs/compliance/residual-risks.md`, `changelog.d/PDK-1099.added.md` |
| PDK-1100 | 3.3 | 12 | — | stub |
| PDK-1101 | 4.2 | 12 | — | stub |

- PDK-1097 and PDK-1098 run **in parallel**. They share no file. Point 2.6's Go doc comments live in
  `offboarding_job.go`, so PDK-1097 corrects them, citing this amendment.
- PDK-1099 starts after PDK-1097 has merged.
- None of the three needs a migration. PDK-1096 keeps `00160`.
- Interactions with tickets in flight:
  - **PDK-1079d** (`platform/db/statementcache.go`, `ingest_plans_test.go`, `cmd/paddock-server/worker.go`): none of
    these files is touched. No new SQL is added, so the statement cache lists are unaffected.
  - **PDK-1096** (migration `00160`): no migration here.
  - **PDK-1091** (`organizations_deletion_integration_test.go`) and **PDK-1092** (`s3test.go`, compiler tests): no
    shared file. PDK-1091's request-path timing is what PDK-1101 removes in alpha.12, and nothing here changes it.
  - **PDK-1085** (todo) also edits `deploy/bundle/paddock` (the check). Whichever of PDK-1085 and PDK-1099 merges
    second rebases. The blocks are independent.
- Never touched: `agent/internal/revoke/`, `agent/cmd/paddock-revoke/`, the revocation issuer, ADRs, dependencies and
  images.

**Proof (lead, after PDK-1097 and PDK-1098 are merged):** OF3L, plus a repeat of the §87 run on the devstack at 2g.
Record in the result documents:
- the small organization's step `devices` duration, which MUST be ≤ 30 s;
- Valkey RSS before and after the large organization's step `devices`. An increase above `devices × 1.0 KB + 64 MiB`
  (about 277 MiB for 218 034 devices) is a stop condition for the release.
- `bp:` and `enr:` counts of the deleting organization right after its step `devices`, which MUST be 0 for handed
  devices;
- the step `valkey`'s count.

## Addendum 2026-11-16 to amendment t point 3 — `./paddock bundles prune` is audited (main §96)

Status: Accepted (main §96; this addendum only implements main's condition).

Main's decision §96 overrides amendment t point 3.1's sentence "It is not an audited action". The command deletes
data, so a deleting run records one audit event in the platform pseudo-organization. Everything else in point 3.1
stays: the selection, the `--keep` rules, the 10-minute guard, the batching and the dry run.

1. **Audit code.** `platform.bundle_versions_pruned` is added to the closed registry
   (`server/internal/domain/audit/codes.go`) as `audit.CodePlatformBundleVersionsPruned`, `Emitted: true`.
   - Description: "An operator ran ./paddock bundles prune --yes on the control-plane host: superseded bundle versions
     were deleted from the bundles bucket, keeping the newest keep per device (actor: system, platform
     pseudo-organization)."
   - Params: `keep`, `listed`, `devices`, `selected`, `deleted`, `failed` (all integers).
   - Outcomes: `success`, `failure`.
   - The portal message key is `audit.platform.bundle_versions_pruned` in `server/web/src/locales/en.json` and
     `de.json`. `make gen` regenerates the generated registry outputs.
2. **Admin subcommand.** `paddock-server admin record-bundle-prune --keep K --listed M --devices D --selected N
   --deleted X --failed F`.
   - Every flag is required and is a decimal integer.
   - Usage error (exit 2) unless `2 ≤ K ≤ 1000`, `0 ≤ M, D, N, X, F ≤ 1 000 000 000`, `N ≤ M` and `X + F ≤ N`.
   - It calls the new use case `func (a *Admin) RecordBundlePrune(ctx context.Context, p BundlePrune) error` with
     `type BundlePrune struct{ Keep, Listed, Devices, Selected, Deleted, Failed int64 }`. The use case runs
     `a.runner.RunTx(system(ctx, uuid.Nil), ScopePlatform, SpecBundleVersionsPruned, fn)`, with
     `SpecBundleVersionsPruned = ActionSpec{Code: audit.CodePlatformBundleVersionsPruned, Actor: &adminActor}`. `fn`
     sets the six params and writes nothing else.
   - It returns `ErrBundlePruneIncomplete` ("the prune ended with failed deletions") when `Failed > 0`, so the runner
     records outcome `failure` with the same params and the command exits 1. Otherwise the outcome is `success`.
   - `paddock-server admin record-bundle-prune --check` (no other flag) opens both pools, pings the platform pool,
     records nothing and exits 0. It exists so the host command can refuse to delete while the event could not be
     recorded.
3. **Host command flow** (`bundles-prune.sh`, run by `./paddock bundles prune`). The script runs the subcommand as
   `./paddock agent-rollout` does: `docker compose run --rm --no-deps paddock-api admin …`, through the `compose`
   helper of `lib.sh`.
   - **Dry run (no `--yes`): not audited.** It deletes nothing and only lists keys, like the read-only commands
     (`backup status`, `upgrade-check`), none of which is audited.
   - `--yes`, before the first deletion: `record-bundle-prune --check`. If it fails, the script exits 1 with "the audit
     log cannot be written; nothing was deleted".
   - `--yes` with `selected = 0`: no deletion. The event is still recorded with `deleted 0`, so every confirmed run is
     on record.
   - After the last batch, or after the batch that returned errors: `record-bundle-prune` with the run's counts.
     `failed` is the number of keys reported in `Errors`, and later batches are not sent.
   - **Erratum 2026-11-16:** the subcommand runs in `paddock-worker`, as the restore admin commands do
     (`compose --profile paddock run --rm --no-deps -T paddock-worker admin …`), not in `paddock-api`: `runAdmin`
     needs the worker database URL, which `paddock-api` does not have. A delete call that fails as a whole (non-zero
     exit, for example a connection reset) counts its whole batch as `failed`, stops, and is recorded like a batch that
     returned errors.
   - If recording fails after deleting, the script exits 1 and prints the counts and "the audit event could not be
     recorded". The counts on stdout are the only record of that run. RR-146 names this residual gap.
4. **Identity.** The event records the fixed system actor `paddock-server admin`, the same actor as
   `bump-bundle-seq`, `raise-bundle-seq` and the rollout commands (RR-90).
   - The subcommand has **no** flag for an actor, user or reason, and the use case takes none. Nothing typed in the
     shell can put a person's name into the audit log.
   - The person is established by the host's own access control: whoever can run `docker compose run` on the control
     plane, from the operating system's login and sudo records.
   - This is the same boundary as RR-90, and the runbook says so.
   - A free-text `--by` was rejected: it would be self-asserted, so it proves nothing and makes a false name possible.
5. **Docs.**
   - `docs/operations/capacity.md` says the command is audited (`platform.bundle_versions_pruned`) and the dry run is
     not.
   - RR-146's mitigation names the event and its system actor. Its ISMS column adds: tie host access to persons (as
     for RR-90), and keep the command's output if the event could not be recorded.
6. **Ticket.** PDK-1099 gains the server scope: the code, the subcommand, the use case and their tests. It now has
   risk high: it adds an audit code and an admin entry point. Its files grow by:
   - `server/internal/domain/audit/codes.go`;
   - `server/internal/app/admin.go`;
   - `server/internal/app/admin_integration_test.go`;
   - `server/cmd/paddock-server/admin.go` and its parse test;
   - `server/web/src/locales/en.json` and `server/web/src/locales/de.json`;
   - the generated registry outputs.

   PDK-1097 and PDK-1098 touch none of these files. PDK-1079d touches `cmd/paddock-server/worker.go`, not `admin.go`.
