# 0052 — Organization offboarding: deletion lifecycle, retained evidence and devices
Status: Accepted (architect, 2026-11-14; product decisions by the maintainer on 2026-11-14; plan
`docs/plans/M17-organization-offboarding.md`)

## Context

Paddock can create an organization but never remove one (finding of PDK-946, decision A10-23). A platform that hosts
several customers must be able to end a customer relationship: GDPR Art. 28(3)(g) obliges a processor to delete (or
return) the controller's personal data at the end of the service unless Union or Member State law requires storage,
and ISO/IEC 27001:2022 A.5.33 (protection of records) and A.8.10 (information deletion) require that what is deleted
is deleted provably and what must be kept is kept. Development stacks need the same path: leftover test
organizations made identity rounds cost several CPU cores (PDK-570, PDK-1010).

Facts about the code that bound the design (checked 2026-11-14, `main` at `f6d59cb9`):

- 74 tables carry `organization_id` with `ENABLE` + `FORCE ROW LEVEL SECURITY`; none has `ON DELETE CASCADE` to
  `organization`, and most application roles have no `DELETE` grant on most of them. A finished `action` row is
  read-only for every role (ADR 0032).
- Per organization the Authentik adapter owns: the groups `paddock.<slug>` and every `paddock.<slug>.*` child (roles,
  `.locked`, `.g.*`, `.s.*`, `.d.*`), the users it created (path `paddock/<slug>`, attribute `paddock_managed`), the
  scope mapping `paddock-device-groups-<slug>`, the OAuth provider and application `paddock-device-<slug>` and the
  expression policy `paddock-device-<slug>-access` with its binding.
- Object storage under `org/<organization_id>/` in the bundles bucket (bundles, icons), `apt/<organization_id>/`
  (organization repository, ADR 0050) and the escrow bucket (LUKS headers, diagnostics bundles); the audit WORM bucket
  under `org/<organization_id>/` is COMPLIANCE-locked and cannot be deleted before its retention date.
- OpenBao holds **no** per-organization path: every Transit key is platform-wide; organization secrets (escrow,
  repository keys, notification credentials) are ciphertexts in PostgreSQL or object storage, some under derived
  keys whose context is the organization. Deleting the ciphertexts is the deletion.
- Fleet hosts of the organization's devices; Valkey keys per device (`dk:`, `cmd:`, `seq:`, `sd:`, `bp:`, `hb:`,
  `au:`, `nonce:`) and per organization (`tt:<org>`), session records `sess:*` of its administrators.
- Uninstall (ADR 0037 decision D3) exists: the signed command `uninstall` with mode `leave` removes the Paddock
  packages, state and keys and keeps local accounts, Himmelblau, the disk encryption and all user data; the device
  retires itself through its final report.

Maintainer decisions of 2026-11-14 (`decisions-alpha11.md` §3), binding for this ADR:

1. Before deletion every device receives an uninstall `leave` command; deletion waits for a grace period; a device
   that is offline then leaves at its next contact; local data and encryption stay; no revocation.
2. The organization's audit log stays in WORM until its retention ends and is readable only by platform
   administrators and auditors; everything else of the organization is deleted.

## Options

### A. How data is deleted

- **A1 — Cascading foreign keys and one `DELETE FROM organization`.** + One statement. − Changes 74 constraints in
  one migration; a single huge transaction holds locks on every table; the RLS policies of the application roles
  would have to allow it, or it runs as the owner outside every policy; no progress, no resumption.
- **A2 — Per-table `DELETE` grants for the worker, deletion in Go.** + Ordinary code. − Grants the worker deletion of
  every organization table permanently (least privilege), and every new table needs a grant and a code change that
  nothing forces.
- **A3 — One `SECURITY DEFINER` function owned by `paddock_owner`, executable by `paddock_worker` only, that deletes
  in batches in the order of a registry table, only for the organization of the transaction's
  `paddock.org_id` and only while that organization's status is `deleting`; a test fails when a table with
  `organization_id` is missing from the registry.** + The worker gains exactly one capability, usable only on an
  organization the platform has already put into `deleting` with a step-up; batches keep transactions short and the
  job resumable; new tables cannot be forgotten silently. − A definer function is a privileged object (inventory and
  `search_path` lint of M12h-2 apply). **Chosen.**

### B. What happens to devices

- **B1 — Leave devices alone (retire them).** − The agent stops with 401; every Paddock artifact, a stale sudoers
  file and the deny list stay on the device. Rejected by the maintainer.
- **B2 — Revoke (Lock or Destroy).** − Destroys user data; contradicts agent contract 8. Rejected by the maintainer.
- **B3 — Uninstall `leave` for every device, issued by the system when the deletion is requested; grace period;
  devices that never reported keep a minimal platform record after the deletion, so that they still receive the
  uninstall at their next contact.** **Chosen** (maintainer decision 1).

### C. Audit evidence

- **C1 — Delete the audit index with the organization.** − The WORM objects stay anyway and the evidence becomes
  unreadable; contradicts maintainer decision 2.
- **C2 — Keep index, WORM objects, manifests and their metadata under their normal retention; stop the nightly
  verification after one final verification; let platform administrators read the log and produce the existing
  evidence export for the organization's auditors.** **Chosen** (maintainer decision 2).

## Decision

1. **Lifecycle.** `organization.status` gains `deleting` and `deleted`. A pending deletion is `active` with
   `deletion_requested_at`, `delete_after` and `deletion_requested_by` set: the organization keeps working during the
   grace period, so that its administrators can reveal recovery keys and local administrator passwords they need.
   `POST /api/platform/v1/organizations/{id}/delete` (platform administrator, step-up, typed slug, reason,
   `grace_days`) starts it; `POST /api/platform/v1/organizations/{id}/cancel-deletion` ends it while the status is
   `active`. At `delete_after` the worker sets `deleting` and runs the deletion steps; then the row becomes a
   tombstone with status `deleted` and `deleted_at`. The tombstone keeps `id`, `slug`, `name` and the deletion
   columns; slug and domains become free for reuse.
2. **Devices.** The deletion request issues the signed command `uninstall` with mode `leave` (reason
   `organization_offboarding`) to every `active` device, as the system and inside the platform administrator's
   stepped-up action; this is the only path on which the system issues an uninstall (deviation from ADR 0037
   decision D3, which requires an organization administrator per device). The command's expiry is `delete_after`
   plus `OffboardedDeviceRetention` (365 days). Cancelling the deletion cancels every uninstall not yet delivered.
   When the deletion runs, every device that has not reported its removal keeps one row in the platform table
   `offboarded_device` (device ID, key IDs with their public keys, the signed uninstall envelope, the tombstone's
   organization ID); the gateway authenticates such a device from that row, answers its check-in with the uninstall
   command only, and accepts exactly its final `agent.uninstalled` event. The row and its Valkey keys are deleted on
   that event or after `OffboardedDeviceRetention`. No Lock, no Destroy, no self-lock token, no wipe.
3. **Deletion steps**, in this order, each idempotent and checkpointed (`offboarding_step`): `sessions` (portal and
   MCP sessions, API tokens of the organization), `devices` (write `offboarded_device` rows), `outbox` (wait until
   every outbox row of the organization is published, so no audit event is lost), `authentik` (the objects listed in
   the context; synced users only lose their memberships with the groups), `fleet` (hosts of the organization's
   devices, with the existing in-use check across organizations), `objects` (bundles bucket `org/<id>/`,
   `apt/<id>/`, escrow bucket `org/<id>/`; never the audit WORM bucket), `valkey` (the device and organization keys
   listed in the context), `database` (the definer function of option A3 until nothing is left), `tombstone`.
4. **Database deletion** follows option A3: function `paddock_offboard_delete_batch(max_rows int) RETURNS bigint`
   and registry table `offboarding_table (table_name text PRIMARY KEY, delete_order int NOT NULL UNIQUE)`.
5. **Kept** (and the only things kept): the tombstone row; the audit index rows, `audit_object`, `audit_manifest`,
   `audit_org_seq`, `audit_verification_run` and the WORM objects of the organization until their normal retention
   (`PADDOCK_AUDIT_RETENTION_DAYS` ≥ 400, index retention ≥ WORM retention, ADR 0032); the platform pseudo-
   organization's events about the deletion; `offboarded_device` rows (no personal data) as in decision 2; backup
   sets taken before the deletion, until their own retention (they are not edited; after a restore to a point before
   the deletion the deletion is repeated, runbook in the plan).
6. **Audit.** Platform pseudo-organization events: `organization.deletion_requested` (step-up),
   `organization.deletion_cancelled`, `organization.deletion_step_completed`, `organization.deletion_step_failed`
   (once per step and error code until the step succeeds), `organization.deleted`, and
   `platform.offboarded_device_uninstalled`. Before the tombstone is written, the audit writer performs one final
   verification of the organization's chain and records `audit.chain_verified` with param `final: true` as the last
   event of the organization's own log; afterwards it no longer verifies or writes into that organization.
7. **Reading retained evidence.** For an organization in status `deleted` only, a platform administrator reads the
   audit log (`GET /api/platform/v1/organizations/{id}/audit-events`, list contract) and requests the existing
   evidence export package (`POST /api/platform/v1/organizations/{id}/audit-exports`), which is handed to auditors
   and verified offline as today. The database entry point is `db.AuditReader.InDeletedOrg(ctx, orgID, fn)`: the only
   place where an organization ID from a URL opens an organization context, accepted only for a platform principal and
   only after the control database confirmed `status = 'deleted'`; every read is recorded like other audit reads.
   This is a deliberate, narrow exception to architecture §5 rule 4 and to "platform administrators have no access
   to organization data".

## Consequences

- + Customers can be offboarded with evidence of what was deleted and what was kept and why; the acceptance gates
  can clean up after themselves (PDK-946); identity rounds stop paying for dead organizations.
- + Devices are left in a usable state: local accounts, the managed local administrator, disk encryption and user
  data stay (contract 8).
- − Directory logins on the organization's devices stop working once its Authentik objects are deleted; only local
  accounts remain (the managed local administrator is kept by `leave`, its escrowed password is deleted with the
  organization). The grace-period banner tells the organization's administrators to reveal what they need. Recorded
  as residual risk RR-137.
- − Recovery keys and LUKS header copies are deleted; after the deletion a forgotten disk passphrase cannot be
  recovered through Paddock. Same banner; RR-137.
- − Backup sets keep the organization's data until their retention ends (RR-138).
- − One new definer function, one new platform table, one narrow exception to the isolation rules (decision 7).
- Follow-up: re-evaluate decision 7 if a platform auditor role is introduced; re-evaluate `OffboardedDeviceRetention`
  once real offboardings show how long devices stay offline.

## Amendment 2026-11-14 b — encrypted recovery export during the grace period (maintainer decision; plan M17 amendment b)

**Context.** Decision 5 deletes the escrowed LUKS recovery keys and the escrowed passwords of the managed local
administrators with the organization; the consequences named the loss and relied on administrators revealing what they
need one device at a time. The maintainer decided that an organization administrator, or the platform administrator,
can take all of them out at once before the deletion, encrypted.

**Options.** (a) Reveal per device only (status quo) — impractical for hundreds of devices. (b) A plaintext download —
puts every secret of the organization on a laptop in the clear; rejected. (c) **An OpenPGP message encrypted to a
public key or a passphrase the requester supplies, built in memory by the escrow-reader and streamed in the response;
nothing stored.** + Decrypts with standard `gpg`; uses `github.com/ProtonMail/go-crypto`, already an approved
dependency (Q4, PDK-812); the escrow-reader stays the only role that decrypts escrow. **Chosen.**

**Decision.**
8. While a deletion is pending (status `active`, `delete_after` set), `POST /api/v1/recovery-export` (organization
   administrator) and `POST /api/platform/v1/organizations/{id}/recovery-export` (platform administrator) return one
   OpenPGP message (ASCII-armoured) containing, per non-retired device that has escrow, the hostname, the device ID, every
   volume's LUKS recovery key and the managed local administrator's username and newest escrowed password. Both need a
   step-up, which counts as one decryption use of that step-up; each attempt records exactly one audit event,
   `organization.recovery_exported`, in the **organization's** log (params: `recipient` = `public_key` or `passphrase`,
   the key fingerprint for `public_key`, `devices`, `secrets`; never a secret, never the passphrase). The api forwards the
   request to the escrow-reader like a reveal; the escrow-reader decrypts in Transit batches and encrypts into the
   message as it streams; no plaintext and no message is written to disk, object storage, Valkey or a log. At most five
   exports per organization per grace period (409 `export_limit`). The platform path opens the organization context
   from the URL only for a platform principal and only while that organization's deletion is pending: a second narrow
   exception to architecture §5 rule 4, next to decision 7.
9. The grace-period banner links to the export.

**Consequences.** RR-137 narrows to: directory logins on offboarded devices stop, and recovery keys and local
administrator passwords are lost **only if no export was taken**. An export is a full set of the organization's
device secrets in the hands of its requester: its protection rests on the supplied key or passphrase (at least 16
characters) and is audited.
