# Organization offboarding

How a platform administrator deletes an organization, what its users and devices experience, what each failure of the
deletion means and what to do, and how to repeat a deletion after a restore (ADR 0052, plan M17). What is deleted,
what is kept and on which basis: [retention.md](../compliance/retention.md), section "Organization offboarding".
Residual risks: [residual-risks.md](../compliance/residual-risks.md) RR-137, RR-138, RR-140 to RR-144.

Sentences marked **(PDK-1017)** describe the audit retirement, the reading of retained evidence and the host command
`paddock-server audit deletions`, which arrive with PDK-1017; they follow plan M17 amendment o.

## Overview

1. **Request.** A platform administrator requests the deletion: step-up, the typed slug, a reason and a grace period.
2. **Grace period.** The organization keeps working; every device is told to remove Paddock; administrators see a
   banner and can export recovery keys and local administrator passwords.
3. **Deletion.** At the end of the grace period the worker deletes the organization's data step by step. The audit
   evidence stays.
4. **Afterwards.** Devices that were offline remove Paddock at their next contact, for up to 365 days.

## Request

`POST /api/platform/v1/organizations/{id}/delete` (role `platform_admin`, step-up) or the organization's detail page in
the platform portal. Body: `confirm_slug`, `reason` (2 to 500 characters), `grace_days`.

- `grace_days` is 7 to 90 (the portal proposes 30). Only a development stack (`PADDOCK_ENV=development`) accepts 0 to
  90; with 0 there is no recovery export window.
- Only an `active` or `provisioning_failed` organization can be deleted. A second request, or one for an organization
  that is `deleting` or `deleted`, is refused with 409 `invalid_state`.
- The request records `organization.deletion_requested` in the platform audit log (slug, reason, `grace_days`,
  `delete_after`, `uninstalls_issued`, `uninstalls_skipped`). In the same action it issues the signed uninstall
  `leave` to every active device. A device with an open uninstall or an open Lock or Destroy is skipped and counted.
- **A request that failed after the uninstalls went out.** If the failure event carries `uninstalls_issued` and the
  organization shows a deletion pending without counts, the uninstalls are live but the deletion never started. Wait
  10 minutes, cancel the deletion (this withdraws the uninstalls that were not delivered), then request it again. A
  cancel within the 10 minutes is refused.

## Grace period

The organization works as usual: devices, configuration and logins are unchanged, and enrollment and approval are not
refused. Cancel with `POST /api/platform/v1/organizations/{id}/cancel-deletion` (portal: *Cancel deletion*); it records
`organization.deletion_cancelled`, clears the deletion and withdraws every offboarding uninstall that was not yet
delivered. A removal that a device already received runs to completion: **that device removes Paddock even though
the deletion was cancelled**, and is retired (re-enroll it if it should stay).

### Recovery export before the deletion (RR-137)

The deletion removes the escrowed LUKS recovery keys, LUKS header copies and the managed local administrator's password
with the organization, and directory logins on the devices stop. Take the export during the grace period:

1. An organization administrator (banner link) or the platform administrator (organization detail) opens *Export
   recovery keys*, chooses the recipient (an OpenPGP public key is recommended; a passphrase needs at least 20
   characters) and confirms with a step-up. The API calls are `POST /api/v1/recovery-export` and
   `POST /api/platform/v1/organizations/{id}/recovery-export`.
2. The download is one ASCII-armoured OpenPGP message `paddock-recovery-<slug>-<time>.asc` with, per device that has
   escrow, the hostname, device ID, every volume's recovery key and the local administrator's name and newest password.
   Open it with `gpg --decrypt`.
3. Rules: at most five exports per grace period (409 `export_limit`); the export closes 20 minutes before the deletion
   starts, so a short grace period leaves little time; Paddock stores nothing of it; every attempt is one
   `organization.recovery_exported` event in the organization's log (never the secret or the passphrase).
4. The file is the only remaining copy after the deletion: store it encrypted, restrict who can open it, and decide
   when it is destroyed.

Advise administrators to finish any in-place encryption during the grace period: a device with an unfinished one
refuses the removal (RR-142).

## What users experience

- **Before the deletion:** nothing changes for users. Administrators see the banner with the date. Devices show the
  removal as pending ("Removal for the organization's deletion"); an organization administrator cannot cancel it
  per device, only the platform administrator cancels the whole deletion. A Lock or Destroy an administrator requests
  still takes precedence.
- **The device:** at its next check-in it removes Paddock (agent, supervisor, sudoers files, state and keys). Local
  accounts, the managed local administrator, Himmelblau, the disk encryption and all user data stay; the device is
  never locked or wiped, even when the removal fails (a disarm of the dead man's switch is delivered first).
- **Logins:** once the organization's Authentik objects are deleted, directory logins on the device stop. Only local
  accounts sign in. Tell users before the deletion.
- **After the start of the deletion:** the organization's administrators' sessions and API tokens no longer work, and
  a request against the organization is refused (403 `organization_inactive`); the refusal is recorded as
  `organization.inactive_denied` in the platform audit log, not in the organization's log.

## Devices that are offline

A device that has not reported its removal when the deletion runs keeps a minimal record (no personal data) in the
platform table `offboarded_device`. At its next contact it receives only two commands, the disarm and the removal, and
no configuration, agent update or time ticket; its final report `agent.uninstalled` is recorded as
`platform.offboarded_device_uninstalled` and deletes the record. Rules:

- The removal commands stay valid for 365 days. A device that never returns is forgotten after 365 days
  (`retention.purged`, store `offboarded_device`); it keeps an inert agent that no longer reaches the server.
- A pending removal that would expire more than 30 days before the end of the 365-day period (for example one an
  administrator issued, which is valid for 7 days) is replaced at the step `devices` by one with the same mode that
  is valid for the full period; the deletion request's own removal is kept.
- The count `devices_offboarded` of `organization.deleted` is an upper bound (RR-143).
- A device that refused the removal (unfinished in-place encryption, a revocation just handed to `paddock-revoke`)
  keeps an inert agent (RR-142): remove the packages by hand, `sudo apt purge paddock-agent paddock-supervisor`.
- **Devices still pending approval get no removal** (RR-141): they never received a bundle and cannot verify a command.
  Before the deletion, approve and then delete them (they then receive the removal), or have their owners run
  `sudo apt purge paddock-agent paddock-supervisor`; the grace-period banner counts them. After the deletion their
  enrollment status answers `rejected` and the agent stays inert. The number is `devices_pending_dropped` in
  `organization.deleted` (PDK-1061).
- Monitor `platform.offboarded_device_uninstalled` in the platform audit log to see devices return.

## The steps and their failures

After `delete_after` the worker sets the status `deleting` and runs one step per organization per minute, in this order:
`sessions`, `devices`, `outbox`, `authentik`, `fleet`, `objects`, `valkey`, `audit_final`, `database`, `tombstone`.
Every step can be repeated safely and resumes after a restart. The platform portal shows the current step and the last
error code on the organization (`deletion.step`, `deletion.last_error_code` in the API). A failing step is retried every
round without any action; `organization.deletion_step_failed` is recorded once per step and error code until the step
succeeds, so a repeated identical failure does not flood the log. A finished step records
`organization.deletion_step_completed` with its count. The last event is `organization.deleted` with the counts per
store.

| Error code | Step | Meaning | Operator action |
| --- | --- | --- | --- |
| `authentik_unavailable` | `authentik` | Authentik cannot be reached or refused a call | Check `docker compose ps` and the logs of the Authentik server and worker, and the API token of the Paddock integration. Nothing else is needed: the step continues in the next round once Authentik answers. |
| `fleet_unavailable` | `fleet` | Fleet cannot be reached or refused a call | Check Fleet and its API token (`docs/operations/fleet.md`). The step continues by itself. |
| `object_store_unavailable` | `objects` | The object store cannot be reached, or the offboarding credentials are missing (the step fails closed) | Check RustFS. Run `./paddock check`: it fails when the four `rustfs_*_offboard_*` secret files or the two RustFS users are missing; `./paddock upgrade` (or `up`) generates the files and creates the users, then the step continues. Do not widen the worker's own object-store policies. |
| `object_retained` | `objects` | An object version is kept by Object Lock retention or a legal hold (neither bucket has Object Lock by default; an operator added it) | Let the retention expire or remove the legal hold. The deletion continues by itself; nothing is counted as deleted meanwhile. |
| `valkey_unavailable` | `valkey` | Valkey cannot be reached or refused a command | Check Valkey and its ACL file (`deploy/compose/valkey/users.acl.tmpl`: the worker user must be allowed `DEL` on the device and organization keys). The step continues by itself. |
| `outbox_pending` | `outbox` | The organization still has unpublished outbox rows; the step never deletes them, so that no audit event is lost | Check RabbitMQ and the outbox relay (`serve outbox-relay`) and their alerts. The step continues once the relay has published everything. |
| `signing_unavailable` | `devices` | The uninstall and disarm commands could not be signed (OpenBao) | Check that OpenBao is unsealed and reachable (`docs/operations/openbao.md`). The step continues by itself. |
| `audit_writer_pending` | `audit_final` | **(PDK-1017)** The audit writer did not acknowledge its final verification of the organization within 1 hour | Check the audit writer (its logs, `PaddockAuditWriterNotConsuming`, `PaddockAuditWriterLag`), the audit database and RabbitMQ: the exchange `paddock.offboarding` and the queue `worker.offboarding`. The writer republishes an unconfirmed acknowledgement every 5 minutes and at its start, so restarting the audit writer is safe. The step continues when the acknowledgement arrives. |
| `database_error` | `database` | A database batch failed | Read the worker log for the SQL error (PostgreSQL down, a migration missing, disk full) and fix its cause. Batches resume where they stopped. A persistent error with a healthy database is a bug: keep the log and report it, do not delete rows by hand. |
| `finalize_waiting` | `tombstone` | The tombstone waited more than 1 hour for transactions of an organization role that were open when the deletion started | Find the transaction in `pg_stat_activity` as the database superuser (organization roles `paddock_api`, `paddock_gateway`, `paddock_worker`, `paddock_compiler`, `paddock_notifier`, `paddock_escrow_reader`, `paddock_revocation`; `state` idle in transaction or a long query). If it is hung, end it with `SELECT pg_terminate_backend(<pid>)`. The step continues in the next round. |

A row of the organization that appears after the delete loop (a straggler of a transaction that was open at the start)
is deleted by the next round automatically; the step then returns to `database`.

### Final audit verification (PDK-1017)

Before the tombstone the audit writer verifies the organization's chain one last time and records `audit.chain_verified`
(or `audit.chain_verification_failed`) with `final: true` as the last event of the organization's own log, then it
stops verifying or writing into that organization. It also acknowledges to the worker on its own channel; the
step waits for that acknowledgement.

- **The outcome can be `failed`.** The deletion still completes, and `organization.deleted` carries the outcome as
  `audit_final_outcome`. `PaddockAuditChainBroken` fires on the nightly verification's gauge; whether a failed final verification raises an
  alert is defined by PDK-1017, so read the outcome from `audit_final_outcome` in `organization.deleted` and from
  `audit.chain_verification_failed` in the platform audit log. What to do: do not retry the deletion (it is finished); treat it as an audit
  integrity incident: run `paddock-server audit verify --org <id> --from <day> --to <day>` for the organization as
  described in `docs/operations/audit-bucket.md`, find the broken day, keep the report and the WORM objects, compare
  with the audit bucket's replica if you keep one (`docs/operations/audit-bucket.md`), and record the finding in your ISMS (A.5.33, A.8.10 evidence).
- **The sealer stops after the final verification day.** The manifest of that day carries `"retired": true`, and no
  manifest follows. This is expected, not a gap: the nightly verification and `paddockctl audit verify-export` accept no
  manifest after a retired one. Do not read the missing days of a deleted organization as a missing-evidence finding.
- Events of the organization that arrive after the retirement are not lost: they are written to the platform
  pseudo-organization as `audit.event_after_retirement` with their original code.
- An `audit.event_after_retirement` for an organization that is **not** being deleted means that something requested
  its audit retirement without a deletion (RR-144). Investigate a compromised control plane: find the
  `organization.audit_retirement_requested` event in the platform audit log, check which role wrote it and rotate
  that role's credentials. The alerts: Prometheus `PaddockAuditEventAfterRetirement` (`increase(paddock_audit_events_after_retirement_total{role="paddock-audit-writer"}[1h]) > 0`, warning), Wazuh rule 100916 (level 10, group `paddock_integrity`) and the Sigma rule `integrations/sigma/paddock_audit_event_after_retirement.yml` (level high), all PDK-1017.

## Reading the retained evidence (PDK-1017)

For an organization in status `deleted` only, a platform administrator reads its audit log
(`GET /api/platform/v1/organizations/{id}/audit-events`) and requests the usual evidence export package
(`POST /api/platform/v1/organizations/{id}/audit-exports`, step-up); the package is handed to the customer's auditors
and verified offline with `paddockctl audit verify-export`. Every read is recorded as
`platform.deleted_organization_audit_read`. An organization administrator gets 404. The evidence stays until the WORM
retention ends.

## Restore to a point before a deletion (RR-138)

Backup sets keep the organization's data until their retention ends. A restore to a point before a deletion
(`docs/operations/restore.md`) brings the organization back, with its devices, secrets and Authentik objects, although
it was deleted. A restore does not roll back the WORM objects of the platform pseudo-organization, so the deletion
events survive it. After such a restore:

1. List the deletions after the restore point: `paddock-server audit deletions --since <RFC3339 restore point>`
   **(PDK-1017)**. It prints one line per `organization.deleted` event after that time (`occurred_at`,
   `organization_id`, `slug`), read from the WORM objects.
2. For each line, request the deletion again with the **minimum** grace period (7 days in production), with a reason that
   names the restore. The organization's devices have long since left; the repeated deletion removes the resurrected
   data and Authentik objects again. Repeat the recovery export step only if the customer is still active.
3. Record each repeated deletion in your ISMS together with the restore it follows.

## Evidence for auditors and customers

- Deletion evidence: `organization.deletion_requested`, `organization.deletion_step_completed` per step,
  `organization.deleted` (slug, `devices_offboarded`, `rows_deleted`, `objects_deleted`, `authentik_objects_deleted`,
  `fleet_hosts_deleted`) in the platform audit log.
- Kept evidence: the organization's audit log and export (above).
- Residual stores and their bounds: Valkey keys `nonce:` (10 minutes), `diag:` (24 hours) and `cres:` (30 days) expire by
  themselves; the `enr:` key of a rejected enrollment (no device was created) can remain up to 7 days (the enrollment
  lifetime) and holds the organization ID, key ID, public key and reason, no secret; backup sets until their retention
  ends. State these to the customer.
