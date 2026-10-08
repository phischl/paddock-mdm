# Implementierungsplan: M4c.1 — Revocation erases every LUKS volume of the device

Status: Ready for implementation (after M5c) · 2026-10-07 · Author: architect
Basis: review page finding "only the root volume is erased"; architect recommendation adopted under the product
owner's "continue with the recommendations" (2026-10-07); plan M4c decisions 11–13. Two-person rule applies.

## 1. Goal
Lock, Destroy and the dead man's switch erase the keyslots of **every** LUKS volume listed in `/etc/crypttab`, not only
the root volume.

## 2. Binding decisions
1. `paddock-revoke` determines the targets as: the root volume (as today) plus every `/etc/crypttab` entry whose source
   resolves (UUID=, PARTUUID=, /dev/…) to a LUKS2 or LUKS1 device; duplicates removed; order: non-root volumes first,
   root last. The test-target build keeps its single override target.
2. Sequence unchanged except step (2): erase each target, verify each with `luksDump`; the confirmation reports
   `{volumes: [{device, slots_before, slots_after, erased}]}` and `erased` is true only if every volume has 0 slots.
3. A crypttab entry that cannot be resolved is reported in the confirmation (`unresolved: [...]`) and does not stop the
   erasure of the others.
4. Server: confirmation schema extended (additive), portal timeline shows per-volume results.
5. Review page and hardware protocol updated by the architect after implementation.

## 3. Steps
1. Implementation + unit tests (fake crypttab with root, one extra LUKS volume, one unresolvable entry).
2. Gate R1 keeps its single test target (test-target build). Multi-volume behaviour is covered by unit tests and by an
   acceptance check of the extended confirmation schema.
3. Regression of R1/R4 on both VMs. One commit (two-person-rule path: mark the commit message "needs second review").

## 4. Stop conditions
Any change that would let `paddockd` erase keyslots; M0 §11 S2/S6/S7/S8.

## Amendment 2026-10-08 (architect, PDK-009)

A Lock is restorable by definition (concept: Lock vs. Destroy), so Paddock escrows the header of every LUKS volume it
erases, not only the root volume. Binding:

1. The agent `luks` reconciler escrows the header of each `/etc/crypttab` LUKS1/LUKS2 volume (same target resolution
   as `paddock-revoke`, shared code in `agent/internal/luks/crypttab.go`, no duplicate parser) with kind
   `luks_header` and a new field `volume` = LUKS UUID (root volume: its UUID as well). Existing rows get the root UUID
   with the device's first check-in that reports it; until then they are matched as the root volume's. Object keys
   become `org/<org>/devices/<dev>/luks-header/<volume_uuid>/<generation>.bin`; existing root objects stay readable
   under the old key (the row records it; no object copy). Header generations count across all volumes of a device.
2. No Paddock recovery key is added to non-root volumes; their own keyslots come back with `luksHeaderRestore`. Root
   keeps today's recovery key.
3. Keyslot-change detection and re-escrow per volume (`device.tamper_keyslot_changed` gains param `volume`).
4. `health.disk` reports per volume (`volumes`, `unresolved`); device state `compliant` requires every volume
   escrowed. Unresolved crypttab entries are reported but do not block compliance.
5. Portal *Disk encryption* card lists the volumes; header download per volume (step-up, typed hostname, audit
   `disk.header_downloaded` with param `volume`). Destroy deletes the escrowed headers of **all** volumes.
6. A Lock erases only volumes whose header escrow is confirmed. `paddockd` must not influence the revoke path, so the
   **revocation-issuer** writes the device's confirmed volume UUIDs into the signed Lock and `self_lock` tokens
   (`volumes`; `self_lock` tokens are re-issued when the confirmed set changes), and `paddock-revoke` erases root plus
   exactly those — both are restorable locks. Destroy erases all volumes (as before). Volumes not listed are reported
   as `skipped_not_escrowed` in the confirmation. `paddock-revoke` builds before PDK-009 refuse tokens with `volumes`,
   so the issuer adds them only when the device's check-in health reports `revoke_capabilities: ["volumes"]` (from
   `paddock-revoke capabilities`); other devices get tokens without volumes.
7. Two-person rule applies to the `paddock-revoke` part (item 6, and the shared `agent/internal/luks/crypttab.go`,
   which is added to CODEOWNERS); commit marked `needs second review`.
8. This amendment; `docs/operations/revocation.md` and `disk-recovery.md` are updated. Architecture §12.4 (object key)
   is amended by the architect.

Review round 1 (architect, 2026-10-08):
- At most 32 distinct volumes per device: the worker refuses a header of a 33rd (`device.header_escrow_refused`,
  `too_many_volumes`); tokens carry at most 32, the first by UUID, in the issuer and in the self-lock reconciliation
  alike; never an error that blocks a Lock.
- Duplicate LUKS UUIDs in the crypttab selection (also the root volume's): corrected in review round 2, see below.
- A token lists a volume only when its newest header generation (that did not fail) is stored.
- A failed `paddock-revoke capabilities` call reports nothing; the server keeps the last reported value.
- Migration renumbered to `00033` (M5c has 00029, M6c 00030–00032); at the M6 integration renumbered to `00035`
  (M6c also has 00034; 00033 stays unused).
- Residual risk (forged escrow, false root UUID) named in `docs/operations/revocation.md`.

Review round 2 (architect, 2026-10-08):
- Volumes with a shared LUKS UUID, including a clone of the root volume, stay erase targets; the crypttab selection
  marks them `Shared`. They are neither escrowed nor tamper-tracked, are reported as `shared_uuid` in `health.disk`
  and in the confirmation (not as unresolved; they do not make `erased` false), are erased by a Destroy and skipped
  by a Lock (`skipped_not_escrowed`).
- After a `too_many_volumes` refusal (escrow status `refused`) the agent does not escrow that volume again for 24 h
  or until its crypttab volume set changes.
- After a `paddock-revoke` downgrade, Locks with volumes are refused (fail-safe) until the device reports its
  capabilities again after the upgrade; documented in `docs/operations/revocation.md`.

Review round 3 (architect, 2026-10-08; exception to the two-round limit, findings in the revocation path):
- The crypttab entries are classified first, each within the shared deadline; the root UUID is read separately and
  never blocks or shrinks a Destroy, which erases every classified LUKS entry plus root even when the root-UUID read
  fails or hangs. Shared marking only affects a Lock.
- While the root UUID is unknown, a Lock or self-lock skips every secondary volume (`skipped_not_escrowed`) and erases
  root only.
- In `paddockd` the crypttab classification (with the inventory of the volumes) runs at most once at a time in its
  own goroutine; the reconciler uses the last completed result and skips the multi-volume work while none exists.
  The agent loop never blocks on it.
- A redelivered refused upload with the same `escrow_id` writes no second refusal audit.
- The 32-volume cap check takes a transaction-level advisory lock per device.

Review round 4 (architect, 2026-10-08; `agent/internal/reconcile/luks.go` only):
- Before a header backup is sealed, its LUKS UUID (`cryptsetup luksUUID <file>`) must equal the volume's; on a
  mismatch (renumbered devices) the backup is discarded, nothing is escrowed for that volume, and a new inventory
  follows.
- No header escrow while an inventory is in flight: escrows run only right after a completed inventory, against its
  result.
