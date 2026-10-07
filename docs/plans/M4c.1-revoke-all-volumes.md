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
