# 0005 — State compilation and bundle format (A9)
Status: Proposed

## Context
Principle 2 and A9: per-device bundles precomputed and signed, recomputed on change, cacheable at the edge,
devices fetch only changed bundles; monotonic versions against replay/downgrade.

## Options
- **Event-driven compiler, full per-device bundle, DSSE envelope, object storage + presigned URLs.**
  + Simple agent logic, immutable objects, static read path. − Full bundle per change (small: < 256 KiB).
- **Delta bundles.** + Less transfer. − Complex, error-prone apply logic on the riskiest component.
- **Per-request rendering.** − Violates principle 2.
- **TUF repository per device.** + Strong rollback/freeze protection model. − Heavy for per-device content.

## Decision
The compiler consumes `state.<org>.changed`, expands the scope to affected devices, renders canonical JSON
(RFC 8785), skips content-equal results, increments `device.bundle_seq`, signs via OpenBao Transit (Ed25519,
batch) into a DSSE envelope, stores `org/<org>/devices/<dev>/bundles/<version>.dsse`, updates the KV pointer.
Devices receive the pointer in the check-in response and download through a presigned URL (TTL 120 s).

## Consequences
+ Check-in steady state is one small request; bundle fetch only on change.
− A database restore can lower `bundle_seq`; the restore runbook bumps it before the compiler starts.
