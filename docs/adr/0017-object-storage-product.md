# 0017 — Object storage product for the reference stack
Status: Accepted (product owner, 2026-10-03)

## Context
Paddock needs S3-compatible object storage for three buckets: `bundles` (immutable, presigned GET),
`paddock-escrow` (versioned, deletable for Destroy) and `paddock-audit` (Object Lock, COMPLIANCE mode,
WORM evidence, on a separate host). The concept names "Loki and MinIO" as reference stack and allows equivalents.

MinIO is no longer usable as a bundled component: community binaries and Docker images stopped in October 2025,
the community edition went into maintenance mode in December 2025, the repository was archived in 2026, and the
Docker Hub images no longer resolve. Bundling an unmaintained storage engine in the audit trust chain is not acceptable.

The Paddock code depends only on the S3 API including Object Lock (`PutObjectRetention`, `x-amz-object-lock-*`),
so the product choice is an operations decision, not a code decision.

## Options
- **RustFS** (Apache-2.0). + Lightweight single binary, MinIO-like operations, versioning + Object Lock + replication
  in 1.0 GA (September 2026). − Young; an Object Lock enforcement vulnerability existed before 1.0.
- **Ceph RGW** (LGPL). + Most proven self-hosted Object Lock implementation. − Heavy (MON/OSD/RGW), overkill for
  30–100 devices, significant ops know-how needed.
- **SeaweedFS** (Apache-2.0). + Mature for bulk storage. − Reported issues with COMPLIANCE retention not being
  enforced on delete in 2025/2026.
- **External S3 provider with Object Lock** (AWS S3, other providers). + Proven WORM, no operation. − Not fully
  self-hosted (C8 allows it as an option, not as a mandatory dependency).
- **Build MinIO from archived source.** − Unmaintained security-critical component; rejected.

## Decision
1. RustFS is the bundled default for all three buckets, pinned to a version ≥ 1.0.0.
2. The audit acceptance gate ("an object in WORM storage cannot be deleted or have its retention shortened, even
   with admin/root credentials") runs in M0 against the pinned RustFS **and on every RustFS upgrade**. If it fails,
   Ceph RGW becomes the default for the audit bucket.
3. Operators MAY point the audit bucket at Ceph RGW or an external S3 provider with Object Lock; the operations
   documentation describes both.
4. Paddock code MUST NOT use any vendor-specific API beyond S3 + Object Lock.

## Consequences
+ No dependency on an abandoned project; product swap without code changes.
− The WORM guarantee rests on a young implementation until the gate has passed repeatedly; operators with strict
audit requirements are advised to use Ceph RGW or an external provider for `paddock-audit`.

