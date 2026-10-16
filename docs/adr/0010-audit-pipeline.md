# 0010 — Audit pipeline and storage
Status: Proposed

## Context
F7 and the audit section: two storage paths (query index + WORM evidence), signed daily hash chain, separation of
duties, partitioning by organization, exactly one event per privileged action including failures. Reference stack
names Loki + MinIO; equivalents are allowed. MinIO is no longer maintained; the object store is chosen in ADR 0017.

## Options
- **Outbox → RabbitMQ → audit-writer → PostgreSQL index (separate DB, separate host) + S3 Object Lock COMPLIANCE.**
  + Typed queries, RLS reuse, fewer components. − Index scaling needs partitioning (monthly).
- **Loki index + MinIO.** + Log tooling. − Weak structured queries for the portal; another component.
- **OpenSearch index.** + Powerful search. − Heavy to operate.

## Decision
First option. Events `paddock.audit.v1` with stable English codes from a closed registry. Privileged use cases write
an `action` row and the outbox record in the same transaction; failures are recorded by a deferred handler; stuck
actions are finalized as `outcome=unknown`. Objects `org/<org>/YYYY/MM/DD/HH-<seq>.jsonl.zst`, dated by **recording** day (amended 2026-10-03: late events are covered by the manifest of the day they are recorded); daily per-organization
manifest chained and signed with `audit-chain`. Audit domain on a separate host with separate credentials and an
offsite replica. Optional SIEM forwarding.

## Consequences
+ The portal gate (exactly one event, also on failure) is structurally supported.
− Production audit bucket must be created correctly once (Object Lock cannot be added later).

## Amendment 2026-10-15 (ADR 0030, plan M8b)

- **The audit writer is an event source for its own verification.** After every chain verification (nightly at
  00:45 UTC for the last seven sealed days of each organization plus one random older day; `paddock-server audit
  verify` at any time) it writes `audit.chain_verified` or `audit.chain_verification_failed` (actor `system`,
  id `audit-writer`) through its own writer into the verified organization's index and WORM, then records the run
  in `audit_verification_run`. The verification event of day *D* lands in the objects of the recording day, as
  every other late event does. These are the only events that do not pass through the control plane's outbox and
  queue; the writer has neither.
- **Reader-visible chain status.** `paddock_audit_reader` has a row-level-security policy on `audit_manifest` and
  `audit_verification_run` (its organization only). The api exposes them to `org_admin` and `org_auditor`
  (`GET /api/v1/audit/integrity`, `/audit/verification-runs`, `/audit/manifests`); the evidence export of M10 reads
  the same tables.
- "Optional SIEM forwarding" is not implemented by M8b; ADR 0031 specifies it (see the next amendment).

## Amendment 2026-10-15 — outbound integrations

The "optional SIEM forwarding" of the decision is specified in ADR 0031 (notifications, the audit cursor feed and
the SIEM forward): the source is the committed index in commit order (`audit_event.commit_seq`, assigned by the
audit writer under a per-organization row lock), never the queue; the forward runs in a new control-plane role
`notifier`, not in the audit domain. Nothing else in this decision changes.
