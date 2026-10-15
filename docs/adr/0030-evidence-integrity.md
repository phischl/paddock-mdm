# 0030 — Evidence integrity: self-verification of the audit chain, device event gaps, audited portal roles
Status: Accepted (2026-10-16, with plan M8b)

## Context
The compliance pack and the architecture promised six controls the code did not have (roadmap 2026-10-15, auditor
review §"Verified gaps", G1–G6): Authentik admin events in the audit pipeline, a log gap as an audit event
(`audit.event_gap`), clock-drift monitoring, a Himmelblau component check plus a watched log shipper,
per-organization retention with deletion, and an evidence export for the auditor role. In an ISO 27001 audit,
"documented but not operating" is a nonconformity. The documents are corrected now; three of the controls are
built in M8b because they make the product's own premise true ("a missing heartbeat or log gap is itself an audit
event"; the chain is verified routinely, not only when an operator remembers; privileged portal roles are granted
outside Paddock and were never in the WORM trail). Retention, export and notifications are planned by other
architects (M9–M12) and consume what this decision produces.

Constraints: the audit writer runs in the audit domain without `ActionRunner`, `action` table or outbox; the api
reads the audit index as `paddock_audit_reader` under row-level security; devices stay pull-only and the agent
is not changed; Authentik is read, never written, for this purpose.

## Options
- **Verification results as log lines and a metric only** — + nothing new in the index. − No evidence that a
  verification ran, invisible to the auditor role, not in the chain.
- **Verification results written by the audit writer into its own index and WORM as system audit events, plus a
  reader-visible run table** — + the chain itself records that it was verified (the event of day D lands in day
  D+1's objects); the auditor sees runs and manifests through the api with the same RLS as events. − The audit
  writer becomes an event source that bypasses the control plane's outbox (it has none); one more table with reader
  and writer policies.
- **Verification run by the worker in the control plane** — − needs the WORM credential on the control plane,
  breaking the separation of the audit domain. Rejected.
- **Event gaps detected in the gateway** — − the gateway has no database and must stay stateless and fast. Rejected.
- **Event gaps detected by a worker round over the delivered sequence numbers** (`device_event_seen`), reported
  after two further check-ins, with the agent-declared drops excluded and a counter reset as its own event —
  + uses the counters that exist, no agent change, deterministic and testable. − Detection lags by one or two
  heartbeat intervals; a device that wipes its state is seen as a reset, not as deleted events.
- **Authentik event ingestion (`/api/v3/events/`)** — + complete. − M-sized, Authentik schema coupling, end-user
  logins with IPs (works council), needs an architect decision on scope. Deferred (AUD-03, not scheduled).
- **Snapshot of the `paddock.*` role groups and Authentik superusers every identity round, diffs audited** —
  + S-sized, covers the A.5.18 evidence that matters (who became admin, when), reuses the Authentik adapter and the
  identity round, no new secret. − Changes between two rounds (5 minutes) collapse into one diff; no actor (who
  granted) — Authentik's own log keeps that.
- **Clock drift from the signed request timestamp** — + already present in every request, no agent change,
  second resolution. − Only measurable within the ±300 s acceptance window; a device beyond it is silent, not
  drifting.

## Decision
1. The audit writer is an audit event source for its own verification: after every verification run it writes
   `audit.chain_verified` or `audit.chain_verification_failed` (actor `system`, id `audit-writer`) through its
   writer into the index and WORM of the verified organization, then records the run in `audit_verification_run`.
   Nightly at 00:45 UTC it verifies the last seven sealed days of every organization plus one random older day.
   `paddock_audit_reader` may read `audit_verification_run` and `audit_manifest` of its organization; the api
   exposes them as `GET /api/v1/audit/integrity`, `/audit/verification-runs`, `/audit/manifests` to `org_admin`
   and `org_auditor`, and the portal shows an *Evidence integrity* page. `PaddockAuditChainBroken` alerts on a
   failed nightly run.
2. Device event gaps are detected on the server from the delivered sequence numbers: the worker keeps a contiguous
   pointer per device, reports a hole that survives two further check-ins as `device.event_gap` (the codes are
   `device.*`, because the device is the target and the actor is the system — not `audit.event_gap`), a hole
   filled later as `device.event_gap_filled`, and a counter that restarted as `device.event_seq_reset`, after which
   the delivered numbers of that device are forgotten so the new numbering is recorded. Agent-declared drops
   (`device.agent_events_dropped`) are not gaps. Both appear on the attention list (`event_gap`).
3. Clock drift is the difference between server time and the signed timestamp of each check-in, stored per device;
   more than 60 s raises `device.clock_drift` and the attention kind `clock_drift`, 30 s or less clears it
   (`device.clock_drift_cleared`). Thresholds are constants.
4. Portal role evidence: every identity sync round snapshots the members of `paddock.<slug>.admins|operators|auditors`
   and `paddock.platform.admins` and the Authentik superusers; every difference is `admin.role_granted` or
   `admin.role_revoked` (organization events for organization roles, platform pseudo-organization for platform
   roles and superusers), with `baseline: true` for the first snapshot. Authentik's event log is not ingested.
5. Documents describe only what the code does. Every unbuilt promise carries a milestone marker (`planned: M9/M10/M12`),
   `not scheduled`, or `dropped` (the device log shipper is dropped; continuous device log shipping is out of
   scope). The ticket that implements an item removes its marker in the same commit.

## Consequences
- Positive: the product premise holds (gaps, resets and drift are evidence); the chain carries proof of its own
  verification; the auditor needs no platform operator to see the verification status; privileged portal roles
  have a WORM trail; the compliance pack is defensible by sampling.
- Negative: one more event source outside the outbox path (the audit writer; bounded to two codes); verification
  reads up to seven days of objects per organization per night; the first role snapshot of an existing installation
  produces one baseline event per member; drift is unmeasurable beyond ±300 s (RR-37); gap evidence ends at the
  device's counter (RR-35); the replica of the WORM store is not compared (RR-36).
- Follow-ups: M9 notifies on `device.event_gap`, `device.event_seq_reset`, `device.clock_drift`,
  `audit.chain_verification_failed` and `admin.role_granted` (interface: the codes and params of plan M8b §3.2 and
  the attention kinds `event_gap`, `clock_drift`); M10's export reads `audit_verification_run` and `audit_manifest`
  through the same reader policies; M12's access review report reads `organization_role_member` and
  `platform_role_member`. Re-evaluate the snapshot approach when AUD-03 (Authentik event ingestion) is planned.
- Amends ADR 0010 (dated section 2026-10-15). Plan: `docs/plans/M8b-evidence-integrity.md`.
