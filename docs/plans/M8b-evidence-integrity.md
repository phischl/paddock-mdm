# Implementierungsplan: M8b — Honest documentation and evidence integrity

Status: Ready for implementation · 2026-10-15 · Author: architect
Basis: ADR 0030 (evidence integrity; proposed with this plan), ADR 0010 (audit pipeline, amended 2026-10-15),
ADR 0007 (Authentik organization mapping), ADR 0018 (lists and dialogs); roadmap 2026-10-15 ("Findings that come
first", M8b); auditor review AUD-02, AUD-03 (narrow), AUD-04, AUD-16 and §4.3 (G1–G6); sysadmin review §0 and §4.

Binding language: **MUST** / **MUST NOT** / **SHOULD** / **MAY**.

## 1. Goal

After this milestone the compliance pack and the architecture describe only what the code does (every unbuilt
promise is marked as planned with its milestone, or removed), and four pieces of evidence that the documents already
promised exist: a device whose event sequence has a hole, whose event counter was reset or whose clock drifts is
reported as an audit event and on the attention list; the audit writer verifies its own hash chain every night and
the `org_auditor` role sees the result in the portal and the API; and every grant or revocation of a Paddock portal
role (membership of the `paddock.*` role groups, Authentik superusers) is an audit event.

The lab installation itself (M8a) is not part of this plan; the maintainer runs it and feeds findings back as tickets.

## 2. Context (verified against `main` at `c4e528f`, 2026-10-15)

- **Device events.** The agent numbers every event (`State.EventSeq`, `agent/internal/state`) and reports the
  highest number in each check-in (`protocol.CheckinRequest.EventSeqHigh`, `agent/internal/agent/agent.go`
  `checkinRequest`). The gateway copies it into `ingest.Heartbeat.EventSeqHigh` (`server/internal/transport/http/device/handlers.go`
  `checkin`), but the worker never reads it: `app.DeviceReports.RecordStatus` (`server/internal/app/devicereports.go`)
  writes `device_status` without it. Events are deduplicated by `device_event_seen (device_id, event_seq)`
  (`InsertDeviceEventSeen`, `server/internal/adapters/postgres/queries/device_status.sql`); role `paddock_worker` has
  `SELECT, INSERT` on it (`server/migrations/paddock/00003_devices.sql`). The agent admits spool overflows with
  `agent.events_dropped` (`from_seq`, `to_seq`; `agent/internal/spool/spool.go`), recorded as
  `device.agent_events_dropped`. No gap code exists.
- **Clock.** Every signed device request carries a unix-second timestamp (`protocol.Headers.Timestamp`); the gateway
  refuses requests outside ±300 s (`protocol.CheckTimestamp`, `MaxClockSkew`; `server/internal/transport/http/device/auth.go`
  `readSigned`). The offset is not recorded anywhere. The agent's `time` reconciler only keeps an NTP client running
  (`agent/internal/reconcile/time.go`); it reports no drift.
- **Heartbeats** are coalesced: `devicecache.ClaimHeartbeat` lets `RecordStatus` run at most once per device and
  `devicecache.HeartbeatInterval` (60 s). `device_status.last_seq` is the gateway-issued sequence number of the last
  materialized heartbeat (`UpsertDeviceStatus`, `greatest(...)`).
- **Attention list.** `attention_condition` is a `security_invoker` view (`server/migrations/paddock/00042_attention_current_key_once.sql`,
  current definition) with one `UNION ALL` branch per condition kind; `ListAttentionDevices`
  (`queries/attention.sql`) ranks kinds with a `CASE` (critical 2, `revocation_pending` 0, every other kind 1).
  Kinds are the OpenAPI enum `AttentionKind` (`api/openapi/admin.yaml`), the portal's `attentionKinds`
  (`server/web/src/lib/updates.ts`), `attentionStatus` (`server/web/src/lib/status.ts`, exhaustive switch) and the
  message keys `attention.kinds.<kind>` and `attention.action.<kind>` in `server/web/src/locales/{en,de}.json`.
- **Staleness round** (`server/internal/worker/staleness.go`, `server/internal/app/staleness.go`) is the pattern of a
  periodic per-organization evaluation under a platform advisory lock (`PlatformPool.WithLeaderLock`), recording
  transitions exactly once with `ActionRunner.RecordOnce` and a claim that re-reads state in the event's
  transaction. Its interval in the worker is `min(worker.StalenessInterval, stalenessUnit/4)`
  (`server/cmd/paddock-server/worker.go`); with `PADDOCK_STALENESS_UNIT=minute` (development) that is 15 s.
- **Audit chain.** The audit writer seals day *D* at *D*+1 00:15 UTC (`auditwriter.Sealer.RunDaily`,
  `SealDelay`) into `audit_manifest` and the WORM object `org/<org>/manifests/<day>.json`.
  `auditwriter.Verifier.Verify(ctx, org, from, to)` (`server/internal/auditwriter/verify.go`) checks manifests,
  signatures, links and every object's SHA-256 and returns a `Report{Days, Objects, Problems}`. It runs only from the
  CLI `paddock-server audit verify --org --from --to` (`server/cmd/paddock-server/auditwriter.go` `runAudit`) inside
  the audit-writer container. Nothing records that a verification ran. The api reads the audit index as
  `paddock_audit_reader` through `db.AuditReader.InOrg` (`server/internal/platform/db/db.go`); that role has
  `SELECT` on `audit_event` only (`server/migrations/audit/00001_init.sql`): `audit_manifest` and `audit_object`
  have no reader policy.
- **Audit writer as a source.** `auditwriter.Writer.WriteBatch(ctx, []audit.Event)` validates (`auditwriter.Validate`)
  and stores events — index row plus WORM object per organization and transaction. Events must carry
  `audit.Schema`, an `EventID`, a registered `Code`, `OccurredAt`, an `Outcome`, `Source`, `Actor.Type` and a
  `CorrelationID`. The writer runs in the audit domain and has no `ActionRunner`, no `action` table and no outbox.
- **Portal roles** are Authentik group memberships resolved at login (`admin.ResolveRole`,
  `server/internal/transport/http/admin/role.go`): `paddock.<slug>.admins|operators|auditors`
  (`organization.RoleGroup`), `paddock.platform.admins` (`organization.PlatformAdminsGroup`). The worker's identity
  rounds (`server/internal/worker/identity.go`: `RunSync` every `PADDOCK_IDENTITY_SYNC_INTERVAL`, default 5 min,
  under lock `identitySyncLockKey`) call `app.IdentitySync.SyncUsers` and `SyncGroupMirrors`
  (`server/internal/app/identitysync.go`). The Authentik adapter lists users of a group with
  `GET /api/v3/core/users/?groups_by_pk=<pk>&include_groups=false` (`authentik.Client.GroupMembers`,
  `server/internal/adapters/authentik/authentik.go`, returning pks only) and finds groups by name
  (`FindGroup`). Role grants are invisible to the audit trail except as the `role` param of the next `admin.login`.
- **Agent detection today** (for the document correction): every `DriftInterval` (300 s) the agent re-plans the
  current bundle and corrects what changed (`agent/internal/agent/bundles.go` `drift`, event
  `config.drift_corrected`). Dedicated tamper events: `/etc/sudoers` and `/etc/sudoers.d/` (`reconcile/sudo.go`),
  privileged group members (`reconcile/groups.go`), LUKS keyslots (`reconcile/luks.go`), the managed local
  administrator (`localadmin/account.go`), the deny-list lines of `/etc/pam.d/common-auth` and `common-account`
  (`reconcile/login.go` `checkPAM` → `tamper.protected_file_changed`), the files the updates and inventory
  reconcilers wrote (`tamper.protected_file_changed`), `orbit.service` stopped (`reconcile/inventory.go` →
  `tamper.service_stopped`). There is **no** inotify watch, no hash rescan of `/etc/pam.d/`, `/etc/nsswitch.conf`
  or `/etc/security/`, no Himmelblau version or config-hash check, and no log shipper. `/etc/himmelblau/himmelblau.conf`
  is covered by the drift loop (re-rendered, reported as `config.drift_corrected`).
- **Unbuilt but documented** (architecture): `collect_status` command (§11.4; `pkg/command/command.go` has
  `rotate_admin_password`, `delete_self_lock`, `install_now` only), `playbook` reconciler (§11.3; no such file in
  `agent/internal/reconcile/`), Git export (§17.3), SIEM forward and Authentik event webhook and Fleet activities
  (§14.1), per-organization retention (§14.4, §18), evidence export (§9.6, §18), `tamper.login_component_changed`,
  `policy.clock_drift`, `audit.event_gap` (§11.5).

## 3. Binding decisions

### 3.1 Document correction (G1–G6 and the unbuilt items)

1. The documents MUST describe the code at the commit of the change. Every unbuilt promise is either marked
   **planned** with the milestone that delivers it, or removed. Markers are literal: `*(planned: M9)*`,
   `*(planned: M10)*`, `*(planned: M12)*`, `*(not scheduled)*`, `*(dropped)*`, or `*(planned: M8b, PDK-1xx)*` for the
   items of this plan. An item of this plan keeps its `planned` marker until the ticket that implements it removes
   the marker in the same commit (decision 2). The milestone mapping is fixed: notifications, finding handling and
   the audit cursor feed → M9; retention matrix, purge jobs, per-organization WORM retention, privacy pack and the
   signed evidence export → M10; diagnostics bundle (`collect_status`), SIEM push forward, access review report →
   M12; Git export and the `playbook` reconciler → not scheduled; the log shipper → dropped.
2. Every implementing ticket of this plan (PDK-107 to PDK-111) MUST, in its own commit, replace the `planned`
   marker of the sentence it fulfils by the implemented description (same files as in decision 3). A ticket MUST NOT
   touch markers of items it does not deliver.
3. `docs/architecture.md` MUST change exactly in these places (dated amendment blocks where the section already uses
   them, inline wording otherwise; section numbers are not renumbered):
   - §1 table, row *Configuration source of truth*: "optional Git export" → "optional Git export *(not scheduled)*";
     row *Apply engine on device*: "optional Ansible `playbook` resource, off by default" → "`playbook` resource
     *(not scheduled; ADR 0012 keeps the option)*".
   - §3.1 diagram: node `git` label → `Optional Git remote<br/>config export (not scheduled)`; node `siem` label →
     `Optional SIEM<br/>(planned: M12; cursor feed M9)`.
   - §9.2 diagram: the edge `users -->|events webhook| P` → `P -->|polls role-group membership| users`.
   - §9.6 roles table, `org_auditor`: "Read-only, including audit log and evidence export" → "Read-only: audit log,
     attention list, evidence integrity *(planned: M8b, PDK-110)*; evidence export *(planned: M10)*".
   - §11.3 reconcilers table: `systemd_unit` row → "enable/active state of listed units (agent, fleetd, Himmelblau,
     time sync)"; `playbook` row → "`playbook` *(not scheduled)* — the slot in the apply order is reserved; no
     reconciler exists"; the apply-order paragraph: "`playbook` *(not scheduled)*" and
     "`config.playbook_touched_protected` *(not a registry code; defined with the playbook)*".
   - §11.4 commands table: keep `install_now`, `rotate_admin_password`, `lock`, `destroy`; add the row
     `delete_self_lock | 30 d | by command_id` (exists: `pkg/command/command.go`); `escrow_luks_header` → "*(dropped;
     header escrow is part of the `luks` reconciler, §12.4)*"; `collect_status` → "*(planned: M12 diagnostics
     bundle)*".
   - §11.5 table MUST be replaced by the actual checks (one row per check, column *Event* with the agent event type and
     the registry code in parentheses): drift loop every 300 s over every resource of the applied bundle
     (`config.drift_corrected` / `device.config_drift_corrected`); `/etc/sudoers` hash and `/etc/sudoers.d/`
     contents at every apply and drift round (`tamper.sudoers_changed`, `tamper.sudoers_d_file`); members of
     sudo-granting groups (`tamper.sudo_group_member`); LUKS keyslot inventory per volume (`tamper.keyslot_changed`);
     managed local administrator fields (`tamper.local_admin_changed`); deny-list lines of
     `/etc/pam.d/common-auth`, `common-account` and the files the updates and inventory reconcilers own
     (`tamper.protected_file_changed`); `orbit.service` active (`tamper.service_stopped`); `paddockd` running
     (osquery policy `paddock_agent_running` → `device.tamper_agent_not_running` after 15 min without check-in);
     local admin login (`local_admin.login`); clock offset of each check-in *(planned: M8b, PDK-107)*
     (`device.clock_drift`, > 60 s). Rows for "inotify + full rescan", "Himmelblau version and config hash
     (`tamper.login_component_changed`)" and "log shipper" MUST be removed, with one sentence below the table: "Not
     watched today: `/etc/nsswitch.conf`, `/etc/security/`, `/etc/pam.d/` beyond the deny-list lines, Himmelblau's
     package version *(not scheduled)*; `/etc/himmelblau/himmelblau.conf` is re-rendered by the drift loop." The
     paragraph "The worker reports gaps as `audit.event_gap` …" → "The worker reports a hole in a device's sequence
     numbers as `device.event_gap`, a counter that restarted as `device.event_seq_reset`, and a hole that was filled
     later as `device.event_gap_filled` *(planned: M8b, PDK-108)*; a spool overflow the agent admits
     (`device.agent_events_dropped`) is not a gap."
   - §11.6 item 3: remove "log shipper".
   - §14.1 diagram: node `idp` → `Authentik role-group membership<br/>polled by the worker (M8b)`; node `fleet` →
     `Fleet activities<br/>(not scheduled)`; edge `aw -.-> siem[(Optional SIEM forward)]` → `aw -.-> siem[(SIEM forward<br/>planned: M12; cursor feed M9)]`;
     node `ui` → `Portal audit view, evidence integrity (M8b);<br/>notifications (planned: M9)`; new node and edge
     `aw --> ver[Nightly chain verification<br/>audit_verification_run, audit.chain_verified]`.
   - §14.4 first bullet: "Organization-specific longer retention is set per object at write time; deletion after
     retention is performed by a lifecycle rule." → "One platform-wide retention (`PADDOCK_AUDIT_RETENTION_DAYS`,
     at least 400 days) applies to every object; per-organization retention *(planned: M10)*. Paddock never deletes
     audit objects; expiry after the retention is an operator lifecycle rule (`docs/operations/audit-bucket.md`)."
     Add the dated block `> **Amendment 2026-10-15 (M8b):** the audit writer verifies its chain every night (ADR 0030, §6.4 of plan M8b) *(planned: M8b, PDK-109)*.`
   - §17.3 heading → "17.3 Git export *(not scheduled)*" and the first sentence "A worker job serializes…" prefixed
     with "Design only; not implemented:".
   - §18 key screens: "Audit (search, export)" → "Audit (search; evidence integrity *(planned: M8b, PDK-110)*;
     export *(planned: M10)*)"; "Settings (staleness, DMS, login options, retention)" → "Settings (staleness, DMS,
     login options, updates; retention *(planned: M10)*)".
   - §24 milestones table: append the rows `**M7 Operations, distribution, portal** | IP allow list, operator
     bundle, portal redesign, lab profile (plans M7a–M7c, M8a) | Edge, bundle smoke, lab smoke` and
     `**M8b Evidence integrity** | Document correction, event gap and clock-drift detection, nightly chain
     verification with auditor-visible status, audited role-group membership (plan M8b, ADR 0030) | Event gap,
     clock drift, audit integrity, role membership`.
   - §25.2 table, row *Authentik superuser sees all organizations*: mitigation → "Authentik admin accounts limited to
     platform operators; membership of the Paddock role groups and the set of Authentik superusers are snapshotted
     by the worker and every change is audited (`admin.role_granted`, `admin.role_revoked`) *(planned: M8b,
     PDK-111)*; ingestion of Authentik's own event log *(planned: AUD-03, not scheduled)*".
4. `docs/compliance/residual-risks.md` MUST change exactly:
   - RR-01 mitigation: "tamper checks (services every 60 s, protected files by inotify plus a 5-minute rescan,
     keyslots and sudo groups every 5 minutes)" → "every 5 minutes the agent re-plans its bundle and corrects and
     reports drift of every managed resource; dedicated tamper checks for sudoers, privileged groups, keyslots, the
     local administrator, the PAM deny-list lines and `orbit.service` (architecture §11.5)"; append to the same cell
     "a hole in a device's event numbering or a restarted counter is itself an audit event *(planned: M8b,
     PDK-108)*".
   - RR-08 mitigation: "Authentik admin events reach the audit pipeline" → "every grant and revocation of a Paddock
     role group membership and of Authentik superuser status is an audit event *(planned: M8b, PDK-111)*;
     Authentik's own event log is not ingested *(planned: AUD-03, not scheduled)*".
   - New rows at the end of *Control plane and audit domain*: `RR-35 | **Evidence of device event gaps ends at the
     device's counter.** Gap detection compares the numbers the device delivered with the number it claims; a root
     user who wipes the agent state restarts the counter at 1, which Paddock records as a reset (and, because the
     check-in sequence restarts too, as a suspected clone) but cannot attribute to deleted events. |
     device.event_gap, device.event_gap_filled, device.event_seq_reset, attention kind event_gap *(planned: M8b,
     PDK-108)*; device.clone_suspected and quarantine | Treat device.event_seq_reset like a tamper event.` and `RR-36 | **Chain verification covers the
     primary store only.** The nightly verification reads the audit bucket the writer uses; the replica outside the
     failure domain is not compared. | audit.chain_verified / audit.chain_verification_failed, alert
     PaddockAuditChainBroken *(planned: M8b, PDK-109)* | Verify the replica with your object store's replication
     status and record it.` and `RR-37 | **Clock drift is reported between 60 s and 300 s.** A device whose clock is
     off by more than 300 s cannot authenticate (401 clock_skew) and appears as silent, not as drifting. |
     device.clock_drift, attention kind clock_drift *(planned: M8b, PDK-107)*; staleness alerts | React to silent
     devices; keep NTP reachable from the network the devices use.`
5. `docs/compliance/iso27001-mapping.md` MUST change exactly:
   - *Hash chain* paragraph: append "The audit writer verifies the chain every night; the result is visible to the
     auditor role (*Evidence integrity*, `GET /api/v1/audit/integrity`) and recorded as `audit.chain_verified` or
     `audit.chain_verification_failed` *(planned: M8b, PDK-109/PDK-110)*."
   - A.5.33 evidence: append "nightly verification runs and `audit.chain_verified` *(planned: M8b, PDK-109)*";
     operator duties: "add the lifecycle rule for expiry once it is final" stays; append "the replica is not verified
     by Paddock (RR-36)".
   - A.8.15 operator duties: "forward to a SIEM if required" → "a SIEM forward is *(planned: M12)*, a cursor feed
     *(planned: M9)*; until then the audit log and `GET /api/v1/audit-events` are the only readers".
   - A.8.16 Paddock feature: append "event gaps and counter resets (`device.event_gap`, `device.event_seq_reset`)
     and clock drift (`device.clock_drift`) on the attention list *(planned: M8b, PDK-107/PDK-108)*"; operator
     duties: unchanged.
   - A.8.17 Paddock feature: append "the clock offset of every check-in is recorded; more than 60 s is
     `device.clock_drift` and an attention entry *(planned: M8b, PDK-107)*"; evidence: append "`device.clock_drift`".
   - A.8.2 evidence: append "`admin.role_granted`, `admin.role_revoked` *(planned: M8b, PDK-111)*".
   - New row after A.8.2: `**A.5.18 Access rights** | Portal roles are Authentik group memberships; every grant and
     revocation, and every change of Authentik superuser status, is an audit event with the user name
     *(planned: M8b, PDK-111)*. | admin.role_granted, admin.role_revoked | Review the role groups periodically
     (an access review report is *(planned: M12)*); restrict who may edit the paddock.* groups in Authentik.`
6. `docs/compliance/privacy.md` MUST change exactly: in the *Paddock agent* table, the *Check-in* row gains "the
   signed request timestamp, from which the server derives the device's clock offset (stored as one number per
   device; `device.clock_drift` above 60 s) *(planned: M8b, PDK-107)*" and "the highest event sequence number the
   agent assigned (`event_seq_high`)"; the sentence "There is no time synchronization policy: osquery has no table
   for it on Linux." stays and gains "; Paddock measures drift from the check-in instead (*Paddock agent* table)";
   section *Administrators* gains the paragraph "Paddock snapshots the membership of its portal role groups
   (`paddock.<slug>.admins`, `.operators`, `.auditors`, `paddock.platform.admins`) and the set of Authentik
   superusers every 5 minutes: user name and Authentik ID per role, and an audit event for every change
   *(planned: M8b, PDK-111)*."
7. `docs/compliance/README.md` MUST gain, in the operational evidence paragraph, "nightly chain verification
   (`docs/operations/audit-bucket.md` section 3) *(planned: M8b, PDK-109)*". `docs/reqirements/00_concept_v1.md`
   MUST NOT change; the architecture's §2.1 table gains the row `K12 | The concept lists a log shipper among the
   watched units and protected areas (layer 3, protected area 3). | **Dropped (M8b):** Paddock ships no device log
   shipper; continuous shipping of device logs is out of scope (roadmap *Won't*). Protected area 3 is the agent, the
   supervisor, fleetd and the update timer.`
8. `CHANGELOG.md` `[Unreleased]` → `### Changed`: one entry "Documentation: the architecture and the compliance pack
   now mark every unbuilt feature as planned (with its milestone) or dropped: Authentik event ingestion, event-gap
   and clock-drift detection, Himmelblau component check and log shipper, per-organization retention, evidence
   export, `collect_status`, `playbook`, Git export, SIEM forward (plan M8b, ADR 0030)."

### 3.2 Audit codes (registry, `server/internal/domain/audit/codes.go`)

9. The registry MUST gain exactly these codes, all `Emitted: true`; `make gen` regenerates
   `docs/compliance/audit-codes.md` and `server/web/src/lib/auditCodes.gen.ts`; `en.json` and `de.json` gain
   `audit.<code>` messages (ICU, the params as arguments) and `docs/compliance/glossary-de.md` the new terms:

   | Code | Params | Outcomes | Actor / organization |
   | --- | --- | --- | --- |
   | `device.event_gap` | `from_seq`, `to_seq`, `event_seq_high`, `first_seen_at`, `last_contact_at` | success | system; the device's organization; target device |
   | `device.event_gap_filled` | `from_seq`, `to_seq`, `reported_at` | success | system; target device |
   | `device.event_seq_reset` | `previous_high`, `reported_high`, `events_seen` | success | system; target device |
   | `device.clock_drift` | `offset_s`, `threshold_s`, `last_contact_at` | success | system; target device |
   | `device.clock_drift_cleared` | `offset_s`, `threshold_s`, `since` | success | system; target device |
   | `audit.chain_verified` | `run_id`, `trigger`, `from_day`, `to_day`, `days`, `objects` | success | system `audit-writer`; the verified organization; target `audit_chain` (id = organization id, display `<from_day>..<to_day>`) |
   | `audit.chain_verification_failed` | `run_id`, `trigger`, `from_day`, `to_day`, `days`, `objects`, `problem_count`, `problems` | failure (error_code `chain_broken`) | as above |
   | `admin.role_granted` | `role`, `username`, `authentik_pk`, `group`, `baseline` | success, failure | system; the organization of the role group, platform pseudo-organization for `platform_admin` and `authentik_superuser`; target `identity_user` (id = Authentik pk, display username) |
   | `admin.role_revoked` | `role`, `username`, `authentik_pk`, `group` | success, failure | as above |

   Descriptions and notes (verbatim in `codes.go`):
   - `device.event_gap`: "The worker found event sequence numbers from_seq..to_seq of a device missing after two
     further check-ins: the events never arrived and the agent did not report them as dropped (actor: system)."
     Note: "event_seq_high is the highest number the device reported in its last check-in; to_seq may equal it when
     the device claims events it never delivered. A spool overflow the agent admits (device.agent_events_dropped) is
     not a gap. Recorded once per gap; device.event_gap_filled follows if the events arrive later."
   - `device.event_gap_filled`: "Every event of a gap that was reported as device.event_gap arrived later (actor:
     system)."
   - `device.event_seq_reset`: "A device reported a highest event sequence number below the numbers it had already
     delivered: its agent state was reset (re-installed or wiped). The worker forgets the delivered numbers so that
     the new numbering is recorded, and closes open gaps without an event (actor: system)." Note: "events_seen is
     the number of forgotten sequence numbers. A state wipe also restarts the check-in sequence, which quarantines
     the device as a suspected clone (device.clone_suspected)."
   - `device.clock_drift`: "The clock of a device differs from the server's by more than threshold_s seconds,
     measured from the signed timestamp of its check-in (actor: system). Recorded once per episode;
     device.clock_drift_cleared ends it." Note: "offset_s is server time minus device time in seconds (positive: the
     device is behind). A device off by more than 300 s cannot authenticate and is silent instead (RR-37)."
   - `device.clock_drift_cleared`: "The clock of a device is back within 30 s of the server's (actor: system)."
   - `audit.chain_verified`: "The audit writer verified the organization's hash chain for from_day..to_day: every
     manifest exists, is signed by audit-chain, links to the previous day and lists exactly the indexed objects,
     and every object's SHA-256 matches (actor: system audit-writer)." Note: "trigger is nightly (the last 7 sealed
     days), sample (one random older day) or cli (paddock-server audit verify)."
   - `audit.chain_verification_failed`: "The audit writer found problems in the organization's hash chain for
     from_day..to_day (actor: system audit-writer)." Note: "problems lists at most 50 findings of at most 500
     characters each; problem_count is the full number. Raises PaddockAuditChainBroken."
   - `admin.role_granted`: "A user became member of a Paddock role group in Authentik, or an Authentik superuser,
     as seen by the worker's snapshot (actor: system)." Note: "role is org_admin, org_operator, org_auditor,
     platform_admin or authentik_superuser; group is the Authentik group name, empty for authentik_superuser;
     baseline is true for every member found by the first snapshot of an organization (or of the platform). failure
     with error_code upstream_unavailable when Authentik could not be read."
   - `admin.role_revoked`: "A user left a Paddock role group in Authentik, or lost Authentik superuser status, as
     seen by the worker's snapshot (actor: system)."
10. The portal message keys MUST be `audit.device.event_gap`, … (the existing convention `audit.<code>`); the
    German terms: *Ereignislücke* (event gap), *Zählerrücksetzung* (counter reset), *Zeitabweichung* (clock
    drift), *Nachweisintegrität* (evidence integrity), *Prüflauf* (verification run), *Manifest* (manifest).

### 3.3 Clock drift (AUD-16, G3)

11. `ingest.Heartbeat` MUST gain `ClockOffsetS int64 \`json:"clock_offset_s"\``. The gateway's `checkin` MUST set it
    to `hb.ReceivedAt.Unix() - dev.headers.Timestamp` (server minus device; the device's `Headers.Timestamp` is
    the unix second it signed with). No change to the device protocol or the agent.
12. Migration `server/migrations/paddock/00045_evidence_integrity.sql` (one file for decisions 12, 18, 19, 25;
    forward-only) MUST add to `device_status`: `clock_offset_s bigint` (NULL until measured),
    `clock_drift_since timestamptz`, `event_seq_high bigint NOT NULL DEFAULT 0`,
    `event_seq_contiguous bigint NOT NULL DEFAULT 0`. `UpsertDeviceStatus` MUST write `clock_offset_s` and
    `event_seq_high` from the heartbeat (`event_seq_high = greatest(device_status.event_seq_high, EXCLUDED.event_seq_high)`
    is **wrong**: it MUST take `EXCLUDED.event_seq_high` as reported, because a reset lowers it).
13. Thresholds are constants in `server/internal/domain/device/clock.go`: `DriftThreshold = 60 * time.Second`
    (raise when `|offset| > 60`), `DriftClearThreshold = 30 * time.Second` (clear when `|offset| ≤ 30`); between 30
    and 60 s the state does not change (hysteresis).
14. `app.DeviceReports.RecordStatus` MUST, after the upsert and in the same call, evaluate the drift:
    - read `clock_drift_since` (new query `GetDeviceClockState :one` → `clock_offset_s, clock_drift_since`);
    - `since IS NULL` and `|offset| > 60` → `runner.RecordOnce(ctx, spec device.clock_drift, claim)` where the claim
      runs `SetClockDrift :execrows` (`UPDATE device_status SET clock_drift_since = @now WHERE device_id = @device_id AND clock_drift_since IS NULL`)
      and claims when it updated one row;
    - `since IS NOT NULL` and `|offset| ≤ 30` → `device.clock_drift_cleared` with claim `ClearClockDrift :execrows`
      (`… SET clock_drift_since = NULL WHERE device_id = @device_id AND clock_drift_since IS NOT NULL`), param
      `since` = the cleared timestamp;
    - the device MUST be `active` for a raise (a retired or quarantined device records nothing; `GetDevice` in the
      claim); a clear is recorded in every state.
    The evaluation happens only when the heartbeat was materialized (the existing `ClaimHeartbeat` coalescing
    stays), so a device is evaluated at most once per 60 s.
15. The attention list MUST gain the kind `clock_drift` (warn): view branch
    `SELECT 'clock_drift', d.id, d.hostname, s.clock_drift_since, s.clock_offset_s::text || ' s', 'clock_drift:' || d.id::text FROM device d JOIN device_status s ON s.device_id = d.id WHERE d.state = 'active' AND s.clock_drift_since IS NOT NULL`.
    `AttentionKind` (OpenAPI), `attentionKinds`, `attentionStatus` (`warn`), `attention.kinds.clock_drift`
    ("Clock drift" / "Zeitabweichung") and `attention.action.clock_drift` ("Open device" / "Gerät öffnen") in
    both locales, and the description of `GET /api/v1/attention` MUST be extended. The device page shows the
    condition through the existing `device_id` filter; no new component.
16. Devicesim (`test/acceptance/devicesim/devicesim.go`) already has `ClockOffset`; `Checkin` MUST send
    `EventSeqHigh: d.EventSeqHigh` (new field `EventSeqHigh int64`).

### 3.4 Event gap and counter reset (AUD-04, G2)

17. Semantics. For a device the worker keeps `event_seq_contiguous` *c*: every sequence number `1..c` was either
    delivered (`device_event_seen`) or declared dropped by the agent (`device_event_dropped`, decision 18). A
    **hole** is a maximal range `[a, b]` with `a > c` whose numbers are neither delivered nor declared, bounded above
    by `max(highest delivered number, event_seq_high)`. A hole is **reported** (`device.event_gap`) when it still
    exists in a round in which `device_status.last_seq ≥ first_seen_last_seq + 2` (the device checked in at least
    twice since the round that first saw the hole; the two check-ins give out-of-order batches time to arrive). A
    reported hole whose numbers all arrive later is **filled** (`device.event_gap_filled`). A hole that fills before
    it is reported is closed without an event. A **reset** is a heartbeat whose `event_seq_high` is below *c*
    or below the highest delivered number.
18. Migration 00045 MUST add:
    ```sql
    CREATE TABLE device_event_dropped (
      device_id uuid NOT NULL REFERENCES device(id), from_seq bigint NOT NULL, to_seq bigint NOT NULL,
      organization_id uuid NOT NULL, PRIMARY KEY (device_id, from_seq),
      FOREIGN KEY (organization_id, device_id) REFERENCES device (organization_id, id)
    );
    CREATE TABLE device_event_gap (
      id uuid PRIMARY KEY, organization_id uuid NOT NULL, device_id uuid NOT NULL REFERENCES device(id),
      from_seq bigint NOT NULL, to_seq bigint NOT NULL,
      first_seen_at timestamptz NOT NULL, first_seen_last_seq bigint NOT NULL,
      reported_at timestamptz, filled_at timestamptz,
      FOREIGN KEY (organization_id, device_id) REFERENCES device (organization_id, id)
    );
    CREATE UNIQUE INDEX device_event_gap_open_idx ON device_event_gap (device_id, from_seq) WHERE filled_at IS NULL;
    CREATE INDEX device_event_gap_org_reported_idx ON device_event_gap (organization_id, reported_at) WHERE filled_at IS NULL;
    ```
    with `ENABLE` and `FORCE ROW LEVEL SECURITY` and the tenant policy (`current_setting('paddock.org_id')::uuid`,
    no `missing_ok`) for `paddock_worker` on both and for `paddock_api` on `device_event_gap`; grants:
    `SELECT, INSERT` on `device_event_dropped` and `SELECT, INSERT, UPDATE` on `device_event_gap` to
    `paddock_worker`, `SELECT` on `device_event_gap` to `paddock_api`; and `GRANT DELETE ON device_event_seen,
    device_event_dropped TO paddock_worker` (reset handling, decision 22).
19. `eventEntry` (`devicereports.go`) MUST, for `protocol.EventAgentEventsDropped`, insert
    `device_event_dropped (device_id, from_seq, to_seq)` (`InsertDeviceEventDropped :exec … ON CONFLICT DO NOTHING`)
    in the same claim, after `InsertDeviceEventSeen`, when `from_seq` and `to_seq` are present and `1 ≤ from_seq ≤ to_seq`.
20. New use case `app.EventGaps` (`server/internal/app/eventgaps.go`), constructor
    `NewEventGaps(runner *ActionRunner, org *db.OrgPool) *EventGaps`, method
    `Evaluate(ctx context.Context, now time.Time) error` for the organization in `ctx`:
    1. `ListEventGapCandidates :many` → `SELECT s.device_id, s.event_seq_high, s.event_seq_contiguous, s.last_seq, s.last_contact_at FROM device_status s JOIN device d ON d.id = s.device_id WHERE d.state = 'active' AND (s.event_seq_high > s.event_seq_contiguous OR EXISTS (SELECT 1 FROM device_event_gap g WHERE g.device_id = s.device_id AND g.filled_at IS NULL) OR EXISTS (SELECT 1 FROM device_event_seen e WHERE e.device_id = s.device_id AND e.event_seq > s.event_seq_contiguous)) ORDER BY s.device_id`.
    2. Per candidate, in one `InOrg` read: `ListDeviceEventSeenAbove :many` (`SELECT event_seq FROM device_event_seen WHERE device_id = @device_id AND event_seq > @above ORDER BY event_seq LIMIT 10000`),
       `ListDeviceEventDroppedAbove :many` (`… FROM device_event_dropped WHERE device_id = @device_id AND to_seq > @above ORDER BY from_seq`),
       `ListOpenDeviceEventGaps :many` (`SELECT * FROM device_event_gap WHERE device_id = @device_id AND filled_at IS NULL ORDER BY from_seq`).
    3. Pure function `holes(c, high int64, seen []int64, dropped []Range) (newC int64, holes []Range)` in
       `server/internal/domain/device/eventseq.go`: advance *c* while `c+1` is seen or dropped; then every maximal
       unseen, undropped range between `c+1` and `max(high, last seen)`. Unit-tested (table-driven: no hole, hole in
       the middle, trailing hole up to `high`, dropped range bridging, 10 000-row cap).
    4. `SetEventSeqContiguous :exec` (`UPDATE device_status SET event_seq_contiguous = @value WHERE device_id = @device_id AND event_seq_contiguous < @value`).
    5. For every hole not covered by an open row (covered: `from_seq ≥ row.from_seq AND to_seq ≤ row.to_seq`):
       `InsertDeviceEventGap :exec` (`id` uuid v7, `first_seen_at = now`, `first_seen_last_seq = last_seq`, `reported_at NULL`).
    6. For every open row whose range has no remaining hole (all numbers seen or dropped): if `reported_at IS NULL`
       → `FillDeviceEventGap :execrows` (`UPDATE … SET filled_at = @now WHERE id = @id AND filled_at IS NULL`) without
       an event; else `runner.RecordOnce(device.event_gap_filled, claim = FillDeviceEventGap updated one row)`.
    7. For every open row with `reported_at IS NULL`, a remaining hole and `last_seq ≥ first_seen_last_seq + 2` →
       `runner.RecordOnce(device.event_gap, claim = ReportDeviceEventGap :execrows` (`UPDATE … SET reported_at = @now WHERE id = @id AND reported_at IS NULL AND filled_at IS NULL`) updated one row)`
       with params `from_seq`, `to_seq` (of the row), `event_seq_high`, `first_seen_at`, `last_contact_at`.
    A device whose evaluation fails is logged and skipped; the round goes on (as `Staleness.Evaluate`).
21. Worker round `worker.EventGaps` (`server/internal/worker/eventgaps.go`): same shape as `worker.Staleness`,
    advisory lock key `0x7061646420676170` ("padd gap"), interval the same expression as the staleness round
    (`min(worker.StalenessInterval, stalenessUnit/4)`; 15 s in development), started in
    `server/cmd/paddock-server/worker.go` next to `staleness`.
22. Reset handling in `app.DeviceReports.RecordStatus`, before the upsert: read `event_seq_contiguous` and the
    highest delivered number (`MaxDeviceEventSeen :one` → `SELECT coalesce(max(event_seq), 0) FROM device_event_seen WHERE device_id = @device_id`);
    if `hb.EventSeqHigh < event_seq_contiguous OR hb.EventSeqHigh < max_seen` →
    `runner.RecordOnce(device.event_seq_reset, claim)` where the claim, in the event's transaction:
    `DeleteDeviceEventSeen :execrows` (all rows of the device), `DeleteDeviceEventDropped :exec`,
    `CloseOpenDeviceEventGaps :exec` (`UPDATE device_event_gap SET filled_at = @now WHERE device_id = @device_id AND filled_at IS NULL`),
    `UPDATE device_status SET event_seq_contiguous = 0, event_seq_high = @high WHERE device_id = @device_id`, and
    claims when the delete removed at least one row (a second heartbeat of the same reset finds nothing to delete
    and records nothing). Params: `previous_high` (the greater of *c* and `max_seen`), `reported_high`,
    `events_seen` (rows deleted). The documented race: events the device sends between its first check-in after a
    reset and the worker's processing of that heartbeat are deduplicated against the old numbers and lost; the
    reset event stays the evidence (RR-35).
23. The attention list MUST gain the kind `event_gap` (warn): view branch
    `SELECT 'event_gap', d.id, d.hostname, g.reported_at, g.from_seq::text || '-' || g.to_seq::text, 'event_gap:' || g.id::text FROM device_event_gap g JOIN device d ON d.id = g.device_id WHERE d.state = 'active' AND g.reported_at IS NOT NULL AND g.filled_at IS NULL`,
    plus enum, `attentionKinds`, `attentionStatus` (`warn`), locales (`attention.kinds.event_gap`: "Event gap" /
    "Ereignislücke"; action "Open device" / "Gerät öffnen") and the `GET /api/v1/attention` description.

### 3.5 Nightly chain verification (AUD-02)

24. Migration `server/migrations/audit/00004_verification.sql` (forward-only) MUST add:
    ```sql
    CREATE TABLE audit_verification_run (
      id              uuid PRIMARY KEY,
      organization_id uuid NOT NULL,
      trigger         text NOT NULL CHECK (trigger IN ('nightly','sample','cli')),
      from_day        date NOT NULL,
      to_day          date NOT NULL,
      started_at      timestamptz NOT NULL,
      finished_at     timestamptz NOT NULL,
      days            int NOT NULL,
      objects         int NOT NULL,
      ok              boolean NOT NULL,
      problems        jsonb NOT NULL DEFAULT '[]',
      event_id        uuid NOT NULL
    );
    CREATE INDEX audit_verification_run_org_started_idx ON audit_verification_run (organization_id, started_at DESC);
    ALTER TABLE audit_verification_run ENABLE ROW LEVEL SECURITY; ALTER TABLE audit_verification_run FORCE ROW LEVEL SECURITY;
    CREATE POLICY reader ON audit_verification_run TO paddock_audit_reader USING (organization_id = current_setting('paddock.org_id')::uuid);
    CREATE POLICY writer ON audit_verification_run TO paddock_audit_writer USING (true) WITH CHECK (true);
    CREATE POLICY reader ON audit_manifest TO paddock_audit_reader USING (organization_id = current_setting('paddock.org_id')::uuid);
    GRANT SELECT ON audit_verification_run, audit_manifest TO paddock_audit_reader;
    GRANT SELECT, INSERT ON audit_verification_run TO paddock_audit_writer;
    ```
    No `UPDATE` or `DELETE` grant. `db_test.go`'s `TestAuditWriterCannotUpdateOrDelete` MUST cover the new table.
25. `Verifier.Verify` keeps its signature and its plain session (`WithSession`): a verification run is not bounded
    by `WriterTransactionTimeout`; only the recording of its result (decision 26) runs in a writer transaction. The
    nightly cycle and the CLI call the same `Verify`; there is no second verification code path.
26. `auditwriter.Recorder` (new, `server/internal/auditwriter/verification.go`): `NewRecorder(pool *db.AuditWriterPool, writer *Writer, now func() time.Time) *Recorder`
    with `Record(ctx, org uuid.UUID, trigger string, from, to time.Time, started time.Time, report *Report) (uuid.UUID, error)`:
    builds the event (decision 9; `EventID` uuid v7, `OccurredAt = now`, `Actor{Type: audit.ActorSystem, ID: "audit-writer", Display: "audit-writer"}`,
    `Source: audit.SourceSystem`, `CorrelationID = "verify-" + run id`, params with `problems` capped at 50 entries
    of 500 characters), writes it with `Writer.WriteBatch` **first**, then inserts the run row
    (`InsertAuditVerificationRun :exec`) in `InWriter`. A failed row insert is returned as an error and counted
    (`result="record_error"`); the event is the evidence of record.
27. `auditwriter.Nightly` (`server/internal/auditwriter/nightly.go`): `NewNightly(pool, verifier *Verifier, recorder *Recorder, now func() time.Time) *Nightly`;
    constants `VerifyDelay = 45 * time.Minute` (after 00:00 UTC, i.e. 30 minutes after the seal) and
    `VerifyWindowDays = 7`. `RunNightly(ctx)` waits for the next `00:45 UTC` like `Sealer.RunDaily`, then
    `Cycle(ctx) error`: under the advisory lock `pg_try_advisory_lock(hashtext('audit-verify'))`
    (`TryAuditVerifyLock`/`ReleaseAuditVerifyLock`, session like the sealer), for every organization of
    `ListAuditOrganizations`: `to = LastSealableDay(now)`; `first = FirstAuditDay`; skip the organization when
    `first > to`; `from = max(first, to − 6 days)`; run `Verify(from, to)` → `Record(trigger "nightly")`; if
    `first < from`, pick a uniformly random day in `[first, from − 1]` (`math/rand/v2`), `Verify(day, day)` →
    `Record(trigger "sample")`. A verifier error (store unreachable) is logged, counted as `result="error"` and the
    cycle continues with the next organization. After the cycle: gauge `paddock_audit_verify_failed_organizations`
    = number of organizations whose nightly run had problems or errored; gauge
    `paddock_audit_verify_last_run_timestamp_seconds` = `now`. At writer start the last-run gauge MUST be set to
    `max(finished_at)` of nightly runs (`LatestNightlyRunFinished :one`) or, without any, to the start time.
    Metrics (promauto in `auditwriter`): `paddock_audit_verify_runs_total{trigger,result}` with result
    `ok|failed|error|record_error`, the two gauges above.
28. `serveAuditWriter` (`server/cmd/paddock-server/auditwriter.go`) MUST start `nightly.RunNightly` as a fourth
    `runAll` function. `runAudit "verify"` MUST record its run with trigger `cli` through the same `Recorder` and
    print the run id after `OK …` / before the `FAIL` lines (`run <uuid>`); its exit code is unchanged.
29. `deploy/compose/prometheus/alerts.yml`, group `paddock-audit`, MUST gain
    `PaddockAuditChainBroken` (`paddock_audit_verify_failed_organizations > 0`, `for: 0m`, severity critical,
    summary "The audit hash chain failed its nightly verification", description "{{ $value }} organization(s) have
    a broken or unreadable audit chain; see the evidence integrity page and paddock-server audit verify.") and
    `PaddockAuditVerifyStale` (`time() - paddock_audit_verify_last_run_timestamp_seconds > 36 * 3600`, `for: 1h`,
    severity warning, summary "The audit chain was not verified for 36 hours"). `alerts_test.yml` MUST gain one
    test per rule. `docs/operations/monitoring.md` MUST list both alerts and the three metrics;
    `docs/operations/audit-bucket.md` MUST gain section "3. Nightly verification" (what runs when, where the result
    is visible, what to do on `PaddockAuditChainBroken`: run `audit verify` for the day, check the object store and
    the replica, record the outcome in the ISMS).

### 3.6 Auditor-visible status (API and portal)

30. `api/openapi/admin.yaml` MUST gain, tag `audit`, "Roles: org_admin, org_auditor." (`app.RolesAudit`):
    - `GET /api/v1/audit/integrity` → `AuditIntegrity` (200; 401; 403).
    - `GET /api/v1/audit/verification-runs` → `AuditVerificationRunPage`, list contract:
      `x-paddock-list: {sort: [started_at, from_day, ok], default_sort: -started_at, search: [problems], filters: [ok, trigger]}`;
      parameters `Page`, `PageSize`, new `AuditVerificationRunSort` (enum of the six sort values), `Search`,
      `ok` (boolean), `trigger` (repeatable enum `nightly|sample|cli`); tie-breaker `id`.
    - `GET /api/v1/audit/manifests` → `AuditManifestPage`, list contract:
      `x-paddock-list: {sort: [day], default_sort: -day, search: [object_key], filters: [from, to, verified]}`;
      parameters `Page`, `PageSize`, `AuditManifestSort`, `Search`, `from`/`to` (date, inclusive), `verified`
      (boolean: has at least one `ok` run covering the day); tie-breaker `day` (primary key).
    Schemas:
    ```yaml
    AuditVerificationRun:
      required: [id, trigger, from_day, to_day, started_at, finished_at, days, objects, ok, problems, event_id]
      properties:
        id: {type: string, format: uuid}
        trigger: {type: string, enum: [nightly, sample, cli]}
        from_day: {type: string, format: date}
        to_day: {type: string, format: date}
        started_at: {type: string, format: date-time}
        finished_at: {type: string, format: date-time}
        days: {type: integer}
        objects: {type: integer}
        ok: {type: boolean}
        problems: {type: array, items: {type: string}}
        event_id: {type: string, format: uuid}
    AuditManifest:
      required: [day, sha256, prev_sha256, key_version, object_key, last_verified_at, last_verified_ok]
      properties:
        day: {type: string, format: date}
        sha256: {type: string, description: hex}
        prev_sha256: {type: string, nullable: true}
        key_version: {type: integer}
        object_key: {type: string}
        last_verified_at: {type: string, format: date-time, nullable: true}
        last_verified_ok: {type: boolean, nullable: true}
    AuditIntegrity:
      required: [sealed_through, manifests, verification_window_days, last_run, last_success_at, last_failure_at]
      properties:
        sealed_through: {type: string, format: date, nullable: true}
        manifests: {type: integer}
        verification_window_days: {type: integer}
        last_run: {allOf: [{$ref: AuditVerificationRun}], nullable: true}
        last_success_at: {type: string, format: date-time, nullable: true}
        last_failure_at: {type: string, format: date-time, nullable: true}
    ```
    `AuditVerificationRunPage` and `AuditManifestPage` follow `AuditEventPage` (`items, page, page_size, total,
    total_capped, sort`). Cross-organization reads are impossible by RLS (the reader pool scopes every query); a
    manifest of another organization is simply absent (the list contract has no `{id}` route here, so no 404 case).
31. `app.AuditIntegrity` (`server/internal/app/auditintegrity.go`, reader pool only, `RequireOrg(ctx, RolesAudit)`):
    `Summary(ctx) (IntegritySummary, error)`, `ListRuns(ctx, RunQuery) (Listed[auditstore.AuditVerificationRun], error)`,
    `ListManifests(ctx, ManifestQuery) (Listed[auditstore.ListAuditManifestsWithVerificationRow], error)`.
    Queries in `server/internal/adapters/auditpg/queries/audit.sql`: `ListAuditVerificationRuns`,
    `CountAuditVerificationRuns`, `GetLatestAuditVerificationRun`, `GetLatestAuditVerificationRunByOK` (`@ok`),
    `CountAuditManifests`, `LatestAuditManifestDay`, `ListAuditManifestsWithVerification` (LEFT JOIN LATERAL the
    newest run with `from_day ≤ day AND to_day ≥ day`, `last_verified_ok = run.ok`), `CountAuditManifestsFiltered`,
    one ascending and one descending `ORDER BY` branch per sort value (ADR 0018 pattern of `ListAuditEvents`).
    Handlers in `server/internal/transport/http/admin/handlers_auditintegrity.go` with `listing.Spec` definitions.
32. Portal page `/audit/integrity` (`server/web/src/views/AuditIntegrity.vue`, route name `audit-integrity`,
    navigation group `organization` after `/audit`, label `nav.auditIntegrity` ("Evidence integrity" /
    "Nachweisintegrität"), icon `shield-check`, `visible: (a) => a.canReadAudit`): a `KpiStrip` with *Sealed
    through*, *Manifests*, *Last verification* (time + ok/failed chip), *Last failure*; below, two `DataList`s
    (verification runs with columns started_at, trigger, from_day–to_day, days, objects, result chip, problems
    (expandable text); manifests with day, sha256 (mono, truncated with full value as title), key version, last
    verified, result chip). All texts from the catalog; list state in the URL (`DataList` does this). Playwright
    spec `server/web/e2e/auditIntegrity.spec.ts`: an auditor opens the page and sees the strip and both lists; an
    operator has no navigation entry and `GET /api/v1/audit/integrity` returns 403.

### 3.7 Audited role-group membership (AUD-03 narrow, G1)

33. `ports.GroupDirectory` MUST gain `GroupMemberUsers(ctx, groupPK string) ([]IdentityUser, error)` (the users
    listed by `GET /api/v3/core/users/?groups_by_pk=<pk>&include_groups=true`; `include_groups=true` so that
    membership through a nested group counts, as the groups claim of the login does — stop condition if the
    acceptance Authentik does not honour the parameter) and `ports.UserDirectory` MUST gain
    `Superusers(ctx) ([]IdentityUser, error)` (`GET /api/v3/core/users/?is_superuser=true`). Both implemented in
    `server/internal/adapters/authentik/` with `pages`, both covered by the adapter's contract test
    (`adapter_test.go` with the fake, `live_test.go` where the live suite runs).
34. Migration 00045 MUST add:
    ```sql
    CREATE TABLE organization_role_member (
      organization_id uuid NOT NULL REFERENCES organization(id), role text NOT NULL CHECK (role IN ('org_admin','org_operator','org_auditor')),
      authentik_pk text NOT NULL, username text NOT NULL, first_seen_at timestamptz NOT NULL,
      PRIMARY KEY (organization_id, role, authentik_pk)
    );
    CREATE TABLE organization_role_snapshot (organization_id uuid PRIMARY KEY REFERENCES organization(id), taken_at timestamptz NOT NULL);
    CREATE TABLE platform_role_member (
      role text NOT NULL CHECK (role IN ('platform_admin','authentik_superuser')), authentik_pk text NOT NULL,
      username text NOT NULL, first_seen_at timestamptz NOT NULL, PRIMARY KEY (role, authentik_pk)
    );
    CREATE TABLE platform_role_snapshot (singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton), taken_at timestamptz NOT NULL);
    ```
    `organization_role_member` and `organization_role_snapshot`: RLS enabled and forced, tenant policy for
    `paddock_worker`, grants `SELECT, INSERT, DELETE` (member) and `SELECT, INSERT` (snapshot) to `paddock_worker`.
    `platform_role_member`, `platform_role_snapshot`: grants `SELECT, INSERT, DELETE` / `SELECT, INSERT` to
    `paddock_platform` (no `organization_id`, no RLS; platform scope uses the separate pool).
35. `app.RoleMembership` (`server/internal/app/rolemembership.go`), constructor
    `NewRoleMembership(runner *ActionRunner, org *db.OrgPool, platform *db.PlatformPool, users ports.UserDirectory, groups ports.GroupDirectory) *RoleMembership`:
    - `SyncOrganization(ctx) error` (organization in `ctx`, active organizations only): for each role
      (`org_admin` ↔ `organization.GroupAdmins`, `org_operator` ↔ `GroupOperators`, `org_auditor` ↔ `GroupAuditors`):
      `pk := groups.FindGroup(organization.RoleGroup(slug, role))`; a missing group (`""`) is skipped with a warning
      (the reconcile round recreates it); `members := groups.GroupMemberUsers(pk)`; compare with
      `ListOrganizationRoleMembers :many` (by role): for each upstream user not stored →
      `runner.RunTx(ScopeOrg, admin.role_granted, …)` inserting the row (`InsertOrganizationRoleMember :exec`),
      params `role`, `username`, `authentik_pk`, `group`, `baseline` (true while `organization_role_snapshot` has
      no row for the organization), target `{Type: "identity_user", ID: pk, Display: username}`; for each stored
      row not upstream → `admin.role_revoked` deleting the row (`DeleteOrganizationRoleMember :exec`). After all
      three roles succeeded: `InsertOrganizationRoleSnapshot :exec … ON CONFLICT DO NOTHING`. An Authentik read
      error MUST NOT delete rows: the role is skipped and the error returned (`failure` is not recorded per member;
      the round's failure is logged, as the identity rounds do today).
    - `SyncPlatform(ctx) error` (once per round, `systemPlatform` context, `ScopePlatform`): members of
      `organization.PlatformAdminsGroup()` → role `platform_admin`; `users.Superusers()` → role
      `authentik_superuser`; same diff against `platform_role_member` through `PlatformPool`; `baseline` while
      `platform_role_snapshot` is empty. Events land in the platform pseudo-organization.
36. `worker.Identity.syncOrg` MUST call `roles.SyncOrganization` after `SyncGroupMirrors`, and `RunSync`'s round MUST
    call `roles.SyncPlatform` once after the organizations (inside the same leader lock). Constructor
    `worker.NewIdentity` gains the parameter `roles *app.RoleMembership`.

## 4. Non-goals

- No ingestion of Authentik's event log (`/api/v3/events/`), no Authentik write path, no access review report (M12).
- No notification of any new event (M9), no cursor feed, no SIEM forward (M12), no evidence export, no offline
  verifier, no retention or purge (M10). The interface M9 consumes is the audit index: the codes of decision 9 and
  the attention kinds `event_gap` and `clock_drift`.
- No change to the device protocol, the bundle format, the agent, `agent/internal/revoke/`, `agent/cmd/paddock-revoke/`,
  the supervisor, or Fleet's configuration.
- No replica comparison of the WORM store (RR-36), no per-organization verification schedule, no re-verification
  of every historical day (the sample covers it over time).
- No change to the staleness round, `device_alert`, or the existing attention kinds; no change to the sealer.
- No `collect_status`, `playbook`, Git export, log shipper, Himmelblau version check.
- No new Go module, npm package or container image.

## 5. Affected files

| Path | Action | Purpose |
| --- | --- | --- |
| `docs/architecture.md`, `docs/compliance/residual-risks.md`, `iso27001-mapping.md`, `privacy.md`, `README.md`, `CHANGELOG.md` | change | document correction (decisions 1–8); the markers of decisions 2 are flipped by PDK-107–111 |
| `docs/adr/0030-evidence-integrity.md` | new (with this plan) | the decisions that bind later milestones |
| `docs/adr/0010-audit-pipeline.md` | change (with this plan) | amendment: the audit writer as event source, reader-visible verification |
| `server/internal/domain/audit/codes.go`, `docs/compliance/audit-codes.md`, `server/web/src/lib/auditCodes.gen.ts`, `server/web/src/locales/{en,de}.json`, `docs/compliance/glossary-de.md` | change | codes (decisions 9–10) |
| `server/internal/ingest/ingest.go`, `server/internal/transport/http/device/handlers.go` | change | `ClockOffsetS` (decision 11) |
| `server/migrations/paddock/00045_evidence_integrity.sql` | new | decisions 12, 18, 23 (view), 34 |
| `server/internal/adapters/postgres/queries/device_status.sql`, new `eventgaps.sql`, `rolemembership.sql`, `attention.sql` (description comment) | change / new | queries (decisions 12, 14, 19–22, 35) |
| `server/internal/domain/device/clock.go`, `eventseq.go` (+ tests) | new | thresholds, hole computation |
| `server/internal/app/devicereports.go`, new `eventgaps.go`, `auditintegrity.go`, `rolemembership.go` (+ integration tests) | change / new | decisions 14, 19–22, 31, 35 |
| `server/internal/worker/eventgaps.go`, `identity.go`, `server/cmd/paddock-server/worker.go` | new / change | rounds (decisions 21, 36) |
| `server/migrations/audit/00004_verification.sql`, `server/internal/adapters/auditpg/queries/audit.sql` | new / change | decisions 24, 26, 27, 31 |
| `server/internal/auditwriter/verification.go`, `nightly.go` (+ tests), `server/cmd/paddock-server/auditwriter.go`, `main.go` (usage) | new / change | decisions 26–28 |
| `server/internal/platform/db/db_test.go` | change | the new audit table in the writer grant test |
| `deploy/compose/prometheus/alerts.yml`, `alerts_test.yml`, `docs/operations/monitoring.md`, `docs/operations/audit-bucket.md` | change | decision 29 |
| `api/openapi/admin.yaml`, `server/internal/transport/http/admin/handlers_auditintegrity.go`, `handlers_attention.go` (no change expected), `adminapi` (generated), `server/web/src/api/schema.d.ts` (generated) | change / new | decisions 15, 23, 30 |
| `server/web/src/views/AuditIntegrity.vue`, `lib/auditIntegrity.ts`, `lib/navigation.ts`, `router.ts`, `lib/status.ts`, `lib/updates.ts`, `e2e/auditIntegrity.spec.ts` | new / change | decisions 15, 23, 32 |
| `server/internal/ports/identity.go`, `server/internal/adapters/authentik/authentik.go`, `users.go`, `adapter_test.go`, `fake_test.go` | change | decision 33 |
| `test/acceptance/devicesim/devicesim.go`, new `test/acceptance/evidence_clock_test.go`, `evidence_gap_test.go`, `audit_integrity_test.go`, `role_membership_test.go` | change / new | gates (§9) |

Not to be touched: `agent/` (all of it), `pkg/`, `server/internal/app/staleness.go`, `server/internal/worker/staleness.go`,
`server/internal/auditwriter/sealer.go`, `writer.go`, `verify.go` (read only; the verifier's signature stays),
`docs/reqirements/`, every ADR but 0010 and 0030, `deploy/compose/compose*.yaml`, `server/migrations/*/0000[1-9]*`
and every committed migration.

## 6. Interfaces and formats

### 6.1 Go signatures

```go
// server/internal/ingest/ingest.go
type Heartbeat struct { …; EventSeqHigh int64 `json:"event_seq_high"`; ClockOffsetS int64 `json:"clock_offset_s"`; … }

// server/internal/domain/device/clock.go
const DriftThreshold = 60 * time.Second
const DriftClearThreshold = 30 * time.Second
func DriftState(offset time.Duration, drifting bool) (raise, clear bool)

// server/internal/domain/device/eventseq.go
type SeqRange struct{ From, To int64 }
func Holes(contiguous, high int64, seen []int64, dropped []SeqRange) (newContiguous int64, holes []SeqRange)

// server/internal/app/eventgaps.go
type EventGaps struct{ … }
func NewEventGaps(runner *ActionRunner, org *db.OrgPool) *EventGaps
func (g *EventGaps) Evaluate(ctx context.Context, now time.Time) error

// server/internal/worker/eventgaps.go
const eventGapLockKey = 0x7061646420676170
func NewEventGaps(gaps *app.EventGaps, pool *db.OrgPool, platform *db.PlatformPool, interval time.Duration) *EventGaps
func (e *EventGaps) Run(ctx context.Context) error

// server/internal/auditwriter/verification.go
type Recorder struct{ … }
func NewRecorder(pool *db.AuditWriterPool, writer *Writer, now func() time.Time) *Recorder
func (r *Recorder) Record(ctx context.Context, org uuid.UUID, trigger string, from, to, started time.Time, report *Report) (uuid.UUID, error)

// server/internal/auditwriter/nightly.go
const VerifyDelay = 45 * time.Minute
const VerifyWindowDays = 7
type Nightly struct{ … }
func NewNightly(pool *db.AuditWriterPool, verifier *Verifier, recorder *Recorder, now func() time.Time) *Nightly
func (n *Nightly) RunNightly(ctx context.Context)
func (n *Nightly) Cycle(ctx context.Context) error

// server/internal/app/auditintegrity.go
type AuditIntegrity struct{ … }
func NewAuditIntegrity(reader *db.AuditReader) *AuditIntegrity
type IntegritySummary struct { SealedThrough *time.Time; Manifests int; LastRun *auditstore.AuditVerificationRun; LastSuccessAt, LastFailureAt *time.Time }
type RunQuery struct { OK *bool; Triggers []string; Page ListPage }
type ManifestQuery struct { From, To *time.Time; Verified *bool; Page ListPage }
func (a *AuditIntegrity) Summary(ctx context.Context) (IntegritySummary, error)
func (a *AuditIntegrity) ListRuns(ctx context.Context, q RunQuery) (Listed[auditstore.AuditVerificationRun], error)
func (a *AuditIntegrity) ListManifests(ctx context.Context, q ManifestQuery) (Listed[auditstore.ListAuditManifestsWithVerificationRow], error)

// server/internal/ports/identity.go
GroupMemberUsers(ctx context.Context, groupPK string) ([]IdentityUser, error)   // on GroupDirectory
Superusers(ctx context.Context) ([]IdentityUser, error)                          // on UserDirectory

// server/internal/app/rolemembership.go
type RoleMembership struct{ … }
func NewRoleMembership(runner *ActionRunner, org *db.OrgPool, platform *db.PlatformPool, users ports.UserDirectory, groups ports.GroupDirectory) *RoleMembership
func (r *RoleMembership) SyncOrganization(ctx context.Context) error
func (r *RoleMembership) SyncPlatform(ctx context.Context) error

// server/internal/worker/identity.go
func NewIdentity(s *app.IdentitySync, roles *app.RoleMembership, brand BrandFlows, org *db.OrgPool, platform *db.PlatformPool, syncEvery, reconcile time.Duration) *Identity
```

### 6.2 Audit event examples (as stored)

```json
{"schema":"paddock.audit.v1","code":"device.event_gap","outcome":"success","source":"system",
 "actor":{"type":"system","id":"worker","display":"worker"},
 "target":{"type":"device","id":"0b6d…","display":"lt-alice-01"},
 "params":{"from_seq":3,"to_seq":3,"event_seq_high":7,"first_seen_at":"2026-10-15T09:00:12Z","last_contact_at":"2026-10-15T09:10:40Z"}}

{"schema":"paddock.audit.v1","code":"audit.chain_verified","outcome":"success","source":"system",
 "actor":{"type":"system","id":"audit-writer","display":"audit-writer"},
 "target":{"type":"audit_chain","id":"5c1e…","display":"2026-10-07..2026-10-13"},
 "params":{"run_id":"0192…","trigger":"nightly","from_day":"2026-10-07","to_day":"2026-10-13","days":7,"objects":412},
 "correlation_id":"verify-0192…"}

{"schema":"paddock.audit.v1","code":"admin.role_granted","outcome":"success","source":"system",
 "actor":{"type":"system","id":"worker","display":"worker"},
 "target":{"type":"identity_user","id":"42","display":"bob"},
 "params":{"role":"org_admin","username":"bob","authentik_pk":"42","group":"paddock.acme.admins","baseline":false}}
```

### 6.3 Attention kinds after this plan

`stale_warning, stale_critical, presumed_lost, quarantined, disk_not_compliant, agent_outdated, login_apply_failed,
sudo_apply_failed, revocation_pending, revocation_expired, agent_rollback_pending, event_gap, clock_drift` — the
last two rank `warn` (1), `detail` = `"<from>-<to>"` and `"<offset> s"`.

### 6.4 Nightly schedule

| UTC | What | Where |
| --- | --- | --- |
| 00:15 | seal day D−1 (`Sealer.RunDaily`, unchanged) | audit-writer, leader by advisory lock `audit-seal` |
| 00:45 | verify `[max(first, D−7), D−1]` per organization, then one random older day | audit-writer, advisory lock `audit-verify` |
| any time | `paddock-server audit verify --org --from --to` | audit-writer container; recorded as `cli` |

## 7. Steps (tickets, in order)

1. **PDK-105 — Document correction G1–G6 and unbuilt items.** Decisions 1, 3–8. Verify: `grep -n "log shipper\|collect_status\|playbook\|event_gap\|clock_drift\|login_component_changed\|Git export\|SIEM\|evidence export" docs/architecture.md docs/compliance/*.md`
   shows every hit with a marker or an implemented description; `make scan-secrets` green.
2. **PDK-106 — Audit codes and portal messages.** Decisions 9–10. Verify: `make gen` yields no diff after commit;
   `GOTOOLCHAIN=auto go test -count=1 ./server/internal/domain/audit/ ./server/internal/transport/http/admin/`
   (spec test); `make web` (catalog check: every `audit.<code>` in `en` and `de`).
3. **PDK-107 — Clock drift.** Decisions 11–16, the marker flips of decision 2 for drift. Verify: unit tests of
   `device.DriftState`; integration tests of `RecordStatus` (raise, hysteresis, clear, inactive device);
   acceptance gate `TestClockDrift` (§9 C1–C2).
4. **PDK-108 — Event gap and counter reset.** Decisions 17–23, marker flips. Verify: unit tests of `device.Holes`;
   integration tests of `EventGaps.Evaluate` (report after two check-ins, fill, dropped range, cap) and of the
   reset in `RecordStatus`; acceptance gate `TestEventGap` (§9 G1–G4).
5. **PDK-109 — Nightly chain verification.** Decisions 24, 26–29, marker flips. Verify: `go test ./server/internal/auditwriter/ ./server/internal/platform/db/`
   (recorder writes event then row; nightly cycle with a fake clock over three organizations incl. one without a
   sealable day; gauges); `make lint-prometheus`; acceptance gate `TestAuditIntegrity` steps V1–V3 (the CLI run
   recorded; the index holds `audit.chain_verified`).
6. **PDK-110 — Evidence integrity API and portal page.** Decisions 30–32, marker flips. Verify: list contract
   gate `TestListContract` extended with the two lists; `TestAuditIntegrity` steps V4–V6; Playwright spec;
   `make typecheck`, `make web`.
7. **PDK-111 — Audited role-group membership.** Decisions 33–36, marker flips. Verify: adapter contract tests;
   integration tests of `RoleMembership` (baseline, grant, revoke, upstream error keeps rows, platform scope);
   acceptance gate `TestRoleMembership` (§9 R1–R4).

PDK-107 and PDK-108 both touch `RecordStatus`, migration 00045 and the attention view: PDK-107 creates migration
00045 with its columns and view branch; PDK-108 adds its tables and branch to the **same uncommitted-to-main**
file only if PDK-107 has not merged yet; otherwise PDK-108 creates `00046_event_gaps.sql`. PDK-109 and PDK-111 MAY
run in parallel with PDK-107/108 (disjoint files except `codes.go`, which PDK-106 finishes first).

## 8. Tests

- **Unit:** `device.DriftState`, `device.Holes` (table-driven, incl. the 10 000 cap and dropped ranges), the
  params cap of the verification event, `ResolveRole` unchanged, `Nightly.Cycle` scheduling with a fake clock.
- **Integration (pgtest):** `RecordStatus` drift transitions and reset (claims idempotent under a second heartbeat);
  `EventGaps.Evaluate` end to end with `device_event_seen` fixtures; `AuditIntegrity` reads as reader (RLS: a
  second organization's runs invisible); `Recorder.Record` (event in index + WORM fake, row inserted; writer cannot
  update/delete); `RoleMembership` with the Authentik fake (baseline flag, grant, revoke, read error).
- **Contract:** `TestOpenAPISpec`; Authentik adapter fake for `GroupMemberUsers` (`include_groups=true`) and
  `Superusers`.
- **Acceptance gates** (§9), **Playwright** (`auditIntegrity.spec.ts`), **promtool** (`alerts_test.yml`).
- Privacy and isolation: the acceptance isolation gate (`isolation_test.go`) MUST gain the three new audit routes
  (carol of globex sees `total: 0` runs for acme's run ids; `GET /api/v1/audit/integrity` as bob (operator) → 403
  `forbidden`).

## 9. Acceptance criteria (Given / When / Then; role in brackets)

- **C1 (org_admin, org_auditor) — `TestClockDrift`:** Given an active devicesim device, when it checks in with
  `ClockOffset = -120 s` and the worker materializes the heartbeat, then within 90 s `GET /api/v1/attention/devices?device_id=…`
  lists the kind `clock_drift` with detail `"120 s"`, and the audit log holds exactly one `device.clock_drift`
  for the device with `offset_s: 120`, `threshold_s: 60`; a second skewed check-in adds no event.
- **C2 — `TestClockDrift`:** Given C1, when the device checks in with `ClockOffset = 0` (after ≥ 60 s), then within
  90 s the condition is gone and exactly one `device.clock_drift_cleared` exists; a check-in with `-45 s` in between
  changes nothing (hysteresis).
- **G1 (org_admin) — `TestEventGap`:** Given an active device that sent events with `event_seq` 1, 2 and 4
  (`SendEvents`) and checks in with `EventSeqHigh = 4`, when it has checked in twice more (materialized: wait
  ≥ 65 s between check-ins), then within 30 s the attention list shows `event_gap` with detail `"3-3"` and the
  audit log holds exactly one `device.event_gap` with `from_seq: 3, to_seq: 3, event_seq_high: 4`.
- **G2 — `TestEventGap`:** Given G1, when the device sends event 3, then within 30 s the condition is gone and
  exactly one `device.event_gap_filled` with `from_seq: 3, to_seq: 3` exists.
- **G3 — `TestEventGap`:** Given an active device that sent 1..3 and reported `EventSeqHigh = 6`, when it checks in
  twice more, then `device.event_gap` with `from_seq: 4, to_seq: 6` (silence: events claimed, never delivered).
- **G4 — `TestEventGap`:** Given G2, when the device checks in with `EventSeqHigh = 1` (after ≥ 65 s), then exactly
  one `device.event_seq_reset` with `previous_high: 4, reported_high: 1` exists, and when it then sends an event
  with `event_seq` 1 again, then the audit log holds two `device.bundle_applied` events of that device with
  `event_seq: 1` (the forgotten number was accepted again). Given an event with `agent.events_dropped` for 5..6,
  when the round runs, then no gap is reported for 5..6.
- **V1 (operator) — `TestAuditIntegrity`:** Given a fresh organization with activity sealed today (`audit seal
  --day --org`, development), when `paddock-server audit verify --org <id> --from <today> --to <today>` runs, then
  it exits 0, prints `OK …` and `run <uuid>`, and the audit index holds one `audit.chain_verified` of that
  organization with `trigger: "cli"`, `days: 1`.
- **V2 — `TestAuditIntegrity`:** Given V1, when `audit verify` runs for `<today>..<tomorrow>`, then it exits 1, and
  the index holds one `audit.chain_verification_failed` with `problem_count ≥ 1` and a problem containing
  `no manifest`.
- **V3 (operator):** Given the writer's `/metrics`, then `paddock_audit_verify_runs_total{trigger="cli",result="ok"} ≥ 1`
  and `…{result="failed"} ≥ 1` after V1–V2; `paddock_audit_verify_last_run_timestamp_seconds` is exported.
- **V4 (org_auditor) — `TestAuditIntegrity`:** Given V1 and an auditor account of the fresh organization, when it
  calls `GET /api/v1/audit/manifests`, then today's day is listed with `last_verified_ok = true` and
  `last_verified_at` = the cli run's `finished_at`. Given V2, when it calls `GET /api/v1/audit/integrity`, then
  `sealed_through = today`, `manifests = 1`, `last_run.ok = false`, `last_success_at` and `last_failure_at` are
  both set; `GET /api/v1/audit/verification-runs?sort=started_at` lists the two runs in order (ok, then failed);
  and `GET /api/v1/audit/manifests` now shows today with `last_verified_ok = false`, because the newest run
  covering the day (`from_day ≤ day ≤ to_day`, ordered by `started_at DESC`) is the failed one.
- **V5 (org_operator):** Given bob, when he calls any of the three routes, then 403 `forbidden`.
- **V6 (org_auditor, portal) — Playwright:** Given the auditor signs in, when she opens *Evidence integrity*, then
  the KPI strip shows the sealed day and the last verification, both lists render with pagination controls, and
  the page's state survives a reload (URL query).
- **R1 (org_admin) — `TestRoleMembership`:** Given a temporary Authentik user, when he is added to
  `paddock.<slug>.operators`, then within 3 minutes the audit log of the organization holds exactly one
  `admin.role_granted` with `role: org_operator`, `username`, `group: paddock.<slug>.operators`, `baseline: false`.
- **R2:** Given R1, when he is removed, then exactly one `admin.role_revoked` within 3 minutes.
- **R3 (platform):** Given the user is added to `paddock.platform.admins`, then `admin.role_granted` with
  `role: platform_admin` in the platform pseudo-organization (`env.AuditIndex`).
- **R4 (baseline):** Given a freshly created organization whose admin group has one member, then its first
  sync records `admin.role_granted` with `baseline: true` for that member, and no further event on the next round.
- **D1 (auditor) — documents:** Given PDK-105, when the auditor greps the compliance pack and the architecture for
  the terms of step 1, then every occurrence either describes implemented behaviour or carries a milestone marker;
  `docs/reqirements/00_concept_v1.md` is unchanged.

## 10. Freedoms

- Internal names of queries, helper functions and test fixtures; whether the gap round lives in one file or two;
  the exact layout of the portal page (cards vs. strip rows) within the design system; the wording of comments; the
  German wording beyond the glossary terms; the file split of migration 00045/00046 (§7).
- Whether `Recorder` and `Nightly` share a file; whether the CLI prints the run id before or after `OK`.
- The random sample's generator seeding (`math/rand/v2` default is fine).

## 11. Stop conditions

- Authentik's `groups_by_pk` with `include_groups=true` does not return members of nested groups, or `is_superuser`
  is not a supported filter on the pinned Authentik version: stop; report with the response; do not fall back to
  per-user lookups silently.
- `CREATE OR REPLACE VIEW attention_condition` is refused (column shape changed): stop; do not drop the view.
- The writer transaction timeout (5 min) is hit by `Recorder.Record` or the nightly cycle for one organization:
  stop and report sizes; do not raise the timeout.
- Any need to change the agent, `pkg/protocol`, the device API, `verify.go`'s `Verify` signature, or to add a
  dependency.
- A heartbeat race makes `TestEventGap` flaky (reset events dropped): report with timings; do not weaken the gate.
- Any `planned` marker that cannot be flipped because the behaviour differs from decision 3–7: report; do not
  describe behaviour that does not exist.

## 12. Risks and open points

- **Heartbeat coalescing delays detection** by up to 60 s and the gap report by two materialized check-ins (≈ 2–10
  minutes in production). Accepted: evidence, not alerting; M9 notifies on the event.
- **`device_event_seen` grows forever** (no purge): the gap round only scans numbers above the contiguous pointer,
  so cost stays proportional to new events. Retention is M10's.
- **Reset race** (decision 22): documented as RR-35; the reset event is the evidence.
- **Nightly verification cost**: 7 days of objects per organization per night; for 100 devices a few MB. The
  stop condition covers the timeout.
- **A failed seal** (OpenBao sealed at 00:15) shows up as `no manifest` in the 00:45 run → `PaddockAuditChainBroken`.
  This is intended: a missing seal is a broken chain until sealed; the next night's run after `audit seal` recovers
  it. The runbook section says so.
- **Baseline flood**: the first role snapshot of an existing installation records one `admin.role_granted` per
  current member (`baseline: true`). Intended: it is the first evidence of who held which role.
- **Open (default chosen):** the clock-drift thresholds are constants (60/30 s), not organization settings; a
  setting is M11's territory if ever needed. The sample day per night is one; a configurable count was not
  requested.
- **Open (default chosen):** `GroupMemberUsers` uses `include_groups=true` (nested membership counts, matching the
  login claim). If the Authentik version disagrees, the stop condition applies.

## Amendment 2026-10-24 (PDK-108, main as architect lead)

**Race.** The agent reports `event_seq_high` in a check-in and sends the events it numbers afterwards right after that
check-in; the worker handles check-ins one at a time (after the 60 s coalescing claim) and events eight at a time, so
events N+1… can be recorded before the check-in that reported N. Decision 22 as written would then see a reset on a
healthy device: a false `device.event_seq_reset`, the device's deduplication rows deleted and its open gaps closed.

- **Decision 18:** migration `00069_event_gaps.sql` (the numbers 00045/00046 were taken) also adds
  `device_event_seen.received_at timestamptz` (nullable), the gateway's receipt time of the event's batch
  (`ingest.Events.ReceivedAt`; `RecordEvents` takes it, `RecordEvent` uses the worker's clock). Rows from before
  the migration have none and count as received earlier.
- **Decision 22:** a reset is a heartbeat whose `event_seq_high` is below the highest number received before
  `hb.ReceivedAt` (`MaxDeviceEventSeenBefore`). The `< event_seq_contiguous` arm is dropped: every number up to the
  pointer was delivered or lies below a delivered `agent.events_dropped` event, so the bounded maximum covers it, and
  the pointer itself may include events received after the check-in. The claim forgets only the rows received before
  the check-in (`DeleteDeviceEventSeenBefore`): later rows already belong to the new numbering, which narrows the
  documented race of RR-74 to events whose new numbers collided with old ones before the reset was processed.
  `previous_high` is that bounded maximum.
- **Decision 20 (same race, gap side):** the upper bound of holes is `max(event_seq_high, highest number received
  before the device's last materialized check-in)`, not the highest delivered number: an event received after the
  check-in is no evidence of a hole below it yet. A trailing gap that grows with a later claim opens a row for the
  new numbers only (open rows never overlap). A false gap remains possible only if the event queue lags the
  check-in queue by more than one check-in interval; the late events then close it with `device.event_gap_filled`.

## Amendment 2026-10-25 (PDK-109, main as architect lead)

**Reason.** `paddock-server audit verify` runs as a process of its own (`docker compose exec paddock-audit-writer
/paddock-server audit verify`), so a promauto counter it increments never reaches the serving writer's `/metrics`
and gate V3 (`{trigger="cli"}` on the writer) could not pass. The run counts therefore come from the table every
process records into.

- **Decision 27, metrics:** `paddock_audit_verify_runs_total{trigger,result}` is a custom collector of the serving
  audit writer (`Recorder.Collector()`, registered in `serveAuditWriter`), not a promauto counter. `ok` and `failed`
  are read from `audit_verification_run` at every scrape (`CountAuditVerificationRuns`: one aggregate
  `GROUP BY trigger, ok` over the index `audit_verification_run_trigger_ok_idx`, 5 s timeout) and only grow, because
  the table has no `UPDATE` or `DELETE` grant. `error` and `record_error` write no row and stay in-process counters
  merged into the same family; the two label sets are disjoint. A database error at scrape time does not fail the
  scrape: the in-process series are emitted, the error is logged once until a scrape succeeds again.
- **Decision 27, last-run gauge:** `paddock_audit_verify_last_run_timestamp_seconds` stays unlabelled and in-process
  as written (set after every cycle; at start from `LatestNightlyRunFinished`, served by the index
  `audit_verification_run_trigger_finished_idx`, else the start time). It is not derived from the table: a CLI run
  must not mask a nightly cycle that stopped running (`PaddockAuditVerifyStale`), and a cycle without any sealable
  day writes no row but did run.
- **Decision 27, last-run gauge after a failed read (option A, Review 1):** the start-time fallback applies only when
  no nightly run exists. If `LatestNightlyRunFinished` fails at start (for example, a writer restarted during an
  audit database outage), the gauge stays unset. It exports 0, so `PaddockAuditVerifyStale` fires after its 1 h
  `for`. The writer retries the read every minute until it succeeds or a cycle finishes and sets the gauge, and it
  logs the failure once. A start-time seed on error would mask a verification that is already stale for up to 37 h.
  promtool tests cover a restart that re-seeds the old value (fires), a fresh seed (does not fire), and the unset 0
  after a restart during an outage (fires).
- **Decision 28, exit code:** `paddock-server audit verify` exits 1 when the chain verified but the run could not be
  recorded (event or row). The exit code is otherwise unchanged. Decision 28 makes the record mandatory, so a
  verification that leaves no evidence must not report success. The output still states that the chain is intact
  and names the run ID if the event was written.
- **Decision 27, failed organizations:** an organization counts as failed when its nightly window or its sample day
  failed or errored.
- V3 stays as written.
