# 0031 — Outbound integrations: notifications, audit cursor feed and SIEM forward
Status: Accepted (architect, 2026-10-15)

## Context

Paddock detects (tamper events, clone suspicion, staleness, failed rollouts, platform alerts) and records
(audit index, WORM chain), but nothing reaches a person outside the portal: there is no e-mail, no webhook, no
SIEM forward, and the attention list has no place to record who assessed what. ISO/IEC 27001:2022 A.8.16 and
A.5.25–A.5.26 require that security events reach a responsible person in a defined time and that the assessment
and reaction are recorded. ADR 0010 and architecture §14.1 name an "optional SIEM forward" that was never built.
The roadmap (2026-10-15, three independent reviews) agreed on one design for every outbound path and asked for
one decision covering notifications (M9), the pull-based cursor feed (M9) and the push forward to SIEMs (M12), so
that M12 only implements what M9 has already built.

Facts about the code that bound the design (checked 2026-10-15):

- The audit index (`server/migrations/audit/00001_init.sql`) is `audit_event`, partitioned by `occurred_at`,
  with `recorded_at` set from `transaction_timestamp()` by the audit writer (`server/internal/auditwriter/writer.go`,
  one transaction per organization and batch). Rows are inserted `ON CONFLICT DO NOTHING`; late events (an
  offline device's spool) get an old `occurred_at` and a new `recorded_at`. There is no commit-ordered sequence.
- The control plane holds only a read-only credential on the index (`paddock_audit_reader`, RLS by
  `paddock.org_id`, `db.AuditReader.InOrg`); the audit domain holds no control-plane credential (architecture
  §4.1). Platform events live in the pseudo-organization `audit.PlatformOrganizationID` (the nil UUID).
- Every privileged action goes through `app.ActionRunner` (one event per attempt). System rounds in the worker use
  a system principal per organization (`worker.systemContext`) and `ActionRunner.RecordOnce` with a claim key.
- Secrets reach roles only as files (`*_FILE`); per-organization secrets that administrators enter in the portal
  have no store yet. OpenBao Transit holds `escrow-wrap` (RSA, decrypt only in `escrow-reader`) and the roles
  hold one AppRole each (`deploy/compose/scripts/openbao-configure.sh`).
- The admin API list contract (ADR 0018) caps `page × page_size` at 10 000 and the audit list at 92 days; neither
  fits a consumer that must read every event exactly once.
- The agent reports `tamper.service_stopped` for `orbit.service` from the inventory reconciler and restarts it
  (`agent/internal/reconcile/inventory.go`); the protocol's event types are a closed enum.
- `docs/compliance/privacy.md` binds a negative list (no commands, process lists, connections, …) and lists what
  leaves a device. Today nothing leaves the server to third parties.

## Options

### Source of outbound events
- **The message queue (`paddock.audit` exchange, a second consumer).** + Lowest latency. − A SIEM could see an
  event that never reached WORM; replay after an outage needs a second mechanism; a stalled consumer backs up the
  broker; late events from spools sort by `occurred_at`, which no cursor can follow.
- **The committed audit index in commit order (chosen).** + The SIEM never sees an event that the evidence store
  does not have; replay is a cursor reset; late events are delivered when they are recorded, in order. − Latency
  of the writer's batch plus the poll interval (30–60 s on top of the device's minutes); the forward goes quiet
  when the audit domain stalls, which is exactly when the heartbeat and the stall event must make that visible.

### Ordering key
- `occurred_at` or `event_id` (UUIDv7, time-ordered at creation). − A late event sorts before a cursor that has
  already passed it and is never fetched (the same lesson as ADR 0010's recording-day amendment).
- **A per-organization sequence assigned by the audit writer under a per-organization row lock, in the writing
  transaction (chosen).** + Strictly commit-ordered and contiguous per organization; a cursor is one integer;
  gaps are impossible by construction, so a consumer can detect loss. − One more lock per writer transaction
  (writers already run one transaction per organization and batch), one backfill migration.

### Where the outbound process runs
- **Inside `worker`.** + Nothing new to deploy. − The role that opens connections to administrator-chosen URLs
  would also hold the Fleet token, the Authentik token, the command-signing AppRole and the worker database role.
- **In the audit domain (`audit-writer` host).** + The control plane never holds destination credentials.
  − The audit host would need a control-plane database credential (destinations, device names, outbox) and
  OpenBao: it would stop being a separate administrative domain (architecture §4.1).
- **A new control-plane role `notifier` with its own database role, AppRole and credentials (chosen).**
  + Least privilege for the only process that makes outbound requests; the same shape as `escrow-reader`. − One
  more service, database role, AppRole and set of secrets, in the bundle and `prod-check`.

### Destination secrets
- Plain in PostgreSQL. − Any database read exposes webhook secrets.
- OpenBao KV per organization. − The api would need write access to KV and the notifier read access; KV paths
  per organization are a second tenant model.
- **OpenBao Transit key `notification-wrap` (AES-256-GCM): the api may only encrypt, the notifier may only
  decrypt; ciphertext in PostgreSQL (chosen).** + The api never holds a decryption capability; the shape of
  `escrow-wrap`. − Transit round trip per delivery (cached per destination for the poll interval).

### Transport for notifications
- Chat-specific adapters (Slack, Teams, Matrix). − Each is a format to maintain; all accept a generic webhook
  through their own relays.
- **A generic HTTPS JSON webhook signed with HMAC-SHA256, and e-mail over SMTP through the operator's relay with
  the standard library (chosen).** + Everything the target organizations have; the webhook transport is 60 % of
  the SIEM forwarder. − Chat formatting is the receiver's job.

### SMTP library
- A third-party package (`go-mail`, `gomail`). − New dependency, licence review, supply-chain surface, for
  features (HTML, attachments, embedded images) notifications do not need.
- **`net/smtp` plus `crypto/tls` (chosen).** + Standard library, STARTTLS and implicit TLS, PLAIN/CRAM-MD5
  auth. − Plain-text messages only, which is the privacy-minimal choice anyway.

### Scope of forwarded events
- Everything. − Volume without detection value and, for a works council, a purpose-limitation problem.
- **An allow list by code (a versioned "security" preset in code) by default; "all" and "custom" as explicit
  opt-ins (chosen).** + The preset follows the registry across releases; a changed filter is an audited setting.

## Decision

1. **Boundary.** Outbound integrations are one subsystem, `outbound`: a domain package
   `server/internal/domain/outbound` (filter presets, URL policy, signing, pseudonymization, message formats), use
   cases in `server/internal/app`, a delivery engine in `server/internal/notifier` and a new role
   `paddock-server serve notifier` on the control plane. M9 ships the webhook and e-mail transports and the
   pull-based cursor feed; M12 adds the syslog/TLS transport and the checkpoint message to the same engine.
2. **Source and order.** Every outbound path reads the committed audit index in commit order. The audit writer
   assigns `audit_event.commit_seq` (bigint, contiguous per organization, starting at 1) inside its writing
   transaction while holding the row lock of `audit_org_seq (organization_id, last_seq)`; the lock is taken before
   the duplicate check, so concurrent writers of one organization serialize and the sequence has no gaps and no
   reordering. Existing rows are backfilled in `(recorded_at, event_id)` order. `occurred_at` stays the key of
   the portal's queries and of the index partitions.
3. **Cursor feed (pull).** `GET /api/v1/audit-events/feed?after=<commit_seq>&limit=<1..1000>` returns
   `{schema, events: [{commit_seq, event}], next_after, latest}` in ascending `commit_seq`, for `org_admin` and
   `org_auditor` sessions and API tokens. It is not a collection list: ADR 0018's list contract does not apply
   (an exact-once consumer cannot work with offset pages, a 10 000-row depth cap or a 92-day window). The
   deviation is explicit: the operation carries the extension `x-paddock-feed` instead of `x-paddock-list`, its
   response has `events` instead of `items`, and the contract test checks feeds against their own rule. Retention
   of the index bounds how far back a consumer can catch up (M10).
4. **Per-destination sequence.** Every push destination (webhook now, syslog in M12) numbers what it sends with a
   contiguous `forward_seq` starting at 1; the mapping `forward_seq → event_id, commit_seq` is stored
   (`notification_delivery_event`), so a replay sends the same numbers and a receiver's gap rule stays valid. The
   index position of the last scanned event is the destination's cursor; filtering never leaves gaps in
   `forward_seq`, only in `commit_seq`.
5. **Completeness.** Delivery is at-least-once with the delivery ID as the receiver's idempotency key and
   `event_id` as the per-event key. A failed delivery is retried with exponential backoff (5 s doubling, capped at
   10 min) without advancing the cursor; after `PADDOCK_NOTIFY_STALL_AFTER` (default 15 min) without success the
   destination is `stalled` and one audit event `notification.destination_stalled` is recorded; the first success
   afterwards records `notification.destination_resumed`. Nothing is dead-lettered or dropped: the operator fixes
   the destination and the engine catches up. Webhook destinations can send a heartbeat
   (`kind: heartbeat`, carrying the last `forward_seq` and the cursor) every `heartbeat_interval_s` while no
   batch was sent; e-mail destinations never heartbeat.
6. **Daily checkpoint (M12).** After the audit writer seals day *D* for an organization, push destinations
   receive one message `kind: checkpoint` with the organization, the recording day, the event count, the
   manifest's SHA-256, the `audit-chain` signature and its key version. A receiver or an auditor can reconcile
   its copy against the WORM chain. M9 defines the message and the reader grant it needs (`SELECT` on
   `audit_manifest` for `paddock_audit_reader` with an RLS policy, shared with M10's evidence export); M12
   implements the sending.
7. **Filter.** A destination has `filter_mode ∈ {security, all, custom}` and, for `custom`, a list of registered
   codes. `security` is the preset `outbound.SecurityCodes()` in code, versioned with the registry: every
   `device.tamper_*` code, `device.clone_suspected`, `device.bundle_rejected`, `device.agent_events_dropped`,
   `device.agent_rollback_failed`, `device.stale_critical`, `device.presumed_self_locked`,
   `device.revocation_trust_pinned_tofu`, `device.revocation_confirmed`, `device.revocation_refused`,
   `local_admin.revealed`, `local_admin.login`, `disk.recovery_key_revealed`, `disk.header_downloaded`,
   `permission_profile.*`, `profile_assignment.*`, `user_group.member_added`, `user_group.member_removed`,
   `user.locked`, `user.unlocked`, `admin.login`, `api_token.*`, `revocation.*`, `agent_rollout.halted`,
   `agent_release.published`, `platform.osv_stale`, `platform.ip_allowlist_changed`,
   `platform.ip_allowlist_disabled`, `platform.ip_allowlist_denied`, `organization.*`, `config.applied`,
   `settings.*`, `notification.destination_*`, `notification.pseudonym_resolved`, `finding.*`,
   `vulnerability.critical_summary`, the M8b codes (ADR 0030) `device.event_gap`, `device.event_seq_reset`,
   `device.clock_drift`, `audit.chain_verification_failed`, `admin.role_granted` and `admin.role_revoked`, and the
   M11 code (ADR 0033) `config_rollout.halted`. `device.event_gap_filled` and `device.clock_drift_cleared` are not
   in the preset (they end a condition). An `admin.role_granted` with `params.baseline = true` (the first run's
   inventory of existing members) is never matched in any mode. In every mode an event with outcome `unknown` is
   included. A unit test asserts that every preset code is registered.
8. **Privacy.** A destination's `pseudonymize_users` replaces user names with `u_` + the first 24 hex characters of
   HMAC-SHA256 over the lower-cased name with a per-organization key (`notification_pseudonym_key`, Transit-wrapped,
   created on first use) in `actor.display` (actor types `admin`, `platform_admin`), `target.display` (target types
   `user`, `admin_account`) and the params `username`, `user`, `display_name`, `requested_by`, `approved_by`,
   `created_by`, `members`, `users`; `actor.ip` and `actor.id` of admin actors are dropped. Re-identification is
   `POST /api/v1/notification-destinations/{id}/resolve-pseudonym` by an `org_admin` with step-up, audited as
   `notification.pseudonym_resolved`. E-mail bodies carry code, outcome, time, device and a portal link; `params`
   only when `include_params` is set. Nothing leaves that Paddock does not collect; `device_user_seen` is not an
   audit event and is never forwarded. A webhook URL is a secret (Slack, Teams and SIEM ingest URLs carry the
    credential in the path or query): it is validated in plaintext, then stored Transit-encrypted like the HMAC
    secret (`url_ciphertext`); lists, responses and audit params show only `url_display` = scheme, host and a
    masked path (`https://hooks.slack.com/…`), computed and stored at write time.
9. **Configuration is privileged.** Creating, changing, deleting, testing, enabling and rotating a destination,
   and changing the watched units, go through `ActionRunner` with `RequiresStepUp` for `org_admin` (organization
   destinations) or `platform_admin` (platform destinations, `/api/platform/v1/notification-destinations`, which
   receive the events of the platform pseudo-organization: rollouts, releases, OSV, IP allow list, chain
   verification). Every attempt is one audit event.
10. **Isolation.** Organization destinations and their state are organization-scoped tables with `ENABLE` and
    `FORCE ROW LEVEL SECURITY` and the `paddock.org_id` policy; platform destinations use the same tables with
    `organization_id = audit.PlatformOrganizationID` under a second policy for the role `paddock_platform` only.
    The notifier reads the index through `db.AuditReader` with a system principal per organization and, for the
    platform pseudo-organization, through the named method `AuditReader.InPlatformScope`. A destination never
    receives another organization's events (gate N7).
11. **Role and credentials.** `serve notifier` holds: database role `paddock_notifier` (SELECT on
    `notification_destination`, `notification_pseudonym_key`, `device`, `organization`; SELECT/INSERT/UPDATE on
    `notification_destination_state`, `notification_delivery`, `notification_delivery_event`; INSERT on `action`
    and `outbox`), the platform URL for platform destinations, the audit reader URL, AppRole `paddock-notifier`
    with `transit/decrypt/notification-wrap` only, and `PADDOCK_SMTP_PASSWORD_FILE`. The api's AppRole gains
    `transit/encrypt/notification-wrap`. No other role may decrypt destination secrets.
12. **SSRF and transport policy for webhooks.** `https` only; no userinfo; port 443 or 1024–65535; the host is a
    name or a public IP; every address the name resolves to is checked against the deny list (0.0.0.0/8, 10/8,
    100.64/10, 127/8, 169.254/16, 172.16/12, 192.0.0/24, 192.168/16, 198.18/15, 224/4, 240/4, ::/128, ::1/128,
    fc00::/7, fe80::/10, ::ffff:0:0/96) at validation and again at every dial, and the dial uses the checked
    address with the hostname as SNI (no re-resolution, no rebinding window); redirects are failures; 10 s
    connect, 30 s total; response bodies are discarded. The development stack alone may set
    `PADDOCK_OUTBOUND_DEV_ALLOW_PRIVATE=true` (plain `http` and private addresses, for the acceptance sinks);
    `prod-check` fails on it. The SMTP relay is platform configuration (`PADDOCK_SMTP_*`), not administrator input.
13. **Signature.** Headers `X-Paddock-Timestamp` (Unix seconds), `X-Paddock-Signature: v1=<hex HMAC-SHA256 over
    timestamp "." body>`, `X-Paddock-Delivery`, `X-Paddock-Destination`; the secret is generated by the server (32
    random bytes, base64url), shown once, rotatable. Receivers reject timestamps older than 5 minutes.
14. **One-way.** Paddock exposes no endpoint that accepts a SIEM verdict and never acts on a response body. Lock,
    Destroy, quarantine and user locks stay human, step-up actions (design contract 8).
15. **Reaction is recorded.** Tamper events and attention conditions become findings (`finding` table) with
    `open → acknowledged → in_progress → resolved | accepted_risk | false_positive`, assignee, reason and external
    reference; every human transition is an `ActionRunner` action (`finding.acknowledged`, `finding.assigned`,
    `finding.closed`, `finding.reopened`). Automatic opening (a tamper event, an attention condition) and automatic
    clearing (the condition disappeared) are not separately audited: the condition's own event is the record.
    `accepted_risk` needs `org_admin`.
16. **Presence policy.** An organization lists third-party units (`watched_unit`), compiled into the bundle section
    `watch` (schema v2; unknown sections are ignored by older agents). The agent reports a stopped or missing unit
    as `tamper.service_stopped` with `state ∈ {inactive, failed, missing}` once per stop and never starts,
    stops, installs or configures it. Paddock never reads, stores or forwards that agent's output; the negative
    list of `privacy.md` binds Paddock's own components, not software the operator installs.

## Consequences

- + One mechanism (index cursor, filter, delivery engine, audit events) serves e-mail, webhooks, the pull feed
  and, in M12, syslog; the auditor gets evidence that detection reached a person and that the reaction was
  recorded; a SIEM can prove completeness with `forward_seq`, heartbeats and checkpoints.
- + No new Go module, npm package or container image.
- − One more role to deploy (`paddock-notifier`), one more database role, one Transit key, one AppRole, SMTP
  settings, and a backfill migration of the audit index (`commit_seq`), whose duration grows with the index
  (upgrade notes).
- − Writer transactions of one organization serialize on `audit_org_seq`; with the current one-transaction-per-
  organization batches this changes nothing measurable (`paddock_audit_writer_transaction_seconds` watches it).
- − Notification latency is the device's path plus the writer's batch plus the poll interval; the heartbeat and
  the stall event make silence visible instead of fast.
- Follow-ups: M10 adds `finding`, `notification_delivery*` and the pseudonym key to the retention matrix and
  grants the reader `audit_manifest`; M12 implements syslog/TLS, checkpoints, Wazuh decoders and Sigma rules on
  this engine; M8b's `device.event_gap` and `device.clock_drift` are finding sources through their attention
  kinds `event_gap` and `clock_drift` (the attention view is the source of attention findings), so M9 needs no
  tamper-finding entry for them.

## Amendment 2026-10-31 — IPv6 prefixes that embed IPv4 (decision 12)

Authorised by the architect on 2026-10-31 (external review of PDK-122). The deny list of decision 12 gains three
IPv6 prefixes: `64:ff9b::/96` (NAT64 well-known prefix, RFC 6052), `2002::/16` (6to4, RFC 3056) and `2001::/32`
(Teredo, RFC 4380). Each embeds an IPv4 address that a translator or relay on the control plane's network reaches,
so a webhook name resolving to, for example, `64:ff9b::a00:1` or `2002:a00:1::1` would reach `10.0.0.1` past the
IPv4 entries of the list. They are checked like every other entry: at validation and again at every dial.
The list also denies `64:ff9b:1::/48` (local-use NAT64, RFC 8215), `100::/64` (discard, RFC 6666) and the
documentation ranges `2001:db8::/32`, `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` (RFC 3849, RFC 5737), which no
real receiver uses (`198.18.0.0/15` was already listed). `outbound.DeniedPrefixes` implements the list.
