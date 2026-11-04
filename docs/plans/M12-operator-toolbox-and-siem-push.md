# Implementierungsplan: M12 — Operator toolbox and SIEM push (diagnostics bundle, syslog forward, checkpoints, access review)

Status: Ready for implementation · 2026-11-04 · Author: architect
Basis: ADR 0048 (diagnostics bundle; **Accepted 2026-11-04** — the maintainer signed off the content list and the
notice text, roadmap decision 3 taken); ADR 0031 with the amendment of 2026-11-04 (syslog transport, checkpoints, replay); ADR 0010 (audit
pipeline), ADR 0030 (manifests, signatures), ADR 0032 (retention; read-access recording), ADR 0034 (step-up),
ADR 0018 (lists and dialogs), ADR 0024 (no event type an older server could receive from a newer agent — see
decision 6); plans M4a (commands), M4b (header escrow and the escrow-reader), M8b (role membership snapshots),
M9 (notifier engine, destinations, `outbound` domain), M10 (evidence export, read-access recording, retention
round); roadmap M12 (F-16, F-26, AUD-08, AUD-05).

Binding language: **MUST** / **MUST NOT** / **SHOULD** / **MAY**.

This plan is written against `main` at `80984bde` (0.1.0-alpha.8). Tickets: PDK-747 to PDK-756 (§8). §13 holds
the outline for alpha.10 (M13b, M13c, M12h) as the orchestrator asked; it binds nothing.

## 1. Goal

An operator who must understand a misbehaving laptop asks Paddock for its diagnostics bundle — a closed, documented
set of Paddock's own logs and configuration — with a reason, the user sees a notice on the device, the bundle is
stored sealed, downloaded after a step-up, audited at every step, purged after seven days, and never readable by
an auditor. A security team receives every security event over syslog/TLS as it is committed, can prove
completeness with `forward_seq`, heartbeats and a daily checkpoint that matches the WORM manifest, replays a range
after an outage, and gets Wazuh decoders, rules and Sigma rules to detect with. An administrator or auditor reads
an access review report — who holds which role, which API tokens exist, who revealed what — for any period and
exports it.

## 2. Context (verified in the code on 2026-11-04, `main` at `80984bde`)

- **Commands**: `pkg/command` (closed registry `TypeRotateAdminPassword`, `TypeDeleteSelfLock`, `TypeInstallNow`,
  `TypeUninstall`, `TypeEncryptDisk`, `TypeEncryptDiskAbort`; `Lifetime(typ)`; DSSE signing/verification);
  `server/internal/app/commands.go` (`issueCommand(ctx, q, rec, deviceID, typ, params, now, notBefore)` inside an
  action, `rec.CommandIssued`); `agent/internal/commands` (`Handler func(ctx, c *command.Command) (status string,
  result map[string]any)`, `Handlers(map)`; results ≤ `protocol.MaxCommandResult` = 4 KiB, posted by
  `agent.postResults` with retry); `device_command` table and `retention` store `device_command`.
- **Header escrow** (the upload pattern): `POST /v1/escrow` kind `luks_header` → `{escrow_id, upload_url}`
  (presigned PUT, 10 min, ≤ 32 MiB, `objectstore.Presigner.PresignPut`), the worker's `Escrow.Round` verifies size
  and SHA-256 (`Store.Size`, `Store.SHA256`) and marks `stored`; the device seals with `escrow.SealHeader(dek,
  nonce, escrowID, plain)` (gzip + AES-256-GCM, the ID as additional data) and wraps the DEK RSA-OAEP to
  `keys.escrow_wrap`; the api's `Disk.DownloadHeader` runs under `RequiresStepUp`, reads the object with the api's
  escrow credential and gets the DEK from the escrow-reader (`escrow.decrypt(ctx, deviceID, ids, PurposeDiskHeader)`;
  the reader verifies the step-up proof itself, `server/internal/escrowreader`).
- **Agent**: `agent/internal/agent/commands.go` (dispatch), `agent/internal/paths` (`Layout`: `State()`,
  `Managed()`, `Bundle()`, `Probation()`, `UpdateResult()`, `UpdatesResult()`, `SupervisorUpgradeResult()`,
  `Trust()`, `AgentConfig()`, `Socket()`), `agent/internal/health` (`Report`), `reconcile.System` (`ReadFile`,
  `Run`-style exec through the port; `fakesys`), events through `reconcile.Events` and the closed enum
  `protocol.EventTypes`.
- **Notifier** (plan M9): `server/internal/notifier` (`Engine.Round` per scope, `Transport` interface
  `Deliver(ctx, Destination, outbound.Message) error`, `transports map[outbound.Type]Transport`, `PGStore` with
  `Pending`, `CreateBatch`, `Succeeded`, `Failed`, `After`, `Latest`), `server/internal/domain/outbound`
  (`Type` `webhook|email`, `ValidateDestination`, `SafeTransport`, `Message`, `KindCheckpoint`,
  `Checkpoint(day, count, manifestSHA256, signature, keyVersion)`), tables `notification_destination` (`type` CHECK
  `('webhook','email')`), `notification_destination_state`, `notification_delivery`, `notification_delivery_event`
  (migration `00085`); `app.Notifications` with `SpecNotification*` and the platform twins; portal
  `Notifications.vue`, `PlatformNotifications.vue`, `NotificationDestinationForm.vue`; `docs/operations/
  notifications.md`, `siem.md` (feed, push outlook).
- **Audit manifests**: `audit_manifest` (audit database; `day`, `organization_id`, `event_count`, `sha256`,
  `signature`, `key_version`, `sealed_at`); `SELECT` granted to `paddock_audit_reader` (plan M10) with RLS;
  `db.AuditReader.InOrg` / `InPlatformScope`.
- **Role membership and tokens** (plan M8b, M6c): `organization_role_member` (worker-written; RLS policy for
  `paddock_worker` only; no api grant), `platform_role_member` (platform pool), `api_token` (api), `admin_account`,
  `platform_admin`; the audit index for reveal events (`local_admin.revealed`, `disk.recovery_key_revealed`,
  `disk.header_downloaded`, `api_token.*`, `admin.role_granted/_revoked`, `admin.sessions_revoked`,
  `admin.login` with `step_up`), read through `db.AuditReader` by `app.AuditLog`.
- **Read-access recording** (plan M10 decision 21): `app.recordRead(ctx, code, …)` coalesced per actor and window
  (store `read_audit_window`), switched on per organization (`settings.privacy.read_audit`).
- **Security review** (plan M8s decision 25): `app.SecurityReview`, `GET /api/v1/security-review`, portal
  `SecurityReview.vue` — the shape of a read-only report page.
- **Desktop sessions**: nothing in the agent talks to a user session today; `loginctl` and `systemd-run` are on
  every Ubuntu 24.04/26.04 target.
- **Migrations**: `00099` is the last control-plane migration; M15 takes `00100`.

## 3. Binding decisions

### 3.1 Diagnostics: protocol, command, server tables (PDK-747)

1. `pkg/command`: `TypeCollectStatus = "collect_status"`, lifetime 1 h, `CollectStatusParams{RequestID string
   `json:"request_id"`; Reason string `json:"reason"`}`, result `CollectStatusResult{Uploaded bool; Files int;
   Bytes int64; TruncatedEntries []string; NotifiedSessions int; Reason string `json:"reason,omitempty"`}` (the
   refusal reasons `invalid_params`, `upload_refused`, `upload_failed`, `collect_failed`, `too_large`).
2. `pkg/protocol`: `DiagnosticsRequest{CommandID string; SHA256 string; Size int64; Nonce string; WrappedDEK
   string}` (standard base64 for `nonce` and `wrapped_dek`, hex for `sha256`, `size` ≤ 32 MiB) and
   `DiagnosticsResponse{DiagnosticsID string; UploadURL string}`; event type `diagnostics.collected` is **not**
   added to `EventTypes` (decision 6). `api/openapi/device.yaml`: `POST /v1/diagnostics` (the signed-request
   parameters of every device endpoint; 202 with the response; 400, 401, 404 `not_found` when `command_id` is not
   a delivered `collect_status` command of the device, 409 `already_uploaded`, 413, 429, 503) — additive
   (ADR 0013).
3. Migration `server/migrations/paddock/00101_device_diagnostics.sql`:

   ```sql
   CREATE TABLE device_diagnostics (
     id uuid PRIMARY KEY,                    -- = the command id
     organization_id uuid NOT NULL, device_id uuid NOT NULL REFERENCES device(id),
     requested_by text NOT NULL, requested_at timestamptz NOT NULL DEFAULT now(),
     reason text NOT NULL CHECK (char_length(reason) BETWEEN 2 AND 500),
     state text NOT NULL CHECK (state IN ('requested','uploaded','stored','failed','expired','purged')),
     object_key text, size bigint, sha256 text, nonce bytea, wrapped_dek bytea,
     files int, truncated_entries text[] NOT NULL DEFAULT '{}', notified_sessions int,
     stored_at timestamptz, expires_at timestamptz, failed_reason text,
     download_count int NOT NULL DEFAULT 0, last_downloaded_at timestamptz, purged_at timestamptz,
     FOREIGN KEY (organization_id, device_id) REFERENCES device (organization_id, id)
   );
   CREATE INDEX device_diagnostics_org_device_idx ON device_diagnostics (organization_id, device_id, requested_at DESC);
   CREATE INDEX device_diagnostics_expiry_idx ON device_diagnostics (expires_at) WHERE state = 'stored';
   ```

   RLS `ENABLE` + `FORCE`, policy `tenant` on `paddock.org_id` for `paddock_api` (SELECT, INSERT, UPDATE) and
   `paddock_worker` (SELECT, UPDATE, DELETE — the purge); `paddock_gateway` has no grant (the gateway publishes
   to the worker as the escrow upload does).
4. `app.Diagnostics` (`server/internal/app/diagnostics.go`): `Request(ctx, deviceID, reason) (Diagnostics,
   error)` (`SpecDiagnosticsRequest{Code: device.diagnostics_requested, AllowedRoles: RolesWrite}` — `org_admin`,
   `org_operator`; the device must be `active` (409 `invalid_state`); at most one `requested` per device (409
   `invalid_state`, detail `a collection is pending`); inserts the row with `id = command id` and issues
   `collect_status` with `{request_id: id, reason}` through `issueCommand`; params `request_id`, `reason`,
   `command_id`, `hostname`); `List(ctx, deviceID, page)` and `ListAll(ctx, page)` (`RolesWrite`: the auditor
   role is refused with 403 — a negative test); `Get`; `Download(ctx, id) (Bundle{Name, Size, Reader}, error)`
   (`SpecDiagnosticsDownload{Code: device.diagnostics_downloaded, AllowedRoles: RolesWrite, RequiresStepUp:
   true}`; state must be `stored` (409 `invalid_state`); the object is read with the api's escrow credential, the
   DEK unwrapped by the escrow-reader with `PurposeDiagnostics = "diagnostics"` (a new purpose the reader accepts
   under the same proof rules as `PurposeDiskHeader`; the reader's policy table gains it), `escrow.OpenObject(dek,
   nonce, id, sealed)` streams the tar.gz; params `sha256`, `bytes`, `files`; `download_count++`);
   `Purge(ctx, id)` (`SpecDiagnosticsPurge{Code: device.diagnostics_purged, AllowedRoles: RolesAdmin}`: deletes the
   object (`DeleteAllVersions`), clears `object_key`, `nonce`, `wrapped_dek`, state `purged`).
5. Device side of the server: `POST /v1/diagnostics` handler (gateway) validates the signed request, checks the
   command (`GetDeviceCommand`: type `collect_status`, state `delivered`, device match; 404 otherwise), refuses a
   row not in `requested` (409), publishes `ingest.DiagnosticsAnnounced{DiagnosticsID, DeviceID, Org, SHA256, Size,
   Nonce, WrappedDEK}` to the worker (exchange and queue as the escrow announce), and answers the presigned PUT
   for key `org/<org>/devices/<device>/diagnostics/<id>.bin` (10 minutes, the `size` bound in the signature as
   SEC-3 did for headers). The worker's `Diagnostics.Round` (new file `worker/diagnostics.go`, the escrow round's
   shape: every 30 s, rows `uploaded` older than 10 s) checks `Size` and `SHA256`, sets `stored`, `stored_at`,
   `expires_at = stored_at + 7 d`, or `failed` with `failed_reason` (`size_mismatch`, `sha256_mismatch`,
   `missing`) after 15 minutes without the object; the command result sets `uploaded`, `files`, `bytes`,
   `truncated_entries`, `notified_sessions` (the result handler of `collect_status` in `app.DeviceCommands`'s
   result path: `state requested → uploaded` on `uploaded: true`, else `failed` with the result's `reason`; a
   command that expires sets `expired`).
6. **Event.** The agent reports the collection as the **command result** (decision 5) and not as a device event:
   ADR 0024 forbids a new event type an older server would refuse; the result path already exists and is
   idempotent. The server records `device.diagnostics_collected` (actor device, target device; params
   `request_id`, `files`, `bytes`, `sha256`, `truncated_entries`, `notified_sessions`) from the worker's `stored`
   transition through `ActionRunner.RecordOnce` (claim key the diagnostics ID), so the audit trail has request,
   collection, download(s) and purge, and only the hash of the content.
7. Retention: `app.StoreDeviceDiagnostics = "device_diagnostics"`; the worker's retention round deletes the
   object and clears the three columns of every `stored` row past `expires_at` (state `expired`), records
   `retention.purged` with `store`, `deleted`, `cutoff` in the organization; rows older than the action retention
   are deleted with the actions (ADR 0032 amendment, §7).

### 3.2 Diagnostics: agent (PDK-748)

8. `agent/internal/diagnostics` (new): `Entries() []Entry` — the closed list of ADR 0048 decision 2 as data
   (`Entry{Name, Kind (file|journal|exec), Source, MaxBytes, Redact func}`), `Collect(ctx, sys reconcile.System,
   l paths.Layout, h health.Reader, w io.Writer) (Manifest, error)` writes the tar.gz (`manifest.json` first:
   `{schema: "paddock.diagnostics.v1", collected_at, device_id, agent_version, entries: [{name, bytes, sha256,
   truncated, error}]}`; one entry per `Entries()` element; a missing file or a failed command is an entry with
   `error` and no content — the archive is never aborted by one entry; the total is cut at 24 MiB plain so that
   the sealed object stays under 32 MiB; journals are read newest-first with `journalctl -u <unit> --since -7d
   --no-pager -o short-iso --reverse` and cut at 8 MiB each). `himmelblau.conf` redaction replaces the value of
   every line whose key matches `(?i)secret|password|key` with `<redacted>`; `state.json` is marshalled without
   `identity`-named fields (the identity key never leaves `/var/lib/paddock/identity/` anyway: the list does not
   include that directory, and a unit test asserts no entry's `Source` lies under it or under `/home`).
   The collector runs commands through `reconcile.System` (a new port method `Output(ctx, name string, args
   ...string) ([]byte, error)` with a 30 s timeout, implemented by `reconcile.OS`, faked by `fakesys`).
9. `agent/internal/escrow` (device side): `SealObject(dek []byte, id string, plain io.Reader) (sealed []byte,
   nonce []byte, err error)` generalizes `SealHeader` (the header path keeps its name as a wrapper); the DEK is
   wrapped with the bundle's `escrow_wrap` key as the header's is.
10. Handler `collect_status` (`agent/internal/agent/diagnostics.go`, registered in `Handlers`): validate params;
    refuse `invalid_params`; **before** collecting, notify the user (decision 11); collect into a temporary file
    under `/var/lib/paddock/diagnostics/<request_id>.tar.gz` (0600), seal, `POST /v1/diagnostics` (client method
    `Diagnostics(ctx, req)`), PUT to `upload_url` with `Content-Length` = size, delete the temporary files, answer
    `{uploaded: true, files, bytes, truncated_entries, notified_sessions}`; on any failure answer `failed` with the
    reason. A pending revocation, uninstall or disk conversion does not refuse the command: those states are
    unrelated to a log collection, and the device's state is exactly what the operator wants to see. The handler
    runs at most one collection at a time.
11. `agent/internal/desktop/notify.go` (new): `Notify(ctx, sys, summary, body string) (sessions int, err error)`:
    `loginctl list-sessions --no-legacy -o json` → sessions with `Type` `wayland` or `x11` and `State` `active`
    (or `Class` `user`), for each `systemd-run --machine=<user>@.host --user --quiet --collect --wait
    notify-send --app-name=Paddock --urgency=normal "<summary>" "<body>"` with a 5 s timeout; failures are logged
    at debug level and counted as not notified. The text is the one of ADR 0048 decision 6, in German when the
    session's `LANG` starts with `de` (read from `loginctl show-session <id> -p Environment`? no such property;
    the agent reads `/etc/default/locale` once and uses it for every session), English otherwise.
12. `agent/internal/paths`: `Diagnostics() = /var/lib/paddock/diagnostics`; the uninstall step (plan M8d)
    removes it in both modes; the directory is not a protected area.

### 3.3 Diagnostics: admin API, portal, retention, documents (PDK-749, PDK-750)

13. Endpoints: `POST /api/v1/devices/{id}/diagnostics` body `{reason}` → 202 `Diagnostics`; `GET
    /api/v1/devices/{id}/diagnostics` (list: sort `[requested_at, state]` default `-requested_at`; filters
    `state`), `GET /api/v1/diagnostics` (list: sort `[requested_at, hostname, state]`; search `[hostname,
    requested_by]`; filters `state`), `GET /api/v1/diagnostics/{id}` → 200, `GET /api/v1/diagnostics/{id}/download`
    → 200 `application/gzip` (`Content-Disposition: attachment; filename="paddock-diagnostics-<hostname>-<id>.tar.gz"`),
    403 `step_up_required`, 409; `POST /api/v1/diagnostics/{id}/purge` → 200. Roles: `org_admin`, `org_operator`
    for everything but `purge` (`org_admin`); `org_auditor` → 403 everywhere; API tokens may request and list,
    never download (step-up). `Diagnostics` = `{id, device_id, hostname, requested_by, requested_at, reason, state,
    size, sha256, files, truncated_entries, notified_sessions, stored_at, expires_at, failed_reason,
    download_count, last_downloaded_at}`.
14. Portal: device tab **Diagnostics** (`views/DeviceDiagnostics.vue`, tab after *Apply status*): the list with
    state chips, *Request diagnostics* (dialog with the reason field and the sentence *The user is told that
    Paddock collects its own logs and configuration; nothing else is collected* — the content list is linked), the
    *Download* action (runs the step-up flow of `lib/stepUp.ts` on 403), *Purge* (ConfirmDialog, admins); the
    fleet page `views/Diagnostics.vue` (route `/diagnostics`, navigation under the devices group) lists every
    bundle of the organization; the auditor role does not see the tab, the page or the navigation entry
    (`navigation.ts` role filter). e2e `diagnostics.spec.ts`.
15. Documents (PDK-750, binding text): `docs/compliance/privacy.md` section *Diagnostics bundle (on request only)*
    with the list of ADR 0048 decision 2 verbatim, the retention (7 days, hash in the audit trail), the roles
    (requested and downloaded by organization administrators and operators after a step-up; auditors never),
    the notice to the user and its text; the Fleet row *free disk space, uptime* gains *on request also in a
    diagnostics bundle*. `docs/operations/diagnostics.md` (new): when to use it, what it holds, how to read the
    archive, the step-up, the purge, the audit codes. `docs/architecture.md` §11.4 row `collect_status` (planned →
    the description), §11.3 the playbook row stays unscheduled, §17.1 and §17.2 the endpoints, §16.1 the table.
    Residual risks RR-108 to RR-110 (§6.6).

### 3.4 Syslog transport (PDK-751)

16. Migration `00102_syslog_destinations.sql`: `ALTER TABLE notification_destination DROP CONSTRAINT
    <type check>; ADD CONSTRAINT notification_destination_type_check CHECK (type IN ('webhook','email','syslog'))`;
    `ADD COLUMN syslog_host text, syslog_port int CHECK (syslog_port BETWEEN 1 AND 65535), syslog_ca_pem text,
    syslog_server_name text, checkpoints boolean NOT NULL DEFAULT false`; `notification_destination_state ADD
    COLUMN last_checkpoint_day date, replay_from bigint`. (The constraint's current name is read from the
    database in the migration with `DO $$ … $$` — the implementer verifies the generated name `…_type_check`.)
17. `outbound`: `TypeSyslog = "syslog"`; `ValidateDestination` for syslog: `syslog_host` a DNS name or public IP
    (the deny list of ADR 0031 decision 12; `PADDOCK_OUTBOUND_DEV_ALLOW_PRIVATE` relaxes it on the development
    stack), `syslog_port` default 6514, `syslog_ca_pem` parses as one or more PEM certificates (≤ 16 KiB),
    `syslog_server_name` a DNS name; `heartbeat_interval_s` as for webhooks; `pseudonymize_users`,
    `include_params` apply; `checkpoints` allowed for webhook and syslog, refused for email (400).
    `outbound/syslog.go`: `FormatSyslog(m Message, ev MessageEvent, hostname string) []byte` (RFC 5424 message of
    the ADR 0031 amendment item 2 with octet-counting framing), `FormatSyslogControl(m Message, hostname string)
    []byte` for heartbeat, test and checkpoint messages.
18. `notifier/syslog.go`: `Syslog{allowPrivate bool; version string}` implements `Transport`: one TLS connection
    per delivery through `SafeTransport`'s dialer logic (the pinned address, SNI = `syslog_server_name` or the
    host, `RootCAs` = the CA PEM when set, TLS 1.2 minimum, 10 s connect, 30 s total, no renegotiation), writes
    every message of the batch (`kind: events` → one per event; other kinds → one control message), waits for
    the server to close or for the write deadline, and returns the error classes `dns`, `dial`, `tls`, `timeout`,
    `denied_address`, `io`; a partial write fails the delivery (the engine retries the batch under the same
    numbers). Registered in `serve notifier` as `transports[outbound.TypeSyslog]`.
19. API and portal: the destination schemas gain the syslog fields (`NotificationDestinationInput` oneOf by
    `type`); `NotificationDestinationForm.vue` gains the syslog branch (host, port, CA PEM textarea, server name,
    checkpoints switch; the switch is also shown for webhooks); the test action sends one `kind: test` message
    over syslog. `docs/operations/notifications.md` gains the *Syslog* section; `siem.md` the *Push over syslog*
    section with an rsyslog and a Wazuh receiver example (`imtcp` with TLS; Wazuh `<remote>` with `syslog`).

### 3.5 Checkpoints and replay (PDK-752)

20. Engine: after serving a destination's events in a round, when `checkpoints` is true: read the sealed days of
    the scope newer than `last_checkpoint_day` (`ListManifestsAfter(ctx, day)` through the reader on
    `audit_manifest (organization_id, day, sha256, signature, key_version)`; the platform scope reads the
    pseudo-organization's manifests). A day D is **due** when the destination has forwarded every event recorded
    on D: the event at the destination's cursor (`GetEventByCommitSeq(cursor)`) has `recorded_at >= D + 1 day`,
    or the cursor equals the scope's `latest`. For each due day in day order: `event_count = CountEventsRecordedOn(ctx,
    D)` (the index rows with `recorded_at` on D, a reader query; `audit_manifest` stores no count), one delivery
    `kind: checkpoint` with `outbound.Checkpoint(D, event_count, hex(sha256), signature, key_version)`, numbered
    in `forward_seq` (`notification_delivery.kind` gains `checkpoint`), delivered through the destination's
    transport; on success `last_checkpoint_day = D` and `notification.checkpoint_sent`. A failure is handled as
    an events failure (retry, stall). Days sealed before the destination was created are not sent (the initial
    `last_checkpoint_day` is the day before the creation).
21. Replay: `app.Notifications.Replay(ctx, id, fromForwardSeq)` (`SpecNotificationReplay{Code:
    notification.replay_requested, AllowedRoles: RolesAdmin, RequiresStepUp: true}` and the platform twin):
    `from_forward_seq` must be ≥ 1 and ≤ `state.forward_seq` (400); refused while a pending delivery exists (409
    `invalid_state`, detail `the destination is retrying a batch; wait or disable it`); sets
    `state.replay_from`. Engine: when `replay_from` is set, before scanning new events, rebuild the batches from
    `notification_delivery` / `notification_delivery_event` with `forward_seq >= replay_from` in order (one
    delivery per stored batch, the same `delivery_id`s and numbers, events re-read from the index by `event_id`;
    an event purged from the index is sent as `{forward_seq, event_id, missing: true}`), deliver them, then clear
    `replay_from`. Audit `notification.replayed` (system) per replayed batch with `forward_from`, `forward_to`,
    `original_delivery_id`. Endpoint `POST /api/v1/notification-destinations/{id}/replay` body `{from_forward_seq}`
    → 202; the platform twin. Portal: *Replay from…* action in the destination detail (dialog with the number,
    step-up).

### 3.6 Detection content (PDK-753)

22. `integrations/wazuh/decoders/0900-paddock_decoders.xml` (parent decoder on `MSGID` prefix / the JSON
    `schema` field for the pull feed's JSON lines and the push's syslog MSG; child decoders extract `code`,
    `outcome`, `actor.type`, `actor.display`, `target.type`, `target.display`, `organization`, `forward_seq`,
    `commit_seq`, `params.*` as dynamic fields), `integrations/wazuh/rules/0900-paddock_rules.xml` (rule groups
    `paddock`, `paddock_tamper`, `paddock_privilege`, `paddock_identity`, `paddock_platform`, `paddock_integrity`;
    levels: tamper and revocation 12, reveals and root grants 10, step-up failures and denied outcomes 7, login
    and configuration 5; a frequency rule for repeated `api_token.use_denied` and for `admin.login` failures;
    a rule that fires when a `paddock.checkpoint` arrives whose `event_count` differs from the count of the day's
    events the SIEM stored is documented as a query, not a rule — Wazuh rules cannot count a day), and
    `integrations/sigma/paddock_*.yml` (one Sigma rule per detection of the rules file, `logsource: product:
    paddock, service: audit`, fields `code`, `outcome`, `actor.type`, `params.*`). `integrations/README.md` names
    the install paths. Tests: `integrations/wazuh/decoders_test.go` parses both XML files and asserts every
    `<if_sid>` and `<if_group>` references a defined rule or group, every rule has an `id` in 100900–100999, and
    every sample event of `docs/compliance/audit-codes.md` (the generated examples) matches at least the parent
    decoder's regex; `integrations/sigma/sigma_test.go` parses every YAML and asserts the `detection` fields exist
    in `paddock.audit.v1` (`audit.Event` field names and the registry's params).
23. `docs/operations/siem.md`: the *Wazuh* pointer becomes a section (decoders, rules, the syslog receiver, the
    reconcile query for checkpoints, the replay); the *Splunk* pointer gains the syslog receiver.

### 3.7 Access review report (PDK-754, PDK-755)

24. Migration `00103_access_review_grants.sql`: `GRANT SELECT ON organization_role_member,
    organization_role_snapshot TO paddock_api` with a `tenant` policy for `paddock_api` (read-only); nothing else
    changes (the platform report uses the platform pool, which already reads `platform_role_member`).
25. `app.AccessReview` (`server/internal/app/accessreview.go`): `Organization(ctx, period Period) (Report,
    error)` (`RolesAudit` = `org_admin`, `org_auditor`; recorded through the read-access path as
    `access_review.viewed` with params `from`, `to` — coalesced per actor and UTC day as `device.inventory_viewed`
    is, and only when the organization's `read_audit` is on), `Platform(ctx, period) (PlatformReport, error)`
    (`platform_admin`; recorded always as `platform.access_review_viewed`: platform reads are not under the
    organization's privacy switch). `Period{From, To time.Time}` defaults to the last 90 days, at most 400 days.
    `Report` = `{generated_at, period, roles: [{role, members: [{username, authentik_pk, first_seen_at}]}]
    (from organization_role_member; snapshot_taken_at), role_changes: [{at, code, username, role, actor}] (audit
    `admin.role_granted/_revoked` in the period, baseline excluded), accounts: [{username, display_name, role,
    last_login_at, disabled}] (admin_account), api_tokens: [{name, role, prefix, created_by, created_at,
    expires_at, last_used_at, revoked_at, revoked_by}] (every token that existed in the period), token_denials:
    int (`api_token.use_denied` count), reveals: [{at, code, actor, device_hostname, params subset}] (audit codes
    `local_admin.revealed`, `disk.recovery_key_revealed`, `disk.header_downloaded`, `device.diagnostics_downloaded`,
    `notification.pseudonym_resolved`), step_up: {succeeded, failed} (counts from `admin.login` events with
    `step_up` params in the period), sessions_revoked: [{at, username, reason}], break_glass_accounts: [names]
    (the organization's login settings), destructive: [{at, code, actor, target}] (`device.destroy_*`,
    `revocation.*approved`, `device.retired`, `user.locked`), caps: {reveals: 1000, role_changes: 1000, …} (every
    list is capped at 1 000 with the total)}`. `PlatformReport` = platform role members and superusers, platform
    admins' last logins, `platform.*` privileged events, `admin.sessions_revoked` and `platform.sessions_ended`,
    organizations created, agent releases published and rolled out, in the same shape.
26. Endpoints: `GET /api/v1/access-review?from&to` → 200 `AccessReviewReport`; `GET
    /api/v1/access-review/export?from&to&format=json|csv` → 200 (`application/json` the same object;
    `text/csv` one CSV with a `section` column; `Content-Disposition: attachment; filename="paddock-access-review-
    <slug>-<from>-<to>.<ext>"`), recorded as `access_review.exported` (always, not coalesced: an export leaves the
    system); `GET /api/platform/v1/access-review` and `/export` likewise with `platform.access_review_viewed` /
    `platform.access_review_exported`. The report is one object, not a collection: no list contract and no
    `x-paddock-list`, exactly as `GET /api/v1/security-review` is documented today; `listspec_test.go` already
    skips operations without `items`.
27. Portal: page **Access review** (`views/AccessReview.vue`, route `/access-review`, navigation in the
    organization's security group next to *Security review*; platform twin `PlatformAccessReview.vue` at
    `/platform/access-review`): period picker (presets 30/90/365 days and custom), sections as expandable cards
    each with a `DataList`-styled table (client-side; the report is one response — the cap is shown when hit),
    *Export JSON* / *Export CSV* buttons. The auditor sees it (the report is its purpose); the operator does not
    (`RolesAudit`). e2e `accessReview.spec.ts`.

### 3.8 Gates and documents (PDK-756)

28. §9 and §7; `CHANGELOG` fragments per ticket; residual risks RR-108 to RR-112 (§6.6).

## 4. Non-goals

- No free-form command on devices, no playbook step, no extension of the content list by configuration.
- No reading of the diagnostics archive in the portal (download only); no per-entry selection by the operator.
- No syslog over plain TCP or UDP; no mutual TLS; no CEF, LEEF or ECS mapping; no OTLP.
- No SIEM verdict endpoint (ADR 0031 decision 14).
- No recertification campaign or approval workflow on the access review (roadmap AUD-05 "later"); no
  scheduled e-mail of the report (F-24 "later").
- No change to the revocation path, the audit writer's sealing, the manifest format, `pkg/bundle`.
- No new Go module, npm package or container image (Wazuh is not run in CI: the tests parse the files).

## 5. Affected files

| Path | Action | Purpose |
| --- | --- | --- |
| `pkg/command/command.go`, `pkg/protocol/types.go`, `api/openapi/device.yaml` | change | decisions 1–2 |
| `server/migrations/paddock/00101_device_diagnostics.sql`, `00102_syslog_destinations.sql`, `00103_access_review_grants.sql` | new | decisions 3, 16, 24 |
| `server/internal/app/diagnostics.go`, `accessreview.go`, `notifications.go`, `commands.go`, `retention.go` (+ tests) | new / change | decisions 4–7, 21, 25 |
| `server/internal/ingest/ingest.go`, `server/internal/transport/http/device/handlers_diagnostics.go` | change / new | decision 5 |
| `server/internal/worker/diagnostics.go`, `retention.go` | new / change | decisions 5, 7 |
| `server/internal/escrowreader/*` (purpose table), `server/internal/app/escrowdecrypt.go` | change | `PurposeDiagnostics` |
| `server/internal/domain/outbound/{destination,syslog,message}.go`, `server/internal/notifier/{syslog,engine,store,types}.go`, `server/cmd/paddock-server/notifier.go` | new / change | decisions 17–21 |
| `server/internal/domain/audit/codes.go` | change | §6.4 |
| `api/openapi/admin.yaml`, `server/internal/transport/http/admin/handlers_diagnostics.go`, `handlers_accessreview.go`, `handlers_notifications.go`, `server.go` | new / change | §6.2 |
| `agent/internal/diagnostics/*.go`, `agent/internal/desktop/notify.go`, `agent/internal/agent/diagnostics.go`, `agent/internal/escrow/seal.go`, `agent/internal/client/client.go`, `agent/internal/paths/paths.go`, `agent/internal/reconcile/{reconcile,system}.go`, `fakesys`, `agent/internal/uninstall/*` | new / change | decisions 8–12 |
| `server/web/src/views/DeviceDiagnostics.vue`, `Diagnostics.vue`, `AccessReview.vue`, `PlatformAccessReview.vue`, `components/NotificationDestinationForm.vue`, `DeviceTabs.vue`, `lib/{diagnostics,accessReview,notifications,navigation}.ts`, `router.ts`, `locales/*`, `e2e/{diagnostics,accessReview,notifications}.spec.ts` | new / change | decisions 14, 19, 21, 27 |
| `integrations/wazuh/decoders/0900-paddock_decoders.xml`, `integrations/wazuh/rules/0900-paddock_rules.xml`, `integrations/sigma/*.yml`, `integrations/README.md`, `integrations/wazuh/decoders_test.go`, `integrations/sigma/sigma_test.go` | new | decision 22 |
| `test/acceptance/diagnostics_test.go`, `notifications_syslog_test.go`, `access_review_test.go`, `test/acceptance/internal/syslogsink/*`; `test/system/diagnostics_test.go` | new | §9 |
| `docs/compliance/privacy.md`, `docs/operations/diagnostics.md` (new), `siem.md`, `notifications.md`, `docs/architecture.md`, `docs/compliance/residual-risks.md`, `changelog.d/*` | change / new | decisions 15, 19, 23; §7 |

Not to be touched: `agent/internal/revoke/`, `agent/cmd/paddock-revoke/`, `pkg/revocation/`, the audit writer's
sealing, `server/migrations/audit/`, existing migrations, ADRs other than 0048 and the 0031 amendment.

## 6. Interfaces and formats

### 6.1 Device protocol (additive)

```
POST /v1/diagnostics   body DiagnosticsRequest{command_id, sha256, size (≤ 33554432), nonce, wrapped_dek}
                       → 202 {diagnostics_id, upload_url}; 400, 401, 404 not_found, 409 already_uploaded, 413, 429, 503
collect_status params  {"request_id": "<uuid>", "reason": "…"}      lifetime 1 h
collect_status result  {"uploaded": true, "files": 41, "bytes": 1834221, "truncated_entries": ["journal:himmelblaud"], "notified_sessions": 1}
                    or {"uploaded": false, "reason": "upload_failed"}
```

### 6.2 Admin API

```
POST /api/v1/devices/{id}/diagnostics          {reason} → 202 Diagnostics; 404, 409                      audit device.diagnostics_requested
GET  /api/v1/devices/{id}/diagnostics          list: sort [requested_at,state] default -requested_at; filters [state]      roles org_admin, org_operator
GET  /api/v1/diagnostics                       list: sort [requested_at,hostname,state]; search [hostname,requested_by]; filters [state]
GET  /api/v1/diagnostics/{id}                  → 200; 404
GET  /api/v1/diagnostics/{id}/download         → 200 application/gzip; 403 step_up_required; 404; 409       audit device.diagnostics_downloaded   step-up
POST /api/v1/diagnostics/{id}/purge            → 200; 404; 409                                              audit device.diagnostics_purged       org_admin
POST /api/v1/notification-destinations/{id}/replay            {from_forward_seq} → 202; 400; 404; 409      audit notification.replay_requested   step-up
POST /api/platform/v1/notification-destinations/{id}/replay   likewise
NotificationDestination(+Input): + syslog_host, syslog_port, syslog_ca_pem (write-only), syslog_server_name, checkpoints; type enum + syslog
NotificationDestinationState: + last_checkpoint_day, replay_from
GET  /api/v1/access-review?from&to             → 200 AccessReviewReport                                    read audit access_review.viewed (coalesced)
GET  /api/v1/access-review/export?from&to&format → 200 json|csv                                             audit access_review.exported
GET  /api/platform/v1/access-review[/export]   → 200                                                        audit platform.access_review_viewed / _exported
```

### 6.3 Go signatures (binding names)

```go
// pkg/command
const TypeCollectStatus = "collect_status"
type CollectStatusParams struct { RequestID string `json:"request_id"`; Reason string `json:"reason"` }
type CollectStatusResult struct { Uploaded bool `json:"uploaded"`; Files int `json:"files,omitempty"`; Bytes int64 `json:"bytes,omitempty"`; TruncatedEntries []string `json:"truncated_entries,omitempty"`; NotifiedSessions int `json:"notified_sessions"`; Reason string `json:"reason,omitempty"` }
// agent/internal/diagnostics
type Entry struct { Name, Kind, Source string; MaxBytes int64; Redact func([]byte) []byte }
func Entries() []Entry
func Collect(ctx context.Context, sys reconcile.System, l paths.Layout, h health.Reader, w io.Writer) (Manifest, error)
// agent/internal/desktop
func Notify(ctx context.Context, sys reconcile.System, summary, body string) (int, error)
// agent/internal/escrow
func SealObject(dek []byte, id string, plain io.Reader) (sealed, nonce []byte, err error)
// server/internal/app
func (d *Diagnostics) Request(ctx context.Context, deviceID uuid.UUID, reason string) (DiagnosticsRow, error)
func (d *Diagnostics) Download(ctx context.Context, id uuid.UUID) (Bundle, error)
func (d *Diagnostics) Purge(ctx context.Context, id uuid.UUID) (DiagnosticsRow, error)
func (n *Notifications) Replay(ctx context.Context, id uuid.UUID, from int64) error
func (a *AccessReview) Organization(ctx context.Context, p Period) (Report, error)
func (a *AccessReview) Platform(ctx context.Context, p Period) (PlatformReport, error)
// server/internal/domain/outbound
const TypeSyslog Type = "syslog"
func FormatSyslog(m Message, ev MessageEvent, hostname string) []byte
func FormatSyslogControl(m Message, hostname string) []byte
// server/internal/notifier
func NewSyslog(allowPrivate bool, version string) *Syslog   // implements Transport
```

### 6.4 Audit codes (closed registry; descriptions verbatim)

| Code | Actor | Target | Params | Outcomes |
| --- | --- | --- | --- | --- |
| `device.diagnostics_requested` | admin / token | device | `request_id`, `reason`, `command_id`, `hostname` | success, failure, denied |
| `device.diagnostics_collected` | device | device | `request_id`, `files`, `bytes`, `sha256`, `truncated_entries`, `notified_sessions` | success, failure |
| `device.diagnostics_downloaded` | admin | device | `request_id`, `sha256`, `bytes`, `files`, `hostname` | success, failure, denied |
| `device.diagnostics_purged` | admin / system (retention) | device | `request_id`, `hostname` | success, failure, denied |
| `notification.replay_requested` | admin / platform admin | notification_destination | `destination`, `destination_id`, `from_forward_seq`, `to_forward_seq` | success, failure, denied |
| `notification.replayed` | system | notification_destination | `destination_id`, `forward_from`, `forward_to`, `original_delivery_id`, `missing` | success, failure |
| `notification.checkpoint_sent` | system | notification_destination | `destination_id`, `day`, `event_count`, `forward_seq` | success, failure |
| `access_review.viewed` | admin / auditor | organization | `from`, `to` | success |
| `access_review.exported` | admin / auditor | organization | `from`, `to`, `format` | success, failure, denied |
| `platform.access_review_viewed` / `_exported` | platform admin | platform | `from`, `to` (`format`) | success (, failure, denied) |

`device.diagnostics_requested`, `_downloaded`, `_purged`, `notification.replay_requested`,
`notification.checkpoint_sent` and `access_review.exported` join `outbound.SecurityCodes()`.

### 6.5 Diagnostics archive (`paddock.diagnostics.v1`)

```
paddock-diagnostics-<hostname>-<id>.tar.gz
  manifest.json                         {schema, collected_at, device_id, agent_version, entries: [{name, bytes, sha256, truncated, error}]}
  paddock/health.json                   the agent socket's health report
  paddock/state.json                    without identity fields
  paddock/managed.json, probation.json, update-result.json, updates-result.json, supervisor-upgrade-result.json
  paddock/bundle.dsse, trust.json, agent.yml
  journal/paddock-supervisor.log, paddockd.log, paddock-encrypt.log, paddock-uninstall.log, himmelblaud.log, himmelblaud-tasks.log
  systemd/status.txt, failed-units.txt
  etc/sudoers, sudoers.d/<file>…, pam.d/common-*, nsswitch.conf, himmelblau/himmelblau.conf (redacted), apt/sources.list.d/paddock-*, apt/preferences.d/5*paddock*, crypttab, fstab
  system/os-release, uname.txt, timedatectl.txt, df.txt, uptime.txt, lsblk.txt, luksDump-<uuid>.txt, tpm.txt, dpkg.txt, ip-link.txt, resolvectl.txt, apt-history.log, server-healthz.txt
```

### 6.6 Residual risks (RR-108 to RR-112)

| ID | Risk | Mitigation | ISMS record |
| --- | --- | --- | --- |
| RR-108 | **Journals name users.** Himmelblau's journal carries UPNs and the agent's carries the names of locked users and sudo decisions; a bundle is personal data of the device's users. | Closed list; reason required; notice on the device; step-up and audit for every download; 7-day purge; no auditor access; works-council text in `privacy.md`. | Purpose limitation of diagnostics; who may be operator. |
| RR-109 | **The notice is best effort.** A device without a graphical session, or one where `notify-send` is missing, shows nothing; the user learns from the organization's transparency notice only. | `notified_sessions` is recorded and shown; the transparency notice names the bundle. | The organization's notice to employees. |
| RR-110 | **Syslog is at-least-once.** A receiver sees duplicates after a retry or a replay. | `forward_seq` and `event_id` in every message; the runbook's deduplication guidance; decoders carry both fields. | SIEM deduplication rule. |
| RR-111 | **The SIEM copy is not evidence.** A SIEM retains and transforms; only the WORM chain and the evidence export are evidence. | Checkpoints let the SIEM copy be reconciled; `siem.md` says so. | Which copy is cited in an audit. |
| RR-112 | **The access review reads snapshots, not Authentik.** Role membership is the worker's 5-minute snapshot; a member added and removed between two rounds never appears. | The audit events of role changes are included; the snapshot time is shown. | Authentik's own audit for sub-5-minute changes. |

### 6.7 Portal texts (binding English)

- Request dialog: *Paddock will collect its own logs and configuration from this device — nothing else. The
  user is told on the device. Give a reason; it is shown to the user and recorded.*
- Device notice (ADR 0048 decision 6): *Paddock collected diagnostic data from this device for your
  administrator. Reason: <reason>. What was collected: Paddock's own logs and configuration, no personal files.*
- Replay dialog: *Resend every batch from sequence number N on. The receiver sees the same numbers again; it must
  deduplicate.*

## 7. Architecture and rule amendments (PDK-750, PDK-756)

- `docs/architecture.md`: §11.4 `collect_status` row (the description; TTL 1 h; the upload); §14.1 *SIEM forward*
  from *planned* to the syslog transport, checkpoints and replay; §17.1 the new endpoints; §17.2 `POST
  /v1/diagnostics`; §16.1 `device_diagnostics`; §9.6 the access review as an auditor-visible report.
- `docs/compliance/privacy.md` (decision 15); `docs/compliance/iso27001-mapping.md` rows A.5.18 (access review:
  the report), A.8.15/A.8.16 (syslog forward, checkpoints), A.5.28 (diagnostics evidence: the hash).
- `docs/adr/0032-retention-and-deletion.md` amendment 2026-11-04: `device_diagnostics` (device data, 7 days after
  stored, worker, `retention.purged` store `device_diagnostics`; the row's metadata with the actions).
- `CLAUDE.md` is not changed.

## 8. Steps (tickets, in order)

1. **PDK-747 — Diagnostics: command type, device endpoint, table, worker verification, result handling, audit
   codes.** Decisions 1–7; §6.1, §6.4 (diagnostics codes). Verify: `make gen` no diff; the device contract test;
   integration tests for the state machine (requested → uploaded → stored / failed / expired → purged).
2. **PDK-748 — Diagnostics: agent collector, sealing, upload, desktop notice.** Decisions 8–12; §6.5. Depends on
   PDK-747 (`pkg`). Verify: `go test ./agent/...` with `fakesys` (every entry listed; redaction; truncation; no
   entry under `/home` or the identity directory; the notice command per active session); `make typecheck`.
3. **PDK-749 — Diagnostics: admin API, escrow-reader purpose, portal, retention.** Decisions 4 (download),
   13–14, 7. Depends on PDK-747. Verify: the privileged route table, the list contract, the auditor negative
   tests; `make e2e T=diagnostics`.
4. **PDK-750 — Diagnostics: privacy amendment, runbook, gates, residual risks.** Decision 15; §9 D1–D3, DS1.
   Depends on PDK-748, PDK-749. The privacy amendment has the maintainer's sign-off of 2026-11-04 (orchestrator
   relay): the content list of ADR 0048 decision 2 including `/var/log/apt/history.log`, the notice text without
   the administrator's name.
5. **PDK-751 — Syslog/TLS destination type.** Decisions 16–19. Independent of 1–4. Verify: the sink of §9 S1;
   `go test ./server/internal/notifier/ ./server/internal/domain/outbound/`.
6. **PDK-752 — Checkpoints and replay.** Decisions 20–21. Depends on PDK-751 (state columns). Verify: §9 S2–S3.
7. **PDK-753 — Wazuh decoders and rules, Sigma rules, runbook.** Decisions 22–23. Depends on PDK-751 (format).
   Verify: `go test ./integrations/...`.
8. **PDK-754 — Access review: grants, use cases, API, export.** Decisions 24–26. Independent. Verify: §9 A1–A2.
9. **PDK-755 — Access review: portal pages.** Decision 27. Depends on PDK-754. Verify: `make e2e T=accessReview`.
10. **PDK-756 — M12 gates on the VMs, architecture amendments, ISO mapping, changelog, regression.** §7; §9 DS1;
    the full regression. Depends on every other ticket.

PDK-747/748/749/750, PDK-751/752/753 and PDK-754/755 are three independent chains; they MAY run in parallel.

## 9. Tests and gates

- **Unit:** `diagnostics.Entries()` closed-list properties (names unique, every `Source` absolute and outside
  `/home`, `/root`, `/var/lib/paddock/identity`; `MaxBytes` set), `Collect` with `fakesys` (manifest entries =
  `Entries()`, truncation flag at the cap, a failing command is an entry with `error`, redaction of
  `himmelblau.conf`, the archive stays under 24 MiB), `desktop.Notify` (one `systemd-run` per active graphical
  session, none for `tty`, German text with `LANG=de_DE.UTF-8`), `SealObject`/`OpenObject` round trip and the
  additional-data binding; `outbound.FormatSyslog` (RFC 5424 shape, octet count, BOM, PRI by outcome, MSGID =
  code), `ValidateDestination` syslog branch (deny list, port, PEM, checkpoints on email refused);
  `notifier.Syslog` against a local TLS listener (pinned address, SNI, CA, partial write = failure); the engine's
  checkpoint selection (only sealed days behind the cursor, in order) and replay (same numbers, missing events
  marked); `AccessReview` assembly with seeded rows (caps, period bounds).
- **Integration (`pgtest`):** migrations `00101`–`00103`; RLS fail-closed for `device_diagnostics`; the api cannot
  write `organization_role_member`; the diagnostics state machine; the retention purge of `device_diagnostics`
  (object delete called, columns cleared, `retention.purged` recorded once); `spec_test.go` / `listspec_test.go`.
- **Acceptance (`test/acceptance/`):**
  - D1 `TestDiagnosticsFlow`: operator requests with a reason → 202, the devicesim receives `collect_status`,
    announces (`POST /v1/diagnostics` with a sealed fixture archive), PUTs it, posts the result → `stored` within
    one worker round with `files`, `sha256`; `device.diagnostics_requested` and `_collected` in the index; the
    download without step-up → 403; with step-up → a tar.gz whose `manifest.json` matches the fixture and
    `device.diagnostics_downloaded` carries the hash; purge → `purged`, the object gone (`GET` of the download →
    409); the auditor → 403 on every endpoint; an API token requests and lists but cannot download; a second
    request while one is `requested` → 409; a wrong `size` on announce → `failed` with `size_mismatch`.
  - D2 `TestDiagnosticsRetention` (development retention unit): a stored bundle is `expired` after the unit with
    `retention.purged`.
  - D3 `TestIsolation` fixtures: the diagnostics endpoints and table.
  - S1 `TestNotificationsSyslog`: an acceptance TLS syslog sink (`test/acceptance/internal/syslogsink`, the
    shape of the webhook sink) receives one RFC 5424 message per event with `forward_seq` contiguous, `MSGID` =
    code, the JSON parses; a `test` message; a heartbeat after the interval; a stopped sink → `stalled` and
    `notification.destination_stalled`; restart → catch-up without a gap; the CA PEM option works with the
    sink's self-signed certificate; a private sink address is refused without the dev flag.
  - S2 `TestNotificationsCheckpoints`: after the audit writer sealed a day (the acceptance clock helper of M8b),
    a destination with `checkpoints` receives one `checkpoint` message whose `manifest_sha256` equals
    `audit_manifest.sha256` of that day, numbered in `forward_seq`, once; `notification.checkpoint_sent` once.
  - S3 `TestNotificationsReplay`: replay from N → the sink receives the batches ≥ N again with the same
    `delivery_id`s and numbers, then new events continue; replay while a pending retry → 409; audit
    `notification.replay_requested` (admin, step-up) and `notification.replayed` per batch.
  - A1 `TestAccessReview`: org admin and auditor read the report with the seeded role members, a created and a
    revoked API token, a `local_admin.revealed` event, a role change; the operator → 403; the export CSV has the
    `section` column and every row; `access_review.exported` recorded; with `read_audit` on, `access_review.viewed`
    once per day; the period is capped at 400 days (400 `invalid_request` beyond).
  - A2 `TestPlatformAccessReview`: platform admin reads members and superusers; an organization session → 403.
- **System (`test/system/diagnostics_test.go`, both VMs):** DS1 `TestDiagnosticsGates`: a real `collect_status` on
  the VM → the archive downloaded by the test contains every entry of `Entries()` (or an `error` for entries the
  VM lacks), `journal/paddockd.log` holds the VM's last check-in line, `etc/himmelblau/himmelblau.conf` has no
  line matching `(?i)secret.*=.*[^<]` (redacted), no file under `home/`, the temporary directory on the VM is
  empty afterwards, `notified_sessions` ≥ 1 when the VM has a graphical autologin session (the VM harness
  provides one; otherwise 0 and the gate asserts the journal line *no active graphical session*).
- **Portal (`e2e/`):** `diagnostics.spec.ts` (tab hidden for the auditor, request dialog requires a reason,
  download triggers step-up, purge confirm), `notifications.spec.ts` (syslog form, checkpoints switch, replay
  dialog), `accessReview.spec.ts` (period presets, sections, export buttons).
- Never weakened: `TestNotificationsDelivery`, `TestNotificationsEmail`, `TestAuditChain`, `TestEscrow*`.

## 10. Acceptance criteria

- **C1 diagnostics (F-16; operator, user, auditor):** Given an active device, when an operator requests
  diagnostics with a reason, then the user sees a notice naming the reason, the bundle holds exactly the closed
  list and nothing else, the operator downloads it after a step-up, every step is one audit event carrying only
  the hash, the bundle is gone after seven days, and the auditor can read the events but never the bundle.
- **C2 syslog (F-26, AUD-08; security team):** Given a syslog destination, then every security event arrives over
  TLS as one RFC 5424 message with a contiguous `forward_seq`, a stalled receiver is reported and catches up,
  and the receiver can prove completeness.
- **C3 checkpoints (ADR 0031 decision 6; auditor, security team):** Given a sealed day, then the destination
  receives one checkpoint whose hash equals the WORM manifest's, and the runbook shows how to reconcile.
- **C4 replay (ADR 0031 decision 4; security team):** Given an outage longer than the SIEM's buffer, when the
  administrator replays from a sequence number, then the receiver gets the same batches with the same numbers.
- **C5 detection content (roadmap; security team):** Given Wazuh with the shipped decoders and rules, then a
  tamper event raises a level-12 alert and the Sigma rules match the same events; the files pass the parse tests.
- **C6 access review (AUD-05; admin, auditor):** Given a period, then the report lists role members, role
  changes, accounts, API tokens, reveals, step-ups, revoked sessions and destructive actions, exports as JSON and
  CSV, and the operator cannot read it.
- **C7 privacy (privacy.md; works council):** the content list in `privacy.md` equals `Entries()` (a test
  renders the list from code and compares it with the document's section).
- **C8 compatibility (ADR 0013, 0024; operator):** an agent of the previous release answers `collect_status`
  with `unsupported_type` and nothing else breaks; a new agent against the previous server never sends a new
  event type (the result path is used).

## 11. Stop conditions

- The escrow-reader's purpose check cannot take a new purpose without a change to the proof format: report.
- `systemd-run --machine=<user>@.host` is refused on the VM image (polkit): report with the journal line; do not
  run `notify-send` as root with `DISPLAY` hacks.
- `journalctl` is absent or restricted on a target (non-systemd journal): the entry records `error`; if the whole
  collection cannot run, report.
- Wazuh's decoder XML cannot express the JSON extraction without `<plugin_decoder>JSON_Decoder</plugin_decoder>`
  on a syslog MSG: report with the chosen fallback (a `prematch` on the BOM and the JSON plugin).
- Any change in the revocation path, the audit writer's sealing, `pkg/bundle`, or an ADR other than 0048 and the
  0031 amendment; any new dependency.

## 12. Risks and open points

- **R1 — Privacy sign-off.** Resolved: the maintainer signed off the content list (incl. the apt history log)
  and the notice text without the administrator's name on 2026-11-04; PDK-750 merges `privacy.md` with it.
- **R2 — Step-up on every download** is friction for operators. Kept (the bundle is reveal-class data).
- **R3 — Syslog receivers differ** in framing tolerance. Default: octet-counting (RFC 6587 §3.4.1), the only
  framing safe for JSON with newlines; the runbook shows rsyslog and Wazuh settings.
- **R4 — Checkpoint ordering** relies on `recorded_at` of the cursor's event (decision 20): a day whose events
  were recorded late (an offline device's spool) after the day was sealed is covered by the manifest's own rule
  (ADR 0010 recording-day amendment: sealing happens by recording day, so no event is recorded on a sealed day).
- **R5 — Access review size** for large organizations: lists capped at 1 000 with totals; the export carries the
  same cap (documented); a paged export is F-24's.
Decisions taken on 2026-11-04 (binding for this plan):

- **The device notice shows no administrator name** (maintainer).
- **`org_admin` and `org_operator` may download**, each download with a step-up (maintainer).
- **`/var/log/apt/history.log` is in the content list** (package names and versions, no users; maintainer);
  ADR 0048 decision 2 and §6.5 list it.
- **The access review is recorded for the auditor under the organization's `read_audit` switch**, as every
  other read (maintainer).
- **Syslog: TLS server authentication only, optional pinned CA**; no mutual TLS, no UDP or plain TCP (architect lead).

## 13. Outline for 0.1.0-alpha.10 (ordering, dependencies, open decisions; no tickets yet)

Order: **M12h first half → M13b → M13c → M12h second half**, so that the catalog gets the hardening that
touches its surfaces (network segmentation, rate limits) before self-service opens a socket to users.

- **M13b — Self-service app, intent `available`, Flatpak, user targets.** Outline: `docs/plans/M13a-software-catalog.md`
  "Outline M13b". Depends on M13a (shipped in alpha.8) and on this plan's `agent/internal/desktop/notify.go`
  (decision 11) for desktop notifications. Open decisions before its plan: the desktop toolkit (GTK or Qt, licence
  check; ADR), the socket's authorization model (`SO_PEERCRED` + `device_owner` ∩ audience; ADR 0042 decisions 5–6),
  Flathub as a trust anchor (RR-79 reserved).
- **M13c — Waves, maintenance windows, approvals, stored packages, compliance report, shared catalog.** Outline:
  the same file, "Outline M13c". Depends on M11's rollout engine (shipped) for waves, on M13b for approvals of
  `available` entries, on ADR 0022's release store for a Paddock-hosted APT repository (its own ADR: a new trust
  decision), on the platform scope for the shared catalog. Open decisions: the repository signing key in OpenBao,
  the SLA definitions of the patch compliance report (AUD-14), whether `software_*` sections join the declarative
  document before or after approvals.
- **M12h — Application hardening** (roadmap M12h table, `roadmap-appsec.md` §4 items 3, 5–9 and "next in line").
  Split into **M12h-1** (before M13b): container hardening of third-party services one service per PR (CR-2, RL-4,
  CR-8 `make lint-compose`), network segmentation and narrow proxy defaults (CR-3–CR-6; ADR 0016 amendment — open
  decision 4 of the appsec list), Valkey ACL users per role (AZ-4, SE-2; ADR 0003 amendment — open decision 5),
  rate limits on the admin API and auth endpoints (RL-1; open decision 8: application-level limiter without a
  dependency is the recommendation), agent file safety and systemd sandboxing (AG-1–AG-3); and **M12h-2** (after
  M13c): Authentik controls (AU-3–AU-6), Trusted Types and isolation headers (PO-1, PO-2, HT-3), parsers and
  runtime OpenAPI validation (IV-1, IV-2, IV-5), SECURITY DEFINER inventory, central log redaction, session-key
  rotation (AZ-2, SE-1, CK-1), supply chain (SLSA provenance, SBOMs for agent artifacts, `persist-credentials:
  false`, `npm ci --ignore-scripts`, image update watch; SC-1, SC-2, CI-1, SC-4, SC-5 — open decision 6: new CI
  tools need approval). Each half gets its own plan; the threat-model review of every plan (`roadmap-appsec.md`
  §3) applies to M13b and M13c as well.
- **Carried from alpha.9:** the SMB client library (rejected for M15; reconsidered only if operators object to
  the host step) and the revocation acceptance records (roadmap decision 4) stay open for the alpha.10 plans.

## Amendment 2026-11-04 — access review deviations signed off (PDK-754)

Decisions taken by the architect lead on 2026-11-04 after Review 1 of PDK-754 (decisions 24–26 of §3.7 and gates
A1/A2 are read with these changes):

1. **Who may read the report.** The organization's access review is read by **role**, the same rule as the audit
   log (`org_admin`, `org_auditor`; operators get 403 `forbidden`), with **no organization switch**. The maintainer's
   rule is "the auditor sees the access review under the same rule as the audit log". The platform report is for
   `platform_admin`.
2. **`audit_search_recorded` controls recording, not access.** The plan's `read_audit` switch does not exist.
   While `audit_search_recorded` is on, opening the organization report is recorded as `access_review.viewed`,
   coalesced to one event per actor and UTC day (the first view of the day, with its effective period). With the
   switch off nothing is recorded and the report is still readable. A role that may not read it is recorded as
   `denied` whatever the setting. Exports are always recorded (`access_review.exported`,
   `platform.access_review_exported`), and so is every view of the platform report
   (`platform.access_review_viewed`).
3. **Step-up counting.** `admin.login` events carry no `step_up` param, so the plan's source does not exist. The
   section counts, per actor, the **successful events of a step-up actor** as succeeded and the **denied events
   with `step_up_required`** as failed; it exposes aggregate counts only.
4. **Destructive actions follow the plan list.** The section lists `revocation.approved`,
   `device.escrow_destroyed`, `device.retired` and `user.locked` (`device.destroy_*` does not exist in the
   registry). `revocation.requested` was added in the first implementation and **removed again in Fix Round 1**, so
   the implementation matches decision 25; the widening accepted in principle is not in the code.
5. **Docs.** `access_review.viewed`, `access_review.exported` and the `platform.access_review_*` codes are in
   `docs/compliance/audit-codes.md` (generated from the registry) and in the privacy documents
   (`privacy.md`, and the privacy pack: record of processing, DPIA input, works-council annex).
6. **Migration label**: `00104_access_review_grants.sql` (the plan's `00103` follows landing order; the grants are
   a read-only `tenant_api_read` policy on `organization_role_member` and `organization_role_snapshot`).
