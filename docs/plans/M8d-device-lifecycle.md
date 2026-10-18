# Implementierungsplan: M8d — Device lifecycle (owners, login history, hardware facts, staleness per group, agent update policy and update now, supervisor updates, uninstall, disk unlock mode)

Status: Ready for implementation · 2026-10-17 · Author: architect
Basis: ADR 0037 (device lifecycle: update policy, update now, supervisor updates, uninstall, owners, login history,
hardware facts, staleness per group); ADR 0038 (disk unlock mode; in-place encryption deferred to M8e); ADR 0032
amendment 2026-10-17 (retention of the login history and the hardware facts); ADR 0013 (additive protocol changes);
ADR 0018 (lists and dialogs); ADR 0024 (no event type an older server could receive from a newer agent); plans M2b
(supervisor, rollouts), M4a (commands, step-up), M4b (disk encryption), M5a (fleetd, inventory), M5b (updates,
staleness, attention); lab findings L12, L27, L30–L35 (`.claude/roadmap/lab-findings.md`).

Binding language: **MUST** / **MUST NOT** / **SHOULD** / **MAY**.

Milestones M9, M10 and M11 (ADRs 0032, 0033) are planned but not implemented on `main` at `ecfaad0`. This plan is
written against the code as it is; §11 names what to do when one of them lands first.

## 1. Goal

After M8d an organization administrator sees on the device page who owns a device, which hardware it is, which
directory users signed in on it (when the organization switched the history on), and whether the device is on the
newest agent; the organization decides whether devices take agent releases automatically; one device can be updated
now; the supervisor and fleetd follow the agent through the same staged waves; a device can be removed from Paddock
in two well-defined ways that never leave it without an administrator or an unbootable disk; laptops are not
"presumed lost" after a week of holidays; and new installations unlock their disk with TPM2 + PIN or TPM only, as
the policy of their device group says.

## 2. Context (verified in the code on 2026-10-17, `main` at `ecfaad0`)

- **Agent update path.** `server/internal/app/agentreleases.go::EvaluateRollouts` publishes one platform-wide
  `agentrelease.Offer` to Valkey `ar:current` (`devicecache/rollout.go`); the gateway's `agentUpdate`
  (`server/internal/transport/http/device/handlers.go:306`) calls `offer.For(dev.id, req.Arch, req.AgentVersion)`
  (`domain/agentrelease/agentrelease.go:233`: artifact for the arch, newer by SemVer, bucket inside the wave) and
  answers `protocol.AgentUpdate{Version, URL, SHA256, Size, Minisig}`. The agent (`agent/internal/agent/updates.go::handleUpdate`)
  stages every offer unless it runs that version, that version failed before (`state.FailedUpdateVersion`) or a
  request is pending; `update.Stage` writes `/var/lib/paddock/staging/<version>/paddockd(.minisig)` and
  `request.json`, then signals the supervisor (SIGUSR1). The supervisor (`agent/internal/supervisor/supervisor.go`)
  verifies, installs into the inactive slot, self-tests, flips, runs a 10-minute probation and writes
  `update-result.json`; `reportUpdate` turns it into `agent.updated|update_failed|rolled_back`.
- **Packages on the device.** fleetd: `agent/internal/reconcile/inventory.go` downloads
  `bundle.Inventory.Package{Version, URLPath, SHA256}` from `https://bundles.<domain>/<url_path>` into
  `/var/lib/paddock/packages/`, checks the SHA-256 and runs `dpkg -i` through the bounded package path
  (`reconcile.OS.DpkgWithin`, 15 min, process-group kill). The compiler renders it from `FleetdPackage(arch)`
  (`compiler/inventory.go`, amd64 only). Packages of a release: `agent_package` (migration 00015), object keys
  `packages/<version>/<name>_<version>_<arch>.deb`, public-read. The supervisor package is in every release
  (`agentrelease.RequiredPackages`), installed by the autoinstall or by hand only; its postinst restarts
  `paddock-supervisor.service` (`packaging/scripts/supervisor-postinst.sh`), whose cgroup contains the agent
  (`KillMode=mixed`).
- **Commands.** `pkg/command` (closed registry `lifetimes`, `Verify` with `DisallowUnknownFields`); the api issues
  through `app.issueCommand`; the worker signs and publishes to `cmd:<device_id>` (`worker/commands.go`); the agent
  executes through `agent/internal/commands` (handlers map in `agent/internal/agent/agent.go:New`, executed IDs kept
  60 days), results posted by `postResults`. `device_command.status` admits `cancelled` (migration 00011), but no
  use case cancels a command today.
- **Device events.** `pkg/protocol.EventTypes` is closed; the gateway rejects a batch with an unknown type (ADR 0024).
  `app/devicereports.go::eventEntry` maps a type to an audit code, copies the allow-listed params
  (`audit.deviceEventParams`) and updates `agent_update_report`, `device_status.login_state`, escrow activation in
  the claim. `session.login` is not audited: `sessionLoginEntry` upserts `device_user_seen`.
- **Sessions on the device.** `agent/internal/agent/sessions.go::trackSessions` polls `loginctl` every 10 s and
  reports `session.login{username, at}` once per user and 24 h (`state.SessionsReported`, `sessions.NewLogins`).
- **Staleness.** `app/staleness.go::Evaluate` reads `LoadUpdateSettings` once per organization and
  `ListStalenessCandidates` (`queries/staleness.sql`), computes `updates.StaleLevel(last, now, warning, critical,
  unit)` per device and records transitions through `RecordOnce`; `PADDOCK_STALENESS_UNIT=minute` in development.
  The contact state (`paddock_device_contact`, migration 00043) derives from the open alert, not from thresholds.
- **Device groups.** `device_group(id, organization_id, name, description, created_at, updated_at)` (migration
  00001); `app/devicegroups.go` (`Create`, `Update`, `Delete`, specs `SpecDeviceGroup*`); `DeviceGroupCreate` /
  `DeviceGroupUpdate` schemas in `api/openapi/admin.yaml:3838`; `components/DeviceGroupForm.vue`,
  `views/DeviceGroupDetail.vue`.
- **Devices.** `device` (migration 00003; later columns `logins_suspended`, `presumed_lost_at` on `device_status`,
  `login_state`, `schema_versions`, `version_key`); `app/devices.go` (`DeviceDetail`, `TransitionDevice`,
  `SetGroups` with the root-grant guard); `domain/device` (states, `Transition`); the portal frame
  `views/DeviceDetail.vue`, `components/DeviceHeader.vue` (primary actions), `views/DeviceOverview.vue` (identity
  facts, groups, cards, `DangerZone.vue`), `components/DeviceTabs.vue` (tabs `device`, `device-software`,
  `device-vulnerabilities`, `device-access`, `device-configuration`, `device-commands`, `device-audit`),
  `lib/deviceDetailPage.ts` (`useDeviceDetailPage`: `load`, `run`, `confirmation`, step-up resume pattern),
  `lib/devices.ts` (`runDeviceAction`, `actionsFor`).
- **Disk.** `pkg/protocol.DiskHealth{State, LUKSVersion, Tokens, Keyslots, Volumes, Unresolved}`, `DiskStates`
  (closed, ordered); `agent/internal/reconcile/luks.go` (`compliantKeyslots`, `state`, `step`, `removePassphrase`);
  `agent/internal/disksetup` (`Run`, `minPINLength` from `/etc/paddock/disk-setup.json`); `agent/internal/luks`
  (`EnrollTPM2PIN`, `EnrollRecovery`, `WipeSlot`, `TPM2Present`); `server/internal/autoinstall` (`Input.BootPINMinLength`
  → `disk-setup.json`), `app/autoinstall.go::Generate` (`GetLoginSettings`, token → device group through
  `enrollmentConfig`); `app/disk.go` (`Get`, `RevealRecoveryKey`, `confirmedEscrow` with typed hostname);
  `components/DiskEncryptionCard.vue`; attention `disk_not_compliant` (view `attention_condition`, migration 00026,
  state ≠ `compliant`).
- **Inventory.** `ports.Inventory`, `ports.HostInventory{OSVersion, AgentVersion, LastSeenAt, Software, Policies}`;
  `adapters/fleet/hosts.go::host` (the Fleet host JSON as far as read); `app/inventory.go::StoreHost`
  (`UpsertInventoryRef`); `device_inventory_ref` (migration 00024); acceptance helper `test/acceptance/fleethost.go`.
- **Settings.** `organization_login_settings` (migration 00007 + `boot_pin_min_length` 00016, `local_admin_*`,
  `notice_text`), `app/loginsettings.go`, `views/LoginSettings.vue`; `organization_update_settings` (00025),
  `app/updates.go`, `views/UpdateSettings.vue`; `domain/updates.Settings` with `Validate`.
- **Gates.** `test/acceptance` (helpers `login`, `steppedUpTempUser`, `stepUp`, `expectOneEvent`, `activeDevice`,
  `devicesim.Device{Checkin, Fetch, SendEvents}`, `portal.NewAuditIndex`, `fleethost.go`); `test/system`
  (`Install`, `Device.WaitEvent`, `Stack.Release/Rollout/Call`, `VM.PowerOff/Restore/Start/Must`, `vmGroup`,
  `autoinstall.go` for throwaway VMs); build tags for broken agents in `agent/internal/buildinfo`
  (`paddock_testbroken_selftest`, `paddock_testbroken_probation`).
- **Migrations.** `server/migrations/paddock/NNNNN_name.sql`, goose, forward-only; last on `main`: 00048. Every new
  organization table: `ENABLE` and `FORCE ROW LEVEL SECURITY`, policy on `current_setting('paddock.org_id')::uuid`
  without `missing_ok`, grants per role. Audit codes: closed registry `server/internal/domain/audit/codes.go`,
  `make gen` regenerates `docs/compliance/audit-codes.md` and `server/web/src/lib/auditCodes.gen.ts`.

## 3. Binding decisions

### 3.1 Device owners (L34, PDK-220)

1. Migration `device_owners` (next free number):

   ```sql
   CREATE TABLE device_owner (
     organization_id uuid NOT NULL, device_id uuid NOT NULL, user_id uuid NOT NULL,
     assigned_at timestamptz NOT NULL DEFAULT now(), assigned_by uuid,
     PRIMARY KEY (device_id, user_id),
     FOREIGN KEY (organization_id, device_id) REFERENCES device (organization_id, id),
     FOREIGN KEY (organization_id, user_id) REFERENCES app_user (organization_id, id) ON DELETE CASCADE
   );
   CREATE INDEX device_owner_user_idx ON device_owner (organization_id, user_id);
   -- RLS tenant for paddock_api (SELECT, INSERT, DELETE); paddock_worker SELECT (retention, later).
   ```

2. `app.Devices.SetOwners(ctx, deviceID uuid.UUID, userIDs []uuid.UUID) (DeviceDetail, error)`: `ActionSpec{Code:
   audit.CodeDeviceOwnersChanged, AllowedRoles: RolesWrite}`, target the device (hostname as display), params
   `hostname`, `added`, `removed` (usernames, sorted), `owners` (usernames after the change, sorted). At most 20
   owners (400 `invalid_request` above); an unknown or foreign user → 400 `invalid_request` with
   `unknown user <id>` (as `Logins.SetAssignment` does). Duplicates are collapsed. No recompile (owners are not in
   the bundle). `DeviceDetail` gains `Owners []pgstore.AppUser`; `loadDeviceDetail` loads them (`ListDeviceOwners`).
3. Device list: `DeviceQuery.OwnerID *uuid.UUID` (filter `owner_id`); the search `q` additionally matches the
   owners' `username` and `display_name` (`EXISTS` subquery in `ListDevices`/`CountDevices`). `ListDevicesRow` gains
   `owner_usernames text[]` (aggregated, for the list column).
4. `GET /api/v1/users/{id}/devices` (list contract, tag `users`, roles `RolesRead`, sort allow list `hostname`,
   `-hostname`, `last_contact_at`, `-last_contact_at`, default `hostname`; `x-paddock-list`): the devices the user
   owns, as `DevicePage`. Unknown or foreign user → 404.
5. Portal: `views/DeviceOverview.vue` gets a panel *Owners* (`devices.owners.title`) under the identity panel with a
   `v-autocomplete` of users (`allUsers()`, chips) and *Save* for writers, read-only chips otherwise, each chip a link
   to the user. `views/Devices.vue` gets a column *Owners* (`devices.owners.column`, usernames joined with `, `,
   not sortable) and the filter `owner_id` (`DataList` filter with the user autocomplete). `views/UserDetail.vue`
   gets a `DataList` *Devices owned* (`users.ownedDevices.title`) over the new endpoint.

### 3.2 Hardware facts from Fleet (L12, PDK-221)

6. `ports.HostInventory` gains `Hardware HostHardware` with

   ```go
   // HostHardware are the asset facts of a host (ADR 0037 decision 7): empty strings and zero values when the
   // inventory system does not report them.
   type HostHardware struct {
       Vendor, Model, Serial, CPUBrand string
       CPUCores                        int
       MemoryBytes, DiskTotalBytes     int64
   }
   ```

   `adapters/fleet/hosts.go::host` gains `HardwareVendor string json:"hardware_vendor"`, `HardwareModel string
   json:"hardware_model"`, `HardwareSerial string json:"hardware_serial"`, `CPUBrand string json:"cpu_brand"`,
   `CPUPhysicalCores int json:"cpu_physical_cores"`, `Memory int64 json:"memory"`, `GigsTotalDiskSpace float64
   json:"gigs_total_disk_space"`; `HostInventory` fills `Hardware` (`DiskTotalBytes = round(gigs × 1e9)`; every
   string trimmed and cut at 128 runes). The adapter MUST NOT read `gigs_disk_space_available`,
   `percent_disk_space_available`, `uptime`, `primary_ip`, `primary_mac`, `public_ip`.
7. Migration `inventory_hardware`: `ALTER TABLE device_inventory_ref ADD COLUMN hardware_vendor text NOT NULL
   DEFAULT '', ADD COLUMN hardware_model text NOT NULL DEFAULT '', ADD COLUMN hardware_serial text NOT NULL DEFAULT
   '', ADD COLUMN cpu_brand text NOT NULL DEFAULT '', ADD COLUMN cpu_cores int NOT NULL DEFAULT 0, ADD COLUMN
   memory_bytes bigint NOT NULL DEFAULT 0, ADD COLUMN disk_total_bytes bigint NOT NULL DEFAULT 0;` plus
   `CREATE INDEX device_inventory_ref_org_serial_idx ON device_inventory_ref (organization_id, hardware_serial);`.
   `UpsertInventoryRef` writes them; `StoreHost` passes `inv.Hardware`.
8. API: `Device` gains `hardware` (object `DeviceHardware{vendor, model, serial, cpu_brand, cpu_cores,
   memory_bytes, disk_total_bytes}`, nullable: `null` while no inventory row exists). The device search `q` also
   matches `hardware_serial` (prefix, case-insensitive). The device list and detail read it through a `LEFT JOIN
   device_inventory_ref`.
9. Portal: the identity panel of `DeviceOverview.vue` gains the rows *Manufacturer*, *Model*, *Serial number*,
   *Processor*, *Memory*, *Disk size* (`devices.hardware.*`; memory and disk formatted with `Intl.NumberFormat`
   in GiB / GB with one decimal; `–` when null or empty). `docs/compliance/privacy.md` §"What Paddock stores of it"
   gains the row for `device_inventory_ref` hardware facts and the sentence "Free disk space, uptime and network
   addresses stay in Fleet" replaces the current sentence (§3.14).

### 3.3 Staleness thresholds per device group (L27, PDK-222)

10. Migration `device_group_policies` (one migration for this section, §3.5 and §3.9):

    ```sql
    ALTER TABLE device_group
      ADD COLUMN staleness_warning_h int CHECK (staleness_warning_h BETWEEN 1 AND 720),
      ADD COLUMN staleness_critical_h int CHECK (staleness_critical_h <= 2160),
      ADD COLUMN agent_update_policy text CHECK (agent_update_policy IN ('automatic','manual')),
      ADD COLUMN disk_unlock_mode text CHECK (disk_unlock_mode IN ('tpm_pin','tpm_only')),
      ADD CONSTRAINT device_group_staleness_pair CHECK ((staleness_warning_h IS NULL) = (staleness_critical_h IS NULL)),
      ADD CONSTRAINT device_group_staleness_order CHECK (staleness_critical_h IS NULL OR staleness_critical_h > staleness_warning_h);
    ```

11. `DeviceGroupCreate` / `DeviceGroupUpdate` gain `staleness` (object `{warning_h: integer, critical_h: integer}`,
    nullable; `null` clears both), `agent_update_policy` (enum, nullable) and `disk_unlock_mode` (enum, nullable);
    `DeviceGroup` returns the three. `app.DeviceGroups.Create/Update` validate (same bounds as the organization
    settings; 400 `invalid_request` with the field name) and record the params `staleness_warning_h`,
    `staleness_critical_h`, `agent_update_policy`, `disk_unlock_mode` (null when unset) on `device_group.created`
    and `device_group.updated`; a change of `agent_update_policy` or `disk_unlock_mode` calls
    `rec.StateChanged(statechange.ScopeDeviceGroup, id)` (the compiler re-renders the members); a staleness change
    does not (the worker reads the table).
12. `ListStalenessCandidates` gains the columns `group_warning_h int`, `group_critical_h int` = `max(...)` over the
    device's groups whose values are set (NULL when none). `app.Staleness.Evaluate` MUST use, per device, the pair
    `(group_warning_h, group_critical_h)` when both are set, else the organization's; `transition` records the params
    `threshold_h`, `source` (`organization` | `device_group`) — the claim re-reads the pair the same way (helper
    `stalenessThresholds(c, settings) (warning, critical int, source string)` in `app/staleness.go`).
13. Portal: `DeviceGroupForm.vue` gains a section *Contact thresholds* (`deviceGroups.staleness.title`) with a
    switch *Override the organization's thresholds* (`deviceGroups.staleness.override`), two number fields in hours
    (`deviceGroups.staleness.warning`, `.critical`) and a button *Laptop preset (5 days / 35 days)*
    (`deviceGroups.staleness.laptopPreset`) that fills 120 and 840; the help line `deviceGroups.staleness.hint`.
    `DeviceGroupDetail.vue` shows the effective pair with the source. `UpdateSettings.vue` gets the help line
    `updateSettings.staleness.groupsHint` under the thresholds.

### 3.4 Login history (L35, PDK-223 server, PDK-224 agent and portal)

14. Migration `login_history`:

    ```sql
    ALTER TABLE organization_login_settings
      ADD COLUMN login_history_enabled boolean NOT NULL DEFAULT false,
      ADD COLUMN login_history_days int NOT NULL DEFAULT 90 CHECK (login_history_days BETWEEN 7 AND 365);
    CREATE TABLE device_login_event (
      id uuid PRIMARY KEY, organization_id uuid NOT NULL, device_id uuid NOT NULL REFERENCES device(id),
      username text NOT NULL, at timestamptz NOT NULL,
      UNIQUE (device_id, username, at),
      FOREIGN KEY (organization_id, device_id) REFERENCES device (organization_id, id)
    );
    CREATE INDEX device_login_event_device_at_idx ON device_login_event (organization_id, device_id, at DESC);
    CREATE INDEX device_login_event_org_at_idx ON device_login_event (organization_id, at);
    -- RLS tenant for paddock_api (SELECT, DELETE) and paddock_worker (SELECT, INSERT, DELETE).
    ```

15. `LoginSettings` (API and `domain/loginsettings`) gain `login_history_enabled`, `login_history_days`.
    `PUT /api/v1/settings/login` (`org_admin`, existing spec `settings.login_changed`) records both as params;
    switching `login_history_enabled` from true to false deletes every `device_login_event` row of the organization
    in the same transaction and records `login_history_deleted` (the count). Enabling or changing the days calls
    `rec.StateChanged(statechange.ScopeOrg, org)` (the bundle flag of decision 17 changes).
16. `app/devicereports.go::sessionLoginEntry` MUST, when the organization's `login_history_enabled` is true, insert
    `device_login_event{id: uuidv7, username, at}` with `ON CONFLICT DO NOTHING` after the `device_user_seen` upsert,
    in the same claim. The settings are read once per `RecordEvents` call (`GetLoginSettings`), not per event.
17. `pkg/bundle.LoginSpec` gains `ReportEverySession bool json:"report_every_session,omitempty"`; the compiler sets it
    from the organization's `login_history_enabled`. The agent's `trackSessions` MUST, when the applied bundle's
    login spec has `ReportEverySession`, report one `session.login` per logind session (dedupe key
    `<username>\x00<session id>` in `state.SessionsReported`, entries pruned once the session is gone; otherwise the
    existing once-per-24-h rule). The event data stays `protocol.SessionLogin{Username, At}` (`At` = the session's
    start as `loginctl show-session -p Timestamp` reports it, else now).
18. `GET /api/v1/devices/{id}/logins` (list contract, tag `devices`, roles `RolesRead`, sort allow list `-at`
    (default), `at`, `username`, `-username`; filter `username` (exact, lower-cased); `q` matches `username`;
    tie-breaker `id`): items `DeviceLoginEvent{id, username, at}`. Unknown or foreign device → 404. While the
    history is off the list is empty (200).
19. Worker round `login-history` (`worker/loginhistory.go`, `LoginHistoryInterval = 6 * time.Hour`, leader lock key
    `0x70616464206c6f67` "padd log", same `Round` pattern as `worker/staleness.go`): per organization (`OrganizationIDs`),
    inside `InOrg`, `DELETE FROM device_login_event WHERE ctid IN (SELECT ctid FROM device_login_event WHERE at <
    @cutoff LIMIT 1000)` repeated until 0 rows, cutoff `now − login_history_days`; when at least one row was deleted
    the round records, through `ActionRunner` with the system principal, `retention.purged` with params
    `store: "device_login_event"`, `deleted`, `cutoff`. In development `PADDOCK_RETENTION_UNIT=seconds` counts days
    as seconds (refused by `prod-check` like `PADDOCK_STALENESS_UNIT`; the variable is M10's and is reused, not
    duplicated).
20. Portal: `LoginSettings.vue` gains the section *Login history* (`loginSettings.loginHistory.title`) with the
    switch, the days field and the privacy notice `loginSettings.loginHistory.notice` (always visible, `v-alert`
    type `info`); turning it off opens `ConfirmDialog` with `loginSettings.loginHistory.disableConfirm` (destructive:
    the rows are deleted). `DeviceTabs.vue` gains the tab `device-logins` (`devices.tabs.logins`, after
    `device-access`), view `views/DeviceLogins.vue`: a `DataList` over decision 18 with the columns *User*, *Signed
    in*; while the history is off it shows the empty state `devices.logins.off` with a link to the settings for
    administrators.

### 3.5 Agent update policy (L32, PDK-225)

21. Migration `agent_update_policy`: `ALTER TABLE organization_update_settings ADD COLUMN agent_update_policy text
    NOT NULL DEFAULT 'automatic' CHECK (agent_update_policy IN ('automatic','manual'));` (the device-group column is
    in decision 10). `UpdateSettings` (API, `domain/updates.Settings`) gain `agent_update_policy`; `settings.updates_changed`
    records it. Constants `updates.UpdatePolicyAutomatic = "automatic"`, `updates.UpdatePolicyManual = "manual"`.
22. `pkg/bundle.AgentCfg` gains `UpdatePolicy string json:"update_policy,omitempty"` (absent = `automatic`). The
    compiler sets it on v2 bundles: `manual` when the organization's policy is `manual` or any of the device's
    groups overrides with `manual`; `automatic` when a group overrides with `automatic` and the organization is
    `manual`; else absent. `ContentSHA256` covers it (a policy change publishes a new version).
23. Agent: `handleUpdate` MUST return without staging when `a.current != nil && a.current.Agent.UpdatePolicy ==
    bundle.UpdatePolicyManual && !offer.Requested`, logging once per offered version at info level
    `agent update offer ignored by the organization's policy`. The same gate applies to the supervisor package
    (decision 30) and to the fleetd package install in `reconcile.Inventory` (a new field
    `Inventory.UpdatesAllowed func() bool`, true when the policy is automatic or an update was requested since the
    last check-in; fleetd is still *installed* when it is missing, the policy only blocks *upgrades*).
24. Portal: `UpdateSettings.vue` gets the section *Agent updates* (`updateSettings.agentUpdates.title`) with a radio
    group (`updateSettings.agentUpdates.automatic`, `.manual`) and the hint `updateSettings.agentUpdates.hint`;
    `DeviceGroupForm.vue` gets the select *Agent updates* (`deviceGroups.agentUpdates.label`: inherit / automatic /
    manual). `paddockctl`'s declarative document (`api/schema/paddock.v1.json`, section `settings.updates`) gains
    `agent_update_policy` through the existing update-settings use case (ADR 0011).

### 3.6 Update now (L32, PDK-226)

25. Migration `agent_update_request`: `ALTER TABLE device ADD COLUMN agent_update_requested_version text,
    ADD COLUMN agent_update_requested_at timestamptz; ALTER TABLE device_status ADD COLUMN arch text NOT NULL
    DEFAULT '';` The heartbeat (`ingest.Heartbeat`) gains `Arch string`; the gateway copies `req.Arch`; the worker's
    heartbeat materialization writes `device_status.arch`.
26. `POST /api/v1/devices/{id}/update-agent` (tag `devices`, `x-paddock-audit: device.agent_update_requested`,
    `ActionSpec{AllowedRoles: RolesWrite}`, no step-up, no body, 200 `Device`, 404, 409 `invalid_state`):
    `app.AgentUpdates.RequestNow(ctx, deviceID)` (new file `app/agentupdates.go`):
    - locks the device; state must be `active` (409 `invalid_state`, detail `only active devices can be updated`);
    - reads the current offer from the platform pool (`AgentReleases.offer` exposed as `CurrentOffer(ctx)`; nil or
      `halted` → 409 `invalid_state`, detail `no agent release is being offered`);
    - `device_status.agent_version` must be older than the offer's version by `semver.Compare` (or no semantic
      version) → else 409 `invalid_state`, detail `the device already runs <version>`; when `device_status.arch` is
      set and the offer has no artifact for it → 409 `invalid_state`, detail `no artifact for <arch>`;
    - sets `agent_update_requested_version = offer.Version`, `agent_update_requested_at = now()`; params
      `hostname`, `version`, `from_version`.
    The existing `device_cache_notify` trigger fires on the update; the worker's cache sync (`worker/cachesync.go`)
    MUST write Valkey `au:<device_id>` = `{"version": …, "requested_at": …}` with `PX` = `24 h − (now −
    requested_at)` when both columns are set and the request is younger than 24 h, and delete the key otherwise;
    `paddock-server admin rebuild-cache` rebuilds it.
27. `agentrelease.Offer.For` gains a parameter `requested bool`: when true the wave check is skipped (the halt
    check and the version check stay). `devicecache.Cache` gains `UpdateRequest(ctx, deviceID) (version string,
    requestedAt time.Time, ok bool, err error)`. The gateway's `agentUpdate` reads it, passes `requested = ok &&
    version == offer.Version` and sets `protocol.AgentUpdate.Requested bool json:"requested,omitempty"` and
    `RequestedAt *time.Time json:"requested_at,omitempty"`.
28. Agent: `state.State` gains `UpdateRequestHandledAt *time.Time json:"update_request_handled_at,omitempty"`.
    `handleUpdate` MUST treat an offer with `Requested` whose `RequestedAt` is after `UpdateRequestHandledAt` as a
    fresh request: it ignores the policy (decision 23) and `FailedUpdateVersion` once, stages, signals, and records
    `UpdateRequestHandledAt = RequestedAt`. A requested offer that is not newer than the handled one follows the
    normal rules.
29. *(Amended 2026-10-18, §15.1: the request stays open after `agent.updated` while the supervisor or fleetd is outdated.)* Clearing: the claim of `eventEntry` for `agent.updated`, `agent.update_failed` and `agent.rolled_back` MUST set
    both request columns to NULL when `params.version` equals `agent_update_requested_version` (query
    `ClearAgentUpdateRequest(device_id, version)`); the worker's command round (`worker/commands.go::Round`) MUST
    also clear requests older than 24 h (`ExpireAgentUpdateRequests(before)`), unaudited. `Device` (API) gains
    `agent_update_requested_version` (nullable) and `agent_update_requested_at` (nullable); `DeviceHeader.vue` gets
    the primary action *Update agent now* (`devices.updateAgent.label`, writers, active devices only) behind a
    non-destructive `ConfirmDialog` (`devices.updateAgent.title`, `.confirm`), the status line
    `devices.updateAgent.requested` while a request is open, and the problem texts for the 409 details.

### 3.7 Supervisor package updates (L32, PDK-227)

30. *(Amended 2026-10-18, §15.2: rendered while the rollout runs or completed, per device once its wave is reached.)* `pkg/bundle.AgentCfg` gains `SupervisorPackages map[string]PackageRef json:"supervisor_packages,omitempty"`
    keyed by arch, with `type PackageRef struct { Version string; URLPath string; SHA256 string }` (JSON
    `version`, `url_path`, `sha256`; `bundle.InventoryPackage` is left as it is). The compiler (new
    `compiler/supervisor.go`) renders, on v2 bundles only, the `paddock-supervisor` packages of the **current
    release** (`CurrentAgentRollout` with status `completed`; nothing while it is `halted` or no rollout completed)
    for every arch that has one (query `SupervisorPackages(version)` over `agent_package`). Nothing is rendered for
    a device whose last reported `agent_version` is not a semantic version (there is no release to follow).
31. Agent: `agent/internal/supervisorpkg/supervisorpkg.go` with

    ```go
    // Plan decides whether the supervisor package of the bundle is installed on this device (ADR 0037 decision 3):
    // the policy allows updates (automatic, or requested since the last check-in), the agent runs the package's
    // release (buildinfo.Version == ref.Version), dpkg reports an older paddock-supervisor version, no upgrade is in
    // progress and the version did not fail before.
    func Plan(ref bundle.PackageRef, installed string, policyAllows bool, failed string, inProgress bool) (install bool, reason string)
    // Stage downloads the package to <packages>/paddock-supervisor_<version>_<arch>.deb and checks its SHA-256.
    func Stage(ctx context.Context, download func(ctx context.Context, url string, max int64) ([]byte, error), l paths.Layout, url string, ref bundle.PackageRef) (path string, err error)
    // Launch starts the transient unit paddock-supervisor-upgrade.service (systemd-run --unit … --collect
    // --no-block --property=KillMode=process <current>/paddockd supervisor-upgrade --deb <path> --from <installed>)
    // and writes <state>/supervisor-upgrade.json {version, from_version, started_at}.
    func Launch(ctx context.Context, run func(ctx context.Context, name string, args ...string) error, l paths.Layout, deb, version, from string) error
    ```

    `paddockd supervisor-upgrade --deb <path> --from <version>` (new subcommand, root only, runs inside the
    transient unit): copies `/usr/sbin/paddock-supervisor` and `/usr/lib/systemd/system/paddock-supervisor.service`
    to `/var/lib/paddock/packages/supervisor-backup/`, runs `dpkg -i <path>` with `DEBIAN_FRONTEND=noninteractive`
    (killed with its process group after 15 min; the postinst restarts the supervisor, which stops the agent that
    launched the unit — the unit survives because it is outside the supervisor's cgroup), then waits up to 10 min
    for `/run/paddock/last-checkin` with an mtime after `started_at`. Outcome `updated` when it arrives;
    `install_failed` when dpkg failed (the backup is restored only if `paddock-supervisor.service` is not active
    afterwards); `rolled_back` when the check-in mark does not arrive: the backup binary and unit file are copied
    back, `systemctl daemon-reload && systemctl restart paddock-supervisor.service`. It writes
    `<state>/supervisor-upgrade-result.json {version, from_version, outcome, at}` and removes `supervisor-upgrade.json`.
32. *(Amended 2026-10-18, §15.3: `rolled_back_unreachable` is retried, not failed.)* The agent's run loop (`Cycle`, after `reportUpdate`): `reportSupervisorUpgrade` turns the result into the event
    `agent.supervisor_updated{version, from_version, outcome}` once (`state.ReportedSupervisorUpgradeAt`), sets
    `state.FailedSupervisorVersion` on `install_failed` and `rolled_back`, and removes the result once the spool is
    empty (as `clearUpdateResult`). A `supervisor-upgrade.json` older than 30 min without a result counts as
    `install_failed` (the helper died). The health report gains `SupervisorVersion string json:"supervisor_version"`
    (output of `/usr/sbin/paddock-supervisor version`, refreshed per check-in; "" when unreadable).
33. *(Amended 2026-10-18, §15.2: failed outcomes count toward the rollout's threshold.)* Server: `protocol.EventAgentSupervisorUpdated = "agent.supervisor_updated"` with the outcomes
    `SupervisorOutcomeUpdated = "updated"`, `SupervisorOutcomeInstallFailed = "install_failed"`,
    `SupervisorOutcomeRolledBack = "rolled_back"`; `eventCodes` maps it to `device.supervisor_updated`, and
    `eventEntry` switches to `device.supervisor_update_failed` for the other two outcomes (the ADR 0024 pattern).
    `audit.deviceEventParams` gains nothing (`version`, `from_version`, `outcome` are allow-listed already). The
    outcome does not count toward any rollout threshold. `Device` (API) gains `supervisor_version` (nullable, from
    health); the identity panel shows it (`devices.supervisorVersion`); the release detail of the portal
    (`AgentReleaseDetail.vue`) notes `agentReleases.supervisorFollows` under the packages list.
34. Test build tag `paddock_testbroken_supervisor` in `agent/internal/buildinfo` (`BrokenSupervisor bool`): a
    supervisor built with it exits 1 twenty seconds after start, so the gate of §9 S-UP2 sees a rollback. `make deb`
    passes `TAGS` to the supervisor build too; `make agent-release` and `make release-packages` refuse it like the
    other test tags.

### 3.8 Uninstall (L33, PDK-228 server, PDK-229 agent, PDK-230 gates and runbook)

35. `pkg/command`: `TypeUninstall = "uninstall"`, lifetime 7 days, with

    ```go
    // Uninstall modes (ADR 0037 decision 4).
    const (
        UninstallLeave = "leave" // remove Paddock, keep everything else working
        UninstallReset = "reset" // remove Paddock, Himmelblau, managed files and the managed local administrator
    )
    // UninstallParams are the params of uninstall.
    type UninstallParams struct {
        Mode           string `json:"mode"`
        ClearTPM       bool   `json:"clear_tpm,omitempty"`        // reset only
        KeepLocalAdmin bool   `json:"keep_local_admin,omitempty"` // reset only
    }
    // UninstallAccepted is the command result the agent posts before it starts the removal.
    type UninstallAccepted struct {
        Accepted bool   `json:"accepted"`
        Reason   string `json:"reason,omitempty"` // when not accepted: invalid_params, revocation_pending, helper_failed
    }
    ```

36. Migration `uninstall`: `ALTER TABLE device ADD COLUMN uninstall_requested_at timestamptz, ADD COLUMN
    uninstall_mode text CHECK (uninstall_mode IN ('leave','reset')), ADD COLUMN uninstall_command_id uuid,
    ADD COLUMN uninstalled_at timestamptz, ADD COLUMN retired_reason text;` plus `CREATE INDEX
    device_org_uninstall_idx ON device (organization_id) WHERE uninstall_requested_at IS NOT NULL AND uninstalled_at
    IS NULL;` and the attention view extended by

    ```sql
    UNION ALL
    SELECT 'uninstall_pending', d.id, d.hostname, d.uninstall_requested_at, d.uninstall_mode || ':' || c.status
    FROM device d JOIN device_command c ON c.id = d.uninstall_command_id
    WHERE d.state = 'active' AND d.uninstall_requested_at IS NOT NULL AND d.uninstalled_at IS NULL
    ```

    (recreate the view as migration 00042 did; `paddock_api` gets `UPDATE (status, finished_at, result)` on
    `device_command` for the cancel of decision 38 — no: the cancel runs in the api role, so grant
    `UPDATE (status, finished_at)` on `device_command` to `paddock_api`).
37. `POST /api/v1/devices/{id}/uninstall` (tag `devices`, `x-paddock-audit: device.uninstall_requested`, body
    `DeviceUninstallRequest{mode (enum leave|reset, required), confirm_hostname (required), reason (2–500,
    required), clear_tpm (bool, default false), keep_local_admin (bool, default false)}`, 200 `Device`, 403
    `step_up_required|forbidden`, 404, 409 `invalid_state|tpm_in_use_by_disk`, 422 `invalid_request`):
    `app.Uninstalls.Request(ctx, deviceID, in UninstallInput)` (new `app/uninstall.go`), `ActionSpec{AllowedRoles:
    RolesAdmin, RequiresStepUp: true}`, params `hostname`, `mode`, `clear_tpm`, `keep_local_admin`, `reason`,
    `command_id`:
    - locks the device; state `active` else 409 `invalid_state`; `confirm_hostname` equals the hostname else 422
      `invalid_request` (detail `confirm_hostname does not match`, as the reveal does);
    - an open uninstall (`uninstall_requested_at IS NOT NULL AND uninstalled_at IS NULL`) → 409 `invalid_state`
      (detail `an uninstall is already requested`);
    - an open revocation request (`revocation_request.status IN ('requested','approved','issued','delivered')`) →
      409 `invalid_state` (detail `a lock or destroy is pending for this device`);
    - `clear_tpm` or `keep_local_admin` with mode `leave` → 422 `invalid_request`;
    - `clear_tpm` while the last health report lists any volume with a token `tpm2` or `tpm2+pin` (`diskHealth`,
      root tokens and `Volumes[].Tokens`) → 409 `tpm_in_use_by_disk` (new problem code, status 409, detail `the
      disk unlocks with the TPM; clearing it would leave only the recovery key`);
    - issues the command (`issueCommand`, type `uninstall`, params of decision 35) and sets the four columns.
38. `POST /api/v1/devices/{id}/uninstall/cancel` (`x-paddock-audit: device.uninstall_cancelled`, `RolesAdmin`, no
    step-up, 200 `Device`, 404, 409 `invalid_state`): allowed while the command's status is `pending`, `failed` or
    `expired` (409 with detail `the device already received the command` for `delivered`, `the uninstall completed`
    for `succeeded`); sets the command `cancelled` (`finished_at = now()`), clears the four columns, and the worker's
    command round removes a cancelled command from `cmd:<device_id>` (query `ListCancelledDeviceCommands(since)`,
    `cache.DeleteCommand`). Params `hostname`, `command_id`, `mode`.
39. Agent handler (`agent/internal/agent/uninstall.go`): on the verified command it validates the params (unknown
    mode → `failed {reason: invalid_params}`), refuses while a revocation envelope was handed to `paddock-revoke`
    within the last 24 h (`state.HandedRevocations`) with `failed {reason: revocation_pending}`, writes the plan
    `/run/paddock/uninstall/plan.json {command_id, mode, clear_tpm, keep_local_admin, device_id, event_seq_base,
    requested_at}` (0600) and copies the running binary to `/run/paddock/uninstall/paddockd` (0700), stores
    `state.PendingUninstall{CommandID}` and returns `succeeded {accepted: true}`. In `Cycle`, after `postResults`
    returned and the result of that command is no longer in `state.CommandResults`, the agent launches
    `systemd-run --unit=paddock-uninstall --collect --no-block --property=KillMode=process
    /run/paddock/uninstall/paddockd uninstall --plan /run/paddock/uninstall/plan.json` once and records
    `state.PendingUninstall.LaunchedAt`. A launch failure is reported as the final event with
    `outcome: helper_failed` and the pending mark is cleared (the administrator cancels and retries).
40. `paddockd uninstall --plan <file>` (new `agent/internal/uninstall/uninstall.go`, root only, runs inside the
    transient unit, never from the supervisor), steps in this order, each recorded in `steps` of the final event as
    `done | skipped | failed:<message>`; a failed step never stops the following ones except where stated:
    1. `systemctl stop paddock-supervisor.service` (stops the agent; `disable` too) and `paddock-updates.timer`,
       `paddock-disk-setup.service`; `systemctl reset-failed` of them.
    2. `apt-mark unhold` of every package in `/var/lib/paddock/state/held-packages`; remove
       `/etc/apt/preferences.d/50paddock`, `/etc/apt/apt.conf.d/52paddock-unattended`,
       `/etc/systemd/system/apt-daily-upgrade.timer.d/50-paddock.conf`,
       `/etc/systemd/system/apt-daily-upgrade.service.d/50-paddock.conf`, `/etc/systemd/system/paddock-updates.service`,
       `/etc/systemd/system/paddock-updates.timer`; `systemctl daemon-reload`.
    3. Remove `/etc/sudoers.d/paddock-u-*` (one `visudo -c` afterwards; a failing check restores the last removed
       file and reports `failed`); remove `/etc/paddock/login-deny`, `/etc/paddock/notice`,
       `/etc/issue.d/90-paddock.issue`, `/etc/ssh/sshd_config.d/90-paddock-banner.conf` (then
       `systemctl try-reload-or-restart ssh.service`), `/etc/dconf/db/gdm.d/90-paddock-notice` (then `dconf update`).
    4. Copy `/var/lib/paddock/quarantine/` to `/root/paddock-uninstall/quarantine/` (0700) when it exists; nothing is
       restored to `/etc/sudoers.d/`.
    5. Mode `reset` only: remove the managed files recorded in `/var/lib/paddock/state/managed.json` whose current
       content hash equals the recorded one (changed files stay; files on paths `policy.ValidatePath` denies stay);
       `systemctl daemon-reload`.
    6. Mode `reset` only: `apt-get remove --purge -y` the packages `himmelblau`, `pam-himmelblau`, `nss-himmelblau`,
       `himmelblau-qr-greeter`, `himmelblau-sshd-config` (the list of `reconcile.himmelblauPackages`), then remove
       `/etc/himmelblau/`, `/var/cache/himmelblau/`, `/var/lib/himmelblau/` (credential and identity caches, never
       home directories), `/etc/apt/sources.list.d/paddock-himmelblau.list`, `/etc/apt/keyrings/himmelblau.gpg`;
       `pam-auth-update --package --remove` of the Himmelblau profiles is left to the packages. Any directory user's
       home directory stays. Mode `leave`: nothing of this.
    7. Mode `reset` only, unless `keep_local_admin`: the **last-administrator guard**: another account in
       `/etc/passwd` with UID in `[1000, 60000)`, a login shell not ending in `nologin` or `false`, a `/etc/shadow`
       hash not starting with `!` or `*`, and membership (primary group or `/etc/group`) in `sudo`, `admin` or
       `wheel` must exist; then `userdel --remove <managed local admin>` and remove
       `/var/lib/AccountsService/users/<name>`; result `local_admin: removed`. Without such an account the account is
       kept: `local_admin: kept_last_admin`. With `keep_local_admin`: `kept`. Mode `leave`: `kept`.
    8. `apt-get remove --purge -y fleet-osquery paddock-revoke paddock-agent paddock-supervisor` (one apt run,
       bounded 15 min; the uninstall helper runs from `/run`, so the removal of its own package is harmless). Then
       remove `/opt/orbit/`, `/etc/paddock/orbit.env`, `/etc/systemd/system/orbit.service.d/`, `/opt/paddock/`,
       `/var/lib/paddock/packages/`, `/var/lib/paddock/staging/`, `/var/lib/paddock/rollback/`,
       `/var/lib/paddock/quarantine/` (copied in step 4).
    9. Mode `reset` with `clear_tpm` only: re-check every LUKS volume of `/etc/crypttab` plus the root volume
       (`luks.Inspect`); any token `tpm2` or `tpm2+pin` → `tpm: skipped_in_use` (nothing is cleared). Otherwise
       `tpm2_clear` (lockout hierarchy, empty auth); on an authorization failure write `5` to
       `/sys/class/tpm/tpm0/ppi/request` → `tpm: requested_at_next_boot` (the firmware asks for confirmation);
       success → `tpm: cleared`; other failure → `tpm: failed`. Without `clear_tpm`: `tpm: not_requested`.
    10. Final report: the helper loads the spool (`/var/lib/paddock/spool/events.jsonl`) and the identity key, sends
        the pending events and then one event `agent.uninstalled{command_id, mode, outcome, local_admin, tpm,
        steps}` with `event_seq = state.EventSeq + 1`, signed as the agent would (`client.Client`, device headers,
        `Paddock-Seq` from the state), retrying with the agent's back-off for at most 30 min; `outcome` is
        `completed` when every step is `done` or `skipped`, else `partial`. Delivered or not, the helper then
        removes `/var/lib/paddock/` and `/etc/paddock/` (`/etc/paddock/revoke-trust.json` and `revoke-enabled` with
        them; the revocation code is untouched), writes a one-line summary to the journal and to
        `/root/paddock-uninstall/result.json` (0600), and exits 0.
    The helper MUST NOT delete anything below `/home/`, `/root/` (except its own directory), `/srv/`, `/var/lib/`
    other than the paths named here, and MUST NOT touch LUKS keyslots, `/etc/crypttab`, `/etc/fstab`, the ESP or
    the boot loader. The quarantine copy and the result stay in `/root/paddock-uninstall/`.
41. Server: `protocol.EventAgentUninstalled = "agent.uninstalled"`; `eventCodes` maps it to `device.uninstalled`
    (actor the device); `audit.deviceEventParams` gains `command_id`, `mode`, `local_admin`, `tpm`, `steps` (the
    steps object is copied as a map of string values, capped at 32 entries). The claim sets
    `device.uninstalled_at = occurred_at` (query `MarkDeviceUninstalled`). After `RecordEvents`, the worker's
    report consumer calls `app.Devices.RetireUninstalled(ctx, deviceID)` (system principal, `RunTx` with
    `SpecDeviceRetire` + param `reason: "uninstalled"`, `TransitionDevice(retire)`, sets `retired_reason =
    'uninstalled'`; idempotent: a device already retired records nothing — `RecordOnce` keyed on `uninstalled_at
    IS NOT NULL AND state = 'active'`). `device.retired` gains the optional param `reason`.
42. Portal (`DangerZone.vue`): a new row *Remove Paddock from this device* (`devices.danger.uninstall.title`,
    `.explanation`, button `.label`) for organization administrators of active devices; the flow is the step-up
    first (`startStepUp('uninstall', deviceId)`), then a dialog component `components/UninstallDialog.vue`
    (built on `ConfirmDialog`'s layout: radio `leave` / `reset` with the explanations `devices.uninstall.leave.*`,
    `devices.uninstall.reset.*`; for `reset` the checkboxes `devices.uninstall.clearTpm.label` (disabled with the
    hint `devices.uninstall.clearTpm.disabledTpmDisk` when the disk state shows a TPM token) and
    `devices.uninstall.keepLocalAdmin.label`; the reason field as for Lock; `requireTypedText: hostname`;
    destructive). While an uninstall is pending the row shows `devices.uninstall.pending` with the mode and the
    command status and a button *Cancel request* (`devices.uninstall.cancel.label`, `ConfirmDialog`
    `devices.uninstall.cancel.*`) when cancellable. A retired device with `uninstalled_at` shows the banner
    `devices.uninstall.done` (mode, time, local administrator and TPM result) in the header meta line. `Device` (API)
    gains `uninstall` (nullable object `{mode, requested_at, command_id, command_status, uninstalled_at,
    local_admin, tpm}`; `local_admin` and `tpm` from the command's result) and `retired_reason` (nullable).
    Attention: kind `uninstall_pending` (label `attention.kinds.uninstall_pending`, severity `warn`, detail the
    `mode:status` string).
43. Runbook `docs/operations/uninstall.md` (PDK-230): both modes step by step as decision 40, what stays, the
    last-administrator guard, the TPM clear and its PPI fallback, cancel, what the retired device shows, and the
    manual steps when the final report never arrived (`/root/paddock-uninstall/result.json`; retire by hand).
    `docs/operations/local-admin.md` gains the paragraph "After an uninstall"; `disk-recovery.md` the sentence that
    uninstall never changes keyslots; `revocation.md` that an uninstall is refused while a revocation is pending.

### 3.9 Disk unlock mode (L30, PDK-231 server, PDK-232 agent)

44. Migration `disk_unlock_mode`: `ALTER TABLE organization_login_settings ADD COLUMN disk_unlock_mode text NOT NULL
    DEFAULT 'tpm_pin' CHECK (disk_unlock_mode IN ('tpm_pin','tpm_only'));` (the group column is in decision 10).
    `LoginSettings` gain `disk_unlock_mode`; `settings.login_changed` records it; a change calls
    `rec.StateChanged(statechange.ScopeOrg, org)`. Constants `disk.UnlockModeTPMPIN = "tpm_pin"`,
    `disk.UnlockModeTPMOnly = "tpm_only"` in a new domain package `server/internal/domain/disk` with
    `EffectiveUnlockMode(org string, groups []string) string` (any group `tpm_pin` → `tpm_pin`; else any group
    `tpm_only` → `tpm_only`; else org).
45. Autoinstall: `autoinstall.Input` gains `UnlockMode string`; `disk-setup.json` becomes `{"boot_pin_min_length":
    n, "unlock_mode": "<mode>"}`; `app.Autoinstall.Generate` resolves the mode from the token's `device_group_id`
    (its override) else the organization; the audit params of `autoinstall.generated` gain `unlock_mode`.
46. `pkg/bundle.Bundle` gains `Disk *DiskSpec json:"disk,omitempty"` with `type DiskSpec struct { UnlockMode string
    json:"unlock_mode" }` (schema v2 only; part of `ContentSHA256`; agents that do not know it ignore it). The
    compiler sets it on every v2 bundle from `EffectiveUnlockMode` over the device's groups.
47. Agent, `disksetup`: `minPINLength` becomes `settings(l) (minLength int, mode string)`; for `tpm_only` `Run`
    prints `introTPMOnly` (below), calls `luks.EnrollTPM2(ctx, tools, device, keyFile)` (new: `systemd-cryptenroll
    --tpm2-device=auto --tpm2-pcrs=7 --unlock-key-file=<file> <device>`), up to `MaxEnrollFailures` attempts, no
    dialogue, no skip; success and failure messages as for the PIN. Console text (English, plain text, binding):

    ```
    Paddock disk encryption setup

    The disk of this device is encrypted and unlocks automatically with the
    security chip (TPM) of this device while Secure Boot stays unchanged.
    No PIN is needed. IT keeps a recovery key for this device.

    Enrolling the TPM unlock. This takes a few seconds ...
    ```

48. Agent, `reconcile.LUKS`: `Tick(ctx, keys, full)` gains the parameter `mode string` (the applied bundle's
    `Disk.UnlockMode`, `tpm_pin` when absent); `compliantKeyslots` becomes `compliantKeyslotsFor(mode) []string`
    (`{recovery, tpm2}` for `tpm_only`, `{recovery, tpm2+pin}` for `tpm_pin`); `state(md, passphrase, mode)`:

    ```
    no tpm2 and no tpm2+pin keyslot and no TPM 2.0        → tpm_missing
    keyslot of the other mode's kind present, none of own → unlock_mode_mismatch
    no keyslot of the own kind                            → tpm_pin_missing
    passphrase, pending, no recovery stored, digest differs, or kinds ≠ compliant set → escrow_pending
    else                                                  → compliant
    ```

    `removePassphrase` requires the keyslot of the mode's kind (`md.Has(kind(mode))`). `protocol.DiskStates` gains
    `DiskUnlockModeMismatch = "unlock_mode_mismatch"` after `DiskTPMPINMissing`; `DiskHealth` gains `UnlockMode
    string json:"unlock_mode,omitempty"` (the mode applied) and `BootSeparate *bool json:"boot_separate,omitempty"`
    (set only in state `not_encrypted`: `findmnt --target /boot --noheadings --output TARGET` equals `/boot`). The
    agent never enrolls or wipes a TPM2 keyslot of an enrolled device.
49. Portal: `LoginSettings.vue` section *Disk encryption* gets the radio *Unlock mode* (`loginSettings.unlockMode.*`)
    with the security notice `loginSettings.unlockMode.tpmOnlyNotice` (`v-alert` type `warning`, visible when
    `tpm_only` is selected); `DeviceGroupForm.vue` the select *Unlock mode* (inherit / TPM + PIN / TPM only);
    `DiskEncryptionCard.vue` shows the applied mode (`devices.disk.unlockMode`) and, for
    `unlock_mode_mismatch`, the hint `devices.disk.states.unlock_mode_mismatch` with a link to
    `docs/operations/disk-recovery.md#changing-the-unlock-mode`. The device list filter `disk_state` and the status
    chips accept the new state (`encryptionStatus` → *Partial*). `docs/operations/disk-recovery.md` gains the section
    "Changing the unlock mode" (the `systemd-cryptenroll` steps with the recovery key for both directions, the
    expected `device.tamper_keyslot_changed` event, the new header escrow).

### 3.10 In-place encryption: deferred (L31, PDK-233)

50. M8d changes no disk. `DiskEncryptionCard.vue` shows, for state `not_encrypted`, the alert
    `devices.disk.notEncrypted.reinstall` and, when `boot_separate` is true, additionally
    `devices.disk.notEncrypted.conversionPlanned`; for `unmanaged`, `devices.disk.unmanaged.reinstall`. The attention
    detail stays the state. `docs/operations/autoinstall.md` gains the section "Encrypting an installed device"
    that says: reinstall with the Paddock autoinstall after a backup; in-place conversion is planned for layouts
    with a separate `/boot` (ADR 0038, milestone M8e); never run `cryptsetup reencrypt` by hand on a Paddock device.
    `preflight` (M11, PDK-153) is not touched; when it exists, its `luks` check names the same sentence (stop
    condition S7).

### 3.11 Documents, residual risks, regression (PDK-234)

51. `docs/architecture.md` amendments (dated 2026-10-17, ADR 0037/0038): §11.2 (supervisor update through the
    bundle's package and the transient unit; the apt sentence is replaced), §11.4 (command `uninstall`, 7 d), §12.1
    (per-group thresholds), §12.4 (unlock modes; "no in-place conversion" → "in-place conversion deferred to M8e,
    ADR 0038"), §16.1 (`device_owner`, `device_login_event`, new columns), §17.1 (new endpoints), §6.7
    (`agent_update.requested`). `docs/operations/agent-releases.md`: the sections "Update policy", "Update now",
    "Supervisor package". `docs/operations/device-login.md`: "Login history". `docs/operations/fleet.md`: the
    hardware facts. `docs/compliance/privacy.md`: §3.14, the `session.login` row ("at most once per user and 24
    hours; every session start while the organization's login history is on"), the new row `device_login_event`,
    the administrator-facing sentence on the works council. `docs/compliance/glossary-de.md`: the terms of §6.6.
    `docs/compliance/residual-risks.md`: RR-44 … RR-53 (§12). `CHANGELOG.md` `[Unreleased]`: one operator-visible
    line per ticket.

## 4. Non-goals

- In-place encryption (ADR 0038 option B3): milestone M8e. Nothing in M8d writes to a LUKS header except what
  M4b already does.
- A Paddock apt repository; updating `paddock-revoke` by any path other than its package (contract 7, 10).
- Starting agent rollouts automatically on publish; maintenance windows for agent updates (open point 2).
- Per-organization WORM retention, the retention rounds of M10 (except the login-history round of decision 19),
  M9 notifications, M11 adoption and report-only (their plans stand).
- Removing user data from a device: never, in any mode.
- The setup wizard (M8g, PDK-200): it surfaces the settings of this plan; it is not built here.
- Any change to `agent/internal/revoke/`, `agent/cmd/paddock-revoke/`, `pkg/revocation`.
- Changes to the device API path (`/v1` stays; every change is additive).

## 5. Affected files

| Path | Action | Purpose |
| --- | --- | --- |
| `docs/adr/0037-device-lifecycle.md`, `docs/adr/0038-disk-unlock-mode-and-in-place-encryption.md` | new (done) | decisions |
| `docs/adr/0032-retention-and-deletion.md` | amended (done) | login history and hardware facts in the matrix |
| `server/migrations/paddock/<next>_device_owners.sql`, `_inventory_hardware.sql`, `_device_group_policies.sql`, `_login_history.sql`, `_agent_update_policy.sql`, `_agent_update_request.sql`, `_uninstall.sql`, `_disk_unlock_mode.sql` | new | §3 |
| `server/internal/adapters/postgres/queries/{device,device_group,inventory,login,login_settings,updates,staleness,command,agent_release}.sql`, new `device_owner.sql`, `login_history.sql`; `pgstore` (gen) | change/new | queries |
| `server/internal/domain/audit/codes.go`, `docs/compliance/audit-codes.md` (gen), `server/web/src/lib/auditCodes.gen.ts` (gen) | change | §6.4 |
| `server/internal/domain/updates/updates.go`, new `server/internal/domain/disk/disk.go`, `server/internal/domain/device/device.go` | change/new | policy constants, `EffectiveUnlockMode`, `retired_reason` |
| `server/internal/problem/problem.go` | change | `TPMInUseByDisk` |
| `pkg/command/command.go`, `pkg/bundle/bundle.go`, `pkg/protocol/types.go`, `api/openapi/device.yaml` | change | §6.2, §6.3 |
| `server/internal/app/{devices,devicegroups,staleness,loginsettings,updates,devicereports,inventory,autoinstall,agentreleases,commands,attention}.go`, new `agentupdates.go`, `uninstall.go`, `loginhistory.go` | change/new | use cases |
| `server/internal/ports/inventory.go`, `server/internal/adapters/fleet/hosts.go` | change | hardware facts |
| `server/internal/compiler/{compiler,v2}.go`, new `supervisor.go`, `disk.go` | change/new | bundle sections |
| `server/internal/devicecache/{rollout,keys}.go`, new `updaterequest.go`; `server/internal/worker/{cachesync,commands,reports,staleness}.go`, new `loginhistory.go`; `server/cmd/paddock-server/{worker,admin}.go` | change/new | cache, rounds |
| `server/internal/transport/http/device/handlers.go`, `server/internal/ingest/ingest.go` | change | `requested` offer, `arch` |
| `server/internal/transport/http/admin/handlers_devices.go`, `handlers_devicegroups.go`, `handlers_identity.go`, `handlers_settings.go`, `handlers.go` (`privileged`), `spec_test.go`, `listspec_test.go`; `api/openapi/admin.yaml`, `api/schema/paddock.v1.json`; generated Go/TS | change | §6.1 |
| `agent/internal/agent/{agent,updates,sessions,luks,commands}.go`, new `uninstall.go`, `supervisor.go`; `agent/internal/state/state.go`; `agent/internal/health/health.go`; `agent/internal/reconcile/{luks,inventory}.go`; `agent/internal/luks/luks.go`; `agent/internal/disksetup/disksetup.go`; `agent/internal/update/update.go`; new `agent/internal/supervisorpkg/`, `agent/internal/uninstall/`; `agent/cmd/paddockd/main.go`; `agent/internal/buildinfo/` (new tag file) | change/new | §3.5–§3.9 |
| `agent/cmd/paddock-supervisor/main.go` | change | `BrokenSupervisor` exit for the gate only |
| `Makefile`, `packaging/nfpm/paddock-supervisor.yaml` (no content change; `TAGS` plumbing) | change | §3.7 decision 34 |
| `server/web/src/views/{DeviceOverview,Devices,UserDetail,DeviceGroupDetail,UpdateSettings,LoginSettings,AgentReleaseDetail,Attention}.vue`, new `DeviceLogins.vue`; `components/{DeviceGroupForm,DeviceHeader,DeviceTabs,DangerZone,DiskEncryptionCard}.vue`, new `UninstallDialog.vue`; `lib/{devices,deviceDetailPage,deviceGroups,users,updates,loginSettings,status,deviceHealth}.ts`, new `lib/loginHistory.ts`, `lib/uninstall.ts`; `router.ts`; `locales/{en,de}.json` | change/new | portal |
| `test/acceptance/*` (§9), `test/system/*` (§9), `test/acceptance/devicesim`, `test/acceptance/fleethost.go` | new/change | gates |
| `docs/architecture.md`, `docs/operations/{agent-releases,device-login,fleet,disk-recovery,local-admin,revocation,autoinstall}.md`, new `docs/operations/uninstall.md`, `docs/compliance/{privacy,residual-risks,glossary-de}.md`, `CHANGELOG.md` | change/new | §3.11 |

MUST NOT be touched: `agent/internal/revoke/`, `agent/cmd/paddock-revoke/`, `pkg/revocation/`,
`packaging/nfpm/paddock-revoke.yaml`, `server/migrations/paddock/00001…00048`, `docs/adr/0001…0036` except the
amendment of 0032 already made, `deploy/compose/compose.prod.yaml`, `deploy/compose/compose.lab.yaml`, the device
API path version, any file of plans M9–M11 and their tickets.

## 6. Interfaces and formats

### 6.1 Admin API (additions to `api/openapi/admin.yaml`; every collection `GET` with `x-paddock-list`)

```yaml
# schemas
Device:            + hardware (DeviceHardware, nullable), supervisor_version (string, nullable),
                     agent_update_requested_version (string, nullable), agent_update_requested_at (date-time, nullable),
                     uninstall (DeviceUninstall, nullable), retired_reason (string, nullable), owners ([UserRef], required)
DeviceHardware:    {vendor, model, serial, cpu_brand: string; cpu_cores: integer; memory_bytes, disk_total_bytes: integer int64}
DeviceUninstall:   {mode: enum[leave,reset], requested_at: date-time, command_id: uuid, command_status: string,
                    uninstalled_at: date-time nullable, local_admin: string nullable, tpm: string nullable}
DeviceUninstallRequest: {mode (required), confirm_hostname (required), reason (required, 2–500), clear_tpm (bool), keep_local_admin (bool)}
DeviceOwnersUpdate: {user_ids: [uuid], maxItems 20}
UserRef:           {id: uuid, username, display_name}
DeviceLoginEvent:  {id: uuid, username, at: date-time}
DeviceLoginEventPage: list contract page of DeviceLoginEvent
DeviceGroup:       + staleness ({warning_h, critical_h}, nullable), agent_update_policy (enum, nullable), disk_unlock_mode (enum, nullable)
DeviceGroupCreate/Update: + the same three (optional)
LoginSettings:     + login_history_enabled (bool), login_history_days (integer), disk_unlock_mode (enum tpm_pin|tpm_only)
UpdateSettings:    + agent_update_policy (enum automatic|manual)
DiskState / DiskHealth: + unlock_mode (string), boot_separate (bool, nullable); state enum + unlock_mode_mismatch
AttentionKind:     + uninstall_pending

# operations
PUT  /api/v1/devices/{id}/owners            x-paddock-audit: device.owners_changed      200 DeviceDetail · 400 · 403 · 404
GET  /api/v1/devices/{id}/logins            list: sort [-at, at, username, -username], filter username, q  200 DeviceLoginEventPage · 404
GET  /api/v1/users/{id}/devices             list: sort [hostname, -hostname, last_contact_at, -last_contact_at]  200 DevicePage · 404
POST /api/v1/devices/{id}/update-agent      x-paddock-audit: device.agent_update_requested  200 Device · 403 · 404 · 409 invalid_state
POST /api/v1/devices/{id}/uninstall         x-paddock-audit: device.uninstall_requested  200 Device · 403 step_up_required|forbidden · 404 · 409 invalid_state|tpm_in_use_by_disk · 422 invalid_request
POST /api/v1/devices/{id}/uninstall/cancel  x-paddock-audit: device.uninstall_cancelled  200 Device · 403 · 404 · 409 invalid_state
GET  /api/v1/devices                        + filter owner_id (uuid); q also matches owner username/display name and hardware serial
# documented problem code added: tpm_in_use_by_disk (409)
```

Every new `POST` route goes into `privileged`; `TestOpenAPISpec` and `listspec_test.go` MUST pass unchanged in
their assertions.

### 6.2 Device protocol (`pkg/protocol/types.go`, `api/openapi/device.yaml`; all additive, ADR 0013)

```go
// CheckinRequest.Health (health.Report) gains:
SupervisorVersion string `json:"supervisor_version,omitempty"`
// DiskHealth gains:
UnlockMode   string `json:"unlock_mode,omitempty"`   // tpm_pin | tpm_only (the policy the agent applied)
BootSeparate *bool  `json:"boot_separate,omitempty"` // only in state not_encrypted
// DiskStates gains, after DiskTPMPINMissing:
DiskUnlockModeMismatch = "unlock_mode_mismatch"
// AgentUpdate gains:
Requested   bool       `json:"requested,omitempty"`
RequestedAt *time.Time `json:"requested_at,omitempty"`
// Event types (closed set gains two; only emitted after a section or command of this release):
EventAgentSupervisorUpdated = "agent.supervisor_updated" // data: {version, from_version, outcome}
EventAgentUninstalled       = "agent.uninstalled"        // data: {command_id, mode, outcome, local_admin, tpm, steps{name: status}}
// Heartbeat (server-internal ingest.Heartbeat) gains Arch string.
```

### 6.3 Bundle (`pkg/bundle/bundle.go`; additive; schema v2 renders the new fields)

```go
type AgentCfg struct {
    CheckinIntervalS   int                   `json:"checkin_interval_s"`
    UpdatePolicy       string                `json:"update_policy,omitempty"`       // "" | automatic | manual
    SupervisorPackages map[string]PackageRef `json:"supervisor_packages,omitempty"` // by arch
}
type PackageRef struct { Version string `json:"version"`; URLPath string `json:"url_path"`; SHA256 string `json:"sha256"` }
type DiskSpec struct { UnlockMode string `json:"unlock_mode"` }
// Bundle gains: Disk *DiskSpec `json:"disk,omitempty"`
// LoginSpec gains: ReportEverySession bool `json:"report_every_session,omitempty"`
```

### 6.4 Audit codes (closed registry, `codes.go`; descriptions verbatim; Outcomes `adminOutcomes` unless stated)

| Code | Description | Params |
| --- | --- | --- |
| `device.owners_changed` | An administrator changed the owners of a device. | `hostname`, `added`, `removed`, `owners` |
| `device.agent_update_requested` | An administrator asked a device to install the offered agent release at its next check-in, outside its rollout wave and regardless of the organization's update policy. | `hostname`, `version`, `from_version` |
| `device.supervisor_updated` | The device installed the supervisor package of the current release and checked in with it (actor: the device). | `version`, `from_version`, `outcome` (success only) |
| `device.supervisor_update_failed` | Installing the supervisor package failed, or the supervisor was restored from its backup because the agent did not check in within 10 minutes (actor: the device). | `version`, `from_version`, `outcome` (failure only) |
| `device.uninstall_requested` | An organization administrator asked, with a step-up, to remove Paddock from a device; mode leave keeps everything else working, mode reset also removes Himmelblau, the managed files and the managed local administrator. | `hostname`, `mode`, `clear_tpm`, `keep_local_admin`, `reason`, `command_id` |
| `device.uninstall_cancelled` | An organization administrator cancelled an uninstall before the device received it. | `hostname`, `mode`, `command_id` |
| `device.uninstalled` | The device removed Paddock as requested and reported the outcome of every step (actor: the device); the device is retired by the next event. | `command_id`, `mode`, `outcome`, `local_admin`, `tpm`, `steps` (success, failure) |
| `retention.purged` | (M10's code; registered here if M10 has not landed, with M10's description extended by `device_login_event`.) | `store`, `deleted`, `cutoff` |

Existing entries gain params: `device.retired` → `reason`; `device_group.created`, `device_group.updated` →
`staleness_warning_h`, `staleness_critical_h`, `agent_update_policy`, `disk_unlock_mode`; `settings.login_changed` →
`login_history_enabled`, `login_history_days`, `login_history_deleted`, `disk_unlock_mode`;
`settings.updates_changed` → `agent_update_policy`; `device.stale_warning`, `device.stale_critical` → `source`;
`autoinstall.generated` → `unlock_mode`. Message keys `audit.<code>` in `en.json` and `de.json`.

### 6.5 Valkey keys

`au:<device_id>` string (JSON `{version, requested_at}`, PX = remaining 24 h), written by the worker's cache sync
from `device.agent_update_requested_*`, read by the gateway, rebuilt by `rebuild-cache`.

### 6.6 Portal texts (binding; English `en.json`, German `de.json`; ICU where plural or values appear)

| Key | English | German |
| --- | --- | --- |
| `devices.owners.title` | Owners | Besitzer |
| `devices.owners.column` | Owners | Besitzer |
| `devices.owners.hint` | Who is responsible for this device. Owners have no login or sudo rights through this setting. | Wer für dieses Gerät verantwortlich ist. Besitzer erhalten über diese Einstellung keine Anmelde- oder sudo-Rechte. |
| `devices.owners.saved` | Owners saved. | Besitzer gespeichert. |
| `devices.owners.none` | No owner assigned. | Kein Besitzer zugewiesen. |
| `devices.ownerFilter` | Owner | Besitzer |
| `users.ownedDevices.title` | Devices owned | Geräte im Besitz |
| `devices.hardware.manufacturer` | Manufacturer | Hersteller |
| `devices.hardware.model` | Model | Modell |
| `devices.hardware.serial` | Serial number | Seriennummer |
| `devices.hardware.cpu` | Processor | Prozessor |
| `devices.hardware.cpuCores` | {cores, plural, one {# core} other {# cores}} | {cores, plural, one {# Kern} other {# Kerne}} |
| `devices.hardware.memory` | Memory | Arbeitsspeicher |
| `devices.hardware.disk` | Disk size | Festplattengröße |
| `devices.hardware.pending` | Not reported by the inventory yet | Vom Inventar noch nicht gemeldet |
| `deviceGroups.staleness.title` | Contact thresholds | Kontaktschwellen |
| `deviceGroups.staleness.override` | Override the organization's thresholds for this group | Schwellen der Organisation für diese Gruppe überschreiben |
| `deviceGroups.staleness.warning` | Warning after (hours) | Warnung nach (Stunden) |
| `deviceGroups.staleness.critical` | Critical after (hours) | Kritisch nach (Stunden) |
| `deviceGroups.staleness.laptopPreset` | Laptop preset (5 days / 35 days) | Laptop-Voreinstellung (5 Tage / 35 Tage) |
| `deviceGroups.staleness.hint` | A device in several groups takes the most lenient value of its groups. Without an override the organization's thresholds apply. | Ein Gerät in mehreren Gruppen übernimmt den mildesten Wert seiner Gruppen. Ohne Überschreibung gelten die Schwellen der Organisation. |
| `deviceGroups.staleness.effective` | Effective: warning after {warning} h, critical after {critical} h ({source}) | Wirksam: Warnung nach {warning} h, kritisch nach {critical} h ({source}) |
| `deviceGroups.staleness.sources.organization` | organization | Organisation |
| `deviceGroups.staleness.sources.device_group` | device group | Gerätegruppe |
| `updateSettings.staleness.groupsHint` | Device groups can override these thresholds, for example for laptops. | Gerätegruppen können diese Schwellen überschreiben, zum Beispiel für Laptops. |
| `loginSettings.loginHistory.title` | Login history | Anmeldeverlauf |
| `loginSettings.loginHistory.enabled` | Record which directory users sign in on each device, and when | Aufzeichnen, welche Verzeichnisbenutzer sich wann an welchem Gerät anmelden |
| `loginSettings.loginHistory.days` | Keep the history for (days) | Verlauf aufbewahren für (Tage) |
| `loginSettings.loginHistory.notice` | The login history is personal data of your employees: every session start is stored with user name, device and time for the period above and deleted afterwards. Switch it on only with the agreement of your works council or the equivalent body and inform the users. It is off by default; user locks do not depend on it. | Der Anmeldeverlauf sind personenbezogene Daten Ihrer Beschäftigten: Jeder Sitzungsstart wird mit Benutzername, Gerät und Zeitpunkt für die obige Dauer gespeichert und danach gelöscht. Schalten Sie ihn nur mit Zustimmung Ihres Betriebsrats oder der entsprechenden Stelle ein und informieren Sie die Benutzer. Er ist standardmäßig aus; Benutzersperren hängen nicht davon ab. |
| `loginSettings.loginHistory.disableConfirm` | Switch the login history off? Every recorded login of this organization is deleted at once. | Anmeldeverlauf ausschalten? Jede aufgezeichnete Anmeldung dieser Organisation wird sofort gelöscht. |
| `devices.tabs.logins` | Logins | Anmeldungen |
| `devices.logins.user` | User | Benutzer |
| `devices.logins.at` | Signed in | Angemeldet |
| `devices.logins.off` | The login history is off for this organization. | Der Anmeldeverlauf ist für diese Organisation ausgeschaltet. |
| `devices.logins.offLink` | Switch it on under Login & privileges. | Unter „Anmeldung & Rechte“ einschalten. |
| `devices.logins.empty` | No logins recorded yet. | Noch keine Anmeldungen aufgezeichnet. |
| `updateSettings.agentUpdates.title` | Agent updates | Agent-Updates |
| `updateSettings.agentUpdates.automatic` | Automatic: devices install every agent release the platform rolls out, in their wave | Automatisch: Geräte installieren jedes Agent-Release, das die Plattform ausrollt, in ihrer Welle |
| `updateSettings.agentUpdates.manual` | Manual: devices install an agent release only when an administrator requests it per device | Manuell: Geräte installieren ein Agent-Release nur, wenn ein Administrator es pro Gerät anfordert |
| `updateSettings.agentUpdates.hint` | The policy also covers the supervisor and fleetd packages. Device groups can override it. Devices on an old agent appear on the attention page. | Die Richtlinie gilt auch für die Pakete des Supervisors und von fleetd. Gerätegruppen können sie überschreiben. Geräte mit altem Agent erscheinen unter Handlungsbedarf. |
| `deviceGroups.agentUpdates.label` | Agent updates | Agent-Updates |
| `deviceGroups.inherit` | Organization setting | Einstellung der Organisation |
| `devices.updateAgent.label` | Update agent now | Agent jetzt aktualisieren |
| `devices.updateAgent.title` | Update the agent now | Agent jetzt aktualisieren |
| `devices.updateAgent.confirm` | Offer {version} to {hostname} at its next check-in, outside the rollout wave and regardless of the update policy? The supervisor installs it with self-test, probation and automatic rollback as usual. | {version} dem Gerät {hostname} beim nächsten Check-in anbieten, außerhalb der Rollout-Welle und unabhängig von der Update-Richtlinie? Der Supervisor installiert es wie üblich mit Selbsttest, Probezeit und automatischem Rollback. |
| `devices.updateAgent.requested` | Update to {version} requested {at}; the device picks it up at its next check-in. | Update auf {version} angefordert {at}; das Gerät holt es beim nächsten Check-in ab. |
| `devices.updateAgent.noRelease` | No agent release is being offered right now. | Derzeit wird kein Agent-Release angeboten. |
| `devices.updateAgent.upToDate` | The device already runs the offered release. | Das Gerät läuft bereits mit dem angebotenen Release. |
| `devices.supervisorVersion` | Supervisor version | Supervisor-Version |
| `agentReleases.supervisorFollows` | Devices install the supervisor package of this release after its agent, in the same waves, when their organization's update policy allows it. | Geräte installieren das Supervisor-Paket dieses Releases nach seinem Agent, in denselben Wellen, wenn die Update-Richtlinie ihrer Organisation es erlaubt. |
| `devices.danger.uninstall.title` | Remove Paddock | Paddock entfernen |
| `devices.danger.uninstall.explanation` | Removes the Paddock agent from the device with a signed command and retires the device. You choose whether the device is left as it is or reset. User data is never deleted. | Entfernt den Paddock-Agent mit einem signierten Befehl vom Gerät und nimmt das Gerät außer Betrieb. Sie wählen, ob das Gerät so bleibt, wie es ist, oder zurückgesetzt wird. Benutzerdaten werden nie gelöscht. |
| `devices.danger.uninstall.label` | Remove Paddock… | Paddock entfernen … |
| `devices.uninstall.title` | Remove Paddock from {hostname} | Paddock von {hostname} entfernen |
| `devices.uninstall.leave.label` | Leave the device as it is | Gerät so lassen, wie es ist |
| `devices.uninstall.leave.explanation` | Removes the agent, supervisor, fleetd and Paddock's own files. Keeps every local account including the managed local administrator (its password stays revealable), the sudo rights of break-glass accounts, Himmelblau and directory logins, managed files and the disk encryption with its PIN and recovery key. | Entfernt Agent, Supervisor, fleetd und Paddocks eigene Dateien. Behält jedes lokale Konto einschließlich des lokalen Administrators (sein Passwort bleibt abrufbar), die sudo-Rechte der Notfallkonten, Himmelblau und Verzeichnis-Anmeldungen, verwaltete Dateien und die Festplattenverschlüsselung mit PIN und Wiederherstellungsschlüssel. |
| `devices.uninstall.reset.label` | Reset the system | System zurücksetzen |
| `devices.uninstall.reset.explanation` | Everything of "leave", and additionally: Himmelblau and its configuration are removed (directory users can no longer sign in; their home directories stay), managed files that are unchanged are removed, and the managed local administrator is removed unless it is the last local administrator. The disk encryption is never changed. | Alles wie bei „so lassen“ und zusätzlich: Himmelblau und seine Konfiguration werden entfernt (Verzeichnisbenutzer können sich nicht mehr anmelden; ihre Home-Verzeichnisse bleiben), unveränderte verwaltete Dateien werden entfernt, und der lokale Administrator wird entfernt, außer er ist der letzte lokale Administrator. Die Festplattenverschlüsselung wird nie verändert. |
| `devices.uninstall.clearTpm.label` | Also clear the TPM (only possible while the disk does not unlock with it) | Auch den TPM löschen (nur möglich, solange die Festplatte nicht damit entsperrt wird) |
| `devices.uninstall.clearTpm.disabledTpmDisk` | Not available: the disk of this device unlocks with the TPM. Clearing it would leave only the recovery key. | Nicht verfügbar: Die Festplatte dieses Geräts wird mit dem TPM entsperrt. Ein Löschen ließe nur den Wiederherstellungsschlüssel übrig. |
| `devices.uninstall.keepLocalAdmin.label` | Keep the managed local administrator account | Das Konto des lokalen Administrators behalten |
| `devices.uninstall.confirmLabel` | Remove Paddock | Paddock entfernen |
| `devices.uninstall.typed` | Type the hostname to confirm. The device is retired once it reports the removal. | Geben Sie den Hostnamen zur Bestätigung ein. Das Gerät wird außer Betrieb genommen, sobald es die Entfernung meldet. |
| `devices.uninstall.pending` | Removal requested ({mode}) — {status}. The device removes Paddock at its next check-in and is then retired. | Entfernung angefordert ({mode}) — {status}. Das Gerät entfernt Paddock beim nächsten Check-in und wird dann außer Betrieb genommen. |
| `devices.uninstall.modes.leave` | leave as is | so lassen |
| `devices.uninstall.modes.reset` | reset | zurücksetzen |
| `devices.uninstall.cancel.label` | Cancel request | Anforderung zurückziehen |
| `devices.uninstall.cancel.title` | Cancel the removal | Entfernung zurückziehen |
| `devices.uninstall.cancel.confirm` | Cancel the removal of Paddock from {hostname}? Only possible while the device has not received the command. | Entfernung von Paddock von {hostname} zurückziehen? Nur möglich, solange das Gerät den Befehl nicht erhalten hat. |
| `devices.uninstall.done` | Paddock was removed on {at} ({mode}); local administrator: {localAdmin}; TPM: {tpm}. | Paddock wurde am {at} entfernt ({mode}); lokaler Administrator: {localAdmin}; TPM: {tpm}. |
| `devices.uninstall.localAdmin.removed` | removed | entfernt |
| `devices.uninstall.localAdmin.kept` | kept | behalten |
| `devices.uninstall.localAdmin.kept_last_admin` | kept (last local administrator) | behalten (letzter lokaler Administrator) |
| `devices.uninstall.tpm.cleared` | cleared | gelöscht |
| `devices.uninstall.tpm.requested_at_next_boot` | clear requested at the next boot | Löschen beim nächsten Start angefordert |
| `devices.uninstall.tpm.skipped_in_use` | not cleared (the disk unlocks with it) | nicht gelöscht (die Festplatte wird damit entsperrt) |
| `devices.uninstall.tpm.not_requested` | not requested | nicht angefordert |
| `devices.uninstall.tpm.failed` | clearing failed | Löschen fehlgeschlagen |
| `attention.kinds.uninstall_pending` | Removal of Paddock pending | Entfernung von Paddock ausstehend |
| `problems.tpm_in_use_by_disk` | The disk of this device unlocks with the TPM; it cannot be cleared. | Die Festplatte dieses Geräts wird mit dem TPM entsperrt; er kann nicht gelöscht werden. |
| `loginSettings.unlockMode.label` | Disk unlock mode for new installations | Entsperrmodus der Festplatte für neue Installationen |
| `loginSettings.unlockMode.tpm_pin` | TPM + boot PIN: the disk asks for a PIN at every start | TPM + Boot-PIN: Die Festplatte fragt bei jedem Start nach einer PIN |
| `loginSettings.unlockMode.tpm_only` | TPM only: the disk unlocks automatically while Secure Boot is unchanged | Nur TPM: Die Festplatte entsperrt sich automatisch, solange Secure Boot unverändert ist |
| `loginSettings.unlockMode.hint` | Applies to devices installed with the Paddock autoinstall from now on. Device groups can override it. Installed devices keep their mode until an operator changes it at the device. | Gilt ab jetzt für Geräte, die mit dem Paddock-Autoinstall installiert werden. Gerätegruppen können ihn überschreiben. Installierte Geräte behalten ihren Modus, bis ein Operator ihn am Gerät ändert. |
| `loginSettings.unlockMode.tpmOnlyNotice` | TPM only protects the data against a removed disk, not against someone who has the device: it unlocks at boot and the login screen is the remaining barrier. Use it for shared devices and kiosks, not for laptops with personal data. | Nur TPM schützt die Daten gegen eine ausgebaute Festplatte, nicht gegen jemanden, der das Gerät in der Hand hat: Sie entsperrt sich beim Start, und die Anmeldemaske ist die verbleibende Hürde. Verwenden Sie ihn für geteilte Geräte und Kioske, nicht für Laptops mit personenbezogenen Daten. |
| `deviceGroups.unlockMode.label` | Disk unlock mode | Entsperrmodus der Festplatte |
| `devices.disk.unlockMode` | Unlock mode | Entsperrmodus |
| `devices.disk.unlockModes.tpm_pin` | TPM + boot PIN | TPM + Boot-PIN |
| `devices.disk.unlockModes.tpm_only` | TPM only | Nur TPM |
| `devices.disk.states.unlock_mode_mismatch` | The disk is enrolled for the other unlock mode than its policy says. An operator changes it at the device with the recovery key (see the runbook). | Die Festplatte ist für den anderen Entsperrmodus eingerichtet, als ihre Richtlinie vorsieht. Ein Operator ändert ihn am Gerät mit dem Wiederherstellungsschlüssel (siehe Runbook). |
| `devices.disk.notEncrypted.reinstall` | This device is not encrypted. Encrypt it by reinstalling it with the Paddock autoinstall after a backup; Paddock does not encrypt a running device in place. | Dieses Gerät ist nicht verschlüsselt. Verschlüsseln Sie es, indem Sie es nach einer Sicherung mit dem Paddock-Autoinstall neu installieren; Paddock verschlüsselt ein laufendes Gerät nicht nachträglich. |
| `devices.disk.notEncrypted.conversionPlanned` | Its disk layout (separate /boot) qualifies for the in-place encryption planned for a later release. | Sein Festplattenlayout (separates /boot) kommt für die nachträgliche Verschlüsselung in Frage, die für ein späteres Release geplant ist. |
| `devices.disk.unmanaged.reinstall` | This device was encrypted outside Paddock: no recovery key or header is escrowed, and a Lock cannot be restored. Reinstall it with the Paddock autoinstall to manage its encryption. | Dieses Gerät wurde außerhalb von Paddock verschlüsselt: Kein Wiederherstellungsschlüssel und kein Header sind hinterlegt, und eine Sperre lässt sich nicht aufheben. Installieren Sie es mit dem Paddock-Autoinstall neu, um seine Verschlüsselung zu verwalten. |

German terms added to `glossary-de.md`: Besitzer (owner), Anmeldeverlauf (login history), Kontaktschwellen
(contact thresholds), Update-Richtlinie (update policy), Paddock entfernen (uninstall), Entsperrmodus (unlock mode),
Supervisor (Supervisor, unchanged).

## 7. Host and operator notes (binding figures for the documents)

- Update policy `manual` keeps a device on its agent until *Update agent now*; such devices stay on the attention
  page as `agent_outdated` and fall outside the support window after N-2 minors (426 `agent_unsupported`, the
  update pointer still works).
- The supervisor package reaches a device only after its agent runs the current release and only when the
  policy allows it; a rollback restores the previous binary within 10 minutes; the dpkg database may name the new
  version until the next successful upgrade (`dpkg -l paddock-supervisor` versus `paddock-supervisor version`).
- Uninstall: the request is one signed command with a 7-day lifetime; cancel only before delivery; the device
  retires itself by its final report; `/root/paddock-uninstall/result.json` on the device is the evidence when the
  report never arrived. The escrowed secrets stay with the retired device.
- Unlock mode: changes apply to new installations; `disk-recovery.md` has the conversion steps; the agent reports
  the keyslot change of the conversion as `device.tamper_keyslot_changed` (expected) and escrows the header again.

## 8. Steps (tickets, in order)

1. **PDK-220 — Device owners.** §3.1. Verify: `make gen` no diff; `go test ./server/internal/app/`;
   `make acceptance T=TestDeviceOwners`; the isolation gate.
2. **PDK-221 — Hardware facts from Fleet.** §3.2. Verify: `go test ./server/internal/adapters/fleet/
   ./server/internal/app/`; `make acceptance T=TestInventoryHardware`.
3. **PDK-222 — Staleness thresholds per device group.** §3.3 (migration of decision 10 with all four columns).
   Verify: `go test ./server/internal/app/ ./server/internal/domain/updates/`; `make acceptance T=TestStalenessGroups`.
4. **PDK-223 — Login history: settings, store, API, purge.** §3.4 decisions 14–16, 18–19. Verify:
   `go test ./server/internal/app/ ./server/internal/worker/`; `make acceptance T=TestLoginHistory`.
5. **PDK-224 — Login history: agent per-session reporting, portal tab, privacy document.** §3.4 decisions 17, 20.
   Verify: `go test ./agent/...`; `make e2e` (the tab); system gate S-LH1.
6. **PDK-225 — Agent update policy.** §3.5. Verify: `go test ./server/internal/compiler/ ./agent/...`;
   `make acceptance T=TestAgentUpdatePolicy`; system gate S-UP3.
7. **PDK-226 — Update now.** §3.6. Verify: `go test ./server/internal/domain/agentrelease/
   ./server/internal/transport/http/device/ ./server/internal/devicecache/ ./agent/...`;
   `make acceptance T=TestUpdateNow`; system gate S-UP1.
8. **PDK-227 — Supervisor package updates.** §3.7. Verify: `go test ./agent/... ./server/internal/compiler/`;
   `make acceptance T=TestSupervisorPackage`; system gates S-UP2a, S-UP2b.
9. **PDK-228 — Uninstall: server.** §3.8 decisions 35–38, 41 (server part), 42. Verify: `make gen` no diff;
   `go test ./server/internal/app/ ./pkg/command/`; `make acceptance T=TestUninstall`; the isolation gate.
10. **PDK-229 — Uninstall: agent.** §3.8 decisions 39–40. Verify: `go test ./agent/...` (fake system for every
    step, the last-administrator guard with table tests); `make typecheck`.
11. **PDK-230 — Uninstall: system gates and runbook.** §3.8 decision 43, gates S-UN1 … S-UN4. Verify:
    `make system-test VM=all T='TestUninstall'`.
12. **PDK-231 — Disk unlock mode: server.** §3.9 decisions 44–46, 49 (portal). Verify: `go test
    ./server/internal/autoinstall/ ./server/internal/app/ ./server/internal/compiler/ ./server/internal/domain/disk/`;
    `make acceptance T=TestUnlockMode`.
13. **PDK-232 — Disk unlock mode: agent and system gates.** §3.9 decisions 47–48, gates S-DU1, S-DU2. Verify:
    `go test ./agent/...`; `make system-test VM=all T='TestDiskUnlockMode'`.
14. **PDK-233 — In-place encryption deferred: layout detection, portal message, docs.** §3.10. Verify:
    `go test ./agent/internal/reconcile/`; `make e2e` (the card texts).
15. **PDK-234 — Documents, residual risks, CHANGELOG, regression.** §3.11, §12, the full regression (`make lint
    test`, `make acceptance`, `make e2e`, `make system-test VM=all`, `make bundle-test`), `make scan-secrets`.

PDK-220, PDK-221, PDK-222 MAY run in parallel. PDK-224 depends on PDK-223; PDK-226 on PDK-225; PDK-227 on PDK-226;
PDK-229 on PDK-228; PDK-230 on PDK-229; PDK-232 on PDK-231; PDK-233 MAY run after PDK-232. PDK-234 is last.

## 9. Tests and gates

Unit and integration tests per ticket follow the project's rules (business logic → unit; persistence, RLS, worker
rounds → integration with testcontainers; portal components with behaviour → component tests over the user's view).
Positive and negative tests for every role and tenant rule.

Acceptance (`test/acceptance`, `make acceptance`; roles **A** org_admin with step-up, **O** org_operator, **U**
org_auditor, **P** platform admin, **T** API token; "event" = exactly one audit event found with `expectOneEvent`):

| # | Given / When / Then | Role sees |
| --- | --- | --- |
| A1 `TestDeviceOwners` | O PUTs two owners → 200, `owners` lists both, event `device.owners_changed` with `added` (2), `removed` (0); PUT with one → `removed` names the other; 21 owners → 400; a globex user id → 400 `invalid_request`; U → 403; `GET /devices?owner_id=` lists the device, `q=<owner username>` finds it; `GET /users/{id}/devices` lists it; deleting the user removes it from `owners`; globex admin → 404 on all routes (isolation fixtures). | O, U, A |
| A2 `TestInventoryHardware` | A fake Fleet host (`fleethost.go`) with vendor, model, serial, CPU, memory, disk → after a sync round `GET /devices/{id}.hardware` carries them; `q=<serial prefix>` finds the device; a host without them → `hardware` with empty strings and zeros; free disk space is not stored (no column). | A |
| A3 `TestStalenessGroups` | Development stack (`PADDOCK_STALENESS_UNIT=minute`): a device in a group with 2/4 and a device without a group under the organization's 24/168: after 3 minutes without check-in only the group device has `stale_warning` with `source: device_group`, `threshold_h: 2`; a second group with 10/20 on the same device → the group values become 10/20 (lenient wins) and the alert clears at the next round; `warning_h` without `critical_h` → 400; `critical ≤ warning` → 400. | A, U (audit) |
| A4 `TestLoginHistory` | Default: `GET /devices/{id}/logins` empty, bundle login spec without `report_every_session`; A enables with 30 days → event with the params, bundle gains `report_every_session: true`; devicesim sends three `session.login` with distinct times → three rows, sorted `-at`, filter `username`; `device_user_seen` has one row; the purge round with `PADDOCK_RETENTION_UNIT=seconds` and `login_history_days=7` deletes rows older than 7 s and records `retention.purged` store `device_login_event`; A disables → rows deleted, event param `login_history_deleted: n`; globex → 404. | A, U |
| A5 `TestAgentUpdatePolicy` | Organization `manual` → the device's bundle carries `agent.update_policy: manual`; a group override `automatic` → `automatic`; two groups `automatic` and `manual` → `manual`; back to organization `automatic` without overrides → the field is absent; `settings.updates_changed` records `agent_update_policy`; `paddockctl` applies `settings.updates.agent_update_policy`. | A, T |
| A6 `TestUpdateNow` | A rollout with waves `[1,100]`, 60 min: a devicesim whose bucket is ≥ 1 gets no `agent_update` at check-in; O POSTs `update-agent` → 200, `agent_update_requested_version` set, event; the next check-in carries `agent_update{requested: true, requested_at}`; the device reports `agent.updated` for that version → both columns null; a second POST while the device runs the version → 409 `invalid_state` (`upToDate` detail); without any rollout → 409; a halted rollout → 409 and no offer even with an open request; U → 403; T (operator) → 200. | O, A, T |
| A7 `TestSupervisorPackage` | A published release with a `paddock-supervisor` package whose rollout completed → a v2 bundle of an active device with a semantic agent version carries `agent.supervisor_packages.amd64{version, url_path, sha256}` equal to the package; while the rollout is halted the field is absent; devicesim sends `agent.supervisor_updated{outcome: rolled_back}` → event `device.supervisor_update_failed`; `outcome: updated` → `device.supervisor_updated`; the rollout's failure count is unchanged. | P, A |
| A8 `TestUninstall` | A without step-up → 403 `step_up_required`; A with step-up, wrong `confirm_hostname` → 422; mode `leave` → 200, `uninstall{mode, command_id, command_status: pending}`, event `device.uninstall_requested`, attention `uninstall_pending` detail `leave:pending`, the device's commands list has type `uninstall`; a second request → 409; `clear_tpm` with `leave` → 422; `clear_tpm` on a device whose health lists a `tpm2+pin` token → 409 `tpm_in_use_by_disk`; cancel → 200, command `cancelled`, columns null, event `device.uninstall_cancelled`; request again, devicesim checks in (command delivered) → cancel 409; devicesim posts the result `{accepted: true}` and the event `agent.uninstalled{outcome: completed, local_admin: kept, tpm: not_requested, steps}` → events `device.uninstalled` (actor device) and `device.retired` with `reason: uninstalled`, device state `retired`, `uninstalled_at` set, attention entry gone; a Lock pending on another device → its uninstall 409; globex → 404. | A, U |
| A9 `TestUnlockMode` | Default settings → `disk_unlock_mode: tpm_pin`, the autoinstall of a token without a group embeds `"unlock_mode":"tpm_pin"`; A sets `tpm_only` → event param, autoinstall embeds `tpm_only`, bundle `disk.unlock_mode: tpm_only`; a group override `tpm_pin` on the token's group → autoinstall `tpm_pin`, the member's bundle `tpm_pin`; `boot_pin_min_length` is still embedded; a devicesim reporting `disk.state: unlock_mode_mismatch` is listed as `disk_not_compliant` with that detail and the device list filter `disk_state=unlock_mode_mismatch` finds it. | A |
| A10 `TestListContractM8d` | Every new collection `GET` of §6.1 passes `listspec_test.go` and `TestListContract` (page sizes, sort allow list, `total_capped`). | — |

System (`test/system`, `make system-test VM=all`; both VMs in parallel where possible, `vmGroup`):

| # | Gate | Content |
| --- | --- | --- |
| S-UP1 `TestUpdateNow` | update now | A release rolled out with a first wave that excludes the device (first wave percentage `max(1, Bucket(device))`; if the bucket is 0, set the organization's policy to `manual` instead): no update within 2 check-ins; *Update agent now* → `device.agent_updated` within 10 min (probation 2 min in dev builds), `paddockd version` equals the release. |
| S-UP2a `TestSupervisorUpdate` | supervisor update | A release whose `paddock-supervisor` package has a higher version (built by `s.Release` with `--supervisor-version` bump; the stack helper `BuildAgent` gains the supervisor build) and a completed rollout → `paddock-supervisor version` on the device changes, event `device.supervisor_updated{outcome: updated}`, the agent checked in afterwards (`/run/paddock/last-checkin` newer than the dpkg log entry), `systemctl is-active paddock-supervisor` active, the transient unit gone. |
| S-UP2b `TestSupervisorRollback` | supervisor rollback | The same with the tag `paddock_testbroken_supervisor` → within 12 min `device.supervisor_update_failed{outcome: rolled_back}`, the previous `paddock-supervisor version` runs again, the agent checks in; a second offer of the same version is not installed (`FailedSupervisorVersion`). |
| S-UP3 `TestUpdatePolicyManual` | manual policy | Organization `manual` → a completed rollout of a newer release is not installed within 3 check-ins (journal line `agent update offer ignored by the organization's policy`); the supervisor package is not installed either; *Update agent now* installs it. |
| S-UN1 `TestUninstallLeave` | leave | `Install` with a managed file and a managed local administrator (organization with a domain, break-glass account `vagrant`): request `leave` → within 10 min `device.uninstalled{outcome: completed, local_admin: kept}`, device `retired` with `retired_reason: uninstalled`; on the VM: no `paddock-*` or `fleet-osquery` package (`dpkg -l`), `/etc/paddock`, `/var/lib/paddock`, `/opt/paddock`, `/opt/orbit` absent, `paddock-supervisor.service` unknown; the managed file still present; `getent passwd paddock-admin` present, `id vagrant` in `sudo`; `himmelblau` package present and `/etc/himmelblau/himmelblau.conf` present; `/etc/sudoers.d/paddock-u-*` absent; `visudo -c` passes; `/root/paddock-uninstall/result.json` present; a reboot works (SSH back). |
| S-UN2 `TestUninstallReset` | reset | As S-UN1 with `reset` and `clear_tpm: true` on the base VM (passphrase-only LUKS, no TPM token) → `local_admin: removed`, `tpm: cleared` or `requested_at_next_boot` (the swtpm answers `tpm2_clear`; either is accepted and asserted against `tpm2_getcap properties-variable` when `cleared`), Himmelblau packages absent, `/etc/himmelblau` absent, the managed file absent, a modified managed file (changed by the test before the request) present, home directories present, `vagrant` still in `sudo`, reboot works, the LUKS passphrase still opens the disk (`type_luks_passphrase`). |
| S-UN3 `TestUninstallLastAdmin` | last-admin guard | As S-UN2 after `gpasswd -d vagrant sudo` → `local_admin: kept_last_admin`, the account exists, is in `sudo`, and the escrowed password (reveal through the API for the retired device) logs in over SSH. |
| S-UN4 `TestUninstallTpmInUse` | TPM in use | On a device from the D-24 flow (`tpm2+pin` keyslot): the request with `clear_tpm` → 409 `tpm_in_use_by_disk`; the request without it → the result reports `tpm: not_requested` and the disk still unlocks with the PIN after the reboot. |
| S-DU1 `TestDiskUnlockModeTPMOnly` | tpm_only autoinstall | D-AI with the organization set to `tpm_only`: the throwaway VM shows no PIN dialogue at first boot (screenshot contains "unlocks automatically"), reaches `compliant` with tokens `[recovery, tpm2]` and `unlock_mode: tpm_only`; a reboot unlocks without input; the install passphrase no longer opens the disk; the recovery key does. |
| S-DU2 `TestDiskUnlockModeMismatch` | mismatch | A D-24 device (`tpm2+pin`) whose group is set to `tpm_only` → within one drift pass `disk.state: unlock_mode_mismatch`, attention `disk_not_compliant` detail `unlock_mode_mismatch`; the runbook's conversion with the recovery key (`systemd-cryptenroll --wipe-slot=tpm2 --tpm2-device=auto --tpm2-pcrs=7`, unlock with the key) → `device.tamper_keyslot_changed`, then `compliant` with `[recovery, tpm2]`. |
| S-LH1 `TestLoginHistoryDevice` | every session | History on: two GDM logins of the same directory user within the run (`test/system/login.go`) → two rows in `GET /devices/{id}/logins`; history off → `session.login` once per 24 h (one row in `device_user_seen`, no login event rows). |
| regression | existing | `make acceptance`, `make e2e`, `make system-test VM=all` (every existing gate), `make bundle-test`. |

## 10. Acceptance criteria

| # | Given / When / Then | Req. | Observed by |
| --- | --- | --- | --- |
| AC1 | Given a device, when an operator assigns owners, then the device page and list show them, the user page lists the device, and the change is audited once. | L34 | Org admin, operator, auditor |
| AC2 | Given a device whose Fleet host reports hardware, then the device page shows vendor, model, serial number, processor, memory and disk size, and the serial number is searchable; the privacy document says so. | L12 | Org admin |
| AC3 | Given a device group with its own contact thresholds, then its members are warned and marked lost by those thresholds and the audit event names the source; other devices follow the organization. | L27 | Org admin, auditor |
| AC4 | Given an organization with the login history on, then the Logins tab of a device lists every session start of directory users for the configured period and nothing older; with it off, nothing is recorded and existing rows are deleted. | L35 | Org admin, auditor |
| AC5 | Given an organization on the `manual` policy, then its devices install no agent, supervisor or fleetd release until an administrator requests it per device; on `automatic` they follow the platform's waves. | L32 | Org admin, platform admin |
| AC6 | Given *Update agent now*, then the device installs the offered release at its next check-in regardless of its wave and policy, with self-test, probation and rollback, and the request is cleared by the device's report. | L32 | Org admin, operator |
| AC7 | Given a current release with a newer supervisor package, then a device on that agent installs the supervisor and checks in again, or restores the previous supervisor within 10 minutes and reports it. | L32 | Platform admin, auditor |
| AC8 | Given an uninstall request in mode `leave`, then the device removes Paddock, keeps every local account, sudo for break-glass accounts, Himmelblau, managed files and the disk encryption, reports once and is retired. | L33 | Org admin, user at device |
| AC9 | Given mode `reset`, then additionally Himmelblau, unchanged managed files and the managed local administrator are removed — the administrator only when another local administrator exists — and the TPM is cleared only when no disk unlocks with it; user data is never deleted. | L33 | Org admin, user at device |
| AC10 | Given a device group with unlock mode `tpm_only`, then a device installed from an enrollment token of that group unlocks without a PIN, is `compliant` with `[recovery, tpm2]`, and the setting shows the security notice. | L30 | Org admin, user at device |
| AC11 | Given an installed device whose keyslots do not match its policy, then it is reported as `unlock_mode_mismatch` on the device page and the attention list, and the runbook's conversion makes it compliant. | L30 | Org admin, operator at device |
| AC12 | Given an unencrypted device, then the device page says that a reinstall with the autoinstall is needed and, for a separate `/boot`, that in-place conversion is planned; nothing on the disk changes. | L31 | Org admin |

## 11. Stop conditions

- S1: M10's `retention.purged` or `organization_privacy_settings` exists on `main` when PDK-223 starts: extend the
  M10 round and registry entry instead of adding a second round; keep the setting in `organization_login_settings`
  (do not move it) and report the overlap.
- S2: `systemd-run` is not available on the test VMs' Ubuntu releases in the form decision 31 and 39 assume, or a
  transient unit is killed with the supervisor's cgroup: report the journal; do not fall back to in-process dpkg.
- S3: `tpm2_clear` on the swtpm of the test VMs fails for a reason other than authorization, and the PPI fallback
  is not available either: report; do not weaken the gate S-UN2 to accept `tpm: failed`.
- S4: `systemd-cryptenroll --tpm2-device=auto --tpm2-pcrs=7` without `--tpm2-with-pin` cannot be unlocked by
  dracut's `tpm2-device=auto` on either release without a PIN prompt: report (ADR 0038 decision 1 depends on it).
- S5: the gateway cannot read a per-device Valkey key in `agentUpdate` without a second round trip the load gate
  (`test/load`) rejects: report the measured p99; do not move the decision to the agent.
- S6: the Fleet host detail of the pinned version lacks one of the fields of decision 6: report the JSON; store
  what exists, never a substitute.
- S7: M11's `paddockd preflight` exists when PDK-233 starts: add the sentence to its `luks` check and report.
- S8: any change seems necessary in `agent/internal/revoke/`, `agent/cmd/paddock-revoke/`, `pkg/revocation/` or
  in the device API path version.
- S9: a new Go module, npm package or container image seems necessary (none is expected; `tpm2-tools` is already a
  dependency of `paddock-agent`).
- S10: the last-administrator guard of decision 40 step 7 would remove the managed local administrator on any
  test VM whose only other sudo member is the test's own SSH account: report before changing the guard.
- S11: a step of decision 40 would require touching a LUKS keyslot, `/etc/crypttab`, `/etc/fstab` or the boot loader.

## 12. Residual risks and open points

Residual risks (`docs/compliance/residual-risks.md`, numbered from RR-44; PDK-234 writes the table rows):

- **RR-44 TPM-only unlock.** A `tpm_only` disk unlocks for whoever boots the device while Secure Boot is unchanged;
  the kernel command line is not measured into PCR 7. Mitigation: the setting's notice, `tpm_pin` default, the
  stricter mode wins across groups. Record: where `tpm_only` is allowed; whether a GRUB password is set.
- **RR-45 Uninstall is one-way once delivered.** A device offline at the request removes Paddock when it returns;
  cancel works only before delivery; `reset` ends directory logins on the device. Mitigation: typed hostname,
  step-up, reason, the pending state on the attention page. Record: who may request, and the return process.
- **RR-46 TPM clear needs the lockout authorization or physical presence.** With a set lockout auth the clear
  fails; the PPI fallback needs confirmation at the next boot by whoever is at the device. Mitigation: the result
  names what happened. Record: the reissue process checks the TPM state.
- **RR-47 Supervisor rollback restores the binary, not the dpkg state.** `dpkg -l` may show the new version while
  the old binary runs until the next successful upgrade. Mitigation: the event names the outcome; the device page
  shows the running supervisor version. Record: watch `device.supervisor_update_failed`.
- **RR-48 Login history is employee data.** Every session start is stored for up to 365 days; purged rows survive
  in backups up to 30 days (RR-35). Mitigation: off by default, notice at the setting, deletion on disable, audited
  purge. Record: the works council agreement and the retention chosen.
- **RR-49 Serial numbers in Paddock.** A serial number identifies a person's laptop indirectly and is searchable by
  every reader of the organization. Mitigation: read-only, purged with the retired inventory. Record: the asset
  register's legal basis.
- **RR-50 Lenient thresholds across groups.** A device in a laptop group and a server group is alerted by the
  laptop values. Mitigation: the effective pair with its source is shown on the group and device. Record: group
  design.
- **RR-51 Manual policy and the support window.** Devices on `manual` can fall outside the agent support window
  (ADR 0013) and get 426 until updated. Mitigation: `agent_outdated` on the attention page; *Update agent now*.
  Record: who reviews the attention page.
- **RR-52 Unencrypted adopted devices stay unencrypted** until M8e or a reinstall. Mitigation: `disk_not_compliant`
  on the attention page; the card names the way forward. Record: the deadline for reinstalls.
- **RR-53 Unlock mode change is manual.** An installed device keeps its mode until an operator converts it with the
  recovery key at the device; the conversion is a keyslot change that is reported as tampering (expected).
  Mitigation: `unlock_mode_mismatch` is visible; the runbook names the steps. Record: the conversion plan per fleet.

Open points (default chosen):

1. Should the organization defaults for staleness move to 120 h / 840 h for new organizations? **Default: no** —
   the wizard (M8g) proposes the laptop preset per organization; existing organizations are unchanged.
2. Maintenance windows for agent updates (for example "only 02:00–05:00 local time")? **Default: not in M8d**; the
   policy is `automatic | manual`. Revisit with M9's notifications and the lab's feedback.
3. Should `reset` offer to delete the home directories of directory users? **Default: no, never** (the task's
   rule "never wipes user data"); a reissue wipes by reinstall.
4. Should an uninstall in mode `reset` delete the device's escrow? **Default: no** — the recovery key may still be
   needed for the encrypted disk; Destroy is the path to unrecoverable data.
5. Should `update-agent` exist for a device group (fan-out)? **Default: no** in M8d; a later ticket can add
   `POST /api/v1/device-groups/{id}/update-agent` with the `install-now` pattern (≤ 500 devices).
6. Should the login history also be listed per user (`GET /users/{id}/logins`)? **Default: not in M8d**; the device
   tab and the audit log suffice for the lab; a later ticket adds it under the same retention.

Handover to M8g (PDK-200 wizard): the wizard MUST surface `disk_unlock_mode` (default `tpm_pin`, notice for
`tpm_only`), the staleness preset per device group (laptop 120/840), `agent_update_policy`, and the login history
switch with its notice.

## 13. CHANGELOG rule for M8d

Every ticket adds its operator-visible line under `[Unreleased]` in `### Added` or `### Changed` in operator
language, for example "Devices can be removed from Paddock from the portal in two modes (leave as is, reset); the
device retires itself after reporting the removal." The upgrade note of the release says: server first, then the
agents (every change is additive; older agents ignore the new bundle fields; the new event types are only sent to
servers that carry this release).

## 14. Amendment 2026-10-17 — component versions per device (PDK-235, PDK-236) and the upstream version watch (PDK-237)

Decided in ADR 0037, amendment 2026-10-17. Supplements §3; the decision numbering continues.

### 14.1 Component versions reported by the agent, targets, outdated flag (PDK-235)

52. `health.Report` gains `Components map[string]string json:"components,omitempty"` with exactly these keys and
    sources, refreshed once per check-in (`refreshComponents`): `paddockd` = `buildinfo.Version`;
    `paddock_supervisor` = output of `/usr/sbin/paddock-supervisor version` (decision 32's `SupervisorVersion` is
    folded into this map — do not add both fields); `paddock_revoke` = `Sys.PackageVersion("paddock-revoke")`;
    `himmelblau` = `Sys.PackageVersion("himmelblau")`; `fleetd` = `Sys.PackageVersion("fleet-osquery")`. A component
    that is not installed is reported as `""` (key present); a lookup that fails keeps the last value.
    `api/openapi/device.yaml` documents the field (additive, ADR 0013). Package versions are Debian versions
    (`4.0.6-1`); the agent never normalizes them.
53. Migration `component_targets`:

    ```sql
    CREATE TABLE component_target (
      component text PRIMARY KEY CHECK (component IN ('paddockd','paddock_supervisor','paddock_revoke','himmelblau','fleetd')),
      version text NOT NULL, source text NOT NULL, updated_at timestamptz NOT NULL DEFAULT now()
    );
    GRANT SELECT, INSERT, UPDATE, DELETE ON component_target TO paddock_compiler, paddock_worker;
    CREATE FUNCTION paddock_component_targets() RETURNS SETOF component_target
      LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$ SELECT * FROM component_target $$;
    REVOKE ALL ON FUNCTION paddock_component_targets() FROM PUBLIC;
    GRANT EXECUTE ON FUNCTION paddock_component_targets() TO paddock_api, paddock_worker;
    ALTER TABLE device_status ADD COLUMN components_outdated text[] NOT NULL DEFAULT '{}';
    CREATE INDEX device_status_org_outdated_idx ON device_status (organization_id) WHERE cardinality(components_outdated) > 0;
    ```

    The table is platform-wide (no `organization_id`, like `agent_release`). The compiler upserts `himmelblau`
    (`version = cfg.HimmelblauVersion`, `source = "PADDOCK_HIMMELBLAU_VERSION"`) at start. The worker's rollout
    round upserts, after `EvaluateRollouts`, from the current release (completed rollout, not halted): `paddockd`
    and `paddock_supervisor` (= the release version, `source = "agent_release"`), `paddock_revoke` (= the release
    version only when the release has a `paddock-revoke` package, else the row is deleted), `fleetd` (= the
    `package_version` of the newest published release with a `fleet-osquery` package, `source = "agent_release"`).
    Without a completed rollout the four rows are deleted.
54. The worker's heartbeat materialization computes `components_outdated` in Go
    (`server/internal/domain/components/components.go`, `Outdated(installed, targets map[string]string) []string`,
    sorted): a component is outdated when it is installed (`""` is never outdated — it is *missing*, reported
    separately), a target exists, and `installed` is older: `paddockd`, `paddock_supervisor`, `paddock_revoke` by
    `semver.Compare` on the Debian version with `~` mapped to `-` (`0.1.0~alpha.4` = `0.1.0-alpha.4`); `himmelblau`
    and `fleetd` by the rule of `reconcile.login.installed`: not outdated when `installed == target` or `installed`
    has the prefix `target + "-"`, otherwise compared as dotted integers of the part before the first `-`. Targets
    are read once per heartbeat batch through `paddock_component_targets()`.
55. API: `Device` gains `components` (required array of `DeviceComponent{name, installed (string, "" = not
    installed), expected (string, nullable), status (enum ok|outdated|missing|unknown)}`; `unknown` when the agent
    reported no `components` at all), computed by the api from `device_status.health` and the targets. Device list:
    filter `component_outdated` (boolean: `cardinality(components_outdated) > 0`); `ListDevicesRow` gains
    `components_outdated`. Platform: `GET /api/platform/v1/component-targets` → `{items: [{component, version,
    source, updated_at}]}` (tag `platform`, platform administrators; no list contract: at most five rows).

### 14.2 Portal (PDK-236)

56. `DeviceOverview.vue` gets the panel *Components* (`devices.components.title`) directly below the hardware facts
    with one row per component (`devices.components.names.*`): installed version (`mono`), expected version,
    `StatusChip` (`devices.components.status.*`) and the hint `devices.components.hint`; `Devices.vue` gets the column
    *Components* (`devices.components.column`: `ok` or `devices.components.outdatedCount`) and the filter
    `component_outdated` (`devices.componentFilter`); `AgentReleases.vue` gets the card *Rollout targets*
    (`agentReleases.targets.title`: one line per target with its source; `agentReleases.targets.himmelblauHint`;
    `agentReleases.targets.none` when empty). Decision 33's identity row `devices.supervisorVersion` is dropped in
    favour of the panel. Texts (binding):

    | Key | English | German |
    | --- | --- | --- |
    | `devices.components.title` | Components | Komponenten |
    | `devices.components.column` | Components | Komponenten |
    | `devices.components.installed` | Installed | Installiert |
    | `devices.components.expected` | Expected | Erwartet |
    | `devices.components.names.paddockd` | Agent (paddockd) | Agent (paddockd) |
    | `devices.components.names.paddock_supervisor` | Supervisor | Supervisor |
    | `devices.components.names.paddock_revoke` | Revocation module (paddock-revoke) | Widerrufsmodul (paddock-revoke) |
    | `devices.components.names.himmelblau` | Himmelblau | Himmelblau |
    | `devices.components.names.fleetd` | fleetd (osquery) | fleetd (osquery) |
    | `devices.components.status.ok` | Up to date | Aktuell |
    | `devices.components.status.outdated` | Outdated | Veraltet |
    | `devices.components.status.missing` | Not installed | Nicht installiert |
    | `devices.components.status.unknown` | Not reported | Nicht gemeldet |
    | `devices.components.outdatedCount` | {count, plural, one {# outdated} other {# outdated}} | {count, plural, one {# veraltet} other {# veraltet}} |
    | `devices.componentFilter` | Component outdated | Komponente veraltet |
    | `devices.components.hint` | Expected versions come from the current agent release and the Himmelblau version the server rolls out. A device catches up at its next apply or agent update. | Erwartete Versionen stammen aus dem aktuellen Agent-Release und der Himmelblau-Version, die der Server ausrollt. Ein Gerät zieht beim nächsten Apply oder Agent-Update nach. |
    | `agentReleases.targets.title` | Rollout targets | Rollout-Ziele |
    | `agentReleases.targets.himmelblauHint` | Set with PADDOCK_HIMMELBLAU_VERSION of the compiler; devices install it with their next apply. | Gesetzt über PADDOCK_HIMMELBLAU_VERSION des Compilers; Geräte installieren sie beim nächsten Apply. |
    | `agentReleases.targets.none` | No agent release has completed a rollout yet. | Noch kein Agent-Release hat einen Rollout abgeschlossen. |

### 14.3 Upstream version watch (PDK-237)

57. Tool `tools/upstreamwatch/` (Go, standard library only; module `github.com/phischl/paddock-mdm/tools/upstreamwatch`
    added to `go.work`; no new dependency). Commands: `upstreamwatch check [--versions deploy/compose/versions.env]
    [--compiler server/cmd/paddock-server/compiler.go] [--json]` prints one line per pin
    `<name> <pinned> <latest> <patch|minor|major|digest|ok|unknown>` and exits 0 (a reporting tool);
    `upstreamwatch issues --repo <owner/repo>` runs `check` and reconciles GitHub issues (decision 60) through
    `gh api`.
58. Pins and upstream sources (table `tools/upstreamwatch/pins.go`, one row per pin; the unit test
    `TestEveryPinIsMapped` parses `versions.env` and the compiler default and fails on an unmapped pin):
    - every `*_IMAGE` of `versions.env`: registry tag listing — Docker Hub
      `https://hub.docker.com/v2/repositories/<ns>/<repo>/tags?page_size=100` (paginated; `library/` for official
      images), ghcr.io, gcr.io and mcr.microsoft.com through the OCI distribution API `/v2/<repo>/tags/list` with an
      anonymous bearer token from the `WWW-Authenticate` challenge. The latest tag is the highest tag with the same
      *shape* as the pinned tag: every digit run of the pinned tag becomes `\d+`, everything else is literal
      (`2.11.6` → `^\d+\.\d+\.\d+$`, `v4.92.3` → `^v\d+\.\d+\.\d+$`, `4.3.6-management` → `^\d+\.\d+\.\d+-management$`,
      `1.27.2-trixie`, `v1.63.0-noble`, `qemu-v10.2.3-68`), ordered by the numeric fields. A floating tag (`nonroot`
      of `RUNTIME_IMAGE`) compares the resolved manifest digest (`HEAD /v2/<repo>/manifests/<tag>`,
      `Docker-Content-Digest`) with the pinned digest and reports `digest` when it differs.
    - `PADDOCK_HIMMELBLAU_VERSION` default in `server/cmd/paddock-server/compiler.go` (regex
      `"PADDOCK_HIMMELBLAU_VERSION", "([0-9.]+)"`): the directory listing `https://packages.himmelblau-idm.org/stable/`,
      entries `^\d+\.\d+\.\d+/$`, highest version; reported as `himmelblau`.
    - fleetd: the tag of `FLEETCTL_IMAGE` (`make fleetd-deb` builds fleetd with it), reported as `fleetctl`; Fleet's
      server image is its own pin.
    - `FLEET_CPE_DATABASE_URL` / `FLEET_CPE_TRANSLATIONS_URL`: the release tag `\d{12}` of `fleetdm/nvd` versus
      `gh api repos/fleetdm/nvd/releases/latest`; reported as `fleet_nvd`.
    - For images whose project publishes GitHub releases (`caddy`, `authentik`, `openbao`, `rustfs`, `valkey`,
      `fleet`, `prometheus`, `syft`, `cosign`, `gitleaks`, `trivy`, `k6`, `nfpm`, `golangci-lint`, `buildkit`,
      `binfmt`) the table names the repository and the release notes URL is `https://github.com/<repo>/releases/tag/<tag>`;
      the registry listing stays the source of truth for "available" (a release whose image is not published yet
      is not reported).
    - `GITLEAKS_DEFAULT_CONFIG_BYTES/SHA256` are derived values and not pins; the gitleaks issue body says to update them.
59. Classification: `patch` when only the last numeric field grew, `minor` when the middle one, `major` when the
    first; `digest` for floating tags; `ok` when equal; `unknown` on any network or parse error (printed to stderr;
    never fails the run).
60. Issues (`issues` command): for every pin that is `patch|minor|major|digest`, list the open issues with label
    `upstream` (`gh api repos/{repo}/issues?labels=upstream&state=open&per_page=100`, paginated) and match the title
    prefix `upstream: <name> ` in Go; none → create (`gh api repos/{repo}/issues`) with title
    `upstream: <name> <pinned> → <latest>`, label `upstream` (created once if missing), body: the pinned line
    (`versions.env` or the compiler line), the latest version, the classification, the release-notes URL, and the
    **gates to run before the bump** from the table (RustFS: WORM gate `TestWORM`; Authentik: `TestIdentityLockAuthentik`;
    Fleet and fleetctl: inventory gates F0–F4; Postgres and Caddy: `make restore-drill`; gitleaks: update
    `GITLEAKS_DEFAULT_CONFIG_BYTES/SHA256`; every other image: `make acceptance`; Himmelblau: `make system-test VM=all
    T=TestIdentity`); an existing issue with another latest → edit title and body; a pin that is `ok` with an open
    issue → comment `pinned <version> now` and close it. Never more than one open issue per pin. The tool never
    creates branches or pull requests.
61. Workflow `.github/workflows/upstream-watch.yml`: `schedule: - cron: "17 5 * * 1"` (weekly, Monday 05:17 UTC) and
    `workflow_dispatch`; `permissions: {contents: read, issues: write}`; steps: checkout, Go (the same setup as
    `ci.yml`), `go run ./tools/upstreamwatch issues --repo ${{ github.repository }}` with `GH_TOKEN: ${{ github.token }}`.
    The job fails only when the tool cannot start, never on an outdated pin. `Makefile` target `upstream-check`
    runs `go run ./tools/upstreamwatch check`.
62. Tests: `tools/upstreamwatch/*_test.go` with fixtures under `testdata/` (a `versions.env`, Docker Hub and OCI tag
    JSON, a GitHub release JSON, the Himmelblau index HTML): the shape matcher, the ordering, the classification,
    the issue reconciliation against a fake of the `gh api` calls (interface `GitHub` with `List`, `Create`, `Edit`,
    `Comment`, `Close`; no network in tests), and `TestEveryPinIsMapped`. `docs/operations/upgrade.md` gains the
    section "Upstream version watch" (what the job checks, the label, what to do with an issue, the local run, why
    issues and not pull requests).

### 14.4 Steps, gates, risks, stop conditions (additions)

- Steps: 16. **PDK-235** (decisions 52–55). Verify: `GOTOOLCHAIN=auto go test -count=1 ./agent/...
  ./server/internal/domain/components/... ./server/internal/worker/...`; `make acceptance T=TestComponentVersions`.
  17. **PDK-236** (decision 56). Verify: `make e2e`; `make acceptance T=TestComponentTargets`. 18. **PDK-237**
  (decisions 57–62). Verify: `go test ./tools/upstreamwatch/...`; `make upstream-check` prints every pin of
  `versions.env` plus `himmelblau`, `fleetctl` and `fleet_nvd`; a `workflow_dispatch` run on the branch opens the
  Himmelblau issue while the pin is behind. PDK-235 SHOULD run after PDK-227 (it folds in `SupervisorVersion`);
  PDK-237 is independent of every other ticket and MAY run first.
- Acceptance: **A11 `TestComponentVersions`**: with the targets `paddockd`/`paddock_supervisor` = the current
  release, `himmelblau` = the compiler's version (`4.0.4` in the development stack), a devicesim reports
  `components{paddockd: <current>, paddock_supervisor: <current>, paddock_revoke: "", himmelblau: "4.0.3-1", fleetd: ""}`
  → `GET /devices/{id}.components` shows `paddockd: ok`, `himmelblau: outdated`, `paddock_revoke: missing`,
  `fleetd: missing`; `GET /devices?component_outdated=true` lists the device; a report with `himmelblau: "4.0.4-1"` →
  `ok` and the device leaves the filter; a device without `components` → every status `unknown`. **A12
  `TestComponentTargets`**: P reads `/api/platform/v1/component-targets` and sees `himmelblau` with
  `source: PADDOCK_HIMMELBLAU_VERSION` and `paddockd` with the current release's version; an org admin → 403.
- Residual risks: **RR-54 Component targets lag.** `components_outdated` is recomputed at the device's next
  heartbeat (≤ 6 min) after a target changed; an offline device keeps its last evaluation. Mitigation: the device
  page computes the status live from the targets; the list column follows at the next heartbeat. **RR-55 The upstream
  watch depends on anonymous listings.** A blocked or changed registry listing or GitHub API turns a pin `unknown`
  (visible in the job log, not as an issue). Mitigation: `make upstream-check` for a local run; the maintainer
  reviews the job log when a known release is missing.
- Stop conditions: **S12** a registry of `versions.env` refuses anonymous tag listing (report which; do not add a
  secret without a decision). **S13** the label `upstream` cannot be created with `issues: write` (report; do not
  widen the permissions).

## 15. Amendment 2026-10-18 — review 1 of M8d (PDK-234), fix round 1

The maintainer's architect decisions on PDK-326 (ADR 0037 amendment 2026-10-18) and the review's blocking findings
change these decisions; the result document of PDK-234 (*Fix Round 1*) records the implementation.

### 15.1 Update now and the supervisor (decisions 23, 26, 27, 29)

- 23/26: `RequestNow` also accepts a device that runs the offered release while its health reports another
  `paddock_supervisor` than that version (`app.SupervisorBehind`, Debian form normalized) or `components_outdated`
  contains `fleetd`; otherwise 409 `the device already runs <version>` as before.
- 27: the gateway reads `au:<device_id>` also for a device on the offered version and then answers its own version
  marked `requested` (not while the rollout is halted, only with an artifact for its arch). The agent never stages its
  own version; the flag only opens `updatesAllowed` for the supervisor package and fleetd.
- 29: `agent.updated` of the requested version clears the request only when the health reports `paddock_supervisor`
  at that version (or none at all) and `components_outdated` does not name `fleetd`; `agent.supervisor_updated` of that version (any outcome) clears it; the 24-hour
  expiry stays. `handleUpdate` returns without staging while `supervisor-upgrade.json` exists (review finding 12).

### 15.2 Supervisor package in waves (decisions 30 and 33, design contract 6)

- 30: migration `00062_supervisor_package_waves.sql` replaces `paddock_supervisor_packages()`; it returns the current
  rollout's packages while its status is `running` or `completed`, with `status`, `waves` and `current_wave_index`.
  The compiler keeps `{packages, percent}` (`agentrelease.Percent`) in the reconcile digest, so a new wave recompiles
  every device, and renders the packages for a device only when `agentrelease.Eligible(device, percent)` or the
  device has an open update-now request for the rollout's version younger than `devicecache.UpdateRequestLifetime`
  (`ListCompileTargets` returns `agent_update_requested_version/_at`; `RequestNow` queues a device state change).
  A halted rollout renders nothing (fix round 2, review 2 finding C).
- 33 (replaces "The outcome does not count toward any rollout threshold"): a local-health failure (`install_failed`,
  `rolled_back`) writes `agent_update_report` outcome `supervisor_failed` for the version; the rollout, current-release
  and evaluation statistics count it like `update_failed` (distinct devices). `rolled_back_unreachable` writes no
  report and never counts (fix round 2, review 2 finding B).

### 15.3 Retry after an unreachable server (decisions 31 and 32, design contract 8)

- 31: `Plan` gains `backoff bool` (reason `backoff`). The helper's wait tracks the supervisor's PID separately from the
  check-in; at the deadline without a check-in it reports `rolled_back_unreachable` when the supervisor kept one PID
  for `Stable` and `/run/paddock/last-checkin-failed` (written by the agent after a check-in without an answer or with
  502/503/504) is newer than the installation; else `rolled_back`.
- 32: `rolled_back_unreachable` sets `state.supervisor_retry {version, attempts, not_before = at + 24 h}`; the third such
  rollback of a version sets `failed_supervisor_version`; `updated` clears the retry. Every other failure is permanent
  as before.

### 15.4 Uninstall (decisions 38, 39, 41)

- 38: `Cancel` claims the command's result (`cres:<command_id>`) as `cancelled` in its transaction — refused when the
  device's result was claimed first — and deletes the `cmd:<device_id>` field after the commit; the worker's command
  round stays as the fallback. A request whose removal report is overdue (`UninstallReportTimeout`, 24 h after the
  command's result, or its delivery) can be cancelled or requested again; audited with `report_overdue`, and
  `DeviceUninstall.report_overdue` lets the portal offer the cancel. Fix round 2 (review 2 finding A): the overdue
  cancel and re-request also withdraw a `delivered` command (`WithdrawDeviceCommand` after `ClaimResult(cancelled)`,
  409 when the device reported first; `DeleteCommand` after the commit); `succeeded` stays as it is.
- 37 (fix round 2, review 2 finding D, replaces PDK-327's refusal): `Revocations.Request` cancels an uninstall without a removal
  report in its transaction (same withdrawal; a device that reported first does not stop the revocation),
  `ClearDeviceUninstall`, and records the cancel as the params `uninstall_cancelled` (`before_delivery`,
  `after_delivery`) and `uninstall_command_id` on the one `revocation.requested` event (fix round 3: no second
  event, `ActionRunner` records exactly one per attempt); `RevocationRequest.uninstall_cancelled` drives the portal
  warning.
- 39: the agent starts the helper only after the server accepted the result with 2xx; a 404/409 drops the pending
  uninstall and removes its plan and binary copy; `LaunchedAt` is saved after `systemd-run` succeeded. When
  `systemd-run` fails while `paddock-uninstall.service` is active (a relaunch after a crash), the agent adopts the
  running removal instead of reporting `helper_failed` (fix round 2, review 2 finding E).
- 41: `MarkDeviceUninstalled` requires the open request, the event's `command_id` and the command `succeeded`; a report
  before the worker recorded the result (`pending`/`delivered`, not expired) is retried; any other report is audited
  only. `RetireUninstalled` runs through `RecordOnceWith` keyed on `uninstalled_at IS NOT NULL AND state = 'active'`
  under the device's row lock.

### 15.5 Login history (decisions 14–17)

- The worker reads `login_history_enabled` in the inserting transaction after `pg_advisory_xact_lock_shared` on the
  organization's login history key; `LoginSettings.Update` takes the exclusive lock first.
- A login time is capped at the server's time plus `protocol.MaxClockSkew`; logins older than `login_history_days`
  or before `organization_login_settings.login_history_enabled_at` (migration `00061`, set on the switch-on, cleared
  on the switch-off) are not stored.
