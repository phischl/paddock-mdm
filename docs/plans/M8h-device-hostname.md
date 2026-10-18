# Implementierungsplan: M8h — Device name set from the platform (desired name, reported hostname, `hostname` section)

Status: Ready for implementation · 2026-10-18 · Author: architect
Basis: ADR 0041 (device name: desired name, reported hostname, `hostname` section); ADR 0005 (bundle format,
additive sections); ADR 0013 (additive protocol changes, support window); ADR 0018 (lists and dialogs); ADR 0024 (no
event type an older server could receive from a newer agent); ADR 0019 (Himmelblau in generic OIDC mode); plans M2b
(apply engine, drift loop), M5b (the `updates` section as the precedent of a section mapped to one internal
resource), M8d (device lifecycle; `health.Report.supervisor_version` as the precedent of a reported fact), M8s (path
tiers).

Binding language: **MUST** / **MUST NOT** / **SHOULD** / **MAY**.

Merge order of the release batch: M8u, M8d, M8f, **M8h**. This plan is written against `main` at `177c234` plus the
branches `M8d-impl` (migrations `00051`–`00060`) and `M8f-impl` (migration `00061`); §11 names what to do when the
code differs.

## 1. Goal

After M8h an organization administrator or operator sets a device's name in the portal; the device takes it as its
hostname (static, transient and pretty) at its next check-in without a reboot, `/etc/hosts` and Avahi follow, sudo
keeps resolving the host; a name changed by hand on the device is corrected within five minutes and is visible in the
audit log; the device page shows whether the name is unmanaged, pending or applied; and the hostname Paddock lists is
the one the device reports now, not the one it reported at enrollment.

## 2. Context (verified in the code on 2026-10-18, `main` at `177c234`)

- **Reported hostname.** `pkg/protocol.EnrollRequest.Hostname` is `os.Hostname()` at enrollment
  (`agent/internal/enroll/enroll.go::Request`); `app.Enrollments` validates it with `device.ValidateReported`
  (1–253 printable characters) and inserts `device.hostname` (migration `00003`). Nothing updates the column later.
  `device.hostname` is the audit `Target.Display` and the param `hostname` of every device action, the typed text of
  the typed confirmations (`lib/deviceDetailPage.ts::confirmation`, `app/disk.go::confirmedEscrow`), the list's
  default sort (`handlers_devices.go::deviceList`, `queries/device.sql::ListDevices`), the `q` match together with
  `hardware_uuid`, and the header text (`components/DeviceHeader.vue`).
- **Check-in and health.** `agent/internal/agent/agent.go::checkinRequest` marshals `health.Report`
  (`agent/internal/health/health.go`: `status`, `version`, `sudo_flavor`, `disk`, `reboot_required`,
  `revoke_capabilities`; M8d adds `supervisor_version`) into `CheckinRequest.Health`. The gateway copies it into
  `ingest.Heartbeat.Health`; the worker (`worker/reports.go::heartbeat`) coalesces per `devicecache.HeartbeatInterval`
  and calls `app.DeviceReports.RecordStatus` (`app/devicereports.go`), which upserts `device_status` and sets the
  root header volume from `health.disk`. The worker role has `SELECT, INSERT, UPDATE` on `device`.
- **Bundle and apply.** `pkg/bundle.Bundle` carries the optional sections `keys`, `revocation`, `dms`, `inventory`,
  `updates` (M8d adds `disk`); `Verify` ignores unknown fields; `apply.Applier` (`agent/internal/apply/apply.go`)
  applies in `order = [time, file, systemd_unit, updates, login, sudo]`, maps the `updates` section to the internal
  resource `updates` (`bundle.UpdatesResource`) and the `inventory` section last; `CheckTypes` rejects unknown
  `resources[]` types only. `reconcile.Reconciler{Type, Plan, Apply}` and the `reconcile.System` port
  (`agent/internal/reconcile/reconcile.go`, implemented by `reconcile.OS` in `system.go`, faked by
  `reconcile/fakesys.System`). `apply` (`reconcile.go::apply`) is the common Plan-then-do shape; `run` executes
  planned `systemctl …` and `timedatectl …` strings. The drift loop (`agent/internal/agent/bundles.go::drift`)
  re-plans the cached bundle every `config.DriftInterval` (default 300 s, 30 s minimum in development builds) and
  emits `config.drift_corrected{version, resource_ids}`.
- **Compiler.** `compiler.compileOrg` loads `ListCompileTargets` (`queries/bundle.sql`: `id, state, bundle_seq,
  logins_suspended, schema_versions`) and renders per device in `compiler.render`; v2 sections are set from `v2Trust`
  and per-device data; `bundle.ContentSHA256` decides whether a new version is published. A device recompiles when a
  use case records `rec.StateChanged(statechange.ScopeDevice, id)` (`app/devices.go::SetGroups`).
- **Device use cases.** `app.Devices` (`app/devices.go`): `Get`, `SetGroups` (the pattern: `runner.RunTx`,
  `LockDevice`, `rec.SetTarget`, `rec.SetParam("hostname", …)`, `StateChanged`, `loadDeviceDetail`),
  `DeviceDetail{Device, Contact, Status, LatestBundle, Groups, IdentityKeys, Login}`; handlers in
  `transport/http/admin/handlers_devices.go` (`SetDeviceGroups`, `toDevice`, `toDeviceDetail`); the privileged route
  map in `transport/http/admin/server.go` (`"PUT /api/v1/devices/{id}/groups": {app.ScopeOrg, app.SpecDeviceSetGroups}`).
  Role sets `app.RolesRead`, `RolesWrite`, `RolesAdmin` (`app/app.go`).
- **Autoinstall.** `server/internal/autoinstall/autoinstall.go` validates the installer hostname with
  `hostnamePattern = ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$` (`ErrHostname`) — the same rule this plan makes the single
  source in `pkg/bundle`.
- **Managed files.** `app/managedconfig.go` validates paths through `pkg/policy` (tiers denied / sensitive /
  allowed; `/etc/hostname`, `/etc/hosts`, `/etc/machine-info` are allowed today). The agent's `file` reconciler
  tracks what it wrote (`reconcile.Managed`) and `removeStale` deletes unchanged files that left the bundle.
- **Portal.** `views/DeviceOverview.vue` has the panels *Health*, *Identity* (`dl.pd-facts`), *Groups* (a form with
  `v-autocomplete`, a save button `data-testid="save-device-groups"` and an inline "saved" status); `views/Devices.vue`
  lists `hostname` as the first sortable column (`item.hostname` slot); i18n catalogues `locales/en.json`,
  `locales/de.json` (keys `devices.*`); audit codes are localized under `audit.<code>` after `make gen`.
- **Gates.** `test/acceptance` (helpers `login`, `expectOneEvent`, `activeDevice`, `devicesim.Device{Checkin,
  Fetch, SendEvents}`, `listspec_test.go`, `TestOpenAPISpec`); `test/system` (`forEachVM`, `Install`, `Device.Must`,
  `Device.WaitEvent`, `Stack.Call`, `vm.group.Exclusive`; gate pattern `notice_test.go`).
- **Upstream facts (ADR 0041 context).** `hostnamectl hostname NAME` sets static, transient and pretty at once;
  `hostnamectl --json=short` prints `Hostname`, `StaticHostname`, `PrettyHostname`; NetworkManager never overrides a
  valid static hostname and sends it in DHCP by default; `avahi-daemon` reads the host name at startup only; fleetd
  identifies hosts by hardware UUID (`--host_identifier=uuid`, hard-coded) and Paddock maps by hardware UUID
  (`app.InventorySync.MapHosts`); Himmelblau in generic OIDC mode registers no device and `himmelblau.conf` has no
  hostname-derived key.
- **Numbering.** Migrations: M8u `00050`, M8d `00051`–`00060`, M8f `00061`; **M8h starts at `00062`**. Residual
  risks: M8f ends at RR-66; **M8h reserves RR-67 to RR-70**. ADRs: 0040 is the last; this plan adds **0041**.
  Tickets: **PDK-329 to PDK-332**.

## 3. Binding decisions

### 3.1 Data model and validation (PDK-329)

1. Migration `server/migrations/paddock/00062_device_name.sql` (forward-only):

   ```sql
   -- Device name set from the platform (ADR 0041, plan M8h decision 1): the desired hostname of a device. NULL = not
   -- managed. device.hostname stays the name the device reports. Forward-only: there is no Down migration.
   -- +goose Up
   ALTER TABLE device ADD COLUMN name text
     CHECK (name ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$' AND name <> 'localhost');
   CREATE UNIQUE INDEX device_org_name_key ON device (organization_id, name)
     WHERE name IS NOT NULL AND state <> 'retired';
   -- +goose Down
   ```

   No new grants: `paddock_api` has `UPDATE` on `device`, `paddock_worker` has `UPDATE` on `device`,
   `paddock_compiler` has `SELECT` on `device` (migration `00003`).
2. `pkg/bundle` gains the single validation of a device name, used by the server, the compiler and the agent:

   ```go
   // MaxHostname is the length limit of a device name (one DNS label; Linux limits the hostname to 64 bytes).
   const MaxHostname = 63
   var hostnameLabel = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
   // ValidHostname reports whether name is a lowercase RFC 1123 label of 1 to 63 characters that is not "localhost".
   func ValidHostname(name string) bool
   ```

   `server/internal/autoinstall/autoinstall.go` MUST replace `hostnamePattern` by `bundle.ValidHostname` and keep
   `ErrHostname` and its message. Uppercase input is refused, not normalized (the device's name is what the
   administrator typed).
3. Uniqueness: one name per organization among devices whose state is not `retired`. A retired device keeps its
   name for the audit trail and does not block its reuse.

### 3.2 Use case, API, audit (PDK-329)

4. `app.Devices.SetName(ctx context.Context, id uuid.UUID, name *string) (DeviceDetail, error)`:
   `SpecDeviceSetName = ActionSpec{Code: audit.CodeDeviceNameChanged, AllowedRoles: RolesWrite}`; `LockDevice`
   (404 `not_found` for missing and foreign devices); `nil` clears the name; a non-nil name MUST pass
   `bundle.ValidHostname` (400 `invalid_request`, detail `name must be a lowercase host name label of 1 to 63
   characters (letters, digits, hyphens), not "localhost"`); the unique index violation (SQLSTATE `23505` on
   `device_org_name_key`) MUST map to 409 `conflict` with detail `name is used by another device of this organization`;
   a retired device MUST be refused with 409 `invalid_state`. Params: `hostname` (reported), `name` (new, `""` when
   cleared), `previous_name` (`""` when none). Target: the device with `Display: dev.Hostname`. On success
   `rec.StateChanged(statechange.ScopeDevice, id)` and `loadDeviceDetail`. Setting the same value again is a success
   with an audit event (one event per attempt) and still recompiles (idempotent for the compiler: content-equal).
5. Audit registry (`server/internal/domain/audit/codes.go`, closed; `make gen` regenerates
   `docs/compliance/audit-codes.md` and `server/web/src/lib/auditCodes.gen.ts`):

   | Code | Description | Params | Outcomes |
   | --- | --- | --- | --- |
   | `device.name_changed` | An administrator set or cleared the managed name of a device; the device applies it as its hostname at its next check-in. | `hostname`, `name`, `previous_name` | `adminOutcomes` |

6. API (`api/openapi/admin.yaml`, §6.1): `PUT /api/v1/devices/{id}/name` → 200 `DeviceDetail`; the route enters the
   privileged map of `transport/http/admin/server.go` with `app.SpecDeviceSetName`; `TestOpenAPISpec` and
   `listspec_test.go` pass unchanged in their assertions. `Device` and `DeviceDetail` gain `name` (nullable string)
   and `name_state` (`unmanaged | pending | applied`), derived in `toDevice`: `unmanaged` when `name` is null,
   `applied` when `name == hostname`, `pending` otherwise. `GET /api/v1/devices` and
   `GET /api/v1/device-groups/{id}/devices`: `q` MUST also match `name` (`OR name ILIKE …`); the sort allow list is
   unchanged (`hostname`, `last_contact_at`, `enrolled_at`, `state`).
7. Managed files: `app.ManagedFiles` create and update (and the declarative path through the same use case) MUST
   refuse the paths `/etc/hostname` and `/etc/machine-info` with 400 `invalid_request`, detail `path is owned by the
   device name policy`. `/etc/hosts` stays allowed (decision 14 names the interplay). `pkg/policy` is unchanged.

### 3.3 Reported hostname (PDK-329 server, PDK-330 agent)

8. `health.Report` gains `Hostname string json:"hostname,omitempty"`; the agent sets it from `os.Hostname()` in
   `checkinRequest` (a new `refreshHostname` next to `refreshRebootRequired`). It is the kernel (transient) hostname.
9. `app.DeviceReports.RecordStatus` MUST read `hostname` from the health JSON (a bounded decode of the one field,
   next to `diskHealth`); when it is non-empty, passes `device.ValidateReported(hostname)` and differs from
   `device.hostname`, it MUST run the new query

   ```sql
   -- name: UpdateReportedHostname :execrows
   -- The hostname the device reports at check-in (plan M8h decision 9); unchanged values skip the row so the
   -- device_cache_notify trigger does not fire.
   UPDATE device SET hostname = @hostname WHERE id = @id AND hostname IS DISTINCT FROM @hostname;
   ```

   No audit event (status, like `device_status`). An invalid or empty value is ignored (fail safe: the check-in
   never fails because of it). Older agents send no `hostname`; their `device.hostname` stays as enrolled.

### 3.4 Bundle and compiler (PDK-329)

10. `pkg/bundle`:

    ```go
    // TypeHostname is the type and ID of the resource the agent makes of the hostname section (plan M8h decision 10).
    const TypeHostname = "hostname"
    // HostnameSpec is the hostname section: the device's managed name (ADR 0041). Agents that do not know the
    // section ignore it; a device without a managed name has no section.
    type HostnameSpec struct { Name string `json:"name"` }
    // Bundle gains: Hostname *HostnameSpec `json:"hostname,omitempty"`
    // HostnameResource turns the section into the resource the agent plans and applies.
    func HostnameResource(s HostnameSpec) (Resource, error) { return resource(TypeHostname, TypeHostname, s) }
    ```

11. Compiler: `ListCompileTargets` gains `d.name`; `compileTarget` gains `name *string`; `compiler.render` sets
    `Hostname: &bundle.HostnameSpec{Name: *t.name}` for schema v2 when `t.name != nil`, nil otherwise. The section is
    part of `ContentSHA256` as every other field. v1 bundles never carry it. The compiler MUST NOT render a name that
    fails `bundle.ValidHostname` (the CHECK constraint makes this unreachable; the guard logs and omits the section).

### 3.5 Agent (PDK-330)

12. `reconcile.System` gains `Hostnamectl(ctx context.Context, args ...string) (stdout string, exit int, err error)`;
    `reconcile.OS` implements it like `Timedatectl` (test-root guard `errTestRoot`, `commandTimeout`);
    `fakesys.System` gains `Hostnames struct{ Static, Transient, Pretty string }`, answers `--json=short` with
    `{"Hostname":…,"StaticHostname":…,"PrettyHostname":…}` and `hostname <name>` by setting all three and recording
    the call in `Calls`; `FailCmd` applies.
13. New reconciler `agent/internal/reconcile/hostname.go`:

    ```go
    // Hostname reconciles the hostname resource (plan M8h decision 13): the static, transient and pretty hostname,
    // the 127.0.1.1 line of /etc/hosts and a running avahi-daemon.
    type Hostname struct {
        Sys System
        // HostsManaged reports whether the current bundle manages /etc/hosts as a file; then the reconciler leaves
        // the file alone (ADR 0041 decision 6).
        HostsManaged func() bool
    }
    func (h *Hostname) Type() string { return bundle.TypeHostname }
    func (h *Hostname) Plan(ctx context.Context, r bundle.Resource) ([]string, error)
    func (h *Hostname) Apply(ctx context.Context, r bundle.Resource) Result
    ```

    `Plan`: decode `HostnameSpec`; a name that fails `bundle.ValidHostname` is an error (`invalid hostname spec`);
    read `hostnamectl --json=short` (an error or non-zero exit is an error: `hostnamed unavailable`); append
    `"hostnamectl hostname <name>"` when `StaticHostname`, `Hostname` or `PrettyHostname` differs from the name;
    unless `HostsManaged()`, read `/etc/hosts` and append `"write /etc/hosts 127.0.1.1 <name>"` when no line's first
    field is `127.0.1.1` with the name as its second field (comments and other lines are ignored for the check).
    `Apply` (through `reconcile.apply`): for each change in order — run `hostnamectl hostname <name>` (non-zero exit
    → error with the output); rewrite `/etc/hosts` with `WriteFileAtomic(path, data, 0o644, 0, 0)` where `data` is the
    existing content with the **first** line whose first field is `127.0.1.1` replaced by `127.0.1.1\t<name>` and every
    other byte preserved; when no such line exists, `127.0.1.1\t<name>` is inserted directly after the first line whose
    first field is `127.0.0.1`, or appended with a trailing newline when there is none; when the file is absent it is
    created as `127.0.0.1\tlocalhost\n127.0.1.1\t<name>\n`. After a successful `hostnamectl` the reconciler runs
    `systemctl is-active avahi-daemon.service`; exit 0 → `systemctl restart avahi-daemon.service`, a failure of the
    restart is the resource's error (`avahi-daemon restart failed: …`). The reconciler MUST NOT reboot, MUST NOT
    touch NetworkManager, resolved or DNS, MUST NOT change `/etc/hostname` directly (hostnamed writes it).
14. `apply.Applier`: `order` becomes `[hostname, time, file, systemd_unit, updates, login, sudo]`; `sorted` maps
    `b.Hostname != nil` to `bundle.HostnameResource(*b.Hostname)` at the `hostname` position (like `updates`);
    `reconciler(bundle.TypeHostname)` returns the `Hostname` reconciler, whose `HostsManaged` closure answers whether
    the bundle being applied has a resource with ID `file:/etc/hosts`. `CheckTypes` is unchanged (sections are not
    resources). The resource ID `hostname` appears in `bundle.applied.errors[].id` and
    `config.drift_corrected.resource_ids` like every other resource.
15. A bundle without the section (name cleared or never set) applies nothing for the hostname and corrects no drift:
    the device keeps the name it has. The reconciler never restores an "old" name.
16. `packaging/systemd/paddock-supervisor.service` and `paddockd.service` MUST NOT set `ProtectHostname=` (ADR 0041
    decision 7).

### 3.6 Portal (PDK-331)

17. `views/DeviceOverview.vue`: a new panel *Device name* between *Identity* and *Groups*, same markup as *Groups*: a
    form with one `v-text-field` (`data-testid="device-name"`, `autocapitalize="off"`, `spellcheck="false"`, max
    length 63, hint `devices.name.hint`), a *Save* button (`data-testid="save-device-name"`, disabled while
    unchanged or saving), a *Clear* text button shown only when a name is set (`data-testid="clear-device-name"`, sends
    `null`, no modal: the change is reversible), an inline status line below the field driven by `name_state`
    (`devices.name.state.unmanaged | pending | applied`, with the reported hostname for `pending`), and the inline
    "saved" status (`devices.name.saved`). A 400 shows the server's detail inline under the field; a 409 shows
    `devices.name.conflict`. The panel is read-only for `org_auditor` (no form; the status line only). The header and
    the typed confirmations keep using `hostname`.
18. `views/Devices.vue`: the `hostname` cell additionally shows a small chip `devices.name.pendingChip` (status
    `warning`) when `item.name_state === 'pending'`, with the managed name as its tooltip. No new column, no new
    filter; the list contract is unchanged but for `q`.
19. Portal component tests (`src/__tests__/deviceOverview.test.ts`, `deviceNamePanel` cases) through the user's view:
    the three states, a save, a clear, a 400 detail, a 409 message, the auditor's read-only panel. `make e2e` covers a
    rename through the panel (frontend-verify).

### 3.7 Gates, documents, residual risks (PDK-332)

20. Acceptance `test/acceptance/device_name_test.go::TestDeviceName` (§9). System gate `S-HN1` in
    `test/system/hostname_test.go::TestHostnameGate` on both VMs (§9).
21. `docs/operations/device-name.md` (new, §7): what the name does on the device, what it does not do on the
    network (DHCP, dynamic DNS, Avahi), the `/etc/hosts` interplay, the audit codes, troubleshooting (`hostnamed`
    inactive, `bundle.applied` error `hostname`), the `ProtectHostname=` rule. `docs/operations/autoinstall.md`: one
    line that the installer hostname is the first reported name and is not the managed name.
22. Architecture amendments (dated 2026-10-18, M8h): §7.2 (section `hostname`), §11.3 (reconciler `hostname` first
    in the apply order, the avahi restart), §16.1 (`device.name`, `device.hostname` = reported, refreshed at
    check-in), §17.1 (`PUT /devices/{id}/name`). `docs/compliance/residual-risks.md` RR-67 to RR-70 (§12).
    `docs/compliance/privacy.md`: the reported hostname is already listed; add "refreshed at every check-in".
23. CHANGELOG `[Unreleased]` `### Added`: "A device can be named from the portal; the device applies the name as its
    hostname at its next check-in and keeps it; the device page shows whether the name is pending or applied." and
    `### Changed`: "The hostname shown for a device follows what the device reports at every check-in instead of the
    name it had at enrollment." (PDK-329 adds the second line, PDK-331 the first.)

## 4. Non-goals

- Naming templates per organization or device group, bulk renames, a `hostname_mismatch` attention kind (open
  question 1).
- A change of `pkg/policy` tiers for `/etc/hostname`, `/etc/hosts`, `/etc/machine-info` (ADR 0041 option E2).
- Managing `/etc/hosts` beyond the `127.0.1.1` line, DNS or DHCP registration, dynamic DNS updates, NetworkManager
  settings, Avahi configuration.
- Changing what the typed confirmations compare against, the audit `Target.Display`, the list's sort keys or the
  header text (they keep `hostname`).
- Any change to `device.yaml`'s `EnrollRequest`, to `pkg/protocol.EventTypes` or to the gateway.
- The declarative document (`paddock.yml`) does not carry device names.

## 5. Affected files

| Path | Action | Purpose |
| --- | --- | --- |
| `server/migrations/paddock/00062_device_name.sql` | new | `device.name`, partial unique index (3.1) |
| `pkg/bundle/bundle.go`, `bundle_test.go` | change | `ValidHostname`, `MaxHostname`, `TypeHostname`, `HostnameSpec`, `Bundle.Hostname`, `HostnameResource` |
| `server/internal/autoinstall/autoinstall.go`, `autoinstall_test.go` | change | use `bundle.ValidHostname` |
| `server/internal/adapters/postgres/queries/device.sql`, `bundle.sql`, `device_status.sql` | change | `SetDeviceName`, `UpdateReportedHostname`, `q` on `name`, `ListCompileTargets.name` |
| `server/internal/adapters/postgres/pgstore/*` | generated | `make gen` |
| `server/internal/app/devices.go`, `devices_test.go` | change | `SetName`, `SpecDeviceSetName`, `nameState` |
| `server/internal/app/devicereports.go`, `devicereports_test.go` | change | reported hostname in `RecordStatus` |
| `server/internal/app/managedconfig.go`, test | change | refuse `/etc/hostname`, `/etc/machine-info` |
| `server/internal/domain/audit/codes.go` | change | `device.name_changed` |
| `server/internal/compiler/compiler.go`, `v2_test.go` | change | `compileTarget.name`, the section |
| `server/internal/transport/http/admin/handlers_devices.go`, `server.go` | change | `SetDeviceName`, privileged map, `name`, `name_state`, `q` |
| `server/internal/transport/http/admin/adminapi/adminapi.gen.go` | generated | `make gen` |
| `api/openapi/admin.yaml` | change | §6.1 |
| `api/openapi/device.yaml` | change | `health.hostname` (documentation of the health object) |
| `docs/compliance/audit-codes.md`, `server/web/src/lib/auditCodes.gen.ts` | generated | `make gen` |
| `agent/internal/health/health.go` | change | `Report.Hostname` |
| `agent/internal/agent/agent.go` | change | `refreshHostname` in `checkinRequest` |
| `agent/internal/reconcile/reconcile.go`, `system.go`, `fakesys/fakesys.go` | change | `System.Hostnamectl`, fake hostnames |
| `agent/internal/reconcile/hostname.go`, `hostname_test.go` | new | the reconciler (3.5) |
| `agent/internal/apply/apply.go`, `apply_test.go` | change | order, section mapping, `HostsManaged` |
| `server/web/src/views/DeviceOverview.vue`, `views/Devices.vue` | change | panel, chip (3.6) |
| `server/web/src/lib/devices.ts` | change | `setDeviceName` client call, `nameStateView` |
| `server/web/src/locales/en.json`, `de.json` | change | §6.6, `audit.device.name_changed` |
| `server/web/src/__tests__/deviceOverview.test.ts` | change | panel cases |
| `test/acceptance/device_name_test.go` | new | `TestDeviceName` |
| `test/acceptance/devicesim/devicesim.go` | change | `Checkin` accepts a health hostname (helper option) |
| `test/system/hostname_test.go` | new | `TestHostnameGate` (S-HN1) |
| `docs/operations/device-name.md` | new | 3.7 |
| `docs/operations/autoinstall.md`, `docs/architecture.md`, `docs/compliance/residual-risks.md`, `docs/compliance/privacy.md`, `CHANGELOG.md` | change | 3.7 |

MUST NOT be touched: `pkg/policy/`, `pkg/protocol/types.go` (`EventTypes`, `EnrollRequest`, `CheckinRequest`),
`server/internal/transport/http/device/`, `server/internal/ingest/`, `agent/internal/revoke/`,
`agent/cmd/paddock-revoke/`, `agent/internal/supervisor/`, `packaging/systemd/*.service` (except to assert decision
16 in a test), `docs/adr/` (other than 0041), the typed-confirmation code paths, the `attention_condition` view.

## 6. Interfaces and formats

### 6.1 Admin API (additions to `api/openapi/admin.yaml`)

```yaml
# schemas
Device:        + name (string, nullable, required key), name_state (enum [unmanaged, pending, applied], required)
DeviceDetail:  + the same two
DeviceNameUpdate:
  type: object
  required: [name]
  properties:
    name: { type: string, nullable: true, pattern: "^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$", maxLength: 63,
            description: "The managed name; null clears it (the device keeps its current hostname)." }

# operations
PUT /api/v1/devices/{id}/name
  operationId: setDeviceName   tags: [devices]   x-paddock-audit: device.name_changed
  description: |
    Roles: org_admin, org_operator. Sets or clears the managed name of a device. The device applies it as its
    hostname (static, transient and pretty) at its next check-in; a name changed on the device is corrected at the
    next drift check. The name is one lowercase DNS label (1–63 characters, letters, digits, hyphens; not
    "localhost") and unique among the organization's devices that are not retired.
  parameters: Id, Csrf     requestBody: DeviceNameUpdate (required)
  responses: 200 DeviceDetail · 400 invalid_request · 401 · 403 forbidden · 404 not_found · 409 conflict | invalid_state

GET /api/v1/devices, GET /api/v1/device-groups/{id}/devices: q also matches name (x-paddock-list description).
```

### 6.2 Device protocol (`api/openapi/device.yaml` health object; `agent/internal/health/health.go`; additive, ADR 0013)

```go
// health.Report gains:
Hostname string `json:"hostname,omitempty"` // os.Hostname() at the check-in
```

### 6.3 Bundle (`pkg/bundle/bundle.go`; additive; schema v2 only)

```json
"hostname": { "name": "lap-0421" }
```

```go
const TypeHostname = "hostname"
type HostnameSpec struct { Name string `json:"name"` }
// Bundle: Hostname *HostnameSpec `json:"hostname,omitempty"`
func HostnameResource(s HostnameSpec) (Resource, error)
func ValidHostname(name string) bool
const MaxHostname = 63
```

### 6.4 Go signatures (new or changed)

```go
// server/internal/app/devices.go
var SpecDeviceSetName = ActionSpec{Code: audit.CodeDeviceNameChanged, AllowedRoles: RolesWrite}
func (d *Devices) SetName(ctx context.Context, id uuid.UUID, name *string) (DeviceDetail, error)
func nameState(name *string, hostname string) string // "unmanaged" | "pending" | "applied"

// server/internal/adapters/postgres/queries/device.sql
-- name: SetDeviceName :one
UPDATE device SET name = sqlc.narg(name) WHERE id = @id RETURNING *;
-- name: UpdateReportedHostname :execrows   (3.3 decision 9)

// server/internal/adapters/postgres/queries/bundle.sql — ListCompileTargets gains d.name

// agent/internal/reconcile
type System interface { …; Hostnamectl(ctx context.Context, args ...string) (string, int, error) }
type Hostname struct { Sys System; HostsManaged func() bool }

// agent/internal/apply
var order = []string{bundle.TypeHostname, bundle.TypeTime, bundle.TypeFile, bundle.TypeSystemdUnit, bundle.TypeUpdates, bundle.TypeLogin, bundle.TypeSudo}
```

### 6.5 Audit codes (closed registry; descriptions verbatim)

| Code | Description | Params |
| --- | --- | --- |
| `device.name_changed` | An administrator set or cleared the managed name of a device; the device applies it as its hostname at its next check-in. | `hostname`, `name`, `previous_name` |

Message keys `audit.device.name_changed` in `en.json` ("Device name changed") and `de.json` ("Gerätename geändert").

### 6.6 Portal texts (binding; English `en.json`, German `de.json`)

| Key | English | German |
| --- | --- | --- |
| `devices.name.title` | Device name | Gerätename |
| `devices.name.label` | Name | Name |
| `devices.name.hint` | One lowercase label of 1–63 letters, digits or hyphens. The device uses it as its hostname at its next check-in. | Ein kleingeschriebenes Label aus 1–63 Buchstaben, Ziffern oder Bindestrichen. Das Gerät übernimmt es beim nächsten Check-in als Hostnamen. |
| `devices.name.save` | Save | Speichern |
| `devices.name.clear` | Clear name | Namen entfernen |
| `devices.name.saved` | Device name saved. | Gerätename gespeichert. |
| `devices.name.conflict` | Another device of this organization already has this name. | Ein anderes Gerät dieser Organisation trägt diesen Namen bereits. |
| `devices.name.state.unmanaged` | Not managed: the device keeps its own hostname. | Nicht verwaltet: das Gerät behält seinen eigenen Hostnamen. |
| `devices.name.state.pending` | Pending: the device still reports {hostname}. | Ausstehend: das Gerät meldet noch {hostname}. |
| `devices.name.state.applied` | Applied: the device reports this name. | Übernommen: das Gerät meldet diesen Namen. |
| `devices.name.pendingChip` | Name pending | Name ausstehend |
| `devices.name.pendingTooltip` | Managed name: {name} | Verwalteter Name: {name} |

### 6.7 Residual risks (`docs/compliance/residual-risks.md`; M8h reserves RR-67 to RR-70)

- **RR-67 Name registration on the network is not Paddock's.** DHCP and dynamic DNS learn the new name at the next
  lease renewal or reconnect; records of the old name persist until the operator removes them; Paddock never updates
  DNS. Mitigation: the operations page says so; the device page shows pending/applied. Record: the DNS cleanup step
  of the rename process.
- **RR-68 A local rename is drift, not tampering.** A local administrator can rename the device repeatedly; each
  correction is one `device.config_drift_corrected` within the drift interval (5 min); the hostname is not a
  protected area. Record: review repeated corrections on one device.
- **RR-69 Uniqueness is per organization inside Paddock.** Devices outside Paddock on the same LAN may carry the
  same name; Avahi then announces `name-2`; nothing in Paddock detects it. Record: the naming convention.
- **RR-70 A managed `/etc/hosts` owns the `127.0.1.1` line.** When an organization ships `/etc/hosts` as a managed
  file, Paddock does not edit it; a stale line makes sudo print "unable to resolve host" (sudo still works).
  Mitigation: the operations page; the file tier is unchanged. Record: which organizations manage `/etc/hosts`.

## 7. Host and operator notes (binding figures for the documents)

- The name is applied at the next check-in (≤ 5 minutes plus the event-triggered check-ins) and corrected within the
  drift interval (5 minutes) after a local change; no reboot, no logout. Open shells keep their old prompt until a
  new shell starts; GNOME's *About* page shows the new name immediately.
- The agent runs `hostnamectl hostname <name>`, keeps `127.0.1.1 <name>` in `/etc/hosts` (unless `/etc/hosts` is a
  managed file) and restarts `avahi-daemon.service` when it is running. It does not touch NetworkManager, resolved,
  DNS or DHCP; NetworkManager sends the static hostname in DHCP at the next lease renewal or reconnect.
- Himmelblau (generic OIDC mode) and Fleet (hardware UUID) are unaffected; the Fleet host record shows the new name
  after osquery's next detail query.
- `ProtectHostname=` must never be set on the Paddock units.

## 8. Steps (tickets, in order)

1. **PDK-329 — Device name: server, bundle, compiler, reported hostname.** §3.1–3.4, §6.1–6.5. Verify: `make gen`
   no diff; `GOTOOLCHAIN=auto go test -count=1 ./pkg/bundle/ ./server/internal/app/ ./server/internal/compiler/
   ./server/internal/autoinstall/ ./server/internal/transport/http/admin/`; `make acceptance T='TestDeviceName'`;
   the isolation gate; `TestOpenAPISpec`.
2. **PDK-330 — Device name: agent.** §3.3 decision 8, §3.5. Verify: `GOTOOLCHAIN=auto go test -count=1 ./agent/...`;
   `make typecheck`. Depends on PDK-329 (`pkg/bundle` types).
3. **PDK-331 — Device name: portal.** §3.6, §6.6. Verify: `make web` (unit tests), `make e2e` (the panel),
   frontend-verify. Depends on PDK-329 (API).
4. **PDK-332 — Device name: system gate, documents, residual risks, regression.** §3.7, §6.7, §7, §12. Verify:
   `make system-test VM=all T='TestHostnameGate'`; the full regression (`make lint test`, `make acceptance`,
   `make e2e`, `make system-test VM=all`); `make scan-secrets`. Depends on PDK-330 and PDK-331.

PDK-330 and PDK-331 MAY run in parallel after PDK-329.

## 9. Tests and gates

- **Unit, `pkg/bundle`:** `ValidHostname` table: `a`, `lap-0421`, 63 characters → true; `""`, `-a`, `a-`, `A1`,
  `a.b`, `localhost`, 64 characters, `a_b` → false. `HostnameResource` encodes `{"name":…}` with ID and type
  `hostname`; `ContentSHA256` differs between a bundle with and without the section.
- **Unit, `server/internal/app`:** `SetName` — valid name (event params `hostname`, `name`, `previous_name`,
  `StateChanged(ScopeDevice)`); clear (`""` params); same name twice (two events); invalid → 400 and a `failure`
  event; conflict with a non-retired device → 409 `conflict`; the same name as a retired device → 200; retired target
  → 409 `invalid_state`; foreign device → 404; `org_auditor` → 403 `denied` event; `nameState` table.
  `RecordStatus` — health with `hostname` updates `device.hostname`; equal value → `UpdateReportedHostname` returns 0
  rows; invalid (254 characters, control characters) → ignored; absent → ignored. `ManagedFiles` — `/etc/hostname`
  and `/etc/machine-info` refused on create and update, `/etc/hosts` accepted.
- **Unit, `server/internal/compiler`:** v2 render with `name` set carries the section; with `name` null carries none;
  v1 never; a changed name changes the content hash.
- **Unit, `agent/internal/reconcile` (fakesys):** Plan no-op when the three names and the `/etc/hosts` line match;
  Plan lists `hostnamectl hostname` when only the pretty name differs; Apply sets all three and records the call;
  `/etc/hosts` cases — existing `127.0.1.1 old` line replaced in place with the rest byte-identical (including a
  comment block and a `::1` section), no `127.0.1.1` line → inserted after `127.0.0.1`, no `127.0.0.1` line → appended,
  file absent → created with both lines, `HostsManaged()` true → file untouched and not in the plan; avahi active →
  `systemctl restart avahi-daemon.service` recorded, inactive → no restart; `FailCmd = "hostnamectl hostname x"` →
  `Error` with the output and `/etc/hosts` untouched; invalid name in the spec → `Error`; `hostnamectl --json=short`
  failing → `Error`.
- **Unit, `agent/internal/apply`:** a bundle with the section applies `hostname` first; without the section nothing
  is planned for it; `Drifted` after a fake rename returns `["hostname"]`; `CheckTypes` still accepts a bundle whose
  only novelty is the section.
- **Unit, `agent/internal/agent`:** `checkinRequest` carries `health.hostname`.
- **Portal:** §3.6 decision 19.
- **Acceptance `TestDeviceName`** (against the dev stack, devicesim): as `org_operator` set `lap-0421` → 200,
  `name_state: pending`, exactly one `device.name_changed` with the three params; the devicesim's next check-in
  offers a newer bundle whose payload has `hostname.name == "lap-0421"`; a check-in whose health reports
  `hostname: lap-0421` → `GET /devices/{id}` shows `hostname: lap-0421`, `name_state: applied`; `GET /devices?q=lap-04`
  finds it by name before the device reported it; a second device with the same name → 409 `conflict`; `A1` → 400;
  clear → 200 `unmanaged` and the next bundle has no section; `org_auditor` → 403 and a `denied` event; a managed file
  at `/etc/hostname` → 400; the list contract test passes; the isolation gate (`isolation_test.go`) covers the
  endpoint with a foreign ID → 404.
- **System gate S-HN1 `TestHostnameGate`** (`forEachVM`, fresh base install, `vm.group.Exclusive` on the device):
  (a) set the name `s-hn1-<vm>` → within one check-in (`Device.WaitEvent(bundle.applied)`) `hostnamectl --static`,
  `hostname` and `hostnamectl --pretty` print the name, `/etc/hosts` contains a `127.0.1.1` line with it,
  `sudo -n true 2>&1` prints no `unable to resolve host`, `avahi-daemon` (when active) was restarted after the apply
  (`systemctl show -p ActiveEnterTimestamp avahi-daemon.service` newer than the bundle apply), `GET /devices/{id}`
  reports `name_state: applied` after the next check-in; (b) `sudo hostnamectl hostname other-<vm>` on the device →
  within the drift interval the name is back and the device reported `config.drift_corrected` with `resource_ids`
  `["hostname"]` (`Device.WaitEvent`), the audit log has `device.config_drift_corrected`; (c) clear the name →
  the device keeps `s-hn1-<vm>` after the next bundle and a local rename is **not** corrected; (d) the inventory
  mapping survives: `GET /devices/{id}` keeps `hardware_uuid` and `GET /devices/{id}/software` answers 200 after the
  rename (the inventory gate's host); (e) both VMs end with their original hostname restored by the test.

## 10. Acceptance criteria (positive and negative per role)

- **AC-1 (org_operator, org_admin).** Given an active device, when the operator saves the name `lap-0421` on the
  device page, then the response is 200 with `name_state: pending`, the audit log shows one `device.name_changed`
  with `name: lap-0421`, and the device's next bundle carries `hostname.name: lap-0421`.
- **AC-2 (device user, org_admin).** Given the device received that bundle, when its next check-in happens, then
  `hostnamectl --static` on the device prints `lap-0421`, `sudo` resolves the host without a warning, no reboot or
  logout happened, and the device page shows *Applied* with the reported hostname `lap-0421`.
- **AC-3 (org_admin).** Given a managed name, when a local administrator runs `hostnamectl hostname other`, then
  within five minutes the device is `lap-0421` again and the audit log shows `device.config_drift_corrected` with
  `resource_ids: ["hostname"]`.
- **AC-4 (org_operator).** Given another non-retired device of the organization is named `lap-0421`, when the
  operator saves that name, then the response is 409 `conflict` and the portal shows the conflict message inline.
- **AC-5 (org_operator).** Given any device, when the operator saves `A1`, `a.b` or `localhost`, then the response is
  400 `invalid_request` and the portal shows the server's detail under the field.
- **AC-6 (org_auditor).** Given an auditor, when they open the device page, then the *Device name* panel shows the
  state without a form, and `PUT /devices/{id}/name` answers 403 with a `denied` event.
- **AC-7 (org_admin).** Given a managed name, when the administrator clears it, then the device keeps its current
  hostname, the next bundle has no `hostname` section, and a later local rename is not corrected.
- **AC-8 (operator of the stack).** Given an agent older than this release, when it receives a bundle with the
  section, then it applies the bundle as before and reports no error for `hostname` (the section is ignored).
- **AC-9 (org_admin).** Given any organization, when an administrator creates a managed file at `/etc/hostname`,
  then the response is 400 `invalid_request` with the detail of decision 7.
- **AC-10 (org_operator, other organization).** Given a device of organization B, when an operator of organization
  A calls `PUT /devices/{id}/name`, then the response is 404 `not_found`.

## 11. Stop conditions

- `main` or `M8d-impl` already has a migration `00062` → take the next free number and report it.
- `health.Report` is no longer the type marshalled into `CheckinRequest.Health`, or M8d changed `RecordStatus` into a
  shape where the hostname update would run outside `InOrg` → stop and report.
- `apply.Applier.sorted` or `order` no longer exist as in §2 (M8d's `disk` section may have reshaped them) → adapt
  to the same pattern M8d used; if M8d used a different mechanism for its section, follow M8d's and report.
- `hostnamectl --json=short` is unavailable on a target release (the system gate fails on the parse) → stop; the
  fallback (`--static`, `--transient`, `--pretty`) is an architect decision.
- A unit of the Paddock packages carries `ProtectHostname=` → stop and report (decision 16).
- The `device_cache_notify` trigger or the worker's cache sync misbehaves with the hostname update (cache churn in
  the acceptance run) → stop and report; the conditional `UPDATE` is the intended mitigation.
- Any need for a new Go module, npm package or container image → stop.
- Any need to add a path to `pkg/policy` → stop (ADR 0041 option E2 is rejected for this release).

## 12. Residual risks and open points

Residual risks: §6.7 (RR-67 to RR-70; PDK-332 writes the rows).

Open points (default chosen):

1. **Naming templates** (`{org}-{serial}`, `{owner}-{nn}`) per organization or device group. **Default: not in M8h**
   (ADR 0041 option A3): the serial arrives with M8d's hardware facts after the first Fleet sync, owners are assigned
   by hand, and a template needs a collision counter and a second source of truth. Revisit when the lab asks for
   bulk naming; a later plan can add `POST /api/v1/device-groups/{id}/assign-names` with a preview.
2. **Should the autoinstall's hostname become the managed name?** **Default: no.** A token is not bound to one
   device (`max_uses` up to 1000); binding by first enrollment would name the wrong device on reuse. The installer
   hostname stays the first reported name.
3. **Should a persistent mismatch (name pending for more than one day) appear on the attention page?** **Default:
   not in M8h**; the device page and the list chip show it; M9's notifications can subscribe to
   `device.config_drift_corrected` later.
4. **Uppercase input: refuse or lowercase silently?** **Default: refuse** (400), the portal hint names the rule.
5. **Should the reconciler also restart `systemd-resolved`?** **Default: no** — resolved reads the hostname live
   from hostnamed; only Avahi is startup-bound.

## Amendment 2026-10-18 — review 1 of M8h (architect decisions)

- **Pretty hostname (ADR 0041 amendment 2026-10-18).** `hostnamectl hostname <name>` clears the pretty hostname
  for a valid host name instead of setting it; §2 "Upstream facts" and decisions 12 and 13 are refined: `fakesys`
  models the clearing, `Plan` treats a pretty hostname of `""` or the name as in sync, and S-HN1 (§9) accepts both
  and checks that two consecutive drift passes after the correction change nothing and report no
  `config.drift_corrected`.
- **Avahi after a partial failure.** Decision 13 is refined: `Apply` restarts a running `avahi-daemon.service` right
  after a successful `hostnamectl`, before the `/etc/hosts` write, and reports both errors (`errors.Join`). A failed
  restart stays pending in `reconcile.HostnameState`, which the applier keeps for the agent's lifetime; while it is
  pending and the names are in sync, `Plan` lists `systemctl restart avahi-daemon.service`, so the next pass (drift
  or bundle) retries it. An agent restart forgets a pending restart; Avahi then follows at the next rename or reboot.
- **`/etc/hosts` keeps names and aliases.** Decision 13 is refined: the reconciler replaces only the first host name
  (field 1) of the first `127.0.1.1` line; the separators, further names and aliases, a comment and the line ending
  stay. A `127.0.1.1` line without a host name gets `\t<name>` after the address.
