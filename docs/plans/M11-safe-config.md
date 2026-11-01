# Implementierungsplan: M11 — Safe configuration changes (apply status, revert, staged rollout, adoption)

Status: Ready for implementation · 2026-10-15 · Author: architect
Basis: ADR 0033 (staged configuration rollout, revert, report-only adoption), ADR 0005 (bundles), ADR 0011
(configuration source of truth, amendment 2026-10-08), ADR 0012 (apply engine), ADR 0013 (version compatibility),
ADR 0018 (lists and dialogs), ADR 0024 (discriminator in an existing event instead of a new event type), ADR 0028
(per-device derived values); plans M2a/M2b (compiler, agent, agent rollouts), M3b (sudo reconciler), M6c
(declarative configuration, change sets); roadmap M11 (F-01, F-02, F-03, F-19, AUD-15).

Binding language: **MUST** / **MUST NOT** / **SHOULD** / **MAY**.

## 1. Goal

An organization administrator sees per device and per resource what applied, failed, drifted or is pending; undoes
any change set with a reviewed plan; lets a change to managed files, units, package holds or update settings reach
the fleet in waves that stop automatically when devices fail, with an audited urgent opt-out; and enrolls an
already installed laptop by a documented path whose first apply changes nothing on the device until the
administrator confirms. Everything is audited through `app.ActionRunner`, listed under the ADR 0018 contract and
visible in the portal.

## 2. Context

- **Change sets** (`server/internal/app/declarative.go`, `declarative_exec.go`, `domain/declarative/diff.go`,
  migration `00031_change_sets.sql`): only `PUT /api/v1/config` records one (`insertChangeSet`); its `plan` holds
  `declarative.Plan{Changes[{Section, Key, Action, Fields[{Name, Before, After}]}], Created, Updated, Deleted}`; a
  managed file's content appears as `declarative.ContentSummary` (hash and length). Per-resource use cases
  (`app/managedconfig.go`, `app/updates.go`, `app/privileges.go`, `app/devicegroups.go`, `app/loginsettings.go`)
  audit their action and call `stateChangedFor` / `rec.StateChanged`, but record no change set. Applies and dry
  runs serialize on `LockConfigApply` (advisory lock per organization).
- **Compiler** (`server/internal/compiler/compiler.go`): `compileOrg` loads `app.LoadManagedDefinitions`
  (`ManagedDefinitions{Files []managedconfig.File, Units []managedconfig.Unit}`), `loadUpdates`
  (`orgUpdates{settings app.UpdateSettings, holds []pgstore.PackageHold}`), then `render` per `compileTarget`
  resolves `defs.Resolve(groups)` → `managedconfig.Resources`, `keys.Updates.section(groups)` → `app.UpdatesSection`,
  compares `bundle.ContentSHA256` with `GetLatestBundle`, and `publish`/`commit` insert the `bundle` row and set the
  pointer. `expand` turns `statechange.Event` scopes into device IDs.
- **Agent** (`agent/internal/apply/apply.go`, `agent/internal/agent/bundles.go`): `Applier.Apply` returns
  `Report{Version, Changed, Errors[{ID, Message}], ChangedIDs (json:"-")}` which is the data of `bundle.applied`;
  `Applier.Plan` returns `[]Planned{ID, Changes[], Error}`; `drift` plans the cached bundle and applies drifted
  IDs, reporting `config.drift_corrected {version, resource_ids}`. `handleBundle` verifies, applies, caches the
  envelope, sets `state.AppliedBundleVersion`. The sudo reconciler's `Plan` lines are `quarantine <file>`,
  `remove <user> from <group>`, `write <file>`, `remove <file>`, `lecture`, `check /etc/sudoers`, `resolve <user>`,
  `render <user>`.
- **Server-side events** (`server/internal/app/devicereports.go`): `RecordEvents` → `eventEntry` → one audit event
  per `(device, event_seq)` with `eventParams` copying an allow list (`audit.deviceEventParams`); the `Claim`
  closure also writes `agent_update_report`, `device_status.login_state` and escrow activation. The worker's
  `decode` uses `DisallowUnknownFields` for the ingest envelope only; event `Data` is `json.RawMessage`.
- **Agent rollouts** (`server/internal/domain/agentrelease/agentrelease.go`, `app/agentreleases.go`,
  `worker/rollouts.go`, migration `00004_agent_releases.sql`): the pattern this plan mirrors for configuration
  rollouts (`Decide`, `Threshold`, `Percent`, the worker round with a leader lock, `agent_rollout.*` audit codes,
  `paddock_rollout_bucket`).
- **Enrollment**: `agent/internal/enroll/enroll.go` (`Run`, `Autoinstalled`, `Request`), `pkg/protocol/types.go`
  `EnrollRequest`, `api/openapi/device.yaml` `EnrollRequest`, `server/internal/ingest/ingest.go` `Enroll`,
  `server/internal/transport/http/device/handlers.go` (enroll handler publishes `ingest.Enroll`),
  `server/internal/app/enrollments.go` (`Enroll`, `createDevice`, `validateEnroll`), migration `00003_devices.sql`
  (`device`, `device_status`, `bundle`). `test/system/device.go` `Install` is the de-facto adoption procedure.
- **Admin API**: `api/openapi/admin.yaml` (source of truth, `make gen`), handlers in
  `server/internal/transport/http/admin/handlers_*.go`, the privileged route table in `handlers.go` (`privileged`),
  the contract tests `spec_test.go` (every `x-paddock-audit` registered and in the table) and `listspec_test.go`
  (every collection `GET` has the list parameters and `x-paddock-list`). List parsing: `listing.Spec{Sort,
  DefaultSort}`, `listing.Parse`, `listing.Enum`. Verbs are `POST /<collection>/{id}/<verb>`; a device verb handler
  looks like `RetireDevice` → `h.transition`.
- **Portal**: `server/web/src/views/*.vue`, `components/DataList.vue`, `ConfirmDialog.vue`, `ChangeSetPlan.vue`,
  `lib/changeSets.ts`, `lib/deviceDetailPage.ts`, `components/DeviceTabs.vue`, `router.ts`, `locales/en.json` and
  `de.json` (audit codes under `audit.<code>`, generated list in `lib/auditCodes.gen.ts`), e2e in `server/web/e2e/*.spec.ts`
  (`make e2e`, `devicesim` CLI).
- **Gates**: `test/acceptance/*_test.go` (`make acceptance`, helpers `login`, `call`, `expectStatus`,
  `activeDevice`, `devicesim.Device{Checkin, Fetch, SendEvents}`, `portal.NewAuditIndex`), `test/system/*_test.go`
  (`make system-test VM=all`, `forEachVM`, `Install`, `Device.WaitEvent`, `Stack.Call`, `Until`, `vmGroup.Together`).
- **Migrations**: `server/migrations/paddock/NNNNN_name.sql` (goose, forward-only; last today: 00044). Every
  organization table: `ENABLE` and `FORCE ROW LEVEL SECURITY`, policy on `current_setting('paddock.org_id')::uuid`
  without `missing_ok`, grants per role (`paddock_api`, `paddock_worker`, `paddock_compiler`).

## 3. Binding decisions

### 3.1 Vocabulary

1. **Rollout-able sections** are exactly `managed_files`, `managed_units`, `package_holds` and `settings.updates`
   (`declarative.SectionManagedFiles`, `SectionManagedUnits`, `SectionPackageHolds`, `SectionSettingsUpdates`).
   A constant `declarative.RolloutSections() []string` returns them in `Sections()` order.
2. **Staged key** = the pair `(section, key)` of a change of a change set whose rollout is `running` or `halted`,
   with `key` the `declarative.Key.String()` form (settings: `""`).
3. **Resource status values** (`protocol` constants, see §6.2): `applied`, `failed`, `pending`, `drift_corrected`.
4. **Rollout modes of a change set** (`change_set.rollout`): `immediate` (rollouts disabled, or the change set
   touches no rollout-able section), `staged` (a rollout was created), `urgent` (rollouts enabled, the change set
   touches a rollout-able section, the caller opted out with a reason).
5. **Device configuration modes** (`device.config_mode`): `enforce`, `report_only`.
6. **Enrollment methods** (`device.enrollment_method`): `autoinstall`, `adopted`, `unknown`.

### 3.2 Agent: per-resource outcomes and report-only apply (PDK-150, PDK-161)

7. `apply.Report` MUST gain `Resources []ResourceOutcome` (json `resources`) and `Mode string` (json `mode`), with
   `type ResourceOutcome struct { ID string; Status string; Message string \`json:"message,omitempty"\`; Changes
   []string \`json:"changes,omitempty"\` }`. `Apply` fills one entry per resource of `sorted(b, all)` plus the deny
   list entry and every stale-file removal: status `applied` for `reconcile.OK` and `reconcile.Changed`, `failed`
   with the message for `reconcile.Error` and for an unsupported type. `Errors` stays as today (the audit params read
   it). `Mode` is `enforce` unless the bundle's `Mode` is `report_only`.
8. `pkg/bundle.Bundle` MUST gain `Mode string \`json:"mode,omitempty"\`` with constants `ModeEnforce = ""` (absent)
   and `ModeReportOnly = "report_only"`. `ContentSHA256` covers it (a mode change publishes a new version).
   `VerifyVersions` MUST reject a value other than `""` or `report_only` with `ErrSchema`.
9. **Report-only apply.** `Applier.Apply(ctx, b)` with `b.Mode == bundle.ModeReportOnly` MUST NOT call any
   reconciler's `Apply`, `EnsureDenyList` or `removeStale`. It MUST run `Plan` for every resource (`sorted(b,
   all)`) and return `Report{Version, Changed: 0, Errors: [], Mode: report_only, Resources: [...]}` with status
   `pending` and the plan lines as `Changes` (at most 50 lines of at most 256 bytes each; a longer list is cut and the
   last line replaced by `… and N more`) for a resource with changes, `applied` for a resource whose plan is empty,
   `failed` with the message for a plan error. Stale managed files are listed as `pending` with the single line
   `remove`. `Agent.drift` MUST return without planning while `a.current.Mode == report_only`; `tickLocalAdmin`
   MUST NOT run the local administrator manager while the current bundle is report-only (the LUKS tick, DMS tick,
   commands, revocation handling and session tracking are unchanged). `handleBundle` caches the envelope and sets
   `AppliedBundleVersion` exactly as for an enforced bundle.
10. **Enrollment method.** `protocol.EnrollRequest` gains `EnrollmentMethod string \`json:"enrollment_method,omitempty"\``
    with constants `EnrollmentAutoinstall = "autoinstall"`, `EnrollmentAdopted = "adopted"`. `enroll.Request` takes it
    from `Options.Method`; `enroll.Run` called by `paddockd enroll` sets `adopted`; `enroll.Autoinstalled` sets
    `autoinstall`. `device.yaml` documents the optional field (enum) — additive, ADR 0013.
11. **`paddockd preflight`** (new subcommand, `agent/internal/preflight/preflight.go`, read-only, exit 0 when no
    check is `fail`, exit 1 otherwise, `--json` for a JSON report, human-readable table otherwise) MUST run these
    checks with results `ok | warn | fail` and a one-line detail:
    `os` (fail unless `/etc/os-release` is Ubuntu 24.04 or 26.04), `systemd` (fail unless `/run/systemd/system`),
    `root` (fail unless euid 0), `sudo` (fail unless `reconcile.SudoFlavor` resolves; detail: flavor), `tpm2` (warn
    unless `luks.TPM2Present`), `luks` (warn unless the root file system is on LUKS; detail: the `protocol.DiskStates`
    value the agent would report), `sssd` (warn when package `sssd` is installed: it conflicts with Himmelblau's NSS
    and PAM configuration), `himmelblau` (info line: installed version or `not installed; the agent installs it`),
    `sudoers_d` (warn listing the files of `/etc/sudoers.d` that the agent will quarantine at the first enforced
    apply, i.e. every regular file not named `paddock-*` and not `README`), `privileged_groups` (warn listing the
    members of `sudo` and `admin` that are no break-glass account; the organization's list is unknown before
    enrollment, so every member is listed), `server` (only with `--config <enrollment configuration>`: `GET
    <server_url>/healthz` answers 200 within 10 s; fail otherwise), `clock` (warn when `timedatectl show -p NTP`
    reports `no`). No check changes anything on the device.

### 3.3 Server: apply status and history (PDK-151)

12. Migration `00045_config_status.sql` MUST create:

    ```sql
    CREATE TABLE device_bundle_report (
      device_id uuid NOT NULL REFERENCES device(id), organization_id uuid NOT NULL,
      version bigint NOT NULL, outcome text NOT NULL CHECK (outcome IN ('applied','rejected')),
      mode text NOT NULL DEFAULT 'enforce' CHECK (mode IN ('enforce','report_only')),
      changed int NOT NULL DEFAULT 0, error_count int NOT NULL DEFAULT 0, reason text,
      occurred_at timestamptz NOT NULL, recorded_at timestamptz NOT NULL DEFAULT now(),
      PRIMARY KEY (device_id, version),
      FOREIGN KEY (organization_id, device_id) REFERENCES device (organization_id, id)
    );
    CREATE INDEX device_bundle_report_org_occurred_idx ON device_bundle_report (organization_id, occurred_at);
    CREATE TABLE device_resource_status (
      device_id uuid NOT NULL REFERENCES device(id), organization_id uuid NOT NULL,
      resource_id text NOT NULL CHECK (char_length(resource_id) <= 512),
      status text NOT NULL CHECK (status IN ('applied','failed','pending','drift_corrected')),
      message text NOT NULL DEFAULT '' CHECK (char_length(message) <= 1024),
      changes text[] NOT NULL DEFAULT '{}',
      bundle_version bigint NOT NULL, occurred_at timestamptz NOT NULL,
      PRIMARY KEY (device_id, resource_id),
      FOREIGN KEY (organization_id, device_id) REFERENCES device (organization_id, id)
    );
    CREATE INDEX device_resource_status_org_resource_idx ON device_resource_status (organization_id, resource_id, status);
    CREATE INDEX device_resource_status_org_status_idx ON device_resource_status (organization_id, status);
    ```

    RLS and policies for `paddock_api` (SELECT) and `paddock_worker` (SELECT, INSERT, UPDATE, DELETE) as in
    `00003_devices.sql`. The comment header states the retention class (`configuration evidence`, owned by M10).
13. **Ingest.** In `eventEntry`'s `Claim` (same transaction as the audit event, after `InsertDeviceEventSeen`):
    - `bundle.applied`: upsert `device_bundle_report` (`outcome applied`, `mode`, `changed`, `error_count =
      len(errors)`, `occurred_at`; a row with a newer `occurred_at` wins). Then, when the data has `resources`:
      delete every `device_resource_status` row of the device whose `resource_id` is not in the list, and upsert one
      row per entry (`status`, `message`, `changes`, `bundle_version`, `occurred_at`), never replacing a row with a
      newer `occurred_at`. When the data has no `resources` (older agent): upsert `failed` rows from `errors` and
      delete the device's `failed` rows whose ID is not in `errors`; other rows stay.
    - `bundle.rejected`: upsert `device_bundle_report` (`outcome rejected`, `reason`); resource rows unchanged.
    - `config.drift_corrected`: for every ID of `resource_ids` upsert `status drift_corrected`, `message ''`,
      `changes '{}'`, `bundle_version`, `occurred_at` (newer wins).
    Values are bounded as `eventParams` bounds them (`stripControls`, 256 bytes per string, 50 list entries; the
    `message` column takes up to 1024 bytes, `changes` entries 256 bytes, at most 50). The audit params of
    `device.bundle_applied` gain `mode` only (`audit.deviceEventParams` + `eventParams`); `resources` is never
    copied into audit params.
14. **Endpoints** (all `org_admin, org_operator, org_auditor`, list contract, `x-paddock-list`):
    - `GET /api/v1/devices/{id}/config-status` → `DeviceResourceStatusPage`; items `{resource_id, type, status,
      message, changes[], bundle_version, occurred_at}` where `type` is the prefix before `:` (`file`, `unit`) or
      the whole ID (`time`, `login`, `sudo`, `updates`, `inventory`, `pam-deny-list`). Sort allow list
      `[resource_id, status, occurred_at]`, default `resource_id`; search `[resource_id]`; filter `status`
      (repeatable). 404 for an unknown or foreign device.
    - `GET /api/v1/devices/{id}/bundles` → `DeviceBundlePage`; items `{version, created_at, schema_version,
      config_rollout_id (nullable), report: {outcome, mode, changed, error_count, reason, occurred_at} | null}`
      from `bundle LEFT JOIN device_bundle_report`. Sort `[version, created_at]`, default `-version`; no search;
      filter `outcome` (`applied | rejected | none`).
    - `GET /api/v1/config-status` → `ResourceStatusPage`; one item per distinct `resource_id` of
      `device_resource_status` of the organization: `{resource_id, type, applied, failed, pending, drift_corrected,
      last_failure_at (nullable)}` (counts of devices per status; only active devices). Sort `[resource_id, failed,
      pending, applied]`, default `-failed`; search `[resource_id]`; filter `status` (repeatable; keeps resources with
      at least one device in that status).
    The device detail `GET /api/v1/devices/{id}` gains `config_status: {applied, failed, pending, drift_corrected}`
    (counts over the device's rows; zeros without rows).

### 3.4 Portal: apply status (PDK-152)

15. Device tab **Apply status** (`views/DeviceApplyStatus.vue`, route name `device-apply-status`, path
    `apply-status`, tab after `device-configuration` with testid `tab-apply-status`): a `DataList` over
    `GET /devices/{id}/config-status` with columns resource, type, status (`StatusChip`: applied → success,
    drift_corrected → info, pending → warning, failed → error), message, bundle version, time; a `pending` row shows
    its `changes` as a monospace list in an expandable row; a header strip with the four counts and, when the
    device's `config_mode` is `report_only`, the alert `devices.reportOnly.banner` (text: the agent reports what it
    would change and changes nothing until enforcement is enabled) — the alert exists from PDK-160 on; PDK-152 keys
    it on a field that PDK-152 reads as absent (`false`) until then. A second `DataList` **Bundle history** over
    `GET /devices/{id}/bundles` (version, created, schema, rollout link when `config_rollout_id` is set — PDK-159
    adds the link target —, report outcome and time).
16. Fleet page **Configuration status** (`views/ConfigStatus.vue`, route `/config-status`, name `config-status`,
    navigation entry under the configuration group next to *Change sets*): `DataList` over `GET /config-status`
    with the counts as columns, `failed` sortable and in the error colour when > 0. A row is a count only: there is
    no per-resource device list in M11 (non-goal); which devices fail is read on the device page. i18n keys in
    `en.json` and `de.json`.

### 3.5 Change sets for every write, before-states (PDK-154)

17. Migration `00046_change_set_before.sql`:

    ```sql
    ALTER TABLE change_set
      ADD COLUMN before jsonb,
      ADD COLUMN before_purged_at timestamptz,
      ADD COLUMN reverts_change_set_id uuid REFERENCES change_set(id),
      ADD COLUMN rollout text NOT NULL DEFAULT 'immediate' CHECK (rollout IN ('immediate','staged','urgent')),
      ADD COLUMN urgent_reason text CHECK (char_length(urgent_reason) BETWEEN 2 AND 500),
      ADD COLUMN reason text CHECK (char_length(reason) <= 500);
    CREATE INDEX change_set_reverts_idx ON change_set (reverts_change_set_id) WHERE reverts_change_set_id IS NOT NULL;
    GRANT UPDATE (before, before_purged_at) ON change_set TO paddock_worker;  -- M10's purge
    ```

    Existing rows keep `before NULL` and `before_purged_at NULL`; a revert of such a change set is refused with 409
    `invalid_state` and detail `this change set was recorded before before-states were stored`.
18. `before` is a JSON object `{"<section>": {"<key>": <item>}}` for every change with action `update` or `delete`,
    where `<item>` is the declarative item of the section as `GET /api/v1/config` exports it (`declarative.ManagedFile`
    with full `content`, `ManagedUnit`, `PackageHold`, `PermissionProfile`, `DeviceGroup`, `ProfileAssignment`,
    `LoginSettings`, `UpdateSettings`) plus `"id": "<uuid>"` for items that have a row ID. The secrets rule: managed
    file contents are already refused by the secret scan rules of ADR 0025–0027 at write time; nothing more is
    stored than what the live table holds.
19. **Per-resource writes record change sets.** Every use case that writes one of the eight sections
    (`ManagedConfig.CreateFile/UpdateFile/DeleteFile/CreateUnit/UpdateUnit/DeleteUnit`, `Updates.UpdateSettings/
    CreateHold/UpdateHold/DeleteHold`, `Privileges.*` for profiles and assignments, `DeviceGroups.Create/Update/Delete`,
    `LoginSettings.Update`) MUST, inside its existing `RunTx` closure and after its write, call
    `recordChangeSet(ctx, q, rec, change declarative.Change, before any)` (new helper in `app/changesets.go`), which
    builds `declarative.Plan{Changes: [change], Created/Updated/Deleted: 1}` through `declarative.Diff` of two
    one-item documents, inserts the change set with the actor and source of the principal, `rollout` and the
    `before` map, sets `rec.SetParam("change_set_id", id)` and, when the write is staged (decision 25), creates the
    rollout. A device group deletion records one change set with its own deletion and one `delete` change per
    cascaded managed file, unit, hold and assignment (all in one plan), before items included. The audit codes of
    these actions (`managed_file.created` … `settings.login_changed`) gain the params `change_set_id`, `rollout`,
    `rollout_id`, `urgent_reason` in the registry. `PUT /api/v1/config` records `before` the same way (from `st.doc`).
20. `ChangeSet` (OpenAPI) gains `rollout`, `urgent_reason` (nullable), `reverts_change_set_id` (nullable),
    `reverted_by` (nullable uuid: the newest change set whose `reverts_change_set_id` is this one), `before_available`
    (boolean: `before IS NOT NULL`), `rollout_id` (nullable, from PDK-157); the list filter `rollout` (repeatable)
    and the search field set stays `[actor_display]`.

### 3.6 Revert (PDK-155)

21. `POST /api/v1/change-sets/{id}/revert` (roles `org_admin, org_operator`; `x-paddock-audit: config.reverted`;
    query `dry_run` (boolean), `expected_plan` (hex SHA-256), `urgent` (boolean), `reason` (2–500 characters, see
    decision 26); body none). Semantics (`Declarative.Revert(ctx, id, expectedPlan, opts)` in `app/declarative.go`):
    1. Load the change set (404 `not_found` for unknown or foreign). Refuse with 409 `invalid_state` when
       `before IS NULL` (never stored or purged) or when `reverted_by` is set (detail `already reverted by <id>`).
       A revert of a revert is allowed for every write role: it is an ordinary change set.
    2. Build `desired` = `loadConfig(ctx, q).doc` with, per change of the original plan: `create` → remove the
       item with that key from its section (settings: not applicable); `delete` → append the before item;
       `update` → replace the item with the before item (settings: replace the settings object). A key whose current
       item does not exist for an `update` is appended (the before item is restored). Every section of the document
       is present (full export), so the diff only contains the inverse changes.
    3. `plan = declarative.Diff(current, desired)`; with `dry_run` the plan is executed in a rolled-back transaction
       exactly as `Declarative.Plan` does and returned, not audited. Without `dry_run`: `expected_plan` is required
       (400 `invalid_request` when absent; 412 `plan_changed` when different), the plan is executed through
       `configExec`, a change set is recorded with `reverts_change_set_id = id`, `rollout` per decision 25 **except**
       that a revert of the change set of the organization's `running` or `halted` rollout is always `immediate` and
       sets that rollout's status to `reverted` (`config_rollout.ended_at = now()`, `ended_reason = 'reverted by
       change set <new id>'`) in the same transaction; the audit params are `change_set_id` (new),
       `reverts_change_set_id`, `plan_sha256`, `created`, `updated`, `deleted`, `sections`, and when a rollout ended:
       `rollout_id`, `rollout_status: reverted`.
    4. Response 200 `ConfigApplyResult` (`dry_run`, `change_set_id`, `plan`, `plan_sha256`) as for `PUT /config`.
22. Portal: the change-set list and detail get a **Revert** action (write roles; disabled with tooltip when
    `before_available` is false or `reverted_by` is set). Clicking runs the dry run and opens `ConfirmDialog` with
    the inverse plan (`ChangeSetPlan`), the urgent checkbox and reason field (PDK-159 adds them; PDK-155 ships the
    dialog without them), confirm button *Revert* in the error colour; then calls the revert with `expected_plan`.
    412 `plan_changed` shows the inline alert `changeSets.revert.planChanged` and reloads the dry run. `reverted_by`
    and `reverts_change_set_id` are shown as links in the detail.

### 3.7 Rollout settings (PDK-156)

23. Migration `00047_rollout_settings.sql`:

    ```sql
    CREATE TABLE organization_rollout_settings (
      organization_id uuid PRIMARY KEY REFERENCES organization(id),
      enabled boolean NOT NULL DEFAULT false,
      waves int[] NOT NULL DEFAULT '{1,10,50,100}',
      min_wave_minutes int NOT NULL DEFAULT 60 CHECK (min_wave_minutes >= 1),
      failure_threshold_percent int NOT NULL DEFAULT 2 CHECK (failure_threshold_percent BETWEEN 0 AND 100),
      failure_threshold_min int NOT NULL DEFAULT 3 CHECK (failure_threshold_min >= 0),
      canary_device_group_id uuid REFERENCES device_group(id) ON DELETE SET NULL,
      updated_at timestamptz NOT NULL DEFAULT now(), updated_by uuid,
      FOREIGN KEY (organization_id, canary_device_group_id) REFERENCES device_group (organization_id, id) ON DELETE SET NULL
    );
    ```

    RLS for `paddock_api` (SELECT, INSERT, UPDATE), `paddock_compiler` and `paddock_worker` (SELECT). Without a row
    the defaults apply (`app.LoadRolloutSettings` mirrors `LoadUpdateSettings`).
24. `GET /api/v1/settings/rollout` (read roles) and `PUT /api/v1/settings/rollout` (`org_admin`, `x-paddock-audit:
    settings.rollout_changed`, body `RolloutSettingsUpdate{enabled, waves, min_wave_minutes,
    failure_threshold_percent, failure_threshold_min, canary_device_group_id}`), validation with
    `configrollout.ValidateWaves` (same rule as `agentrelease.ValidateWaves`), `min_wave_minutes ≥
    configrollout.MinWaveMinutesProduction = 15` outside development (`PADDOCK_ENV=development`: ≥ 1), an unknown
    or foreign canary group → 404 `not_found`. Audit params: every field. Portal page `views/RolloutSettings.vue`
    (route `/settings/rollout`, name `rollout-settings`) with the same form conventions as `UpdateSettings.vue`.
    Changing the settings does not touch a running rollout (its parameters were copied at start).

### 3.8 Staged change sets and the compiler overlay (PDK-157)

25. **Staging rule** (`app/changesets.go` `rolloutModeFor(settings, plan, urgent)`): a change set is `staged` when
    the organization's rollout settings are `enabled`, the plan has at least one change in a rollout-able section,
    and `urgent` is false; `urgent` when the first two hold and `urgent` is true; else `immediate`. A `staged`
    change set creates one `config_rollout` row in the same transaction (decision 27) and records
    `rec.StateChanged(ScopeOrg)` as today (every device is recompiled; the overlay decides what each gets).
26. **Urgent opt-out**: the query parameters `urgent` (boolean, default false) and `reason` (string, 2–500
    characters) on `PUT /api/v1/config`, `POST/PUT/DELETE /api/v1/managed-files[/{id}]`, `POST/PUT/DELETE
    /api/v1/managed-units[/{id}]`, `POST/PUT/DELETE /api/v1/package-holds[/{id}]`, `PUT /api/v1/settings/updates`,
    and `POST /api/v1/change-sets/{id}/revert`. Rules, checked inside the action (so refusals are audited as
    failures or denials): `urgent=true` without `reason` → 400 `invalid_request`; `urgent=true` while rollouts are
    disabled → 400 `invalid_request` with detail `rollouts are disabled for this organization`; `urgent=true` needs
    a fresh step-up (`rec.RequireStepUp()`; an API token has none → 403 `step_up_required`). The reason is stored as
    `change_set.urgent_reason` and audited as `urgent_reason`. `paddockctl apply` gains `--urgent --reason <text>`
    (PDK-159).
27. Migration `00048_config_rollout.sql`:

    ```sql
    CREATE TABLE config_rollout (
      id uuid PRIMARY KEY, organization_id uuid NOT NULL REFERENCES organization(id),
      change_set_id uuid NOT NULL UNIQUE REFERENCES change_set(id),
      waves int[] NOT NULL, current_wave_index int NOT NULL DEFAULT 0,
      wave_started_at timestamptz NOT NULL DEFAULT now(),
      min_wave_minutes int NOT NULL CHECK (min_wave_minutes >= 1),
      failure_threshold_percent int NOT NULL CHECK (failure_threshold_percent BETWEEN 0 AND 100),
      failure_threshold_min int NOT NULL CHECK (failure_threshold_min >= 0),
      canary_device_group_id uuid REFERENCES device_group(id) ON DELETE SET NULL,
      status text NOT NULL CHECK (status IN ('running','halted','completed','reverted')),
      halted_reason text, evaluation_since timestamptz NOT NULL DEFAULT now(),
      started_by text NOT NULL, started_at timestamptz NOT NULL DEFAULT now(),
      ended_at timestamptz, ended_reason text, updated_at timestamptz NOT NULL DEFAULT now(),
      CHECK (current_wave_index >= 0 AND current_wave_index < cardinality(waves)),
      FOREIGN KEY (organization_id, canary_device_group_id) REFERENCES device_group (organization_id, id) ON DELETE SET NULL
    );
    CREATE UNIQUE INDEX config_rollout_one_open_idx ON config_rollout (organization_id) WHERE status IN ('running','halted');
    CREATE INDEX config_rollout_org_started_idx ON config_rollout (organization_id, started_at);
    ALTER TABLE bundle ADD COLUMN config_rollout_id uuid REFERENCES config_rollout(id);
    CREATE INDEX bundle_rollout_idx ON bundle (config_rollout_id) WHERE config_rollout_id IS NOT NULL;
    ```

    plus `paddock_config_rollout_bucket(device_id uuid, rollout_id uuid) RETURNS int`: FNV-1a (32 bit) over the
    UTF-8 bytes of `device_id::text || ':' || rollout_id::text`, modulo 100 (same loop as `paddock_rollout_bucket`),
    and the org-scoped count function `paddock_config_rollout_stats(rollout uuid, pct int, canary uuid, since
    timestamptz) RETURNS TABLE (eligible bigint, failed bigint)` (SECURITY INVOKER, RLS applies): `eligible` =
    active devices of the organization with bucket < pct or a member of the canary group; `failed` = distinct
    eligible devices whose newest `device_bundle_report` for a bundle with `config_rollout_id = rollout` and
    `occurred_at >= since` is `rejected`, or `applied` with a `device_resource_status` row of status `failed` whose
    `bundle_version` equals that version and whose `resource_id` is one of the rollout's staged resource IDs
    (passed as `text[]` argument `staged_ids`). RLS for `paddock_api` (SELECT, INSERT, UPDATE), `paddock_compiler`
    (SELECT), `paddock_worker` (SELECT, UPDATE). The compiler needs no new grant on `bundle`: it sets
    `config_rollout_id` in `InsertBundle` (INSERT is granted). The bucket and stats functions are `GRANT EXECUTE` to
    the three roles.
28. Domain package `server/internal/domain/configrollout` (new): `Bucket(device, rollout uuid.UUID) int` (Go twin of
    the SQL function; a server test asserts equality on 1 000 random pairs as `TestRolloutBucketMatchesSQL` does for
    agents), `Eligible(bucket, percent int, canary bool) bool` (`canary || bucket < percent`), `ValidateWaves`,
    `Threshold`, `Decide(Rollout, now) Decision` (`Keep | Halt | Advance | Complete`: halt when `Failed > 0 &&
    Failed >= Threshold`; advance when `now - WaveStartedAt >= MinWaveMinutes` and a next wave exists; complete after
    the last wave; `halted`, `completed`, `reverted` → `Keep`), `StagedResourceIDs(plan declarative.Plan) []string`
    (managed file key → `file:<path>`, unit key → `unit:<name>`, package hold or settings.updates → `updates`),
    `StagedKeys(plan) map[string]map[string]bool` (section → key set), status constants and
    `MinWaveMinutesProduction = 15`, `DefaultWaves`, `DefaultMinWaveMinutes = 60`, `DefaultFailureThresholdPercent =
    2`, `DefaultFailureThresholdMin = 3`.
29. **Conflict rule** (`app/changesets.go` `requireNotStaged(ctx, q, plan)`): while the organization has a
    `running` or `halted` rollout, every write of a rollout-able section (declarative apply, per-resource,
    revert) MUST compare its plan's `(section, key)` pairs with the rollout's staged keys and refuse on any overlap
    with 409 `rollout_conflict` (new problem code; detail names the rollout ID and the first conflicting key). A
    second staged change set while one is open → 409 `rollout_running` (new problem code; detail: `complete or revert
    rollout <id> first`). Both are checked inside the action (audited as failure). An `urgent` change set that
    overlaps is refused the same way (the administrator completes or reverts first). Device group deletion is a
    write of every section it cascades into (decision 19), so it is subject to the same check.
30. **Compiler overlay** (`server/internal/compiler/rollout.go`, new): `compileOrg` MUST load, per organization and
    round, the open rollout (`GetOpenConfigRollout`: status `running` or `halted`), its change set's `plan` and
    `before`, the canary group's member IDs (`ListActiveGroupMemberIDs`) and the group name → ID map
    (`ListAllDeviceGroups`), into `rolloutOverlay{id uuid.UUID; percent int; canary map[uuid.UUID]bool; files
    []managedconfig.File; units []managedconfig.Unit; holds []pgstore.PackageHold; settings *app.UpdateSettings;
    stagedFiles, stagedUnits, stagedHolds map[key]bool; stagedSettings bool}` where `percent =
    configrollout.Percent(status, waves, current)` (`running` → `waves[current]`, `halted` → the same as running —
    a halted rollout keeps the wave it reached, so devices inside keep the new state and devices outside keep the
    old; `completed`/`reverted` → no overlay). `render` MUST, for a device with `!configrollout.Eligible(Bucket(id,
    rollout), percent, canary[id])`, call `overlay.apply(defs, updates) (ManagedDefinitions, *orgUpdates)` which
    returns copies in which every staged key is replaced by its before item (deleted from the slice when the change
    was `create`; the before item, with its stored `id` and the group ID resolved by name, replaces or is appended
    otherwise; `settings.updates` replaced by the before settings when staged). A device inside the wave renders
    from the live tables and `InsertBundle` MUST set `config_rollout_id = overlay.id` for it; a device outside
    renders from the overlaid inputs with `config_rollout_id NULL`. A device in `report_only` mode (PDK-160) is
    never eligible (it renders the overlay) and never counts. The effective-config endpoint
    (`GET /devices/{id}/effective-config`) is unchanged (it shows the live configuration) and gains the field
    `rollout: {id, in_wave: bool} | null`.
31. Rollout start (in `recordChangeSet`): `InsertConfigRollout` with the settings' waves, thresholds, canary group,
    `status running`, `started_by = actorName(ctx)`; the apply's audit event carries `rollout: staged`, `rollout_id`.
    When the staged change set's resources touch no active device (every device outside wave 0 is unaffected) the
    rollout still runs; the worker advances it on time.

### 3.9 Rollout evaluation and wave actions (PDK-158)

32. `app.ConfigRollouts` (`server/internal/app/configrollouts.go`): `List(ctx, page, statuses)`, `Get(ctx, id)
    (RolloutDetail{Rollout, ChangeSet summary, Counts{eligible, applied, failed, pending}})`, `ListDevices(ctx, id,
    page, filters)`, `Halt(ctx, id, reason)`, `Resume(ctx, id)`, `Advance(ctx, id)`, `Complete(ctx, id)`,
    `Evaluate(ctx, now)` (worker). Specs: `SpecConfigRolloutHalt{Code: config_rollout.halted, RolesWrite}`,
    `SpecConfigRolloutResume{config_rollout.resumed, RolesWrite}`, `SpecConfigRolloutAdvance{config_rollout.advanced,
    RolesWrite}`, `SpecConfigRolloutComplete{config_rollout.completed, RolesWrite}`. Transitions: `Halt`: running →
    halted (`halted_reason = reason`, 2–500 characters required); `Resume`: halted → running (`evaluation_since =
    now()`: failures before the resume no longer count, as for agent rollouts); `Advance`: running → running with
    `current_wave_index + 1`, `wave_started_at = now()` (409 `invalid_state` on the last wave or when halted);
    `Complete`: running | halted → completed (`ended_at`, `ended_reason = 'completed by <actor>'`). Every transition
    that changes the eligible set (`Advance`, `Complete`, `Resume` after a halt does not change it) records
    `rec.StateChanged(ScopeOrg)` so the compiler re-renders; content-equal devices keep their version.
33. **Worker round** (`server/internal/worker/configrollouts.go`, `ConfigRolloutInterval = 60 s`, advisory lock
    key `0x7061646420636672` ("padd cfr"), system principal `worker`): for every organization (`pool.OrganizationIDs`,
    then `InOrg`), for every `running` rollout: `stats = paddock_config_rollout_stats(id, waves[current], canary,
    evaluation_since, staged_ids)`, `configrollout.Decide`; `Halt` → `config_rollout.halted` with params `rollout_id`,
    `change_set_id`, `reason` (`"%d failed devices reached the threshold of %d"`), `wave`, `eligible`, `failed`,
    `threshold` and status `halted`; `Advance` → `config_rollout.advanced` with `wave`, `percent` and
    `StateChanged(ScopeOrg)`; `Complete` → `config_rollout.completed` with `ended_reason = 'every wave passed'` and
    `StateChanged(ScopeOrg)`. Each change is one `runner.RunTx(ScopeOrg, …)`. A halted rollout is not evaluated.
    The round exports one gauge, `paddock_config_rollouts{status}` (rollouts by status across organizations); no
    metric carries an organization label.
34. **Endpoints** (`x-paddock-list` where a list):
    - `GET /api/v1/config-rollouts` (read roles) → `ConfigRolloutPage`; item `ConfigRollout{id, change_set_id,
      waves, current_wave_index, wave_started_at, min_wave_minutes, failure_threshold_percent, failure_threshold_min,
      canary_device_group_id, status, halted_reason, started_by, started_at, ended_at, ended_reason, counts{eligible,
      applied, failed, pending}}`; sort `[started_at, status]`, default `-started_at`; search `[started_by]`; filter
      `status` (repeatable).
    - `GET /api/v1/config-rollouts/{id}` → `ConfigRolloutDetail{rollout, change_set (ChangeSet), staged_resource_ids[]}`.
    - `GET /api/v1/config-rollouts/{id}/devices` → `ConfigRolloutDevicePage`; item `{device_id, hostname, in_wave,
      bundle_version (newest bundle of the device, nullable), carries_rollout (bool: that bundle has this rollout
      id), report_outcome (applied | rejected | none), failed_resource_ids[]}`; sort `[hostname, in_wave,
      report_outcome]`, default `hostname`; search `[hostname]`; filters `in_wave` (boolean), `report_outcome`.
    - `POST /api/v1/config-rollouts/{id}/halt` (body `{reason}`), `/resume`, `/advance`, `/complete` (no body;
      `Csrf` parameter) → 200 `ConfigRollout`; 404 unknown or foreign; 409 `invalid_state` for a wrong status.
35. **Attention and overview hooks**: no attention kind for rollouts (a rollout is organization-level); PDK-164 adds
    the overview card. M9's interface is the audit code `config_rollout.halted`.

### 3.10 Portal and CLI for rollouts (PDK-159)

36. Views `ConfigRollouts.vue` (route `/config-rollouts`, name `config-rollouts`, navigation entry next to *Change
    sets*; `DataList` with status chip, wave `x of y` and the percent, counts, started by/at) and
    `ConfigRolloutDetail.vue` (route `/config-rollouts/:id`, name `config-rollout`): the wave strip (every wave with
    its percent, the current one highlighted, the canary group named), counts, the change set's plan
    (`ChangeSetPlan`), the device `DataList` of decision 34, and the actions **Halt** (ConfirmDialog with required
    reason), **Resume**, **Advance wave**, **Complete** (ConfirmDialog: consequence sentence `every device receives
    this change at its next check-in`), **Revert change set** (navigates to the change set's revert dialog of
    decision 22). The change-set detail shows the rollout chip (`staged`/`urgent` with the reason) and links to the
    rollout.
37. Every form of the rollout-able sections (`ManagedFileForm.vue`, `ManagedUnitForm.vue`, `PackageHoldForm.vue`,
    `UpdateSettings.vue`, the delete confirmations of managed files/units/holds, the revert dialog) MUST, when the
    organization's rollout settings are `enabled` (read once per page from `GET /settings/rollout`), show the
    checkbox `rollout.urgent.label` (*Apply immediately to every device (urgent)*) and, when checked, the required
    reason field; the submit then passes `urgent=true&reason=…` and runs the step-up flow of `lib/stepUp.ts` on 403
    `step_up_required` as the profile forms do. When rollouts are disabled the checkbox is absent.
38. `paddockctl apply` gains `--urgent` and `--reason <text>` (both required together; usage error 2 otherwise);
    the plan output prints `Rollout: staged (rollout <id>)`, `Rollout: urgent` or nothing for immediate from the
    response field `rollout` and `rollout_id` that `ConfigApplyResult` gains. `docs/operations/paddockctl.md` and
    the command table are updated (PDK-163 owns the operator guide; PDK-159 updates the paddockctl page).

### 3.11 Adoption: enrollment method, report-only mode, enforce (PDK-160)

39. Migration `00049_adoption.sql`:

    ```sql
    ALTER TABLE device
      ADD COLUMN enrollment_method text NOT NULL DEFAULT 'unknown' CHECK (enrollment_method IN ('autoinstall','adopted','unknown')),
      ADD COLUMN config_mode text NOT NULL DEFAULT 'enforce' CHECK (config_mode IN ('enforce','report_only')),
      ADD COLUMN config_mode_changed_at timestamptz;
    CREATE INDEX device_org_config_mode_idx ON device (organization_id, config_mode) WHERE config_mode = 'report_only';
    ```

    plus the attention view branch `report_only` (`CREATE OR REPLACE VIEW attention_condition` as `00042` does;
    kind `report_only`, `since = coalesce(config_mode_changed_at, enrolled_at)`, `detail = enrollment_method`, `id =
    'report_only:' || device.id`, for active devices with `config_mode = 'report_only'`); the kind is added to the
    `AttentionKind` enum of `admin.yaml`, to the kinds list of `server/internal/app/attention.go` and to the portal's
    `attention.kinds.*` keys, exactly as `agent_rollback_pending` was added (`00040_rollback_failed.sql`, ADR 0024
    rule 8).
40. `ingest.Enroll` gains `EnrollmentMethod string`; the gateway copies `EnrollRequest.EnrollmentMethod` after
    validating it is `""`, `autoinstall` or `adopted` (400 `invalid_request` otherwise). `createDevice` writes
    `enrollment_method` (`unknown` for `""`) and `config_mode = 'report_only'` for `adopted`, else `enforce`;
    `device.enrolled` gains the params `enrollment_method`, `config_mode`.
41. Compiler: `ListCompileTargets` returns `config_mode`; `render` sets `Mode = bundle.ModeReportOnly` for
    `report_only` devices and renders them with the overlay (decision 30).
42. `POST /api/v1/devices/{id}/enforce` (roles `org_admin, org_operator`; `x-paddock-audit:
    device.enforcement_enabled`; `Csrf`; body `{hostname}` which MUST equal the device's hostname, 400
    `invalid_request` otherwise — the typed-name confirmation of ADR 0018 is verified server-side, as the destroy
    request does) → 200 `Device`; 409 `invalid_state` unless `config_mode = report_only` and state `active`. The use
    case sets `config_mode = enforce`, `config_mode_changed_at = now()`, records `rec.StateChanged(ScopeDevice)`;
    params `hostname`, `enrollment_method`, `report_only_since`.
43. `Device` (OpenAPI) gains `enrollment_method`, `config_mode`, `config_mode_changed_at` (nullable); the device
    list gets the filters `enrollment_method` and `config_mode` (repeatable) and `x-paddock-list.filters` lists them;
    `DeviceDetail` gains `config_status` (decision 14). Portal: `DeviceHeader.vue` shows the chips `adopted` /
    `autoinstall` (none for `unknown`) and `report-only`; the device overview shows the **Enable enforcement** button
    (`DangerZone` style, `ConfirmDialog` with typed hostname, consequence sentence `the agent will quarantine foreign
    sudoers files, remove unexpected members of privileged groups, install the login component and apply every
    managed resource`), the device list gets the two filters; the attention page localizes kind `report_only`.
    `paddockctl devices list` gains `--enrollment-method` and `--config-mode` (same module as PDK-159's CLI work;
    PDK-160 owns these two flags).

### 3.12 Runbook (PDK-153, PDK-163)

44. `docs/operations/enroll-existing.md` (new, English) MUST contain, in this order: 1 When to use it (an installed
    Ubuntu 24.04/26.04 laptop; what adoption does and does not do: disk stays `unmanaged` (RR-04) unless reinstalled,
    report-only first apply, what enforcement changes); 2 Prerequisites (UEFI not required, TPM optional, network to
    `device.<domain>` and `bundles.<domain>`, root shell); 3 Pre-flight (`paddockd preflight`, the check table of
    decision 11 with what each result means and what to fix); 4 Install the packages (download
    `https://bundles.<domain>/packages/<version>/paddock-supervisor_<version>_<arch>.deb` and `paddock-agent_…`,
    optionally `paddock-revoke_…`, verify the SHA-256 against the release page of the portal
    (`/platform/agent-releases/<version>`) or `GET /api/platform/v1/agent-releases/<version>`, `dpkg -i`); 5 Enroll
    (create an enrollment token, write the enrollment configuration to `/etc/paddock/enroll.json` with `umask 077`,
    `paddockd enroll --config /etc/paddock/enroll.json --remove-config`, exit codes, approval when the token is not
    auto-approve); 6 Report-only phase (what the *Apply status* tab shows, how to read `pending` resources and their
    planned changes, the attention item `report_only`); 7 Enable enforcement (the dialog, the tamper events the
    first enforced apply records and why they are expected, the login component installation, the local
    administrator); 8 Rollback of an adoption (retire the device, `apt remove` of the packages, what is left on the
    device: the quarantine directory, `/var/lib/paddock`); 9 Troubleshooting (`paddockd preflight`, `journalctl -u
    paddock-supervisor`, `invalid_token`, `clock_skew`). Until PDK-160/161 are merged the runbook states that
    devices enrolled with an agent before release X are `unknown` and enforced at once; PDK-163 removes that note.
45. `docs/operations/configuration-rollouts.md` (new, PDK-163): settings, how a staged change set rolls out, the
    counts, halt/resume/advance/complete, revert, the urgent opt-out and its audit trail, what is never staged, the
    interaction with agent releases, and the audit codes. `docs/architecture.md` amendments (PDK-163, dated
    `Amendment 2026-10-15 (M11)`): §7.1 (overlay, `config_rollout`, bundle tag), §7.2 (`mode`), §11.3 (report-only
    apply), §11.5 (`bundle.applied` resources), §6.6 (`enrollment_method`), §16.1 (new tables), §17.1 (new
    endpoints), §12 (new subsection *Adoption of existing devices*). `docs/compliance/privacy.md` row "Events of the
    agent's own work" gains `per-resource outcome (resource ID, status, error message) and, in report-only mode, the
    planned change lines (file names, unit names, user and group names)`. `CHANGELOG.md` `[Unreleased]`.

### 3.13 Overview (PDK-164)

46. `GET /api/v1/overview` gains `configuration: {rollout: ConfigRollout | null (the open rollout), failed_resources:
    int (distinct resource IDs with at least one failed active device), failed_devices: int, report_only_devices:
    int}`; `OverviewResult` gains `Configuration`; the portal overview gets the card **Configuration** (rollout
    status with wave and counts linking to the rollout, failed resources linking to `/config-status`, report-only
    devices linking to the device list filtered by `config_mode=report_only`). ADR 0028 rule: the counts are
    set-based queries over `device_resource_status` and `device`, no per-row function calls.

## 4. Non-goals

- No staging of permission profiles, profile assignments, device groups, login settings, user locks, login
  suspension, revocation, DMS or agent releases (ADR 0033 option B1).
- No `settings.rollout` section in the declarative document; no `paddockctl` commands for rollouts or reverts
  beyond the flags of decisions 38 and 43.
- No silence-based failure signal (ADR 0033 option D2); no notifications (M9); no retention or purge of
  `change_set.before`, `device_bundle_report`, `device_resource_status` (M10 owns the matrix; this plan ships the
  columns and the grant).
- No adoption of an existing LUKS volume (TPM2+PIN enrollment, header escrow) — the disk stays `unmanaged`.
- No per-resource device list on the fleet status page (decision 16).
- No change to `agent/internal/revoke/`, `agent/cmd/paddock-revoke/`, `pkg/revocation`, the revocation issuer or
  any revocation endpoint. No new Go module, npm package or container image.
- No change to agent rollouts (`agentrelease`, `agent_rollout`, `worker/rollouts.go`) beyond reading their pattern.
- No new event type in `protocol.EventTypes`.

## 5. Affected files

| Path | Action | Purpose |
| --- | --- | --- |
| `pkg/protocol/types.go`, `api/openapi/device.yaml` | change | `BundleAppliedResource`, status constants, `EnrollRequest.enrollment_method` (PDK-150, 161) |
| `pkg/bundle/bundle.go` | change | `Mode` field and constants (PDK-150) |
| `agent/internal/apply/apply.go`, `agent/internal/agent/bundles.go`, `agent/internal/agent/localadmin.go` | change | per-resource outcomes, report-only apply, drift skip (PDK-150, 161) |
| `agent/internal/enroll/enroll.go`, `agent/cmd/paddockd/main.go` | change | enrollment method, `preflight` subcommand (PDK-153, 161) |
| `agent/internal/preflight/preflight.go` (+ `_test.go`) | new | pre-flight checks (PDK-153) |
| `server/migrations/paddock/00045_config_status.sql` … `00049_adoption.sql` | new | decisions 12, 17, 23, 27, 39 |
| `server/internal/adapters/postgres/queries/device_config_status.sql`, `config_rollout.sql`, `rollout_settings.sql` | new | sqlc queries |
| `server/internal/adapters/postgres/queries/change_set.sql`, `bundle.sql`, `device.sql`, `device_status.sql`, `attention.sql`, `overview.sql` | change | new columns, filters, counts |
| `server/internal/domain/configrollout/configrollout.go` (+ `_test.go`) | new | bucket, waves, decide (decision 28) |
| `server/internal/domain/declarative/diff.go` | change | `RolloutSections`, item accessors for the revert (decision 21) |
| `server/internal/domain/audit/codes.go` | change | new codes and params (§6.4) |
| `server/internal/problem/problem.go` | change | `rollout_conflict`, `rollout_running` |
| `server/internal/app/changesets.go` (new), `declarative.go`, `declarative_exec.go`, `managedconfig.go`, `updates.go`, `privileges.go`, `devicegroups.go`, `loginsettings.go` | change | change sets for every write, staging, revert (PDK-154, 155, 157) |
| `server/internal/app/configstatus.go`, `configrollouts.go`, `rolloutsettings.go` | new | use cases (PDK-151, 156, 158) |
| `server/internal/app/devicereports.go`, `devices.go`, `enrollments.go`, `overview.go`, `attention.go` | change | ingest, enforce, enrollment method, overview (PDK-151, 160, 164) |
| `server/internal/compiler/compiler.go`, `compiler/rollout.go` (new), `compiler/updates.go` | change / new | overlay, bundle tag, report-only mode (PDK-157, 160) |
| `server/internal/worker/configrollouts.go` (new), `worker/worker.go` | new / change | evaluation round (PDK-158) |
| `server/internal/ingest/ingest.go`, `server/internal/transport/http/device/handlers.go` | change | `EnrollmentMethod` (PDK-160) |
| `api/openapi/admin.yaml` | change | every endpoint and schema of §6.1 |
| `server/internal/transport/http/admin/handlers_config.go`, `handlers_devices.go`, `handlers_managed.go`, `handlers_updates.go`, `handlers_overview.go`, `handlers.go` | change | handlers, privileged route table |
| `server/internal/transport/http/admin/handlers_configstatus.go`, `handlers_rollouts.go` | new | handlers (PDK-151, 156, 158) |
| `server/web/src/views/DeviceApplyStatus.vue`, `ConfigStatus.vue`, `RolloutSettings.vue`, `ConfigRollouts.vue`, `ConfigRolloutDetail.vue` | new | portal views |
| `server/web/src/views/ChangeSets.vue`, `DeviceOverview.vue`, `Devices.vue`, `Overview.vue`, `Attention.vue`, `ManagedFiles.vue`, `ManagedUnits.vue`, `PackageHolds.vue`, `UpdateSettings.vue` | change | revert, enforce, filters, urgent opt-out, overview card |
| `server/web/src/components/DeviceTabs.vue`, `DeviceHeader.vue`, `ManagedFileForm.vue`, `ManagedUnitForm.vue`, `PackageHoldForm.vue`, `UrgentOptOut.vue` (new) | change / new | tab, chips, urgent checkbox |
| `server/web/src/lib/configStatus.ts`, `configRollouts.ts`, `rolloutSettings.ts` (new), `changeSets.ts`, `devices.ts`, `navigation.ts`, `deviceDetailPage.ts`, `overview.ts` | new / change | API wrappers, navigation |
| `server/web/src/router.ts`, `locales/en.json`, `locales/de.json` | change | routes, texts, `audit.<code>` keys |
| `server/web/e2e/configStatus.spec.ts`, `configRollouts.spec.ts`, `adoption.spec.ts` | new | e2e gates |
| `cli/internal/cmd/commands.go` | change | `--urgent --reason`, device list flags (PDK-159, 160) |
| `test/acceptance/config_status_test.go`, `change_set_revert_test.go`, `config_rollout_test.go`, `adoption_test.go` | new | acceptance gates (§8) |
| `test/system/config_test.go` | new | VM gates (PDK-162) |
| `docs/operations/enroll-existing.md`, `docs/operations/configuration-rollouts.md` | new | runbooks |
| `docs/architecture.md`, `docs/compliance/privacy.md`, `docs/operations/paddockctl.md`, `docs/operations/autoinstall.md`, `README.md`, `CHANGELOG.md` | change | amendments and pointers (PDK-163) |

Not to be touched: `agent/internal/revoke/`, `agent/cmd/paddock-revoke/`, `pkg/revocation/`,
`server/internal/revocationissuer/`, `server/internal/revocationsign/`, `agent/internal/supervisor/`,
`agent/cmd/paddock-supervisor/`, `server/internal/domain/agentrelease/`, `server/internal/app/agentreleases.go`,
`server/internal/worker/rollouts.go`, every ADR but 0033, `docs/reqirements/`, `deploy/`, existing migrations.

## 6. Interfaces and formats

### 6.1 Admin API (additions to `api/openapi/admin.yaml`)

```
GET  /api/v1/devices/{id}/config-status          list: sort [resource_id,status,occurred_at] default resource_id; search [resource_id]; filters [status]
GET  /api/v1/devices/{id}/bundles                list: sort [version,created_at] default -version; filters [outcome]
GET  /api/v1/config-status                       list: sort [resource_id,failed,pending,applied] default -failed; search [resource_id]; filters [status]
POST /api/v1/change-sets/{id}/revert             ?dry_run&expected_plan&urgent&reason → 200 ConfigApplyResult; 400,401,403,404,409,412   audit config.reverted
GET  /api/v1/settings/rollout                    → 200 RolloutSettings
PUT  /api/v1/settings/rollout                    body RolloutSettingsUpdate → 200; 400,401,403,404                          audit settings.rollout_changed
GET  /api/v1/config-rollouts                     list: sort [started_at,status] default -started_at; search [started_by]; filters [status]
GET  /api/v1/config-rollouts/{id}                → 200 ConfigRolloutDetail; 404
GET  /api/v1/config-rollouts/{id}/devices        list: sort [hostname,in_wave,report_outcome] default hostname; search [hostname]; filters [in_wave,report_outcome]
POST /api/v1/config-rollouts/{id}/halt           body {reason} → 200 ConfigRollout; 400,404,409                              audit config_rollout.halted
POST /api/v1/config-rollouts/{id}/resume         → 200; 404,409                                                             audit config_rollout.resumed
POST /api/v1/config-rollouts/{id}/advance        → 200; 404,409                                                             audit config_rollout.advanced
POST /api/v1/config-rollouts/{id}/complete       → 200; 404,409                                                             audit config_rollout.completed
POST /api/v1/devices/{id}/enforce                body {hostname} → 200 Device; 400,404,409                                   audit device.enforcement_enabled
PUT  /api/v1/config, managed-files, managed-units, package-holds, settings/updates: query urgent (boolean), reason (string 2..500)
GET  /api/v1/devices: filters enrollment_method, config_mode (repeatable)
GET  /api/v1/change-sets: filter rollout (repeatable)
```

Schemas (required fields in brackets):

```yaml
DeviceResourceStatus: [resource_id, type, status, message, changes, bundle_version, occurred_at]
  status: enum [applied, failed, pending, drift_corrected]
DeviceBundle: [version, created_at, schema_version, config_rollout_id, report]
  report: nullable {outcome: enum [applied, rejected], mode: enum [enforce, report_only], changed, error_count, reason (nullable), occurred_at}
ResourceStatus: [resource_id, type, applied, failed, pending, drift_corrected, last_failure_at]
ChangeSet: + rollout (enum [immediate, staged, urgent]), urgent_reason (nullable), reverts_change_set_id (nullable), reverted_by (nullable), before_available (boolean), rollout_id (nullable)
ConfigApplyResult: + rollout (enum, nullable for dry runs), rollout_id (nullable)
RolloutSettings: [enabled, waves, min_wave_minutes, failure_threshold_percent, failure_threshold_min, canary_device_group_id, updated_at]
RolloutSettingsUpdate: additionalProperties false; same fields without updated_at; waves minItems 1 maxItems 10 items 1..100
ConfigRollout: [id, change_set_id, waves, current_wave_index, wave_started_at, min_wave_minutes, failure_threshold_percent, failure_threshold_min, canary_device_group_id, status, halted_reason, started_by, started_at, ended_at, ended_reason, counts]
  status: enum [running, halted, completed, reverted]; counts: {eligible, applied, failed, pending}
ConfigRolloutDetail: [rollout, change_set, staged_resource_ids]
ConfigRolloutDevice: [device_id, hostname, in_wave, bundle_version, carries_rollout, report_outcome, failed_resource_ids]
ConfigRolloutHalt: [reason] (2..500)
DeviceEnforce: [hostname]
Device: + enrollment_method (enum [autoinstall, adopted, unknown]), config_mode (enum [enforce, report_only]), config_mode_changed_at (nullable)
DeviceDetail: + config_status {applied, failed, pending, drift_corrected}
EffectiveConfig: + rollout (nullable {id, in_wave})
Overview: + configuration {rollout (ConfigRollout, nullable), failed_resources, failed_devices, report_only_devices}
```

New problem codes (`server/internal/problem/problem.go`): `RolloutConflict = {Code: "rollout_conflict", Status:
409}`, `RolloutRunning = {Code: "rollout_running", Status: 409}`.

### 6.2 Device protocol (`pkg/protocol/types.go`, `api/openapi/device.yaml`)

```go
// Resource outcome statuses of BundleAppliedResource.Status (plan M11 decision 7).
const (
	ResourceApplied        = "applied"
	ResourceFailed         = "failed"
	ResourcePending        = "pending"         // report-only: the resource would change
	ResourceDriftCorrected = "drift_corrected" // server-side only (config.drift_corrected)
)

// Bundle modes of BundleApplied.Mode (plan M11 decision 8).
const (
	BundleModeEnforce    = "enforce"
	BundleModeReportOnly = "report_only"
)

// BundleAppliedResource is one entry of bundle.applied's resources: the outcome of one resource.
type BundleAppliedResource struct {
	ID      string   `json:"id"`
	Status  string   `json:"status"`
	Message string   `json:"message,omitempty"`
	Changes []string `json:"changes,omitempty"` // report-only: the planned changes, at most 50 lines
}

// Enrollment methods of EnrollRequest.EnrollmentMethod (plan M11 decision 10).
const (
	EnrollmentAutoinstall = "autoinstall"
	EnrollmentAdopted     = "adopted"
)
```

`bundle.applied` data (agent → server), both agents and servers tolerate absence of the new fields:

```json
{"version": 4183, "changed": 2, "errors": [{"id": "unit:foo.service", "message": "unknown unit foo.service"}],
 "mode": "enforce",
 "resources": [{"id": "time", "status": "applied"}, {"id": "file:/etc/motd", "status": "applied"},
               {"id": "unit:foo.service", "status": "failed", "message": "unknown unit foo.service"}]}
```

Report-only: `{"version": 12, "changed": 0, "errors": [], "mode": "report_only", "resources": [{"id": "sudo",
"status": "pending", "changes": ["quarantine 90-local-admins", "remove bob from sudo", "write paddock-u-…"]}, …]}`.

Bundle (`pkg/bundle.Bundle`): `"mode": "report_only"` optional top-level string; absent = enforce.

`EnrollRequest`: `"enrollment_method": "adopted"` optional, enum `autoinstall | adopted`.

### 6.3 Go signatures

```go
// agent/internal/apply/apply.go
type ResourceOutcome struct{ ID, Status, Message string; Changes []string }
type Report struct{ Version int64; Changed int; Errors []ResourceError; Mode string; Resources []ResourceOutcome; ChangedIDs []string `json:"-"` }
func (a *Applier) Apply(ctx context.Context, b *bundle.Bundle) Report   // report-only when b.Mode == bundle.ModeReportOnly

// agent/internal/preflight/preflight.go
type Result struct{ Name, Status, Detail string }                        // Status: ok | warn | fail | info
func Run(ctx context.Context, l paths.Layout, sys reconcile.System, configPath string) []Result

// pkg/bundle/bundle.go
const ModeEnforce, ModeReportOnly = "", "report_only"

// server/internal/domain/configrollout/configrollout.go
func Bucket(device, rollout uuid.UUID) int
func Eligible(bucket, percent int, canary bool) bool
func ValidateWaves(w []int) error
func Threshold(eligible int64, percent, minimum int) int64
func Decide(r Rollout, now time.Time) Decision
func Percent(status string, waves []int, current int) int
func StagedKeys(p declarative.Plan) map[string]map[string]bool
func StagedResourceIDs(p declarative.Plan) []string

// server/internal/app/changesets.go
func recordChangeSet(ctx context.Context, q *pgstore.Queries, rec Recorder, plan declarative.Plan, before map[string]map[string]any, opts WriteOptions) (uuid.UUID, error)
type WriteOptions struct{ Urgent bool; Reason string }
func requireNotStaged(ctx context.Context, q *pgstore.Queries, plan declarative.Plan) error

// server/internal/app/declarative.go
func (d *Declarative) Revert(ctx context.Context, id uuid.UUID, expectedPlan string, dryRun bool, opts WriteOptions) (uuid.UUID, declarative.Plan, string, error) // id, plan, rollout mode

// server/internal/app/configrollouts.go
func (c *ConfigRollouts) Halt(ctx context.Context, id uuid.UUID, reason string) (pgstore.ConfigRollout, error)
func (c *ConfigRollouts) Resume / Advance / Complete(ctx context.Context, id uuid.UUID) (pgstore.ConfigRollout, error)
func (c *ConfigRollouts) Evaluate(ctx context.Context, now time.Time) error

// server/internal/app/devices.go
func (d *Devices) Enforce(ctx context.Context, id uuid.UUID, hostname string) (pgstore.Device, error)

// server/internal/compiler/rollout.go
type rolloutOverlay struct{ … }
func loadOverlay(ctx context.Context, q *pgstore.Queries) (*rolloutOverlay, error)
func (o *rolloutOverlay) eligible(device uuid.UUID) bool
func (o *rolloutOverlay) apply(defs app.ManagedDefinitions, u *orgUpdates) (app.ManagedDefinitions, *orgUpdates)
```

### 6.4 Audit codes (closed registry, `server/internal/domain/audit/codes.go`)

| Code | Actor | Target | Params | Outcomes |
| --- | --- | --- | --- | --- |
| `config.reverted` | admin / token | change_set (new) | `change_set_id`, `reverts_change_set_id`, `plan_sha256`, `created`, `updated`, `deleted`, `sections`, `rollout`, `rollout_id`, `rollout_status`, `urgent_reason` | success, failure, denied |
| `settings.rollout_changed` | admin | organization | `enabled`, `waves`, `min_wave_minutes`, `failure_threshold_percent`, `failure_threshold_min`, `canary_device_group_id` | success, failure, denied |
| `config_rollout.advanced` | system / admin | config_rollout | `rollout_id`, `change_set_id`, `wave`, `percent`, `manual` | success, failure, denied |
| `config_rollout.halted` | system / admin | config_rollout | `rollout_id`, `change_set_id`, `reason`, `wave`, `eligible`, `failed`, `threshold` | success, failure, denied |
| `config_rollout.resumed` | admin | config_rollout | `rollout_id`, `change_set_id`, `wave` | success, failure, denied |
| `config_rollout.completed` | system / admin | config_rollout | `rollout_id`, `change_set_id`, `wave`, `manual` | success, failure, denied |
| `device.enforcement_enabled` | admin | device | `hostname`, `enrollment_method`, `report_only_since` | success, failure, denied |

Extended params: `config.applied`, `managed_file.*`, `managed_unit.*`, `package_hold.*`, `settings.updates_changed`,
`settings.login_changed`, `permission_profile.*`, `profile_assignment.*`, `device_group.*` gain `change_set_id`,
`rollout`, `rollout_id`, `urgent_reason`; `device.enrolled` gains `enrollment_method`, `config_mode`;
`device.bundle_applied` gains `mode` (`deviceEventParams`). Portal keys `audit.<code>` in both locales; `make gen`
regenerates `lib/auditCodes.gen.ts` and the audit code document.

### 6.5 Paddockctl

```
paddockctl apply -f <file> [--dry-run] [--yes] [--urgent --reason <text>] [-o text|json]
paddockctl devices list [... existing ...] [--enrollment-method <m>]… [--config-mode <m>]…
```

## 7. Umsetzungsschritte (tickets, in order)

1. **PDK-150 — Agent reports per-resource outcomes.** Decisions 7, 8 (field only; report-only apply is PDK-161).
   `pkg/protocol`, `pkg/bundle`, `agent/internal/apply`, `device.yaml`. Verify: `GOTOOLCHAIN=auto go test -count=1
   ./pkg/... ./agent/...`; the `bundle.applied` of a devicesim-free unit test contains `resources` for every resource
   and `mode: enforce`.
2. **PDK-151 — Server stores and lists apply status and bundle history.** Decisions 12–14; migration 00045; ingest
   in `devicereports.go`; three endpoints; `DeviceDetail.config_status`. Verify: `make gen` no diff; `make lint
   test`; acceptance gate `TestConfigStatus` (§8).
3. **PDK-152 — Portal apply status.** Decisions 15–16; e2e `configStatus.spec.ts`. Verify: `make e2e`.
4. **PDK-153 — Enroll an existing device: runbook and preflight.** Decisions 11, 44 (runbook without the
   report-only sections 6–7 finalized: they reference the mode as "from the next release"; PDK-163 completes them).
   Verify: `paddockd preflight` on a test VM prints the table; `make system-test VM=paddock-u2404 T=TestPreflight`
   (PDK-162 adds the gate; PDK-153 ships the unit tests with `fakesys`).
5. **PDK-154 — Change sets for every configuration write, before-states.** Decisions 17–20; migration 00046.
   Verify: acceptance `TestDeclarativeConfig` unchanged green; new `TestChangeSetsEveryWrite` (§8).
6. **PDK-155 — Revert a change set.** Decisions 21–22. Verify: acceptance `TestChangeSetRevert` (§8); e2e
   `changeSets.spec.ts` gains the revert flow.
7. **PDK-156 — Rollout settings.** Decisions 23–24; migration 00047; `configrollout.ValidateWaves` (the domain
   package starts here with waves only). Verify: acceptance `TestRolloutSettings` (§8).
8. **PDK-157 — Staged change sets and the compiler overlay.** Decisions 25–31; migration 00048; the domain package
   completed. Verify: acceptance `TestConfigRolloutStaging` (§8); compiler unit tests of the overlay with every
   action per section.
9. **PDK-158 — Rollout evaluation and wave actions.** Decisions 32–35. Verify: acceptance `TestConfigRolloutAutoStop`,
   `TestConfigRolloutActions` (§8).
10. **PDK-159 — Portal and CLI for rollouts and the urgent opt-out.** Decisions 36–38; e2e `configRollouts.spec.ts`.
    Verify: `make e2e`; `paddockctl apply --urgent --reason x` against the development stack.
11. **PDK-160 — Enrollment method, report-only mode, enforce.** Decisions 39–43 (server, API, portal, CLI flags);
    migration 00049. Verify: acceptance `TestAdoption` (§8) with devicesim sending `enrollment_method: adopted` and
    a `bundle.applied` with `mode: report_only`.
12. **PDK-161 — Agent report-only apply and enrollment method.** Decisions 9–10. Verify: `go test ./agent/...`; the
    applier's report-only unit test asserts that `fakesys` recorded no write; system gate of PDK-162.
13. **PDK-162 — System gates on the VMs.** `test/system/config_test.go`: `TestPreflight`, `TestAdoptionGates`,
    `TestConfigRolloutGates` (§8). Verify: `make system-test VM=all T='TestPreflight|TestAdoptionGates|TestConfigRolloutGates'`.
14. **PDK-163 — Documentation.** Decisions 44 (final), 45; architecture amendments; privacy row; CHANGELOG. Verify:
    every endpoint of §6.1 appears in `docs/architecture.md` §17.1 or the amendment; `make scan-secrets`.
15. **PDK-164 — Overview card.** Decision 46. Verify: acceptance `TestOverview` extended; e2e overview check.

PDK-152 MAY run in parallel with PDK-153; PDK-156 MAY run in parallel with PDK-155; PDK-161 MAY run in parallel with
PDK-160 once PDK-150 is merged; PDK-163 and PDK-164 MAY run in parallel after PDK-162.

## 8. Tests

- **Unit (Go):** `apply` report shape (every resource listed, statuses, cut-off of 50 change lines); report-only
  apply never calls a reconciler's `Apply` (`fakesys` write log empty) and skips drift; `preflight` checks with
  `fakesys` (every result value reachable); `configrollout` (bucket equals SQL on random pairs; `Eligible`;
  `Decide` table: keep/halt/advance/complete, halted and completed keep; threshold rounding); `StagedKeys` and
  `StagedResourceIDs` for every section and action; compiler overlay (`create` removes, `update` restores with ID and
  group, `delete` restores, settings restore, untouched keys unchanged, devices in wave untouched, report-only
  devices never eligible); `recordChangeSet` plan and before shape per section; revert desired-document builder
  (create → removed, delete → restored, update → restored, keys created since kept, purged before refused).
- **Integration (Go, `pgtest`):** migrations 00045–00049 apply on the previous schema; RLS fail-closed for every new
  table (the isolation fixtures of `isolation_test.go` gain them: cross-organization reads of `config_rollout`,
  `device_resource_status`, `device_bundle_report`, `organization_rollout_settings` return nothing / 404);
  `config_rollout_one_open_idx`; `paddock_config_rollout_stats` counts (eligible by bucket and canary, failed by
  rejected report and by failed staged resource, not by failures on unstaged resources, not before
  `evaluation_since`); ingest upserts (newer wins, older agent without `resources` keeps rows, resources that left
  the bundle are deleted); the privileged route table and `x-paddock-audit` (`spec_test.go`), the list contract
  (`listspec_test.go`) for every new collection `GET`.
- **Acceptance (`test/acceptance/`, against the running stack):**
  - `TestConfigStatus`: a devicesim device sends `bundle.applied` with resources → `GET /devices/{id}/config-status`
    lists them with statuses; a later `config.drift_corrected` marks `drift_corrected`; `GET /config-status` counts
    the failed resource once per device; `GET /devices/{id}/bundles` shows the version with its report; an
    `org_auditor` can read all three; a device of another organization is 404.
  - `TestChangeSetsEveryWrite`: a managed file created through `POST /managed-files` appears as a change set with
    one `create` change; its update records `before` (`before_available: true`) with the full content; the audit
    event `managed_file.updated` carries `change_set_id`.
  - `TestChangeSetRevert`: dry run returns the inverse plan and `plan_sha256`; revert without `expected_plan` → 400;
    with a stale hash → 412; a successful revert creates a change set with `reverts_change_set_id`, the original
    shows `reverted_by`, the file content is the before content, an item created after the original is kept; a
    second revert of the same original → 409 `invalid_state`; `config.reverted` is in the audit index once with
    outcome success and once with failure for the 412.
  - `TestRolloutSettings`: defaults, validation (waves not ending with 100 → 400; `min_wave_minutes` 0 → 400 — the
    development stack accepts ≥ 1, the production minimum of 15 is a unit test; a foreign canary group → 404),
    audit event with every field, `org_operator` → 403.
  - `TestConfigRolloutStaging` (own organization via `gateOrg`): enable rollouts with `waves [50,100]`, canary group
    with device A; devices A, B, C enrolled (devicesim, schema 2); a managed file apply returns `rollout: staged`
    and a `rollout_id`; A's next bundle contains the file, and the bundle row carries the rollout (via
    `GET /devices/{id}/bundles`); of B and C, those with bucket ≥ 50 receive a new bundle only if other content
    changed (the gate computes `configrollout.Bucket` itself and asserts per device); a second staged apply → 409
    `rollout_running`; an apply changing the staged file → 409 `rollout_conflict`; an apply of an unrelated unit is
    `immediate` and reaches every device; `urgent=true` without reason → 400, with reason and without step-up → 403
    `step_up_required`, with step-up → `rollout: urgent` and every device gets it; the change set's `rollout` field
    and the audit params match.
  - `TestConfigRolloutAutoStop`: `waves [100]`, `failure_threshold_min 1`, `failure_threshold_percent 0`,
    `min_wave_minutes 60`; a device reports `bundle.applied` with a `failed` entry for the staged resource → within
    3 minutes the rollout is `halted` by `worker` (audit `config_rollout.halted`, outcome success, exactly one); a
    failure on an unstaged resource does not halt; `resume` → running; `complete` → completed and a device outside
    the wave receives the file at its next check-in; the revert of the staged change set of a running rollout ends
    it with `reverted`.
  - `TestConfigRolloutActions`: halt with reason (400 without), resume, advance (409 at the last wave), complete,
    404 for a foreign rollout, `org_auditor` → 403 for every POST, `GET /config-rollouts/{id}/devices` marks
    `in_wave` per device.
  - `TestAdoption`: devicesim enrolls with `enrollment_method: adopted` → device shows `adopted`, `report_only`; its
    bundle has `mode: report_only`; a `bundle.applied` with `mode: report_only` and `pending` resources is listed
    with its `changes`; the attention list has kind `report_only` for it; `POST /devices/{id}/enforce` with a wrong
    hostname → 400, right hostname → `enforce`, the next bundle has no `mode`, the attention item is gone, the audit
    event `device.enforcement_enabled` exists; a device enrolled without the field is `unknown`/`enforce`; the
    device list filters work.
  - `TestOverview` extension: the `configuration` object with the open rollout and the counts.
  - `TestIsolation` fixtures: the new tables and endpoints.
- **System (`test/system/config_test.go`, VMs, PDK-162):**
  - `TestPreflight`: on a fresh VM `paddockd preflight --json` exits 0 or 1 and reports `os ok`, `root ok`,
    `sudoers_d warn` after the test drops a file into `/etc/sudoers.d`, `privileged_groups warn` listing the VM user.
  - `TestAdoptionGates` (per VM, `forEachVM`): the VM gets a foreign `/etc/sudoers.d/90-systest` and the test user
    in group `sudo`; install packages and enroll with `paddockd enroll` (as `Install` does) → the device is
    `adopted`/`report_only`; `device.bundle_applied` with `mode report_only` arrives; the file and the membership
    are unchanged on the VM; the config status shows `sudo` as `pending` with `quarantine 90-systest` and `remove
    <user> from sudo`; the managed files of this run are `pending` with their path; `POST /enforce` → the next
    `device.bundle_applied` is `enforce`, the file is quarantined, the membership removed, the managed files written
    (`tamper.sudoers_d_file` and `tamper.sudo_group_member` audited).
  - `TestConfigRolloutGates` (both VMs, like S5): rollouts enabled with waves `[1,100]`, canary group = VM A's
    group, `min_wave_minutes 60`; a managed file created for the device group of both VMs → A applies it
    (`device.bundle_applied` with the file `applied`), B does not receive a new bundle within 2 minutes; `complete`
    → B applies it; then a second staged change set that fails on a real VM: a managed unit resource naming a unit
    that does not exist (`systest-missing-<run>.service`, error `unknown unit …`) → A reports `failed` for
    `unit:…` → the worker halts the rollout (`config_rollout.halted` by `worker`); revert of that change set → A's
    next apply has no such resource and the rollout is `reverted`.
- **Portal (`server/web/e2e/`):** `configStatus.spec.ts` (device tab and fleet page render the devicesim data,
  accessible, no CSP violation), `configRollouts.spec.ts` (settings page, urgent checkbox appears when enabled,
  rollout list and detail, halt dialog requires a reason, complete dialog), `adoption.spec.ts` (chips, enforce dialog
  with typed hostname, attention item), `changeSets.spec.ts` (revert dialog shows the inverse plan).
- Never weakened: every existing gate, in particular `TestDeclarativeConfig`, `TestAgentGates` S1–S4,
  `TestRolloutAutoStop` and the list contract test.

## 9. Acceptance criteria

- **C1 apply status (F-03; org admin, operator, auditor):** Given an enrolled device that applied a bundle with one
  failed resource, when the administrator opens the device's *Apply status* tab, then every resource of the bundle
  is listed with `applied` or `failed` and the error message, and the fleet page *Configuration status* shows that
  resource with `failed = 1`; given an older agent that sends no `resources`, then the failed resource is listed and
  no other row appears.
- **C2 history (A.8.9; auditor):** Given a device with three bundle versions, when the auditor opens *Bundle
  history*, then every version shows its creation time, the report outcome and time, and the rollout it belonged
  to; `GET /devices/{id}/bundles` answers the same.
- **C3 change sets (ADR 0011; administrator):** Given a managed file updated in the portal, then *Change sets*
  lists a change set with the update and `before_available`; given `paddockctl apply`, then the change set is
  unchanged from today plus the new fields.
- **C4 revert (F-02; administrator, auditor):** Given a change set with before-states, when the administrator
  reverts it, then a dry-run plan is shown first, the revert is refused when the plan changed meanwhile, the result
  is a new change set referencing the original, the original shows who reverted it, items created since are kept,
  and `config.reverted` is in the audit log with the plan hash. Given a change set whose before-state was purged or
  never stored, then the revert is refused with a visible reason.
- **C5 staged rollout (F-01; administrator):** Given rollouts enabled with a canary group, when a managed file is
  changed, then the canary group's devices and the first wave's share receive it at their next check-in and every
  other device receives nothing new; the change set shows `staged` and the rollout page shows the wave, the counts
  and the devices with `in_wave`; given failures on the staged resource reaching the threshold, then the rollout is
  halted by the worker within one round and audited `config_rollout.halted`; given *Complete*, then every device
  receives the change; given an unrelated change during the rollout, then it reaches every device immediately.
- **C6 urgent opt-out (AUD-15; administrator, auditor):** Given rollouts enabled, when the administrator applies a
  change with *urgent* and a reason after a step-up, then every device receives it, the change set shows `urgent`
  with the reason, and the audit event carries `rollout: urgent` and `urgent_reason`; without a reason or without a
  step-up the change is refused and the refusal audited.
- **C7 never staged (contract 8, auditor):** Given a running rollout, when a user is locked, logins are suspended, a
  profile assignment is removed or a revocation is approved, then the affected devices receive it at their next
  check-in regardless of the wave, and the audit events are unchanged.
- **C8 adoption (F-19; administrator, device user):** Given an installed Ubuntu laptop with a foreign sudoers file
  and an extra sudo group member, when the operator follows `enroll-existing.md`, then `paddockd preflight` warns
  about both, the device appears as `adopted` and `report-only`, nothing on the laptop changes, the *Apply status*
  tab lists what enforcement would change, and the attention list shows it; when the administrator enables
  enforcement with the typed hostname, then the next apply quarantines the file, removes the member and applies the
  managed resources, audited.
- **C9 compatibility (ADR 0013; operator):** Given an agent of the previous release, then its enrollment, check-in,
  `bundle.applied` and bundles work unchanged (it is `unknown`, enforced, and its failures are listed); given a new
  agent against the previous server, then its events are accepted (no new event type) and its enrollment succeeds.
- **C10 lists and dialogs (ADR 0018; administrator):** every new list has search, filters, sortable columns and
  pagination with the page size selector, state in the URL; every destructive action (revert, halt, complete,
  enforce) is a modal, enforce requires the typed hostname; no `window.confirm`.
- **C11 isolation (ADR 0002; platform):** every new table has RLS; a rollout, change set, status row or settings of
  another organization is 404 or absent.

## 10. Freiheitsgrade

- Internal structure of `app/changesets.go`, `compiler/rollout.go`, the overlay type, helper names, the sqlc query
  names beyond those named here, the shape of `before` item structs (as long as they round-trip through
  `declarative` types), column widths of the portal tables, the exact wording of i18n texts (English and German both
  required), the layout of the wave strip, whether `UrgentOptOut.vue` is one component or a composable plus a
  snippet, the exact cut-off message of decision 9, the metric names beyond `paddock_config_rollouts_total`, the
  order of checks in `preflight` output, and whether the preflight reads `/etc/os-release` through `reconcile.System`
  or `os.ReadFile` (tests need the former).
- Migration file numbers 00045–00049 are the next free numbers at planning time; if M8b, M9 or M10 land migrations
  first, the implementer takes the next free numbers and keeps the order of this plan.

## 11. Stopp-Bedingungen

- The compiler cannot resolve a before item's device group (the group was deleted while the rollout ran): report;
  do not silently drop the item (decision 29 is meant to make this impossible; a gap there is a bug to fix first).
- A per-resource use case cannot build a one-change plan with `declarative.Diff` because the section's item type
  lacks a field accessor: report, do not invent a second plan shape.
- `bundle.applied` with `resources` exceeds the gateway's 1 MiB event batch limit for a plausible bundle (more than
  ~2 000 resources): report with numbers; do not raise the limit.
- The agent's `Plan` of any reconciler turns out to have side effects in report-only mode (PDK-081 fixed this for
  `paddockd plan`; verify with `fakesys`): stop and report; report-only must not write.
- Any change seems necessary in the revocation path, the supervisor, agent rollouts, the audit writer or an ADR
  other than 0033.
- A new Go module, npm package or container image seems necessary.
- The attention view change conflicts with a concurrent M8b/M9 migration of `attention_condition`: report; the
  later of the two must `CREATE OR REPLACE` the full view.

## 12. Risiken und offene Punkte

- **Parallel plans share migrations and the attention view.** Default: numbers are reassigned at implementation;
  the view is always replaced whole; the orchestrator sequences the four plans' migration tickets.
- **Overlay correctness** is the riskiest piece (PDK-157): mitigated by unit tests per section and action, the
  acceptance staging gate per device bucket, and the system gate on two VMs.
- **Change sets for every write** touch many use cases (PDK-154): mitigated by one helper and the existing
  `TestDeclarativeConfig` as a regression net; risk of double audit events is nil (the change set is recorded inside
  the same action).
- **Report-only devices and the DMS**: a report-only device still accepts time tickets and runs the dead man's
  switch if the organization enabled it; stated in the runbook. Default kept (DMS is an explicit opt-in).
- **Old agents enrolling by hand** are `unknown` and enforced at once (as today). Default kept; the runbook names
  the minimum agent release for report-only.
- **Halted rollouts block the next staged change** until completed or reverted (decision E1 of the ADR). Default
  kept; the portal's rollout page and the overview card make the open rollout visible.
- **Retention of `before` and status rows** is M10's; until M10 lands, rows accumulate (≤ 64 KiB per file content
  per change). Accepted for the lab fleet size.
- **Open question for the orchestrator:** should `settings.rollout` join the declarative document in M11 (then
  `paddockctl apply` could disable rollouts and push a change in one apply, which is audited but weakens the
  opt-out trail)? Default: no (non-goal), to be decided before M13 adds packages to the rollout-able sections.
- **Open question:** the minimum wave duration in production (15 minutes chosen; one check-in interval is 5
  minutes). Default: 15.
- **Open question:** whether profile changes should be staged in a later milestone (ADR option B2). Default: not in
  M11.

## Amendment 2026-10-29 (plan M10 refresh)

Plan M10 decision 15a (the worker's purge of `change_set.before` after 90 days, store `change_set_before`) is
implemented by **PDK-154**, the ticket that creates the column with migration `00046_change_set_before.sql` of
decision 17 — not by M10: at M10's start the column does not exist. PDK-154 adds the pass `PurgeChangeSetBefore`
to `worker.Retention` (plan M10 amendment A3: after pass 4, batches of 1 000, one `retention.purged` per
organization and round when > 0, `paddock_retention_stores` + 1) and keeps the `GRANT UPDATE (before,
before_purged_at)` of decision 17 in its own migration. The non-goal "no retention or purge of `change_set.before`"
in §4 is narrowed accordingly; the matrix row stays with ADR 0032. The migration number `00046` of decision 17 is
historical: PDK-154 takes the number main's registry assigns at ticket start.

## Amendment 2026-10-31 (refresh)

Architect refresh against `origin/main` at `986df91f` (branch `cluster/config-software`; cluster H of the alpha.7
plan) and against plan M9 (branch `cluster/getting-started-notifications`, migrations `00085`–`00088`, audit `00010`),
which lands on `main` before cluster H and is treated as present. Decided text above is not rewritten; **where this
amendment and §2–§12 differ, this amendment wins.** Numbers in bold refer to the decisions of §3.

### R1. Migration numbers (binding)

`main` has paddock migrations up to `00084` and audit migrations up to `00009`. M9 reserves paddock `00085`–`00088`
and audit `00010`. Paddock `00089` and audit `00011` stay free as a buffer for hotfixes on `main`. Cluster H starts at
paddock **`00090`** and audit **`00012`**. Neither M11 nor M13a needs an audit migration; audit `00012` stays
reserved for cluster H and is otherwise free.

| Ticket | Migration | Replaces |
| --- | --- | --- |
| PDK-151 | `server/migrations/paddock/00090_config_status.sql` | `00045` of **12** |
| PDK-154 | `server/migrations/paddock/00091_change_set_before.sql` | `00046` of **17** |
| PDK-156 | `server/migrations/paddock/00092_rollout_settings.sql` | `00047` of **23** |
| PDK-157 | `server/migrations/paddock/00093_config_rollout.sql` | `00048` of **27** |
| PDK-160 | `server/migrations/paddock/00094_adoption.sql` | `00049` of **39** |
| M13a (PDK-408, 409, 411) | `00095`–`00097` (plan M13a, amendment 2026-10-31) | `00068`–`00070` |

goose runs without `AllowMissing`: a migration whose number is lower than one already applied is never applied. The
numbers therefore **are** the merge order into `cluster/config-software`: PDK-151 → 154 → 156 → 157 → 160 → 408 → 409
→ 411. A ticket that is ready to merge out of this order takes the lowest free number greater than every migration
on the cluster branch at that moment, renames its file before merging, records the number in its result document and
in this table (a dated line below this paragraph); the displaced tickets shift. Every `00045`–`00049` in §3, §5, §7,
§8 and §10 is historical. A development database that applied `00090`+ before M9's `00085`–`00088` were merged is
reset with `make down V=1` and `make up` (alpha: no upgrade path).

### R2. Interfaces and files that changed since 2026-10-15 (binding corrections)

1. **Privileged route table.** It is `var privileged` in `server/internal/transport/http/admin/server.go`, not
   `handlers.go` (§2, §5, PDK-155/156/157/158/160 references). `spec_test.go` checks two things: every
   `x-paddock-audit` is registered and in the table, and `x-paddock-step-up: true` is present **iff** the spec has
   `RequiresStepUp: true` (`checkStepUpAnnotations`). No M11 spec has `RequiresStepUp: true` — the urgent opt-out
   (**26**) and the revert (**21**) use the conditional `rec.RequireStepUp()` / `configExec.requireStepUp` — so no M11
   operation carries `x-paddock-step-up`, and nothing is added to the table under `## What the assistant cannot do`
   in `skills/operate-paddock/SKILL.md` (`test/skill_test.sh` keeps that table equal to the catalog's step-up
   operations). Every state-changing operation of §6.1 MUST have a `privileged` entry (spec_test: every exposed MCP
   write tool is in the table). `make gen` regenerates the MCP catalog (`pkg/mcpcatalog/catalog.gen.go`,
   `skills/operate-paddock/references/tools.md`); "`make gen` no diff" covers it.
2. **MCP exposure (ADR 0044).** New operations are MCP tools by default. `POST /api/v1/devices/{id}/enforce` MUST
   carry `x-paddock-mcp: { expose: false }`: it is confirmed with a typed hostname in the portal (ADR 0018 high-risk
   class) and an assistant cannot give that confirmation; it stays a portal and API action. Every other M11 operation
   is exposed (reads as `read` tools; revert, halt, resume, advance, complete, settings as `write` tools that the MCP
   write policy governs). The implementer checks in `pkg/mcpcatalog/catalog.gen.go` that `revertChangeSet`,
   `haltConfigRollout`, `completeConfigRollout` are generated with `Destructive: true`; if the generator's rule does
   not mark them, stop and report (§11).
3. **Worker rounds** are started in `server/cmd/paddock-server/worker.go` (the `jobs` list; the agent-rollout round
   `worker.NewRollouts(...)` is the pattern), not in `worker/worker.go` (**33**, §5, PDK-158). The leader lock is the
   `LeaderLocker` interface (`WithLeaderLock(ctx, key, fn)`) the other rounds use.
4. **Retention pass of PDK-154** (amendment 2026-10-29 made concrete): `worker.NewRetention` has eight passes today
   (`device_login_event`, `device_user_seen`, `retired_inventory`, `read_audit_window`, `device_command`,
   `device_alert`, `device_event_gap`, `action`). PDK-154 appends the ninth and last pass `{store:
   app.StoreChangeSetBefore, purge: a.PurgeChangeSetBefore}` with `const StoreChangeSetBefore = "change_set_before"`
   in `server/internal/app/retention.go` and `func (a *Retention) PurgeChangeSetBefore(ctx context.Context, now
   time.Time) (int64, error)` shaped like `PurgeUserSeen` (batches of 1 000 in one `RunTx` per organization, cutoff
   `applied_at < now - 90 × a.unit`, sets `before = NULL, before_purged_at = now()` where `before IS NOT NULL`, one
   `retention.purged` with param `store` per organization and round when > 0). `paddock_retention_stores` is
   `len(r.passes)` and needs no change. `docs/compliance/retention.md` already carries the row and the clause
   "`change_set_before` only once M11 (PDK-154) adds …" (line 71): PDK-154 removes that clause. The comment header of
   `00090_config_status.sql` (**12**) cites "ADR 0032 §1, row `device_bundle_report`/`device_resource_status`:
   current state only, overwritten by the device's next report; rows of a retired device stay with the device
   record" instead of "owned by M10".
5. **Declarative sections.** `declarative.Sections()` has ten sections on `main` (`device_groups`,
   `permission_profiles`, `managed_files`, `managed_units`, `package_holds`, `profile_assignments`,
   `settings.updates`, `settings.login`, `settings.managed_files`, `settings.privacy`) and eleven after M9
   (`settings.watched_units`, `declarative.SectionSettingsWatched`). "The eight sections" in **19** and PDK-154 reads
   "every section of `declarative.Sections()`". The per-resource use cases that MUST record a change set therefore
   also include `ManagedConfig.SetOperatorRoots` (`app/managedfilesettings.go`, section `settings.managed_files`),
   `Privacy.Update` (`app/privacy.go`, `settings.privacy`) and M9's `WatchedUnits.Set` (`app/watchedunits.go`,
   `settings.watched_units`). The before item of a settings section is the settings object as `GET /api/v1/config`
   exports it. The revert (**21**) runs through `configExec`, so each section's own refusal rules apply unchanged
   (`requireAdminStepUp` for `settings.managed_files` and `settings.watched_units`, `requireStepUp` for a
   root-equivalent profile). The rollout-able sections of **1** are unchanged (none of the three is rollout-able).
6. **Bundle sections and the applier.** M9 adds the section `watch` (`bundle.TypeWatch`, `WatchSpec`,
   `WatchResource`; `apply.Applier.WithWatch`, appended after the inventory resource in `sorted`; `apply.order` is
   unchanged). **7**: `Resources` lists the inventory and the watch resource like every other. **9**: the report-only
   apply MUST NOT call `Apply` of the inventory or watch reconciler either; their `Plan` is side-effect free (the
   implementer proves it with `fakesys`, stop condition §11 otherwise). `agent.go` writes `Layout.LastCheckin()` at
   line 515 and builds the check-in at `checkinRequest` (line 465); informational.
7. **Ingest (`devicereports.go`).** After M9, `app.OnceEntry` has a third field `After` and `eventEntry` returns
   `After: tamperFindingAfter(...)`; PDK-151 rebases on M9 before touching `eventEntry`. The allow lists
   `eventParams` (`devicereports.go`) and `audit.deviceEventParams` (`codes.go`) already contain `mode`: **13**'s
   "the audit params of `device.bundle_applied` gain `mode`" needs no list change, only the registry Description/Note
   of `device.bundle_applied`. `resources` is never added to either list.
8. **Attention view and findings.** The latest definition of `attention_condition` is `00069_event_gaps.sql`; M9 does
   not replace the view but grants `SELECT ON attention_condition TO paddock_worker` (`00086_findings.sql`) and its
   findings round turns every attention condition into a finding (`finding.KindAttention`, key `attention:<id>`).
   `00094_adoption.sql` (**39**) MUST `CREATE OR REPLACE VIEW attention_condition` from the `00069` definition plus
   the `report_only` branch (same columns in the same order; grants survive). A report-only device therefore also gets
   an attention finding — intended: it is a device waiting for a decision. The kind list lives in
   `api/openapi/admin.yaml` (schema `AttentionKind`) and in the view; there is no kinds list in
   `server/internal/app/attention.go` (PDK-160 reference corrected). The portal has two maps with one key per kind
   in `en.json`/`de.json` (the kind label and the action label next to `agent_rollback_pending`); both gain
   `report_only`.
9. **Compiler.** `compileTarget` (`compiler.go:154`) has `id, state, seq, suspended, v2, agent, forced, request,
   name`; `ListCompileTargets` (`queries/bundle.sql:11`) selects from `device d LEFT JOIN device_status s`. PDK-160
   adds `d.config_mode` → `compileTarget.reportOnly bool`; M13a (PDK-410) later adds `d.os_release` and `s.arch` to
   the same query. M9 adds `compiler/watch.go` (watch section render) — `render` has one more section call to keep.
10. **Overlay and M13a holds (**30**).** `rolloutOverlay.apply(defs, updates)` keeps `*orgUpdates` as its second
    input and output. M13a's `UpdatesSection(settings, holds, softwareHolds, groups)` receives the **overlaid**
    settings and holds and the un-overlaid software holds (software is not rollout-able before M13c); PDK-410
    implements that order in `render`, PDK-157 leaves `orgUpdates` as the overlay's input type.
11. **Problem codes.** Existing and used: `invalid_request`, `not_found`, `invalid_state`, `plan_changed`,
    `step_up_required`, `already_exists`, `in_use`. New as planned: `rollout_conflict`, `rollout_running`. Request
    bodies above `maxBodyBytes` (256 KiB, `limitBody` in `server.go`) are refused `400 invalid_request`; there is no
    413 code.
12. **Portal files.** The tab list is `components/DeviceTabs.vue` with `lib/deviceDetailPage.ts`; `views/DeviceDetail.vue`
    hosts it. M9 edits `views/Overview.vue`, `views/DeviceOverview.vue`, `lib/navigation.ts` and `router.ts`
    (findings, watched services); PDK-152/156/159/160/164 rebase on M9. `components/KpiStrip.vue`, `DangerZone.vue`,
    `StatusChip.vue`, `ChangeSetPlan.vue`, `ConfirmDialog.vue` exist as referenced; `UrgentOptOut.vue` does not yet.
13. **Audit registry and routes after M9.** M9 adds about 200 lines to `codes.go`, 117 to `server.go` and 86 to
    `handlers.go` (notifications, findings, feed). Every M11 ticket touching these files rebases on M9; conflicts are
    additive. `config_rollout.halted` is a preset event of M9's notification rules (plan M9 §6.9): the code name is
    frozen.
14. **CHANGELOG.** `CHANGELOG.md [Unreleased]` is no longer edited (PDK-518): every ticket with an operator-visible
    change adds `changelog.d/<ticket-id>.<section>.md` (`added`, `changed`, …; `make changelog-check` is part of
    `make lint`). **45**'s "`CHANGELOG.md [Unreleased]`" and PDK-163's consolidated block become one fragment per
    ticket; PDK-163 adds `changelog.d/PDK-163.added.md` for the two guides and the `bundle.applied` change goes into
    `changelog.d/PDK-150.changed.md`.
15. **Metric name.** The gauge of **33** is `paddock_config_rollouts{status}`; the `paddock_config_rollouts_total` of
    §10 is a typo. No agent-rollout gauge exists to mirror.
16. **Acceptance shards.** New acceptance tests SHOULD add a measured line to `test/acceptance/shard-weights.txt`
    (default weight 60 s otherwise).
17. **Preflight port (**11**).** `reconcile.System` provides `ReadFile`, `ReadDir`, `PackageInstalled`,
    `PackageVersion`, `Timedatectl`, `Getent`, `SudoVersion`, `EvalSymlinks`; `reconcile.SudoFlavor(ctx, sys)` and
    `luks.TPM2Present(root string) bool` exist as referenced.

### R3. Cross-cutting rules now in force (no plan change, stated for the implementer)

- **ADR 0045 (role switch):** decision 4 — one role per request, authorisation unchanged. Acceptance `login(t, user)`
  lands in the organization role. `actorName(ctx)` / `started_by` show the principal's display name. Nothing to do.
- **PostgreSQL 18 (PDK-343):** every statement of §3 is valid on PG 18 (plpgsql functions, partial unique indexes,
  `CREATE OR REPLACE VIEW` with appended rows); integration tests run on the compose image. Nothing to do.
- **M10 (ADR 0032, retention and evidence):** `action` rows are immutable once finished (`00082`–`00084`); the
  `ActionRunner` handles it. The new tables of **12**, **23**, **27** and the columns of **17**, **39** are covered by
  ADR 0032 §1 (rows `change_set`, `change_set.before`, `device_bundle_report`/`device_resource_status`);
  `organization_rollout_settings` and `config_rollout` are configuration and operational history like `change_set`
  (no purge). `docs/compliance/privacy.md` row of **45** stays with PDK-163. No erase path exists for organization
  data; nothing to add.
- **ADR 0044 (MCP):** see R2.1–R2.2. Read-access recording (`readaudit`) is per route class and needs no change for
  new `GET`s.

### R4. Ticket order, dependencies, lanes, risk

Risk per ticket as stated in the tickets: low — 152, 153, 156, 163, 164; medium — 150, 151, 154, 159, 162;
high — 155, 157, 158, 160, 161.

| Step | Ticket | Lane | Depends on | Migration |
| --- | --- | --- | --- | --- |
| 1 | PDK-150 | agent/pkg | — | — |
| 2 | PDK-151 | server | 150 (protocol types) | 00090 |
| 2′ | PDK-153 | agent + docs | — (parallel to 1–4) | — |
| 3 | PDK-154 | server | 151 merged (migration order); M9 on the branch | 00091 |
| 3′ | PDK-152 | portal | 151 | — |
| 4 | PDK-155 | server + portal | 154 | — |
| 4′ | PDK-156 | server + portal | — (parallel to 154/155; merges after 154) | 00092 |
| 5 | PDK-157 | server/compiler | 154, 155, 156 | 00093 |
| 6 | PDK-158 | server/worker | 157 | — |
| 6′ | PDK-161 | agent | 150 (parallel to 157/158) | — |
| 7 | PDK-159 | portal + CLI | 158 | — |
| 8 | PDK-160 | server + portal + CLI | 151, 157 | 00094 |
| 9 | PDK-164 | server + portal | 158, 160 | — |
| 10 | PDK-162 | system gates | 158, 160, 161 | — |
| 11 | PDK-163 | docs | 162 (parallel to 164) | — |

Three lanes run in parallel: agent (150 → 161; 153), server (151 → 154 → 155 → 157 → 158 → 160, with 156 beside
154/155), portal (152 after 151; 159 after 158; 164 after 160). Merge order of the migration tickets is R1; tickets
without a migration merge as soon as their dependencies are on the branch. The VM gate (PDK-162) runs once per cluster
(alpha.7 plan, cluster H row), together with M13a's `TestSoftwareGates` at the end of the cluster.

### R5. Open questions for the maintainer (default chosen; blocks only what is named)

1. **`paddockctl apply --urgent` can never succeed** (**26** + **38**): an API token never satisfies a step-up (ADR
   0034 decision 3, ADR 0044), so `--urgent` always answers 403 `step_up_required`. Options: (a) keep the flags as
   documented refusal; (b) drop `--urgent`/`--reason` from `paddockctl apply` and `docs/operations/paddockctl.md`,
   keep the `Rollout:` output line, state in `configuration-rollouts.md` that the urgent opt-out is portal-only;
   (c) let API tokens opt out (contradicts ADR 0034). **Recommendation: (b).** Blocks the CLI part of PDK-159 only;
   default (b) applies unless overruled before PDK-159 starts.
2. **MCP exposure of `enforceDevice`** (R2.2): (a) hide (typed-name class); (b) expose like every write tool.
   **Recommendation: (a)**, default chosen; PDK-160 proceeds.
3. **Change sets for the three settings sections** (R2.5: `settings.managed_files`, `settings.privacy`,
   `settings.watched_units`): (a) include — ADR 0011 "every configuration change is a change set"; (b) exclude and
   keep them audit-only. **Recommendation: (a)**, default chosen; PDK-154 proceeds.
4. **Report-only devices as findings** (R2.8): (a) keep — every attention condition is a finding; (b) exclude the
   kind in M9's findings round. **Recommendation: (a)**, default chosen; nothing blocked.
5. Unchanged from §12 with their defaults: `settings.rollout` not in the declarative document; minimum wave duration
   15 minutes in production; profiles not staged.

### R6. Answers of the architect (2026-10-31)

1. `paddockctl apply` has no `--urgent` and no `--reason`; the urgent opt-out is portal-only. PDK-159 documents it in
   the `paddockctl apply` help text, in `docs/operations/paddockctl.md` and in `configuration-rollouts.md`.
2. `POST /api/v1/devices/{id}/enforce` carries `x-paddock-mcp: { expose: false }` (R2.2 option a).
3. Change sets cover `settings.managed_files` and `settings.privacy` in PDK-154; `settings.watched_units` is covered
   once M9 is merged into `cluster/config-software` (PDK-154 starts after that merge anyway, R4).
4. Report-only devices become M9 attention findings (R2.8 option a).
5. **Enrollment method from an autoinstall-only marker (decisions 10, 44; PDK-161).** The agent sends
   `enrollment_method: autoinstall` only when an autoinstall-only marker exists on the device (the disk-setup marker of
   `docs/operations/autoinstall.md`); a configuration file without that marker gives `adopted`, so report-only is the
   default when in doubt (fail safe). The enroll-existing runbook places the enrollment configuration outside the
   daemon's path, at `/root/paddock-enroll.json` with mode 0600, so the daemon's autoinstall loop never picks it up.
   `paddockd enroll` and the daemon's loop share one file lock, so a device never sends two concurrent enrollment
   requests. A local administrator who creates the marker by hand only opts their own device into immediate
   enforcement; that is accepted.
6. **Plan errors of report-only devices (decision 9; PDK-158, PDK-160).** The report-only report keeps `errors: []`;
   plan errors appear only as `failed` resources. The server shows them as their own state ("report-only, plan
   errors"), never as a failed apply, and they never count toward a wave's failure rate.
7. **What report-only does not stop.** Paddock's own updates (agent and supervisor), revocation, the LUKS tick and the
   dead man's switch keep running on a report-only device (intended); PDK-163's adoption guide lists them.
   `rotate_admin_password` on a report-only device is answered `failed` with reason `report_only`.
8. **Amendment to item 5 (2026-10-31, architect).** The autoinstall-only marker is a dedicated file
   `/etc/paddock/autoinstall.marker` (root, 0600) that only the autoinstall template writes in its late-commands.
   Neither the disk-setup marker (removed by the first-boot disk setup before the agent enrolls) nor
   `/etc/paddock/disk-setup.json` (also written by the in-place disk conversion of an adopted device) qualifies. The
   enrollment lock is `/var/lib/paddock/enroll.lock` (flock); `paddockd enroll` waits on it interruptibly, the daemon
   skips. PDK-162 asserts the enrollment method in the VM gate and moves the harness to the runbook path.
9. **Consequences of item 8 for the other tickets (2026-10-31).** Every mention of `/etc/paddock/enroll.json` as the
   adoption path in §3–§7 (e.g. the adoption guide of PDK-163) reads `/root/paddock-enroll.json`; item 5's "the
   disk-setup marker" reads `/etc/paddock/autoinstall.marker` (the disk-setup-pending marker is also written by the
   in-place disk conversion of an adopted device). The system-test harness enrolls through `paddockd enroll` and
   therefore as `adopted`: once PDK-160 stores `report_only` for adopted devices, the harness's install step enforces
   the device (`POST /api/v1/devices/{id}/enforce`) unless a gate tests report-only (PDK-160/162). Recovering a failed
   first-boot enrollment with `paddockd enroll` makes an autoinstalled device `adopted` (safe direction); PDK-163
   states it in the autoinstall troubleshooting section.
10. **Change-set recording by document diff (PDK-154, 2026-11-01).** Decision 19's per-item before documents are
    implemented as a diff of the whole declarative document read before and after the write, inside the write's
    transaction. This is correct only because every writer of a declarative section takes `LockConfigApply` as the
    first lock of its transaction (including `Users.Delete`, `UserGroups.Delete` and the identity sync's rename and
    removal); a new writer that skips the lock would be attributed to a concurrent change set. A rename of a device
    group or a file path appears as delete plus create (natural keys), which PDK-155's revert handles like any other
    pair of items.
