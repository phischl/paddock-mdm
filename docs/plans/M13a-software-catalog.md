# Implementierungsplan: M13a — Software catalog: APT sources, catalog entries, assignments, agent enforcement

Status: Ready for implementation · 2026-10-24 · Author: architect
Basis: ADR 0042 (software catalog and self-service; **Proposed** — this plan builds on it, the maintainer accepts it
with the first merged ticket); ADR 0005 (bundle format, additive sections); ADR 0013 (additive protocol changes,
support window); ADR 0018 (lists and dialogs); ADR 0024 (no event type an older server could receive from a newer
agent); ADR 0028 (per-device derivations on read paths); ADR 0034 (step-up on root-equivalent actions; API tokens
never satisfy a step-up; `/etc/apt/` is a denied managed-file path); ADR 0037 (uninstall modes); plans M5b (the
`updates` section as the precedent of a section mapped to one internal resource; `package_hold`; `updates.Merge`),
M8d (`device_owner`, `health.Report.components`), M8h (`hostname` section; the shape of this plan).

Binding language: **MUST** / **MUST NOT** / **SHOULD** / **MAY**.

This plan is written against `main` at `358c4335` (release v0.1.0-alpha.5 pending in PR #140). §11 names what to
do when the code differs. Epic: PDK-355. Tickets: PDK-408 to PDK-414 (§8).

## 1. Goal

After M13a an organization administrator adds third-party APT repositories with their signing keys (step-up, the
key fingerprint in the audit trail), operators describe applications in a catalog (name, description, icon,
category, source, package name per distribution, release and architecture) and assign them to device groups with
the intents *required*, *uninstall*, *hold* and *forbid*; devices install, remove, pin or block the packages from
their signed bundle, reinstall a required application a user removed locally and report it, and the portal shows the
state of every application on every device. The managed source files and keyrings are a protected area.

## 2. Context (verified in the code on 2026-10-24, `main` at `358c4335`)

- **Bundle and apply.** `pkg/bundle.Bundle` carries the optional sections `keys`, `revocation`, `dms`, `inventory`,
  `updates`, `disk`, `hostname`; `Verify` ignores unknown fields; `apply.Applier` (`agent/internal/apply/apply.go`)
  applies in `order = [hostname, time, file, systemd_unit, updates, login, sudo]`, maps the `updates` section to the
  internal resource `updates` (`bundle.UpdatesResource`, `sorted`) and the `hostname` section to `hostname`;
  `CheckTypes` rejects unknown `resources[]` types only. `reconcile.Reconciler{Type, Plan, Apply}` and the
  `reconcile.System` port (`agent/internal/reconcile/reconcile.go`: `ReadFile`, `WriteFileAtomic`, `Remove`,
  `ReadDir`, `AptGet`, `AptMark`, `Dpkg`, `PackageInstalled`, `PackageVersion`, …; implemented by `reconcile.OS` in
  `system.go`, faked by `reconcile/fakesys.System`). `reconcile.PackageTimeout` is 15 min. The drift loop
  (`agent/internal/agent/bundles.go::drift`) re-plans the cached bundle every `config.DriftInterval` (300 s) and
  emits `config.drift_corrected{version, resource_ids}`. `agent.go:505` writes `Layout.LastCheckin()`
  (`/run/paddock/last-checkin`) after every successful check-in.
- **Updates reconciler** (`agent/internal/reconcile/updates.go::Updates`): renders `UnattendedConf`, `PinFile`
  (`/etc/apt/preferences.d/50paddock`, `Pin-Priority: 1001`), the timers; `holdChanges`/`applyHolds` own
  `apt-mark hold|unhold` with the record `/var/lib/paddock/state/held-packages`; `writeFiles` emits
  `tamper.protected_file_changed{file}` when a file differs from the last applied spec (`u.applied`).
  `managedHeader` (`notice.go:34`) is `"# Managed by Paddock. Do not edit: local changes are reverted.\n"`.
- **Login reconciler** (`login.go::install`): writes `/etc/apt/keyrings/himmelblau.gpg` and
  `/etc/apt/sources.list.d/paddock-himmelblau.list`, runs a scoped `apt-get update -o Dir::Etc::sourcelist=… -o
  Dir::Etc::sourceparts=- -o APT::Get::List-Cleanup=0`, installs with `DPkg::Lock::Timeout=600`, repairs
  `dpkg was interrupted` with `dpkg --configure -a`, retries dependency failures after a full `apt-get update`.
- **Updates run** (`agent/internal/osupdates`): `RunRegular` = `apt-get update` + `dist-upgrade --force-confold`
  with `DPkg::Lock::Timeout=600`; it upgrades everything not held. Result event `updates.run`.
- **Server update management.** `server/internal/domain/updates`: `Hold{GroupID, Package, Version}`,
  `ValidateHold`, `Merge(holds) ([]bundle.Hold, []Conflict)` (smallest version wins, nil first), `MaxReasonLength`
  500. `app.Updates` (`server/internal/app/updates.go`): `SpecPackageHold*` with `RolesWrite`, `RunTx`,
  `requireGroups`, `StateChanged`. `app.UpdatesSection(settings, holds, groups)` renders the section; the compiler
  (`server/internal/compiler/updates.go::orgUpdates`, `compiler.go:374`) loads holds once per round and renders per
  device from `groups []uuid.UUID`. Migration `00025_updates.sql` is the table pattern (RLS, `tenant` policy for
  `paddock_api, paddock_compiler`, `UNIQUE NULLS NOT DISTINCT`, composite FK to `device_group`).
- **Devices.** `device.os_release jsonb` (from `EnrollRequest.OSRelease`, keys of `/etc/os-release`: `ID`,
  `VERSION_ID`), `device_status.arch text` (migration `00056`, from `CheckinRequest.Arch`), `device_status.health
  jsonb`. `app.DeviceReports.RecordStatus` (`devicereports.go:40`) upserts `device_status` from the heartbeat and
  reads parts of the health (`HealthComponents`, disk). `health.Report` (`agent/internal/health/health.go`) is the
  check-in health; `Components map[string]string` and `Hostname` are the latest additions.
- **Device events.** `pkg/protocol.EventTypes` is the closed set the gateway admits; `app/devicereports.go:195`
  maps every type to an audit code; `deviceEventParams` are the params. `tamper.protected_file_changed` maps to
  `device.tamper_protected_file_changed`.
- **Audit registry.** `server/internal/domain/audit/codes.go`: `Code` constants, `registry` map of `Definition{Code,
  Description, Params, Outcomes, Emitted, Note}`, `adminOutcomes`; `docs/compliance/audit-codes.md` is generated by
  `make gen`. Portal keys `audit.<code>` in `server/web/src/locales/en.json` and `de.json`.
- **Step-up.** `app.ActionSpec.RequiresStepUp` refuses with 403 `step_up_required` (denied event) unless the
  step-up is fresh (`StepUpValidity` 300 s); API tokens never pass. Portal: `server/web/src/lib/stepUp.ts`
  (`startStepUp`, `stepUpRequired`, resume on return). Acceptance helpers: `stepup_helpers_test.go`
  (`adminUser`, `withoutStepUp`, `expectRefusal`).
- **Admin API conventions.** Routes and specs in `server/internal/transport/http/admin/server.go` (the privileged
  route map `{app.ScopeOrg, app.Spec…}`); list handlers in `handlers_updates.go` (`listPackageHolds`); OpenAPI
  `api/openapi/admin.yaml` with `x-paddock-list`, shared parameters `Page`, `PageSize`, `Search`,
  `DeviceGroupFilter`, `Csrf`, `Id`; `TestOpenAPISpec` and `list_contract_test.go` enforce the contract;
  `isolation_fixtures.go` lists every organization-scoped endpoint for the 404 gate. Existing paths
  `/api/v1/software` and `/api/v1/devices/{id}/software` are the **inventory** (Fleet) and stay untouched.
- **Portal.** `views/PackageHolds.vue` (`DataList`, `useManagedPage`, `PackageHoldForm`), `lib/updates.ts`
  (generated client `api`, `listPage`, `problemCode`), `lib/navigation.ts` (section with `/package-holds`,
  `/software`, `/vulnerabilities`, `/settings/updates`), `router.ts`, `DeviceDetail.vue` with tabs
  (`DeviceSoftware.vue` is the inventory tab).
- **Uninstall.** `agent/internal/uninstall/steps.go`: `updateConfiguration` unholds the record and removes
  `updateFiles`; `himmelblauPaths` lists the login source and keyring; `packages` removes `/var/lib/paddock/…`.
- **Policy.** `pkg/policy/policy.go:49,146`: `/etc/apt/` is a denied tier for managed files. Nothing in this plan
  adds a path to `pkg/policy`.
- **Tests.** `agent/internal/reconcile/updates_test.go` (fakesys fixture, `event` recorder); acceptance
  `updates_test.go` (`holdIn`, `auditCase`), `devicesim` (`--health <json>`); system `updates_test.go`
  (`TestUpdatesGates`, `forEachVM`, `vm.Fresh`, `Install`, `Device.hold`, `Until`, `Device.WaitEvent`,
  `Device.Must`), `test/system/README.md`.
- **Residual risks.** `docs/compliance/residual-risks.md`: RR-76 is the highest (RR-74 to RR-76 are taken by M8b); RR-41 and RR-42 are unassigned and
  stay so. **M13a reserves RR-77 to RR-83.**

## 3. Binding decisions

### 3.1 Package sources (PDK-408)

1. **Table `software_source`** (migration `00068_software_sources.sql`, §6.5): `id`, `organization_id`, `slug`
   (immutable), `name`, `uris text[]`, `suites text[]`, `components text[]`, `architectures text[]`,
   `signing_key text` (ASCII-armored OpenPGP public key), `fingerprint text` (40 uppercase hex characters),
   `created_by`, `created_at`, `updated_at`. RLS with the `tenant` policy for `paddock_api` and `paddock_compiler`;
   `UNIQUE (organization_id, slug)`, `UNIQUE (organization_id, name)`.
2. **Validation** (`server/internal/domain/software/source.go`, §6.4): `slug` `^[a-z0-9][a-z0-9-]{1,40}$`; `name`
   1–100 characters after trimming; `uris` 1–4 entries, each `https://` + host + optional path, at most 512
   characters, no query, no fragment, no user info, no whitespace — any other scheme is refused with 400
   `invalid_request` and the detail `uris must use https`; `suites` 1–8 tokens `^[A-Za-z0-9./_-]{1,64}$`;
   `components` 0–8 tokens `^[a-z0-9-]{1,32}$`; a flat repository (a suite ending in `/`) MUST have no components;
   `architectures` 0–2 of `amd64`, `arm64`; `signing_key` at most 65 536 bytes and exactly one v4 OpenPGP public key
   (subkeys allowed) as `pkg/openpgpkey.Fingerprint` reads it; the typed `fingerprint` (spaces ignored, case
   ignored, stored uppercase) MUST equal the computed one, otherwise 422 `fingerprint_mismatch` with both values in
   the detail.
3. **`pkg/openpgpkey`** (new, stdlib only, §6.4): `Fingerprint(armored []byte) (fp string, keyring []byte, err error)`
   decodes the ASCII armor (`-----BEGIN PGP PUBLIC KEY BLOCK-----`, base64 body, CRC-24 checked when present),
   walks the packets (old and new header formats), requires the first packet to be a public-key packet (tag 6) of
   version 4, computes the v4 fingerprint (SHA-1 over `0x99`, two-byte length, key packet body), accepts the
   following packets only when they are user ID (13), user attribute (17), signature (2) or public-subkey (14)
   packets, refuses versions 3, 5 and 6 and any other packet tag, and returns the binary (dearmored) key material as
   the keyring the agent writes. Tests: a table of real-world v4 keys (the Himmelblau key embedded in
   `agent/internal/reconcile`, a generated RSA and an Ed25519 key as fixtures), truncated input, wrong CRC, a secret
   key block (tag 5 → error), a v3 key (error), and a fuzz test `FuzzFingerprint` that MUST NOT panic.
4. **Use cases `app.SoftwareSources`** (`server/internal/app/softwaresources.go`): `List`, `Get`, `Create`,
   `Update`, `Delete`. `Create`, `Update` and `Delete` use `ActionSpec{AllowedRoles: RolesAdmin, RequiresStepUp:
   true}`; every success calls `rec.StateChanged(statechange.ScopeOrg, org)`. `Update` MUST NOT change `slug`
   (400 `invalid_request`). `Delete` of a source referenced by a catalog entry is 409 `in_use`. Audit params §6.3.
5. **Admin API** §6.1: `/api/v1/software-sources` and `/api/v1/software-sources/{id}`. The response never contains
   `signing_key` in the list (`SoftwareSourceSummary`); `GET …/{id}` returns it (it is a public key).
6. **The server never contacts a source.** No reachability check, no key server lookup.

### 3.2 Catalog entries and assignments (PDK-409)

7. **Table `software_catalog_entry`** (migration `00069_software_catalog.sql`): `id`, `organization_id`, `name`
   (unique per organization), `description` (≤ 1000), `category` (≤ 64, may be empty), `source_id` (nullable FK to
   `software_source`, `ON DELETE RESTRICT`; NULL = the distribution's own repositories), `packages jsonb` (§6.4
   `PackageRef` list), `icon bytea` (nullable, PNG ≤ 65 536 bytes), `created_by`, `created_at`, `updated_at`.
8. **`packages`**: 1–20 entries `{distribution, release, architecture, package}`; `distribution` `^[a-z][a-z0-9-]{0,31}$`
   (the `ID` of `/etc/os-release`, e.g. `ubuntu`, `debian`); `release` `*` or `^[a-z0-9][a-z0-9.-]{0,31}$` (the
   `VERSION_ID`, e.g. `24.04`, `12`); `architecture` `*`, `amd64` or `arm64`; `package` `bundle.ValidPackage`. The
   tuple (distribution, release, architecture) is unique within an entry. **Resolution for a device**
   (`software.Resolve(entry, osID, versionID, arch) (pkg string, ok bool)`): candidates with `distribution == osID`;
   the most specific wins in the order (release exact, arch exact) > (release exact, `*`) > (`*`, arch exact) >
   (`*`, `*`); an empty device `arch` matches `*` only; no candidate → the entry is *not applicable* to the device.
9. **Table `software_assignment`**: `id`, `organization_id`, `catalog_entry_id` (FK, `ON DELETE CASCADE`),
   `device_group_id` (nullable; NULL = every device of the organization; composite FK as `package_hold`), `intent`
   (`required | uninstall | hold | forbid`), `update_rule` (`latest | pinned`; `latest` unless `intent = required`
   and a version is given), `version` (nullable, `bundle.ValidPackageVersion`), `reason` (≤ 500), timestamps,
   `UNIQUE NULLS NOT DISTINCT (organization_id, catalog_entry_id, device_group_id)`. Rules: `required` with
   `update_rule = pinned` requires `version`; `required latest` MUST NOT carry a version; `hold` MAY carry a version
   (pinned hold) or none (hold the installed version); `uninstall` and `forbid` MUST NOT carry a version or an update
   rule other than `latest`.
10. **Merge per device and package** (`software.MergeIntents(entries []Effective) []Resolved` in the domain, §6.4):
    severity `forbid (4) > uninstall (3) > required (2) > hold (1)`; the highest wins; when the winner is `required`
    and any `hold` or `required pinned` names a version, the result is `required` pinned at the lexicographically
    smallest named version (the rule of `updates.Merge`); a `hold` winner with several versions takes the smallest.
    Two or more distinct versions produce one `Conflict{Package, Versions, Chosen}`, reported like the hold
    conflicts of `app.UpdatesSection` (same code path, the implementer follows it).
11. **Use cases `app.SoftwareCatalog`** (`softwarecatalog.go`): entries `List`, `Get`, `Create`, `Update`, `Delete`,
    `SetIcon`, `Icon`; assignments `ListAssignments`, `GetAssignment`, `CreateAssignment`, `UpdateAssignment`,
    `DeleteAssignment`. All writes `RolesWrite`, no step-up; `requireGroups` for `device_group_id`; every write
    records `StateChanged`: entry and assignment writes with `ScopeOrg` (the compiler recomputes the affected
    devices; a finer scope is a freedom, §13). `SetIcon` accepts `Content-Type: image/png`, checks the PNG signature
    (`\x89PNG\r\n\x1a\n`) and decodes the header with `image/png` (`image.DecodeConfig`): width and height ≤ 512,
    body ≤ 65 536 bytes; otherwise 400 `invalid_request`. `Icon` answers `image/png` with `Cache-Control:
    private, max-age=300` or 404.
12. **Admin API** §6.1: `/api/v1/software-catalog`, `/api/v1/software-catalog/{id}`, `/api/v1/software-catalog/{id}/icon`,
    `/api/v1/software-assignments`, `/api/v1/software-assignments/{id}`.

### 3.3 Bundle and compiler (PDK-410)

13. **`pkg/bundle`** (§6.2): `TypeSoftware = "software"`, `Bundle.Software *SoftwareSpec json:"software,omitempty"`,
    `SoftwareSpec{Sources []SoftwareSource, Packages []SoftwarePackage}`, `ValidateSoftware`,
    `SoftwareResource(s) (Resource, error)` (ID and type `software`, nil lists encoded as empty lists). The section is
    schema v2 only. `ContentSHA256` covers it.
14. **Compiler** (`server/internal/compiler/software.go`): `loadSoftware(ctx, q) (*orgSoftware, error)` loads the
    sources, entries and assignments once per round (`ListAllSoftwareSources`, `ListAllSoftwareCatalogEntries`,
    `ListAllSoftwareAssignments`); `orgSoftware.section(device) (*bundle.SoftwareSpec, []bundle.Hold, []Conflict)`
    resolves per device: assignments whose scope is NULL or one of the device's groups → entries → `Resolve` with
    the device's `os_release.ID`, `os_release.VERSION_ID` and `device_status.arch` → `MergeIntents`. Output:
    - `Packages`: one per resolved package (`intent`, `version`, `source` slug or `""`, `catalog_entry_id`), sorted
      by package;
    - `Sources`: every source referenced by a `required` package, sorted by slug, each with `slug`, `uris`,
      `suites`, `components`, `architectures`, `keyring` (standard base64 of the binary key material from
      `pkg/openpgpkey.Fingerprint`), `fingerprint`;
    - `holds`: one `bundle.Hold{Package, Version}` per package whose result is `required pinned` (version) or `hold`
      (version or nil), merged with the organization's `package_hold` rows through `updates.Merge` into the `updates`
      section (`compiler.go:374`: `updatesSection` is rendered from both lists). The `software` section is omitted
      when `Packages` is empty. `ListCompileTargets` MUST provide `os_release` and `arch` for the render (extend the
      query; stop condition §11 if the row shape is shared with code that this would break).
15. **Upgrade semantics.** `required latest` means *installed*; the version moves with `paddockd updates run` and
    the daily security run, never by the software reconciler. `required pinned` means *installed at exactly that
    version* (install, upgrade or downgrade to it; held there by the pin of the `updates` section). `hold` installs
    nothing.

### 3.4 Status ingestion and read paths (PDK-411)

16. **Health** (`pkg/protocol`, §6.2): `SoftwareHealth{Digest string, Items []SoftwareItem}`; `health.Report.Software
    *protocol.SoftwareHealth json:"software,omitempty"`. `Items` is bounded by `protocol.MaxSoftwareItems = 200`;
    `Error` by 200 characters. `api/openapi/device.yaml` documents the health object additively.
17. **Table `device_software_status`** (migration `00070_device_software_status.sql`): `device_id`,
    `organization_id`, `catalog_entry_id` (FK `ON DELETE CASCADE`), `package`, `intent`, `state`, `version`,
    `reason`, `error`, `reported_at`; PK `(device_id, catalog_entry_id)`; RLS for `paddock_api` (SELECT) and
    `paddock_worker` (SELECT, INSERT, UPDATE, DELETE); `device_status.software_digest text NOT NULL DEFAULT ''`.
18. **`RecordStatus`**: when `health.software.items` is present, replace the device's rows with the items (delete
    rows whose `catalog_entry_id` is absent, upsert the rest; an item whose `catalog_entry_id` is not a UUID or not
    an entry of the organization is skipped) and store `software.digest`; when only `digest` is present, store it.
19. **Read paths** (ADR 0028): `GET /api/v1/software-catalog/{id}/devices` lists the devices targeted by the entry's
    assignments (devices of the assignment's groups, or every active device for an organization-wide assignment)
    with the status row or the derived state `not_applicable` (no package for the device's `os_release`/`arch`,
    computed in Go with `Resolve`) or `unknown` (targeted, applicable, no row yet).
    `GET /api/v1/devices/{id}/managed-software` lists the device's rows joined with the entry name and the derived
    `not_applicable` entries. Both follow the list contract (§6.1).

### 3.5 Agent (PDK-412)

20. **Reconciler `reconcile.Software`** (`agent/internal/reconcile/software.go`, §6.4) owns, for the slugs of the
    spec: `/etc/apt/sources.list.d/paddock-<slug>.sources` (deb822, §6.2 rendering, mode 0644 root:root),
    `/etc/apt/keyrings/paddock-<slug>.gpg` (the decoded `keyring`, mode 0644), `/etc/apt/preferences.d/51paddock-software`
    (one `Package: <pkg>\nPin: release *\nPin-Priority: -1` stanza per `forbid` package, absent when none), the
    record `/var/lib/paddock/state/software-installed` (packages the reconciler installed, one per line, mode
    0600), and the installs and removals. It MUST NOT call `apt-mark`, write `50paddock`, or touch
    `paddock-himmelblau.list` and `himmelblau.gpg`.
21. **Fingerprint check.** Before writing a keyring the reconciler computes `pkg/openpgpkey.Fingerprint` of the
    decoded bytes (re-armoring is not needed: a second entry point `FingerprintBinary(keyring []byte)` is part of
    §6.4) and refuses the source with `software.apply_failed{stage: keyring, reason: fingerprint_mismatch}` when it
    differs from the spec's `fingerprint`. Nothing of that source is written then.
22. **Plan** lists, in this order: `remove-unmanaged <path>` for every `paddock-*.sources` or `paddock-*.gpg` file
    (excluding the two Himmelblau files) that the spec does not name; `source <slug>` / `keyring <slug>` for files
    that differ; `file /etc/apt/preferences.d/51paddock-software` when it differs; `install <pkg>` (required, not
    installed, not in the record), `install <pkg>=<version>` (required pinned, installed version differs or not
    installed), `reinstall <pkg>` (required, in the record, not installed), `remove <pkg>` (uninstall or forbid,
    installed). `Plan` never changes the system.
23. **Apply** in this order: (a) files (remove unmanaged, write sources, keyrings, forbid pins); for every file that
    differs from the last applied spec when the spec is unchanged, emit `tamper.protected_file_changed{file}`
    (the `updates.writeFiles` rule); (b) when a source file or keyring changed, a scoped `apt-get update -q -o
    Dir::Etc::sourcelist=sources.list.d/paddock-<slug>.sources -o Dir::Etc::sourceparts=- -o
    APT::Get::List-Cleanup=0 -o DPkg::Lock::Timeout=60` per changed slug; (c) when any install, reinstall or
    removal is planned and `dpkg --audit`-style breakage is indicated by apt's `dpkg was interrupted`, `dpkg
    --configure -a` first; (d) installs and reinstalls in **one** `apt-get install -y -q -o DPkg::Lock::Timeout=60
    -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold --allow-downgrades <pkg>[=<version>]…`,
    preceded by the same command with `-s`; when the simulation lists any package under `The following packages
    will be REMOVED:` that is not itself a planned removal, the whole install step is refused and every planned
    package reports `failed/would_remove_dependents`; when the simulation says `Unable to locate package` or `has
    no installation candidate`, one full `apt-get update -q -o DPkg::Lock::Timeout=60` and one retry, then
    `failed/no_candidate`; (e) removals in one `apt-get remove -y -q -o DPkg::Lock::Timeout=60 <pkg>…` (no
    `--purge`), preceded by `-s`; the simulation MUST remove the planned packages only, otherwise
    `failed/would_remove_dependents`; removals run only when `ServerReachable()` is true, otherwise every planned
    removal reports `pending/deferred_offline` and the pass ends with `Result{Status: OK}` for the removals (they are
    not an error); (f) the record is rewritten (installed required packages added; packages no longer required
    removed); (g) the status (§6.2) is recomputed. A `Could not get lock` / `Unable to acquire the dpkg frontend
    lock` output of any apt step ends the pass with every pending operation as `pending/dpkg_locked` and
    `Result{Status: Error, Message: "dpkg locked; retrying at the next pass"}` — the drift loop retries.
24. **Events.** `software.installed{package, version, intent, catalog_entry_id, reason: first_install}` for a
    package not in the record; `software.reinstalled{…, reason: locally_removed}` for a recorded package;
    `software.removed{package, version, intent, catalog_entry_id}`; `software.apply_failed{package, source, stage,
    reason, error}` once per failed package or source per pass (not again while the failure is unchanged: the
    reconciler keeps the last failure key per package in memory; a changed spec or a success resets it). The agent
    emits these types only while the applied bundle has a `software` section (ADR 0024) — which is always the case
    when the reconciler runs; the implementer adds the four types to `protocol.EventTypes`, the gateway's accepted
    set and `device.yaml`.
25. **`ServerReachable`** is injected by `agent/internal/agent`: `func() bool { info, err := os.Stat(layout.LastCheckin());
    return err == nil && now().Sub(info.ModTime()) <= reconcile.RemovalWindow }` with `RemovalWindow = 15 * time.Minute`.
26. **Apply order** (`apply.go::order`): `[hostname, time, file, systemd_unit, updates, software, login, sudo]`;
    `sorted` maps `b.Software` to `bundle.SoftwareResource` at that position; `CheckTypes` is unchanged.
27. **Health.** After every apply or drift pass that ran the software resource, the agent sets
    `health.Report.Software` from `Software.Status()`. `checkinRequest` sends `software.digest` always and
    `software.items` when the digest differs from the one sent with the last successful check-in or when the last
    full send is older than 24 h (`agent.lastSoftwareDigest`, `lastSoftwareFullAt`, in memory).
28. **Protected areas and tamper.** The three path patterns of decision 20 are protected (ADR 0042 decision 9).
    Detection is the drift pass (300 s) through `Plan`; correction and `tamper.protected_file_changed{file}` through
    `Apply`. CLAUDE.md "Protected areas on the device" gains item 5 and architecture §11.6 gains item 5 (§7).
29. **Uninstall** (`agent/internal/uninstall/steps.go`): a new step `softwareSources` in both modes removes every
    `/etc/apt/sources.list.d/paddock-*.sources`, every `/etc/apt/keyrings/paddock-*.gpg` (not the Himmelblau files;
    `reset` removes those in `himmelblau`) and `/etc/apt/preferences.d/51paddock-software`, then runs
    `apt-get update -q` (a failing update is reported, not fatal). Installed applications stay. The step runs after
    `updateConfiguration`. The summary names the step as `software_sources`.

### 3.6 Portal (PDK-413)

30. **Views**: `SoftwareSources.vue` (`/software-sources`; `DataList`; create and edit in a dialog `SoftwareSourceForm.vue`
    with the fields of §6.1, a textarea for the armored key, the typed fingerprint; save → on `step_up_required`
    `startStepUp('software-source.save', id|'new', payload)` and resume; delete through `ConfirmDialog` with the
    typed source name, step-up on refusal the same way), `SoftwareCatalog.vue` (`/software-catalog`; `DataList`;
    columns name, category, source, packages (count), assignments (count), updated; create dialog
    `SoftwareCatalogEntryForm.vue` with a package-row editor), `SoftwareCatalogDetail.vue`
    (`/software-catalog/:id`; header with icon upload (PNG), the entry form, the assignments `DataList`
    (`SoftwareAssignmentForm.vue`: scope, intent, update rule, version, reason) and the devices `DataList` with
    state chips), `DeviceManagedSoftware.vue` (tab *Managed software* on `DeviceDetail.vue`, `DataList` of
    `/api/v1/devices/{id}/managed-software`). Every list reads and writes its state from the URL query.
31. **Navigation**: entries `nav.softwareSources` (visible `orgAdmin`) and `nav.softwareCatalog` (visible
    `orgReader`) in the section that holds `/package-holds`, placed before it.
32. **State chips** (`state`): `installed` success, `held` info, `absent` neutral, `pending` warning (with `reason`
    tooltip), `failed` error (with `error` tooltip), `not_applicable` neutral, `unknown` neutral.
33. **Texts** §6.6; every text in `en.json` and `de.json`; audit codes under `audit.<code>`; problem codes
    `fingerprint_mismatch` and `in_use` under `problems.<code>` (the existing problem text mechanism).
34. **Client**: `server/web/src/lib/software.ts` over the generated client only.

### 3.7 Gates, documents, residual risks (PDK-414)

35. Acceptance tests `TestSoftwareSources`, `TestSoftwareCatalog`, `TestSoftwareStatus` (§9); audit-once cases;
    isolation fixtures; the system gate `TestSoftwareGates` with SW1–SW8 (§9); `docs/operations/software.md`;
    RR-77 to RR-83 (§6.7); architecture amendments (§7); CLAUDE.md item 5 of "Protected areas on the device";
    `CHANGELOG.md`; the full regression.

## 4. Non-goals

- The self-service desktop app, the socket `/run/paddock/selfservice.sock`, the intent `available`, Flatpak, user
  and user-group targets (M13b).
- Update waves through ADR 0033's rollout, maintenance windows, an approval workflow, packages stored in Paddock, the
  patch compliance report, the platform-wide catalog, declarative sections for software in `PUT /api/v1/config` and
  `paddockctl` (M13c). Software writes record **no** change set in M13a.
- Snap, AppImage, distribution release upgrades, Windows, macOS.
- Changing `package_hold`, the `updates` reconciler's files, `paddock-himmelblau.list`, `himmelblau.gpg`,
  `pkg/policy`, `agent/internal/revoke/`, `agent/cmd/paddock-revoke/`.
- Upgrading `required latest` packages outside the update schedule.
- Purging configuration files on removal (`apt-get remove`, never `--purge`).
- Blocking a local administrator technically.

## 5. Affected files

| Path | Action | Purpose |
| --- | --- | --- |
| `pkg/openpgpkey/openpgpkey.go`, `openpgpkey_test.go`, `testdata/` | new | armor decode, v4 fingerprint, fuzz (decision 3) |
| `pkg/bundle/bundle.go`, `bundle_test.go` | change | `TypeSoftware`, `SoftwareSpec`, `ValidateSoftware`, `SoftwareResource` |
| `pkg/protocol/types.go` | change | software events, `SoftwareHealth`, `SoftwareItem`, constants |
| `api/openapi/device.yaml` | change | events and health, additive |
| `api/openapi/admin.yaml` | change | §6.1 endpoints, schemas, parameters |
| `server/migrations/paddock/00068_software_sources.sql`, `00069_software_catalog.sql`, `00070_device_software_status.sql` | new | §6.5 |
| `server/internal/adapters/postgres/queries/software.sql`, `queries/bundle.sql` | new / change | sqlc queries; compile targets with `os_release`, `arch` |
| `server/internal/domain/software/source.go`, `catalog.go`, `merge.go`, `*_test.go` | new | validation, `Resolve`, `MergeIntents` |
| `server/internal/domain/audit/codes.go` | change | §6.3 codes |
| `server/internal/app/softwaresources.go`, `softwarecatalog.go`, `softwarestatus.go`, `*_integration_test.go` | new | use cases |
| `server/internal/app/devicereports.go` | change | event map, `RecordStatus` software items |
| `server/internal/app/updates.go` | change | `UpdatesSection` takes the software holds as a second list |
| `server/internal/compiler/software.go`, `compiler.go`, `*_test.go` | new / change | section render, holds merge |
| `server/internal/transport/http/admin/handlers_software.go`, `server.go`, `listspec_test.go` | new / change | handlers, routes |
| `server/web/src/views/SoftwareSources.vue`, `SoftwareCatalog.vue`, `SoftwareCatalogDetail.vue`, `DeviceManagedSoftware.vue` | new | §3.6 |
| `server/web/src/components/SoftwareSourceForm.vue`, `SoftwareCatalogEntryForm.vue`, `SoftwareAssignmentForm.vue` | new | dialogs |
| `server/web/src/lib/software.ts`, `lib/navigation.ts`, `router.ts`, `views/DeviceDetail.vue`, `locales/en.json`, `locales/de.json` | new / change | client, nav, routes, tab, texts |
| `agent/internal/reconcile/software.go`, `software_test.go` | new | the reconciler |
| `agent/internal/reconcile/fakesys/fakesys.go` | change | only if `AptGet` simulation output needs a scripted response table (freedom §13) |
| `agent/internal/apply/apply.go`, `apply_test.go` | change | order, `sorted` |
| `agent/internal/health/health.go`, `agent/internal/agent/agent.go`, `bundles.go`, `*_test.go` | change | health field, digest rule, `ServerReachable`, status update |
| `agent/internal/uninstall/steps.go`, `uninstall.go`, `*_test.go` | change | step `software_sources` |
| `test/acceptance/software_test.go`, `isolation_fixtures.go`, `audit_once_*_test.go` | new / change | §9 |
| `test/system/software.go`, `software_test.go`, `README.md` | new / change | gate SW1–SW8, the gate repository |
| `docs/operations/software.md` | new | runbook |
| `docs/compliance/residual-risks.md` | change | RR-77 … RR-83 |
| `docs/architecture.md` | change | §7 amendments (architect decision: this plan) |
| `CLAUDE.md` | change | protected areas item 5 |
| `CHANGELOG.md`, `docs/compliance/audit-codes.md` (generated) | change | — |

**MUST NOT be touched:** `agent/internal/revoke/`, `agent/cmd/paddock-revoke/`, `pkg/policy/`,
`agent/internal/reconcile/updates.go` (except nothing — the file stays as is), `agent/internal/reconcile/login.go`,
`server/migrations/paddock/00001`–`00067`, `docs/adr/0001`–`0041`, the existing endpoints `/api/v1/software`,
`/api/v1/devices/{id}/software`, `/api/v1/package-holds`.

## 6. Interfaces and data model

### 6.1 Admin API (additions to `api/openapi/admin.yaml`)

All collection `GET`s carry `x-paddock-list`, the shared `Page`, `PageSize`, `Search` parameters and answer
`{items, page, page_size, total, total_capped, sort}`. Roles: read = `org_admin, org_operator, org_auditor`.

```yaml
/api/v1/software-sources:
  get:   # listSoftwareSources; x-paddock-list: sort [name, created_at, updated_at], default_sort name, search [name, slug], filters []
  post:  # createSoftwareSource; org_admin + step-up; 201 SoftwareSource (Location); 400 invalid_request; 403 step_up_required|forbidden; 409 already_exists (slug or name); 422 fingerprint_mismatch
/api/v1/software-sources/{id}:
  get:   # getSoftwareSource → SoftwareSource (with signing_key); 404
  patch: # updateSoftwareSource; org_admin + step-up; body SoftwareSourceUpdate (name, uris, suites, components, architectures, signing_key+fingerprint together); 200; 400 (slug given); 403; 404; 409; 422
  delete:# deleteSoftwareSource; org_admin + step-up; 204; 403; 404; 409 in_use
/api/v1/software-catalog:
  get:   # listSoftwareCatalog; sort [name, category, created_at, updated_at], default_sort name, search [name, description], filters [category, source_id]
  post:  # createSoftwareCatalogEntry; RolesWrite; 201; 400; 404 (source_id unknown → not_found); 409 already_exists (name)
/api/v1/software-catalog/{id}:
  get: patch: delete:   # RolesWrite for patch/delete; delete 204 cascades assignments; 409 never (cascade)
/api/v1/software-catalog/{id}/icon:
  put:   # setSoftwareCatalogIcon; RolesWrite; body image/png ≤ 65536 bytes, ≤ 512×512; 204; 400; 413 payload_too_large
  get:   # getSoftwareCatalogIcon; image/png; 404
/api/v1/software-catalog/{id}/devices:
  get:   # listSoftwareCatalogDevices; sort [hostname, state, reported_at], default_sort hostname, search [hostname], filters [state, device_group_id]
/api/v1/software-assignments:
  get:   # listSoftwareAssignments; sort [created_at, updated_at, intent], default_sort -created_at, search [app_name], filters [catalog_entry_id, device_group_id, intent]
  post:  # createSoftwareAssignment; RolesWrite; 201; 400 (intent/version rules of decision 9); 404 (entry or group); 409 already_exists
/api/v1/software-assignments/{id}:
  get: patch: delete:   # patch: intent, update_rule, version, reason (scope and entry fixed → 400); delete 204
/api/v1/devices/{id}/managed-software:
  get:   # listDeviceManagedSoftware; sort [name, state, reported_at], default_sort name, search [name], filters [state, intent]
```

Schemas (fields and types; `*` = required in requests):

```yaml
SoftwareSourceCreate: { slug*: string, name*: string, uris*: [string], suites*: [string], components: [string],
                        architectures: [enum amd64|arm64], signing_key*: string, fingerprint*: string }
SoftwareSourceUpdate: { name, uris, suites, components, architectures, signing_key, fingerprint }   # signing_key and fingerprint only together
SoftwareSourceSummary: { id, slug, name, uris, suites, components, architectures, fingerprint, entry_count: integer, created_at, updated_at }
SoftwareSource: SoftwareSourceSummary + { signing_key }
PackageRef: { distribution*: string, release*: string, architecture*: enum ['*', amd64, arm64], package*: string }
SoftwareCatalogEntryCreate: { name*, description, category, source_id: uuid|null, packages*: [PackageRef] }
SoftwareCatalogEntry: { id, name, description, category, source_id, source_slug, packages, has_icon: boolean,
                        assignment_count: integer, created_at, updated_at }
SoftwareAssignmentCreate: { catalog_entry_id*: uuid, device_group_id: uuid|null, intent*: enum [required, uninstall, hold, forbid],
                            update_rule: enum [latest, pinned], version: string|null, reason: string }
SoftwareAssignment: SoftwareAssignmentCreate + { id, app_name, created_at, updated_at }
DeviceSoftwareState: enum [installed, held, absent, pending, failed, not_applicable, unknown]
SoftwareCatalogDevice: { device_id, hostname, name, device_group_ids, state: DeviceSoftwareState, intent, package, version, reason, error, reported_at }
DeviceManagedSoftware: { catalog_entry_id, name, package, intent, state, version, reason, error, reported_at }
```

Problem codes: existing `invalid_request`, `not_found`, `already_exists`, `in_use`, `step_up_required`,
`payload_too_large`; new `fingerprint_mismatch` (422, `problem.FingerprintMismatch`).

### 6.2 Bundle, device protocol, health (additive, ADR 0013)

```go
// pkg/bundle
const TypeSoftware = "software"

type Bundle struct { …; Software *SoftwareSpec `json:"software,omitempty"` }

// SoftwareSpec is the software section (ADR 0042 decision 2): the APT sources the device needs and the packages
// with their intents. Sources and Packages are sorted by slug and package.
type SoftwareSpec struct {
    Sources  []SoftwareSource  `json:"sources"`
    Packages []SoftwarePackage `json:"packages"`
}

type SoftwareSource struct {
    Slug          string   `json:"slug"`           // ^[a-z0-9][a-z0-9-]{1,40}$
    URIs          []string `json:"uris"`           // https only
    Suites        []string `json:"suites"`
    Components    []string `json:"components"`
    Architectures []string `json:"architectures"`  // empty = apt's default
    Keyring       string   `json:"keyring"`        // standard base64 of the binary OpenPGP public key
    Fingerprint   string   `json:"fingerprint"`    // 40 uppercase hex characters
}

// Intents of SoftwarePackage.Intent.
const (
    SoftwareRequired  = "required"
    SoftwareUninstall = "uninstall"
    SoftwareHold      = "hold"
    SoftwareForbid    = "forbid"
)

type SoftwarePackage struct {
    Package        string  `json:"package"`
    Intent         string  `json:"intent"`
    Version        *string `json:"version"`          // required pinned, or a pinned hold; nil otherwise
    Source         string  `json:"source"`           // slug of a Sources entry, "" for the distribution's repositories
    CatalogEntryID string  `json:"catalog_entry_id"` // UUID
}

func ValidateSoftware(s SoftwareSpec) error           // every rule of §3.1 decision 2 and §3.2 decisions 8–9; a Source referenced by a package must exist; slugs and packages unique
func SoftwareResource(s SoftwareSpec) (Resource, error) // ID "software", type TypeSoftware, nil lists → []
```

deb822 rendering of a source (binding, byte for byte; `managedHeader` is the existing constant):

```
# Managed by Paddock. Do not edit: local changes are reverted.
Types: deb
URIs: <uri1> <uri2>
Suites: <suite1> <suite2>
Components: <c1> <c2>              ← line omitted when Components is empty
Architectures: <a1> <a2>           ← line omitted when Architectures is empty
Signed-By: /etc/apt/keyrings/paddock-<slug>.gpg
```

Forbid pin file `/etc/apt/preferences.d/51paddock-software` (absent when no package is forbidden):

```
# Managed by Paddock. Do not edit: local changes are reverted.

Package: <pkg>
Pin: release *
Pin-Priority: -1
```

```go
// pkg/protocol
const (
    EventSoftwareInstalled   = "software.installed"    // data: SoftwareChange{reason: first_install}
    EventSoftwareReinstalled = "software.reinstalled"  // data: SoftwareChange{reason: locally_removed}
    EventSoftwareRemoved     = "software.removed"      // data: SoftwareChange
    EventSoftwareApplyFailed = "software.apply_failed" // data: SoftwareApplyFailed
)
// SoftwareChange is the data of software.installed, software.reinstalled and software.removed.
type SoftwareChange struct {
    Package        string `json:"package"`
    Version        string `json:"version"`
    Intent         string `json:"intent"`
    CatalogEntryID string `json:"catalog_entry_id"`
    Reason         string `json:"reason,omitempty"`
}
// SoftwareApplyFailed is the data of software.apply_failed. Stage is source_update, keyring, simulate, install or remove;
// Reason is fingerprint_mismatch, would_remove_dependents, no_candidate, source_unreachable, dpkg_locked or apt_failed.
type SoftwareApplyFailed struct {
    Package string `json:"package,omitempty"`
    Source  string `json:"source,omitempty"`
    Stage   string `json:"stage"`
    Reason  string `json:"reason"`
    Error   string `json:"error"` // ≤ 200 characters
}

// States of SoftwareItem.State.
const (
    SoftwareStateInstalled = "installed"
    SoftwareStateHeld      = "held"
    SoftwareStateAbsent    = "absent"
    SoftwareStatePending   = "pending" // reason: dpkg_locked | deferred_offline | not_yet_applied
    SoftwareStateFailed    = "failed"  // reason as SoftwareApplyFailed.Reason
)
const MaxSoftwareItems = 200
type SoftwareHealth struct {
    Digest string         `json:"digest"`          // hex SHA-256 of the canonical JSON of Items
    Items  []SoftwareItem `json:"items,omitempty"` // present when the digest changed or every 24 h
}
type SoftwareItem struct {
    CatalogEntryID string `json:"id"`
    Package        string `json:"package"`
    Intent         string `json:"intent"`
    State          string `json:"state"`
    Version        string `json:"version,omitempty"`
    Reason         string `json:"reason,omitempty"`
    Error          string `json:"error,omitempty"`
}
```

`health.Report` gains `Software *protocol.SoftwareHealth json:"software,omitempty"`.

### 6.3 Audit codes (closed registry; descriptions verbatim)

| Code | Description | Params | Outcomes |
| --- | --- | --- | --- |
| `software_source.created` | An organization administrator added an APT package source with its signing key; the key's fingerprint is recorded. Adding a source is root-equivalent: every package it signs is installed as root. | `name, slug, uris, suites, components, fingerprint` | adminOutcomes; Note: "Denied with step_up_required without a fresh step-up (API tokens never have one), forbidden for another role; failure with fingerprint_mismatch when the typed fingerprint differs from the key's, already_exists for a duplicate slug or name." |
| `software_source.updated` | An organization administrator changed an APT package source: its name, URIs, suites, components, architectures or its signing key; a key change records the old and the new fingerprint. | `name, slug, fields, fingerprint, old_fingerprint` | adminOutcomes; Note as above |
| `software_source.deleted` | An organization administrator removed an APT package source; devices remove its source file and keyring at their next check-in. | `name, slug, fingerprint` | adminOutcomes; Note: "… failure with in_use while a catalog entry references the source." |
| `software_catalog_entry.created` | An application was added to the software catalog with its package names per distribution, release and architecture. | `name, category, source_id, source_slug, package_count` | adminOutcomes |
| `software_catalog_entry.updated` | A software catalog entry changed (name, description, category, source, package names or icon). | `name, fields` | adminOutcomes |
| `software_catalog_entry.deleted` | A software catalog entry was removed together with its assignments; devices stop managing the application. | `name, assignment_count` | adminOutcomes |
| `software_assignment.created` | An application was assigned to the organization or a device group with an intent: required (installed and kept installed), uninstall (removed), hold (version kept) or forbid (removed and blocked for apt). | `app, catalog_entry_id, device_group_id, intent, update_rule, version, reason` | adminOutcomes; Note: "failure with invalid_request when the intent and version rules are violated, already_exists for a second assignment of the entry in the same scope." |
| `software_assignment.updated` | The intent, update rule, version or reason of a software assignment changed. | `app, catalog_entry_id, device_group_id, intent, update_rule, version, old_intent, old_version, reason` | adminOutcomes |
| `software_assignment.deleted` | A software assignment was removed; devices stop enforcing it (installed software stays). | `app, catalog_entry_id, device_group_id, intent` | adminOutcomes |
| `device.software_installed` | A device installed a required application from its software catalog assignment for the first time (actor: the device). | deviceEventParams | success |
| `device.software_reinstalled` | A device found a required application removed locally and installed it again (actor: the device); nothing blocks the local administrator. | deviceEventParams | success |
| `device.software_removed` | A device removed an application because its assignment says uninstall or forbid (actor: the device). | deviceEventParams | success |
| `device.software_apply_failed` | A device could not apply a software assignment or source: the key fingerprint did not match, the operation would have removed other packages, the package has no candidate, or apt failed (actor: the device). | deviceEventParams | success; Note: "reason is fingerprint_mismatch, would_remove_dependents, no_candidate, source_unreachable, dpkg_locked or apt_failed; dpkg_locked and deferred removals are reported in the status, not as this event." |

Go constants: `CodeSoftwareSourceCreated`, `CodeSoftwareSourceUpdated`, `CodeSoftwareSourceDeleted`,
`CodeSoftwareCatalogEntryCreated`, `…Updated`, `…Deleted`, `CodeSoftwareAssignmentCreated`, `…Updated`,
`…Deleted`, `CodeDeviceSoftwareInstalled`, `CodeDeviceSoftwareReinstalled`, `CodeDeviceSoftwareRemoved`,
`CodeDeviceSoftwareApplyFailed`. Audit target types: `software_source` (display `name`), `software_catalog_entry`
(display `name`), `software_assignment` (display `<app> → <group name | organization>`).

### 6.4 Go signatures (new or changed)

```go
// pkg/openpgpkey
var ErrNotPublicKey = errors.New("openpgpkey: not an OpenPGP v4 public key")
func Fingerprint(armored []byte) (fingerprint string, keyring []byte, err error)
func FingerprintBinary(keyring []byte) (fingerprint string, err error)

// server/internal/domain/software
var ErrSource = errors.New("invalid software source"); var ErrEntry = errors.New("invalid catalog entry"); var ErrAssignment = errors.New("invalid software assignment")
var ErrFingerprint = errors.New("fingerprint mismatch")   // → 422 fingerprint_mismatch
type SourceInput struct { Slug, Name string; URIs, Suites, Components, Architectures []string; SigningKey, Fingerprint string }
func ValidateSource(in SourceInput) (fingerprint string, keyring []byte, err error)   // uses pkg/openpgpkey
func NormalizeFingerprint(s string) string
type PackageRef struct { Distribution, Release, Architecture, Package string }
func ValidateEntry(name, description, category string, packages []PackageRef) error
func Resolve(packages []PackageRef, osID, versionID, arch string) (pkg string, ok bool)
const (IntentRequired = bundle.SoftwareRequired; IntentUninstall = bundle.SoftwareUninstall; IntentHold = bundle.SoftwareHold; IntentForbid = bundle.SoftwareForbid)
const (UpdateLatest = "latest"; UpdatePinned = "pinned")
func ValidateAssignment(intent, updateRule string, version *string, reason string) error
type Effective struct { CatalogEntryID uuid.UUID; Package, Source, Intent, UpdateRule string; Version *string }
type Resolved struct { CatalogEntryID uuid.UUID; Package, Source, Intent string; Version *string }
type Conflict struct { Package string; Versions []*string; Chosen *string }
func MergeIntents(in []Effective) (out []Resolved, holds []bundle.Hold, conflicts []Conflict)

// server/internal/app
var SpecSoftwareSourceCreate = ActionSpec{Code: audit.CodeSoftwareSourceCreated, AllowedRoles: RolesAdmin, RequiresStepUp: true}  // Update, Delete alike
var SpecSoftwareCatalogEntryCreate = ActionSpec{Code: audit.CodeSoftwareCatalogEntryCreated, AllowedRoles: RolesWrite}             // Update, Delete, Assignment* alike
type SoftwareSources struct{ … }; func NewSoftwareSources(runner *ActionRunner, org *db.OrgPool) *SoftwareSources
type SoftwareCatalog struct{ … }; func NewSoftwareCatalog(runner *ActionRunner, org *db.OrgPool) *SoftwareCatalog
func UpdatesSection(settings UpdateSettings, holds []pgstore.PackageHold, softwareHolds []bundle.Hold, groups []uuid.UUID) *bundle.UpdatesSpec  // changed: second list

// server/internal/compiler
type orgSoftware struct { sources []pgstore.SoftwareSource; entries []pgstore.SoftwareCatalogEntry; assignments []pgstore.SoftwareAssignment }
func loadSoftware(ctx context.Context, q *pgstore.Queries) (*orgSoftware, error)
func (s *orgSoftware) section(groups []uuid.UUID, osID, versionID, arch string) (*bundle.SoftwareSpec, []bundle.Hold, []software.Conflict)

// agent/internal/reconcile
const (
    SoftwareSourceDir     = "/etc/apt/sources.list.d"
    SoftwareKeyringDir    = "/etc/apt/keyrings"
    SoftwarePrefix        = "paddock-"
    SoftwareForbidFile    = "/etc/apt/preferences.d/51paddock-software"
    softwareInstalledRecord = "/var/lib/paddock/state/software-installed"
    RemovalWindow         = 15 * time.Minute
)
type Software struct {
    Sys             System
    Events          *Events
    ServerReachable func() bool
    applied         []byte
    failures        map[string]string // package or slug → last failure key
    status          []protocol.SoftwareItem
}
func (s *Software) Type() string                                                   // bundle.TypeSoftware
func (s *Software) Plan(ctx context.Context, r bundle.Resource) ([]string, error)
func (s *Software) Apply(ctx context.Context, r bundle.Resource) Result
func (s *Software) Status() *protocol.SoftwareHealth                               // nil before the first Apply
func SoftwareSourcePath(slug string) string                                        // /etc/apt/sources.list.d/paddock-<slug>.sources
func SoftwareKeyringPath(slug string) string                                       // /etc/apt/keyrings/paddock-<slug>.gpg
func renderSoftwareSource(src bundle.SoftwareSource) []byte
func renderForbidPins(pkgs []string) []byte                                        // nil when empty

// agent/internal/uninstall
func (h *Helper) softwareSources(ctx context.Context) string                        // step "software_sources"
```

### 6.5 Migrations (forward-only, `-- +goose Up` only; RLS as `00025`)

```sql
-- 00068_software_sources.sql
CREATE TABLE software_source (
  id uuid PRIMARY KEY,
  organization_id uuid NOT NULL REFERENCES organization(id),
  slug text NOT NULL CHECK (slug ~ '^[a-z0-9][a-z0-9-]{1,40}$'),
  name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 100),
  uris text[] NOT NULL CHECK (cardinality(uris) BETWEEN 1 AND 4),
  suites text[] NOT NULL CHECK (cardinality(suites) BETWEEN 1 AND 8),
  components text[] NOT NULL DEFAULT '{}' CHECK (cardinality(components) <= 8),
  architectures text[] NOT NULL DEFAULT '{}' CHECK (cardinality(architectures) <= 2),
  signing_key text NOT NULL CHECK (octet_length(signing_key) <= 65536),
  fingerprint text NOT NULL CHECK (fingerprint ~ '^[0-9A-F]{40}$'),
  created_by uuid, created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (organization_id, slug), UNIQUE (organization_id, name)
);
-- RLS: ENABLE + FORCE; POLICY tenant TO paddock_api, paddock_compiler USING/WITH CHECK current_setting('paddock.org_id')::uuid
-- GRANT SELECT, INSERT, UPDATE, DELETE TO paddock_api; GRANT SELECT TO paddock_compiler

-- 00069_software_catalog.sql
CREATE TABLE software_catalog_entry (
  id uuid PRIMARY KEY, organization_id uuid NOT NULL REFERENCES organization(id),
  name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 100),
  description text NOT NULL DEFAULT '' CHECK (char_length(description) <= 1000),
  category text NOT NULL DEFAULT '' CHECK (char_length(category) <= 64),
  source_id uuid REFERENCES software_source(id) ON DELETE RESTRICT,
  packages jsonb NOT NULL,
  icon bytea CHECK (icon IS NULL OR octet_length(icon) <= 65536),
  created_by uuid, created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (organization_id, name),
  FOREIGN KEY (organization_id, source_id) REFERENCES software_source (organization_id, id)
);
CREATE TABLE software_assignment (
  id uuid PRIMARY KEY, organization_id uuid NOT NULL REFERENCES organization(id),
  catalog_entry_id uuid NOT NULL REFERENCES software_catalog_entry(id) ON DELETE CASCADE,
  device_group_id uuid REFERENCES device_group(id) ON DELETE CASCADE,
  intent text NOT NULL CHECK (intent IN ('required','uninstall','hold','forbid')),
  update_rule text NOT NULL DEFAULT 'latest' CHECK (update_rule IN ('latest','pinned')),
  version text CHECK (version ~ '^[A-Za-z0-9.+:~-]+$' AND char_length(version) <= 128),
  reason text NOT NULL DEFAULT '' CHECK (char_length(reason) <= 500),
  created_by uuid, created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE NULLS NOT DISTINCT (organization_id, catalog_entry_id, device_group_id),
  FOREIGN KEY (organization_id, catalog_entry_id) REFERENCES software_catalog_entry (organization_id, id) ON DELETE CASCADE,
  FOREIGN KEY (organization_id, device_group_id) REFERENCES device_group (organization_id, id) ON DELETE CASCADE,
  CHECK ((intent = 'required' AND update_rule = 'pinned' AND version IS NOT NULL)
      OR (intent = 'required' AND update_rule = 'latest' AND version IS NULL)
      OR (intent = 'hold' AND update_rule = 'latest')
      OR (intent IN ('uninstall','forbid') AND update_rule = 'latest' AND version IS NULL))
);
-- RLS on both as above (paddock_api RW, paddock_compiler SELECT); indexes (organization_id, name), (organization_id, catalog_entry_id)

-- 00070_device_software_status.sql
CREATE TABLE device_software_status (
  device_id uuid NOT NULL REFERENCES device(id), organization_id uuid NOT NULL,
  catalog_entry_id uuid NOT NULL REFERENCES software_catalog_entry(id) ON DELETE CASCADE,
  package text NOT NULL, intent text NOT NULL, state text NOT NULL,
  version text NOT NULL DEFAULT '', reason text NOT NULL DEFAULT '', error text NOT NULL DEFAULT '',
  reported_at timestamptz NOT NULL,
  PRIMARY KEY (device_id, catalog_entry_id),
  FOREIGN KEY (organization_id, device_id) REFERENCES device (organization_id, id)
);
CREATE INDEX device_software_status_org_entry ON device_software_status (organization_id, catalog_entry_id, state);
-- RLS: tenant policy TO paddock_api, paddock_worker; GRANT SELECT TO paddock_api; GRANT SELECT, INSERT, UPDATE, DELETE TO paddock_worker
ALTER TABLE device_status ADD COLUMN software_digest text NOT NULL DEFAULT '';
```

### 6.6 Portal texts (binding English; German complete, wording free)

| Key | English |
| --- | --- |
| `nav.softwareSources` | Package sources |
| `nav.softwareCatalog` | Software catalog |
| `software.sources.title` | Package sources |
| `software.sources.summary` | Third-party APT repositories your devices may install from. Each source has its own signing key; adding or changing one is a root-equivalent change and asks for a security key. |
| `software.sources.fingerprintHint` | Enter the fingerprint published by the vendor. It must match the uploaded key. |
| `software.sources.httpsOnly` | Sources must use https. |
| `software.sources.deleteTitle` | Remove package source |
| `software.sources.deleteConfirm` | Devices remove the source file and the keyring at their next check-in. Installed software stays. Type the source name to confirm. |
| `software.catalog.title` | Software catalog |
| `software.catalog.summary` | Applications your devices install, keep, hold or block, by device group. Required applications a user removes are installed again and the event is recorded. |
| `software.intent.required` / `.uninstall` / `.hold` / `.forbid` | Required / Uninstall / Hold version / Forbid |
| `software.updateRule.latest` / `.pinned` | Latest / Pinned version |
| `software.state.installed` / `.held` / `.absent` / `.pending` / `.failed` / `.not_applicable` / `.unknown` | Installed / Held / Not installed / Pending / Failed / Not applicable / No report yet |
| `software.reason.dpkg_locked` | Another package operation is running; the device retries. |
| `software.reason.deferred_offline` | The device waits for a server connection before it removes software. |
| `software.reason.would_remove_dependents` | The operation would remove other packages; nothing was changed. |
| `software.reason.no_candidate` | The package or version is not available from the device's sources. |
| `software.reason.fingerprint_mismatch` | The source key does not match its fingerprint; the source was not written. |
| `problems.fingerprint_mismatch` | The key's fingerprint does not match the one you entered. |
| `problems.in_use` | This source is used by a catalog entry. |
| `device.tabs.managedSoftware` | Managed software |

### 6.7 Residual risks (`docs/compliance/residual-risks.md`, new section "Software catalog (M13a)"; RR-77 to RR-83)

| ID | Risk | Mitigation in Paddock | Record in the ISMS |
| --- | --- | --- | --- |
| RR-77 | **A source key is root-equivalent.** Whoever holds a source's signing key, or controls the HTTPS endpoint of a repository whose key is trusted, ships packages that install as root on every device of the assignment. Paddock never checks a repository's content or reachability; it trusts the key the administrator entered. | Per-source keyring (`Signed-By`), never the global keyring; HTTPS only; `org_admin` with a WebAuthn step-up for every source change; the typed fingerprint must match the uploaded key; the fingerprint is in every audit event; the agent refuses a keyring whose fingerprint differs from the signed bundle. | The verification of vendor fingerprints out of band; who may be `org_admin`. |
| RR-78 | **Maintainer scripts run as root.** `preinst`, `postinst`, `prerm` and `postrm` of every installed or removed package run as root with no sandbox; Paddock cannot confine dpkg. | Only packages from trusted sources or the distribution; the install simulation refuses operations that would remove other packages; every install, reinstall and removal is an audit event. | Which vendors are trusted; review of own repositories. |
| RR-79 | **Flathub is an external trust anchor** (M13b). Apps from Flathub are built and signed by Flathub, not by the vendor; a remote's key change is outside Paddock's control. Reserved here; M13b records the mitigation. | — (M13b) | — (M13b) |
| RR-80 | **Local root bypasses pins and holds.** A local administrator can `dpkg -i` a forbidden package, delete a keyring or edit a source file; apt's pin priority −1 stops `apt-get install`, not `dpkg`. | Protected area with correction within the drift interval and `device.tamper_protected_file_changed`; forbidden packages are removed again and `device.software_removed` recorded; required packages are reinstalled (`device.software_reinstalled`). Nothing is prevented (RR-01). | The reaction to repeated tamper and reinstall events on one device. |
| RR-81 | **Refused operations stay refused.** An install or removal that would remove any package other than the targets is refused (`would_remove_dependents`) and stays refused until the assignment or the device changes; a `forbid` of a package another package depends on never removes it. | The state `failed` with the reason on the device page and the catalog's device list; the event `device.software_apply_failed` once per failure. | Who reviews failed assignments. |
| RR-82 | **Status can lag.** The per-app status travels with the check-in only when it changed and at least daily; after a restore from backup the portal shows the status of the backup until the next change or up to 24 h; removals are deferred while the device had no check-in for 15 minutes. | Every change is also an audit event; `reported_at` is shown. | None beyond reading `reported_at` for decisions. |
| RR-83 | **Pinned versions vanish.** A repository that drops a pinned version leaves a `required pinned` package in `failed/no_candidate` and a `hold` at a version the repository no longer has; the installed version stays. | The state and reason are shown; `required latest` is unaffected. | The policy for pinning versions from third-party repositories. |

## 7. Architecture and rule amendments (binding text; PDK-414 writes them)

- **`docs/architecture.md` §11.3** — after the M8h amendment: "> **Amendment 2026-10-24 (M13a, ADR 0042):** the
  agent maps the optional `software` section to the internal resource `software`, applied after `updates`
  (`hostname → time → file → systemd_unit → updates → software → login → sudo`). It owns
  `/etc/apt/sources.list.d/paddock-*.sources` (deb822, per-source `Signed-By`), `/etc/apt/keyrings/paddock-*.gpg`,
  `/etc/apt/preferences.d/51paddock-software` (forbid pins, priority −1), the installs and removals of catalog
  packages and the record of what it installed. Holds and version pins stay with the `updates` reconciler; the
  compiler merges the catalog's `hold` and `required pinned` results into `updates.holds`. Removals need a check-in
  within 15 minutes; a dpkg lock is retried at the next drift pass; every operation is simulated first and refused
  when it would remove other packages."
- **§11.5** table row: "| Paddock-managed APT sources, keyrings and forbid pins | drift pass 5 min |
  `tamper.protected_file_changed` |".
- **§11.6** item 5: "`/etc/apt/sources.list.d/paddock-*.sources`, `/etc/apt/keyrings/paddock-*.gpg`,
  `/etc/apt/preferences.d/51paddock-software` (ADR 0042); the uninstall removes them in both modes."
- **§12.5** paragraph: "Software catalog (M13a, ADR 0042): catalog entries with package names per distribution,
  release and architecture, assigned per device group with the intents required, uninstall, hold and forbid;
  `required latest` is installed and moves with the update runs, `required pinned` is installed at and held to a
  version; a locally removed required package is reinstalled and reported (`device.software_reinstalled`)."
- **§16.1** list of tables: `software_source`, `software_catalog_entry`, `software_assignment`,
  `device_software_status`, `device_status.software_digest`.
- **`CLAUDE.md` "Protected areas on the device"** item 5: "Paddock-managed APT sources, keyrings and pins
  (`/etc/apt/sources.list.d/paddock-*.sources`, `/etc/apt/keyrings/paddock-*.gpg`,
  `/etc/apt/preferences.d/51paddock-software`)."

## 8. Steps (tickets, in order)

1. **PDK-408 — Software sources: `pkg/openpgpkey`, domain, migration `00068`, use cases, API, step-up, audit.**
   §3.1, §6.1 (sources), §6.3 (source codes), §6.4, §6.5 (`00068`). Verify: `make gen` no diff;
   `GOTOOLCHAIN=auto go test -count=1 ./pkg/openpgpkey/ ./server/internal/domain/software/ ./server/internal/app/
   ./server/internal/transport/http/admin/`; `TestOpenAPISpec`; the list contract test.
2. **PDK-409 — Software catalog entries and assignments: domain, migration `00069`, use cases, API, icons, audit.**
   §3.2, §6.1 (catalog, assignments, icon), §6.3, §6.4, §6.5 (`00069`). Depends on PDK-408 (`source_id`).
3. **PDK-410 — Bundle section `software`, compiler resolution, holds merge.** §3.3, §6.2 (bundle), §6.4
   (`pkg/bundle`, compiler, `UpdatesSection`). Depends on PDK-409. Verify: `go test ./pkg/bundle/
   ./server/internal/compiler/ ./server/internal/app/`.
4. **PDK-411 — Status: protocol health, migration `00070`, `RecordStatus`, device and catalog status endpoints.**
   §3.4, §6.1 (`…/devices`, `…/managed-software`), §6.2 (`SoftwareHealth`), §6.5 (`00070`). Depends on PDK-410
   (bundle types for the derived state), MAY run in parallel with PDK-412.
5. **PDK-412 — Agent: `reconcile.Software`, apply order, health, events, uninstall step, protected areas.** §3.5,
   §6.2 (rendering, events), §6.4 (agent). Depends on PDK-410 (`pkg/bundle`, `pkg/protocol`). Verify:
   `GOTOOLCHAIN=auto go test -count=1 ./agent/...`; `make typecheck`.
6. **PDK-413 — Portal: sources, catalog, detail, device tab, navigation, texts.** §3.6, §6.6. Depends on PDK-408,
   PDK-409, PDK-411 (API). Verify: `make web`, frontend-verify.
7. **PDK-414 — Gates, runbook, residual risks, architecture amendments, regression.** §3.7, §6.7, §7, §9. Depends
   on PDK-412 and PDK-413. Verify: `make acceptance T='TestSoftware'`; `make system-test VM=all
   T='TestSoftwareGates'`; the full regression (`make lint test`, `make acceptance`, `make e2e`,
   `make system-test VM=all`); `make scan-secrets`.

PDK-411 and PDK-412 MAY run in parallel after PDK-410; PDK-413 MAY start its sources and catalog views after
PDK-409.

## 9. Tests and gates

- **Unit, `pkg/openpgpkey`:** §3.1 decision 3 (fixtures, errors, fuzz).
- **Unit, `pkg/bundle`:** `ValidateSoftware` table — valid spec; `http://` URI → error; slug `A` → error; package
  referencing an unknown source → error; duplicate package → error; `required` without version and with version;
  `uninstall` with version → error. `SoftwareResource` encodes nil lists as `[]`; `ContentSHA256` differs with and
  without the section.
- **Unit, `server/internal/domain/software`:** `ValidateSource` (every rule of decision 2, fingerprint case and
  spaces, `fingerprint_mismatch`); `Resolve` table (exact > release/\* > \*/arch > \*/\*; other distribution →
  false; empty arch matches `*` only); `MergeIntents` table — `required` + `hold v1` → `required pinned v1` and a
  hold; `required latest` + `required pinned v2` → pinned v2; `forbid` + `required` → `forbid`; `uninstall` +
  `hold` → `uninstall`; two pinned versions → smallest + one conflict; `ValidateAssignment` rules of decision 9.
- **Integration, `server/internal/app`:** sources — create as `org_admin` with step-up (one `success` event with
  `fingerprint`), without step-up → 403 `step_up_required` and a `denied` event, with an API token → 403, as
  `org_operator` → 403 `forbidden`, duplicate slug → 409, `http://` → 400, mismatched fingerprint → 422 and a
  `failure` event, delete while referenced → 409 `in_use`, foreign organization → 404; catalog — create, update,
  delete cascades assignments (counts in params), icon PNG accepted, JPEG refused, 70 KiB PNG → 413, 600×600 PNG →
  400; assignments — rules, duplicate scope → 409, unknown group → 404; `RecordStatus` — items replace rows,
  digest-only keeps rows, unknown entry id skipped, 201 items → the gateway bound (the server stores the first 200;
  stop condition §11 if the gateway's body limit is lower).
- **Unit, `server/internal/compiler`:** a device in group G with `required` → section with the package and its
  source, `updates.holds` unchanged; `required pinned 1.0` → section entry with version and `updates.holds` contains
  `{pkg, 1.0}` merged with a `package_hold` of another package; `hold` → no source, a hold; `forbid` → section
  entry, no source; an entry whose packages do not match the device's `os_release` → omitted; a device without
  assignments → no section; v1 → never.
- **Unit, `agent/internal/reconcile` (fakesys):** Plan lists `source`, `keyring`, `install` for a fresh spec; Apply
  writes the two files byte for byte as §6.2 renders them, runs the scoped `apt-get update`, simulates and installs,
  writes the record, reports `installed` with the version from `PackageVersion`, emits `software.installed`; a
  second Apply is `OK` with no events; the package removed from fakesys → Plan `reinstall`, Apply emits
  `software.reinstalled`; `uninstall` with `ServerReachable` false → status `pending/deferred_offline`, no `apt-get
  remove` call, `OK`; `ServerReachable` true → removed, `software.removed`; simulation output listing another
  package under REMOVED → nothing installed, `failed/would_remove_dependents`, one `software.apply_failed`, a second
  pass emits none; apt output `Could not get lock` → `Error`, status `pending/dpkg_locked`; `dpkg was interrupted`
  → `dpkg --configure -a` recorded before the retry; keyring with a different fingerprint → `failed/fingerprint_mismatch`,
  no file written; a `paddock-rogue.sources` in fakesys → Plan `remove-unmanaged`, Apply removes it and emits
  `tamper.protected_file_changed{file}`; a modified `.sources` with an unchanged spec → restored and the tamper
  event; `forbid` → `51paddock-software` rendered, removed when the last forbid leaves; the Himmelblau files are
  never planned.
- **Unit, `agent/internal/apply`:** order has `software` after `updates`; a bundle with the section applies it; a
  bundle without applies nothing for it; `CheckTypes` accepts a bundle whose only novelty is the section.
- **Unit, `agent/internal/agent`:** `checkinRequest` carries `software.digest` always, `items` on the first send,
  not on the second with the same digest, again after a changed digest, again after 24 h.
- **Unit, `agent/internal/uninstall`:** step `software_sources` removes the three patterns, keeps the Himmelblau
  files, runs `apt-get update`.
- **Portal:** component tests for `SoftwareSourceForm` (https validation message, fingerprint normalization, the
  step-up resume path), `SoftwareAssignmentForm` (version field enabled by intent and rule), state chips.
- **Acceptance (dev stack, devicesim):**
  - `TestSoftwareSources`: as `alice` (`org_admin`) with step-up `POST /software-sources` with the Ed25519 fixture
    key → 201 and one `software_source.created` with `fingerprint`; `withoutStepUp` → 403 `step_up_required` and a
    `denied` event; API token → 403; `http://` → 400; wrong fingerprint → 422 `fingerprint_mismatch`; PATCH with a
    second key → event with `old_fingerprint`; DELETE while referenced → 409 `in_use`; the list contract and the
    isolation gate (new endpoints in `isolation_fixtures.go` → foreign IDs 404).
  - `TestSoftwareCatalog`: entry + `required pinned` assignment for a devicesim device's group → the devicesim's
    next check-in offers a bundle whose payload has `software.packages[0] == {package, intent: required, version,
    source: <slug>, catalog_entry_id}`, `software.sources[0].fingerprint` equal to the source's, and
    `updates.holds` containing `{package, version}`; switch to `forbid` → next bundle has no `sources`, the entry
    with `forbid`, `updates.holds` without it; a device whose `os_release` names another distribution gets no
    section; audit-once cases for the nine administrator codes.
  - `TestSoftwareStatus`: devicesim check-in with `--health '{"software":{"digest":"…","items":[…]}}'` →
    `GET /devices/{id}/managed-software` lists the item with `state`, `reported_at`; `GET
    /software-catalog/{id}/devices` lists the device; a second check-in with digest only keeps the rows; a device
    without a package for its distribution shows `not_applicable`.
- **System gate `TestSoftwareGates`** (`forEachVM`, fresh base install; helper `test/system/software.go`): the
  gate builds a **local signed APT repository on the VM** — `apt-utils` and `gpg` are required (installed with
  `apt-get install -y apt-utils` in the setup if missing; a missing `gpg` fails the gate), a throwaway OpenPGP key
  (`gpg --batch --quick-gen-key`), two packages `paddock-gate-app` 1.0 and 1.1 built with `dpkg-deb --build`
  (`postinst` writes `/var/lib/paddock-gate-app/version`), `apt-ftparchive packages`/`release`, `gpg --clearsign
  -o InRelease`, a self-signed certificate (`openssl req -x509`) installed into
  `/usr/local/share/ca-certificates/paddock-gate.crt` + `update-ca-certificates`, served by a transient unit
  (`systemd-run --unit paddock-gate-repo python3 <tls http.server script>`) at `https://127.0.0.1:8443/`; the
  source is created in Paddock with `uris: ["https://127.0.0.1:8443/"]`, `suites: ["./"]`, the exported armored
  key and its fingerprint (`gpg --fingerprint --with-colons`). The repository is torn down with the VM snapshot.
  - **SW1 required install:** assignment `required pinned 1.0` for the VM's group → within one check-in
    `dpkg-query -W paddock-gate-app` prints `1.0`, `/etc/apt/sources.list.d/paddock-<slug>.sources` and the keyring
    exist with the rendered content, `apt-cache policy paddock-gate-app` shows pin 1001 for 1.0, the device
    reported `software.installed` (`Device.WaitEvent`), the audit log has `device.software_installed`, `GET
    /devices/{id}/managed-software` shows `installed 1.0` after the next check-in.
  - **SW2 local removal → reinstall + event:** `sudo apt-get remove -y paddock-gate-app` → within the drift
    interval (≤ 6 min) the package is back at 1.0, `device.software_reinstalled` is recorded with `reason:
    locally_removed`.
  - **SW3 forbid → removal + event:** switch the assignment to `forbid` → the package is removed,
    `device.software_removed` with `intent: forbid`, `51paddock-software` holds the stanza, `sudo apt-get install
    -y paddock-gate-app` fails (no installation candidate / pinned −1), `dpkg -i` of the 1.0 deb succeeds and the
    package is removed again within the drift interval with a second `device.software_removed`.
  - **SW4 hold → no upgrade:** assignment `required pinned 1.0` again (installed 1.0), then `hold` without a
    version → `apt-mark showhold` lists the package; `sudo systemctl start paddock-updates.service` (the regular
    run) → still 1.0 and `updates.run.held_back` names it; switch to `required latest` → the catalog run does not
    upgrade by itself (still 1.0 after the next check-in), the next `paddock-updates.service` run upgrades to 1.1.
  - **SW5 server unreachable → nothing removed:** assignment `forbid` (package absent), then block the control
    plane from the VM (`sudo iptables -I OUTPUT -d <api-ip> -j REJECT`, the IP from the enrollment configuration),
    wait until `/run/paddock/last-checkin` is older than 15 minutes (the gate fakes it: `sudo touch -d '-20 min'
    /run/paddock/last-checkin` after confirming a check-in fails), `sudo dpkg -i paddock-gate-app_1.0.deb` → after
    two drift intervals the package is **still installed** and the health socket (`Device.Health()`) shows
    `software.items[].state == pending, reason == deferred_offline`; remove the rule → within one check-in the
    package is removed and `device.software_removed` recorded.
  - **SW6 dpkg lock → retry:** `sudo systemd-run --unit gate-lock flock /var/lib/dpkg/lock-frontend sleep 600`,
    assignment `required pinned 1.0` → after the first apply the health shows `pending/dpkg_locked` and no
    `device.software_apply_failed` is recorded; `sudo systemctl stop gate-lock` → within the drift interval the
    package is installed and `device.software_installed` recorded.
  - **SW7 source key change needs step-up:** rotate the repository key and re-sign `InRelease` → `sudo apt-get
    update` on the VM reports `NO_PUBKEY` for the gate source (evidence that the old key no longer verifies);
    `PATCH /software-sources/{id}` with the new key `withoutStepUp` → 403 `step_up_required` and a `denied` event;
    with step-up → 200 and `software_source.updated` with `fingerprint` (new) and `old_fingerprint`; within one
    check-in the keyring on the VM has the new fingerprint (`gpg --show-keys --with-colons
    /etc/apt/keyrings/paddock-<slug>.gpg`), the scoped update succeeds and `required pinned 1.1` installs.
  - **SW8 tamper:** `echo '# x' | sudo tee -a /etc/apt/sources.list.d/paddock-<slug>.sources` and `sudo cp … 
    /etc/apt/sources.list.d/paddock-rogue.sources` → within the drift interval the managed file is byte-identical to
    the rendering again, the rogue file is gone, and two `device.tamper_protected_file_changed` events name both
    files.
  - Both VMs end restored to the snapshot (`vm.Fresh` semantics); every server object carries the run suffix.

## 10. Acceptance criteria (positive and negative per role)

- **AC-1 (org_admin).** Given a verified vendor fingerprint and key, when the administrator adds the source with a
  fresh step-up, then the response is 201, the audit log shows `software_source.created` with that fingerprint, and
  the source appears in the list without its key.
- **AC-2 (org_admin, API token).** Given the same request without a step-up or with an API token, when it is sent,
  then the response is 403 `step_up_required`, one `denied` event is recorded and nothing is stored.
- **AC-3 (org_admin).** Given a key whose fingerprint differs from the typed one, when the source is saved, then the
  response is 422 `fingerprint_mismatch`, the portal shows the message under the fingerprint field, and a `failure`
  event is recorded.
- **AC-4 (org_operator).** Given a source, when the operator creates a catalog entry with packages for `ubuntu
  24.04 amd64` and `ubuntu * *` and assigns it `required pinned 1.0` to a device group, then the response is 201
  each, one `software_catalog_entry.created` and one `software_assignment.created` are recorded, and the group's
  devices receive a bundle with the `software` section and the hold in `updates.holds`.
- **AC-5 (device user, org_operator).** Given that bundle, when the device checks in, then the package is installed
  at 1.0 within one check-in, nothing else was removed, `device.software_installed` is recorded, and the entry's
  device list shows *Installed 1.0* after the next check-in.
- **AC-6 (device user, org_admin).** Given a required package, when a local administrator removes it, then within
  five minutes it is installed again and `device.software_reinstalled` is recorded; the user was not blocked.
- **AC-7 (org_operator, device user).** Given the assignment changed to `forbid`, when the device checks in, then
  the package is removed, `device.software_removed` is recorded, and `apt-get install` of it fails on the device.
- **AC-8 (org_operator).** Given a `hold`, when the regular update run executes, then the package keeps its version
  and `updates.run` lists it as held back.
- **AC-9 (device user).** Given a cached `forbid` or `uninstall` and no check-in for 15 minutes, when the package is
  present, then nothing is removed, the health shows `deferred_offline`, and the removal happens at the first
  check-in after the server is reachable again.
- **AC-10 (device user).** Given another process holds the dpkg lock, when the agent applies, then it reports
  `dpkg_locked`, records no failure event, and completes at a later pass once the lock is released.
- **AC-11 (org_admin).** Given a source's key changed upstream, when the administrator saves the new key, then a
  step-up is required, `software_source.updated` carries both fingerprints, and devices verify the repository again
  within one check-in.
- **AC-12 (org_admin).** Given a modified managed source file or a rogue `paddock-*.sources`, when the drift pass
  runs, then both are corrected and `device.tamper_protected_file_changed` names the files.
- **AC-13 (org_auditor).** Given an auditor, when they open the sources, the catalog or a device's managed-software
  tab, then they see the lists without create, edit or delete controls, and every write endpoint answers 403 with a
  `denied` event.
- **AC-14 (org_operator, other organization).** Given a source, entry or assignment of organization B, when an
  operator of A reads or writes it by ID, then the response is 404 `not_found`.
- **AC-15 (operator of the stack).** Given an agent older than this release, when it receives a bundle with the
  section, then it applies the bundle as before and reports nothing for `software`.
- **AC-16 (org_admin).** Given an uninstall in mode `leave` or `reset`, when it completes, then the device has no
  `paddock-*.sources`, `paddock-*.gpg` or `51paddock-software`, the installed applications are still installed, and
  the summary names `software_sources: done`.

## 11. Stop conditions

- `main` already has a migration `00068`, `00069` or `00070` → take the next free numbers and report them.
- `ListCompileTargets` or `compiler.render` cannot carry `os_release` and `arch` without changing a query that
  other roles share in a way that alters their behaviour → stop and report.
- The gateway's body limit for `POST /v1/checkin` is below the size of 200 `SoftwareItem`s with 200-character errors
  (about 80 KiB) → stop; the bound is an architect decision.
- `pkg/openpgpkey` cannot read a key of a real vendor used in the gates (v5 or v6 key, unusual packet) → stop; the
  parser scope is an architect decision.
- `apt-get update -o Dir::Etc::sourcelist=<file>.sources` does not parse the deb822 file on Ubuntu 24.04 or 26.04
  (the system gate fails on `source_update`) → stop; the fallback is a full `apt-get update`.
- `apt-utils` (`apt-ftparchive`) cannot be installed on a test VM, or the VM cannot serve TLS locally → stop and
  report; the gate's repository approach is an architect decision.
- `fakesys.System.AptGet` cannot return different outputs for the `-s` simulation and the real run without
  changing its contract for existing tests → extend `fakesys` with a scripted response table keyed by the full
  argument list (freedom §13) and report; do not change existing tests.
- Any need for a new Go module, npm package or container image → stop.
- Any need to add a path to `pkg/policy` or to touch `agent/internal/revoke/` → stop.
- The devicesim cannot report a `software` health object (its `--health` flag is `disk`-only) → extend the
  devicesim (test code) and report; do not fake the server side.

## 12. Risks and open points

Residual risks: §6.7 (RR-77 to RR-83; PDK-414 writes the rows).

Risks with countermeasures:

- **R1 — Install removes dependents.** `apt-get install` and `remove` may remove other packages (conflicts, reverse
  dependencies). Countermeasure: the `-s` simulation and the refusal rule (decision 23 d/e); gate SW3 proves the
  removal path, the fakesys test proves the refusal.
- **R2 — Two owners of apt state.** Countermeasure: ADR 0042 decision 3 (the `updates` reconciler owns holds); the
  software reconciler has no `AptMark` call (a unit test asserts that `fakesys.Calls` has none).
- **R3 — Event spool blocked by an unknown type.** Countermeasure: ADR 0024 reasoning (decision 24); the server is
  released first in the normal order; the acceptance run proves the gateway accepts the four types.
- **R4 — Fingerprint parser bugs.** Countermeasure: fuzz test, real-key fixtures, refusal of everything but v4
  public keys; the agent verifies again on the device.

Open questions (default chosen; the maintainer may overrule):

1. **OpenPGP reader.** Default: own minimal reader `pkg/openpgpkey` (stdlib). Alternatives: `golang.org/x/crypto/openpgp`
   (deprecated, would become a direct import) or `github.com/ProtonMail/go-crypto` (new dependency, needs
   approval).
2. **Step-up for assignments.** Default: none (`RolesWrite`, the privilege of `install_now`). Alternative: step-up
   for `required` assignments whose source is a third-party source.
3. **Scope of `StateChanged`.** Default: `ScopeOrg` for entry and assignment writes. Alternative: per device group
   (less compile work for large organizations; needs the group → device expansion the compiler already has for
   managed files — implementer's freedom if the mechanism is identical).
4. **Removal purges configuration?** Default: no (`apt-get remove`). Alternative: a per-assignment `purge` flag.
5. **Status `failed` on the attention page.** Default: not in M13a (the device page and the catalog's device list
   show it; M9's notifications can subscribe to `device.software_apply_failed`).
6. **Per-package events in the audit trail.** Default: one event per install, reinstall, removal and distinct
   failure (first_install events for a fleet are many but bounded by packages × devices, once).
7. **Inline `Signed-By` keys** instead of keyring files (ADR 0042 option A3). Default: keyring files.
8. **Slug immutability.** Default: immutable (the file names on devices follow it). Alternative: a rename that the
   agent handles as remove + add.

## 13. Freedoms (what the implementer decides)

- Names of unexported helpers, test fixture names, the exact wording of the German texts, the layout of the
  package-row editor and the detail page, the order of columns beyond the sort allow list.
- Whether `fakesys.System` gets a scripted response table for `AptGet` (preferred) or the software test uses a
  dedicated fake that embeds `fakesys.System`.
- `StateChanged` scope for catalog writes (open question 3) when the compiler's existing group expansion applies
  unchanged.
- Where the shared `sources`/`catalog` loaders live inside `server/internal/compiler` (one file `software.go` or
  two).

## Outline M13b — Self-service app, intent `available`, Flatpak, user targets (depends on M13a)

- **Depends on:** the `software` section and `reconcile.Software` (PDK-410, PDK-412) for the install/remove code
  path and the record; `device_software_status` and `health.software` (PDK-411) for the per-user state; the
  catalog and assignment tables (PDK-409) for `available` and the audience; `device_owner` (M8d) for user
  resolution; ADR 0042 decisions 5 and 6.
- **Scope:** the desktop app `paddock-self-service` (GTK or Qt — an architect decision with a license check, open),
  shipped as a Paddock package through the catalog (`required` for every device group that gets self-service);
  `/run/paddock/selfservice.sock` with `SO_PEERCRED`; the intent `available` with `audience` in the bundle (device
  wide, or UPNs from `device_owner` ∩ targeted users/user groups); `software_assignment.user_group_id` and `user_id`
  targets; Flatpak remotes (`software_source.kind = flatpak`, remote name, URL, GPG key, fingerprint; `flatpak
  remote-add --if-not-exists --gpg-import`) and apps (`flatpak install --system|--user`); the Flatpak remote list as
  a protected area (`flatpak remotes --columns=name,url` compared against the spec; a rogue `paddock-*` remote is
  removed); the event `software.self_service{user, app, action, outcome}` and the audit code
  `device.software_self_service`; desktop notifications (`notify-send` in the user's session via `systemd-run
  --machine=<user>@`) for installs, updates and restart needs; RR-79 written; the uninstall step removes
  Paddock-managed Flatpak remotes (apps stay).
- **Gates:** SS1 list for a user shows only their audience; SS2 install as user → event with the UPN; SS3 a user
  cannot remove a `required` app (403 `required_by_policy`); SS4 a Flatpak remote key change needs step-up;
  SS5 a user who does not own the device sees device-wide apps only.

## Outline M13c — Waves, maintenance windows, approvals, stored packages, compliance report, shared catalog (depends on M13a, partly M13b)

- **Depends on:** ADR 0033's rollout engine (M11) for waves — `software_assignments` and `software_sources` become
  rollout-able sections with change sets and revert; `device_software_status` (PDK-411) for failure counting and
  the compliance report; the catalog (PDK-409) for the approval state of `available` entries (M13b); the release
  store of ADR 0022 for packages stored in Paddock (a Paddock-hosted APT repository signed by an OpenBao key, served
  at `bundles.<domain>/apt/<org>/…` — a new trust decision, its own ADR); the organization-shared catalog needs the
  platform scope (`paddock_platform`) and a copy-into-organization flow.
- **Scope:** waves with automatic stop at the failure threshold (`software.apply_failed` counts), maintenance
  windows per device group (the agent defers installs and removals outside the window; removals keep the 15-minute
  rule), an approval workflow for `available` apps (request → approve by `org_admin` → audience), packages stored in
  Paddock, the patch compliance and SLA report (`installed_software` × `vulnerability_finding` × catalog targets,
  per device group, exportable), a platform-wide shared catalog (low priority, maintainer decision 7), the
  declarative sections `software_sources` (without step-up it is refused — the GitOps two-step of ADR 0034),
  `software_catalog` and `software_assignments` in `PUT /api/v1/config` and `paddockctl`.

## Amendment 2026-10-31 (refresh)

Architect refresh against `origin/main` at `986df91f` (branch `cluster/config-software`; cluster H of the alpha.7
plan: M11 first, then M13a) and against plan M9 (branch `cluster/getting-started-notifications`, migrations
`00085`–`00088`, audit `00010`), which lands on `main` before cluster H and is treated as present. Decided text above
is not rewritten; **where this amendment and §2–§13 differ, this amendment wins.** Bold numbers refer to §3.

### R1. Migration numbers (binding)

`main` has paddock migrations up to `00084`, audit up to `00009`; M9 reserves paddock `00085`–`00088` and audit
`00010`; `00089` and audit `00011` stay free as a hotfix buffer. Cluster H uses paddock from `00090` (M11:
`00090`–`00094`, plan M11 amendment 2026-10-31) and audit from `00012`. M13a needs no audit migration.

| Ticket | Migration | Replaces |
| --- | --- | --- |
| PDK-408 | `server/migrations/paddock/00095_software_sources.sql` | `00068` (**1**, §6.5) |
| PDK-409 | `server/migrations/paddock/00096_software_catalog.sql` | `00069` (**7**, **9**, §6.5) |
| PDK-411 | `server/migrations/paddock/00097_device_software_status.sql` | `00070` (**17**, §6.5) |

goose runs without `AllowMissing`: a migration with a number lower than one already applied is never applied, so the
numbers are the merge order into `cluster/config-software` (after M11's PDK-160 = `00094`): PDK-408 → 409 → 411. A
ticket that merges out of order takes the lowest free number greater than every migration on the branch at that
moment, renames the file before merging and records it in its result document and in a dated line under this table;
the displaced tickets shift. The stop condition "main already has `00068`, `00069` or `00070`" in §11 is replaced by
this rule. §5 "MUST NOT be touched: `00001`–`00067`" reads "`00001`–`00094` and M9's `00085`–`00088`".

### R2. Interfaces and files that changed since 2026-10-24 (binding corrections)

1. **Step-up markers and the skill table.** The three source specs have `RequiresStepUp: true` (**4**). Therefore
   `createSoftwareSource`, `updateSoftwareSource` and `deleteSoftwareSource` MUST carry `x-paddock-step-up: true` in
   `api/openapi/admin.yaml` (`spec_test.go::checkStepUpAnnotations` keeps the flag equal to the route table in both
   directions) and MUST be added as one row to the table under `## What the assistant cannot do` in
   `skills/operate-paddock/SKILL.md`: `| Add, change or remove an APT package source | \`createSoftwareSource\`,
   \`updateSoftwareSource\`, \`deleteSoftwareSource\` | *Package sources* |` (`test/skill_test.sh` fails when a
   catalog step-up operation is missing there or a listed one is not a step-up operation). Both belong to PDK-408.
   `make gen` regenerates `pkg/mcpcatalog/catalog.gen.go` and `skills/operate-paddock/references/tools.md`; "`make
   gen` no diff" covers them.
2. **MCP exposure (ADR 0044).** Catalog and assignment operations are exposed MCP tools by default (reads as `read`,
   writes as `write`, governed by the MCP write policy); every write operation MUST have an entry in `var
   privileged` of `server/internal/transport/http/admin/server.go` (spec_test: every exposed write tool is in the
   table). `PUT /api/v1/software-catalog/{id}/icon` has a non-JSON body and is never exposed, but is privileged and
   audited like every write. The implementer checks that `deleteSoftwareCatalogEntry` and
   `deleteSoftwareAssignment` are generated with `Destructive: true`; if the generator's rule does not mark them,
   stop and report (§11).
3. **No 413.** `problem.PayloadTooLarge` does not exist. Request bodies above `maxBodyBytes` (256 KiB, `limitBody`
   in `server.go`) are refused `400 invalid_request` before the handler. The icon rule of **11** becomes: the handler
   reads the body through `http.MaxBytesReader(w, r.Body, 65536+1)` and answers `400 invalid_request` with detail
   `icon exceeds 65536 bytes` for a larger body; §6.1 "413 payload_too_large", §9 "70 KiB PNG → 413" and PDK-409's
   criterion read `400 invalid_request`. No new problem code for it.
4. **Bundle and applier after M9.** M9 adds the section `watch` (`bundle.TypeWatch`, `WatchSpec`, `WatchResource`;
   `apply.Applier.WithWatch`; the watch resource is appended after the inventory resource in `sorted`, outside
   `apply.order`). **26** stands: `order = [hostname, time, file, systemd_unit, updates, software, login, sudo]`,
   inventory and watch follow as today. The architecture sentence of §7 (§11.3) is unchanged.
5. **Report-only devices (plan M11, PDK-161).** On a device in `report_only` mode the applier runs `Plan` only and
   reports the software resource as `pending` with the plan lines of **22**. `Software.Plan` MUST NOT call `AptGet`,
   `AptMark`, `Dpkg`, `WriteFileAtomic` or `Remove` (already **22**; PDK-412 proves it with a `fakesys` test that
   records no such call during `Plan`). Per-resource outcomes (plan M11 **7**) list the resource with ID and type
   `software`; the server derives the type `software` from the whole ID (plan M11 **14**); nothing to add.
6. **Compiler with the rollout overlay (plan M11 **30**).** `compiler.render` applies `rolloutOverlay.apply(defs,
   updates)` first and then calls `UpdatesSection(overlaidSettings, overlaidHolds, softwareHolds, groups)` with the
   un-overlaid software holds: software is not rollout-able before M13c. `compileTarget` (`compiler.go:154`: `id,
   state, seq, suspended, v2, agent, forced, request, name`, plus M11's `reportOnly`) gains `osID, versionID, arch
   string` from `ListCompileTargets` (`queries/bundle.sql:11`, `device d LEFT JOIN device_status s`: add
   `d.os_release`, `coalesce(s.arch, '')`). `paddock_compiler` already reads `device_status` (policy
   `tenant_compiler`, `00007`). M9 adds `compiler/watch.go`; `render` keeps its call.
7. **Context corrections (§2).** `agent.go` writes `LastCheckin()` at line 515 (not 505). `reconcile.System`
   (`agent/internal/reconcile/reconcile.go`) has `ReadFile`, `WriteFileAtomic`, `Remove`, `Rename`, `ReadDir`,
   `AptGet`, `AptMark`, `Dpkg`, `PackageInstalled`, `PackageVersion`, `Systemctl`, `Getent` as referenced; `fakesys`
   is `agent/internal/reconcile/fakesys/fakesys.go` (M9 touched it; rebase). `uninstall/steps.go` has
   `updateConfiguration`, `updateFiles`, `himmelblauPaths`, `packages` as referenced; M9 touched
   `agent/internal/uninstall/uninstall.go` (rebase for **29**). `himmelblauKey` is at `login.go:39`, `managedHeader`
   at `notice.go:34`. `app.RolesRead/RolesWrite/RolesAdmin` are in `server/internal/app/app.go`. The privileged
   route map is `server.go` (as written). `test/acceptance/list_contract_test.go` is the acceptance list gate and
   `server/internal/transport/http/admin/listspec_test.go` the unit one; both must pass.
8. **Ingest after M9.** `app.OnceEntry` has a third field `After`; `eventEntry` returns `After:
   tamperFindingAfter(...)` so tamper events become findings — `tamper.protected_file_changed` from the software
   reconciler (**23**) therefore creates findings without any M13a change. The event→code map in `devicereports.go`
   gains the four software types (**24**); `eventParams` and `audit.deviceEventParams` MUST gain the keys `package`,
   `intent`, `catalog_entry_id`, `source` (`reason`, `stage`, `error`, `version` exist). `eventParams` also gained
   `state` in M9 (rebase).
9. **Attention findings (M9) and software failures.** §12 open question 5 keeps its default (no attention kind for
   failed software in M13a). M9's findings round makes a later `software_apply_failed` attention kind cheap; M13c.
10. **Residual risks.** `docs/compliance/residual-risks.md` ends at RR-97 (M10 took RR-94–96); RR-77 to RR-83 are
    unassigned on `main` and stay reserved for M13a (§2, §6.7). The "not assigned" sentence of the file is unchanged.
11. **Retention and privacy (M10, ADR 0032).** The matrix of ADR 0032 §1 has no rows for `software_source`,
    `software_catalog_entry`, `software_assignment` (configuration like `package_hold`: kept while the organization
    exists, no purge) and `device_software_status` (current state only, replaced by the device's next report, like
    `device_bundle_report`). Adding rows needs a dated amendment of ADR 0032 by the architect (R5.2); PDK-414 copies
    the rows into `docs/compliance/retention.md` once the amendment exists and adds the row "software status
    (catalog entry, package name, state, reason, error text that may name paths)" to the agent-data table of
    `docs/compliance/privacy.md`. No erase path exists for organization data; nothing to add.
12. **CHANGELOG.** `CHANGELOG.md [Unreleased]` is not edited any more (PDK-518): every ticket adds
    `changelog.d/<ticket-id>.<section>.md` (`make changelog-check` is part of `make lint`). Every "`CHANGELOG.md`" in
    §3, §5 and §8 reads so.
13. **Portal files.** The device tabs live in `components/DeviceTabs.vue` with `lib/deviceDetailPage.ts`
    (`views/DeviceDetail.vue` hosts them; `views/DeviceSoftware.vue` is the inventory tab and stays). M9 edits
    `lib/navigation.ts`, `router.ts`, `views/DeviceOverview.vue`; PDK-413 rebases.
14. **Acceptance shards.** New acceptance tests SHOULD add a measured line to `test/acceptance/shard-weights.txt`.

### R3. Cross-cutting rules now in force (no plan change)

- **ADR 0045 (role switch):** one role per request, authorisation unchanged; acceptance `login(t, user)` lands in
  the organization role; `adminUser`/`withoutStepUp` (`stepup_helpers_test.go`) exist as referenced. Nothing to do.
- **PostgreSQL 18 (PDK-343):** `UNIQUE NULLS NOT DISTINCT` (PG 15+), the `CHECK` constraints and the composite
  foreign keys of §6.5 are valid; nothing to do.
- **ADR 0042 status** is still *Proposed*. The maintainer accepts it with PDK-408 (R5.1); PDK-414's "ask in the
  result document" step is thereby moved to the start of the milestone.
- **M11 reuse (alpha.7 plan, phase 7).** Within what this plan allows, M13a reuses: the per-resource outcomes and
  status store of M11 (PDK-150/151) for the `software` resource without change; the overlay-aware `render` order
  (R2.6); `ListCompileTargets` extended once by PDK-160 and once by PDK-410. Waves, change sets and revert for software
  stay M13c (§4).

### R4. Ticket order, dependencies, lanes, risk

Risk per ticket as stated: high — 408, 410, 412, 414; medium — 409, 411, 413.

| Step | Ticket | Lane | Depends on | Migration |
| --- | --- | --- | --- | --- |
| 1 | PDK-408 | server (+ `pkg/openpgpkey`) | M11 complete on the branch (PDK-160 = `00094`) | 00095 |
| 2 | PDK-409 | server | 408 | 00096 |
| 3 | PDK-410 | pkg/bundle + compiler | 409 | — |
| 4 | PDK-411 | server | 410 (bundle intents), 409 | 00097 |
| 4′ | PDK-412 | agent | 410; `pkg/protocol` types of 411 (whoever merges first adds them) | — |
| 5 | PDK-413 | portal | 408, 409, 411 (sources and catalog views may start after 409) | — |
| 6 | PDK-414 | gates + docs | 412, 413 | — |

PDK-411 and PDK-412 run in parallel after PDK-410 (server lane and agent lane); PDK-413 starts its sources and
catalog views after PDK-409 and finishes after PDK-411. The VM gate `TestSoftwareGates` runs once per cluster
together with M11's `TestPreflight|TestAdoptionGates|TestConfigRolloutGates` (alpha.7 plan, cluster H row).

### R5. Open questions for the maintainer (default chosen; blocks only what is named)

1. **Accept ADR 0042.** Options: (a) accept as written (status line → `Accepted (<date>)`, a one-line edit the
   orchestrator makes at PDK-408 start); (b) keep *Proposed* and accept at PDK-414 as §8 says. **Recommendation:
   (a)** — the first merged ticket already builds on it. Blocks PDK-408 formally.
2. **ADR 0032 amendment for the four new tables** (R2.11): (a) architect adds a dated amendment with the two rows
   (configuration tables: no purge; `device_software_status`: current state only) before PDK-414; (b) leave the
   matrix without them. **Recommendation: (a)**; blocks the retention document part of PDK-414 only.
3. **Own OpenPGP reader** (§12 open question 1): reaffirmed — stdlib-only `pkg/openpgpkey` with fuzzing; the two
   library alternatives would add a dependency. Default kept; PDK-408 proceeds.
4. **Icon size refusal as 400** (R2.3) instead of a new 413 code: default 400; PDK-409 proceeds.
5. Unchanged from §12 with their defaults: no step-up for assignments; `StateChanged(ScopeOrg)`; `apt-get remove`
   without purge; no attention kind for failed software; per-package audit events; keyring files; immutable slugs.
