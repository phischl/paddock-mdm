# Implementierungsplan: M13c — Software waves, maintenance windows, approvals, stored packages, patch compliance report, shared catalog

Status: Ready for implementation · 2026-11-05 · Author: architect
Basis: ADR 0050 (per-organization APT repository; **Proposed** — the signing library and the access model
pending the maintainer), ADR 0033 with the amendment of 2026-11-05 (`software_assignments` rollout-able), ADR 0042
with the amendment of 2026-11-05, ADR 0049 (the channel the approval requests use), ADR 0034 (step-up; the GitOps
two-step for sources), ADR 0018, ADR 0028, ADR 0032; plans M11 (rollout engine, change sets, overlay, revert),
M13a, M13b, M5a/M5c (`installed_software`, `vulnerability_finding`, severity), M9 (notifications, daily summaries);
roadmap M13 (F-08, F-09, AUD-14, AUD-15), M13a outline "M13c".

Binding language: **MUST** / **MUST NOT** / **SHOULD** / **MAY**.

Written against `cluster/alpha9-features` at `a54c1a82`, after M13b. Tickets: PDK-808 to PDK-818 (§8).
Migrations `00110`–`00114` (renumber at landing).

## 1. Goal

A change to software assignments rolls out in waves and stops itself on failures, like managed files do; devices
install and remove software only inside their group's maintenance window unless an administrator marks a change
urgent; users ask for an application and an administrator approves it in the portal; organizations without a
repository upload their own packages to Paddock and assign them like any other; an administrator and an auditor
read how long devices stay unpatched against the organization's SLA; a platform administrator curates a shared
catalog that organizations copy from; and everything about software is part of the declarative configuration.

## 2. Context (verified in the code on 2026-11-05)

- **Rollout engine (M11)**: `declarative.RolloutSections()` (four sections), `recordChangeSet` with `before`,
  `requireNotStaged`, `config_rollout` with waves and buckets, `compiler/rollout.go` overlay (`rolloutOverlay.apply`
  restores before items per section), `paddock_config_rollout_stats(rollout, pct, canary, since, staged_ids)`
  counting `device_resource_status` failures, `app.ConfigRollouts` (halt/resume/advance/complete), the worker
  round, the portal pages, the urgent opt-out (`urgent=true&reason=`, step-up).
- **Declarative document**: `declarative.Sections()` (eight sections), `PUT /api/v1/config`, `paddockctl apply`,
  `declarative.Diff`, change sets and revert for every section; `software_*` are not sections today.
- **Software**: tables and use cases of M13a/M13b; `device_software_status.state failed`; the compiler's
  `orgSoftware.section(device)`; `reconcile.Software` with `ServerReachable` and the drift pass every 300 s;
  `software.apply_failed` events.
- **Inventory**: `installed_software (device_id, name, version, source)`, `vulnerability_finding (cve, package,
  version, severity, fixed_version, first_seen_at, resolved_at?)`, the daily `vulnerability.critical_summary`
  (M9), `docs/operations/vulnerability-data.md`.
- **Release store**: `paddock-bundles` bucket, `bundles.<domain>` site with public `/packages/*`;
  `app.AgentReleases` upload path (multipart artifact uploads under `/api/platform/v1/agent-releases/…`, the
  256 MiB Caddy matcher); `objectstore.Presigner.PresignGet`.
- **Platform scope**: `paddock_platform` pool, platform tables without RLS (pattern `platform_role_member`),
  `/api/platform/v1/*` routes.
- **Notifications**: `outbound.SecurityCodes()`, destinations with `custom` code lists; the worker's daily
  summary pattern (`vulnerability.critical_summary`).

## 3. Binding decisions

### 3.1 Declarative sections for software (PDK-808)

1. `declarative.Sections()` gains `software_sources`, `software_catalog`, `software_assignments` (in this order,
   after `settings.updates`). Item shapes mirror the API inputs (`SoftwareSourceInput` with `signing_key` armored,
   `SoftwareCatalogEntryInput` with `packages`, `SoftwareAssignmentInput` with `entry` by name and target by
   name/UPN/group slug); keys: source `slug`, entry `name`, assignment `(entry name, target)`. `PUT
   /api/v1/config` and `paddockctl apply` carry them; `GET /api/v1/config` exports them including `signing_key`
   (a public key) and `fingerprint` (derived; an input whose fingerprint differs from the key is refused with 422
   `fingerprint_mismatch`, as the API does).
2. **Step-up rule** (ADR 0034 decision 3): a plan whose `software_sources` section has any change is executed only
   with a fresh step-up; an API token's apply is refused with 403 `step_up_required` *for the whole apply* (the
   two-step: CI applies everything else, an administrator applies sources from the portal). The dry run shows the
   refusal reason in the plan (`requires_step_up: [software_sources]`).
3. Every per-resource write of the three sections records a change set (`recordChangeSet`; `before` holds the
   item); `software_assignments` is rollout-able (ADR 0033 amendment): `requireNotStaged`, staging rule, overlay
   (the compiler's `rolloutOverlay` gains `assignments` with before items replacing live rows per key), failure
   stats (`paddock_config_rollout_stats` gains a `UNION` over `device_software_status` rows `failed` whose
   `catalog_entry_id` is in `staged_entry_ids` — a new `uuid[]` argument — and `reported_at >= since`),
   `StagedResourceIDs` maps an assignment change to `software:<entry id>`. Entries and sources are never staged
   (immediate).

### 3.2 Maintenance windows (PDK-809)

4. Migration `00110_maintenance_windows.sql`: `device_group_maintenance_window (organization_id, device_group_id
   PK/FK composite, days int[] CHECK (1..7, ISO weekday), start_minute int CHECK (0..1439), duration_minutes int
   CHECK (30..1440), timezone text CHECK (IANA name ≤ 64), updated_by, updated_at)`; RLS `paddock_api`
   (SELECT/INSERT/UPDATE/DELETE), `paddock_compiler` (SELECT). API: `GET/PUT/DELETE
   /api/v1/device-groups/{id}/maintenance-window` (`RolesWrite`, audit `device_group.maintenance_window_changed`
   / `_removed`, params all fields). A device in several groups has several windows: the union.
5. Bundle: `SoftwareSpec` gains `Windows []SoftwareWindow json:"windows,omitempty"` with `SoftwareWindow{Days
   []int; StartMinute int; DurationMinutes int; Timezone string}` (the union of the device's groups' windows;
   absent = no window = always). `ValidateSoftware` checks ranges and a loadable timezone name (`time.LoadLocation`
   on the server; the agent falls back to UTC when the zone is unknown on the device and reports
   `window_timezone_unknown` once).
6. Agent: `reconcile.Software` MUST, when `Windows` is non-empty and the local time is outside every window,
   defer every install, reinstall, update-to-pinned, removal and Flatpak operation of the *policy* (self-service
   operations are the user's own and are never deferred) and report them as `pending/outside_window`; file writes
   (sources, keyrings, pins) are not deferred. The next drift pass inside the window executes them. An assignment
   with `urgent: true` (decision 7) ignores the window. The 15-minute removal rule still applies inside the window.
7. `software_assignment` gains `urgent boolean NOT NULL DEFAULT false` (migration `00110`): setting it requires
   `reason` (2–500) and a fresh step-up (audit param `urgent`; API tokens refused); rendered as
   `SoftwarePackage.Urgent bool json:"urgent,omitempty"`.

### 3.3 Approvals for `available` entries (PDK-810, PDK-811)

8. Migration `00111_software_requests.sql`:

   ```sql
   ALTER TABLE software_catalog_entry ADD COLUMN approval text NOT NULL DEFAULT 'none' CHECK (approval IN ('none','required'));
   CREATE TABLE software_request (
     id uuid PRIMARY KEY, organization_id uuid NOT NULL,
     catalog_entry_id uuid NOT NULL REFERENCES software_catalog_entry(id) ON DELETE CASCADE,
     device_id uuid NOT NULL REFERENCES device(id), user_id uuid REFERENCES app_user(id) ON DELETE SET NULL,
     username text NOT NULL, justification text NOT NULL DEFAULT '' CHECK (char_length(justification) <= 500),
     state text NOT NULL CHECK (state IN ('requested','approved','denied','expired','withdrawn')),
     requested_at timestamptz NOT NULL, decided_by text, decided_at timestamptz, decision_reason text CHECK (char_length(decision_reason) <= 500),
     expires_at timestamptz NOT NULL,
     FOREIGN KEY (organization_id, device_id) REFERENCES device (organization_id, id)
   );
   CREATE UNIQUE INDEX software_request_open_idx ON software_request (device_id, catalog_entry_id, username) WHERE state = 'requested';
   ```

   RLS `paddock_api` (SELECT/UPDATE), `paddock_worker` (SELECT/INSERT/UPDATE), `paddock_compiler` (SELECT).
9. **Flow.** An `available` entry with `approval = required` is rendered with `audience` as today plus
   `SoftwarePackage.Approval = "required"`; the app shows *Request* instead of *Install*; `POST
   /v1/apps/{entry_id}/request` on the self-service socket (body `{justification}`) → the agent emits the event
   `software.request{entry_id, user, justification}` (new type; ADR 0024: emitted only while the bundle carries an
   `approval: required` package — only a server that knows approvals renders it) → the worker's event path
   inserts `software_request (state requested, expires_at = +30 d)` idempotently per `(device, entry, user)` and
   records `device.software_requested`; an administrator decides: `POST /api/v1/software-requests/{id}/approve`
   or `/deny` (body `{reason}`; `org_admin`; audit `software_request.approved` / `_denied`; a decision needs no
   step-up — the entry's source was trusted with one); the compiler renders approvals as
   `SoftwarePackage.Approved []string` (the approved UPNs of the audience) next to `Approval: required`; the agent
   lets an approved user install and shows *Request* to the others; when every audience member is approved the
   compiler omits `approval` and `approved`; a denial
   is shown in the app with the reason (`GET /v1/apps/{id}` → `request: {state, reason}`); `withdrawn` by the user
   (`DELETE /v1/apps/{id}/request`), `expired` by the worker's retention round after `expires_at`.
10. Notifications: codes `software_request.opened` (recorded by the worker when the request row is inserted; not
    in the security preset) so a destination with `custom` or `all` tells administrators; the portal's attention
    list gains the kind `software_requests_open` (count per organization, link to the list). API: `GET
    /api/v1/software-requests` (list contract; filters `state`, `catalog_entry_id`, `device_id`; search
    `[username]`), `GET …/{id}`; portal page *Software requests* with approve/deny dialogs (reason required for
    deny); the catalog entry form gains the `approval` switch.

### 3.4 Packages stored in Paddock (PDK-812, PDK-813)

11. Migration `00112_software_repository.sql`:

    ```sql
    CREATE TABLE software_repository (
      organization_id uuid PRIMARY KEY REFERENCES organization(id),
      signing_public_key text NOT NULL, signing_fingerprint text NOT NULL CHECK (signing_fingerprint ~ '^[0-9A-F]{40}$'),
      signing_private_ciphertext text NOT NULL,       -- transit software-repo-wrap (worker decrypts)
      previous_public_key text, previous_fingerprint text, previous_retired_at timestamptz,
      credential_ciphertext text NOT NULL,            -- transit software-repo-wrap: the basic-auth secret
      credential_sha256 bytea NOT NULL,               -- the api checks requests against it
      generation bigint NOT NULL DEFAULT 0, rebuild_requested_at timestamptz, last_built_at timestamptz, last_error text,
      created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now()
    );
    CREATE TABLE software_package (
      id uuid PRIMARY KEY, organization_id uuid NOT NULL REFERENCES organization(id),
      package text NOT NULL, version text NOT NULL, architecture text NOT NULL CHECK (architecture IN ('amd64','arm64','all')),
      size bigint NOT NULL CHECK (size BETWEEN 1 AND 268435456), sha256 text NOT NULL, object_key text NOT NULL,
      control jsonb NOT NULL,                         -- the control fields (Package, Version, Architecture, Depends, Description, …)
      uploaded_by text NOT NULL, uploaded_at timestamptz NOT NULL DEFAULT now(),
      UNIQUE (organization_id, package, version, architecture)
    );
    ```

    RLS `paddock_api` (SELECT/INSERT/DELETE on `software_package`; SELECT/INSERT/UPDATE on `software_repository`),
    `paddock_worker` (SELECT/UPDATE on the repository, SELECT on packages), `paddock_compiler` (SELECT). The
    system source `paddock` is a row of `software_source` with `kind = 'paddock'` (CHECK extended), `slug
    'paddock'`, `uris = ['https://bundles.<domain>/apt/<org_slug>/']`, `suites ['paddock']`, `components ['main']`,
    `signing_key`/`fingerprint` from the repository row, maintained by the worker (never editable; `DELETE` → 409).
12. **Upload**: `POST /api/v1/software-packages` (multipart `file`, ≤ 256 MiB through the Caddy platform-upload
    matcher extended to this path; `org_admin`, `RequiresStepUp`; audit `software_package.uploaded` with
    `package`, `version`, `architecture`, `sha256`, `size`): the api parses the `ar` archive (`debian-binary`
    `2.0\n`, `control.tar.{gz,xz,zst}` → `control` file; stdlib `archive/tar` + `compress/gzip`; xz and zst need a
    decoder — **stop condition**: refuse `control.tar.xz`/`.zst` with 415 `unsupported_compression` in this
    release unless the maintainer approves a decompression dependency; `dpkg-deb` writes `control.tar.zst` on
    Ubuntu ≥ 21.10, so the runbook tells uploaders to build with `-Zgzip` — **pending maintainer**: a zstd/xz
    decoder dependency (`github.com/klauspost/compress`, BSD-3, zstd only) would remove that constraint),
    validates `Package` (`bundle.ValidPackage`), `Version`, `Architecture`, stores the object at
    `apt/<org_id>/pool/main/<p>/<package>/<package>_<version>_<arch>.deb`, inserts the row, sets
    `rebuild_requested_at`. `DELETE /api/v1/software-packages/{id}` (step-up; 409 `in_use` when any catalog entry
    with `source_id = paddock` names the package). `GET /api/v1/software-packages` (list contract). `GET
    /api/v1/software-repository` → `{source, fingerprint, previous_fingerprint, generation, last_built_at,
    last_error, package_count}`; `POST …/rotate-key`, `POST …/rotate-credential` (step-up, audited
    `software_repository.key_rotated` / `_credential_rotated`).
13. **Worker rebuild** (`worker/softwarerepo.go`, every 60 s, per organization with `rebuild_requested_at >
    last_built_at`): lists the organization's packages, writes `dists/paddock/main/binary-<arch>/Packages` (one
    stanza per package from `control` + `Filename`, `Size`, `SHA256`; `all` packages appear in every
    architecture's list) and `.gz`, `Release` (`Origin: Paddock`, `Suite: paddock`, `Codename: paddock`,
    `Architectures`, `Components: main`, `Date`, the `SHA256` list), `InRelease` (clearsigned) and `Release.gpg`
    (detached) with the organization's key (`github.com/ProtonMail/go-crypto/openpgp` — **pending maintainer**;
    until approved the worker refuses to build and the feature is `software_repository.disabled`), uploads them,
    increments `generation`, `last_built_at`, records `StateChanged(ScopeOrg)` (the bundles carry the source's
    fingerprint; a key rotation changes it). Signing happens in the worker process only; the private key is
    decrypted per rebuild and cleared.
14. **Serving**: Caddy `bundles.<domain>` gains `handle /apt/*` → `reverse_proxy paddock-api:8080` (the api gains
    the bundles-host route group, mounted only when `Host` is the bundles host); the api checks `Authorization:
    Basic` (user `paddock`, constant-time compare of `sha256(secret)` with `credential_sha256` of the organization
    whose slug is in the path; 401 with `WWW-Authenticate: Basic realm="paddock"` otherwise; the rate limiter class
    `bundles-apt`), maps `<path>` to the object key and answers 302 to `PresignGet(key, 10 min)` or 404. Nothing is
    logged beyond the organization slug and the path.
15. **Device**: the bundle's `paddock` source renders like an APT source plus `SoftwareSpec.Repository
    *SoftwareRepositoryAuth json:"repository,omitempty"` = `{host, username: "paddock", password}`; the agent
    writes `/etc/apt/auth.conf.d/paddock-repo.conf` (`machine bundles.<domain>/apt/<slug>/ login paddock password
    <secret>`, 0600 root:root; a protected area with the drift rule; removed by the uninstall in both modes). The
    secret is part of the signed bundle (fetched over the authenticated device channel), never in an event, a log
    or the health report.
16. Catalog entries for stored packages: `source_id` = the `paddock` source; `packages[]` elements name the
    uploaded package names; the portal's entry form offers *Uploaded packages* as a picker.

### 3.5 Patch compliance report (PDK-814)

17. Settings: `settings.patch_sla` (declarative section `settings.patch_sla`; table `organization_patch_sla
    (organization_id PK, critical_days 7, high_days 30, medium_days 90, low_days 0 = none, updated_by, updated_at)`
    in migration `00113`; API `GET/PUT /api/v1/settings/patch-sla`, audit `settings.patch_sla_changed`).
18. Report: `GET /api/v1/patch-compliance?from&to&device_group_id` → `{generated_at, period, sla, summary:
    {devices, compliant, breached}, by_severity: [{severity, findings_open, findings_breached, median_days_open,
    p90_days_open}], by_group: [{device_group, devices, breached}], devices: [{device_id, hostname, breached:
    [{cve, package, severity, days_open, fixed_version, sla_days}]}] (capped 1 000 with totals), catalog:
    [{entry, required_version, devices_behind}]}` computed from `vulnerability_finding` (open findings with a
    `fixed_version`, `days_open = now − first_seen_at`, breached when `> sla_days` for the severity),
    `installed_software` and the `required pinned` assignments (devices whose installed version is older than the
    pin); `RolesAudit` + `org_operator` (read, coalesced read audit `patch_compliance.viewed` under `read_audit`);
    export `?format=csv|json` audited `patch_compliance.exported`. Portal page *Patch compliance* (period, group
    filter, cards, tables, export). Daily `vulnerability.sla_breached` summary event by the worker (count per
    severity; reachable through `custom` and `all` destinations, not part of the security preset) and the
    attention kind `patch_sla_breached` with the count — the notification path of M9's critical summary.

### 3.6 Shared catalog (PDK-815; last, droppable)

19. Platform tables `platform_catalog_entry` (the entry shape without `source_id`; packages by name, a
    `source_hint` text naming the vendor repository URL and fingerprint the organization must add itself) and
    `platform_catalog_package` (optional stored packages under `apt/platform/`, same repository shape, platform
    key); `GET/POST/PUT/DELETE /api/platform/v1/catalog` (platform admin, step-up for stored packages);
    organizations read `GET /api/v1/shared-catalog` and `POST /api/v1/shared-catalog/{id}/copy` (`RolesWrite`;
    copies the entry into the organization's catalog with `source_id` NULL or the organization's `paddock` source
    when the platform stores the package — the copy also copies the package object into the organization's
    repository and triggers a rebuild; audit `software_catalog_entry.copied_from_platform`). No automatic sync; a
    copy is a snapshot.

### 3.7 State tables (binding)

**Software rollout** (reuses `config_rollout`): the states and transitions of ADR 0033 decision 4 apply
unchanged; what is new is the failure source (`device_software_status.failed` of staged entries) and the overlay
of assignments.

**Request**: `requested → approved | denied | withdrawn | expired`; `approved` is terminal (the audience carries
it); re-request after `denied` is allowed after 24 h (the unique index covers `requested` only).

**Repository build**: `requested (rebuild_requested_at) → building → built (generation+1) | failed (last_error,
retried every 60 s)`; a failed build leaves the previous generation readable: the worker writes `Packages*` and
`Release` first and `InRelease` last (S3 has no rename), so a reader sees either the old `InRelease` with the old
hashes or the new one with the new hashes; apt verifies the hashes and retries on a mismatch.

**Deferral by window**: `pending/outside_window` → (inside window) executed → `installed | failed`; an `urgent`
assignment bypasses; a window removed → immediate at the next pass.

### 3.8 Loss and failure cases

| # | Case | Behaviour |
| --- | --- | --- |
| L1 | Rollout halted on software failures | as M11: devices outside the wave keep before assignments; `config_rollout.halted` by the worker; revert of the change set ends it |
| L2 | A device in several groups with contradicting windows | the union; documented |
| L3 | Timezone unknown on the device | UTC fallback, `window_timezone_unknown` reported once per bundle |
| L4 | Request for an entry that loses its `approval` flag | existing requests are `expired` by the next compile (the worker marks them when the entry's approval is `none`) and the user may install |
| L5 | Repository key rotation while devices are offline | the old key stays valid for 30 days (`previous_*`); a device that returns later with the old keyring gets the new one with its next bundle and `apt-get update` succeeds because `InRelease` is signed with the new key and the bundle carries the new keyring — the order on the device is keyring first, then update (M13a decision 23 a/b) |
| L6 | Credential rotation | every device's bundle changes; a device offline longer than the overlap (24 h: the api accepts the previous secret for 24 h) fails `apt-get update` with 401 → `source_unreachable` until its next check-in |
| L7 | Upload of a package already present | 409 `exists` (same name/version/arch) |
| L8 | Worker cannot decrypt the signing key (OpenBao sealed) | build `failed`, retried; devices keep the last `InRelease` |
| L9 | A stored package is deleted while assigned | refused 409 `in_use` |
| L10 | SLA report with no inventory | empty sections with `devices: 0`; never an error |
| L11 | Shared catalog entry copied twice | 409 `exists` by name; the administrator renames first |

## 4. Non-goals

- No package content scanning; no lintian; no automatic Flathub mirror; no per-device repository credentials.
- No automatic sync of the shared catalog; no cross-organization visibility of uploaded packages.
- No reboot management (F-07); no distribution release upgrades (F-10).
- No new container image; no Snap.

## 5. Affected files (summary; the tickets list the exact set)

`server/internal/domain/declarative` (sections), `app/declarative*.go`, `app/changesets.go`, `compiler/rollout.go`,
`compiler/software.go`, migrations `00110`–`00114`, `app/softwarerequests.go`, `app/softwarepackages.go`,
`worker/softwarerepo.go`, `worker/softwarerequests.go`, `transport/http/admin/handlers_software*.go`, the bundles
host route group, `deploy/compose/caddy/Caddyfile*` (`/apt/*`), `pkg/bundle/software.go`,
`agent/internal/reconcile/software.go` (windows, urgent, auth.conf), `agent/internal/selfservice` (request),
portal views (`SoftwareRequests.vue`, `SoftwarePackages.vue`, `PatchCompliance.vue`, `PlatformCatalog.vue`,
`MaintenanceWindowForm.vue`, forms), `cli` (`paddockctl apply` sections), docs (`software.md`,
`vulnerability-data.md`, `privacy.md` row for requests, architecture §12.5/§16/§17, RR-114, RR-115, RR-118).

## 6. Interfaces (summary)

```
PUT/GET /api/v1/config                           sections software_sources, software_catalog, software_assignments, settings.patch_sla
GET/PUT/DELETE /api/v1/device-groups/{id}/maintenance-window
GET /api/v1/software-requests [list], GET …/{id}, POST …/{id}/approve, POST …/{id}/deny {reason}
GET/POST /api/v1/software-packages [list, upload], DELETE …/{id}
GET /api/v1/software-repository, POST …/rotate-key, POST …/rotate-credential
GET/PUT /api/v1/settings/patch-sla
GET /api/v1/patch-compliance[/export]
GET /api/platform/v1/catalog [+CRUD], GET /api/v1/shared-catalog, POST /api/v1/shared-catalog/{id}/copy
bundles host: GET /apt/<slug>/<path>  (basic auth → 302 presigned)
self-service socket: POST/DELETE /v1/apps/{id}/request
Bundle: SoftwareSpec + windows[], repository{host,username,password}; SoftwarePackage + urgent, approval, approved[]
Events: software.request (new type); audit: device.software_requested, software_request.approved/_denied,
        software_package.uploaded/_deleted, software_repository.key_rotated/_credential_rotated/_built/_build_failed,
        device_group.maintenance_window_changed/_removed, settings.patch_sla_changed, patch_compliance.viewed/_exported,
        software_catalog_entry.copied_from_platform, software_request.opened, vulnerability.sla_breached
```

Residual risks: RR-114 (uploading a package is root-equivalent; no content scan), RR-115 (one read credential
per organization in every device's bundle), RR-118 (maintenance windows defer security-relevant removals; an
`urgent` flag with step-up exists).

## 7. Architecture amendments

§7.1 (overlay covers assignments), §11.3 (windows, auth.conf), §12.5 (approvals, windows, stored packages,
report), §16.1 (tables), §17.1/§17.2 (endpoints, the bundles host's `/apt/*`), §9.6 (patch compliance for the
auditor); `CLAUDE.md` protected areas item 5 gains `/etc/apt/auth.conf.d/paddock-repo.conf`.

## 8. Steps (tickets, in order)

1. **PDK-808 — Declarative sections for software, change sets, `software_assignments` rollout-able, overlay and
   stats.** §3.1. Verify: `TestDeclarativeConfig` extended; `TestConfigRolloutStaging` for an assignment.
2. **PDK-809 — Maintenance windows and the urgent flag (server, bundle, agent).** §3.2. Verify: agent fakesys
   tests with a fake clock; acceptance window gate.
3. **PDK-810 — Approvals: request table, event, worker, API, attention kind, notification code.** §3.3 decisions
   8–10 (server). Depends on M13b. 
4. **PDK-811 — Approvals: agent request endpoint, app *Request* flow, compiler audience with approvals.** §3.3.
   Depends on 810.
5. **PDK-812 — Stored packages: repository tables, upload, delete, system source, Caddy `/apt/*`, api basic-auth
   redirect, agent auth.conf.** §3.4 decisions 11, 12, 14–16 (**pending maintainer: access model**).
6. **PDK-813 — Repository build and signing in the worker, key and credential rotation.** §3.4 decision 13
   (**pending maintainer: `go-crypto` dependency; zstd decoder**). Depends on 812.
7. **PDK-814 — Patch SLA settings and the compliance report, export, daily summary, portal.** §3.5. Independent.
8. **PDK-815 — Shared platform catalog and copy-into-organization.** §3.6. Depends on 812/813 for stored
   packages; droppable (maintainer decision 7).
9. **PDK-816 — Portal: requests, packages, repository, windows, SLA, shared catalog pages.** Depends on the API
   tickets; MAY be split by the orchestrator.
10. **PDK-817 — Gates (acceptance and system), privacy row for requests, runbook, architecture, RR.** 
11. **PDK-818 — `paddockctl` and the declarative docs for the new sections; full regression.**

Chains: (808 → 809), (810 → 811), (812 → 813 → 815), 814 alone; 816 after the API tickets; 817, 818 last.

## 9. Tests and gates (summary)

- Unit: section diff/plan for the three sections; staging and overlay of assignments; window evaluation
  (fake clock, DST boundaries, union); `ar`/control parsing (fixtures incl. refused compressions); Packages/Release
  rendering golden files; signature verification with the generated public key (`pkg/openpgpkey` verifies
  nothing — the test uses `go-crypto`'s verifier); SLA computation table; shared-catalog copy.
- Integration: migrations `00110`–`00114`; RLS; the stats function with software failures; basic-auth check
  constant time; `software_request` unique index.
- Acceptance: `TestSoftwareDeclarative` (apply the three sections; token refused on a source change),
  `TestSoftwareRollout` (staged assignment halts on `failed` status), `TestMaintenanceWindow` (a package stays
  `pending/outside_window` until the window; `urgent` with step-up bypasses), `TestSoftwareRequests` (request →
  approve → audience; deny with reason; expiry), `TestSoftwarePackages` (upload, rebuild, `InRelease` verifies with
  the published key, `GET /apt/...` 401/302, rotation overlap), `TestPatchCompliance` (seeded findings and SLA),
  `TestSharedCatalog`.
- System: SW9 a VM installs an uploaded package through the Paddock repository (`apt-get update` succeeds with the
  bundle's keyring and auth.conf; `dpkg -l` shows it); SW10 a window defers an install and the next in-window pass
  executes; SW11 the request flow from the real app.
- Never weakened: M11 and M13a/M13b gates.

## 10. Acceptance criteria

- **C1 (ADR 0033 amendment; admin):** an assignment change rolls out in waves and halts on software failures.
- **C2 (decision 6; admin, user):** outside the window nothing of the policy is installed or removed; `urgent`
  with step-up overrides; the device status says why.
- **C3 (decisions 8–10; user, admin):** a user requests, an administrator approves or denies with a reason, the
  user can install after approval; the auditor sees the trail.
- **C4 (ADR 0050; admin, device):** an uploaded package reaches an assigned device through a signed,
  authenticated repository; the audit event carries the hash; a key rotation does not strand offline devices.
- **C5 (decision 18; auditor):** the report shows breached findings per severity and group against the SLA, and
  exports.
- **C6 (decision 19; platform admin):** a shared entry can be copied into an organization.

## 11. Stop conditions

- `control.tar` in a compression without an approved decoder (decision 12): refuse with 415, do not vendor a
  decoder.
- The maintainer declines `go-crypto`: PDK-813 stops; PDK-812 ships uploads with the repository `disabled`.
- The stats function's `UNION` changes the semantics of existing rollouts (a test of M11 fails): report.
- Any revocation-path, supervisor or audit-writer change; any other new dependency.

## 12. Risks and open points

Open questions — **maintainer**: (1) `github.com/ProtonMail/go-crypto` for OpenPGP signing (recommended yes);
(2) a zstd decoder (`github.com/klauspost/compress`) for `control.tar.zst` uploads (recommended yes; otherwise
`-Zgzip` builds only); (3) the per-organization basic-auth credential in every device's bundle (recommended
yes); (4) `software.request` carries the user's justification text (works-council relevant; recommended yes, ≤
500 characters, listed in `privacy.md`); (5) drop the shared catalog from alpha.10 if it does not fit
(recommended: last ticket, droppable). **Architect lead**: (6) decisions on requests need no step-up (recommended);
(7) the 24 h credential overlap and the 30 d key overlap (recommended); (8) windows as a union across groups
(recommended); (9) `settings.patch_sla` as a declarative section (recommended yes).

## 13. Freedoms

Query names; the exact Packages stanza order; the portal layout of the report; the CSV column order; German
texts; whether the window evaluation lives in `reconcile` or a small `window` package in the agent.

## Amendment 2026-11-09 (architect-lead decisions Q15–Q18 and A10-12, PDK-808)

### Decided by the architect lead (`decisions-alpha10.md`, Q15–Q18)

Open points (6) to (9) of §12 are decided as recommended:

- **(6), Q15:** an approval decision (approve or deny) needs no step-up of its own: trusting the source was the
  step-up. Every decision is still recorded with exactly one audit event per attempt (PDK-810).
- **(7), Q16:** on rotation the repository's read credential keeps a 24 h overlap and its signing key a 30 d overlap
  (§3.8 L5, L6; PDK-813).
- **(8), Q17:** a device in several device groups has the union of their maintenance windows as its window (§3.8 L2;
  PDK-809).
- **(9), Q18:** `settings.patch_sla` becomes a declarative section of `PUT /api/v1/config` (PDK-814).

### PDK-808 corrections against the code, decided by the architect lead (A10-12)

PDK-808 landed decisions 1–3 of §3.1 on the code as it is on `cluster/alpha10-features`. The architect lead confirmed
its corrections (A10-12, points 1, 3 and 4) and redirected the entry cascade (point 2, next subsection). ADR 0033's
amendment 2026-11-05 still says "the stats function gains that join"; the first item replaces that.

- **No stats function (point 1).** `paddock_config_rollout_stats` was dropped by migration `00094` (plan M11 amendment
  R6.14 a): the worker and the API count with one Go rule over `ListConfigRolloutReports`. The failure join of
  decision 3 therefore lives in that query: a `device_software_status` row in state `failed` reported since the
  rollout's `evaluation_since` is listed as failed resource `software:<catalog_entry_id>` next to the bundle's failed
  resources, and the existing rule keeps only the staged IDs. `StagedResourceIDs` stays as it was;
  `configrollout.StagedEntries` names the staged entries and the use case resolves them to `software:<entry id>`.
  The M11 rule and its tests are unchanged.
- **Migration `00117_worker_reads_entry_names.sql`** (the numbers `00110`–`00114` were taken): the worker resolves
  the staged entries by name, so it may now read `software_catalog_entry.name` (column grant, nothing else). The
  migration also adds `config_rollout.staged_assignments` (next item).
- **Staged assignments are matched by row ID (point 3).** When a rollout that stages software assignments starts, it
  records per staged key the assignment's row ID, its catalog entry ID and its target ID
  (`config_rollout.staged_assignments`). The compiler's overlay matches live rows and before items by these IDs, not by
  the names in the key: a username comes from identity sync and can change while the rollout runs.
- **Entries of staged assignments are protected (point 4).** While a rollout is open, a write that deletes or renames
  a catalog entry named by a staged assignment key, a staged deletion included, is refused with 409
  `rollout_conflict` — the entry analogue of M11 R6.13 for device groups.

### No entry cascade (A10-12, point 2)

PDK-808 first deleted the assignments of a deleted catalog entry with it and did not stage them. The architect lead
redirected this: every change that reaches devices goes through the rollout and approval path, and an entry's
deletion must not be a side door. This replaces the cascade of plan M13a (`DELETE /api/v1/software-catalog/{id}`
"removes the entry together with its assignments").

- Deleting a catalog entry that still has assignments is refused with 409 `in_use`. The problem detail names the
  assignments by target (`organization`, `device group "<name>"`, `user "<username>"`, `user group "<slug>"`; the
  first ten, then "and N more"). This holds for `DELETE /api/v1/software-catalog/{id}` and for a declarative document
  that deletes or renames the entry, even when the same document deletes the assignments: the configuration as read
  decides, and the refusal is checked before anything is written.
- The admin first removes the assignments. That removal is an assignment change like any other: staged and rolled out
  in waves when rollouts are enabled (and while it rolls out, the entry's deletion is 409 `rollout_conflict`, point 4).
- Once no assignment is left, the entry can be deleted; its change set holds the catalog entry alone, stages nothing
  and changes nothing on any device. The audit event `software_catalog_entry.deleted` keeps `assignment_count`: 0 on
  success, the number of assignments on the refusal.
- An entry that a per-resource write renames by identity keeps its assignment rows; only their keys change, so they
  are not staged, neither the deletions of the old-name keys nor the creations of the new-name keys. This is no
  cascade and stays as it was.

#### Clarification 2026-11-09: revert of the open rollout (A10-13)

The 409 `in_use` guard above does not apply to the revert of the open rollout's change set: that revert is the
rollback itself and must always be possible (root agent contract 4 and 6, plan M11 decision 21.3). When the rollout's
change set created a catalog entry and its assignments, the revert deletes the assignments first and the entry after
them, in the same transaction, and ends the rollout. Only an assignment that the revert keeps still refuses the
entry's deletion. Outside that revert, the guard is unchanged.

### Implementer choices in PDK-808 (within the freedoms of §13)

- **Item shapes.** A source item is `slug, kind, name, uris, suites, components, architectures, signing_key,
  fingerprint`; an entry item `name, description, category, source` (slug or null), `packages`; an assignment item
  `entry, target, intent, update_rule, version, reason` with `target` one of `{type: organization}`,
  `{type: device_group, name}`, `{type: user, username}`, `{type: user_group, slug}`. The assignment key is
  `[device group or null, entry, target type, username or slug or null]`, the form of group-scoped keys, so the
  rules for deleted and renamed device groups (M11 R6.13) cover it unchanged. A plan shows a source's key as its
  SHA-256 and a package reference as `distribution/release/architecture=package` (or `=flatpak:<ref>@<scope>`).
- **Step-up in the plan.** `requires_step_up` is a field of the plan (omitted when empty, so existing plan hashes are
  unchanged); the step-up is checked once for the whole apply before anything is written.
- **Per-resource writes** of sources, entries and assignments record change sets; they take no urgent opt-out yet
  (an urgent assignment change goes through `PUT /api/v1/config?urgent=true`).

## Amendment 2026-11-09 (PDK-810, implementer choices within §13)

- **Migration `00120_software_requests.sql`** (the numbers `00111` and `00117`–`00119` were taken). It creates the table
  of decision 8 **without `justification`**: whether the user's text may be stored, sent and shown is pending with the
  maintainer (§12 Q4). The event `software.request` carries `{user, entry_id}` only. The server drops any other field
  a device sends, so it never reaches the audit log. A later migration can add the column, and an additive event field
  can carry the text.
- **An approval is per device.** A request names its device. The compiler renders `approved[]` for a package from the
  approved requests of that device and entry only, restricted to the package's audience. It renders after the rollout
  overlay chose the package, so an approval never reaches a device by another path (A10-12). An approval changes only
  the request row and queues a compile of its device. It is no change set and stages nothing: it affects one user on
  one device, and staging it would make every decision wait for an open software rollout.
- **Expiry runs in a round of its own** (`worker.SoftwareRequests`, every 10 minutes), not in the retention round. The
  retention round purges stores with `retention.purged` evidence (ADR 0032). An expiry is a state transition with its
  own event, `software_request.expired`, whose `cause` is `validity_ended` or `approval_removed` (§3.8 L4). That code
  is added to the registry next to the codes of §6.
- **A request opens nothing when** the entry is not the organization's or does not require approval, the user name is
  not a valid audience name, or a denial of the same device, entry and user is less than 24 hours old (§3.7). The
  device's event is still recorded as `device.software_requested`. `software_request.opened` is recorded in the same
  transaction only when a row was inserted.
- **The attention kind `software_requests_open`** is one row per active device with open requests: `detail` is their
  number, `since` the oldest. The attention view lists per device, so the organization's total is the sum of the rows.
- **The catalog entry's `approval`** is optional on `PATCH /api/v1/software-catalog/{id}`: when it is absent, the
  stored value is kept, so a client that does not know the field never clears it. In the declarative
  `software_catalog` section it is optional, and an absent value means `none`. Withdrawal by the user (`withdrawn`)
  needs a device-side signal that the plan does not define yet; the state exists, and PDK-811 defines the signal.

### Clarification 2026-11-09: approvals (architect decision A10-17)

- An approval is not a staged change set (confirmed). The entry and its available assignment went through the staged
  rollout path already; an approval only lets the requesting device install what was offered, like a self-service
  install. A forbid of the same package still wins (A10-9), so no approval is rendered for it, and the device's
  maintenance windows apply to the install as to any self-service install (agent side, PDK-809/PDK-811).
- An approval holds only while its entry and an available assignment of it exist. The entry's deletion removes its
  requests (foreign key). When the entry has no available assignment left, the request round expires its open and
  approved requests with cause `assignment_removed`. For this, the worker reads `catalog_entry_id` and `intent` of
  `software_assignment` (column grant, `00120`).
- Expiry in a round of its own is confirmed.
- **Agent gate (PDK-942, done in PDK-810).** The compiler leaves out an available package whose entry requires approval
  for an agent release before `approvalAgent`, the first release with PDK-811 (`0.1.0-alpha.10`). This is the A10-6
  mechanism, tested against the alpha.9 compat fixture. It is a constant of its own, so it moves if PDK-811 ships
  later than the self-service app. No agent release may come from a tree that has PDK-810 without PDK-811.
