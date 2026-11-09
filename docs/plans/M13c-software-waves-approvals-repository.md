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

- **Migration `00119_software_requests.sql`** (the numbers `00111`, `00117` and `00118` were taken; landed before PDK-809, which takes `00120`). It creates the table
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
  `software_assignment` (column grant, `00119`).
- Expiry in a round of its own is confirmed.
- **Agent gate (PDK-942, done in PDK-810).** The compiler leaves out an available package whose entry requires approval
  for an agent release before `approvalAgent`, the first release with PDK-811 (`0.1.0-alpha.10`). This is the A10-6
  mechanism, tested against the alpha.9 compat fixture. It is a constant of its own, so it moves if PDK-811 ships
  later than the self-service app. No agent release may come from a tree that has PDK-810 without PDK-811.

## Amendment 2026-11-09 (PDK-943, the approval gate after PDK-810)

Recorded by the cluster lead after the PDK-943 review; it corrects the "Agent gate" bullet of the PDK-810 amendment.

- **The gate is empty until PDK-811.** The compiler constant for the first agent that understands approvals is empty
  today, which means no agent understands them yet: every agent, including development builds (`0.0.0-dev`,
  devicesim) and an agent built from this tree as `0.1.0-alpha.10`, gets no approval-required package. PDK-811 sets
  the constant to its release; from then on the A10-6 rules apply (older releases are left out, development builds
  are current). Decision A10-17 ("no agent release from a tree with PDK-810 without PDK-811 or this gate") is met by
  the empty gate.
- **The gate holds across catalog entries.** When several entries offer the same package and one of them requires
  approval, the merged package is withheld from an agent below the gate whatever the merge order.
- **Meaning of `approved` in the bundle.** It lists the audience users who may install without a request: the users an
  administrator approved and the users another catalog entry offers the same package to without approval. The agent
  rule is unchanged: a listed user installs, every other audience user sees "Request". PDK-811 reads it with this
  meaning.

## Amendment 2026-11-09 (PDK-809, implementer choices within §13)

- **Migration `00120_maintenance_windows.sql`** (the plan's `00110` was taken) creates `device_group_maintenance_window`
  and `software_assignment.urgent` as decisions 4 and 7 say. The server binary embeds the zone database
  (`time/tzdata`), so the api's `time.LoadLocation` check does not depend on the runtime image.
- **Union (Q17).** Only groups with a window contribute to a device's union: a device in a group with a window and in
  another group without one has the first group's window. A device none of whose groups has a window gets no
  `windows` (no restriction). Identical windows are carried once; the union is capped at `bundle.MaxSoftwareWindows`
  (64). A window that fails the bundle rules is left out with an error log (the devices of that group then apply at any
  time).
- **Duration is elapsed time.** A window opens `start_minute` after local midnight of each of its days (a start in the
  skipped DST hour moves forward by the gap, one in the repeated hour opens at its second occurrence) and stays open
  `duration_minutes` of elapsed time, so it may reach into the next day.
- **Declarative.** A `device_groups` item carries `maintenance_window` (omitted = no window, so an item without it
  removes a stored window; the export always includes a stored one). A plan shows it as one field in the form
  `1,2,3,4,5 22:00+180m Europe/Berlin`. The document does not carry `urgent`: an apply that changes only the reason keeps an assignment's flag; one that
  changes the intent, update rule or version clears it, because the declarative path has no step-up (decision 7).
- **Urgent.** `urgent` is part of the assignment's create and update input (an update without it clears it); a write
  whose result is urgent needs the reason (2–500 characters, not only spaces) and a fresh step-up, checked after the
  other rules. A package is urgent when an urgent assignment contributed its winning intent; the compiler-added flatpak
  runtime is urgent when an urgent Flatpak application needs it. `urgent` is about the window only and does not skip a
  staged rollout's waves.
- **Agent.** Outside the windows the APT and Flatpak installs, reinstalls, moves to a pinned version and removals of
  non-urgent packages are reported `pending/outside_window`; source files, keyrings, pins, Flatpak remotes and masks are
  written. An unknown timezone is evaluated in UTC; the agent logs `window_timezone_unknown` once per bundle and the
  software resource's status message names the zone on every pass. No new event type.
- **Rollouts (contract 6).** A device whose newest report on a rollout's bundle is an enforced apply but whose staged
  catalog entry is reported `pending/outside_window` (current state of `device_software_status`) counts as pending,
  not applied, in the worker's evaluation and the API's counts. The wave-advance rule changed with A10-16 (next
  amendment); the device list's `report_outcome` still shows the bundle report's outcome.

## Amendment 2026-11-09 (architect decision A10-16, PDK-809: waves against maintenance windows)

- **Wave advance (applies to every configuration rollout, plan M11 decision 28 amended).** A wave advances, and the
  last wave completes, only when both hold: (1) `min_wave_minutes` have passed since the worker first saw a device that
  joined in this wave (`configrollout.JoinedIn`: eligible now, not eligible in the previous wave; every eligible device
  in the first wave) applied, with success or failure; (2) the applied share of those devices reaches the rollout's
  `wave_success_threshold_percent`, or none of them still waits for its maintenance window. The threshold alone never
  advances a wave. A wave that no device joined has nothing to observe and counts its duration from its start. The
  failure-rate stop is unchanged; a waiting device is pending, never failed. Consequence beyond windows: a wave whose
  new devices are all offline no longer advances on time; it gets the stall warning and waits for an administrator.
- **Settings.** `organization_rollout_settings` and `config_rollout` gain `wave_success_threshold_percent` (1–100,
  default 90) and `stall_warning_hours` (1–720, default 24); a rollout copies them when it starts. A settings write
  without them keeps the stored values. The decision named "the wave's success threshold" without an existing field;
  the implementer chose this per-rollout setting and its default (to be confirmed by the architect lead).
- **Bookkeeping.** `config_rollout.wave_first_applied_at`, `wave_applied`, `wave_progress_at` and `stall_warned_at`
  (migration 00120, folded into the maintenance-window migration). The worker writes them in its evaluation round with
  the round's time, only while the rollout is still running in the wave it read; an advance resets them, and so does a
  resume (A10-18 below).
- **Stall warning.** The rollout's own audit event `config_rollout.stalled` (system actor; params `rollout_id`,
  `change_set_id`, `wave`, `stalled_since`, `stall_warning_hours`, `wave_eligible`, `wave_applied`, `wave_waiting`),
  once per stall, after `stall_warning_hours` without growth of the wave's applied devices. The compile-warnings
  mechanism (A10-10) is per device and does not fit a rollout. The warning forces nothing; urgent changes keep their
  own bypass (`urgent`).
- **Visibility (additive, ADR 0013).** The rollout device list gains the required boolean `waiting_for_window`; the
  rollout gains `wave_success_threshold_percent`, `stall_warning_hours`, `wave_first_applied_at` and `stalled_since`;
  the rollout settings gain the two fields. The portal does not show them yet (follow-up ticket).
- **Union (Q17) confirmed.** Only groups that have a window contribute to the union. A device restricted by at least
  one group window is restricted by the union of those windows; a device with no windowed group is always open.

## Amendment 2026-11-09 (architect decision A10-18, PDK-809: resume against the wave clock)

- **Resume restarts the observation (plan M11 amendment R6.14 (d)).** A resume clears `wave_first_applied_at` and
  `wave_applied` together with `evaluation_since`, `wave_started_at` and the stall period; the next worker round dates
  the first apply anew, so the wave gets its full `min_wave_minutes` again. This replaces "a resume keeps the first
  apply" from the A10-16 amendment.
- **Only applies after the resume count toward the threshold.** Condition (2) of the A10-16 wave rule reads the share
  of the wave's new devices whose report was received since `evaluation_since`. Before any resume this is every apply.
- **Discarded failures stay outstanding.** A device of the wave whose failure (a rejection, a failed staged resource, or
  a staged software entry still failed) was reported before the last resume no longer counts toward the failure rate,
  but it is outstanding like a waiting device until it retries — of any reached wave, not only of the current one; after
  a resume also every failed device (§4 S12/S13 of the A10-19 amendment): the "none of them still waits" escape of
  condition (2) holds only when no device of the wave waits for its window and none has such a failure. The counts show
  it as pending.
- **Stall warning.** A wave for which only the minimum duration is outstanding (the A10-16 rule holds except for the
  time) is not stalled and gets no warning, also when `min_wave_minutes` is longer than `stall_warning_hours`.

## Amendment 2026-11-09 (architect, A10-19): rollout accounting state table

Amends the A10-16 and A10-18 amendments above (wave rule, resume, stall warning, visibility) and decision 6 of §3.2 where this table scopes them differently, as decided by the architect lead (A10-19) after review 4 of PDK-809. The same text is appended to plan M11 (`docs/plans/M11-safe-config.md`); both copies are binding and identical.

### 1. Scope and the binding invariant

This table is the one accounting rule of configuration rollouts (`app.ConfigRollouts`: `classify`, `countRollout`,
`Evaluate`; `configrollout.Decide`, `WaveDone`, `Observed`, `Stalled`). It replaces the scoping of the A10-16 and
A10-18 amendments where they differ; the halt rule, the maintenance windows, the union and the stall warning as such
stay. Where this table and the code differ, the table wins (PDK-809 fix round 5). The invariant, binding:

- **I1** A rollout never advances a wave and never completes without an observed success: at least one device that
  joined in the current wave applied the change without failure. The only exception is a wave that no device joined
  (nothing to observe).
- **I2** Every device whose failure a resume discarded, in any reached wave, must re-apply successfully before the
  rollout advances or completes. A retry that fails again does not satisfy I2.
- **I3** The halt check counts failures over every reached wave; advance and complete block on the same device set
  (every eligible device), while the observation of progress (first apply, share) is taken from the devices that
  joined in the current wave only.
- **I4** A device waiting for its maintenance window is pending: never failed, never a success.
- **I5** Time never stands in for an observed apply.

### 2. Definitions

- **E (eligible)**: the active devices (`device.state = 'active'`) with stored `config_mode = enforce` that are inside
  the reached percentage (`configrollout.Eligible` on the device's bucket, or a canary member). Report-only devices,
  retired, revoked and deleted devices are never in E.
- **J (joined) ⊆ E**: `configrollout.JoinedIn`: every device of E in wave 0; in wave n > 0 a device of E that wave
  n − 1 did not reach. Canary members are in J only in wave 0. Devices of E \ J belong to an **earlier wave**.
- **Counting report**: the device's newest `device_bundle_report` on a bundle whose `config_rollout_id` is this
  rollout (`ListConfigRolloutReports`), plus the current `device_software_status` rows of the staged entries.
- **recent**: recorded by the server at or after `evaluation_since` (bundle report: `recorded_at`; staged software
  entry: `device_software_status.reported_at`, PDK-944). Before the first resume `evaluation_since = started_at`, so
  every report is recent.
- **resumed**: `evaluation_since > started_at` (both default to the same `now()` at insert).
- **Device states** (exactly one per device of E; `classify`):
  - **NR** not reached: not in E (bucket outside the reached percentage and not canary).
  - **RP** reached, pending: in E, no counting report (no bundle of the rollout exists for the device yet, the device
    is offline or has not reported the bundle), or a report-only report of an enforce device.
  - **WW** waiting_for_window: enforced apply without a failed staged resource, and a staged software entry
    `pending/outside_window`.
  - **OK** applied: enforced apply, no failed staged resource, no staged entry waiting. **OK-pre** when the report is
    not recent (applied before the latest resume), **OK-post** when recent (applied, or retried, after it).
  - **FL** failed: a rejection, or an enforced apply with a failed staged resource (resource row of that version, or a
    staged software entry `failed`), and the report is recent. **FL-0** when the rollout was never resumed; **FL-r**
    when `resumed` (a retry that failed again, or a new failure after the resume; the data cannot tell them apart and
    the rule does not need to).
  - **DC** discarded: as FL but not recent, and no newer counting report since. The device has not retried since the
    resume that discarded its failure.
- **Counts** (all over E unless stated): `Eligible = |E|`; `Failed = |FL|`; `Waiting = |WW|`;
  `AwaitingRetry = |DC| + (resumed ? |FL| : 0)`. Over J: `Wave.Eligible = |J|`; `Wave.Applied = |J ∩ (OK ∪ FL)|`
  (success or failure, any time); `Wave.Recent = |J ∩ (OK-post ∪ FL)|`; `Wave.Succeeded = |J ∩ OK|` (any time).

### 3. The rule (`configrollout.Decide`, evaluated by the worker every round at `now`)

```
Halt      := Failed > 0 ∧ Failed ≥ Threshold(Eligible, failure_threshold_percent, failure_threshold_min)
Observed  := AwaitingRetry = 0
          ∧ ( Wave.Eligible = 0
            ∨ ( first_applied_at ≠ nil ∧ Wave.Succeeded ≥ 1
              ∧ ( Wave.Recent × 100 ≥ wave_success_threshold_percent × Wave.Eligible ∨ Waiting = 0 ) ) )
Clock     := Wave.Eligible = 0 ? wave_started_at : first_applied_at
WaveDone  := Observed ∧ now − Clock ≥ min_wave_minutes
Decision  := ¬running → Keep; Halt → Halt; ¬WaveDone → Keep; current wave is last → Complete; else Advance
Progress  := Wave.Applied grew since the last round ∨ (Waiting + AwaitingRetry) shrank since the last round
Stalled   := running ∧ ¬Observed ∧ ¬warned ∧ now − wave_progress_at ≥ stall_warning_hours
```

- `first_applied_at` is set by the worker in the first round that sees `Wave.Applied > 0` (success or failure, any
  time), dated with the round's time; an advance and a resume clear it (A10-18). `wave_progress_at` is set to the
  round's time on `Progress`; an advance and a resume set it to now and clear `stall_warned_at`.
- The `AwaitingRetry = 0` term is unconditional: it holds the wave also when `Wave.Eligible = 0` and also when the
  share is reached. This closes the hole that `Wave.Eligible = 0` made the share vacuously true.
- A wave that only waits for `min_wave_minutes` (Observed holds) is never stalled.
- Manual `Advance` and manual `Complete` do not run this rule (plan M11 decision 32): they are the administrator's
  override and are audited as such. Manual `Complete` from `halted` stays allowed.

### 4. State table

Columns: (1) counts in `Eligible` / `Failed` for the halt; (2a) counts in `Wave.Applied` (dates the clock) /
`Wave.Succeeded` (gate I1); (2b) counts in `Wave.Recent` (share) / `Waiting` (escape) / `AwaitingRetry` (blocks);
(3) complete = identical to advance in every row (I3), not repeated; (4) counts as stall progress when it appears or
changes; (5) counts bucket of `GET /config-rollouts/{id}` and the device-list fields `report_outcome` /
`waiting_for_window` / `awaiting_retry`. "–" = not counted. "Current" = device in J, "earlier" = device in E \ J.

| # | State | Wave | Time of report | (1) Eligible / Failed | (2a) Applied / Succeeded | (2b) Recent / Waiting / AwaitingRetry | (4) Progress | (5) Counts / list |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| S1 | NR not reached | – | – | – / – | – / – | – / – / – | – | not in counts; list `in_wave=false`, `none`, false, false |
| S2 | RP pending | current | – | yes / – | – / – | – / – / – | – | pending; `none`, false, false |
| S3 | RP pending | earlier | – | yes / – | – / – | – / – / – | – | pending; `none`, false, false |
| S4 | WW waiting | current | any | yes / – | – / – | – / yes / – | leaving WW (shrink) | pending; `applied`, true, false |
| S5 | WW waiting | earlier | any | yes / – | – / – | – / yes / – | leaving WW (shrink) | pending; `applied`, true, false |
| S6 | OK-pre | current | before resume | yes / – | yes / yes | – / – / – | – (already counted) | applied; `applied`, false, false |
| S7 | OK-pre | earlier | before resume | yes / – | – / – | – / – / – | – | applied; `applied`, false, false |
| S8 | OK-post (incl. retried ok) | current | after resume | yes / – | yes / yes | yes / – / – | Applied grows | applied; `applied`, false, false |
| S9 | OK-post (incl. retried ok) | earlier | after resume | yes / – | – / – | – / – / – | leaving DC or FL-r (shrink) | applied; `applied`, false, false |
| S10 | FL-0 (never resumed) | current | since start | yes / yes | yes / – | yes / – / – | Applied grows | failed; `rejected` or `applied`+failed ids, false, false |
| S11 | FL-0 (never resumed) | earlier | since start | yes / yes | – / – | – / – / – | – | failed; as S10, false, false |
| S12 | FL-r (retried failed, or new failure) | current | after resume | yes / yes | yes / – | yes / – / yes | Applied grows | failed; as S10, false, **true** |
| S13 | FL-r (retried failed, or new failure) | earlier | after resume | yes / yes | – / – | – / – / yes | – | failed; as S10, false, **true** |
| S14 | DC discarded | current | before resume | yes / – | – / – | – / – / yes | – | pending; `none`, false, **true** |
| S15 | DC discarded | earlier | before resume | yes / – | – / – | – / – / yes | – | pending; `none`, false, **true** |

**Correction 2026-11-09 (A10-20)** to row S1 (architect lead, after review 5 of PDK-809; the row above is kept as
written, this note is binding where they differ):

- S1 means "does not count for this rollout", not "shows nothing". The `none` in column (5) is withdrawn: the device
  list keeps showing the stored outcome of a not-reached device — `report_only` for a report-only device, or the
  earlier outcome (`applied`, `rejected`) of a device that left E (C3, C4, C6) — and marks the device as not counted
  (`in_wave=false`; `waiting_for_window` and `awaiting_retry` stay `false`). The display behaviour of PDK-809 stays as
  it is; at most a "not counted" hint is added in PDK-804's follow-up.
- Point 1 of A10-20, recorded here because it touches the DC rows: a staged software entry `failed` whose
  `reported_at` lies before `started_at` is not recent and is therefore DC (S14/S15), which holds the wave and never
  advances it. This is accepted for now as the safe side and handled by PDK-944, which re-dates the software statuses
  so the failure counts as FL-0 and the halt is not up to 24 h late; PDK-944 gets the acceptance criterion that a
  failure reported before the rollout start halts the wave on the first evaluation after the rollout starts.

Reading aids:
- S10 is A10-16 unchanged: a sub-threshold failure before any resume counts as "applied (with failure)" for the share
  and does not hold the wave; the threshold decides.
- S12/S13 are stricter than the data can distinguish (I2): after a resume every failed device holds the rollout until
  it applies successfully. A resume is the administrator's statement that the cause is fixed; a failure after it
  contradicts the statement, so the rollout waits (stall warning) instead of widening. Halt still fires first when the
  threshold is reached.
- S14/S15 are the Review 4 blocker: `AwaitingRetry` is counted over E, not over J.
- S6: the pre-resume success satisfies I1 (`Wave.Succeeded`) and dates the clock in the first round after the
  resume, but it never counts toward the share (A10-18). A manual halt and resume of a wave that had fully applied
  therefore advances after a fresh `min_wave_minutes`, through the `Waiting = 0` escape, with no device awaiting a
  retry.
- S4/S5: `Waiting` is counted over E (I3). It only matters while the current wave's share is below the threshold.

### 5. Special cases (binding)

| # | Case | Behaviour |
| --- | --- | --- |
| C1 | No device joined the current wave (`Wave.Eligible = 0`) | Clock from `wave_started_at`; `Wave.Succeeded` and the share are not required (nothing to observe, I1 exception); `AwaitingRetry = 0` is still required. |
| C2 | No eligible device at all (`Eligible = 0`) | C1 in every wave: the rollout completes after `waves × min_wave_minutes` with nothing observed; nothing was changed anywhere. |
| C3 | Device deleted, retired or revoked (`state ≠ active`) | Leaves E in the next round: its failure, success, waiting and awaiting-retry no longer count; a halt already recorded stays. `first_applied_at` is not revisited. |
| C4 | Device moved between groups | Its bucket does not change, so E and J do not change — except the canary group: leaving it drops a device whose bucket is outside the reached percentage to NR (S1); joining it adds the device to E (and to J only in wave 0). If the move changes the device's rendered content it gets a new bundle of the rollout and is counted by its report as any other device. |
| C5 | Device enrolled during the rollout | In E when its bucket is inside the reached percentage; in J only when wave n − 1 would not have reached it. Counted by its report like any other device. |
| C6 | Device switched to report-only during the rollout | Leaves E (the compiler renders the overlay for it, plan M11 decision 30). Switching back to enforce re-enters E. |
| C7 | Device offline for days | RP (S2/S3): pending, never failed, no effect on the share or the escape. It holds the wave only when it is the sole device of J (no first apply, I1) — then the stall warning fires after `stall_warning_hours`. When it returns, its report counts from then on, also after later waves advanced (halt check over E). |
| C8 | Device not concerned by the change (content-equal rendering, no bundle of the rollout) | RP (S2/S3) in this release: it dilutes the share and, if all of J are such devices, holds the wave until the administrator advances. Follow-up (architect, outside PDK-809, see §9): the compiler publishes a bundle whenever the bundle's rollout tag changes, so every device of E reports an apply. |
| C9 | Urgent change set (plan M11 decision 26, `rollout = urgent`) | Not staged, no `config_rollout` row, no accounting. While a rollout is open, urgent writes overlapping staged keys are refused (R6.13 (a)). |
| C10 | Urgent software assignment (plan M13c decision 7) | Bypasses the maintenance window only: its device is never WW for that entry; a staged urgent assignment follows the waves and this table unchanged. |
| C11 | Halt by the administrator (no failures), then resume | S6/S7 for every applied device; `AwaitingRetry = 0`; the wave advances after a fresh `min_wave_minutes` from the first round after the resume. |
| C12 | Halt on failures, resume, no retry | S14/S15: `AwaitingRetry > 0` holds the rollout for ever; stall warning after `stall_warning_hours` with `awaiting_retry` in its params; the administrator advances, completes, halts or reverts. |
| C13 | Halt on failures, resume, every discarded device retried successfully | `AwaitingRetry = 0`; advance or complete once the clock and (share or `Waiting = 0`) hold. |
| C14 | Two worker replicas, or an administrator acting between read and write | Unchanged: the write is guarded by status, wave index, `evaluation_since` and `wave_started_at` (`ignoreStale`). |

### 6. Contract and bookkeeping changes (additive, ADR 0013; all in PDK-809, migration `00120` is uncommitted)

- `config_rollout` gains `wave_outstanding int NOT NULL DEFAULT 0 CHECK (wave_outstanding >= 0)`: the last
  `Waiting + AwaitingRetry` the worker saw; an advance and a resume reset it to 0. `RecordConfigRolloutWaveProgress`
  writes `wave_applied` and `wave_outstanding` and sets `wave_progress_at = now`, `stall_warned_at = NULL` on
  `Progress` (§3), with the same guards as today.
- `configrollout.Rollout` carries `Waiting` and `AwaitingRetry` (over E) next to `Eligible` and `Failed`;
  `configrollout.WaveCounts` carries `Eligible, Applied, Recent, Succeeded` (over J). The J-scoped `Waiting` and
  `Discarded` are removed.
- `RolloutCounts` (`counts` of `ConfigRollout` in `admin.yaml`) gains the required integers `waiting` and
  `awaiting_retry` next to `eligible, applied, failed, pending`; both are subsets of `pending` except that
  `awaiting_retry` also counts S12/S13 (which are in `failed`).
- `ConfigRolloutDevice` (`GET /config-rollouts/{id}/devices`) gains the required boolean `awaiting_retry` (true in
  S12–S15); `report_outcome` keeps R6.14 (c): `none` for S14/S15. New filter `awaiting_retry` (boolean), documented
  in `x-paddock-list`.
- `config_rollout.stalled` params: `rollout_id`, `change_set_id`, `wave`, `stalled_since`, `stall_warning_hours`,
  `wave_eligible`, `wave_applied`, `waiting`, `awaiting_retry` (replaces `wave_waiting`; the code is unreleased).
- The portal does not show the new fields yet (PDK-942 follow-up, unchanged).

### 7. Test rows (PDK-809 fix round 5; one subtest per row, named by its ID)

Unit, `server/internal/domain/configrollout/waves_test.go`, `TestDecideAccounting` (table-driven over
`configrollout.Rollout` → `Decision` and `Observed`), `min_wave_minutes = 30`, `wave_success_threshold_percent = 90`,
`failure_threshold_min = 1` unless stated:

| ID | Input (counts over E / J, clock) | Expected |
| --- | --- | --- |
| U1 | J: Eligible 3, Applied 3, Succeeded 0, Recent 3; Failed 3 ≥ threshold | Halt (halt before anything else) |
| U2 | as U1 but `failure_threshold_min = 5` (no halt); clock +31 min | Keep (I1: no success); Observed false |
| U3 | J: Eligible 10, Applied 9, Succeeded 9, Recent 9; Waiting 1; clock +31 min | Advance (share 90 %) |
| U4 | J: Eligible 10, Applied 8, Succeeded 8, Recent 8; Waiting 1 (over E, an earlier-wave device); clock +31 min | Keep; Observed false (share 80 %, a device waits) |
| U5 | as U4 with Waiting 0 | Advance (escape, I3 over E) |
| U6 | J: Eligible 10, Applied 10, Succeeded 10, Recent 10; AwaitingRetry 1 (earlier wave); clock +31 min | Keep; Observed false (S15) |
| U7 | J: Eligible 0; AwaitingRetry 1; wave_started_at −31 min | Keep (C1 still requires AwaitingRetry 0) |
| U8 | J: Eligible 0; AwaitingRetry 0; wave_started_at −29 min / −30 min | Keep / Advance |
| U9 | J: Eligible 5, Applied 5, Succeeded 5 (pre-resume: Recent 0); Waiting 0; AwaitingRetry 0; first_applied_at −30 min | Advance (C11) |
| U10 | as U9 with first_applied_at nil | Keep (clock not started) |
| U11 | U3 with Observed true and clock +29 min | Keep, and `Stalled` false whatever `wave_progress_at` is |
| U12 | U6 with `wave_progress_at` −24 h, not warned / warned | Stalled true / false |
| U13 | last wave, U3 inputs | Complete |

Integration, new file `server/internal/app/rolloutaccounting_integration_test.go`, `TestRolloutAccountingTable`,
waves `50/100`, `min_wave_minutes = 30`, `failure_threshold_min = 1`, `wave_success_threshold_percent = 90`, one staged
software entry and one staged managed file, fixtures as in `rolloutwindows_integration_test.go`. Each row asserts the
rollout status and `current_wave_index` after `Evaluate` at the stated times, and the counts and device-list fields of
§4 column (5):

| ID | Setup → steps | Expected |
| --- | --- | --- |
| A1 (the probe "wave-0 failure, halt, resume, +32 min → not completed") | rollout at `current_wave_index = 1` (fixture or manual `Advance`); device a (bucket < 50, earlier wave) whose newest report is an enforced apply with a failed staged resource; device b (bucket ≥ 50, J) applied ok and installed; evaluate → halted; `Resume` at T; evaluate at T+1 min and T+32 min | T+1: running, wave 1; T+32: **running, wave 1, not completed**; counts `applied 1, failed 0, pending 1, awaiting_retry 1`; a listed `report_outcome none`, `awaiting_retry true`, b `applied` |
| A2 | A1, then device a reports an enforced apply without failure at T+40 min; evaluate at T+41 min | **completed** (S9 clears `awaiting_retry`; the clock was dated T+1 by b's pre-resume apply, S6; `Wave.Succeeded = 1`; share 0 % but `Waiting = 0`) |
| A3 | A1, then device a reports a failed staged resource again at T+40 min; evaluate at T+41 min and T+71 min | halted again at T+41 (`Failed 1 ≥ threshold 1`). Variant with `failure_threshold_min = 2`: running, wave 1 at T+71 (S13 holds); counts `failed 1, awaiting_retry 1`; a listed `applied` with the failed id, `awaiting_retry true` |
| A4 | wave 0 with three devices, all fail the staged file, `failure_threshold_min = 5`; evaluate at +31 min | running, wave 0 (I1, S10 without a success); `failed = 3`, `awaiting_retry = 0`; stall warning at +24 h |
| A5 | wave 0: device a applied ok before a manual `Halt`; `Resume`; evaluate at +1 min, +29 min, +31 min | running / running / wave 1 (C11) |
| A6 | wave 1: device a (earlier wave) `pending/outside_window` on the staged entry (S5); J = {b, c}: b applied ok, c without report; evaluate at T+31 min; then a's window opens, a installs; evaluate again | T+31: running, wave 1 (share 50 % < 90 % and `Waiting = 1` over E); after a installed: completed (`Waiting = 0`, escape). Variant A6' with J = {b} only: completed at T+31 although a still waits (share 100 % wins) |
| A7 | `Eligible = 0` (no active enforce device); evaluate at +31 min and +62 min | wave 1 at +31 min, completed at +62 min (C2) |
| A8 | wave 1, J = ∅ (every device joined in wave 0), one wave-0 device DC after resume; evaluate at +31 min | running, wave 1 (C1 + U7) |
| A9 | A1 at +1 min, then device a is retired (`state ≠ active`); evaluate at +32 min | completed (C3), `awaiting_retry = 0` |
| A10 | wave 0: device a applied ok, device b offline (no report); evaluate at +31 min | wave 1 (C7: offline does not hold); A10' with a also offline: running, stall warning at +24 h |
| A11 | staged urgent assignment, device outside its window applies and installs; a non-urgent staged entry on another device stays `outside_window` | the urgent device is OK (S8), the other WW (S4); `waiting = 1` (C10) |
| A12 | A1 state; device list filters `awaiting_retry=true` / `report_outcome=none` | both return device a; `in_wave true`, `waiting_for_window false` |
| A13 | stall progress on a shrink: A1 with two earlier-wave devices a1, a2 both DC after the resume at T; evaluate at T+1 min; a1 retries ok at T+10 h; evaluate at T+10 h, T+25 h and T+35 h | T+10 h: running (a2 still holds), `awaiting_retry 2 → 1` resets `wave_progress_at`; T+25 h: no `config_rollout.stalled`; T+35 h: one `config_rollout.stalled` with params `awaiting_retry = 1`, `waiting = 0`, `wave_applied = 1` |

Rows that are trivially implied and need no own test: S3, S7, S11 (earlier-wave counterparts whose only effect is the
halt count, already covered by `TestConfigRolloutCountingRule`), S1 (covered by `TestConfigRolloutCountsAndDevices`).
The software-dated rows after a resume (a staged entry that fails or installs after the resume, dated by
`device_software_status.reported_at`) are PDK-944's tests; until PDK-944 such a failure is DC instead of FL-r, which
holds the rollout the same way (S14 vs S12) but does not count toward the halt. The review of PDK-809 accepts that
difference only in those rows.

### 8. Documentation updates in the same fix round

- Plan M13c amendment A10-18, bullet "Discarded failures stay outstanding": add "— of any reached wave, not only of
  the current one; after a resume also every failed device (§4 S12/S13 of the A10-19 amendment)".
- `docs/operations/configuration-rollouts.md`: section 4's table gains the `waiting` and `awaiting_retry` counts and
  the list field `awaiting_retry`; the A10-18 paragraph reads "A device of any wave whose failure the resume discarded,
  and after a resume every device whose newest report is a failure, is shown with `awaiting_retry: true` and holds the
  rollout until it has applied successfully"; the troubleshooting row "A rollout does not move on" names
  `awaiting_retry` and that a wave with no successful apply never advances by itself.
- `docs/compliance/audit-codes.md`: params of `config_rollout.stalled` as §6.
- `changelog.d/PDK-809.*`: mention the two new counts, the list field and the filter.

### 9. Out of PDK-809 (the lead creates the stubs)

- **Compiler: a changed rollout tag is a new bundle (C8).** `compiler.render` treats a bundle whose
  `config_rollout_id` differs from the latest bundle's as changed, so every eligible device gets a bundle of the
  rollout and reports an apply (a no-op apply for a device the change does not touch). Without it, group-scoped changes
  with small first waves need a manual advance under I1. Architect decision recorded here; implementation in its own
  ticket, with a test that an unchanged device inside the wave gets a tagged bundle and one outside the wave does not.
- **PDK-944** dates staged software applies and failures by `device_software_status.reported_at` (§2 "recent").
- **PDK-937** (other pending software reasons) is unchanged by this table: only `outside_window` is WW.
