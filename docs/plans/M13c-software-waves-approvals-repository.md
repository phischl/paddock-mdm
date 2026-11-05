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
