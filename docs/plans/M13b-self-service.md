# Implementierungsplan: M13b — Self-service app, the `available` intent, Flatpak, user and user-group targets

Status: Ready for implementation · 2026-11-05 · Author: architect
Basis: ADR 0049 (self-service desktop app, channel, Flatpak, user targets; **Proposed** — toolkit and per-user
status pending the maintainer), ADR 0042 with the amendment of 2026-11-05, ADR 0048 (desktop notice mechanism),
ADR 0013/0024 (additive formats, no new event type an older server could receive — see decision 25), ADR 0018,
ADR 0034; plans M13a (catalog, `software` section, `reconcile.Software`, `health.software`), M8d (`device_owner`),
M12 (`agent/internal/desktop/notify.go`); roadmap M13 (F-04, F-06), M13a outline "M13b".

Binding language: **MUST** / **MUST NOT** / **SHOULD** / **MAY**.

Written against `cluster/alpha9-features` at `a54c1a82`. Tickets: PDK-798 to PDK-807 (§8). Migration numbers:
`00107` is reserved by an alpha.9 ticket; this plan takes `00108` and `00109` (renumber at landing).

## 1. Goal

A user opens *Paddock Self-Service* on their laptop, sees the applications their organization offers them —
device-wide or because they own the device — installs, updates or removes them, and sees why a required app is
on the device and cannot be removed. Administrators target applications at users and user groups, offer
Flatpak apps from Flathub or any remote, and see per device which self-service apps are installed. The agent
executes every operation; nothing is collected beyond the operation itself.

## 2. Context (verified in the code on 2026-11-05)

- **Catalog**: `software_source` (`kind` absent: APT only), `software_catalog_entry.packages jsonb`
  (`PackageRef{distribution, release, architecture, package}`), `software_assignment` (`device_group_id`
  nullable, `intent IN (required, uninstall, hold, forbid)`, `update_rule`, `version`, `reason`), migrations
  `00095`–`00099`; `software.Resolve`, `software.MergeIntents`; `app.SoftwareCatalog` (`RolesWrite`, no step-up);
  compiler `server/internal/compiler/software.go` (`loadSoftware`, `orgSoftware.section(device)`);
  `ListCompileTargets` provides `os_release`, `arch`.
- **Bundle**: `bundle.SoftwareSpec{Sources, Packages}`, `SoftwarePackage{Package, Intent, Version, Source,
  CatalogEntryID}`, `ValidateSoftware`; apply order `hostname → time → file → systemd_unit → updates → software →
  login → sudo`.
- **Agent**: `reconcile.Software` (`Plan`, `Apply`, files, `checkSources`, the record
  `/var/lib/paddock/state/software-installed`, `tamper`), `reconcile.System` with `Output`, `fakesys`;
  `health.Report.Software *protocol.SoftwareHealth`; the health socket `/run/paddock/agent.sock` (0600, JSON over
  HTTP) is the pattern for a unix-socket server; `desktop.Notify(ctx, sys, summary, body) (int, error)`;
  `paths.Layout`; events through `reconcile.Events`; `protocol.EventTypes` closed.
- **Identity on the device**: Himmelblau maps directory users to UIDs 200000–999999999 (`himmelblauIDMapRange`),
  user name = UPN; local accounts below 60000.
- **Owners**: `device_owner (organization_id, device_id, user_id)`, `app_user (id, username = lower UPN,
  display_name)`, `user_group`, `user_group_member`.
- **Status**: `device_software_status (device_id, catalog_entry_id, package, intent, state, version, reason,
  error, reported_at)`; `RecordStatus` replaces rows per device from `health.software.items` (≤ 200).
- **Events/audit**: `software.installed|reinstalled|removed|apply_failed` → `device.software_*`.
- **Packaging**: `packaging/nfpm/paddock-{agent,supervisor,revoke}.yaml`, debs built by `make deb`, signed with
  minisign at release, published through the agent-release path (`bundles.<domain>/packages/<version>/`).
- **Portal**: `SoftwareCatalog.vue`, `SoftwareCatalogDetail.vue` (assignments `DataList`,
  `SoftwareAssignmentForm.vue` with scope, intent, update rule, version, reason), `DeviceManagedSoftware.vue`.
- **Privacy**: `docs/compliance/privacy.md` row "Software status (plan M13a)".

## 3. Binding decisions

### 3.1 Vocabulary

1. **Target** of an assignment: `organization` (no FK), `device_group`, `user`, `user_group`. **Owner** = a row of
   `device_owner`. **Audience** of an `available` package in a bundle: `all` or a UPN list. **Self-service
   operation** = one install, update or remove a user asked for. **Scope** of a Flatpak ref: `system` or `user`.
2. Operation states: `queued`, `running`, `succeeded`, `failed`, `refused`. Refusal reasons:
   `required_by_policy`, `not_in_audience`, `offline`, `busy`, `unknown_entry`. Failure reasons: those of
   `protocol.SoftwareApplyFailed.Reason` plus `flatpak_failed`, `interrupted`, `timeout`.

### 3.2 Data model and catalog (PDK-798)

3. Migration `00108_software_targets_flatpak.sql`:

   ```sql
   ALTER TABLE software_source ADD COLUMN kind text NOT NULL DEFAULT 'apt' CHECK (kind IN ('apt','flatpak'));
   -- flatpak: uris[1] is the remote URL; suites, components, architectures stay empty; signing_key/fingerprint as apt
   ALTER TABLE software_assignment
     ADD COLUMN user_id uuid, ADD COLUMN user_group_id uuid,
     ADD CONSTRAINT software_assignment_one_target CHECK (num_nonnulls(device_group_id, user_id, user_group_id) <= 1),
     ADD CONSTRAINT software_assignment_user_fk FOREIGN KEY (organization_id, user_id) REFERENCES app_user (organization_id, id) ON DELETE CASCADE,
     ADD CONSTRAINT software_assignment_group_fk FOREIGN KEY (organization_id, user_group_id) REFERENCES user_group (organization_id, id) ON DELETE CASCADE,
     DROP CONSTRAINT software_assignment_intent_check,
     ADD CONSTRAINT software_assignment_intent_check CHECK (intent IN ('required','uninstall','hold','forbid','available'));
   DROP INDEX IF EXISTS software_assignment_unique_idx;   -- the implementer takes the real name
   CREATE UNIQUE INDEX software_assignment_target_idx ON software_assignment (organization_id, catalog_entry_id, device_group_id, user_id, user_group_id) NULLS NOT DISTINCT;
   ALTER TABLE device_software_status
     ADD COLUMN scope text NOT NULL DEFAULT 'system' CHECK (scope IN ('system','user')),
     ADD COLUMN username text NOT NULL DEFAULT '' CHECK (char_length(username) <= 254),
     DROP CONSTRAINT device_software_status_pkey,
     ADD PRIMARY KEY (device_id, catalog_entry_id, scope, username);
   ```

   Grants and RLS unchanged. The `packages jsonb` of a catalog entry gains the optional fields per element
   `flatpak_ref` (`^[A-Za-z][A-Za-z0-9_-]*(\.[A-Za-z][A-Za-z0-9_-]*){2,}$`, ≤ 255) and `scope` (`system` |
   `user`, default `system`); an element has either `package` or `flatpak_ref` (`software.ValidatePackages`);
   an entry whose `source_id` is a `flatpak` source MUST have `flatpak_ref` elements only, and an entry with
   `flatpak_ref` elements MUST reference a `flatpak` source (400 `invalid_request`).
4. **Assignment rules** (`software.ValidateAssignment`): `available` MUST NOT carry `version` or an update rule
   other than `latest`; `available` with `scope: user` elements is allowed for every target kind; a user or
   user-group target is allowed for every intent. `MergeIntents` severity becomes `forbid (5) > uninstall (4) >
   required (3) > hold (2) > available (1)`; an `available` that loses against any other intent is dropped from
   the audience (the device-wide intent wins; the app shows it as read-only state).
5. **Sources of kind `flatpak`**: `uris` = exactly one `https://` URL (the remote), `suites`, `components`,
   `architectures` empty, `signing_key` the remote's armored GPG key, `fingerprint` as today
   (`pkg/openpgpkey`); `slug` is the remote name on the device (`paddock-<slug>`). Create/update/delete keep the
   step-up rule (ADR 0042 decision 1). A source of kind `apt` cannot change kind (400).
6. **API** (`api/openapi/admin.yaml`): `SoftwareSource` gains `kind`; `SoftwareAssignment(+Input)` gains
   `user_id`, `user_group_id` (nullable; the list filter `target` ∈ `organization|device_group|user|user_group`
   and `user_id`, `user_group_id`); `PackageRef` gains `flatpak_ref`, `scope`; `intent` enum gains `available`;
   `DeviceManagedSoftware` items gain `scope`, `username`; `GET /api/v1/software-catalog/{id}/devices` gains the
   filter `scope`. New read: `GET /api/v1/users/{id}/software` (the entries that target the user directly or
   through a group, with the intent; list contract; `RolesRead`).

### 3.3 Bundle and compiler (PDK-799)

7. `pkg/bundle`: `SoftwareSource` gains `Kind string json:"kind,omitempty"` (`""` = `apt`, `"flatpak"`);
   `SoftwarePackage` gains `FlatpakRef string json:"flatpak_ref,omitempty"`, `Scope string json:"scope,omitempty"`
   (`""` = system) and `Audience *SoftwareAudience json:"audience,omitempty"` with
   `SoftwareAudience{All bool json:"all,omitempty"; Users []string json:"users,omitempty"}` (UPNs, lower case,
   sorted, ≤ 200); constant `SoftwareAvailable = "available"`; `ValidateSoftware` enforces: `available` has an
   audience with `All` or ≥ 1 user; a package with `FlatpakRef` names a `flatpak` source; `Package` and
   `FlatpakRef` are mutually exclusive. `ContentSHA256` covers the fields. Schema stays v2 (additive).
8. Compiler: `loadSoftware` additionally loads `ListDeviceOwnersWithUsernames` (device → owners' UPNs) and
   `ListUserGroupMembers` (group → user IDs) once per round; `section(device)` resolves assignments: `organization`
   and `device_group` as today; `user` applies when the user is an owner of the device; `user_group` applies when
   any owner is a member; for `available` the audience is `{all: true}` for organization/device-group targets and
   `{users: [the targeted owners' UPNs]}` for user/user-group targets (merged across assignments of one entry:
   `all` wins; else the union). Packages of a `flatpak` source render `flatpak_ref`, `scope`, `source`.
   `StateChanged(ScopeOrg)` on owner changes (`app.DeviceOwners.Set` already records `ScopeDevice`; the
   implementer verifies that device scope recompiles the device — it does — and keeps it).
9. **Required `flatpak` package**: when the section has any `flatpak` source, the compiler adds the package
   `flatpak` (distribution repositories, intent `required`, `catalog_entry_id` = the nil UUID,
   `reason: flatpak_runtime`) unless an entry already names it; the agent treats the nil entry ID as
   "system-managed" in its status (`id` `00000000-…`; `RecordStatus` skips it: it is not an entry of the
   organization — consistent with M13a decision 18).

### 3.4 Agent: Flatpak, audience, the self-service server (PDK-800, PDK-801)

10. **Flatpak in `reconcile.Software`** (PDK-800): a `flatpak` source renders no apt files; it is a remote:
    `flatpak remote-add --if-not-exists --system --gpg-import=<tmpfile with the decoded key> paddock-<slug> <url>`
    (`Plan` line `remote <slug>`); each pass compares `flatpak remotes --system --columns=name,url` against the
    agent's own record `/var/lib/paddock/state/flatpak-remotes` (`name url fingerprint`, written after a
    successful `remote-add`); a changed URL or a missing remote is restored and
    `tamper.protected_file_changed{file: "flatpak:remote/paddock-<slug>"}` emitted; a system remote named
    `paddock-*` that the spec does not name is removed, same event). Intents on refs: `required` →
    `flatpak install -y --noninteractive --system|--user paddock-<slug> <ref>` (user scope through
    `systemd-run --machine=<user>@.host --user --wait --pipe flatpak install -y --user …` for every targeted UPN
    that has an active session; a user without a session gets it at their next session start — the agent checks
    on `session.login`), `uninstall`/`forbid` → `flatpak uninstall -y --system <ref>` plus `flatpak mask --system
    <ref>` for `forbid` (and `flatpak mask --remove` when forbid ends), `hold` → `flatpak mask --system <ref>`
    (masked refs do not update). Removals follow the 15-minute rule (ADR 0042 H2). The status item carries
    `flatpak_ref` in `package` with the prefix `flatpak:`. The simulation guard (`apt-get -s`) has no Flatpak
    equivalent: `flatpak uninstall` without `--delete-data` never removes other apps; runtime removal is never
    requested (`--unused` is not used). The agent runs `apt-get install flatpak` through the normal required path
    (decision 9) before any `flatpak` call; a missing `flatpak` binary → every ref `failed/flatpak_missing`.
11. **Audience evaluation and the self-service record** (PDK-801): `agent/internal/selfservice` keeps
    `/var/lib/paddock/state/selfservice.json` (`{installs: [{entry_id, package|flatpak_ref, scope, username,
    installed_at, version}]}`, 0600) and the operation queue in memory (the state file holds only completed
    installs). `Authorize(uid) (principal, error)`: `getent passwd <uid>` → name; `isDirectory = uid in
    [200000, 999999999]`; the principal's UPN is the lower-cased name for directory users, `""` for local accounts.
    `Visible(p principal) []AppView`: every package of the current bundle's section with `intent = available`
    whose audience is `all` or contains the UPN, plus every other intent's package as read-only (`managed: true`)
    — a local account sees `all` entries and managed ones.
12. **Server** on `/run/paddock/selfservice.sock` (`selfservice.Server`, `net.Listen("unix")`, `os.Chmod 0666`,
    `SO_PEERCRED` via `syscall.GetsockoptUcred` on the accepted `*net.UnixConn`'s raw conn; HTTP/1.1 through
    `http.Server` with `ConnContext` carrying the credentials; `ReadHeaderTimeout` 5 s; at most 32 concurrent
    connections; bodies ≤ 4 KiB). Endpoints (§6.2). Rate: 60 requests/min per UID (429), 5 queued operations per
    UID. The server starts with the agent and refuses every request with 503 `no_bundle` until a bundle is
    applied. `UID 0` is an ordinary local principal.
13. **Executor**: one goroutine; an operation calls the same reconciler primitives (`Software.InstallOne`,
    `RemoveOne`, `UpdateOne` — new exported methods that run the planned apt/flatpak command for one target with
    the same simulation and lock rules as `Apply`; APT installs for self-service use the entry's source, pinned
    nothing), records the result in `selfservice.json`, emits `software.self_service`, notifies the session
    (`desktop.Notify`), and marks the status item (`scope`, `username` for user scope). Timeout 30 min →
    `failed/timeout` and the command is killed. A `required`/`forbid` of the same package in the bundle is checked
    again at execution start (the bundle may have changed since queueing) → `refused/required_by_policy`.
14. **Drift interaction**: the drift pass never removes a self-service install (it is not in the policy's
    `uninstall`/`forbid`; if a later bundle forbids it, the policy wins and the app shows `removed by policy`); a
    self-service app the user removed by hand is not reinstalled (only `required` is). Self-service apps are listed
    in `health.software.items` with `scope`/`username` (pending maintainer for user scope; system-scope
    self-service installs are reported without a user name when the maintainer declines).

### 3.5 Desktop app (PDK-802)

15. `selfservice/` (Python 3.12+, GTK 4, libadwaita; `pyproject.toml`; entry point `paddock-self-service`; desktop
    file `com.paddock.SelfService.desktop`, icon; `ruff` and `pytest` in `make lint-selfservice` and `make
    test-selfservice`, run by the agent CI job; packaged by `packaging/nfpm/paddock-self-service.yaml` with
    `Depends: python3-gi, gir1.2-gtk-4.0, gir1.2-adw-1`, files under `/usr/lib/paddock-self-service/`, signed and
    published like the agent debs — `agent-release` gains the artifact `paddock-self-service_<version>_all.deb`).
    Screens: **Apps** (grid of `AppView`: name, icon served by the agent at `GET /v1/apps/{id}/icon` — icons are
    not part of the bundle; the agent fetches `GET /v1/catalog/{entry}/icon` from the server through the device
    client once per entry and caches it under `/var/lib/paddock/cache/icons/`; a missing icon shows the category
    glyph —, state chip,
    *Install*/*Remove*/*Update* or *Managed by your organization*), **Details** (description, version, source,
    scope, the organization's reason), **Activity** (operations with state and reason), a first-start dialog with
    the transparency notice (text from `GET /v1/status.notice`, set by the organization in `settings.privacy
    .self_service_notice`, default text in §6.5). Polling: `GET /v1/operations/{id}` every 2 s while running.
    The app never runs as root and holds no credential.
16. The agent serves icons: `GET /v1/apps/{entry_id}/icon` from its cache; the device API gains `GET
    /v1/catalog/{entry_id}/icon` (signed device request; 200 `image/png`, 404) — additive.

### 3.6 Server: status, events, portal, privacy (PDK-803, PDK-804, PDK-805)

17. `protocol.SoftwareItem` gains `Scope string json:"scope,omitempty"`, `Username string json:"username,omitempty"`;
    `RecordStatus` writes the new PK columns; `MaxSoftwareItems` stays 200 (user-scope items count; the agent
    reports system items first, then user items newest first, and sets `truncated` as today).
18. Event `software.self_service` (`protocol.EventSoftwareSelfService`, data `SoftwareSelfService{User, EntryID,
    Package, FlatpakRef, Scope, Action, Outcome, Reason, Version}`), audit `device.software_self_service` (actor
    device; params all fields; `outcome` maps `succeeded → success`, else `failure`). ADR 0024: the agent emits it
    only while the applied bundle carries an `available` package or a `flatpak` source — only a server that knows
    them renders them (decision 25).
19. Portal (PDK-804): `SoftwareAssignmentForm.vue` gains the target selector (organization, device group, user,
    user group — user and group pickers with search over `/users` and `/user-groups`), the intent `available`;
    `SoftwareSourceForm.vue` gains `kind` with the Flatpak fields; the package-row editor gains `flatpak_ref` and
    `scope` per row for Flatpak sources; `SoftwareCatalogDetail.vue`'s devices list shows `scope`/`username`
    columns and the filter; `DeviceManagedSoftware.vue` likewise; the user detail page (`UserDetail.vue`) gains the
    tab *Software* over `GET /users/{id}/software`; audit code texts; privacy settings page gains
    `self_service_notice` (text ≤ 2000, shown on first start).
20. Privacy (PDK-805): `privacy.md` rows: *Self-service operations* (user name, application, action, outcome,
    reason, version — at the moment of the operation — audit log) and *Self-service status per user* (user name,
    application, state, version — status, replaced at each report) with the works-council note; the negative list
    unchanged; the app's first-start notice. `docs/operations/software.md` gains *Self-service*, *Flatpak*, *User
    targets*. Residual risks RR-116 (shared devices without owners see nothing user-targeted), RR-117 (user-scope
    Flatpak installs run in the user's session context and depend on it being reachable), and RR-79 written out
    (Flathub); §6.6 has the rows.

### 3.7 Failure and loss cases (binding; tested in §9)

| # | Case | Agent behaviour | What the user sees | What the server sees |
| --- | --- | --- | --- | --- |
| F1 | Socket missing or agent down | the app shows *Paddock is not running* and retries every 10 s | banner | nothing |
| F2 | No bundle applied yet | 503 `no_bundle` | *waiting for policy* | nothing |
| F3 | Bundle changes while an operation is queued | re-authorized at start; refused with `required_by_policy`/`not_in_audience` when no longer allowed | refusal with reason | `software.self_service{outcome: refused}` |
| F4 | Agent restarts during `running` | operation `failed/interrupted`; the next drift pass reconciles policy state; a half-installed apt package is finished by `dpkg --configure -a` | failure with *try again* | `… outcome: failed, reason: interrupted` |
| F5 | Source unreachable (APT) | `failed/source_unreachable` after apt's retry | failure | event |
| F6 | Offline and an install is asked | an install needs its source: the simulation's network error ends it as `failed/source_unreachable`; a removal is allowed offline (the user asked for it; the 15-minute rule binds policy removals only) | failure / success | event |
| F7 | dpkg locked by another process | `failed/dpkg_locked` after 60 s; the app offers *retry* | failure | event |
| F8 | User logs out during a user-scope Flatpak install | `systemd-run` fails → `failed/flatpak_failed`; nothing partial (flatpak transactions are atomic) | failure | event |
| F9 | Two users queue operations | sequential; each sees its queue position | *queued (2)* | events in order |
| F10 | User removes a self-service app by hand | status `absent` at the next pass; no reinstall; the record entry is dropped | *not installed* | status |
| F11 | Policy later requires or forbids the app | policy wins at the next apply; a forbid removes it; the user sees *managed by your organization* | read-only | `software.removed` / status |
| F12 | Remote key changes on Flathub (RR-79) | `flatpak remote-add --gpg-import` of the stored key; a mismatch → `failed/fingerprint_mismatch` for every ref of that remote, nothing written | failure | `software.apply_failed` |
| F13 | `flatpak` not installed and the distribution repository unreachable | every ref `failed/flatpak_missing` | failure | status |
| F14 | More than 200 status items | system items first, then newest user items; `truncated` | — | truncated flag (exists) |

## 4. Non-goals

- No approval workflow, no waves or maintenance windows for software, no stored packages, no shared catalog (M13c).
- No Snap; no per-user APT installs; no Flatpak runtime pruning (`--unused`); no Flathub preset (the
  administrator adds the remote with its key).
- No usage data (last opened, run time) — the negative list; no app telemetry.
- No change to the revocation path, the supervisor, `pkg/policy` tiers, or the audit writer.
- No new Go module or npm package; the desktop app's runtime comes from Ubuntu's own packages (pending maintainer).

## 5. Affected files

| Path | Action | Purpose |
| --- | --- | --- |
| `server/migrations/paddock/00108_software_targets_flatpak.sql` | new | decision 3 |
| `server/internal/domain/software/*.go` | change | validation, merge, audience (4, 5) |
| `server/internal/app/softwarecatalog.go`, `users.go` (software tab query) | change | targets, kinds, `GET /users/{id}/software` |
| `server/internal/compiler/software.go` | change | owners, groups, audience, flatpak runtime (8, 9) |
| `pkg/bundle/software.go`, `pkg/protocol/types.go`, `api/openapi/device.yaml`, `api/openapi/admin.yaml` | change | decisions 7, 16, 17, 18 |
| `agent/internal/reconcile/software.go`, `software_flatpak.go` (new), `fakesys` | change / new | decision 10, 13 |
| `agent/internal/selfservice/{server,authorize,executor,state}.go` (+ tests) | new | decisions 11–13 |
| `agent/internal/agent/agent.go`, `sessions.go`, `paths/paths.go`, `client/client.go` | change | server start, session hook, paths, icon fetch |
| `selfservice/**` (Python), `packaging/nfpm/paddock-self-service.yaml`, `Makefile`, `.github/workflows/ci.yml` (agent job) | new / change | decision 15 |
| `server/internal/app/devicereports.go`, `domain/audit/codes.go`, `ingest` | change | status columns, event, audit |
| `server/web/src/components/SoftwareAssignmentForm.vue`, `SoftwareSourceForm.vue`, `SoftwareCatalogEntryForm.vue`, `views/SoftwareCatalogDetail.vue`, `DeviceManagedSoftware.vue`, `UserDetail.vue`, `PrivacySettings.vue`, `locales/*` | change | decision 19 |
| `test/acceptance/software_selfservice_test.go`, `test/system/selfservice_test.go` | new | §9 |
| `docs/compliance/privacy.md`, `docs/operations/software.md`, `docs/compliance/residual-risks.md`, `docs/architecture.md` | change | decision 20, §7 |

Not to be touched: `agent/internal/revoke/`, `agent/cmd/paddock-revoke/`, `agent/internal/supervisor/`,
`pkg/policy` tiers, existing migrations, ADRs other than 0049 and the 0042 amendment.

## 6. Interfaces

### 6.1 Admin API additions

```
SoftwareSource(+Input): + kind (apt|flatpak)
SoftwareAssignment(+Input): + user_id, user_group_id (nullable); intent enum + available; list filters target, user_id, user_group_id
PackageRef: + flatpak_ref, scope (system|user)
DeviceManagedSoftware item, CatalogEntryDevice item: + scope, username; filter scope
GET /api/v1/users/{id}/software        list: sort [name,intent] default name; filters [intent]; RolesRead
PrivacySettings: + self_service_notice (string ≤ 2000)
```

### 6.2 Self-service socket (`/run/paddock/selfservice.sock`, JSON over HTTP/1.1)

```
GET  /v1/status                     → {agent_version, bundle_version, notice, user: {name, directory: bool}, queue: N}
GET  /v1/apps                       → {apps: [AppView]}   AppView{entry_id, name, description, category, kind (apt|flatpak), scope, intent,
                                       managed (bool), installable, removable, updatable, state (installed|absent|pending|failed), version, reason, icon: bool}
GET  /v1/apps/{entry_id}            → AppView; 404
GET  /v1/apps/{entry_id}/icon       → image/png; 404
POST /v1/apps/{entry_id}/install    → 202 {operation_id}; 403 required_by_policy|not_in_audience; 404; 429; 503 no_bundle
POST /v1/apps/{entry_id}/remove     → 202; 403 required_by_policy; 404
POST /v1/apps/{entry_id}/update     → 202; 403; 404
GET  /v1/operations/{id}            → {id, entry_id, action, state (queued|running|succeeded|failed|refused), position, reason, started_at, finished_at}; 404 (another user's operation)
```

Errors are problem objects `{code, detail}`; nothing names other users' entries or operations.

### 6.3 Bundle (additive)

```json
{"software": {"sources": [{"slug": "flathub", "kind": "flatpak", "uris": ["https://dl.flathub.org/repo/"], "keyring": "…", "fingerprint": "…"}],
 "packages": [{"flatpak_ref": "org.gimp.GIMP", "intent": "available", "scope": "system", "source": "flathub", "catalog_entry_id": "…", "audience": {"all": true}},
              {"package": "code", "intent": "available", "source": "vscode", "catalog_entry_id": "…", "audience": {"users": ["alice@example.org"]}},
              {"package": "flatpak", "intent": "required", "source": "", "catalog_entry_id": "00000000-0000-0000-0000-000000000000"}]}}
```

### 6.4 Audit codes

| Code | Actor | Target | Params | Outcomes |
| --- | --- | --- | --- | --- |
| `device.software_self_service` | device | device | `user`, `entry_id`, `package`, `flatpak_ref`, `scope`, `action`, `outcome`, `reason`, `version` | success, failure |
| `software_assignment.*` (existing) | admin | assignment | + `target`, `user_id`, `user_group_id` | unchanged |
| `software_source.*` (existing) | admin | source | + `kind` | unchanged |

### 6.5 Texts (binding English)

- First-start notice default: *Your organization offers applications through Paddock. Installing, updating or
  removing an application here is recorded with your user name. Nothing else about how you use this device is
  collected.*
- Managed entry: *Managed by your organization* with the reason when one is set.

### 6.6 Residual risks (RR-116, RR-117; RR-79 written)

| ID | Risk | Mitigation | ISMS |
| --- | --- | --- | --- |
| RR-79 | Flathub (or any remote) is an external trust anchor; a remote's key or content change is outside Paddock | per-remote key pinned by fingerprint in the signed bundle; a mismatch installs nothing; step-up for every source change | which remotes are allowed |
| RR-116 | A user on a device they do not own sees device-wide apps only; shared devices without owners get no user-targeted apps | documented; owners are set per device; organization-wide `available` covers shared devices | owner hygiene |
| RR-117 | User-scope Flatpak installs run in the user's session; a session that ends mid-install fails the install; a user without a session gets it at next login | atomic flatpak transactions; the status shows `pending` | none |

## 7. Architecture and rule amendments (PDK-805)

`docs/architecture.md` §11.1 (the self-service socket next to the health socket), §11.3 (Flatpak in the software
reconciler), §11.6 item 5 (Flatpak remotes), §12.5 (self-service paragraph), §16.1; `CLAUDE.md` "Protected areas
on the device" item 5 gains *and the Flatpak remotes `paddock-*`*; `docs/compliance/privacy.md` (decision 20).

## 8. Steps (tickets, in order)

1. **PDK-798 — Catalog: targets, `available`, Flatpak sources, migration 00108, API.** §3.2. Verify: `make gen`
   no diff; domain and app tests; list contract.
2. **PDK-799 — Bundle fields, compiler audience and owner resolution, flatpak runtime package.** §3.3. Depends on
   798. Verify: compiler unit tests per target kind and audience merge.
3. **PDK-800 — Agent: Flatpak remotes and refs in `reconcile.Software`, protected remotes.** §3.4 decision 10.
   Depends on 799 (`pkg/bundle`). Verify: fakesys tests (F12, F13), `make typecheck`.
4. **PDK-801 — Agent: self-service server, authorization, executor, state, events.** §3.4 decisions 11–14, §6.2.
   Depends on 800. Verify: unit tests with a fake peer credential (every refusal reason; F3, F4, F9, F10).
5. **PDK-802 — Desktop app (Python/GTK4), packaging, release artifact.** §3.5 (**pending maintainer: toolkit**).
   Depends on 801 (protocol); MAY start against a fake socket. Verify: `make lint-selfservice test-selfservice`;
   the deb installs on a VM and the app lists the fake entries.
6. **PDK-803 — Server: status columns, `software.self_service` event, audit code, icon device endpoint.** §3.6
   decisions 16–18. Depends on 798. MAY run in parallel with 800/801.
7. **PDK-804 — Portal: target selector, Flatpak fields, scope/user columns, user software tab, notice setting.**
   §3.6 decision 19. Depends on 798, 803. Verify: `make web`, frontend-verify, e2e `software.spec.ts` extended.
8. **PDK-805 — Privacy rows, runbook, architecture, residual risks (pending maintainer: per-user status).**
   Depends on 801–804.
9. **PDK-806 — Acceptance gates SS1–SS6.** §9. Depends on 803, 804. (tester)
10. **PDK-807 — System gates on the VMs with a graphical session and the real app.** §9. Depends on 802, 806. (tester)

Chains: (798 → 799 → 800 → 801 → 802) ‖ (798 → 803 → 804); 805 after both; 806, 807 last.

## 9. Tests and gates

- **Unit:** `software` domain (validation table for kinds, refs, scopes, targets; merge with `available`);
  compiler (owner → audience per target kind; union; `all` wins; no owners → absent; flatpak runtime package);
  `reconcile.Software` Flatpak (remote add/restore/remove with fakesys `Output`, mask/unmask, user-scope via
  `systemd-run`, F12, F13); `selfservice` (authorize ranges, visibility, every refusal, queue limits, executor
  timeout, interruption F4, state file round trip); `desktop.Notify` call count cap; Python: `pytest` with a fake
  socket (list, install flow, refusal rendering, notice dialog once).
- **Integration:** migration `00108` on the alpha.9 schema with existing assignments; RLS unchanged;
  `RecordStatus` with scope/username PK; isolation fixtures for the new endpoints.
- **Acceptance (`software_selfservice_test.go`; the socket lives on the device, so the acceptance suite proves the
  server side only — devicesim needs no self-service client):** SS1 an `available` assignment to a user group renders the audience
  of the owners only (bundle fetched by devicesim); SS2 a device without owners gets no user-targeted package;
  SS3 a `software.self_service` event is recorded with its params and the status row carries scope and user;
  SS4 a Flatpak source change needs step-up (403 for tokens); SS5 `GET /users/{id}/software` lists direct and
  group targets; SS6 isolation.
- **System (`test/system/selfservice_test.go`, VM with an autologin graphical session for the test user):**
  SV1 the app package installs (required entry), the socket exists with mode 0666; SV2 as the test user
  (`sudo -u`), `curl --unix-socket` lists only the audience's apps; SV3 install of an `available` APT package →
  `succeeded`, event on the server, notification in the session; SV4 removal of a `required` app → 403; SV5
  Flathub remote added with a pinned key, a system-scope ref installs; a planted `paddock-rogue` remote is removed
  and reported; SV6 F4: restart the agent mid-install → `failed/interrupted`, the package ends consistent.
- Never weakened: `TestSoftwareGates` SW1–SW8, `TestSoftware*` acceptance.

## 10. Acceptance criteria

- **C1 (ADR 0049 decisions 2–3; user):** a user sees and installs only what their audience allows; a managed app is
  read-only; refusals name the reason.
- **C2 (decision 5; admin):** assignments target users and groups; a device with a targeted owner receives the
  policy; one without does not.
- **C3 (decision 4; admin, user):** a Flatpak remote with a pinned key is added, apps install in system or user
  scope, a rogue remote is removed and reported.
- **C4 (decision 7, 9; auditor):** every operation is one audit event with the user; the privacy document lists
  exactly what the event and the status carry.
- **C5 (ADR 0013/0024; operator):** an alpha.9 agent ignores the new fields; an alpha.10 agent against an alpha.9
  server never emits `software.self_service` (no `available` package can be in its bundle).

## 11. Stop conditions

- `SO_PEERCRED` is unavailable on the accepted connection through `net/http` (report; do not parse `/proc`).
- `systemd-run --machine=<user>@.host --user` is refused for Flatpak on the VM image (report with the journal).
- The maintainer declines Python: stop PDK-802 and report; the channel (PDK-801) is toolkit-independent.
- The maintainer declines per-user status: PDK-803 ships `scope` without `username` (the column stays empty)
  and PDK-805 documents it.
- Any new Go module, npm package, container image, or a change to the revocation path or the supervisor.

## 12. Risks and open points

- R1 second language: contained in `selfservice/`, lint and tests in the agent job, no shared code.
- R2 audience size: ≤ 200 UPNs per package. The compiler caps the list at 200, logs `audience_truncated` and the
  entry's portal detail shows the warning; an administrator with larger groups targets by device group instead.
  Documented in the runbook.
- R3 `flatpak` package on Ubuntu 24.04 is in `universe`; devices without `universe` fail with `no_candidate`:
  the runbook names it.

Open questions — **maintainer**: (1) toolkit and language of the app (recommended Python 3 + GTK 4/libadwaita);
(2) per-user status items in `health.software` and `device_software_status.username` (recommended yes, listed
in `privacy.md`); (3) the first-start notice as a per-organization setting with a default text (recommended
yes). **Architect lead**: (4) `flatpak` runtime package added automatically (recommended yes); (5) the audience
cap of 200 UPNs (recommended); (6) user-scope Flatpak installs executed in the user's session rather than
refused (recommended).

## 13. Freedoms

Python package layout and GTK widget choices; the icon cache layout; the exact `AppView` field order; whether the
executor is a goroutine with a channel or a worker pool of one; the sqlc query names; German texts.

## Amendment 2026-11-09 (architect-lead decisions Q12–Q14, PDK-798)

Open points (4) to (6) of §12 are decided as recommended:

- **(4), Q12:** when an organization has a source of kind `flatpak`, the compiler adds the `flatpak` runtime package
  to the affected devices automatically, as decision 9 describes (PDK-799).
- **(5), Q13:** the audience of an `available` package is capped at 200 UPNs; the compiler emits an
  `audience_truncated` warning, and the entry's portal detail shows it (R2; PDK-799, PDK-804).
- **(6), Q14:** a user-scope Flatpak install runs in the user's session (`systemd-run --machine=<uid>@.host --user`)
  instead of being refused. Without an active session of the user the install stays `pending`; it is never escalated
  to system scope (RR-117; PDK-800, PDK-801).

PDK-798 lands the migration as `00113_software_targets_flatpak.sql` (00108 was taken). Its unique index on
`(organization_id, catalog_entry_id, device_group_id, user_id, user_group_id) NULLS NOT DISTINCT` replaces the
unnamed unique constraint of migration 00096, and the table check of `software_assignment` admits `available` with
update rule `latest` and no version. A source of kind `flatpak` is checked in the table too (one URI, no suites,
components or architectures), and the status upsert keys on the new primary key. Until PDK-799 renders them, the
compiler leaves user and user-group targets, the `available` intent and Flatpak sources and entries out of every
bundle, so none of them applies organization-wide or fails a bundle in between.

## Amendment 2026-11-09 (architect decisions A10-6, A10-7 and 18, PDK-799 review 1)

- **C5, A10-6:** C5 is met through compiler gating; there is no schema v3. An agent release older than the first
  alpha.10 agent, the first that contains PDK-800 (`0.1.0-alpha.10`, the compiler's `selfServiceAgent`), gets no
  `available` packages, no Flatpak sources or applications and no `flatpak` runtime package. Its required, forbid,
  uninstall and hold APT packages stay complete. A compiler test checks that section against the alpha.9
  `ValidateSoftware` as the alpha.9 compat fixture (`pkg/compat`) decodes it. Development builds that are no release
  version get everything, as in the support window.
- **Decisions 7 and 9, A10-7:** only `required` and `available` Flatpak applications name their source and bring the
  remote and the `flatpak` runtime package. `forbid`, `uninstall` and `hold` of an application name no source and act
  only where Flatpak is present; they never install it. `ValidateSoftware` accordingly requires a Flatpak source only
  for a required or available application, and a Flatpak source that fails the source rules no longer blocks a
  device with a Flatpak forbid.
- **Audience user names:** an audience carries user names of up to 256 characters, the limit of
  `app_user.username`. The compiler leaves out an owner whose stored name an audience cannot carry
  (`audience_user_dropped` warning) instead of failing the device's bundle.
- **Decision 18:** PDK-799 and PDK-800 are coupled. The agent built from a tree with PDK-799 but without PDK-800
  accepts Flatpak and `available` entries it cannot execute, so no agent is released from such a tree.

## Amendment 2026-11-09 (architect decisions A10-9 and A10-10, PDK-918)

- **A10-10, compile warnings:** the compiler persists what it shortens or drops against an assignment in the
  organization-scoped table `compile_warning` (migration `00116_compile_warning.sql`; ENABLE and FORCE RLS on
  `paddock.org_id`; compiler `SELECT, INSERT, DELETE`, API `SELECT`). A row names the device, and the assignment and
  catalog entry it concerns, a stable English code and its params (never user names). Each compile of a device replaces
  its rows (at most 100 per device); a blocked or unpublished bundle keeps the rows of the current one. The portal
  (PDK-804) reads them through `GET /api/v1/compile-warnings` (list contract, filters `device_id`, `assignment_id`,
  `catalog_entry_id`, `code`). Q13's `audience_truncated` is persisted this way, one row per assignment the package's
  audience came from; `audience_user_dropped` stays a log line.
- **A10-9, forbid flatpak:** when the `flatpak` package itself resolves to `forbid` or `uninstall` on a device, the
  compiler leaves out every Flatpak application of that device, and with them the Flatpak remotes and the runtime
  package; the APT part of the section is unchanged. Each required or available application left out records
  `flatpak_forbidden` (param `flatpak_ref`) for its assignments. The runbook (PDK-805) explains it.

## Amendment 2026-11-09 (architect decision A10-11, PDK-924)

- **A10-11, targeting user-scope Flatpak applications:** a package of the software section with `flatpak_ref`,
  `scope: user` and intent `required`, `forbid` or `uninstall` may carry `users`: the targeted users on the device
  (lower-case UPNs, sorted, distinct, 1 to 200, the limits of an audience). The compiler fills it from the owners a
  user or user-group assignment targets; the assignments of the winning intent merge into the sorted union, and one
  that targets the whole device (organization or device group), or belongs to a system-scope entry of the same
  application, leaves the list out. Without `users` the application
  acts in system scope, never for every user; an empty list is refused by `bundle.ValidateSoftware`. A list over 200
  keeps the first 200 by user name and records `flatpak_users_truncated` (params `users`, `kept`, `flatpak_ref`) for
  its assignments. An assignment whose targeted owners all have names a bundle cannot carry does not apply, rather than
  widening to system scope. The field is additive (ADR 0013); agents before `selfServiceAgent` get no Flatpak
  application and so never see it (A10-6). PDK-800 acts only for the listed users.

## Amendment 2026-11-09 (architect decision A10-14, PDK-935)

- **A10-14, how devices fetch catalog icons:** option (b), object storage with the bundles' path and access model.
  Decision 16's `GET /v1/catalog/{entry_id}/icon` answers **302** to a presigned GET on the bundles host (validity of a
  bundle URL, 120 s), not 200 `image/png`; there are no new Valkey keys, no ACL change and no new internal boundary.
- **Writer:** the compiler, which writes bundles. It reads the organization's icons with the catalog, checks each with
  `software.ValidateIcon` (the api's upload rules: PNG, 64 KiB, 512 × 512 pixels; a failing icon is left out and the
  entry shows the glyph) and uploads every icon a published bundle names once per publish batch, content-addressed, to
  `org/<org>/icons/<sha256>.png` in `paddock-bundles` (`image/png`). A bundle naming an icon whose upload failed is not
  committed and is retried like a failed bundle upload, so a pointer never names a missing icon.
- **Resolution in the gateway:** the bundle pointer `bp:<device>` (an existing key) gains one hash field
  `icon:<entry_id>` = object key per icon its bundle names. The gateway answers only an entry of the requesting
  device's own pointer whose key lies below `org/<device's organization>/icons/`; anything else is 404 `not_found`.
  The bundle row records the digests (`bundle.icons`, entry ID → hex SHA-256) so the reconcile loop restores the
  icon fields with the pointer after a Valkey loss.
- **Bundle (additive, ADR 0013):** a software package of an entry with a valid icon carries `icon_sha256` (64 lower-case
  hex; never on the flatpak runtime). A changed icon therefore changes the bundle and moves the pointer; only an agent
  from `selfServiceAgent` gets the field (A10-6), as an older agent refuses unknown fields.
- **Device:** the client sends the signed GET without following redirects, then fetches the `Location` with a plain
  GET (the signed headers never reach the object store) and accepts only 200 `image/png` of at most 64 KiB with the
  PNG signature; anything else is an error, and the self-service app shows the category glyph (decision 16 unchanged).
  Re-fetching an icon whose `icon_sha256` changed and checking the digest is a follow-up of the agent's icon cache.
