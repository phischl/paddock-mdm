# Implementierungsplan: M3a — Identity and privileges, server side

Status: Ready for implementation (after M2.2) · 2026-10-04 · Author: architect
Basis: `docs/architecture.md` v1.5 §9 (identity, lock, login assignment, suspension), §10 (profiles, sudo), §7 (bundles),
§21 (schema negotiation); ADR 0007 (amended), 0008, 0013, 0018, 0019; concept F2, F11, F13, F15, A13;
PoC M1 report ("Configuration that worked")

Binding language: **MUST** / **MUST NOT** / **SHOULD** / **MAY**. M3 is split: **M3a** (this plan) builds users, groups,
lock, login assignment, suspension, permission profiles and the bundle content for login and sudo; **M3b** (separate
plan) builds the agent reconcilers (`login`, `sudo`, privileged local groups), the deny-list PAM profile and VM gates.

## 1. Goal

An organization administrator manages users and groups (local and synced) in Paddock, locks and unlocks users, decides
who may log in on which device, suspends logins per device, and defines permission profiles assigned globally, per
group or per user, optionally scoped to a device group. Paddock computes each user's effective profile with its
derivation and compiles login and sudo content into the device bundles (schema v2). The Authentik side (device login
application, claims, mandatory MFA, lock) is provisioned automatically.

## 2. Context

- M0–M2.2: organizations with Authentik groups `paddock.<slug>` and `.admins|.operators|.auditors`
  (`server/internal/domain/organization`); devices, device groups, managed config, compiler with bundle schema v1
  (`pkg/bundle`), agents report `schema_versions` (M2b agents: `[1]`); ActionRunner/outbox/audit; list contract; RLS.
- PoC M1 (quoted essentials): device provider `client_type public`, grant types `device_code`, `refresh_token`,
  `authorization_code`; scopes openid, email, profile, offline_access; a **profile-scope mapping that emits `groups`**
  (Himmelblau requests only `openid profile email offline_access` and drops values containing `:`);
  `issuer_mode per_provider`, `sub_mode hashed_user_id`, `access_token_validity minutes=10`,
  `refresh_token_validity days=30`; application policy "member of root group and not of locked group"; brand
  `flow_device_code` set; device codes expire after 60 s; **lock needs group membership AND deletion of the user's
  refresh tokens, access tokens and authenticated sessions** (group alone does not stop PIN logins);
  `pam_allow_groups` read at daemon start, empty value denies all, missing line allows all;
  `himmelblau.conf` that worked: `oidc_issuer_url`, `app_id`, `domain`, `pam_allow_groups`,
  `allow_console_password_only = false`, `enable_hello`, `hello_pin_min_length`, `local_groups = users`.
- Architecture §9.2 names: `paddock.<slug>.locked`, `paddock.<slug>.g.<group_slug>`, `paddock.<slug>.d.<device_id>`;
  §9.4 empty-assignment semantics are decided below (decision 9).

## 3. Binding decisions

### 3.1 Users and groups
1. **Organization domains:** new column `organization.domains text[] NOT NULL DEFAULT '{}'` managed by platform
   admins (`PATCH /api/platform/v1/organizations/{id}` `{domains}`; each a lowercase DNS name; a domain may belong to
   one organization only → 409 `domain_taken`). The first domain is the **primary domain** used as Himmelblau
   `domain`. Local usernames MUST be `<local-part>@<one of the domains>`.
2. **`app_user`** mirrors Authentik users of the organization: `id, organization_id, authentik_pk, username (UPN,
   lowercase), display_name, email, source local|synced, locked bool, locked_at, created_at, updated_at`.
   - *Local users* are created through Paddock (`POST /api/v1/users`): the adapter creates the Authentik user
     (attribute `paddock_managed: true`, `paddock_org: <slug>`, no password), adds it to `paddock.<slug>` and returns a
     **one-time recovery link** (Authentik recovery API) that the portal shows once in a modal with a copy button.
     The brand's recovery flow is provisioned by the adapter (decision 13).
   - *Synced users* are Authentik users that are members of `paddock.<slug>` without `paddock_managed` (put there by an
     upstream source's property mapping, configured by the platform operator — documented in
     `docs/operations/identity-sources.md`). The worker syncs them every 5 minutes (create/update/remove in
     `app_user`, audit `user.synced_added|synced_removed` system actor).
   - Upstream-owned attributes of synced users (username, display name, email, password) are read-only: API returns
     409 `attribute_owned_upstream`.
3. **`user_group`** (`id, organization_id, slug, name, source local|synced, upstream_authentik_pk nullable,
   authentik_pk, created_at`) with membership table `user_group_member`.
   - *Local groups*: Authentik group `paddock.<slug>.g.<group_slug>`, members managed in Paddock.
   - *Synced groups*: an admin **imports** an upstream Authentik group (picker over Authentik groups that are not
     `paddock.*`); Paddock creates `paddock.<slug>.s.<group_slug>` and the worker mirrors its membership from the
     upstream group every 5 minutes (only users that are members of `paddock.<slug>`). Members are read-only in Paddock.
     Rationale: upstream names may contain `:` or spaces, which Himmelblau drops; the mirror gives a claim-safe name.
   - `group_slug` matches `^[a-z0-9][a-z0-9-]{0,40}[a-z0-9]$`.
4. A membership change is a privilege change: audit `user_group.member_added|member_removed` with params
   `{user, group, effective_class_before, effective_class_after}` where the class is the user's highest effective
   class over all devices (§3.3).

### 3.2 Login, lock, suspension
5. **Device login provider per organization** (adapter `EnsureOrganization`, idempotent, reconciled every 10 min):
   OAuth2 provider + application `paddock-device-<slug>` with the PoC settings (§2), redirect URI
   `http://127.0.0.1:8765/callback`, scope mappings openid, email, profile, offline_access and the Paddock mapping
   `paddock-device-groups` on scope `profile`:
   `return {"groups": sorted(g.name for g in request.user.all_groups() if g.name.startswith("paddock.<slug>."))
   + (["paddock.<slug>"] if <member of root> else [])}` (exact expression in the blueprint/adapter; must not emit
   other organizations' or non-Paddock groups). Application policy (expression, `policy_engine_mode all`):
   member of `paddock.<slug>` and not of `paddock.<slug>.locked`.
6. **Mandatory MFA for device logins:** platform-wide flows provisioned by blueprint `paddock-device.yaml`:
   authentication flow `paddock-device-authentication` (identification with user-enumeration prevention, password,
   authenticator validation WebAuthn/TOTP with `not_configured_action: configure` — never `skip`) used as the device
   providers' `authentication_flow`; device-code flow `paddock-device-code` (requires authentication) set as the
   default brand's `flow_device_code`. Device code validity 60 s (default).
7. **Lock (F2)** `POST /api/v1/users/{id}/lock`, **unlock** `…/unlock` (org_admin; `ConfirmDialog`; audit
   `user.locked|unlocked`): `ActionRunner.RunExternal` — prepare: `locked=true`, outbox `state.changed` with
   `priority` scope `user`; external: add to `paddock.<slug>.locked` **and** delete the user's refresh tokens,
   access tokens and authenticated sessions in Authentik; finalize: outcome. Unlock: remove membership (no token
   action). The compiler's priority lane recompiles all affected devices (decision 10) within 10 s.
8. **Organization login settings** (`organization_login_settings`, one row per org, created with defaults):
   `hello_enabled bool true`, `hello_pin_min_length int 6 (6–32)`, `user_lock_session_action lock_screen|terminate
   (lock_screen)`, `break_glass_accounts text[] ('{}')` — local accounts that are never touched by the privileged
   group policy or the deny list (replaced by the managed local admin in M4), `sudoers_d_allowlist text[]
   ('{README}')` — files in `/etc/sudoers.d/` that the agent leaves alone. API `GET/PUT /api/v1/settings/login`
   (org_admin; audit `settings.login_changed`). `devseed` sets acme `break_glass_accounts = {paddock}` and
   `sudoers_d_allowlist = {README, 90-paddock}` (test VMs).
9. **Login assignment** (`device_login_assignment(device_id, subject_type user|group, subject_id)`), API
   `PUT /api/v1/devices/{id}/login-assignment` `{users:[], groups:[]}` (admin, operator; audit
   `device.login_assignment_changed`). **Empty assignment = every user of the organization** (allow list =
   `paddock.<slug>`). Non-empty: allow list = assigned groups' Authentik names, plus `paddock.<slug>.d.<device_id>`
   if users are assigned directly; the adapter creates that per-device group lazily and keeps its membership equal
   to the directly assigned users (removed when the last direct user is removed or the device is retired).
10. **Affected devices of a user** = devices whose effective allow list contains the user (directly, via group, via
    empty assignment) **plus** devices with a `session.login` of the user in the last 365 days. `session.login` is a
    new device event type (closed enum extension: `session.login {username, at}`; M3b agents send it) stored as
    `device_user_seen(device_id, username, last_seen_at)`; audit is **not** written per login (privacy, volume) —
    only the table is updated.
11. **Suspension (F15)** `POST /api/v1/devices/{id}/suspend-logins` / `…/resume-logins` (admin, operator;
    `ConfirmDialog`; audit `device.logins_suspended|logins_resumed`) sets `device.logins_suspended`; priority lane.

### 3.3 Permission profiles
12. **Entities:** `permission_profile(id, organization_id, name, class none|restricted|full, commands text[],
    require_password bool, timestamp_timeout_min int (0–60), lecture always|once|never, created/updated)` and
    `profile_assignment(id, organization_id, profile_id, subject_type global|group|user, subject_id nullable,
    device_group_id nullable)`. A `restricted` profile's commands are absolute paths with optional arguments
    (`^/[^\s]+( .*)?$`, no `ALL`, no `!`, no sudoers meta characters `,:=\\` — 422 `invalid_command`); `none` and
    `full` profiles have no commands.
13. **Effective profile** (pure domain function in `server/internal/domain/privilege`, no I/O):
    `Effective(user, device, assignments, profiles, groupMemberships, deviceGroups) → EffectiveProfile` per
    architecture §10.2: filter assignments by device-group scope; class = max; commands = sorted union;
    scalars user > group > global, among groups the most restrictive (`require_password`: true wins;
    `timestamp_timeout_min`: lowest; `lecture`: always > once > never); `root_equivalent = true` if any command matches
    the catalog (`rootequiv.go`, versioned; match by absolute binary path; any argument wildcard `*` on a catalog
    binary counts); a restricted effective profile with `root_equivalent` is reported as class `full` for detection
    and flagged. Output includes `derivation: [{command|class|scalar, from: assignment_id, profile_id, subject}]`.
    Property tests (`pgregory.net/rapid`, approved): permutation of inputs → identical output (byte-identical JSON);
    union/max laws.
14. **APIs:** profiles CRUD (`/api/v1/permission-profiles`, list contract), assignments CRUD
    (`/api/v1/profile-assignments`, filters `profile_id`, `subject_type`, `subject_id`, `device_group_id`),
    `GET /api/v1/users/{id}/effective-profile?device_id=` (derivation), `GET /api/v1/devices/{id}/effective-sudo`
    (per allowed user). Mutations audited (`permission_profile.*`, `profile_assignment.*`, params include the root-
    equivalent flag). Portal warns (inline alert, not a dialog) when a restricted profile or an effective profile
    contains root-equivalent commands. Changing a profile to class `full` or assigning a `full` profile requires the
    typed-confirmation variant of `ConfirmDialog` (step-up comes in M4).

### 3.4 Bundle schema v2
14a. `pkg/bundle` gets **schema version 2** = v1 + resource types `login` and `sudo` + top-level `policy`. The compiler
    renders v2 only for devices whose last heartbeat lists 2 in `schema_versions`; otherwise v1 exactly as today (no
    login/sudo content; portal shows "agent too old for login management" on the device). M2b agents are unaffected.
15. **`login` resource** (one per bundle, id `login`):
    ```json
    { "provider": "himmelblau",
      "himmelblau": { "oidc_issuer_url": "https://auth.<domain>/application/o/paddock-device-<slug>/",
                      "app_id": "paddock-device-<slug>", "domain": "<primary domain>",
                      "pam_allow_groups": ["paddock.acme"], "enable_hello": true, "hello_pin_min_length": 6 },
      "suspended": false,
      "locked_users": ["bob@acme.test"],
      "session_action": "lock_screen",
      "break_glass_accounts": ["paddock"] }
    ```
    `pam_allow_groups` is `[]` when suspended (the agent writes the line present-and-empty). `locked_users` contains
    locked users among the affected users of this device (decision 10), sorted.
16. **`sudo` resource** (one per bundle, id `sudo`): structured, rendered to sudoers syntax **on the device** by M3b
    (the device resolves the user's numeric UID through NSS and writes `#<uid>` as user spec, so a local account with
    the same short name can never match):
    ```json
    { "lecture_text": "<org lecture text>",
      "entries": [ { "username": "dave@acme.test", "class": "restricted", "root_equivalent": false,
                     "commands": ["/usr/bin/systemctl restart nginx.service"],
                     "require_password": true, "timestamp_timeout_min": 5, "lecture": "always",
                     "profile_digest": "<sha256 of the canonical effective profile>" } ],
      "privileged_groups": ["sudo", "admin", "wheel"],
      "sudoers_d_allowlist": ["README"],
      "break_glass_accounts": ["paddock"] }
    ```
    Entries only for users allowed on the device with class ≠ `none`, sorted by username. The organization's lecture
    text is a new field in login settings (`sudo_lecture_text`, ≤ 2000 chars, default English text referencing the
    acceptable-use policy). **Server-side check before signing:** the compiler renders each entry with the reference
    renderer in `pkg/sudoers` (UID placeholder `#4294967294`) and validates it with `visudo -cf` in the compiler
    container (package `sudo` added to the compiler image); a failure blocks the bundle (previous version stays) and
    raises audit `device.bundle_render_failed`.
17. `pkg/sudoers`: `Render(entry Entry, uid uint32) ([]byte, error)` and `FileName(username) string`
    (`paddock-u-<first 16 hex of sha256(username)>`) — shared by compiler (validation) and agent (M3b).

### 3.5 Authentik recovery flow
18. Blueprint `paddock-recovery.yaml`: recovery flow `paddock-recovery` (identification by link token → password set
    stage with policy: min length 12) set as the default brand's `flow_recovery`; recovery links expire after 24 h.

## 4. Non-goals

Agent reconcilers, PAM profile, VM tests (M3b); managed local admin, step-up, revocation (M4); upstream source
provisioning in Authentik (documented only); per-organization brands/flows; offline emergency access; sudo
`runas` other than root; deny entries in sudoers; German catalog.

## 5. Affected files

New: `server/migrations/paddock/00007_identity.sql`, `server/internal/domain/{user,usergroup,privilege,loginsettings}/`,
`server/internal/domain/privilege/rootequiv.go`, `pkg/sudoers/`, app use cases, worker sync jobs, Authentik adapter
extensions (+ recorded fixtures), blueprints `paddock-device.yaml`, `paddock-recovery.yaml`, compiler v2 renderer,
admin API/OpenAPI additions, portal views *Users*, *User detail*, *Groups*, *Group detail*, *Permission profiles*,
*Profile assignments* (embedded in profile detail), *Settings → Login & privileges*, device detail additions (login
assignment, suspension, effective sudo, "agent too old" notice), `docs/operations/identity-sources.md`, CHANGELOG.
Changed: `pkg/bundle` (schema v2), `server/internal/domain/organization` (domains, group-name functions for `.locked`,
`.g.`, `.s.`, `.d.`), devseed (domains `acme.test`, `globex.test`; login settings for acme), gates.
Off-limits: as in M2.

## 6. Tests and gates

| ID | Gate | Content |
| --- | --- | --- |
| P1 | Effective profile (concept gate) | property tests (decision 13) + golden test: identical inputs in any order → byte-identical `pkg/sudoers` output; every rendered file passes `visudo -cf` (run in the test container) |
| P2 | Root-equivalence | two harmless restricted profiles that combine into a root-equivalent set → effective `root_equivalent=true`, class reported `full`, portal warning (e2e) |
| I1 | Authentik provisioning | fresh org → device provider/application/policy/scope mapping exist; userinfo for a test user via device-code + refresh grant (acceptance helper drives the Authentik flow executor) contains `groups` with only `paddock.<slug>…` names; a globex user is refused by acme's application |
| I2 | Lock (Authentik path) | lock → user in `.locked`, user's refresh tokens/sessions gone (Authentik API), refresh grant with the old token fails; unlock → membership removed; exactly one audit event each |
| I3 | Bundle content | devicesim reporting `schema_versions [1,2]` gets a v2 bundle with `login` and `sudo`; `[1]` gets v1 unchanged; lock of a user → new bundle with the user in `locked_users` within 10 s; suspension → `pam_allow_groups: []`, `suspended: true`; login assignment with a direct user → per-device group exists in Authentik and is in `pam_allow_groups` |
| I4 | Synced identities | an Authentik user added to `paddock.acme` by the test (simulating an upstream source) appears as `synced` within one sync round; attribute edits via Paddock → 409 `attribute_owned_upstream`; importing an upstream group creates `paddock.acme.s.<slug>` with mirrored members |
| A2/A3/list | existing gates | cover all new endpoints automatically |
| E3 | Portal | create local user (recovery link shown once), create group and add member, create restricted profile with a root-equivalent command (warning shown), assign it to the group, view the user's effective profile with derivation, lock user via modal, set device login assignment and suspend via modal; axe clean |

## 7. Steps

0. Wait-free start: M2.2 is merged (Go toolchain); run `git log`.
1. Migration, domain (users, groups, settings, privilege + rootequiv + property tests), `pkg/sudoers` + `pkg/bundle` v2.
   Commit `feat(identity): users, groups and permission profile domain`.
2. Authentik adapter + blueprints (decisions 2, 3, 5, 6, 7, 9, 18) with recorded fixtures and real-instance tests.
   Commit `feat(authentik): device login provider, lock, user and group provisioning`.
3. Admin API + worker sync jobs. Commit `feat(api): users, groups, lock, login assignment, profiles`.
4. Compiler v2 (decisions 14a–17, visudo in compiler image, priority lane for lock/suspension).
   Commit `feat(compiler): bundle schema v2 with login and sudo`.
5. Portal. Commit `feat(web): identity and privileges`.
6. Gates P1, P2, I1–I4, E3 + regression from reset (`make dev-secrets up dev-seed acceptance e2e`, plus
   `system-test VM=all T=S1` to prove M2b agents still get v1 bundles). Commit `test(acceptance): identity gates`.

## 8. Acceptance criteria

| # | Given / When / Then | Req. | Observed by |
| --- | --- | --- | --- |
| AC1 | Given an org admin, when they lock a user, then the user's online logins fail at once (Authentik) and the bundles of all affected devices contain the lock within 10 s | F2 | Org admin; device (devicesim) |
| AC2 | Given profiles assigned globally, per group and per user (some device-group scoped), then the portal shows each user's effective profile per device with the assignment that granted each right | F11 | Org admin |
| AC3 | Given a synced user, then Paddock shows it as synced and refuses edits of upstream attributes | F13 | Org admin |
| AC4 | Given a device, when an admin suspends logins, then its bundle denies all directory users and keeps break-glass accounts out of every policy | F15 | Org admin; device |
| AC5 | Given any rendered sudo entry, then it passes `visudo -c`, and identical inputs give identical output | concept gate "Effective profile" | Developer |

## 9. Freedoms

Package layout below the named domain packages, worker scheduling details, Authentik API call order, portal layout,
recorded-fixture format.

## 10. Stop conditions

Authentik's API cannot delete a user's refresh tokens/sessions, create recovery links, or set the brand's
device-code/recovery flow; a profile-scope mapping cannot emit `groups`; `visudo` cannot run in the compiler image
without privileges; a need for `USING (true)` policies on organization data; a contradiction with ADR 0007/0008/0019
or `CLAUDE.md`; M0 §11 S2/S6/S7/S8.

## 11. Risks

| # | Item | Default |
| --- | --- | --- |
| R1 | Short-name vs. UPN on the device | Solved by `#uid` rendering on the device (decision 16); M3b verifies |
| R2 | Synced-group mirror lag (5 min) | Documented; lock does not depend on it (lock is per user) |
| R3 | Empty login assignment = whole organization may be too broad for some operators | Default per concept; operators narrow it per device or via device-group workflows later |
