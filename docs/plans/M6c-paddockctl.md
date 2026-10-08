# Implementierungsplan: M6c — API tokens, declarative configuration and `paddockctl`

Status: Ready for implementation (after M4c.1, before M6a) · 2026-10-08 · Author: architect
Basis: architecture v1.7 §3.2 (`api` role serves the `paddockctl` API), §8.3 and §20 (restore commands), §9.6 (roles,
step-up), §14 (audit), §17.1 (declarative configuration), §17.3 (API tokens "scoped, audited"), §23 (repo layout
`cli/cmd/paddockctl/`, `api/schema/paddock.v1.json`); ADR 0001 (Go for the CLI), 0007 (roles from Authentik groups),
0011 (configuration source of truth), 0016 (restore rule), 0018 (list contract, dialogs); concept principle 7
("everything as code"); product owner decision 2026-10-08 ("paddockctl gets planned into the next milestone").

Binding language: **MUST** / **MUST NOT** / **SHOULD** / **MAY**.

## 1. Goal
An organization administrator creates scoped, expiring API tokens in the portal and uses them from CI with the static
binary `paddockctl` to export the organization's configuration as `paddock.yml`, preview a change as a diff and apply
it atomically through one audited write path. A platform operator has the restore commands of architecture §20
(`bump-bundle-seq`, `rebuild-cache`, `recompile --all`) as `paddock-server admin` subcommands, which M6a's restore
drill uses.

## 2. Context
- **Ist-Zustand (code is the truth):** there is no `cli/` module, no API token, no `PUT /api/v1/config`, no
  `api/schema/paddock.v1.json` and no `admin` subcommand. The admin API is cookie-session only
  (`server/internal/transport/http/admin/server.go`: `session` middleware → `principal.Principal`; `csrf` middleware
  requires `X-Paddock-CSRF: 1` on mutating requests; the generated binder additionally declares that header as a
  required parameter of every mutating operation). `paddock-server audit verify` exists as a host-side subcommand
  (`server/cmd/paddock-server/auditwriter.go`) and needs the audit DB writer DSN, the audit bucket credentials and
  OpenBao — none of which the `api` role has.
- **Existing patterns to reuse:** secret shown once and stored as SHA-256 (`enrollment_token.secret_sha256`,
  `app.EnrollmentTokens`); cross-organization lookup before an organization context exists only through a
  `SECURITY DEFINER` function (`paddock_org_id_by_slug`, `db.OrgPool.ResolveSlug`); denied authentication recorded with
  `audit.ActorAnonymous` and a system principal (`app.Accounts.recordDenied`); step-up enforced by
  `ActionSpec.RequiresStepUp` / `Recorder.RequireStepUp` (`app.ActionRunner.checkStepUp`: fails for a principal whose
  `StepUpAt` is zero); list contract via `listing.Spec` + `x-paddock-list` + `listspec_test.go`; the privileged route
  table `privileged` in `server.go` checked by `TestOpenAPISpec`; isolation fixtures (`isolation_fixtures.go`) and
  exactly-once cases (`audit_once_test.go`) that enumerate every operation of `api/openapi/admin.yaml`.
- **Compiler:** `compiler.render` skips a device whose rendered content hash equals its latest bundle
  (`metricBundles "unchanged"`). After a PostgreSQL restore devices run bundle versions newer than the restored
  `device.bundle_seq`; the restore rule (§20) bumps `bundle_seq` and then needs a recompile that publishes **even
  unchanged** content, otherwise unchanged devices keep a pointer to a version they already passed.
- **Worker:** `worker.CacheSync.ReconcileAll` rewrites `et:`, `dk:` and `seq:` from PostgreSQL; the compiler's
  `RunReconcile` rewrites `bp:` every 60 s. Both already heal an emptied Valkey.
- **Order of the M6 batch:** M4c.1 (PDK-004) → **M6c (this plan)** → M6a (PDK-005) → M6b (PDK-006) → one combined
  regression (product owner decision 2026-10-07). M6a §2.2 item 7 refers to the restore commands; §5 of this plan
  states how.
- **ADRs touched:** 0011 (Proposed) — this plan realizes the declarative endpoint and records a deviation (§3.2
  decision 12 and §8 open point 3); 0001 (Proposed) — Go CLI confirmed.

## 3. Binding decisions

### 3.1 API tokens (server)
1. **Entity** `api_token`, organization-scoped, migration `server/migrations/paddock/<next free goose number>_api_tokens.sql`
   (forward-only, no Down):
   ```sql
   CREATE TABLE api_token (
     id              uuid PRIMARY KEY,
     organization_id uuid NOT NULL REFERENCES organization(id),
     name            text NOT NULL CHECK (name ~ '^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$'),
     role            text NOT NULL CHECK (role IN ('org_admin', 'org_operator', 'org_auditor')),
     secret_sha256   bytea NOT NULL UNIQUE,
     prefix          text NOT NULL CHECK (char_length(prefix) = 12),
     created_by      uuid NOT NULL REFERENCES admin_account(id),
     created_at      timestamptz NOT NULL DEFAULT now(),
     expires_at      timestamptz NOT NULL,
     last_used_at    timestamptz,
     revoked_at      timestamptz,
     revoked_by      uuid REFERENCES admin_account(id)
   );
   CREATE UNIQUE INDEX api_token_org_name_live_idx ON api_token (organization_id, name) WHERE revoked_at IS NULL;
   CREATE INDEX api_token_org_created_idx ON api_token (organization_id, created_at);
   ALTER TABLE api_token ENABLE ROW LEVEL SECURITY;
   ALTER TABLE api_token FORCE ROW LEVEL SECURITY;
   CREATE POLICY tenant ON api_token TO paddock_api
     USING (organization_id = current_setting('paddock.org_id')::uuid)
     WITH CHECK (organization_id = current_setting('paddock.org_id')::uuid);
   GRANT SELECT, INSERT, UPDATE ON api_token TO paddock_api;

   -- Lookup before an organization context exists (same pattern as paddock_org_id_by_slug). Touches last_used_at at
   -- most once per 60 s and only for a usable token. Returns no row for an inactive organization.
   CREATE FUNCTION paddock_api_token_lookup(p_hash bytea)
     RETURNS TABLE (id uuid, organization_id uuid, name text, role text, created_by uuid, expires_at timestamptz, revoked_at timestamptz)
     LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = public AS $$
   BEGIN
     RETURN QUERY
       UPDATE api_token t SET last_used_at = now()
       FROM organization o
       WHERE t.secret_sha256 = p_hash AND o.id = t.organization_id AND o.status = 'active'
         AND t.revoked_at IS NULL AND t.expires_at > now()
         AND (t.last_used_at IS NULL OR t.last_used_at < now() - interval '60 seconds')
       RETURNING t.id, t.organization_id, t.name, t.role, t.created_by, t.expires_at, t.revoked_at;
     IF NOT FOUND THEN
       RETURN QUERY
         SELECT t.id, t.organization_id, t.name, t.role, t.created_by, t.expires_at, t.revoked_at
         FROM api_token t JOIN organization o ON o.id = t.organization_id
         WHERE t.secret_sha256 = p_hash AND o.status = 'active';
     END IF;
   END $$;
   REVOKE ALL ON FUNCTION paddock_api_token_lookup(bytea) FROM PUBLIC;
   GRANT EXECUTE ON FUNCTION paddock_api_token_lookup(bytea) TO paddock_api;
   ```
   sqlc queries in `server/internal/adapters/postgres/queries/api_token.sql`: `InsertApiToken`, `ListApiTokens`
   (list contract: `q_pattern` over `name`, filter `statuses text[]` computed as
   `CASE WHEN revoked_at IS NOT NULL THEN 'revoked' WHEN expires_at <= now() THEN 'expired' ELSE 'active' END`),
   `GetApiToken`, `RevokeApiToken` (`SET revoked_at = now(), revoked_by = @by WHERE id = @id AND revoked_at IS NULL`),
   `LookupApiToken` (`SELECT * FROM paddock_api_token_lookup(@hash)`).
2. **Secret format** (package `server/internal/domain/apitoken`): `pdk_` + 43 characters base64url without padding of
   32 random bytes (`crypto/rand`) = 47 characters. `prefix` = the first 12 characters (`pdk_` + 8), shown in lists.
   At rest only `secret_sha256 = sha256(secret)`; the secret is returned exactly once in the `201` of the create
   call and never logged, never in audit params (the `app` secret-word guard rejects any param key containing
   `token`; use the keys `name`, `role`, `expires_at`, `prefix`).
   ```go
   package apitoken
   const Prefix = "pdk_"
   func Generate() (secret string, hash []byte, prefix string, err error)
   func Hash(secret string) ([]byte, bool)        // false when the secret has not the expected shape
   func ValidateName(name string) error           // regex of decision 1
   func ValidateExpiry(now, expiresAt time.Time) error // now+1h ≤ expiresAt ≤ now+365d
   func RoleAllowed(creator, requested principal.Role) bool // see decision 3
   ```
3. **Scopes = roles.** A token carries exactly one of the existing organization roles (`org_admin`, `org_operator`,
   `org_auditor`) and is authorized everywhere exactly like a session with that role. Ceiling: `org_admin` creates any
   role; `org_operator` creates `org_operator` or `org_auditor`; `org_auditor` creates nothing (read-only role, §9.6).
   A request above the ceiling is `403 forbidden` (detail `role exceeds the creating administrator's role`), recorded
   as `denied`. Platform-scope tokens are **not** introduced (justification in decision 23).
4. **Step-up for creation.** `SpecAPITokenCreate = ActionSpec{Code: audit.CodeAPITokenCreated, AllowedRoles: RolesWrite,
   RequiresStepUp: true}`. Reason: a token is a long-lived credential that bypasses MFA at every later use; this is the
   same class as reveal and Lock (§9.6, ADR 0014). Consequence by construction: a token principal never has a step-up
   (`StepUpAt` zero), so **a token cannot create tokens** (`403 step_up_required`, recorded as `denied`).
5. **Revocation.** `SpecAPITokenRevoke = ActionSpec{Code: audit.CodeAPITokenRevoked, AllowedRoles: RolesWrite}`.
   `org_admin` revokes any token of the organization; `org_operator` only tokens with `created_by = principal.ID`
   (otherwise `403 forbidden`, denied). A token principal MUST NOT revoke (`403 forbidden`, denied; checked in the use
   case via `principal.APITokenID != uuid.Nil`). Already revoked → `409 invalid_state`. Revocation is effective at
   the next request (lookup reads PostgreSQL on every request; no cache).
6. **Expiry** is required: `expires_at` (RFC 3339) with `now + 1 h ≤ expires_at ≤ now + 365 d`, else
   `400 invalid_request` naming the bound. Expired tokens stay listed with status `expired`.
7. **Principal.** `server/internal/principal/principal.go` gets two fields; no new `Kind`:
   ```go
   // APITokenID and APITokenName are set when the request authenticated with an API token (plan M6c decision 7).
   // The token acts in its organization with Role; ID is the creating administrator's account ID.
   APITokenID   uuid.UUID
   APITokenName string
   ```
   The token principal is `Principal{Kind: KindAdmin, ID: created_by, Display: "<name> (api token)", Role: <token
   role>, OrganizationID: <org>, IP: <client ip>, APITokenID: <id>, APITokenName: <name>}`; `Subject` stays empty,
   `StepUpAt` stays zero.
8. **Audit actor and source.** `server/internal/domain/audit/event.go`: new constants `ActorAPIToken = "api_token"`
   and `SourceAPI = "api"`; `SourceForActor(ActorAPIToken)` returns `SourceAPI` (the audit queue binding `audit.#`
   routes every source). `app.actorOf(p)` returns `Actor{Type: ActorAPIToken, ID: p.APITokenID.String(),
   Display: p.APITokenName, IP: p.IP}` when `p.APITokenID != uuid.Nil`. Every privileged action performed with a
   token is therefore attributed to the token (and, via the token's `created_by`, to the administrator who created
   it) — "scoped, audited" (§17.3).
9. **Bearer authentication** (`server/internal/transport/http/admin/bearer.go`): in `server.session`, when the request
   carries `Authorization: Bearer <secret>` the cookie path is skipped and `h.apiTokens.Authenticate(ctx, secret, ip)`
   runs:
   - malformed secret (not 47 chars, wrong prefix, not base64url) or no row → `401 unauthenticated`; **no audit
     event** (same as an invalid cookie today), `slog` warning without the secret, metric
     `paddock_api_token_auth_total{result="unknown"}`;
   - row found, `revoked_at` set or `expires_at ≤ now` → `401 unauthenticated` (detail `api token revoked` /
     `api token expired`) and exactly one audit event `api_token.use_denied` in the token's organization: system
     principal with that organization, `Actor{Type: ActorAnonymous, Display: <name>, IP}`, params `{name, reason}`
     with `reason ∈ {revoked, expired}`, recorded via `runner.RunTxRefusal(ctx, ScopeOrg, spec, problem.Forbidden, noop)`
     (outcome `denied`); metric result `revoked|expired`;
   - usable → principal of decision 7 in `ctx`, metric result `ok`.
   Bearer requests MUST still send `X-Paddock-CSRF: 1` on mutating requests (the contract declares the header; the
   CLI sends it always). Bearer requests to `/api/platform/...` are refused like any organization principal
   (`403 forbidden`, existing behaviour). Bearer requests to `/api/auth/*` are not possible (outside the session
   middleware).
10. **`GET /api/v1/me` for a token principal** answers from the token without reading `admin_account`: `id` = token
    id, `username` = `display_name` = token name, `role`, `organization` as for a session, `locale: en`, new optional
    object `api_token: {id, name, expires_at}` (absent for sessions). `PATCH /api/v1/me` with a token →
    `403 forbidden`.
11. **Endpoints** (OpenAPI tag `api-tokens`, all under `security: [session]` plus the new scheme `bearer`
    (`type: http, scheme: bearer`) declared in `components.securitySchemes` and added to the global `security`
    list as an alternative; oapi-codegen does not enforce security, the middleware does):
    ```
    GET  /api/v1/api-tokens                 roles: org_admin, org_operator, org_auditor   list contract
         x-paddock-list: { sort: [name, created_at, expires_at, last_used_at], default_sort: name,
                           search: [name], filters: [status] }   status repeatable ∈ active|expired|revoked
         200 ApiTokenPage
    POST /api/v1/api-tokens                 roles: org_admin, org_operator; step-up; x-paddock-audit: api_token.created
         body ApiTokenCreate { name: string, role: org_admin|org_operator|org_auditor, expires_at: date-time }
         201 ApiTokenCreated { token: ApiToken, secret: string }   Location: /api/v1/api-tokens/{id}
         400 invalid_request · 403 forbidden | step_up_required · 409 name_taken
    GET  /api/v1/api-tokens/{id}            roles: read            200 ApiToken · 404 not_found
    POST /api/v1/api-tokens/{id}/revoke     roles: org_admin, org_operator; x-paddock-audit: api_token.revoked
         200 ApiToken · 403 forbidden · 404 not_found · 409 invalid_state
    ApiToken { id, name, prefix, role, status: active|expired|revoked, created_by: { id, display }, created_at,
               expires_at, last_used_at: date-time|null, revoked_at: date-time|null }
    ```
    `created_by.display` is `admin_account.display_name` (join in the list and get queries). Add the four operations
    to `privileged` in `server.go`, to `isolation_fixtures.go`, to `auditCases` in `audit_once_test.go` and the list
    to `listspec_test.go` (`"listApiTokens": {apiTokenList, "postgres/queries/api_token.sql", "ListApiTokens", "id"}`).

### 3.2 Declarative configuration (server)
12. **One write path, two transports.** `PUT /api/v1/config` is the declarative write path for `paddockctl` and for
    CI. The portal keeps its per-resource endpoints (changing every portal form to the document endpoint is out of
    scope). "Same path" (ADR 0011) is realized one layer down: the declarative use case MUST call the same domain
    validation (`loginsettings.Normalize/Validate`, `updates` schedule validation, `privilege` profile and subject
    validation, `app.validateFile`, the unit validation `ManagedConfig.CreateUnit` uses, `app.validateGroup`) and the same `pgstore` insert/update/
    delete queries as the per-resource use cases, inside **one** transaction. Deviation from ADR 0011's literal text
    ("portal forms … use the same endpoints") is recorded as open point 3 for the architecture amendment.
13. **Schema** `api/schema/paddock.v1.json` (JSON Schema draft 2020-12, `$id`
    `https://paddock-mdm.invalid/schema/paddock.v1.json`, `additionalProperties: false` everywhere). Source of truth
    is this file; `server/internal/domain/declarative/paddock.v1.json` and `cli/internal/schema/paddock.v1.json` are
    byte-identical copies produced by `//go:generate cp` directives (run by `make gen`) and guarded by a unit test in
    each module that fails when the copy differs from `api/schema/paddock.v1.json`. The server validates every
    document with `github.com/santhosh-tekuri/jsonschema/v6` (existing dependency) before anything else.
    Document (YAML rendering; the API carries the JSON equivalent):
    ```yaml
    api_version: paddock/v1          # required, const
    kind: OrganizationConfig         # required, const
    settings:                        # optional object
      login:                         # optional; when present ALL fields required (same constraints as PUT /settings/login)
        hello_enabled: true
        hello_pin_min_length: 6
        user_lock_session_action: lock_screen   # lock_screen|terminate
        break_glass_accounts: []
        sudoers_d_allowlist: []
        sudo_lecture_text: "…"
        local_admin_username: paddock-admin
        local_admin_rotation_days: 30
        rotate_after_reveal_hours: null
        notice_text: ""
        boot_pin_min_length: 8
      updates:                       # optional; when present ALL fields required (same constraints as PUT /settings/updates)
        security_daily_at: "03:00"
        regular_schedule: "Sat 04:00"
        regular_updates_enabled: true
        max_random_delay_min: 60
        staleness_warning_h: 24
        staleness_critical_h: 168
    device_groups:                   # optional list; key: name
      - { name: laptops, description: "" }
    permission_profiles:             # optional list; key: name
      - { name: ops, class: restricted, commands: ["/usr/bin/systemctl restart *"], require_password: true,
          timestamp_timeout_min: 5, lecture: once }
    managed_files:                   # optional list; key: (device_group, path)
      - { path: /etc/motd, device_group: null, mode: "0644", owner: root, group: root, content: "…" }
    managed_units:                   # optional list; key: (device_group, unit)
      - { unit: foo.service, device_group: laptops, enabled: true, active: true }
    package_holds:                   # optional list; key: (device_group, package)
      - { package: firefox, version: null, device_group: null, reason: "…" }
    profile_assignments:             # optional list; key: (profile, subject, device_group)
      - { profile: ops, subject: { type: global }, device_group: null }
      - { profile: ops, subject: { type: group, slug: devs }, device_group: laptops }
      - { profile: ops, subject: { type: user, username: alice@example.org }, device_group: null }
    ```
    Field constraints equal the OpenAPI `*Create` schemas of the referenced resources (lengths, patterns, enums);
    `device_group` is a device group **name** or `null`; `profile` is a permission profile name; `subject` is one of
    `{type: global}`, `{type: group, slug}`, `{type: user, username}`. Excluded on purpose (non-goals §4): dead man's
    switch (step-up setting), users and user groups (identity, Authentik side effects), enrollment tokens (secrets),
    devices and device-group membership (device state), login assignments.
14. **Semantics.** A section that is present is authoritative for that section: items not listed are deleted,
    listed items are created or updated to match; absent sections are untouched. Keys are the natural keys of
    decision 13; a renamed key is delete + create. Settings sections are compared field by field. Application order:
    `device_groups` → `permission_profiles` → `managed_files` → `managed_units` → `package_holds` →
    `profile_assignments` → `settings.updates` → `settings.login`; deletions run first in reverse order. Resource
    rules of the per-resource use cases apply unchanged and abort the whole apply with their problem code (for
    example `409 in_use` when a device group still has an enrollment token, `422 path_not_allowed`,
    `422 unit_not_allowed`, `422 invalid_schedule`, `409 already_exists`), with the document path in `detail`
    (`/managed_files/2/path: …`). Creating or changing an assignment of a profile with `class: full` calls
    `rec.RequireStepUp()` exactly as `Privileges.CreateAssignment` does; with a token this is `403 step_up_required`
    and **nothing** is applied (atomic) — the CLI tells the user to make that change in the portal.
15. **Package** `server/internal/domain/declarative`: pure types and the diff, unit-tested with golden files:
    ```go
    type Document struct { APIVersion string `json:"api_version"`; Kind string `json:"kind"`; Settings *Settings `json:"settings,omitempty"`;
        DeviceGroups *[]DeviceGroup `json:"device_groups,omitempty"`; PermissionProfiles *[]PermissionProfile `json:"permission_profiles,omitempty"`;
        ManagedFiles *[]ManagedFile `json:"managed_files,omitempty"`; ManagedUnits *[]ManagedUnit `json:"managed_units,omitempty"`;
        PackageHolds *[]PackageHold `json:"package_holds,omitempty"`; ProfileAssignments *[]ProfileAssignment `json:"profile_assignments,omitempty"` }
    // nil pointer = section absent (untouched); empty slice = section present and empty (delete all).
    func ValidateJSON(raw []byte) error                       // schema validation; *ValidationError lists path+message (max 20)
    func Decode(raw []byte) (Document, error)                 // after ValidateJSON
    type Plan struct { Changes []Change `json:"changes"`; Created, Updated, Deleted int }
    type Change struct { Section string `json:"section"`; Key string `json:"key"`; Action string `json:"action"` /* create|update|delete */;
        Fields []FieldChange `json:"fields"` }
    type FieldChange struct { Name string `json:"name"`; Before any `json:"before"`; After any `json:"after"` }
    func Diff(current, desired Document) Plan                 // deterministic order; managed file content shown as "sha256:<hex> (<n> bytes)"
    ```
16. **Use case** `server/internal/app/declarative.go`, type `app.Declarative`:
    ```go
    func (d *Declarative) Export(ctx context.Context) (declarative.Document, error)                    // RolesRead; every section present
    func (d *Declarative) Plan(ctx context.Context, raw []byte) (declarative.Plan, error)              // RolesWrite; no audit (no change)
    func (d *Declarative) Apply(ctx context.Context, raw []byte) (uuid.UUID, declarative.Plan, error)  // RolesWrite; one RunTx
    ```
    `Apply` runs `runner.RunTx(ctx, ScopeOrg, SpecConfigApply, …)` with `SpecConfigApply = ActionSpec{Code:
    audit.CodeConfigApplied, AllowedRoles: RolesWrite}`: load current state → `Diff` → execute changes in the order
    of decision 14 → insert `change_set` → `rec.SetTarget(Target{Type: "change_set", ID})`,
    `rec.SetParam("change_set_id"|"created"|"updated"|"deleted"|"sections", …)` → `rec.StateChanged(statechange.ScopeOrg,
    org)` once when `len(Changes) > 0`. An empty plan still records one `config.applied` event with zeros and creates
    **no** change set (`change_set_id` null). Request bodies above 1 MiB → `400 invalid_request`.
17. **Change sets.** Migration `<next>_change_sets.sql`:
    ```sql
    CREATE TABLE change_set (
      id              uuid PRIMARY KEY,
      organization_id uuid NOT NULL REFERENCES organization(id),
      applied_at      timestamptz NOT NULL DEFAULT now(),
      actor           jsonb NOT NULL,            -- audit.Actor of the apply
      source          text NOT NULL CHECK (source IN ('session', 'api_token')),
      created_n       int NOT NULL, updated_n int NOT NULL, deleted_n int NOT NULL,
      sections        text[] NOT NULL,
      plan            jsonb NOT NULL             -- declarative.Plan
    );
    CREATE INDEX change_set_org_applied_idx ON change_set (organization_id, applied_at);
    ALTER TABLE change_set ENABLE ROW LEVEL SECURITY; ALTER TABLE change_set FORCE ROW LEVEL SECURITY;
    CREATE POLICY tenant ON change_set TO paddock_api USING (organization_id = current_setting('paddock.org_id')::uuid)
      WITH CHECK (organization_id = current_setting('paddock.org_id')::uuid);
    GRANT SELECT, INSERT ON change_set TO paddock_api;
    ```
    Endpoints (tag `config`):
    ```
    GET /api/v1/change-sets        roles: read; x-paddock-list: { sort: [applied_at], default_sort: -applied_at,
                                   search: [actor_display], filters: [source] }    200 ChangeSetPage
    GET /api/v1/change-sets/{id}   roles: read   200 ChangeSet · 404 not_found
    ChangeSet { id, applied_at, actor: { type, id, display }, source: session|api_token,
                summary: { created, updated, deleted, sections: [string] }, plan: ConfigPlan }
    ```
    (`actor_display` search = `actor->>'display' ILIKE`.)
18. **Endpoints** (tag `config`):
    ```
    GET /api/v1/config                      roles: read     200 ConfigDocument (JSON of decision 13, all sections present)
    PUT /api/v1/config?dry_run={bool}       roles: org_admin, org_operator; x-paddock-audit: config.applied
        body: ConfigDocument (application/json)   dry_run default false
        200 ConfigApplyResult { dry_run: bool, change_set_id: uuid|null, plan: ConfigPlan }
        400 invalid_request · 403 forbidden | step_up_required · 409 in_use | already_exists | invalid_state
        422 invalid_document | path_not_allowed | unit_not_allowed | invalid_schedule
    ConfigPlan { changes: [ { section, key, action: create|update|delete, fields: [ { name, before, after } ] } ],
                 created: int, updated: int, deleted: int }
    ```
    New problem `problem.InvalidDocument = {Code: "invalid_document", Status: 422}`; `detail` lists up to 20
    `path: message` pairs separated by `; `. `x-paddock-audit` is declared on the PUT; the `privileged` table entry is
    `"PUT /api/v1/config": {app.ScopeOrg, app.SpecConfigApply}`. A rejected request (malformed body, CSRF) is
    recorded once by `rejected`, also with `dry_run=true` (the route table cannot see the query parameter; this is
    accepted). The `dry_run=true` success path records no event (decision 16).
19. **Forced recompile.** `statechange.Event` gets `Force bool `json:"force,omitempty"``; `app.Recorder` gets
    `ForcedStateChanged(scope string, id uuid.UUID)`; `compiler.render` publishes a device targeted by at least one
    forced event even when its content hash equals the latest bundle (`metricBundles` label `forced`). Used by
    decision 21 only.

### 3.3 `paddock-server admin` (restore commands, server-side)
20. **Subcommands** in `server/cmd/paddock-server/admin.go`, dispatched from `main.go` (`case "admin"`, usage text
    extended):
    ```
    paddock-server admin bump-bundle-seq --by N      N integer, 1 ≤ N ≤ 1000000000
    paddock-server admin recompile --all
    paddock-server admin rebuild-cache
    ```
    Configuration (env, as every role): `PADDOCK_DB_WORKER_URL_FILE` (OrgPool), `PADDOCK_DB_PLATFORM_URL_FILE`
    (PlatformPool), `PADDOCK_VALKEY_*` via `config.LoadValkey` (rebuild-cache only). In the Compose stack they run as
    `docker compose … run --rm --no-deps paddock-worker admin <subcommand>` (the worker service has exactly these
    variables). Output: one human-readable line on stdout (`bumped bundle_seq of 42 devices by 1000000`,
    `recompile requested for 2 organizations`, `cache rebuilt for 2 organizations`); exit 0/1/2 as `exitCode`.
21. **Behaviour and audit (F7: every privileged action is audited):**
    - `bump-bundle-seq`: migration `<next>_admin_functions.sql` adds
      `CREATE FUNCTION paddock_admin_bump_bundle_seq(p_by bigint) RETURNS bigint LANGUAGE sql VOLATILE SECURITY DEFINER
      SET search_path = public AS $$ WITH u AS (UPDATE device SET bundle_seq = bundle_seq + p_by RETURNING 1) SELECT count(*) FROM u $$;`
      with `EXECUTE` granted to `paddock_platform` only. Recorded as one platform event `platform.bundle_seq_bumped`
      (params `by`, `devices`; actor `Actor{Type: ActorSystem, Display: "paddock-server admin"}`;
      `runner.RunTx(ScopePlatform, …)` with a system principal) in the platform pseudo-organization.
    - `recompile --all`: for every organization (`OrgPool.OrganizationIDs`) one `runner.RunTx(ScopeOrg, Spec{Code:
      organization.recompile_requested, Actor: system "paddock-server admin"})` with a system principal carrying that
      organization that calls `rec.ForcedStateChanged(statechange.ScopeOrg, org)`. One event per organization, visible
      to that organization's auditors. The compiler then publishes a new bundle version for every active device
      (decision 19).
    - `rebuild-cache`: `worker.NewCacheSync(orgPool, devicecache.New(valkeyClient)).ReconcileAll(ctx)` once
      (`et:`, `dk:`, `seq:`); `bp:` and `tt:` are rewritten by the running compiler's reconcile within 60 s (documented).
      Recorded as one platform event `platform.cache_rebuilt` (param `organizations`). No `FLUSHDB`: the restore drill
      starts from fresh Valkey volumes; stale keys of a live Valkey are not a restore scenario.
22. **Restore order** (binding for M6a's runbook): stop `paddock-compiler` → `bump-bundle-seq --by 1000000` →
    start the compiler → `rebuild-cache` → `recompile --all`.
23. **Why server-side, not `paddockctl admin` with a platform token:** (a) the commands need privileges the `api` role
    deliberately lacks (`UPDATE device(bundle_seq)` is compiler-only; cross-organization outbox writes; Valkey writes
    to gateway keys); (b) they run during a restore while `api` may be down and the compiler must be stopped;
    (c) a standing platform-scope bearer token that can bump sequences and rewrite caches would be a high-value
    credential without operational benefit, because a restore already requires host access. Hence **no**
    `paddockctl admin` and **no** platform tokens in M6c. `paddockctl audit verify` is likewise not provided:
    verification needs the audit-domain credentials (audit DB, WORM bucket, OpenBao) that stay on the audit host;
    `paddock-server audit verify` (existing) remains the operator command. Architecture §8.3, §17.1 and §20 wording
    is amended by the main session (open point 4).

### 3.4 `paddockctl` (new module `cli/`)
24. **Module** `cli/` (`module github.com/phischl/paddock-mdm/cli`, `go 1.27.0`, `toolchain go1.27.1`), added to
    `go.work` (`./cli`) and to the module `COPY` lines of `deploy/compose/Dockerfile` (`COPY cli/go.mod cli/go.sum
    cli/`, so the workspace resolves in the image build). Layout: `cli/cmd/paddockctl/main.go`,
    `cli/internal/cfg` (file/env/flag resolution), `cli/internal/client` (HTTP, problem details),
    `cli/internal/cmd` (one file per command), `cli/internal/render` (table, plan text), `cli/internal/schema`
    (embedded copy, decision 13). **Dependencies:** Go standard library and `github.com/oasdiff/yaml v0.1.1`
    (YAML ⇄ JSON; already a direct dependency of `server` and `test/acceptance`; approved by name for `cli`). No
    `cobra`, no `viper`, no other module. Static build: `CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X
    main.version=$(VERSION)"`; Makefile target `paddockctl` builds `bin/paddockctl/{amd64,arm64}/paddockctl`
    (`GOOS=linux`); `lint-go`, `lint-vuln` and `test` pick the module up through `GO_MODULES`.
25. **Configuration** — precedence flags > environment > config file; the token is never in the config file:
    | Source | Key | Meaning |
    | --- | --- | --- |
    | flag `--url` / env `PADDOCK_URL` / file `url` | required | base URL of the admin API, e.g. `https://admin.example.org` (no path) |
    | flag `--token-file` / env `PADDOCK_TOKEN_FILE` / file `token_file` | required | file holding the secret (trailing whitespace trimmed); mode MUST NOT allow group or world access (`mode & 0o077 != 0` → exit 2 `token file … is readable by others`) |
    | flag `--ca-file` / env `PADDOCK_CA_FILE` / file `ca_file` | optional | PEM bundle appended to the system roots (dev stack: `deploy/compose/.secrets/caddy-root.crt`) |
    | flag `--config` | optional | config file path; default `$XDG_CONFIG_HOME/paddockctl/config.yaml`, fallback `$HOME/.config/paddockctl/config.yaml`; a missing default file is not an error |
    HTTP: `net/http`, 60 s timeout, headers `Authorization: Bearer <secret>`, `Accept: application/json`,
    `User-Agent: paddockctl/<version>`, `X-Paddock-CSRF: 1` on PUT/POST. Problem details are printed as
    `error: <code>: <detail> (request <X-Request-Id>)` on stderr.
26. **Commands** (global flags `-o|--output`, `--url`, `--token-file`, `--ca-file`, `--config`):
    ```
    paddockctl version                          prints the version; exit 0
    paddockctl whoami                           GET /api/v1/me → organization slug, role, token name, expires_at
    paddockctl schema                           prints the embedded paddock.v1.json
    paddockctl get config [-o yaml|json]        GET /api/v1/config; default yaml (JSONToYAML); key order as in decision 13
    paddockctl apply -f <file|-> [--dry-run] [--yes] [-o text|json]
        reads YAML or JSON (YAMLToJSON), PUT /api/v1/config?dry_run=true, prints the plan
        (text: one line per change: "+ managed_files /etc/motd", "~ settings.login hello_enabled: false -> true",
         "- package_holds firefox"; then "Plan: 1 to create, 1 to update, 1 to delete");
        --dry-run: stop, exit 0;
        deletions > 0 and no --yes: exit 3 "plan deletes N resources; re-run with --yes" (no prompt, ever);
        otherwise PUT /api/v1/config, prints "Applied change set <id>" (or "No changes" when the plan is empty)
    paddockctl devices list [--page N] [--page-size 10|25|50|100] [--sort hostname|last_contact_at|enrolled_at|state, "-" prefix]
        [-q <text>] [--state <s>]... [--device-group-id <uuid>] [--disk-state <s>]... [-o table|json]
        GET /api/v1/devices with the list contract parameters 1:1; table columns hostname, state, last_contact_at,
        agent_version, applied_bundle_version; footer "page P of ceil(total/page_size) (total N[+])"; json = the envelope unchanged
    ```
    Exit codes: 0 success; 1 API or network error; 2 usage or configuration error; 3 apply refused because of
    deletions without `--yes`. Secrets are never printed, also not in `-o json` of `whoami`.
27. **Documentation:** `docs/operations/api-tokens.md` (model, ceiling, step-up, expiry, revocation, audit codes,
    residual risks) and `docs/operations/paddockctl.md` (install from `bin/paddockctl`, configuration, CI example with
    `apply --dry-run` on pull requests and `apply --yes` on main, exit codes, the restore commands as
    `paddock-server admin …` with the order of decision 22); `examples/paddock.yml` (a complete example that passes
    the schema; the schema unit test validates it). `CHANGELOG.md` *Unreleased → Added*.

### 3.5 Portal
28. **API tokens** page `/api-tokens` (`server/web/src/views/ApiTokens.vue`, nav `nav.apiTokens`, visible to all
    organization roles; create/revoke controls only for `org_admin` and `org_operator`): `DataList` (columns name,
    prefix, role, status chip, created by, created, expires, last used; filters status; search name; sort as the
    contract). *Create* dialog (`components/ApiTokenForm.vue`): name, role select limited by the ceiling of decision 3,
    expiry date (default now + 90 days, max now + 365 days, validation message as the server's); on
    `step_up_required` the dialog uses `lib/stepUp.ts` (`startStepUp('api-token-create', …)`) and resumes once;
    after `201` a dialog shows the secret once with a copy button and the text key `apiTokens.shownOnce`; closing it
    refreshes the list. *Revoke* through `ConfirmDialog` (no name typing; not high-risk). Expired and revoked rows
    are shown muted with their status.
29. **Change sets** page `/change-sets` (`views/ChangeSets.vue`, nav `nav.changeSets`, all roles): `DataList`
    (applied at, actor, source chip, created/updated/deleted counts; filter source; search actor; sort applied_at);
    row action *Details* opens a dialog (`components/ChangeSetPlan.vue`) with a table of the plan (section, key,
    action, field, before, after).
30. **i18n and audit:** keys for both pages in `server/web/src/locales/en.json`; `audit.api_token.created`,
    `audit.api_token.revoked`, `audit.api_token.use_denied`, `audit.config.applied`,
    `audit.organization.recompile_requested`, `audit.platform.bundle_seq_bumped`, `audit.platform.cache_rebuilt`;
    `make gen` regenerates `docs/compliance/audit-codes.md` and `server/web/src/lib/auditCodes.gen.ts`. e2e
    `server/web/e2e/apiTokens.spec.ts`: create (with the TOTP step-up helper of `e2e/auth.ts`), secret shown once and
    absent after reload, revoke via the modal, status chips; axe check on both pages.

### 3.6 Audit codes (closed registry `server/internal/domain/audit/codes.go`)
| Code | Params | Outcomes | Note |
| --- | --- | --- | --- |
| `api_token.created` | name, role, expires_at | success, failure, denied | target `api_token`; the secret is never recorded; denied with `step_up_required` without a fresh step-up, `forbidden` above the creator's role or for a token principal |
| `api_token.revoked` | name, role, created_by | success, failure, denied | denied `forbidden` for an operator revoking another administrator's token or for a token principal |
| `api_token.use_denied` | name, reason | denied | reason `expired` or `revoked`; actor anonymous; unknown secrets are not recorded |
| `config.applied` | change_set_id, created, updated, deleted, sections | success, failure, denied | target `change_set`; dry runs are not recorded; failure carries the refusing resource's problem code |
| `organization.recompile_requested` | organizations_total | success, failure | actor system (`paddock-server admin recompile --all`); one event per organization |
| `platform.bundle_seq_bumped` | by, devices | success, failure | platform pseudo-organization; `paddock-server admin bump-bundle-seq` |
| `platform.cache_rebuilt` | organizations | success, failure | platform pseudo-organization; `paddock-server admin rebuild-cache` |

## 4. Non-goals
Git export (§17.3 worker job) and any Git integration; platform-scope API tokens; `paddockctl admin` and
`paddockctl audit verify` (decision 23); moving portal forms to `PUT /api/v1/config`; DMS, users, user groups,
enrollment tokens, devices, login assignments in `paddock.v1`; token rotation or refresh; per-IP rate limiting of
bearer authentication (256-bit secrets); IDE/YAML language-server integration beyond `paddockctl schema`; Windows
or macOS builds of `paddockctl` (Linux amd64/arm64 only); signed or packaged distribution of `paddockctl` (M6b
decides release artifacts); changes to `agent/`, `pkg/`, `docs/architecture.md`, `docs/adr/`.

## 5. Restore-drill integration (M6a)
M6c is implemented **before** M6a. M6a §2.2 item 7 and `docs/operations/restore.md` MUST use the commands of
decisions 20–22 verbatim in this order:
```
docker compose … stop paddock-compiler
docker compose … run --rm --no-deps paddock-worker admin bump-bundle-seq --by 1000000
docker compose … start paddock-compiler
docker compose … run --rm --no-deps paddock-worker admin rebuild-cache
docker compose … run --rm --no-deps paddock-worker admin recompile --all
```
The M6a implementer amends plan M6a §2.2 item 7 in the step-3 commit with "Amendment 2026-10-08 (architect):
`paddockctl admin …` → `paddock-server admin …` (plan M6c decisions 20–23)". The existing architect note in ticket
PDK-005 says the same. Gate P-3 of M6a observes that devices accept new bundles after the restore, which is exactly
what the forced recompile (decision 19) guarantees.

## 6. Steps
One commit per step; `make lint test` green before each commit; `make gen` after every change to
`api/openapi/admin.yaml`, the sqlc queries, `codes.go` or `api/schema/paddock.v1.json`.
1. **API tokens (server).** Migration, `domain/apitoken`, sqlc queries, `app.APITokens` (`List`, `Get`, `Create`,
   `Revoke`, `Authenticate`), principal fields, actor type and source, audit codes, bearer middleware, `GET /me`
   changes, OpenAPI (schemes, paths, schemas, `x-paddock-list`, `x-paddock-audit`), `privileged` table, fixtures
   (`isolation_fixtures.go`, `audit_once_test.go`, `listspec_test.go`), unit tests (`apitoken`: format, hash,
   expiry window, ceiling), integration tests (`apitokens_integration_test.go`: RLS fail-closed on `api_token`,
   lookup touches `last_used_at` at most once per 60 s, revoked/expired refused), handler tests (bearer path: 401
   without event for unknown, one `use_denied` for expired/revoked, principal fields set, CSRF still required).
   **Gate T1 (acceptance `test/acceptance/api_tokens_test.go`):** alice (org_admin, acme) without step-up → 403
   `step_up_required` + one denied `api_token.created`; with step-up → 201 with a 47-char `pdk_` secret and
   one success event whose params carry no secret; `GET /api/v1/api-tokens/{id}` has no secret; `GET /api/v1/me`
   with the bearer → `api_token.name`, role, acme; an operator creating an `org_admin` token → 403 denied; the
   token calling `POST /api/v1/api-tokens` → 403 `step_up_required`; an `org_auditor` token calling
   `POST /api/v1/device-groups` → 403 and one denied `device_group.created` with `actor.type = api_token`; a token
   with `expires_at = now + 1 h` is accepted while the same with `+ 30 min` is 400; revoke → 200, second revoke → 409,
   a request with the revoked token → 401 and exactly one `api_token.use_denied` (`reason: revoked`); globex
   tokens invisible to acme (isolation gate covers it).
2. **Declarative configuration (server).** `api/schema/paddock.v1.json` + copies + drift tests, `domain/declarative`
   (golden tests: empty diff after export→import, each section create/update/delete, rename = delete+create, file
   content shown as hash), `app.Declarative`, change sets (migration, queries, use case, endpoints), `Force` on
   state changes + compiler change (`compiler_test.go`: forced event publishes unchanged content), OpenAPI,
   fixtures, handler tests (422 `invalid_document` with paths, 1 MiB limit, `dry_run` parsing).
   **Gate T2 (acceptance `declarative_config_test.go`):** `GET /api/v1/config` → `PUT …?dry_run=true` with the same
   document → empty plan and no audit event for the request ID; a document adding a managed file, updating
   `settings.updates.security_daily_at` and omitting an existing package hold → dry run lists `+`, `~`, `-` with
   correct counts; the apply → 200 with `change_set_id`, exactly one `config.applied` (success), the change set
   listed and detailed via `GET /api/v1/change-sets[/{id}]`, the managed file present in
   `GET /api/v1/managed-files`, the hold gone, `GET /api/v1/devices/{id}/effective-config` of an acme device
   containing the file; a document with `mode: "999"` → 422 `invalid_document` naming `/managed_files/0/mode` and
   nothing changed; a document assigning a `class: full` profile, sent with an `org_admin` API token → 403
   `step_up_required`, one denied event, nothing changed; the same via a stepped-up session → 200.
3. **`paddock-server admin`.** `admin.go`, migration with `paddock_admin_bump_bundle_seq`, audit codes, usage text,
   unit tests of argument parsing, integration test of the function (grant only to `paddock_platform`).
   **Gate T4 (acceptance `admin_commands_test.go`, runs the subcommands with `stack.Compose(ctx, nil, "run", "--rm",
   "--no-deps", "paddock-worker", "admin", …)`):** `bump-bundle-seq --by 5` raises `device.bundle_seq` of a seeded
   device by 5 (read through `stack.PaddockOwnerDSN()`) and records `platform.bundle_seq_bumped {by: 5}`;
   `recompile --all` records one `organization.recompile_requested` per organization and within 90 s the seeded
   device has a new bundle version greater than its bumped `bundle_seq` without any configuration change;
   `rebuild-cache` records `platform.cache_rebuilt` and, after `DEL dk:<key_id>` of the seeded device in Valkey, the
   key exists again right after the command.
4. **`paddockctl`.** Module, commands, config resolution, Makefile targets (`paddockctl`; `acceptance` builds
   `bin/paddockctl` and exports `PADDOCK_ACCEPTANCE_PADDOCKCTL=$(CURDIR)/bin/paddockctl`), Dockerfile `COPY`,
   `examples/paddock.yml`, docs. Unit tests: config precedence, token-file mode check, YAML→JSON→YAML round trip of
   `examples/paddock.yml`, plan rendering, exit codes (with `httptest` servers).
   **Gate T3 (acceptance `paddockctl_test.go`, uses the binary from the env variable, `PADDOCK_URL` = `env.AdminURL()`,
   `PADDOCK_CA_FILE` = the Caddy root, a token created as in T1 written to a 0600 file):** `whoami` prints the token
   name and `acme`; `get config` is valid YAML that `apply --dry-run -f -` accepts with an empty plan; `apply --dry-run`
   of a changed file prints the `+` line and exits 0 without a change set; `apply` with a deletion and no `--yes`
   exits 3 and changes nothing; `apply --yes` exits 0, prints the change set id and the resource exists;
   `devices list --page-size 10 -o json` returns the envelope with `page_size: 10`; a wrong secret → exit 1 with
   `unauthenticated`; a 0644 token file → exit 2.
5. **Portal.** Pages, dialogs, nav, i18n, `make gen`, Vitest for the role ceiling in the form and the plan table,
   e2e `apiTokens.spec.ts`. Verified by `make e2e` for the new spec.
6. **Docs and hand-over.** `docs/operations/api-tokens.md`, `docs/operations/paddockctl.md`, `CHANGELOG.md`, note in
   ticket PDK-005 confirmed. **No separate regression; covered by the combined M6 regression after M6b** (product
   owner decision 2026-10-07).

## 7. Acceptance criteria
| # | Given / When / Then | Req. | Observed by |
| --- | --- | --- | --- |
| AC1 | Given an org admin with a fresh step-up, when they create an API token with a role not above their own and an expiry within 365 days, then the secret is shown exactly once in the portal and never again, and the audit log shows `api_token.created` without the secret | §17.3, F7 | Org admin, auditor |
| AC2 | Given an API token, when it is used, then every privileged action it performs is audited with actor type `api_token` and the token's name, and a revoked or expired token is refused with one `api_token.use_denied` event | F7 | Auditor |
| AC3 | Given a token of org A, when it requests any resource of org B, then the answer is 404 `not_found` | F10 | Automated gate |
| AC4 | Given `paddockctl get config`, when the output is applied unchanged, then the plan is empty; when a changed `paddock.yml` is applied, then the diff is shown first, deletions require `--yes`, the change is applied atomically with one `config.applied` event and a change set the auditor can open in the portal, and devices receive the result in their next bundle | ADR 0011, principle 7 | Org admin, auditor, CI operator |
| AC5 | Given a document that violates the schema or needs a step-up (full profile assignment) sent with a token, then nothing is applied and the CLI names the path or the reason | ADR 0011 | CI operator |
| AC6 | Given a restored database with devices ahead of `bundle_seq`, when the operator runs `bump-bundle-seq`, `rebuild-cache` and `recompile --all` in the order of decision 22, then every active device gets a bundle version above its applied version and the three actions appear in the audit log | A11, §20, F7 | Platform operator, auditor |

## 8. Stop conditions, freedoms, risks and open points

**Stop conditions** (report back instead of deciding): the generated strict server cannot bind `PUT /api/v1/config`
with a `dry_run` query parameter together with a JSON body; `github.com/oasdiff/yaml` cannot round-trip
`examples/paddock.yml` (key order or multi-line strings lost in a way the gate T3 detects); the worker role turns out
to lack a grant needed by `recompile --all` or `rebuild-cache` (do not widen grants of another role silently — report);
`santhosh-tekuri/jsonschema/v6` rejects the draft-2020-12 schema; a change outside `cli/`, `server/`, `api/`,
`test/acceptance/`, `examples/`, `docs/operations/`, `docs/plans/M6a-…` (amendment note only), `Makefile`,
`go.work`, `deploy/compose/Dockerfile`, `CHANGELOG.md` would be required; any need for a further dependency;
M0 §11 S2/S6/S7/S8.

**Freedoms of the implementer:** names of internal helpers and test fixtures; the exact text of the plan rendering
beyond the examples given; the table layout of `devices list`; splitting `cli/internal/cmd` into files; whether
`app.APITokens.Authenticate` lives in `app` or a small `transport` helper calls `app` (the lookup query and the audit
recording MUST stay in `app`); the migration numbers (next free goose numbers, in the order api_tokens → change_sets →
admin_functions).

**Risks:** (R1) a token outlives the creator's access rights (the creator is locked or loses the role in Authentik)
— mitigation: `org_admin` revocation, mandatory expiry, documented in `api-tokens.md` as a residual risk; a follow-up
MAY revoke tokens of removed accounts. (R2) section-authoritative semantics delete unlisted items — mitigation:
dry run first, `--yes` required for deletions, CI example shows `--dry-run` on pull requests. (R3) `rejected` records
`config.applied` also for malformed dry-run requests — accepted (one event, outcome failure). (R4) forced recompiles
of large organizations load the compiler — accepted; restore-only.

**Open points (defaults chosen; product owner may override):**
1. Step-up for **every** token creation (decision 4) — default yes.
2. Auditors cannot create tokens; an `org_admin` creates auditor tokens for them (decision 3) — default yes.
3. ADR 0011 amendment: change sets and `PUT /api/v1/config` exist for declarative applies; portal forms keep their
   endpoints and share the use-case layer (decision 12) — architect decision, needs recording in `docs/adr/0011` by
   the main session.
4. Architecture amendments for the main session: §17.1 `POST /api/v1/config:plan` → `PUT /api/v1/config?dry_run=true`
   (CLAUDE.md forbids `:verb`); §8.3 and §20 `paddockctl admin …` → `paddock-server admin …`; §17.3 unchanged.
5. DMS and identity excluded from `paddock.v1` (decision 13) — default yes.
6. Expiry maximum 365 days and minimum 1 hour (decision 6) — default yes.
