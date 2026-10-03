# Implementierungsplan: M0 — Foundations

Status: Ready for implementation · 2026-10-03 · Author: architect
Basis: `docs/architecture.md` v1.2, ADRs 0001–0017 (0003 and 0017 Accepted, all others Proposed — treated as binding for this plan)

Language rule: this plan is binding. **MUST** / **MUST NOT** are requirements, **SHOULD** needs a documented
reason to deviate, **MAY** is a free choice. Anything not covered here and not listed under *Freedoms* is a
stop condition (§11).

---

## 1. Goal

After M0, an operator can start the Paddock control plane and the audit domain locally with one command. Platform
administrators can create organizations, and organization administrators can sign in to the portal through
Authentik, manage device groups and read their organization's audit log. Organization isolation and "exactly one
audit event per privileged action" are enforced and proven by automated acceptance tests, and audit evidence is
stored immutably in RustFS with a signed daily hash chain.

## 2. Context

- The repository currently contains only documentation (`docs/`) and `.claude/agents/architect.md`. There is no
  code, no Git repository, no build tooling. Everything in this plan is created from scratch.
- `test/vms/virtualbox/` may already contain VirtualBox VM scripts created in parallel by another agent. **Do not
  modify anything under `test/vms/`.**
- Relevant architecture decisions (quoted where needed, see §3):
  - ADR 0001 Go for server/agent/CLI — *Proposed*
  - ADR 0002 PostgreSQL + Row-Level Security — *Proposed*
  - ADR 0003 RabbitMQ + Valkey — *Accepted* (product owner: managed equivalents on AWS)
  - ADR 0006 OpenBao Transit — *Proposed*
  - ADR 0007 Authentik organization mapping — *Proposed*
  - ADR 0010 Audit pipeline — *Proposed*
  - ADR 0011 DB as configuration source of truth — *Proposed*
  - ADR 0015 Vue 3 portal with BFF session — *Proposed*
  - ADR 0016 Compose deployment, backup, observability — *Proposed*
  - ADR 0017 RustFS as object store — **Accepted**
- Host tooling verified on the development machine: Go 1.25.6, Docker 29.8, Docker Compose v5.6, GNU make. Node is
  **not** required on the host; the portal is built in a container.

## 3. Binding decisions

1. **Go module layout:** a `go.work` workspace at the repository root with two modules in M0: `pkg`
   (module path `github.com/paddock-mdm/paddock/pkg`) and `server` (`github.com/paddock-mdm/paddock/server`).
   `go 1.25.0` in both `go.mod` files. — Shared code with the future agent lives in `pkg`; the agent will be its own
   module so it never links server dependencies.
2. **One binary, roles as subcommands:** `paddock-server serve api|outbox-relay|audit-writer`,
   `paddock-server migrate paddock|audit`, `paddock-server provision rabbitmq`. — ADR 0001/architecture §3.2.
3. **Configuration** exclusively via environment variables listed in §6.9; every secret is read from a file whose path
   is given in a `*_FILE` variable. Parsing with the standard library only. — No secret ever appears in `docker inspect`.
4. **Persistence:** PostgreSQL 17, access only through `sqlc`-generated code on `pgx/v5`. No ORM. Migrations with
   `goose` (library, embedded SQL files), forward-only. — ADR 0002.
5. **Organization isolation:** every organization-scoped table has `ENABLE` and `FORCE ROW LEVEL SECURITY` and a policy
   on `current_setting('paddock.org_id')::uuid` **without** `missing_ok`. The only way to get a transaction on
   organization data is `db.OrgPool.InOrg(ctx, fn)`, which takes the organization from the authenticated principal in
   `ctx`. — Architecture §5.
6. **Platform scope** uses a **separate PostgreSQL role and connection pool** (`paddock_platform`), never a session
   flag. — A flag can be set by any code path; a role cannot.
7. **Not found and cross-organization access both return 404** with problem code `not_found`.
8. **Audit:** every privileged action goes through `app.ActionRunner` (§6.5), which records exactly one audit event per
   attempt — success, failure or denial — through a transactional outbox. — Architecture §14.3.
9. **Queue:** RabbitMQ with quorum queues and **no plugins** (Amazon MQ compatibility, ADR 0003). M0 declares only the
   audit topology (§6.8). The outbox relay publishes with publisher confirms, `delivery_mode=2`, `mandatory=true` and
   AMQP `message_id` = audit `event_id`. RabbitMQ does not deduplicate; the audit writer is idempotent on `event_id`.
   Valkey is **not** part of M0 (first needed by the device gateway in M2).
10. **Audit domain:** separate Compose file `compose.audit.yaml` with its own PostgreSQL (`audit-postgres`) and RustFS
    (`audit-rustfs`) and the `audit-writer` role. The control plane has only a read-only DB role on the audit index and
    no credential for the audit bucket. — Architecture §4.1.
11. **WORM:** bucket `paddock-audit` created with Object Lock enabled, default retention COMPLIANCE 400 days, plus
    explicit per-object retention. Proven by acceptance test before anything else is built on it (step 3).
12. **Keys:** OpenBao (integrated Raft storage), Transit key `audit-chain` (Ed25519) for the daily manifest signature;
    KV v2 path `secret/paddock/session` for the portal session keys. One AppRole per role. — ADR 0006.
13. **Admin authentication:** OIDC authorization code + PKCE against Authentik application `paddock-portal`, handled by
    the `api` role as BFF. The browser only holds an AES-256-GCM encrypted cookie. — ADR 0015.
14. **Authentik organization mapping** (subset of ADR 0007 needed in M0): on organization creation Paddock creates the
    Authentik groups `paddock:<slug>`, `paddock:<slug>:admins`, `paddock:<slug>:operators`, `paddock:<slug>:auditors`.
    Platform administrators are members of `paddock:platform:admins`.
15. **API contract first:** `api/openapi/admin.yaml` (OpenAPI 3.1 — if `oapi-codegen` cannot process 3.1 constructs,
    write it in the 3.0.3 subset and set `openapi: 3.0.3`) is the source of truth; Go server interfaces generated with
    `oapi-codegen` (strict server, `net/http` standard library router), TypeScript types with `openapi-typescript`.
16. **Errors:** RFC 9457 problem details, `type` = `urn:paddock:problem:<code>`, always with `code` and `instance`
    (= request ID).
17. **Portal:** Vue 3 + TypeScript + Vite + Pinia + Vue Router + PrimeVue; `vue-i18n` with an `intl-messageformat`
    message compiler; only `en` catalog in M0. Built in a container and embedded into the Go binary via `embed`.
18. **Container image:** multi-stage Dockerfile, runtime image `gcr.io/distroless/static-debian12:nonroot`,
    `CGO_ENABLED=0`.
19. **Version pinning rule:** in step 1 every dependency is pinned to the newest stable release of the major line
    stated in §6.10 that is available on the day of implementation (Go modules in `go.mod`, npm in `package-lock.json`,
    container images by tag **and** digest in `deploy/compose/versions.env`). Upgrading later is a separate change.
20. **Development-only weakening** (OpenBao unseal shares stored on disk, Authentik admin flow without MFA for test
    users) is only active when `PADDOCK_ENV=development` and lives in `compose.dev.yaml` / `dev/` directories. Scripts
    MUST refuse to run the weakened path when `PADDOCK_ENV=production`.

## 4. Non-goals

MUST NOT be implemented in M0 (no stubs, no "preparation" code beyond what is listed):

- Device gateway, enrollment, check-in, agent, compiler, bundles, `pkg/protocol` contents (only an empty `pkg/doc.go`).
- RabbitMQ exchanges/queues other than the audit topology; Valkey (service, client, code).
- Authentik device-login applications, lock, users/groups management in Paddock, Himmelblau anything.
- Step-up authentication, revocation, escrow, OpenBao keys other than `audit-chain`.
- Fleet, inventory, updates, profiles.
- Git export of change sets (`change_set` table is not created in M0).
- German or any non-English catalog.
- OpenTelemetry tracing (metrics, health and logs only).
- Helm/Kubernetes manifests.
- Backup tooling (pgBackRest) — M6.
- Any change to `docs/architecture.md`, `docs/adr/`, `docs/reqirements/`, `.claude/`, `test/vms/`.

## 5. Affected files

| Path | Action | Purpose |
| --- | --- | --- |
| `CLAUDE.md` | new | Binding rules for AI-assisted development (content in step 1) |
| `README.md` | new | Quick start (`make dev-secrets`, `make up`, URLs, test accounts) |
| `.gitignore`, `.editorconfig` | new | Ignore `deploy/compose/.secrets/`, `server/web/dist/`, `node_modules/`, `*.out` |
| `go.work` | new | Workspace `./pkg`, `./server` |
| `Makefile` | new | Targets in §6.11 |
| `.golangci.yml` | new | Linters: `govet`, `staticcheck`, `errcheck`, `gosec`, `revive`, `ineffassign`, `unused`, `gocritic`, `bodyclose`, `sqlclosecheck`, `rowserrcheck`, `forbidigo` (forbid `fmt.Print*`, `log.Print*` outside `cmd/`) |
| `.github/workflows/ci.yml` | new | Jobs `lint`, `test`, `web`; `acceptance` on `main` only |
| `pkg/go.mod`, `pkg/doc.go` | new | Empty shared module |
| `server/go.mod` | new | Server module incl. `tool` directives for `sqlc`, `oapi-codegen`, `goose`, `govulncheck` |
| `server/cmd/paddock-server/main.go` | new | Subcommand dispatch |
| `server/internal/config/` | new | Env parsing, `*_FILE` secrets |
| `server/internal/principal/` | new | Principal type and context helpers |
| `server/internal/platform/db/` | new | Pools, `InOrg`, `InPlatform`, `InSystem` |
| `server/internal/platform/mq/` | new | AMQP connection with reconnect, publisher-confirm publisher, consumer helper, topology provisioning |
| `server/internal/platform/bao/` | new | AppRole login, token renewal, Transit sign, KV read |
| `server/internal/platform/objectstore/` | new | S3 client for RustFS (aws-sdk-go-v2) |
| `server/internal/platform/httpx/` | new | Request ID, problem details, logging, recovery middleware |
| `server/internal/domain/organization/`, `devicegroup/`, `audit/` | new | Entities, validation, audit code registry |
| `server/internal/app/` | new | `ActionRunner`, use cases |
| `server/internal/ports/identity.go` | new | `IdentityProvider` port |
| `server/internal/adapters/authentik/` | new | Authentik REST adapter |
| `server/internal/adapters/postgres/` | new | sqlc queries + generated package `pgstore` |
| `server/internal/adapters/auditpg/` | new | sqlc queries + generated package `auditstore` |
| `server/internal/transport/http/admin/` | new | Generated strict server + handlers, BFF auth, static portal |
| `server/internal/outbox/` | new | Relay + reaper |
| `server/internal/auditwriter/` | new | Consumer, index writer, WORM writer, daily sealer |
| `server/migrations/paddock/*.sql`, `server/migrations/audit/*.sql` | new | Schemas (§6.1, §6.2) |
| `server/sqlc.yaml` | new | Two sqlc packages |
| `server/web/` | new | Vue portal |
| `api/openapi/admin.yaml` | new | Admin API contract (§6.6) |
| `deploy/compose/compose.yaml`, `compose.audit.yaml`, `compose.dev.yaml` | new | Stack (§6.8) |
| `deploy/compose/versions.env`, `.env.example` | new | Pinned images, non-secret settings |
| `deploy/compose/Dockerfile` | new | paddock-server image |
| `deploy/compose/caddy/Caddyfile` | new | Reverse proxy |
| `deploy/compose/rabbitmq/rabbitmq.conf`, `deploy/compose/rabbitmq/definitions.json` (generated by `gen-dev-secrets.sh` from a template) | new | vhost `paddock`, users and permissions |
| `deploy/compose/postgres/init/10-roles.sh`, `deploy/compose/audit-postgres/init/10-roles.sh` | new | DB roles |
| `deploy/compose/openbao/config.hcl` | new | OpenBao server config |
| `deploy/compose/authentik/blueprints/paddock-portal.yaml`, `dev/paddock-dev.yaml` | new | Authentik bootstrap |
| `deploy/compose/scripts/gen-dev-secrets.sh`, `openbao-bootstrap.sh`, `rustfs-audit-bootstrap.sh` | new | Bootstrap |
| `docs/operations/openbao.md`, `docs/operations/audit-bucket.md`, `docs/operations/local-dev.md` | new | Runbooks |
| `docs/compliance/audit-codes.md` | new | Generated from `codes.go` (`make gen`) |
| `test/acceptance/` | new | Go module `github.com/paddock-mdm/paddock/test/acceptance`, added to `go.work`; gates in §8 |

**MUST NOT be touched:** `docs/architecture.md`, `docs/adr/**`, `docs/reqirements/**`, `docs/plans/**`, `.claude/**`, `.idea/**`, `test/vms/**`.

## 6. Interfaces and data model

### 6.1 Database `paddock` (cluster `postgres`)

Roles (created by `deploy/compose/postgres/init/10-roles.sh` from secret files, all `LOGIN`, `NOSUPERUSER`,
`NOBYPASSRLS` except `paddock_owner`):

| Role | Purpose | Grants |
| --- | --- | --- |
| `paddock_owner` | Owns schema, runs migrations | owner of database `paddock` and all objects |
| `paddock_api` | `api` role, organization data | `SELECT, INSERT, UPDATE, DELETE` on `admin_account`, `device_group`; `SELECT` on `organization`; `INSERT, SELECT, UPDATE` on `action`; `INSERT` on `outbox`; `EXECUTE` on `paddock_org_id_by_slug` |
| `paddock_platform` | `api` role, platform endpoints only | `SELECT, INSERT, UPDATE` on `organization`, `platform_admin`; `INSERT, SELECT, UPDATE` on `action`; `INSERT` on `outbox` |
| `paddock_relay` | `outbox-relay` role | `SELECT, UPDATE, DELETE` on `outbox`; `SELECT, UPDATE` on `action`; `INSERT` on `outbox` (reaper) |

Migration `server/migrations/paddock/00001_init.sql`:

```sql
-- +goose Up
CREATE TABLE organization (
  id          uuid PRIMARY KEY,
  slug        text NOT NULL UNIQUE CHECK (slug ~ '^[a-z0-9][a-z0-9-]{1,30}[a-z0-9]$' AND slug <> 'platform'),
  name        text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 200),
  status      text NOT NULL CHECK (status IN ('provisioning','active','provisioning_failed','suspended')),
  created_at  timestamptz NOT NULL DEFAULT now(),
  updated_at  timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE organization ENABLE ROW LEVEL SECURITY;
ALTER TABLE organization FORCE ROW LEVEL SECURITY;
CREATE POLICY org_self ON organization TO paddock_api
  USING (id = current_setting('paddock.org_id')::uuid);
CREATE POLICY org_platform ON organization TO paddock_platform USING (true) WITH CHECK (true);

CREATE TABLE platform_admin (
  id            uuid PRIMARY KEY,
  authentik_sub text NOT NULL UNIQUE,
  username      text NOT NULL,
  display_name  text NOT NULL,
  locale        text NOT NULL DEFAULT 'en',
  last_login_at timestamptz
);
-- platform_admin is not organization-scoped; listed in the RLS lint allow list.

CREATE TABLE admin_account (
  id              uuid PRIMARY KEY,
  organization_id uuid NOT NULL REFERENCES organization(id),
  authentik_sub   text NOT NULL UNIQUE,
  username        text NOT NULL,
  display_name    text NOT NULL,
  role            text NOT NULL CHECK (role IN ('org_admin','org_operator','org_auditor')),
  locale          text NOT NULL DEFAULT 'en',
  last_login_at   timestamptz
);

CREATE TABLE device_group (
  id              uuid PRIMARY KEY,
  organization_id uuid NOT NULL REFERENCES organization(id),
  name            text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 100),
  description     text NOT NULL DEFAULT '' CHECK (char_length(description) <= 1000),
  created_at      timestamptz NOT NULL DEFAULT now(),
  updated_at      timestamptz NOT NULL DEFAULT now(),
  UNIQUE (organization_id, name)
);

-- organization_id = '00000000-0000-0000-0000-000000000000' is the platform pseudo-organization (audit only).
CREATE TABLE action (
  id              uuid PRIMARY KEY,           -- equals the audit event_id
  organization_id uuid NOT NULL,              -- no FK: may be the platform pseudo-organization
  code            text NOT NULL,
  status          text NOT NULL CHECK (status IN ('started','finished')),
  outcome         text CHECK (outcome IN ('success','failure','denied','unknown')),
  actor           jsonb NOT NULL,
  target          jsonb,
  params          jsonb NOT NULL DEFAULT '{}',
  error_code      text,
  correlation_id  text NOT NULL,
  started_at      timestamptz NOT NULL,
  finished_at     timestamptz,
  CHECK ((status = 'started' AND outcome IS NULL) OR (status = 'finished' AND outcome IS NOT NULL))
);
CREATE INDEX action_started_idx ON action (started_at) WHERE status = 'started';

CREATE TABLE outbox (
  id              bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  organization_id uuid NOT NULL,
  subject         text NOT NULL,
  msg_id          text NOT NULL UNIQUE,
  payload         jsonb NOT NULL,
  created_at      timestamptz NOT NULL DEFAULT now(),
  published_at    timestamptz
);
CREATE INDEX outbox_unpublished_idx ON outbox (id) WHERE published_at IS NULL;

-- RLS for organization-scoped tables (same pattern for admin_account, device_group, action, outbox)
ALTER TABLE admin_account ENABLE ROW LEVEL SECURITY;  ALTER TABLE admin_account FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON admin_account TO paddock_api
  USING (organization_id = current_setting('paddock.org_id')::uuid)
  WITH CHECK (organization_id = current_setting('paddock.org_id')::uuid);
ALTER TABLE device_group ENABLE ROW LEVEL SECURITY;  ALTER TABLE device_group FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON device_group TO paddock_api
  USING (organization_id = current_setting('paddock.org_id')::uuid)
  WITH CHECK (organization_id = current_setting('paddock.org_id')::uuid);
ALTER TABLE action ENABLE ROW LEVEL SECURITY;  ALTER TABLE action FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON action TO paddock_api
  USING (organization_id = current_setting('paddock.org_id')::uuid)
  WITH CHECK (organization_id = current_setting('paddock.org_id')::uuid);
CREATE POLICY platform ON action TO paddock_platform USING (true) WITH CHECK (true);
CREATE POLICY relay ON action TO paddock_relay USING (true) WITH CHECK (true);
ALTER TABLE outbox ENABLE ROW LEVEL SECURITY;  ALTER TABLE outbox FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON outbox TO paddock_api
  USING (organization_id = current_setting('paddock.org_id')::uuid)
  WITH CHECK (organization_id = current_setting('paddock.org_id')::uuid);
CREATE POLICY platform ON outbox TO paddock_platform USING (true) WITH CHECK (true);
CREATE POLICY relay ON outbox TO paddock_relay USING (true) WITH CHECK (true);

-- Login: map slug to id before an organization context exists.
CREATE FUNCTION paddock_org_id_by_slug(p_slug text) RETURNS uuid
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS
  $$ SELECT id FROM organization WHERE slug = p_slug AND status = 'active' $$;
REVOKE ALL ON FUNCTION paddock_org_id_by_slug(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION paddock_org_id_by_slug(text) TO paddock_api;

-- Wake up the relay.
CREATE FUNCTION outbox_notify() RETURNS trigger LANGUAGE plpgsql AS
  $$ BEGIN PERFORM pg_notify('outbox', ''); RETURN NULL; END $$;
CREATE TRIGGER outbox_notify AFTER INSERT ON outbox FOR EACH STATEMENT EXECUTE FUNCTION outbox_notify();
```

The grants of §6.1 table are part of the same migration (`GRANT ... TO ...`). `-- +goose Down` is empty: migrations
are forward-only.

**RLS lint** (`server/internal/platform/db/rlslint_test.go`, integration test): after migrating, every table in schema
`public` except `{goose_db_version, organization, platform_admin}` MUST have a column `organization_id`, and every table
with that column MUST have `relrowsecurity = true`, `relforcerowsecurity = true` and at least one policy. The test lists
offending tables in its failure message.

### 6.2 Database `paddock_audit` (cluster `audit-postgres`)

Roles: `audit_owner` (migrations), `paddock_audit_writer` (cross-organization writer), `paddock_audit_reader`
(read-only for the `api` role).

Migration `server/migrations/audit/00001_init.sql`:

```sql
-- +goose Up
CREATE TABLE audit_event (
  event_id        uuid NOT NULL,
  organization_id uuid NOT NULL,
  occurred_at     timestamptz NOT NULL,
  recorded_at     timestamptz NOT NULL,
  code            text NOT NULL,
  outcome         text NOT NULL CHECK (outcome IN ('success','failure','denied','unknown')),
  source          text NOT NULL,
  actor           jsonb NOT NULL,
  target          jsonb,
  params          jsonb NOT NULL,
  correlation_id  text NOT NULL,
  object_key      text NOT NULL,
  PRIMARY KEY (event_id, occurred_at)
) PARTITION BY RANGE (occurred_at);
CREATE INDEX audit_event_org_time_idx ON audit_event (organization_id, occurred_at DESC);

CREATE TABLE audit_object (
  object_key      text PRIMARY KEY,
  organization_id uuid NOT NULL,
  day             date NOT NULL,
  event_count     int  NOT NULL,
  sha256          bytea NOT NULL,
  created_at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX audit_object_org_day_idx ON audit_object (organization_id, day);

CREATE TABLE audit_manifest (
  organization_id uuid NOT NULL,
  day             date NOT NULL,
  sha256          bytea NOT NULL,
  prev_sha256     bytea,
  signature       text NOT NULL,          -- OpenBao transit signature string "vault:vN:..."
  key_version     int  NOT NULL,
  object_key      text NOT NULL,
  PRIMARY KEY (organization_id, day)
);

ALTER TABLE audit_event ENABLE ROW LEVEL SECURITY; ALTER TABLE audit_event FORCE ROW LEVEL SECURITY;
CREATE POLICY reader ON audit_event TO paddock_audit_reader
  USING (organization_id = current_setting('paddock.org_id')::uuid);
CREATE POLICY writer ON audit_event TO paddock_audit_writer USING (true) WITH CHECK (true);
-- same ENABLE/FORCE + writer policy for audit_object and audit_manifest; no reader policy on them.

GRANT SELECT ON audit_event TO paddock_audit_reader;
GRANT SELECT, INSERT ON audit_event, audit_object, audit_manifest TO paddock_audit_writer;
-- No UPDATE or DELETE grant to any non-owner role.

CREATE FUNCTION audit_ensure_partition(p_month date) RETURNS void
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  start_ts date := date_trunc('month', p_month)::date;
  end_ts   date := (date_trunc('month', p_month) + interval '1 month')::date;
  part     text := format('audit_event_%s', to_char(start_ts, 'YYYY_MM'));
BEGIN
  EXECUTE format('CREATE TABLE IF NOT EXISTS %I PARTITION OF audit_event FOR VALUES FROM (%L) TO (%L)',
                 part, start_ts, end_ts);
END $$;
REVOKE ALL ON FUNCTION audit_ensure_partition(date) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION audit_ensure_partition(date) TO paddock_audit_writer;
```

### 6.3 Principal and database access

```go
// server/internal/principal/principal.go
package principal

type Kind string
const (
    KindAdmin         Kind = "admin"          // organization administrator (portal)
    KindPlatformAdmin Kind = "platform_admin" // platform administrator (portal)
    KindSystem        Kind = "system"         // background roles
)

type Role string
const (
    RoleOrgAdmin    Role = "org_admin"
    RoleOrgOperator Role = "org_operator"
    RoleOrgAuditor  Role = "org_auditor"
    RolePlatform    Role = "platform_admin"
)

type Principal struct {
    Kind           Kind
    ID             uuid.UUID // admin_account.id or platform_admin.id; uuid.Nil for system
    Subject        string    // Authentik sub; "" for system
    Display        string
    Role           Role      // "" for system
    OrganizationID uuid.UUID // uuid.Nil for platform admins and system
    IP             string
}

func With(ctx context.Context, p Principal) context.Context
func From(ctx context.Context) (Principal, bool)
```

```go
// server/internal/platform/db/db.go
package db

var ErrNoOrganization = errors.New("db: no organization in context")

type OrgPool struct{ /* *pgxpool.Pool for paddock_api */ }
type PlatformPool struct{ /* *pgxpool.Pool for paddock_platform */ }
type RelayPool struct{ /* *pgxpool.Pool for paddock_relay */ }

// InOrg opens a transaction, executes
//   SELECT set_config('paddock.org_id', <principal.OrganizationID>, true)
// and calls fn. Returns ErrNoOrganization if the principal is missing or OrganizationID == uuid.Nil.
// Commits if fn returns nil, otherwise rolls back and returns fn's error unchanged.
func (p *OrgPool) InOrg(ctx context.Context, fn func(ctx context.Context, q *pgstore.Queries) error) error

// InPlatform requires principal.Kind == KindPlatformAdmin or KindSystem; otherwise returns ErrForbiddenScope.
func (p *PlatformPool) InPlatform(ctx context.Context, fn func(ctx context.Context, q *pgstore.Queries) error) error

func (p *RelayPool) InRelay(ctx context.Context, fn func(ctx context.Context, q *pgstore.Queries) error) error

// AuditReader: read-only pool on paddock_audit as paddock_audit_reader, same InOrg semantics.
type AuditReader struct{ /* ... */ }
func (r *AuditReader) InOrg(ctx context.Context, fn func(ctx context.Context, q *auditstore.Queries) error) error
```

Handlers and use cases MUST NOT import `pgxpool` or execute SQL outside these functions (`forbidigo` rule:
`pgxpool\.` forbidden outside `server/internal/platform/db`).

Primary keys are UUIDv7, generated in Go with `uuid.NewV7()`.

### 6.4 Audit event (shared payload)

```go
// server/internal/domain/audit/event.go
package audit

var PlatformOrganizationID = uuid.Nil

type Outcome string // "success" | "failure" | "denied" | "unknown"

type Actor struct {
    Type    string `json:"type"`              // "admin" | "platform_admin" | "system" | "anonymous"
    ID      string `json:"id,omitempty"`
    Display string `json:"display,omitempty"`
    IP      string `json:"ip,omitempty"`
    StepUp  bool   `json:"step_up"`
}
type Target struct {
    Type    string `json:"type"`              // "organization" | "device_group" | "admin_account"
    ID      string `json:"id"`
    Display string `json:"display,omitempty"`
}

type Event struct {
    Schema         string         `json:"schema"`          // always "paddock.audit.v1"
    EventID        uuid.UUID      `json:"event_id"`
    OrganizationID uuid.UUID      `json:"organization_id"`
    OccurredAt     time.Time      `json:"occurred_at"`     // UTC, millisecond precision
    RecordedAt     time.Time      `json:"recorded_at"`     // set by audit-writer
    Code           Code           `json:"code"`
    Outcome        Outcome        `json:"outcome"`
    Actor          Actor          `json:"actor"`
    Target         *Target        `json:"target,omitempty"`
    Source         string         `json:"source"`          // "portal" | "platform" | "system"
    Params         map[string]any `json:"params"`          // never nil; {} when empty
    ErrorCode      string         `json:"error_code,omitempty"`
    CorrelationID  string         `json:"correlation_id"`
}
```

Closed code registry `server/internal/domain/audit/codes.go`:

| Code | Emitted by | Organization of the event |
| --- | --- | --- |
| `admin.login` | BFF callback (success, denied) | admin's organization; platform pseudo-org for platform admins and for denied logins without a resolvable organization |
| `organization.created` | platform API | the new organization |
| `device_group.created` / `device_group.updated` / `device_group.deleted` | admin API | caller's organization |
| `action.finalized_unknown` | reaper | organization of the stuck action (the reaper finalizes the original action with `outcome=unknown`; it emits the event under the **original** action code, see §6.5 — this registry entry exists only for the reaper's own metric label and MUST NOT be emitted as a separate event) |

`make gen` renders `docs/compliance/audit-codes.md` from the registry (code, description, params, possible outcomes).

### 6.5 ActionRunner — exactly one audit event per privileged action

```go
// server/internal/app/action.go
package app

type ActionSpec struct {
    Code         audit.Code
    AllowedRoles []principal.Role     // empty = any authenticated admin
    Target       *audit.Target        // MAY be completed by the callback via rec.SetTarget
    Params       map[string]any       // MUST NOT contain secrets
}

type Recorder interface {
    SetTarget(t audit.Target)
    SetParam(key string, value any)
    SetOrganization(id uuid.UUID) // platform actions only, e.g. organization.created
}

// RunTx: pure database actions. fn runs inside the scope's transaction.
//  - authorization check first; on failure: record outcome=denied, return ErrForbidden.
//  - success: in the SAME transaction insert action(status=finished, outcome=success) + outbox row; commit.
//  - fn error or commit error: rollback, then in a NEW transaction insert action(finished, outcome=failure|denied,
//    error_code=<problem code>) + outbox row. The original error is returned.
func (r *ActionRunner) RunTx(ctx context.Context, scope Scope, spec ActionSpec,
    fn func(ctx context.Context, q *pgstore.Queries, rec Recorder) error) error

// RunExternal: actions with side effects outside PostgreSQL.
//  tx1: insert action(status=started); commit.
//  prepare(ctx, q, rec) runs inside tx1 (e.g. insert organization with status=provisioning).
//  external(ctx) runs outside any transaction.
//  tx2: finalize(ctx, q, rec, externalErr) + update action to finished with outcome + outbox row; commit.
func (r *ActionRunner) RunExternal(ctx context.Context, scope Scope, spec ActionSpec,
    prepare func(ctx context.Context, q *pgstore.Queries, rec Recorder) error,
    external func(ctx context.Context) error,
    finalize func(ctx context.Context, q *pgstore.Queries, rec Recorder, externalErr error) error) error

type Scope int
const (
    ScopeOrg Scope = iota      // OrgPool.InOrg
    ScopePlatform              // PlatformPool.InPlatform
)
```

Rules:

- Error → outcome mapping: `ErrForbidden` → `denied`; every other error → `failure` with `error_code` = problem code
  (§6.6). `context.Canceled` → `failure` with `error_code = "canceled"`.
- Outbox row: `subject = "audit.<organization_id>.<source>"`, `msg_id = event_id`, `payload` = `audit.Event` JSON
  without `recorded_at`.
- `event_id` = `action.id` = UUIDv7 generated before anything else.
- `correlation_id` = request ID from `httpx` middleware.
- **Reaper** (in `outbox-relay` role, every 60 s): `action` rows with `status='started' AND started_at < now() - interval
  '10 minutes'` are updated to `finished/unknown` and get an outbox row with the original `code`, `outcome=unknown`,
  `error_code="reaped"`, in one transaction per row.
- Unauthenticated requests (401) are not privileged actions and produce no audit event (logged only).
- Use cases MUST NOT write to `action` or `outbox` directly; only the runner does (`forbidigo`: generated query names
  `InsertAction`, `FinishAction`, `InsertOutbox` may only be called from `server/internal/app/action.go` and
  `server/internal/outbox/`).

### 6.6 Admin API (`api/openapi/admin.yaml`)

All paths below `https://admin.<domain>`. JSON only. Mutating requests require header `X-Paddock-CSRF: 1`
(otherwise 403 `csrf_missing`). Every operation that is a privileged action carries the extension
`x-paddock-audit: <code>`; the acceptance test uses it (§8).

| Method | Path | Roles | Success | Errors | Audit |
| --- | --- | --- | --- | --- | --- |
| GET | `/api/auth/login?return_to=` | public | 302 to Authentik | 400 | – |
| GET | `/api/auth/callback?code&state` | public | 302 to `return_to` (default `/`) | 302 to `/login-denied?reason=<code>` | `admin.login` |
| POST | `/api/auth/logout` | any session | 200 `{end_session_url}` | 401 | – |
| GET | `/api/v1/me` | any session | 200 `Me` | 401 | – |
| PATCH | `/api/v1/me` | any session | 200 `Me` (body `{locale}`; allowed: `en`) | 400, 401 | – |
| GET | `/api/v1/device-groups?cursor&limit` | org_admin, org_operator, org_auditor | 200 `DeviceGroupPage` | 401, 403 | – |
| POST | `/api/v1/device-groups` | org_admin, org_operator | 201 `DeviceGroup` + `Location` | 400, 401, 403, 409 `name_taken` | `device_group.created` |
| GET | `/api/v1/device-groups/{id}` | org_admin, org_operator, org_auditor | 200 | 401, 403, 404 | – |
| PATCH | `/api/v1/device-groups/{id}` | org_admin, org_operator | 200 | 400, 401, 403, 404, 409 | `device_group.updated` |
| DELETE | `/api/v1/device-groups/{id}` | org_admin | 204 | 401, 403, 404 | `device_group.deleted` |
| GET | `/api/v1/audit-events?from&to&code&cursor&limit` | org_admin, org_auditor | 200 `AuditEventPage` | 400, 401, 403 | – |
| GET | `/api/platform/v1/organizations?cursor&limit` | platform_admin | 200 `OrganizationPage` | 401, 403 | – |
| POST | `/api/platform/v1/organizations` | platform_admin | 201 `Organization`; 200 when re-provisioning a `provisioning_failed` organization with the same slug | 400, 401, 403, 409 `slug_taken`, 502 `upstream_unavailable` | `organization.created` |
| GET | `/api/platform/v1/organizations/{id}` | platform_admin | 200 | 401, 403, 404 | – |

- Platform admins calling `/api/v1/*` (except `/me`) get 403 `no_organization`. Organization admins calling
  `/api/platform/*` get 403 `forbidden`.
- Pagination: `limit` 1–200 (default 50); opaque `cursor` = base64url of the last UUIDv7; ordering by `id DESC` (audit:
  `occurred_at DESC, event_id DESC`).
- `audit-events`: `from`/`to` RFC 3339, default last 7 days, max range 92 days (400 `range_too_large`).

Schemas (OpenAPI components, shown as TypeScript for brevity — field names and types are binding):

```ts
type Me = { id: string; username: string; display_name: string; role: 'org_admin'|'org_operator'|'org_auditor'|'platform_admin';
            organization: { id: string; slug: string; name: string } | null; locale: 'en' };
type DeviceGroup = { id: string; name: string; description: string; created_at: string; updated_at: string };
type DeviceGroupCreate = { name: string; description?: string };      // name 1–100, description ≤ 1000
type DeviceGroupUpdate = { name?: string; description?: string };
type DeviceGroupPage = { items: DeviceGroup[]; next_cursor: string | null };
type Organization = { id: string; slug: string; name: string; status: 'provisioning'|'active'|'provisioning_failed'|'suspended'; created_at: string };
type OrganizationCreate = { slug: string; name: string };              // slug regex as in §6.1
type OrganizationPage = { items: Organization[]; next_cursor: string | null };
type AuditEvent = { event_id: string; occurred_at: string; recorded_at: string; code: string;
                    outcome: 'success'|'failure'|'denied'|'unknown'; source: string;
                    actor: { type: string; id?: string; display?: string; ip?: string; step_up: boolean };
                    target: { type: string; id: string; display?: string } | null;
                    params: Record<string, unknown>; error_code?: string; correlation_id: string };
type AuditEventPage = { items: AuditEvent[]; next_cursor: string | null };
type Problem = { type: string; title: string; status: number; code: string; detail?: string; instance: string };
```

Problem codes in M0: `invalid_request` (400), `range_too_large` (400), `unauthenticated` (401), `forbidden` (403),
`no_organization` (403), `csrf_missing` (403), `not_found` (404), `name_taken` (409), `slug_taken` (409),
`upstream_unavailable` (502), `internal` (500).

### 6.7 BFF session and login

- `GET /api/auth/login`: creates `state` (32 random bytes), PKCE verifier (S256) and `nonce`; stores them in cookie
  `paddock_login` (AES-256-GCM, `HttpOnly; Secure; SameSite=Lax; Path=/api/auth; Max-Age=600`) and redirects to the
  Authentik authorization endpoint with `scope=openid profile email groups`. `return_to` MUST be a relative path
  starting with `/` and not `//` (else 400).
- `GET /api/auth/callback`: verifies `state`, exchanges the code (client secret + PKCE), verifies the ID token with
  `go-oidc` (issuer, audience, nonce, expiry). Reads the `groups` claim (Authentik property mapping in the blueprint,
  §6.8). Determines the role:
  - membership of `paddock:platform:admins` → platform admin;
  - otherwise all groups matching `^paddock:([a-z0-9-]{3,32}):(admins|operators|auditors)$`; exactly **one** match
    required → `org_admin` / `org_operator` / `org_auditor` of that slug, organization resolved via
    `paddock_org_id_by_slug` (must be `active`);
  - zero matches, more than one match, platform + organization membership, or unknown/inactive slug → denied:
    redirect `/login-denied?reason=not_authorized`, audit `admin.login` outcome `denied` (organization = resolved
    organization if exactly one slug resolves, else platform pseudo-organization).
  - On success upsert `admin_account` (inside `InOrg`) or `platform_admin` (inside `InPlatform`) by `authentik_sub`,
    set `last_login_at`, emit `admin.login` success through `ActionRunner.RunTx`. The callback puts the resolved
    `principal.Principal` into `ctx` **before** calling the runner (`InOrg` reads the organization from it). A new
    `admin_account` gets its ID (UUIDv7) generated in the callback before the principal is built.
  - Denied logins are recorded with `ActionRunner.RunTx` using a `KindSystem` principal and `ScopePlatform` when no
    organization resolves, or a `KindSystem` principal carrying the resolved `OrganizationID` and `ScopeOrg` when exactly
    one does; the actor in the event is `{type:"anonymous", display:<preferred_username from the ID token>, ip}`.
- Session cookie `paddock_session`: AES-256-GCM (key from OpenBao KV `secret/paddock/session` field `current`; field
  `previous` accepted for decryption), payload JSON
  `{v:1, sub, pid, kind, role, org, disp, loc, iat, exp, idle}`; `HttpOnly; Secure; SameSite=Strict; Path=/`.
  Absolute lifetime 8 h, idle timeout 30 min; the cookie is re-issued when more than 5 min passed since `idle` was set.
- The session middleware turns a valid cookie into a `principal.Principal` in `ctx`. Role and organization come only
  from the cookie, which is set only by the callback.
- Logout clears the cookie and returns the Authentik `end_session_endpoint` URL with `id_token_hint` omitted and
  `post_logout_redirect_uri=https://admin.<domain>/`.
- Session keys are reloaded from OpenBao every 10 min.

### 6.8 Compose stack

Hostnames (dev, port `PADDOCK_HTTPS_PORT`, default `8443`; all resolve to 127.0.0.1 because of the `.localhost` TLD):
`admin.paddock.localhost` → `api:8080`, `auth.paddock.localhost` → `authentik-server:9000`. Caddy uses its internal CA
(`tls internal`); the CA root certificate is exported to `deploy/compose/.secrets/caddy-root.crt` by a one-shot
service and mounted into `api` (env `SSL_CERT_FILE`). Caddy gets the network aliases `admin.paddock.localhost` and
`auth.paddock.localhost` on network `cp`, so containers reach Authentik through the same URL as the browser.

`compose.yaml` (control plane, network `cp`):

| Service | Image (pin in `versions.env`) | Notes |
| --- | --- | --- |
| `caddy` | `caddy:2` | ports `${PADDOCK_HTTPS_PORT}:443` |
| `postgres` | `postgres:17` | DB `paddock`, init script creates roles |
| `rabbitmq` | `rabbitmq:4-management` (newest 4.x; the management UI is bound to `127.0.0.1` only in `compose.dev.yaml`) | vhost `paddock`; no plugins besides `rabbitmq_management`; users and permissions (configure / write / read regex): `provisioner` (`.*`/`.*`/`.*`), `relay` (`^$` / `^paddock\.audit$` / `^$`), `audit_writer` (`^$` / `^$` / `^audit\.writer$`); default `guest` user removed |
| `openbao` | `openbao/openbao:2` (Docker Hub; if unavailable `quay.io/openbao/openbao:2`) | `server -config=/openbao/config/config.hcl`, Raft storage on volume, `disable_mlock = true` only in `compose.dev.yaml` |
| `authentik-postgres` | `postgres:17` | Authentik's own DB |
| `authentik-server`, `authentik-worker` | `ghcr.io/goauthentik/server` (newest stable `YYYY.N`) | blueprints mounted at `/blueprints/paddock`; add a Redis service **only** if the pinned release notes require Redis |
| `paddock-migrate` | paddock image | one-shot: `migrate paddock`, then `provision rabbitmq` |
| `paddock-api` | paddock image | `serve api`; connected to networks `cp` and `audit-index` |
| `paddock-outbox-relay` | paddock image | `serve outbox-relay` |

`compose.audit.yaml` (audit domain, networks `audit-index`, `audit-store`; `audit-writer` additionally on `cp` for RabbitMQ and OpenBao):

| Service | Image | Notes |
| --- | --- | --- |
| `audit-postgres` | `postgres:17` | DB `paddock_audit` |
| `audit-rustfs` | `rustfs/rustfs:1` (≥ 1.0.0) | on `audit-store` only; volume `audit-rustfs-data` |
| `paddock-audit-migrate` | paddock image | one-shot `migrate audit` |
| `paddock-audit-writer` | paddock image | `serve audit-writer` |

`compose.dev.yaml`: dev blueprint mount, `PADDOCK_ENV=development`, OpenBao `disable_mlock`, host port mapping
`127.0.0.1:9001→audit-rustfs:9000` (for the WORM test), `127.0.0.1:5432→postgres`, `127.0.0.1:5433→audit-postgres`,
`127.0.0.1:5672→rabbitmq`, `127.0.0.1:15672→rabbitmq` (management UI), `127.0.0.1:8200→openbao`.

Every service has a `healthcheck`; `paddock-*` services use `paddock-server healthcheck` (HTTP GET on
`/readyz`). Every container runs as non-root where the image allows, with `read_only: true` for paddock services.

Bootstrap scripts:

- `gen-dev-secrets.sh`: creates `deploy/compose/.secrets/` with random values (≥ 32 bytes, base64url) for all DB role
  passwords, `authentik_secret_key`, `authentik_bootstrap_token`, `authentik_bootstrap_password`,
  `oidc_client_secret`, `rustfs_audit_root_user/password`, `rustfs_audit_writer_access_key/secret_key`,
  RabbitMQ user passwords, dev test-user passwords. Idempotent: never overwrites existing files.
- `openbao-bootstrap.sh` (`make bao-bootstrap`): in `development` initializes OpenBao (5 shares, threshold 3), stores
  shares and root token in `.secrets/openbao/` (dev only), unseals, enables `transit/` and `secret/` (kv-v2), creates
  key `audit-chain` (`type=ed25519`, `exportable=false`, `allow_plaintext_backup=false`), writes
  `secret/paddock/session` with `current`/`previous` (32 random bytes each, base64), creates policies and AppRoles:

  | AppRole | Policy |
  | --- | --- |
  | `paddock-api` | `read` on `secret/data/paddock/session` |
  | `paddock-audit-writer` | `update` on `transit/sign/audit-chain`; `read` on `transit/keys/audit-chain` |

  writes `role_id`/`secret_id` to `.secrets/approle/<name>/`. In `production` the script refuses and points to
  `docs/operations/openbao.md`.
- `rustfs-audit-bootstrap.sh` (`make audit-bootstrap`): creates bucket `paddock-audit` with Object Lock enabled
  (`CreateBucket` + `ObjectLockEnabledForBucket`), sets default retention `COMPLIANCE` / 400 days, creates the writer
  user with a policy allowing only `s3:PutObject`, `s3:PutObjectRetention`, `s3:GetObject`, `s3:ListBucket`,
  `s3:GetObjectRetention` on that bucket. Uses the AWS CLI container `amazon/aws-cli:2` for S3 calls and the RustFS
  admin API/CLI for the user and policy. Refuses to run when the bucket exists without Object Lock.

Authentik blueprint `paddock-portal.yaml` (production and dev): OAuth2 provider `paddock-portal` (confidential,
client ID `paddock-portal`, secret from `!Env PADDOCK_OIDC_CLIENT_SECRET`, redirect URI
`https://admin.${domain}:${port}/api/auth/callback` from env, signing key = default certificate, include claims in ID
token), scope mapping `groups` (expression returns `[g.name for g in request.user.ak_groups.all()]`), application
`paddock-portal` with an expression policy binding "user is member of any group whose name starts with `paddock:`",
group `paddock:platform:admins`, flow `paddock-admin-login` (identification → password → authenticator validation
WebAuthn/TOTP with `not_configured_action: configure`) bound as the provider's authentication flow, service account
`paddock-service` with an API token (key from `!Env PADDOCK_AUTHENTIK_TOKEN`) and permissions to view/add groups.
Dev blueprint `dev/paddock-dev.yaml`: users `platform-admin@paddock.test`, `alice@acme.test`, `bob@acme.test`,
`carol@globex.test` (passwords from env), and rebinding of the admin flow without the authenticator validation stage.

### 6.9 Environment variables (`paddock-server`)

| Variable | Roles | Example / default |
| --- | --- | --- |
| `PADDOCK_ENV` | all | `production` (default) \| `development` |
| `PADDOCK_LOG_LEVEL` | all | `info` |
| `PADDOCK_HTTP_ADDR` | api | `:8080` |
| `PADDOCK_OPS_ADDR` | all | `:9090` (`/healthz`, `/readyz`, `/metrics`) |
| `PADDOCK_PUBLIC_ADMIN_URL` | api | `https://admin.paddock.localhost:8443` |
| `PADDOCK_DB_URL_FILE` | api, migrate paddock | DSN for `paddock_api` (migrate: `PADDOCK_DB_OWNER_URL_FILE`) |
| `PADDOCK_DB_PLATFORM_URL_FILE` | api | DSN for `paddock_platform` |
| `PADDOCK_DB_RELAY_URL_FILE` | outbox-relay | DSN for `paddock_relay` |
| `PADDOCK_AUDIT_DB_READER_URL_FILE` | api | DSN for `paddock_audit_reader` |
| `PADDOCK_AUDIT_DB_WRITER_URL_FILE` | audit-writer | DSN for `paddock_audit_writer` (migrate audit: `PADDOCK_AUDIT_DB_OWNER_URL_FILE`) |
| `PADDOCK_AMQP_URL`, `PADDOCK_AMQP_USER`, `PADDOCK_AMQP_PASSWORD_FILE` | relay, audit-writer, provision | `amqp://rabbitmq:5672/paddock` (`amqps://` in production) |
| `PADDOCK_OPENBAO_ADDR`, `PADDOCK_OPENBAO_ROLE_ID_FILE`, `PADDOCK_OPENBAO_SECRET_ID_FILE` | api, audit-writer | `http://openbao:8200` |
| `PADDOCK_OIDC_ISSUER`, `PADDOCK_OIDC_CLIENT_ID`, `PADDOCK_OIDC_CLIENT_SECRET_FILE` | api | `https://auth.paddock.localhost:8443/application/o/paddock-portal/` |
| `PADDOCK_AUTHENTIK_URL`, `PADDOCK_AUTHENTIK_TOKEN_FILE` | api | `https://auth.paddock.localhost:8443` |
| `PADDOCK_AUDIT_S3_ENDPOINT`, `PADDOCK_AUDIT_S3_ACCESS_KEY_FILE`, `PADDOCK_AUDIT_S3_SECRET_KEY_FILE` | audit-writer | `http://audit-rustfs:9000` |
| `PADDOCK_AUDIT_S3_BUCKET` | audit-writer | `paddock-audit` |
| `PADDOCK_AUDIT_RETENTION_DAYS` | audit-writer | `400` (minimum 1; values below the bucket default are rejected at startup) |

Missing required variables → process exits with code 2 and one log line listing all missing names.

### 6.10 Dependencies (major lines; exact versions per decision 19)

Go (`server`): `github.com/jackc/pgx/v5`, `github.com/pressly/goose/v3`, `github.com/google/uuid` (v1, UUIDv7),
`github.com/rabbitmq/amqp091-go` (v1), `github.com/openbao/openbao/api/v2`,
`github.com/aws/aws-sdk-go-v2` (+ `config`, `credentials`, `service/s3`), `github.com/coreos/go-oidc/v3`,
`golang.org/x/oauth2`, `github.com/oapi-codegen/runtime`, `github.com/getkin/kin-openapi`,
`github.com/prometheus/client_golang`, `github.com/klauspost/compress` (zstd), `github.com/gowebpki/jcs` (RFC 8785).
Tools via `tool` directive: `github.com/sqlc-dev/sqlc/cmd/sqlc`, `github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen`,
`golang.org/x/vuln/cmd/govulncheck`. Linter: container image `golangci/golangci-lint:v2`.
Tests: `github.com/testcontainers/testcontainers-go` (+ `modules/postgres`), `github.com/google/go-cmp`.
No other Go dependency without stop (§11).

npm (`server/web`, Node 24 LTS in the build container): `vue@3`, `vue-router@4`, `pinia@3`, `vue-i18n@11`,
`intl-messageformat@10`, `primevue@4`, `@primevue/themes@4`, `openapi-fetch@0`, dev: `vite@7`, `typescript@5`,
`vue-tsc@3`, `@vitejs/plugin-vue@6`, `openapi-typescript@7`, `vitest@3`, `@vue/test-utils@2`, `jsdom`,
`eslint@9`, `eslint-plugin-vue@10`, `@intlify/eslint-plugin-vue-i18n@4`, `@playwright/test@1`, `@axe-core/playwright@4`.
If a stated major does not exist or has been superseded as "latest" by a newer major, use the newest major and note it
in the report; this is not a stop condition.

### 6.11 Makefile targets

`gen` (sqlc, oapi-codegen, openapi-typescript, audit-codes doc), `lint` (golangci-lint, `go vet`, eslint, vue-tsc,
OpenAPI lint via `kin-openapi` validation test), `test` (unit + integration, requires Docker), `web` (containerized
portal build into `server/web/dist`), `image`, `dev-secrets`, `up` (all three compose files), `down`, `bao-bootstrap`,
`audit-bootstrap`, `acceptance` (requires `make up`; optional `T=<regex>`), `e2e` (Playwright in container against
the running stack), `ci` (= `lint test web`).

## 7. Implementation steps

Every step leaves a buildable, testable state. Run `make lint test` at the end of every step from step 4 on.

1. **Skeleton and rules**
   - **Do:** create root files (§5 rows `CLAUDE.md` … `pkg/doc.go`, `server/go.mod`, `server/cmd/paddock-server/main.go`
     with subcommands that print "not implemented" and exit 1, `.golangci.yml`, `Makefile`, CI workflow). Pin versions
     per decision 19. `CLAUDE.md` contains, as imperative rules: the agent design contract (concept "Design contract"
     1–10, quoted), the four protected areas, organization isolation rules (§3 items 5–7 of this plan), "audit events
     are never translated or rewritten", "every privileged action goes through ActionRunner", "acceptance gates are the
     definition of done", two-person rule for `agent/internal/revoke/`, "English for code, comments, commits, docs",
     "no new dependency without architect approval", and a pointer to `docs/architecture.md` and `docs/adr/`.
   - **Result:** `go build ./...` succeeds in the workspace; `make lint` passes.
   - **Check:** `make lint && go build ./... && ./paddock-server serve api; test $? -eq 1`.
   - **Git:** `git init -b main`; the first commit contains everything that exists in the repository at that point
     **except** `test/vms/` (another agent works there; it is committed separately later), so
     do not stage it. Every later step ends with a commit of that step's files.

2. **Compose infrastructure without Paddock services**
   - **Do:** compose files, Caddyfile, RabbitMQ config, OpenBao config, Postgres init scripts, Authentik blueprints,
     bootstrap scripts, `versions.env`, `.env.example`, `docs/operations/local-dev.md`. Paddock services are defined but
     behind the Compose profile `paddock` so `make up` without them works in this step.
   - **Result:** `make dev-secrets && make up && make bao-bootstrap && make audit-bootstrap` yields all infrastructure
     containers healthy; Authentik login page reachable; OpenBao unsealed with key `audit-chain`.
   - **Check:** `docker compose ... ps --format json` shows all services `healthy`;
     `curl -sfk https://auth.paddock.localhost:8443/-/health/ready/`; `bao read transit/keys/audit-chain` shows
     `type ed25519`; `aws s3api get-object-lock-configuration --bucket paddock-audit` shows `COMPLIANCE`/400 days.

3. **WORM gate first**
   - **Do:** create module `test/acceptance` (add to `go.work`) with `worm_test.go` (§8, test A1).
   - **Result:** the gate is green against the pinned RustFS.
   - **Check:** `make acceptance T=TestWORM`. **If it fails → stop condition S1.**

4. **Migrations, roles, database layer**
   - **Do:** §6.1, §6.2 migrations; `migrate paddock|audit` subcommands; `platform/db` with `InOrg`, `InPlatform`,
     `InRelay`, `AuditReader`; sqlc configuration and initial queries for all tables; `principal` package.
   - **Result:** `paddock-migrate` and `paddock-audit-migrate` run in Compose; integration tests pass.
   - **Check:** `make test` including: RLS lint; `InOrg` without principal returns `ErrNoOrganization`; raw query on
     `device_group` as `paddock_api` without `set_config` fails with an error (fail closed); org A transaction cannot
     read, update or delete org B rows (0 rows affected); `paddock_api` cannot `SELECT` from `outbox`;
     `paddock_audit_writer` gets `permission denied` on `UPDATE`/`DELETE audit_event`.

5. **Domain, ActionRunner, outbox relay, reaper**
   - **Do:** `domain/organization`, `domain/devicegroup`, `domain/audit` (event, codes, registry doc generator),
     `app/action.go`, `outbox/` relay (LISTEN `outbox` + 1 s poll fallback, batches of 500,
     `FOR UPDATE SKIP LOCKED`, publish to exchange `paddock.audit` with routing key `audit.<source>.<organization_id>`,
     `message_id` = `msg_id`, wait for the publisher confirm, then set `published_at`; a negative confirm or a returned
     (unroutable) message leaves the row unpublished and is retried with back-off 1 s → 30 s; delete rows published
     more than 7 days ago, hourly), reaper, `provision rabbitmq` (idempotent declarations in vhost `paddock`:
     exchange `paddock.audit` (topic, durable); queue `audit.writer` (quorum, `x-overflow: reject-publish`,
     `x-max-length-bytes` from `PADDOCK_AUDIT_QUEUE_MAX_BYTES` default 1 GiB, `x-delivery-limit: 20`,
     `x-dead-letter-exchange: paddock.dlx`, **no** message TTL) bound with `audit.#`; exchange `paddock.dlx` (topic)
     with queue `dlq.audit.writer` (quorum) bound with `audit.#`. No retry queue in M0: the audit writer retries by
     pausing 5 s and `nack`ing with `requeue=true`; the quorum queue's delivery limit moves poison messages to the
     DLQ), `serve
     outbox-relay`.
   - **Result:** use cases write outbox rows; the relay delivers every row to RabbitMQ at least once.
   - **Check:** unit tests for outcome mapping; integration tests (Postgres + RabbitMQ testcontainers): success, fn error,
     commit error (injected), denied, `RunExternal` with failing external call, reaper finalizing a 10-min-old
     `started` row; relay killed between confirm and `published_at` update re-publishes the row (duplicate allowed) and
     loses nothing; RabbitMQ stopped → rows stay unpublished and are delivered after restart.

6. **Audit writer**
   - **Do:** `auditwriter/` consumer on queue `audit.writer` (manual ack, prefetch 1000; collects batches of up to
     500 messages or 5 s, whichever comes first). Per batch and per (organization, UTC hour): one transaction —
     `audit_ensure_partition` for the months involved → `INSERT ... ON CONFLICT DO NOTHING RETURNING event_id` →
     only returned events are serialized as JSON lines (sorted by `occurred_at`, `event_id`), zstd-compressed, written
     to `org/<organization_id>/<YYYY>/<MM>/<DD>/<HH>-<first event_id>.jsonl.zst` with `ObjectLockMode=COMPLIANCE`
     and `ObjectLockRetainUntilDate = occurred day + PADDOCK_AUDIT_RETENTION_DAYS` → `INSERT audit_object` → commit
     → ack (multiple). Any error → rollback, wait 5 s, `nack` the batch with `requeue=true`; after 20 deliveries
     RabbitMQ dead-letters a message to `dlq.audit.writer`. Platform pseudo-organization uses the prefix
     `org/00000000-0000-0000-0000-000000000000/`.
     **Daily sealer:** the sealer runs in every audit-writer replica
     at 00:15 UTC and uses `pg_try_advisory_lock(hashtext('audit-seal'))` on the audit DB; for every organization that
     has an `audit_manifest` or `audit_object` row, and for each day not yet sealed up to yesterday, build manifest JSON
     `{schema:"paddock.audit-manifest.v1", organization_id, day, objects:[{key, sha256(hex), event_count}] sorted by key,
     prev_manifest_sha256}` canonicalized with RFC 8785, sign SHA-256 via `transit/sign/audit-chain` (`prehashed=false`),
     store `org/<org>/manifests/<YYYY-MM-DD>.json` (`{manifest, signature, key_version}`) with the same retention,
     insert `audit_manifest`. Days without objects get a manifest with `objects: []`.
     Subcommand `paddock-server audit verify --org <id> --from <day> --to <day>` (uses the writer credentials) verifies
     the chain and every object hash; exit code 0/1.
   - **Result:** events published to `audit.>` appear in the index and as WORM objects; manifests chain.
   - **Check:** integration test with Postgres + RabbitMQ + RustFS (testcontainers, RustFS image from `versions.env`) +
     OpenBao (dev mode allowed in tests): duplicate delivery produces one index row; object retention mode is
     `COMPLIANCE`; manipulated object makes `audit verify` exit 1; missing day breaks the chain → exit 1.

7. **Admin API and Authentik adapter**
   - **Do:** `admin.yaml` (§6.6), generated strict server, handlers, `httpx` middleware (request ID `X-Request-Id`,
     problem details, panic recovery → 500 `internal` with audit failure via runner where an action was running,
     JSON slog access log without bodies), BFF (§6.7), static portal serving with SPA fallback to `index.html` for
     non-`/api` paths and CSP `default-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'`,
     `ports/identity.go`:

     ```go
     type OrgIdentityRefs struct{ RootGroupPK, AdminsGroupPK, OperatorsGroupPK, AuditorsGroupPK string }
     type IdentityProvider interface {
         // EnsureOrganization creates the four groups if missing; idempotent; returns their Authentik pks.
         EnsureOrganization(ctx context.Context, slug string) (OrgIdentityRefs, error)
     }
     ```

     Authentik adapter on `/api/v3/core/groups/` (GET `?name=`, POST), timeouts 10 s, 3 retries with back-off on 5xx
     and network errors, never on 4xx. Organization creation uses `RunExternal` with `ScopePlatform`: prepare = insert
     `organization(status=provisioning)` (or reuse a `provisioning_failed` row with the same slug), external =
     `EnsureOrganization`, finalize = status `active` or `provisioning_failed`; external error → 502
     `upstream_unavailable`.
     Headless login helper `test/acceptance/internal/authflow` (drives `/api/v3/flows/executor/paddock-admin-login/`
     stage by stage with a cookie jar, then follows the redirects to `/api/auth/callback` and returns an `http.Client`
     holding the `paddock_session` cookie). Seeder `test/acceptance/cmd/devseed` (`make dev-seed`): logs in as
     `platform-admin@paddock.test`, creates organizations `acme` and `globex` through the platform API (idempotent:
     409 `slug_taken` is accepted), then puts `alice@acme.test` into `paddock:acme:admins`, `bob@acme.test` into
     `paddock:acme:auditors`, `carol@globex.test` into `paddock:globex:admins` through the Authentik API with the
     bootstrap token.
   - **Result:** `paddock-api` serves the API; dev users can sign in after `make dev-seed`.
   - **Check:** handler tests with OpenAPI request/response validation (`kin-openapi` middleware in tests); adapter
     tests against a real Authentik testcontainer **or** recorded fixtures (see Freedoms); `make up && make dev-seed`;
     manual: sign in as `alice@acme.test`, `GET /api/v1/me` returns organization `acme`.

8. **Portal**
   - **Do:** `server/web`: Vite + Vue 3 + TS; generated API types; `openapi-fetch` client adding `X-Paddock-CSRF: 1`;
     i18n setup with `intl-messageformat` compiler; `en.json`; routes `/` (redirect by role), `/login-denied`,
     `/device-groups` (list, create dialog, edit dialog, delete confirm), `/audit` (table with filters date range and
     code; event text from message key `audit.<code>` with `params`, fallback to the raw code), `/platform/organizations`
     (list, create); header with display name, role, logout; 401 from API → redirect to `/api/auth/login?return_to=`.
     ESLint with `@intlify/vue-i18n/no-raw-text` (error) and `no-missing-keys` (error).
   - **Result:** portal usable for all M0 functions; strings only from the catalog.
   - **Check:** `make web lint`; Vitest component tests for the i18n compiler (ICU plural) and device group form
     validation; `make e2e` (Playwright, §8).

9. **Acceptance gates**
   - **Do:** implement tests A2–A5 (§8) using the `authflow` helper from step 7. Tests create additional Authentik
     users they need (for A4) through the Authentik API and delete them afterwards.
   - **Result:** all gates green against the running stack.
   - **Check:** `make up && make dev-seed && make acceptance`.

10. **Runbooks and README**
    - **Do:** `docs/operations/openbao.md` (production init with 5 named custodians, unseal after restart, AppRole
      secret-id rotation, what stops while sealed), `docs/operations/audit-bucket.md` (one-shot production bucket
      creation, verification with `make acceptance T=TestWORM` adapted to production endpoint, why it cannot be redone),
      `README.md` quick start.
    - **Result:** a new developer can start the stack from the README alone.
    - **Check:** follow `README.md` on a clean clone (`make down -v`, delete `.secrets/`) → stack up, login works.

## 8. Tests

| ID | Level | File | Content |
| --- | --- | --- | --- |
| U1 | unit | `server/internal/app/action_test.go` | outcome mapping, params copy, no secrets in params (keys `password`, `secret`, `token` rejected with panic in tests) |
| U2 | unit | `server/internal/transport/http/admin/session_test.go` | cookie encrypt/decrypt, previous key accepted, tampered cookie rejected, idle + absolute expiry, re-issue after 5 min |
| U3 | unit | `.../admin/role_test.go` | group → role resolution table incl. 0, 2, platform+org, invalid slug |
| U4 | unit | `server/internal/auditwriter/manifest_test.go` | canonical manifest bytes stable for permuted object input |
| U5 | unit | `server/internal/transport/http/admin/returnto_test.go` | `return_to` validation (`//evil`, `https://`, `/\evil`) |
| I1 | integration | `server/internal/platform/db/*_test.go` | RLS lint, fail closed, cross-org 0 rows, role grants (step 4) |
| I2 | integration | `server/internal/app/action_integration_test.go` | step 5 cases |
| I3 | integration | `server/internal/outbox/relay_test.go` | dedup on restart, ordering per organization preserved, no loss |
| I4 | integration | `server/internal/auditwriter/writer_test.go` | step 6 cases |
| I5 | integration | `server/internal/adapters/authentik/adapter_test.go` | idempotent `EnsureOrganization`, retry on 5xx, no retry on 4xx |
| A1 | acceptance | `test/acceptance/worm_test.go` | **Audit gate:** put object with COMPLIANCE retention using the **root** credentials of `audit-rustfs`; `DeleteObject` with version ID → error; `PutObjectRetention` shortening → error; `DeleteObject` with `x-amz-bypass-governance-retention: true` → error; switching to GOVERNANCE → error; object still readable with identical SHA-256. Also asserts the writer credential cannot `DeleteObject` or `PutBucketPolicy` |
| A2 | acceptance | `test/acceptance/isolation_test.go` | **Organization isolation gate:** load `api/openapi/admin.yaml`; for every operation under `/api/v1/` with a path parameter, create the resource in `globex` (as carol), call it as alice (`acme`) → **404** `not_found`, response body contains no `globex` IDs; for every list operation, response as alice contains no `globex` IDs; audit-events of `globex` never visible to `acme`. The test fails if an operation exists in the spec without a fixture mapping in `isolation_fixtures.go` |
| A3 | acceptance | `test/acceptance/audit_once_test.go` | **Portal gate:** for every operation with `x-paddock-audit`, cases success, validation failure (400), wrong role (403), not found (404, where applicable), conflict (409, where applicable); after each request poll `/api/v1/audit-events` (max 10 s) filtered by the request's `X-Request-Id` (= `correlation_id`) → **exactly one** event with the expected `code` and `outcome` (`success`/`failure`/`denied`); a second poll after 5 s still returns exactly one. Organization creation with Authentik stopped (`docker compose stop authentik-server`) → 502 and exactly one `organization.created` event with `failure` in the platform audit (checked via `paddock-server audit verify` + index query in the audit DB). Test for unknown: kill `paddock-api` (`docker kill`) during `RunExternal` using a test-only delay hook `PADDOCK_TEST_EXTERNAL_DELAY` (honoured **only** when `PADDOCK_ENV=development`) → after ≥ 10 min + 60 s the reaper produced exactly one event with `unknown` (test MAY reduce the reaper threshold via `PADDOCK_REAPER_THRESHOLD` honoured only in development) |
| A4 | acceptance | `test/acceptance/login_test.go` | user without Paddock groups → `/login-denied`, audit `admin.login` denied; user in groups of two organizations → denied; platform admin calling `/api/v1/device-groups` → 403 `no_organization`; org admin calling `/api/platform/v1/organizations` → 403 |
| A5 | acceptance | `test/acceptance/audit_chain_test.go` | trigger the sealer for "yesterday" via `paddock-server audit seal --day <day>` (subcommand, development only for arbitrary days) and run `audit verify` → exit 0; objects in RustFS under `org/<org>/…` for both organizations; organization ID in every object path |
| E1 | e2e | `server/web/e2e/*.spec.ts` | login as alice → create, rename, delete device group → audit page shows three localized events; auditor sees audit but no create button; axe: no serious/critical violations on all pages |

## 9. Acceptance criteria

| # | Given / When / Then | Requirement | Observed by |
| --- | --- | --- | --- |
| AC1 | Given a clean checkout, when the developer runs `make dev-secrets up bao-bootstrap audit-bootstrap dev-seed`, then all services are healthy and `https://admin.paddock.localhost:8443` shows the Authentik login | C8 | Developer |
| AC2 | Given admins of `acme` and `globex`, when alice requests any `globex` resource by ID, then she receives 404, on every `/api/v1` path (A2 green) | F10 | Org admin; automated test |
| AC3 | Given any privileged action, when it succeeds, fails validation, is denied or hits a missing resource, then exactly one audit event with the matching outcome exists in index and WORM store (A3 green) | F7 | Auditor (portal audit page) |
| AC4 | Given an audit object, when anyone — including the RustFS root account — tries to delete it or shorten its retention, then the request fails (A1 green) | F7 | Auditor; platform operator |
| AC5 | Given a sealed day, when `paddock-server audit verify` runs, then it confirms the signed chain; a tampered or missing object or manifest makes it fail (A5, I4 green) | F7 | Auditor |
| AC6 | Given a user who is not member of a Paddock admin group, when they sign in, then they see the login-denied page and no data (A4 green) | F8 | Any user |
| AC7 | Given an organization admin, when they create, edit and delete a device group in the portal, then the portal shows the changes and the audit page lists the three `device_group.*` events in English rendered from message keys (E1 green) | F8, C7 | Org admin |
| AC8 | Given a platform admin, when they create an organization, then the four Authentik groups exist and the organization is `active`; with Authentik unreachable the organization is `provisioning_failed` and can be re-provisioned by repeating the request | F10, A1 | Platform admin |

## 10. Freedoms

The coding agent MAY decide on its own:

- Internal package structure below the listed packages, helper names, file splits, test helper design.
- SQL query names and shapes in sqlc files (except the forbidden direct uses in §6.3/§6.5).
- Visual design, layout and PrimeVue component choice of the portal; wording of English UI messages.
- Whether the Authentik adapter test runs against a real Authentik testcontainer or against recorded HTTP fixtures
  (recorded from the pinned version, stored in `testdata/`); the acceptance tests always use the real instance.
- Prometheus metric names beyond these mandatory ones: `paddock_http_requests_total{route,code}`,
  `paddock_outbox_unpublished`, `paddock_outbox_publish_total{result}`, `paddock_audit_events_written_total`,
  `paddock_audit_seal_total{result}`.
- The exact Caddy, RabbitMQ and OpenBao configuration syntax, as long as §6.8 holds.
- CI runner details in `.github/workflows/ci.yml`.

## 11. Stop conditions

Stop, do not work around, and report back with findings when:

- **S1** The WORM gate A1 fails against RustFS (ADR 0017 then requires Ceph RGW for the audit bucket — architect decision).
- **S2** A dependency outside §6.10 seems necessary, or a stated library cannot do what is required.
- **S3** The pinned Authentik version cannot do something required here (blueprint `!Env`, group claim mapping,
  flow executor API for headless login, service-account token with group permissions).
- **S4** OpenBao Transit cannot create non-exportable Ed25519 keys or AppRole cannot be restricted as in §6.8.
- **S5** PostgreSQL RLS behaves differently from this plan (for example, partitioned `audit_event` policies not applied
  as expected, or `FORCE ROW LEVEL SECURITY` conflicting with `SECURITY DEFINER` functions in a way that breaks the
  stated grants).
- **S6** Any requirement in this plan contradicts another, or contradicts `docs/architecture.md`.
- **S7** Fulfilling a requirement would need a change in a file listed as "MUST NOT be touched".
- **S8** An acceptance test can only be made green by weakening the test or by a production-effective shortcut.

## 12. Risks and open points

| # | Item | Default / mitigation |
| --- | --- | --- |
| R1 | Go module path `github.com/paddock-mdm/paddock` — GitHub organization not yet reserved (concept "Naming") | Use it; a later rename is one `go mod edit` + import rewrite. Product owner to reserve the organization |
| R2 | Git hosting for CI not decided | GitHub Actions workflow file. **Git (approved by the product owner):** the coding agent runs `git init -b main` in step 1 and commits at the end of every step (§7) with a Conventional Commits message (`feat(m0): step N — <title>`). It MUST NOT push and MUST NOT add a remote. |
| R3 | Authentik flow executor API changes between versions could break the headless login helper | Pinned version; helper isolated in `test/acceptance/internal/authflow`; fallback per S3 |
| R4 | RustFS is young (ADR 0017) | A1 runs in every acceptance run, not only once |
| R5 | `.localhost` hostnames do not resolve inside containers by default | Caddy network aliases (§6.8); documented in `local-dev.md` |
| R6 | OpenBao sealed after `docker compose restart` in dev | `make bao-unseal` target using stored dev shares; production runbook |
| R7 | The reaper test (A3 unknown case) needs ≥ 10 min with production thresholds | Development-only override `PADDOCK_REAPER_THRESHOLD`; production default fixed at 10 min |
| R8 | Test VMs from `test/vms/virtualbox/` are not used in M0 | They serve M1 (PoC) and M2 |
