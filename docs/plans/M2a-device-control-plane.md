# Implementierungsplan: M2a — Device control plane (enrollment, identity, check-in, bundles)

Status: Ready for implementation · 2026-10-04 · Author: architect
Basis: `docs/architecture.md` v1.4 §5–§8, §16, §17; ADR 0003, 0004, 0005, 0006, 0011, 0013, 0018; `CLAUDE.md`

Binding language: **MUST** / **MUST NOT** / **SHOULD** / **MAY**. M2 is split: **M2a** (this plan) builds everything
on the server side and a reference device client in Go; **M2b** (separate plan, after M2a) builds `paddockd`, the
supervisor, reconcilers, packaging and VM tests on top of the protocol defined here.

## 1. Goal

After M2a, an organization administrator can create enrollment tokens, see devices enroll, approve, reject and
retire them, assign them to device groups, and define managed files and systemd units per device group. The server
compiles a signed, versioned bundle per device whenever its inputs change, and a device (proven by a reference Go
client in the acceptance tests) can enroll, check in every few minutes and fetch and verify its own bundle — with no
synchronous device-to-database write.

## 2. Context

- M0–M0.3 are complete: admin API with list contract (ADR 0018), ActionRunner + outbox + audit pipeline, RLS
  isolation (`db.OrgPool.InOrg`), RabbitMQ (only the audit topology), OpenBao (key `audit-chain`), RustFS only in the
  audit domain, Vuetify portal with `DataList` and `ConfirmDialog`. Device groups exist (table `device_group`) but have
  no members.
- Architecture essentials (quoted where binding):
  - §6.3 request signature: headers `Paddock-Device`, `Paddock-Key-Id`, `Paddock-Timestamp`, `Paddock-Nonce`,
    `Paddock-Content-SHA256`, `Paddock-Seq`, `Paddock-Signature`; canonical string
    `paddock-v1\n<METHOD>\n<path incl. query>\n<device>\n<key id>\n<timestamp>\n<nonce>\n<content sha256>\n<seq>`;
    ECDSA P-256; timestamp window ±300 s; nonce `SET NX EX 600` in Valkey; verification order as listed there.
  - §6.4 clone detection via server-issued monotonic `seq`; §6.5 identity states `pending → active | rejected`,
    `active → quarantined | retired`.
  - §7 compiler: recompute on change, never per request; debounce 2 s per device; content-equal renders do not
    increment; per-device monotonic `bundle_version`; DSSE envelope, payload type
    `application/vnd.paddock.bundle.v1+json`, RFC 8785 canonical JSON; Ed25519 via OpenBao Transit; object key
    `org/<org>/devices/<dev>/bundles/<version>.dsse`; presigned GET TTL 120 s.
  - §8 RabbitMQ topology and Valkey keys (§8.3); gateway has **no** database credentials.
  - §3.2 roles: `gateway`, `worker`, `compiler` (this plan adds them).

## 3. Binding decisions

1. **New roles** `paddock-server serve gateway|worker|compiler`, each its own Compose service and OpenBao AppRole
   (compiler only) and DB role (`paddock_worker`, `paddock_compiler`; gateway none). Gateway reaches only RabbitMQ,
   Valkey and (for presigning) local credentials of the bundles bucket.
2. **Valkey** (`valkey/valkey:8`, pinned by digest) joins the control plane; client `github.com/valkey-io/valkey-go`
   (approved). Persistence AOF `everysec`; password from secret file; dev port bound to `127.0.0.1:6379` in
   `compose.dev.yaml` only.
3. **Control-plane RustFS** (`rustfs` service, same pinned image as the audit store, separate volume and credentials)
   with bucket `paddock-bundles` (versioning off, no Object Lock). Credentials: `compiler` read/write, `gateway`
   read-only (used only to compute presigned URLs). Public hostname `bundles.<domain>` via Caddy → `rustfs:9000`;
   presigned URLs are computed for that public host.
4. **Device API hostname** `device.<domain>` via Caddy → `gateway:8081`. Device API under `/v1/…` (§6). OpenAPI
   contract `api/openapi/device.yaml`.
5. **Shared Go packages in `pkg`** (module `github.com/paddock-mdm/paddock/pkg`, used by server now and agent in M2b):
   `pkg/protocol` (headers, canonical string, `Sign`, `Verify`, request/response types), `pkg/canonicaljson`
   (RFC 8785, wrapping `github.com/gowebpki/jcs`), `pkg/dsse` (envelope encode/verify, Ed25519), `pkg/bundle`
   (schema v1 types + `Verify(envelope, trust, deviceID, orgID, minVersion)`). `pkg` MUST NOT import `server/...`.
   Allowed dependencies in `pkg`: standard library and `gowebpki/jcs` only.
6. **Trust anchor:** the bundle-signing public keys reach the device through the **enrollment config** that the admin
   receives when creating an enrollment token (decision 9), not through the network at enrollment. The device pins
   them in `/etc/paddock/trust.json`.
7. **Bundle resources in M2a:** `time` (fixed: NTP enabled), `file`, `systemd_unit`. Sources: new organization
   entities `managed_file` and `managed_unit`, each optionally scoped to a device group (null = all devices of the
   organization). Several matching definitions for the same path/unit: the one with the most specific scope wins
   (device group over organization); among several device groups, the definition with the lexicographically smallest
   `id` wins and the conflict is shown in the portal (device detail) — no silent merge.
8. **File path policy** (enforced in the domain, API returns 422 `path_not_allowed`): absolute path, normalized, no
   `..`, below `/etc/` or `/usr/local/etc/` or `/opt/`, and **not** below any protected or system-critical path:
   `/etc/sudoers`, `/etc/sudoers.d/`, `/etc/pam.d/`, `/etc/security/`, `/etc/nsswitch.conf`, `/etc/himmelblau/`,
   `/etc/paddock/`, `/opt/paddock/`, `/etc/crypttab`, `/etc/fstab`, `/etc/passwd`, `/etc/shadow`, `/etc/group`,
   `/etc/gshadow`, `/etc/apt/` (reserved for M5), `/etc/systemd/system/paddock*`. Content ≤ 64 KiB UTF-8 text; mode
   `0[0-7]{3}` without setuid/setgid/sticky; owner and group are names matching `^[a-z_][a-z0-9_-]{0,31}$`.
   Unit names match `^[a-zA-Z0-9@._-]+\.(service|timer|socket|path)$`; units `paddock*`, `himmelblau*`, `fleet*`,
   `ssh*`, `gdm*`, `systemd-*` are rejected (422 `unit_not_allowed`).
9. **Enrollment tokens:** created by `org_admin`; fields `name`, `expires_at` (≤ 30 days), `max_uses` (1–1000),
   `device_group_id` (nullable), `auto_approve` (bool). The secret (32 random bytes, base64url) is shown **once** in the
   create response together with an `enrollment_config` JSON document:
   `{ "server_url": "https://device.<domain>", "organization_id": "...", "token": "<secret>",
      "bundle_keys": [{"key_id": "bundle-signing:v1", "public_key": "<base64 ed25519>"}] }`.
   Only `sha256(secret)` is stored. Revocation sets `revoked_at`.
10. **Enrollment flow** (gateway never touches the DB): `POST /v1/enroll` (signed with the new key; headers
    `Paddock-Device: enroll`, `Paddock-Key-Id: <sha256 of public key, hex>`) → gateway verifies proof of possession,
    looks up `et:<sha256(token)>` in Valkey (exists, not revoked, not expired), writes
    `enr:<enrollment_id>` = `{key_id, public_key, organization_id, status: "processing"}` (TTL 7 d), publishes
    `ingest.enroll.<org>` → 202 `{enrollment_id}`. Worker: in one `InOrg` transaction consumes one token use (row lock),
    creates `device` + `device_identity_key`, state `active` if `auto_approve` else `pending`, adds the token's device
    group, records audit `device.enrolled`, publishes state change; then updates `enr:` (`active|pending|rejected`,
    `device_id`) and, if active, `dk:<key_id>`. Exhausted, revoked or expired token at worker time → `rejected` with
    reason. `GET /v1/enroll/{id}` is signed with the same key (`Paddock-Device: enroll`), verified against `enr:`.
11. **Check-in** (`POST /v1/checkin`): gateway verifies (§6.3), checks `dk:` status (`active` → normal;
    `quarantined` → normal response but no bundle URL; `retired|rejected` → 401 `identity_revoked`), `INCR seq:<dev>`
    → new `seq`; if the request's `Paddock-Seq` is lower than the stored value minus 1 → publish event
    `clone_suspected`. Publishes `ingest.heartbeat.<org>` with the request body, applied version, seq. Reads `bp:<dev>`;
    if `version > applied_bundle_version` → presigned URL. Response:
    `{seq, server_time, bundle: {version, sha256, url}|null, next_checkin_s}` with `next_checkin_s` = 300 × U(0.8,1.2).
12. **Worker heartbeat materialization:** `device_status` upsert at most once per 60 s per device (coalesced via
    Valkey `hb:<dev>` `SET NX EX 60`); fields `last_contact_at`, `applied_bundle_version`, `agent_version`,
    `last_seq`, `health jsonb`. `clone_suspected` → device state `quarantined` + audit `device.clone_suspected`.
13. **Compiler:** consumes `state.p00…p15` + `state.priority` (single active consumer each; partition =
    `fnv32a(organization_id) % 16`). Events: `{organization_id, scope: org|device_group|device, id}`. Expands scope to
    active devices, debounces 2 s per device, renders, compares SHA-256 of canonical payload with the last bundle
    row; if different: increments `device.bundle_seq` and inserts `bundle` row in the same transaction, signs via
    `transit/sign/bundle-signing` (`batch_input`, `marshaling_algorithm` not used for Ed25519), uploads, then
    `SET bp:<dev>`. Upload failure → transaction rolled back, message nacked (retry). Valkey failure after commit →
    a reconcile loop (every 60 s) rewrites `bp:` for bundles newer than the cached pointer.
14. **Events from devices (M2a):** `POST /v1/events` accepts a batch of at most 500 events, types (closed enum):
    `bundle.applied`, `bundle.rejected`, `config.drift_corrected`. Each event `{event_seq, type, occurred_at, data}`;
    unknown type → 400 `unknown_event_type` for the whole batch. Worker turns them into audit events with codes
    `device.bundle_applied`, `device.bundle_rejected`, `device.config_drift_corrected` (actor `{type:"device", id}`),
    deduplicated by `(device_id, event_seq)` (table `device_event_seen`, primary key, `ON CONFLICT DO NOTHING`).
15. **Keys:** OpenBao Transit `bundle-signing` (`ed25519`, non-exportable); AppRole `paddock-compiler` with
    `update` on `transit/sign/bundle-signing` and `read` on `transit/keys/bundle-signing`; the `api` AppRole gets
    `read` on `transit/keys/bundle-signing` (public keys for the enrollment config).
16. **Portal** (all lists via `DataList`, all destructive actions via `ConfirmDialog`): *Devices* (list: hostname,
    state, last contact, bundle version, agent version; filters state, device group; search hostname/hardware UUID;
    detail with identity, groups, effective resources and conflicts, actions approve / reject / quarantine release /
    retire — retire requires typing the hostname), *Enrollment tokens* (list, create dialog that shows the token and
    a copy button for `enrollment_config` exactly once, revoke), *Managed files* and *Managed units* (list, create/edit
    dialog, delete). Device group detail gets a device membership list.

## 4. Non-goals

`paddockd`, supervisor, packaging, VMs (M2b); commands, escrow, identity rotation, agent releases/rollouts, time
tickets, dead man's switch, staleness alerts (later milestones); TPM key protection (the protocol carries
`key_protection`, the reference client uses `file`); Fleet; login/Himmelblau settings; delta bundles.

## 5. Affected files (new unless stated)

| Path | Purpose |
| --- | --- |
| `pkg/protocol/`, `pkg/canonicaljson/`, `pkg/dsse/`, `pkg/bundle/` | decision 5 |
| `api/openapi/device.yaml`; `api/openapi/admin.yaml` (change) | contracts §6 |
| `server/migrations/paddock/00003_devices.sql` | §6.1 |
| `server/internal/domain/{device,enrollment,managedconfig}/` | entities, validation (decision 8) |
| `server/internal/platform/valkey/`, `server/internal/platform/mq/` (change: ingest/state topology, publisher for state) | infra |
| `server/internal/transport/http/device/` | gateway handlers |
| `server/internal/worker/`, `server/internal/compiler/` | roles |
| `server/internal/transport/http/admin/` (change) | new admin endpoints |
| `server/web/src/views/{Devices,DeviceDetail,EnrollmentTokens,ManagedFiles,ManagedUnits}.vue`, `src/locales/en.json` (change), router (change) | portal |
| `deploy/compose/{compose.yaml,compose.dev.yaml,versions.env,caddy/Caddyfile}` (change), `deploy/compose/scripts/*` (change: secrets, OpenBao key + AppRoles, bundles bucket bootstrap) | stack |
| `test/acceptance/devicesim/` | reference device client (uses `pkg/protocol`, `pkg/bundle`) |
| `test/acceptance/{device_protocol_test.go,device_security_test.go,device_portal…}` | gates §8 |
| `CHANGELOG.md` (change), `README.md`, `docs/operations/local-dev.md` (change) | docs |

Off-limits: `docs/architecture.md`, `docs/adr/**`, `docs/plans/**`, `docs/poc/**`, `test/poc/**`, `test/vms/**`, `.claude/**`.

## 6. Interfaces and data model

### 6.1 Migration `00003_devices.sql` (all organization-scoped tables with ENABLE + FORCE RLS and `tenant` policies for the roles that use them, as in 00001)

```sql
CREATE TABLE enrollment_token (
  id uuid PRIMARY KEY, organization_id uuid NOT NULL REFERENCES organization(id),
  name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 100),
  secret_sha256 bytea NOT NULL UNIQUE,
  device_group_id uuid REFERENCES device_group(id),
  auto_approve boolean NOT NULL, max_uses int NOT NULL CHECK (max_uses BETWEEN 1 AND 1000),
  uses int NOT NULL DEFAULT 0, expires_at timestamptz NOT NULL, revoked_at timestamptz,
  created_by uuid NOT NULL, created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE device (
  id uuid PRIMARY KEY, organization_id uuid NOT NULL REFERENCES organization(id),
  hostname text NOT NULL, state text NOT NULL CHECK (state IN ('pending','active','rejected','quarantined','retired')),
  bundle_seq bigint NOT NULL DEFAULT 0, hardware_uuid text, machine_id text, os_release jsonb NOT NULL DEFAULT '{}',
  enrollment_token_id uuid REFERENCES enrollment_token(id), enrolled_at timestamptz NOT NULL DEFAULT now(),
  state_changed_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE device_identity_key (
  key_id text PRIMARY KEY,                 -- hex sha256 of the SubjectPublicKeyInfo DER
  organization_id uuid NOT NULL, device_id uuid NOT NULL REFERENCES device(id),
  public_key bytea NOT NULL,               -- SubjectPublicKeyInfo DER, ECDSA P-256
  key_protection text NOT NULL CHECK (key_protection IN ('tpm','file')),
  status text NOT NULL CHECK (status IN ('active','revoked')), created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE device_group_member (
  organization_id uuid NOT NULL, device_group_id uuid NOT NULL REFERENCES device_group(id) ON DELETE CASCADE,
  device_id uuid NOT NULL REFERENCES device(id), PRIMARY KEY (device_group_id, device_id)
);
CREATE TABLE device_status (
  device_id uuid PRIMARY KEY REFERENCES device(id), organization_id uuid NOT NULL,
  last_contact_at timestamptz, applied_bundle_version bigint, agent_version text, last_seq bigint NOT NULL DEFAULT 0,
  health jsonb NOT NULL DEFAULT '{}'
);
CREATE TABLE bundle (
  device_id uuid NOT NULL REFERENCES device(id), version bigint NOT NULL, organization_id uuid NOT NULL,
  content_sha256 bytea NOT NULL, envelope_sha256 bytea NOT NULL, object_key text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY (device_id, version)
);
CREATE TABLE managed_file (
  id uuid PRIMARY KEY, organization_id uuid NOT NULL REFERENCES organization(id),
  device_group_id uuid REFERENCES device_group(id) ON DELETE CASCADE,
  path text NOT NULL, mode text NOT NULL, owner text NOT NULL DEFAULT 'root', grp text NOT NULL DEFAULT 'root',
  content text NOT NULL, created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE NULLS NOT DISTINCT (organization_id, device_group_id, path)
);
CREATE TABLE managed_unit (
  id uuid PRIMARY KEY, organization_id uuid NOT NULL REFERENCES organization(id),
  device_group_id uuid REFERENCES device_group(id) ON DELETE CASCADE,
  unit text NOT NULL, enabled boolean NOT NULL, active boolean NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE NULLS NOT DISTINCT (organization_id, device_group_id, unit)
);
CREATE TABLE device_event_seen (
  device_id uuid NOT NULL, event_seq bigint NOT NULL, organization_id uuid NOT NULL, PRIMARY KEY (device_id, event_seq)
);
```

DB roles: `paddock_worker` (enrollment, device, device_identity_key, device_status, device_group_member insert,
device_event_seen, action/outbox insert), `paddock_compiler` (read inputs; update `device.bundle_seq`; insert `bundle`;
action/outbox insert). Cross-organization message consumption: both roles open one `InOrg` transaction per message
using the message's `organization_id` (principal `KindSystem`); they get no `USING (true)` policies on organization
data. RLS lint stays green.

### 6.2 Device API (`api/openapi/device.yaml`)

| Method / path | Auth | Success | Errors |
| --- | --- | --- | --- |
| `POST /v1/enroll` | signature with new key, `Paddock-Device: enroll` | 202 `{enrollment_id}` | 400 `invalid_request`, 401 `invalid_signature`/`clock_skew`/`invalid_token`, 429 |
| `GET /v1/enroll/{enrollment_id}` | same key | 200 `{status: processing\|pending\|active\|rejected, device_id?, reason?}` | 401, 404 |
| `POST /v1/checkin` | device signature | 200 (decision 11) | 401 `invalid_signature`/`clock_skew`/`replay`/`identity_revoked`, 429, 503 `backpressure` |
| `POST /v1/events` | device signature | 202 | 400 `unknown_event_type`, 401, 413, 429 |

Request bodies:

```json
// POST /v1/enroll
{ "token": "<secret>", "public_key": "<base64 SPKI DER>", "key_protection": "file",
  "hostname": "lt-alice-01", "hardware_uuid": "…", "machine_id": "…",
  "os_release": {"id": "ubuntu", "version_id": "26.04"}, "agent_version": "0.1.0" }
// POST /v1/checkin
{ "applied_bundle_version": 12, "agent_version": "0.1.0", "schema_versions": [1],
  "health": {"reconcile": "ok"}, "event_seq_high": 41 }
```

Errors on the device API use the same RFC 9457 problem format; 401 responses carry `server_time` as an extension
member. Rate limit per key id and per source IP in the gateway (token bucket, Valkey-backed: 30 requests/min per key,
300/min per IP) → 429 with `Retry-After`.

### 6.3 Bundle schema v1 (`pkg/bundle`)

```go
type Bundle struct {
    SchemaVersion  int        `json:"schema_version"`  // 1
    BundleVersion  int64      `json:"bundle_version"`
    DeviceID       string     `json:"device_id"`
    OrganizationID string     `json:"organization_id"`
    IssuedAt       time.Time  `json:"issued_at"`       // excluded from the content hash (decision 13 compares the payload without issued_at)
    Agent          AgentCfg   `json:"agent"`           // {checkin_interval_s: 300}
    Resources      []Resource `json:"resources"`       // sorted by ID
}
type Resource struct {
    ID   string          `json:"id"`   // "time", "file:<path>", "unit:<name>"
    Type string          `json:"type"` // "time" | "file" | "systemd_unit"
    Spec json.RawMessage `json:"spec"`
}
type FileSpec struct { Path, Mode, Owner, Group, Content, ContentSHA256 string }   // JSON snake_case
type UnitSpec struct { Unit string; Enabled, Active bool }
type TimeSpec struct { NTP bool }

type Trust struct{ Keys map[string]ed25519.PublicKey } // key_id → key
// Verify checks DSSE signature (any trusted key), payload type, device/org match, version > minVersion,
// schema_version supported; returns the decoded bundle or a typed error (ErrSignature, ErrWrongDevice,
// ErrDowngrade, ErrSchema).
func Verify(envelope []byte, trust Trust, deviceID, orgID string, minVersion int64) (*Bundle, error)
```

### 6.4 Admin API additions (`admin.yaml`, all lists per ADR 0018, all mutations audited)

| Method / path | Roles | Audit code |
| --- | --- | --- |
| `GET/POST /api/v1/enrollment-tokens`, `GET /…/{id}`, `POST /…/{id}:revoke` | list/get: admin, operator; create/revoke: admin | `enrollment_token.created`, `enrollment_token.revoked` |
| `GET /api/v1/devices` (sort `hostname`, `last_contact_at`, `enrolled_at`, `state`; search `hostname`, `hardware_uuid`; filters `state`, `device_group_id`), `GET /…/{id}` | admin, operator, auditor | – |
| `POST /api/v1/devices/{id}:approve`, `:reject`, `:release-quarantine`, `:retire` | admin (approve/release also operator) | `device.approved`, `device.rejected`, `device.quarantine_released`, `device.retired` |
| `PUT /api/v1/devices/{id}/groups` `{device_group_ids: []}` | admin, operator | `device.groups_changed` |
| `GET /api/v1/devices/{id}/effective-config` | admin, operator, auditor | – |
| `GET/POST /api/v1/managed-files`, `GET/PATCH/DELETE /…/{id}` | read: all three; write: admin, operator | `managed_file.created/updated/deleted` |
| `GET/POST /api/v1/managed-units`, `GET/PATCH/DELETE /…/{id}` | same | `managed_unit.created/updated/deleted` |
| `GET /api/v1/device-groups/{id}/devices` (list contract) | all three | – |

Every mutation that changes compiler inputs writes a `state.changed` outbox row in the same transaction (scope per
decision 13). System-actor audit codes: `device.enrolled`, `device.clone_suspected`, `device.bundle_applied`,
`device.bundle_rejected`, `device.config_drift_corrected`.

## 7. Implementation steps

1. **Shared packages** — `pkg/*` with unit tests: canonical string golden test, sign/verify round trip, tampered
   field per header → fail, RFC 8785 vectors, DSSE vectors, `bundle.Verify` for each error. Fuzz tests
   (`go test -fuzz`, 30 s in CI) for canonical string parsing and DSSE decoding. **Commit:** `feat(pkg): device protocol, DSSE and bundle schema`.
2. **Stack** — Valkey, control-plane RustFS + bucket bootstrap, Caddy hosts `device.` and `bundles.`, OpenBao key +
   AppRoles, RabbitMQ topology (`paddock.ingest`, `paddock.state`, DLX/DLQ per ADR 0003), new Compose services for
   the three roles (initially exiting with "not implemented" is not allowed — add each service in the step that
   implements it). **Check:** `make up` healthy; `provision rabbitmq` idempotent. **Commit:** `build(compose): valkey, bundles store, device hostnames`.
3. **Migration + domain + admin API + worker enrollment path** — §6.1, §6.4 (without portal), worker consumes
   `ingest.enroll`. **Check:** `make lint test`; isolation fixtures and list-contract gate extended for all new
   endpoints (the existing generic tests MUST cover them, no exemptions). **Commit:** `feat(devices): enrollment tokens, devices, managed config`.
4. **Gateway** — device API §6.2, verification order §6.3, Valkey caches, rate limits, backpressure (negative
   publisher confirm → 503 `backpressure`). **Check:** handler tests incl. every 401 cause, replay, ±300 s boundary.
   **Commit:** `feat(gateway): device API`.
5. **Compiler + worker heartbeat/events** — decisions 11–14. **Check:** integration tests: change of managed file →
   new version for exactly the affected devices; no-op edit → no new version; group membership change → recompile;
   upload failure → retry without version gap visible to devices (`bp:` only points to uploaded bundles).
   **Commit:** `feat(compiler): signed per-device bundles`.
6. **Reference device client + gates** — `test/acceptance/devicesim` and gates D1–D4 (§8). **Commit:** `test(acceptance): device protocol gates`.
7. **Portal** — decision 16, e2e E2. **Commit:** `feat(web): devices, enrollment tokens, managed config`.
8. **Regression** — `make down V=1`, delete `.secrets`, `make dev-secrets up dev-seed acceptance e2e` green.
   Also add the missing test from the M0.3 review: the blueprint-wait timeout path of `devseed` prints the pending
   blueprints (unit test with a fake Authentik client). **Commit:** `test(dev): blueprint wait timeout message` if needed.

## 8. Tests (acceptance gates)

| ID | Gate | Content |
| --- | --- | --- |
| D1 | Device protocol | devicesim enrolls with an auto-approve token → `active`; check-in returns a bundle URL; bundle verifies with the keys from `enrollment_config`; resources equal the effective config API; second check-in without changes → `bundle: null` when applied version is current; managed-file edit → new version visible at the next check-in within 10 s; no-op edit → same version; manual-approve token → `pending` until an admin approves |
| D2 | Device security | wrong signature, altered body, altered path, old timestamp (−301 s), future timestamp (+301 s), replayed nonce → 401 with the right code; revoked/expired/exhausted token → `rejected`/401; retired device → 401 `identity_revoked`; quarantined device → 200 without bundle URL; device A's presigned URL path with device B's key in the object path → 403 from the bundles host; guessed object URL without signature → 403 |
| D3 | Clone detection | two devicesim instances with the same key and diverging `seq` → device `quarantined` within one check-in + exactly one `device.clone_suspected` audit event |
| D4 | No synchronous DB path | `docker compose config` shows no database secret or DSN for `paddock-gateway`; with PostgreSQL stopped, check-ins of an enrolled device still return 200 (from Valkey) and the heartbeat is processed after PostgreSQL is back |
| A2/A3/list | existing gates | automatically include the new admin endpoints; new fixtures in `isolation_fixtures.go` |
| E2 | Portal | create token (secret shown once, copy button), devicesim enrolls, device appears, approve (manual token), add to group, create managed file for the group, device detail shows it in effective config, retire with typed hostname; axe clean, no CSP violations |

## 9. Acceptance criteria

| # | Given / When / Then | Req. | Observed by |
| --- | --- | --- | --- |
| AC1 | Given an enrollment token, when a device enrolls with it, then the org admin sees the device in the portal as active (auto-approve) or pending | A6 | Org admin |
| AC2 | Given an active device, when the admin changes a managed file for its device group, then at the device's next check-in it receives a new, correctly signed bundle containing the file | F1, A9 | Device (devicesim), org admin (effective config) |
| AC3 | Given any device request with a bad signature, stale timestamp or replayed nonce, then it is rejected | A5 | Platform operator (logs/metrics) |
| AC4 | Given a cloned identity, then the device is quarantined and an audit event exists | A6 | Org admin, auditor |
| AC5 | Given PostgreSQL is down, then device check-ins still succeed | Principle 3, C2 | Platform operator |
| AC6 | Given org A's admin, then no org B device, token or managed config is reachable (404) or listed | F10 | Org admin |

## 10. Freedoms

Internal package structure, worker/compiler concurrency settings, Valkey client usage details, portal layout,
metric names beyond `paddock_gateway_requests_total{route,code}`, `paddock_gateway_auth_failures_total{reason}`,
`paddock_compiler_bundles_total{result}`, `paddock_compiler_latency_seconds`.

## 11. Stop conditions

OpenBao Transit cannot batch-sign Ed25519 or does not expose the public key needed for decision 9; RustFS presigned
URLs cannot be computed for the public host; RLS design needs a `USING (true)` policy on organization data for
worker/compiler; a requirement conflicts with ADR 0003/0004/0005/0018 or `CLAUDE.md`; M0 §11 S2/S6/S7/S8.

## 12. Risks

| # | Item | Default |
| --- | --- | --- |
| R1 | Bundles bucket on the same host as the control plane | Intended (bundles are not evidence); backups not needed (recompiled) |
| R2 | Valkey loss empties `dk:`/`bp:`/`seq:` | Worker/compiler reconcile loops rebuild from PostgreSQL every 60 s; documented in `local-dev.md` |
| R3 | Enrollment config contains the token in plain text | Shown once; operator distributes it like a password; token hashes only in DB |
