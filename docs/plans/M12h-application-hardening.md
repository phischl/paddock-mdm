# Implementierungsplan: M12h — Application hardening (first half in alpha.10; second half outlined for alpha.11)

Status: Ready for implementation (M12h-1) · 2026-11-05 · Author: architect
Basis: ADR 0051 (network segmentation, Valkey ACL users, application rate limiter, third-party container
hardening, agent file safety; **Proposed**; amends ADR 0003 and ADR 0016), ADR 0034 (step-up), ADR 0017 (WORM gate
after any RustFS change), ADR 0022 (bundle, smoke), ADR 0029 (lab host), ADR 0047 (upgrade guarantee: every
Compose change must upgrade from alpha.9), plans M8s (CR-1, SEC-1–3), M6a (prod-check), M7b (bundle, smoke);
roadmap M12h table; `roadmap-appsec.md` §2, §4, §5 "Container hardening: what can break".

Binding language: **MUST** / **MUST NOT** / **SHOULD** / **MAY**.

Written against `cluster/alpha9-features` at `a54c1a82`. **M12h-1 belongs to alpha.10** (tickets PDK-819 to
PDK-827, §8); **M12h-2 is outlined in §13 for alpha.11** (no tickets). The split follows the roadmap's "may be
split" note: M12h-1 is what touches the surfaces M13b/M13c open (networks, limits, Valkey, the device's file
writes); M12h-2 is portal, parsers, Authentik and supply-chain work that stands alone.

## 1. Goal

After M12h-1 a compromised edge or identity container cannot reach PostgreSQL, OpenBao, Valkey or RabbitMQ; every
role can only read and write its own Valkey keys and nobody but the escrow-reader reads step-up tokens; every
unauthenticated endpoint answers 429 under abuse instead of consuming the host; every third-party container runs
with the minimum capabilities its entrypoint needs and a memory limit, and a lint plus `./paddock check` keep it
that way; the agent refuses to write below a parent directory a service user could redirect and the supervisor
unit is sandboxed as far as the agent's work allows. Nothing a device or an administrator sees changes, except
429 responses under abuse.

## 2. Context (verified in the code on 2026-11-05)

- `compose.yaml`: anchor `x-paddock` (`read_only`, `tmpfs /tmp`, `cap_drop ALL`, `no-new-privileges`,
  `pids_limit 256`) for the Paddock roles; `caddy` has `cap_drop ALL`, `cap_add NET_BIND_SERVICE`,
  `no-new-privileges`, `pids_limit`; `postgres`, `rabbitmq`, `valkey`, `rustfs`, `openbao` (`cap_add IPC_LOCK`),
  `authentik-postgres`, `authentik-server`, `authentik-worker`, `fleet-mysql`, `fleet-redis`, `fleet`,
  `prometheus` have `pids_limit` only; networks `cp`, `audit-index`, `escrow` (internal), `fleet` (internal);
  `compose.audit.yaml` likewise with `audit-postgres`, `audit-rustfs`; `compose.prod.yaml` `x-paddock-prod`,
  `PADDOCK_ADMIN_ALLOWED_CIDRS` default `0.0.0.0/0 ::/0`, `PADDOCK_INTERNAL_CIDRS` default `private_ranges`;
  `PADDOCK_TRUSTED_PROXY_CIDRS` default private ranges; `rabbitmq/enabled_plugins` = management + prometheus.
- `prodcheck` (`server/internal/prodcheck`): items over `compose config --format json` (`Service.Networks`,
  `CapAdd`, `CapDrop`, `SecurityOpt`, `PidsLimit` are already parsed); `deploy/bundle/ci/assert-hardening.sh`
  inspects running containers of the smoke test.
- Valkey: `deploy/compose/valkey/valkey.conf` with `requirepass` from a secret include; one `valkey_auth_conf`
  secret; clients in `server/internal/devicecache` (gateway: `dk:`, `bp:`, nonces, per-IP windows
  `DefaultPerIPLimit = 300`), `server/internal/sessions` (`sess:`, `acct-sess:`), `stepupproof` (`stepup:`),
  `allowlistcache`, the compiler's bundle pointers, the unsealer.
- Admin API: `server.go` body limits (`MaxDocumentBytes`, `maxBodyBytes`), `securityHeaders` (CSP, HSTS without
  `includeSubDomains`), no `ReadTimeout`/`WriteTimeout` (`cmd/paddock-server/api.go`, `gateway.go`:
  `ReadHeaderTimeout` only); Caddy sites `admin.`, `auth.`, `device.`, `bundles.`, `fleet.` with `body_limit`
  on some handlers.
- Agent: `agent/internal/fsutil` (`WriteFile`, `WriteFileOwned`, `writeSync`, `SyncDir`; `MkdirAll` and
  `Rename` resolve parents), `reconcile/system.go` `Lstat` at the final component; `packaging/systemd/
  paddock-supervisor.service` without sandboxing directives; `renderHimmelblauConf` without agent-side validation.
- Tools: `tools/migrationsfrozen`, `tools/upstreamwatch` (Go tools run by `make`); `make lint` aggregates.

## 3. Binding decisions (M12h-1)

### 3.1 Networks (PDK-819)

1. `compose.yaml` MUST define the networks `edge` (`ipam` subnet `PADDOCK_EDGE_SUBNET` default `172.28.0.0/24`;
   Caddy gets `ipv4_address` `172.28.0.10`), `data`, `authentik` (internal), keeping `escrow`, `fleet`,
   `audit-index`; membership: Caddy: `edge`; `paddock-api`, `paddock-gateway`: `edge` + `data` (+ `escrow` for the
   api); `authentik-server`: `edge` + `authentik` (its database is `authentik-postgres` on `authentik`; the
   implementer verifies from `compose.yaml` that it reaches no `data` service — the stack lists no Redis for
   Authentik; a dependency on a `data` service is a stop condition, §11); `authentik-worker`: `authentik`;
   `authentik-postgres`: `authentik`; `postgres`, `valkey`,
   `rabbitmq`, `openbao`: `data`; `rustfs`: `data` + `edge` (bundle and package reads through Caddy); `fleet`:
   `edge` + `fleet`; `fleet-mysql`, `fleet-redis`: `fleet`; the other Paddock roles: `data` (+ their special
   networks); `prometheus`: `data` + `edge` (scrapes Caddy); `paddock-backup`: `data` + `escrow`. `cp` is
   removed. The audit host keeps its files unchanged except `audit-rustfs` ↔ `paddock-audit-writer` on `audit-store`
   (exists) and the interconnect.
2. `PADDOCK_TRUSTED_PROXY_CIDRS` default becomes `172.28.0.10/32` (Caddy's address); `PADDOCK_INTERNAL_CIDRS`
   default in production becomes the `edge` subnet; `PADDOCK_ADMIN_ALLOWED_CIDRS` keeps `0.0.0.0/0 ::/0` as the
   *documented* default but `./paddock check` WARNs on it (the runbook recommends the office ranges);
   `rabbitmq.conf` gains `management.tcp.ip = 127.0.0.1` in `compose.prod.yaml`; `prod-check` items: `networks:
   caddy on edge only`, `networks: no datastore on edge`, `networks: fleet not on data`, `trusted proxies: caddy's
   address only`, `rabbitmq: management bound to loopback`. The development stack keeps the same topology
   (`compose.dev.yaml` adds published ports, never networks). The lab profile applies the same networks on one
   host.
3. Upgrade (ADR 0047): `./paddock up` recreates every container with the new networks; the `.env` key
   `PADDOCK_TRUSTED_PROXY_CIDRS` of an existing installation is listed by `upgrade-check` item `env` as *changed
   default*; the CI `upgrade` job proves alpha.9 → alpha.10 with the new topology.

### 3.2 Valkey ACL users (PDK-820)

4. `deploy/compose/valkey/valkey.conf`: `aclfile /run/valkey/users.acl`; the Valkey container's entrypoint wrapper
   (`deploy/compose/valkey/entrypoint.sh`, new, replacing the plain command) renders `users.acl` from the secrets
   `valkey_<role>_password` (`api`, `gateway`, `worker`, `compiler`, `escrow_reader`, `unsealer`; the backup
   and notifier roles use no Valkey; `user default off`) with the key patterns and command
   categories of ADR 0051 (binding list in §6.3); the file is written to a tmpfs, mode 0600, never logged.
   `gen-dev-secrets.sh` and `gen-prod-secrets.sh` generate the passwords; `valkey_auth_conf` is removed.
5. Every Valkey client takes `PADDOCK_VALKEY_USER` and `PADDOCK_VALKEY_PASSWORD_FILE` (`config.Loader`), with the
   role's user in `compose.yaml`; the unsealer and `admin rebuild-cache` use `worker`'s user; acceptance helpers
   use `api`'s. Step-up tokens (`stepup:*`): `api` `+set +del +expire`, `escrow-reader` `+get` (SE-2); device keys
   (`dk:*`): `worker` writes, `gateway` reads (and `setnx` nonces under `nonce:*`); bundle pointers (`bp:*`):
   `compiler` writes, `gateway` and `api` read; sessions (`sess:*`, `acct-sess:*`): `api` only; rate-limit windows
   (`rl:*`): `api` and `gateway`; allow-list cache (`al:*`): `api` writes, `gateway` reads.
6. `prod-check`: `valkey: ACL file mounted and default user off`, `valkey: every role has its own user`; the
   upgrade note documents the one-time secret generation (`./paddock secrets` creates them).

### 3.3 Application rate limiter (PDK-821)

7. Package `server/internal/platform/ratelimit` (`Limiter{store, clock}`, `Allow(ctx, class, key) (ok bool,
   retryAfter time.Duration, err error)`; fixed 60 s windows in Valkey `rl:<class>:<key>:<window>` with `INCR` +
   `EXPIRE`; fail-open on a store error with `paddock_ratelimit_errors_total`), classes and defaults:
   `auth` 20/min per IP (`/api/auth/*`, the MCP login), `admin_read` 600/min per principal (session or token),
   `admin_write` 120/min per principal, `platform_upload` 10/min per principal (artifact and package uploads),
   `bundles_apt` 60/min per IP (M13c's `/apt/*`), `device` the existing per-IP window moved here
   (`PADDOCK_DEVICE_PER_IP_LIMIT` default 300, `PADDOCK_DEVICE_PER_IP_V6_PREFIX` default 64: IPv6 keys are the
   /64), `device_key` the existing per-key window. 429 with `Retry-After` (seconds) and the problem code
   `rate_limited`; `paddock_ratelimit_rejected_total{class}`; never on `/healthz`, `/readyz`, `/metrics`. Settings
   `PADDOCK_RATELIMIT_<CLASS>` (0 = off, refused by `prod-check` in production).
8. Middleware order in the api: client IP (edge header) → rate limit `auth` for `/api/auth/*` → authentication →
   rate limit by principal → the handlers; in the gateway the existing windows are replaced by the package with
   the same semantics (gate `TestDeviceProtocol` rate cases stay green).

### 3.4 Third-party containers, lint, check (PDK-822 … PDK-825)

9. One service (group) per ticket, each merged only with its gate green (ADR 0051 option "one per PR"):
   - **PDK-822 PostgreSQL ×3 and Valkey ×2**: `cap_drop ALL`, `cap_add [CHOWN, SETUID, SETGID, DAC_OVERRIDE,
     FOWNER]` (PostgreSQL) / `[CHOWN, SETUID, SETGID]` (Valkey), `no-new-privileges`, `read_only` for Valkey
     (`/data` volume, `/tmp` tmpfs), `mem_limit` PostgreSQL 2g (paddock), 1g (authentik, audit), Valkey 512m;
     gates: `make acceptance` shards, `make restore-drill`, `TestWORM` unaffected.
   - **PDK-823 OpenBao and RustFS ×2**: the stock OpenBao entrypoint runs as root, `setcap`s the binary and drops
     privileges; the plan chooses **`user: "100:1000"` with `cap_drop ALL`, `cap_add [IPC_LOCK]` and
     `disable_mlock = false` kept** (pending maintainer, §12), the data directory pre-owned by a one-off `chown`
     step in `openbao-bootstrap.sh` that `./paddock up` runs; if the image refuses to start that way, the
     exceptions file records `SETUID,SETGID,CHOWN` with the reason and the root entrypoint stays; RustFS: inspect the image first
     (`docker inspect`), then `cap_drop ALL` + the measured set, `read_only` with `/data` and `/tmp`; gates:
     an OpenBao seal/unseal cycle with the dev shares, `make restore-drill` (OpenBao step), **`TestWORM` on the
     audit RustFS (ADR 0017)**.
   - **PDK-824 MySQL, RabbitMQ, Fleet, Fleet's Redis, Prometheus**: MySQL `cap_add [CHOWN, SETUID, SETGID,
     DAC_OVERRIDE]`; RabbitMQ `cap_drop ALL` without `read_only` (exception recorded: it renders its config and
     cookie); Fleet `cap_drop ALL`, `read_only` with `/tmp`; Prometheus `cap_drop ALL`, `read_only` with the data
     volume; `mem_limit` per service from the measured peaks of the lab (`docs/operations/capacity.md` gains the
     table); gates: the inventory gates (`TestInventory*`), `TestNotifications*`, `TestObservability`.
   - **PDK-825 Authentik server and worker**: `cap_drop ALL`, `no-new-privileges`, no `read_only` (exception:
     media, templates, blueprints), `mem_limit` 1g each; gate `TestIdentityLockAuthentik`, `TestStepUp*`, the
     e2e login suite.
10. `tools/composelint` + `make lint-compose` (in `make lint`): renders `docker compose config --format json` for
    every host's file set (`compose_files` of `lib.sh` for `controlplane`, `audit`, `lab`, and the dev set) and
    fails when a service lacks `cap_drop: [ALL]`, `security_opt no-new-privileges:true`, `pids_limit`, `mem_limit`
    (or `deploy.resources.limits.memory`), or has `cap_add` entries, unless `deploy/compose/hardening-exceptions.yaml`
    lists the service with the exact setting and a reason; the file is part of the bundle and `prod-check` reads
    it for the running-container matrix: `./paddock check --online` gains `containers: capabilities and security
    options match the matrix` (`docker inspect` of every running container of the project).
11. `deploy/bundle/ci/assert-hardening.sh` asserts the matrix against the running smoke stack (it exists; it
    gains the per-service expectations from the exceptions file instead of a hard-coded list).

### 3.5 Agent (PDK-826)

12. `fsutil.WriteFileOwned` and every path-creating primitive the reconcilers use (`MkdirAll`, `Rename`,
    `Remove`) MUST resolve the target's parent step by step with `openat2`-free Go primitives: open each component
    with `O_PATH|O_NOFOLLOW|O_DIRECTORY` from `/`, refuse a component that is a symlink (`ELOOP`/`ENOTDIR`), refuse
    a directory not owned by uid 0 or writable by group/others (mode `& 0o022 != 0`) unless the directory is one
    of the allow-listed sticky system directories (`/tmp`, `/var/tmp` — never used by managed files anyway),
    and perform the write relative to the final directory file descriptor (`unix.Openat`, `Renameat`,
    `Unlinkat`). A refusal is `reconcile.ErrParentNotTrusted`; a managed file below such a parent reports
    `failed/parent_not_trusted` in its resource status; the quarantine, the uninstall steps and the software
    reconciler's files use the same primitives. Paths under `/home` are refused by `pkg/policy` already (denied
    tier) — unchanged.
13. `packaging/systemd/paddock-supervisor.service` gains the directives of ADR 0051 (the "on" set) with the
    comment block naming why each "off" directive stays off; `paddock-disk-setup.service` gets the same "on" set
    (it reads the install passphrase from `/var/lib/paddock`, not from `/tmp`, so `PrivateTmp=yes` applies; the
    autoinstall gate proves it). The system gates on both VMs are the proof
    (`TestAgentGates`, `TestDiskGates`, `TestEncryptGates`, `TestSoftwareGates`, `TestSelfServiceGates`); a
    directive that breaks a gate is removed with the gate named in the comment.
14. `pkg/policy.ValidateLoginSpec(spec bundle.LoginSpec) error` holds the server's regexes for `domain`,
    `app_id`, `tenant_id`, group names and UPN patterns; the server calls it in `app.LoginSettings.Update` and the
    compiler before signing; the agent calls it in `reconcile.Login` before `renderHimmelblauConf` and refuses the
    resource with `failed/invalid_spec` (never writes a partial `himmelblau.conf`).

### 3.6 Servers and headers (PDK-827)

15. `cmd/paddock-server/api.go` and `gateway.go`: `ReadTimeout 60s`, `WriteTimeout 120s`, `IdleTimeout 120s`;
    the artifact and package upload handlers and the export download set `rc.SetWriteDeadline(now + 30 min)`
    through `http.NewResponseController`; the audit feed and lists are unaffected (seconds).
16. Caddy: a snippet `(hardening_headers)` imported by every site: `X-Content-Type-Options: nosniff`,
    `Referrer-Policy: strict-origin-when-cross-origin`, `Strict-Transport-Security: max-age=31536000;
    includeSubDomains`, `X-Frame-Options: DENY`; `request_body` per site: `admin` 2 MiB default with the
    256 MiB matcher for `/api/platform/v1/agent-releases/*` and `/api/v1/software-packages`, `device` 1 MiB (the
    escrow presign path keeps 33 MiB), `bundles` 1 MiB, `auth` 1 MiB, `fleet` 64 MiB (Fleet's documented
    maximum). The admin api's `securityHeaders` gains `includeSubDomains`. `make lint-caddy` renders both
    Caddyfiles; the acceptance gate `TestEdgeHeaders` (new) asserts the headers on every site of the dev stack.

### 3.7 Threat model (M12h-1)

| Threat | Before | After |
| --- | --- | --- |
| Compromised Caddy or Authentik container reaches PostgreSQL/OpenBao/Valkey | yes (flat `cp`) | no (`edge` only) |
| Any container spoofs the client IP to the api | yes (private ranges trusted) | no (Caddy's address only) |
| Gateway code execution writes device keys or reads step-up tokens | yes (one password) | no (ACL users) |
| Credential stuffing on `/api/auth/*`, enumeration on `/apt/*` | unlimited | 429 after the window |
| A runaway third-party container starves the host | pids only | pids + memory limits |
| A service-user-owned parent redirects an agent write | yes | refused `parent_not_trusted` |
| A malformed login spec from a compromised server renders a broken `himmelblau.conf` | yes | refused `invalid_spec` |

## 4. Non-goals (M12h-1)

- No Caddy rate-limit plugin or custom Caddy image; no Renovate, Scorecard or new CI tools (M12h-2, maintainer).
- No change to the Paddock roles' images; no `user:` change for third-party images except OpenBao as decided.
- No Trusted Types, isolation headers beyond §3.6, Authentik policies, fuzzing, runtime OpenAPI validation,
  SECURITY DEFINER lint, log redaction, key rotation job, SLSA/SBOM work (M12h-2).
- No change to the revocation path, `pkg/revocation`, or the two-person-rule files.

## 5. Affected files (M12h-1)

`deploy/compose/compose.yaml`, `compose.prod.yaml`, `compose.dev.yaml`, `compose.lab.yaml`, `compose.backup.yaml`,
`compose.audit.yaml`, `compose.auto-unseal.yaml`, `deploy/compose/valkey/{valkey.conf,entrypoint.sh}`,
`deploy/compose/rabbitmq/rabbitmq.conf`, `deploy/compose/caddy/Caddyfile*`, `deploy/compose/hardening-exceptions.yaml`
(new), `deploy/compose/scripts/{gen-dev-secrets,gen-prod-secrets,openbao-bootstrap,lib}.sh`,
`deploy/bundle/ci/{assert-hardening.sh,compose.ci.yaml}`, `deploy/bundle/paddock` (check item),
`tools/composelint/`, `Makefile`, `server/internal/prodcheck/*`, `server/internal/platform/ratelimit/` (new),
`server/internal/devicecache/gateway.go`, `server/internal/transport/http/{admin,device}/*` (middleware),
`server/internal/config`, `server/cmd/paddock-server/{api,gateway}.go`, every Valkey client package,
`agent/internal/fsutil/*`, `agent/internal/reconcile/{system,file,login,software}.go`,
`agent/internal/uninstall/steps.go`, `pkg/policy/login.go` (new), `packaging/systemd/*.service`,
`test/acceptance/{edge_headers_test.go,ratelimit_test.go}` (new), `docs/operations/{install,upgrade,capacity,
monitoring}.md`, `docs/architecture.md` §4.1/§10, `docs/compliance/residual-risks.md` (RR-119–RR-121).

## 6. Interfaces

### 6.1 Environment (new or changed)

```
PADDOCK_EDGE_SUBNET=172.28.0.0/24            PADDOCK_TRUSTED_PROXY_CIDRS=172.28.0.10/32 (default)   PADDOCK_INTERNAL_CIDRS=<edge subnet> (prod default)
PADDOCK_VALKEY_USER=<role>  PADDOCK_VALKEY_PASSWORD_FILE=/run/secrets/valkey_<role>_password
PADDOCK_RATELIMIT_AUTH=20  PADDOCK_RATELIMIT_ADMIN_READ=600  PADDOCK_RATELIMIT_ADMIN_WRITE=120  PADDOCK_RATELIMIT_PLATFORM_UPLOAD=10  PADDOCK_RATELIMIT_BUNDLES_APT=60
PADDOCK_DEVICE_PER_IP_LIMIT=300  PADDOCK_DEVICE_PER_IP_V6_PREFIX=64
```

### 6.2 Problem code and metrics

`rate_limited` (429, `Retry-After`); `paddock_ratelimit_rejected_total{class}`, `paddock_ratelimit_errors_total`;
alert `PaddockRateLimitStorm` (`rate(rejected[5m]) > 50` warning).

### 6.3 Valkey ACL (binding)

```
user default off
user api            on >… ~sess:* ~acct-sess:* ~stepup:* ~bp:* ~al:* ~rl:* ~nonce:* +@read +@write +@keyspace +@string +@set +@hash -@dangerous -@admin
user gateway        on >… ~dk:* ~bp:* ~nonce:* ~rl:* ~al:* +get +mget +set +setnx +setex +incr +expire +ttl +del +exists +ping -@all
user worker         on >… ~dk:* ~bp:* ~al:* ~cache:* +@read +@write +@keyspace -@dangerous -@admin
user compiler       on >… ~bp:* +get +set +setex +del +ping -@all
user escrow_reader  on >… ~stepup:* +get +ping -@all
user unsealer       on >… ~unseal:* +get +set +setex +del +ping -@all
```

(the implementer takes the exact key prefixes from the packages; a missing prefix is a stop condition, never a
wildcard `~*`).

### 6.4 Residual risks (RR-119 to RR-121)

| ID | Risk | Mitigation | ISMS |
| --- | --- | --- | --- |
| RR-119 | Fixed-window limits allow a burst of 2× the limit at a window edge; a NAT with many administrators shares the `auth` limit per IP | per-principal limits after authentication; the operator raises `PADDOCK_RATELIMIT_AUTH` for large NATs | office NAT sizing |
| RR-120 | Memory limits derived from lab peaks; a larger installation may OOM a service (OpenBao → sealed) | `capacity.md` table, alert `PaddockRoleDown`, the limits are `.env`-tunable | capacity review per installation |
| RR-121 | Sandboxing of the supervisor unit is validated on Ubuntu 24.04/26.04 only; another systemd version may reject a directive | the gates per release; a rejected directive stops the unit, which the supervisor's watchdog surfaces | distribution scope |

## 7. Architecture amendments (PDK-827)

§4.1 (the control-plane networks by zone), §10 (Valkey users), §9.4 (rate limits), §11.1 (sandboxed unit, the
parent rule), `docs/operations/install.md` §1 (the seccomp/AppArmor expectation, CR-7), `upgrade.md` (networks,
Valkey secrets, defaults), `capacity.md` (limits table), `monitoring.md` (the new alert).

## 8. Steps (tickets, in order; M12h-1)

1. **PDK-819 — Network segmentation, trusted-proxy and CIDR defaults, RabbitMQ management on loopback, prod-check
   items.** §3.1. Verify: `make acceptance` shards, `smoke.sh`, the CI `upgrade` job (alpha.9 → candidate).
2. **PDK-820 — Valkey ACL users per role.** §3.2, §6.3. Independent of 819. Verify: acceptance incl. step-up and
   escrow-reader gates; a unit test that every client package's prefixes are in the ACL file (the test renders
   the ACL and greps each package's `const` prefixes).
3. **PDK-821 — Application rate limiter (api, gateway, bundles).** §3.3. Independent. Verify: `TestRateLimit`
   acceptance (429 + `Retry-After` on `/api/auth/*`, per-principal on admin, `/healthz` never), `TestDeviceProtocol`.
4. **PDK-822 — Container hardening: PostgreSQL ×3, Valkey ×2.** §3.4 (with `composelint` and the exceptions file
   created here). Verify: acceptance shards, `make restore-drill`, `TestWORM`.
5. **PDK-823 — Container hardening: OpenBao, RustFS ×2.** Verify: seal/unseal cycle, restore drill, `TestWORM`.
6. **PDK-824 — Container hardening: MySQL, RabbitMQ, Fleet, Fleet Redis, Prometheus; `capacity.md` limits.**
7. **PDK-825 — Container hardening: Authentik; `./paddock check --online` container matrix;
   `assert-hardening.sh` from the exceptions file.** Verify: `TestIdentityLockAuthentik`, e2e login, `smoke.sh`.
8. **PDK-826 — Agent: parent-directory safety, supervisor sandboxing, login spec validation.** §3.5. Verify:
   `go test ./agent/... ./pkg/policy/`; `make system-test VM=all` (every gate).
9. **PDK-827 — Server timeouts, Caddy headers and body limits per site, `TestEdgeHeaders`, documents, RR.** §3.6, §7.

Parallelism: 819 ‖ 820 ‖ 821 (three independent chains); 822 → 823 → 824 → 825 strictly sequential (one
service group per PR, each with its gate); 826 and 827 independent of the rest. The CI `upgrade` job runs for every
ticket (PRs to `cluster/alpha10-features` gate `acceptance`; the orchestrator runs the upgrade job before the
cluster merges to `main`).

## 9. Tests and gates (M12h-1)

- Unit: `ratelimit` (window edges, fail-open, IPv6 prefix keys); `composelint` (missing setting, exception with
  reason, cap_add without exception, every host file set); `prodcheck` new items; `fsutil` parent rules (symlink
  parent, group-writable parent, sticky allow list, relative-fd writes) with a temp tree; `policy.ValidateLoginSpec`
  table; ACL coverage test.
- Acceptance: `TestRateLimit`, `TestEdgeHeaders`, every existing gate (the hardening tickets change nothing
  functional); `TestIsolation` unchanged.
- Shell/CI: `smoke.sh` + `assert-hardening.sh` matrix; the `upgrade` job (ADR 0047) for the Compose changes.
- System: every VM gate after PDK-826.
- Never weakened: `TestWORM`, `TestStepUp*`, `TestEscrow*`, `TestDeviceProtocol`.

## 10. Acceptance criteria (M12h-1)

- **C1 (ADR 0051 decision 1; operator):** `./paddock check` fails on a datastore reachable from `edge`; from
  inside the Caddy container `postgres:5432` and `openbao:8200` are unreachable (smoke assertion).
- **C2 (decision 2; operator):** `redis-cli` as the gateway user cannot `GET stepup:x` or `SET dk:x`; as the api
  user it cannot read `dk:*`.
- **C3 (decision 3; administrator, attacker):** 25 sign-in attempts per minute from one address → 429 with
  `Retry-After`; a device's check-in is unaffected; `/healthz` never limited.
- **C4 (decision 4; operator):** `make lint-compose` fails on a removed `cap_drop`; every running container's
  capabilities match the matrix; every gate stays green after each hardening PR.
- **C5 (decision 5; device user):** a managed file whose parent a service user owns is refused and reported; the
  supervisor runs sandboxed on both VMs with every gate green.
- **C6 (decision 6; administrator):** every site answers with the hardening headers; a 3 MiB body to the admin
  API is refused by Caddy (413).

## 11. Stop conditions

- A third-party entrypoint needs a capability not listed and the exceptions file would need `SYS_ADMIN` or
  `NET_ADMIN`: report; do not grant.
- Authentik needs `data` network access (decision 1): report with the dependency; keep it on `edge` + `authentik`
  until decided.
- A Valkey client uses a key prefix not in §6.3: add it to the ACL with the ticket's review, never `~*`.
- A sandbox directive breaks a VM gate: remove it and record the gate in the unit's comment (not a stop).
- Any new Go module, npm package, container image, CI tool, or Caddy plugin.

## 12. Risks and open points

- R1 Compose topology change on upgrade: proven by the CI `upgrade` job; the lab upgrade before the release.
- R2 Memory limits too tight: tunable, alert, capacity table.
- R3 Fixed-window limiter edge bursts: documented (RR-119).

Open questions — **maintainer**: (1) `PADDOCK_ADMIN_ALLOWED_CIDRS` default stays `0.0.0.0/0 ::/0` with a WARN
(recommended) or becomes required in production (a public promise about installation friction); (2) OpenBao
with `user: 100:1000` instead of the root entrypoint (changes the volume ownership on upgrade — recommended yes,
with the one-off chown in `./paddock up`'s bootstrap and the restore drill as the gate). **Architect lead**:
(3) the limit defaults of decision 7 (recommended); (4) the network names and subnet (recommended); (5) the ACL
command sets (recommended; a stop condition guards prefixes).

## 13. Outline M12h-2 (alpha.11; no tickets)

- **Authentik controls (AU-3, AU-4, AU-6):** reputation policy with `failed_attempts_before_cancel` plus the
  reputation scoring in the portal and device flows (blueprint change, `TestIdentityLockAuthentik`), MFA enrolment
  by invitation (`not_configured_action: deny` plus an invitation stage, maintainer: changes the first-login
  promise), API tokens refused once their creator lost the rights (`api_token.use_denied` reason
  `creator_demoted`).
- **Portal (PO-1, PO-2, AU-5):** Trusted Types report-only → enforce (Vue 3 compatible; a Playwright console
  gate), `Permissions-Policy`, COOP/CORP, `__Host-` cookie prefixes (session cookie version 3).
- **Parsers (IV-1, IV-2, IV-5):** fuzz targets for `bundle.VerifyVersions`, `command.Verify`, `timeticket.Verify`,
  escrow parsing, `declarative` and the admin validators; runtime OpenAPI request validation with kin-openapi
  (already a dependency) behind a feature flag first; fixed binder error details.
- **Database and secrets (AZ-2, AZ-3, SE-1, CK-1, CK-3):** SECURITY DEFINER inventory with a lint
  (`search_path = pg_temp`, a reason per function), the role-matrix gate (every OpenAPI operation × role, generated
  from `x-paddock-roles`), `slog` `ReplaceAttr` redaction, a monthly session-key rotation job
  (`platform.session_key_rotated`), escrow-reader bearer rotation with the AppRole secret IDs.
- **Supply chain and CI (SC-1, SC-2, SC-4, CI-1; SC-5, SC-6 maintainer):** `buildx --provenance=mode=max`,
  `cosign attest-blob` with SLSA predicates for agent binaries, debs and the bundle, SBOMs for the agent
  artifacts, `npm ci --ignore-scripts`, `persist-credentials: false` on every checkout; Renovate and OpenSSF
  Scorecard only with the maintainer's tool decision.
- **Documentation (CR-7):** the seccomp/AppArmor expectation in `install.md` (done in M12h-1 §7) and a threat-model
  section per plan (practice §3 of `roadmap-appsec.md`).
- Dependencies: M12h-2 needs nothing from M13b/M13c; the role-matrix gate benefits from every endpoint of
  alpha.10 being in place. Open decisions before its plan: the MFA enrolment model (maintainer), the Trusted
  Types enforcement date (architect lead), new CI tools (maintainer).
