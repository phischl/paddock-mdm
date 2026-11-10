# Implementierungsplan: M12h — Application hardening (first half in alpha.10; second half outlined for alpha.11)

Status: Ready for implementation (M12h-1) · 2026-11-05 · Author: architect · **Amendment 2026-11-08 (§14): the
Valkey ACL of PDK-820 is revised against the code; §14 supersedes §3.2 decisions 4–5, §6.3, §8 step 2 and §10 C2.**
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
role can only read and write its own Valkey keys, only the api reads and writes step-up tokens and only the
escrow-reader counts their uses (§14, RR-129); every
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

> **Superseded on 2026-11-08 by §14** (decisions 4 and 5 in full; decision 6 is kept and extended by §14.9). The
> text below is kept for the record and MUST NOT be implemented.

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
    a directory not owned by uid 0 or writable by group/others (mode `& 0o022 != 0`; group write by gid 0 without
    an access ACL allowed, see Correction 2026-11-09, PDK-963) unless the directory is one
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
    **Note 2026-11-10:** behind the edge the 60 s do not hold for one case, a slow body on a non-GET request
    answered 2xx/3xx without reading it (about 120 s); see RR-131 (§6.4) and the amendment "2026-11-10 (PDK-970,
    PDK-971)" at the end of this plan.
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
`compose.audit.yaml`, `compose.auto-unseal.yaml`, `deploy/compose/valkey/{valkey.conf,entrypoint.sh}` (PDK-820's full
file list is §14.12),
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

> **Superseded on 2026-11-08 by §14.3 to §14.5.** The list below contains prefixes that do not exist in the code
> (`al:*`, `cache:*`, `unseal:*`), misses 18 keys that do, gives the escrow-reader a read it never performs and the
> unsealer a user it does not need. It is kept for the record and MUST NOT be rendered.

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
| RR-129 | The api reads raw step-up ID tokens (`stepup:<jti>`) to forward them to the escrow-reader and the revocation approval (added 2026-11-08, §14.9) | token TTL, `MaxUses` counted by the escrow-reader in a key the api cannot write, `revocation-jti` claims, audit | accepted for alpha.10; M12h-2 candidate |
| RR-130 | The worker can enumerate and delete portal session records (account revocation runs in the worker; added 2026-11-08, §14.9) | sealed cookies: a session identifier alone is not a bearer; the worker is on `data` only | accepted |
| RR-131 | A slow request body on a non-GET request that a role answers 2xx/3xx without reading it is cut after about 120 s (`WriteTimeout`) instead of 60 s (`ReadTimeout`), on HTTP/1.x; anonymous case `POST /api/auth/logout` without a cookie (added 2026-11-10, amendment "2026-11-10 (PDK-970, PDK-971)") | the rate limiter (`auth` per address, admin API per principal, device API per device and address), the edge body limits; error answers, GET/HEAD and every body-reading route end at 60 s (PDK-970) | accepted for alpha.10; fixed in alpha.11 by PDK-971 |

## 7. Architecture amendments (PDK-827)

§4.1 (the control-plane networks by zone), §8.3 (Valkey users and the key table; written by PDK-820, §14.11), §9.4 (rate limits), §11.1 (sandboxed unit, the
parent rule), `docs/operations/install.md` §1 (the seccomp/AppArmor expectation, CR-7), `upgrade.md` (networks,
Valkey secrets, defaults), `capacity.md` (limits table), `monitoring.md` (the new alert).

## 8. Steps (tickets, in order; M12h-1)

1. **PDK-819 — Network segmentation, trusted-proxy and CIDR defaults, RabbitMQ management on loopback, prod-check
   items.** §3.1. Verify: `make acceptance` shards, `smoke.sh`, the CI `upgrade` job (alpha.9 → candidate).
2. **PDK-820 — Valkey ACL users per role.** **§14** (supersedes §3.2 and §6.3). Independent of 819 (both edit the
   `valkey` service block of `compose.yaml`; the second to merge rebases). Verify: the role-matrix test §14.10.1,
   `TestValkeyACL` §14.10.2, every acceptance gate (step-up, escrow reveal, device protocol, sessions, IP allow
   list, admin commands), the CI `upgrade` job.
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
- **C2 (decision 2; operator):** replaced on 2026-11-08 by **C2a–C2f in §14.13**.
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
- A Valkey client uses a key, prefix or command not in §14.4/§14.5: stop and report (§14.14); never `~*`, never a
  category wider than §14.5 grants.
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
command sets — **decided 2026-11-08 by the architect lead's guidelines (A10-2), see §14**.

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

## Amendment 2026-11-08 (architect-lead decision Q19)

Open point (4) of §12 is decided: the network names `edge`, `data` and `authentik` and the edge subnet
`172.28.0.0/24` (Caddy at `172.28.0.10`) are accepted as proposed in §3.1 and §6.1. The rate-limit defaults of §3.3
and the ACL command sets of §6.3 (open points 3 and 5) are accepted by the same decision; a Valkey key prefix missing
from the ACL stays a stop condition, never `~*`. Open point (1), the default of `PADDOCK_ADMIN_ALLOWED_CIDRS`, is
still with the maintainer: until answered the recommended variant applies (the default stays open, `./paddock check`
warns).

## Amendment 2026-11-08 (architect-lead decision A10-1, PDK-819)

The implementation of §3.1 deviates from its membership list as follows; decision A10-1 (`decisions-alpha10.md` §9)
accepts it with the conditions below.

- `paddock-worker`, `paddock-escrow-reader` and `paddock-revocation-issuer` join `data` **and** `edge`, not `data`
  alone: the worker calls Authentik's API and the certificate probe through Caddy's aliases and Fleet's API
  (`fleet:8080`), and the escrow-reader and the revocation-issuer run the step-up issuer's discovery against
  `auth.<domain>`.
- Condition: the ops listener (port 9090: `/healthz`, `/readyz`, `/metrics`) of these three roles is not reachable
  from `edge`. Each binds `PADDOCK_OPS_ADDR` to an alias that exists on `data` only (`worker-ops`,
  `escrow-reader-ops`, `revocation-issuer-ops`), as the escrow-reader's API already binds to its `escrow` alias; no
  new dependency. `prod-check` item `networks: ops listeners off edge` fails a role of the three on `edge` whose ops
  listener binds to every address or to a name that is not an alias of another network only. Gates: acceptance
  `TestOpsListenersOffEdge` (9090 of the three and the escrow-reader's API refuse a container on `edge`; 9090 answers
  on `data`) and `deploy/bundle/ci/assert-segmentation.sh` (the same from inside Caddy, by name and by edge address).
  With the worker scaled (`--scale paddock-worker=N`) every replica carries the alias; the ops listener therefore
  binds the one resolved address that is assigned to a local interface and fails closed on none or several, and the
  container health check dials that same address.
- Residual risk (until PDK-824 and PDK-825 land): under Linux's weak host model a container on `edge` that may craft
  or route packets (`NET_RAW`/`NET_ADMIN`; `fleet` and `authentik-server` keep Docker's default `NET_RAW`, Caddy drops
  every capability) can reach the `data`-bound port 9090 through a role's `edge` interface. PDK-824 (Fleet) and
  PDK-825 (Authentik) close it by dropping those capabilities. The exposure is limited: `/healthz` returns a fixed
  text, `/readyz` the dependency error texts (PostgreSQL errors omit the password, OpenBao errors carry URL and status,
  not the request body), and `/metrics` counters and gauges labelled by status, store, route, code, host and reason;
  none carries a secret.
  - *Closed 2026-11-09 (PDK-824, PDK-825):* `fleet` (PDK-824) and `authentik-server` (PDK-825) run with
    `cap_drop: [ALL]` and `no-new-privileges`; a container of each image shows CapPrm, CapEff and CapBnd 0. `rustfs`
    keeps Docker's default capabilities until PDK-823, but it is on `data` as well, so its `edge` interface adds no
    path to the `data`-bound port 9090; it is outside this risk.
- `prometheus` is on `data` only, not `data` + `edge`: it scrapes no Caddy target. The k6 load generator joins
  `data` beside `edge` to read the queue backlog.
- `edge` gets the pool of dynamic addresses `PADDOCK_EDGE_IP_RANGE` (default `172.28.0.128/25`), and Caddy's fixed
  address must lie outside it, so that no container started while Caddy is down takes the trusted proxy's address;
  `networks: caddy on edge only` fails a missing pool or Caddy inside it. `PADDOCK_EDGE_CADDY_ADDRESS` and the
  per-instance development subnets `172.28.(n-1).0/24` (pool `172.28.(n-1).128/25`) are accepted.
- Production keeps one documented, overridable subnet; `./paddock check` warns (item `networks: edge subnet free on
  this host`) when an existing Docker network other than `<project>_edge` overlaps it.

## 14. Amendment 2026-11-08 (PDK-820, A10-2) — Valkey ACL users revised against the code

Author: architect · basis: the implementer's key-prefix inventory of PDK-820 (stopped before any code change),
`cluster/alpha10-features` at `2a4e061b`, the architect lead's guidelines of 2026-11-08 (A10-2), ADR 0051
amendment 2026-11-08. This section **supersedes §3.2 decisions 4–5, §6.3, §8 step 2 and §10 C2**. Where this section
and an earlier section disagree, this section wins. Everything else in the plan is unchanged.

### 14.1 Why

§6.3 was written from ADR 0051's option text, not from the code. The code uses 25 keys or prefixes; §6.3 named 7,
three of which do not exist (`al:*`, `cache:*`, `unseal:*`). The unsealer uses no Valkey at all
(`compose.auto-unseal.yaml`: "no Valkey"); the revocation-issuer does (`cmd:*`, `revocation-jti:*`) and had no user.
The escrow-reader never reads `stepup:*`: the api reads the raw token (`app/escrowdecrypt.go`, `app/revocations.go`)
and passes it to the escrow-reader in the request; the escrow-reader only counts uses in `stepup-uses:*`. The
command sets of §6.3 (`-@all +get +set …`) would have broken the gateway's Lua scripts, hashes and transactions.
Fleet's Redis mounts the same `valkey.conf`, so `aclfile` in that file would have changed Fleet.

### 14.2 Decisions (A1–A12; binding)

- **A1 Users.** Paddock's Valkey has exactly these users: `api`, `gateway`, `worker`, `compiler`, `escrow_reader`,
  `revocation_issuer`, `healthcheck`, and `default` (off). The development and CI stack adds `acceptance`
  (§14.6.4). There is **no** `unsealer`, `notifier`, `backup`, `audit_writer` or `outbox_relay` user: those roles
  open no Valkey client. One user per role that has a client, because a user for a role without a client is a
  credential nobody rotates and nobody notices.
- **A2 Key permissions by direction.** A user gets `~<pattern>` (read and write) on the keys its code writes and
  `%R~<pattern>` (read only) on the keys it only reads. The table in §14.4 is derived from the code, is complete for
  `2a4e061b`, and is the **only** source of the patterns. Writers need `~` because `HSET`, `HDEL`, `INCR`,
  `EXPIRE*`, `SADD`, `SREM` and the declared `KEYS` of `EVAL`/`EVALSHA` carry read-and-write key flags in Valkey.
- **A3 Commands by need.** Every user is `-@all` plus the exact commands its code issues (§14.5), plus the
  connection set `+hello +ping +client|setinfo` that `valkey-go` v1.0.79 sends on connect (`HELLO 3 AUTH`, two
  `CLIENT SETINFO`). No production user gets a category; only the development-and-CI user `acceptance` does
  (§14.6.4). No user gets `CONFIG`, `FLUSHALL`, `FLUSHDB`, `KEYS`, `DEBUG`, `MODULE`,
  `ACL`, `SHUTDOWN`, `MIGRATE`, `SCRIPT`, `FUNCTION`, `CLIENT KILL|LIST|PAUSE`, `MONITOR`, `SAVE`, `BGSAVE`,
  `REPLICAOF`, `SLAVEOF`, `CLUSTER`, `PSYNC`, `SYNC`, `SORT` — that is `-@dangerous -@admin` restated as the
  absence of grants. The commands inside a Lua script are checked against the caller's ACL too (Valkey semantics
  since Redis 7), so a script needs each command it calls granted.
- **A4 Step-up: narrowed goal, contract unchanged.** The api keeps `~stepup:*` (`SET PX`, `GET`); the
  escrow-reader gets only `~stepup-uses:*` (`INCR`, `EXPIREAT`). `EscrowDecryptRequest.StepUpIDToken`, the
  revocation approval flow (`app/revocations.go`, the revocation-issuer, `pkg/revocation`, the agent's revoke
  path) are **not** touched. The residual risk is RR-129 (§14.9). Moving the token fetch into the escrow-reader
  is a contract change plus a revocation-path change under the two-person rule and goes to M12h-2 as a candidate.
- **A5 Revocation-issuer user.** `revocation_issuer`: `~revocation-jti:*` (`SET NX EX`, `GET`) and `~cmd:*`
  (`HSET`, `HEXISTS`, `HDEL`). The gateway reads `cmd:*` only (`%R~`), so a compromised gateway cannot inject or
  remove a signed command — the AZ-4 goal for the revocation channel.
- **A6 Hashed passwords in the ACL file.** The entrypoint renders `user <name> on #<sha256-hex>` from each
  secret file (`sha256` of the file content with surrounding whitespace stripped, the same trimming as
  `config.Loader.SecretFile`); the rendered file holds no plaintext password. Valkey accepts `#<hex>` in `aclfile`.
- **A7 Fleet's Redis keeps its configuration.** `deploy/compose/valkey/fleet-redis.conf` (new) is the byte-for-byte
  content of today's `valkey.conf`; `fleet-redis` mounts it at `/etc/valkey/valkey.conf` (its `command`, secrets
  and health check stay as they are). Paddock's `valkey.conf` loses `include /run/secrets/valkey_auth_conf` and
  gains `aclfile /run/valkey/users.acl`. Fleet is out of scope for every other change.
- **A8 Host tooling runs as `worker`.** `paddock-server admin rebuild-cache|end-sessions|allowlist|upgrade-check`
  run inside the `paddock-worker` container (`./paddock compose run --rm --no-deps paddock-worker admin …`, the
  only documented invocation; the admin loader reads `PADDOCK_DB_WORKER_URL_FILE`) and therefore authenticate as
  `worker`. The worker's patterns gain `~ipal:ver` and `~sess-gen` (two integrity-only keys: a bump reloads the
  allow list, an increment ends every portal session). Reasoning in §14.8.
- **A9 Health check user.** The container health check runs `valkey-cli --user healthcheck ping` with the secret
  `valkey_healthcheck_password`; the user has no key pattern and only the connection set. `default` stays off.
- **A10 Test approach.** A role-matrix test starts Valkey with the **real** entrypoint, template and configuration
  (testcontainers), opens one client per user and runs the real package methods of each role under that user;
  it also probes that denied commands fail with `NOPERM`. An acceptance gate `TestValkeyACL` repeats six probes
  against the running stack through `valkey-cli`. A `NOPERM` anywhere in the acceptance suite is a stop
  condition, not something to fix by widening the ACL (§14.14).
- **A11 Environment.** Every Valkey client reads `PADDOCK_VALKEY_USER` (required) and
  `PADDOCK_VALKEY_PASSWORD_FILE` (required, as today); `valkey.Config` gains `Username string`. The secrets are
  `valkey_<user>_password`, one file each, created by `gen-dev-secrets.sh` and `gen-prod-secrets.sh`; the
  secrets `valkey_password` and `valkey_auth_conf` are removed from every Compose file and from both generators
  (Fleet's `fleet_redis_password` and `fleet_redis_auth_conf` stay).
- **A12 Upgrade (ADR 0047).** `./paddock up` already runs `gen-prod-secrets.sh` before `compose up`, so the seven
  new secret files appear on the first `./paddock up` of alpha.10 without an operator step; the stale files
  `.secrets/valkey_password` and `.secrets/valkey/auth.conf` are harmless and `upgrade.md` says they may be
  deleted. The CI `upgrade` job (alpha.9 → candidate) proves it.

### 14.3 ACL template (binding; file `deploy/compose/valkey/users.acl.tmpl`)

`#{{<user>}}` is replaced by `#<sha256-hex of the user's secret>` by the entrypoint (§14.6.1). Every line is one
user; the order of the command rules matters (`-@all` first). The connection set is identical for every user.

```
user default off
user api on #{{api}} ~sess:* ~acct-sess:* ~sess-gen ~mcp-bind:* ~acct-mcp-bind:* ~mcp-chain:* ~mcp-used:* ~stepup:* ~ipal:ver ~et:* ~cmd:* ~cres:* ~rl:* %R~ar:current -@all +hello +ping +client|setinfo +get +mget +set +del +exists +incr +expire +pexpire +pexpireat +multi +exec +hset +hdel +sadd +srem +smembers +sismember +eval +evalsha
user gateway on #{{gateway}} %R~dk:* %R~bp:* %R~et:* %R~cmd:* %R~tt:* %R~ar:current %R~au:* %R~esc:* ~nonce:* ~seq:* ~sd:* ~rl:* ~enr:* ~cres:* ~diag:* -@all +hello +ping +client|setinfo +get +set +del +exists +incr +decr +expire +multi +exec +hset +hgetall +hexists +pexpireat +eval +evalsha
user worker on #{{worker}} ~dk:* ~seq:* ~enr:* ~et:* ~au:* ~esc:* ~cmd:* ~hb:* ~sd:* ~ar:current ~sess:* ~acct-sess:* ~acct-mcp-bind:* ~mcp-bind:* ~mcp-chain:* ~ipal:ver ~sess-gen -@all +hello +ping +client|setinfo +get +set +del +exists +incr +multi +exec +hset +hdel +hexists +pexpireat +smembers +eval +evalsha
user compiler on #{{compiler}} ~bp:* ~tt:* -@all +hello +ping +client|setinfo +set +del +multi +exec +hset +hgetall
user escrow_reader on #{{escrow_reader}} ~stepup-uses:* -@all +hello +ping +client|setinfo +incr +expireat
user revocation_issuer on #{{revocation_issuer}} ~revocation-jti:* ~cmd:* -@all +hello +ping +client|setinfo +get +set +hset +hexists +hdel
user healthcheck on #{{healthcheck}} -@all +hello +ping +client|setinfo
```

File `deploy/compose/valkey/users.acl.dev.tmpl` (mounted by `compose.dev.yaml` only, §14.6.4):

```
user acceptance on #{{acceptance}} ~* -@all +@read +@write +@scripting +@transaction +hello +ping +client|setinfo -@dangerous
```

### 14.4 Keys per user (derived from the code at `2a4e061b`; complete)

Type and commands are those the code issues. "RW" is `~pattern`, "R" is `%R~pattern`. A user not listed for a key
has no access to it.

| Key | Type | Written by (method) | Read by (method) | api | gateway | worker | compiler | escrow_reader | revocation_issuer |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `dk:<key_id>` | hash | worker `PutDeviceKey` (`MULTI DEL HSET EXEC`) | gateway `DeviceKey` (`HGETALL`) | – | R | RW | – | – | – |
| `seq:<device>` | string | worker `RestoreSeq` (`SET NX`); gateway `NextSeq`/`ReleaseSeq` (Lua `EXISTS INCR` / `GET DECR`) | gateway | – | RW | RW | – | – | – |
| `sd:<device>` | string | gateway and worker `MarkDelivered` (Lua `GET SET`) | gateway `LastDelivered` (`GET`) | – | RW | RW | – | – | – |
| `nonce:<device>:<nonce>` | string | gateway `UseNonce` (`SET NX EX`) | gateway | – | RW | – | – | – | – |
| `rl:<scope>:<minute>` | string | gateway `Allow` (`INCR EXPIRE GET`); api (PDK-821, same package) | gateway, api | RW | RW | – | – | – | – |
| `bp:<device>` | hash | compiler `PutBundlePointer` (`HGETALL` then `MULTI DEL HSET EXEC`) | gateway `BundlePointer` (`HGETALL`) | – | R | – | RW | – | – |
| `tt:<org>` | string | compiler `PutTimeTicket` (`SET`) | gateway `TimeTicket` (`GET`) | – | R | – | RW | – | – |
| `et:<sha256>` | hash | api `PutToken`, worker `PutToken` (`MULTI DEL HSET PEXPIREAT EXEC`; `DEL` when expired) | gateway `Token` (`HGETALL`) | RW | R | RW | – | – | – |
| `enr:<id>` | hash | worker and gateway `PutEnrollment` (`MULTI DEL HSET PEXPIREAT EXEC`) | gateway `Enrollment` (`HGETALL`) | – | RW | RW | – | – | – |
| `cmd:<device>` | hash | worker, revocation_issuer `PutCommand` (`HSET`); api, worker, revocation_issuer `DeleteCommand` (`HDEL`); worker, revocation_issuer `HasCommand` (`HEXISTS`) | gateway `Commands` (`HGETALL`), `HasCommand` (`HEXISTS`) | RW | R | RW | – | – | RW |
| `cres:<command_id>` | string | gateway and api `ClaimResult` (`SET NX EX`, `GET`); api `ReleaseResult` (Lua `GET DEL`) | gateway `Result` (`GET`) | RW | RW | – | – | – | – |
| `esc:<escrow_id>` | string | worker `PutEscrowStatus` (`SET EX`) | gateway `EscrowStatus` (`GET`) | – | R | RW | – | – | – |
| `diag:<command_id>` | string | gateway `ClaimDiagnostics` (`SET NX EX`), `ReleaseDiagnostics` (Lua `GET DEL`) | gateway | – | RW | – | – | – | – |
| `hb:<device>` | string | worker `ClaimHeartbeat` (`SET NX EX`), `ReleaseHeartbeat` (`DEL`) | worker | – | – | RW | – | – | – |
| `au:<device>` | string | worker `PutUpdateRequest` (`SET PX`), `DeleteUpdateRequest` (`DEL`) | gateway `UpdateRequest` (`GET`) | – | R | RW | – | – | – |
| `ar:current` | string | worker `PutOffer` (`SET` / `DEL`) | gateway and api `Offer` (`GET`) | R | R | RW | – | – | – |
| `stepup:<jti>` | string | api `stepupproof.Store.Put` (`SET PX`) | api `Get` (`GET`) | RW | – | – | – | – | – |
| `stepup-uses:<jti>` | string | escrow_reader `stepupproof.Store.Use` (`INCR`, `EXPIREAT`) | escrow_reader | – | – | – | – | RW | – |
| `revocation-jti:<jti>` | string | revocation_issuer `JTIClaims.Claim` (`SET NX EX`, `GET`) | revocation_issuer | – | – | – | – | – | RW |
| `sess:<sid>` | string | api `Create`/`CreateMCP`/`Bind` (Lua `SET PX`), `Touch` (`PEXPIRE`), `Delete` (`DEL`); api and worker `RevokeAccount`, api `Unbind` (Lua `DEL`) | api `Get` (`MGET`); api and worker `CountAccount` (Lua `EXISTS`) | RW | – | RW | – | – | – |
| `acct-sess:<account>` | set | api `Create`/`CreateMCP` (Lua `SADD PEXPIRE`), `Touch` (`PEXPIRE GT`), `Delete` (`SREM`), `Unbind` (Lua `SREM`); api and worker `RevokeAccount` (Lua `SMEMBERS DEL`) | api and worker `CountAccount` (Lua `SMEMBERS`) | RW | – | RW | – | – | – |
| `sess-gen` | string | api `EndAll` (`INCR`); host tooling `admin end-sessions` as worker (`INCR`) | api `Create`/`Get`/`Binding` (Lua `GET`, `MGET`) | RW | – | RW | – | – | – |
| `mcp-bind:<sha256>:<auth_time>` | string | api `Bind` (Lua `SET PX`), `Unbind` (Lua `DEL`); api and worker `RevokeAccount` (Lua `DEL`) | api `Binding` (`MGET`), `CreateMCP`/`Bind` (Lua `EXISTS GET`) | RW | – | RW | – | – | – |
| `acct-mcp-bind:<account>` | set | api `Bind` (Lua `SADD PEXPIRE`), `Unbind` (Lua `SREM`); api and worker `RevokeAccount` (Lua `SMEMBERS DEL`) | api, worker | RW | – | RW | – | – | – |
| `mcp-chain:<sha256>:<auth_time>` | set | api `CreateMCP`/`Bind` (Lua `SADD PEXPIRE`), `Unbind` (Lua `SMEMBERS DEL`); api and worker `RevokeAccount` (Lua `DEL`) | api `Bind` (Lua `SISMEMBER`) | RW | – | RW | – | – | – |
| `mcp-used:<sha256>` | string | api `UseLoginToken` (`SET NX PX`) | api | RW | – | – | – | – | – |
| `ipal:ver` | string | api `allowlistcache.Version.Bump` (`INCR`); host tooling `admin allowlist` as worker | api `Get` (`GET`), host tooling | RW | – | RW | – | – | – |

Not in the code and therefore not in the ACL: `al:*`, `cache:*`, `unseal:*`, `lock:*` (the `lock:compile:*` row of
`docs/architecture.md` §8.3 describes no code; PDK-820 corrects that table, §14.11). `RestoreSeq` has no caller
outside `PutDeviceKey` (dead code noted, not removed).

### 14.5 Commands per user (binding) and the code path that needs each

| User | Commands beyond `hello ping client|setinfo` | Needed by |
| --- | --- | --- |
| `api` | `get mget set del exists incr expire pexpire pexpireat multi exec hset hdel sadd srem smembers sismember eval evalsha` | sessions (`createScript`, `createMCPScript`, `bindScript`, `unbindScript`, `revokeScript`, `countScript`, `Get`/`Binding` `MGET`, `Touch` `PEXPIRE`, `Delete` `DEL SREM`, `EndAll` `INCR`, `UseLoginToken` `SET NX PX`); `stepupproof` `SET PX`/`GET`; `allowlistcache` `INCR`/`GET`; `PutToken` (`MULTI DEL HSET PEXPIREAT EXEC`); `DeleteCommand` `HDEL`; `ClaimResult`/`ReleaseResult`/`Result`; `Offer` `GET`; PDK-821 `INCR EXPIRE GET` on `rl:*` |
| `gateway` | `get set del exists incr decr expire multi exec hset hgetall hexists pexpireat eval evalsha` | `UseNonce`; `nextSeqScript` (`EXISTS INCR`); `releaseSeqScript` (`GET DECR`); `markDeliveredScript`; `LastDelivered`; `BundlePointer`/`DeviceKey`/`Enrollment`/`Token`/`Commands` (`HGETALL`); `HasCommand` (`HEXISTS`); `PutEnrollment` (`MULTI DEL HSET PEXPIREAT EXEC`); `Allow` (`INCR EXPIRE GET`); `ClaimResult`/`Result`; `ClaimDiagnostics`; `releaseScript` (`GET DEL`); `EscrowStatus`, `TimeTicket`, `Offer`, `UpdateRequest` (`GET`) |
| `worker` | `get set del exists incr multi exec hset hdel hexists pexpireat smembers eval evalsha` | `PutDeviceKey` (`SET NX` + hash), `PutEnrollment`, `PutToken`, `PutUpdateRequest` (`SET PX`), `DeleteUpdateRequest`, `PutEscrowStatus` (`SET EX`), `PutCommand`, `HasCommand`, `DeleteCommand`, `ClaimHeartbeat`, `ReleaseHeartbeat`, `markDeliveredScript`, `PutOffer`; sessions `countScript` (`SMEMBERS EXISTS`), `revokeScript` (`SMEMBERS DEL`); host tooling `EndAll` (`INCR`), `allowlistcache` (`INCR GET`) |
| `compiler` | `set del multi exec hset hgetall` | `PutBundlePointer` (`HGETALL`, then `MULTI DEL HSET EXEC`), `PutTimeTicket` (`SET`) |
| `escrow_reader` | `incr expireat` | `stepupproof.Store.Use` |
| `revocation_issuer` | `get set hset hexists hdel` | `JTIClaims.Claim` (`SET NX EX`, `GET`); `PutCommand`, `HasCommand`, `DeleteCommand` |
| `healthcheck` | none | `valkey-cli ping` in the container health check |
| `acceptance` (dev/CI) | `@read @write @scripting @transaction` minus `@dangerous` | `test/acceptance` helpers: `SCAN` (`--scan --pattern 'stepup:*'`), `GET`, `DEL`, `EXISTS`, `HSET` on any key |

`SETNX`, `SETEX`, `TTL`, `HGET`, `HMSET`, `SCAN`, `KEYS`, `EXPIRE` for the compiler and so on are **not** granted
to production users: the code does not issue them. `AUTH` and `HELLO` are accepted before authentication by
Valkey regardless of the ACL; `+hello` is listed so the connection set is explicit.

### 14.6 Rendering, secrets and Compose wiring

#### 14.6.1 Entrypoint `deploy/compose/valkey/entrypoint.sh` (new, `#!/bin/sh`, `set -eu`)

1. For each user in `api gateway worker compiler escrow_reader revocation_issuer healthcheck`: read
   `/run/secrets/valkey_<user>_password`; a missing or empty file is a fatal error naming the file (exit 1, no
   password in the message). Compute `hash=$(tr -d '[:space:]' < "$f" | sha256sum | cut -d' ' -f1)`.
2. Render `/etc/valkey/users.acl.tmpl` to `/run/valkey/users.acl`, replacing `#{{<user>}}` by `#<hash>`. If
   `/etc/valkey/users.acl.dev.tmpl` exists **and** `/run/secrets/valkey_acceptance_password` exists, render and
   append it the same way; if only one of the two exists, exit 1 (a half-configured development user is a
   misconfiguration). After rendering, a remaining `#{{` in the output is a fatal error. The generated passwords
   contain no whitespace, so stripping all whitespace equals the loader's `strings.TrimSpace`.
3. `chmod 0600 /run/valkey/users.acl`, `chown valkey:valkey /run/valkey/users.acl` (the image's
   `docker-entrypoint.sh` drops to user `valkey`; `/run/valkey` is a Compose `tmpfs` of the service).
4. `exec /usr/local/bin/docker-entrypoint.sh "$@"` with `"$@"` = `valkey-server /etc/valkey/valkey.conf`.

The script never echoes a secret, never writes outside `/run/valkey`, and passes `shellcheck -s sh`
(`make lint-shell` adds it to the list).

#### 14.6.2 Compose (`compose.yaml`)

`valkey` service: `entrypoint: ["/usr/local/bin/paddock-entrypoint.sh"]`, `command: ["valkey-server",
"/etc/valkey/valkey.conf"]`, volumes `./valkey/entrypoint.sh:/usr/local/bin/paddock-entrypoint.sh:ro`,
`./valkey/valkey.conf:/etc/valkey/valkey.conf:ro`, `./valkey/users.acl.tmpl:/etc/valkey/users.acl.tmpl:ro`,
`valkey-data:/data`; `tmpfs: [/run/valkey]` (PDK-822 keeps it when it adds `read_only` and `/tmp`); secrets: the
seven `valkey_<user>_password`; health check
`REDISCLI_AUTH="$$(cat /run/secrets/valkey_healthcheck_password)" valkey-cli --user healthcheck ping | grep -q PONG`.
`fleet-redis`: volume `./valkey/fleet-redis.conf:/etc/valkey/valkey.conf:ro`; nothing else changes.
Role services: `PADDOCK_VALKEY_USER: <user>` and `PADDOCK_VALKEY_PASSWORD_FILE: /run/secrets/valkey_<user>_password`
with the mapping `paddock-api → api`, `paddock-gateway → gateway`, `paddock-worker → worker`,
`paddock-compiler → compiler`, `paddock-escrow-reader → escrow_reader`,
`paddock-revocation-issuer → revocation_issuer`; each mounts exactly its own secret. `compose.prod.yaml`'s
`secrets: !override` lists of `paddock-api`, `paddock-escrow-reader`, `paddock-revocation-issuer` and
`paddock-worker` replace `valkey_password` by the role's secret. Top-level `secrets:` defines the seven files
under `./.secrets/valkey_<user>_password` and drops `valkey_password` and `valkey_auth_conf`.
`prodcheck.autoUnsealForbiddenEnv` gains `PADDOCK_VALKEY_USER` and `PADDOCK_VALKEY_PASSWORD_FILE`.

#### 14.6.3 Secrets generators

`gen-dev-secrets.sh` and `gen-prod-secrets.sh`: `secret valkey_<user>_password` for the seven users (random,
through the existing `secret` helper, which creates a file only when missing); `gen-dev-secrets.sh` additionally
`secret valkey_acceptance_password`. Both drop `valkey_password` and `valkey/auth.conf`; both keep
`fleet_redis_password` and `fleet-redis/auth.conf` unchanged.

#### 14.6.4 Development and CI user `acceptance`

`compose.dev.yaml` adds to `valkey`: volume `./valkey/users.acl.dev.tmpl:/etc/valkey/users.acl.dev.tmpl:ro` and
secret `valkey_acceptance_password` (top-level definition in `compose.dev.yaml`,
`./.secrets/valkey_acceptance_password`). The production file sets (`PROD_FILES_controlplane`, `PROD_FILES_lab`,
`deploy/bundle/ci`) never include it; `prod-check` fails when the `valkey` service mounts either (§14.11). This is
the one deliberate development-only relaxation of the ticket; it exists because the acceptance helpers enumerate
keys (`SCAN`) and no production user may.

### 14.7 Client configuration

```go
// server/internal/platform/valkey/valkey.go
type Config struct {
	Addr     string // host:port
	Username string // ACL user of the role (PADDOCK_VALKEY_USER)
	Password string
}
// New passes Username and Password to valkey.ClientOption; DisableCache stays true.

// server/internal/config/config.go
type Valkey struct {
	Addr     string
	Username string
	Password string
}
func LoadValkey(l *Loader) Valkey // Addr: Required("PADDOCK_VALKEY_ADDR"); Username: Required("PADDOCK_VALKEY_USER");
                                  // Password: SecretFile("PADDOCK_VALKEY_PASSWORD_FILE")
```

Every `valkey.New(valkey.Config{Addr: …, Password: …})` call site in `server/cmd/paddock-server/{api,gateway,worker,
compiler,escrowreader,revocationissuer,admin}.go` passes `Username: vkCfg.Username`. `valkeytest.Start` (plain
`--requirepass`, the `default` user) stays for the existing package tests; `valkeytest.StartACL` is new (§14.10.1).

### 14.8 Host tooling: why the worker's user and not its own

Options: (a) one `admin_tooling` user with its own secret; (b) one user per subcommand; (c) the user of the
container the tooling runs in. The tooling runs in `paddock-worker` by design (its loader reads the worker's
database credential) and is started by an operator with root on the host, who can read every secret file; a
separate Valkey user therefore separates nothing from the operator. What it would separate is the *worker
container* from `ipal:ver` and `sess-gen` — two keys whose abuse is a forced allow-list reload or a forced
re-login of every administrator, both visible and both recoverable. Against that stand one or four more secrets
to generate, mount into the worker container at run time (where a compromised worker reads them anyway), rotate,
check in `prod-check` and carry through the upgrade. **Decision: (c).** The worker gains `~ipal:ver ~sess-gen`;
`rebuild-cache`'s keys (`dk:*`, `seq:*`, `et:*`, `au:*`) and `upgrade-check`'s (`acct-sess:*`, `sess:*`) are the
worker's already. Documented in `paddockctl.md` (admin table) by PDK-820.

### 14.9 Residual risks (added to §6.4; written to `docs/compliance/residual-risks.md` by PDK-827)

| ID | Risk | Mitigation | ISMS |
| --- | --- | --- | --- |
| RR-129 | **The api reads raw step-up ID tokens.** It fetches `stepup:<jti>` to hand the token to the escrow-reader and to the revocation approval; a compromised api can replay a live token. | Token TTL is the step-up window (`tokenTTL`, ADR 0034); the escrow-reader caps uses at `stepupproof.MaxUses` (5) in `stepup-uses:*`, which the api cannot write; the revocation-issuer binds a `jti` to one request (`revocation-jti:*`, api has no access); every use is audited. Follow-up candidate M12h-2: the escrow-reader fetches the token by `jti` itself (contract and revocation-path change, two-person rule). | Accepted for alpha.10; review with M12h-2 |
| RR-130 | **The worker can enumerate and delete portal session records.** Account revocation (`RevokeAccount`) runs in the worker (identity sync) and needs `SMEMBERS acct-sess:*` and `DEL sess:*`, so the worker also holds `GET`-capable rights on `sess:*`. | Session cookies are sealed with the api's key (`Keys.Seal`); a session identifier alone is not a bearer. The worker is on `data` only (PDK-819). | Accepted; revisit if sessions ever become unsealed tokens |

### 14.10 Tests

#### 14.10.1 Role-matrix test (integration, `server/internal/platform/valkey/acl_test.go`, package `valkey_test`)

- `valkeytest.StartACL(t)` (new in `server/internal/testsupport/valkeytest`): starts `VALKEY_IMAGE` with the
  repository files `deploy/compose/valkey/{entrypoint.sh,valkey.conf,users.acl.tmpl,users.acl.dev.tmpl}` bind-mounted
  read-only at the container paths of §14.6.2, a temporary directory with one random password per user
  (`api gateway worker compiler escrow_reader revocation_issuer healthcheck acceptance`) bind-mounted at
  `/run/secrets`, a tmpfs at `/run/valkey`, `Entrypoint` = the wrapper, `Cmd` = `valkey-server /etc/valkey/valkey.conf`.
  `Client(t, user)` opens `valkey.New` as that user. The test therefore exercises the real entrypoint and the real
  template; a rendering bug fails here, not on the operator's host.
- `TestACLRoleMatrix`: for every row of §14.5, run the listed methods of the real packages
  (`devicecache`, `sessions`, `stepupproof`, `allowlistcache`, `revocationissuer.JTIClaims`) through the user's
  client and require no error (a Lua path MUST be exercised once with `EVALSHA` missing, i.e. a fresh server, so
  the `EVAL` fallback is covered). Then the denied probes, each asserting an error whose message contains
  `NOPERM`: `gateway` `HSET dk:x f v`, `gateway` `GET stepup:x`, `gateway` `HSET cmd:x f v`; `api` `HGETALL dk:x`,
  `api` `GET revocation-jti:x`; `worker` `GET stepup:x`; `compiler` `HGETALL cmd:x`; `escrow_reader` `GET stepup:x`,
  `escrow_reader` `SET stepup:x v`; `revocation_issuer` `GET stepup:x`; `healthcheck` `GET sess-gen`; every user
  including `acceptance`: `CONFIG GET maxmemory`, `KEYS *`, `FLUSHALL`, `ACL LIST`; a client as `default` with any
  password fails to connect (authentication error).
- `TestACLTemplateComplete`: parses `users.acl.tmpl` and asserts (1) `user default off` is the first user line,
  (2) the user set equals §14.2 A1, (3) no line contains `~*` except in `users.acl.dev.tmpl`, (4) no line grants
  `+@all`, `+@admin`, `+@dangerous`, `+config`, `+flushall`, `+flushdb`, `+keys`, `+debug`, `+module`, `+acl`,
  `+shutdown`, `+migrate`, (5) every key prefix constant of the client packages (the `tokenKey`, `usesKey`,
  `sessionKey`, `accountKey`, `genKey`, `bindingKey`, `accountBindingsKey`, `chainKey`, `"mcp-used:"`, `"nonce:"`,
  `seqKey`, `deliveredKey`, `bundleKey`, `"rl:"`, `heartbeatKey`, `commandsKey`, `resultKey`, `escrowKey`,
  `ticketKey`, `updateRequestKey`, `deviceKeyKey`, `enrollmentKey`, `diagnosticsKey`, `offerKey`,
  `"revocation-jti:"`, `allowlistcache.key` prefixes — exported for the test as a `Prefixes()` function per package
  or asserted by literal list in the test; the implementer picks one and applies it to every package) appears in
  at least one user's pattern list.

#### 14.10.2 Acceptance `TestValkeyACL` (`test/acceptance/valkey_acl_test.go`, new)

Through `stack.Compose(… "exec", "-T", "valkey", "sh", "-c", …)` with
`REDISCLI_AUTH="$(cat /run/secrets/valkey_<user>_password)" valkey-cli --no-auth-warning --user <user> <args>`:
C2a–C2f of §14.13. The helper `valkeyCLI(t, user, args)` in `test/acceptance/admin_commands_test.go` replaces
`valkeyCLI(t, args)`; call sites: `DEL dk:`/`EXISTS dk:` → `worker`; `DEL hb:` (four tests) → `worker`;
`latestStepUpToken` (`escrow_reader_test.go`) → `acceptance`. `test/system/revoke_test.go` line 231 (`HSET cmd:`)
authenticates as `worker` with `/run/secrets/valkey_worker_password`; this is a test fixture under `test/system`,
not the revocation path (`agent/internal/revoke/`, `agent/cmd/paddock-revoke/`), which is not touched.

#### 14.10.3 Unit

`prodcheck` items of §14.11 with a positive and a negative Compose fixture each; `config.LoadValkey` requires
`PADDOCK_VALKEY_USER`; `scripts/changelog-assemble` untouched; `shellcheck` on `entrypoint.sh`.

### 14.11 `prod-check`, documents, upgrade

`prod-check` items (names are the item strings shown to the operator):
- `valkey: ACL entrypoint and default user off` — the `valkey` service's `entrypoint` is `/usr/local/bin/paddock-entrypoint.sh`,
  it mounts `users.acl.tmpl`, has `tmpfs /run/valkey`, and the template file on disk starts its user lines with
  `user default off`.
- `valkey: one user per role` — every service with `PADDOCK_VALKEY_ADDR` sets `PADDOCK_VALKEY_USER` to the user of
  the mapping in §14.6.2 and mounts exactly `valkey_<user>_password` among the `valkey_*_password` secrets; the
  `valkey` service mounts the seven; no service mounts `valkey_password` or `valkey_auth_conf`.
- `valkey: no development user` — the `valkey` service mounts neither `valkey_acceptance_password` nor
  `users.acl.dev.tmpl`.
- `fleet-redis: own configuration file` — `fleet-redis` mounts `./valkey/fleet-redis.conf`, not `./valkey/valkey.conf`.

Documents (PDK-820): `docs/architecture.md` §8.3 — replace the key table by the table of §14.4 (columns Key,
Type, Written by, Read by, TTL, Users) and add one paragraph "Users" naming the users and the rule of A2; §4.1's
role table row `gateway` already says "reads only from Valkey … nonces"; add "and its own coordination keys
(`seq:`, `sd:`, `enr:`, `cres:`, `diag:`, `rl:`)". `docs/operations/upgrade.md`: a "Valkey users (alpha.10)"
note — `./paddock up` creates the secrets, administrators are not signed out, the stale `.secrets/valkey_password`
and `.secrets/valkey/auth.conf` may be deleted. `docs/operations/local-dev.md` §Valkey: the `valkey-cli` example
uses `--user acceptance` with `.secrets/valkey_acceptance_password`. `docs/operations/paddockctl.md` admin table:
one sentence that the admin commands authenticate to Valkey as the worker. `changelog.d/PDK-820.security.md`
(operator-visible: new secrets, removed secret).

### 14.12 Affected files (delta to §5)

| Path | Action | Purpose |
| --- | --- | --- |
| `deploy/compose/valkey/users.acl.tmpl` | new | §14.3 |
| `deploy/compose/valkey/users.acl.dev.tmpl` | new | §14.3 dev user |
| `deploy/compose/valkey/fleet-redis.conf` | new | A7 (today's `valkey.conf` content) |
| `deploy/compose/valkey/entrypoint.sh` | new | §14.6.1 |
| `deploy/compose/valkey/valkey.conf` | change | `aclfile`, drop `include` |
| `deploy/compose/compose.yaml`, `compose.prod.yaml`, `compose.dev.yaml` | change | §14.6.2, §14.6.4 |
| `deploy/compose/scripts/gen-dev-secrets.sh`, `gen-prod-secrets.sh` | change | §14.6.3 |
| `server/internal/platform/valkey/valkey.go`, `acl_test.go` (new) | change / new | §14.7, §14.10.1 |
| `server/internal/config/config.go` | change | `PADDOCK_VALKEY_USER` |
| `server/cmd/paddock-server/{api,gateway,worker,compiler,escrowreader,revocationissuer,admin}.go` | change | pass `Username` |
| `server/internal/testsupport/valkeytest/valkeytest.go` | change | `StartACL`, `Client(t, user)` |
| `server/internal/prodcheck/*` | change | §14.11 items |
| `test/acceptance/valkey_acl_test.go` (new), `admin_commands_test.go`, `escrow_reader_test.go`, `device_osrelease_test.go`, `evidence_gap_test.go`, `evidence_clock_test.go`, `software_status_test.go` | change | `valkeyCLI(t, user, args)` |
| `test/system/revoke_test.go` | change | `HSET cmd:` as `worker` |
| `Makefile` | change | `lint-shell` covers `entrypoint.sh` |
| `docs/architecture.md` §8.3, §4.1; `docs/operations/{upgrade,local-dev,paddockctl}.md`; `changelog.d/PDK-820.security.md` | change / new | §14.11 |

Not touched: `agent/`, `pkg/revocation`, `server/internal/revocationissuer/*` (the user is wired in `cmd`, the
package is unchanged), `server/internal/escrowreader/*`, `app/escrowdecrypt.go`, `app/revocations.go`, every
Fleet service and secret, `compose.audit.yaml`, `compose.backup*.yaml`, `compose.auto-unseal.yaml`, the sessions
and devicecache packages' logic (only the test support changes).

### 14.13 Acceptance criteria (replace §10 C2)

- **C2a (operator):** Given the running stack, when `valkey-cli --user gateway` runs `GET stepup:x`, `HSET dk:x f v`
  and `HSET cmd:x f v`, then each answers `NOPERM`; `HGETALL dk:x` answers (an empty hash).
- **C2b (operator):** `--user api`: `HGETALL dk:x` → `NOPERM`; `GET stepup:x` → `(nil)`; `GET revocation-jti:x` → `NOPERM`.
- **C2c (operator):** `--user escrow_reader`: `GET stepup:x` → `NOPERM`; `INCR stepup-uses:x` → `1` (the test deletes it afterwards as `acceptance`).
- **C2d (operator):** `--user compiler`: `HGETALL cmd:x` → `NOPERM`; `--user revocation_issuer`: `GET stepup:x` → `NOPERM`.
- **C2e (operator):** every user, `acceptance` included: `CONFIG GET maxmemory`, `KEYS *`, `FLUSHALL`, `ACL LIST` → `NOPERM`; `--user default` with any password → authentication fails.
- **C2f (operator, administrator, device user):** every acceptance gate is green with the ACL in place — step-up, escrow reveal, revocation approval, device protocol, sessions (`TestSessionsEndAll` disruptive), IP allow list, `admin rebuild-cache|allowlist|end-sessions|upgrade-check`; `TestACLRoleMatrix` and `TestACLTemplateComplete` are green; `make lint` is green; `./paddock check` on the production file set reports the four items of §14.11 as OK and FAILS on a fixture that mounts `users.acl.dev.tmpl`.
- **C2g (operator; ADR 0047):** the CI `upgrade` job from alpha.9 passes: the seven secrets appear, the roles connect, no administrator is signed out, Fleet's Redis is untouched (`fleet-redis` container not recreated for a configuration reason other than the file path).

### 14.14 Stop conditions (delta to §11)

- A client package issues a command or touches a key that §14.4/§14.5 does not list for its user (found by the
  role-matrix test, an acceptance gate, or reading): stop, report the method, key and command. Do not widen the
  ACL, do not add a category.
- `NOPERM` in any acceptance or system gate: stop and report; never weaken the gate, never widen the ACL.
- The Valkey image lacks `sha256sum`, `docker-entrypoint.sh` is not at `/usr/local/bin/docker-entrypoint.sh`, or
  the process user is not `valkey`: stop.
- PDK-819 has merged and the `valkey` service block conflicts beyond networks: rebase; a conflict in the health
  check or secrets is resolved in favour of §14.6.2; anything else is a stop.
- A need to change `EscrowDecryptRequest`, `app/revocations.go`, `server/internal/escrowreader`, or anything under
  `agent/internal/revoke/`, `agent/cmd/paddock-revoke/`, `pkg/revocation`: stop (A4).

### 14.15 Freedom of the implementer

Names of shell variables and helper functions in `entrypoint.sh`; whether `Prefixes()` functions or a literal list
backs `TestACLTemplateComplete` (one approach for every package); the structure of the Go table in
`TestACLRoleMatrix`; the Compose fixture format of the `prodcheck` tests (follow `compose_test.go`).

## Amendment 2026-11-09 (architect-lead decision A10-5, PDK-822)

The `cap_add` of the Valkey container is exactly `CHOWN`, `SETUID`, `SETGID` and `DAC_READ_SEARCH`; decision A10-5
(`decisions-alpha10.md` §14) accepts `DAC_READ_SEARCH` in addition to the three the plan named.

- Reason: without `DAC_READ_SEARCH` the entrypoint crash-loops on an existing data volume, because root, with every
  other capability dropped, cannot traverse the existing mode-0700 data directory (`/data/appendonlydir`, owned by
  the valkey user) before it drops to that user. The reviewer of PDK-822 reproduced the crash loop.
- Scope: the capability lets the root-run entrypoint read and traverse the container's own filesystem and its data
  volume only, until `setpriv` drops to the valkey user. No other capability is added.
- Reference: PDK-824 (`fleet-redis`) and PDK-825 (the hardening and prod-check matrix) use this four-capability set
  as the Valkey reference. `tools/composelint` pins it: any extra or missing capability for `valkey` in any host file
  set fails `make lint-compose` and its tests.

## Amendment 2026-11-09 (architect-lead decision A10-8, PDK-825)

§3.4 decision 9 named a memory limit of 1g for each Authentik container. Decision A10-8 (`decisions-alpha10.md` §17)
sets `authentik-server` to 2g, based on the measurement in PDK-825: 860 MiB to 1.05 GiB idle with four web workers
and a 1.08 GiB peak at the first start, so 1g would let the kernel kill a web worker during normal operation.
`authentik-worker` keeps 1g (measured 265–330 MiB, 370 MiB peak at the first start). Both values are overridable per
installation (`PADDOCK_AUTHENTIK_SERVER_MEM_LIMIT`, `PADDOCK_AUTHENTIK_WORKER_MEM_LIMIT`) and listed in
`docs/operations/capacity.md`.

## Correction 2026-11-09 (PDK-963, regression finding A10-22)

§3.5 decision 12 refused every group-writable parent (`mode & 0o022 != 0`). That also refused root-owned system state
directories whose group is root: Ubuntu 26.04 ships `/var/lib/AccountsService` as 0775 root:root, so the agent could
no longer hide the local administrator from the login screen (plan M4a.1 decision 4). Corrected rule: a parent is
refused when it is world-writable (`mode & 0o002`, except the allow-listed sticky `/tmp` and `/var/tmp`), when it is
group-writable and its group is not gid 0, when it is group-writable and carries an access ACL (the group bits are
then the ACL mask, which may grant write to a named user or group), or when it is not owned by uid 0. Group write for
gid 0 without an ACL grants nothing beyond root. The component-by-component, descriptor-relative walk is unchanged.

## Amendment 2026-11-10 (PDK-970, PDK-971; `decisions-alpha10.md` §39) — residual risk RR-131

§3.6 decision 15 sets `ReadTimeout 60s`, and `docs/operations/capacity.md` "Request limits" promises that a body sent
at 1 byte/s ends after 60 s. Behind the edge that held only for requests whose body the role reads to the end.

- Cause: when a role answers an HTTP/1.x request whose body is unfinished, Caddy drains the rest of the body (below
  256 KiB) for up to its 60 s read idle timeout before it writes the answer, unless the answer carries
  `Connection: close`. The role's `ReadTimeout` never fires for a body the handler does not read; the connection ends
  at the role's `WriteTimeout` (120 s).
- Fixed in alpha.10 (PDK-970, snippet `(close_unread_body)` in `deploy/compose/caddy/guards.caddy`): every 4xx/5xx
  answer of a role, and every 2xx/3xx answer to a GET or HEAD that carries a body, closes the HTTP/1.x connection at
  once. HTTP/2 is unchanged (it does not drain, and `Connection: close` would shut the multiplexed connection down).
- Not fixed in alpha.10 (**RR-131**): a POST, PUT, PATCH or DELETE that a role answers 2xx or 3xx **without reading
  its body**. A body sent at 1 byte/s ends after about 120 s. One anonymous route is known:
  `POST /api/auth/logout` with `X-Paddock-CSRF: 1` and no session cookie answers 200 without reading the body.
  Closing every 2xx/3xx answer is not an option: the agents' check-ins and apt would lose their HTTP/1.1 keep-alive.
- Impact: a slow-loris attempt holds a connection for about 120 s instead of 60 s. No data is exposed. The rate
  limiter (decision 7: `auth` per client address, the admin API per principal, the device API per device and
  address) and the edge's body limits apply unchanged.
- Decision: accepted for alpha.10. PDK-971 (alpha.11) audits every role route that can answer 2xx/3xx to a request
  with a body without reading it, and makes each such handler read or refuse the body, or closes the edge connection
  for exactly those routes. RR-131 is removed from `docs/compliance/residual-risks.md` by that ticket.
- §6.4 and `docs/compliance/residual-risks.md` (section "Application hardening (M12h)") carry the row.
