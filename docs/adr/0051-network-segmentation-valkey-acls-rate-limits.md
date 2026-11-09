# 0051 — Control-plane hardening: network segmentation, Valkey ACL users, an application rate limiter, third-party container hardening (M12h, first half)
Status: Proposed (architect, 2026-11-05; amends ADR 0003 (Valkey) and ADR 0016 (deployment topology); the
items marked maintainer are new tools or public behaviour)

## Context

Plan M8s delivered CR-1 (the Paddock roles and Caddy run with `cap_drop: ALL`, `no-new-privileges`, `read_only`,
`pids_limit`), SEC-1–3, WebAuthn-only step-up (AU-2) and body limits on the edge. Open from
`roadmap-appsec.md` §2 and the roadmap's M12h table (verified on `cluster/alpha9-features` a54c1a82):

- One flat `cp` network: Caddy and the internet-facing `gateway` reach PostgreSQL, OpenBao, Valkey, RabbitMQ
  (management on 15672 is enabled in production) and Authentik's internals; `PADDOCK_TRUSTED_PROXY_CIDRS`
  defaults to every private range, so any container on `cp` can call `paddock-api:8080` and spoof the client
  address (CR-3, CR-4, CR-5, CR-6).
- Valkey has one password for every role (`valkey_auth_conf`); the gateway could write device keys, every role can
  read raw step-up tokens (AZ-4, SE-2).
- No rate limit on the admin API, `/api/auth/*`, the Authentik flows, `bundles.` and `fleet.`; the device per-IP
  limit is a constant (RL-1, AU-7). Caddy's stock image has no rate-limit module.
- Third-party services carry `pids_limit` only; no memory limits anywhere (CR-2, RL-4); no Compose lint (CR-8).
- The agent's file writes resolve parent symlinks and accept non-root-owned parents (AG-1); the supervisor unit
  has no sandboxing directive (AG-2); no agent-side validation of the login spec (AG-3).
- No `ReadTimeout`/`WriteTimeout` on the api and gateway servers (HT-2); no header gate on `auth.`, `fleet.`,
  `bundles.` (HT-3).

## Options

### Network topology
- **Keep `cp` flat and rely on authentication.** − Every container is one hop from every datastore; a compromised
  Caddy or Authentik reaches PostgreSQL. Rejected.
- **One network per pair.** − Dozens of networks; Compose's dependency graph becomes unreadable. Rejected.
- **Four networks by trust zone (chosen):** `edge` (Caddy ↔ api, gateway, authentik-server, fleet, rustfs for
  bundle reads), `data` (the Paddock roles and authentik ↔ postgres, valkey, rabbitmq, openbao; Caddy and
  Fleet are not members), `authentik` (authentik-server/worker ↔ authentik-postgres, authentik's redis if any),
  the existing `fleet`, `escrow` and `audit-index`. RabbitMQ management stays enabled for `rabbitmqctl` inside
  the container but its port is published to no network (`rabbitmq.conf: management.tcp.ip = 127.0.0.1`).
  The trusted-proxy default becomes Caddy's fixed address on `edge` (`ipv4_address` in a defined subnet), and
  `PADDOCK_INTERNAL_CIDRS` defaults to that subnet.

### Valkey authorization
- **One user per role with ACL rules (chosen, ADR 0003 amendment):** `api` (`~sess:* ~acct-sess:* ~stepup:* ~bp:*
  ~nonce:* ~rl:* +@all -@dangerous`), `gateway` (`~dk:* ~bp:* ~nonce:* ~rl:* +get +set +setnx +expire +incr +ttl
  +del -@all`), `worker` (`~dk:* ~bp:* ~cache:* …`), `escrow-reader` (`~stepup:* +get -@all`), `compiler`
  (`~bp:* +set +get -@all`), `notifier` none (no Valkey), `unsealer` none. Passwords from one secret file per
  role (`valkey_<role>_password`), rendered into `users.acl` by the entrypoint from the secrets (never on a
  command line). Step-up tokens: only `api` writes, only `escrow-reader` reads (`SE-2`). − One more secret per
  role; the ACL file is a protected production file checked by `prod-check`.
- **Separate Valkey instances per concern.** − Three more containers for the same memory. Rejected.

### Rate limiting
- **Caddy rate-limit plugin (a custom Caddy build).** − A new image build of a third-party component in every
  release. Rejected (maintainer's earlier refusal of a new tool; stock image stays).
- **An application limiter in the api over Valkey, the gateway's `devicecache` windows generalized (chosen):**
  key classes `ip` and `principal`, fixed windows of 60 s, limits per route class (`auth` 20/min/IP,
  `admin-read` 600/min/principal, `admin-write` 120/min/principal, `platform-upload` 10/min/principal,
  `bundles-apt` 60/min/IP, `device` the existing per-IP limit now configurable `PADDOCK_DEVICE_PER_IP_LIMIT`
  default 300 and `PADDOCK_DEVICE_PER_IP_V6_PREFIX` default 64), 429 with `Retry-After`, metrics
  `paddock_ratelimit_rejected_total{class}`, never a limit on `/healthz`. Authentik's own flows: Authentik's
  reputation policy (M12h second half, AU-3).

### Third-party containers
- **`cap_drop: ALL` with the exact `cap_add` each entrypoint needs, `no-new-privileges`, `read_only` where the
  image tolerates it, `pids_limit` (exists) and `mem_limit` from measured peaks × 2 (chosen), one service per
  pull request** with the gate that proves it (acceptance for the roles, WORM gate for RustFS, restore drill for
  PostgreSQL and OpenBao, a seal/unseal cycle for OpenBao, the inventory gates for Fleet, `TestIdentityLockAuthentik`
  for Authentik). A service whose entrypoint cannot run without a capability keeps exactly that capability with
  the reason in `deploy/compose/hardening-exceptions.yaml`, which `make lint-compose` reads.

### Agent file safety
- **Open parents with `O_PATH|O_NOFOLLOW` step by step and refuse a parent not owned by root or writable by
  others (chosen, AG-1)**; managed files below such parents are refused with `parent_not_trusted` and reported
  in the apply status; `fsutil.WriteFileOwned` gains the check; the uninstall and the quarantine paths use it too.
- **Supervisor unit sandboxing (AG-2):** the directives that the agent's work allows: `LockPersonality=yes`,
  `RestrictRealtime=yes`, `SystemCallArchitectures=native`, `ProtectKernelLogs=yes`, `ProtectKernelTunables=yes`
  (the agent writes no sysctl), `PrivateTmp=yes`, `SystemCallFilter=~@obsolete @cpu-emulation`; and the ones that
  stay off with the reason in the unit file: `ProtectClock` (the time reconciler), `RestrictSUIDSGID` (dpkg installs
  setuid binaries), `ProtectHostname` (the hostname reconciler), `NoNewPrivileges` (dpkg maintainer scripts and
  `visudo -c`), `@mount` (LUKS conversion and the quarantine of sudoers files need mounts). The system gates on
  both VMs prove the set; a directive that breaks a gate is removed with the gate named in the unit's comment.

## Decision

1. **Networks** as the chosen option; `compose.yaml`, `compose.prod.yaml`, `compose.dev.yaml`, `compose.lab.yaml`
   and `compose.backup.yaml` move every service to its zones; `prod-check` fails when Caddy or Fleet is a member of
   `data`, when `PADDOCK_TRUSTED_PROXY_CIDRS` is wider than the `edge` subnet, when RabbitMQ publishes 15672, or
   when `PADDOCK_INTERNAL_CIDRS` is `private_ranges` in production. ADR 0016 amendment: the two-host topology's
   internal networks are named here.
2. **Valkey ACLs** as the chosen option; `valkey.conf` gets `aclfile /run/valkey/users.acl`; the roles' Valkey
   clients take `PADDOCK_VALKEY_USER` and `PADDOCK_VALKEY_PASSWORD_FILE`; `rebuild-cache`, the unsealer and every
   test fixture use their role's user; the shared `valkey_auth_conf` secret is removed. ADR 0003 amendment.
3. **Rate limiter** as the chosen option (`server/internal/platform/ratelimit`, Valkey-backed, fail-open on a
   Valkey error with a metric, never fail-closed for devices); the limits are environment variables with the
   defaults above (`PADDOCK_RATELIMIT_<CLASS>`), `prod-check` refuses `0` (off) in production.
4. **Third-party containers** one per PR in the order PostgreSQL (×3), Valkey (×2), OpenBao, RustFS, MySQL,
   RabbitMQ, Authentik, Fleet, Prometheus, with the gates named above; `make lint-compose` (`tools/composelint`)
   fails when a service lacks `cap_drop`, `no-new-privileges`, `pids_limit` or `mem_limit` and is not in the
   exceptions file; `./paddock check` gains the capability-matrix item (`docker inspect` of running containers
   against the expected matrix, `--online`).
5. **Agent** AG-1 and AG-2 as the chosen options; AG-3: the agent validates `login` spec fields with the same
   regexes the server uses (`pkg/policy` gains `ValidateLoginSpec`) before rendering `himmelblau.conf`.
6. **Servers and headers:** `ReadTimeout` 60 s and `WriteTimeout` 120 s on api and gateway (artifact uploads and
   exports set per-route deadlines through `http.ResponseController`); Caddy `header` on every site (`nosniff`,
   `Referrer-Policy: strict-origin-when-cross-origin`, HSTS with `includeSubDomains`, `X-Frame-Options: DENY` on
   every site — Authentik's flows and Fleet's UI are never framed) and `request_body` limits per site (`admin` 2 MiB with a 256 MiB matcher for platform uploads and the package
   upload of ADR 0050, `device` 1 MiB, `bundles` 1 MiB, `fleet` per Fleet's documentation, `auth` 1 MiB).

## Consequences

- + A compromised edge or identity container no longer reaches the datastores; a role can only touch its own
  keys; no unauthenticated endpoint can be hammered without a 429; every third-party container runs with the
  minimum its entrypoint needs; agent writes cannot be redirected by a service user.
- − Four networks and fixed addresses in Compose; one secret per role for Valkey; one more Go package; a Compose
  lint and an exceptions file to maintain; a sandboxed supervisor unit that must be re-validated on every
  systemd major (the system gates prove it).
- No new Go module, npm package, container image or CI tool. Second half (M12h-2, alpha.11): Authentik controls
  (AU-3–AU-6), portal Trusted Types and isolation headers (PO-1, PO-2), parsers and runtime OpenAPI validation
  (IV-1, IV-2, IV-5), SECURITY DEFINER inventory and role-matrix gate (AZ-2, AZ-3), log redaction and key rotation
  (SE-1, CK-1, CK-3), supply chain (SC-1, SC-2, SC-4, CI-1; SC-5, SC-6 need the maintainer's tool decision).

## Amendment 2026-11-08 (PDK-820, A10-2) — Valkey users derived from the code; step-up goal narrowed

### Context

The Valkey option above and decision 2 were written from the roadmap's examples, not from the code. PDK-820's
implementer inventoried the clients on `cluster/alpha10-features` (`2a4e061b`) and stopped: 18 keys in use were
missing from the plan's ACL, three listed prefixes do not exist, the unsealer (listed) uses no Valkey, the
revocation-issuer (not listed) does, the escrow-reader never reads `stepup:*` — the api reads the raw token and
sends it in `EscrowDecryptRequest.StepUpIDToken`, the escrow-reader only counts uses in `stepup-uses:*` — and the
proposed command lists would have broken the gateway's Lua scripts, hashes and transactions. Fleet's Redis mounts
the same `valkey.conf`, so `aclfile` there would have changed Fleet.

### Options

- **Step-up as decided (only the escrow-reader reads `stepup:*`).** Requires the escrow-reader to fetch the token
  by `jti` itself: a change of the api↔escrow-reader contract, of the revocation approval (`app/revocations.go`)
  and of the issuer's verification — the revocation path, two-person rule, real-hardware test. − Not deliverable
  inside PDK-820 without widening it into the revocation path. Deferred to M12h-2 as a candidate.
- **Step-up narrowed (chosen):** the api keeps read and write on `stepup:*`; the escrow-reader gets
  `stepup-uses:*` only; the contract and the revocation flow stay. − The api can replay a live step-up token
  (residual risk RR-129); + the escrow-reader's use counter and the issuer's `jti` claim live in keys the api
  cannot touch, so the blast radius of a compromised api is bounded by `MaxUses` and one approval per token.
- **Host tooling with its own Valkey user(s).** + Separates the worker *container* from `ipal:ver` and
  `sess-gen`. − One to four more secrets mounted into the worker container at run time (where a compromised worker
  reads them anyway), rotation, `prod-check`, upgrade; the tooling is run by a host root who reads every secret.
- **Host tooling as the worker (chosen):** the admin commands run in `paddock-worker` by design and authenticate
  as `worker`; the worker gains two integrity-only keys.
- **Fleet's Redis on the same configuration file.** Rejected: Fleet is out of scope; a separate
  `fleet-redis.conf` with today's content keeps it byte-for-byte unchanged.

### Decision (replaces decision 2)

2. **Valkey ACLs.** Paddock's Valkey has the users `api`, `gateway`, `worker`, `compiler`, `escrow_reader`,
   `revocation_issuer`, `healthcheck` and `default` (off); the development and CI stack adds `acceptance`
   (`compose.dev.yaml` only; `prod-check` fails on it in production). No user exists for a role without a Valkey
   client (unsealer, notifier, backup, audit-writer, outbox-relay). Key permissions follow the direction of the
   code: `~` on keys a role writes, `%R~` on keys it only reads; command grants are the exact commands the role's
   code issues plus the client's connection set (`HELLO`, `PING`, `CLIENT SETINFO`); no category, no admin or
   dangerous command for any user. The binding table of keys, directions and commands is plan M12h §14.3–§14.5;
   it is derived from the code and complete for `2a4e061b`; any new key or command is a stop condition for the
   implementer, never a wildcard. Passwords are rendered into `/run/valkey/users.acl` as SHA-256 hashes by the
   container's entrypoint from one secret per user (`valkey_<user>_password`); `valkey_password` and
   `valkey_auth_conf` are removed. `fleet-redis` keeps its configuration in a separate file. Host tooling
   authenticates as `worker`. Step-up: the api writes and reads `stepup:*`, the escrow-reader counts
   `stepup-uses:*`; RR-129 records the residual. ADR 0003 amendment.

The context bullet "every role can read raw step-up tokens (AZ-4, SE-2)" is corrected to: after this decision only
the api can; SE-2's wording "only the escrow-reader path reads them" is narrowed to "only the api reads them and
only the escrow-reader counts their uses" (recorded with this date in the appsec roadmap's SE-2 row).

### Consequences

- + The AZ-4 goal holds for every device-facing key: the gateway cannot write `dk:*`, `bp:*`, `cmd:*`, `et:*`,
  `tt:*`, `ar:current`, `au:*`, `esc:*`; the compiler, escrow-reader and revocation-issuer see only their own keys.
- + A rendering or permission mistake fails in the role-matrix test (real entrypoint, real template, every
  role's code paths under its own user) and in the acceptance gate `TestValkeyACL`, not on an operator's host.
- − RR-129 (api reads step-up tokens) and RR-130 (the worker holds delete rights on session records) are
  accepted for alpha.10; the M12h-2 plan re-evaluates the escrow-reader fetching tokens by `jti`.
- − Seven secrets instead of one; one development-only user, guarded by `prod-check`.
- Follow-up: `docs/architecture.md` §8.3's key table is replaced by the real inventory (PDK-820).

## Amendment 2026-11-08 — decision 5: two AG-2 directives move to the "off" list

Decided by the architect lead on 2026-11-08 (alpha.10 decision A10-3, PDK-826). Decision 5 stands; the AG-2 set
changes:

1. **`ProtectKernelTunables` is off.** It makes all of `/sys` and `/proc/sys` read-only, not only sysctl. The agent's
   job is installing packages, and their maintainer scripts reload AppArmor profiles (`/sys/kernel/security`,
   e.g. `himmelblau-apparmor` on Ubuntu 26.04), trigger udev (`uevent` files) or write EFI variables
   (`grub-install`, `efibootmgr` on a grub or shim upgrade). Under the directive these fail or are skipped silently
   and no system gate would notice.
2. **`SystemCallArchitectures=native` is off**, for the same reason: maintainer scripts of multiarch packages (for
   example i386) run foreign-architecture binaries, which the filter kills.
3. The "on" set of `paddock-supervisor.service` and `paddock-disk-setup.service` is `LockPersonality=yes`,
   `RestrictRealtime=yes`, `ProtectKernelLogs=yes`, `PrivateTmp=yes`, `SystemCallFilter=~@obsolete @cpu-emulation`;
   both moved directives are named with their reason in the unit's "off" list.
4. **Revocation path.** `paddock-revoke` runs as the agent's child and inherits the unit's sandbox, so its runtime
   environment changes although its code does not. Every directive in effect was checked against what
   `paddock-revoke` and cryptsetup need (block devices, device mapper, the kernel keyring, `/run/cryptsetup`,
   `mlock`, `loginctl`, `systemctl reboot --force --force`); none restricts them. If a later directive could hinder
   the revocation, the revoke invocation must not inherit it (the unit or the exec path escapes the sandbox) or the
   directive goes on the "off" list; the revocation is never weakened to fit the sandbox. The revocation VM gates
   (`TestRevocationLockGate`, `TestRevocationRefusalGates`, the destroy flow) and `TestDiskGates` must be green on
   both VMs before the sandboxed units merge.
