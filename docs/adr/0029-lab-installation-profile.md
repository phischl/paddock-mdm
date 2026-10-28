# 0029 — Lab installation profile: one host behind an external TLS proxy
Status: Accepted (2026-10-13)

## Context
The production topology is two hosts (control plane, audit domain; ADR 0010, ADR 0016, architecture §4.1) with Caddy
terminating public TLS from an ACME CA on ports 80/443 (plan M6a decision 1). The operator bundle (ADR 0022) and
`./paddock check` (`paddock-server prod-check`) enforce that shape: `PADDOCK_HOST` is `controlplane` or `audit`,
only 80/443 are public, every other published port sits on the interconnect address, every cross-host link uses TLS.

The maintainer wants to run a released Paddock in a homelab to test it with real devices (VMs and laptops):

- one Ubuntu server (amd64) runs everything, control plane and audit domain together;
- the server is reachable from the test devices with valid, publicly trusted TLS, but not from the internet;
- TLS is terminated by the maintainer's existing Nginx reverse proxy, which forwards to Paddock over plain HTTP on
  the LAN;
- outbound internet is open (images, OSV, Fleet feeds);
- backups are optional.

Neither the development stack (`make up`: internal CA, `PADDOCK_ENV=development`, test hooks, dev blueprint) nor
the production bundle (two hosts, ACME) fits. What is needed is the production configuration — production
environment, production checks, signed images, no development shortcuts — in a single-host, proxy-fronted shape.

Facts about the code that bound the design (checked 2026-10-13):

- Device authentication is a request signature (ECDSA P-256 over method, path with query, and the signed headers;
  `pkg/protocol`), not mTLS; the agent's HTTP client uses the system trust store and no pinning
  (`agent/internal/client`). fleetd gets `ORBIT_FLEET_CERTIFICATE=/etc/ssl/certs/ca-certificates.crt`.
- Presigned bundle, package and escrow URLs are SigV4 path-style URLs computed for `PADDOCK_BUNDLES_PUBLIC_URL`
  (`objectstore.NewPresigner`); the signature covers the `Host` header, not the scheme.
- The api sets `Strict-Transport-Security` and `Secure` cookies unconditionally and builds every redirect from
  `PADDOCK_PUBLIC_ADMIN_URL`; it never reads `r.Host`, `X-Forwarded-Proto` or the TLS state.
- Authentik's redirect URIs and launch URL come from `PADDOCK_PUBLIC_ADMIN_URL` (blueprints); its issuer and
  cookie flags follow `X-Forwarded-Proto`, which Caddy's `reverse_proxy` passes through from a trusted proxy and
  resets for anybody else.
- The roles reach Authentik and the OIDC issuers through the public names (`https://auth.<domain>`): in production
  those names resolve to Caddy's network aliases on the Compose network, where Caddy serves TLS on 443 inside the
  container as well.
- The worker's certificate probe dials `PADDOCK_TLS_PROBE_ADDR` (default `caddy:443`) with each public name as
  SNI and verifies the chain against the system roots.
- Body limits: device API 64 KiB (events 1 MiB), admin documents 1 MiB, agent artifacts 128 MiB
  (`agentrelease.MaxArtifactBytes`), escrowed LUKS headers a presigned PUT of up to 16 MiB. No endpoint streams,
  long-polls or uses SSE; Authentik's administrative UI uses a websocket (`/ws/`).

## Options

### Single host
- **Two bundle directories and two Compose projects on one host** (the CI smoke test's shape). + No new Compose
  file. − Two `.env`, two `.secrets/`, the cross-copies of passwords and CA certificates, the interconnect address
  and TLS on links that never leave the host; the operator does the two-host dance for one machine.
- **One Compose project with the production control-plane overlay plus a lab overlay (chosen).** The file set is
  `compose.yaml compose.prod.yaml compose.audit.yaml compose.lab.yaml`, optionally `compose.backup.yaml`. The
  control-plane hardening is `compose.prod.yaml` itself, not a copy; the audit domain runs on the same Compose
  network with the control plane's own OpenBao (TLS, internal CA) and RabbitMQ (plaintext 5672 on the network, as
  the control plane's roles use it). + One `.env`, one `.secrets/`, one `./paddock`, no drift from the production
  hardening by construction. − One real change to a production file: `PADDOCK_ACME_EMAIL` in `compose.prod.yaml`
  becomes a default-empty interpolation; production stays protected twice (`./paddock check` fails on an empty
  e-mail, and Caddy's `email` option with no argument fails `caddy validate` in the entrypoint).
- **A standalone lab overlay that copies both production overlays.** + Clean `.env`. − 200 lines of duplicated
  security configuration guarded only by a drift test. Rejected for ADR 0022's reason: one source.

### TLS termination
- **Caddy keeps TLS inside (internal CA, as the CI overlay does) and the proxy re-encrypts.** − Two certificates for
  every name, `tls internal` in a production check, the CA export plumbing of the development stack. Rejected.
- **Caddy serves plain HTTP on one LAN-bound port; the proxy terminates TLS and is the single trusted proxy
  (chosen).** Caddy matches the five sites by host name over HTTP (`http://admin.<domain>` …, `auto_https off`),
  reads the client address from `X-Forwarded-For` of `PADDOCK_EDGE_TRUSTED_PROXIES` only (ADR 0021 unchanged) and
  passes the proxy's `X-Forwarded-Proto: https` on to Authentik and Fleet. The roles reach the public names through
  the proxy as the devices do: the lab overlay removes Caddy's network aliases and adds `extra_hosts` entries that
  map the five names to `PADDOCK_LAB_PROXY_ADDR`, so the stack does not depend on the host's DNS for its own calls
  and uses exactly one TLS endpoint. The certificate probe dials the proxy and therefore watches the maintainer's
  certificate.
- **Roles talk to Authentik directly over plain HTTP on the Compose network.** − The OIDC issuer in the discovery
  document would not match the browser-facing issuer; go-oidc refuses that. Rejected.

### Proxy on the same host as Paddock
Supported as a documented variant (bind Caddy to `127.0.0.1`, trust the gateway address of network `paddock_cp`),
not as the default: the default is a proxy on another machine of the LAN, which keeps the trusted-proxy address a
plain LAN address.

### Nginx reference configuration and its test
- **Prose only.** − The deliverable the maintainer depends on would be untested.
- **A shipped `nginx/paddock.conf.example` exercised by a CI smoke test with a pinned `nginx` image (chosen).**
  The image is a tooling image like `k6` and `cosign`: pinned in `versions.env` below "Build and tooling images",
  never shipped, never pulled on a host. A Caddy stand-in would test Paddock's trusted-proxy handling but not the
  configuration the maintainer pastes.

## Decision
A third value of `PADDOCK_HOST`: **`lab`**. One host, one Compose project, the production control-plane overlay
plus `compose.lab.yaml`, Caddy on plain HTTP bound to `PADDOCK_INTERCONNECT_ADDR:PADDOCK_LAB_HTTP_PORT` (default
8080) behind an external TLS proxy named by `PADDOCK_LAB_PROXY_ADDR`, client addresses from `X-Forwarded-For` of
`PADDOCK_EDGE_TRUSTED_PROXIES` only, the roles' public-name traffic through the proxy, backups optional
(`PADDOCK_LAB_BACKUP=yes` adds `compose.backup.yaml` with the maintainer's S3 endpoint). `./paddock secrets lab`
writes both halves' secrets into one `.secrets/` with one internal CA. `./paddock check` keeps every production item
that applies on one host and replaces the host-shape items: exactly one published port (Caddy's, on the bind
address), a Caddyfile that serves `http://` sites with `auto_https off` and no ACME e-mail, a proxy configuration
that is mandatory (`X-Forwarded-For`, trusted proxies that are specific addresses, never `private_ranges` or a /0),
an edge admin allow list without a /0, no hostname aliases on Caddy, and `extra_hosts` of the four roles that call
the public names. The WORM audit bucket, the production release keys, the sealed OpenBao with custodian shares, the
revocation acceptance and the development-variable refusals apply unchanged. A shipped Nginx reference
configuration is tested in CI against the lab bundle.

## Consequences
- + A released bundle runs on one homelab server with publicly trusted TLS from the maintainer's proxy; install,
  check and upgrade are the same `./paddock` commands as in production; no development shortcut is reachable.
- + The security model of ADR 0021 is unchanged: a header counts only from the trusted proxy; the roles' own
  calls pass the same perimeter as the devices'.
- − **Not for production.** The lab profile gives up the separation of duties of the audit domain: the audit
  database, the WORM bucket and their credentials live on the same host, in the same `.secrets/`, under the same
  Docker daemon as the control plane; a root on the host can delete the evidence volume. It gives up Paddock's own
  TLS: certificate issuance, renewal, protocol versions and HSTS at the edge are the proxy's; a compromised proxy can
  name any client address. It gives up the public-exposure assessment: nothing in this profile was assessed for an
  internet-facing proxy. `./paddock check` and `./paddock up` print this on every run.
- − The roles depend on the proxy for Authentik and the step-up issuer: a stopped proxy stops logins, step-ups and
  identity synchronization; devices keep working (fail safe, design contract 8).
- − One more tooling image (`nginx`) and one more CI smoke job.
- Follow-ups: none required for production; the two-host documentation gains a pointer to the lab guide.

## Amendment 2026-10-28 — nginx line of the smoke-test image

**Context.** Plan M8a decision 17 pinned `NGINX_IMAGE` to the newest 1.28 patch, the stable line of that day. The
image runs the lab smoke test only (`deploy/bundle/ci/smoke-lab.sh`, `make bundle-smoke-lab`): it is never shipped
and never pulled on a host; its job is to prove that the shipped `nginx/paddock.conf.example` works in front of the
lab bundle. The upstream version watch (ADR 0037 amendment 2026-10-17) opened issue #105: `nginx 1.28.3 → 1.31.8`,
classified `minor` (the first numeric field is unchanged). nginx publishes two lines: **stable** (even minor, a new
branch once a year, critical and security fixes backported) and **mainline** (odd minor, every one to two months,
all fixes and features). nginx's installation guide recommends mainline "for production unless your organization has
strict requirements for stability". On 2026-10-28 stable is 1.30.6 (2026-10-14) and mainline 1.31.8 (2026-10-21);
Docker Hub carries both. The watch takes the highest tag of the pin's shape (`x.y.z`), which is always the mainline
release, so a stable pin is reported as outdated for as long as it exists. Operators run their distribution's nginx
(Ubuntu 24.04: 1.24, Debian 13: 1.26); the smoke test reproduces neither line's operator reality, it tests the
configuration against a current nginx.

**Options.**
- **Stable line with an nginx-specific filter in `tools/upstreamwatch` (skip odd minors).** + Two fewer bumps a year
  (2026: seven stable, nine mainline releases). − A per-pin rule in a generic tool (code, fixture, test) for one
  tooling image; the odd/even convention is nginx's alone. − Deprecations that will reach operators with their next
  distribution release appear in the smoke test a year later.
- **Stable line without a filter.** − A permanently open issue `nginx 1.30.x → 1.31.y`, a false positive that trains
  everyone to ignore the label. Rejected.
- **Mainline line (chosen).** + The line nginx recommends; the watch works unchanged; deprecations and behaviour
  changes reach the smoke test first, while the configuration can still be corrected before an operator meets them.
  − About two more bumps a year of an image that never ships. − A bump can fail the smoke test for a change an
  operator on a stable distribution package would not see yet; that is a finding about the configuration operators
  paste, not a reason to pin back.

**Decision.** `NGINX_IMAGE` follows nginx **mainline**: the highest `x.y.z` tag on Docker Hub, exactly what the
watch proposes. `tools/upstreamwatch` gets no line filter. The pin's comment in `versions.env` names the line. The
gate of a bump stays the lab smoke test; a mainline change that breaks the reference configuration is fixed in
`deploy/compose/nginx/paddock.conf.example` (and, if operators are affected, noted in `docs/operations/lab-install.md`),
never by returning to the stable line. The 1.31 line is adopted in v0.1.0-alpha.7 (ticket PDK-347). Reassess when
the reference configuration gains a directive whose behaviour differs between the two lines, or when two consecutive
mainline bumps break the smoke test.

**Consequences.** + No tool change; the watch stays generic. + The reference configuration is proven against the
line nginx recommends. − About nine bumps a year instead of seven, each a one-line change gated by
`make bundle-smoke-lab`. − Plan M8a decision 17's "1.28" is superseded by this amendment.
