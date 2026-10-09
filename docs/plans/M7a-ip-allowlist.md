# Implementierungsplan: M7a — IP allow list for the administrative surfaces

Status: Ready for implementation (after the M6 regression) · 2026-10-09 · Author: architect
Basis: architecture v1.7 §4.1 (hostnames; `admin.` "SHOULD be restricted by IP allow list or VPN"), §9.6 (roles,
step-up), §14 (audit, one event per attempt), §17.1 (admin API), §19 (observability); ADR 0007 (shared Authentik,
"Authentik admin accounts are platform-level and must be restricted"), 0016 (operations), 0018 (list contract,
dialogs); plan M6a decision 1 (`PADDOCK_ADMIN_ALLOWED_CIDRS` at the edge), plan M6c decisions 7–9 (API tokens,
bearer path); product owner requests 2026-10-09 ("the whole application is usable only from approved IP addresses;
the only exceptions are the endpoints devices need" and "trusted proxies and the client-IP header are configurable,
Paddock can run behind further proxies or CDNs such as Cloudflare").

Binding language: **MUST** / **MUST NOT** / **SHOULD** / **MAY**.

## 1. Goal
A platform administrator restricts the portal, the admin API and Authentik's administrative interface to approved
IP ranges — at the edge (Caddy, static) and in the application (a list managed in the portal, enforced by every
`api` replica) — so that a stolen admin session or API token is useless from any other network. Devices, their
users' logins and the device-code approval on a phone keep working from anywhere. The client address is derived
from a configurable chain of trusted proxies at the edge and from one canonical header behind it, so that the allow
lists, the rate limits and the audit log see the real client even behind a CDN, and a spoofed header never counts.
The feature is off until the first entry exists; a platform administrator cannot lock themselves out by accident,
and an operator on the host can always switch it off.

## 2. Context
- **Ist-Zustand (code is the truth):**
  - The edge allow list exists for `admin.<domain>` only: `deploy/compose/caddy/Caddyfile.prod` matches
    `not remote_ip {$PADDOCK_ADMIN_ALLOWED_CIDRS}` and answers 403; `compose.prod.yaml` defaults the variable to
    `0.0.0.0/0 ::/0`. The development `Caddyfile` has no allow list. `auth.<domain>` is proxied as a whole, so
    Authentik's admin interface (`/if/admin/`) and its API (`/api/v3/`) are reachable from the internet. Neither
    Caddyfile configures `trusted_proxies`; Caddy therefore replaces a client-sent `X-Forwarded-For` with the peer
    address. The Caddy service runs the image's default command; Authentik already uses a mounted
    `entrypoint.sh` (`compose.yaml`, service `authentik-server`), which is the pattern for a Paddock entrypoint.
  - `httpx.ClientIP` (`server/internal/platform/httpx/httpx.go`) returns the **first** `X-Forwarded-For` entry
    whatever the peer is: any caller that reaches a role directly (development port mappings, a compromised
    container) can spoof it. Callers: `admin/server.go` (session principal), `admin/bearer.go`, `admin/bff.go`
    (login audit), `device/auth.go` (per-IP rate limit), `httpx.AccessLog`.
  - The api role has PostgreSQL (`OrgPool`, `PlatformPool` role `paddock_platform`), Valkey (`valkey-io/valkey-go`,
    used by `stepupproof.Store` and `devicecache`) and **no RabbitMQ credential** (`compose.prod.yaml`, secrets of
    `paddock-api`). It cannot consume outbox events. Its port 8080 is not published, also not in development.
  - Platform-scope tables (`agent_release`, `osv_*`) have no `organization_id`, are listed in the allow list of
    `server/internal/platform/db/rlslint_test.go` and are granted to `paddock_platform` only. Platform actions run
    `runner.RunTx(ctx, app.ScopePlatform, …)` and are recorded in the platform pseudo-organization
    (`audit.PlatformOrganizationID`). Unauthenticated refusals are recorded with a system principal and an anonymous
    actor (`app.Accounts.recordDenied`, `app.APITokens.Authenticate` → `api_token.use_denied`).
  - `paddock-server admin <cmd>` (`server/cmd/paddock-server/admin.go`) runs host-side with the worker's
    configuration (`PADDOCK_DB_WORKER_URL_FILE`, `PADDOCK_DB_PLATFORM_URL_FILE`, `config.LoadValkey`), as
    `docker compose … run --rm --no-deps paddock-worker admin …`.
  - Step-up: `ActionSpec.RequiresStepUp` / `Recorder.RequireStepUp` (`app.ActionRunner.checkStepUp`); the portal
    helper `lib/stepUp.ts` (`startStepUp(key, …)`); the acceptance helpers `authflow.StepUp` and the dev users'
    TOTP keys (`env.TOTP`). The platform administrator of the dev seed has a TOTP authenticator.
  - Platform events are not visible in the portal (`app.AuditLog.List` requires an organization); the acceptance
    gates read them with `env.AuditIndex` (direct `paddock_audit_reader`, any organization including the platform).
  - Acceptance gates run from the host against the dev stack through Caddy (`stack.AdminURL()`,
    `https://admin.paddock.localhost:8443`); Caddy sees the Docker gateway address as the peer. The Authentik
    device-code flow is driven by `test/acceptance/internal/authflow/device.go` (`/application/o/device/`,
    `/device?code=…`, `/if/flow/<slug>/`, `/api/v3/flows/executor/<slug>/`, `/application/o/token/`,
    `/application/o/userinfo/`). Caddy is pinned to 2.11.6 (`versions.env`): it has the `client_ip` matcher, the
    `trusted_proxies`, `trusted_proxies_strict` and `client_ip_headers` server options and the `{client_ip}`
    placeholder; Caddyfile env placeholders `{$VAR}` are substituted before parsing and may expand to nothing or to
    several lines.
- **ADRs touched:** new ADR 0021 (text in §9, placed by the main session); architecture §4.1 hostname table
  amendment (open point 7).

### 2.1 Requirements
| ID | Requirement | Acceptance (who observes) |
| --- | --- | --- |
| IPA-1 | Only requests from approved ranges reach the portal, the admin API (sessions **and** API tokens) and Authentik's admin interface and API. | Platform admin sees 403 from a foreign IP with a valid session; automated gate |
| IPA-2 | Device communication, device logins and the device-code approval on a second device work from any network. | Device user; automated gate (device flow from a foreign IP) |
| IPA-3 | Platform administrators manage the application list in the portal; every change is audited; every write needs a fresh step-up. | Platform admin, auditor (audit index) |
| IPA-4 | A change that would exclude the caller's own address, or switch the feature off, is refused unless confirmed by typing the entry's CIDR. | Platform admin |
| IPA-5 | An operator on the host can disable the application list or add an entry without portal access; both are audited. An environment variable bypasses the application list on the api. | Platform operator |
| IPA-6 | The client address is derived from a configurable list of trusted proxies and a selectable header at the edge (`X-Forwarded-For`, `CF-Connecting-IP` or none) and, behind the edge, from one canonical header only Caddy sets; a header from an untrusted peer never counts, at the edge, in the api, in the gateway's rate limits or in the logs. IPv6 is handled. | Automated gates; platform operator (`prod-check`) |
| IPA-7 | Denied requests reveal nothing; a scan does not flood the audit log. | Auditor; automated gate |

## 3. Binding decisions

### 3.1 Client address: trusted proxies and canonical header
1. **Edge configuration (Caddy).** Two variables of the `caddy` service, documented in `prod.env.example` and
   `docs/operations/ip-allowlist.md`:
   | Variable | Values | Default |
   | --- | --- | --- |
   | `PADDOCK_EDGE_TRUSTED_PROXIES` | space-separated CIDRs or single addresses, optionally the keyword `private_ranges`: the peers that may set the client address through a header | empty = Caddy is the first proxy |
   | `PADDOCK_EDGE_CLIENT_IP_HEADER` | `none`, `X-Forwarded-For` or `CF-Connecting-IP` (production: exactly one; development MAY list both names, the first non-empty header wins) | `none` |
   Semantics: `none` with an empty proxy list = no proxy in front; a header with a non-empty list = that header is
   read **only** from peers in the list; `X-Forwarded-For` is parsed right to left (`trusted_proxies_strict`), so a
   chain of trusted proxies that append resolves to the first untrusted address; `CF-Connecting-IP` carries one
   address. A header without proxies, proxies without a header, a `/0` prefix (`0.0.0.0/0`, `::/0`, any `/0`), an
   unknown header name or an unparsable range are **invalid**: Caddy refuses to start (decision 2) and `prod-check`
   FAILs (decision 24). Cloudflare is the documented example — its published ranges (`https://www.cloudflare.com/ips/`,
   IPv4 and IPv6, fetched by the operator at install and refreshed on a schedule) in `PADDOCK_EDGE_TRUSTED_PROXIES`
   and `CF-Connecting-IP` as the header; nothing of Cloudflare is hard-coded.
2. **Caddy entrypoint** `deploy/compose/caddy/entrypoint.sh` (POSIX sh, busybox; mounted read-only at
   `/paddock/entrypoint.sh`; `compose.yaml` sets `entrypoint: ["/bin/sh", "/paddock/entrypoint.sh"]` for the
   `caddy` service, development and production alike). It validates decision 1's rules (exit 1 with one line
   `caddy: PADDOCK_EDGE_…: <reason>` on stderr), then exports `CADDY_SERVERS_BLOCK`:
   - empty when `PADDOCK_EDGE_CLIENT_IP_HEADER=none`;
   - otherwise the text
     ```
     servers <listener> {
     	trusted_proxies static <PADDOCK_EDGE_TRUSTED_PROXIES>
     	trusted_proxies_strict
     	client_ip_headers <PADDOCK_EDGE_CLIENT_IP_HEADER>
     }
     ```
     where `<listener>` is `PADDOCK_EDGE_SERVERS_LISTENER` (default empty = every listener; the development stack
     sets `:${PADDOCK_HTTPS_PORT}` so that its second, untrusted listener of decision 9 stays untrusted);
   then runs `caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile` and
   `exec caddy run --config /etc/caddy/Caddyfile --adapter caddyfile`. Both Caddyfiles carry
   `{$CADDY_SERVERS_BLOCK}` as the last line of their global options block. The healthcheck is unchanged.
3. **Canonical header.** Every `reverse_proxy` of both Caddyfiles that targets a Paddock role (`paddock-api:8080`,
   `paddock-gateway:8081`) sets `header_up X-Paddock-Client-IP {client_ip}`; the snippets of decision 6 contain
   the line for `admin.`, and the `device.` sites of both Caddyfiles get it inline. `header_up` **replaces** any
   incoming `X-Paddock-Client-IP`; `{client_ip}` is the address Caddy resolved with decision 1 (the peer when no
   trusted proxy sent a header). Caddy's own `X-Forwarded-For` handling stays as it is and is **not** read by any
   Paddock role. The roles therefore see exactly one hop with exactly one header, whatever runs in front of Caddy.
4. **Role configuration.** `config.Common` gets `TrustedProxies []netip.Prefix`, read by `config.LoadCommon` from
   `PADDOCK_TRUSTED_PROXY_CIDRS` (space-separated CIDRs; unparsable → `l.Invalid`; a `/0` → `l.Invalid`). Default
   when unset: empty (trust no peer; every client address is the peer). `deploy/compose/compose.yaml` sets it in
   the shared environment anchor (the block that holds `PADDOCK_LOG_LEVEL` and `PADDOCK_OPS_ADDR`) to
   `${PADDOCK_TRUSTED_PROXY_CIDRS:-10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 127.0.0.0/8 fc00::/7 ::1/128}`: Caddy's
   address on the Compose network is not fixed, and the roles' ports are never published in production
   (`prod-check` refuses it), so only containers of the stack can be peers of a role.
5. **Derivation in the roles.** `server/internal/platform/httpx/httpx.go`:
   ```go
   // ClientIPHeader is the canonical client address header Caddy sets (plan M7a decision 3).
   const ClientIPHeader = "X-Paddock-Client-IP"
   // WithClientIP resolves the client address once per request and stores it in the context (plan M7a decision 5).
   func WithClientIP(trusted []netip.Prefix) func(http.Handler) http.Handler
   // ClientIP returns the address resolved by WithClientIP as a string; without the middleware, the host of RemoteAddr.
   func ClientIP(r *http.Request) string
   // ClientAddr is ClientIP as netip.Addr; ok is false when none could be parsed.
   func ClientAddr(r *http.Request) (addr netip.Addr, ok bool)
   ```
   Algorithm: `peer` = host of `r.RemoteAddr` parsed with `netip.ParseAddr` and `Unmap()`. If `peer` is inside no
   trusted prefix → client = `peer`; every header is ignored. Else `v := r.Header.Get(ClientIPHeader)`; if `v`
   parses (`netip.ParseAddr`, zone stripped, `Unmap()`) → client = `v`; else client = `peer` and a warning
   `client ip header unparsable` is logged once per minute at most. `X-Forwarded-For`, `X-Real-IP` and
   `CF-Connecting-IP` are never read by a role. Installed as the outermost middleware after the request ID in
   `admin.NewHandler` (`server/internal/transport/http/admin/server.go`) and `device.NewHandler`
   (`server/internal/transport/http/device/device.go`):
   `httpx.RequestIDMiddleware(httpx.WithClientIP(d.TrustedProxies)(httpx.Recover(httpx.AccessLog(…))))`; both
   `Deps` get `TrustedProxies []netip.Prefix`, filled from `common.TrustedProxies` in `api.go` and `gateway.go`.
   The gateway's per-IP limit (`device/auth.go`, key `"ip:"+httpx.ClientIP(r)`), the login audit (`bff.go`), the
   bearer path, the session principal and the access log keep calling `httpx.ClientIP` and thereby share the
   derivation; no other code reads a client address header.

### 3.2 Edge (Caddy)
6. **Shared guard snippets** in the new file `deploy/compose/caddy/guards.caddy`, mounted read-only at
   `/etc/caddy/guards.caddy` by `compose.yaml` (inherited by the production overlay) and imported by both
   Caddyfiles with `import /etc/caddy/guards.caddy` as the first line after the global options:
   ```
   # Edge allow lists shared by Caddyfile (development) and Caddyfile.prod (plan M7a decisions 3, 6–8).
   # PADDOCK_ADMIN_ALLOWED_CIDRS: ranges that may use the administrative surfaces (space-separated; default: every
   # address). PADDOCK_INTERNAL_CIDRS: ranges of the Paddock roles, which use Authentik's API through Caddy.
   # client_ip is the address resolved through the trusted proxies of PADDOCK_EDGE_TRUSTED_PROXIES.
   (admin_site) {
   	@admin_denied not client_ip {$PADDOCK_ADMIN_ALLOWED_CIDRS}
   	handle @admin_denied {
   		respond 403
   	}
   	reverse_proxy paddock-api:8080 {
   		header_up X-Paddock-Client-IP {client_ip}
   	}
   }
   (authentik_site) {
   	# Public: OAuth/OIDC endpoints, the device-code page, the flow executor (logins, MFA enrollment, step-up,
   	# recovery) and its assets. Everything else is administrative.
   	@denied_other {
   		not path /application/o/* /device /device/* /if/flow/* /flows/* /api/v3/* /static/* /media/* /.well-known/* /favicon.ico
   		not client_ip {$PADDOCK_ADMIN_ALLOWED_CIDRS}
   	}
   	handle @denied_other {
   		respond 403
   	}
   	@denied_api {
   		path /api/v3/*
   		not path /api/v3/flows/executor/* /api/v3/root/config/ /api/v3/core/brands/current/
   		not client_ip {$PADDOCK_ADMIN_ALLOWED_CIDRS}
   		not client_ip {$PADDOCK_INTERNAL_CIDRS}
   	}
   	handle @denied_api {
   		respond 403
   	}
   	reverse_proxy authentik-server:9000
   }
   ```
   `Caddyfile.prod`: the `admin.` site body becomes `import admin_site` (the inline matcher and proxy are
   removed); the `auth.` site body becomes `import authentik_site`. The development `Caddyfile` does the same in
   its `admin.` and `auth.` sites (keeping `tls internal`). The `device.` sites of both files become
   `reverse_proxy paddock-gateway:8081 { header_up X-Paddock-Client-IP {client_ip} }`. `bundles.` and `fleet.` are
   not changed.
7. **Public on `auth.<domain>`** (exhaustive): `/application/o/*` (authorize, token, device authorization,
   userinfo, revoke, introspect, per-application `.well-known/openid-configuration`, `jwks/`, `end-session/`),
   `/device` and `/device/*` (the verification page users open on a phone), `/if/flow/*` (flow executor UI: every
   login, the device-code flow `paddock-device-code`, MFA enrollment through `not_configured_action: configure`,
   `paddock-stepup`, `paddock-recovery`), `/flows/*` (flow redirects such as `/flows/-/default/invalidation/`),
   `/api/v3/flows/executor/*`, `/api/v3/root/config/`, `/api/v3/core/brands/current/` (the three API calls the flow
   UI makes), `/static/*`, `/media/*`, `/.well-known/*`, `/favicon.ico`. **Restricted** to
   `PADDOCK_ADMIN_ALLOWED_CIDRS`: `/if/admin/*`, `/if/user/*` (open point 2), `/ws/*`, `/outpost.goauthentik.io/*`,
   `/-/*`, the site root and every other path. `/api/v3/*` other than the three public paths is additionally
   allowed from `PADDOCK_INTERNAL_CIDRS`, because `paddock-api`, `paddock-worker` and `paddock-compiler` reach
   Authentik's API through Caddy's network alias (`PADDOCK_AUTHENTIK_URL = https://auth.<domain>`) with the service
   token. Admin logins to the portal use the same flow executor from an allowed address, so nothing breaks for them.
8. **Variables of the `caddy` service.** `compose.yaml`: `PADDOCK_ADMIN_ALLOWED_CIDRS:
   ${PADDOCK_ADMIN_ALLOWED_CIDRS:-private_ranges 198.51.100.0/24 192.0.2.0/24 2001:db8::/32}`,
   `PADDOCK_INTERNAL_CIDRS: ${PADDOCK_INTERNAL_CIDRS:-private_ranges}`,
   `PADDOCK_EDGE_TRUSTED_PROXIES: ${PADDOCK_EDGE_TRUSTED_PROXIES:-private_ranges}`,
   `PADDOCK_EDGE_CLIENT_IP_HEADER: ${PADDOCK_EDGE_CLIENT_IP_HEADER:-CF-Connecting-IP X-Forwarded-For}`,
   `PADDOCK_EDGE_SERVERS_LISTENER: ":${PADDOCK_HTTPS_PORT:-8443}"`. `compose.prod.yaml` overrides:
   `PADDOCK_ADMIN_ALLOWED_CIDRS: ${PADDOCK_ADMIN_ALLOWED_CIDRS:-0.0.0.0/0 ::/0}` (unchanged default),
   `PADDOCK_INTERNAL_CIDRS: ${PADDOCK_INTERNAL_CIDRS:-private_ranges}`,
   `PADDOCK_EDGE_TRUSTED_PROXIES: ${PADDOCK_EDGE_TRUSTED_PROXIES:-}`,
   `PADDOCK_EDGE_CLIENT_IP_HEADER: ${PADDOCK_EDGE_CLIENT_IP_HEADER:-none}`, `PADDOCK_EDGE_SERVERS_LISTENER: ""`.
   The development defaults admit the host (private ranges) and three documentation networks the gates use to
   simulate foreign clients (`198.51.100.0/24`, `192.0.2.0/24` and `2001:db8::/32` pass the edge;
   `203.0.113.0/24` is refused at the edge). `prod.env.example` documents all five variables with the Cloudflare
   example and the recommendation to narrow `PADDOCK_INTERNAL_CIDRS` to the Compose network's subnet when the host
   has other machines in private ranges.
9. **Development trusted-proxy test path.** With decision 8 the development Caddy trusts the host, so a gate
   sends `X-Forwarded-For: <address>` or `CF-Connecting-IP: <address>` and Caddy's `client_ip` matcher, Caddy's
   access log and (through `X-Paddock-Client-IP`) the api and the gateway all see that address. For the untrusted
   case the development `Caddyfile` adds a second listener: the site block
   `https://admin.{$PADDOCK_DOMAIN}:{$PADDOCK_HTTPS_UNTRUSTED_PORT}` with `tls internal` and `import admin_site`;
   `compose.yaml` publishes `${PADDOCK_HTTPS_UNTRUSTED_PORT:-8444}` next to `PADDOCK_HTTPS_PORT` and passes the
   variable to Caddy; the `servers` block of decision 2 is bound to the main listener only, so on 8444 no peer is
   trusted and every header is ignored. `stack.AdminUntrustedURL()` returns
   `PADDOCK_TEST_ADMIN_UNTRUSTED_URL` (default `https://admin.paddock.localhost:8444`). The production overlay
   publishes 80 and 443 only (unchanged; `prod-check` enforces it), so the listener exists in development only. No
   `PADDOCK_TEST_*` header hook is added to the api.

### 3.3 Application allow list (server)
10. **Entity** `ip_allowlist_entry`, platform scope, migration `server/migrations/paddock/<next free goose number>_ip_allowlist.sql`
    (forward-only; 00036 at the time of writing):
    ```sql
    -- IP allow list of the administrative surfaces (plan M7a decision 10): platform data, role paddock_platform only.
    CREATE TABLE ip_allowlist_entry (
      id         uuid PRIMARY KEY,
      cidr       cidr NOT NULL UNIQUE,
      label      text NOT NULL CHECK (char_length(label) BETWEEN 1 AND 64),
      created_by text NOT NULL,              -- display name of the platform administrator, or "paddock-server admin"
      created_at timestamptz NOT NULL DEFAULT now(),
      updated_at timestamptz NOT NULL DEFAULT now()
    );
    CREATE INDEX ip_allowlist_entry_created_idx ON ip_allowlist_entry (created_at);
    GRANT SELECT, INSERT, UPDATE, DELETE ON ip_allowlist_entry TO paddock_platform;
    ```
    Add `"ip_allowlist_entry": true` to the allow list of `rlslint_test.go` (platform data without organization
    data). sqlc queries in `server/internal/adapters/postgres/queries/ip_allowlist.sql`: `ListIPAllowlistEntries`
    (list contract: `q_pattern` over `label` and `cidr::text`, sort allow list of decision 16, `id` tie-breaker),
    `CountIPAllowlistEntries`, `GetIPAllowlistEntry`, `AllIPAllowlistEntries` (every row ordered by `cidr`),
    `InsertIPAllowlistEntry`, `UpdateIPAllowlistEntry` (`cidr`, `label`, `updated_at = now()`),
    `DeleteIPAllowlistEntry`, `DeleteAllIPAllowlistEntries` (`RETURNING cidr`). pgx v5 maps `cidr` to `netip.Prefix`.
11. **Domain package** `server/internal/domain/ipallowlist`, pure, unit-tested:
    ```go
    package ipallowlist
    type Entry struct { ID uuid.UUID; CIDR netip.Prefix; Label, CreatedBy string; CreatedAt, UpdatedAt time.Time }
    // ParseCIDR accepts "a.b.c.d/n" and "<ipv6>/n" only: netip.ParsePrefix, IPv4-mapped IPv6 refused, bits ≥ 1
    // (a /0 is refused: it would switch the feature on without restricting anything), host bits zero
    // (prefix == prefix.Masked(); otherwise the error names the canonical form). A single address is "/32" or "/128".
    func ParseCIDR(s string) (netip.Prefix, error)
    func ValidateLabel(s string) error              // 1–64 runes, no control characters, trimmed by the caller
    type Consequence string
    const ( ConsequenceNone Consequence = "none"; ConsequenceLockout Consequence = "lockout"; ConsequenceDisable Consequence = "disable" )
    // ConsequenceOf: Disable when before is non-empty and after is empty; Lockout when after is non-empty and no
    // prefix of after contains caller (an invalid caller address counts as not contained); otherwise None.
    func ConsequenceOf(before, after []netip.Prefix, caller netip.Addr) Consequence
    type Set struct{ /* prefixes */ }
    func NewSet(prefixes []netip.Prefix) Set
    func (s Set) Enabled() bool                      // len(prefixes) > 0
    func (s Set) Allows(ip netip.Addr) bool          // !Enabled() || any prefix contains ip.Unmap()
    func (s Set) Covering(ip netip.Addr) []netip.Prefix
    ```
12. **Use case** `server/internal/app/ipallowlist.go`, `type IPAllowlist struct` with `runner *ActionRunner`,
    `platform *db.PlatformPool`, `version Version` (decision 19), `now func() time.Time`:
    ```go
    type IPAllowlistItem struct { ipallowlist.Entry; CoversCaller bool }
    func NewIPAllowlist(runner *ActionRunner, platform *db.PlatformPool, version Version) *IPAllowlist
    func (a *IPAllowlist) List(ctx context.Context, page ListPage) (Listed[IPAllowlistItem], error)   // RequirePlatform
    func (a *IPAllowlist) Get(ctx context.Context, id uuid.UUID) (IPAllowlistItem, error)            // RequirePlatform; 404 not_found
    func (a *IPAllowlist) Create(ctx context.Context, cidr, label string, confirm ipallowlist.Consequence) (IPAllowlistItem, error)
    func (a *IPAllowlist) Update(ctx context.Context, id uuid.UUID, cidr, label *string, confirm ipallowlist.Consequence) (IPAllowlistItem, error)
    func (a *IPAllowlist) Delete(ctx context.Context, id uuid.UUID, confirm ipallowlist.Consequence) error
    // Load reads every prefix with a system principal; used by the enforcer (decision 18) and the CLI.
    func (a *IPAllowlist) Load(ctx context.Context) ([]netip.Prefix, error)
    // DisableAll and AddBreakGlass are the host-side break-glass operations (decision 21); system principal.
    func (a *IPAllowlist) DisableAll(ctx context.Context) (removed []netip.Prefix, err error)
    func (a *IPAllowlist) AddBreakGlass(ctx context.Context, cidr, label string) (IPAllowlistItem, error)
    ```
    `SpecIPAllowlistChange = ActionSpec{Code: audit.CodePlatformIPAllowlistChanged, AllowedRoles: RolesPlatform,
    RequiresStepUp: true}`; `SpecIPAllowlistDisable = ActionSpec{Code: audit.CodePlatformIPAllowlistDisabled}`
    (system principal only). `Create`, `Update`, `Delete` run one `runner.RunTx(ctx, ScopePlatform,
    SpecIPAllowlistChange, …)` each: lock the table (`LOCK TABLE ip_allowlist_entry IN SHARE ROW EXCLUSIVE MODE`
    — the consequence check must see a consistent set under concurrent writes), read `AllIPAllowlistEntries`
    (before), compute `after`, `c := ipallowlist.ConsequenceOf(before, after, caller)` with `caller` parsed from
    `p.IP`; when `c != None && confirm != c` return `problem.LockoutConfirmationRequired` or
    `problem.DisableConfirmationRequired` (recorded as **failure** by the runner, nothing changed); otherwise write,
    `rec.SetTarget(audit.Target{Type: "ip_allowlist_entry", ID: id, Display: cidr})`, params `action`
    (`added|updated|removed`), `cidr`, `label`, `previous_cidr`, `previous_label` (updates only), `entries` (count
    after), `consequence` (`none|lockout|disable`). A `confirm` that does not match the computed consequence is
    ignored (the UI re-asks on the next 409). Duplicate `cidr` → `409 already_exists`. After a successful commit the
    use case calls `a.version.Bump(ctx)` (errors logged, not returned) and the enforcer of the same process reloads
    synchronously (decision 18) before the handler answers. `created_by` is `p.Display`.
13. **Problems** (`server/internal/problem/problem.go`): `IPNotAllowed = {Code: "ip_not_allowed", Status: 403}`,
    `LockoutConfirmationRequired = {Code: "lockout_confirmation_required", Status: 409}`,
    `DisableConfirmationRequired = {Code: "disable_confirmation_required", Status: 409}`. `app.OutcomeOf` maps
    `IPNotAllowed` to `denied`.
14. **Audit codes** (closed registry `server/internal/domain/audit/codes.go`):
    | Code | Params | Outcomes | Note |
    | --- | --- | --- | --- |
    | `platform.ip_allowlist_changed` | action, cidr, label, previous_cidr, previous_label, entries, consequence | success, failure, denied | target `ip_allowlist_entry`; denied `step_up_required` without a fresh step-up or `forbidden` for a non-platform principal; failure `lockout_confirmation_required` / `disable_confirmation_required` / `already_exists`; actor system (`paddock-server admin allowlist add`) for the break-glass add |
    | `platform.ip_allowlist_denied` | ip, count, window_seconds, first_at, last_at, aggregated, distinct_ips | denied | actor anonymous with the client address; aggregated per address and window (decision 20); edge denials are not audited |
    | `platform.ip_allowlist_disabled` | method, entries_removed, removed | success, failure | actor system; `method` is `cli` (`paddock-server admin allowlist disable`, `removed` lists the CIDRs) or `env` (`PADDOCK_IP_ALLOWLIST_BYPASS`, recorded once per api start with `entries_removed: 0`) |
    All three are recorded in the platform pseudo-organization. `make gen` regenerates `docs/compliance/audit-codes.md`
    and `server/web/src/lib/auditCodes.gen.ts`.
15. **`GET /api/v1/me`** gains the required field `client_ip: string` (the resolved address of decision 5, for
    sessions and API tokens alike). The portal uses it for the "your current address" hint; the gates use it to
    observe the derivation.
16. **Endpoints** (OpenAPI tag `platform`, `security: [session]` only — platform tokens do not exist; a bearer
    request is `403 forbidden` as for every platform operation):
    ```
    GET    /api/platform/v1/ip-allowlist                 roles: platform_admin   list contract
           x-paddock-list: { sort: [cidr, label, created_at], default_sort: cidr, search: [label, cidr], filters: [] }
           200 IpAllowlistEntryPage
    POST   /api/platform/v1/ip-allowlist?confirm={lockout|disable}   roles: platform_admin; step-up
           x-paddock-audit: platform.ip_allowlist_changed
           body IpAllowlistEntryCreate { cidr: string, label: string }
           201 IpAllowlistEntry   Location: /api/platform/v1/ip-allowlist/{id}
           400 invalid_request · 403 forbidden | step_up_required · 409 already_exists | lockout_confirmation_required
    GET    /api/platform/v1/ip-allowlist/{id}            roles: platform_admin   200 IpAllowlistEntry · 404 not_found
    PATCH  /api/platform/v1/ip-allowlist/{id}?confirm=   roles: platform_admin; step-up; x-paddock-audit: platform.ip_allowlist_changed
           body IpAllowlistEntryUpdate { cidr?: string, label?: string }   (at least one field)
           200 IpAllowlistEntry · 400 · 403 · 404 · 409 already_exists | lockout_confirmation_required
    DELETE /api/platform/v1/ip-allowlist/{id}?confirm=   roles: platform_admin; step-up; x-paddock-audit: platform.ip_allowlist_changed
           204 · 403 · 404 · 409 lockout_confirmation_required | disable_confirmation_required
    IpAllowlistEntry { id: uuid, cidr: string, label: string, created_by: string, created_at: date-time,
                       updated_at: date-time, covers_caller: boolean }
    ```
    `confirm` is an optional query parameter with `enum: [lockout, disable]` (any other value → 400). Mutating
    operations declare the `X-Paddock-CSRF` header like every other. Add the three mutating routes to `privileged`
    in `server.go` (`{app.ScopePlatform, app.SpecIPAllowlistChange}`), the operations to `isolation_fixtures.go`
    (as the existing platform operations are listed), the exactly-once cases to `audit_once_test.go`, the list to
    `listspec_test.go` (`"listIpAllowlist": {…, "postgres/queries/ip_allowlist.sql", "ListIPAllowlistEntries", "id"}`).
17. **Enforcement middleware** `server/internal/transport/http/admin/ipguard.go`:
    ```go
    // IPGuard enforces the application allow list on every request of the admin surface (plan M7a decision 17).
    type IPGuard struct { /* atomic.Pointer[ipallowlist.Set], load, version, denials, bypass, metrics */ }
    func NewIPGuard(load func(context.Context) ([]netip.Prefix, error), version app.Version, denials *app.IPDenials, bypass bool) *IPGuard
    func (g *IPGuard) Run(ctx context.Context) error   // decision 18; returns when ctx ends
    func (g *IPGuard) Ready() bool                      // true after the first successful load, or with bypass
    func (g *IPGuard) Reload(ctx context.Context) error // synchronous reload (used after a write in this process)
    func (g *IPGuard) Middleware(next http.Handler) http.Handler
    ```
    `Deps` gets `IPGuard *IPGuard` (nil = not installed; `serveAPI` always installs it). Chain in `NewHandler`:
    `RequestIDMiddleware(WithClientIP(Recover(AccessLog(securityHeaders(ipGuard.Middleware(root))))))` — the guard
    runs before the static handler, `/api/auth/*` and the session middleware, so a denied request never touches a
    session, a token or a use case. Decision per request: `set := g.current()`; `ip, ok := httpx.ClientAddr(r)`;
    allowed when bypass, or `!set.Enabled()`, or (`ok` and `set.Allows(ip)`). Denied: `denials.Note(ip, now)` and
    `metricDenied.Inc()`; for a path with prefix `/api/` → `httpx.WriteProblem(w, r, problem.IPNotAllowed)` (no
    detail); for every other path → status 403, `Content-Type: text/plain; charset=utf-8`, body `403 Forbidden\n`,
    `Cache-Control: no-store`. The response carries no hint of the list, the feature or the server version. The api's
    readiness (`ops.Serve` callback in `api.go`) adds `errors.New("ip allow list not loaded")` while `!g.Ready()`.
18. **Cache and propagation.** Every api replica keeps the set in memory. `Run` loads it at start (retrying every
    5 s until the first success), then every 2 s reads the version (decision 19) and reloads from PostgreSQL when it
    changed, and reloads unconditionally every 60 s. A failed reload keeps the last set, logs a warning and raises
    `paddock_ip_allowlist_reload_errors_total`. `Load` runs `platform.InPlatform` with a system principal
    (`principal.Principal{Kind: principal.KindSystem}`) and `AllIPAllowlistEntries`. The writing replica calls
    `Reload` synchronously after its commit; other replicas follow within 2 s via the version, or within 60 s if
    Valkey is unavailable. No outbox or RabbitMQ path is used: the api has no RabbitMQ credential, and the list is
    small, platform-wide and read on every request, so a version key plus a periodic reload is simpler and has no
    new failure mode.
19. **Version key** — new package `server/internal/allowlistcache`:
    ```go
    // Version is the change counter of the IP allow list in Valkey under ipal:ver (plan M7a decision 19).
    type Version struct{ c valkey.Client }
    func NewVersion(c valkey.Client) *Version
    func (v *Version) Bump(ctx context.Context) error          // INCR ipal:ver
    func (v *Version) Get(ctx context.Context) (int64, error)  // GET ipal:ver; 0 when absent
    ```
    `app.Version` is the interface `{ Bump(ctx) error; Get(ctx) (int64, error) }`. `worker.CacheSync.ReconcileAll`
    is not involved (the key is a counter, not a cache of data).
20. **Denial aggregation** `server/internal/app/ipdenials.go`, `type IPDenials struct`, `NewIPDenials(runner
    *ActionRunner, window time.Duration, now func() time.Time)`, `Note(ip netip.Addr, at time.Time)` (no I/O on
    the request path: a mutex-protected map), `Run(ctx context.Context)` (background recorder). Window:
    10 minutes (`PADDOCK_TEST_IP_ALLOWLIST_WINDOW` shortens it in development only; the variable is refused in
    production by the existing `PADDOCK_TEST_` rule of `prod-check`). Per replica and window:
    - the first denial of an address → one event at once (`ip`, `count: 1`, `window_seconds`, `aggregated: false`),
      for at most **20** distinct addresses per window;
    - further denials of a seen address are counted; at the window's end one summary event per address with
      `count > 1` (`ip`, `count`, `first_at`, `last_at`, `window_seconds`, `aggregated: true`);
    - addresses beyond the 20 are counted only; at the window's end one event with `ip: ""`, `distinct_ips`, `count`,
      `aggregated: true`.
    Bound: 41 events per window and replica (5 904 per day) however large the scan. Every event is recorded with
    `runner.RunTxRefusal(ctx, ScopePlatform, ActionSpec{Code: audit.CodePlatformIPAllowlistDenied, Actor:
    &audit.Actor{Type: audit.ActorAnonymous, IP: ip}, Params: …}, problem.IPNotAllowed, noop)` under a system
    principal; the correlation ID is `ipal-<window start unix>-<ip>` (immediate and summary events of one address
    and window share it). The exact per-request count is always in the metric
    `paddock_ip_allowlist_denied_total` (no address label).
21. **Break-glass.** `paddock-server admin allowlist show | disable | add --cidr <cidr> --label <label>` in
    `server/cmd/paddock-server/admin.go` (`parseAdmin` extended; usage text extended), run as
    `docker compose … run --rm --no-deps paddock-worker admin allowlist …`; configuration
    `PADDOCK_DB_PLATFORM_URL_FILE` and `config.LoadValkey` (the worker service has both):
    - `show`: one line per entry `<cidr>\t<label>\t<created_by>\t<created_at RFC 3339>` ordered by `cidr`, or
      `ip allowlist: off (no entries)`; exit 0.
    - `disable`: `IPAllowlist.DisableAll` in one platform transaction, recorded as `platform.ip_allowlist_disabled`
      (`method: cli`, `entries_removed`, `removed`; actor `Actor{Type: ActorSystem, Display: "paddock-server admin"}`),
      prints `ip allowlist disabled: N entries removed`; with an empty list prints `ip allowlist: already off`,
      records nothing; exit 0.
    - `add`: `IPAllowlist.AddBreakGlass` (`created_by: "paddock-server admin"`, no consequence check, no step-up:
      system principal), recorded as `platform.ip_allowlist_changed` (`action: added`, `consequence: none`), prints
      `ip allowlist: added <cidr>`; duplicate → exit 1 `already exists`.
    Both writers call `Version.Bump`; when Valkey is unreachable they print `note: api replicas reload within 60 s`
    and still exit 0. Exit codes as `exitCode` (0/1/2).
22. **Environment override.** `PADDOCK_IP_ALLOWLIST_BYPASS` (bool, api only, default `false`;
    `compose.prod.yaml` and `compose.yaml` pass `${PADDOCK_IP_ALLOWLIST_BYPASS:-false}` to `paddock-api`). When
    true: the guard allows everything, logs `ip allow list bypassed by PADDOCK_IP_ALLOWLIST_BYPASS` at start and
    every 10 minutes, sets the gauge `paddock_ip_allowlist_bypass` to 1, and records one
    `platform.ip_allowlist_disabled` (`method: env`) at start. The edge list is bypassed by setting
    `PADDOCK_ADMIN_ALLOWED_CIDRS` to `0.0.0.0/0 ::/0` and recreating Caddy (`docker compose up -d caddy`); both
    steps are the runbook of decision 28.
23. **Metrics** (api): `paddock_ip_allowlist_entries` (gauge), `paddock_ip_allowlist_enabled` (gauge 0/1),
    `paddock_ip_allowlist_bypass` (gauge 0/1), `paddock_ip_allowlist_denied_total` (counter),
    `paddock_ip_allowlist_reload_errors_total` (counter), `paddock_ip_allowlist_last_reload_timestamp_seconds`
    (gauge). Alert in `deploy/compose/prometheus/alerts.yml`: `PaddockIPAllowlistBypassed`
    (`max(paddock_ip_allowlist_bypass) == 1` for 15 m, severity warning, summary "IP allow list bypassed on the
    api", description naming the variable) with a case in `alerts_test.yml`.
24. **prod-check** (`server/internal/prodcheck/prodcheck.go`), new item `edge client address` on the `caddy`
    service's environment, FAIL when: `PADDOCK_EDGE_CLIENT_IP_HEADER` is not exactly one of `none`,
    `X-Forwarded-For`, `CF-Connecting-IP`; the header is not `none` and `PADDOCK_EDGE_TRUSTED_PROXIES` is empty;
    the header is `none` and the list is not empty; the list contains an unparsable entry or any `/0`
    (`0.0.0.0/0`, `::/0`); `PADDOCK_EDGE_SERVERS_LISTENER` is not empty. New item `role trusted proxies`: FAIL when
    `PADDOCK_TRUSTED_PROXY_CIDRS` of any role is unparsable or contains a `/0`. `checkCaddy` additionally FAILs when
    `/etc/caddy/guards.caddy` is not mounted from `deploy/compose/caddy/guards.caddy` or `/paddock/entrypoint.sh`
    is not mounted from `deploy/compose/caddy/entrypoint.sh`, or the mounted Caddyfile declares `trusted_proxies`
    or `client_ip_headers` itself (the entrypoint is the only place). New item `ip allow list bypass is off`: FAIL
    when `paddock-api` has `PADDOCK_IP_ALLOWLIST_BYPASS` set to a true value. `compose_test.go` (the static test
    that renders the real Compose configurations) asserts both Caddyfiles import the snippet, carry
    `{$CADDY_SERVERS_BLOCK}` and set `header_up X-Paddock-Client-IP {client_ip}` on every proxy to `paddock-api`
    and `paddock-gateway`, and that the production overlay publishes 80 and 443 only.

### 3.4 Portal
25. **Page** `/platform/ip-allowlist` (`server/web/src/views/IpAllowlist.vue`, router name `ip-allowlist`, nav item
    `nav.ipAllowlist` in the `platform` group after `nav.agentReleases`, visible to `isPlatform`):
    - a status card: "Your current address: {client_ip}" (from `GET /api/v1/me`), then one of "The allow list is
      off: no entries. Everyone who can log in can use the portal." / "Enabled with N entries; your address is
      covered by <cidr list>" / "Enabled with N entries; **your address is not covered** (you will be locked out
      when your session ends)" — the last in the warning colour;
    - `DataList` (columns cidr, label, created_by, created_at; search; sort as the contract; no filters) with row
      actions *Edit* and *Remove*;
    - *Add entry* and *Edit* dialogs (`components/IpAllowlistEntryForm.vue`): fields `cidr` and `label`, a "use my
      address" button that fills `<client_ip>/32` or `/128`, client-side validation through the new `lib/cidr.ts`
      (`parseCIDR(text): { ok: true, kind: 'v4' | 'v6', canonical: string } | { ok: false, message: string }`:
      IPv4 dotted quad with prefix 1–32 and host bits zero; IPv6 syntax — hex groups, at most one `::`, optional
      embedded IPv4 — with prefix 1–128; the server stays authoritative and its `detail` is shown on 400);
    - on `step_up_required` every write uses `startStepUp('ip-allowlist', …)` (`lib/stepUp.ts`) and resumes once;
    - *Remove* confirms with `ConfirmDialog` (destructive, no typed text); on `409 lockout_confirmation_required`
      (add, edit or remove) the dialog re-opens with `requireTypedText` = the entry's CIDR and the message key
      `ipAllowlist.confirmLockout` ("This change removes your own address {ip} from the list. You will lose access
      when your session ends."), confirm repeats the request with `?confirm=lockout`; on
      `409 disable_confirmation_required` the same with `ipAllowlist.confirmDisable` ("Removing the last entry
      switches the allow list off for everyone.") and `?confirm=disable`;
    - errors and successes as inline alerts or snackbars (ADR 0018).
    `lib/ipAllowlist.ts` wraps the four operations (`listIpAllowlist`, `createIpAllowlistEntry`,
    `updateIpAllowlistEntry`, `deleteIpAllowlistEntry`), each returning the problem code on error as
    `lib/organizations.ts` does.
26. **i18n and audit:** keys in `server/web/src/locales/en.json` and `de.json` (`nav.ipAllowlist`, `ipAllowlist.*`,
    `audit.platform.ip_allowlist_changed`, `audit.platform.ip_allowlist_denied`,
    `audit.platform.ip_allowlist_disabled`). Vitest: `lib/cidr.ts` (table of valid and invalid IPv4/IPv6 inputs,
    canonical form), the status card's three states. e2e `server/web/e2e/ipAllowlist.spec.ts` (step 4).

### 3.5 Documentation
27. `docs/operations/ip-allowlist.md` (new): the two layers and what each one protects; the exhaustive public path
    list of decision 7; **client address** — the edge variables of decision 1 with three worked configurations
    (Caddy first: defaults; a load balancer that appends `X-Forwarded-For`: its addresses and `X-Forwarded-For`;
    Cloudflare: the published ranges from `https://www.cloudflare.com/ips/` and `CF-Connecting-IP`, with the
    note that the origin MUST be firewalled to those ranges so that nobody bypasses the CDN, and that a refresh of
    the ranges is a recurring operator task), the canonical header `X-Paddock-Client-IP` and why the roles read
    nothing else, `PADDOCK_TRUSTED_PROXY_CIDRS`; managing the list, step-up, the two confirmations; **egress
    addresses for `paddockctl` and CI** — API-token requests are subject to the same list, so CI runners need a
    stable egress address (self-hosted runner, NAT gateway or VPN; hosted runners without a fixed address cannot be
    allow-listed) and `paddockctl` users need to be inside an allowed range or VPN; break-glass runbook (decisions
    21 and 22, including the edge variable); the audit codes; metrics and the alert; residual risks (private-range
    peers of the host can reach Authentik's API with a token; a shared NAT address admits every host behind it; a
    stale CDN range list silently stops trusting a new CDN address, which then counts as a client).
28. `docs/operations/install.md`: hostname table row `auth.<domain>` → "internet for logins and device approvals;
    administrative paths restricted by `PADDOCK_ADMIN_ALLOWED_CIDRS`", row `admin.<domain>` → "restricted by
    `PADDOCK_ADMIN_ALLOWED_CIDRS` and the application allow list (`docs/operations/ip-allowlist.md`)"; in section 1
    a paragraph "Proxies or a CDN in front of Caddy" pointing to decision 1's variables; a step in section 8 "4. Set
    the IP allow list (optional) …"; the `prod-check` paragraph lists the new items. `docs/operations/api-tokens.md`
    and `docs/operations/paddockctl.md`: one paragraph each on egress addresses linking the runbook.
    `docs/operations/monitoring.md`: the new metrics and alert. `docs/operations/local-dev.md`: the development edge
    defaults, the trusted-proxy test path and the untrusted listener 8444 (decisions 8 and 9).
    `deploy/compose/prod.env.example`: `PADDOCK_ADMIN_ALLOWED_CIDRS` (existing), `PADDOCK_INTERNAL_CIDRS`,
    `PADDOCK_EDGE_TRUSTED_PROXIES`, `PADDOCK_EDGE_CLIENT_IP_HEADER`, `PADDOCK_IP_ALLOWLIST_BYPASS`,
    `PADDOCK_TRUSTED_PROXY_CIDRS` (commented, with the defaults). `CHANGELOG.md` *Unreleased → Added*.

## 4. Non-goals
Per-user or per-organization IP rules; organization-scoped lists (the perimeter is platform-wide: ADR 0007 makes
Authentik's admin surface platform-level, and a per-organization list would leave `auth.` and the platform pages
unprotected — open point 1); GeoIP or ASN rules; rate limiting of the admin surface; a platform audit view in the
portal (platform events stay in the audit index and SIEM, as today — open point 6); allow-listing `device.`,
`bundles.` or `fleet.`; restricting `/if/user/*` for end users (restricted by default, open point 2); automatic
download of a CDN's address ranges (operator task, documented); the PROXY protocol on Caddy's listener (open point
5); a trusted-proxy list in the database (the edge cannot read the database, and one source of truth for the same
fact is required — open point 8); changes to `agent/`, `pkg/`, `cli/`, `docs/architecture.md`, `docs/adr/` (the main
session places ADR 0021), `docs/reqirements/`; Kubernetes manifests.

## 5. Affected files
| Path | Action | Purpose |
| --- | --- | --- |
| `server/internal/platform/httpx/httpx.go` (+ test) | change | `ClientIPHeader`, `WithClientIP`, `ClientIP`, `ClientAddr` (decision 5) |
| `server/internal/config/config.go` (+ test) | change | `Common.TrustedProxies`, `PADDOCK_TRUSTED_PROXY_CIDRS` (decision 4) |
| `server/internal/transport/http/admin/server.go`, `device/device.go` | change | install `WithClientIP`; `IPGuard` in the admin chain; `Deps.TrustedProxies`, `Deps.IPGuard` |
| `server/cmd/paddock-server/api.go`, `gateway.go`, `admin.go`, `main.go` | change | wiring, bypass, `admin allowlist` subcommands, usage |
| `deploy/compose/caddy/entrypoint.sh` | new | validation and `CADDY_SERVERS_BLOCK` (decision 2) |
| `deploy/compose/caddy/guards.caddy` | new | shared edge sites (decision 6) |
| `deploy/compose/caddy/Caddyfile`, `Caddyfile.prod` | change | `{$CADDY_SERVERS_BLOCK}`, imports, canonical header on `device.`, dev untrusted listener (decisions 2, 3, 6, 9) |
| `deploy/compose/compose.yaml`, `compose.prod.yaml`, `compose.dev.yaml`, `prod.env.example` | change | caddy entrypoint and mounts, variables, port 8444 (dev), test window |
| `server/migrations/paddock/<next>_ip_allowlist.sql` | new | decision 10 |
| `server/internal/adapters/postgres/queries/ip_allowlist.sql` (+ `make gen`) | new | decision 10 |
| `server/internal/platform/db/rlslint_test.go` | change | allow list entry |
| `server/internal/domain/ipallowlist/` (+ tests) | new | decision 11 |
| `server/internal/app/ipallowlist.go`, `ipdenials.go` (+ tests, integration tests) | new | decisions 12, 20 |
| `server/internal/allowlistcache/` | new | decision 19 |
| `server/internal/transport/http/admin/ipguard.go`, `handlers_ipallowlist.go` (+ tests) | new | decisions 16, 17 |
| `server/internal/transport/http/admin/handlers.go` | change | `client_ip` in `GET /api/v1/me` |
| `server/internal/problem/problem.go`, `server/internal/app/action.go` (`OutcomeOf`) | change | decision 13 |
| `server/internal/domain/audit/codes.go` (+ `make gen`) | change | decision 14 |
| `api/openapi/admin.yaml` (+ `make gen`) | change | decisions 15, 16 |
| `server/internal/transport/http/admin/listspec_test.go`, `test/acceptance/isolation_fixtures.go`, `audit_once_test.go` | change | contract fixtures |
| `server/internal/prodcheck/prodcheck.go`, `prodcheck_test.go`, `compose_test.go` | change | decision 24 |
| `deploy/compose/prometheus/alerts.yml`, `alerts_test.yml` | change | decision 23 |
| `server/web/src/views/IpAllowlist.vue`, `components/IpAllowlistEntryForm.vue`, `lib/ipAllowlist.ts`, `lib/cidr.ts` (+ tests), `lib/navigation.ts`, `router.ts`, `locales/en.json`, `locales/de.json` | new / change | decisions 25, 26 |
| `server/web/e2e/ipAllowlist.spec.ts` | new | step 4 |
| `test/acceptance/ip_allowlist_test.go`, `edge_client_ip_test.go` | new | gates A1–A4 |
| `test/acceptance/internal/env/env.go` | change | `HeaderClient(headers map[string]string) (*http.Client, error)`: `NewHTTPClient` with a transport that sets the given headers on every request (gates A1, A2, A4) |
| `test/acceptance/internal/stack/stack.go` | change | `AdminUntrustedURL()` (decision 9) |
| `docs/operations/ip-allowlist.md`, `install.md`, `api-tokens.md`, `paddockctl.md`, `monitoring.md`, `local-dev.md`, `CHANGELOG.md` | new / change | decisions 27, 28 |

MUST NOT be touched: `agent/`, `pkg/`, `cli/`, `server/internal/revoke*`, `docs/architecture.md`, `docs/adr/`,
`docs/reqirements/`, the `bundles.` and `fleet.` sites of both Caddyfiles, existing migrations.

## 6. Steps
One commit per step; `make lint test` green before each commit; `make gen` after every change to
`api/openapi/admin.yaml`, the sqlc queries or `codes.go`.
1. **Client address and edge.** Decisions 1–9, 24 (edge and role items, Caddyfile findings) and the `client_ip`
   field of decision 15. Unit tests: `httpx` derivation table (untrusted peer with `X-Paddock-Client-IP`,
   `X-Forwarded-For` and `CF-Connecting-IP` → peer; trusted peer with the canonical header → header; trusted peer
   with only `X-Forwarded-For` or `CF-Connecting-IP` → peer; unparsable canonical header → peer; IPv6 peer and IPv6
   header value; IPv4-mapped); `config` parsing incl. `/0` refusal; `device/auth` rate-limit key uses the derived
   address; `prodcheck` tests for every finding of decision 24; `compose_test.go` assertions; a shell test of
   `entrypoint.sh` (run with `sh` in the pinned Caddy image through `docker run`, as `lint-prometheus` runs
   `promtool`): each invalid combination exits 1 with its message, `none` yields an empty block, a valid pair yields
   the block of decision 2.
   **Gate A2 (acceptance `TestEdgeClientIP`, file `edge_client_ip_test.go`)**, platform admin logged in, through
   `stack.AdminURL()` (trusted listener) with `env.HeaderClient`:
   - `X-Forwarded-For: 198.51.100.7` → `GET /api/v1/me` 200 with `client_ip: 198.51.100.7`;
   - `CF-Connecting-IP: 198.51.100.8` → `client_ip: 198.51.100.8`;
   - both headers with different values → `client_ip` is the `CF-Connecting-IP` value (header selection order);
   - `X-Forwarded-For: 198.51.100.9, 198.51.100.10` → `client_ip: 198.51.100.10` (right-to-left parsing);
   - `X-Forwarded-For: 2001:db8::9` → `client_ip: 2001:db8::9` (IPv6);
   - `X-Paddock-Client-IP: 198.51.100.11` alone → `client_ip` ≠ `198.51.100.11` (Caddy overwrote the canonical
     header; it equals the peer);
   - no header → `client_ip` equals the peer address P (recorded for the next cases);
   - `X-Forwarded-For: 203.0.113.9` → HTTP 403 without `X-Request-Id` and without a JSON body (the edge answered).
   Through `stack.AdminUntrustedURL()` (untrusted listener): `X-Forwarded-For: 198.51.100.7`,
   `CF-Connecting-IP: 198.51.100.8` and `X-Paddock-Client-IP: 198.51.100.11` each → 200 with `client_ip` = P;
   `X-Forwarded-For: 203.0.113.9` → 200 (not edge-denied: the spoofed address does not count).
   Through `stack.AuthURL()` with `X-Forwarded-For: 203.0.113.9`: `GET /if/admin/` → 403, `GET /api/v3/core/users/me/`
   → 403, `GET /if/user/` → 403; `GET /api/v3/root/config/` → not 403; the complete device-code login of
   `alice@acme.test` (`authflow` device helper with the header client: device authorization, `/device?code=`, flow
   executor with MFA, token, userinfo) succeeds. `env.NewAuthentik()` (bootstrap token, host address) still reaches
   `/api/v3/`. Gateway: the device protocol gate (`device_protocol_test.go`) is run once with `HeaderClient` setting
   `X-Forwarded-For: 198.51.100.12` to prove nothing breaks on `device.`; the access log line of that check-in (read
   with `stack.Compose(ctx, nil, "logs", "paddock-gateway")`) carries `"ip":"198.51.100.12"`.
2. **Application allow list (server).** Decisions 10–20, 23 (metrics). Unit tests: `ipallowlist` (`ParseCIDR` table
   incl. `/0`, host bits, mapped addresses; `ConsequenceOf` table; `Set.Allows` with IPv4 and IPv6); `IPDenials`
   with a fake clock (first event at once, 20-address cap, summary at window end, correlation IDs); `IPGuard` with
   `httptest` (allowed, denied JSON for `/api/…`, denied plain text for `/`, bypass, not ready before the first
   load). Integration tests (`ipallowlist_integration_test.go`): `paddock_api` cannot read the table; lock +
   consequence under two concurrent writers; `DeleteAll` returns the CIDRs. Handler tests: the three 409s, `confirm`
   enum, step-up required, bearer refused, exactly one event per attempt.
   **Gate A1 (acceptance `TestIPAllowlist`):** the platform admin (`env.PlatformAdmin`, step-up with its TOTP)
   reads `client_ip` = C from `/me`; `GET /api/platform/v1/ip-allowlist` is empty (precondition; otherwise the gate
   fails naming `paddock-server admin allowlist disable`); `POST` without step-up → 403 `step_up_required` and one
   denied `platform.ip_allowlist_changed` in the platform pseudo-organization (`env.AuditIndex`); after the step-up
   `POST {cidr: "198.51.100.0/24"}` → 409 `lockout_confirmation_required` and one failure event, list still empty;
   `POST {cidr: C/32 or C/128, label: "gate host"}` → 201 with `covers_caller: true`, one success event
   (`action: added`, `consequence: none`, `entries: 1`); `POST 198.51.100.0/24` → 201; `POST 2001:db8::/32` → 201;
   `POST 198.51.100.0/24` again → 409 `already_exists`; `PATCH` label → 200, one event `action: updated` with
   `previous_label`; through `env.HeaderClient` with `X-Forwarded-For: 198.51.100.7` → `/me` 200; with
   `X-Forwarded-For: 2001:db8::9` → 200; with `192.0.2.9`: `GET /api/v1/me` → 403 `ip_not_allowed` with
   `X-Request-Id`, `GET /` → 403 `text/plain`, `GET /api/platform/v1/organizations` with the platform admin's
   session → 403, and `GET /api/v1/me` with a valid acme API token (`createAPIToken` of `api_token_helpers.go`) →
   403 `ip_not_allowed`; exactly one `platform.ip_allowlist_denied` (`ip: 192.0.2.9`, `count: 1`,
   `aggregated: false`) within 10 s; 20 further requests from `192.0.2.9` → no further event within 5 s, then one
   summary event (`count: 21`, `aggregated: true`) within 40 s (development window 20 s); through
   `stack.AdminUntrustedURL()` with `X-Forwarded-For: 192.0.2.9` → `/me` 200 (the spoofed address is ignored, the
   peer is allowed); `DELETE` of C's entry → 409 `lockout_confirmation_required`; `DELETE 198.51.100.0/24` and
   `DELETE 2001:db8::/32` → 204; `DELETE` of C's entry → 409 `disable_confirmation_required`;
   `DELETE …?confirm=disable` → 204, event `consequence: disable`, list empty, `192.0.2.9` → `/me` 200 again.
   `t.Cleanup` runs `paddock-server admin allowlist disable` through `stack.Compose` so that a failed gate never
   leaves the stack restricted.
3. **Break-glass, bypass, alert, prod-check.** Decisions 21, 22, 23 (alert), 24 (bypass item). Unit tests of
   `parseAdmin` for the three subcommands; prodcheck test for the bypass finding; `make lint-prometheus`.
   **Gate A3 (acceptance `TestIPAllowlistBreakGlass`, with `stack.Compose(ctx, nil, "run", "--rm", "--no-deps",
   "paddock-worker", "admin", "allowlist", …)`):** `add --cidr <C>/32 --label host` → exit 0, the entry is listed by
   `GET /api/platform/v1/ip-allowlist` with `created_by: "paddock-server admin"` and one `platform.ip_allowlist_changed`
   with actor type `system`; `show` prints it; `disable` → exit 0, prints `1 entries removed`, list empty, one
   `platform.ip_allowlist_disabled` (`method: cli`, `entries_removed: 1`, `removed: [<C>/32]`); `disable` again →
   `already off`, no new event.
   **Gate A4 (acceptance `TestProdCheckEdgeClientIP`, `stack.ComposeProduction` as the existing prod-check gates
   use it):** `prod-check` with `PADDOCK_EDGE_TRUSTED_PROXIES=0.0.0.0/0` and header `X-Forwarded-For` FAILs the item
   `edge client address` naming `0.0.0.0/0`; with header `CF-Connecting-IP` and an empty list FAILs naming the
   missing proxies; with `203.0.113.0/24` and `CF-Connecting-IP` PASSes the item; with `PADDOCK_IP_ALLOWLIST_BYPASS=true`
   FAILs `ip allow list bypass is off`.
4. **Portal.** Decisions 25, 26. `make gen`, Vitest, e2e `ipAllowlist.spec.ts`: the platform admin opens the page
   (status "off"), adds its own address with "use my address" through the step-up (TOTP helper of `e2e/auth.ts`),
   sees "covered", adds `198.51.100.0/24`, removes it through the modal, tries to remove its own entry and gets the
   typed-confirmation dialog, cancels, then confirms with the typed CIDR and `disable`, sees "off" again; axe check;
   cleanup through the API in `e2e/cleanup.ts`. Verified by `make e2e` for the new spec.
5. **Docs and hand-over.** Decisions 27, 28; `CHANGELOG.md`; the main session places ADR 0021 (§9) and the
   architecture amendment (open point 7). Regression: `make acceptance` and `make e2e` complete; system tests are
   not needed (no agent change), but the system VMs' device login MUST still pass after step 1
   (`make system-test VM=all T=<regex of the login gate>`) because the `auth.` and `device.` edge rules changed.

## 7. Acceptance criteria
| # | Given / When / Then | Req. | Observed by |
| --- | --- | --- | --- |
| AC1 | Given a non-empty application list, when a request with a valid session or API token arrives from an address outside it, then the api answers 403 `ip_not_allowed` (JSON under `/api/`, plain text elsewhere) and records at most the aggregated denial events of decision 20 | IPA-1, IPA-7 | Platform admin (403), auditor (audit index), automated gate A1 |
| AC2 | Given `PADDOCK_ADMIN_ALLOWED_CIDRS` set, when a client outside it opens `/if/admin/`, `/if/user/` or `/api/v3/core/…` on `auth.`, or anything on `admin.`, then Caddy answers 403; when a device user starts a device-code login and approves it on a phone from any network, then it completes | IPA-1, IPA-2 | Device user, automated gate A2 |
| AC3 | Given a platform admin with a fresh step-up, when they add, edit or remove an entry, then the list changes on every api replica within 2 s and one `platform.ip_allowlist_changed` with `action`, `cidr` and `consequence` exists; without a fresh step-up the request is denied with `step_up_required` | IPA-3 | Platform admin, auditor |
| AC4 | Given a change that would remove the caller's address while entries remain, or remove the last entry, when it is sent without `confirm`, then it is refused with 409 and nothing changes; in the portal the admin must type the CIDR to proceed | IPA-4 | Platform admin |
| AC5 | Given a locked-out platform, when the operator runs `paddock-server admin allowlist disable` (or `add`) on the host, or sets `PADDOCK_IP_ALLOWLIST_BYPASS=true`, then access is restored, the action is audited as `platform.ip_allowlist_disabled` / `…_changed`, and `prod-check` fails while the bypass is set | IPA-5 | Platform operator, auditor |
| AC6 | Given `PADDOCK_EDGE_TRUSTED_PROXIES` and `PADDOCK_EDGE_CLIENT_IP_HEADER` set for a proxy or CDN in front of Caddy, when a request arrives through that proxy, then the edge allow list, the application allow list, the gateway's per-IP limit, the audit log and the access logs see the real client (IPv4 and IPv6); when any peer outside the list sends `X-Forwarded-For`, `CF-Connecting-IP` or `X-Paddock-Client-IP`, then every layer uses the peer's own address instead; `prod-check` fails on `0.0.0.0/0`, `::/0`, a header without proxies or proxies without a header | IPA-6 | Automated gates A2, A4; platform operator |

## 8. Stop conditions, freedoms, risks and open points

**Stop conditions** (report back instead of deciding): Caddy 2.11.6 rejects `trusted_proxies static` inside a
`servers <listener>` block, the `{client_ip}` placeholder in `header_up`, or a `not` with several arguments inside a
named matcher block; `header_up X-Paddock-Client-IP {client_ip}` does not replace an incoming header of that name
(verify in gate A2; report, do not fall back to `X-Forwarded-For`); the device-code gate of A2 fails on an
Authentik path that is not in decision 7 (report the path; do **not** open `/api/v3/*`); sqlc cannot map the
`cidr` column to `netip.Prefix`; `PlatformPool.InPlatform` refuses the system principal of decision 18; the
`paddock-worker` service lacks a variable the `admin allowlist` subcommands need; the generated strict server cannot
bind the `confirm` query parameter on `DELETE`; a change outside the files of §5 would be required; any need for a
new dependency; the Playwright run cannot complete a step-up for the platform admin; M0 §11 S2/S6/S7/S8.

**Freedoms of the implementer:** internal names and file splits inside `ipallowlist`, `ipguard.go`, `ipdenials.go`;
the exact wording of log lines, entrypoint messages, i18n texts beyond the keys and the three quoted messages, the
status card's layout; the table layout of `allowlist show`; the migration number (next free goose number); whether
`IPDenials.Note` uses a mutex or a channel (bounded, never blocking the request); the regex-free IPv6 parser in
`lib/cidr.ts`; how the entrypoint shell test is wired into `make test` (a Go test shelling out to `docker run`, or a
Makefile target included in `lint`).

**Risks:** (R1) a platform admin locks everyone out by adding a first entry that covers only themself —
mitigation: documented, every write audited, break-glass on the host, typed confirmation is required only for
self-lockout (open point 3). (R2) a NAT address shared with untrusted hosts is allow-listed — accepted, documented
as residual risk. (R3) `private_ranges` as `PADDOCK_INTERNAL_CIDRS` admits private-range peers of the host to
Authentik's API (token still required) — mitigation: documented narrowing to the Compose subnet. (R4) a stale CDN
range list makes a new CDN address an untrusted peer: its forwarded header is ignored and the CDN's address is
treated as the client, so allow-listed admins behind that address are denied (fail closed, never spoofable) —
mitigation: documented refresh task; the origin firewall limits exposure. (R5) the Caddy restart after changing an
edge variable interrupts connections for a second — accepted. (R6) denial events are per replica, so N replicas
record up to N × 41 per window — accepted, bounded.

**Open points (defaults chosen; product owner may override):**
1. Platform-wide list, no organization-scoped lists (decision 10, §4) — default yes.
2. `/if/user/*` (Authentik's self-service UI, where users manage their own MFA devices) restricted to the allow list;
   MFA enrollment during login still works through the flow executor — default restricted. If end users must manage
   authenticators from home, `/if/user/*`, `/api/v3/core/users/me/`, `/api/v3/authenticators/*` and `/ws/client/`
   become public in a follow-up.
3. Every write needs a step-up; the typed confirmation applies only to self-lockout and switch-off (decisions 12,
   25) — default yes.
4. Denial aggregation: 10-minute window, 20 addresses with immediate events, bounded summary (decision 20) — default
   yes.
5. Proxies in front of Caddy are supported through HTTP headers only (decision 1); the PROXY protocol on Caddy's
   listener is not configured — default no (follow-up if a TCP load balancer without headers is needed).
6. No platform audit view in the portal; platform admins read `platform.*` events from the audit index or SIEM as
   today — default yes (follow-up candidate).
7. Architecture amendment for the main session: §4.1 hostname table — `admin.<domain>`: "restricted by the edge allow
   list and the application allow list (M7a)"; `auth.<domain>`: "internet for logins and device approvals;
   administrative paths restricted by the edge allow list"; a sentence under the table: "Proxies or a CDN in front
   of Caddy are declared with `PADDOCK_EDGE_TRUSTED_PROXIES` and `PADDOCK_EDGE_CLIENT_IP_HEADER`; the roles read the
   client address only from Caddy's `X-Paddock-Client-IP`." ADR 0021 (§9) placed as `docs/adr/0021-ip-allowlist.md`.
8. Trusted proxies are configured by environment only, not additionally as a platform setting in the database: the
   edge (Caddy) cannot read the database, the roles must agree with the edge, and two sources for one security fact
   invite drift — default environment only. If the product owner wants portal visibility, a read-only display of
   the effective edge configuration (exposed by the api from its environment) is a follow-up.
9. In production `PADDOCK_EDGE_CLIENT_IP_HEADER` names exactly one header; the development stack lists both so one
   stack covers both modes (decision 1) — default yes.

## 9. ADR 0021 — IP allow list for administrative surfaces (text for `docs/adr/0021-ip-allowlist.md`)
```markdown
# 0021 — IP allow list for the administrative surfaces and client address derivation
Status: Proposed

## Context
The product owner requires that the application is usable only from approved addresses, except for what devices
and their users need, and that Paddock can run behind further proxies or CDNs (for example Cloudflare) with a
configurable notion of trusted proxies and client-IP header. Architecture §4.1 already recommends an allow list or
VPN for `admin.`; `auth.` is one shared Authentik (ADR 0007) whose admin interface is platform-level. API tokens
(M6c) are long-lived credentials used from CI. A stolen session or token must be useless from outside, and a
spoofed header must never count anywhere: edge, api, gateway rate limits, logs.

## Options
- **Edge only (Caddy, static CIDRs per host and path).** + No application change, protects Authentik too.
  − Managed by operators on the host, not by platform admins; no audit; not visible in the portal.
- **Application only (list in PostgreSQL, enforced by the api).** + Managed in the portal, audited, lockout
  protection, multi-replica. − Cannot protect Authentik's admin interface, which is not a Paddock handler.
- **Both layers (chosen).** + Each layer covers what the other cannot; the edge list is the coarse perimeter, the
  application list the audited, admin-managed one. − Two places to configure; documented together.
- Client address: **roles parse the proxy chain themselves** (every role needs the trusted-proxy list and the
  header choice; two implementations of one rule) vs. **Caddy resolves once and forwards one canonical header**
  (chosen: `trusted_proxies` + `client_ip_headers` at the edge, `header_up X-Paddock-Client-IP {client_ip}` to the
  roles, roles trust only Caddy's address range). − The roles depend on Caddy for the client address; + one
  implementation, Caddy's matchers and logs agree with the roles, nothing a client sends survives the hop.
- Per-organization lists were rejected: the perimeter is shared (Authentik admin, platform pages). A trusted-proxy
  list in the database was rejected: the edge cannot read it, and one fact needs one source.

## Decision
Edge: Caddy `client_ip` guards from one shared snippet, `PADDOCK_ADMIN_ALLOWED_CIDRS` for `admin.` and the
administrative paths of `auth.`; an exhaustive public path list for logins and the device-code flow; the Paddock
roles reach Authentik's API from `PADDOCK_INTERNAL_CIDRS`. Client address: `PADDOCK_EDGE_TRUSTED_PROXIES` and
`PADDOCK_EDGE_CLIENT_IP_HEADER` (`none`, `X-Forwarded-For` right-to-left, `CF-Connecting-IP`), validated by Caddy's
entrypoint and by `prod-check` (no `/0`, header and proxies together or neither); Caddy forwards the resolved
address as `X-Paddock-Client-IP`, which the roles accept from `PADDOCK_TRUSTED_PROXY_CIDRS` only and use for the
allow list, rate limits, audit actors and logs. Application: table `ip_allowlist_entry` (platform scope), enforced
by a middleware in every api replica before sessions and tokens, cached in memory with a Valkey change counter and
a periodic reload. Lockout protection by a server-side consequence check with explicit confirmation plus step-up;
break-glass on the host (`paddock-server admin allowlist`) and an api environment bypass that `prod-check`
reports. Denials are audited aggregated per address and window.

## Consequences
+ A session or token from a foreign network is refused before it is even authenticated; the perimeter is audited
  and visible in the portal; devices and device logins are unaffected; a CDN or load balancer in front is a
  configuration, not a code change; a spoofed header is ignored in every layer by construction.
− CI runners and `paddockctl` users need stable egress addresses. − The operator keeps the CDN's address ranges
  current; a stale list fails closed. − Private-range peers of the host can reach Authentik's API (token required)
  unless `PADDOCK_INTERNAL_CIDRS` is narrowed.
```
