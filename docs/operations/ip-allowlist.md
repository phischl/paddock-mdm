# IP allow list and client addresses

Paddock restricts its administrative surfaces to approved address ranges in two layers (ADR 0021, plan M7a). Devices,
their users' logins and the device-code approval on a phone are never restricted: they work from any network.

| Layer | Protects | Managed by | Configuration |
| --- | --- | --- | --- |
| **Edge** (Caddy) | `admin.<domain>` as a whole and the administrative paths of `auth.<domain>` (Authentik's admin interface `/if/admin/`, the self-service UI `/if/user/`, its API `/api/v3/` and websockets) | the operator on the host | `PADDOCK_ADMIN_ALLOWED_CIDRS`, `PADDOCK_INTERNAL_CIDRS` in `.env`; `docker compose up -d caddy` after a change |
| **Application** (api) | the portal and the admin API, for sessions **and** API tokens, before any session or token is read | platform administrators in the portal (*Platform* → *IP allow list*), every change with a step-up and an audit event | the table `ip_allowlist_entry`; off while it has no entries |

The edge list is the coarse, static perimeter; the application list is the audited one that administrators manage
themselves. A request must pass both.

## Public on `auth.<domain>`

Everything logins and the device-code flow need stays reachable from the internet; everything else on `auth.` is
restricted to `PADDOCK_ADMIN_ALLOWED_CIDRS`:

- `/application/o/*` — authorize, token, device authorization, userinfo, revoke, introspect, the per-application
  `.well-known/openid-configuration`, `jwks/`, `end-session/`
- `/device` and `/device/*` — the verification page users open on a phone
- `/if/flow/*` — the flow executor UI: every login, the device-code flow, MFA enrollment during login, the step-up
  and the recovery flow
- `/flows/*` — flow redirects
- `/api/v3/flows/executor/*`, `/api/v3/root/config/`, `/api/v3/core/brands/current/` — the three API calls the flow
  UI makes
- `/static/*`, `/media/*`, `/.well-known/*`, `/favicon.ico`

The rest of `/api/v3/*` is additionally allowed from `PADDOCK_INTERNAL_CIDRS` (default `private_ranges`), because the
Paddock roles reach Authentik's API through Caddy with their service token. Narrow it to the Compose network's subnet
(`docker network inspect paddock_cp`) when other machines share the host's private ranges.

## Client address: trusted proxies and the canonical header

Every allow list, the gateway's per-address rate limit, the audit actors and the access logs use the **same** client
address. Caddy resolves it once:

| Variable (service `caddy`) | Meaning | Default |
| --- | --- | --- |
| `PADDOCK_EDGE_TRUSTED_PROXIES` | the peers that may name the client through a header: CIDRs or single addresses, space-separated, optionally `private_ranges` | empty: Caddy is the first proxy |
| `PADDOCK_EDGE_CLIENT_IP_HEADER` | `none`, `X-Forwarded-For` (read right to left: a chain of trusted proxies that append resolves to the first untrusted address) or `CF-Connecting-IP` | `none` |

A header is read **only** from peers in the list; anybody else's `X-Forwarded-For`, `CF-Connecting-IP` or
`X-Paddock-Client-IP` is ignored and the peer's own address counts. A header without proxies, proxies without a
header, any `/0` range, an unknown header name or an unparsable range stop Caddy from starting (`caddy/entrypoint.sh`
prints the reason) and fail `./paddock check` (item `edge client address`).

Four configurations:

1. **Caddy is the first proxy** (default): leave both variables at their defaults.
2. **A load balancer that appends `X-Forwarded-For`:**
   ```sh
   PADDOCK_EDGE_TRUSTED_PROXIES=10.20.0.5 10.20.0.6
   PADDOCK_EDGE_CLIENT_IP_HEADER=X-Forwarded-For
   ```
3. **Cloudflare:** the published ranges from <https://www.cloudflare.com/ips/> (IPv4 and IPv6) and the header
   Cloudflare sets:
   ```sh
   PADDOCK_EDGE_TRUSTED_PROXIES=173.245.48.0/20 103.21.244.0/22 … 2400:cb00::/32 …
   PADDOCK_EDGE_CLIENT_IP_HEADER=CF-Connecting-IP
   ```
   The origin MUST be firewalled to those ranges, otherwise anybody can bypass the CDN. Refreshing the list is a
   recurring operator task: a new Cloudflare address that is not in the list counts as an untrusted peer, so requests
   through it are treated as coming from that address (fail closed, never spoofable) and allow-listed administrators
   behind it are denied until the list is updated.
4. **A LAN proxy (lab profile):** the proxy that terminates TLS in front of a lab host; its address only, never
   `private_ranges` (`./paddock check` refuses it on a lab host):
   ```sh
   PADDOCK_EDGE_TRUSTED_PROXIES=<proxy address>
   PADDOCK_EDGE_CLIENT_IP_HEADER=X-Forwarded-For
   ```
   Details and the same-host variant: `docs/operations/lab-install.md`.

Behind Caddy there is exactly one hop: Caddy replaces the header `X-Paddock-Client-IP` on every request to the
Paddock roles with the address it resolved, and the roles read that header only from peers in
`PADDOCK_TRUSTED_PROXY_CIDRS` (default: the private ranges, which is where the Compose network lives; the roles'
ports are never published in production). The roles never read `X-Forwarded-For`, `X-Real-IP` or
`CF-Connecting-IP`. `GET /api/v1/me` returns the resolved address as `client_ip`; the portal shows it on the allow
list page as *Your current address*.

## Managing the application list

- *Platform* → *IP allow list*: the own address, whether the list covers it, the entries (CIDR, label, who added it,
  when) and the dialogs. *Use my address* fills `<client_ip>/32` or `/128`. Ranges are `a.b.c.d/n` or
  `<ipv6>/n` with the host bits zero; a `/0` and IPv4-mapped IPv6 are refused.
- Every add, edit and remove needs a step-up authentication within the step-up window (`403 step_up_required`
  otherwise) and records `platform.ip_allowlist_changed`.
- A change that would remove the caller's own address while entries remain answers `409
  lockout_confirmation_required`; removing the last entry (which switches the feature off for everyone) answers
  `409 disable_confirmation_required`. The portal asks the administrator to type the entry's CIDR, then repeats the
  request with `?confirm=lockout` or `?confirm=disable`.
- Changes reach every api replica within 2 s (a change counter in Valkey; without Valkey within 60 s).
- Denied requests answer `403 ip_not_allowed` under `/api/` and a plain `403 Forbidden` elsewhere, without any hint
  of the list. They are audited as `platform.ip_allowlist_denied`, aggregated per address and 10-minute window: the
  first denial of an address at once (at most 20 addresses per window), the rest as one summary per address and one
  for every further address at the window's end — at most 41 events per window and replica however large a scan.
  The exact count is the metric `paddock_ip_allowlist_denied_total`. The summary of the further addresses remembers
  at most 10 000 of them; beyond that `distinct_ips` is a lower bound and `distinct_ips_capped` is `true`.
- Until an api replica has loaded the list (after a start, and for as long as PostgreSQL refuses the load) it
  refuses every request with `503 ip_allowlist_unavailable` under `/api/` and a plain `503 Service Unavailable`
  elsewhere, because an unloaded list is not an empty one (fail closed). `PADDOCK_IP_ALLOWLIST_BYPASS=true` lifts
  this together with the list.

## Egress addresses for `paddockctl` and CI

API-token requests are subject to the same list. A CI pipeline that runs `paddockctl` therefore needs a stable egress
address that is on the list: a self-hosted runner, a NAT gateway or a VPN. Hosted runners without a fixed address
cannot be allow-listed. `paddockctl` users work from inside an allowed range or through the VPN. While the list is
off (no entries), nothing changes for them.

## Break-glass: locked out

Symptoms: the portal answers *403 Forbidden* (or `ip_not_allowed`) from every address the administrators use, for
example after a provider change or a mistaken entry. Access is restored on the control-plane host:

1. See what is listed: `./paddock compose run --rm --no-deps paddock-worker admin allowlist show` (one line per entry: CIDR, label,
   who, when; or `ip allowlist: off (no entries)`).
2. Either add the current egress address — `./paddock compose run --rm --no-deps paddock-worker admin allowlist add --cidr
   203.0.113.7/32 --label "break-glass $(date -I)"` (audited as `platform.ip_allowlist_changed`, actor `system`,
   created by `paddock-server admin`) — or switch the list off: `./paddock compose run --rm --no-deps paddock-worker admin
   allowlist disable` (removes every entry, audited as `platform.ip_allowlist_disabled` with the removed ranges;
   `already off` when there is none). The api replicas follow within 2 s; when Valkey is unreachable the command
   says so and they follow within 60 s.
3. If the database itself is unreachable for the command, set `PADDOCK_IP_ALLOWLIST_BYPASS=true` in `.env` and
   `./paddock compose up -d paddock-api`: the api ignores the application list, logs it every 10 minutes, records one
   `platform.ip_allowlist_disabled` (method `env`) and exports `paddock_ip_allowlist_bypass = 1`; the alert
   `PaddockIPAllowlistBypassed` fires after 15 minutes and `./paddock check` fails (item `ip allow list bypass is
   off`) until the variable is removed again.
4. If the **edge** list is the problem: set `PADDOCK_ADMIN_ALLOWED_CIDRS=0.0.0.0/0 ::/0` in `.env` and
   `./paddock compose up -d caddy`, fix the ranges, set them again and recreate Caddy once more.

(Run the commands in the control plane's bundle directory, `docs/operations/install.md`.)

## Audit codes, metrics and alert

| Code | When |
| --- | --- |
| `platform.ip_allowlist_changed` | an entry was added, updated or removed (params `action`, `cidr`, `label`, `previous_cidr`, `previous_label`, `entries`, `consequence`); denied without step-up or for a non-platform principal; failure for an unconfirmed consequence, a duplicate or an invalid range |
| `platform.ip_allowlist_denied` | a request was refused by the application list (params `ip`, `count`, `window_seconds`, `first_at`, `last_at`, `aggregated`, `distinct_ips`, `distinct_ips_capped`); edge denials are not audited |
| `platform.ip_allowlist_disabled` | the list was switched off on the host (`method: cli`, `entries_removed`, `removed`) or the api started with the bypass (`method: env`) |

Metrics of the api: `paddock_ip_allowlist_entries`, `paddock_ip_allowlist_enabled`, `paddock_ip_allowlist_bypass`,
`paddock_ip_allowlist_denied_total`, `paddock_ip_allowlist_reload_errors_total`,
`paddock_ip_allowlist_last_reload_timestamp_seconds`. Alert: `PaddockIPAllowlistBypassed` (warning).

## Residual risks

- Peers in `PADDOCK_INTERNAL_CIDRS` (default: every private range) can reach Authentik's API with a valid token;
  narrow the variable to the Compose subnet on hosts that share private ranges with other machines.
- A shared NAT address on the list admits every host behind it.
- A stale CDN range list silently stops trusting a new CDN address, which then counts as the client: administrators
  behind it are denied until the list is refreshed (fail closed).
- The application list is enforced per api replica from a cached copy; a replica that cannot load it stays
  not-ready (`ip allow list not loaded`) and allows everything until its first successful load.
