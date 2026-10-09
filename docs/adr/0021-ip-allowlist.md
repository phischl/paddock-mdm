# 0021 — IP allow list for the administrative surfaces and client address derivation
Status: Accepted (2026-10-09)

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
