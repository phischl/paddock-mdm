# Implementierungsplan: M8a — Lab installation profile (one host behind an external TLS proxy)

Status: Ready for implementation · 2026-10-13 · Author: architect
Basis: ADR 0029 (lab profile), ADR 0021 (trusted proxies, client address), ADR 0022 (operator bundle), ADR 0016
and plan M6a (production overlays, `prod-check`, backups), plan M7a (edge guards, entrypoint), plan M7b (bundle,
smoke test); maintainer request 2026-10-13 (one Ubuntu server, Nginx terminates TLS, LAN only, backups optional).

Binding language: **MUST** / **MUST NOT** / **SHOULD** / **MAY**.

## 1. Goal

An operator installs a released Paddock bundle on **one** amd64 Linux host of a private network behind an existing
TLS-terminating reverse proxy (`PADDOCK_HOST=lab`): control plane and audit domain in one Compose project, Caddy on
plain HTTP on one LAN-bound port, the proxy as the only trusted source of client addresses, the production checks
and images, no development shortcut, backups optional. A shipped Nginx configuration is pasted by the operator and
tested in CI.

## 2. Context

- Compose file sets live in `deploy/compose/scripts/lib.sh` (`PROD_FILES_controlplane`, `PROD_FILES_audit`),
  read literally by `deploy/bundle/paddock`, `deploy/bundle/build.sh`, `deploy/bundle/bundle_test.sh` and
  `server/internal/prodcheck/compose_test.go`.
- `compose.prod.yaml` hardens the control plane (TLS on OpenBao and RabbitMQ with the internal CA of
  `scripts/gen-prod-secrets.sh`, production URLs, `secrets: !override` lists, Caddy on 80/443 with ACME,
  interconnect ports 5671 and 8200). `compose.audit.prod.yaml` is the audit host's overlay (not used by the lab).
- `caddy/Caddyfile.prod` is rendered by `caddy/entrypoint.sh`, which validates `PADDOCK_EDGE_TRUSTED_PROXIES` and
  `PADDOCK_EDGE_CLIENT_IP_HEADER` and injects the `servers` block as `{$CADDY_SERVERS_BLOCK}`; `caddy/guards.caddy`
  holds the `admin_site` and `authentik_site` snippets. Caddy's `reverse_proxy` passes incoming `X-Forwarded-*`
  headers through only from `trusted_proxies` and resets them otherwise.
- `compose.yaml` gives the `caddy` service the network aliases `admin.`, `auth.`, `bundles.`, `device.` under
  `PADDOCK_DOMAIN` on network `cp`; in production the roles reach Authentik through them (Caddy serves TLS on 443
  inside the container).
- `server/internal/prodcheck/prodcheck.go` implements `./paddock check`; `server/cmd/paddock-server/prodcheck.go`
  is its CLI (`--host controlplane|audit`, `--compose-files`, `--online`, `--dev-release-key`).
- `docker compose config --format json` renders `extra_hosts` as a list of `"<host>=<ip>"` strings and service
  networks as `{"cp": {"aliases": ["…"]}}` (checked with Compose v5.6.0 on 2026-10-13).
- The worker's certificate probe (`server/internal/worker/opsprobe.go`, `DialCertExpiry`) dials
  `PADDOCK_TLS_PROBE_ADDR` with every name of `PADDOCK_TLS_PROBE_HOSTS` as SNI, verified against the system roots.
- `deploy/bundle/ci/smoke.sh` installs a bundle as two projects on one runner with the CI overlay
  `deploy/bundle/ci/compose.ci.yaml` (added through `PADDOCK_COMPOSE_EXTRA`, never shipped).

## 3. Binding decisions

### 3.1 Profile selection and file set

1. `PADDOCK_HOST` gains the value **`lab`**. `lib.sh` MUST define
   `PROD_FILES_lab="compose.yaml compose.prod.yaml compose.audit.yaml compose.lab.yaml"` and
   `LAB_BACKUP_FILES="compose.backup.yaml"`. `compose_files` MUST append `LAB_BACKUP_FILES` after
   `PROD_FILES_lab` when `env_value PADDOCK_LAB_BACKUP` is `yes`, and MUST print the usage error
   `set PADDOCK_HOST to controlplane, audit or lab in .env (is '…')` for any other value. The order is fixed:
   `compose.backup.yaml` comes last so that its worker secrets add to the `!override` list of `compose.prod.yaml`.
2. `deploy/compose/lab.env.example` is the settings template of the lab (shipped by the bundle as
   `.env.lab.example`). It MUST contain exactly these keys, with these defaults and the comment lines of §6.1:
   `PADDOCK_ENV=production`, `PADDOCK_LOG_LEVEL=info`, `PADDOCK_HOST=lab`, `PADDOCK_DOMAIN=paddock.example.org`,
   `PADDOCK_PUBLIC_ADMIN_URL=https://admin.paddock.example.org`,
   `PADDOCK_PUBLIC_DEVICE_URL=https://device.paddock.example.org`, `PADDOCK_INTERCONNECT_ADDR=192.0.2.10`,
   `PADDOCK_LAB_HTTP_PORT=8080`, `PADDOCK_LAB_PROXY_ADDR=192.0.2.5`, `PADDOCK_EDGE_TRUSTED_PROXIES=192.0.2.5`,
   `PADDOCK_EDGE_CLIENT_IP_HEADER=X-Forwarded-For`, `PADDOCK_ADMIN_ALLOWED_CIDRS=192.0.2.0/24`,
   `PADDOCK_INTERNAL_CIDRS=192.0.2.10/32`, `PADDOCK_LAB_BACKUP=no`,
   `PADDOCK_BACKUP_S3_ENDPOINT=https://backup-s3.example.org`, `PADDOCK_BACKUP_S3_BUCKET=paddock-backup`,
   `PADDOCK_BACKUP_S3_REGION=us-east-1`, `PADDOCK_AUDIT_RETENTION_DAYS=400`, `PADDOCK_REVOCATION_ENABLED=false`,
   `PADDOCK_REVOCATION_ACCEPTED=no`; commented: `# PADDOCK_PROJECT=paddock`, `# PADDOCK_BACKUP_S3_CA_FILE=`,
   `# PADDOCK_TRUSTED_PROXY_CIDRS=…` (the production default), `# PADDOCK_IP_ALLOWLIST_BYPASS=false`.
   Variable meanings in the lab:
   - `PADDOCK_INTERCONNECT_ADDR`: this host's address on the LAN; Caddy's HTTP port binds to it and nothing else is
     published. The name is kept because `compose.prod.yaml` and `prod-check` already use it for "this host's
     address on the private network".
   - `PADDOCK_LAB_PROXY_ADDR`: the IP address of the TLS proxy as the Paddock host reaches it. The roles resolve the
     five public names to it (`extra_hosts`) and the worker's certificate probe dials `<addr>:443`.
   - `PADDOCK_EDGE_TRUSTED_PROXIES`: the proxy's address as Caddy sees it (normally equal to
     `PADDOCK_LAB_PROXY_ADDR`; the same-host variant of §3.6 differs).
3. `compose.prod.yaml` MUST change exactly one line: `PADDOCK_ACME_EMAIL: ${PADDOCK_ACME_EMAIL:?set PADDOCK_ACME_EMAIL in .env}`
   becomes `PADDOCK_ACME_EMAIL: ${PADDOCK_ACME_EMAIL:-}`. Justification: the lab has no ACME; production stays
   protected by `prod-check` (item "Caddy: …", `PADDOCK_ACME_EMAIL is not set`) and by `caddy validate` in the
   entrypoint (`email` without an argument is a Caddyfile error). No other production file changes.

### 3.2 `compose.lab.yaml` (new, `deploy/compose/compose.lab.yaml`)

4. The overlay MUST contain exactly the following (comments are free; values are not):

   ```yaml
   x-paddock-prod:
     lab_proxy_addr: ${PADDOCK_LAB_PROXY_ADDR:?set PADDOCK_LAB_PROXY_ADDR in .env}

   x-lab-hosts: &lab-hosts
     - "admin.${PADDOCK_DOMAIN}:${PADDOCK_LAB_PROXY_ADDR}"
     - "auth.${PADDOCK_DOMAIN}:${PADDOCK_LAB_PROXY_ADDR}"
     - "device.${PADDOCK_DOMAIN}:${PADDOCK_LAB_PROXY_ADDR}"
     - "bundles.${PADDOCK_DOMAIN}:${PADDOCK_LAB_PROXY_ADDR}"
     - "fleet.${PADDOCK_DOMAIN}:${PADDOCK_LAB_PROXY_ADDR}"

   services:
     caddy:
       ports: !override
         - "${PADDOCK_INTERCONNECT_ADDR}:${PADDOCK_LAB_HTTP_PORT:-8080}:80"
       environment:
         PADDOCK_ADMIN_ALLOWED_CIDRS: ${PADDOCK_ADMIN_ALLOWED_CIDRS:?set PADDOCK_ADMIN_ALLOWED_CIDRS in .env}
         PADDOCK_EDGE_TRUSTED_PROXIES: ${PADDOCK_EDGE_TRUSTED_PROXIES:?set PADDOCK_EDGE_TRUSTED_PROXIES in .env}
         PADDOCK_EDGE_CLIENT_IP_HEADER: ${PADDOCK_EDGE_CLIENT_IP_HEADER:-X-Forwarded-For}
       volumes:
         - ./caddy/Caddyfile.lab:/etc/caddy/Caddyfile:ro
       networks: !override [cp]

     openbao:
       ports: !override []

     rabbitmq:
       ports: !override []

     paddock-api:
       extra_hosts: *lab-hosts

     paddock-escrow-reader:
       extra_hosts: *lab-hosts

     paddock-revocation-issuer:
       extra_hosts: *lab-hosts

     paddock-worker:
       extra_hosts: *lab-hosts
       environment:
         PADDOCK_TLS_PROBE_ADDR: ${PADDOCK_LAB_PROXY_ADDR}:443

     paddock-audit-migrate:
       environment:
         PADDOCK_ENV: production

     paddock-audit-writer:
       environment:
         PADDOCK_ENV: production
         PADDOCK_OPENBAO_ADDR: https://openbao:8200
         BAO_CACERT: /run/secrets/internal_ca_bundle
       secrets:
         - internal_ca_bundle

     prometheus:
       volumes:
         - ./prometheus/scrape/audit.yml:/etc/prometheus/scrape/audit.yml:ro
   ```

   Notes that bind the implementer: the audit writer keeps `amqp://rabbitmq:5672/paddock` and
   `http://audit-rustfs:9000` of `compose.audit.yaml` (local links on one host, as the control plane's roles use
   RabbitMQ in production); `audit-postgres` runs without TLS and without a published port (its only client is the
   api on network `audit-index`); the `rabbitmq` and `openbao` services keep the TLS listeners of `compose.prod.yaml`
   (the secret files exist because `./paddock secrets lab` writes them); `caddy-ca-export` stays the no-op of
   `compose.prod.yaml`. The `secrets` key of `paddock-audit-writer` is a plain list (no `!override`), which Compose
   merges with the base list.
5. `deploy/compose/caddy/Caddyfile.lab` (new) MUST be:

   ```
   {
   	# Lab (compose.lab.yaml, ADR 0029): the operator's reverse proxy terminates TLS and forwards plain HTTP to
   	# port 80 of this container, which compose.lab.yaml publishes on PADDOCK_INTERCONNECT_ADDR only. The sites
   	# are explicit http:// addresses: no certificates, no redirects.
   	auto_https off
   	http_port 80
   	admin 127.0.0.1:2019
   	# Trusted proxies and the client address header, rendered by /paddock/entrypoint.sh from
   	# PADDOCK_EDGE_TRUSTED_PROXIES and PADDOCK_EDGE_CLIENT_IP_HEADER (plan M7a decision 2).
   	{$CADDY_SERVERS_BLOCK}
   }

   import /etc/caddy/guards.caddy

   http://admin.{$PADDOCK_DOMAIN} {
   	import admin_site
   }

   http://auth.{$PADDOCK_DOMAIN} {
   	import authentik_site
   }

   http://device.{$PADDOCK_DOMAIN} {
   	reverse_proxy paddock-gateway:8081 {
   		header_up X-Paddock-Client-IP {client_ip}
   	}
   }
   ```

   followed by the `bundles.` and `fleet.` sites of `Caddyfile.prod` verbatim, each with the site address prefixed
   by `http://` (`http://bundles.{$PADDOCK_DOMAIN} {`, `http://fleet.{$PADDOCK_DOMAIN} {`) and otherwise
   byte-identical bodies. `TestCaddyfilesEdge` (`server/internal/prodcheck/compose_test.go`) MUST include
   `Caddyfile.lab` in both loops; the expected proxy count becomes 4.

### 3.3 Secrets

6. `scripts/gen-prod-secrets.sh` MUST accept `lab` (usage line
   `gen-prod-secrets.sh [controlplane|audit|lab]`). For `lab` it MUST, in this order: (a) run the audit part
   without the `audit-postgres` certificate and without the two "copy … to the … host" messages; (b) run the
   control-plane part, in which the audit reader URL is
   `postgres://paddock_audit_reader:<password>@audit-postgres:5432/paddock_audit?sslmode=disable` (the password
   from (a); the `PADDOCK_AUDIT_ADDR` lookup and the "copy it from the audit host" message do not run), the message
   "copy .secrets/rabbitmq_audit_writer_password to the audit host" does not print, and the `paddock-audit-writer`
   AppRole placeholders are written once; (c) write `internal-ca/bundle.crt` from this host's CA only and print no
   `peer-ca.crt` message. The `openbao` and `rabbitmq` certificates are issued as for `controlplane`. When `.env` is
   missing, the script MUST print `created .env from prod.env.example: … (for a lab host copy .env.lab.example to
   .env instead)` and exit 1 as today. Refactor the two existing branches into functions
   `controlplane_secrets` and `audit_secrets` with the two differences as parameters or `if [[ $HOST == lab ]]`
   guards; the implementer chooses.
7. `scripts/secrets-argv_test.sh` (exists) MUST gain a case for `lab`: after one run, `.secrets/` holds
   `db_paddock_audit_reader_url` with host `audit-postgres` and `sslmode=disable`, `tls/openbao.crt`,
   `tls/rabbitmq.crt`, no `tls/audit-postgres.crt`, and no secret value appears in the output.

### 3.4 `./paddock` and the bundle

8. `deploy/bundle/paddock` MUST accept `PADDOCK_HOST=lab` (error text of decision 1 for other values). Changes:
   `require_host` gains a second allowed host: `require_host controlplane lab "bootstrap openbao"` etc.; every
   `bootstrap` subcommand, `agent-release`, `check --online` and the amd64 refusal of `up` apply to `lab` as to the
   host they belong to today. `check` passes `--host lab`. `check` and `up` MUST print, as their first output line,
   `lab profile (PADDOCK_HOST=lab): not for production — see docs/operations/lab-install.md` to stderr when the host
   is `lab`. `bootstrap audit-bucket` on `lab` uses network `${PADDOCK_PROJECT}_audit-store` as on the audit host
   (unchanged script).
9. `deploy/bundle/build.sh` MUST ship, in addition: `compose.lab.yaml`, `caddy/Caddyfile.lab`,
   `nginx/paddock.conf.example` (decision 17) and `lab.env.example` as `.env.lab.example`; its validation loop MUST
   render `controlplane`, `audit` and `lab` (for `lab` with `--env-file .env.lab.example` and the environment
   `PADDOCK_LAB_BACKUP=yes` so that the backup file renders too). `deploy/bundle/bundle_test.sh` MUST render and
   diff the `lab` configuration (settings file `lab.env.example` in the repository, `.env.lab.example` in the bundle)
   and run `check_mounts` for all three hosts. `deploy/bundle/README.md` MUST mention `PADDOCK_HOST=lab` with
   `.env.lab.example` in the "Commands" paragraph and the table rows that name hosts.
10. `server/internal/prodcheck/compose_test.go`: `prodFiles(t, "lab")` plus the cases "lab" and "lab with backups"
    (`PROD_FILES_lab` + `LAB_BACKUP_FILES`, env file `lab.env.example`) in `TestComposeConfigsMountEverySecretTheyName`;
    a new `TestLabEdge` that renders the lab configuration and asserts: Caddy publishes exactly one port with
    `host_ip` `192.0.2.10` and target 80, `openbao`, `rabbitmq`, `audit-postgres` publish nothing, `caddy` has no
    aliases, and every item of `prodcheck.Run` with `Options{Host: prodcheck.HostLab}` whose name is in
    {`edge client address`, `role trusted proxies`, `Caddy: plain HTTP behind the TLS proxy`,
    `lab: edge admin allow list`, `lab: caddy has no hostname aliases`, `lab: roles resolve the public names to the
    proxy`, `only Caddy's HTTP port published, on the bind address`} passes.

### 3.5 `prod-check` for the lab (`server/internal/prodcheck`)

11. `const HostLab = "lab"`; `Prod` gains `LabProxyAddr string \`json:"lab_proxy_addr"\``; `Service` gains
    `ExtraHosts []string \`json:"extra_hosts"\`` and `Networks map[string]ServiceNetwork \`json:"networks"\`` with
    `type ServiceNetwork struct { Aliases []string \`json:"aliases"\` }`. The CLI accepts `--host lab`
    (usage string `controlplane, audit or lab`) and allows `--online` with `lab` (the writer service is in the lab
    configuration).
12. `Run` MUST produce, for `o.Host == HostLab`, these items instead of or in addition to the production ones:
    - `only Caddy's HTTP port published, on the bind address` (replaces `only 80/443 published, …`): FAIL when
      `Prod.InterconnectAddr` is empty or not a specific IP (reuse the existing message), when the `caddy` service
      publishes anything but exactly one port with `HostIP == InterconnectAddr` and `Target == 80`
      (`caddy: port %s published on %q, not on the bind address` / `caddy: publishes %d ports, want exactly one`),
      and when any other service publishes a port (`%s: port %s published; the lab publishes nothing but Caddy`).
    - `Caddy: plain HTTP behind the TLS proxy` (replaces `Caddy: public ACME certificates, …`): the mount checks of
      `checkCaddy` unchanged (Caddyfile, `guards.caddy` and `entrypoint.sh` next to it), `caddyfileFindings`
      unchanged (`tls internal`, `trusted_proxies`, `client_ip_headers` forbidden), **no** `PADDOCK_ACME_EMAIL`
      requirement, plus: FAIL unless the Caddyfile has a line whose fields are exactly `auto_https off`, and FAIL for
      every site address that does not start with `http://` (a site address is a line that ends with ` {`, is not
      indented, is not `{`, and does not start with `(` or `import`): `Caddyfile site %q is not an http:// site`.
    - `edge client address` (same item name, stricter): the existing findings, plus FAIL when the header is not
      `X-Forwarded-For` (`PADDOCK_EDGE_CLIENT_IP_HEADER must be X-Forwarded-For behind the lab proxy`), when the
      proxy list is empty, and when it contains `private_ranges` (`PADDOCK_EDGE_TRUSTED_PROXIES: private_ranges
      trusts every LAN peer; name the proxy's address`).
    - `lab: edge admin allow list`: FAIL when `PADDOCK_ADMIN_ALLOWED_CIDRS` of `caddy` is empty or contains a range
      with prefix length 0 (`rangeProblem(p, true)` plus the empty case; `private_ranges` is accepted).
    - `lab: caddy has no hostname aliases`: FAIL for every alias of `caddy` on any network
      (`caddy: alias %s on network %s would short-circuit the proxy`).
    - `lab: roles resolve the public names to the proxy`: for each of `paddock-api`, `paddock-worker`,
      `paddock-escrow-reader`, `paddock-revocation-issuer`, FAIL unless `ExtraHosts` contains
      `<name>=<Prod.LabProxyAddr>` for every name in {`admin`, `auth`, `device`, `bundles`, `fleet`} under the
      domain taken from the api's `PADDOCK_PUBLIC_ADMIN_URL` host without the `admin.` prefix; FAIL when
      `Prod.LabProxyAddr` is empty or not a specific IP. Also FAIL when `paddock-worker`'s `PADDOCK_TLS_PROBE_ADDR`
      is not `<Prod.LabProxyAddr>:443`.
    - Every other item runs unchanged: dev overlay, `PADDOCK_ENV`, dev variables, revocation, secret files, mounted
      references, TLS links (local service names pass; `PADDOCK_OPENBAO_ADDR` must be https everywhere), role trusted
      proxies, allow-list bypass, release keys, and with `--online` the Object Lock item (minimum 400 days unchanged).
13. `Write` is unchanged. Unit tests in `prodcheck_test.go`: a lab fixture (derived from `newFixture` with
    `Host: HostLab`, `LabProxyAddr: "192.0.2.5"`, one Caddy port on `interconnect`:80, extra hosts, no aliases, a
    Caddyfile with `auto_https off` and `http://` sites) that passes every item, and one failing case per new
    finding: a second published port; Caddy on `0.0.0.0`; an `https://` site; missing `auto_https off`; header
    `CF-Connecting-IP`; `private_ranges`; empty proxies; a `/0` admin range; an alias; a missing extra host; a wrong
    probe address; an unspecific `lab_proxy_addr`. An ACME e-mail that is empty MUST pass in the lab fixture.

### 3.6 Same-host proxy variant (documentation only)

14. When the proxy runs on the Paddock host itself: `PADDOCK_INTERCONNECT_ADDR=127.0.0.1` (Caddy binds to loopback;
    the proxy's upstream is `127.0.0.1:8080`), `PADDOCK_LAB_PROXY_ADDR` is the host's LAN address (the roles reach the
    proxy there), and `PADDOCK_EDGE_TRUSTED_PROXIES` is the gateway address of network `paddock_cp`, which the proxy's
    connections carry after Docker's NAT: `docker network inspect paddock_cp -f '{{(index .IPAM.Config 0).Gateway}}'`
    after `./paddock up --infra`. The lab guide documents this as a variant; the CI smoke test (decision 18) runs it.

### 3.7 Nginx reference configuration

15. `deploy/compose/nginx/paddock.conf.example` (new; shipped as `nginx/paddock.conf.example`) MUST be exactly:

    ```nginx
    # Paddock lab profile (docs/operations/lab-install.md): TLS termination for the five Paddock names in front of
    # Caddy's plain-HTTP port. Replace paddock.example.org (the domain), 192.0.2.10:8080 (PADDOCK_INTERCONNECT_ADDR
    # and PADDOCK_LAB_HTTP_PORT of the Paddock host) and the certificate paths. The certificate must cover all five
    # names (a wildcard *.paddock.example.org or five SANs).

    map $http_upgrade $connection_upgrade {
        default upgrade;
        ""      "";
    }

    upstream paddock_lab {
        server 192.0.2.10:8080;
        keepalive 32;
    }

    server {
        listen 80;
        listen [::]:80;
        server_name admin.paddock.example.org auth.paddock.example.org device.paddock.example.org
                    bundles.paddock.example.org fleet.paddock.example.org;
        return 301 https://$host$request_uri;
    }

    server {
        listen 443 ssl;
        listen [::]:443 ssl;
        http2 on;
        server_name admin.paddock.example.org auth.paddock.example.org device.paddock.example.org
                    bundles.paddock.example.org fleet.paddock.example.org;

        ssl_certificate     /etc/letsencrypt/live/paddock.example.org/fullchain.pem;
        ssl_certificate_key /etc/letsencrypt/live/paddock.example.org/privkey.pem;
        ssl_protocols TLSv1.2 TLSv1.3;

        # Agent artifacts are up to 128 MiB (uploads through the admin API); escrowed LUKS headers up to 16 MiB.
        client_max_body_size 160m;
        client_body_timeout 300s;
        proxy_connect_timeout 10s;
        proxy_send_timeout 300s;
        proxy_read_timeout 300s;

        location / {
            # No URI part after the upstream: the request URI, including presigned S3 query strings, is passed as
            # received.
            proxy_pass http://paddock_lab;
            proxy_http_version 1.1;
            proxy_set_header Host $host;
            # The client's address only; a client-supplied X-Forwarded-For never reaches Paddock.
            proxy_set_header X-Forwarded-For $remote_addr;
            proxy_set_header X-Forwarded-Proto https;
            proxy_set_header X-Forwarded-Host $host;
            # Authentik's administrative UI uses a websocket; every other path keeps the upstream keepalive.
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection $connection_upgrade;
        }
    }
    ```

    Rationale the lab guide repeats: `$remote_addr` instead of `$proxy_add_x_forwarded_for` (Caddy reads the header
    right to left and would stop at the first untrusted address anyway, but a single address leaves nothing to
    interpret); `Host $host` because the SigV4 signature of presigned URLs covers the `Host` header; no
    `add_header Strict-Transport-Security` (the api sends it; a second header is undefined); no `proxy_pass` URI
    (Nginx would re-encode the path). Nginx MUST NOT be reachable from the internet with this configuration.
16. `docs/operations/lab-install.md` (new) MUST contain the file verbatim in a fenced block and the variants:
    proxy on another LAN host (default) and on the same host (decision 14).

### 3.8 CI smoke test of the lab bundle

17. `deploy/compose/versions.env` gains, below `# Build and tooling images`, `NGINX_IMAGE=nginx:1.28.<patch>@sha256:<digest>`
    with the comment `# Lab smoke test only (plan M8a decision 17); never shipped, never pulled on a host`. The
    implementer resolves the newest 1.28 patch and its index digest with `docker buildx imagetools inspect nginx:1.28`
    on the day of implementation. Approved by this plan (ADR 0029).
18. `deploy/bundle/ci/smoke-lab.sh <tarball> [--work <dir>]` (new) MUST: extract and verify the bundle into one
    directory; copy `.env.lab.example` to `.env` and set `PADDOCK_PROJECT=paddock-lab`, `PADDOCK_DOMAIN=paddock.localhost`,
    the two public URLs, `PADDOCK_INTERCONNECT_ADDR=127.0.0.1`, `PADDOCK_LAB_HTTP_PORT=8080`,
    `PADDOCK_LAB_PROXY_ADDR=<primary address of the runner>`, `PADDOCK_EDGE_TRUSTED_PROXIES=172.30.0.1`,
    `PADDOCK_ADMIN_ALLOWED_CIDRS=172.30.0.0/24 127.0.0.0/8 <primary address>/32`, `PADDOCK_INTERNAL_CIDRS=172.30.0.0/24 <primary address>/32`,
    `PADDOCK_LAB_BACKUP=no`; generate a CA and a certificate for the five names with `openssl` into `<work>/tls/`
    (`ca.crt`, `fullchain.pem`, `privkey.pem`) before anything starts; add the CI overlay
    `deploy/bundle/ci/compose.ci-lab.yaml` (new, through `PADDOCK_COMPOSE_EXTRA`, environment
    `PADDOCK_CI_LAB_TLS=<work>/tls`) that (a) pins network `cp` to subnet `172.30.0.0/24` (gateway `172.30.0.1`) and
    (b) for `paddock-api`, `paddock-worker`, `paddock-escrow-reader` and `paddock-revocation-issuer` bind-mounts
    `${PADDOCK_CI_LAB_TLS}/ca.crt` read-only at `/ci/ca.crt` and sets `SSL_CERT_FILE: /ci/ca.crt`, because those
    roles reach Authentik and the step-up issuer through Nginx and must trust the throwaway CA (a real lab trusts the
    system store); run `./paddock secrets`, write throwaway release keys and the empty `caddy-root.crt` as `smoke.sh`
    does; `up --infra`, OpenBao init and unseal, `bootstrap openbao`, `bootstrap buckets`, `bootstrap audit-bucket`,
    `bootstrap fleet`; `./paddock check` and `./paddock check --online` (both must pass and print the lab warning
    line; `check` renders without the overlay as today); start Nginx (below) **before** `./paddock up`, because the
    roles' readiness needs OIDC discovery through it; `./paddock up`;
    render `nginx/paddock.conf.example` of the bundle with `sed` (`paddock.example.org` → `paddock.localhost`,
    `192.0.2.10:8080` → `127.0.0.1:8080`, the two certificate paths → `/tls/fullchain.pem`, `/tls/privkey.pem`);
    start `docker run -d --name paddock-lab-nginx --network host -v <conf>:/etc/nginx/conf.d/default.conf:ro -v <work>/tls:/tls:ro $NGINX_IMAGE`;
    then probe through Nginx on `127.0.0.1:443` with `--resolve` and `--cacert`:
    `GET https://admin.paddock.localhost/` → 200; `GET https://auth.paddock.localhost/application/o/paddock-portal/.well-known/openid-configuration`
    → 200 and the body's `issuer` starts with `https://auth.paddock.localhost/`; `POST https://device.paddock.localhost/v1/checkin`
    → 4xx; `GET https://bundles.paddock.localhost/` → 403; `GET https://fleet.paddock.localhost/` → 404;
    `GET https://admin.paddock.localhost/api/v1/me` with header `X-Forwarded-For: 203.0.113.9` → 401 or 403 (never
    a 5xx; the header from an untrusted client is dropped by Nginx); a `PUT` of 20 MiB of zeros to
    `https://bundles.paddock.localhost/paddock-escrow/org/x` → 403 (the edge passes it to RustFS, which rejects the
    unsigned request: proves the body size limit lets 16 MiB headers through); directly on Caddy's port
    (`http://127.0.0.1:8080`, header `Host: admin.paddock.localhost`): `GET /` → 200 (127.0.0.1 is allow-listed),
    and `GET /` with `X-Forwarded-For: 203.0.113.9` → 200 as well (127.0.0.1 is not a trusted proxy, so the header
    is ignored and the peer stays the client; a 403 here would mean the header was honoured); after `sleep 90`,
    `./paddock logs paddock-worker` does not match `TLS probe failed` (the probe reached Nginx on 443 with the
    throwaway CA, which the overlay's `SSL_CERT_FILE` makes the worker trust); idempotence of
    a second `./paddock up` as in `smoke.sh`; logs to `<work>/logs/`; `docker rm -f paddock-lab-nginx` and
    `./paddock down --volumes` in the trap.
19. `.github/workflows/ci.yml`: the edge job runs `deploy/bundle/ci/smoke-lab.sh` after `smoke.sh` on the same
    bundle, with its own `upload-artifact` step `edge-smoke-lab-logs`. `Makefile`: target `bundle-smoke-lab`
    (`deploy/bundle/ci/smoke-lab.sh dist/bundle/paddock-deploy-0.0.0-local.tar.gz`) next to the existing bundle
    targets; `make test` is unchanged apart from `bundle-test` and `secrets-argv_test.sh` growing.

### 3.9 Documentation

20. `docs/operations/lab-install.md` (new, English) with the sections: 1 What the lab profile is and is not (the
    consequences of ADR 0029 verbatim: audit separation, TLS, exposure; "not for production"); 2 Host requirements
    (§7 of this plan); 3 DNS and certificate (five names → proxy address from devices and from the Paddock host;
    DNS-01 for a non-public name; wildcard or five SANs); 4 The proxy (decision 15 verbatim, both variants);
    5 Install (download and verify as `install.md` §3; `cp .env.lab.example .env`; the variables of decision 2 with
    the operator's values; `./paddock secrets`; `./paddock pull`; `./paddock up --infra`; OpenBao init with
    `./paddock bao operator init -key-shares=5 -key-threshold=3` and unseal; `bootstrap openbao`, `buckets`,
    `audit-bucket`, `fleet`; release keys: generate the installation's own minisign key pair offline
    (`docs/operations/agent-releases.md`), copy the public keys to `.secrets/release-production/`; `./paddock check`,
    `./paddock check --online`, `./paddock up`); 6 First administrator, organization, device (pointer to
    `install.md` §9–10); 7 Backups (`PADDOCK_LAB_BACKUP=yes`, the S3 endpoint and credentials of
    `docs/operations/restore.md`; without them there is no backup and `./paddock down --volumes` deletes everything,
    the WORM bucket included); 8 What `./paddock check` enforces in the lab (decision 12 as a list, and what it
    relaxes); 9 Upgrade (pointer to `upgrade.md`; `migrate-from` works unchanged); 10 Troubleshooting (Caddy
    refuses to start: `./paddock logs caddy` names the edge variable; 403 on `admin.`: the client address Caddy
    resolved is in Caddy's access log; logins fail while the proxy is down).
21. `docs/operations/install.md` gets one paragraph after the host table: "A single-host lab behind your own TLS
    proxy is a separate profile: `docs/operations/lab-install.md` (not for production)". `README.md`'s table of
    guides gains the row. `docs/operations/ip-allowlist.md` gets a fourth configuration "4. **A LAN proxy (lab
    profile):** `PADDOCK_EDGE_TRUSTED_PROXIES=<proxy address>`, `PADDOCK_EDGE_CLIENT_IP_HEADER=X-Forwarded-For`;
    `docs/operations/lab-install.md`". `docs/operations/monitoring.md`: one sentence that in the lab
    `PaddockCertificateExpiry` watches the proxy's certificate. `CHANGELOG.md` `[Unreleased]` → `### Added`: the lab
    profile, `PADDOCK_HOST=lab`, the Nginx example, the `./paddock` changes; `### Changed`: `PADDOCK_ACME_EMAIL`
    no longer refuses to render when unset (prod-check and Caddy still refuse to start without it).

## 4. Non-goals

- No change to the two-host production topology, its file sets, `compose.audit.prod.yaml`, the interconnect or
  the CI smoke of the two-host bundle beyond adding the lab run after it.
- No TLS inside Caddy in the lab, no internal CA export, no `tls internal` anywhere outside the development stack.
- No Kubernetes, no HA, no second proxy product (Traefik, HAProxy, Caddy-as-proxy) — the reference configuration is
  Nginx only; other proxies are the operator's translation.
- No relaxation of: the audit bucket's Object Lock and its 400-day minimum, the production release keys, the sealed
  OpenBao, the revocation acceptance, the development-variable refusals, the `/0` refusals, `PADDOCK_ENV=production`.
- No change to the agent, the device protocol, Fleet's configuration or the portal.

## 5. Affected files

| Path | Action | Purpose |
| --- | --- | --- |
| `deploy/compose/compose.lab.yaml` | new | lab overlay (decision 4) |
| `deploy/compose/caddy/Caddyfile.lab` | new | plain-HTTP sites (decision 5) |
| `deploy/compose/lab.env.example` | new | lab settings template (decision 2) |
| `deploy/compose/nginx/paddock.conf.example` | new | Nginx reference configuration (decision 15) |
| `deploy/compose/compose.prod.yaml` | change | `PADDOCK_ACME_EMAIL` default-empty (decision 3) |
| `deploy/compose/scripts/lib.sh` | change | `PROD_FILES_lab`, `LAB_BACKUP_FILES`, `compose_files` (decision 1) |
| `deploy/compose/scripts/gen-prod-secrets.sh` | change | `lab` mode (decision 6) |
| `deploy/compose/scripts/secrets-argv_test.sh` | change | lab case (decision 7) |
| `deploy/compose/versions.env` | change | `NGINX_IMAGE` tooling image (decision 17) |
| `deploy/bundle/paddock` | change | host `lab`, warning line (decision 8) |
| `deploy/bundle/build.sh`, `deploy/bundle/bundle_test.sh`, `deploy/bundle/README.md` | change | ship and test the lab files (decision 9) |
| `deploy/bundle/ci/smoke-lab.sh`, `deploy/bundle/ci/compose.ci-lab.yaml` | new | lab smoke test (decision 18) |
| `.github/workflows/ci.yml`, `Makefile` | change | run the lab smoke (decision 19) |
| `server/internal/prodcheck/prodcheck.go`, `prodcheck_test.go`, `compose_test.go` | change | lab host and items (decisions 10–13) |
| `server/cmd/paddock-server/prodcheck.go`, `main.go` | change | `--host lab`, usage (decision 11) |
| `docs/operations/lab-install.md` | new | the lab guide (decision 20) |
| `docs/operations/install.md`, `ip-allowlist.md`, `monitoring.md`, `README.md`, `CHANGELOG.md` | change | pointers and entries (decision 21) |

Not to be touched: `compose.audit.prod.yaml`, `caddy/Caddyfile`, `caddy/Caddyfile.prod`, `caddy/guards.caddy`,
`caddy/entrypoint.sh`, `compose.dev.yaml`, `compose.backup*.yaml`, `agent/`, `pkg/`, the portal, `docs/architecture.md`,
every ADR but 0029, the two-host smoke `deploy/bundle/ci/smoke.sh` and `compose.ci.yaml`.

## 6. Interfaces and formats

### 6.1 `lab.env.example` (the file, verbatim)

```sh
# Non-secret settings of a lab host (docs/operations/lab-install.md, ADR 0029): one host behind your own TLS proxy.
# NOT FOR PRODUCTION. Secrets never go here; they live in files under .secrets/.
PADDOCK_ENV=production
PADDOCK_LOG_LEVEL=info
# The lab profile: control plane and audit domain in one Compose project on this host.
PADDOCK_HOST=lab
# Compose project name (prefix of the containers, volumes and networks); keep it across upgrades.
# PADDOCK_PROJECT=paddock

# Public hostnames: admin., auth., device., bundles. and fleet. below this domain. All five resolve to your proxy,
# from the devices and from this host. Your proxy holds a publicly trusted certificate for all five.
PADDOCK_DOMAIN=paddock.example.org
PADDOCK_PUBLIC_ADMIN_URL=https://admin.paddock.example.org
PADDOCK_PUBLIC_DEVICE_URL=https://device.paddock.example.org

# This host's LAN address: Caddy's plain-HTTP port binds here and nothing else is published.
PADDOCK_INTERCONNECT_ADDR=192.0.2.10
PADDOCK_LAB_HTTP_PORT=8080
# The proxy's address as this host reaches it: the Paddock roles resolve the five names to it, and the certificate
# probe dials it on 443.
PADDOCK_LAB_PROXY_ADDR=192.0.2.5
# The proxy's address as Caddy sees it (the same address, unless the proxy runs on this host: see the guide). Only
# this peer may name the client through X-Forwarded-For; never private_ranges, never a /0.
PADDOCK_EDGE_TRUSTED_PROXIES=192.0.2.5
PADDOCK_EDGE_CLIENT_IP_HEADER=X-Forwarded-For
# Addresses that may open the portal, the admin API and Authentik's administrative paths: your LAN; never a /0.
PADDOCK_ADMIN_ALLOWED_CIDRS=192.0.2.0/24
# The Paddock roles reach Authentik's API through the proxy; the proxy sees them as this host.
PADDOCK_INTERNAL_CIDRS=192.0.2.10/32
# Peers of the Paddock roles whose X-Paddock-Client-IP (set by Caddy) names the client; only the stack's containers.
# PADDOCK_TRUSTED_PROXY_CIDRS=10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 127.0.0.0/8 fc00::/7 ::1/128
# Break-glass only: the api ignores the application IP allow list while true; ./paddock check fails until removed.
# PADDOCK_IP_ALLOWLIST_BYPASS=false

# Backups are optional in the lab: yes adds compose.backup.yaml, which needs the S3 settings below and the
# credentials of docs/operations/restore.md in .secrets/. With no, nothing is backed up.
PADDOCK_LAB_BACKUP=no
PADDOCK_BACKUP_S3_ENDPOINT=https://backup-s3.example.org
PADDOCK_BACKUP_S3_BUCKET=paddock-backup
PADDOCK_BACKUP_S3_REGION=us-east-1
# PADDOCK_BACKUP_S3_CA_FILE=

# Audit retention in days (minimum: the bucket default of 400 days; the lab does not relax it).
PADDOCK_AUDIT_RETENTION_DAYS=400

# Lock and Destroy stay off until the hardware acceptance protocol and the second-person review have passed.
PADDOCK_REVOCATION_ENABLED=false
PADDOCK_REVOCATION_ACCEPTED=no
```

### 6.2 `prod-check` items of the lab (names are the contract of the smoke test and the guide)

```
compose.dev.yaml is not in the effective configuration
PADDOCK_ENV=production in every service
no development-only variables
revocation path enabled only after its acceptance
secret files present, not empty and not world-readable
secrets the services reference are mounted
only Caddy's HTTP port published, on the bind address          (lab)
links between the hosts use TLS
Caddy: plain HTTP behind the TLS proxy                          (lab)
edge client address                                             (stricter in the lab)
lab: edge admin allow list                                      (lab)
lab: caddy has no hostname aliases                              (lab)
lab: roles resolve the public names to the proxy                (lab)
role trusted proxies
ip allow list bypass is off
release public keys are production keys
audit bucket has Object Lock COMPLIANCE                         (--online)
```

### 6.3 Go signatures

```go
// server/internal/prodcheck/prodcheck.go
const HostLab = "lab"
type Prod struct { InterconnectAddr, RevocationAccepted, LabProxyAddr string }      // json tags as today + "lab_proxy_addr"
type ServiceNetwork struct { Aliases []string `json:"aliases"` }
type Service struct { …; ExtraHosts []string `json:"extra_hosts"`; Networks map[string]ServiceNetwork `json:"networks"` }
func checkLabPorts(c Config) Result
func checkLabCaddy(c Config) Result
func checkLabAdminAllowlist(c Config) Result
func checkLabAliases(c Config) Result
func checkLabProxyResolution(c Config) Result
// checkEdgeClientAddress(c Config, lab bool) Result — or a separate checkLabEdgeClientAddress; the item name stays.
```

## 7. Host requirements of the lab server (for the guide, binding figures)

- **Hardware:** 4 vCPU, 8 GB RAM, 60 GB SSD (NVMe or SATA SSD; not a spinning disk — PostgreSQL, MySQL, RabbitMQ
  and RustFS share it). Reasoning: the development stack with all services idle uses about 3.4 GB of container
  memory (`docker stats`, 2026-10-13: Authentik 0.8 GB, RustFS 0.5 GB + 0.3 GB, MySQL 0.36 GB, PostgreSQL 0.25 GB,
  the Paddock roles 20–50 MB each); the production figure of 16 GB for 100 devices (`capacity.md`, `install.md`)
  includes head-room for 1 000 check-ins/s, which a lab of up to 25 devices never reaches. Disk: about 8 GB of
  images (Authentik 1.2 GB, fleetctl 2.4 GB, MySQL 0.6 GB, PostgreSQL 0.45 GB, the rest below 0.3 GB each),
  Fleet's vulnerability database about 1 GB, the databases below 3 GB for a lab, Prometheus 30 days about 1 GB,
  audit evidence about 1 GB per 100 devices and year, Docker's own overhead and logs; 60 GB leaves room for the
  images of two bundle versions during an upgrade.
- **Software:** Ubuntu 24.04 LTS (amd64), Docker Engine ≥ 27 and the Compose plugin ≥ 2.24 from Docker's apt
  repository (not Ubuntu's `docker.io`), `openssl`, `curl`, `sha256sum`, time synchronization (the device protocol
  has a ±300 s replay window). The implementer's development host runs Docker 29.8.2 with Compose v5.6.0.
- **Network:** one static LAN address (`PADDOCK_INTERCONNECT_ADDR`); inbound only `PADDOCK_LAB_HTTP_PORT` from the
  proxy and SSH from the operator; outbound HTTPS to `ghcr.io`, Docker Hub, `osv-vulnerabilities.storage.googleapis.com`,
  `github.com` and `objects.githubusercontent.com` (Fleet's vulnerability feeds), the backup endpoint if any, and the
  identity sources Authentik connects to; outbound to the proxy on 443.
- **DNS:** the five names resolve to the proxy's address from every test device and from the Paddock host (the
  roles do not need it — `extra_hosts` — but `./paddock` commands and the operator's browser do). A certificate
  for names that are not reachable from the internet is obtained with the ACME DNS-01 challenge; this is the
  proxy's concern, not Paddock's.

## 8. Steps (tickets, in order)

1. **PDK-099 — prod-check: lab host.** Decisions 11–13. `server/internal/prodcheck/` and the CLI. Fixture-based
   unit tests for every new finding. Verify: `GOTOOLCHAIN=auto go test -count=1 ./server/internal/prodcheck/
   ./server/cmd/...`; `paddock-server prod-check --host lab < fixture.json` prints the items of §6.2.
2. **PDK-100 — Lab overlay, Caddyfile, secrets and bundle.** Decisions 1–10, 17 (the `versions.env` line only).
   Verify: `make bundle-test`; `make test`; `./paddock check` of a local lab bundle on the development host passes
   offline with throwaway keys (the smoke test of PDK-101 automates this); `make typecheck`.
3. **PDK-101 — Nginx reference configuration and the lab smoke test.** Decisions 14–19. Verify: `make bundle
   bundle-smoke-lab` passes locally; the CI edge job runs it.
4. **PDK-102 — Lab guide and pointers.** Decisions 20–21. Verify: every command of the guide appears in
   `smoke-lab.sh` in the same order (the reviewer checks this by reading; there is no markdown linter);
   `make scan-secrets` is green (the example addresses are documentation ranges).

PDK-102 MAY run in parallel with PDK-101 once PDK-100 is merged.

## 9. Acceptance criteria

- **L1 (operator):** Given a bundle extracted on one amd64 host with `.env` from `.env.lab.example` and the proxy's
  settings, when the operator runs the commands of the guide's section 5 in order, then `./paddock check` and
  `./paddock check --online` print every item of §6.2 as PASS, both begin with the lab warning line, and
  `./paddock up` ends with `all services healthy`. (`smoke-lab.sh` steps 1–8.)
- **L2 (portal user, device):** Given the proxy of decision 15 in front, when a browser opens
  `https://admin.<domain>/`, then the portal loads over the proxy's certificate, the login redirect goes to
  `https://auth.<domain>/…`, and the discovery document's `issuer` is `https://auth.<domain>/application/o/paddock-portal/`;
  when a device posts to `https://device.<domain>/v1/checkin`, then the gateway answers (4xx for an unsigned probe),
  and `GET /api/v1/me` of a logged-in administrator returns the administrator's LAN address as `client_ip`.
- **L3 (security):** Given the lab configuration, when `.env` sets `PADDOCK_EDGE_TRUSTED_PROXIES=private_ranges`,
  `0.0.0.0/0`, an empty value, `PADDOCK_EDGE_CLIENT_IP_HEADER=none`, `PADDOCK_ADMIN_ALLOWED_CIDRS=0.0.0.0/0`, or
  publishes a second port, then `./paddock check` exits 1 naming the item. Given a request to Caddy's port that
  does not come from the trusted proxy, when it carries `X-Forwarded-For: 203.0.113.9`, then the header is ignored
  (the peer's address counts). Given a request through Nginx from a LAN client with a forged `X-Forwarded-For`,
  then Paddock sees the client's address.
- **L4 (production unchanged):** Given the two-host production configuration, when `make bundle-test`, `make test`
  and the two-host smoke run, then they pass unchanged; `./paddock check` on a control plane without
  `PADDOCK_ACME_EMAIL` fails the Caddy item and Caddy refuses to start.
- **L5 (uploads):** Given the Nginx configuration, when a 20 MiB `PUT` reaches `bundles.<domain>`, then it is not
  refused by Nginx (`413`) but answered by RustFS (`403` for an unsigned request); when a 128 MiB artifact is
  uploaded through the admin API, then Nginx passes it (`client_max_body_size 160m`).
- **L6 (backups optional):** Given `PADDOCK_LAB_BACKUP=no`, then no backup service is in `./paddock ps` and
  `./paddock check` does not require the backup credentials; given `yes` with an https endpoint and credentials,
  then the three backup containers run and `pgbackrest info` lists a full backup after the first run.
- **L7 (documentation):** Given the guide, when the maintainer follows it with an Nginx on another LAN host or on the
  same host, then every value they must supply is named in one table (domain, five DNS names, LAN address of the
  host, proxy address, LAN CIDR, certificate path) and no value is to be guessed.

## 10. Freedoms

- Internal structure of the new `check*` functions and the lab fixture; helper names in `gen-prod-secrets.sh`;
  whether `smoke-lab.sh` and `smoke.sh` share a sourced helper file (`deploy/bundle/ci/smoke-lib.sh`) or duplicate
  the small helpers (`step`, `fail`, `setenv`, `rand`, `probe`); wording of comments; the exact `openssl` commands of
  the smoke test's throwaway certificate.

## 11. Stop conditions

- Compose does not apply `networks: !override [cp]` or `ports: !override []` as decision 4 expects (the rendered
  configuration still shows aliases or ports): report; do not switch to another mechanism silently.
- The rendered JSON of `extra_hosts` or `networks` differs from §2 on the CI's Compose version: report with the
  rendered shape.
- Caddy does not pass `X-Forwarded-Proto` from the trusted proxy (the discovery document's issuer is `http://…`):
  stop; the fallback (a `header_up X-Forwarded-Proto https` in the lab Caddyfile) needs an architect decision because
  it would hard-code the scheme.
- The NAT source address of the same-host proxy in CI is not `172.30.0.1`: report the observed address; do not widen
  the trusted proxies.
- Any change to `compose.audit.prod.yaml`, `caddy/entrypoint.sh`, `guards.caddy` or the agent seems necessary.
- A new Go module or npm package seems necessary (none is expected).

## 12. Risks and open points

- **Nginx on the Paddock host** (open, default chosen): the maintainer did not say where Nginx runs. Default: another
  LAN machine (decision 2's example values). The same-host variant is documented and smoke-tested (decisions 14, 18).
- **Compose `!override` on nested `aliases`:** decision 4 uses `networks: !override [cp]` (the whole key), which
  is the documented use of the tag. Mitigation: `TestLabEdge` asserts the absence of aliases.
- **Caddy `X-Forwarded-Proto` pass-through:** documented behaviour for trusted proxies; verified end to end by the
  issuer assertion of the smoke test (stop condition above if it fails).
- **A LAN peer connecting to Caddy's port directly** bypasses the proxy's TLS and, since it is not a trusted proxy,
  counts as the client: the edge allow list and the application allow list still apply; cookies marked `Secure`
  are not sent over plain HTTP, so the portal does not work that way. The guide states that the port is for the
  proxy only and recommends a host firewall rule limiting it to the proxy's address.
- **WORM in a lab:** the audit bucket keeps 400 days of Object Lock; the evidence of a lab cannot be deleted through
  S3 but disappears with `./paddock down --volumes`. Stated in the guide; not relaxed.
- **Fleet's feeds:** the lab keeps Fleet's anonymous GitHub lookup; a rate-limited runner shows up as a Fleet
  warning, not as a Paddock failure.
