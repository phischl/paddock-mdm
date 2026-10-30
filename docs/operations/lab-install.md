# Lab installation (one host behind your own TLS proxy)

How to run a released Paddock on **one** amd64 Linux host of a private network, behind a TLS-terminating reverse
proxy you already operate (`PADDOCK_HOST=lab`; ADR 0029, plan M8a). The lab profile exists to test Paddock with real
devices (VMs, laptops) in a homelab. It uses the production images, the production configuration and the production
checks of the operator bundle; it is **not** a production installation. A production installation is two hosts with
Paddock's own public TLS: `docs/operations/install.md`.

## 1. What the lab profile is and is not

**It is:** control plane and audit domain in one Compose project on one host (`compose.yaml`, `compose.prod.yaml`,
`compose.audit.yaml`, `compose.lab.yaml`, optionally `compose.backup.yaml`). Caddy serves plain HTTP on one port bound
to the host's LAN address; your proxy terminates TLS for the five public names and is the only peer whose
`X-Forwarded-For` names the client. The Paddock roles reach Authentik and the step-up issuer through your proxy, as
the devices do. `PADDOCK_ENV=production`, the sealed OpenBao, the WORM audit bucket, the production release keys and
every refusal of development settings apply unchanged.

**It is not for production.** It gives up three things a production installation has (ADR 0029, consequences):

- **Audit separation.** The audit database, the WORM bucket and their credentials live on the same host, in the same
  `.secrets/`, under the same Docker daemon as the control plane. Anybody with root on the host can delete the
  evidence volume.
- **Paddock's own TLS.** Certificate issuance, renewal, protocol versions and HSTS at the edge are your proxy's. A
  compromised proxy can name any client address.
- **The public-exposure assessment.** Nothing in this profile was assessed for an internet-facing proxy. Your proxy
  and the Paddock host MUST NOT be reachable from the internet.

`./paddock check` and `./paddock up` print `lab profile (PADDOCK_HOST=lab): not for production — see
docs/operations/lab-install.md` as their first line on every run.

## 2. Host requirements

| | Minimum | Comfortable |
| --- | --- | --- |
| CPU | 4 vCPU | 4 vCPU |
| Memory | 8 GB | 16 GB |
| Disk | 60 GB SSD | 100 GB SSD |

- **Disk:** NVMe or SATA SSD, not a spinning disk: PostgreSQL, MySQL, RabbitMQ and RustFS share it. About 8 GB are
  images, 1 GB Fleet's vulnerability database, up to 3 GB the databases of a lab, 1 GB Prometheus (30 days), 1 GB
  audit evidence per 100 devices and year; 60 GB leave room for the images of two bundle versions during an upgrade.
- **Memory:** the stack uses about 3.9 GB idle (3.4 GB plus about 0.5 GB for Authentik's four web workers,
  `PADDOCK_AUTHENTIK_WEB_WORKERS`). The production figure of 16 GB (`docs/operations/capacity.md`) has
  head-room for 1 000 check-ins/s, which a lab of up to 25 devices never reaches.
- **Operating system:** Ubuntu 24.04 LTS, **amd64** (Fleet's image is published for `linux/amd64` only; `./paddock
  up` refuses another architecture).
- **Software:** Docker Engine ≥ 27 and the Compose plugin ≥ 2.24 from Docker's apt repository (not Ubuntu's
  `docker.io`), `openssl`, `curl`, `sha256sum`.
- **Time:** time synchronization (NTP, for example `systemd-timesyncd`). The device protocol has a ±300 s replay
  window; a host or device clock that drifts further is refused.
- **Network:** one static LAN address for the host (`PADDOCK_INTERCONNECT_ADDR`). Inbound: only
  `PADDOCK_LAB_HTTP_PORT` (default 8080) from your proxy, and SSH from you. Outbound: HTTPS to `ghcr.io` and Docker
  Hub (images), `osv-vulnerabilities.storage.googleapis.com` (Ubuntu's OSV feed), `github.com` and
  `objects.githubusercontent.com` (Fleet's vulnerability feeds), the backup endpoint if any (section 7), the identity
  sources Authentik connects to, and your proxy on 443.

## 3. DNS and certificate

The five names below one domain of yours MUST resolve to **your proxy's** address, from every test device and from
the Paddock host itself. The Paddock roles do not depend on it (the lab overlay maps the five names to
`PADDOCK_LAB_PROXY_ADDR` in their `/etc/hosts`), but your browser and the devices do.

| Name | Serves |
| --- | --- |
| `admin.<domain>` | portal and admin API (edge allow list `PADDOCK_ADMIN_ALLOWED_CIDRS`) |
| `auth.<domain>` | Authentik: portal login, device logins; administrative paths restricted like `admin.` |
| `device.<domain>` | device API (gateway) |
| `bundles.<domain>` | presigned bundle downloads, agent packages, header uploads |
| `fleet.<domain>` | osquery and fleetd endpoints only |

Your proxy needs a **publicly trusted** certificate for all five names: a wildcard `*.<domain>` or one certificate
with five SANs. Devices and the Paddock roles verify it against the system trust store; a private CA does not work
without changing every device. A name that is not reachable from the internet gets its certificate with the ACME
DNS-01 challenge (for example certbot with your DNS provider's plugin); that is your proxy's concern, not Paddock's.

## 4. The proxy

The bundle ships the Nginx reference configuration `nginx/paddock.conf.example`; it is tested in CI against the lab
bundle. Other proxies are your translation of it. The file:

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

Why it looks like this — keep these properties when you adapt it:

- `X-Forwarded-For $remote_addr`, not `$proxy_add_x_forwarded_for`: Paddock sees exactly the address your proxy
  saw. Caddy would stop at the first untrusted address anyway, but a single address leaves nothing to interpret.
- `Host $host`: presigned bundle, package and escrow URLs carry a SigV4 signature over the `Host` header.
- `X-Forwarded-Proto https`: Authentik derives its issuer and cookie flags from it; Caddy passes it on only from the
  trusted proxy.
- No `add_header Strict-Transport-Security`: the api sends it; a second header is undefined.
- No URI after `proxy_pass http://paddock_lab`: with one, Nginx re-encodes the path and breaks signed URLs.
- `client_max_body_size 160m`: agent artifacts (128 MiB) and escrowed LUKS headers (16 MiB) must pass.

The configuration MUST NOT be reachable from the internet.

### Proxy on another LAN host (default)

Use the file as above with the Paddock host's LAN address and port in `upstream`. In `.env` (section 5), the proxy's
LAN address goes into both `PADDOCK_LAB_PROXY_ADDR` and `PADDOCK_EDGE_TRUSTED_PROXIES`, and the Paddock host's own
address into `PADDOCK_INTERNAL_CIDRS` (the roles' calls leave the host with its address and come back through the
proxy).

Caddy's port is for the proxy only. A LAN peer that connects to it directly is not a trusted proxy and counts as the
client itself; the allow lists still apply, and the portal does not work over plain HTTP (its cookies are `Secure`).
Restrict the port to the proxy's address on the Paddock host anyway. Docker publishes ports past `ufw`; the rule
belongs in the `DOCKER-USER` chain (persist it with your firewall tooling):

```sh
sudo iptables -I DOCKER-USER -p tcp -m conntrack --ctorigdst 192.0.2.10 --ctorigdstport 8080 --ctdir ORIGINAL \
  ! -s 192.0.2.5 -j DROP
```

Replace `192.0.2.10` with `PADDOCK_INTERCONNECT_ADDR`, `8080` with `PADDOCK_LAB_HTTP_PORT` and `192.0.2.5` with the
proxy's address. Keep `--ctorigdst`: without it the rule matches every forwarded connection to port 8080, including
the containers' own calls to each other (Caddy to Fleet and the api, the api to the escrow reader) and breaks the
stack.

### Proxy on the Paddock host itself

Bind Caddy to loopback and let the proxy forward there:

- `upstream` of the Nginx file: `server 127.0.0.1:8080;`
- `PADDOCK_INTERCONNECT_ADDR=127.0.0.1`
- `PADDOCK_LAB_PROXY_ADDR`: the host's LAN address (the roles reach the proxy there).
- `PADDOCK_EDGE_TRUSTED_PROXIES`: the gateway address of the Compose network `<project>_cp` (`paddock_cp` with the
  default project name). The proxy's connections reach Caddy from that address after Docker's NAT. It exists after
  `./paddock up --infra` (section 5); set it then, before `./paddock check`:
  ```sh
  docker network inspect paddock_cp -f '{{(index .IPAM.Config 0).Gateway}}'
  ```
- `PADDOCK_INTERNAL_CIDRS`: the subnets of `paddock_cp` and of `paddock_audit-index`, separated by a space
  (`{{(index .IPAM.Config 0).Subnet}}` of each): the roles' calls reach the proxy on this host from their container
  addresses, and the api leaves through `audit-index`, its first network. Without that subnet the api's calls to
  Authentik's API are refused with 403.
  ```sh
  docker network inspect paddock_cp paddock_audit-index -f '{{(index .IPAM.Config 0).Subnet}}'
  ```
- In this variant every local process on the host reaches Caddy from the same gateway address as the proxy, so Caddy
  trusts its `X-Forwarded-For` like the proxy's. Prefer the proxy on another machine when the host runs anything else.
- Docker assigns these addresses when it creates the networks. After `./paddock down` (which removes them) read the
  gateway and both subnets again and update `.env` before the next `./paddock up`.

## 5. Install

What you must provide before you start. Every value below goes into `.env` or is a file you place; nothing else is to
be chosen.

| # | What you provide | Where it goes | Example (proxy on another host) |
| --- | --- | --- | --- |
| 1 | your domain | `PADDOCK_DOMAIN` | `paddock.example.org` |
| 2 | admin URL | `PADDOCK_PUBLIC_ADMIN_URL` | `https://admin.paddock.example.org` |
| 3 | device URL | `PADDOCK_PUBLIC_DEVICE_URL` | `https://device.paddock.example.org` |
| 4 | five names → proxy | DNS (section 3) | `admin.`, `auth.`, `device.`, `bundles.`, `fleet.` to `192.0.2.5` |
| 5 | certificate, five names | proxy: `ssl_certificate` | `/etc/letsencrypt/live/paddock.example.org/fullchain.pem` |
| 6 | its private key | proxy: `ssl_certificate_key` | `/etc/letsencrypt/live/paddock.example.org/privkey.pem` |
| 7 | LAN address of this host | `PADDOCK_INTERCONNECT_ADDR`, proxy `upstream` | `192.0.2.10` |
| 8 | Caddy's HTTP port | `PADDOCK_LAB_HTTP_PORT`, proxy `upstream` | `8080` |
| 9 | proxy as this host reaches it | `PADDOCK_LAB_PROXY_ADDR` | `192.0.2.5` |
| 10 | proxy as Caddy sees it | `PADDOCK_EDGE_TRUSTED_PROXIES` | `192.0.2.5` |
| 11 | administrators' LAN CIDR | `PADDOCK_ADMIN_ALLOWED_CIDRS` (never a `/0`) | `192.0.2.0/24` |
| 12 | roles' address at the proxy | `PADDOCK_INTERNAL_CIDRS` | `192.0.2.10/32` |
| 13 | release public keys | `.secrets/release-production/` (step 7) | `minisign.pub`, `revoke-minisign.pub` |
| 14 | five OpenBao custodians | the unseal shares of step 5 | five people, or five safe places |
| 15 | backups (optional) | `PADDOCK_LAB_BACKUP`, `PADDOCK_BACKUP_S3_*` | `no` (section 7) |

With the proxy on the Paddock host (section 4), rows 7, 9, 10 and 12 change: `127.0.0.1`, the host's LAN address,
the gateway of `paddock_cp`, and the subnets of `paddock_cp` and `paddock_audit-index` separated by a space; the
proxy's `upstream` is `127.0.0.1:8080`.

Run every command inside the bundle directory, as the user who runs Docker.

1. **Download and verify** the bundle of a release exactly as `docs/operations/install.md` section 3 describes
   (cosign `verify-blob`), then:
   ```sh
   tar -xzf paddock-deploy-$v.tar.gz && cd paddock-deploy-$v
   ./paddock verify
   ```
2. **Settings.** Copy the lab template and set the values of the table above; keep `PADDOCK_ENV=production`,
   `PADDOCK_HOST=lab` and the defaults you do not need to change:
   ```sh
   cp .env.lab.example .env
   ```
   `PADDOCK_EDGE_CLIENT_IP_HEADER` stays `X-Forwarded-For`; leave `PADDOCK_TRUSTED_PROXY_CIDRS` and
   `PADDOCK_IP_ALLOWLIST_BYPASS` commented out.
3. **Secrets.** Writes the random secrets of both halves and one internal CA into `.secrets/` (mode 0700, keep it so)
   and prints file names only; running it again never overwrites a file:
   ```sh
   ./paddock secrets
   ```
4. **Images and infrastructure.** Starts everything but the Paddock roles and waits until healthy (OpenBao sealed):
   ```sh
   ./paddock pull
   ./paddock up --infra
   ```
   With the proxy on this host, set `PADDOCK_EDGE_TRUSTED_PROXIES` and `PADDOCK_INTERNAL_CIDRS` now (section 4).
5. **OpenBao.** Initialize it with five shares and a threshold of three. The output holds the shares and the root
   token: hand one share to each custodian (or store them apart) and never keep them on the host. With PGP-encrypted
   shares, follow `docs/operations/openbao.md` section 1 instead.
   ```sh
   ./paddock bao operator init -key-shares=5 -key-threshold=3
   ./paddock bao operator unseal          # three times, one share each; prompts for the share
   read -rs BAO_TOKEN && export BAO_TOKEN # the root token, typed without echo
   ./paddock bootstrap openbao
   ./paddock bao token revoke -self
   unset BAO_TOKEN
   ```
   `bootstrap openbao` writes every AppRole's credentials to `.secrets/approle/`, the audit writer's included; on a
   lab host nothing is copied between hosts. OpenBao starts sealed after every restart of the host or the container;
   three shares unseal it (`docs/operations/openbao.md` section 2).
6. **Buckets and Fleet** (idempotent):
   ```sh
   ./paddock bootstrap buckets           # paddock-bundles, paddock-agent-artifacts, paddock-escrow and their users
   ./paddock bootstrap audit-bucket      # WORM bucket paddock-audit (Object Lock COMPLIANCE, 400 days)
   ./paddock bootstrap fleet             # Fleet's admin, the API-only user paddock, the enroll secret
   ```
7. **Release keys.** Generate your installation's own minisign key pairs offline, on a machine that is not the
   Paddock host (`docs/operations/agent-releases.md`, "Production key"), and copy the two public keys:
   ```sh
   mkdir -p .secrets/release-production
   cp <offline>/minisign.pub <offline>/revoke-minisign.pub .secrets/release-production/
   chmod 644 .secrets/release-production/*.pub   # the services run as uid 65532
   ```
   The secret keys never come to the host. `./paddock check` refuses the development release key.
8. **Check and start.** Your proxy must be running before `./paddock up`: the roles' readiness needs Authentik's
   discovery document through it.
   ```sh
   ./paddock check                       # every item PASS, else fix and repeat
   ./paddock check --online              # also reads the audit bucket's Object Lock
   ./paddock up                          # ends with "all services healthy"
   ./paddock ps
   ```

## 6. First administrator, organization and device

As in production: `docs/operations/install.md` section 9 (first platform administrator, first organization with its
domains, the break-glass accounts before the first device, IP allow list; every sign-in asks for a second factor) and section 10 (first agent release with `./paddock agent-release`). The release directory and
its files must be readable by the `paddock-api` service (uid 65532): `chmod -R a+rX <dir>`.

## 7. Backups

Backups are optional in the lab. With `PADDOCK_LAB_BACKUP=no` (the default) nothing is backed up, `./paddock ps` shows
no backup service and `./paddock check` does not ask for backup credentials. Then `./paddock down --volumes` deletes
everything for good, the WORM audit bucket included: its Object Lock protects the objects against S3 deletes, not
against the deletion of the Docker volume.

To back up, set `PADDOCK_LAB_BACKUP=yes` and `PADDOCK_BACKUP_S3_ENDPOINT` (https), `PADDOCK_BACKUP_S3_BUCKET`,
`PADDOCK_BACKUP_S3_REGION` (and `PADDOCK_BACKUP_S3_CA_FILE` for a private CA) in `.env`. Create the bucket and its
three credentials as `docs/operations/restore.md` "Backup bucket" describes, write them to
`.secrets/backup_{pgbackrest,worker,fleet}_{access,secret}_key`, store a copy of `.secrets/backup_encryption_key`
offline, then run `./paddock check` and `./paddock up` again. After the first run,
`./paddock compose run --rm --no-deps pgbackrest info` lists a full backup.

## 8. What `./paddock check` enforces in the lab

Every production item that applies to one host runs unchanged:

- `compose.dev.yaml is not in the effective configuration`
- `PADDOCK_ENV=production in every service`
- `no development-only variables`
- `revocation path enabled only after its acceptance`
- `secret files present, not empty and not world-readable`
- `secret files readable by the Paddock services` (the Paddock images run as uid 65532: a secret file of a Paddock
  service must have mode 644, or belong to uid 65532; the finding names the `chmod`)
- `secrets the services reference are mounted`
- `links between the hosts use TLS` (local service names pass; OpenBao is `https://` everywhere)
- `container hardening` (the Paddock roles and Caddy drop every capability but Caddy's `NET_BIND_SERVICE` and may not
  gain privileges; every service has a `pids_limit`)
- `role trusted proxies` (no `/0` in `PADDOCK_TRUSTED_PROXY_CIDRS`)
- `ip allow list bypass is off`
- `authentik web workers` (`PADDOCK_AUTHENTIK_WEB_WORKERS` is an integer of at least 1)
- `release public keys are production keys`
- `audit bucket has Object Lock COMPLIANCE` (with `--online`; at least 400 days)

These replace or tighten the host-shape items of production:

- `only Caddy's HTTP port published, on the bind address`: exactly one published port, Caddy's, on
  `PADDOCK_INTERCONNECT_ADDR` (a specific address) and forwarding to port 80; no other service publishes anything,
  and no service runs with `network_mode: host`.
- `Caddy: plain HTTP behind the TLS proxy`: the Caddyfile has `auto_https off`, every site is an `http://` site, no
  `tls internal`, no `trusted_proxies` of its own, `guards.caddy` and `entrypoint.sh` mounted next to it.
- `edge client address`: the header MUST be `X-Forwarded-For`, the trusted proxies MUST NOT be empty, a `/0` or
  `private_ranges`.
- `lab: edge admin allow list`: `PADDOCK_ADMIN_ALLOWED_CIDRS` is not empty and has no `/0`.
- `lab: caddy has no hostname aliases`: no alias on any network would let a role bypass the proxy.
- `lab: roles resolve the public names to the proxy`: the api, worker, escrow reader and revocation issuer map all
  five names to `PADDOCK_LAB_PROXY_ADDR` and nothing else; the worker's certificate probe dials
  `PADDOCK_LAB_PROXY_ADDR:443`.

What the lab relaxes, compared with a production control plane: no ACME e-mail and no published 80/443 (TLS is the
proxy's); the audit database link is local and without TLS (`sslmode=disable` on the Compose network); the Object
Lock item runs only with `--online`. Nothing else is relaxed: not the 400-day Object Lock, not the production release
keys, not the sealed OpenBao, not the revocation acceptance, not the development-variable refusals.

In the lab, the worker's certificate probe and the alert `PaddockCertificateExpiry` watch **your proxy's**
certificate (`docs/operations/monitoring.md`).

## 9. Upgrade

As in production: `docs/operations/upgrade.md`. Extract the new bundle next to the running one, take over `.env` and
`.secrets/` with `./paddock migrate-from <old dir>`, then `./paddock check` and `./paddock up`.

## 10. Troubleshooting

- **Caddy does not start.** `./paddock logs caddy` names the edge variable it refuses (`PADDOCK_EDGE_TRUSTED_PROXIES`,
  `PADDOCK_EDGE_CLIENT_IP_HEADER`); `./paddock check` names the item.
- **403 on `admin.<domain>`.** The client address Caddy resolved is not in `PADDOCK_ADMIN_ALLOWED_CIDRS` (or, once set,
  the application IP allow list). Caddy's access log (`./paddock logs caddy`) shows the address it resolved: the
  proxy's own address there means `PADDOCK_EDGE_TRUSTED_PROXIES` does not match the proxy as Caddy sees it (with the
  proxy on the same host: the gateway of `paddock_cp`).
- **Logins, step-ups and identity synchronization fail.** The roles reach Authentik through your proxy; while it is
  down or its certificate is not trusted, logins fail. Devices keep working (fail safe).
- **`PaddockCertificateProbeFailing`.** The worker cannot verify your proxy's certificate for one of the five names:
  check that it is publicly trusted and covers all five.

## 11. Automatic unseal (replacing a cron job)

A lab host that unseals OpenBao with a hand-made cron job (a script and a file with three shares) moves to the bundled
automatic unseal (ADR 0035, `docs/operations/openbao.md` section 6), which Paddock checks, monitors and audits:

1. Enable it as in `docs/operations/openbao.md` section 6: a platform administrator acknowledges the disclaimer in
   the portal (*Platform* → *OpenBao*), then `./paddock auto-unseal enable` on the host with the three shares typed
   at the prompts.
2. Remove the cron job and its share file:

   ```sh
   crontab -e                      # delete the unseal line (or remove the file of /etc/cron.d/ that holds it)
   shred -u /path/to/your/share/file
   ```

   Remove every other copy of those shares on the host as well.
3. Verify: `./paddock compose restart openbao`, then `./paddock bao status` shows `Sealed false` within 30 s, and the
   portal page shows the automatic unseal.

On the lab host `./paddock check` passes the item `openbao auto-unseal` and names the residual risk RR-43; on a
production control plane the same setting is reported as `WARN` on every run.
