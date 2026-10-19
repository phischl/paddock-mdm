# Production installation

How to install Paddock on two hosts with public TLS and without development shortcuts (plan M6a, plan M7b,
architecture §4.1, ADR 0016, ADR 0022). Every host runs the **operator bundle** `paddock-deploy-<version>.tar.gz`
of a release: the Compose files, their configuration, the bootstrap scripts and the entry script `./paddock`. The
images are pulled from `ghcr.io/phischl/` by tag and digest; neither `git`, `make` nor Go is needed on a host. The
development stack (`make up`, `docs/operations/local-dev.md`) is a different thing and never runs in production.

| Host | `PADDOCK_HOST` | Compose files | Runs |
| --- | --- | --- | --- |
| Control plane | `controlplane` | `compose.yaml` + `compose.prod.yaml` + `compose.backup.yaml` | Caddy, the Paddock roles, PostgreSQL, RabbitMQ, Valkey, OpenBao, RustFS (bundles, escrow, artifacts), Authentik, Fleet, pgBackRest |
| Audit domain | `audit` | `compose.audit.yaml` + `compose.audit.prod.yaml` | audit writer, audit PostgreSQL, RustFS with the WORM audit bucket |

`./paddock` picks the files from `PADDOCK_HOST` in `.env`. The audit domain has its own credentials (separation of
duties). The control plane holds only RabbitMQ's publish credential for audit events and the read-only audit database
role; it holds nothing for the audit bucket.

A single-host lab behind your own TLS proxy is a separate profile (`PADDOCK_HOST=lab`):
`docs/operations/lab-install.md` (not for production).

## 1. Host requirements

- Two Linux hosts with Docker Engine and the Compose plugin ≥ 2.24 (`!override`/`!reset` tags), `openssl`, `curl` and
  `sha256sum`. **The control-plane host must be amd64**: the Fleet image (`fleetdm/fleet`) is published for
  `linux/amd64` only, and `./paddock up` refuses another architecture there. The audit host may be amd64 or arm64
  (the Paddock images are published for both).
- Keep Docker's default seccomp and AppArmor profiles enabled (do not run the daemon with them turned off). The
  Paddock roles run without any Linux capability and without privilege gain (`cap_drop: [ALL]`,
  `no-new-privileges:true`); Caddy keeps only `NET_BIND_SERVICE` for 80 and 443; every service has a `pids_limit`.
  `./paddock check` fails the item `container hardening` when a Compose edit removes one of these settings.
- Control plane: 4 vCPU, 16 GB RAM, 100 GB disk for 100 devices. Audit domain: 2 vCPU, 4 GB RAM, disk for 400 days
  of audit evidence (about 1 GB per 100 devices and year).
- A **private interconnect** between the hosts (VPN such as WireGuard, or a private network), each host with a fixed
  address on it. Only these endpoints are published there, all with TLS from the internal CAs:
  - control plane → audit host: RabbitMQ `amqps` 5671 (the audit writer consumes), OpenBao 8200 (the audit writer
    signs the daily manifests);
  - audit host → control plane: PostgreSQL 5432 (the api's read-only audit view, `sslmode=verify-full`).
- The control plane is reachable from the internet on 80 (ACME HTTP-01, redirect) and 443. Nothing else is published;
  `./paddock check` refuses any other published port that is not bound to the interconnect address.
- An S3 bucket for backups **outside the control-plane host** (section 11).
- **Proxies or a CDN in front of Caddy** (optional): declare them with `PADDOCK_EDGE_TRUSTED_PROXIES` and
  `PADDOCK_EDGE_CLIENT_IP_HEADER` (`X-Forwarded-For` or `CF-Connecting-IP`), so that the allow lists, rate limits
  and audit log see the real client; without them Caddy treats its peer as the client and ignores every such header.
  Firewall the origin to the proxy's ranges. Details and the Cloudflare example: `docs/operations/ip-allowlist.md`.
- Outbound HTTPS from the control plane (allow it in the host's firewall): `ghcr.io` and Docker Hub (images), the ACME
  CA (Caddy), Ubuntu's OSV feed `https://osv-vulnerabilities.storage.googleapis.com` (`paddock-worker`, daily;
  without it the alert `PaddockOSVStale` fires after 3 days, and `docs/operations/vulnerability-data.md` describes the
  offline import), Fleet's vulnerability feeds (`fleet`), the backup S3 endpoint, and the identity sources Authentik
  connects to. The audit host needs `ghcr.io` and Docker Hub only.

## 2. DNS

Point these names at the control-plane host's public address. Caddy requests one certificate per name from a public
ACME CA as soon as it starts.

| Name | Serves | Exposure |
| --- | --- | --- |
| `admin.<domain>` | portal and admin API | restricted by `PADDOCK_ADMIN_ALLOWED_CIDRS` and the application allow list (`docs/operations/ip-allowlist.md`) |
| `auth.<domain>` | Authentik (portal login, device logins) | internet for logins and device approvals; administrative paths restricted by `PADDOCK_ADMIN_ALLOWED_CIDRS` |
| `device.<domain>` | device API (gateway) | internet |
| `bundles.<domain>` | presigned bundle downloads, agent packages, header uploads | internet |
| `fleet.<domain>` | osquery and fleetd endpoints only | internet |

## 3. Download and verification

On **each** host, download the bundle and its signature from the GitHub release of the version
(`https://github.com/phischl/paddock-mdm/releases`), verify the keyless signature, and extract it into a directory of
its own; that directory is the installation (keep it, an upgrade takes `.env` and `.secrets/` from it):

```sh
v=<version>      # for example 1.2.0
curl -fLO https://github.com/phischl/paddock-mdm/releases/download/v$v/paddock-deploy-$v.tar.gz
curl -fLO https://github.com/phischl/paddock-mdm/releases/download/v$v/paddock-deploy-$v.tar.gz.sigstore.json
# COSIGN_IMAGE of versions.env in the repository at the release tag (tag and digest)
cosign_image=ghcr.io/sigstore/cosign/cosign:v3.1.3@sha256:9e5c2f2edc34351160407ca3416c61855bdf9403c3c5936e0f0be7fc261611b8
docker run --rm -v "$PWD:/w" -w /w "$cosign_image" verify-blob paddock-deploy-$v.tar.gz \
  --bundle paddock-deploy-$v.tar.gz.sigstore.json \
  --certificate-identity-regexp '^https://github.com/phischl/paddock-mdm/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
tar -xzf paddock-deploy-$v.tar.gz && cd paddock-deploy-$v
./paddock verify       # every shipped file matches SHA256SUMS
./paddock version
```

Take the cosign image with its digest from `deploy/compose/versions.env` (`COSIGN_IMAGE`) of the release tag on
GitHub; the line above is the one of this documentation's version. The bundle's `README.md` shows the same commands
with that image filled in and how to verify an image (`cosign verify` of the reference in `versions.env`). Run every command below inside the bundle directory, as
the operator who runs Compose. Never edit the shipped files; local settings belong in `.env`.

To pull the Paddock images from a mirror of your own, set `PADDOCK_IMAGE`, `PADDOCK_COMPILER_IMAGE` and
`PADDOCK_PGBACKREST_IMAGE` in `.env` (tag and digest of the mirrored images); `.env` overrides `versions.env`.

## 4. Configuration and secrets

```sh
cp .env.example .env
```

Set `PADDOCK_HOST` (`controlplane` or `audit`), the domain, the ACME e-mail, `PADDOCK_INTERCONNECT_ADDR` (this host's
own interconnect address), `PADDOCK_CONTROLPLANE_ADDR`, `PADDOCK_AUDIT_ADDR` and, on the control plane, the backup
bucket (`PADDOCK_BACKUP_S3_*`). Keep the default project name (`PADDOCK_PROJECT`, `paddock`) unless two installations
share a host. Then:

```sh
./paddock secrets
```

It writes random secrets and this host's internal CA with its TLS certificates into `.secrets/` (directory mode 0700;
keep it so) and prints file names only, never a secret. Running it again never overwrites a file.

Exchange these files between the hosts over a secure channel (for example `scp` over the interconnect), then run
`./paddock secrets` again on both hosts:

| File in `.secrets/` | From | To | When |
| --- | --- | --- | --- |
| `db_paddock_audit_reader_password` | audit host | control plane (builds `db_paddock_audit_reader_url`) | now |
| `rabbitmq_audit_writer_password` | control plane | audit host | now |
| `internal-ca/ca.crt` | each host | the other host, as `internal-ca/peer-ca.crt` (public; `bundle.crt` then trusts both) | now |
| `approle/paddock-audit-writer/` (`role_id`, `secret_id`) | control plane | audit host | after section 6 |

Copy the production release public keys (`docs/operations/agent-releases.md`, "Production key") to
`.secrets/release-production/minisign.pub` and `.secrets/release-production/revoke-minisign.pub` on the control
plane and make them readable by the services (they run as uid 65532; `./paddock check` names a file they cannot
read): `chmod 644 .secrets/release-production/*.pub`. Their secret keys never come to a server.

Pull the images: `./paddock pull`.

## 5. Audit host

```sh
./paddock up --infra                  # audit-postgres and audit-rustfs; waits until healthy
./paddock bootstrap audit-bucket      # WORM bucket paddock-audit and the writer credential (idempotent)
```

The bucket has Object Lock with the default retention COMPLIANCE / 400 days; the command refuses an existing bucket
without Object Lock. Run the WORM gate of `docs/operations/audit-bucket.md` section 2 once. For an S3 provider other
than the bundled RustFS, follow `docs/operations/audit-bucket.md` section 1 instead.

## 6. Control plane: OpenBao

```sh
./paddock up --infra                  # infrastructure without the Paddock roles; waits until healthy (OpenBao sealed)
```

Initialize OpenBao with five custodians and PGP-encrypted shares, unseal it with three of them, configure it, and
revoke the root token, as `docs/operations/openbao.md` section 1 describes. The initialization runs where the
custodians' public keys are (`bao operator init … -pgp-keys=…` against the interconnect endpoint); without PGP
encryption (not recommended) `./paddock bao operator init -key-shares=5 -key-threshold=3` does it on the host. Then,
on the control plane:

```sh
./paddock bao operator unseal          # three custodians, one share each; prompts for the share
read -rs BAO_TOKEN && export BAO_TOKEN # the decrypted root token, typed without echo
./paddock bootstrap openbao
./paddock bao token revoke -self
unset BAO_TOKEN
```

The root token stays out of the shell history and off every command line: `./paddock` passes it to the container
by name only.

`./paddock bootstrap openbao` creates the transit keys, the session secret, the policies and the AppRoles and writes
every AppRole's `role_id` and `secret_id` to `.secrets/approle/<role>/`. Copy `.secrets/approle/paddock-audit-writer/`
to the audit host (section 4). OpenBao starts sealed after every restart; three custodians unseal it
(`docs/operations/openbao.md` section 2).

Optionally, a platform administrator can accept automatic unseal in the portal and the host operator then enables the
unsealer with `./paddock auto-unseal enable` (`docs/operations/openbao.md` section 6). **On a production host this is
a residual risk**: whoever controls the host or a copy of its disk can unseal OpenBao and use every key. Record RR-43
(`docs/compliance/residual-risks.md`) in your ISMS before you enable it; `./paddock check` warns on every run while it
is on.

## 7. Control plane: buckets and Fleet

```sh
./paddock bootstrap buckets           # paddock-bundles, paddock-agent-artifacts, paddock-escrow and their users
./paddock bootstrap fleet             # Fleet's admin, the API-only user paddock (.secrets/fleet_api_token), enroll secret
```

Both are idempotent. Fleet's UI is never published; `docs/operations/fleet.md` describes access through an SSH
tunnel.

## 8. Check and start

```sh
./paddock check                       # control plane: every item PASS, else fix and repeat
./paddock check --online              # audit host: also reads the audit bucket's Object Lock
./paddock up                          # control plane first, then the audit host; starts the roles and Prometheus
./paddock ps
```

`./paddock check` runs `paddock-server prod-check` from the server image of `versions.env` over this host's rendered
configuration. It prints one PASS/FAIL line per item and exits 1 on any FAIL. It refuses: `compose.dev.yaml` in the
configuration; `PADDOCK_ENV` other than `production`; development-only variables (`PADDOCK_STEPUP_WINDOW`,
`PADDOCK_STEPUP_MAX_AUTH_AGE`, `PADDOCK_STALENESS_UNIT`, `PADDOCK_RETENTION_UNIT`, `PADDOCK_REAPER_THRESHOLD`, `PADDOCK_OSV_SYNC_INTERVAL`,
`PADDOCK_TEST_*`); `PADDOCK_REVOCATION_ENABLED=true` without `PADDOCK_REVOCATION_ACCEPTED=yes`; a secret file that is
missing, empty or readable by every user of the host (symbolic links resolved; `.secrets/` must stay 0700); a path
below `/run/secrets/` that a service names (in a variable or as the `sslrootcert` of a DSN) without mounting that
secret; 80/443 published by any service but Caddy, or another published port that is not bound to
`PADDOCK_INTERCONNECT_ADDR`; a link between the hosts without TLS; `tls internal` in the Caddyfile or no ACME e-mail;
`caddy/guards.caddy` and `caddy/entrypoint.sh` not mounted next to the Caddyfile, or a Caddyfile that sets
`trusted_proxies` itself; an edge client address configuration that is not consistent (a `/0` trusted proxy, a header
without proxies or proxies without a header, an unknown header name, item `edge client address`); a `/0` in a role's
`PADDOCK_TRUSTED_PROXY_CIDRS`; a Paddock role or Caddy that keeps capabilities (beyond Caddy's `NET_BIND_SERVICE`)
or may gain privileges, or a service without `pids_limit` (item `container hardening`);
`PADDOCK_IP_ALLOWLIST_BYPASS=true` on the api (item `ip allow list bypass is off`);
the development release key (its secret key next to the public key); and, on the audit host with `--online`, an
audit bucket without Object Lock COMPLIANCE of at least 400 days.

Portal sessions are kept in Valkey: while Valkey is unreachable the portal answers 503 `session_store_unavailable`
(devices and API tokens are not affected), and after Valkey is back every session continues. Signing out ends the
session on the server. A platform administrator ends every portal session at once under *Platform* → *Sessions*
(with a step-up), or on the control plane with
`./paddock compose run --rm --no-deps paddock-worker admin end-sessions` when the portal is not usable.

## 9. First platform administrator, first organization, first device

1. Sign in to `https://auth.<domain>/if/admin/` as `akadmin` with the password of
   `.secrets/authentik_bootstrap_password`. Create the platform administrator's user, enroll a WebAuthn
   authenticator for it (step-up requires one) and add it to the group `paddock.platform.admins`. Then deactivate
   `akadmin` or give it a new password held by the custodians.
2. Sign in to `https://admin.<domain>` as the platform administrator (every sign-in asks for the second factor and
   enrols one when missing) and create the first organization (*Platform* → *Organizations*) **with the domains of its
   users** (the create dialog takes them; *Domains* in the list changes them). Without a domain the organization's
   devices get no login management and no managed local administrator. Connect its identity source
   (`docs/operations/identity-sources.md`) and make its first administrator a member of `paddock.<slug>.admins`.
3. Publish the first agent release (section 10).
4. As the organization administrator, **set the break-glass accounts first** (*Login & privileges*: the existing
   local administrator accounts of the devices, `docs/operations/device-login.md`, *Break-glass accounts and sudo*).
   Then create an enrollment token and install the first device with the autoinstall
   (`docs/operations/autoinstall.md`) or the packages under `https://bundles.<domain>/packages/`.
5. Set the IP allow list (optional, recommended): as the platform administrator open *Platform* → *IP allow list*,
   add your own address with *Use my address* first (the server refuses a first entry that would lock you out), then
   the office and VPN ranges. From then on the portal and the admin API are reachable from those ranges only, with
   sessions and API tokens alike. The edge list `PADDOCK_ADMIN_ALLOWED_CIDRS` in `.env` is the second, static layer;
   the runbook for a lockout is in `docs/operations/ip-allowlist.md`.

## 10. First agent release

The agent binaries and packages are not part of the bundle: the release workflow signs `paddockd` and the
`paddock-agent` and `paddock-supervisor` packages and attaches them with their `.minisig` files to the GitHub release;
`paddock-revoke` is attached `-unsigned` and signed offline by the revocation key holders, fleetd is built and signed
by the release manager (`docs/operations/agent-releases.md`). Put them on the control plane in this layout (the
signature covers the content, not the file name, so `paddockd_<version>_linux_amd64` becomes `amd64/paddockd`) and
publish them:

```
<dir>/amd64/paddockd  <dir>/amd64/paddockd.minisig          (and arm64/ when released)
<dir>/paddock-agent_<version>_amd64.deb  (+ .minisig)      paddock-supervisor_…, paddock-revoke_… likewise
<dir>/fleet-osquery_<fleetd version>_amd64.deb  (+ .minisig)
```

```sh
./paddock agent-release <version> <dir>
```

`<dir>` and its files must be readable by the `paddock-api` service (uid 65532): `chmod -R a+rX <dir>`; the command
refuses a directory it cannot read and names the files. It verifies every signature with the release public keys of
`.secrets/release-production/` before anything is stored, uploads the files, publishes the release and prints it as JSON; the release then shows on the portal's
*Agent releases* page, where its staged rollout starts.

## 11. Backups

The control plane's configuration includes `compose.backup.yaml`: pgBackRest for both PostgreSQL databases, OpenBao
snapshots and Fleet dumps, all encrypted, to the backup bucket of `PADDOCK_BACKUP_S3_*` outside this host. Before
section 8, create the bucket and its three credentials as `docs/operations/restore.md` "Backup bucket" describes,
write them to `.secrets/backup_{pgbackrest,worker,fleet}_{access,secret}_key`, and store a copy of
`.secrets/backup_encryption_key` offline with the custodians. After the start check that
`./paddock compose run --rm --no-deps pgbackrest info` lists a full backup. The restore runbook and the quarterly
restore drill are in the same document.

## 12. Upgrade

Upgrades extract the new bundle next to the running one and take over its `.env` and `.secrets/`:
`docs/operations/upgrade.md`. Agent releases are separate: `docs/operations/agent-releases.md`.

**Release 0.1.0-alpha.4 and later: second factor on every sign-in.** After this upgrade every Authentik sign-in — the portal, Authentik's own user and admin interfaces (`akadmin` included) and
the device approval page — asks for a second factor and enrols one when missing.

**Release with the managed-file path tiers, server-side sessions and WebAuthn-only step-up (ADR 0034).** Four steps,
in this order:

1. **Before the upgrade, every administrator enrols a WebAuthn authenticator** (security key or platform
   authenticator) in Authentik's user settings, `https://auth.<domain>/if/user/` → MFA devices. From this release
   the step-up accepts WebAuthn only; an administrator with TOTP only can still sign in but cannot reveal keys, lock or
   destroy devices, create API tokens or grant root-equivalent rights (`docs/operations/step-up.md`). The same
   applies to every administrator added later.
2. **Agents first, then the server.** From this release on the server no longer ships managed files on denied paths.
   An agent of this release keeps such a file on the device unchanged and stops tracking it (`left_denied_file`); an
   agent older than this release deletes every unchanged file that leaves its bundle, so it would delete those files
   at its next check-in after the server upgrade, without any operator action. Before you upgrade the control plane,
   upload the agent release of the new version to the running server and roll it out to every device
   (`docs/operations/agent-releases.md`); upgrade the server only when no device runs an older agent. A device that is
   offline during the rollout and returns after the server upgrade with an older agent loses its unchanged files on
   denied paths (residual risk RR-36).
3. **Upgrade the server; every administrator signs in again.** Portal sessions now also live in Valkey, and the
   session cookies of earlier versions are no longer accepted. While Valkey is unreachable the portal answers 503
   `session_store_unavailable`; devices and API tokens are not affected (residual risk RR-35).
4. **Run the security review once** on the control plane:

   ```sh
   ./paddock compose run --rm --no-deps paddock-worker admin security-review
   ```

   It prints one line per organization (`<slug>: root_grants=<n> sensitive_files=<n> denied_files=<n>`) and records
   `organization.security_review_required` in every organization with something to review. Organization
   administrators then open the banner on the overview (`/security-review`): they confirm existing root grants and
   files on sensitive paths with a step-up, and delete the definitions on denied paths they no longer need. Root
   grants and files on sensitive paths keep working while they await review. Files on denied paths are no longer
   shipped; they stay on the devices unchanged only on agents of this release or newer (step 2). Operators manage
   files without a step-up only below the organization's operator roots, which are empty after the upgrade; an
   organization administrator sets them in the portal under *Configuration* → *Operator roots* (residual risk RR-37).

## 13. Residual risks you must record in your ISMS

Paddock leaves risks that only your organization can accept, mitigate or transfer, for example the young WORM
implementation of the bundled RustFS (ADR 0017) and the custody of the OpenBao unseal shares. Record each risk of
`docs/compliance/residual-risks.md` in your ISMS's risk register with an owner and a decision. Among them: the step-up
factor is enforced by Authentik only, because the ID token's `amr` does not tell WebAuthn from TOTP (RR-38).

## Appendix: installing from source

Without a published release (for example to test a branch), build the images and a local bundle on a machine with
the repository, Docker and Go, then copy the bundle to the hosts:

```sh
make image image-compiler image-pgbackrest      # paddock-server:dev, paddock-compiler:dev, paddock-pgbackrest:dev
make bundle                                     # dist/bundle/paddock-deploy-0.0.0-local.tar.gz (RELEASE_VERSION=… names it)
```

Load the three images on the hosts (`docker save … | ssh <host> docker load`, or push them to your registry and set
the image variables in `.env`) and follow the sections above with the local bundle. A local bundle references the
images by tag only, without digests, and carries no signature: `./paddock verify` checks the files, nothing checks
their origin.
