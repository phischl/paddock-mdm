# Production installation

How to install Paddock on two hosts with public TLS and without development shortcuts (plan M6a, architecture §4.1,
ADR 0016). The development stack (`make up`, `docs/operations/local-dev.md`) is a different thing: never use
`compose.dev.yaml`, `make dev-secrets`, `make bao-bootstrap` or `make dev-seed` in production.

| Host | Compose files | Runs |
| --- | --- | --- |
| Control plane | `compose.yaml` + `compose.backup.yaml` + `compose.prod.yaml` | Caddy, the Paddock roles, PostgreSQL, RabbitMQ, Valkey, OpenBao, RustFS (bundles, escrow, artifacts), Authentik, Fleet |
| Audit domain | `compose.audit.yaml` + `compose.audit.prod.yaml` | audit writer, audit PostgreSQL, RustFS with the WORM audit bucket |

The audit domain has its own credentials (separation of duties). The control plane holds only RabbitMQ's publish
credential for audit events and the read-only audit database role; it holds nothing for the audit bucket.

## 1. Host requirements

- Two Linux hosts (amd64) with Docker Engine and the Compose plugin ≥ 2.24 (`!override`/`!reset` tags), `make`,
  `git` and `openssl`. Go is not needed: `make prod-check` runs in the pinned Go image.
- Control plane: 4 vCPU, 16 GB RAM, 100 GB disk for 100 devices. Audit domain: 2 vCPU, 4 GB RAM, disk for 400 days
  of audit evidence (about 1 GB per 100 devices and year).
- A **private interconnect** between the hosts (VPN such as WireGuard, or a private network), each host with a fixed
  address on it. Only these endpoints are published there, all with TLS from the internal CAs:
  - control plane → audit host: RabbitMQ `amqps` 5671 (the audit writer consumes), OpenBao 8200 (the audit writer
    signs the daily manifests);
  - audit host → control plane: PostgreSQL 5432 (the api's read-only audit view, `sslmode=verify-full`).
- The control plane is reachable from the internet on 80 (ACME HTTP-01, redirect) and 443. Nothing else is published;
  `make prod-check` refuses any other published port that is not bound to the interconnect address.
- An S3 bucket for backups **outside the control-plane host** (section 9).
- Outbound HTTPS from the control plane (allow it in the host's firewall): the ACME CA (Caddy), Ubuntu's OSV feed
  `https://osv-vulnerabilities.storage.googleapis.com` (`paddock-worker`, daily; without it the alert
  `PaddockOSVStale` fires after 3 days, and `docs/operations/vulnerability-data.md` describes the offline import),
  Fleet's vulnerability feeds (`fleet`), the backup S3 endpoint, and the identity sources Authentik connects to.

## 2. DNS

Point these names at the control-plane host's public address. Caddy requests one certificate per name from a public
ACME CA as soon as it starts.

| Name | Serves | Exposure |
| --- | --- | --- |
| `admin.<domain>` | portal and admin API | SHOULD be restricted (`PADDOCK_ADMIN_ALLOWED_CIDRS` or a VPN) |
| `auth.<domain>` | Authentik (portal login, device logins) | internet |
| `device.<domain>` | device API (gateway) | internet |
| `bundles.<domain>` | presigned bundle downloads, agent packages, header uploads | internet |
| `fleet.<domain>` | osquery and fleetd endpoints only | internet |

## 3. Configuration and secrets

On **each** host, as the operator who runs Compose:

```sh
git clone https://github.com/phischl/paddock-mdm.git && cd paddock-mdm && git checkout <release tag>
make prod-secrets HOST=audit          # on the audit host; HOST=controlplane on the control plane
```

The first run copies `deploy/compose/prod.env.example` to `deploy/compose/.env` and stops. Set the domain, the ACME
e-mail, `PADDOCK_INTERCONNECT_ADDR` (this host's own interconnect address), `PADDOCK_CONTROLPLANE_ADDR` and
`PADDOCK_AUDIT_ADDR`, then run it again. It writes random secrets and this host's internal CA with its TLS
certificates into `deploy/compose/.secrets/` (directory mode 0700) and prints file names only, never a secret.
Running it again never overwrites a file.

Exchange these files between the hosts over a secure channel (for example `scp` over the interconnect), then run
`make prod-secrets` again on both hosts:

| File in `deploy/compose/.secrets/` | From | To |
| --- | --- | --- |
| `db_paddock_audit_reader_password` | audit host | control plane (builds `db_paddock_audit_reader_url`) |
| `rabbitmq_audit_writer_password` | control plane | audit host |
| `internal-ca/ca.crt` | each host | the other host, as `internal-ca/peer-ca.crt` (public; `bundle.crt` then trusts both) |

Copy the production release public keys (`docs/operations/agent-releases.md`, "Production key") to
`.secrets/release-production/minisign.pub` and `.secrets/release-production/revoke-minisign.pub` on the control
plane. Their secret keys never come to a server.

Build or pull the images: `make image image-compiler`, or set `PADDOCK_IMAGE` and `PADDOCK_COMPILER_IMAGE` in `.env`
to your registry's images (tag and digest).

Define a shell helper per host for the commands below:

```sh
# control plane
pc() { docker compose --project-directory deploy/compose -p paddock --env-file deploy/compose/versions.env \
  --env-file deploy/compose/.env -f deploy/compose/compose.yaml -f deploy/compose/compose.backup.yaml \
  -f deploy/compose/compose.prod.yaml "$@"; }
# audit host
pa() { docker compose --project-directory deploy/compose -p paddock --env-file deploy/compose/versions.env \
  --env-file deploy/compose/.env -f deploy/compose/compose.audit.yaml -f deploy/compose/compose.audit.prod.yaml "$@"; }
```

## 4. Audit host

1. Start the stores: `pa up -d audit-postgres audit-rustfs`.
2. Create the WORM audit bucket and the writer credential once, exactly as `docs/operations/audit-bucket.md` section 1
   describes, and run the WORM gate of its section 2. Write the writer's keys to
   `.secrets/rustfs_audit_writer_access_key` and `.secrets/rustfs_audit_writer_secret_key`.
3. `make prod-check HOST=audit ONLINE=1` must pass every item except the AppRole files, which section 5 fills.

## 5. Control plane: OpenBao

1. Start the infrastructure: `pc up -d` (the Paddock roles have the profile `paddock` and do not start yet).
2. Initialize OpenBao with five custodians and configure keys, policies and AppRoles as `docs/operations/openbao.md`
   section 1 describes, with `BAO_ADDR=https://<control-plane interconnect address>:8200` and
   `BAO_CACERT=deploy/compose/.secrets/internal-ca/bundle.crt`.
3. Write each AppRole's role ID and secret ID to `.secrets/approle/<role>/role_id` and `secret_id` on the host of
   the role: `paddock-audit-writer` on the audit host, the others on the control plane.
4. Revoke the root token.

OpenBao starts sealed after every restart; three custodians unseal it (`docs/operations/openbao.md` section 2).

## 6. Control plane: buckets and Fleet

1. Create the buckets `paddock-bundles`, `paddock-agent-artifacts` (anonymous read on `packages/`) and
   `paddock-escrow` (versioned) with the credentials of `.secrets/rustfs_*`, as
   `deploy/compose/scripts/rustfs-bundles-bootstrap.sh` does in development (it refuses to run in production; follow
   its commands with the production credentials).
2. Set up Fleet as `docs/operations/fleet.md` "Bootstrap" describes and write the API-only user's token to
   `.secrets/fleet_api_token`.

## 7. Check and start

```sh
make prod-check HOST=controlplane          # every item PASS, else fix and repeat
pc --profile paddock --profile observability up -d   # monitoring: docs/operations/monitoring.md
make prod-check HOST=audit ONLINE=1        # on the audit host
pa --profile paddock --profile observability up -d
```

`make prod-check` prints one PASS/FAIL line per item and exits 1 on any FAIL. It refuses: `compose.dev.yaml` in the
configuration; `PADDOCK_ENV` other than `production`; development-only variables (`PADDOCK_STEPUP_WINDOW`,
`PADDOCK_STEPUP_MAX_AUTH_AGE`, `PADDOCK_STALENESS_UNIT`, `PADDOCK_REAPER_THRESHOLD`, `PADDOCK_OSV_SYNC_INTERVAL`,
`PADDOCK_TEST_*`); `PADDOCK_REVOCATION_ENABLED=true` without `PADDOCK_REVOCATION_ACCEPTED=yes`; a secret file that is
missing, empty or readable by every user of the host; a published port other than 80/443 that is not bound to
`PADDOCK_INTERCONNECT_ADDR`; a link between the hosts without TLS; `tls internal` in the Caddyfile or no ACME e-mail;
the development release key (its secret key next to the public key, or the key of `make dev-release-key`); and, on the
audit host with `ONLINE=1`, an audit bucket without Object Lock COMPLIANCE of at least 400 days.

## 8. First platform administrator, first organization, first device

1. Sign in to `https://auth.<domain>/if/admin/` as `akadmin` with the password of
   `.secrets/authentik_bootstrap_password`. Create the platform administrator's user, enroll a WebAuthn
   authenticator for it (step-up requires one) and add it to the group `paddock.platform.admins`. Then deactivate
   `akadmin` or give it a new password held by the custodians.
2. Sign in to `https://admin.<domain>` as the platform administrator and create the first organization (*Platform* →
   *Organizations*), with the e-mail domains of its users. Connect its identity source
   (`docs/operations/identity-sources.md`) and make its first administrator a member of `paddock.<slug>.admins`.
3. As the organization administrator, create an enrollment token and install the first device with the autoinstall
   (`docs/operations/autoinstall.md`) or the packages under `https://bundles.<domain>/packages/`.

## 9. Backups

The control plane's configuration includes `compose.backup.yaml`: pgBackRest for both PostgreSQL databases, OpenBao
snapshots and Fleet dumps, all encrypted, to the backup bucket of `PADDOCK_BACKUP_S3_*` outside this host. Before
section 7, create the bucket and its three credentials as `docs/operations/restore.md` "Backup bucket" describes,
write them to `.secrets/backup_{pgbackrest,worker,fleet}_{access,secret}_key`, and store a copy of
`.secrets/backup_encryption_key` offline with the custodians. After the start check that `pc run --rm --no-deps
pgbackrest info` lists a full backup. The restore runbook and the quarterly restore drill are in the same document.

## 10. Upgrade procedure

1. Read the release notes (`CHANGELOG.md`) for steps that the release needs.
2. Take a backup of both PostgreSQL databases and an OpenBao snapshot (`docs/operations/restore.md`) and check that
   it is in the backup bucket.
3. `git fetch && git checkout <new release tag>`, then build or pull the new images.
4. `make prod-check` on both hosts.
5. Control plane: `pc --profile paddock --profile observability up -d`. `paddock-migrate` applies the database migrations before the roles
   start; migrations only move forward. Audit host: `pa --profile paddock --profile observability up -d`.
6. Watch the roles' readiness (`pc ps`) and the alerts (`docs/operations/monitoring.md`).

Agent releases are separate: `docs/operations/agent-releases.md`.

## 11. Residual risks you must record in your ISMS

Paddock leaves risks that only your organization can accept, mitigate or transfer, for example the young WORM
implementation of the bundled RustFS (ADR 0017) and the custody of the OpenBao unseal shares. Record each risk of
`docs/compliance/residual-risks.md` in your ISMS's risk register with an owner and a decision.
