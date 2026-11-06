# Paddock deployment bundle @VERSION@

@CHANNEL_NOTICE@

This directory installs and runs one host of a Paddock installation with Docker Compose: the control-plane host or the
audit host. It holds the Compose files, their configuration, the bootstrap scripts and the entry script `./paddock`.
The Paddock images are pulled from `@REGISTRY@` by tag and digest (`versions.env`); nothing is built on the host, and
neither `git` nor `make` is needed.

Read the installation guide of this version before you start:
<https://github.com/phischl/paddock-mdm/blob/@DOCS_REF@/docs/operations/install.md>. Upgrades follow
<https://github.com/phischl/paddock-mdm/blob/@DOCS_REF@/docs/operations/upgrade.md>.

## Verify the download

Verify the tarball's keyless signature before you extract it (in the directory with both downloaded files):

```sh
docker run --rm -v "$PWD:/w" -w /w @COSIGN_IMAGE@ verify-blob paddock-deploy-@VERSION@.tar.gz \
  --bundle paddock-deploy-@VERSION@.tar.gz.sigstore.json \
  --certificate-identity-regexp '@IDENTITY@' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

After extracting, `./paddock verify` checks that no shipped file has changed. Verify the signature of an image the
same way (the reference with digest is in `versions.env`):

```sh
docker run --rm @COSIGN_IMAGE@ verify "$(sed -n 's/^PADDOCK_IMAGE=//p' versions.env)" \
  --certificate-identity-regexp '@IDENTITY@' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

## Commands

Every command except `version`, `verify`, `migrate-from`, `upgrade-check` and `upgrade` needs `.env` (copied from `.env.example`) with
`PADDOCK_ENV=production` and `PADDOCK_HOST=controlplane` or `PADDOCK_HOST=audit`. A single-host lab behind your own
TLS proxy copies `.env.lab.example` instead and runs with `PADDOCK_HOST=lab` (not for production;
`docs/operations/lab-install.md`); there every command of both hosts applies, and `check` and `up` begin with a warning
line.

| Command | Purpose |
| --- | --- |
| `./paddock version` | Prints `VERSION`. |
| `./paddock verify` | Checks every shipped file against `SHA256SUMS`. |
| `./paddock secrets` | Generates this host's secrets into `.secrets/` (idempotent, prints file names only). |
| `./paddock pull [service...]` | Pulls every image of this host that is not already present locally by its reference (tag and digest), so images loaded with `docker load` are kept; with services, pulls those services always. |
| `./paddock check [--online]` | Production checklist of this host's configuration; exit code 0 only when every item passes. `--online` also reads the audit bucket's Object Lock (audit or lab host) and warns when `compose.backup-targets.yaml` is older than the targets in the database (host with backups). |
| `./paddock up [--infra]` | Starts the stack and waits until every service is healthy; `--infra` starts the infrastructure only (before the bootstrap). |
| `./paddock down [--volumes]` | Stops the stack; `--volumes` also deletes all data. |
| `./paddock ps`, `./paddock logs [service…]` | Service list, last log lines. |
| `./paddock compose <args…>` | `docker compose` with this host's files and project. `compose config` (and its alias `convert`) refuses to print while `compose.backup-targets.yaml` is part of the files: Compose would print the SMB passwords. |
| `./paddock bao <args…>` | The `bao` CLI inside the OpenBao container (control plane, lab); `BAO_TOKEN` is passed on when set. |
| `./paddock bootstrap openbao` | Configures an initialized and unsealed OpenBao (needs `BAO_TOKEN`). |
| `./paddock bootstrap buckets` | Creates the control plane's buckets and credentials. |
| `./paddock bootstrap audit-bucket` | Creates the WORM audit bucket (audit host, lab). |
| `./paddock bootstrap fleet` | Sets up Fleet and its API token (control plane, lab). |
| `./paddock backup-target apply` | Mounts the local, SMB and NFS backup targets saved in the portal as Docker volumes of `paddock-backup` (control plane, lab with `PADDOCK_LAB_BACKUP=yes`), then run `./paddock up`. Writes `compose.backup-targets.yaml` (mode 0600, it holds the share passwords: never copy, commit or print it; `migrate-from` moves it to a new version), tries every mount before it replaces the previous file, and removes the volumes of changed and deleted targets once they are unused. A local target is a directory below `PADDOCK_BACKUP_LOCAL_ROOT`, writable by uid 999; every parent root-owned and not writable by group or others. An SMB password with a comma or whitespace is refused when the target is saved, and by `apply` for one saved earlier: choose another password for the share. A mount error shows the password as `<redacted>` and keeps Docker's reason (for example `permission denied`). After `apply` the portal shows a target `mounted` once its share accepts the new settings; `paddock-backup` uses them after `./paddock up`. Refused while a restore plan runs. |
| `./paddock backup now [--kind k]… [--label l] [--wait]`, `./paddock backup status` | Requests a backup run of every kind (or the named ones) without the portal; `--wait` follows it and exits non-zero naming a failed kind. `status` prints the key, the newest run per kind and the targets. |
| `./paddock agent-release <version> <dir>` | Uploads and publishes the signed agent artifacts of a release (control plane, lab). |
| `./paddock migrate-from <old dir>` | Copies `.env`, `.secrets/` and, when present, `compose.backup-targets.yaml` (mode and owner kept) from the bundle directory of the running version (upgrade); refuses to overwrite any of them. |
| `./paddock upgrade-check <old dir> [--json]` | Read-only check, run in this (new) directory before `migrate-from`: old bundle intact, adjacent release, release notes, missing `.env` keys, secrets, disk, images, the old stack's server report, unseal path, stack health. PASS/WARN/FAIL table, or `{items, exit}` as JSON; exit 0 without FAIL, 1 with, 2 on usage. Changes nothing. |
| `./paddock upgrade <old dir> [--yes] [--allow-unsupported-agents] [--skip-backup]` | Upgrade from the running version, in this (new) directory: `upgrade-check` (stops on FAIL; `--allow-unsupported-agents` accepts only the agents FAIL), the plan and a typed `yes` (unless `--yes`), `migrate-from`, `secrets`, `pull`, `check`, `backup now --label pre-upgrade-<version> --wait` in the old directory (control plane, lab with backups; `--skip-backup` only when the release notes say `Schema: unchanged` and Fleet's image stays), on the audit host or lab with audit migrations the old audit writer stopped, `up`, `bootstrap openbao` when `BAO_TOKEN` is set, post-checks. Every step prints its command; a failed run keeps `.upgrade-state` and the next run continues at the failed step. `.upgrade-rollback` keeps the rollback point, bound to this attempt. A lab host without backups needs `--skip-backup` for a schema or Fleet change. From 0.1.0-alpha.8, which has no `backup now`, the backup step runs that release's own backup through its `./paddock compose` instead (pgBackRest `backup --start-fast` for both stanzas, `paddock-worker backup openbao`, `fleet-backup once`), checks all four in the backup bucket and records their names; right before `up` it stops that release's `pgbackrest` and `pgbackrest-authentik` and flushes both spools, so the bucket's WAL archive ends before the new release migrates. |
| `./paddock rollback <old dir> [--yes]` | Back to the version of `<old dir>`: `down` here; when this release's notes say `Schema: migrations …` (control plane, lab with backups), the restore of postgres, OpenBao, escrow and, when `FLEET_IMAGE` changed, Fleet from the local backup repository to the point just before the upgrade's `up`, with the old release's `restore.sh` (the legacy key file of the old directory, else the key is asked for); then `up` in `<old dir>`. Asks for `yes` and says that every change after that point is lost; the restore's preflight and its `restore` question (unless `--yes`) come before anything stops. The rollback point holds only for the upgrade attempt that recorded it and is retired after a successful rollback, so a second rollback is refused. A later upgrade from this directory supersedes its rollback point (`.upgrade-rollback.superseded-by-<version>`), and the rollback refuses unless the running Paddock containers carry this release's version label. The audit host and `Schema: unchanged` roll back with `down` and the old `up` only. To 0.1.0-alpha.8, the restore is that release's own procedure from the backup bucket (its `docs/operations/restore.md`): before anything stops, it checks that both directories name the same Compose project (`PADDOCK_PROJECT`), that the newest backup of each stanza is the recorded one and downloads and decrypts the recorded OpenBao snapshot and Fleet dump; then PostgreSQL to the newest WAL archived before the upgrade's fence, OpenBao into a fresh instance (unsealed by the custodians or the automatic unseal), Fleet's database when `FLEET_IMAGE` changed, and the restore commands. |

Keep local settings in `.env`; never edit the shipped files (`./paddock verify` would report them, and an upgrade
replaces them). To pull the Paddock images from a mirror, set `PADDOCK_IMAGE`, `PADDOCK_COMPILER_IMAGE` and
`PADDOCK_PGBACKREST_IMAGE` in `.env`.

## Agent packages

The agent packages (`paddockd`, the Debian packages and their `.minisig` signatures) are not part of this bundle. The
release workflow signs `paddockd`, `paddock-agent` and `paddock-supervisor` and attaches them to the GitHub release of
this version; `paddock-revoke` is attached unsigned and must be signed offline before use:
<https://github.com/phischl/paddock-mdm/releases>. Upload them with `./paddock agent-release`.
