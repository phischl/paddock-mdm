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

Every command except `version`, `verify` and `migrate-from` needs `.env` (copied from `.env.example`) with
`PADDOCK_ENV=production` and `PADDOCK_HOST=controlplane` or `PADDOCK_HOST=audit`. A single-host lab behind your own
TLS proxy copies `.env.lab.example` instead and runs with `PADDOCK_HOST=lab` (not for production;
`docs/operations/lab-install.md`); there every command of both hosts applies, and `check` and `up` begin with a warning
line.

| Command | Purpose |
| --- | --- |
| `./paddock version` | Prints `VERSION`. |
| `./paddock verify` | Checks every shipped file against `SHA256SUMS`. |
| `./paddock secrets` | Generates this host's secrets into `.secrets/` (idempotent, prints file names only). |
| `./paddock pull` | Pulls every image of this host. |
| `./paddock check [--online]` | Production checklist of this host's configuration; exit code 0 only when every item passes. `--online` (audit or lab host) also reads the audit bucket's Object Lock. |
| `./paddock up [--infra]` | Starts the stack and waits until every service is healthy; `--infra` starts the infrastructure only (before the bootstrap). |
| `./paddock down [--volumes]` | Stops the stack; `--volumes` also deletes all data. |
| `./paddock ps`, `./paddock logs [service…]` | Service list, last log lines. |
| `./paddock compose <args…>` | `docker compose` with this host's files and project. |
| `./paddock bao <args…>` | The `bao` CLI inside the OpenBao container (control plane, lab); `BAO_TOKEN` is passed on when set. |
| `./paddock bootstrap openbao` | Configures an initialized and unsealed OpenBao (needs `BAO_TOKEN`). |
| `./paddock bootstrap buckets` | Creates the control plane's buckets and credentials. |
| `./paddock bootstrap audit-bucket` | Creates the WORM audit bucket (audit host, lab). |
| `./paddock bootstrap fleet` | Sets up Fleet and its API token (control plane, lab). |
| `./paddock agent-release <version> <dir>` | Uploads and publishes the signed agent artifacts of a release (control plane, lab). |
| `./paddock migrate-from <old dir>` | Copies `.env` and `.secrets/` from the bundle directory of the running version (upgrade). |

Keep local settings in `.env`; never edit the shipped files (`./paddock verify` would report them, and an upgrade
replaces them). To pull the Paddock images from a mirror, set `PADDOCK_IMAGE`, `PADDOCK_COMPILER_IMAGE` and
`PADDOCK_PGBACKREST_IMAGE` in `.env`.

## Agent packages

The agent packages (`paddockd`, the Debian packages and their `.minisig` signatures) are not part of this bundle. The
release workflow signs `paddockd`, `paddock-agent` and `paddock-supervisor` and attaches them to the GitHub release of
this version; `paddock-revoke` is attached unsigned and must be signed offline before use:
<https://github.com/phischl/paddock-mdm/releases>. Upload them with `./paddock agent-release`.
