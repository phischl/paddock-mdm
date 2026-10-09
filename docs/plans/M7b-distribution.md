# Implementierungsplan: M7b — Distribution: published images and the operator bundle

Status: Ready for implementation (after M6b; independent of M7a, see §2.9) · 2026-10-09 · Author: architect
Basis: architecture v1.7 §4.1 (two-host topology), §20 (backup), §21 (version compatibility), §23 (repository
layout); ADR 0013, 0016; plan M6a (production overlays, `prod-check`, `prod-secrets`), plan M6b decision 4 (release
workflow, cosign keyless, SBOM); design contract 5 (signed artifacts), 9 (static binary); CLAUDE.md "General"

Binding language: **MUST** / **MUST NOT** / **SHOULD** / **MAY**.

## 1. Goal

An operator installs and upgrades Paddock without cloning the repository or building anything: the three Paddock
images are published on `ghcr.io/phischl/` for every release and for every green commit on `main` (edge), signed
keylessly with an SBOM attestation, and a self-contained bundle `paddock-deploy-<version>.tar.gz` (Compose files,
configuration, scripts, one entry script `./paddock`, a README) references them by tag **and** digest. The repository's
development stack keeps building from source from the same Compose definitions; a test proves there is no drift.

## 2. Context

- `deploy/compose/` holds one set of Compose files used by both the development stack (`make up`:
  `compose.yaml` + `compose.audit.yaml` + `compose.dev.yaml`, optionally the backup files) and production (control
  plane: `compose.yaml` + `compose.prod.yaml` + `compose.backup.yaml`; audit host: `compose.audit.yaml` +
  `compose.audit.prod.yaml`). The Paddock services are declared with `image: ${PADDOCK_IMAGE:-paddock-server:dev}`
  **and** a `build:` section inside the anchors `x-paddock` (`compose.yaml`), `&paddock-audit` (`compose.audit.yaml`)
  and `&pgbackrest` (`compose.backup.yaml`). Third-party images come from `versions.env` as tag plus digest.
- The release workflow (`.github/workflows/release.yml`, plan M6b decision 4) builds `paddock-server` and
  `paddock-compiler` for amd64 only, pushes them, signs them with cosign keyless and attaches an SPDX SBOM. The
  pgBackRest image (`deploy/compose/pgbackrest/Dockerfile`, `make image-pgbackrest`) is built locally only.
- The portal is embedded into the `paddock-server` binary (Dockerfile stage `web` → `server/web/dist/` →
  `go build`); there is no portal image.
- `make prod-secrets HOST=…` and `make prod-check HOST=… [ONLINE=1]` are the only production entry points; the
  bootstrap scripts of `deploy/compose/scripts/` refuse production (`require_development`, plan M0 decision 20), so
  `docs/operations/install.md` describes OpenBao, buckets and Fleet as manual command sequences.
- `paddock-server prod-check` (`server/internal/prodcheck/`) reads `docker compose config --format json` from stdin
  and checks files on the host paths Compose resolved (secret files, the mounted Caddyfile); it needs those paths
  visible where it runs. `server/internal/prodcheck/compose_test.go` renders the real production configurations and
  reads the file lists from the Makefile variables `PROD_FILES_controlplane` and `PROD_FILES_audit`.
- Agent binaries and Debian packages are signed **offline** with minisign (`docs/operations/agent-releases.md`); the
  release workflow attaches them as `-unsigned` files to a draft release. The platform API
  (`/api/platform/v1/agent-releases/…`) is the only upload path; it needs a platform administrator's session.
- Third-party image facts checked on 2026-10-09 with `docker buildx imagetools inspect`: every pinned image of
  `versions.env` is a multi-platform index with `linux/amd64` and `linux/arm64` **except** `fleetdm/fleet:v4.92.3`
  and `fleetdm/fleetctl:v4.92.3`, which are amd64-only single manifests.
- GitHub facts: new GHCR packages are **private** by default even when pushed from a public repository with
  `GITHUB_TOKEN`; visibility is changed once per package in the package settings (no API). `ubuntu-24.04-arm` runners
  are free for public repositories.

## 3. Binding decisions

### 3.1 Image set and platforms

1. Paddock publishes exactly three images, all built from this repository:

   | Image | Dockerfile / target | Content |
   | --- | --- | --- |
   | `ghcr.io/phischl/paddock-server` | `deploy/compose/Dockerfile`, final stage | `paddock-server` with the embedded portal; every role but the compiler; `prod-check`; `admin …` |
   | `ghcr.io/phischl/paddock-compiler` | `deploy/compose/Dockerfile`, target `compiler` | the same binary on Debian with `visudo` |
   | `ghcr.io/phischl/paddock-pgbackrest` | `deploy/compose/pgbackrest/Dockerfile` | pgBackRest for the backups (plan M6a decision 4) |

   Every other image (postgres, rabbitmq, valkey, openbao, authentik, caddy, rustfs, rc, fleet, fleetctl, mysql,
   aws-cli, prometheus) stays upstream and pinned by digest in `versions.env`.
2. Every Paddock image is built with `docker buildx` for `linux/amd64` **and** `linux/arm64` as one multi-platform
   index. `deploy/compose/Dockerfile` MUST cross-compile: stages `web` and `build` run on `$BUILDPLATFORM`
   (`FROM --platform=$BUILDPLATFORM …`), `build` declares `ARG TARGETOS TARGETARCH` and runs
   `GOOS=$TARGETOS GOARCH=$TARGETARCH go build …`. The `compiler` stage and the pgBackRest image run `apt-get` under
   QEMU for arm64 (`docker/setup-qemu-action` in the workflow). Justification: the Go build is free to cross-compile,
   the agent already ships arm64, and the audit host can run on arm64 today.
3. The **control-plane host is amd64-only** in this milestone because Fleet's image is amd64-only. `./paddock up`
   on a host with `PADDOCK_HOST=controlplane` and `uname -m` ≠ `x86_64` MUST refuse with the message
   `the control plane needs an amd64 host: the Fleet image (fleetdm/fleet) is published for linux/amd64 only`.
   `docs/operations/install.md` "Host requirements" states it. The audit host MAY be arm64; the smoke test of §3.6
   covers amd64 only (open point 2).

### 3.2 Tags, channels and labels

4. Stable releases (tag `v<major>.<minor>.<patch>`, exactly as today's `release-check` regex) push every image with
   the tags `<version>`, `<major>.<minor>` and, **only when `<version>` is the highest stable version among all
   `v*` tags of the repository** (`git tag --list 'v*' | sed 's/^v//' | sort -V | tail -1`), `latest`.
5. The edge channel publishes from every **green** commit on `main` (the edge job of `ci.yml` runs after the
   acceptance job, open point 3) with the tags `edge` and `edge-<yyyymmdd>-<sha7>` (`sha7` = the first seven
   characters of the commit). Edge images MUST NOT carry `latest`, `<major>.<minor>` or a semver tag. The version
   string of an edge build is `edge-<yyyymmdd>-<sha7>` everywhere (OCI label, bundle name, `VERSION` file).
6. OCI labels on every image (set in `make release-images`, not in the Dockerfile, because they vary per build):
   `org.opencontainers.image.source=https://github.com/phischl/paddock-mdm`,
   `org.opencontainers.image.url=https://github.com/phischl/paddock-mdm`,
   `org.opencontainers.image.documentation=https://github.com/phischl/paddock-mdm/blob/main/docs/operations/install.md`,
   `org.opencontainers.image.title=<image name without registry>`,
   `org.opencontainers.image.description=<one sentence per image, from the table of decision 1>`,
   `org.opencontainers.image.version=<version string>`, `org.opencontainers.image.revision=<full commit sha>`,
   `org.opencontainers.image.created=<RFC 3339 UTC>`, `org.opencontainers.image.licenses=MIT`,
   `org.opencontainers.image.vendor=Paddock`, `io.paddock.channel=stable|edge`.
7. **Signing and SBOM for every image, stable and edge:** `cosign sign --yes --recursive <repo>@<index digest>`
   (signs the index and every platform manifest), one SPDX SBOM per image and platform
   (`<name>_<version>_linux_<arch>.spdx.json`, produced by syft from the registry with `--platform`), attached with
   `cosign attest --yes --type spdxjson --predicate <file> <repo>@<platform manifest digest>`. Keyless through the
   workflow's GitHub OIDC identity as today. Operators verify with the identity
   `^https://github.com/phischl/paddock-mdm/\.github/workflows/release\.yml@refs/tags/v` (stable) or
   `^https://github.com/phischl/paddock-mdm/\.github/workflows/ci\.yml@refs/heads/main$` (edge) and the issuer
   `https://token.actions.githubusercontent.com`.
8. **Public visibility** is a one-time manual step of the product owner per package (three packages), done after the
   first edge run has created them (open point 5). The smoke job pulls **without** a registry login, so a private
   package fails the gate with the pull error; the job is re-run after the visibility change.
9. **Edge retention:** a weekly workflow `ghcr-prune.yml` (architect; `packages: write`) runs our own script
   `deploy/bundle/ci/prune-edge.sh` (§6.7) for the three packages. No third-party action. The script lists the
   package versions with `gh api --paginate /user/packages/container/<name>/versions`, and deletes
   (`gh api -X DELETE /user/packages/container/<name>/versions/<id>`) every version whose tag set is non-empty,
   consists only of tags matching `^edge-[0-9]{8}-[0-9a-f]{7}$`, and whose `created_at` is older than 30 days. It
   keeps every version that carries the moving tag `edge`, `latest`, or any tag matching `^[0-9]+\.[0-9]+(\.[0-9]+)?$`
   (a release), and every untagged version (platform manifests and cosign signature/attestation manifests of kept
   indexes are untagged or carry `sha256-…` tags; they are never touched). `--dry-run` prints what it would delete
   and deletes nothing; the workflow runs the dry run first and then the real run in the same job. A unit test
   (`prune-edge_test.sh`, `make test`) runs the selection logic against recorded JSON fixtures.

### 3.3 The operator bundle

10. **Copy, do not transform.** The bundle is a copy of the production subset of `deploy/compose/` plus the files of
    `deploy/bundle/`. No YAML is rewritten. To make that possible, every `build:` section moves out of the production
    files: `compose.yaml` and `compose.audit.yaml` keep `image: ${PADDOCK_IMAGE:-paddock-server:dev}` (compiler:
    `${PADDOCK_COMPILER_IMAGE:-paddock-compiler:dev}`, pgBackRest: `${PADDOCK_PGBACKREST_IMAGE:-paddock-pgbackrest:dev}`)
    and lose `build:`; `compose.dev.yaml` gains the `build:` sections of the seven `paddock-*` services of
    `compose.yaml`, the compiler's (target `compiler`) and the two audit services; `compose.backup.dev.yaml` gains the
    pgBackRest build for `pgbackrest` and `pgbackrest-authentik`. YAML anchors inside the dev files keep this short.
    `make up` and `make up BACKUP=1` keep building from source (`--build` is already passed).
11. **Layout** of `paddock-deploy-<version>/` (the extracted bundle; the directory is the Compose project directory):

    ```
    paddock-deploy-<version>/
    ├── README.md                    # from deploy/bundle/README.md
    ├── VERSION                      # version=<v>\nchannel=stable|edge\ncommit=<sha>\nbuilt=<RFC 3339 UTC>\n
    ├── paddock                      # entry script, mode 0755, from deploy/bundle/paddock
    ├── SHA256SUMS                   # sha256 of every file below except itself
    ├── .env.example                 # deploy/compose/prod.env.example (+ PADDOCK_HOST, decision 15)
    ├── versions.env                 # deploy/compose/versions.env up to the line "# Build and tooling images"
    │                                # (exclusive) + the three PADDOCK_*_IMAGE lines (decision 12)
    ├── compose.yaml  compose.prod.yaml  compose.backup.yaml  compose.audit.yaml  compose.audit.prod.yaml
    ├── caddy/Caddyfile.prod
    ├── openbao/config.hcl  openbao/prod.hcl
    ├── rabbitmq/rabbitmq.conf  rabbitmq/enabled_plugins  rabbitmq/tls.conf  rabbitmq/definitions.json.tmpl
    ├── valkey/valkey.conf
    ├── postgres/init/10-roles.sh  audit-postgres/init/10-roles.sh
    ├── authentik/entrypoint.sh  authentik/blueprints/*.yaml          # not authentik/dev/
    ├── fleet/entrypoint.sh  fleet/backup.sh  fleet/backup-upload.sh
    ├── prometheus/prometheus.yml  prometheus/alerts.yml  prometheus/scrape/controlplane.yml  prometheus/scrape/audit.yml
    └── scripts/lib.sh  gen-prod-secrets.sh  openbao-configure.sh  rustfs-bundles-bootstrap.sh
                rustfs-audit-bootstrap.sh  fleet-bootstrap.sh  wait-healthy.sh
    ```

    Not in the bundle: `compose.dev.yaml`, `compose.backup.dev.yaml`, `caddy/Caddyfile`, `openbao/dev.hcl`,
    `authentik/dev/`, `prometheus/alerts_test.yml`, `pgbackrest/` (image sources), `Dockerfile`, every `*_test.sh`,
    `gen-dev-secrets.sh`, `openbao-bootstrap.sh`, `openbao-restore.sh`, `restore-drill*.sh`, `load-guard*.sh`,
    `rustfs-backup-bootstrap.sh`, `.env.example` of the development stack, agent packages (§3.8).
12. The builder appends to the bundle's `versions.env`:

    ```
    # Paddock images of <version> (channel <stable|edge>, commit <sha>)
    PADDOCK_IMAGE=ghcr.io/phischl/paddock-server:<version>@sha256:<index digest>
    PADDOCK_COMPILER_IMAGE=ghcr.io/phischl/paddock-compiler:<version>@sha256:<index digest>
    PADDOCK_PGBACKREST_IMAGE=ghcr.io/phischl/paddock-pgbackrest:<version>@sha256:<index digest>
    ```

    `.env` is loaded after `versions.env`, so an operator who mirrors the images overrides these three variables in
    `.env` (documented; mirroring itself is a non-goal). A local bundle (`make bundle` without a release, §3.5) carries
    `paddock-server:dev`, `paddock-compiler:dev`, `paddock-pgbackrest:dev` without digests.
13. **Bundle integrity:** the tarball `paddock-deploy-<version>.tar.gz` (top-level directory
    `paddock-deploy-<version>/`, files owned by `0:0`, mtime of every file = the commit's author time, created with
    `tar --sort=name --owner=0 --group=0 --numeric-owner --mtime=@<epoch> -czf` so that two builds of one commit are
    byte-identical) is signed keylessly: `cosign sign-blob --yes --bundle paddock-deploy-<version>.tar.gz.sigstore.json`.
    It is also listed in the release's `SHA256SUMS`, which stays signed as today. No minisign signature of the bundle
    (open point 7).
14. **`prod-check` runs from the server image, as root, with the bundle directory mounted at its own absolute path**
    (the configuration names host paths):

    ```sh
    compose --profile '*' config --format json |
      docker run --rm -i --user 0:0 [--network ${PADDOCK_PROJECT}_audit-store] \
        -v "$BUNDLE_DIR:$BUNDLE_DIR:ro" -w "$BUNDLE_DIR" "$PADDOCK_IMAGE" \
        prod-check --host "$PADDOCK_HOST" --compose-files <files, comma-separated> [--online]
    ```

    `--user 0:0` because the secrets directory is mode 0700 of the operator and the image's default user is 65532;
    the check reads modes, so running as root inside the container is correct. `--network` only with `--online`.
    `PADDOCK_IMAGE` is read from `versions.env`, overridden by `.env`. No `--dev-release-key` flags (the bundle has no
    development keys). `docker compose run` is NOT used: it would mount the secrets at `/run/secrets/`, not at the
    paths the configuration names.
15. **`.env` gains `PADDOCK_HOST=controlplane|audit`** (in `deploy/compose/prod.env.example`, with a comment; default
    `controlplane`, the audit host sets `audit`). `gen-prod-secrets.sh` takes the host from its first argument as
    today and, without an argument, from `env_value PADDOCK_HOST`. The dev `.env.example` is unchanged.
16. **The entry script `./paddock`** (`deploy/bundle/paddock`, bash, sources `scripts/lib.sh`):

    ```
    ./paddock version                      prints VERSION
    ./paddock verify                       sha256sum -c --quiet SHA256SUMS (shipped files unchanged)
    ./paddock secrets                      scripts/gen-prod-secrets.sh $PADDOCK_HOST
    ./paddock pull                         compose --profile '*' pull
    ./paddock check [--online]             prod-check (decision 14); exit code of prod-check
    ./paddock up [--infra]                 --infra: compose up -d (no profile); default: --profile paddock
                                           --profile observability up -d, then scripts/wait-healthy.sh with the same profiles
    ./paddock down [--volumes]             compose --profile paddock --profile observability down [-v]
    ./paddock ps | logs [service…]         compose ps / compose --profile '*' logs --no-color --tail 300 [service…]
    ./paddock compose <args…>              compose passthrough with the host's files
    ./paddock bao <args…>                  compose exec -e BAO_ADDR=https://127.0.0.1:8200
                                           -e BAO_CACERT=/run/secrets/internal_ca_bundle [-e BAO_TOKEN] openbao bao <args…>
                                           (BAO_TOKEN forwarded only when set in the caller's environment)
    ./paddock bootstrap openbao            scripts/openbao-configure.sh (decision 17); BAO_TOKEN from the environment
    ./paddock bootstrap buckets            scripts/rustfs-bundles-bootstrap.sh (control plane)
    ./paddock bootstrap audit-bucket       scripts/rustfs-audit-bootstrap.sh (audit host)
    ./paddock bootstrap fleet              scripts/fleet-bootstrap.sh (control plane)
    ./paddock agent-release <version> <dir>  decision 25
    ./paddock migrate-from <old dir>       copies <old dir>/.env and <old dir>/.secrets/ (cp -a) into this directory;
                                           refuses when .env or .secrets/ already exist here
    ```

    Rules: every subcommand except `version` and `verify` requires `.env` with `PADDOCK_ENV=production` and
    `PADDOCK_HOST` set to `controlplane` or `audit`, else exit 2 with a message naming the variable. The file set is
    `PROD_FILES_controlplane` or `PROD_FILES_audit` of `lib.sh` (decision 18). The project name is
    `PADDOCK_PROJECT` from `.env` (default `paddock`). `up` applies decision 3. Unknown subcommand: usage, exit 2.
    The script never prints a secret.

### 3.4 Scripts: production-capable bootstraps

17. **OpenBao bootstrap is split.** `scripts/openbao-configure.sh` (new; shipped) configures an **unsealed** OpenBao
    with the token in `BAO_TOKEN`: enables `transit`, `secret` (kv-v2) and `approle`; creates the transit keys
    `audit-chain`, `bundle-signing`, `command-signing`, `revocation-signing`, `time-ticket` (ed25519) and
    `escrow-wrap` (rsa-4096), the KV secret `secret/paddock/session`, the seven policies and the seven AppRoles —
    exactly the content of today's `openbao-bootstrap.sh` from "bao secrets list" on, unchanged — and writes
    `role_id`/`secret_id` into `$SECRETS_DIR/approle/<role>/` for every role, including `paddock-audit-writer` (the
    operator copies that directory to the audit host; `install.md` gets the row). Idempotent (a non-empty `secret_id`
    is kept). It reaches OpenBao through `compose exec openbao bao` with `BAO_ADDR=https://127.0.0.1:8200` and
    `BAO_CACERT=/run/secrets/internal_ca_bundle` when `PADDOCK_ENV=production`, with `BAO_ADDR=http://127.0.0.1:8200`
    otherwise. It ends with the line `revoke the root token now: ./paddock bao token revoke -self` in production.
    `scripts/openbao-bootstrap.sh` (development only, `require_development` kept) does the plain init with stored
    shares and the unseal as today, exports `BAO_TOKEN` from `init.txt` and calls `openbao-configure.sh`. Production
    initialization with PGP-encrypted shares stays a manual `./paddock bao operator init …` of
    `docs/operations/openbao.md` section 1; that section is shortened to init, unseal, `./paddock bootstrap openbao`,
    snapshot, revoke.
18. **`scripts/lib.sh`** becomes the single source of truth for the file sets and the project name:

    ```sh
    DEV_FILES="compose.yaml compose.audit.yaml compose.dev.yaml"
    DEV_BACKUP_FILES="compose.backup.yaml compose.backup.dev.yaml"
    PROD_FILES_controlplane="compose.yaml compose.prod.yaml compose.backup.yaml"
    PROD_FILES_audit="compose.audit.yaml compose.audit.prod.yaml"
    PADDOCK_PROJECT="${PADDOCK_PROJECT:-$(env_value PADDOCK_PROJECT)}"; PADDOCK_PROJECT="${PADDOCK_PROJECT:-paddock}"
    SECRETS_DIR="${SECRETS_DIR:-$COMPOSE_DIR/.secrets}"
    ```

    `compose()` selects the files: `PADDOCK_ENV=development` → `DEV_FILES` (+ `DEV_BACKUP_FILES` when `BACKUP` is
    set); otherwise `PROD_FILES_<PADDOCK_HOST>` (exit 2 when `PADDOCK_HOST` is unset). After the selected files it
    appends `-f <file>` for every absolute path in `PADDOCK_COMPOSE_EXTRA` (space-separated; CI hook of §3.6, empty by
    default). Every script that hard-codes `paddock_cp`, `paddock_audit-store` or `-p paddock` uses
    `${PADDOCK_PROJECT}_cp`, `${PADDOCK_PROJECT}_audit-store`, `-p "$PADDOCK_PROJECT"` instead; `NETWORK` and
    `ENDPOINT` in the bucket scripts become overridable (`NETWORK="${NETWORK:-…}"`). The Makefile's `COMPOSE` and
    `PROD_FILES_*` variables and `server/internal/prodcheck/compose_test.go` read the lists from `lib.sh`
    (`sed -n 's/^PROD_FILES_controlplane="\(.*\)"$/\1/p' deploy/compose/scripts/lib.sh`; the Go test uses the
    equivalent regular expression on `lib.sh`).
19. `rustfs-bundles-bootstrap.sh`, `rustfs-audit-bootstrap.sh` and `fleet-bootstrap.sh` drop `require_development`:
    nothing in them is development-specific (they read the root credentials and user keys from `$SECRETS_DIR`, which
    `gen-prod-secrets.sh` writes too). `rustfs-audit-bootstrap.sh` keeps its refusal of an existing bucket without
    Object Lock. `fleet-bootstrap.sh` keeps the local admin `admin@paddock-mdm.invalid` (Fleet's UI is never
    published). `rustfs-backup-bootstrap.sh`, `gen-dev-secrets.sh`, `openbao-bootstrap.sh`, `restore-drill*.sh`,
    `load-guard*.sh` stay development-only. `docs/operations/audit-bucket.md` section 1 and `fleet.md` "Bootstrap"
    point to `./paddock bootstrap …` and keep the manual commands only for an S3 provider that is not the bundled
    RustFS. This narrows plan M0 decision 20 to the development shortcuts it was made for (stored unseal shares,
    development users); it does not weaken production.

### 3.5 Makefile and builder

20. Removed: `prod-secrets`, `prod-check`, `PROD_COMPOSE`. The only production path is the bundle; from source means
    "build the images locally, build a local bundle, use the bundle" (`install.md` appendix). New and changed targets
    (all called by the workflows the architect writes; contracts in §6):
    - `release-images` — `docker buildx build --platform $(RELEASE_PLATFORMS) --push` of the three images with the
      tags of decisions 4–5 and the labels of decision 6; writes `dist/release/<version>/images.txt` (§6.3). Requires
      `PUSH=1`; `DRY_RUN=1` prints the commands. Variables: `RELEASE_PLATFORMS ?= linux/amd64,linux/arm64`,
      `RELEASE_CHANNEL ?= stable`, `RELEASE_PGBACKREST_REPO ?= $(RELEASE_REGISTRY)/paddock-pgbackrest`,
      `RELEASE_LATEST` (computed from the tags, decision 4; `edge` never sets it). `release-check` accepts
      `x.y.z` for `stable` and `edge-YYYYMMDD-sha7` for `edge`.
    - `release-sbom` — one SBOM per image and platform from the registry (`syft registry:<repo>@<index digest>
      --platform <os/arch>`), into `dist/release/<version>/`.
    - `release-sign` — `cosign sign --recursive` per image (index digest), `cosign attest` per platform manifest,
      `sign-blob` of `SHA256SUMS` and of the bundle tarball.
    - `release-packages` — the agent part of today's `release-artifacts` (debs and `paddockd` binaries, `-unsigned`),
      with `release-key-check`.
    - `release-bundle` — `deploy/bundle/build.sh --version $(RELEASE_VERSION) --channel $(RELEASE_CHANNEL)
      --images dist/release/$(RELEASE_VERSION)/images.txt --out dist/release/$(RELEASE_VERSION)`.
    - `release-sums` — `SHA256SUMS` over `dist/release/<version>/` as today (excluding `images.txt`, `*.sigstore.json`
      and `SHA256SUMS`).
    - `release-artifacts` — kept as the local umbrella: `release-images` (DRY_RUN unless PUSH), `release-packages`,
      `release-sbom`, `release-bundle`, `release-sums`.
    - `bundle` — a local bundle from the local images (`IMAGE`, `COMPILER_IMAGE`, `PGBACKREST_IMAGE`, no digests)
      into `dist/bundle/`; version `0.0.0-local` unless `RELEASE_VERSION` is set.
    - `bundle-test` — `deploy/bundle/bundle_test.sh`, part of `make test`.
    - `lint-image` — additionally builds the `build` stage for `--platform linux/arm64` (Go cross-compilation, no
      QEMU) so that a commit that breaks the cross-compile fails lint.
21. **`deploy/bundle/build.sh`** (bash; arguments `--version`, `--channel stable|edge|local`, `--images <file or
    "local">`, `--out <dir>`): copies the files of decision 11 from `deploy/compose/` and `deploy/bundle/`, derives
    `.env.example` and `versions.env` as decisions 11–12 say, writes `VERSION`, `SHA256SUMS` (`find . -type f !
    -name SHA256SUMS -printf '%P\n' | LC_ALL=C sort | xargs sha256sum`), builds the tarball of decision 13. It then
    validates its own output: `docker compose --project-directory <bundle> -p paddock-bundle-check --env-file
    versions.env --env-file .env.example -f <PROD_FILES_controlplane> --profile '*' config` and the same for
    `PROD_FILES_audit` MUST succeed (with `PADDOCK_BACKUP_S3_ENDPOINT=https://backup-s3.example.org` in the
    environment) and MUST NOT contain the key `build:`. Exit 1 with the offending file otherwise.
22. **Drift test `deploy/bundle/bundle_test.sh`** (`make test`): builds a local bundle into a temporary directory and
    asserts (a) both rendered production configurations of the bundle equal the repository's rendering of the same file
    sets from `deploy/compose/` with the same env files, after replacing the two project directories by `<dir>` and
    the three `PADDOCK_*_IMAGE` values by `<image>` (`diff` of the normalized `docker compose config` output);
    (b) every bind-mount source of both renderings exists inside the bundle; (c) every `${…_IMAGE}` variable referenced
    in the shipped Compose files and scripts is defined in the shipped `versions.env`; (d) `./paddock verify` passes;
    (e) no shipped file contains the string `require_development` except `lib.sh`; (f) the tarball of two consecutive
    builds of the same tree has the same SHA-256.

### 3.6 Workflows and the smoke test

23. **Release workflow** (`release.yml`, tags `v*.*.*`, architect writes; three jobs):
    1. `build` (`ubuntu-24.04`, `packages: write`, `id-token: write`): checkout (fetch-depth 0), setup-go, setup-qemu,
       setup-buildx, login to ghcr, `make release-images RELEASE_VERSION=<v> PUSH=1`, `make release-packages
       RELEASE_VERSION=<v> RELEASE_PUBLIC_KEY_FILE=<var>`, `make release-sbom`, `make release-bundle`,
       `make release-sums`, `make release-sign`; uploads `dist/release/<v>/` as the artifact `release`.
    2. `smoke` (`ubuntu-24.04`, needs `build`, `contents: read` only, **no registry login**): downloads `release`,
       setup-go (for the throwaway minisign key), runs `deploy/bundle/ci/smoke.sh dist/release/<v>/paddock-deploy-<v>.tar.gz
       --agent-artifacts dist/release/<v>`; on failure uploads the Compose logs of both projects.
    3. `publish` (needs `smoke`, `contents: write`): downloads `release`, `gh release create --draft --verify-tag`
       with every file of `dist/release/<v>/` except `images.txt`; notes as today plus the bundle verification line.
    Images are pushed and signed before the smoke runs; a failed smoke leaves signed images under the tag and no draft
    (same acceptance as plan M6b for the sign step: consumers verify digests, the tag is re-run or deleted).
24. **Edge job in `ci.yml`** (architect): job `edge`, `needs: [acceptance]`, `if: github.event_name == 'push' &&
    github.ref == 'refs/heads/main'`, permissions `packages: write`, `id-token: write`, `contents: read`; runs
    `make release-images RELEASE_VERSION=edge-$(date -u +%Y%m%d)-${GITHUB_SHA::7} RELEASE_CHANNEL=edge PUSH=1`,
    `make release-sbom`, `make release-bundle`, `make release-sums`, `make release-sign`, then
    `deploy/bundle/ci/smoke.sh` (without `--agent-artifacts`), and uploads the bundle tarball and its
    `.sigstore.json` as the artifact `paddock-deploy-edge` (retention 30 days). The weekly `schedule` run of `ci.yml`
    never reaches this job (event name).
25. **`deploy/bundle/ci/smoke.sh <tarball> [--agent-artifacts <dir>]`** exercises the install guide on one runner with
    two bundle directories and two Compose projects (`paddock-cp`, `paddock-audit`). Public ACME is impossible on a
    runner, so the running stack adds the overlay `deploy/bundle/ci/compose.ci.yaml` through `PADDOCK_COMPOSE_EXTRA`
    (decision 18) while **`./paddock check` renders the production configuration without the overlay** — that is the
    CI-safe mode: the static checks run against the real production files, the stack runs with internal TLS. Steps:
    1. Extract the tarball into `$W/cp` and `$W/audit`; `./paddock verify` in both.
    2. `.env` from `.env.example` in both with `PADDOCK_HOST`, `PADDOCK_PROJECT=paddock-cp|paddock-audit`,
       `PADDOCK_DOMAIN=paddock.localhost`, `PADDOCK_ACME_EMAIL=ci@paddock.localhost`, `PADDOCK_PUBLIC_ADMIN_URL=https://admin.paddock.localhost`,
       `PADDOCK_PUBLIC_DEVICE_URL=https://device.paddock.localhost`, `PADDOCK_INTERCONNECT_ADDR`,
       `PADDOCK_CONTROLPLANE_ADDR`, `PADDOCK_AUDIT_ADDR` all = the runner's primary address (`hostname -I | awk
       '{print $1}'`), `PADDOCK_BACKUP_S3_ENDPOINT=https://backup-s3-tls:9443`.
    3. `./paddock secrets` in both; copy `db_paddock_audit_reader_password` (audit → cp),
       `rabbitmq_audit_writer_password` (cp → audit), `internal-ca/ca.crt` ↔ `internal-ca/peer-ca.crt`; `./paddock
       secrets` again in both. Throwaway minisign key pairs (`cd agent && go run aead.dev/minisign/cmd/minisign -G -W
       -p $W/keys/<name>.pub -s $W/keys/<name>.key`) → only the `.pub` files to `cp/.secrets/release-production/`.
       Random `backup_{pgbackrest,worker,fleet}_{access,secret}_key` into `cp/.secrets/`; an empty
       `cp/.secrets/caddy-root.crt` (mode 0666, as `gen-dev-secrets.sh` does; the overlay's `caddy-ca-export` fills it).
    4. Audit: `./paddock up --infra`, `./paddock bootstrap audit-bucket`; backup bucket with the repository's
       `deploy/compose/scripts/rustfs-backup-bootstrap.sh` run as `PADDOCK_ENV=development SECRETS_DIR=$W/audit/.secrets
       NETWORK=paddock-audit_audit-store` after copying the `backup_*` files into `$W/audit/.secrets/`.
    5. Control plane: `PADDOCK_COMPOSE_EXTRA=<abs>/compose.ci.yaml` exported for every `./paddock` call from here on;
       `./paddock up --infra`; `./paddock bao operator init -key-shares=5 -key-threshold=3 -format=json >$W/init.json`;
       three `./paddock bao operator unseal <share>`; `BAO_TOKEN=<root> ./paddock bootstrap openbao`; copy
       `cp/.secrets/approle/paddock-audit-writer/` to `audit/.secrets/approle/paddock-audit-writer/`;
       `./paddock bootstrap buckets`; `./paddock bootstrap fleet`.
    6. `./paddock check` in `cp` (exit 0) and `./paddock check --online` in `audit` (exit 0); `caddy validate` of
       `cp/caddy/Caddyfile.prod` in `CADDY_IMAGE` with `PADDOCK_DOMAIN`, `PADDOCK_ACME_EMAIL`,
       `PADDOCK_ADMIN_ALLOWED_CIDRS="0.0.0.0/0 ::/0"`, and — once M7a is merged — `PADDOCK_EDGE_TRUSTED_PROXIES` and
       `PADDOCK_EDGE_CLIENT_IP_HEADER` with the defaults of `prod.env.example` (and every further variable
       `Caddyfile.prod` references at that time) set in the container's environment. The variable list is read from
       the bundle's `.env.example` (every `NAME=` line, including commented `# NAME=` lines with their value), so a
       variable added to `prod.env.example` reaches this step without an edit.
    7. `./paddock up` in both (waits until healthy, timeout 900 s).
    8. Probes with `curl --cacert cp/.secrets/caddy-root.crt --resolve <name>:443:127.0.0.1`: `https://admin.paddock.localhost/`
       → 200, `https://auth.paddock.localhost/-/health/ready/` → 200, `https://device.paddock.localhost/v1/checkin`
       (POST without signature) → a 4xx status (the gateway answers through Caddy; the code is whatever the device
       API returns to an unsigned request, asserted as 400–499, never 5xx or a connection error); `./paddock compose run --rm --no-deps pgbackrest backup --start-fast` exits 0
       and `… pgbackrest info` prints `full backup`; with `--agent-artifacts`: sign `paddockd_<v>_linux_amd64-unsigned`
       (as `paddockd`) and the three `*_amd64-unsigned.deb` (renamed) with the throwaway keys and the trusted comments of
       `agent-releases.md`, then `./paddock agent-release <v> $W/agent` exits 0 and `GET
       https://admin.paddock.localhost/api/platform/v1/agent-releases/<v>` is not needed (the command prints the release
       JSON with `published: true`).
    9. Idempotence: record the container IDs of both projects, run `./paddock up` again in both, assert the same IDs.
    10. `./paddock down --volumes` in both (also on failure, after collecting `./paddock logs` into the job's artifact).
26. **`deploy/bundle/ci/compose.ci.yaml`** (CI only, never shipped): re-applies the internal-TLS wiring of the
    development stack over the production overlay and routes the backups to the audit project's RustFS:
    `caddy` with `PADDOCK_HTTPS_PORT: "443"`, volumes `!override` `[${PADDOCK_CI_DIR}/../../compose/caddy/Caddyfile:/etc/caddy/Caddyfile:ro,
    caddy-data:/data, caddy-config:/config]` and the development healthcheck (root certificate present);
    `caddy-ca-export` with the command and volumes of `compose.yaml`; `paddock-api`, `paddock-escrow-reader`,
    `paddock-revocation-issuer`, `paddock-worker` with `SSL_CERT_FILE: /run/secrets/caddy_root_crt` and `secrets:
    [caddy_root_crt]` (appended to the overridden lists); `backup-s3-tls`, `pgbackrest`, `pgbackrest-authentik`,
    `fleet-backup-upload`, `paddock-worker` exactly as `compose.backup.dev.yaml` wires them, with the network
    `audit-store` declared `external: true, name: paddock-audit_audit-store`; volumes `backup-s3-tls-data`,
    `backup-s3-ca`. `PADDOCK_CI_DIR` is exported by `smoke.sh` (absolute path of `deploy/bundle/ci`).

### 3.7 Upgrade and rollback

27. **Upgrade** (`docs/operations/upgrade.md`, new; `install.md` section 10 links it): download the new bundle and
    its `.sigstore.json`, verify (README), extract next to the running one, `./paddock migrate-from <old dir>`,
    `./paddock pull`, `./paddock check` (exit 0), take a backup (`restore.md`: full backups of both databases and an
    OpenBao snapshot, check they are in the bucket), `./paddock up` (the `paddock-migrate` one-shot applies the
    schema migrations before the roles start), `./paddock ps`, watch the alerts; audit host the same without the
    backup step; control plane first, audit host second. Agents after the server: ADR 0013 (the server supports the
    current and the two previous minors); a server upgrade never requires an agent upgrade, an agent release is
    uploaded only to a server of the same or a newer minor.
28. **Rollback:** migrations are forward-only (`server/migrations/`, `migrate.Paddock`/`migrate.Audit`; there is no
    down migration). The `CHANGELOG.md` section of every release MUST state `Schema: unchanged` or `Schema:
    migrations NNNNN–NNNNN` (both databases), checked by nobody but the release manager (documented in
    `agent-releases.md` "Server release"). Rollback without schema change: `./paddock down` in the new directory,
    `./paddock up` in the old directory (same project name, same volumes, images by digest from the old
    `versions.env`). Rollback with a schema change: the restore runbook (`restore.md`) with the backup taken before the
    upgrade, then `./paddock up` in the old directory; data written after the backup is lost — the runbook says so.
29. **`docs/operations/install.md` is rewritten** for the bundle (sections: host requirements incl. decision 3 and
    Docker Compose ≥ 2.24, DNS, download and verification, configuration and secrets with `./paddock secrets` and
    the exchange table incl. the AppRole row, audit host, control plane OpenBao with `./paddock bao operator init …`
    and `./paddock bootstrap openbao`, buckets and Fleet with `./paddock bootstrap …`, check and start, first
    administrator and organization, first agent release with `./paddock agent-release` (decision 25 of §3.8), backups,
    upgrade link, ISMS). Appendix "Installing from source": `make image image-compiler image-pgbackrest`,
    `make bundle`, then the same steps with the local bundle (images by tag only, no digests, no signature). Every
    `make prod-check`/`make prod-secrets`/`pc`/`pa` mention in `docs/operations/*.md` and `README.md` is replaced
    by the `./paddock` equivalent (`restore.md`: `pc …` → `./paddock compose …`; `make prod-check` →
    `./paddock check`).

### 3.8 Agent packages

30. The bundle contains **no** agent packages: they are signed offline after the draft release exists (unchanged
    flow of `agent-releases.md`), and the GitHub release of a version holds both the bundle and the signed packages
    with their `.minisig` files. The bundle README names the release page.
31. **First (and every) agent release in production** is uploaded on the control-plane host with the new host command
    `paddock-server admin agent-release --version <v> --dir <dir>` (run by `./paddock agent-release <v> <dir>` as
    `compose run --rm --no-deps -v <abs dir>:/release:ro paddock-api admin agent-release --version <v> --dir
    /release`): `<dir>` holds `paddockd` and `paddockd.minisig` per architecture under `<arch>/` and every
    `<name>_<version>_<arch>.deb` with its `.minisig` (the layout the offline signing step produces; fleetd as
    `fleet-osquery_<fleetd version>_<arch>.deb`). The command creates the release, uploads every artifact and package
    through the **same application use cases as the API** (`server/internal/app/agentreleases.go`: signature and
    trusted-comment verification with `PADDOCK_RELEASE_PUBLIC_KEY_FILE` / `PADDOCK_REVOKE_RELEASE_PUBLIC_KEY_FILE`,
    storage in `paddock-agent-artifacts`), publishes it, and prints the release detail as JSON. It MUST record the
    audit events the API path records, with the actor the restore commands of plan M6c use; it MUST NOT add an audit
    code. It runs with the api role's configuration (platform database URL, artifacts bucket, release keys), hence
    `paddock-api` as the service. `agent-releases.md` "Releasing" step 3–5 name this command as the production path
    and keep the API description for automation (open point 1).

### 3.9 Compatibility with M7a (IP allow list)

32. The bundle ships `caddy/Caddyfile.prod` and `compose.prod.yaml` verbatim, and its `.env.example` is generated
    from `deploy/compose/prod.env.example` (decision 11, never a separate file), so whatever M7a changes there (the
    variables `PADDOCK_EDGE_TRUSTED_PROXIES` and `PADDOCK_EDGE_CLIENT_IP_HEADER`, Caddy directives) is in the bundle
    without further work. M7a uses ADR 0021; this plan's ADR is 0022. Two things in this plan touch the same files and MUST
    stay compatible: `compose.ci.yaml` mounts the development `Caddyfile` instead of `Caddyfile.prod`, and
    `smoke.sh` step 6 validates `Caddyfile.prod` with every variable it references set. If M7a is merged first, the
    implementer adds M7a's variables to that step; if M7b is merged first, M7a's implementer does.

## 4. Non-goals

Helm/Kubernetes; registries other than `ghcr.io/phischl` and registry mirroring (the `.env` override exists, it is not
tested); prerelease versions (`v1.2.0-rc.1`); an upload page for agent releases in the portal; Fleet on arm64; an ACME
test CA (Pebble) in CI; automatic upgrades or an upgrade agent; a minisign signature of the bundle; Alertmanager or
Grafana in the bundle; changes to the agent, the revocation path or the system tests (no agent code changes → no VM
system tests); the `edge` bundle on a GitHub release (it is a workflow artifact); an upgrade smoke from the previous
release (open point 11).

## 5. Affected files

| Path | Action | Purpose |
| --- | --- | --- |
| `deploy/compose/Dockerfile` | change | cross-compile (`--platform=$BUILDPLATFORM`, `TARGETOS/TARGETARCH`) |
| `deploy/compose/compose.yaml`, `compose.audit.yaml`, `compose.backup.yaml` | change | remove `build:` |
| `deploy/compose/compose.dev.yaml`, `compose.backup.dev.yaml` | change | add `build:` per service |
| `deploy/compose/prod.env.example` | change | `PADDOCK_HOST`, `PADDOCK_PROJECT` (commented, default `paddock`), remove the `PADDOCK_IMAGE` comment block |
| `deploy/compose/scripts/lib.sh` | change | decision 18 |
| `deploy/compose/scripts/openbao-configure.sh` | new | decision 17 |
| `deploy/compose/scripts/openbao-bootstrap.sh` | change | dev init/unseal, then `openbao-configure.sh` |
| `deploy/compose/scripts/gen-prod-secrets.sh` | change | `.env.example` as template, host from `PADDOCK_HOST`, `approle/paddock-audit-writer` placeholders on the control plane |
| `deploy/compose/scripts/rustfs-bundles-bootstrap.sh`, `rustfs-audit-bootstrap.sh`, `fleet-bootstrap.sh` | change | production-capable (decision 19), project/network variables |
| `deploy/compose/scripts/rustfs-backup-bootstrap.sh`, `wait-healthy.sh`, `restore-drill.sh` | change | project/network/secrets variables only |
| `deploy/bundle/build.sh` | new | decision 21 |
| `deploy/bundle/paddock` | new | decision 16 |
| `deploy/bundle/README.md` | new | operator README of the bundle (§6.5) |
| `deploy/bundle/bundle_test.sh` | new | decision 22 |
| `deploy/bundle/ci/compose.ci.yaml`, `deploy/bundle/ci/smoke.sh` | new | decisions 25–26 |
| `deploy/bundle/ci/prune-edge.sh`, `prune-edge_test.sh`, `deploy/bundle/ci/testdata/*.json` | new | decision 9, §6.7 |
| `Makefile` | change | decision 20 |
| `server/cmd/paddock-server/admin.go`, `main.go` (usage) | change | `admin agent-release` (decision 31) |
| `server/internal/app/agentreleases.go` | change (if needed) | expose a host-side entry point; no behaviour change of the API path |
| `server/internal/prodcheck/compose_test.go` | change | file lists from `lib.sh` |
| `docs/operations/install.md` | rewrite | decision 29 |
| `docs/operations/upgrade.md` | new | decisions 27–28 |
| `docs/operations/agent-releases.md`, `restore.md`, `openbao.md`, `audit-bucket.md`, `fleet.md`, `local-dev.md`, `monitoring.md` | change | `./paddock` commands, three images, edge identity, `Schema:` rule |
| `docs/compliance/third-party.md` | change | `paddock-pgbackrest` (pgBackRest: MIT) as a published image |
| `docs/adr/0022-distribution-images-and-operator-bundle.md` | new | the ADR of §6.6, verbatim (0022: M7a takes 0021) |
| `README.md`, `CHANGELOG.md` | change | quick start for operators; Unreleased entries |
| `.github/workflows/release.yml`, `ci.yml`, `ghcr-prune.yml` | architect | decisions 23–24, 9 |

MUST NOT be touched: `agent/`, `packaging/`, `test/system/`, `server/internal/transport/http/admin/` (no API change),
`api/openapi/`, `docs/architecture.md`, every ADR but 0022, `server/migrations/`.

## 6. Interfaces and formats

### 6.1 `deploy/bundle/build.sh`

```
build.sh --version <v> --channel stable|edge|local --images <path to images.txt | local> --out <dir>
  exit 0: <dir>/paddock-deploy-<v>/ and <dir>/paddock-deploy-<v>.tar.gz exist and validated (decision 21)
  exit 1: validation failed (message names the file); exit 2: usage
  environment: SOURCE_DATE_EPOCH (default: git log -1 --format=%at), GIT_COMMIT (default: git rev-parse HEAD)
```

### 6.2 `deploy/bundle/ci/smoke.sh`

```
smoke.sh <tarball> [--agent-artifacts <dir>] [--work <dir>]
  exit 0: every step of decision 25 passed; exit 1: a step failed (its name on stderr); exit 2: usage
  requires: docker, docker compose ≥ 2.24, go (for the throwaway minisign keys), curl, sha256sum
  environment: PADDOCK_CI_DIR (set by the script), WAIT_TIMEOUT (default 900)
```

### 6.3 `dist/release/<version>/images.txt`

```
server=ghcr.io/phischl/paddock-server:<version>@sha256:<index digest>
server/linux/amd64=ghcr.io/phischl/paddock-server@sha256:<manifest digest>
server/linux/arm64=ghcr.io/phischl/paddock-server@sha256:<manifest digest>
compiler=…            compiler/linux/amd64=…   compiler/linux/arm64=…
pgbackrest=…          pgbackrest/linux/amd64=…  pgbackrest/linux/arm64=…
```

Platform digests come from `docker buildx imagetools inspect <repo>@<index digest> --format
'{{range .Manifest.Manifests}}{{.Platform.OS}}/{{.Platform.Architecture}} {{.Digest}}{{"\n"}}{{end}}'`,
attestation manifests (`unknown/unknown`) excluded.

### 6.4 `paddock-server admin agent-release`

```
paddock-server admin agent-release --version <x.y.z> --dir <dir>
  <dir>/<arch>/paddockd, <dir>/<arch>/paddockd.minisig           arch ∈ {amd64, arm64}, at least one
  <dir>/<name>_<version>_<arch>.deb (+ .minisig)                 name ∈ {paddock-agent, paddock-supervisor, paddock-revoke}
  <dir>/fleet-osquery_<fleetd version>_<arch>.deb (+ .minisig)   optional
  stdout: the release detail as JSON (the API's representation), exit 0
  exit 1: verification or upload failed (first error on stderr; nothing published); exit 2: usage; a release of this
  version that is already published: exit 1 with "already published"
  configuration: the api role's (PADDOCK_DB_PLATFORM_URL_FILE, PADDOCK_ARTIFACTS_S3_*, PADDOCK_RELEASE_PUBLIC_KEY_FILE,
  PADDOCK_REVOKE_RELEASE_PUBLIC_KEY_FILE)
```

### 6.5 Bundle `README.md` (minimum content)

What the bundle is; verification (`docker run --rm -v "$PWD:/w" -w /w <COSIGN_IMAGE of versions.env> verify-blob
paddock-deploy-<v>.tar.gz --bundle paddock-deploy-<v>.tar.gz.sigstore.json --certificate-identity-regexp
'<identity of decision 7>' --certificate-oidc-issuer https://token.actions.githubusercontent.com`, and
`cosign verify` of one image); the `./paddock` command table of decision 16; a pointer to `install.md` and
`upgrade.md` of the same version (`https://github.com/phischl/paddock-mdm/blob/v<v>/docs/operations/install.md`); the
agent packages on the release page; the channel notice for edge bundles (unsupported, never for production).

### 6.6 ADR 0022 (add verbatim as `docs/adr/0022-distribution-images-and-operator-bundle.md`)

```markdown
# 0022 — Distribution: published images and an operator bundle
Status: Angenommen (2026-10-09)

## Kontext
Operators installed from a git checkout with make and local image builds (plan M6a). The product owner wants
installation without cloning or building: images on a registry and a self-contained Compose bundle, with the
development stack still building from source and no drift between the two.

## Optionen
- **Generator that rewrites the Compose files for the bundle** (strip `build:`, replace images). + One source.
  − A YAML transformation step with its own tooling and failure modes; the bundle is not what the repository tests.
- **Copy: the production Compose files carry no `build:`; the development overlay adds it.** + The bundle is a
  byte copy of what the repository tests; no YAML tooling. − `build:` lives in the dev overlay, per service.
- **Separate repository for the bundle.** − Drift by construction.

## Entscheidung
Copy. Three images (`paddock-server`, `paddock-compiler`, `paddock-pgbackrest`) on `ghcr.io/phischl/`, multi-platform
(amd64, arm64), signed keylessly with SBOM attestations, stable tags from `v*` tags and an `edge` channel from `main`.
The bundle `paddock-deploy-<version>.tar.gz` is the only production path; `make` is not used on production hosts.
The bootstrap scripts become production-capable; development-only shortcuts stay behind `require_development`.
Agent packages stay offline-signed and outside the bundle.

## Konsequenzen
+ Install and upgrade are the same documented path, exercised by CI on every release and every green commit.
+ Mirroring is a `.env` override. − The control plane remains amd64-only while Fleet's image is. − GHCR package
visibility is a manual step. Folgearbeiten: upgrade smoke from the previous release; Fleet on arm64 when upstream
publishes it.
```

### 6.7 `deploy/bundle/ci/prune-edge.sh`

```
prune-edge.sh [--dry-run] [--older-than-days N] [--now <RFC 3339>] [--versions-json <file>] <package>...
  package: paddock-server | paddock-compiler | paddock-pgbackrest (names below ghcr.io/phischl/)
  without --versions-json: reads `gh api --paginate /user/packages/container/<package>/versions` (needs GH_TOKEN
    with packages:write; the workflow passes the job's GITHUB_TOKEN); with it: reads the recorded JSON (tests)
  --older-than-days: default 30; --now: default `date -u`; the test fixes both
  selection: decision 9; one line per version on stdout: "<package> <id> <created_at> <tags, comma-separated>
    delete|keep <reason>"; deletes only without --dry-run and only lines marked delete
  exit 0: done (also when nothing qualifies); exit 1: an API call failed (the script stops at the first failure and
    names the version); exit 2: usage
  requires: bash, gh, jq (both present on ubuntu-24.04 runners; jq is a new tool for `make test` on developer
    machines — the test skips with a message when jq is missing)
```

`prune-edge_test.sh` (`make test`) runs the script with `--dry-run --versions-json deploy/bundle/ci/testdata/
versions.json --now 2026-10-09T00:00:00Z` and asserts the decision per fixture version: an `edge-20260801-abcdef0`
version 69 days old → delete; `edge-20261001-1234567` 8 days old → keep; a version tagged `edge` and
`edge-20260801-0000000` → keep (moving tag); a version tagged `1.0.0`, `1.0`, `latest` → keep; a version tagged
`edge-20260701-aaaaaaa` and `1.1.0` → keep (release); an untagged 100-day-old version → keep; a version tagged
`sha256-…sig` → keep.

## 7. Implementation steps

Each step ends with `make lint test` green and one commit.

1. **Compose and Dockerfile.** Do decisions 2 and 10; `lint-image` with the arm64 `build` stage.
   *Result:* `make up` and `make up BACKUP=1` build from source as before; `docker compose … -f compose.yaml -f
   compose.prod.yaml -f compose.backup.yaml config` shows no `build:`.
   *Check:* `make lint-image`; `make up && make acceptance T='TestDeviceProtocol|TestLoginGate'`; `grep -c 'build:'`
   on the rendered production configs = 0.
2. **lib.sh and the scripts.** Decisions 15, 17, 18, 19; Makefile `COMPOSE` and `PROD_FILES_*` from `lib.sh`;
   `compose_test.go` from `lib.sh`; `openbao-bootstrap.sh` calls `openbao-configure.sh`.
   *Result:* `make up` (which runs the bootstraps) is unchanged in behaviour; the scripts print the same lines.
   *Check:* `make down V=1 && make up && make dev-seed && make acceptance T='TestAuditChain|TestOrganizationIsolation'`;
   `go test ./server/internal/prodcheck/`; the shell tests of `make test`.
3. **Bundle builder, entry script, README, drift test.** Decisions 11–14, 16, 20 (`bundle`, `bundle-test`), 21, 22.
   *Result:* `make bundle` produces `dist/bundle/paddock-deploy-0.0.0-local/` and the tarball; `./paddock verify`
   and `./paddock version` work in it.
   *Check:* `make bundle-test`.
4. **Release targets.** Decision 20 (`release-images`, `release-sbom`, `release-sign`, `release-packages`,
   `release-bundle`, `release-sums`, `release-artifacts`, `release-check` for edge versions).
   *Result:* `make release-artifacts RELEASE_VERSION=0.1.0 RELEASE_PUBLIC_KEY_FILE=<any production-shaped key>`
   builds packages, a bundle with `local` images and `SHA256SUMS`; `make release-images RELEASE_VERSION=0.1.0 DRY_RUN=1`
   prints the buildx commands with the tags and labels of decisions 4–6; `make release-sign … DRY_RUN=1` prints the
   cosign commands incl. `--recursive`, one attest per platform and the tarball `sign-blob`.
   *Check:* the dry-run outputs; `grep` for every label key of decision 6 in the printed buildx command.
5. **`admin agent-release`.** Decision 31, §6.4; unit tests of the argument parsing; an integration test in
   `server/cmd/paddock-server/admin_test.go` style or `app/agentreleases_integration_test.go` that uploads a signed
   artifact from a directory and asserts the release is published and the audit events exist.
   *Result:* `docker compose … run --rm --no-deps -v <dir>:/release:ro paddock-api admin agent-release --version
   0.1.0 --dir /release` publishes a release on the development stack.
   *Check:* `make test`; on the dev stack: `make deb VERSION=0.1.0`, sign with `.secrets/release/*.key`
   (`cd agent && go run aead.dev/minisign/cmd/minisign -S …`), run the command, open the release in the portal.
6. **CI overlay and smoke script.** Decisions 25–26. Run it locally against a local bundle:
   `deploy/bundle/ci/smoke.sh dist/bundle/paddock-deploy-0.0.0-local.tar.gz` (images `paddock-server:dev` etc. exist
   locally, so no pull is needed).
   *Result:* the smoke passes locally end to end, including the backup, the probes and the idempotence check.
   *Check:* exit 0; total runtime reported (expected < 25 min on the development machine).
7. **Documentation and ADR.** Decisions 27–30, 32; ADR 0022; README; CHANGELOG (`### Added`: images, bundle, edge
   channel, `./paddock`, `admin agent-release`; `### Changed`: `make prod-check`/`prod-secrets` removed, bootstrap
   scripts production-capable; `Schema: unchanged`); `third-party.md`.
   *Check:* every `make prod-check`, `make prod-secrets`, `pc ` and `pa ` occurrence in `docs/` and `README.md` is
   gone (`grep -rn 'make prod-\|^pc \|^pa ' docs README.md` empty); links resolve.
8. **Regression.** `make lint test`, `make up && make dev-seed && make acceptance && make e2e`; report the smoke
   runtime from step 6 and anything the workflows (architect) need beyond §6.

## 8. Tests

| Level | Test | Covers |
| --- | --- | --- |
| unit (Go) | `prodcheck/compose_test.go` (changed) | production renderings from the lists in `lib.sh`; `prod-check` on them |
| unit (Go) | `admin agent-release` parsing; use-case integration test | §6.4 incl. refusal of an already published version and of a wrong trusted comment |
| shell (`make test`) | `deploy/bundle/bundle_test.sh` | decision 22 (a)–(f) |
| shell (`make test`) | existing guard tests | unchanged behaviour of `restore-drill-guard.sh`, `load-guard.sh` |
| shell (`make test`) | `deploy/bundle/ci/prune-edge_test.sh` | §6.7 selection against recorded JSON; dry run deletes nothing |
| lint | `lint-image` with arm64 build stage | cross-compilation |
| CI gate | `smoke.sh` in `release.yml` and the `edge` job | decision 25, both hosts, anonymous pull, prod-check exit 0, backup, probes, agent release (release only), idempotence |
| acceptance | existing gates on the development stack | no regression from decisions 10, 18, 19 |

Error and edge cases that MUST have a test: `./paddock` without `.env` (exit 2), with `PADDOCK_ENV=development`
(exit 2), `migrate-from` onto an existing `.secrets/` (refused), `build.sh` with a Compose file containing `build:`
(exit 1), `bundle_test.sh` with a referenced file removed from the bundle (fails naming the path), `admin
agent-release` with a `.minisig` of the wrong key (exit 1, nothing stored).

## 9. Acceptance criteria

| # | Given / When / Then | Req. | Observed by |
| --- | --- | --- | --- |
| AC1 | Given a tag `v<x.y.z>`, when the release workflow runs, then `ghcr.io/phischl/paddock-{server,compiler,pgbackrest}:<x.y.z>` exist as amd64+arm64 indexes with the labels of decision 6, `cosign verify` and `cosign verify-attestation --type spdxjson` succeed for each platform, and the draft release holds `paddock-deploy-<x.y.z>.tar.gz`, its `.sigstore.json`, `SHA256SUMS` and `SHA256SUMS.sigstore.json` | design contract 5 | Release manager |
| AC2 | Given the bundle tarball and `cosign`, when the operator follows its README, then the signature verifies and `./paddock verify` passes | design contract 5 | Platform operator |
| AC3 | Given two hosts with Docker and the bundle, when the operator follows `install.md` without `git` or `make`, then `./paddock check` exits 0 on both hosts and `./paddock up` brings every service to healthy | C8, AC1 of M6a | Platform operator |
| AC4 | Given a green commit on `main`, then `ghcr.io/phischl/paddock-server:edge` points at it, carries no `latest`/semver tag, is signed, and the workflow artifact `paddock-deploy-edge` holds a bundle whose `VERSION` names the commit | — | Developer |
| AC5 | Given the repository, when `make test` runs, then `bundle_test.sh` proves the bundle renders the same configuration as `deploy/compose/` | — | Developer |
| AC6 | Given a running installation of version A and the bundle of version B, when the operator follows `upgrade.md`, then version B serves with the data of A; given `Schema: unchanged`, `./paddock up` in A's directory brings A back | A11 | Platform operator |
| AC7 | Given the signed agent artifacts of a release, when the operator runs `./paddock agent-release <v> <dir>`, then the release is published and visible on the portal's release page, with the audit events of an upload | design contract 5 | Platform administrator |
| AC8 | Given an edge image older than 30 days with only `edge-*` tags, when the weekly prune runs, then it is deleted; stable tags and `edge` are untouched | — | Developer |

## 10. Degrees of freedom

Internal helper names in the scripts; the YAML anchor names in the dev overlays; whether `build.sh` uses `rsync` or
`cp` (both allowed); the exact wording of script messages (English, no secrets); the layout of `smoke.sh` (functions,
ordering within a step); whether `admin agent-release` reads the directory with `os.ReadDir` or an explicit list;
the bundle README's prose beyond §6.5; test fixture content.

## 11. Stop conditions

Stop and report instead of deciding when: a production Compose file needs a transformation to work from the bundle
(decision 10 impossible); `prod-check` fails on the bundle's production configuration in the smoke for a reason other
than a missing secret created by a later step (never weaken a check); `agentreleases.go` cannot publish without an
HTTP principal or would need a new audit code; the arm64 build of `paddock-compiler` or `paddock-pgbackrest` exceeds
20 minutes in CI; a third-party image of `versions.env` turns out not to be pullable by digest on amd64; the runner
cannot bind 80/443 or the primary address for the interconnect ports; any need for a dependency beyond those approved
here (`docker/setup-qemu-action` and `docker/setup-buildx-action`, used by the architect's workflows only; `jq` in
`prune-edge.sh`); M0 §11 S2/S6/S7/S8.

## 12. Risks

| Risk | Countermeasure |
| --- | --- |
| QEMU `apt-get upgrade` for arm64 is slow or flaky | buildx layer cache (`cache-from/to type=gha` in the workflow); stop condition at 20 min |
| First release: packages private, smoke fails on anonymous pull | documented one-time step; the edge job creates the packages first (open point 5) |
| `prune-edge.sh` deletes a release by mistake | keep rules are evaluated before delete rules (any release/`edge`/`latest` tag keeps the version); dry run first in the workflow; unit test with the fixture of §6.7 |
| `prod-check` inside the container sees different parent-directory modes than the host | the walk checks `.secrets/` (0700) and below; parents created by Docker are 0755, so a 0644 file in a 0700 `.secrets/` passes in both; documented in `install.md` ("`.secrets/` must stay 0700") |
| Two projects on one runner collide on ports | only Caddy publishes 80/443; interconnect ports 5671/8200 (cp) and 5432 (audit) on the runner's address; distinct project names |
| The dev `Caddyfile` and `Caddyfile.prod` diverge (M7a) | `caddy validate` of `Caddyfile.prod` in the smoke; decision 32 |
| Operators edit shipped files | `./paddock verify` and the in-bundle `SHA256SUMS` make it visible; `upgrade.md` says to keep changes in `.env` |

## Open points (defaults chosen)

1. **Agent release upload in production** — default: the host command `paddock-server admin agent-release` of
   decision 31 in this plan. Alternative: defer to a later milestone and document the API with a browser session
   cookie (no scriptable platform login exists; API tokens are organization-scoped).
2. **arm64 smoke test** — default: no arm64 smoke in M7b; arm64 images are built, signed and SBOM-attested but only
   amd64 is exercised. Alternative: a second smoke job on `ubuntu-24.04-arm` for the audit half only (the control
   plane cannot run there, decision 3).
3. **Edge trigger** — default: job in `ci.yml` after a green acceptance on `main` (only green commits become edge).
   Alternative: nightly `schedule` in a separate workflow (simpler permissions, may publish red commits).
4. **Edge retention** — decided by the architect (2026-10-09): 30 days via our own `prune-edge.sh` over `gh api`,
   no third-party action. Untagged versions are never deleted, so platform children and cosign manifests of kept
   indexes stay intact; the children of deleted `edge-*` indexes remain as untagged versions (accepted: public
   packages cost nothing).
5. **Public visibility** — the product owner sets the three packages to public once after the first edge run; until
   then the release smoke fails on the anonymous pull and is re-run afterwards.
6. **`latest`** — default: highest stable semver among all tags (a patch of an older minor never moves `latest`).
7. **Bundle signature** — default: cosign keyless (bundle `.sigstore.json` plus the signed `SHA256SUMS`). Alternative:
   an additional offline minisign signature with the agent release key, which would add the offline step to every
   release.
8. **Public ACME in the smoke** — default: no (Pebble is a new image and a CA export dance); the smoke runs with
   Caddy's internal CA and validates `Caddyfile.prod` statically.
9. **`make prod-check` / `make prod-secrets` removed** — default: yes; the bundle is the only production path and
   "from source" means a local bundle.
10. **Observability profile** — default: `./paddock up` always starts Prometheus (as `install.md` does today).
11. **Upgrade smoke from the previous release** — default: not in M7b (needs a published previous release);
    `migrate-from` is covered by the drift test and the documented procedure only.
12. **`PADDOCK_HOST` in `.env`** — default: yes (one setting per host instead of `--host` on every call).
