# Agent releases and staged rollouts

How agent releases are signed, uploaded and rolled out (plan M2b §3.2–3.3, design contract 3–6).

## Keys

| Key | Where | Used by |
| --- | --- | --- |
| Release key (minisign, Ed25519) | signing copy: secret of the protected GitHub environment `release` (ADR 0006 amendment 2026-10-11); offline backup copy with the custodians; never on the control plane or a device | sign job of the release workflow, to sign `paddockd` and the `paddock-agent` and `paddock-supervisor` packages; custodians, offline, for rotation, the offline fallback and fleetd |
| Release public key | compiled into `paddock-supervisor` (`-ldflags -X main.releasePublicKey=…`) and given to the api role (`PADDOCK_RELEASE_PUBLIC_KEY_FILE`) | supervisor (verifies before installing), api (refuses uploads that do not verify) |
| Revocation release key (minisign, Ed25519) | **offline**, two holders (architecture §13.1) | release managers, to sign the `paddock-revoke` package |
| Revocation release public key | given to the api role (`PADDOCK_REVOKE_RELEASE_PUBLIC_KEY_FILE`) | api (refuses a `paddock-revoke` package that does not verify with it, and any other package signed with it) |

The supervisor is the only component that decides whether a release is installed; the server check only keeps
unsigned or mis-signed binaries out of the artifact bucket. Rotating the release key therefore means shipping a new
`paddock-supervisor` package (signed by the apt repository key) and changing `PADDOCK_RELEASE_PUBLIC_KEY_FILE`.

### Development key

`make dev-release-key` (run by `make dev-secrets`) creates password-less pairs in
`deploy/compose/.secrets/release/` (`minisign.pub`, `minisign.key`, and `revoke-minisign.pub`, `revoke-minisign.key`
for `paddock-revoke`). They are for development stacks only.

### Production key

Generate once on an offline machine with a passphrase, store the secret key and its passphrase with the custodians
as the offline backup copy (see `openbao.md` for the custodian procedure; it serves rotation, the offline fallback and
fleetd), and publish only the public key:

```sh
minisign -G -p paddock-release.pub -s paddock-release.key   # offline; choose a strong passphrase
```

Then give the key to the release workflow (once, and again after a rotation):

1. Create the GitHub environment `release` (*Settings → Environments*): deployment branches and tags *Selected* with
   the tag rule `v*` only, and the maintainer (two-factor authentication on) as *Required reviewer*.
2. Add the environment secrets `PADDOCK_RELEASE_KEY` (the complete content of `paddock-release.key`, both lines) and
   `PADDOCK_RELEASE_KEY_PASSPHRASE` (the passphrase). Never as repository secrets: only the environment's tag rule and
   approval keep them away from other workflows and refs.
3. Set the repository variable `PADDOCK_RELEASE_PUBLIC_KEY` to the complete two-line `paddock-release.pub`.
4. Restrict the release tags to the maintainer with a tag ruleset (*Settings → Rules → Rulesets → New tag ruleset*):
   enforcement *Active*, target tags `v*`, rules *Restrict creations*, *Restrict updates* and *Restrict deletions*,
   bypass list only the maintainer (`gh api users/<login> --jq .id` gives the user id). Otherwise anyone with write
   access could push a `v*` tag on a commit with a changed workflow and ask for the approval. Releases are tagged only
   on `main`; check 2 below rejects a tag on any other branch. The same with the CLI:

   ```sh
   gh api --method POST repos/phischl/paddock-mdm/rulesets --input - <<'EOF'
   {"name": "release tags", "target": "tag", "enforcement": "active",
    "conditions": {"ref_name": {"include": ["refs/tags/v*"], "exclude": []}},
    "rules": [{"type": "creation"},
              {"type": "update", "parameters": {"update_allows_fetch_and_merge": false}},
              {"type": "deletion"}],
    "bypass_actors": [{"actor_id": 18677661, "actor_type": "User", "bypass_mode": "always"}]}
   EOF
   ```

The trusted comment is part of the signature and must be exactly `paddock-agent version=<version> arch=<arch>`
(`amd64` or `arm64`): the server refuses other comments at upload (422 `release_signature_mismatch`), and the
supervisor installs a binary only as the version and architecture its comment names (plan M4b.1 decision 10). The
workflow and the offline fallback both sign with it:

```sh
minisign -S -s paddock-release.key -m paddockd -t "paddock-agent version=<version> arch=<arch>"
```

minisign reads the passphrase from stdin when stdin is not a terminal (one line; minisign 0.11 of Ubuntu 24.04 and
`aead.dev/minisign` alike). `packaging/sign-release.sh`, which the sign job runs, pipes it from the environment
variable `PADDOCK_RELEASE_KEY_PASSPHRASE`, so it never appears on a command line.

## Releasing

1. Build `paddockd` for each architecture with the version injected
   (`-ldflags "-X github.com/phischl/paddock-mdm/agent/internal/buildinfo.Version=<version>"`, `CGO_ENABLED=0`).
2. Sign it (above; the release workflow does it for a tagged release).
3. **Production:** put the signed files on the control-plane host (layout in `docs/operations/install.md` section 10)
   and run `./paddock agent-release <version> <dir>` in the bundle directory (`<dir>` and its files must be readable by
   the `paddock-api` service, uid 65532: `chmod -R a+rX <dir>`). It runs
   `paddock-server admin agent-release` in the `paddock-api` service, which verifies every signature first, then
   creates the release, uploads every binary and package and publishes it through the same use cases and audit events
   as the API below, with the system actor `paddock-server admin`, and prints the release as JSON (steps 3–5 in one
   command; a published release is refused). For automation, the platform API does the same step by step:
   create the release and upload each artifact as a platform administrator:
   `POST /api/platform/v1/agent-releases {"version"}`, then
   `PUT /api/platform/v1/agent-releases/<version>/artifacts/<arch>` with the binary as body and
   `X-Paddock-Minisig: <base64 of the .minisig file>`. The server stores it in `paddock-agent-artifacts` under
   `releases/<version>/<arch>/paddockd`.
4. Upload the Debian packages `paddock-agent`, `paddock-supervisor` and `paddock-revoke` of the release (built by
   `make deb`), each signed like the binary — `paddock-revoke` with the revocation release key, never with the agent
   release key, and never built with `REVOKE_TAGS` (the test build tag `paddock_revoke_testtarget`; `make
   agent-release` refuses it): `PUT /api/platform/v1/agent-releases/<version>/packages/<name>/<arch>` with the package
   as body and `X-Paddock-Minisig`. The server stores them under
   `packages/<version>/<name>_<version>_<arch>.deb`; the Paddock autoinstall installs new devices from them.
   fleetd (plan M5a) is uploaded the same way as package `fleet-osquery`, signed with the agent release key, with the
   query parameter `package_version=<fleetd version>`; it is stored as
   `packages/<version>/fleet-osquery_<fleetd version>_<arch>.deb` and installed by the agent, never by the autoinstall
   (`docs/operations/fleet.md`).
5. Publish: `POST …/<version>/publish`. Published releases are immutable.

In development, `make agent-release VERSION=x.y.z` does all of this with the development key, fleetd included.

### Public packages

Objects below `packages/` in `paddock-agent-artifacts` are **public-read** (plan M4b decision 1): packages contain
no secrets, and the generated autoinstall pins the SHA-256 of each package, so the installer refuses anything
else. The edge serves them at `https://bundles.<domain>/packages/<version>/<name>_<version>_<arch>.deb`; listing
the bucket and every other prefix still need credentials or a presigned URL. The bucket policy that allows this is

```json
{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"AWS": ["*"]},
  "Action": ["s3:GetObject"], "Resource": ["arn:aws:s3:::paddock-agent-artifacts/packages/*"]}]}
```

(`aws s3api put-bucket-policy --bucket paddock-agent-artifacts --policy file://policy.json`; the development
bootstrap `deploy/compose/scripts/rustfs-bundles-bootstrap.sh` sets it).

### Import from GitHub

A platform administrator imports an agent release from the official repository in the portal (*Agent releases*,
check and import) or through the platform API (ADR 0043):

- `GET /api/platform/v1/agent-release-source` names the configured source; it makes no outbound request.
- `POST /api/platform/v1/agent-release-source/check` lists the source's releases and reports the latest one and
  whether it can be imported; it changes nothing and is not audited.
- `POST /api/platform/v1/agent-releases/import {"version": "<version>"}` imports that version. It needs a step-up
  within the last 300 s (API tokens cannot import) and is audited as `agent_release.imported`; the release's
  `agent_release.created`, `agent_release.artifact_uploaded` and `agent_release.published` events follow with the
  administrator as actor.

**What is imported.** The candidates are the releases on the first page of the source (100 releases) that are not
drafts and whose tag is `v<version>` with a version of the release channel, `x.y.z` or `x.y.z-alpha.N`, `-beta.N`,
`-rc.N` (the rule of `make release-check`; GitHub's pre-release flag is ignored). The latest is the candidate with the
highest SemVer precedence. A version can be imported when it is newer than the newest **published** release on this
installation and no published release has it; a draft of the same version is continued, an equal or older version is
refused (409 `release_not_newer`). The import needs exactly what the release workflow ships, each file with its
`.minisig`: `paddockd_<version>_linux_amd64`, `paddockd_<version>_linux_arm64`, `paddock-agent_<version>_amd64.deb`
and `paddock-supervisor_<version>_amd64.deb`; packages of other architectures and `fleet-osquery_<fleetd
version>_<arch>.deb` are imported when they are attached with their signature. A missing file or signature refuses
the import (422 `release_incomplete`, naming the file). Every file is verified with the release public key
(`PADDOCK_RELEASE_PUBLIC_KEY_FILE`) — the binaries also with the trusted comment `paddock-agent version=<v>
arch=<arch>` — before anything is stored; GitHub is transport only, and `SHA256SUMS` and its Sigstore bundle are not
checked (RR-84). The release is published, ready for a rollout; the import never starts one.

**What is never imported.** `paddock-revoke` stays on the offline two-person path: sign it with the revocation key and
upload it with the host command or the package upload above, with or without a signature on GitHub. Unsigned files,
`SHA256SUMS*` and every other asset are ignored. fleetd that is not attached to the GitHub release is uploaded by hand
as above.

**Configuration** (environment of the `paddock-api` service, `.env`):

| Variable | Default | Meaning |
|---|---|---|
| `PADDOCK_AGENT_RELEASE_SOURCE_REPO` | `phischl/paddock-mdm` | `<owner>/<repo>` (letters, digits, `_`, `.`, `-`; neither part only dots); `off` switches the import off (air-gapped installations): the portal hides it, check and import answer 403 `release_source_disabled`. |
| `PADDOCK_AGENT_RELEASE_SOURCE_URL` | `https://api.github.com` | The API base; GitHub Enterprise Server: `https://<host>/api/v3`. `https` only (plain `http` is refused outside `PADDOCK_ENV=development`). |
| `PADDOCK_AGENT_RELEASE_SOURCE_TOKEN_FILE` | unset | Optional file with a token that can read the repository's releases; never logged, audited or shown. |

Without a token GitHub allows 60 API requests per hour per public address; a check costs one request, an import one
(the downloads are not counted). An exhausted limit answers 502 `release_source_unavailable` with the reset time;
nothing is retried. The token needs a Compose override next to the bundle's files, e.g.

```yaml
services:
  paddock-api:
    environment:
      PADDOCK_AGENT_RELEASE_SOURCE_TOKEN_FILE: /run/secrets/agent_release_source_token
    secrets: [agent_release_source_token]
secrets:
  agent_release_source_token:
    file: ./.secrets/agent_release_source_token
```

**Proxy.** The api reaches GitHub (`api.github.com`, `github.com` and `*.githubusercontent.com`, which serves the
downloads) directly or through the proxy of `HTTPS_PROXY` / `HTTP_PROXY`, which Compose passes to `paddock-api`. With
a proxy, `NO_PROXY` must list the stack's internal hosts the api talks to (`openbao`, `rustfs`, `escrow-reader` and
the hosts below `PADDOCK_DOMAIN`). Downloads follow at most 5 redirects and only to these hosts.

**Bounds.** The release list may have 1 MiB and 15 s, each file 128 MiB and 60 s, each signature 4 KiB, and the
whole import 90 s. A slow or filtered uplink fails the import without storing anything; an error after the release
was created (the artifact store fails mid-way) leaves a draft that the next import of the same version continues.
The host command `./paddock agent-release` (step 3 above, `docs/operations/install.md` section 10) remains the
fallback for installations without access to GitHub.

## Server release

A tag `v<version>` runs the release workflow (`.github/workflows/release.yml`, plan M6b decision 4, plan M7b
decision 23). Its build job calls, in this order:

1. `make release-images RELEASE_VERSION=<version> PUSH=1`: builds `ghcr.io/phischl/paddock-server`,
   `paddock-compiler` and `paddock-pgbackrest` with `docker buildx` for `linux/amd64` and `linux/arm64` as one
   multi-platform index each, with the OCI labels of the release (source, URL, documentation, title, description,
   version, revision, created, license, vendor, `io.paddock.channel`), pushes them and records the index and platform
   digests in `images.txt`.
2. `make release-packages RELEASE_VERSION=<version> RELEASE_PUBLIC_KEY_FILE=<production release public key>`: the
   Debian packages and the agent binaries for amd64 and arm64 with the production public key compiled into
   `paddock-supervisor`. It refuses the development keys, `TAGS` and `REVOKE_TAGS`.
3. `make release-sbom`: one SPDX SBOM per image and platform with `syft`, read from the registry.
4. `make release-bundle`: the operator bundle `paddock-deploy-<version>.tar.gz`, which references the three images
   by tag and index digest (`docs/operations/install.md`).
5. `make release-sums`: `SHA256SUMS` over every release file.
6. `make release-sign`: signs each image index recursively (index and platform manifests) with `cosign` keyless (the
   workflow's GitHub OIDC identity, Sigstore's public good instance; no key to keep), attaches each SBOM as a signed
   SPDX attestation to its platform manifest, and signs `SHA256SUMS` and the bundle (`*.sigstore.json`).

A smoke job then installs the bundle on one runner as two hosts (`deploy/bundle/ci/smoke.sh`: anonymous pull,
`./paddock check` on both, start, probes, a backup, an agent release with throwaway keys, idempotence); only a build
that passed it reaches the sign job, which signs the agent files with the agent release key (*Signing in the release
workflow*, below), and only after signing does the publish job create the draft release.

`<version>` is `x.y.z` or a pre-release `x.y.z-alpha.N`, `x.y.z-beta.N` or `x.y.z-rc.N` (`make release-check`
refuses anything else). Image tags: a pre-release gets only `<version>`; a plain `x.y.z` gets `<version>`,
`<major>.<minor>` and, when it is the highest plain `x.y.z` among the repository's `v*` tags, `latest` (a patch of an
older minor never moves `latest`). The Debian packages of a pre-release carry the Debian version `x.y.z~alpha.N`
(`~beta.N`, `~rc.N`) inside, which sorts before `x.y.z`, but their release files are named with the release version,
`<name>_0.1.0-alpha.1_amd64.deb`: GitHub renames asset names with characters such as `~`, and `SHA256SUMS`
names the files exactly as published (`make release-sums` refuses file names outside `[A-Za-z0-9._+-]`). Agents and
supervisors order the versions by SemVer precedence (`0.1.0-alpha.1 < 0.1.0-alpha.2 < 0.1.0-beta.1 < 0.1.0-rc.1 <
0.1.0`).

**Schema line.** The `CHANGELOG.md` section of every release states `Schema: unchanged` or `Schema: migrations
NNNNN–NNNNN` (the migrations of both databases since the previous release). The release manager checks it before
tagging; `docs/operations/upgrade.md` decides the rollback by it.

The images are pushed before `release-sign` runs, so a run that fails between the two leaves unsigned images under the
release tag. This is accepted (architect decision 2026-10-08): cosign signs digests, and consumers verify the
signature (`cosign verify`, below) instead of trusting the tag, so an unsigned image fails verification. Re-run the
release, or delete the tags, before announcing it. The three packages on `ghcr.io` must be public (a one-time
setting per package in its GitHub settings); the smoke job pulls anonymously and fails on a private package.

The workflow attaches the files to a **draft** GitHub release: `paddockd_<version>_linux_<arch>` and the
`paddock-agent` and `paddock-supervisor` packages with their `.minisig`, and
`paddock-revoke_<version>_<arch>-unsigned.deb`, which CI never signs. Locally, `make release-artifacts` runs the same
targets without pushing (`release-images` and `release-sbom` print their commands, the bundle references the local
images; the agent files stay `-unsigned`), and `make release-sign DRY_RUN=1` prints the cosign commands.
Verify a published image with

```sh
cosign verify ghcr.io/phischl/paddock-server:<version> \
  --certificate-identity-regexp '^https://github.com/phischl/paddock-mdm/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
cosign verify-attestation --type spdxjson … (same identity options)
cosign verify-blob SHA256SUMS --bundle SHA256SUMS.sigstore.json … (same identity options)
```

### Edge channel

Every green commit on `main` publishes the three images with the tags `edge` and `edge-<yyyymmdd>-<sha7>` (never
`latest` or a version tag; edge job of `.github/workflows/ci.yml`), signed and attested the same way, and a bundle
`paddock-deploy-edge-<yyyymmdd>-<sha7>.tar.gz` as the workflow artifact `paddock-deploy-edge` (30 days). Edge builds
are unsupported and never for production. Verify them with the identity
`^https://github.com/phischl/paddock-mdm/\.github/workflows/ci\.yml@refs/heads/main$`. A weekly workflow
(`ghcr-prune.yml`, `deploy/bundle/ci/prune-edge.sh`) deletes image versions older than 30 days whose tags are all
`edge-<date>-<sha>`; releases, `edge`, `latest` and untagged versions stay.

### Signing in the release workflow

The `sign` job runs after `smoke` (only a build that passed the smoke test is signed) in the GitHub environment
`release` (ADR 0006 amendment 2026-10-11). GitHub admits it only for a `v*` tag and holds it until the maintainer
approves the deployment (*Review deployments* on the run page); without approval the run stops there and nothing is
published.

**Before approving**, the maintainer checks, for the tag `<tag>` of the run:

1. The `sign` job waits for exactly that tag: the run page names `<tag>` and its commit, and the commit equals
   `git rev-parse <tag>^{commit}` after `git fetch origin --tags`.
2. The tag's commit is on `main`: `git merge-base --is-ancestor <tag> origin/main` succeeds.
3. The signing code at the tag is unchanged from `main`:
   `git diff --exit-code origin/main <tag> -- .github/workflows/release.yml packaging/sign-release.sh go.work go.work.sum ':(glob)**/go.mod' ':(glob)**/go.sum'`
   prints nothing (the workspace files pin the minisign the job builds; it resolves through `go.work`).

If any check fails, reject the deployment. The job:

1. builds `minisign` from the module pinned in the Go workspace (`aead.dev/minisign`, the library the server and the
   supervisor verify with) before the key exists, without a build cache;
2. writes `PADDOCK_RELEASE_KEY` with umask 077 to a file under `$RUNNER_TEMP` and runs `packaging/sign-release.sh`:
   `paddockd` for amd64 and arm64 and every `paddock-agent` and `paddock-supervisor` package, each with the trusted
   comment `paddock-agent version=<version> arch=<arch>`, under the final name without `-unsigned`, then verifies each
   signature and trusted comment against `PADDOCK_RELEASE_PUBLIC_KEY`;
3. deletes the key file in an `always()` step and uploads only the signed files and their `.minisig` (artifact
   `release-signed`).

The build and smoke jobs never see the key. The publish job replaces the `-unsigned` agent files with the signed ones
(`make release-merge-signed`, which refuses an agent file left unsigned and any signed `paddock-revoke`), recomputes
`SHA256SUMS` over the published names (`make release-sums`) and re-signs it keyless (`make release-sign-sums`), so
the checksums and their Sigstore signature cover exactly the files of the draft release.

Then, for each draft release:

1. Download the files, `SHA256SUMS` and `SHA256SUMS.sigstore.json`; check the checksums with `cosign verify-blob`
   (above), the files with `sha256sum -c SHA256SUMS` (the asset names are the names in `SHA256SUMS`, also for a
   pre-release) and each agent file with `minisign -V -p paddock-release.pub -m <file>`.
2. **paddock-revoke (offline, unchanged):** the two holders of the revocation release key sign
   `paddock-revoke_<version>_<arch>-unsigned.deb` offline as `paddock-revoke_<version>_<arch>.deb` (two-person rule).
3. Build fleetd for the release with `make fleetd-deb` (needs outbound HTTPS to Fleet's update server) and sign it
   offline with the custodians' backup copy of the agent release key.
4. Upload and publish through the platform API as under *Releasing* (`<version>` is the release version, e.g.
   `0.1.0-alpha.1`, while `dpkg-deb -f` shows the Debian version `0.1.0~alpha.1`; the upload takes name, version and
   architecture from the URL, not from the file name), then attach the remaining `.minisig` files to the GitHub
   release and publish it. Tagging and publishing a release are the product owner's decision.

The offline-signed `paddock-revoke_<version>_<arch>.deb` and its `.minisig` (and fleetd, if attached) are added after
the workflow ran, so they are **not** in `SHA256SUMS` or its Sigstore signature. Verify them with minisign instead:
`minisign -V -p paddock-revoke-release.pub -m paddock-revoke_<version>_<arch>.deb` against the revocation release
public key (fleetd against the agent release public key).

**Offline fallback.** If the sign job cannot run (environment or secrets unavailable, GitHub outage), sign on the
offline machine with the custodians' backup copy as before: check the inputs against their `SHA256SUMS`, remove the suffix
(`paddockd_<version>_linux_amd64-unsigned` → `paddockd`, `paddock-agent_<version>_amd64-unsigned.deb` →
`paddock-agent_<version>_amd64.deb`, …) of the files of the workflow artifact `release` or of a local
`make release-artifacts`, and sign each as under *Keys*.

## Rolling out

`POST …/<version>/rollout` (or *Start rollout* on the release page of the portal, or `./paddock agent-rollout` on the
control-plane host, see below) starts a staged rollout. Defaults:
waves 1 %, 10 %, 50 %, 100 % of the devices, each wave at least 1440 minutes, halt when the failed devices reach
`max(3, ceil(2 % of the devices in the waves so far))`. Overrides in the request body: `waves`,
`min_wave_minutes` (at least 60 outside development), `failure_threshold_percent`, `failure_threshold_min`.
Only one rollout runs at a time.

- A device belongs to a wave by its rollout bucket, `FNV-1a(device ID) mod 100`; the gateway offers the release at
  check-in to active devices whose bucket is below the current wave's percentage and that report another agent
  version and an architecture with an artifact. The buckets do not depend on the fleet's size, so a small fleet can
  have no device in the first waves: a one-device lab is reached by the 1 % wave only if its device's bucket is 0, and
  otherwise waits `min_wave_minutes` per wave. Start a small fleet's rollout with `waves` `[100]` (`--waves 100` on the
  host) or a short list such as `[50,100]`.
- The worker evaluates every 60 seconds: devices that reported `agent.update_failed` (except `downgrade_refused`;
  including `rollback_failed`) or `agent.rolled_back` for the version count as failed, each device once. Reaching the threshold halts the rollout (audit `agent_rollout.halted`, actor system) and
  stops the offer immediately. Otherwise the rollout advances after `min_wave_minutes` (`agent_rollout.advanced`)
  and completes after the last wave (`agent_rollout.completed`). A completed rollout keeps offering its release to
  devices that enroll later.
- *Halt* stops the offer within a minute (the next worker round); devices that already updated keep the release. *Resume* continues in the current wave; if
  the failures still reach the threshold, the next round halts it again.

### From the control-plane host

The host operator can start, halt and resume a rollout in the bundle directory of the control plane (or a lab host)
without a portal account (ADR 0034 amendment 2026-10-26):

```sh
./paddock agent-rollout <version> [--waves 1,10,50,100] [--min-wave-minutes N] [--failure-threshold-percent P] [--failure-threshold-min M]
./paddock agent-rollout-halt <version>
./paddock agent-rollout-resume <version>
```

They run `paddock-server admin agent-rollout`, `admin agent-rollout-halt` and `admin agent-rollout-resume` in the
`paddock-api` service: the same use cases, defaults, validation and audit codes (`agent_rollout.started`,
`agent_rollout.halted`, `agent_rollout.resumed`) as *Start rollout*, *Halt* and *Resume*, with the system actor
`paddock-server admin`. Resume only continues a rollout that was started and halted; it keeps the rollout's waves and
thresholds (a release that already has a rollout cannot be started again with other waves). Without options the defaults above apply. They print the
rollout as JSON; a refusal exits with status 1 and names the API's problem code on stderr, e.g.
`agent-rollout 1.2.0: refused: problem invalid_state: only published releases can be rolled out` (`invalid_state`
also for another running rollout, a halt of a rollout that does not run or a resume of a rollout that is not halted,
`already_exists` for a release that already has a rollout, `invalid_request` for invalid waves or bounds, `not_found`
for an unknown release or a resume of a release without a rollout). A usage error exits with status 2.

The commands skip the portal's sign-in, second factor and step-up: whoever can run commands in the `paddock-api`
container on the control-plane host can roll any published release out to every device (residual risk RR-90).
Restrict shell and container access on that host accordingly, and review `agent_rollout.*` events whose actor is
`paddock-server admin`.

## On the device

The agent downloads an offered release into `/var/lib/paddock/staging/<version>/`, checks size and SHA-256 and
signals `paddock-supervisor`. The supervisor verifies the signature and its trusted comment (the requested version
and its own architecture), refuses a version that is not newer than the active one (semantic version precedence;
any version may replace an active agent that cannot report its version), installs into the inactive slot
(`/opt/paddock/agent/A` or `B`), runs `paddockd self-test`, flips `/opt/paddock/agent/current`, and watches a
probation of 10 minutes: the new agent must keep running and check in. Three crashes or no check-in by the end of
the probation flip back. A version that failed is not tried again on that device. The supervisor writes the result
before it restarts the previous agent, so the restarted agent never stages the release it just rolled back from; a
request the agent stages for a release whose result it has not read yet is removed without a second install. The
outcomes in
`update-result.json` and their audit codes:

| Outcome | Event | Audit code | Meaning |
|---|---|---|---|
| `updated` | `agent.updated` | `device.agent_updated` | Self-test and probation passed; the new version runs. |
| `signature_invalid` | `agent.update_failed` | `device.agent_update_failed` | Signature, version or architecture of the release did not verify; nothing installed. |
| `downgrade_refused` | `agent.update_failed` | `device.agent_update_failed` | The release is not newer than the active agent; not counted as a rollout failure. |
| `self_test_failed` | `agent.update_failed` | `device.agent_update_failed` | Installing or the self-test failed, or the switch failed; the previous version runs. |
| `rolled_back` | `agent.rolled_back` | `device.agent_rolled_back` | The probation failed and the supervisor flipped back; the previous version runs. |
| `rollback_failed` | `agent.update_failed` | `device.agent_rollback_failed` | The probation failed and the flip back failed; the new version keeps running and the supervisor retries the rollback (ADR 0024). |

Troubleshooting on a device: `journalctl -u paddock-supervisor`, `readlink /opt/paddock/agent/current`,
`/var/lib/paddock/state/update-result.json` (until the event is delivered), `/var/lib/paddock/state/probation.json`
(during a probation, and while a rollback is pending).

If `probation.json` is unreadable when the supervisor starts (disk corruption), the supervisor rebuilds the probation
from the slots while they still describe an update: `current` points at `A` or `B`, the other slot holds an agent
with a valid version, the active agent is newer, and `update-result.json` does not already name it `updated`. The
rebuilt log carries `"rebuilt": true` and a full probation runs again. If `update-result.json` names the active
version `rolled_back` or `rollback_failed`, or the marker `/var/lib/paddock/state/rollback-pending` exists (the
supervisor keeps it from a failed rollback until the rollback is made; do not remove it by hand), the supervisor
resumes the pending rollback instead. Otherwise it drops the log; both cases are logged at error level with the
reason:

```sh
journalctl -u paddock-supervisor -p err | grep 'probation log'
```

### A rollback that failed

The portal lists the device on the attention page as *Agent rollback pending* (kind `agent_rollback_pending`, detail:
the version), and the audit log shows `device.agent_rollback_failed`. The device keeps working on the new version.
The supervisor keeps `probation.json` with `"rollback_pending": true` and retries the flip back on its own: the first
retry 10 seconds after the failure, then with a doubling wait up to every 5 minutes, also after a restart of the
supervisor or the device. Every failed retry is logged at error level with the attempt, the active slot, the target
slot and the error:

```sh
journalctl -u paddock-supervisor -p err | grep 'retrying the rollback failed'
```

There is no way back through the update channel: a release that is not newer than the active agent, also the
previous version, is refused as `downgrade_refused`, and update offers are ignored while the rollback is pending.
The way back is on the device:

1. Remove the cause that the error names, typically a read-only or full file system under `/opt/paddock/agent`, or
   a stray directory `/opt/paddock/agent/.current.tmp` (`rm -r /opt/paddock/agent/.current.tmp`). The next retry
   flips back.
2. If the flip still fails, point `current` at the previous slot by hand; the next retry recognises it, restarts the
   previous agent and reports the rollback:

   ```sh
   cat /var/lib/paddock/state/probation.json      # from_slot is the previous slot, here A
   ln -sfn A /opt/paddock/agent/.current.new && mv -T /opt/paddock/agent/.current.new /opt/paddock/agent/current
   ```

Once the rollback is made, the device reports `device.agent_rolled_back` and the attention entry disappears. It also
disappears when the device reports another agent version. The rollout counts the device once as failed, whether it
reported `rollback_failed`, `rolled_back` or both.

## Update policy

An organization chooses whether its devices take agent releases automatically (*Updates* → *Agent updates*,
`agent_update_policy` of the update settings, also in the declarative document; ADR 0037 decision 1):

- **Automatic** (default): devices install every release the platform rolls out, in their wave.
- **Manual**: devices install an agent release only when an administrator requests it per device (*Update agent
  now*). The same policy holds back the supervisor package and fleetd upgrades; a missing fleetd is still installed.

A device group can override the organization's policy; a device in several groups is `manual` when any of them says
so, and `automatic` when a group says so on a `manual` organization. The bundle carries the result
(`agent.update_policy`, absent for automatic). An agent on `manual` logs `agent update offer ignored by the
organization's policy` once per offered version. Devices left on an old agent appear on the attention page as
`agent_outdated` and leave the support window after N-2 minor releases (426 `agent_unsupported`, residual risk RR-51).

## Update now

*Update agent now* on the device page (`POST /api/v1/devices/{id}/update-agent`, organization administrators and
operators, audited as `device.agent_update_requested`) asks one active device to install the release the platform
currently offers at its next check-in — outside its rollout wave and regardless of the update policy, with the usual
self-test, probation and rollback. It is refused (409 `invalid_state`) while no release is offered (no rollout, or a
halted one), when the device already runs the release, or when the release has no artifact for the device's
architecture. The request ends with the device's report of that version (`device.agent_updated`, `…update_failed` or
`…rolled_back`) or after 24 hours; an earlier failure of the same version on the device is retried once per request.

## Supervisor package

A device updates `paddock-supervisor` from the current release (ADR 0037 decision 3, amendment 2026-10-18): while a
release's rollout runs or after it completed, the v2 bundle of every device whose agent reports a semantic version
and whose rollout bucket the waves reached carries the release's `paddock-supervisor` package per architecture
(`agent.supervisor_packages`, SHA-256 in the signed bundle) — the same wave gate as the agent offer, so the
supervisor never goes to every device at once. An open *Update agent now* request for the release lifts the wave
gate for that device, as for the agent. Nothing is offered after the rollout was halted. A new wave reaches the
bundles at the compiler's next reconcile. An agent installs the package only when

- it runs that release itself (agent first, supervisor second, in the same waves),
- `dpkg` reports an older `paddock-supervisor` (the Debian form `0.1.0~alpha.4` of a pre-release counts as
  `0.1.0-alpha.4`),
- the update policy is automatic or an *Update agent now* request is open (after the agent update it stays open
  until the supervisor's result arrives while the device reports an older supervisor or an outdated fleetd, at most
  24 hours; a device that already runs the release can be asked again under the same condition),
- no agent update is pending, no supervisor upgrade runs, the version did not fail on the device before and is not
  waiting for its retry.

The agent downloads the package to `/var/lib/paddock/packages/`, writes `/var/lib/paddock/state/supervisor-upgrade.json`
and starts `paddockd supervisor-upgrade` in the transient unit `paddock-supervisor-upgrade.service` (`systemd-run`,
outside the supervisor's cgroup, so the restart by the package's postinst does not stop it). The helper copies
`/usr/sbin/paddock-supervisor` and its unit file to `/var/lib/paddock/packages/supervisor-backup/`, runs `dpkg -i`
(killed after 15 minutes) and waits up to 10 minutes for a check-in of the agent after the installation; the new
supervisor must then keep running with the same process for a minute. It writes
`/var/lib/paddock/state/supervisor-upgrade-result.json`, which the agent reports as `agent.supervisor_updated`:

| Outcome | Audit code | Meaning |
|---|---|---|
| `updated` | `device.supervisor_updated` | The new supervisor runs and its agent checked in. |
| `install_failed` | `device.supervisor_update_failed` | The backup or `dpkg -i` failed, or the helper did not finish within 30 minutes; the backup is restored only if the supervisor is not running afterwards. |
| `rolled_back` | `device.supervisor_update_failed` | No check-in within 10 minutes, or the new supervisor kept restarting: the backup was copied back and the supervisor restarted. |
| `rolled_back_unreachable` | `device.supervisor_update_failed` | The new supervisor ran stable, but the agent's check-ins did not reach the server within 10 minutes (`/run/paddock/last-checkin-failed`): the backup was copied back. The device retries the version 24 hours later at the earliest, at most 3 times (`supervisor_retry` in `/var/lib/paddock/state/state.json`). |

`install_failed` and `rolled_back` count once per device toward the failure threshold of the release's rollout,
exactly like a failed agent update (`agent_update_report` outcome `supervisor_failed`): enough failures halt the
rollout, and a halted rollout offers neither the agent nor the supervisor. `rolled_back_unreachable` never counts: a
server outage is no defect of the release. After a rollback `dpkg -l paddock-supervisor` may name the
new version while the previous binary runs (`/usr/sbin/paddock-supervisor version`) until the next successful
upgrade. A failed version is not installed again on that device (`failed_supervisor_version` in
`/var/lib/paddock/state/state.json`); a newer release is. Troubleshooting:

```sh
journalctl -u paddock-supervisor-upgrade -u paddock-supervisor --since today
cat /var/lib/paddock/state/supervisor-upgrade-result.json   # until the event is delivered
```

## GitHub release workflow

`.github/workflows/release.yml` runs on tags `v*.*.*`. Before the first tag, set the repository variable
`PADDOCK_RELEASE_PUBLIC_KEY` to the **complete two-line** production minisign public key (`untrusted comment:` line plus
key line, as in the `.pub` file), and create the environment `release` with its two secrets (*Production key*). The
workflow refuses to run without them and `make release-key-check` refuses a development key. It pushes the server
images, signs them keylessly, signs the agent files in the `sign` job after the maintainer's approval, and creates a
**draft** release; sign `paddock-revoke` offline as described above before publishing the release.
