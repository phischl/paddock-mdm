# Agent releases and staged rollouts

How agent releases are signed, uploaded and rolled out (plan M2b §3.2–3.3, design contract 3–6).

## Keys

| Key | Where | Used by |
| --- | --- | --- |
| Release key (minisign, Ed25519) | **offline**; the secret key never touches CI, the control plane or a device | release manager, to sign `paddockd` |
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
(see `openbao.md` for the custodian procedure), and publish only the public key:

```sh
minisign -G -p paddock-release.pub -s paddock-release.key   # offline; choose a strong passphrase
```

Sign each binary offline and copy only the binary and its `.minisig` back. The trusted comment is part of the
signature and must be exactly `paddock-agent version=<version> arch=<arch>` (`amd64` or `arm64`): the server refuses
other comments at upload (422 `release_signature_mismatch`), and the supervisor installs a binary only as the
version and architecture its comment names (plan M4b.1 decision 10):

```sh
minisign -S -s paddock-release.key -m paddockd -t "paddock-agent version=<version> arch=<arch>"
```

## Releasing

1. Build `paddockd` for each architecture with the version injected
   (`-ldflags "-X github.com/phischl/paddock-mdm/agent/internal/buildinfo.Version=<version>"`, `CGO_ENABLED=0`).
2. Sign it (above).
3. Create the release and upload each artifact through the platform API as a platform administrator:
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

## Server release

A tag `v<version>` runs the release workflow (`.github/workflows/release.yml`, plan M6b decision 4). It calls

1. `make release-artifacts RELEASE_VERSION=<version> PUSH=1 RELEASE_PUBLIC_KEY_FILE=<production release public key>`:
   builds `ghcr.io/phischl/paddock-server:<version>` and `ghcr.io/phischl/paddock-compiler:<version>` (OCI
   labels for source, version, revision and license), pushes them and records their digests in `images.txt`,
   builds the Debian packages and the agent binaries for amd64 and arm64 with the production public key compiled
   into `paddock-supervisor`, writes an SPDX SBOM per image with `syft` and `SHA256SUMS` over all files, all into
   `dist/release/<version>/`. It refuses the development keys, `TAGS` and `REVOKE_TAGS`.
2. `make release-sign RELEASE_VERSION=<version>`: signs each pushed image by digest with `cosign` keyless (the
   workflow's GitHub OIDC identity, Sigstore's public good instance; no key to keep), attaches its SBOM as a signed
   SPDX attestation, and signs `SHA256SUMS` (`SHA256SUMS.sigstore.json`).

The workflow attaches the files to a **draft** GitHub release. Debian packages and agent binaries carry the suffix
`-unsigned`: CI never holds the release keys, so they are not releasable as they are. Locally, the same targets run
with images that are only built (`PUSH` unset) and `make release-sign DRY_RUN=1`, which checks the inputs and
prints the cosign commands. Verify a published image with

```sh
cosign verify ghcr.io/phischl/paddock-server:<version> \
  --certificate-identity-regexp '^https://github.com/phischl/paddock-mdm/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
cosign verify-attestation --type spdxjson … (same identity options)
cosign verify-blob SHA256SUMS --bundle SHA256SUMS.sigstore.json … (same identity options)
```

### Offline signing of the agent artifacts

On the offline signing machine, for each draft release:

1. Download the `-unsigned` files, `SHA256SUMS` and `SHA256SUMS.sigstore.json`; check the bundle with
   `cosign verify-blob` (above) and the files with `sha256sum -c SHA256SUMS`.
2. Remove the suffix (`paddockd_<version>_linux_amd64-unsigned` → `paddockd`,
   `paddock-agent_<version>_amd64-unsigned.deb` → `paddock-agent_<version>_amd64.deb`, …) and sign every binary and
   package as described under *Keys*: `paddockd` and the `paddock-agent` and `paddock-supervisor` packages with the
   agent release key, the `paddock-revoke` package with the revocation release key (two holders).
3. Build fleetd for the release with `make fleetd-deb` (needs outbound HTTPS to Fleet's update server) and sign it
   with the agent release key.
4. Upload and publish through the platform API as under *Releasing*, then attach the `.minisig` files to the GitHub
   release and publish it. Tagging and publishing a release are the product owner's decision.

## Rolling out

`POST …/<version>/rollout` (or *Start rollout* on the release page of the portal) starts a staged rollout. Defaults:
waves 1 %, 10 %, 50 %, 100 % of the devices, each wave at least 1440 minutes, halt when the failed devices reach
`max(3, ceil(2 % of the devices in the waves so far))`. Overrides in the request body: `waves`,
`min_wave_minutes` (at least 60 outside development), `failure_threshold_percent`, `failure_threshold_min`.
Only one rollout runs at a time.

- A device belongs to a wave by its rollout bucket, `FNV-1a(device ID) mod 100`; the gateway offers the release at
  check-in to active devices whose bucket is below the current wave's percentage and that report another agent
  version and an architecture with an artifact.
- The worker evaluates every 60 seconds: devices that reported `agent.update_failed` or `agent.rolled_back` for the
  version count as failed. Reaching the threshold halts the rollout (audit `agent_rollout.halted`, actor system) and
  stops the offer immediately. Otherwise the rollout advances after `min_wave_minutes` (`agent_rollout.advanced`)
  and completes after the last wave (`agent_rollout.completed`). A completed rollout keeps offering its release to
  devices that enroll later.
- *Halt* stops the offer within a minute (the next worker round); devices that already updated keep the release. *Resume* continues in the current wave; if
  the failures still reach the threshold, the next round halts it again.

## On the device

The agent downloads an offered release into `/var/lib/paddock/staging/<version>/`, checks size and SHA-256 and
signals `paddock-supervisor`. The supervisor verifies the signature and its trusted comment (the requested version
and its own architecture), refuses a version that is not newer than the active one (semantic version precedence;
any version may replace an active agent that cannot report its version), installs into the inactive slot
(`/opt/paddock/agent/A` or `B`), runs `paddockd self-test`, flips `/opt/paddock/agent/current`, and watches a
probation of 10 minutes: the new agent must keep running and check in. Three crashes or no check-in by the end of
the probation flip back. The outcome is reported as `device.agent_updated`, `device.agent_update_failed`
(`signature_invalid`, `downgrade_refused`, `self_test_failed`) or `device.agent_rolled_back`; a version that failed is
not tried again on
that device.

Troubleshooting on a device: `journalctl -u paddock-supervisor`, `readlink /opt/paddock/agent/current`,
`/var/lib/paddock/state/update-result.json` (until the event is delivered), `/var/lib/paddock/state/probation.json`
(during a probation).
