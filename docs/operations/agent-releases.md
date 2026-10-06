# Agent releases and staged rollouts

How agent releases are signed, uploaded and rolled out (plan M2b §3.2–3.3, design contract 3–6).

## Keys

| Key | Where | Used by |
| --- | --- | --- |
| Release key (minisign, Ed25519) | **offline**; the secret key never touches CI, the control plane or a device | release manager, to sign `paddockd` |
| Release public key | compiled into `paddock-supervisor` (`-ldflags -X main.releasePublicKey=…`) and given to the api role (`PADDOCK_RELEASE_PUBLIC_KEY_FILE`) | supervisor (verifies before installing), api (refuses uploads that do not verify) |

The supervisor is the only component that decides whether a release is installed; the server check only keeps
unsigned or mis-signed binaries out of the artifact bucket. Rotating the release key therefore means shipping a new
`paddock-supervisor` package (signed by the apt repository key) and changing `PADDOCK_RELEASE_PUBLIC_KEY_FILE`.

### Development key

`make dev-release-key` (run by `make dev-secrets`) creates a password-less pair in
`deploy/compose/.secrets/release/` (`minisign.pub`, `minisign.key`). It is for development stacks only.

### Production key

Generate once on an offline machine with a passphrase, store the secret key and its passphrase with the custodians
(see `openbao.md` for the custodian procedure), and publish only the public key:

```sh
minisign -G -p paddock-release.pub -s paddock-release.key   # offline; choose a strong passphrase
```

Sign each binary offline and copy only the binary and its `.minisig` back:

```sh
minisign -S -s paddock-release.key -m paddockd -t "paddockd <version> <arch>"
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
4. Publish: `POST …/<version>/publish`. Published releases are immutable.

In development, `make agent-release VERSION=x.y.z` does all of this with the development key.

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
signals `paddock-supervisor`. The supervisor verifies the signature, installs into the inactive slot
(`/opt/paddock/agent/A` or `B`), runs `paddockd self-test`, flips `/opt/paddock/agent/current`, and watches a
probation of 10 minutes: the new agent must keep running and check in. Three crashes or no check-in by the end of
the probation flip back. The outcome is reported as `device.agent_updated`, `device.agent_update_failed`
(`signature_invalid`, `self_test_failed`) or `device.agent_rolled_back`; a version that failed is not tried again on
that device.

Troubleshooting on a device: `journalctl -u paddock-supervisor`, `readlink /opt/paddock/agent/current`,
`/var/lib/paddock/state/update-result.json` (until the event is delivered), `/var/lib/paddock/state/probation.json`
(during a probation).
