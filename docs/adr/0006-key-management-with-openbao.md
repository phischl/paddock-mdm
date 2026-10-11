# 0006 — Key management with OpenBao (A3)
Status: Proposed

## Context
A3: keys for agent updates, bundles, revocation tokens, escrowed headers and recovery keys; never in plaintext
on the application server; rotation and revocation defined; compromise of one key type does not compromise
others; self-hosted without a commercial service. No HSM is available.

## Options
- **OpenBao Transit (MPL-2.0) + offline release keys.** + Keys non-exportable; one key and policy per purpose;
  batch signing; open source. − Another stateful service with unseal procedure.
- **OpenBao + HSM (PKCS#11).** + Higher assurance. − Hardware cost; not available.
- **age/SOPS + offline keys only.** − Online bundle signing would need a plaintext key on a worker; violates A3.

## Decision
OpenBao with integrated Raft, Shamir unseal 3 of 5. Transit keys: `bundle-signing`, `command-signing`,
`revocation-signing`, `time-ticket`, `audit-chain` (Ed25519) and `escrow-wrap` (RSA-4096 OAEP, decrypt only
via `escrow-reader` / `revocation-recovery` policies). One AppRole per server role. Agent release and
revocation-module release keys are offline Ed25519 (minisign) on YubiKeys; their public keys are compiled
into supervisor and `paddock-revoke` respectively.

## Consequences
+ A compromised gateway or API cannot sign bundles or revocations.
− OpenBao sealed ⇒ no new bundles or reveals (devices keep working). Unseal shares need named custodians.

## Amendment 2026-10-11 — agent release key in a protected CI environment

The agent release key (minisign, Ed25519) is used for signing in the release workflow; an offline backup copy stays
with the custodians for rotation, the offline fallback and fleetd. Its secret key and passphrase are secrets of the GitHub environment `release`; only tags `v*` may deploy to it, and every run waits for
the approval of a required reviewer (the maintainer, with two-factor authentication). The workflow signs `paddockd`
for each architecture and the `paddock-agent` and `paddock-supervisor` packages with the trusted comment
`paddock-agent version=<version> arch=<arch>`, verifies each signature against the public key in the repository
variable `PADDOCK_RELEASE_PUBLIC_KEY`, and attaches the files and their `.minisig` signatures to the draft release.
The key never reaches the build or smoke jobs, logs, artifacts other than the signatures, or the control plane.
The revocation release key (`paddock-revoke`) stays offline with two holders; `paddock-revoke` is published
unsigned and must be signed offline before use.

Consequence: a compromise of the GitHub repository together with the maintainer's account can produce a validly
signed agent. Accepted for the operational cost of offline signing; mitigated by the required approval, tag-only
deployment, staged rollout with automatic stop, and the server-side and supervisor-side signature checks. Rotation
stays as described above (new supervisor package, new public key).
