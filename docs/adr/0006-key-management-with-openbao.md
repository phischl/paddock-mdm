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
