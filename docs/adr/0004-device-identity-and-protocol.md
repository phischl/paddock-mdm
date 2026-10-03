# 0004 — Device identity and agent–server protocol (A5, A6)
Status: Proposed

## Context
A5: device-initiated, mutual authentication, replay protection, idempotent commands, works through restrictive
proxies. A6: identity issued at enrollment, bound to one organization, rotatable, revocable, cloned disk
image detectable. The concept's diagram routes device authentication through Authentik.

## Options
- **mTLS with device certificates.** + Standard. − Breaks behind TLS-intercepting proxies.
- **Authentik OAuth client per device.** + One identity system. − Not built for machine identities at scale,
  no TPM binding, couples every check-in to IdP availability.
- **Per-request signatures with a device key (TPM-resident where available) plus end-to-end signed payloads.**
  + Proxy-tolerant, end-to-end, stateless verification, TPM binding prevents cloning. − Own small protocol.

## Decision
Per-request ECDSA P-256 signatures over a canonical string (method, path, device, key ID, timestamp,
nonce, body hash, sequence), timestamp window ±300 s, nonce cache 600 s. Server authenticity for the parts
that matter comes from DSSE-signed bundles and commands; secrets are HPKE-encrypted to a device X25519 key.
Enrollment with one-time, organization-bound tokens. Clone detection via a server-issued monotonic `seq`
echoed by the device, plus hardware fingerprints. Devices authenticate against **Paddock**, not Authentik
(confirmed by the product owner: **user** logins at the device go through Himmelblau against Authentik, which provides
MFA flows and upstream brokering; the **device** exchanges all other data and configuration with Paddock only).
Besides the 5-minute timer the agent checks in immediately on network-up, resume from suspend and boot
(rate-limited to one per 60 s), so pending user locks arrive within seconds of connectivity.

## Consequences
+ Works through intercepting proxies; device identity cannot be copied when TPM-resident.
− The protocol must be specified and fuzz-tested (`pkg/protocol`). File-based keys on TPM-less devices are cloneable;
detection relies on `seq` divergence.
