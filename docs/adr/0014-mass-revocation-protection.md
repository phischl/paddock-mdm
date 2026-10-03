# 0014 — Mass-revocation protection (A4)
Status: Proposed

## Context
A4: a single compromised session cannot revoke more than a defined number of devices; step-up for destructive actions;
rate limits and alerting.

## Options
- **Rate limits in the API only.** − A compromised API node bypasses them.
- **Separate `revocation-issuer` role holding the revocation key, verifying Authentik-signed step-up proofs and enforcing limits.**
  + Compromise of API or database alone cannot mint revocations; approvals are cryptographically bound to Authentik.
  − More moving parts; Authentik becomes part of the revocation trust chain.

## Decision
Second option. Every Lock/Destroy carries step-up ID tokens (`auth_time` ≤ 300 s, WebAuthn flow); Destroy needs two
distinct subjects. Limits enforced in the revocation-issuer: per admin 3 per hour and 10 per 24 h; per organization
20 per 24 h (configurable downwards only; upwards only by platform admin with audit). Exceeding blocks the request,
raises an alert and audit event, and freezes further revocations of that admin for 24 h. `paddock-revoke` on the device
additionally refuses more than one revocation per 24 h.

## Consequences
+ Satisfies the mass-revocation gate. − Large intentional revocations (office closure) require a platform admin to raise limits.
