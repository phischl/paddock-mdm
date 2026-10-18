# 0040 — Transport trust: what TLS protects, no pinning, server-side freeze detection
Status: Accepted (architect, 2026-10-18)

## Context

A maintainer asked whether DNS manipulation can make a device talk to a man-in-the-middle (plan M8f, PDK-293).
Verified in the code: bundles and commands are DSSE-signed and verified against trust anchors from the enrollment
configuration (`/etc/paddock/trust.json`), bundle versions are monotonic, device requests are signed with the device
key, the check-in response carries the organization's signed time ticket and signed commands, agent releases are
minisign-signed with the supervisor's key, escrow secrets are encrypted to the escrow key. A DNS-only attacker fails
at TLS (system CA store). An attacker who holds a certificate the device trusts — an interception CA installed on the
device, a compromised public CA — still cannot forge configuration, commands, releases or device requests, but can:
read health and inventory reports (signed, not encrypted); capture an enrollment token at enrolment; phish the device
login, because Himmelblau's OIDC and fleetd's connection trust the system CA store and pin nothing; **freeze** a
device by withholding newer bundles (for example a revoked sudo right) while proxying its check-ins; or block the
device entirely, which makes it stale and, with the dead man's switch enabled, locks it after the period.

Constraints: devices must work behind TLS-intercepting corporate proxies (architecture §6.1, requirement C1), which
rules out pinning by default; the agent must stay fail safe (contract 8); the server learns a device's applied bundle
version with every signed check-in, which the attacker cannot alter.

## Options

- **A. Certificate or SPKI pinning per organization** (device gateway; optionally Authentik for Himmelblau and Fleet
  for fleetd), off by default, carried in the enrollment configuration with rotation and rollover. + Closes the
  confidentiality and phishing exposure for organizations without interception proxies. − A pin rollover that goes
  wrong bricks the fleet's communication; three pin sets to manage (gateway, Authentik, Fleet); Himmelblau and fleetd
  need their own settings (`--fleet-certificate` exists for fleetd; Himmelblau has no documented pin); no customer
  asks for it yet.
- **B. Encrypt reports to a server key (HPKE)** in addition to TLS. + Reports stay confidential under interception.
  − A new key in OpenBao with rotation, a new envelope in the device protocol, a compatibility window (ADR 0013); the
  reports hold inventory and health, not secrets.
- **C. Sign the bundle pointer or a per-device "latest version" statement** so that the agent detects withholding.
  + The device notices a freeze itself. − The time ticket is per organization, the bundle version per device; a
  per-device signed statement costs a signature per device per check-in in the gateway's hot path; and the attacker
  who can withhold a bundle can withhold the statement too, so detection on the device needs a timeout anyway, which
  the server-side check provides without new keys.
- **D. Server-side freeze detection** (chosen): the server knows, from the signed check-ins, that a device is online
  and which bundle it applied; a device that keeps checking in but stays behind its newest bundle beyond a grace
  period is listed on the attention page. + No new key, no protocol change, works for every cause of "not applied";
  cannot be hidden by the attacker (a modified request fails the signature; a dropped request makes the device stale).
  − A delay of the grace period; it names the symptom, not the cause (M11's apply status adds the cause later).
- **E. Accept and document only.** − The freeze gap would stay invisible.

## Decision

1. **What the connection protects.** TLS protects the confidentiality of reports and of the enrollment token and
   the authenticity of the device login's and fleetd's endpoints; integrity and the revocation path never depend on
   it (unchanged, architecture §6.1). Pinning (A), report encryption (B) and a signed pointer (C) are **deferred**;
   the residual risk is recorded (RR-64).
2. **Freeze detection on the server.** The attention kind `config_behind` lists an active device whose newest bundle
   was compiled more than one hour ago, which checked in after that hour, and whose applied bundle version is older
   than the newest (plan M8f §3.6). The grace period is one hour (bundles are compiled within seconds and applied at
   the next check-in, at most ~6 minutes later; an hour tolerates a sealed OpenBao or a compiler restart). No audit
   event: the kind is a derived condition like `agent_outdated`.
3. **Blocking and the dead man's switch.** A blocked connection is treated like an outage: staleness alerts and,
   when enabled, the self-lock after the period. The setting says so (plan M8f §3.6 decision 25; RR-65).
4. **Enrollment token.** Unchanged: expiry, maximum uses, revocation and approval unless auto-approve is set (RR-05).

Revisit A when a customer requires pinning or an interception-free fleet is the norm; revisit B when reports carry
data classified as confidential; revisit C if the gateway gains per-device signing for another reason.

## Consequences

+ The freeze gap is closed with one view branch and one portal kind; operators see a withheld or failed
  configuration within an hour. + The dead man's switch's consequence under blocking is stated where it is enabled.
− Confidentiality of reports and the device login's endpoint authenticity remain TLS-only (RR-64); a withheld
configuration is visible only after an hour (RR-65). Follow-ups: M11 apply status names the cause of
`config_behind`; the deferred options above have their triggers.
