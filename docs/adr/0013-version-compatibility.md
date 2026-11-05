# 0013 — Server–agent version compatibility (A7)
Status: Proposed

## Context
A7: defined support window; outdated agents degrade predictably, never silently; server upgrades never strand the fleet.

## Options
- **Versioned device API path + bundle schema negotiation + support window.** + Predictable. − Server keeps old renderers.
- **Lock-step versions.** − Strands offline devices after every server upgrade.

## Decision
Device API `/v1` (additive changes only; a new major runs in parallel ≥ 12 months). Agents report supported
`schema_versions`; the compiler renders the newest common one. Support window: current + two previous minors or
6 months, whichever is wider. Outside the window: 426 `agent_unsupported` with an update pointer; last state stays
applied; portal shows `agent_outdated`. Server upgrade tooling refuses to drop a version used by > 1 % of active devices.

## Consequences
+ No silent degradation. − Renderers for old schema versions must be maintained within the window.

## Amendment 2026-10-16 (ADR 0034)
Tightening `pkg/policy` (the agent's defence-in-depth path check) is not a bundle format change: the server enforces
the policy before it signs a bundle, so an agent inside the support window that still carries the older, looser
check accepts every bundle a newer server produces. During a staged agent rollout the only difference is on the
device: an older agent deletes an unchanged managed file that left the bundle, a newer agent keeps a file on a
denied path and stops tracking it. Operators roll the agent out before deleting denied definitions (residual risk
RR-36).

## Amendment 2026-10-16 (2) — upgrade order of the path tiers (ADR 0034 amendment of the same date)
The trigger named in the first amendment of this date is wrong: an older agent does not wait for an administrator to
delete denied definitions. The server stops shipping files on denied paths as soon as it is upgraded, and an agent
older than that release deletes every unchanged file that leaves its bundle at its next check-in. For that release the
upgrade order is therefore binding and reverses the usual order: **agents first, then the server** (the agent release
is uploaded to the running server of the same minor version and rolled out to every device before the control plane
is upgraded). Devices that are offline during the rollout and return with an older agent after the server upgrade are
residual risk RR-36.

## Amendment 2026-11-04 — the support window until 0.1.0 (ADR 0047)
Every alpha release is `0.1.0-alpha.N`: the minor version of the decision never changes, so "current and two
previous minors" is undefined. Until 0.1.0 is cut, the window is **the server's own release and the two previous
releases** (alpha.N, N−1, N−2). The "server upgrade tooling" of the decision is `./paddock upgrade-check` (ADR 0047
decision 2): it refuses an upgrade that would leave more than 1 % of active devices (or more than 5, whichever is
larger) outside the window, unless the operator overrides it. With 0.1.0 the minor-version rule applies again.
The 426 `agent_unsupported` answer of the decision was never built and is replaced: the gateway accepts the
check-in of an agent outside the window and answers it with the `agent_update` pointer only — no bundle pointer,
no commands — and the portal shows the device as `agent_outdated` (plan M16 decision 4a). An agent that cannot
check in at all could never learn of the update; the last applied state stays in force either way.

## Amendment 2026-11-04 (2) — safety commands reach out-of-window agents (PDK-765)
The out-of-window answer of the previous amendment withholds every command. Since `agent_version` is asserted by the
device, a device that reports an old version would thereby escape a Lock or Destroy, which contradicts F5 ("no later
than the device's next contact") and agent design contract 7; and a device that misses `delete_self_lock` keeps an
armed dead man's switch after the organization turned it off, which contradicts contract 8. The rule is therefore
narrowed: an agent outside the window still receives its pending **safety commands**, reported as delivered like any
other command:

- the **revocation tokens** (DSSE payload type `application/vnd.paddock.revocation.v1+json`, actions `lock`,
  `destroy` and `self_lock`), and
- **`delete_self_lock`** (`pkg/command` type, payload type `application/vnd.paddock.command.v1+json`), which
  removes the stored self-lock token when the organization turns the dead man's switch off.

The bundle pointer and every other command of the `pkg/command` registry (`uninstall`, `install_now`,
`rotate_admin_password`, `encrypt_disk`, `encrypt_disk_abort`) stay withheld. The gateway selects by the unverified
payload type and, for commands, the payload's `type`; the envelopes in the cache are the server's own and the device
verifies every signature. It never interprets a revocation token. The selection runs before the per-response cap of
20 commands, so withheld commands cannot crowd out a safety command.

Version support: the command registry carries no minimum agent version per type. Revocation tokens of payload v1 and
`delete_self_lock` exist since M4c and are understood by every release (0.1.0-alpha.1 onward). The one later token
extension, `volumes`, is already bound to the capability the device reports (`revoke_capabilities`, PDK-009), and
the revocation-issuer leaves it out for a device that does not report it.

**Delivery is not effect.** `paddock-revoke` refuses every token with `revocation.refused{reason: disabled}` while
`/etc/paddock/revoke-enabled` is missing, and the agent keeps that file exactly while its last applied bundle enables
revocation. An out-of-window agent receives no bundle, so a delivered Lock or Destroy takes effect only if the
device's last applied bundle enabled revocation; otherwise the device answers `revocation.refused{reason: disabled}`.
An old agent therefore stays lockable only if revocation was enabled before it left the window — not when the
organization enabled revocation afterwards, and not for a device that never applied a bundle because it reported an
old version from its first check-in. The same gap holds for the time-ticket keys, which also arrive with the bundle:
after a rotation of the `time-ticket` key an out-of-window agent rejects every time ticket, and if its last bundle
armed the dead man's switch, the switch counts down although the device still checks in. Whether the revocation
switch and the time-ticket keys should reach out-of-window agents through a server-side option is open (PDK-772).

This is a server-side delivery rule only; the revocation path on the device (`agent/internal/revoke`,
`agent/cmd/paddock-revoke`) is unchanged.
