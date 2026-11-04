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
