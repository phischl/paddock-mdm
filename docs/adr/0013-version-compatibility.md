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
