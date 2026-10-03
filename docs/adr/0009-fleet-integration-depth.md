# 0009 — Depth of Fleet integration (A10)
Status: Proposed

## Context
A10: Fleet replaceable in principle; Paddock's data model does not leak Fleet concepts; no Fleet premium features.
Fleet free has no team/organization separation.

## Options
- **Fleet behind an `Inventory` port; Paddock imports normalized data into its own tables.** + Replaceable, isolation
  via Paddock RLS. − Data duplicated, sync lag.
- **Portal embeds/proxies Fleet UI and API.** + Less code. − Leaks all organizations; ties UI to Fleet.
- **Own inventory agent.** − Rejected in the concept.

## Decision
Port `Inventory` with a Fleet adapter (REST, read-mostly, pinned version, contract tests). Host matching by
hardware UUID. Fleet UI/API not exposed publicly. osquery policies defined in Paddock and pushed via API.
Only `device_inventory_ref.external_id` stores Fleet IDs.

## Consequences
+ Swapping Fleet means one adapter. − Fleet requires MySQL and Redis in the stack.
