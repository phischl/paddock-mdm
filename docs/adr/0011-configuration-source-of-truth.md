# 0011 — Configuration source of truth
Status: Proposed

## Context
Principle 7: configuration as code; the portal writes through the same path. Decided by the product owner:
database primary with Git export.

## Options
- **PostgreSQL primary, versioned change sets, declarative API used by portal and CLI, optional Git export.**
  + Transactional, organization-isolated, no merge conflicts. − Git is a mirror, not the editing surface.
- **Git primary (Forgejo).** + Literal GitOps. − Extra component, merge conflicts, isolation per repo.
- **Hybrid.** − Two sources of truth.

## Decision
Every configuration change is a `change_set` (author, time, reason, diff) produced by the declarative endpoints
`PUT /api/v1/config` and `POST /api/v1/config:plan`. Portal forms and `paddockctl apply -f paddock.yml` use the same
endpoints. A worker MAY export each change set to a per-organization Git remote. GitOps users run `paddockctl apply`
in their own CI.

## Consequences
+ "Same path" holds: there is exactly one write path. − Git history is derived, not authoritative.
