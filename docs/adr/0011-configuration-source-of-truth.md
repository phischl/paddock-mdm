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

## Amendment 2026-10-08
The dry run is `PUT /api/v1/config?dry_run=true` instead of `POST /api/v1/config:plan` (no `:verb` endpoints).
The declarative endpoint and its `change_set` records serve `paddockctl apply` and CI; portal forms keep their
per-resource endpoints, and both paths share the same use-case layer and validation (one write path at the use-case
level, not at the HTTP level). Sections present in a document are authoritative for that section; absent sections
are untouched. Plan: `docs/plans/M6c-paddockctl.md`.
