# 0002 — PostgreSQL with Row-Level Security for organization isolation
Status: Proposed

## Context
Principle 5: every entity carries `organization_id`, isolation enforced in one layer. A forgotten
per-query filter is "the most likely defect in generated code". Cross-organization access MUST return 404.

## Options
- **RLS in PostgreSQL, context set once per transaction by the repository layer.** + The database
  enforces isolation even for a query that forgets the filter; fails closed when the context is missing.
  − RLS policies must exist on every table (lintable); slight planner overhead.
- **Query builder / ORM global filter.** + Familiar. − Bypassed by raw SQL; enforcement lives in app code only.
- **Schema or database per organization.** + Hard isolation. − Migrations and connections scale with organizations; contradicts C6.

## Decision
PostgreSQL 17. Every organization-scoped table has `ENABLE` and `FORCE ROW LEVEL SECURITY` and a policy on
`current_setting('paddock.org_id')::uuid` (no `missing_ok`). Application DB roles are `NOBYPASSRLS` and not
owners. `db.InOrg(ctx, fn)` is the only way to obtain a transaction for organization data; the organization
ID comes only from the authenticated principal. Handlers map not-found to 404.

## Consequences
+ Isolation does not depend on every query being correct.
− Cross-organization jobs must iterate organizations explicitly via the `paddock_scheduler` role.
Follow-up: CI migration lint; generated negative isolation test over all OpenAPI operations.
