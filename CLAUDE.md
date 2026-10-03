# Paddock — binding rules for AI-assisted development

These rules are binding for every change in this repository. Read `docs/architecture.md` and the ADRs in
`docs/adr/` before changing structure, interfaces, the data model or dependencies. Milestone plans live in
`docs/plans/`.

## Agent design contract (from the concept, quoted)

1. **Supervisor and agent are separate.** A minimal supervisor (systemd unit plus watchdog) starts, monitors, and
   replaces the agent. The agent never replaces itself in-process. The supervisor is simple enough to need no updates.
2. **A/B installation.** New versions install alongside the current one; switching and rollback both flip one symlink.
3. **Self-test before switch.** The new version must pass defined checks (start, server connection, signature
   verification, readable configuration, health endpoint) before it becomes active.
4. **Watchdog with automatic rollback.** If the new version does not report healthy within a fixed window, the
   supervisor reverts and emits an audit event.
5. **Signed artifacts.** Updates are signed and verified before installation. The public key belongs to the
   supervisor, not the agent.
6. **Staged rollout.** Every update rolls out in waves with an automatic stop at a defined failure rate. Never all
   devices at once.
7. **Isolated revocation path.** Data revocation is a separately signed module. It requires a short-lived,
   device-bound token and is never changed through the same channel as the agent core.
8. **Fail safe.** If the server is unreachable, the device works normally. The agent never locks, wipes, or blocks on
   its own initiative – except through the dead man's switch, if an organization enables it.
9. **Static binary.** No runtime dependencies (for example Go), which avoids library breakage, especially on
   rolling-release distributions.
10. **Two-person rule for the revocation path.** Every change to that code requires review by a second person and a
    passed test on real hardware.

## Protected areas on the device

Treat these as protected: changes are tamper events and the agent must re-verify them.

1. `/etc/sudoers`, `/etc/sudoers.d/` and all files managed by Paddock's configuration.
2. LUKS keyslots and headers.
3. The agent, the supervisor, `fleetd`, the configuration timer and the log shipper (`/opt/paddock/`, `/etc/paddock/`,
   their systemd units).
4. Identity configuration: Himmelblau, PAM, NSS (`/etc/himmelblau/`, `/etc/pam.d/`, `/etc/nsswitch.conf`,
   `/etc/security/`).

## Organization isolation

- Every organization-scoped table MUST have `ENABLE` and `FORCE ROW LEVEL SECURITY` and a policy on
  `current_setting('paddock.org_id')::uuid` **without** `missing_ok`, so a missing context fails closed.
- The only way to get a transaction on organization data is `db.OrgPool.InOrg(ctx, fn)`. It takes the organization
  from the authenticated principal in `ctx` — never from a URL, a body or a header.
- Platform scope uses the separate PostgreSQL role and pool `paddock_platform`, never a session flag.
- Not found and cross-organization access both return **404** with problem code `not_found`.
- Do not import `pgxpool` or execute SQL outside `server/internal/platform/db`.

## Audit

- Every privileged action goes through `app.ActionRunner`. It records exactly one audit event per attempt — success,
  failure or denial. Use cases never write to `action` or `outbox` themselves.
- Audit events are never translated or rewritten. Codes are stable English identifiers from the closed registry in
  `server/internal/domain/audit/codes.go`; the portal localizes the display via message key `audit.<code>`.
- Never put secrets into audit params.

## Portal and list endpoints (ADR 0018)

- Never use `window.confirm`, `window.alert`, `window.prompt` or `beforeunload` prompts. Every destructive,
  irreversible or security-relevant action is confirmed in a modal (`ConfirmDialog`); high-risk actions require
  typing the target's name. Errors and success messages use inline alerts or snackbars.
- Every list in the portal uses the shared `DataList` component: search, filters, sortable columns, pagination with
  page numbers and items per page (10/25/50/100); list state lives in the URL query.
- Every collection `GET` in the admin API implements the list contract: `page`, `page_size` (10/25/50/100), `sort`
  (documented allow list, `-` = descending, primary key as tie-breaker), `q`, documented filters; response
  `{items, page, page_size, total, total_capped, sort}`; `page × page_size ≤ 10000`; documented with the OpenAPI
  extension `x-paddock-list`.

## Definition of done

- The acceptance gates in `test/acceptance/` are the definition of done. A milestone is finished when its gates are
  green against the running stack. Never weaken a test to make it pass.
- Run `make lint test` before every commit.

## Revocation path

- Every change to `agent/internal/revoke/` and `agent/cmd/paddock-revoke/` requires review by a second person and a
  passed test on real hardware (two-person rule).

## General

- English for code, comments, commits and documentation.
- No new dependency (Go module, npm package, container image) without architect approval.
- Configuration only via environment variables; secrets only from files referenced by `*_FILE` variables.
- Never modify `docs/architecture.md`, `docs/adr/` or `docs/reqirements/` without an architect decision.
