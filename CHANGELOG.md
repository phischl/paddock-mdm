# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Compose stack for the control plane (Caddy, PostgreSQL, RabbitMQ, OpenBao, Authentik) and a separate audit domain (`compose.audit.yaml` with its own PostgreSQL and RustFS); all images are pinned by tag and digest in `deploy/compose/versions.env` (M0 step 2).
- `make dev-secrets`, `make up`, `make dev-seed` start a complete local development stack; `make up` also initializes and unseals OpenBao and creates the audit bucket (M0 steps 2, 7, 10).
- WORM audit bucket `paddock-audit` with Object Lock COMPLIANCE and 400 days default retention, verified by the acceptance gate `make acceptance T=TestWORM` (F7, M0 step 3).
- `paddock-server migrate paddock|audit` applies the forward-only database migrations; organization data is isolated by PostgreSQL row-level security (F10, M0 step 4).
- `paddock-server provision rabbitmq` declares the audit exchange, quorum queue and dead-letter queue; the `outbox-relay` role delivers audit events with publisher confirms and finalizes stuck actions as `unknown` after 10 minutes (F7, M0 step 5).
- `audit-writer` role: indexes audit events, stores them as WORM objects under `org/<organization_id>/`, and seals a daily per-organization manifest signed with the OpenBao Transit key `audit-chain` at 00:15 UTC (F7, M0 step 6).
- `paddock-server audit verify --org <id> --from <day> --to <day>` checks the signed manifest chain and every object hash (exit code 0/1) (F7, M0 step 6).
- Admin API (`api/openapi/admin.yaml`) with portal login through Authentik (OIDC with PKCE, encrypted session cookie), device groups, audit log and platform organization management; every privileged action records exactly one audit event (F7, F8, F10, M0 step 7).
- Creating an organization creates its Authentik groups `paddock:<slug>`, `:admins`, `:operators`, `:auditors`; an organization left in `provisioning_failed` is re-provisioned by repeating the request (F10, M0 step 7).
- Administration portal at `https://admin.<domain>` for device groups, the audit log and organizations, English only, served with a strict Content Security Policy (F8, C7, M0 step 8).
- Acceptance gates for organization isolation, exactly-once auditing, login rules and the audit hash chain (`make acceptance`) (M0 step 9).
- Runbooks `docs/operations/openbao.md` (production initialization with five custodians, unsealing, credential rotation) and `docs/operations/audit-bucket.md` (one-shot production bucket creation and verification) (M0 step 10).

### Fixed

- `make up` on a fresh stack no longer fails because both Authentik containers populate the shared data volume at the same time (M0 step 10).
