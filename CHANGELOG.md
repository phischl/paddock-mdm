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
- Creating an organization creates its Authentik groups `paddock.<slug>`, `.admins`, `.operators`, `.auditors`; an organization left in `provisioning_failed` is re-provisioned by repeating the request (F10, M0 step 7).
- Administration portal at `https://admin.<domain>` for device groups, the audit log and organizations, English only, served with a strict Content Security Policy (F8, C7, M0 step 8).
- Portal roles come from Authentik group membership: `paddock.<slug>.admins`, `.operators` and `.auditors` map to organization administrator, operator and auditor; `paddock.platform.admins` grants platform administration (F8, M0 step 7).
- `make dev-seed` creates the development organizations `acme` and `globex` and assigns the test accounts listed in `README.md` (M0 step 9).
- Acceptance gates for organization isolation, exactly-once auditing, login rules and the audit hash chain (`make acceptance`) (M0 step 9).
- Runbooks `docs/operations/openbao.md` (production initialization with five custodians, unsealing, credential rotation) and `docs/operations/audit-bucket.md` (one-shot production bucket creation and verification) (M0 step 10).
- Admin API lists support sorting (`sort`, `-` prefix for descending), case-insensitive search (`q`) and filters (audit log: `code`, `outcome`, `actor_type`; organizations: `status`), documented per endpoint by the OpenAPI extension `x-paddock-list` (ADR 0018, M0.2 step 1).
- Database migrations add indexes for sorting and searching lists; the audit database migration installs the PostgreSQL extension `pg_trgm` as `audit_owner`, no operator action needed (ADR 0018, M0.2 step 1).
- Every portal list (device groups, audit log, organizations) offers search, filters, sortable columns, page numbers and 10, 25, 50 or 100 items per page; the list state is kept in the URL, so reload, back navigation and shared links restore it (ADR 0018, M0.2 step 4).
- The audit log in the portal can be filtered by outcome and actor type in addition to time range and event; without a time range it shows the last 7 days (ADR 0018, M0.2 step 4).
- Valkey (`valkey` service, AOF `everysec`, password from `.secrets/valkey_password`) and a control-plane RustFS (`rustfs` service) with the bucket `paddock-bundles` join the stack; `make bundles-bootstrap` (run by `make up`) creates the bucket and the compiler (read/write) and gateway (read-only) credentials (M2a step 2).
- Public hostname `bundles.<domain>` serves bundles through presigned `GET` URLs only; other methods and paths are refused with 403 (M2a step 2).
- `paddock-server provision rabbitmq` also declares the exchanges `paddock.ingest` (queues `ingest.enroll`, `ingest.heartbeat`, `ingest.event`, byte limit `PADDOCK_INGEST_QUEUE_MAX_BYTES`, default 256 MiB) and `paddock.state` (queues `state.p00`…`state.p15`, `state.priority` with single active consumer), each queue with a dead-letter queue `dlq.<queue>` (M2a step 2).
- OpenBao Transit key `bundle-signing` (Ed25519, not exportable) and AppRole `paddock-compiler`; the `paddock-api` policy may read the public keys of `bundle-signing` (M2a step 2).
- Admin API for the device control plane: enrollment tokens (`/api/v1/enrollment-tokens`, the secret and the enrollment configuration with the bundle-signing public keys are returned once, only a hash is stored), devices with approve, reject, release-quarantine and retire actions, device group memberships, effective configuration per device, managed files and managed systemd units, and the members of a device group; all lists follow the list contract and all changes are audited (A6, F1, M2a step 3).
- Managed files are restricted to paths below `/etc/`, `/usr/local/etc/` and `/opt/` outside protected areas (sudoers, PAM, NSS, Himmelblau, Paddock, crypttab, fstab, account databases, `/etc/apt/`), at most 64 KiB of UTF-8 text; reserved units (`paddock*`, `himmelblau*`, `fleet*`, `ssh*`, `gdm*`, `systemd-*`) are refused with 422 (M2a decision 8).
- `worker` role (`paddock-server serve worker`, Compose service `paddock-worker`): turns enrollment requests from `ingest.enroll` into devices and keeps the enrollment token and device key caches in Valkey in step with PostgreSQL (every change immediately, everything every 60 s) (A6, M2a step 3).
- Audit codes `enrollment_token.created`, `enrollment_token.revoked`, `device.enrolled`, `device.approved`, `device.rejected`, `device.quarantine_released`, `device.retired`, `device.groups_changed`, `managed_file.*`, `managed_unit.*`; devices appear as audit actor type `device` (M2a step 3).
- Device API at `https://device.<domain>` served by the new `gateway` role (`paddock-server serve gateway`, Compose service `paddock-gateway`): enrollment, enrollment status, check-in with presigned bundle URLs (valid 120 s) and device event batches, contract `api/openapi/device.yaml`. Every request is signed with the device's ECDSA P-256 key (timestamp within ±300 s, single-use nonce); the gateway has no database credentials and keeps answering check-ins while PostgreSQL is down (A5, C2, M2a step 4).
- The gateway limits device requests to 30 per minute per key and 300 per minute per source address (429 with `Retry-After`) and answers 503 `backpressure` when an ingest queue refuses a message (M2a step 4).
- Metrics `paddock_gateway_requests_total{route,code}` and `paddock_gateway_auth_failures_total{reason}` (M2a step 4).
- `compiler` role (`paddock-server serve compiler`, Compose service `paddock-compiler`): after every change of a device's inputs it renders the device's bundle (schema v1: NTP, managed files, managed units), signs it as a DSSE envelope with the OpenBao key `bundle-signing` and stores it as `org/<organization>/devices/<device>/bundles/<version>.dsse` in `paddock-bundles`; content-equal renders keep the version, changes within 2 s are coalesced, and bundle pointers in Valkey are rebuilt from PostgreSQL every 60 s (F1, A9, M2a step 5).
- The worker records check-ins in the device status at most once per minute per device, quarantines a device whose sequence numbers diverge (cloned identity, audit event `device.clone_suspected`) and records device events as audit events `device.bundle_applied`, `device.bundle_rejected` and `device.config_drift_corrected`, each once per event sequence number (A6, M2a step 5).
- Metrics `paddock_compiler_bundles_total{result}` and `paddock_compiler_latency_seconds` (M2a step 5).
- Acceptance gates D1–D4 for the device protocol, its security, clone detection and the absence of a synchronous device-to-database path, run with the reference device client `test/acceptance/devicesim` (`go run ./test/acceptance/cmd/devicesim enroll` enrolls a simulated device) (M2a step 6).

### Changed

- **BREAKING:** the control-plane database has the new roles `paddock_worker` and `paddock_compiler`, created when the PostgreSQL volume is initialized, and `paddock-api` requires `PADDOCK_PUBLIC_DEVICE_URL`. Development stacks: `make down V=1`, `make dev-secrets`, `make up`. Existing installations: none (pre-release) (M2a step 3).
- Deleting a device group that an enrollment token still assigns devices to answers 409 `in_use` (M2a step 3).
- **BREAKING:** Authentik group names use `.` instead of `:` (`paddock.<slug>`, `paddock.<slug>.admins`, `.operators`, `.auditors`, `paddock.platform.admins`), so the same names work for portal and device logins; groups with the old names are ignored. Development stacks: `make down V=1`. Existing installations: none (pre-release) (ADR 0007, M0.3 step 1).
- **BREAKING:** `GET /api/v1/device-groups`, `GET /api/v1/audit-events` and `GET /api/platform/v1/organizations` page with `page` and `page_size` (10, 25, 50, 100) instead of `cursor` and `limit`, and return `{items, page, page_size, total, total_capped, sort}` instead of `next_cursor`; `page × page_size` above 10 000 answers 400 `page_out_of_range`. API clients must switch to the new parameters (ADR 0018, M0.2 step 1).
- WORM object keys, `audit_object.day`, daily manifests and object retention are dated by the UTC day on which the audit writer recorded the events instead of their occurrence day; writer transactions are limited to 5 minutes and `paddock-server audit seal` refuses a day before 00:15 UTC of the following day (F7, M0.1 step 2).
- Portal UI library switched from PrimeVue to Vuetify (MIT); PrimeVue 5 requires a commercial license (C8, M0.1 step 4).
- Deleting a device group is confirmed in a modal dialog with the focus on *Cancel*; the portal never uses browser-native confirmation dialogs, and while a dialog is open the page behind it is inert for keyboard and screen reader users (ADR 0018, M0.2 step 4).

### Fixed

- Audit events recorded after their occurrence day was sealed are now covered by the manifest of their recording day (F7, M0.1 step 2).
- `make up` on a fresh stack no longer fails because both Authentik containers populate the shared data volume at the same time (M0 step 10).
- `make dev-seed` right after `make up` no longer fails intermittently: it waits up to 180 s until the Authentik login flow `paddock-admin-login` is executable (M1 step 1).
- `make dev-seed` right after `make up` waits up to 300 s until Authentik reports every Paddock blueprint as applied successfully before it checks the login flow, and names the pending blueprints and their status on timeout (M0.3 step 3).
- The development blueprint `paddock-dev.yaml` no longer ends in status `error` when Authentik re-applies it after the first start (M0.3 step 3).
- `make up` after `make down V=1` no longer leaves `paddock-api` and `paddock-audit-writer` unhealthy: re-initializing OpenBao now also replaces the stored AppRole secret-ids (M1 step 1).

### Security

- Organization data is isolated by PostgreSQL row-level security that fails closed without an organization context; platform endpoints use a separate database role, and cross-organization access returns 404 (F10, M0 steps 4, 9).
- The portal uses a backend-for-frontend session: tokens stay on the server, the browser only holds an encrypted, `HttpOnly`, `SameSite=Strict` session cookie (F8, M0 step 7).
- The portal is served with a strict Content Security Policy without `'unsafe-inline'`, with `frame-ancestors 'none'` and no third-party origins (C7, M0 step 8).
- Portal CSP now uses a per-response style nonce: `index.html` is served with `Cache-Control: no-store` and a fresh nonce in its `style-src` directive, still without `'unsafe-inline'` (C7, M0.1 step 4).
