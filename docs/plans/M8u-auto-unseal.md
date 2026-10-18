# Implementierungsplan: M8u — Automatic unseal of OpenBao (acknowledged in the portal, performed on the host)

Status: Ready for implementation · 2026-10-17 · Author: architect
Basis: ADR 0035 (automatic unseal; accepted); ADR 0006 (key management, Shamir 3 of 5); ADR 0016 (backups);
ADR 0018 (lists and dialogs); ADR 0022 (operator bundle); ADR 0029 (lab profile); ADR 0034 (step-up, sessions);
plan M6a decision 2 (prod-check), plan M7a decision 16 (platform routes are sessions only), plan M8a (lab bundle
smoke test), plan M8s decision 16 (`platform.sessions_ended` as the platform step-up pattern).

Binding language: **MUST** / **MUST NOT** / **SHOULD** / **MAY**.

## 1. Goal

After M8u a platform administrator can, with a fresh step-up and a typed acknowledgement of a versioned disclaimer,
record in the portal that automatic unseal of OpenBao is accepted; the host operator can then start a dedicated
unsealer that holds three unseal shares and unseals OpenBao after every restart while that setting is on; the portal
shows the setting, the unsealer's state and the last automatic unseal; disabling in the portal stops the unseal at
once; `./paddock check` warns on a production host and passes on a lab host; every step is in the audit trail.

## 2. Context (verified in the code on 2026-10-17, `main` at `ecfaad0`)

- **OpenBao** `openbao/openbao:2.7.1` (`deploy/compose/versions.env`). `sys/seal-status` and `sys/unseal` need no
  token. The Go client `github.com/openbao/openbao/api/v2` is a dependency already; `server/internal/platform/bao`
  wraps it (`Client.Sealed` reads `sys/health`; `Client.New(addr, roleID, secretID)`; TLS through `BAO_CACERT`).
  The OpenBao container runs `bao server -config=/openbao/config/prod.hcl` (production, TLS with the internal CA) or
  `config.hcl` (development, plain HTTP). Nothing in OpenBao is reconfigured by this plan.
- **Worker probe.** `server/internal/worker/opsprobe.go`: `OpsProbe.Run` polls OpenBao every 30 s and exports
  `paddock_openbao_sealed` and `paddock_openbao_reachable`; wired in `server/cmd/paddock-server/worker.go:121`
  (`jobs := []func(context.Context) error{…}`). `db.PlatformPool.WithLeaderLock(ctx, key, fn)` exists.
- **Platform step-up pattern.** `server/internal/app/sessions.go` (`SpecSessionsEndAll` with `RolesPlatform` and
  `RequiresStepUp: true`; `EndAllCLI` with `systemPlatform(ctx)` and `adminActor`), route table `privileged` in
  `server/internal/transport/http/admin/server.go:81`, handler `handlers_sessions.go`, OpenAPI
  `/api/platform/v1/sessions/end-all` with `x-paddock-audit`, portal `server/web/src/views/PlatformSessions.vue`
  with `startStepUp`/`resumeStepUp` (`server/web/src/lib/stepUp.ts`) and `useConfirm` (`ConfirmDialog.vue`,
  `requireTypedText`). `TestOpenAPISpec` requires every `x-paddock-audit` route in `privileged` and every code in
  the registry `server/internal/domain/audit/codes.go`. Problem codes: `server/internal/problem/problem.go`.
- **Platform data pattern.** `server/migrations/paddock/00036_ip_allowlist.sql` (table without organization,
  `GRANT … TO paddock_platform`); `app.IPAllowlist` uses `*db.PlatformPool` and the runner. Next migration number:
  `00049`. PostgreSQL roles are created once by `deploy/compose/postgres/init/10-roles.sh`; migrations run as
  `paddock_owner` (`NOCREATEROLE`). Pools live in `server/internal/platform/db/db.go` (`OrgPool`, `PlatformPool`,
  `RelayPool`, `AuditReader`, `AuditWriterPool`); SQL runs only there and through sqlc (`pgstore`).
- **Admin CLI.** `server/cmd/paddock-server/admin.go`: `parseAdmin`, `adminCommand{name, sub, …}`, platform DSN
  from `PADDOCK_DB_PLATFORM_URL_FILE`; `./paddock agent-release` runs `compose run --rm --no-deps paddock-api admin …`.
- **Compose and bundle.** `deploy/compose/scripts/lib.sh` holds the file sets (`DEV_FILES`, `PROD_FILES_*`,
  `LAB_BACKUP_FILES`, appended by `compose_files` when `PADDOCK_LAB_BACKUP=yes`). YAML anchors (`x-paddock`,
  `x-paddock-env`) do not cross files. `compose.prod.yaml` declares `x-paddock-prod` (`interconnect_addr`,
  `revocation_accepted`), read by `prodcheck.Config.Prod`. `compose.lab.yaml` mounts an extra Prometheus scrape file
  (`./prometheus/scrape/audit.yml`). `deploy/bundle/build.sh` lists the shipped files (`shipped=(…)`);
  `deploy/bundle/bundle_test.sh` renders `controlplane`, `audit`, `lab-backup` and checks bind-mount sources;
  `deploy/bundle/ci/smoke-lab.sh` installs the lab bundle in CI (step 5 initializes OpenBao with
  `-format=json` and unseals with three shares on stdin). `./paddock` (`deploy/bundle/paddock`) has `require_host`,
  `lab_warning`, `tty_flag`, `dotenv`, `die`; the `bao` command runs `compose exec … openbao bao`.
- **Secrets.** `gen-prod-secrets.sh` and `gen-dev-secrets.sh` write `db_<role>_password` and `db_<role>_url`
  (`postgres://<role>:<pw>@postgres:5432/paddock?sslmode=disable`) for a fixed role list; files are 0644 inside the
  0700 `.secrets/`; `prodcheck.checkSecretFiles` fails missing, empty or world-readable files of *used* secrets. The
  development bootstrap `openbao-bootstrap.sh` stores the five shares in `.secrets/openbao/init.txt`
  (`Unseal Key N: …`) and `openbao-bootstrap.sh unseal` unseals with the first three.
- **prod-check.** `server/internal/prodcheck/prodcheck.go`: `Result{Item, OK, Detail}`, `Write` prints `PASS`/`FAIL`,
  `Run` appends items by host; fixtures in `prodcheck_test.go`; acceptance helper `prodCheck(t, env…)` and
  `expectItem(t, out, status, item, detail)` in `test/acceptance/prodcheck_edge_test.go`; `stack.ProdFiles(host)`
  reads `PROD_FILES_<host>` literally.
- **Portal.** Navigation `server/web/src/lib/navigation.ts` (group `platform`), router `server/web/src/router.ts`,
  catalogs `server/web/src/locales/{en,de}.json` (`nav.*`, `problems.*`, `audit.platform.*`, page keys), component
  tests `server/web/src/__tests__/platformSessions.test.ts`, generated types `server/web/src/api/schema.d.ts`
  (`make gen`).
- **Acceptance.** `test/acceptance`: `login(t, env.PlatformAdmin)`, `stepUp(t, p, user, ok)`, `call`,
  `expectStatus`, `expectOneIndexEvent(t, idx, platformOrg, "correlation_id = $1", requestID, code, outcome, timeout)`,
  `stack.Compose(ctx, env, args…)`, disruptive gates behind `PADDOCK_ACCEPTANCE_DISRUPTIVE=1` in their own CI step
  (`.github/workflows/ci.yml:109`). Prometheus rules are tested with `promtool` (`make lint-prometheus`,
  `deploy/compose/prometheus/alerts_test.yml`).
- **Lab stop-gap.** The maintainer's homelab runs a host cron job with three shares in a 0600 file; it is not part of
  the repository.

## 3. Binding decisions

### 3.1 Domain, setting and acknowledgement

1. Package `server/internal/domain/autounseal` MUST exist with (file `autounseal.go`):

   ```go
   // Package autounseal holds the setting of the automatic unseal of OpenBao and the disclaimer a platform
   // administrator acknowledges before it may be enabled (ADR 0035).
   package autounseal

   // DisclaimerVersion is the version (date) of the disclaimer text of plan M8u §6.6; a changed text gets a new date.
   const DisclaimerVersion = "2026-10-17"

   // Acknowledgements are the exact sentences, one per portal language, that acknowledge DisclaimerVersion.
   var Acknowledgements = []string{
       "I understand and accept the risk",
       "Ich verstehe und akzeptiere das Risiko",
   }

   // State of the setting.
   type State string

   const (
       StateDisabled State = "disabled"
       StateEnabled  State = "enabled"
   )

   // ValidateAcknowledgement reports whether version is DisclaimerVersion (else ErrDisclaimerOutdated) and
   // acknowledgement is one of Acknowledgements byte for byte, without trimming (else ErrAcknowledgementMismatch).
   func ValidateAcknowledgement(version, acknowledgement string) error

   var (
       ErrDisclaimerOutdated     = errors.New("autounseal: disclaimer version is not the current one")
       ErrAcknowledgementMismatch = errors.New("autounseal: acknowledgement does not match")
   )

   // Setting is the row openbao_auto_unseal.
   type Setting struct {
       State                 State
       DisclaimerVersion     string // "" while never enabled
       Acknowledgement       string
       AcknowledgedBy        string // display name of the platform administrator
       AcknowledgedBySubject string // Authentik subject
       AcknowledgedAt        time.Time
       DisabledBy            string
       DisabledAt            time.Time
       Report                Report
   }

   // Report is what the unsealer writes about itself.
   type Report struct {
       SeenAt            time.Time
       SharesPresent     bool
       UnsealCount       int64
       LastUnsealAt      time.Time
       FailureCount      int64
       LastFailureAt     time.Time
       LastFailureReason string // one of the FailureReason* constants, "" when none
   }

   // UnsealerRunning reports whether the unsealer reported within UnsealerStaleAfter of now.
   func (r Report) UnsealerRunning(now time.Time) bool

   // UnsealerStaleAfter is how long after its last report the unsealer counts as not running (six 10 s ticks).
   const UnsealerStaleAfter = 60 * time.Second

   // Failure reasons the unsealer reports (never a share, never an OpenBao error text).
   const (
       FailureReasonUnreachable  = "unreachable"
       FailureReasonInvalidShare = "invalid_share"
       FailureReasonStillSealed  = "still_sealed"
   )
   ```

2. Migration `server/migrations/paddock/00049_openbao_auto_unseal.sql` MUST be exactly (goose statement markers
   around the `DO` block are required):

   ```sql
   -- Automatic unseal of OpenBao (ADR 0035, plan M8u decision 2): the platform administrator's acknowledged decision
   -- and the unsealer's report, one row. Platform data (role paddock_platform); the unsealer's own role reads the
   -- state and writes its report. Forward-only: there is no Down migration.
   -- +goose Up
   CREATE TABLE openbao_auto_unseal (
     id                      smallint PRIMARY KEY CHECK (id = 1),
     state                   text NOT NULL CHECK (state IN ('disabled', 'enabled')),
     disclaimer_version      text,
     acknowledgement         text,
     acknowledged_by         text,
     acknowledged_by_subject text,
     acknowledged_at         timestamptz,
     disabled_by             text,
     disabled_at             timestamptz,
     unsealer_seen_at        timestamptz,
     unsealer_shares_present boolean NOT NULL DEFAULT false,
     unseal_count            bigint NOT NULL DEFAULT 0,
     last_unseal_at          timestamptz,
     failure_count           bigint NOT NULL DEFAULT 0,
     last_failure_at         timestamptz,
     last_failure_reason     text,
     audited_unseal_count    bigint NOT NULL DEFAULT 0,
     audited_failure_count   bigint NOT NULL DEFAULT 0,
     updated_at              timestamptz NOT NULL DEFAULT now(),
     CHECK (state = 'disabled' OR (disclaimer_version IS NOT NULL AND acknowledgement IS NOT NULL
       AND acknowledged_by IS NOT NULL AND acknowledged_at IS NOT NULL))
   );
   INSERT INTO openbao_auto_unseal (id, state) VALUES (1, 'disabled');
   GRANT SELECT, UPDATE ON openbao_auto_unseal TO paddock_platform;
   -- The unsealer's role exists only where the operator enabled automatic unseal; deploy/compose/scripts/
   -- postgres-unsealer-role.sh grants the same when it creates the role after this migration ran.
   -- +goose StatementBegin
   DO $$
   BEGIN
     IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'paddock_unsealer') THEN
       GRANT SELECT ON openbao_auto_unseal TO paddock_unsealer;
       GRANT UPDATE (unsealer_seen_at, unsealer_shares_present, unseal_count, last_unseal_at, failure_count,
         last_failure_at, last_failure_reason, updated_at) ON openbao_auto_unseal TO paddock_unsealer;
     END IF;
   END $$;
   -- +goose StatementEnd
   ```

   Amendment 2026-10-18 (architect note, decided by the orchestrator as architect, 2026-10-18; PDK-303): the column
   grant lets `paddock_unsealer` write any value into `unseal_count` and `failure_count`, and a lowered counter
   would suppress `platform.openbao_auto_unsealed` events. Audit integrity wins: migration 00050 (amended before it
   was merged) also creates the `BEFORE UPDATE` trigger `openbao_auto_unseal_counters_monotonic`, which rejects any
   decrease of either counter, for every role, with SQLSTATE `23514` and the message `openbao_auto_unseal:
   unseal_count and failure_count never decrease`. The grants stay as above.

3. sqlc queries in `server/internal/adapters/postgres/queries/auto_unseal.sql` MUST provide: `GetAutoUnseal`
   (the row), `GetAutoUnsealForUpdate` (`… FOR UPDATE`), `EnableAutoUnseal` (sets `state='enabled'`,
   `disclaimer_version`, `acknowledgement`, `acknowledged_by`, `acknowledged_by_subject`, `acknowledged_at=now()`,
   clears `disabled_by`/`disabled_at`, `updated_at=now()`), `DisableAutoUnseal` (sets `state='disabled'`,
   `disabled_by`, `disabled_at=now()`, `updated_at=now()`; keeps the acknowledgement columns), `ReportUnsealer`
   (sets `unsealer_seen_at=now()`, `unsealer_shares_present=$1`, `updated_at=now()`), `RecordUnseal`
   (`unseal_count=unseal_count+1`, `last_unseal_at=now()`), `RecordUnsealFailure` (`failure_count=failure_count+1`,
   `last_failure_at=now()`, `last_failure_reason=$1`), `MarkAutoUnsealAudited` (sets `audited_unseal_count=$1`,
   `audited_failure_count=$2`).

### 3.2 Use cases and admin API

4. `server/internal/app/autounseal.go` MUST provide:

   ```go
   // SealStatusReader reads OpenBao's seal status without a token (bao.Client).
   type SealStatusReader interface {
       SealStatus(ctx context.Context) (bao.SealStatus, error)
   }

   // Privileged actions of the automatic unseal (ADR 0035 decision 2).
   var (
       SpecAutoUnsealEnable     = ActionSpec{Code: audit.CodePlatformAutoUnsealEnabled, AllowedRoles: RolesPlatform, RequiresStepUp: true}
       SpecAutoUnsealDisable    = ActionSpec{Code: audit.CodePlatformAutoUnsealDisabled, AllowedRoles: RolesPlatform, RequiresStepUp: true}
       specAutoUnsealDisableCLI = ActionSpec{Code: audit.CodePlatformAutoUnsealDisabled, Actor: &adminActor}
       // specAutoUnsealObserved is recorded by the worker for the unsealer's report (decision 12).
       specAutoUnsealObserved = ActionSpec{Code: audit.CodePlatformOpenBaoAutoUnsealed, Actor: &unsealerActor}
   )

   // unsealerActor is the actor of every automatic unseal.
   var unsealerActor = audit.Actor{Type: audit.ActorSystem, Display: "paddock-unsealer"}

   // AutoUnseal are the platform use cases of the automatic unseal.
   type AutoUnseal struct {
       runner   *ActionRunner
       platform *db.PlatformPool
       seal     SealStatusReader // nil: seal status reported as unreachable
       now      func() time.Time
   }

   func NewAutoUnseal(runner *ActionRunner, platform *db.PlatformPool, seal SealStatusReader) *AutoUnseal

   // Status is the setting, the report and the seal status the portal shows.
   type AutoUnsealStatus struct {
       Setting autounseal.Setting
       Seal    bao.SealStatus // Reachable false when OpenBao did not answer
   }

   // Status reads the setting with the platform role and the seal status; platform administrators only
   // (ErrForbidden for others, no audit event: a read).
   func (a *AutoUnseal) Status(ctx context.Context) (AutoUnsealStatus, error)

   // Enable records the acknowledgement and sets the state to enabled (audited platform.auto_unseal_enabled with
   // disclaimer_version, acknowledgement and previous_state). Validation errors: problem.DisclaimerOutdated (409)
   // and problem.InvalidRequest with detail "acknowledgement does not match the disclaimer" (400); both are
   // recorded as failure.
   func (a *AutoUnseal) Enable(ctx context.Context, disclaimerVersion, acknowledgement string) (AutoUnsealStatus, error)

   // Disable sets the state to disabled (audited platform.auto_unseal_disabled, method portal).
   func (a *AutoUnseal) Disable(ctx context.Context) (AutoUnsealStatus, error)

   // DisableCLI is Disable for paddock-server admin auto-unseal disable (method cli, system principal).
   func (a *AutoUnseal) DisableCLI(ctx context.Context) (autounseal.Setting, error)

   // Load reads the setting with a system principal (CLI show and verify).
   func (a *AutoUnseal) Load(ctx context.Context) (autounseal.Setting, error)
   ```

   `acknowledged_by` MUST be the principal's `Display`, `acknowledged_by_subject` the principal's `Subject`;
   `disabled_by` is the principal's `Display` or `paddock-server admin`. Enable and Disable MUST run inside
   `runner.RunTx(ctx, ScopePlatform, spec, …)`, read the row `FOR UPDATE`, set `previous_state` as a parameter,
   and return the status read in the same transaction (seal status read after the commit).
5. `server/internal/platform/bao/bao.go` MUST gain:

   ```go
   // SealStatus is sys/seal-status (no token).
   type SealStatus struct {
       Reachable   bool
       Initialized bool
       Sealed      bool
       Type        string // "shamir" today
       Threshold   int    // t
       Shares      int    // n
       Progress    int    // shares submitted so far
   }

   // SealStatus reads sys/seal-status. An unreachable OpenBao is SealStatus{Reachable: false} with the error.
   func (c *Client) SealStatus(ctx context.Context) (SealStatus, error)

   // Unseal submits one share to sys/unseal and returns the status after it. The share is never logged.
   func (c *Client) Unseal(ctx context.Context, share string) (SealStatus, error)

   // ResetUnseal discards a partial unseal progress (sys/unseal with reset=true).
   func (c *Client) ResetUnseal(ctx context.Context) error
   ```

   implemented with `api.Sys().SealStatusWithContext`, `UnsealWithContext` and `ResetUnsealProcessWithContext`.
6. `server/internal/problem/problem.go` MUST gain `DisclaimerOutdated = &Error{Code: "disclaimer_outdated",
   Status: http.StatusConflict}`.
7. Admin API (`api/openapi/admin.yaml`), §6.1: `GET /api/platform/v1/openbao/auto-unseal` (operationId
   `getAutoUnseal`), `POST …/enable` (`enableAutoUnseal`, `x-paddock-audit: platform.auto_unseal_enabled`),
   `POST …/disable` (`disableAutoUnseal`, `x-paddock-audit: platform.auto_unseal_disabled`). Both POSTs MUST be in
   `privileged` with `app.ScopePlatform` and their specs. Handlers in
   `server/internal/transport/http/admin/handlers_autounseal.go`. The api's existing `bao.Client` is passed as
   `SealStatusReader`.
8. `paddock-server admin auto-unseal show|verify|disable` MUST exist (`admin.go`, usage text in `main.go`):
   `show` prints the setting and report as `key: value` lines (never a share: there is none in the row); `verify`
   exits 0 and prints `automatic unseal acknowledged by <acknowledged_by> on <acknowledged_at> (disclaimer
   <version>)` when the state is `enabled`, else exits 1 with `automatic unseal is not enabled: a platform
   administrator enables it in the portal first (Platform → OpenBao)`; `disable` calls `DisableCLI`. The commands
   use the platform DSN like `end-sessions`; they do not open Valkey.

### 3.3 The unsealer

9. `paddock-server serve unsealer` MUST exist (`server/cmd/paddock-server/unsealer.go`, dispatched in `run.go`,
   listed in the usage text). Configuration: `PADDOCK_DB_UNSEALER_URL_FILE` (required),
   `PADDOCK_OPENBAO_ADDR` (required; `config.LoadOpenBao` without AppRole files — add a loader
   `config.LoadOpenBaoAddr(l)` that reads the address only), `BAO_CACERT` (read by the OpenBao client from the
   environment, as the other roles), `PADDOCK_OPENBAO_UNSEAL_SHARES_FILE` (required, path),
   `PADDOCK_OPS_ADDR` (`:9090`, as every role). It MUST NOT read `PADDOCK_OPENBAO_ROLE_ID_FILE`,
   `PADDOCK_OPENBAO_SECRET_ID_FILE`, any Valkey or AMQP variable, or any other database URL.
10. `server/internal/platform/db/db.go` MUST gain `UnsealerPool` with `NewUnsealerPool(ctx, dsn, o)` and
    `InUnsealer(ctx, fn func(ctx context.Context, q *pgstore.Queries) error) error` (a transaction on the pool of role
    `paddock_unsealer`; no principal check: the unsealer is a background role with one credential), plus `Ping`.
11. `server/internal/unsealer/unsealer.go` MUST implement:

    ```go
    // Package unsealer unseals OpenBao with the shares on the host while the platform setting allows it (ADR 0035).
    package unsealer

    // Seal is the part of bao.Client the unsealer uses.
    type Seal interface {
        SealStatus(ctx context.Context) (bao.SealStatus, error)
        Unseal(ctx context.Context, share string) (bao.SealStatus, error)
        ResetUnseal(ctx context.Context) error
    }

    // Store reads the setting and writes the report (db.UnsealerPool through pgstore).
    type Store interface {
        State(ctx context.Context) (autounseal.State, error)
        Report(ctx context.Context, sharesPresent bool) error
        RecordUnseal(ctx context.Context) error
        RecordFailure(ctx context.Context, reason string) error
    }

    const (
        Interval      = 10 * time.Second // one tick
        FailureBackoff = 60 * time.Second // no attempt after a failed one
        SharesRequired = 3                // lines of the shares file
        MaxShareBytes  = 128              // longest accepted line
    )

    type Unsealer struct { /* seal, store, sharesPath, now, backoffUntil, metrics */ }

    func New(seal Seal, store Store, sharesPath string) *Unsealer

    // Run ticks every Interval until ctx ends.
    func (u *Unsealer) Run(ctx context.Context) error

    // Tick is one round: read the shares file, read the state, read the seal status, unseal when allowed, report.
    func (u *Unsealer) Tick(ctx context.Context)

    // ReadShares returns the shares of path: present only when the file exists and holds exactly SharesRequired
    // non-empty lines of at most MaxShareBytes bytes each (trailing newline and surrounding whitespace trimmed);
    // otherwise present is false and err names the condition (count or length), never a line's content.
    func ReadShares(path string) (shares []string, present bool, err error)
    ```

    One `Tick` MUST do, in this order: (1) `ReadShares`; (2) `store.State` — on error log at warn level at most once
    per minute and return without any OpenBao call (a gate that cannot be read is closed); (3) `seal.SealStatus` —
    on error set `reachable` false; (4) when `Initialized && Sealed && state == StateEnabled && present &&
    now >= backoffUntil`: submit the shares in file order with `seal.Unseal`, stopping as soon as `Sealed` is false;
    when a call fails → `seal.ResetUnseal`, `store.RecordFailure(FailureReasonInvalidShare)` for an HTTP 400 and
    `FailureReasonUnreachable` for every other error, `backoffUntil = now + FailureBackoff`; when all shares were
    accepted and OpenBao is still sealed → `ResetUnseal`, `RecordFailure(FailureReasonStillSealed)`, backoff; when
    unsealed → `store.RecordUnseal` and log at info level `OpenBao unsealed automatically` with the field
    `shares_submitted`; (5) `store.Report(present)`. A share MUST NOT appear in any log line, error, metric label
    or audit parameter. The file is re-read on every tick, so deleting it takes effect within one tick.
12. Readiness of the unsealer (`/readyz`) is `store` reachable (`Ping`); it MUST NOT depend on OpenBao. Metrics:
    `paddock_unsealer_shares_present` (gauge 0/1), `paddock_unsealer_setting_enabled` (gauge 0/1, unchanged while
    the state cannot be read), `paddock_unsealer_unseals_total{result="success"|"failure"}` (counter).
13. **Worker observation.** `server/internal/worker/autounseal.go` MUST add `AutoUnsealObserver` (constructor
    `NewAutoUnsealObserver(platform *db.PlatformPool, runner *app.ActionRunner)`, `Run(ctx)` every 30 s under
    `WithLeaderLock` with a new key constant next to the existing lock keys). Each round: read the row with a system
    principal; export `paddock_auto_unseal_enabled` (0/1), `paddock_auto_unseal_shares_present` (0/1),
    `paddock_auto_unseal_unsealer_up` (1 when `Report.UnsealerRunning(now)`); when `unseal_count >
    audited_unseal_count` record one `platform.openbao_auto_unsealed` success event with params `unseals`
    (the difference), `last_unseal_at`; when `failure_count > audited_failure_count` record one event with outcome
    `failure` and error code `auto_unseal_failed` (through `runner.RunTxRefusal` with the refusal
    `ErrAutoUnsealFailed`, defined in `app/autounseal.go` as `&problem.Error{Code: "auto_unseal_failed", Status:
    http.StatusInternalServerError}`) with params `failures`, `last_failure_at`, `last_failure_reason`; both update
    `audited_*` in the same transaction (`MarkAutoUnsealAudited`). No change → no event.
    Amendment 2026-10-18 (architect note, decided by the orchestrator as architect, 2026-10-18; PDK-199 Review 1):
    `paddock_auto_unseal_shares_present` is 1 only when the unsealer reports shares **and**
    `Report.UnsealerRunning(now)` holds (`Report.SharesOnHost(now)`). `./paddock auto-unseal disable` removes the
    unsealer before it deletes the file, so nothing writes `false` afterwards; without this rule
    `PaddockAutoUnsealWithdrawn` would fire for good after the documented remediation. The admin API's
    `unsealer.shares_present` follows the same rule. Trade-off: a stopped unsealer whose file is still on the host
    is reported as "not running", not as "shares present"; `./paddock auto-unseal status` reads the file itself.

### 3.4 Compose, secrets, host commands

14. `deploy/compose/compose.auto-unseal.yaml` MUST define the service `paddock-unsealer` with every hardening field
    of the `x-paddock` anchor spelled out (`image: ${PADDOCK_IMAGE:-paddock-server:dev}`, `profiles: [paddock]`,
    `read_only: true`, `tmpfs: [/tmp]`, `cap_drop: [ALL]`, `security_opt: ["no-new-privileges:true"]`,
    `pids_limit: 256`, `restart: unless-stopped`, the anchor's healthcheck), `command: ["serve", "unsealer"]`,
    environment `PADDOCK_ENV: ${PADDOCK_ENV:-production}`, `PADDOCK_LOG_LEVEL: ${PADDOCK_LOG_LEVEL:-info}`,
    `PADDOCK_OPS_ADDR: ":9090"`, `PADDOCK_DB_UNSEALER_URL_FILE: /run/secrets/db_paddock_unsealer_url`,
    `PADDOCK_OPENBAO_ADDR: https://openbao:8200`, `BAO_CACERT: /run/secrets/internal_ca_bundle`,
    `PADDOCK_OPENBAO_UNSEAL_SHARES_FILE: /run/secrets/openbao_auto_unseal_shares`; secrets
    `db_paddock_unsealer_url`, `openbao_auto_unseal_shares`, `internal_ca_bundle`; `networks: [cp]`; `depends_on`
    `postgres` healthy, `openbao` healthy, `paddock-migrate` completed; a `prometheus` service entry that mounts
    `./prometheus/scrape/auto-unseal.yml:/etc/prometheus/scrape/auto-unseal.yml:ro`; top-level secrets
    `db_paddock_unsealer_url: { file: ./.secrets/db_paddock_unsealer_url }` and
    `openbao_auto_unseal_shares: { file: ./.secrets/openbao/auto-unseal-shares }`. `compose.prod.yaml`
    `x-paddock-prod` MUST gain `auto_unseal: ${PADDOCK_AUTO_UNSEAL:-no}`. `compose.dev.yaml` MUST override the
    unsealer for development: `PADDOCK_OPENBAO_ADDR: http://openbao:8200`, no `BAO_CACERT`, secrets
    `!override [db_paddock_unsealer_url, openbao_auto_unseal_shares]`.
15. `deploy/compose/prometheus/scrape/auto-unseal.yml` MUST add the job `paddock-unsealer` with the static target
    `paddock-unsealer:9090` and the label `role: paddock-unsealer`, in the shape of `scrape/controlplane.yml`.
16. `deploy/compose/scripts/lib.sh` MUST gain `AUTO_UNSEAL_FILES="compose.auto-unseal.yaml"`; `DEV_FILES` MUST
    become `compose.yaml compose.audit.yaml compose.auto-unseal.yaml compose.dev.yaml`; `compose_files` MUST append
    `AUTO_UNSEAL_FILES` for `controlplane` and `lab` when `PADDOCK_AUTO_UNSEAL` is `yes` (before `LAB_BACKUP_FILES`
    on a lab host, so that the backup file stays last). The Makefile reads `DEV_FILES` from `lib.sh` and needs no
    change for the file set; the literal development list in `test/acceptance/internal/stack/stack.go::compose`
    MUST gain `compose.auto-unseal.yaml` before `compose.dev.yaml`; `server/internal/prodcheck/compose_test.go` reads
    `DEV_FILES` from `lib.sh` and MUST stay green. `gen-prod-secrets.sh` (control plane and lab) and
    `gen-dev-secrets.sh` MUST add `paddock_unsealer` to the role list that gets `db_<role>_password` and
    `db_<role>_url`. `prod.env.example` and `lab.env.example` MUST document `PADDOCK_AUTO_UNSEAL=no` with the
    comment: `# Automatic unseal of OpenBao (ADR 0035, docs/operations/openbao.md section 6): set by
    ./paddock auto-unseal enable|disable after a platform administrator acknowledged the disclaimer in the portal;
    do not edit by hand.`
17. `deploy/compose/scripts/postgres-unsealer-role.sh` MUST create the role idempotently. It sources `lib.sh`,
    exports `UNSEALER_PASSWORD` from `$SECRETS_DIR/db_paddock_unsealer_password`, and runs
    `compose exec -T -e UNSEALER_PASSWORD postgres psql -v ON_ERROR_STOP=1 -U postgres -d paddock` with this SQL on
    stdin (the password reaches psql through the container's environment, never a command line):

    ```sql
    \set pw `printf '%s' "$UNSEALER_PASSWORD"`
    SELECT format('CREATE ROLE paddock_unsealer LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS PASSWORD %L', :'pw')
      WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'paddock_unsealer') \gexec
    SELECT format('ALTER ROLE paddock_unsealer PASSWORD %L', :'pw') \gexec
    GRANT CONNECT ON DATABASE paddock TO paddock_unsealer;
    GRANT USAGE ON SCHEMA public TO paddock_unsealer;
    SELECT 'GRANT SELECT ON openbao_auto_unseal TO paddock_unsealer'
      WHERE to_regclass('public.openbao_auto_unseal') IS NOT NULL \gexec
    SELECT 'GRANT UPDATE (unsealer_seen_at, unsealer_shares_present, unseal_count, last_unseal_at, failure_count, last_failure_at, last_failure_reason, updated_at) ON openbao_auto_unseal TO paddock_unsealer'
      WHERE to_regclass('public.openbao_auto_unseal') IS NOT NULL \gexec
    ```

    It waits up to 60 s for `pg_isready` first. The Makefile target `up` MUST run it right after `compose up -d`
    and before `wait-healthy.sh`. The development `openbao-bootstrap.sh` MUST write
    `.secrets/openbao/auto-unseal-shares` (mode 0644 in the 0700 directory) from the first three `Unseal Key N`
    lines of `init.txt` when the file is missing, so that the development unsealer has material.
18. `./paddock auto-unseal status|enable|disable` (`deploy/bundle/paddock`):
    - `status`: prints `PADDOCK_AUTO_UNSEAL` of `.env`, `shares file: present|absent`, the `compose ps` line of
      `paddock-unsealer` (or `not running`), and the `Sealed` line of `./paddock bao status`. Never a share.
    - `enable`: `require_host controlplane lab`; `die` when `PADDOCK_AUTO_UNSEAL` is already `yes` or the shares
      file exists (`run ./paddock auto-unseal disable first`); run `scripts/gen-prod-secrets.sh "$PADDOCK_HOST"`;
      run `compose run --rm --no-deps $(tty_flag) paddock-worker admin auto-unseal verify` and `die` with its
      message on a non-zero exit; run `scripts/postgres-unsealer-role.sh`; read three shares with
      `read -rs -p "Unseal share N of 3 (from a custodian, not echoed): " share` (prompts on stderr; from a pipe the
      three lines are read without prompting), `die` on an empty share, a share with whitespace, or two equal
      shares; write the three lines with `umask 077` to `.secrets/openbao/auto-unseal-shares` via a temporary file
      and `mv`, then `chmod 644` (the directory stays 0700, as for every secret); set `PADDOCK_AUTO_UNSEAL=yes` in
      `.env` (helper `set_dotenv <name> <value>`: replaces the line or appends it); `compose --profile paddock up -d
      paddock-unsealer`; print exactly:
      `automatic unseal is enabled on this host. Verify it now: ./paddock compose restart openbao, then ./paddock bao
      status shows "Sealed false" within 30 s. Remove every other unseal automation (for example a cron job) and its
      copies of the shares.`
    - `disable`: `require_host controlplane lab`; `compose --profile paddock stop paddock-unsealer` and
      `compose --profile paddock rm -f paddock-unsealer` (ignoring a missing service); delete the shares file
      (`shred -u` when available, else `rm -f`); set `PADDOCK_AUTO_UNSEAL=no`; print exactly:
      `the shares are deleted from this host. If the host, its disk or its backups may have been copied while
      automatic unseal was on, rotate the shares with three custodians (docs/operations/openbao.md section 6). If
      the portal still shows automatic unseal as enabled, a platform administrator disables it there.`
    - `usage` MUST list the command. `./paddock up` needs no change: the overlay is part of the file set.
19. `deploy/bundle/build.sh` MUST ship `compose.auto-unseal.yaml`, `prometheus/scrape/auto-unseal.yml` and
    `scripts/postgres-unsealer-role.sh`. `deploy/bundle/bundle_test.sh` MUST render and check a fourth variant
    `controlplane-auto-unseal` (`PROD_FILES_controlplane` plus `AUTO_UNSEAL_FILES`) and a fifth `lab-auto-unseal`
    (`PROD_FILES_lab` plus `AUTO_UNSEAL_FILES` plus `LAB_BACKUP_FILES`).

### 3.5 prod-check

20. `prodcheck.Result` MUST gain `Warn bool`; `Write` MUST print `WARN  <item>` for `OK && Warn` and MUST keep
    returning true for warnings. `Prod` MUST gain `AutoUnseal string \`json:"auto_unseal"\``. `Run` MUST append
    `checkAutoUnseal(c, o)` for every host. The item is named `openbao auto-unseal` and finds:
    - `FAIL` `paddock-unsealer is configured but PADDOCK_AUTO_UNSEAL is not yes` when the service exists and
      `Prod.AutoUnseal != "yes"`;
    - `FAIL` `PADDOCK_AUTO_UNSEAL=yes but paddock-unsealer is not in the configuration` when the switch is set and
      the service is missing;
    - `FAIL` `PADDOCK_AUTO_UNSEAL=yes on the audit host: there is no OpenBao here` for `Host == HostAudit`;
    - `FAIL` `<service>: mounts openbao_auto_unseal_shares` for every service other than `paddock-unsealer` that
      mounts that secret;
    - `FAIL` `paddock-unsealer: mounts <secret>` for every mounted secret of the unsealer whose name starts with
      `approle_`, or is a `db_paddock_*_url` other than `db_paddock_unsealer_url`;
    - `FAIL` `paddock-unsealer: <var> is set` for `PADDOCK_OPENBAO_ROLE_ID_FILE`, `PADDOCK_OPENBAO_SECRET_ID_FILE`,
      `PADDOCK_VALKEY_ADDR`, `PADDOCK_AMQP_URL` in its environment;
    - `WARN` with the detail `automatic unseal is on: whoever controls this host or a copy of its disk, snapshots or
      .secrets/ can unseal OpenBao and use every key; the custodian threshold of ADR 0006 does not gate the unseal
      (residual risk RR-43)` when the service exists, the switch is `yes`, there is no finding and
      `Host == HostControlPlane`;
    - `PASS` with the same detail line on a lab host; `PASS` with the detail `automatic unseal is off` when neither
      the service nor the switch is present.
    The generic items (`secret files present…`, `PADDOCK_ENV=production…`, `container hardening`, `links between
    the hosts use TLS`, `secrets the services reference are mounted`) apply to the new service without change.

### 3.6 Portal

21. Route `/platform/openbao` (name `platform-openbao`), view `server/web/src/views/PlatformOpenBao.vue`, navigation
    item `{ to: '/platform/openbao', label: 'nav.openbao', icon: 'shield-check', visible: (a) => a.isPlatform }`
    after `nav.sessions` (an icon of the existing set; `shield-check` if present, else the icon the IP allow list
    uses). API access through the generated client only (`server/web/src/lib/autoUnseal.ts`).
22. The view MUST show: a status card with the seal (`Unsealed` / `Sealed` / `OpenBao not reachable`, seal type,
    `threshold of shares`), the setting (`Automatic unseal: off` / `on — acknowledged by <name> on <time>, disclaimer
    <version>`; when `acknowledgement_version != disclaimer_version`: the hint `The disclaimer has changed since
    this acknowledgement.`), the unsealer (`not running` / `running, shares present` / `running, no shares on the
    host`, last report time), the last automatic unseal (time, count) and the last failure (time, reason). When the
    state is `disabled` and the unsealer reports shares present, the view MUST show an inline warning alert
    `Automatic unseal is off, but the shares are still on the host. Run ./paddock auto-unseal disable there.`
    When the state is `enabled` and the unsealer is not running or has no shares, it MUST show the info alert `The
    acknowledgement is recorded. An operator enables the unsealer on the host with ./paddock auto-unseal enable.`
    Amendment 2026-10-18 (architect note, decided by the orchestrator as architect, 2026-10-18; PDK-199 Review 1):
    "the unsealer reports shares present" means `unsealer.running` **and** `unsealer.shares_present` (decision 13
    amendment); the warning clears once `./paddock auto-unseal disable` has removed the unsealer.
23. Enabling opens `server/web/src/components/AutoUnsealDisclaimerDialog.vue`: a modal in the conventions of
    `ConfirmDialog` (focus on Cancel, Esc cancels, Enter never submits, `aria-labelledby`/`aria-describedby`) that
    renders the disclaimer of §6.6 as title, paragraphs and a numbered list, a text field labelled with the
    acknowledgement sentence to type, and the destructive button `Enable automatic unseal` that is disabled until the
    typed text equals the sentence of the current locale byte for byte. Confirming calls `enableAutoUnseal({
    disclaimer_version, acknowledgement })`; on `step_up_required` it calls `startStepUp('auto-unseal-enable',
    'setting', input)` and `resumeStepUp` on return resends the stored input without asking again (the pattern of
    `PermissionProfileDetail.vue`). Disabling uses `useConfirm` with `destructive: false`, no typed text, and the
    message `Automatic unseal stops at once. The shares stay on the host until an operator runs ./paddock
    auto-unseal disable.`; `step_up_required` is handled the same way with the action `auto-unseal-disable`.
    Problems `disclaimer_outdated` and `step_up_failed` are shown inline (`problems.*`).
24. The catalog keys are listed in §6.6; `audit.platform.auto_unseal_enabled`, `audit.platform.auto_unseal_disabled`
    and `audit.platform.openbao_auto_unsealed` MUST exist in both languages.

### 3.7 Observability

25. `deploy/compose/prometheus/alerts.yml` MUST gain `PaddockAutoUnsealWithdrawn` (`max(paddock_auto_unseal_enabled)
    == 0 and max(paddock_auto_unseal_shares_present) == 1`, `for: 1h`, severity `warning`, summary `Automatic unseal
    was disabled in the portal, but the shares are still on the host`, description `Run ./paddock auto-unseal disable
    on the control-plane host (docs/operations/openbao.md section 6).`) and `PaddockAutoUnsealerDown`
    (`max(paddock_auto_unseal_enabled) == 1 and max(paddock_auto_unseal_unsealer_up) == 0`, `for: 10m`, severity
    `warning`, summary `Automatic unseal is enabled, but the unsealer does not report`, description `OpenBao will
    stay sealed after the next restart until the unsealer runs or three custodians unseal it.`); `alerts_test.yml`
    MUST test both.

### 3.8 Documents

26. `docs/operations/openbao.md` MUST gain section 6 `Automatic unseal`: what it is, the two-step enablement (portal
    acknowledgement, then `./paddock auto-unseal enable` with three custodians present), the verification by
    restarting the OpenBao container, disabling (portal, then host), the rekey recommendation after disabling, what
    the unsealer can and cannot do (no AppRole, no keys, three shares), the alerts, and the restore note (after a
    restore with a temporary single share the unsealer's attempts fail with `invalid_share` until the restored node
    restarts; then it unseals automatically). `docs/operations/lab-install.md` MUST gain section 11 `Automatic unseal
    (replacing a cron job)` with the migration from a hand-made cron script: enable as above, remove the cron entry
    and its share file, verify. `docs/operations/install.md` MUST gain a pointer with the production warning.
    `docs/operations/monitoring.md` MUST list the two alerts and the new metrics. `docs/operations/restore.md` step 4
    MUST gain the note above. `docs/compliance/residual-risks.md` MUST gain RR-43 (§6.7, verbatim) in the section
    `Control plane and audit domain`; `docs/compliance/iso27001-mapping.md` row A.8.24 MUST mention the acknowledged
    automatic unseal as a recorded decision. `docs/architecture.md` §13.2 MUST replace the sentence `Auto-unseal MAY
    be configured by the operator with a KMS of their choice (not bundled).` by `Automatic unseal is a bundled option
    (ADR 0035): a platform administrator acknowledges a versioned disclaimer in the portal, the host operator starts
    the unsealer that holds three shares; a KMS of the operator's choice stays possible outside the bundle.`, and
    §25.2 row `OpenBao sealed after restart` MUST end with `optional automatic unseal (ADR 0035, RR-43)`.
    `CHANGELOG.md` `[Unreleased]` `### Added` MUST describe the feature for operators (one entry, §13).

## 4. Non-goals

- No change to OpenBao's seal type, its configuration files (`config.hcl`, `prod.hcl`), its policies, AppRoles or
  keys; no seal migration; no `transit`, KMS or PKCS#11 seal.
- No CLI or API that enables automatic unseal without a person's acknowledgement in the portal.
- No sealing of OpenBao by Paddock (`sys/seal`), no rekey automation.
- No change to the revocation path (`agent/internal/revoke/`, `agent/cmd/paddock-revoke/`, `pkg/revocation/`),
  to `api/openapi/device.yaml`, to the bundle format or to any agent code.
- No change to the backup contents, the restore procedure (beyond the note) or the escrow path.
- No new Go module, npm package or container image.

## 5. Affected files

| Path | Action | Purpose |
| --- | --- | --- |
| `server/internal/domain/autounseal/autounseal.go`, `autounseal_test.go` | new | decision 1 |
| `server/migrations/paddock/00049_openbao_auto_unseal.sql` | new | decision 2 |
| `server/internal/adapters/postgres/queries/auto_unseal.sql` | new | decision 3 (`make gen`) |
| `server/internal/domain/audit/codes.go` | change | §6.4 codes |
| `server/internal/problem/problem.go` | change | `DisclaimerOutdated` |
| `server/internal/platform/bao/bao.go`, `seal_test.go` | change / new | decision 5 |
| `server/internal/platform/db/db.go` | change | `UnsealerPool` |
| `server/internal/app/autounseal.go`, `autounseal_integration_test.go` | new | decision 4 |
| `server/internal/config/config.go` | change | `LoadOpenBaoAddr` |
| `server/internal/unsealer/unsealer.go`, `unsealer_test.go`, `store.go` | new | decisions 11–12 |
| `server/internal/worker/autounseal.go`, `autounseal_test.go` | new | decision 13 |
| `server/cmd/paddock-server/unsealer.go`, `run.go`, `main.go`, `admin.go`, `api.go`, `worker.go` | new / change | wiring, CLI |
| `server/internal/transport/http/admin/handlers_autounseal.go`, `server.go`, `autounseal_test.go` | new / change | decision 7 |
| `api/openapi/admin.yaml` | change | §6.1 |
| `server/internal/prodcheck/prodcheck.go`, `prodcheck_test.go`, testdata | change | decision 20 |
| `server/web/src/views/PlatformOpenBao.vue`, `components/AutoUnsealDisclaimerDialog.vue`, `lib/autoUnseal.ts`, `lib/navigation.ts`, `router.ts`, `locales/en.json`, `locales/de.json`, `__tests__/autoUnseal.test.ts` | new / change | §3.6 |
| `deploy/compose/compose.auto-unseal.yaml`, `compose.prod.yaml`, `compose.dev.yaml`, `prometheus/scrape/auto-unseal.yml`, `prometheus/alerts.yml`, `prometheus/alerts_test.yml`, `prod.env.example`, `lab.env.example` | new / change | §3.4, §3.7 |
| `deploy/compose/scripts/lib.sh`, `gen-prod-secrets.sh`, `gen-dev-secrets.sh`, `openbao-bootstrap.sh`, `postgres-unsealer-role.sh` | change / new | decisions 16–17 |
| `Makefile` | change | `up` runs the role script |
| `deploy/bundle/paddock`, `build.sh`, `bundle_test.sh`, `ci/smoke-lab.sh` | change | decisions 18–19, §9 |
| `test/acceptance/auto_unseal_test.go`, `prodcheck_autounseal_test.go` | new | §9 |
| `test/acceptance/internal/stack/stack.go` | change | development file list gains the overlay (decision 16) |
| `docs/compliance/glossary-de.md` | change | entry `Unsealer` |
| `.github/workflows/ci.yml` | change | disruptive step runs `TestAutoUnsealRestart` too |
| `docs/operations/openbao.md`, `lab-install.md`, `install.md`, `monitoring.md`, `restore.md`, `docs/compliance/residual-risks.md`, `iso27001-mapping.md`, `docs/architecture.md`, `CHANGELOG.md` | change | §3.8 |

**MUST NOT be touched:** `agent/`, `pkg/`, `api/openapi/device.yaml`, `deploy/compose/openbao/*.hcl`,
`deploy/compose/scripts/openbao-configure.sh`, `deploy/compose/postgres/init/10-roles.sh`, every existing
migration, `docs/adr/` other than through the architect, `docs/reqirements/`.

## 6. Interfaces and formats

### 6.1 Admin API additions (`api/openapi/admin.yaml`)

```yaml
  /api/platform/v1/openbao/auto-unseal:
    get:
      operationId: getAutoUnseal
      tags: [platform]
      security:
        - session: []
      description: |
        Roles: platform_admin. The automatic-unseal setting (ADR 0035): the acknowledged decision, the unsealer's
        report and OpenBao's seal status. Sessions only: platform tokens do not exist.
      responses:
        "200":
          description: The setting.
          content:
            application/json:
              schema: { $ref: "#/components/schemas/AutoUnsealStatus" }
        "401": { $ref: "#/components/responses/Problem" }
        "403": { $ref: "#/components/responses/Problem" }
  /api/platform/v1/openbao/auto-unseal/enable:
    post:
      operationId: enableAutoUnseal
      tags: [platform]
      security:
        - session: []
      description: |
        Roles: platform_admin, with a step-up within the last 5 minutes (403 step_up_required). Records the typed
        acknowledgement of the current disclaimer and enables the setting; the unsealer on the host acts only while it
        is enabled. 409 disclaimer_outdated when disclaimer_version is not the current version (the response of GET
        carries it); 400 invalid_request when acknowledgement is not the exact sentence of the disclaimer. Every
        attempt is audited.
      x-paddock-audit: platform.auto_unseal_enabled
      parameters:
        - $ref: "#/components/parameters/Csrf"
      requestBody:
        required: true
        content:
          application/json:
            schema: { $ref: "#/components/schemas/AutoUnsealEnable" }
      responses:
        "200":
          description: Enabled.
          content:
            application/json:
              schema: { $ref: "#/components/schemas/AutoUnsealStatus" }
        "400": { $ref: "#/components/responses/Problem" }
        "401": { $ref: "#/components/responses/Problem" }
        "403": { $ref: "#/components/responses/Problem" }
        "409": { $ref: "#/components/responses/Problem" }
  /api/platform/v1/openbao/auto-unseal/disable:
    post:
      operationId: disableAutoUnseal
      tags: [platform]
      security:
        - session: []
      description: |
        Roles: platform_admin, with a step-up within the last 5 minutes (403 step_up_required). Disables the setting:
        the unsealer stops unsealing at once; the shares stay on the host until the operator runs
        ./paddock auto-unseal disable. Every attempt is audited.
      x-paddock-audit: platform.auto_unseal_disabled
      parameters:
        - $ref: "#/components/parameters/Csrf"
      responses:
        "200":
          description: Disabled.
          content:
            application/json:
              schema: { $ref: "#/components/schemas/AutoUnsealStatus" }
        "401": { $ref: "#/components/responses/Problem" }
        "403": { $ref: "#/components/responses/Problem" }

components:
  schemas:
    AutoUnsealEnable:
      type: object
      required: [disclaimer_version, acknowledgement]
      properties:
        disclaimer_version: { type: string, maxLength: 16 }
        acknowledgement: { type: string, maxLength: 128 }
    AutoUnsealStatus:
      type: object
      required: [state, disclaimer_version, acknowledgement_version, acknowledgement, acknowledged_by,
                 acknowledged_at, disabled_by, disabled_at, unsealer, seal]
      properties:
        state: { type: string, enum: [disabled, enabled] }
        disclaimer_version: { type: string, description: The current version of the disclaimer text. }
        acknowledgement_version: { type: string, nullable: true, description: The version that was acknowledged. }
        acknowledgement: { type: string, nullable: true }
        acknowledged_by: { type: string, nullable: true }
        acknowledged_at: { type: string, format: date-time, nullable: true }
        disabled_by: { type: string, nullable: true }
        disabled_at: { type: string, format: date-time, nullable: true }
        unsealer: { $ref: "#/components/schemas/UnsealerReport" }
        seal: { $ref: "#/components/schemas/SealStatus" }
    UnsealerReport:
      type: object
      required: [running, seen_at, shares_present, unseal_count, last_unseal_at, failure_count, last_failure_at,
                 last_failure_reason]
      properties:
        running: { type: boolean, description: The unsealer reported within the last 60 s. }
        seen_at: { type: string, format: date-time, nullable: true }
        shares_present: { type: boolean }
        unseal_count: { type: integer, format: int64 }
        last_unseal_at: { type: string, format: date-time, nullable: true }
        failure_count: { type: integer, format: int64 }
        last_failure_at: { type: string, format: date-time, nullable: true }
        last_failure_reason: { type: string, nullable: true, enum: [unreachable, invalid_share, still_sealed, null] }
    SealStatus:
      type: object
      required: [reachable, initialized, sealed, type, threshold, shares]
      properties:
        reachable: { type: boolean }
        initialized: { type: boolean }
        sealed: { type: boolean }
        type: { type: string }
        threshold: { type: integer }
        shares: { type: integer }
```

### 6.2 Route table (`server/internal/transport/http/admin/server.go`)

```go
"POST /api/platform/v1/openbao/auto-unseal/enable":  {app.ScopePlatform, app.SpecAutoUnsealEnable},
"POST /api/platform/v1/openbao/auto-unseal/disable": {app.ScopePlatform, app.SpecAutoUnsealDisable},
```

### 6.3 Go signatures

Decisions 1, 4, 5, 10, 11 and 13 give the signatures. In addition:

```go
// server/internal/config/config.go
// LoadOpenBaoAddr reads PADDOCK_OPENBAO_ADDR only (roles without an AppRole: the unsealer).
func LoadOpenBaoAddr(l *Loader) string

// server/cmd/paddock-server/admin.go: adminCommand.name gains "auto-unseal", adminCommand.sub gains show | verify | disable
```

### 6.4 Audit codes (closed registry, `codes.go`; descriptions verbatim)

```go
// Automatic unseal of OpenBao (ADR 0035, plan M8u §6.4).
CodePlatformAutoUnsealEnabled   Code = "platform.auto_unseal_enabled"
CodePlatformAutoUnsealDisabled  Code = "platform.auto_unseal_disabled"
CodePlatformOpenBaoAutoUnsealed Code = "platform.openbao_auto_unsealed"
```

| Code | Description | Params | Outcomes | Note |
| --- | --- | --- | --- | --- |
| `platform.auto_unseal_enabled` | A platform administrator acknowledged the automatic-unseal disclaimer with a step-up and enabled the setting. | `disclaimer_version`, `acknowledgement`, `previous_state` | success, failure, denied | Denied with step_up_required without a fresh step-up, forbidden for a non-platform principal; failure with disclaimer_outdated or invalid_request when the version or the sentence does not match. Platform pseudo-organization. |
| `platform.auto_unseal_disabled` | The automatic-unseal setting was disabled; the unsealer stops unsealing at once. | `previous_state`, `method` | success, failure, denied | method is portal or cli (paddock-server admin auto-unseal disable). Platform pseudo-organization. |
| `platform.openbao_auto_unsealed` | The unsealer unsealed OpenBao with the shares on the host, or failed to; recorded by the worker from the unsealer's report. | `unseals`, `last_unseal_at`, `failures`, `last_failure_at`, `last_failure_reason` | success, failure | One event per observed change of the counters, at most every 30 s; a failure carries error code auto_unseal_failed and last_failure_reason unreachable, invalid_share or still_sealed. Actor is the system actor paddock-unsealer. Platform pseudo-organization. |

Portal catalog (`audit.platform.*`), en:
`"auto_unseal_enabled": "{actor} enabled automatic unseal of OpenBao and acknowledged the disclaimer {disclaimer_version}"`,
`"auto_unseal_disabled": "{method, select, cli {Automatic unseal of OpenBao was disabled on the host} other {{actor} disabled automatic unseal of OpenBao}}"`,
`"openbao_auto_unsealed": "{failures, plural, =0 {The unsealer unsealed OpenBao automatically ({unseals, number} times since the last report)} other {The unsealer failed to unseal OpenBao ({failures, number} failures, last reason {last_failure_reason})}}"`.
de: `"{actor} hat das automatische Entsiegeln von OpenBao aktiviert und den Hinweis {disclaimer_version} bestätigt"`,
`"{method, select, cli {Das automatische Entsiegeln von OpenBao wurde auf dem Host deaktiviert} other {{actor} hat das automatische Entsiegeln von OpenBao deaktiviert}}"`,
`"{failures, plural, =0 {Der Unsealer hat OpenBao automatisch entsiegelt ({unseals, number} Mal seit dem letzten Bericht)} other {Der Unsealer konnte OpenBao nicht entsiegeln ({failures, number} Fehlversuche, letzter Grund {last_failure_reason})}}"`.

### 6.5 Files, variables, metrics, alerts

| Item | Value |
| --- | --- |
| Shares file (host) | `.secrets/openbao/auto-unseal-shares`: three lines, one share each as `bao operator init` prints it (base64 or hex), mode 0644 in the 0700 `.secrets/` |
| Compose secret | `openbao_auto_unseal_shares` → `/run/secrets/openbao_auto_unseal_shares`, mounted into `paddock-unsealer` only |
| Host switch | `PADDOCK_AUTO_UNSEAL=yes|no` in `.env`; `x-paddock-prod.auto_unseal` |
| Overlay | `deploy/compose/compose.auto-unseal.yaml`; `AUTO_UNSEAL_FILES` in `lib.sh` |
| Database role | `paddock_unsealer`: `CONNECT`, `USAGE`, `SELECT` on `openbao_auto_unseal`, `UPDATE` on its report columns |
| Secrets | `db_paddock_unsealer_password`, `db_paddock_unsealer_url` |
| Unsealer env | `PADDOCK_DB_UNSEALER_URL_FILE`, `PADDOCK_OPENBAO_ADDR`, `BAO_CACERT`, `PADDOCK_OPENBAO_UNSEAL_SHARES_FILE`, `PADDOCK_OPS_ADDR`, `PADDOCK_ENV`, `PADDOCK_LOG_LEVEL` |
| Unsealer metrics | `paddock_unsealer_shares_present`, `paddock_unsealer_setting_enabled`, `paddock_unsealer_unseals_total{result}` |
| Worker metrics | `paddock_auto_unseal_enabled`, `paddock_auto_unseal_shares_present`, `paddock_auto_unseal_unsealer_up` |
| Alerts | `PaddockAutoUnsealWithdrawn` (warning, 1 h), `PaddockAutoUnsealerDown` (warning, 10 min) |
| prod-check item | `openbao auto-unseal` (`PASS` / `WARN` / `FAIL`, decision 20) |
| Step-up actions (portal) | `auto-unseal-enable`, `auto-unseal-disable` |

### 6.6 Disclaimer and portal catalog (binding, verbatim)

Catalog keys under `openbao` in `en.json`:

```json
"openbao": {
  "title": "OpenBao",
  "summary": "OpenBao holds every key of this installation. It starts sealed after every restart; three custodians unseal it, or, if you accept the risk below, the unsealer on the control-plane host does.",
  "seal": {
    "title": "Seal",
    "unsealed": "Unsealed",
    "sealed": "Sealed",
    "unreachable": "OpenBao is not reachable",
    "threshold": "{threshold} of {shares} shares unseal it ({type})"
  },
  "setting": {
    "title": "Automatic unseal",
    "off": "Off",
    "on": "On — acknowledged by {by} on {at}, disclaimer {version}",
    "outdated": "The disclaimer has changed since this acknowledgement.",
    "disabledBy": "Disabled by {by} on {at}"
  },
  "unsealer": {
    "title": "Unsealer on the host",
    "notRunning": "Not running",
    "runningWithShares": "Running, shares present",
    "runningNoShares": "Running, no shares on the host",
    "seenAt": "Last report {at}",
    "lastUnseal": "Last automatic unseal {at} ({count, number} in total)",
    "neverUnsealed": "No automatic unseal yet",
    "lastFailure": "Last failure {at}: {reason}",
    "reason": {
      "unreachable": "OpenBao did not answer",
      "invalid_share": "a share was refused",
      "still_sealed": "still sealed after three shares"
    }
  },
  "alerts": {
    "sharesLeft": "Automatic unseal is off, but the shares are still on the host. Run ./paddock auto-unseal disable there.",
    "hostStep": "The acknowledgement is recorded. An operator enables the unsealer on the host with ./paddock auto-unseal enable."
  },
  "enable": "Enable automatic unseal",
  "disable": "Disable automatic unseal",
  "disableConfirmTitle": "Disable automatic unseal?",
  "disableConfirmMessage": "Automatic unseal stops at once. The shares stay on the host until an operator runs ./paddock auto-unseal disable.",
  "disclaimer": {
    "title": "Enable automatic unseal of OpenBao",
    "intro": "Automatic unseal keeps three of the five unseal shares on the control-plane host, in .secrets/openbao/auto-unseal-shares. A small service on that host, the unsealer, reads them and unseals OpenBao whenever it starts sealed, as long as this setting is on.",
    "lead": "Before you enable it, understand and accept these consequences:",
    "risk1": "Whoever controls the host controls every key. Anyone with root on the host, a copy of its disk, a snapshot of the virtual machine or a copy of .secrets/ can unseal OpenBao and use every key in it: the signing keys for device configuration, commands and revocation tokens, the escrow key that decrypts the escrowed disk recovery material of every device, the audit chain key and the portal session keys.",
    "risk2": "The custodian model no longer protects the unseal. Today three named custodians must act together before OpenBao unseals. With automatic unseal their shares still exist, but three of them lie on the host; no person has to act, and no one is asked.",
    "risk3": "Copies and backups of the host become as sensitive as the keys. Paddock never writes the shares into its own backups, but a disk image, a VM snapshot or a copy of the bundle directory does contain them, and nothing in Paddock can tell that such a copy exists.",
    "risk4": "This is a residual risk of your information security management system (RR-43 in docs/compliance/residual-risks.md). Record it with an owner and a decision. On a production host, ./paddock check warns on every run while automatic unseal is on.",
    "outro": "Enabling here places no share on the host. It records your acknowledgement, with your name, the time and the version of this text ({version}), in the audit log. An operator with access to the host then runs ./paddock auto-unseal enable, which refuses to run without this acknowledgement. Disabling here stops the automatic unseal at once; the shares stay on the host until the operator runs ./paddock auto-unseal disable.",
    "typeLabel": "Type the sentence to confirm: {sentence}",
    "sentence": "I understand and accept the risk"
  }
}
```

`de.json`:

```json
"openbao": {
  "title": "OpenBao",
  "summary": "OpenBao verwahrt jeden Schlüssel dieser Installation. Nach jedem Neustart ist es versiegelt; drei Schlüsselverwahrer entsiegeln es — oder, wenn Sie das Risiko unten akzeptieren, der Unsealer auf dem Control-Plane-Host.",
  "seal": {
    "title": "Siegel",
    "unsealed": "Entsiegelt",
    "sealed": "Versiegelt",
    "unreachable": "OpenBao ist nicht erreichbar",
    "threshold": "{threshold} von {shares} Anteilen entsiegeln es ({type})"
  },
  "setting": {
    "title": "Automatisches Entsiegeln",
    "off": "Aus",
    "on": "An — bestätigt von {by} am {at}, Hinweis {version}",
    "outdated": "Der Hinweistext hat sich seit dieser Bestätigung geändert.",
    "disabledBy": "Deaktiviert von {by} am {at}"
  },
  "unsealer": {
    "title": "Unsealer auf dem Host",
    "notRunning": "Läuft nicht",
    "runningWithShares": "Läuft, Anteile vorhanden",
    "runningNoShares": "Läuft, keine Anteile auf dem Host",
    "seenAt": "Letzter Bericht {at}",
    "lastUnseal": "Letztes automatisches Entsiegeln {at} ({count, number} insgesamt)",
    "neverUnsealed": "Noch kein automatisches Entsiegeln",
    "lastFailure": "Letzter Fehlversuch {at}: {reason}",
    "reason": {
      "unreachable": "OpenBao hat nicht geantwortet",
      "invalid_share": "ein Anteil wurde abgelehnt",
      "still_sealed": "nach drei Anteilen weiterhin versiegelt"
    }
  },
  "alerts": {
    "sharesLeft": "Das automatische Entsiegeln ist aus, aber die Anteile liegen noch auf dem Host. Führen Sie dort ./paddock auto-unseal disable aus.",
    "hostStep": "Die Bestätigung ist aufgezeichnet. Ein Operator aktiviert den Unsealer auf dem Host mit ./paddock auto-unseal enable."
  },
  "enable": "Automatisches Entsiegeln aktivieren",
  "disable": "Automatisches Entsiegeln deaktivieren",
  "disableConfirmTitle": "Automatisches Entsiegeln deaktivieren?",
  "disableConfirmMessage": "Das automatische Entsiegeln endet sofort. Die Anteile bleiben auf dem Host, bis ein Operator ./paddock auto-unseal disable ausführt.",
  "disclaimer": {
    "title": "Automatisches Entsiegeln von OpenBao aktivieren",
    "intro": "Beim automatischen Entsiegeln liegen drei der fünf Entsiegelungsanteile auf dem Control-Plane-Host, in .secrets/openbao/auto-unseal-shares. Ein kleiner Dienst auf diesem Host, der Unsealer, liest sie und entsiegelt OpenBao, wann immer es versiegelt startet — solange diese Einstellung an ist.",
    "lead": "Bevor Sie es aktivieren, verstehen und akzeptieren Sie diese Folgen:",
    "risk1": "Wer den Host kontrolliert, kontrolliert jeden Schlüssel. Wer Root auf dem Host hat, eine Kopie seiner Festplatte, einen Snapshot der virtuellen Maschine oder eine Kopie von .secrets/, kann OpenBao entsiegeln und jeden Schlüssel darin verwenden: die Signaturschlüssel für Gerätekonfiguration, Kommandos und Widerrufs-Token, den Escrow-Schlüssel, der das hinterlegte Wiederherstellungsmaterial der Festplatten aller Geräte entschlüsselt, den Audit-Ketten-Schlüssel und die Sitzungsschlüssel des Portals.",
    "risk2": "Das Verwahrer-Modell schützt das Entsiegeln nicht mehr. Heute müssen drei benannte Schlüsselverwahrer gemeinsam handeln, bevor OpenBao entsiegelt wird. Mit dem automatischen Entsiegeln existieren ihre Anteile weiter, aber drei davon liegen auf dem Host; niemand muss handeln, und niemand wird gefragt.",
    "risk3": "Kopien und Backups des Hosts werden so sensibel wie die Schlüssel selbst. Paddock schreibt die Anteile nie in seine eigenen Backups, aber ein Festplattenabbild, ein VM-Snapshot oder eine Kopie des Bundle-Verzeichnisses enthält sie — und nichts in Paddock kann erkennen, dass eine solche Kopie existiert.",
    "risk4": "Dies ist ein Restrisiko Ihres Informationssicherheits-Managementsystems (RR-43 in docs/compliance/residual-risks.md). Erfassen Sie es mit einem Verantwortlichen und einer Entscheidung. Auf einem Produktions-Host warnt ./paddock check bei jedem Lauf, solange das automatische Entsiegeln an ist.",
    "outro": "Das Aktivieren hier legt keinen Anteil auf den Host. Es zeichnet Ihre Bestätigung mit Ihrem Namen, der Uhrzeit und der Version dieses Textes ({version}) im Audit-Log auf. Ein Operator mit Zugang zum Host führt danach ./paddock auto-unseal enable aus; ohne diese Bestätigung verweigert der Befehl die Ausführung. Das Deaktivieren hier beendet das automatische Entsiegeln sofort; die Anteile bleiben auf dem Host, bis der Operator ./paddock auto-unseal disable ausführt.",
    "typeLabel": "Geben Sie zur Bestätigung den Satz ein: {sentence}",
    "sentence": "Ich verstehe und akzeptiere das Risiko"
  }
}
```

Further keys: `nav.openbao` (`"OpenBao"` in both languages), `problems.disclaimer_outdated` (en `"The disclaimer
has changed. Read the new text and confirm it again."`, de `"Der Hinweistext hat sich geändert. Lesen Sie den neuen
Text und bestätigen Sie erneut."`). The dialog MUST render `disclaimer.title`, `intro`, `lead`, `risk1`–`risk4` as a
numbered list, `outro` and the field labelled `typeLabel`; a component test MUST assert the rendered text of the
four risks. The constants `autounseal.Acknowledgements` MUST equal `disclaimer.sentence` of `en.json` and `de.json`;
a Go test in `server/internal/domain/autounseal` MUST read both catalogs and compare.

Amendment 2026-10-18 (architect note, decided by the orchestrator as architect, 2026-10-18; PDK-199 fix round 2,
browser check at 375 px): the field label cut the sentence off on a phone. The dialog shows the sentence as its own
quoted block after the new key `typePrompt` (en `"Type this sentence to confirm:"`, de `"Geben Sie zur Bestätigung
diesen Satz ein:"`), and `typeLabel` becomes the short field label (en `"Sentence to confirm"`, de
`"Bestätigungssatz"`) without `{sentence}`. `sentence` and every other key above stay verbatim.

### 6.7 Residual risk RR-43 (`docs/compliance/residual-risks.md`, section "Control plane and audit domain", verbatim)

M8b reserved RR-40 to RR-42; this plan takes **RR-43**.

| ID | Risk | Mitigation in Paddock | Record in the ISMS |
| --- | --- | --- | --- |
| RR-43 | **Automatic unseal puts three unseal shares on the control-plane host.** With automatic unseal enabled (ADR 0035), the unsealer holds three of the five shares in `.secrets/openbao/auto-unseal-shares`. Whoever controls the host, a disk image, a VM snapshot or a copy of `.secrets/` can unseal OpenBao and use every key in it: bundle, command and revocation signing, escrow decryption, the audit chain and the portal sessions. The custodian threshold of ADR 0006 no longer gates the unseal (it still gates rekeying and root-token generation), and Paddock cannot see copies of the host. | Enabling needs a platform administrator's step-up and the typed acknowledgement of a versioned disclaimer (`platform.auto_unseal_enabled`), and then the host operator with three custodians' shares; the unsealer acts only while the setting is enabled, holds no AppRole and reports every unseal (`platform.openbao_auto_unsealed`); `./paddock check` warns on a production host; the shares are never in a Paddock backup; disabling in the portal stops the unseal at once and `./paddock auto-unseal disable` removes the shares; alerts when the shares outlive the setting or the unsealer stops reporting. | Decide whether automatic unseal is acceptable for the installation (a lab: usually yes; production: only with compensating host controls — full-disk encryption of the host, restricted host access, controlled snapshots and images); record the acknowledgement and its owner; after disabling, rotate the shares (`bao operator rekey`, three custodians) when the host may have been copied. |

## 7. Host and operator notes (binding figures for the documents)

- The unsealer ticks every 10 s and backs off 60 s after a failure; OpenBao is unsealed within about 20 s of
  reporting sealed. The worker records the event within the next 30 s.
- Enabling needs: a platform administrator with a WebAuthn step-up (portal), the host operator, and three custodians
  who each type their share once into `./paddock auto-unseal enable` (nothing is echoed, nothing is on a command
  line). The shares never travel in e-mail or chat.
- After `./paddock auto-unseal disable`, a rekey with three custodians (`bao operator rekey -key-shares=5
  -key-threshold=3`, new shares to the custodians, then `./paddock compose run --rm --no-deps paddock-worker backup
  openbao`) invalidates every copy of the shares file.
- Restore: the unsealer reports `invalid_share` failures against the temporary single-share instance of restore step 4
  and unseals automatically after the restored node restarts; no manual step.

## 8. Steps (tickets, in order)

1. **PDK-192 — Domain, migration, queries, audit codes, problem code, catalog texts.** Decisions 1–3, 6, §6.4,
   `problems.disclaimer_outdated`, `audit.platform.*` in both languages, glossary entry `Unsealer`, `make gen`.
   Verify: `make gen` has no diff; `GOTOOLCHAIN=auto go test -count=1 ./server/internal/domain/... ./server/internal/transport/http/admin/`
   (`TestOpenAPISpec` not yet affected); `make web`.
2. **PDK-193 — OpenBao client seal calls, `UnsealerPool`, the unsealer role.** Decisions 5, 9–12. Unit tests with an
   `httptest` OpenBao stand-in (`/v1/sys/seal-status`, `/v1/sys/unseal`, `/v1/sys/health`). Verify:
   `GOTOOLCHAIN=auto go test -count=1 ./server/internal/platform/bao/ ./server/internal/platform/db/ ./server/internal/unsealer/ ./server/cmd/...`.
3. **PDK-194 — Use cases, admin API, CLI, worker observer and metrics.** Decisions 4, 7, 8, 13, §6.1, §6.2. Verify:
   `GOTOOLCHAIN=auto go test -count=1 ./server/internal/app/ ./server/internal/worker/ ./server/internal/transport/http/admin/`;
   `make typecheck`.
4. **PDK-195 — Portal page and disclaimer dialog.** Decisions 21–24, §6.6. Verify: `make web` (component tests
   `autoUnseal.test.ts`, `navigation.test.ts`, `i18n.test.ts`); browser check per skill `frontend-verify`.
5. **PDK-196 — Compose overlay, secrets, role script, `./paddock auto-unseal`, development bootstrap, bundle.**
   Decisions 14–19. Verify: `make bundle-test`; `make down V=1 dev-secrets up dev-seed` (the development unsealer
   runs and reports); `shellcheck` of the changed scripts (`make lint`).
6. **PDK-197 — prod-check item and WARN status.** Decision 20 with fixtures for every finding, WARN on controlplane,
   PASS on lab. Verify: `GOTOOLCHAIN=auto go test -count=1 ./server/internal/prodcheck/`; `make acceptance
   T=TestProdCheckAutoUnseal`.
7. **PDK-198 — Acceptance gates, lab bundle smoke test, alerts.** §9 U1–U6, `smoke-lab.sh` step 10, decision 25,
   CI disruptive step. Verify: `make acceptance T='TestAutoUnseal'`; `PADDOCK_ACCEPTANCE_DISRUPTIVE=1 make acceptance
   T=TestAutoUnsealRestart`; `make lint-prometheus`; `make bundle-smoke-lab`.
8. **PDK-199 — Documents, residual risk, architecture amendment, CHANGELOG, regression.** Decision 26, §6.7, §13.
   Verify: `make lint test`, `make acceptance`, `make e2e`, `make bundle-test`, `make bundle-smoke-lab`,
   `make scan-secrets`.

PDK-193 and PDK-194 depend on PDK-192; PDK-195 depends on PDK-194 (generated client); PDK-196 depends on PDK-193;
PDK-197 depends on PDK-196 (the overlay it checks); PDK-198 depends on PDK-194, PDK-195, PDK-196 and PDK-197;
PDK-199 last. PDK-193 and PDK-194 MAY run in parallel.

## 9. Acceptance criteria (test/acceptance, positive and negative per role)

Roles: **P** = platform admin (`env.PlatformAdmin`, step-up with `stepUp`), **A** = org_admin (`env.Alice`),
**T** = API token of `env.Alice`, **O** = host operator (CI smoke test). "Event" = exactly one audit event with the
given code and outcome in the platform pseudo-organization, found with `expectOneIndexEvent` by `correlation_id`.

| # | Given / When / Then | Role sees |
| --- | --- | --- |
| U1 | `TestAutoUnsealAcknowledgement`: P GETs `/api/platform/v1/openbao/auto-unseal` → 200 with `disclaimer_version = "2026-10-17"`, `seal.reachable = true`, `seal.type = "shamir"`, `seal.threshold = 3`, `seal.shares = 5`; A GETs → 403 `forbidden`; T GETs → 401 or 403 (platform routes refuse tokens; assert status ≥ 401, no 200). | P, A, T |
| U2 | P without step-up POSTs `enable` with the current version and `I understand and accept the risk` → 403 `step_up_required`, event `platform.auto_unseal_enabled` denied; P with step-up POSTs with `disclaimer_version = "2000-01-01"` → 409 `disclaimer_outdated`, event failure; with `acknowledgement = "I accept"` → 400 `invalid_request`, event failure; with the German sentence → 200 `state = enabled`, `acknowledged_by` = the platform admin's display name, `acknowledgement_version = "2026-10-17"`, `acknowledgement` = the German sentence, event success with params `disclaimer_version`, `acknowledgement`, `previous_state = disabled`. A with step-up POSTs → 403 `forbidden`, event denied. | P, A |
| U3 | P without step-up POSTs `disable` → 403 `step_up_required`, event `platform.auto_unseal_disabled` denied; with step-up → 200 `state = disabled`, `disabled_by` set, event success with `previous_state = enabled`, `method = portal`; the acknowledgement fields stay filled. The gate restores the state it found at the start. | P |
| U4 | `TestAutoUnsealRestart` (disruptive, `PADDOCK_ACCEPTANCE_DISRUPTIVE=1` only): P enables; the development unsealer reports `running = true`, `shares_present = true` within 70 s; the gate runs `docker compose restart openbao` (`stack.Compose`); within 90 s GET shows `seal.sealed = false` and `unsealer.last_unseal_at` later than before, `unseal_count` grew by 1; event `platform.openbao_auto_unsealed` success with `unseals = 1` within `auditPollTimeout + 30 s`. Then P disables; the gate restarts OpenBao again; after 30 s GET shows `seal.sealed = true` and `unseal_count` unchanged; the gate unseals OpenBao with the development shares (`deploy/compose/scripts/openbao-bootstrap.sh unseal` through `stack`) in `t.Cleanup`, also on failure. | P |
| U5 | `TestProdCheckAutoUnseal` (`prodcheck_autounseal_test.go`): the controlplane configuration with `PADDOCK_AUTO_UNSEAL=yes` and the overlay appended to the file list → `WARN  openbao auto-unseal` with the detail containing `RR-43`, exit code 0; the same without the switch but with the overlay → `FAIL  openbao auto-unseal` with `PADDOCK_AUTO_UNSEAL is not yes`; the default configuration → `PASS  openbao auto-unseal` with `automatic unseal is off`; the lab configuration with the switch and the overlay → `PASS  openbao auto-unseal` with `RR-43` in the detail. | O |
| U6 | Lab bundle smoke test (`smoke-lab.sh`, new step 10 after the probes): the acknowledgement row is set with `psql` as the CI stand-in for the portal (`UPDATE openbao_auto_unseal SET state='enabled', disclaimer_version='2026-10-17', acknowledgement='I understand and accept the risk', acknowledged_by='smoke test', acknowledged_at=now() WHERE id=1`); `./paddock auto-unseal enable` reads the three shares of step 5 from stdin and exits 0; `./paddock check` passes and prints `PASS  openbao auto-unseal`; `./paddock compose restart openbao`; within 60 s `./paddock bao status` shows `Sealed false`; `./paddock auto-unseal status` shows `shares file: present`; `./paddock auto-unseal disable` exits 0, the shares file is gone, `.env` has `PADDOCK_AUTO_UNSEAL=no`, `./paddock ps` lists no `paddock-unsealer`; `./paddock check` passes with `automatic unseal is off`. The smoke test MUST NOT print a share (assert the log has none of the three strings). | O |
| U7 | Portal component tests: the disclaimer dialog's confirm button is disabled until the exact sentence of the locale is typed (en and de), the four risks are rendered, Esc cancels; the status card renders `alerts.sharesLeft` for `state = disabled` with `shares_present = true` and `alerts.hostStep` for `state = enabled` with `running = false`. | P |
| U8 | `make lint-prometheus`: `PaddockAutoUnsealWithdrawn` fires after 1 h of `enabled = 0, shares_present = 1` and not before; `PaddockAutoUnsealerDown` fires after 10 min of `enabled = 1, unsealer_up = 0`. | O |

## 10. Freedoms

Internal structure of the unsealer (one struct or several), the names of unexported helpers, the fake OpenBao
server of the unit tests, the layout of `PlatformOpenBao.vue` within the design system (cards, chips, spacing), the
icon of the navigation item if `shield-check` does not exist in `PdIconSet.ts`, the exact wording of log lines, the
leader-lock key constant of the observer (any unused value), the `promtool` test series, the sqlc query file split,
whether the admin CLI prints `show` as aligned `key: value` or as `key=value`, the shell helper names in `./paddock`
(`set_dotenv` is binding), and the order of the `shipped` array entries in `build.sh`.

## 11. Stop conditions

- S1: `docker compose config` cannot express the development override of decision 14 (`BAO_CACERT` removal or
  `secrets: !override`) — report the rendered configuration; do not mount the internal CA in development.
- S2: `go test` of the `pgstore` queries shows that column-level `GRANT UPDATE` breaks sqlc's generated `UPDATE …
  RETURNING` — report; do not grant `UPDATE` on the whole table to `paddock_unsealer`.
- S3: the OpenBao Go client of the pinned module version lacks `SealStatusWithContext`, `UnsealWithContext` or
  `ResetUnsealProcessWithContext` — report; do not bump the module without a decision.
- S4: `TestOpenAPISpec` or the privileged route table needs a change to how `GET` routes are treated — report; the
  GET is not privileged and MUST NOT carry `x-paddock-audit`.
- S5: `wait-healthy.sh` hangs in `make up` because the unsealer is unhealthy before the role exists even with
  decision 17's order — report the order observed; do not mark the unsealer's healthcheck as disabled.
- S6: the lab smoke test cannot pass a share on stdin to `./paddock auto-unseal enable` through `lab_paddock`
  without the share appearing in a process list — report; do not pass shares as arguments.
- S7: any change seems necessary in `agent/`, `pkg/`, `api/openapi/device.yaml`, `deploy/compose/openbao/*.hcl`,
  `openbao-configure.sh` or `postgres/init/10-roles.sh`.
- S8: a new Go module, npm package or container image seems necessary (none is expected).
- S9: an existing acceptance gate fails because OpenBao was sealed by the disruptive gate and not unsealed again —
  report before changing any gate.
- S10: the disclaimer text of §6.6 needs a change to fit the dialog — report; the text is binding, the layout is free.

## 12. Risks and open points

- **The shares are on the host.** Accepted by design and stated in the disclaimer, RR-43 and `./paddock check`.
  Mitigation beyond Paddock is the operator's: host disk encryption, host access control, snapshot handling.
- **The unsealer is new code in a security path.** It is small, has no AppRole, and fails safe (any error → no
  action). Unit tests cover every branch of `Tick`; the disruptive gate proves the real path.
- **The database role is created after the first release.** The role script is idempotent and runs from
  `./paddock auto-unseal enable` and `make up`; the migration grants conditionally. If the script never ran, the
  unsealer is not ready (`/readyz` 503) and `PaddockRoleDown` fires — visible, not silent.
- **The audit event lags the unseal by up to 30 s** and is recorded by the worker. Accepted (ADR 0035 option C2).
- **Prometheus scrape of a service that does not exist** would fire `PaddockRoleDown`; the scrape file is mounted by
  the overlay only, so the target exists exactly when the service does.
- **`shred` on SSD or copy-on-write file systems** does not guarantee erasure; the disable message points to the
  rekey.
- Open (default chosen): whether production should be refused outright instead of warned. Default: allowed with
  `WARN` (ADR 0035 option E2); the maintainer may tighten this later by turning the `WARN` into a `FAIL` unless
  `PADDOCK_AUTO_UNSEAL_ACCEPTED=yes`, in the shape of `PADDOCK_REVOCATION_ACCEPTED`.
- Open (default chosen): the shares file mode. Default 0644 inside the 0700 `.secrets/` (the convention every secret
  follows; the container's user 65532 must read it). A 0600 file would need a `chown` to 65532 on the host.
- Open (default chosen): the typed sentence is accepted in English and German. Default: both; the one typed is
  stored and audited.
- Open (default chosen): the disruptive gate restarts the OpenBao container of the development stack twice. Default:
  it runs only in the disruptive CI step with `TestSessionsEndAll`.

## 13. CHANGELOG

Every ticket that adds an operator-visible surface (PDK-194 API and CLI, PDK-195 portal, PDK-196 `./paddock
auto-unseal` and the overlay, PDK-197 the check item, PDK-198 the alerts) adds its line under `[Unreleased]`
`### Added`. PDK-199 merges them into one entry that names: the portal page *Platform → OpenBao* with the
acknowledged disclaimer, `./paddock auto-unseal enable|disable|status`, the unsealer, the audit codes, the check
item and its production warning, the two alerts, RR-43, and the lab migration from a cron job. The entry describes
the feature and its risk in operator language; it does not describe an attack.
