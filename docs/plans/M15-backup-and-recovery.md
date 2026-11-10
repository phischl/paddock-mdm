# Implementierungsplan: M15 — Platform backup and recovery (targets, one confirmed key, backup sets, restore plans)

Status: Ready for implementation · 2026-11-04 · Author: architect
Basis: ADR 0046 (platform backup and recovery; **Accepted 2026-11-04**); ADR 0016 (pgBackRest, OpenBao snapshots, audit store excluded); ADR 0018 (lists and
dialogs); ADR 0032 (retention classes); ADR 0034 (step-up; API tokens never satisfy one); ADR 0035 (auto-unseal,
the pattern of a platform setting with a typed acknowledgement); plan M6a §2.2 (the existing backup), M6c decisions
20–22 (restore commands), M8u (platform page with step-up), M9 §3.3 (Transit-wrapped secrets entered in the portal);
epic PDK-474 (the maintainer's binding decisions of 2026-10-28).

Binding language: **MUST** / **MUST NOT** / **SHOULD** / **MAY**.

This plan is written against `main` at `80984bde` (0.1.0-alpha.8). Tickets: PDK-729 to PDK-739 (§8). Milestone
number M15 (M14 is the MCP).

## 1. Goal

A platform administrator sets up where backups go (a local directory, an SMB or NFS share, an S3-compatible
endpoint), receives the one key that protects every backup exactly once and proves that it is stored before the
first backup runs, sees per target and per data kind when the last backup succeeded, and plans a restore — to a
point in time or of single components — with a step-up and a typed confirmation; an operator executes the plan on
the host with one command, or brings a lost installation back from an uploaded backup set or a connected target
with one command. Every step is audited; no key, password or share credential ever reaches a log, a list or an
audit event. The escrow objects of the lab (LUKS headers) are part of every backup set.

## 2. Context (verified in the code on 2026-11-04, `main` at `80984bde`)

- **Backup today** (plan M6a decisions 4–9): `deploy/compose/compose.backup.yaml` (control plane, `lab` with
  `PADDOCK_LAB_BACKUP=yes`) runs `pgbackrest` and `pgbackrest-authentik` (image `paddock-pgbackrest`, uid 999,
  entrypoint `deploy/compose/pgbackrest/run.sh` with the commands `serve|backup|flush|info|restore`; one S3
  repository `repo1-type=s3`, `repo1-cipher-type=aes-256-cbc`, cipher pass from
  `PADDOCK_BACKUP_ENCRYPTION_KEY_FILE`; the WAL spool volumes `pgbackrest-spool-<stanza>`; the state volume with
  the lock and `last-full`), `fleet-backup` (`deploy/compose/fleet/backup.sh`: `mysqldump | gzip | openssl enc`
  into the volume `fleet-dumps`) and `fleet-backup-upload` (`AWS_CLI_IMAGE`). `paddock-worker` runs
  `worker.Backups` (`server/internal/worker/backup.go`: `Round` every 5 min, `SnapshotOpenBao` through the AppRole
  `paddock-backup` when the newest `openbao/` object is older than 6 h, the gauges
  `paddock_backup_last_success_timestamp_seconds{kind}`, `paddock_backup_kinds`,
  `paddock_backup_wal_last_archived_timestamp_seconds{stanza}`, `paddock_backup_wal_stanzas`). `server/internal/backup`
  holds `ParseKey`, `Seal`, `Open` (AES-256-GCM, magic `PADDOCK-BACKUP-1`), `Kinds`, `WALStanzas`,
  `OpenBaoPrefix`. `server/cmd/paddock-server/backup.go` implements `backup openbao` and `backup decrypt`. The
  secrets `backup_encryption_key`, `backup_{pgbackrest,worker,fleet}_{access,secret}_key`,
  `approle/paddock-backup/{role_id,secret_id}` come from `gen-prod-secrets.sh` / `gen-dev-secrets.sh`
  (`backup_encryption_key` = 32 random bytes base64).
- **Restore today**: `docs/operations/restore.md` (seven manual steps), `deploy/compose/scripts/restore-drill.sh`
  (`make restore-drill`, development stack with `BACKUP=1`; sources `openbao-restore.sh` with
  `openbao_restore_snapshot <workdir> <init file>`; guard `restore-drill-guard.sh`), `paddock-server admin
  bump-bundle-seq --by N`, `admin rebuild-cache`, `admin recompile --all`.
- **Host script**: `deploy/bundle/paddock` (commands `version|verify|secrets|pull|check|up|down|ps|logs|compose|
  bao|bootstrap|agent-release|agent-rollout|agent-rollout-halt|auto-unseal|migrate-from`; `dotenv`, `set_dotenv`,
  `require_host`, `lab_warning`); `deploy/compose/scripts/lib.sh` (`compose_files`: `PROD_FILES_controlplane =
  compose.yaml compose.prod.yaml compose.backup.yaml`, `LAB_BACKUP_FILES`, `PADDOCK_COMPOSE_EXTRA`). The bundle
  ships only files of `deploy/compose` and `deploy/bundle` (`deploy/bundle/build.sh`); `.env` and `.secrets/` are
  host-local.
- **prod-check** (`server/internal/prodcheck/prodcheck.go`): reads `docker compose config --format json`
  (`Config{Services, Secrets, Prod}`), items with PASS/FAIL; `x-paddock-prod` carries `.env` values the checks need.
- **Platform settings pattern**: `server/internal/app/autounseal.go` (`RolesPlatform`, `RequiresStepUp`,
  `platform.InPlatform`, the disclaimer with `acknowledgement`), routes in
  `server/internal/transport/http/admin/server.go` (`privileged` table, `/api/platform/v1/openbao/auto-unseal/*`),
  portal `server/web/src/views/PlatformOpenBao.vue` (`startStepUp`, `resumeStepUp`, `AutoUnsealDisclaimerDialog`),
  acceptance `test/acceptance/auto_unseal_test.go`, prod-check item `PADDOCK_AUTO_UNSEAL`.
- **Transit-wrapped secrets from the portal** (plan M9 decisions 12–13): `bao.Client.Encrypt(ctx, key,
  plaintext)` / `Decrypt`, Transit key `notification-wrap`, api policy `transit/encrypt/<key>`, consumer policy
  `transit/decrypt/<key>`; `openbao-configure.sh` creates keys, policies and AppRoles idempotently.
- **Escrow bucket**: `PADDOCK_ESCROW_S3_*` (api: `rustfs_escrow_api_*` read; worker and revocation-issuer have
  their own credentials); objects `org/<org>/devices/<device>/luks-header/…` sealed to `escrow-wrap`.
  `objectstore.Store` has `List`, `ListPage`, `Open`, `Put`, `Size`, `SHA256`, `DeleteAllVersions`.
- **Portal**: platform navigation entries in `server/web/src/lib/navigation.ts`; `DataList`, `ConfirmDialog`
  (typed name for high-risk actions), `StatusChip`, i18n `en.json`/`de.json`; getting-started checklist in
  `Overview.vue` (plan M8g).
- **Migrations**: `server/migrations/paddock/00099_…` is the last; platform-scoped tables without an organization
  column are reachable through `paddock_platform` only (the pattern of `platform_role_member`, migration `00070`).
- **Retention**: `server/internal/app/retention.go` (store names, the worker round, `retention.purged`).
- **Alerts**: `deploy/compose/prometheus/alerts.yml` (`PaddockBackupStale`, `PaddockBackupAgeMissing`,
  `PaddockWALArchiveLag`, `PaddockWALArchiveLagMissing`), tests in `alerts_test.yml`.

## 3. Binding decisions

### 3.1 Vocabulary

1. **Backup set** = the directory tree of ADR 0046 decision 1 (§6.5). **Target** = one place that holds a backup
   set. **Kind** = one of `postgres`, `authentik`, `openbao`, `fleet`, `escrow` (`backup.Kinds` gains `escrow`).
   **Run** = one execution of one kind (a pgBackRest full backup, a snapshot, a dump, an escrow mirror pass) plus
   its mirror to every target. **Key** = the backup encryption key record; **active key** = the one `confirmed`
   key. **Restore plan** = an approved, host-executed restore.
2. Key states: `unconfirmed`, `confirmed`, `retired`, `discarded`. Target host states: `n/a` (S3), `pending_host`,
   `mounted`, `unreachable`. Run outcomes: `succeeded`, `failed`. Restore plan states: `approved`, `running`,
   `completed`, `failed`, `expired`.

### 3.2 Data model, roles and keys (PDK-729)

3. Migration `server/migrations/paddock/00100_backup.sql` MUST create the tables of §6.6: `backup_key`,
   `backup_target`, `backup_target_status`, `backup_schedule`, `backup_run`, `backup_restore_plan`. They are
   platform data without `organization_id`, without RLS, granted to `paddock_platform` (api, through
   `PlatformPool.InPlatform`) and to the new role `paddock_backup` as §6.6 states; the api's organization role gets
   nothing. The comment header states the retention class (`operational evidence`, §7).
4. Role `paddock_backup`: `deploy/compose/postgres/init/10-roles.sh`, `gen-dev-secrets.sh` and
   `gen-prod-secrets.sh` (control plane and lab) MUST create it with `db_paddock_backup_password` /
   `db_paddock_backup_url` exactly as `paddock_notifier` (plan M9 decision 11); `paddock-server migrate` MUST create
   a missing role from the secret file (the mechanism plan M16 PDK-745 generalizes; PDK-729 ships it for this role
   only, as `CREATE ROLE IF NOT EXISTS … LOGIN PASSWORD` inside the migration step).
   *Amendment 2026-11-04 (PDK-745):* the creation of a missing role does not run inside `paddock-server migrate`:
   `paddock_owner` stays `NOCREATEROLE` and the migration holds no superuser credential. The one-shot service
   `db-provision` (compose.yaml, postgres image already in the stack, superuser password mounted there only) runs
   `postgres/provision-roles.sh` before `paddock-migrate`; the same script is the initdb hook. It creates `paddock_backup`
   when absent and sets its password from the secret file on every run.
5. `openbao-configure.sh` MUST create the Transit key `backup-wrap` (`type=aes256-gcm96`, `exportable=false`,
   `allow_plaintext_backup=false`), add `transit/encrypt/backup-wrap` (`update`) to the policy `paddock-api`, and
   extend the policy `paddock-backup` (today: `read` on `sys/storage/raft/snapshot`) with `transit/decrypt/backup-wrap`
   (`update`). The AppRole `paddock-backup` stays; its secret files move from the worker to the backup role
   (decision 15). `docs/operations/openbao.md` section 1 lists key and policies.
6. Package `server/internal/domain/backupset` (new, no I/O): `Manifest` (§6.5) with `Marshal`/`Parse`/`Validate`,
   `KeyID(now time.Time, rnd []byte) string` (`bk-<YYYYMMDD>-<8 hex>`), `Challenge(keyText string, rnd io.Reader)
   (positions [6]int, answer string)` (six distinct 1-based positions in `[1, len(keyText)]`, sorted; the answer is
   the characters at them in order), `ChallengeHash(keyID, answer string) [32]byte`
   (`sha256(keyID + ":" + answer)`), `Fingerprint(key []byte) string` (first 16 hex of SHA-256), target validation
   `ValidateTarget(t Target) error` (§6.1 rules), schedule validation `ValidateSchedule(s Schedule) error`, the set
   layout functions `RepoPath(keyID) = "pgbackrest/" + keyID`, `OpenBaoKey(t) = "openbao/" + t.UTC().Format("20060102T150405Z") + ".snap.enc"`,
   `FleetKey(t)`, `EscrowKey(objectKey) = "escrow/" + objectKey`.

### 3.3 Key use cases and API (PDK-730)

7. `app.BackupKeys` (`server/internal/app/backupkeys.go`), platform scope, every write through
   `runner.RunTx(ctx, ScopePlatform, spec, …)` with `RequiresStepUp: true` and `RolesPlatform`:
   - `Generate(ctx) (GeneratedKey{KeyID, Text, Fingerprint, Positions [6]int, DownloadName}, error)`: refuses with
     409 `invalid_state` (detail `confirm or discard key <id> first`) while an `unconfirmed` key exists; else 32
     random bytes → `Text` = standard base64 (44 characters, the format `backup.ParseKey` reads), `ciphertext =
     bao.Encrypt("backup-wrap", key bytes)`, the challenge of decision 6, `INSERT backup_key (…, state
     unconfirmed, challenge_positions, challenge_sha256, attempts 0)`; audit `platform.backup_key_generated`
     (params `key_id`, `fingerprint`, `rotation: bool` (an active key existed)). The plaintext is in the response
     only; `GeneratedKey.Text` is never logged; the handler sets `Cache-Control: no-store`.
   - `Confirm(ctx, keyID, answer string) (Key, error)`: the key must be `unconfirmed` (409 `invalid_state`); compare
     `ChallengeHash(keyID, answer)` with `challenge_sha256` in constant time; on mismatch `attempts++`, audit
     outcome failure with `attempts`; at the third mismatch state `discarded`, detail `key discarded after three
     failed confirmations; generate a new key`; on match: state `confirmed`, `confirmed_at`, `confirmed_by`; an
     existing `confirmed` key becomes `retired` (`retired_at`) in the same transaction; audit
     `platform.backup_key_confirmed` (params `key_id`, `fingerprint`, `rotated_from` (nullable key id)).
   - `Discard(ctx, keyID)`: `unconfirmed` → `discarded`; audit `platform.backup_key_discarded`.
   - `Status(ctx) (KeyStatus{Active *Key, Pending *Key, Retired []Key}, error)` (read, no audit).
   Reads never return `ciphertext`, `challenge_positions` or `challenge_sha256`. `Key` is `{key_id, fingerprint,
   state, created_at, created_by, confirmed_at, confirmed_by, retired_at, attempts}`.
8. Endpoints (`api/openapi/admin.yaml`, platform, `x-paddock-audit` where audited): `GET
   /api/platform/v1/backup/key` → `BackupKeyStatus`; `POST /api/platform/v1/backup/key` → 201
   `BackupKeyGenerated` (`key_id`, `key` (the text), `fingerprint`, `positions`, `download_name`); `POST
   /api/platform/v1/backup/key/{id}/confirm` body `{answer}` → 200 `BackupKey`, 400 `invalid_request` when the
   answer's length differs from six, 409 for a wrong answer (`problem.BackupKeyMismatch = {Code:
   "backup_key_mismatch", Status: 409}` with `attempts_left` in the detail), 409 `invalid_state` after the discard;
   `POST /api/platform/v1/backup/key/{id}/discard` → 200. Every POST carries `Csrf`.
9. **Legacy import.** The **api** (the only role with `transit/encrypt/backup-wrap`) MUST, at start, when
   `PADDOCK_BACKUP_LEGACY_KEY_FILE` is set and `backup_key` has no row, insert key `legacy` with the file's
   content Transit-encrypted, state `unconfirmed`, the challenge computed from the file text, and record
   `platform.backup_key_generated` with `legacy: true` (actor system `paddock-api`). The file is mounted into the
   api for this one purpose on existing installations; `prod-check` warns when the variable is set while a
   confirmed key exists. The portal's backup page shows the key as *imported from the host file — confirm that
   you hold a copy*. Until confirmation no backup runs (decision 16).

### 3.4 Targets and schedule (PDK-731)

10. `app.BackupTargets` (`server/internal/app/backuptargets.go`): `List(ctx, page)`, `Get(ctx, id)`, `Create(ctx,
    in TargetInput)`, `Update(ctx, id, in)`, `Delete(ctx, id)`, `Test(ctx, id)`, `Enable/Disable(ctx, id)`;
    writes `RolesPlatform` + `RequiresStepUp`; audit codes §6.4. `TargetInput{Name, Type, Enabled, Local{Path},
    SMB{Host, Share, Path, Username, Password, Domain, Options}, NFS{Host, Export, Path, Options}, S3{Endpoint,
    Bucket, Region, Prefix, AccessKey, SecretKey, CAPEM}}`; validation by `backupset.ValidateTarget` (§6.1).
    Secrets (`SMB.Password`, `S3.SecretKey`, `S3.AccessKey`) are Transit-encrypted into `credentials_ciphertext`
    (JSON `{username, password}` or `{access_key, secret_key}`) and never returned; `Update` without a password
    keeps the stored one. A local, SMB or NFS target is created with `host_state = pending_host` and
    `host_revision = 1`; every update of mount-relevant fields increments `host_revision` and resets the state to
    `pending_host`; `Delete` of such a target sets `deleted_at` (the row stays until the host removed the volume:
    `./paddock backup-target apply` deletes rows with `deleted_at` after unmounting). An S3 target has
    `host_state = n/a`.
11. `Test(ctx, id)`: the api MUST NOT decrypt credentials, so a test is asynchronous: the api sets
    `backup_target.test_requested_at = now()` and records `platform.backup_target_tested` (outcome `success` means
    *requested*); the backup role performs the test in its next round (S3: `HeadBucket`, then a 1-byte `PutObject`
    and its delete under `<prefix>/.paddock-test`; mounted: create and delete `<path>/.paddock-test`), writes
    `last_test_at`, `last_test_ok`, `last_test_error` (error class only: `dns`, `dial`, `tls`, `auth`,
    `forbidden`, `not_mounted`, `read_only`, `io`) and clears `test_requested_at`; the role records no audit event
    for it (the result is state, not a privileged action); the api's `GET` shows the three columns and the portal
    polls for up to 60 s.
12. Schedule: `GET /api/platform/v1/backup/schedule` → `BackupSchedule`; `PUT` (platform, step-up, audit
    `platform.backup_schedule_changed` with every field) body `BackupScheduleUpdate{full_interval_hours (6–168,
    default 24), openbao_interval_hours (1–24, default 6), fleet_interval_hours (6–168, default 24),
    escrow_interval_hours (1–24, default 1), retention_full (2–60, default 14), openbao_keep_days (7–365, default
    30), fleet_keep_days (7–365, default 30)}`. Without a row the defaults apply.
13. Endpoints: `GET /api/platform/v1/backup/targets` (list contract: sort `[name, type, created_at]` default
    `name`; search `[name]`; filters `type`, `enabled`, `host_state`), `POST` → 201, `GET/PUT/DELETE
    /api/platform/v1/backup/targets/{id}`, `POST …/{id}/test`, `POST …/{id}/enable`, `POST …/{id}/disable`;
    `BackupTarget` = `{id, name, type, enabled, host_state, host_revision, settings (type-specific, without
    secrets), has_credentials, last_test_at, last_test_ok, last_test_error, status: [BackupTargetKindStatus{kind,
    last_success_at, last_error, bytes}], created_by, created_at, updated_at}`. `GET /api/platform/v1/backup`
    → `BackupOverview{key: BackupKeyStatus, schedule, targets: [BackupTarget], repo: {path, bytes_used,
    bytes_free, stanzas: [{name, last_full_at, wal_archived_at}]}, last_runs: [BackupRun] (newest per kind)}`.
    `GET /api/platform/v1/backup/runs` (list: sort `[started_at, kind, outcome]` default `-started_at`; filters
    `kind`, `outcome`, `target_id`).
14. `POST /api/platform/v1/backup/run` body `{kinds: [..] | null (all), label (0–64 chars)}` (platform, step-up,
    audit `platform.backup_run_requested` with `kinds`, `label`): inserts `backup_run` rows with `state requested`
    that the role picks up within one round (decision 16). `paddock-server backup now [--kind k]... [--label l]
    [--wait]` (host emergency path, runs in a one-off backup container with the system actor) does the same.

### 3.5 The backup role (PDK-732)

15. `paddock-server serve backup` (`server/cmd/paddock-server/backup.go`, replacing `loadBackup` in the worker;
    `server/internal/backuprole` new package) MUST load: `PADDOCK_DB_BACKUP_URL_FILE` (role `paddock_backup`),
    `PADDOCK_DB_PLATFORM_URL_FILE`, `PADDOCK_OPENBAO_ADDR`, `PADDOCK_OPENBAO_ROLE_ID_FILE`,
    `PADDOCK_OPENBAO_SECRET_ID_FILE` (AppRole `paddock-backup`), `PADDOCK_ESCROW_S3_*` with the new read-only
    credential `rustfs_escrow_backup_{access,secret}_key` (`rustfs-bundles-bootstrap.sh`'s escrow policy gains a
    read-only user), `PADDOCK_BACKUP_REPO_DIR` (default `/backup-repo`), `PADDOCK_BACKUP_RUNTIME_DIR` (default
    `/run/paddock-backup`, the tmpfs volume shared with the pgBackRest containers), `PADDOCK_BACKUP_TARGETS_DIR`
    (default `/backup-targets`), `PADDOCK_BACKUP_ROUND_INTERVAL` (default `1m`), `PADDOCK_FLEET_DUMPS_DIR`
    (default `/fleet-dumps`), `PADDOCK_OPS_ADDR`. Readiness: both pools, OpenBao `Ping`, the repo dir writable. The
    service runs as `user: "999:999"` (pgBackRest's uid; the shared files are 0640 root-less), `read_only`,
    `cap_drop: ALL`, `no-new-privileges`, `pids_limit 128`, networks `cp`, `escrow`.
16. **Round** (`backuprole.Engine.Round`, leader lock `0x7061646420626b70` reused): (a) key: load the active key
    (`confirmed`), decrypt it, write `<runtime>/key` (0640) and `<runtime>/schedule.env`
    (`PADDOCK_BACKUP_RETENTION_FULL`, `PADDOCK_BACKUP_FULL_INTERVAL_S`, `PADDOCK_BACKUP_REPO_PATH=pgbackrest/<key_id>`);
    without an active key: delete `<runtime>/key`, set the gauge `paddock_backup_key_confirmed 0`, record nothing,
    return (no backup of any kind runs; pgBackRest's `serve` waits for the key file). (b) due runs: for every kind
    whose newest `succeeded` run is older than its interval, or with a `requested` row: `openbao` → `RaftSnapshot`
    → `backup.Seal` → `<repo>/openbao/<ts>.snap.enc`; `fleet` → the newest `*.sql.gz` in `PADDOCK_FLEET_DUMPS_DIR`
    not yet sealed → `backup.Seal` → `<repo>/fleet/<ts>.sql.gz.enc` and delete the plaintext dump (the
    `fleet-backup` container stops encrypting: `backup.sh` writes `<ts>.sql.gz` only); `escrow` → list the escrow
    bucket, copy every object whose key or size differs from `<repo>/escrow/<key>` (objects are immutable: compare
    by name and size); `postgres`/`authentik` → nothing to execute (pgBackRest's `serve` takes the full backup;
    the role records the run when `<state>/last-full` of the stanza's state volume advanced — mounted read-only at
    `/pgbackrest-state/<stanza>`); (c) expire: delete `openbao/` and `fleet/` files older than their keep days and
    `pgbackrest/<retired key_id>/` paths whose newest backup is older than `retention_full × full_interval`;
    (d) manifest: write `<repo>/manifest.json` (§6.5) after every change; (e) mirror: for every enabled target
    whose host state is `mounted` or `n/a`: copy every file of the set that the target lacks or whose size differs,
    delete files the set no longer has, verify by size (and by SHA-256 for `manifest.json`); S3 through
    `objectstore` with the target's credentials (prefix `<prefix>/paddock-backup/`), mounted targets through the
    filesystem (`<targets>/<id>/paddock-backup/`); per target and kind write `backup_target_status` and the gauge;
    (f) tests requested (decision 11); (g) host state: a local/SMB/NFS target is `mounted` when
    `<targets>/<id>/.paddock-mount` exists (written by `./paddock backup-target apply` into the volume at mount
    time with the `host_revision`), `pending_host` when the directory is absent or carries an older revision,
    `unreachable` when the directory exists but a write fails. Every run (kind × attempt) is one `backup_run` row
    and one audit event `platform.backup_completed` or `platform.backup_failed` (actor system `paddock-backup`,
    params `run_id`, `kind`, `label`, `bytes`, `duration_s`, `targets_ok`, `targets_failed`, `error_class`).
17. pgBackRest: `deploy/compose/pgbackrest/run.sh` MUST read `PGBACKREST_REPO1_CIPHER_PASS` from
    `<runtime>/key` (wait in `serve`, fail in `backup|restore` when absent) and `PGBACKREST_REPO1_PATH` and
    `PGBACKREST_REPO1_RETENTION_FULL` from `<runtime>/schedule.env`; `repo1-type=posix`, `repo1-path=/backup-repo/pgbackrest/<key_id>`.
    The S3 options and `PADDOCK_BACKUP_S3_*` are removed. `serve` takes the full backup when `last-full` is older
    than `PADDOCK_BACKUP_FULL_INTERVAL_S`. A key rotation (a new `key_id` in `schedule.env`) is detected by `serve`
    at the next round: `stanza-create` in the new path and a full backup at once; the previous path is left for
    the role's expire. `restore` gains `--at <timestamp>` (`--type=time --target=<ts> --target-action=promote`)
    and `--repo-path <path>` (restores from a named set path, used by `./paddock restore`).
18. Compose (`compose.backup.yaml`): service `paddock-backup` (decision 15; volumes `backup-repo`,
    `backup-runtime` (tmpfs: `driver_opts: {type: tmpfs, device: tmpfs, o: "size=1m,uid=999,gid=999,mode=0750"}`),
    `fleet-dumps`, `pgbackrest-state-paddock:ro`, `pgbackrest-state-authentik:ro`; `depends_on: postgres,
    openbao healthy`), `pgbackrest*` gain `backup-repo` and `backup-runtime:ro`, `fleet-backup-upload` and the
    `backup_*_access_key` secrets and `x-backup-s3` are removed, the worker loses its backup environment and
    secrets, `compose.backup.dev.yaml` loses `backup-s3-tls` and keeps a development S3 target created by
    `make dev-seed` on the audit host's RustFS (`rustfs-backup-bootstrap.sh` stays for the bucket) and a local
    target on the volume `backup-local-dev`. `compose.backup-targets.yaml` (host-local, rendered, never shipped;
    `.gitignore` and `deploy/bundle/build.sh` exclude it) is appended to the file set by `compose_files` when it
    exists on a control-plane or lab host. `prod-check`: the `paddock-backup` service exists on a host with backups,
    holds the five secrets of decision 15 and no `PADDOCK_BACKUP_S3_*`; `backup-repo` is a named volume;
    `PADDOCK_BACKUP_LEGACY_KEY_FILE` only on the api.
19. Metrics (`backuprole/metrics.go`): `paddock_backup_last_success_timestamp_seconds{kind,target}` (target
    `repo` for the local repository), `paddock_backup_target_reachable{target}` (0/1),
    `paddock_backup_key_confirmed` (0/1), `paddock_backup_runs_total{kind,outcome}`,
    `paddock_backup_repo_bytes{what="used|free"}`, the WAL gauges move here unchanged
    (`paddock_backup_wal_last_archived_timestamp_seconds{stanza}` from the repo's `archive/` directory). Alerts:
    `PaddockBackupStale` (per kind and target, 26 h; `escrow` 3 h), `PaddockBackupAgeMissing` (no series for a
    configured target), `PaddockBackupKeyUnconfirmed` (`== 0 for 1h`, severity warning),
    `PaddockBackupTargetUnreachable` (`== 0 for 30m`), `PaddockBackupRepoFull` (free < 10 %); cases in
    `alerts_test.yml`.

### 3.6 Host commands (PDK-733)

20. `./paddock backup-target apply` (control plane, lab; root): runs `paddock-server admin backup-targets render`
    in a one-off backup container (which prints the target list as JSON with the decrypted SMB credentials on
    **stdout to the host process only**, never to a log — the host script reads the pipe), writes
    `.secrets/backup-targets/<id>.cifs` (`username=…\npassword=…\ndomain=…`, 0600) for SMB targets, renders
    `compose.backup-targets.yaml` (§6.7) with one named volume per local/SMB/NFS target and the `volumes:` entries
    of `paddock-backup`, writes `.paddock-mount` with the `host_revision` into each volume through a one-off
    `alpine`-free step (a `docker compose run --rm paddock-backup backup mark-mount <id> <rev>` writes the marker
    inside the volume), removes volumes of targets with `deleted_at` and tells the operator to run `./paddock up`
    (which recreates `paddock-backup`). Idempotent; prints the rendered file's path and the targets' names only.
    The command refuses to run while `paddock-backup` holds a running restore plan.
21. `./paddock backup now [--kind k]… [--label l] [--wait]` → `paddock-server backup now` in a one-off container;
    `./paddock backup status` → `paddock-server backup status` (the overview of decision 13 as a table); both
    control plane and lab.
22. `./paddock check` items (prodcheck): `backup: paddock-backup service present with its secrets`, `backup: no
    S3 credentials or encryption key on the worker`, `backup: repo volume named`, `backup: targets file matches
    the database revision` (online, control plane: compares `compose.backup-targets.yaml`'s revisions with the
    database through the one-off render; WARN not FAIL).

### 3.7 Restore (PDK-734, PDK-735)

23. `deploy/compose/scripts/restore.sh` (new; sourced by `./paddock restore`; replaces the runbook steps 2–7 and
    is reused by `restore-drill.sh`) MUST implement `restore_run <mode> <source> [--at <ts>] [--only
    <component>]…` with components `postgres` (both stanzas), `openbao`, `fleet`, `escrow`, in this order:
    1. preflight: the source set's `manifest.json` parses, its `schema_versions` are ≤ the bundle's (`paddock-server
       migrate --version` prints the highest embedded migration numbers), its `key_id` is the key the operator
       entered (fingerprint compare; the key is read from `.secrets/backup_encryption_key` which `./paddock
       restore` writes from the interactive prompt with mode 0600 and deletes at the end unless `--keep-key-file`),
       the required custodian or auto-unseal path is stated;
    2. stop the writers (`compose --profile paddock stop`, `stop authentik-server authentik-worker pgbackrest
       pgbackrest-authentik paddock-backup`);
    3. `postgres`: empty `postgres-data` / `authentik-postgres-data`, copy `pgbackrest/<key_id>/` of the source
       into `backup-repo` when the source is not the repo itself, `pgbackrest restore [--at]` per stanza, start
       both databases, wait for `pg_is_in_recovery() = f`;
    4. `openbao`: the newest `openbao/*.snap.enc` at or before `--at` through `backup decrypt` into a fresh OpenBao
       (`openbao-restore.sh`), restart, then unseal: auto-unseal when `PADDOCK_AUTO_UNSEAL=yes` and the shares file
       exists, else the custodians' prompt (the script waits up to 15 min, as `./paddock up` does);
    5. `paddock`: start the roles except the compiler, `admin bump-bundle-seq --by 1000000`, start the compiler,
       `admin rebuild-cache`, `admin recompile --all`;
    6. `fleet`: the newest `fleet/*.sql.gz.enc` at or before `--at` → `backup decrypt` → `gunzip | mysql` into an
       empty `fleet-mysql`;
    7. `escrow`: `PutObject` of every `escrow/<key>` into the escrow bucket (through a one-off `paddock-backup
       backup restore-escrow <dir>`), skipping objects that exist with the same size;
    8. report: `paddock-server backup restore-report --plan <id> --outcome completed|failed --detail …` records
       `platform.restore_completed` / `platform.restore_failed` (actor `operator` from `$SUDO_USER`/`$USER` as
       `display`) and updates the plan row; without a plan (fresh installation) the report records the event with
       `plan_id` empty and `source` = `set` and inserts a `backup_restore_plan` row of kind `fresh_install` with
       state `completed`, so the portal shows what happened.
    Every step prints what it does; the script is `set -euo pipefail` and stops at the first error with the
    component named.
24. `./paddock restore` (control plane, lab) forms: `--plan <id>` (executes an `approved` plan: reads it with
    `paddock-server backup plan <id>` as JSON, refuses `expired` (24 h after approval), `running` or `completed`;
    sets `running`; runs decision 23 with the plan's source, point and components); `--from <path|target name>
    [--at <ts>] [--only …]` (fresh installation: `<path>` is a backup set directory or a `paddock-backup-set-*.tar`
    which the command extracts to `./restore-staging/`; a target name needs a running database and is only valid
    with `--plan`); `--from-target-file <file>` (fresh installation from a connected S3 target without a database:
    the file is the JSON of one target as `./paddock backup-target export <id>` wrote it before the loss, with the
    credentials — the operator keeps it with the key; local/SMB/NFS: mount on the host and use `--from <path>`).
    The command prints the plan summary and asks for the typed word `restore` on the terminal before step 2 of
    decision 23 (also with `--plan`: the portal's confirmation approved the plan; the terminal confirmation
    protects against the wrong host).
25. `app.BackupRestorePlans` (`server/internal/app/backuprestore.go`): `Create(ctx, in PlanInput{Kind
    (point_in_time | components), SourceTargetID (nullable: the local repo), At (nullable), Components [],
    Confirmation string})` (platform, step-up, audit `platform.restore_planned` with `plan_id`, `kind`, `source`,
    `at`, `components`): `Confirmation` MUST equal `restore` (400 `invalid_request` otherwise; the typed check is
    server-side as ADR 0018 requires); refuses 409 `invalid_state` while a plan is `approved` or `running`; checks
    that the source target's status has every chosen component with a success at or before `at` (409
    `invalid_state` with the missing kind); inserts with `expires_at = now + 24 h`. `Get`, `List` (list contract:
    sort `[created_at, state]`, filters `state`), `Cancel(ctx, id)` (`approved` → `expired`, audit
    `platform.restore_cancelled`). The host updates `running`/`completed`/`failed` through decision 23 step 8 with
    the `paddock_backup` role (`UPDATE` grant).
26. Endpoints: `GET/POST /api/platform/v1/backup/restore-plans`, `GET /…/{id}`, `POST /…/{id}/cancel`;
    `BackupRestorePlan` = `{id, kind, source_target_id, source_target_name, at, components, state, created_by,
    created_at, expires_at, started_at, finished_at, outcome_detail, host_command}` where `host_command` is the
    literal `./paddock restore --plan <id>` the portal shows.

### 3.8 Portal (PDK-736)

27. Platform navigation entry **Backup** (`views/PlatformBackup.vue`, route `/platform/backup`, name
    `platform-backup`) with the tabs **Overview** (key state banner; per target × kind the last success as a
    `StatusChip` grid; repository usage; the last runs; buttons *Back up now* (ConfirmDialog, step-up) and *Plan a
    restore*), **Targets** (`DataList` over decision 13 with the host state chip and the actions test, enable,
    disable, edit, delete (ConfirmDialog with the typed target name); the create/edit dialog `BackupTargetForm.vue`
    is one form with a type selector and the type's fields; secrets fields are write-only with the hint *stored
    encrypted, never shown again*; after saving a local/SMB/NFS target an inline alert states the host step
    `./paddock backup-target apply` and then `./paddock up`), **Key** (`BackupKeyDialog.vue`: step 1 explains
    (text from §6.8), step 2 shows the key text once with *Copy* and *Download* (`paddock-backup-key-<id>.txt`,
    content: the key text, the fingerprint and the sentence of §6.8), step 3 asks for the six characters at the
    named positions (six single-character inputs, positions shown above each) and calls `confirm`; a mismatch shows
    the attempts left; the dialog cannot be closed between step 2 and 3 without the explicit *I did not store the
    key — discard it* action (calls `discard`); the page shows the active key's fingerprint and dates, a retired
    list and *Rotate key* (starts the same dialog)), **Schedule** (form of decision 12), **History** (`DataList`
    over runs), **Restore** (`DataList` of plans; *Plan a restore* dialog: kind, source target, point in time
    (date-time picker; the newest success per kind of the chosen target is shown as the bound), components
    checkboxes, the typed word `restore`, step-up; a created plan shows the `host_command` with *Copy* and the
    expiry countdown; *Cancel*).
28. The getting-started checklist (`Overview.vue`, plan M8g) gains the item *Backups: key confirmed and one
    target enabled* linking to `/platform/backup`.
29. e2e `server/web/e2e/backup.spec.ts`: targets list, key dialog with a wrong and a right confirmation (the test
    reads the positions from the API response and types the characters), restore plan dialog requires the typed
    word, no `window.confirm`, accessibility checks.

### 3.9 Gates, documents, residual risks (PDK-737, PDK-738, PDK-739)

30. Acceptance (`test/acceptance/backup_test.go`, development stack with `BACKUP=1`), system
    (`test/system/backup_test.go`), e2e and documents as §9 and §7 state. The restore drill `make restore-drill`
    MUST become `restore-drill.sh` = "backup now, destroy, `restore_run plan …` from the local development target,
    acceptance subset" using `restore.sh`, and record its RTO line in `docs/operations/restore.md` again.

## 4. Non-goals

- No per-organization restore (ADR 0046 options; stated in `restore.md` with the reason).
- No restore of the audit store or the audit index (ADR 0016); the index is rebuilt by the audit writer's
  existing resync when the control plane returns (plan M8b), not by M15.
- No portal upload of a backup set (there is no portal before identity exists; the host receives the set by
  `scp` or a mounted share).
- No userspace SMB or NFS client; no new container image; no Docker socket in any container.
- No change to `agent/`, `pkg/`, the revocation path, the audit writer, or the escrow-reader.
- No client certificates for S3 targets; no object lock on targets (pgBackRest and the mirror must delete).
- No change to the retention of the escrow bucket itself.

## 5. Affected files

| Path | Action | Purpose |
| --- | --- | --- |
| `server/migrations/paddock/00100_backup.sql` | new | tables of §6.6, grants, role creation (PDK-729) |
| `server/internal/domain/backupset/*.go` | new | manifest, challenge, validation, layout (PDK-729) |
| `server/internal/app/backupkeys.go`, `backuptargets.go`, `backupschedule.go`, `backuprestore.go`, `backupruns.go` (+ `_integration_test.go`) | new | use cases (PDK-730, 731, 735) |
| `server/internal/adapters/postgres/queries/backup.sql` | new | sqlc queries |
| `server/internal/backuprole/{engine,mirror,targets,keyfile,metrics,legacy}.go` | new | the role (PDK-732) |
| `server/internal/backup/backup.go` | change | `KindEscrow`, set paths (PDK-732) |
| `server/internal/worker/backup.go`, `worker.go`, `server/cmd/paddock-server/worker.go` | change | remove the worker's backup job (PDK-732) |
| `server/cmd/paddock-server/backup.go`, `main.go`, `admin.go` | change | `serve backup`, `backup now|status|restore-report|plan|mark-mount|restore-escrow`, `admin backup-targets render`, `migrate --version` (PDK-732, 733, 734) |
| `server/internal/prodcheck/prodcheck.go` | change | items of decision 22 |
| `server/internal/domain/audit/codes.go`, `server/internal/problem/problem.go` | change | codes of §6.4, `backup_key_mismatch` |
| `api/openapi/admin.yaml` | change | endpoints of §6.1 |
| `server/internal/transport/http/admin/handlers_backup.go`, `server.go` | new / change | handlers, privileged routes |
| `deploy/compose/compose.backup.yaml`, `compose.backup.dev.yaml`, `compose.prod.yaml`, `compose.lab.yaml` | change | decision 18 |
| `deploy/compose/pgbackrest/run.sh`, `pgbackrest_test.sh` | change | decision 17 |
| `deploy/compose/fleet/backup.sh`; `deploy/compose/fleet/backup-upload.sh` | change; delete | plaintext dump; sidecar removed |
| `deploy/compose/scripts/{gen-dev-secrets,gen-prod-secrets,openbao-configure,rustfs-bundles-bootstrap,lib,restore-drill}.sh`, `restore.sh` (new), `restore_test.sh` (new) | change / new | role, key, escrow reader credential, file set, restore |
| `deploy/compose/postgres/init/10-roles.sh` | change | `paddock_backup` |
| `deploy/compose/prometheus/alerts.yml`, `alerts_test.yml` | change | decision 19 |
| `deploy/bundle/paddock`, `deploy/bundle/README.md`, `deploy/bundle/build.sh`, `.gitignore` | change | commands of §3.6–3.7; exclude the rendered file |
| `server/web/src/views/PlatformBackup.vue`, `components/BackupTargetForm.vue`, `BackupKeyDialog.vue`, `BackupRestorePlanDialog.vue`, `lib/backup.ts`, `lib/navigation.ts`, `router.ts`, `views/Overview.vue`, `locales/{en,de}.json`, `e2e/backup.spec.ts` | new / change | portal (PDK-736) |
| `test/acceptance/backup_test.go`, `backup_helpers.go`; `test/system/backup_test.go`, `share.go` | new | gates (PDK-737, 738) |
| `docs/operations/backup.md` (new), `restore.md`, `install.md`, `lab-install.md`, `monitoring.md`, `openbao.md`, `upgrade.md`; `docs/architecture.md`; `docs/compliance/residual-risks.md`; `docs/adr/0032-retention-and-deletion.md` (amendment rows); `changelog.d/PDK-7xx.*.md` | change / new | documents (PDK-739) |

Not to be touched: `agent/`, `pkg/`, `server/internal/revocationissuer/`, `server/internal/escrowreader/`,
`server/internal/auditwriter/`, `server/migrations/audit/`, existing migrations, every ADR but 0046 and the 0032
amendment, `docs/reqirements/`.

## 6. Interfaces and data model

### 6.1 Target validation (`backupset.ValidateTarget`)

```
name: 1–64 characters, the API-token name pattern ^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$; unique
local: path a relative subpath of PADDOCK_BACKUP_LOCAL_ROOT (amendment 2026-11-05, decision 36): no leading "/",
       no "..", "." or empty element, ≤ 256 bytes; resolved and checked on the host by apply
smb:   host (DNS name or IP literal, ≤ 253), share (^[A-Za-z0-9_$. -]{1,80}$), path (relative, optional, no ".."),
       username (1–104), password (1–256, write-only), domain (optional ≤ 64), options (optional, ≤ 256, the
       allow list vers=3.0|3.1.1, seal, noperm, cache=none|strict, actimeo=N; anything else 400)
nfs:   host, export (absolute path ≤ 256), path (relative, optional), options (optional ≤ 256, allow list
       vers=4|4.1|4.2, hard, timeo=N, retrans=N, nconnect=N)
s3:    endpoint (https URL, no userinfo, no query; the deny list of ADR 0031 decision 12 applies to the host —
       except with PADDOCK_OUTBOUND_DEV_ALLOW_PRIVATE on the development stack), bucket (S3 bucket name rules),
       region (default us-east-1), prefix (optional, no leading "/", ≤ 128), access_key (1–128), secret_key
       (1–256, write-only), ca_pem (optional PEM, ≤ 16 KiB)
```

### 6.2 Admin API (additions to `api/openapi/admin.yaml`; every POST/PUT/DELETE has `x-paddock-audit`)

```
GET  /api/platform/v1/backup                              → 200 BackupOverview
GET  /api/platform/v1/backup/key                          → 200 BackupKeyStatus
POST /api/platform/v1/backup/key                          → 201 BackupKeyGenerated; 409                 audit platform.backup_key_generated   step-up
POST /api/platform/v1/backup/key/{id}/confirm   {answer}  → 200 BackupKey; 400, 409 backup_key_mismatch, 409 invalid_state   audit platform.backup_key_confirmed   step-up
POST /api/platform/v1/backup/key/{id}/discard             → 200 BackupKey; 409                          audit platform.backup_key_discarded   step-up
GET  /api/platform/v1/backup/schedule                     → 200 BackupSchedule
PUT  /api/platform/v1/backup/schedule                     → 200; 400                                    audit platform.backup_schedule_changed step-up
GET  /api/platform/v1/backup/targets                      list: sort [name,type,created_at] default name; search [name]; filters [type,enabled,host_state]
POST /api/platform/v1/backup/targets                      → 201 BackupTarget; 400, 409 (name)            audit platform.backup_target_created  step-up
GET  /api/platform/v1/backup/targets/{id}                 → 200; 404
PUT  /api/platform/v1/backup/targets/{id}                 → 200; 400, 404                               audit platform.backup_target_updated  step-up
DELETE /api/platform/v1/backup/targets/{id}               → 204; 404                                    audit platform.backup_target_deleted  step-up
POST /api/platform/v1/backup/targets/{id}/test            → 202; 404                                    audit platform.backup_target_tested   step-up
POST /api/platform/v1/backup/targets/{id}/enable|disable  → 200; 404, 409                               audit platform.backup_target_updated  step-up
POST /api/platform/v1/backup/run                {kinds,label} → 202 [BackupRun]; 409 (no active key)    audit platform.backup_run_requested   step-up
GET  /api/platform/v1/backup/runs                         list: sort [started_at,kind,outcome] default -started_at; filters [kind,outcome,target_id]
GET  /api/platform/v1/backup/restore-plans                list: sort [created_at,state] default -created_at; filters [state]
POST /api/platform/v1/backup/restore-plans      PlanInput → 201 BackupRestorePlan; 400, 409              audit platform.restore_planned        step-up
GET  /api/platform/v1/backup/restore-plans/{id}           → 200; 404
POST /api/platform/v1/backup/restore-plans/{id}/cancel    → 200; 404, 409                               audit platform.restore_cancelled      step-up
```

Schemas (required in brackets): `BackupKey: [key_id, fingerprint, state, created_at, created_by, confirmed_at,
confirmed_by, retired_at, attempts, legacy]`; `BackupKeyGenerated: [key_id, key, fingerprint, positions,
download_name]` (`positions`: 6 integers); `BackupKeyStatus: [active, pending, retired]`; `BackupTarget` and
`BackupTargetInput` (oneOf by `type` with the field groups of §6.1; secrets write-only: `writeOnly: true`);
`BackupSchedule`, `BackupScheduleUpdate` (`additionalProperties: false`); `BackupRun: [id, kind, label, state,
outcome, started_at, finished_at, bytes, error_class, targets: [{target_id, ok, error_class}]]`; `BackupRestorePlan`
(decision 26); `BackupRestorePlanInput: [kind, components, confirmation]` + `source_target_id`, `at`;
`BackupOverview` (decision 13).

### 6.3 Go signatures (binding names)

```go
// server/internal/domain/backupset
type Manifest struct { Schema string; InstallationID string; ServerVersion string; GeneratedAt time.Time; KeyID, KeyFingerprint string; SchemaVersions map[string]int; Contents Contents }
type Contents struct { PgBackRest PgBackRest; OpenBao []File; Fleet []File; Escrow []File }
type File struct { Path string; Bytes int64; SHA256 string; At time.Time }
func Challenge(keyText string, rnd io.Reader) ([6]int, string, error)
func ChallengeHash(keyID, answer string) [32]byte
func Fingerprint(key []byte) string
func ValidateTarget(t Target) error
func ValidateSchedule(s Schedule) error

// server/internal/app
func (k *BackupKeys) Generate(ctx context.Context) (GeneratedKey, error)
func (k *BackupKeys) Confirm(ctx context.Context, keyID, answer string) (Key, error)
func (k *BackupKeys) Discard(ctx context.Context, keyID string) (Key, error)
func (k *BackupKeys) Status(ctx context.Context) (KeyStatus, error)
func (t *BackupTargets) Create(ctx context.Context, in TargetInput) (Target, error)   // Update, Delete, Test, Enable, Disable, Get, List
func (p *BackupRestorePlans) Create(ctx context.Context, in PlanInput) (Plan, error)  // Get, List, Cancel
func (r *BackupRuns) Request(ctx context.Context, kinds []string, label string) ([]Run, error)

// server/internal/backuprole
type Engine struct{ … }
func NewEngine(cfg Config, platform *db.PlatformPool, pool *db.BackupPool, keys Decrypter, snap Snapshotter, escrow EscrowStore, targets TargetFactory, now func() time.Time) *Engine
func (e *Engine) Run(ctx context.Context) error
func (e *Engine) Round(ctx context.Context) error
type Target interface { List(ctx context.Context) (map[string]int64, error); Put(ctx context.Context, path string, r io.Reader, size int64) error; Delete(ctx context.Context, path string) error; Probe(ctx context.Context) error }
func NewS3Target(store *objectstore.Store, prefix string) Target
func NewDirTarget(root string) Target
```

### 6.4 Audit codes (closed registry; `Outcomes` `adminOutcomes` unless stated; platform pseudo-organization)

| Code | Actor | Target | Params |
| --- | --- | --- | --- |
| `platform.backup_key_generated` | platform admin / api (legacy import) | backup_key | `key_id`, `fingerprint`, `rotation`, `legacy` |
| `platform.backup_key_confirmed` | platform admin | backup_key | `key_id`, `fingerprint`, `rotated_from`, `attempts` |
| `platform.backup_key_discarded` | platform admin | backup_key | `key_id`, `attempts` |
| `platform.backup_schedule_changed` | platform admin | setting | every field of decision 12 |
| `platform.backup_target_created` / `_updated` / `_deleted` / `_tested` | platform admin | backup_target | `target_id`, `name`, `type`, `enabled`, `host_revision` (never a credential, never a path's credentials query) |
| `platform.backup_run_requested` | platform admin / operator (host) | backup | `kinds`, `label` |
| `platform.backup_completed` / `platform.backup_failed` | system `paddock-backup` | backup_run | `run_id`, `kind`, `label`, `bytes`, `duration_s`, `targets_ok`, `targets_failed`, `error_class` (outcomes success / failure) |
| `platform.restore_planned` / `platform.restore_cancelled` | platform admin | backup_restore_plan | `plan_id`, `kind`, `source`, `at`, `components` |
| `platform.restore_started` | operator (host) | backup_restore_plan | `plan_id`, `source`, `source_target_id`, `components` (once per attempt, refusals included; note 2026-11-05 on PDK-735) |
| `platform.restore_completed` / `platform.restore_failed` | operator (host) | backup_restore_plan | `plan_id`, `source`, `at`, `components`, `duration_s`, `detail` |

### 6.5 Backup set (`paddock.backup-set.v1`)

```
paddock-backup/
  manifest.json
  pgbackrest/<key_id>/archive/<stanza>/…   pgBackRest repository (repo1-path), aes-256-cbc with the key
  pgbackrest/<key_id>/backup/<stanza>/…
  openbao/<YYYYMMDDTHHMMSSZ>.snap.enc       backup.Seal (AES-256-GCM, magic PADDOCK-BACKUP-1)
  fleet/<YYYYMMDDTHHMMSSZ>.sql.gz.enc       backup.Seal
  escrow/org/<org>/devices/<device>/…       the escrow bucket's objects, unchanged
```

`manifest.json`: `{"schema":"paddock.backup-set.v1","installation_id":"<uuid of the platform row>",
"server_version":"0.1.0-alpha.9","generated_at":"…","key_id":"bk-20261104-7f3a9c1e","key_fingerprint":"<16 hex>",
"schema_versions":{"paddock":100,"audit":10},"contents":{"pgbackrest":{"path":"pgbackrest/bk-…","stanzas":
[{"name":"paddock","last_full":"<label>","last_full_at":"…","wal_max":"<segment>"},…]},"openbao":[{"path":"…",
"bytes":…,"sha256":"…","at":"…"}],"fleet":[…],"escrow":[{"path":"…","bytes":…}]}}`. A tarball form is
`paddock-backup-set-<generated_at>.tar` with the directory as its root.

### 6.6 Migration `00100_backup.sql` (forward-only; `-- +goose Up` only)

```sql
CREATE TABLE backup_key (
  key_id text PRIMARY KEY CHECK (key_id ~ '^(bk-[0-9]{8}-[0-9a-f]{8}|legacy)$'),
  state text NOT NULL CHECK (state IN ('unconfirmed','confirmed','retired','discarded')),
  ciphertext text NOT NULL,            -- transit backup-wrap of the 32-byte key
  fingerprint text NOT NULL,
  challenge_positions int[] NOT NULL CHECK (cardinality(challenge_positions) = 6),
  challenge_sha256 bytea NOT NULL,
  attempts int NOT NULL DEFAULT 0,
  legacy boolean NOT NULL DEFAULT false,
  created_by text NOT NULL, created_at timestamptz NOT NULL DEFAULT now(),
  confirmed_by text, confirmed_at timestamptz, retired_at timestamptz
);
CREATE UNIQUE INDEX backup_key_one_active_idx ON backup_key ((true)) WHERE state = 'confirmed';
CREATE UNIQUE INDEX backup_key_one_pending_idx ON backup_key ((true)) WHERE state = 'unconfirmed';
CREATE TABLE backup_target (
  id uuid PRIMARY KEY, name text NOT NULL UNIQUE,
  type text NOT NULL CHECK (type IN ('local','smb','nfs','s3')),
  enabled boolean NOT NULL DEFAULT true,
  settings jsonb NOT NULL,             -- type-specific, no secrets (§6.1)
  credentials_ciphertext text,         -- transit backup-wrap; smb and s3
  host_state text NOT NULL CHECK (host_state IN ('n/a','pending_host','mounted','unreachable')),
  host_revision int NOT NULL DEFAULT 1,
  test_requested_at timestamptz, last_test_at timestamptz, last_test_ok boolean, last_test_error text,
  created_by text NOT NULL, created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
  deleted_at timestamptz
);
CREATE TABLE backup_target_status (
  target_id uuid NOT NULL REFERENCES backup_target(id) ON DELETE CASCADE,
  kind text NOT NULL CHECK (kind IN ('postgres','authentik','openbao','fleet','escrow')),
  last_success_at timestamptz, last_error text, last_error_at timestamptz, bytes bigint NOT NULL DEFAULT 0,
  PRIMARY KEY (target_id, kind)
);
CREATE TABLE backup_schedule (
  singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
  full_interval_hours int NOT NULL DEFAULT 24 CHECK (full_interval_hours BETWEEN 6 AND 168),
  openbao_interval_hours int NOT NULL DEFAULT 6 CHECK (openbao_interval_hours BETWEEN 1 AND 24),
  fleet_interval_hours int NOT NULL DEFAULT 24 CHECK (fleet_interval_hours BETWEEN 6 AND 168),
  escrow_interval_hours int NOT NULL DEFAULT 1 CHECK (escrow_interval_hours BETWEEN 1 AND 24),
  retention_full int NOT NULL DEFAULT 14 CHECK (retention_full BETWEEN 2 AND 60),
  openbao_keep_days int NOT NULL DEFAULT 30 CHECK (openbao_keep_days BETWEEN 7 AND 365),
  fleet_keep_days int NOT NULL DEFAULT 30 CHECK (fleet_keep_days BETWEEN 7 AND 365),
  updated_by text, updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE backup_run (
  id uuid PRIMARY KEY, kind text NOT NULL, label text NOT NULL DEFAULT '' CHECK (char_length(label) <= 64),
  state text NOT NULL CHECK (state IN ('requested','running','finished')),
  outcome text CHECK (outcome IN ('succeeded','failed')),
  requested_by text, started_at timestamptz, finished_at timestamptz, bytes bigint NOT NULL DEFAULT 0,
  error_class text, targets jsonb NOT NULL DEFAULT '[]',
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX backup_run_kind_started_idx ON backup_run (kind, started_at DESC);
CREATE TABLE backup_restore_plan (
  id uuid PRIMARY KEY,
  kind text NOT NULL CHECK (kind IN ('point_in_time','components','fresh_install')),
  source_target_id uuid REFERENCES backup_target(id) ON DELETE SET NULL, source text NOT NULL,
  at timestamptz, components text[] NOT NULL,
  state text NOT NULL CHECK (state IN ('approved','running','completed','failed','expired')),
  created_by text NOT NULL, created_at timestamptz NOT NULL DEFAULT now(), expires_at timestamptz,
  started_at timestamptz, finished_at timestamptz, outcome_detail text
);
CREATE UNIQUE INDEX backup_restore_plan_one_open_idx ON backup_restore_plan ((true)) WHERE state IN ('approved','running');
GRANT SELECT, INSERT, UPDATE, DELETE ON backup_key, backup_target, backup_target_status, backup_schedule, backup_run, backup_restore_plan TO paddock_platform;
GRANT SELECT ON backup_key, backup_target, backup_schedule TO paddock_backup;
GRANT UPDATE (host_state, test_requested_at, last_test_at, last_test_ok, last_test_error) ON backup_target TO paddock_backup;
GRANT SELECT, INSERT, UPDATE, DELETE ON backup_target_status, backup_run TO paddock_backup;
GRANT SELECT, INSERT, UPDATE ON backup_restore_plan TO paddock_backup;
GRANT SELECT, INSERT ON action, outbox TO paddock_backup;   -- mirrors paddock_notifier's grants and policies
```

### 6.7 `compose.backup-targets.yaml` (rendered on the host; never shipped)

```yaml
# Rendered by ./paddock backup-target apply on 2026-11-04T10:00:00Z from the database; do not edit.
services:
  paddock-backup:
    volumes:
      - backup-target-3f9c…:/backup-targets/3f9c…
volumes:
  backup-target-3f9c…:
    driver: local
    driver_opts:
      type: cifs
      device: //nas.example.org/paddock
      o: "credentials=/opt/paddock/paddock-deploy-0.1.0-alpha.9/.secrets/backup-targets/3f9c….cifs,vers=3.1.1,uid=999,gid=999,file_mode=0640,dir_mode=0750,noperm"
  # nfs: type: nfs, device: ":/export/paddock", o: "addr=nas.example.org,vers=4.1,hard"
  # local: type: none, device: /srv/paddock-backup, o: bind
```

### 6.8 Portal texts (binding English; German complete, wording free)

- Key step 1: *Paddock protects every backup with one key. You will see it exactly once. Store it where a lost
  server cannot take it with it — a password manager, a printed copy in a safe — and keep it with the OpenBao
  unseal shares. Without the key no backup can ever be read.*
- Key download file sentence: *This is the only copy Paddock will ever show. Keep it outside the server.*
- Key step 3: *Type the characters at the positions shown. This proves the key reached your safe place. After
  three mistakes the key is discarded and a new one is generated.*
- Host step after saving a target: *Mounting a share needs the host: run `./paddock backup-target apply` and then
  `./paddock up` on the control plane. The target shows "mounted" when the backup service sees it.*
- Restore plan consequence: *Restoring replaces the control plane's databases with the backup. Every change after
  the chosen point is lost. Devices keep working and reconnect; the audit log on the audit host is not touched.*

### 6.9 Residual risks (`docs/compliance/residual-risks.md`, new section "Backup and recovery (M15)"; RR-100 to RR-104)

| ID | Risk | Mitigation | ISMS record |
| --- | --- | --- | --- |
| RR-100 | **The key confirmation proves six characters, not a safe place.** An administrator can read the key off the screen, type the characters and close the window. | The sentence of §6.8; the download; the audit event; the key is shown once. | Where the key is kept; who may be platform administrator. |
| RR-101 | **A target holds every secret of the fleet in encrypted form.** Whoever has the key and a target copy has the installation. | AES-256 everywhere; credentials of targets Transit-wrapped; the key never in Paddock's logs; separate credentials per target. | Access control of the share or bucket; key custody. |
| RR-102 | **The local repository is on the control-plane host.** A host loss between two mirrors loses up to one mirror interval; a full disk stops pgBackRest. | `PaddockBackupRepoFull`; mirrors after every run; `./paddock check` repo volume item. | Disk sizing (capacity.md). |
| RR-103 | **A restore plan is executed on the host without the portal's eyes.** The host command trusts the plan row; a root on the host can run `./paddock restore --from` without any plan. | Terminal confirmation; `platform.restore_*` events from the host with the operator's name; an unplanned restore records `fresh_install`. | Host access control. |
| RR-104 | **Point-in-time restore of PostgreSQL alone diverges from OpenBao and Fleet.** OpenBao snapshots are 6-hourly; a restore to 10:17 pairs the 10:00 database with the 06:00 snapshot; AppRole secret IDs issued between must be reissued. | The restore shows the chosen files per component; `restore.md` names the reissue step; the post-restore check (`./paddock check --online`). | None beyond reading the restore report. |

## 7. Architecture and rule amendments (binding text; PDK-739 writes them)

- `docs/architecture.md` §20: replace the table's "Method" column with the set layout and the role; add the
  paragraph *Backup sets, targets and the key (M15, ADR 0046)*; §4.1 role list gains `backup`; §16.1 the tables.
- `docs/adr/0032-retention-and-deletion.md` amendment 2026-11-04: rows `backup_run` (operational evidence, 400
  days, purged by the backup role, `retention.purged` store `backup_run`), `backup_restore_plan` (same),
  `backup_target_status` (state, no purge).
- `docs/operations/backup.md` (new): targets, the host step, the key, the schedule, the set format, the metrics
  and alerts, the emergency commands; `restore.md` rewritten around `./paddock restore` with the three scenarios,
  the fresh-installation checklist (bundle, `.env`, `.secrets`, the key, the custodians, the set), the partial
  restore, the per-organization non-goal, and the drill; `install.md` §11 and `lab-install.md` §7 point to them;
  `monitoring.md` alerts; `upgrade.md` "From 0.1.0-alpha.8: the backup moves …" (legacy key import, the removed
  secrets, `./paddock backup-target apply` for the lab's S3 bucket as an S3 target).
- `CLAUDE.md` is not changed (no new protected area on the device).

## 8. Steps (tickets, in order)

1. **PDK-729 — Backup data model, role, Transit key, domain package.** Decisions 3–6; §6.6; `openbao-configure.sh`,
   secrets scripts, `10-roles.sh`. Verify: `make gen` no diff; `GOTOOLCHAIN=auto go test -count=1
   ./server/internal/domain/backupset/ ./server/internal/app/`; the migration applies on the alpha.8 schema.
2. **PDK-730 — Key: generate, confirm, discard, legacy import, API, audit.** Decisions 7–9; §6.2 (key). Depends on
   PDK-729. Verify: integration tests for the challenge flow (three mismatches discard), the one-active index, the
   step-up refusal for API tokens; `TestOpenAPISpec`.
3. **PDK-731 — Targets, schedule, runs: use cases and API.** Decisions 10–14; §6.1, §6.2. Depends on PDK-729.
   Verify: list contract test; secrets never in responses (test asserts `credentials_ciphertext` and the password
   are absent from every JSON); audit params free of credentials.
4. **PDK-732 — The backup role, pgBackRest local repository, mirrors, metrics, Compose.** Decisions 15–19; §6.3
   (`backuprole`), §6.5. Depends on PDK-730 and PDK-731. Verify: unit tests with a fake target (mirror adds,
   replaces by size, deletes, keeps `manifest.json` last); `pgbackrest_test.sh` adapted to the posix repo and the
   key file; `make up BACKUP=1` on the development stack shows the role healthy and a full backup within the
   first interval after the key is confirmed.
5. **PDK-733 — Host commands: `backup-target apply`, `backup now|status`, prod-check items.** Decisions 20–22; §6.7.
   Depends on PDK-732. Verify: `deploy/bundle/bundle_test.sh` renders a targets file from a fixture; prod-check
   tests.
6. **PDK-734 — `restore.sh` and `./paddock restore` (fresh installation, plan execution, partial).** Decisions
   23–24. Depends on PDK-732. Verify: `restore_test.sh` (the staging, the `--at` selection of snapshot and dump
   files, the refusal of a wrong key fingerprint) with fixtures; the drill of step 9.
7. **PDK-735 — Restore plans: use case, API, host report.** Decisions 25–26. Depends on PDK-731; MAY run in
   parallel with PDK-734. Verify: integration tests (typed word, one open plan, expiry, state transitions by the
   backup role's grant).
8. **PDK-736 — Portal.** Decisions 27–29; §6.8. Depends on PDK-730, 731, 735 (API). Verify: `make web`,
   frontend-verify, `make e2e T=backup`.
9. **PDK-737 — Acceptance gates and the restore drill.** §9 B1–B8; decision 30. Depends on PDK-734–736. Verify:
   `make acceptance T='TestBackup'`; `make restore-drill` green with the RTO line.
10. **PDK-738 — System gates: SMB and NFS targets, fresh-install restore by upload and by connected storage.**
    §9 BS1–BS3. Depends on PDK-737. Verify: `make system-test VM=all T='TestBackupGates'`.
11. **PDK-739 — Documents, residual risks, architecture amendments, changelog.** §6.9, §7. Depends on PDK-738.

PDK-730 and PDK-731 MAY run in parallel after PDK-729; PDK-734 and PDK-735 MAY run in parallel after PDK-732;
PDK-736 MAY start its targets and key tabs after PDK-731.

## 9. Tests and gates

- **Unit (Go):** `backupset` (challenge positions distinct and in range, hash stability, manifest round trip,
  validation table per type including the option allow lists and the deny-listed S3 hosts); `backuprole` mirror
  with a fake target (add, size change, delete, manifest last, a failing target does not stop the others, host
  state from the marker file); key file writing and removal; legacy import once; schedule rendering.
- **Integration (Go, `pgtest`):** migration `00100` on the previous schema; `paddock_api` (organization role) has no
  access to any backup table; `paddock_backup` can update only the granted columns; key flow (generate while
  pending → 409; confirm wrong ×3 → discarded; confirm right → active, previous retired); plan uniqueness; the
  privileged route table and `x-paddock-audit` (`spec_test.go`); the list contract for the three lists.
- **Shell (`make test` with Docker):** `pgbackrest_test.sh` (posix repository, key file wait, `--at`, a new key
  path creates a new stanza); `restore_test.sh` (fixtures); `bundle_test.sh` (targets rendering, `.paddock-mount`,
  excluded from the tarball).
- **Acceptance (`test/acceptance/backup_test.go`, stack with `BACKUP=1`, platform admin with step-up, the
  development S3 target on the audit RustFS and the local target volume):**
  - B1 `TestBackupKeyConfirmation`: no key → `POST /backup/run` 409 and `paddock_backup_key_confirmed 0`;
    generate → the text is 44 base64 characters, `positions` six distinct; a wrong answer → 409
    `backup_key_mismatch` with attempts left, audited failure; after three → `discarded`; a new key confirmed with
    the right characters → `active`; the response of `GET /backup/key` never contains the key text; an API token
    → 403 `step_up_required`.
  - B2 `TestBackupTargets`: create local and S3 targets, list contract, update keeps the secret, the S3 test
    reports `last_test_ok true` within 60 s, a wrong secret key → `auth`; secrets absent from every response;
    audit params free of `secret_key`; a private-address S3 endpoint is refused unless the dev flag is set.
  - B3 `TestBackupRuns`: `backup now` for every kind → within 3 minutes `backup_run` rows `succeeded` for
    `openbao`, `fleet`, `escrow` and the mirror status of both targets; the S3 target holds `manifest.json` whose
    `key_id` is the active key and whose `escrow` lists the devicesim's LUKS header object; `platform.backup_completed`
    once per kind with `targets_ok 2`.
  - B4 `TestBackupRotation`: generate a second key, confirm → the first is `retired`; within one full interval
    (development: `PADDOCK_BACKUP_FULL_INTERVAL_S` 120) `pgbackrest info` shows the new path's stanza with a full
    backup; the old set stays until expire.
  - B5 `TestRestorePlan`: create without the typed word → 400; with → `approved` with `host_command`; a second →
    409; cancel → `expired`; a plan for a component without a success → 409.
  - B6 `TestBackupLegacyKey` (own stack variant: `PADDOCK_BACKUP_LEGACY_KEY_FILE` set and empty table): the key
    appears as `legacy`/`unconfirmed`; no run until confirmed.
  - B7 `TestIsolation` fixtures: every new endpoint answers 403 for organization sessions and tokens.
  - B8 `make restore-drill` (not a Go test): backup now → destroy → `./paddock`-equivalent `restore_run` from the
    local target → the acceptance subset of today; RTO printed.
- **System (`test/system/backup_test.go`, VMs; `share.go` installs `samba` and `nfs-kernel-server` on VM A with
  an export and a share readable by the development host; lab-profile bundle on the host as `bundle-smoke-lab`
  does):**
  - BS1 `TestBackupShareTargets`: an SMB and an NFS target created in the portal API → `pending_host`;
    `./paddock backup-target apply` + `./paddock up` → `mounted`; `backup now` → the set appears on the VM's share
    directory with the manifest; stopping `smbd` on the VM → `unreachable` within 5 minutes and
    `PaddockBackupTargetUnreachable` pending; the control plane's roles stay healthy throughout.
  - BS2 `TestRestoreFreshInstallFromUpload`: on the lab-profile installation enrol VM B, escrow its recovery key,
    `backup now`, copy the set from the local target to the host as a tarball, `./paddock down --volumes`,
    `./paddock secrets`, `./paddock restore --from <tar>` with the key → portal login works, VM B checks in and
    receives a new bundle version, the recovery key is revealed with the same value as before the loss, the
    header download works.
  - BS3 `TestRestoreFreshInstallFromTarget`: as BS2 with `--from-target-file` of the S3 target.
  - BS4 `TestRestorePointInTime`: a managed file created at T1, a second at T2, a plan to T1 + 30 s executed with
    `./paddock restore --plan` → only the first file exists, VM B's next bundle has a higher version, the plan is
    `completed` with the operator's name in `platform.restore_completed`.
- **Portal (`e2e/backup.spec.ts`):** decision 29.
- Never weakened: `TestDeviceProtocol`, `TestAuditChain`, `TestWORM`, the prodcheck tests.

## 10. Acceptance criteria (positive and negative, per role)

- **C1 targets (PDK-474 decision 2; platform admin):** Given the portal, when the administrator adds a local, SMB,
  NFS and S3 target, then each is listed with its host state, the S3 test turns green, the share targets turn
  `mounted` after the host step, and a share outage shows `unreachable` without touching the roles' readiness.
- **C2 key (decision 3; platform admin):** Given no key, then no backup runs and the overview says so; when a key
  is generated, then it is shown once with a download, never again on reload, and confirmed only with the right
  six characters; a wrong confirmation is refused and audited; three wrong ones discard the key.
- **C3 sets (decision 5; operator):** Given a confirmed key and two targets, then every target holds the same
  set with `manifest.json`, the pgBackRest repository, OpenBao snapshots, Fleet dumps and the escrow objects.
- **C4 fresh installation (decision 4a; operator):** Given a lost control plane, when the operator installs the
  same release, provides the key and the set (uploaded or from a connected S3 target), then login works, devices
  check in, a recovery key is readable and the header downloads.
- **C5 point in time (decision 4b; platform admin + operator):** Given a running installation, when a plan is
  approved with step-up and the typed word and executed on the host, then the databases are at the chosen point,
  devices accept new bundles, and the plan shows `completed` with the operator.
- **C6 partial (decision 4c; operator):** Given `--only openbao`, then only OpenBao is restored and the databases
  are untouched; `restore.md` states what is independently restorable and why organizations are not.
- **C7 audit (contract; auditor):** every portal action and every host restore is one audit event; no key,
  password or access key appears in any event, response or log (gate B2, B3; `make scan-secrets` on the logs of
  the acceptance run).
- **C8 emergency path (decision 1; operator):** `./paddock backup now`, `backup status`, `backup-target apply`,
  `restore` work without the portal.

## 11. Stop conditions

- Docker's `local` volume driver cannot mount the share with the rendered options on the CI runner or the lab
  host: report with the daemon error; do not add a privileged container.
- pgBackRest refuses `repo1-type=posix` on the Docker volume with uid 999 (permissions): report; do not run
  pgBackRest as root.
- The tmpfs volume options are not accepted by the Compose version of the bundle's minimum (`>= 2.24`): report.
- The api would need `transit/decrypt/backup-wrap` for any flow: stop; the design forbids it.
- A restore step needs a command the bundle does not ship (`mysql` client is in `FLEET_MYSQL_IMAGE`, `bao` in
  the OpenBao image, `pgbackrest` in its image; anything else → report).
- Any change seems necessary in `agent/`, `pkg/`, the escrow-reader, the audit writer or an ADR other than 0046
  and the 0032 amendment; any new Go module, npm package or container image.

## 12. Risks and open points

Residual risks: §6.9. Risks with countermeasures:

- **R1 — Two-step target setup confuses operators.** Countermeasure: the inline alert with the exact commands,
  the host state chip, `backup status` on the host; the SMB library alternative was rejected (§12, decision 1).
- **R2 — Key rotation and pgBackRest paths.** Countermeasure: `pgbackrest_test.sh` covers the path switch; the
  expire of the old path waits for retention; the manifest names the current path.
- **R3 — Legacy installations without a confirmed key stop backing up after the upgrade.** Countermeasure: the
  alert, the checklist item, the upgrade note; the lab's key is imported automatically.
- **R4 — Mirror correctness** (size-only comparison). Countermeasure: pgBackRest files are immutable and
  checksummed by pgBackRest's own `verify` after a restore; `manifest.json` is compared by SHA-256; OpenBao and
  Fleet files are AEAD-sealed (a corrupt copy fails to open, never silently restores).

Decisions taken on 2026-11-04 (architect lead, per the architect's recommendation; binding for this plan):

1. **SMB without a host step** through a Go SMB2 client library: **no**. Docker volumes for all three mount types,
   no new dependency; the host step `./paddock backup-target apply` is the design.
2. **Portal upload of a backup set**: **no**. The set reaches the host by `scp` or a share and `./paddock restore
   --from` reads it; a portal cannot exist before identity is restored.
3. **Per-organization restore**: **not offered** (ADR 0046); `restore.md` states the reason.
4. **Step-up for `backup now` and the schedule**: **yes**, for every platform backup action (uniform rule).
5. **Challenge size**: **six characters** of the 44, three strikes discard the key.
6. **Where the `legacy` key file is read**: **by the api once** (`PADDOCK_BACKUP_LEGACY_KEY_FILE`); backups pause
   until the imported key is confirmed in the portal.
7. **Local `backup-repo` disk cost**: **accepted** (the reference host has about 260 GB free); PDK-739 documents
   the sizing in `docs/operations/capacity.md` (a full set ≈ `retention_full` × one full backup of both databases
   plus 30 days of snapshots and dumps plus the escrow objects) and PDK-733's `./paddock check` item warns below
   `PADDOCK_BACKUP_REPO_VOLUME_MIN_GB` (default 20).

## 13. Freedoms (what the implementer decides)

- Internal structure of `backuprole` (one mirror goroutine per target or sequential), the fake target type, the
  wording of German texts, the layout of the overview grid, the exact `error_class` strings beyond those listed,
  the name of the one-off render subcommand's JSON shape, whether `restore.sh` and `restore-drill.sh` share a
  `lib-restore.sh`, the sqlc query names, and the `BackupTargetForm` field order.
- Migration number `00100` is the next free number at planning time; if PDK-747's migration lands first, the
  implementer takes the next free number and keeps the order of this plan.

## Amendment 2026-11-04 — backup target input shape and credential binding (PDK-731)

Decision taken by the architect lead on 2026-11-04 after Review 1 of PDK-731; the portal form (PDK-736) builds on it:

1. **Per-type input groups instead of `oneOf`.** §6.2 said `BackupTargetInput` is "oneOf by `type`". The contract
   is: `BackupTargetInput` = `{name, type, enabled}` plus one object per type, `local`, `smb`, `nfs` and `s3`, with
   the field groups of §6.1. The object named by `type` is required and the others are ignored. The spec uses no
   `oneOf` anywhere and the generated Go union types would be awkward. `BackupTarget.settings` mirrors the same
   grouping and never holds a secret. Secrets are `writeOnly` and never returned.
2. **Stored credentials cannot be redirected.** The api can only encrypt, so credentials are replaced whole, never
   merged. An update that changes a **destination-identifying** setting without sending new credentials returns
   **400** `invalid_request` naming the field and the missing credential:
   - SMB: `host`, `share`, `domain`, `username`, `options` change → `smb.password` is required
     (`options` counts because mount.cifs `ip=`, `port=` and `sec=` redirect or weaken the login).
   - S3: `endpoint`, `bucket`, `region`, `ca_pem` change → `s3.access_key` and `s3.secret_key` are required
     (together; the region is compared after its default is applied, so spelling out `us-east-1` is no change).
   - Not counted: SMB `path`, S3 `prefix` (same server), local and NFS (no credentials).
   With new credentials the change is accepted, and any mount-relevant change raises `host_revision` (§3.4).

## Amendment 2026-11-04 — challenge positions of the pending backup key (PDK-730)

Architect decision of 2026-11-04 (alpha.9 decisions, item 4), found in the review of PDK-730: the challenge
positions of key `legacy` reached no response, so an imported key could never be confirmed (decision 9). Positions
are indices, not key material.

- **Decision 7**, the sentence "Reads never return `ciphertext`, `challenge_positions` or `challenge_sha256`" now
  reads: reads never return the key text, `ciphertext` or `challenge_sha256`; they return `challenge_positions` only
  for the key in state `unconfirmed` (freshly generated or the imported `legacy` key) and never once it is
  `confirmed`, `retired` or `discarded`. `Key` gains `positions` (nullable, six 1-based positions in ascending
  order, set only while the key waits for its confirmation). The answer is never stored or returned; there is no
  legacy skip: key `legacy` is confirmed with the characters of the host file at these positions.
- **§6.2**: `BackupKey` gains the required, nullable `positions` (array of six integers); the required list ends
  `…, attempts, legacy, positions]`. No migration: `backup_key.challenge_positions` (§6.6) already holds them.
- **PDK-730 AC 3** now reads: `GET /backup/key` never contains the key text or the challenge hash; it contains the
  challenge positions only while a key waits for its confirmation (`pending.positions`), and `null` for every
  other key (the test asserts on the raw JSON).

## Amendment 2026-11-05 — the mirror follows the local expire rules on the target's own copy (replaces decision 16 c/e)

Decision (architect lead, `decisions-alpha9.md` item 24, after PDK-732 reviews 4 and 5): decision 16 c/e let the
mirror delete on a target whatever the local set no longer held, with one exemption ("a newer completed full in the
same path"). After a lost repository volume that pgBackRest initialises again, that rule deleted every older full,
all WAL and in-keep snapshots on every target. From now on **a target loses only what the local expire would have
removed from the target's own copy**; the local set is the reference for "newer", never the reason to delete. This
amendment is the complete specification of `backuprole.mirrorSet` and of the local expire it mirrors. Where it
contradicts decisions 16 c, 16 e, 17 or §9, it wins. PDK-732 is implemented against it in one round (item 24).

### A1 Vocabulary

- **L** = the local set (`repoIndex` of `backup-repo`), **T** = one target's copy (`Target.List`, sizes;
  `Target.Newest`, modification times). **P** = a repository path `pgbackrest/<key_id>`, **S** = a stanza.
- **Completed full** = a label directory `P/backup/S/<label>F/` that holds `backup.manifest`; nothing else counts
  (PDK-732 review 2).
- **Info files** = `backup.info`, `backup.info.copy`, `archive.info`, `archive.info.copy` of `(P, S)`.
- **WAL segment** = a file of `P/archive/S/<dbver-id>/<tli+log>/` whose name matches `walSegment`.
- **Kind file** = a file of `openbao/`, `fleet/` or `escrow/`; its **age** is the timestamp in its name
  (`fileTime`), identical on L and T; `mtime` is never used for kind files.
- **Retention inputs** of a round: `retention_full` and `full_interval` (schedule), `openbao_keep_days`,
  `fleet_keep_days`, the active key's path **A**, the retired key IDs with their `retired_at`, the key IDs the
  database knows (active, retired, discarded, legacy).
- **Held** = an object T holds, L lacks, and the rules below do not allow to delete this round. Held objects are
  counted per target (`held` in `backupset.RunTarget`, gauge `paddock_backup_target_held_files{target}`); a held
  object is never an error.
- **Shrunk** = a state in which writing pgBackRest files to T could make T's copy unrestorable; the whole target run
  stops before any write (`set_shrunk`, target unreachable, `PaddockBackupTargetUnreachable`), as item 19 decided.

### A2 Local expire (what the role and pgBackRest remove from L; the reference for every target deletion)

| Store | Removed from L when | By |
| --- | --- | --- |
| Completed full of `(A, S)` and its data files | `A/backup/S/` holds at least `retention_full` completed fulls with a newer label | pgBackRest (`repo1-retention-full`) |
| WAL segments of `(A, S)` | older than the archive start of the oldest retained full | pgBackRest (archive retention = full retention) |
| Retired path `P'` as a whole | `P'` is a retired key's path, `A` holds a completed full of every stanza, and `max(newest file of P' on L, retired_at)` is older than `retention_full × full_interval` | the role (`expire`) |
| `openbao/<ts>.snap.enc`, `fleet/<ts>.sql.gz.enc` | age older than the kind's keep days, and the file is not the newest of its kind on L | the role (`expire`) |
| `escrow/<key>` | **new rule:** the escrow bucket listing of this round succeeded and does not contain `<key>` | the role (`expire`, after `mirrorEscrow`; a failed listing removes nothing) |
| `manifest.json` | never (rewritten) | the role |

The role MUST additionally detect local WAL integrity: for every `(A, S)` it computes whether L's archive is
contiguous from its lowest to its highest segment (the same timeline/log/segment walk `run.sh restore` uses) and
whether the last whole-stanza `pgbackrest verify` is newer than L's newest completed full (`run.sh` writes
`$STATE/verify-ok` = epoch after `full_backup` ran `pgbackrest verify` **without** `--set`, i.e. the whole stanza,
and reported `status: ok`; the role reads it from `/pgbackrest-state/<stanza>`). `wal_ok(A, S)` = contiguous and
verified. (Supersedes decision 17's `verify --set=<label>`: the whole-stanza verify after every full replaces it.)

### A3 Mirror state table (one target, one round; the order is binding)

**Amended 2026-11-10:** the keep window uses the effective full interval (B1), and an unknown path no longer stops the
deletions of step 6 (B2); see "Amendment 2026-11-10" at the end of this plan. **Amended 2026-11-11:** "one round"
no longer holds: the steps run in the target's lane (amendment 2026-11-11).

```
step 0  read T/manifest.json (if any): parse error or another installation_id → foreign_set: stop, write nothing
step 1  list T (paths and sizes); for retired paths also T.Newest
step 2  GUARD (no write before it passed):
        G1 for every (P, S) and every completed full F on T that L lacks:
             allowed(F) := L holds ≥ retention_full completed fulls of (P, S) with label > F
             not allowed(F) → SHRUNK (stop)
        G2 for every (P, S) where T holds an info file and L holds neither the file nor its .copy → SHRUNK (stop)
        G3 for every path P on T that L lacks entirely:
             P == A                                   → SHRUNK (stop)   (the active repository was lost)
             P retired, A complete for every stanza,
               max(T.Newest(P), retired_at) older than retention_full × full_interval → DELETE-PATH(P) later
             P retired, otherwise                     → HOLD(P)
             P unknown to the database                → HOLD(P), result class unknown_path (target run fails
                                                         after step 6; amended 2026-11-10, B2: the deletions
                                                         of step 6 run, nothing below P is touched)
        G4 kind files, escrow, WAL: never shrink; they are decided in step 6
step 3  PUT, in this order, only files of L (skip a label directory until L holds its backup.manifest):
        (1) WAL segments  (2) full directories: data files, backup.manifest.copy, backup.manifest last
        (3) openbao/, fleet/, escrow/  (4) info files of every (P, S) (re-put when L's changed since pushed)
        a file T holds with the same size is skipped (info files: unless changed locally); any put error → stop:
        no manifest, no delete, class of the error; the next round continues where it stopped (idempotent)
step 4  VERIFY: list T again; every file put this round has the put size, else stop (error class size_mismatch)
step 5  MANIFEST: put manifest.json when T's differs (SHA-256 compare after the write); skipped when the local
        manifest of this round could not be written (engine writeManifest error) → the round ends here, no deletes
step 6  DELETE, only objects listed in step 1 and still present in step 4, never below a HOLD path:
        D1 completed full F of (P, S) on T, L lacks it:       delete iff allowed(F)  (G1 proved it)
        D2 WAL segment w of (P, S) on T, L lacks it:          delete iff L holds ≥ retention_full completed fulls
                                                               of (P, S) AND w < the lowest segment L holds for
                                                               (P, S) AND wal_ok(P, S); else HOLD(w)
        D3 info file on T, L lacks it (its .copy exists on L): never deleted (pgBackRest rewrites the pair)
        D4 openbao/ or fleet/ file f on T, L lacks it:         delete iff age(f) older than the kind's keep days
                                                               AND f is not the newest of its kind on T (on the
                                                               step-1 listing, before this round's puts)
                                                               AND L holds at least one file of that kind;
                                                               else HOLD(f)
        D5 escrow/<key> on T, L lacks it:                      delete iff this round's bucket listing succeeded
                                                               and lacks <key>; else HOLD
        D6 retired path marked DELETE-PATH in G3:              delete every file below it, then its directories
        D7 any path outside pgbackrest/, openbao/, fleet/, escrow/, manifest.json: never touched
        a delete error → stop (class io); deletes already done are final (they were allowed)
```

Invariants (tests assert them): (I1) no write of any kind before the guard passed; (I2) no delete before step 5
completed; (I3) the manifest never drives a deletion; (I4) every deleted object satisfied its D-rule against L at the
time of the delete; (I5) a HOLD never fails the target and never blocks puts; (I6) a SHRUNK target receives nothing
and loses nothing; (I7) the mirror never reads an object's content from T except `manifest.json`.

### A4 Loss cases and the expected target state

| # | Local state after the loss | pgBackRest behaviour (`run.sh`) | Mirror outcome on T (next rounds) | Operator path |
| --- | --- | --- | --- | --- |
| L1 | **Repository volume lost, state volume kept** (`$STATE/stanza` present, repo empty; openbao/, fleet/, escrow/ gone too) | `ensure_stanza` returns early; `backup` fails (no stanza in the repository), `last-error` set, retried every `RETRY_S` | G1 fails for every full T holds → **SHRUNK**: T unchanged (fulls, WAL, info, snapshots, dumps, escrow, old manifest); `set_shrunk`, alert after 30 min | `./paddock restore --only backup-repo --from <target>` (A5) rebuilds L from T; then normal rounds |
| L2 | **State volume lost, repository kept** (`stanza`, `repo-path`, `last-full`, `verify-ok` gone) | `switch_repo_path` sees no `repo-path`: rewrites it, `stanza-create` on the existing repository (idempotent for the same cluster), full at once | L is complete: no guard trips; the new full is put; when `A/backup/S/` now exceeds `retention_full`, pgBackRest expires the oldest locally and D1 deletes it on T (it is allowed); WAL below the oldest retained full follows D2 once `verify-ok` is written again | none |
| L3 | **Both volumes lost** | stanza created in an empty repository, full at once; snapshot/dump when due | Before and after that full: T holds fulls L lacks with fewer than `retention_full` newer → **SHRUNK**, T unchanged (incl. in-keep snapshots and dumps, escrow). Stays shrunk until L is rebuilt | as L1: `restore --only backup-repo`; the repo restore replaces L wholesale (the lone new full is discarded with it) and resets the state markers; the next `serve` round takes a full |
| L4 | **WAL-only loss** (`A/archive/S/` empty or with a gap; fulls and info kept) | fulls continue; `verify` reports the gap, `verify-ok` is not advanced | D2: L holds no lower segment / `wal_ok` false → every WAL segment L lacks is **HELD**; new fulls and new WAL are put; T keeps its complete archive; `held > 0` in the run record and the gauge | fix the archive (restore `--only backup-repo` from T, or accept and let fulls roll); the hold ends when D2's conditions hold again |
| L5 | **`openbao/` or `fleet/` partly lost** (some files gone, at least one left or a new one taken) | n/a | D4 applied to T's copy: files older than the keep days and not T's newest are deleted (they would have expired locally too); younger ones are **HELD**; the newest is never deleted; new local files are put | none; held files leave T by age |
| L6 | **`openbao/` or `fleet/` wholly lost** (L holds none of the kind) | n/a | D4's third condition fails → every file of the kind on T is **HELD**, nothing of the kind deleted; the rest of the mirror runs; `held > 0` | the next due run (≤ `openbao_interval_hours` / `fleet_interval_hours`) refills L; or `backup now --kind openbao` |
| L7 | **`escrow/` lost or the escrow listing fails** | n/a | D5: listing failed or key still in the bucket → **HELD**; after a successful `mirrorEscrow` L holds the objects again and T is unchanged; an object the bucket really dropped is deleted on T only after a successful listing | none |
| L8 | **Key rotation** (`A` = new path, old path `P'` retired) | `switch_repo_path`: stanza in `A`, full at once; `P'` untouched | `A`'s WAL, info and the first full are put as they appear (G3 does not fire: L holds `P'`); the target manifest's empty `LastFull` is irrelevant (listing-based). `P'` on T follows A2's retired rule: HOLD until `A` is complete and `max(T.Newest(P'), retired_at)` is older than `retention_full × full_interval`, then DELETE-PATH |  none |
| L9 | **Rotation, then L1/L3** (L lacks `P'` entirely, `A` fresh) | as L3 for `A` | G3: `P'` retired but `A` not complete → **HOLD(P')**; `A` on T: G1 → SHRUNK while T holds `A` fulls L lacks (L3), else puts continue. In every case `P'` stays byte for byte until A2's rule holds on T's own copy | as L1/L3 |
| L10 | **Retired path expired locally, T missed the last files** (outage before the rotation) | n/a | G3 with `max(T.Newest, retired_at)`: T never loses `P'` earlier than L would have (review 5 minor 4) | none |
| L11 | **A path on T unknown to the database** (a discarded key never has a path; a foreign-key path can only come from a damaged target) | n/a | HOLD(P), class `unknown_path`: puts run, nothing below P is deleted, every deletion the D-rules allow elsewhere on T runs (retired paths past the keep window included), the path is logged and noted in `./paddock backup status`, and the target run fails so an operator sees it (amended 2026-11-10, B2; before: no delete anywhere on T) | empty the path on the share or bucket by hand, or restore |
| L12 | **T lost files** (share restored from an older snapshot, object store pruned) | n/a | the put phase re-copies every file L holds and T lacks; nothing is deleted (D-rules only remove what L lacks) | none |

### A5 Repository restore from a target (new component `backup-repo`; PDK-734 scope, documented in restore.md)

`./paddock restore --only backup-repo --from <target name | path | target file>`: stops `pgbackrest*` and
`paddock-backup`, empties the `backup-repo` volume, copies T's whole set into it (through the one-off backup
container, `paddock-server backup restore-repo`), writes `$STATE/stanza`, `$STATE/repo-path` (= the manifest's
path) and removes `$STATE/last-full` and `$STATE/verify-ok` of both stanzas, starts the three services; the next
`serve` round runs `stanza-create` (idempotent), a full and a whole-stanza verify. Databases, OpenBao and Fleet are
not touched; no restore plan is needed (the command records `platform.restore_completed` with `components:
[backup-repo]`). It refuses while a restore plan is `running`.

### A6 Test matrix (`server/internal/backuprole`, one regression test per case; a fake target with sizes and
modification times, a fake clock, the key list from a fake store)

| Case | Test | Setup | Assertions (every op recorded in order) |
| --- | --- | --- | --- |
| L1 | `TestMirrorRepoLostStateKept` | L empty except `manifest.json` with `LastFull` ""; T: 2 fulls, WAL, info, 3 snapshots, 2 dumps, escrow | `errSetShrunk`; ops empty; T listing unchanged |
| L2 | `TestMirrorStateLostRepoKept` | L: `retention_full` = 2, fulls F1<F2<F3 (pgBackRest expired F1 locally: L holds F2, F3 and WAL ≥ F2's start); T: F1, F2, WAL from before F1 | ops: puts of F3 and new WAL; delete of F1's files; delete of WAL segments < L's lowest (only with `verify-ok` newer than F3 — a second subtest without it: those WAL are held, F1 still deleted) |
| L3 | `TestMirrorBothLostFreshFull` | L: one new full F9 in `A`, 1 snapshot; T: F1, F2, WAL, info, 3 snapshots | `errSetShrunk`; ops empty (not even F9 or the snapshot) |
| L4 | `TestMirrorWalOnlyLossHolds` | L: fulls F2, F3, no WAL (subtest b: a gap); T: full WAL | ops: no delete below `archive/`; new files put; `held` = number of T's WAL segments |
| L5 | `TestMirrorKindPartialLossFollowsKeep` | keep 30 d; L: snapshot S4 (new) only; T: S1 (40 d), S2 (31 d), S3 (10 d) | ops: put S4; delete S1; S2 and S3 held (S3 inside the keep days; S2 is the newest of its kind on the step-1 listing, D4's "newest" is evaluated before the put); subtest "second round" (T now holds S2, S3, S4): S2 deleted, S3 held |
| L6 | `TestMirrorKindWhollyLostHolds` | L: no `openbao/`; T: S1 (40 d), S2 | ops: no delete under `openbao/`; `held` = 2; no error |
| L7 | `TestMirrorEscrowFollowsBucket` | L: no `escrow/x`; T: `escrow/x`; subtests: listing failed / bucket has x / bucket lacks x | held / held / deleted |
| L8 | `TestMirrorRotationPutsNewPathHoldsOld` | retired P1 (retired_at = now − 1 d), A = P2 with info + WAL, no full yet; T: P1 complete | ops: puts of P2 files only; no delete under P1; `held` counts P1's files; subtest "A complete, T.Newest(P1) older than keep": P1 deleted whole |
| L9 | `TestMirrorRotationThenLossKeepsOldPath` | as L8 but L lacks P1 entirely; subtest a: A has no full → ops empty except puts, P1 held; subtest b: T also holds P2 fulls L lacks → `errSetShrunk`, ops empty | P1 byte for byte identical before and after |
| L10 | `TestMirrorRetiredPathAgeFromRetiredAt` | T.Newest(P1) = now − 20 d, retired_at = now − 2 d, keep 14 d | P1 held (age base is retired_at); subtest retired_at = now − 15 d: deleted |
| L11 | `TestMirrorUnknownPathHeld` | T holds `pgbackrest/bk-20000101-deadbeef/…` unknown to the store, a retired path past the keep window and an expired snapshot | puts run; the unknown path is kept and named in the error; the retired path and the expired snapshot are deleted; error class `unknown_path` (amended 2026-11-10, B2; before: no delete) |
| L12 | `TestMirrorRefillsTarget` | T lacks half of L's files | every missing file put, nothing deleted |
| order | `TestMirrorOrderGuardPutVerifyManifestDelete` | fake target records ops | first op after `Read manifest`/`List` is a put; `Put manifest.json` after every other put; every `Delete` after the second `List`; with a failing put: no manifest, no delete |
| partial | `TestMirrorPartialErrorStopsBeforeDelete` | a put fails midway | ops end at the failing put; T manifest unchanged; next round (fake fixed) completes the puts, then deletes |
| invariants | `TestMirrorInvariants` (property-style, 200 random L/T pairs) | random sets with the rules of A1 | I1–I7 hold; every deleted object satisfies its D-rule |
| engine | `TestRoundRepoLostLeavesEveryTargetIntact` (engine level, two targets) | L1 then L3 through `Engine.Round` with the real `run.sh` markers faked | both targets unchanged; `set_shrunk` in `backup_run.targets`; gauge 0 |

Existing tests that the amendment makes obsolete and that are replaced (not weakened: their assertions move into
the cases above): `TestMirrorKeepsTargetWhenSetShrunk` → L1/L3, `TestMirrorKeepsRetiredKeyAfterRotationAndLoss` →
L8/L9, `TestMirrorGuardIgnoresEmptyLastFull` → L8, `TestMirrorGuardPartialInfoLoss` → G2 case in
`TestMirrorInvariants` plus a named subtest, `TestMirrorGuardWithoutTargetManifest` → L1 subtest without
`manifest.json`, `TestMirrorKeepsEscrowWhenLocalEscrowLost` → L7.

### A7 Consequences for other decisions and tickets

**Amended 2026-11-11:** each target's mirror runs in a lane of its own and the round never waits for it; see
"Amendment 2026-11-11" at the end of this plan.

- Decision 16 c: the escrow expire rule (A2) is added; the OpenBao/Fleet and retired-path rules are unchanged.
- Decision 16 e: replaced by A3.
- Decision 17: `full_backup` runs the whole-stanza `verify` and writes `$STATE/verify-ok`; `run.sh` keeps `--set`
  only as the fast path when the whole verify exceeds 15 minutes (then `verify-ok` is **not** written and WAL on
  targets stays held — the operator sees the hold and can run `./paddock compose run --rm --no-deps pgbackrest
  verify`).
- `Target.Newest` stays (retired paths); `backupset.RunTarget` gains `Held int`; the metric
  `paddock_backup_target_held_files{target}`; alert `PaddockBackupTargetHolding` (`> 0 for 7d`, warning) in
  PDK-732's scope.
- PDK-734 gains the component `backup-repo` (A5); PDK-739 documents A4 as the operator table in `restore.md`
  (this amendment's PR already adds the section).
- Review 4 minors 4–7 are in PDK-732's implementation round: skip the delete phase when the local manifest could not
  be written (step 5), size check before the manifest (step 4), no put of a label directory without
  `backup.manifest` (step 3), and a hard cap on a trickling target (cancel the mirror context at
  `started + budget + size/min_rate` with `min_rate` = 1 MiB/s).

### Note 2026-11-05 a — A6 rows L5 and L8 corrected (A3 wins; decisions-alpha9 item 26)

- **L5** (`TestMirrorKindPartialLossFollowsKeep`): D4 applies to S2 as well, because S3 (10 d) is newer than S2 (31 d),
  so S2 is not the newest of its kind on the step-1 listing. Round 1 puts S4, deletes S1 and S2 and holds S3, the
  newest. The "second round" (25 days later; T holds S3 and S4) deletes S3. The newest file of a kind on the step-1
  listing is never deleted.
- **L8** (`TestMirrorRotationPutsNewPathHoldsOld`): in the main case, L still holds P1, so T holds nothing that L
  lacks, and **held = 0**. The assertion "held counts P1's files" moves to **L9a**, where L lacks P1. The L8 subtest
  "A complete, T.Newest(P1) older than keep: P1 deleted whole" runs with a local set that has already expired P1.

### Note 2026-11-05 b — escrow headers leave only on Destroy evidence (decisions-alpha9 items 27 and 29)

PDK-732 review 6 (S1): under A2 and D5, a *successful* escrow listing that lacked a header removed it from L and from
every target. A lost RustFS volume, whose bucket `rustfs-bundles-bootstrap.sh` re-creates empty, or a wrong
`PADDOCK_ESCROW_S3_BUCKET` would therefore have wiped every escrow copy. From now on, **absence from the listing never
deletes on its own**. This note replaces the `escrow/<key>` row of A2 and rule D5 of A3.

- **Evidence.** An escrowed header copy, in L or on a target, may be deleted only on audited evidence that its
  device's escrow was removed on purpose, and only after the keep window has passed since that evidence. The only
  such evidence in the code base is the revocation-issuer's Destroy (crypto-shredding): the audit action
  `device.escrow_destroyed` with `status = 'finished'` and `outcome = 'success'`. The issuer deletes the device's header
  objects only there. Device retirement (`device.retired`) deletes no escrow, so it is no evidence. The role reads
  `organization_id`, the target device ID and the newest `finished_at` per device (`BackupRoleEscrowEvidence`).
- **Keep window** = `retention_full × full_interval`, the window in which a retained database full can still predate
  the Destroy. No schema change.
- **Rule** (`escrowRule.gone`, used by the local expire and by D5): delete `escrow/<key>` iff this round's bucket
  listing succeeded, was not suspicious, lacks `<key>`, and the device of `<key>` has evidence older than the keep
  window. Otherwise HOLD (counted in `held` on targets).
- **Suspicious listing.** *Unevidenced* absences are the headers L holds that the listing lacks and whose device has
  no evidence. Evidenced absences go through the keep window and never count. When the unevidenced absences are all
  of L's headers, or more than 10 % of them, the listing is suspicious. In that case the escrow pass copies nothing
  from the bucket (a wrong bucket's headers never enter the set), deletes nothing in L or on any target, records the
  escrow run as failed (class `escrow`), and sets `paddock_backup_escrow_listing_suspicious` = 1, which fires
  `PaddockBackupEscrowListingSuspicious` (critical, 5 min). Fewer unevidenced absences are held, logged once per
  change of their set, and counted in `paddock_backup_escrow_unevidenced_missing`. A failed listing or a failed
  evidence query fails the escrow run and deletes nothing.
- **Known limit.** When L has also lost `escrow/`, an empty listing cannot be told apart from a new installation. No
  alert fires, but nothing is deleted either: the targets hold every header that has no evidence.
- **Recorded deviation from organization isolation** (architect lead, item 29; also in `docs/architecture.md` §5):
  migration 00107 adds a permissive `FOR SELECT` policy `backup_escrow_evidence` on `action` TO `paddock_backup`,
  limited to `code = 'device.escrow_destroyed' AND status = 'finished' AND outcome = 'success'` and to the role's
  platform context (`current_setting('paddock.org_id')` = the nil organization, so a missing context fails closed).
  The nil-organization policy `backup` is unchanged, and no other role gains anything.
- **A6 L7** (`TestMirrorEscrowFollowsBucket`) becomes these subtests: listing failed / bucket has x / bucket lacks x
  without evidence / evidence within the keep window / suspicious listing / empty bucket → **held**; evidence older
  than the keep window → **deleted**. Engine-level regression tests: `TestEscrowEmptyBucketHoldsEverything`,
  `TestEscrowWrongBucketHoldsEverything`, `TestEscrowPartialAbsenceWithoutEvidence`, `TestEscrowEvidenceKeepWindow`,
  `TestEscrowEvidenceQueryFailsHoldsEverything`, `TestEscrowUnevidencedWarnedOncePerChange`. The invariants oracle
  states the same rule.

### Note 2026-11-05 c — Destroy evidence applies per copy (decisions-alpha9 item 31)

PDK-732 review 7 (M1): note b matched the evidence per device. A device that has not yet executed its Destroy token
(valid for 30 days) can still escrow new header generations, and an old Destroy then let such a newer copy leave L
and every target as soon as it left the bucket for any other reason. This note narrows the evidence rule of note b.

- **Per copy.** A Destroy covers a header copy only if the escrow object existed at or before the Destroy's
  `finished_at`. A copy newer than the Destroy, or one without a recorded time, is *unevidenced*: held in L and on
  every target, counted in `paddock_backup_escrow_unevidenced_missing`, and part of the suspicious share.
- **Time source.** The escrow object's own time: its `LastModified` (on a versioned bucket, the current version's
  time) from the bucket listing at copy time, never the local file's mtime (A1). The escrow pass lists through
  `objectstore.Store.ListInfo` (size and `LastModified`).
- **L's index.** The time is recorded in the set's index, `manifest.json`: each `contents.escrow` entry gains
  `"at"` (optional, omitted when unknown; no schema bump). A manifest without it stays readable; its copies are
  unevidenced until the bucket lists the same key with the same size again, whose `LastModified` is then recorded
  (objects are immutable, so that is the time at copy time). A recorded time is ignored when L's copy no longer has
  the recorded size.
- **Targets.** A target copy is judged with the time L's index held at the start of the round. Once L has deleted
  its copy, a target copy the same round could not delete (a failed or skipped target mirror) has no recorded time
  and stays held.
- **Tests.** `TestEscrowGenerationNewerThanDestroyHeld` (a generation newer than the Destroy goes missing: held on L
  and both targets, counted), `TestEscrowOlderGenerationWithEvidenceDeleted` (older generations with evidence beyond
  the keep window still leave), `TestEscrowIndexRecordsObjectTime` (manifest records `LastModified`; a manifest
  without times holds); A6 L7 gains "copy as old as the Destroy" (deleted), "copy newer than the Destroy" and "copy
  without a recorded time" (held); the invariants oracle draws the copy times as well.

### Note 2026-11-05 — restore plans: the start is audited, the target must exist (PDK-735; decisions-alpha9 items 37 and 39)

- **Start audited.** `backup restore-report --outcome running` is the moment the host starts overwriting data. It
  goes through the ActionRunner and records exactly one `platform.restore_started` per attempt, a refused one
  included (actor system with the operator as display, `host` when the name is no login name; params `plan_id`,
  `source`, `source_target_id`, `components` of the stored plan; failure `invalid_request`, `not_found` or
  `invalid_state`). §6.4 lists it. Wazuh rule 100932 (level 10, Sigma `high`) classifies it.
- **Target gone.** A plan with `source = target` whose `source_target_id` became NULL (`ON DELETE SET NULL`) is
  refused on the host: `backup plan <id>` exits 1 and `running` fails with `invalid_state`. It is never run from the
  local repository.
- **`at` only for point_in_time.** A `components` plan with `at` is 400 `invalid_request`, so a plan the restored
  database lost is re-inserted with an unambiguous kind.
- **Additive param.** `source_target_id` is part of every restore event (§6.4 lists only `source`).
- The CLI flags of `backup plan` and `backup restore-report` (PDK-734's contract) are unchanged.

## Amendment 2026-11-05 — local targets are subpaths of a configured root (PDK-760, `decisions-alpha9.md` item 36)

Decision: a local target no longer names an absolute host directory. A new host setting `PADDOCK_BACKUP_LOCAL_ROOT`
(default `/srv/paddock-backup`) is the base directory; `local.path` is a **relative subpath** of it. This replaces any
deny list of system and deployment directories (PDK-729 review): there is no absolute path to deny.

- `backupset.ValidateTarget` refuses an empty path, a leading `/`, a `..`, `.` or empty element, a backslash, control
  characters and more than 256 bytes (400 `invalid_request`, field `local.path`). The server does not know the root.
- `backuprole.ResolveLocal(root, sub)` is the host step's join (`./paddock backup-target apply`, PDK-733): the root and
  every component must exist, be a directory and not be a symlink; otherwise the target is refused and nothing is
  mounted (fail closed). The backup role itself still sees only the mounted volume and keeps its `os.Root`
  confinement, so its `dirTarget` is unchanged.
- `./paddock check` item `backup: local target root`: FAIL when the root is not a clean absolute path other than `/`,
  is a symlink or not a directory, or is writable by group or others; WARN when it does not exist.
- Alpha: existing local targets with an absolute path fail validation on the next edit and need the subpath form;
  there is no migration (no users).

### Note 2026-11-06 — host restore: escrow credential, key file, fresh-install duration (PDK-734; decisions-alpha9 items 38 and 39)

- **Escrow credential (M5 accepted).** The escrow step of `./paddock restore` runs `backup restore-escrow` in a
  one-off `paddock-backup` container that mounts the gateway's RustFS escrow write credential
  (`rustfs_bundles_gateway_access_key`, `rustfs_bundles_gateway_secret_key`) read-only as files, because only that
  credential may put headers. The mount exists only in that one-off container and only for the duration of the
  restore step; the long-running `paddock-backup` role never holds it. A host restore is operator-initiated and the
  host already holds every secret, so this crosses no boundary the operator does not already hold. No dedicated
  restore credential is introduced.
- **Key file.** `./paddock restore` writes the entered backup key to `.secrets/restore/backup_key` (0600), which no
  Compose file mounts, and deletes it on every exit (success, failure, refusal; EXIT trap) unless `--keep-key-file`
  is given. It never writes the api-mounted `.secrets/backup_encryption_key`.
- **No duration for a fresh install.** A `fresh_install` run has no plan and therefore no `started_at`; its
  `platform.restore_completed` / `platform.restore_failed` event carries no `duration_s` (§6.4 lists it for planned
  runs only). `backup restore-report` has no `--duration-s` flag; the duration is computed from the plan's
  `started_at`.

## Note 2026-11-06 — §6.7: the SMB login in the volume's options (PDK-733, `decisions-alpha9.md` item 35)

`credentials=` is a mount.cifs option the kernel ignores, and Docker's local driver mounts with `mount(2)`; ADR 0046
amendment 2026-11-06 records it. §6.7 changes accordingly: no `.secrets/backup-targets/<id>.cifs` file; an SMB
volume's `o` is `uid=999,gid=999,file_mode=0640,dir_mode=0750,<options, vers=3 by default>,username=…[,domain=…],password=…`
(password last). A comma or whitespace in the password is refused when the target is saved and again at render (PDK-733 review 3: Compose folds the `o` line at a space, past any line-based redaction): Docker splits `o` on every comma and takes a segment
that names a mount flag (`bind`, `ro`, `remount`, …) as a flag of the mount, so doubled commas do not protect it. The
volume name is `backup-target-<id>-r<revision>-<fingerprint>`, the fingerprint being the first 12 hex digits of the
SHA-256 of type, device and options without the password, because Docker never changes an existing volume's options
and a non-interactive Compose run keeps a volume whose options changed: another `PADDOCK_BACKUP_LOCAL_ROOT` or a
release's new default options change the name without a new revision (a new password always raises the revision).
`apply` removes every other volume of the targets once `paddock-backup` no longer uses them, then the deleted targets' rows. Every value is YAML-quoted with `$`
doubled. The header records `# revisions:` (for the online check item of decision 22) and every local device
(`# local: <base64>`), which `./paddock up` resolves again below `PADDOCK_BACKUP_LOCAL_ROOT` before each start.

### Note 2026-11-06 b — the escrow step reads the Destroy evidence from the audit index (PDK-831; decisions-alpha9 items 39, 44 and 45)

- **Evidence source.** A restore never puts back an escrowed LUKS header whose device has a successful
  `device.escrow_destroyed` not older than the copy. `backup restore-escrow` reads that evidence from the audit index
  (`paddock_audit_reader`, once per organization of the set's escrow keys, `max(occurred_at)` per device), because the
  audit domain survives the restore and a point-in-time restore to before the Destroy leaves the restored database
  without it. The audit index is the only source: item 44 allowed the restored database as an extra skip-only source,
  item 45 dropped it together with its database credential (least privilege on a container that holds the gateway's
  put credential). An unreadable audit index, or an escrow key whose organization or device segment is not a
  canonical UUID (the evidence is matched on that exact string), fails the step and puts nothing back.
- **Trust path (replaces the escrow-credential bullet of the note 2026-11-06 above).** The step runs in the one-off
  service `backup-restore-escrow` of `compose.backup.yaml` (profile `restore`, never started by `up`; the backup image
  and hardening, uid 999, read-only root, `backup-repo` read-only), on networks `cp` and `audit-index`, with the escrow
  lister (`rustfs_escrow_backup_*`), the gateway putter (`rustfs_bundles_gateway_*`), `db_paddock_audit_reader_url`
  and the public `internal_ca_bundle` for the reader's `verify-full` DSN, and with no control-plane database
  credential (item 45). `restore.sh` no longer mounts the gateway credential into a `paddock-backup` container. The
  long-running `paddock-backup` never holds the audit credential or joins `audit-index`, and the step never holds a
  database credential other than the audit reader's; `./paddock check` fails if either happens.
- **Report.** The terminal lists every skipped header, one line per device ID. `platform.restore_completed` gains the
  additive param `escrow_skipped_destroyed` (a count, no device IDs), set only for a completed run that included the
  escrow step (`backup restore-report --escrow-skipped-destroyed <n>`).

### Note 2026-11-06 c — decision 30: the drill restores as a fresh install (PDK-737, decisions-alpha9 item 48)

- **Change.** `restore-drill.sh` runs `restore_run fresh repo` after `backup fetch-set` from the local development
  target, not `restore_run plan …` as decision 30 states. The rest of decision 30 holds: backup now, destroy, restore
  through `restore.sh`, acceptance subset, RTO line in `docs/operations/restore.md`.
- **Reason.** A restore plan lives in the control-plane database, which is what the drill destroys; a plan cannot
  survive the loss the drill measures. The drill measures the RTO from losing the databases, the case an operator
  restores without a plan.
- **Plan path.** The plan-based path is covered by the `TestRestorePlan` gates (§9 B5: typed word, point in time,
  approval, expiry, cancel, the host command `./paddock restore --plan <id>`); its execution on a host stays with
  system gate BS4.

### Note 2026-11-07 — the budget and the hard cap count only the copy phase (PDK-865; decisions-alpha9 items 66 and 67)

- A7's round budget (10 min) and its hard cap on a trickling target (`copy start + budget + size/min_rate`) apply only
  to the copy phase of step 3. The budget starts with the first copied file and is checked after every copied file;
  the cap applies only while a file is in flight.
- Listings (step 1 and step 4) are not charged against the budget. Only the stall watchdog guards them: the S3
  listing reports progress after every page, a mounted target's walk every 1 024 entries, and a listing whose next
  page does not arrive within the stall window fails the mirror. Once the copies are done, step 6 stays reachable.
  **Amended 2026-11-10 (B3 of the amendment 2026-11-10):** on an S3 target a page may take longer than the stall
  window while the endpoint answers a probe; one page is bounded at 20 minutes.
- The watchdog's error names the phase (for example `no progress for 2m0s while listing the target`); a copy-rate
  error is only ever reported for a copy.
- Step 6 is not bounded by the budget yet. After a long target outage, the first successful mirror can hold the role
  for the length of the delete backlog (RR-126). Bounding the deletions by the budget is planned for alpha.10 with an
  A3/A7 amendment (PDK-869).


### Note 2026-11-07 b — runs are recorded in two phases (PDK-881; decisions-alpha9 items 78 and 79)

- **Phase 1.** Each kind's run is written right after its local step (snapshot, dump, escrow pass, pgBackRest
  marker, timeout), before the round's mirror: the `backup_run` row (or the answered request, which ends
  `backup now --wait`) with outcome, times, bytes, error class and `targets = []`. Restore plans and the history see
  the backup at once; before, a mirror of hours (item 67) kept it out of the database for as long.
- **Phase 2** (amended 2026-11-11, C4 of the amendment 2026-11-11: recorded when the targets' lanes finish, not
  after the round's mirror). After `mirrorAll`, every finished run without `mirrored_at` gets the round's per-target results and its
  audit event `platform.backup_completed` / `platform.backup_failed` as before (§6.4; params gain `completed_at`, the
  local completion). That covers this round's runs and any an earlier round could not finish because the role
  stopped between the phases: exactly one event per run; a target the set did not reach counts as `targets_failed`.
  Migration `00112_backup_run_mirrored` adds `mirrored_at` with the default `now()`: existing runs, and runs an older
  backup role writes during an upgrade (it records their event itself), count as mirrored; phase 1 writes NULL. A
  phase-2 write that fails leaves the runner's failure event as the run's one event and marks the run mirrored; a run
  phase 1 cannot write gets a `platform.backup_failed` with `error_class` `record` instead.
- **Copy budget.** A target whose mirror used the round's copy budget gets `RunTarget{ok: false, error_class:
  "continues"}`; its `backup_target_status` keeps `last_success_at` and `bytes` and has no `last_error` (an error of an
  earlier round is cleared: the mirror is progressing); the portal's run history says "continues next round". A3's
  order of steps is unchanged.

### Note 2026-11-07 c — the Fleet run is recorded while the mirror runs (PDK-885; decisions-alpha9 item 82)

- The Fleet kind is asynchronous: a round writes the dump request, fleet-backup answers some seconds later. Phase 1 of
  note "2026-11-07 b" could only record it in the next round, i.e. after the round's mirror, which can take hours. A
  round that asked for a dump now watches the dumps volume while its mirror runs (every 5 s) and seals and records the
  dump as soon as it is there. This round's mirror does not hold that file, so the run's mirror results and audit
  event are the next round's phase 2 (the round passes the IDs of runs recorded after its index to `MirrorRuns` as
  skipped). A request the round already answered with a timeout is not given to the watcher. When the mirror ends
  first, the next round seals the dump as before.
- The development stack's full interval is 20 minutes (was 120 s); gate B4 bounds the key switch without it, since a
  new repository path makes a full due at once, and requests a full in the old path right before the switch, so a
  switch that waited for the schedule cannot fall inside the bound.

### Note 2026-11-08 — a request is answered by a full that starts after it; a share outage is unreachable (PDK-893; decisions-alpha9 item 89)

- **Requested fulls.** A requested pgBackRest backup (`backup now`, decision 16) is answered only by a full that
  started at or after the request (Unix seconds). run.sh records the start of every full in `last-full-start` next to
  `last-full` (its end) and takes a new full when a request is newer than that start; the backup role answers
  requests by the same start. A full that was already running when the request came (the installation's first full,
  the path switch's full after a restore or a rotation) no longer answers it. Before, it did: the run's start lay
  before its own request, and the target status, which reports the full's start, never reached the request (gates
  BS1/BS3 timed out).
- **Restore staging.** `run.sh restore` stages the WAL from the start of the backup pgBackRest reports having restored,
  on that backup's timeline, with the history files up to it (for `--at` it refuses to guess when pgBackRest names no
  backup); before, a point in time was staged from the oldest backup's timeline and failed after an earlier restore
  had moved the stanza to a later timeline (gate BS4). A point on a later timeline than the restored backup's (after
  a promotion that followed that backup) is not walked yet: a timeline-aware walk is planned for alpha.10
  (decisions-alpha9 item 91). Every completed restore that replaces the databases removes the pgBackRest state, so
  serve takes a full on the new timeline at once, and a later point in time has a backup on its own timeline.
- **Restore on a running installation.** The postgres step removes the backup role's stopped container with the
  databases and pgBackRest before it deletes the pgBackRest state volumes, which the role mounts read-only.
- **Share outage.** The host state of a volume target is `unreachable` when its mount or marker returns an error of a
  share whose server is gone (EIO, EHOSTDOWN, ETIMEDOUT, ESTALE and the like, as a soft CIFS or NFS mount does), and
  `pending_host` only while the marker is absent or not what the host step wrote (decision 2, gate BS1).

## Amendment 2026-11-10 — keep window, unknown paths, slow S3 listings, versioned buckets (A10-25; PDK-972, PDK-977)

Decision (architect lead, `decisions-alpha10.md` §42, after the alpha.10 regression): on a long-lived development
stack the mirror to the S3 target failed for days as "stalled", six key paths (about 160 GB) were never removed, and
the bucket kept every deleted object as a version. The rules of the amendment 2026-11-05 (A2, A3) stay; this
amendment corrects four points. Where it contradicts A1–A6 or the note 2026-11-07, it wins. Bounding step 6 by the
round budget (PDK-869, RR-126) is **not** part of it.

Binding language: **MUST** / **MUST NOT** / **SHOULD** / **MAY**. Ticket: PDK-972, which also carries the
development bootstrap of PDK-977 (B4). The amendment was written while PDK-972 was in review and records its rules
as implemented; the one point it still has to meet is the retired-path listing of B3.

### B1 The keep window follows the effective full interval (amends A1 "retention inputs", A2, A3 G3, note 2026-11-05 b)

- **Effective full interval** = the interval at which pgBackRest takes a full backup, i.e. the value the role writes
  to `schedule.env` as `PADDOCK_BACKUP_FULL_INTERVAL_S` (decision 16 a): the schedule's `full_interval_hours`, or
  `backuprole.Config.FullInterval` when it is greater than zero. `Config.FullInterval` is only ever set from
  `PADDOCK_BACKUP_FULL_INTERVAL_S` with `PADDOCK_ENV=development` (`loadBackupRole` refuses it otherwise), so in
  production the effective full interval **is** the schedule's.
- **Keep window** = `retention_full × effective full interval`. It replaces `retention_full × full_interval` in A2
  (retired path), A3 G3, A4 L8–L10 and in the escrow rule of the note 2026-11-05 b. There is one keep window per
  round (`retention.keep`); the retired-path rule and the escrow rule MUST NOT use different windows. Reason: the
  window stands for the time span the retained fulls cover, and that span is `retention_full` effective intervals.
- Defaults: production 14 × 24 h = 14 days (unchanged). Development (`compose.backup.dev.yaml`,
  `PADDOCK_BACKUP_FULL_INTERVAL_S: "1200"`): 14 × 20 min = 4 h 40 min, before this amendment 14 days.
- `Engine.retention` and `Engine.writeRuntime` MUST take the effective full interval from one unexported method
  `Engine.fullInterval(sched backupset.Schedule) time.Duration`, so the two cannot diverge again.
- The escrow rule shortens with it in development: about 4.7 h instead of 14 days (B8 point 1).
- The rule for a retired path `P'` is otherwise unchanged: `P'` is removed from L (role `expire`) and from a target
  (G3 → D6) only when `A` holds a completed full of every stanza **and** `max(newest file of P', retired_at)` is
  older than the keep window.
- Invariants (tests assert them, in addition to I1–I7):
  - (I8) no rule ever deletes below the active path `A` as a whole; `A` only loses what D1 and D2 allow.
  - (I9) no retired path is deleted, locally or on a target, while its replacement lacks a completed full of every
    stanza. The **replacement** of every retired path is the active path `A`: it is the only path that receives
    backups, so an older retired path is not protected by a newer retired one but by `A` alone.
  - (I10) a path that is neither `A` nor retired (discarded, legacy, unknown) is never deleted.

### B2 An unknown path is held and no longer blocks deletions (replaces the `unknown` line of A3 G3, A4 L11, A6 L11)

An **unknown path** is a repository path `pgbackrest/<key_id>` on a target that no key row names. It is no sign of a
damaged target alone: a database restored to a point before a key was created, or a development database that was
reset, leaves the paths of the lost key rows behind. Under A3 such a path stopped **every** deletion on the target
(`judge` counted every deletable object as held and `mirrorSet` returned before step 6), so the target could never
reclaim space.

```
G3      P unknown to the database → HOLD(P); remember P in plan.unknown (the list of unknown repository paths)
step 3–5 unchanged
step 6  runs in full: every deletion D1–D6 allows is carried out, on every path outside the HOLD paths:
        expired fulls and WAL of the active path (D1, D2), OpenBao snapshots and Fleet dumps (D4), escrowed
        headers (D5) and retired paths past the keep window (D6). D3 and D7 never delete, as before.
        Nothing below an unknown path is written, read or deleted.
end     when plan.unknown is not empty and steps 3–6 ended without another error, the target run ends with
        errUnknownPath, wrapped with the unknown paths (class unknown_path). Any other error of steps 3–6 wins.
```

- **The rule is the broad one, on purpose.** `decisions-alpha10.md` §42 asks that an unknown path never blocks the
  deletion of known retired paths; the implementation lets every D-rule go on, and that is the binding rule. Reason:
  each D-rule is decided against L on its own (I4) and none reads the unknown path. A key path is a self-contained
  pgBackRest repository (fulls, WAL and info files below it, all held), and its key is in the operator's custody,
  not in a target object. Holding all deletions protected nothing a restore needs.
- **What still stops everything:** G1 and G2 (`set_shrunk`) and `foreign_set` are unchanged: nothing written, nothing
  deleted. Without a local manifest (step 5) there is no delete phase, with or without an unknown path.
- **One consequence to know:** when the unknown path is the newer timeline (the database was restored to a point
  before that key existed), the OpenBao snapshots and Fleet dumps that belong to it now leave the target after their
  keep days (D4), as every other snapshot does. Before, they stayed for ever by accident. An operator who wants to
  keep a lost timeline restorable beyond the keep days copies the target before that (restore.md).
- The class `unknown_path`, the target run's outcome (not ok), `backup_target_status.last_error`, the gauge
  `paddock_backup_target_reachable` (0) and the alert `PaddockBackupTargetUnreachable` are unchanged: the operator
  still sees the target as failing until the path is gone (A4 L11: "empty the path on the share or bucket by hand,
  or restore"). No schema change, no API change.
- **Logged:** the engine's WARN `mirror to backup target failed` (attributes `target`, `error_class`, `error`) names
  the unknown paths through the wrapped error. The path is a key ID, not a secret.
- **Surfaced:** `./paddock backup status` shows the class `unknown_path` in the `ERROR` column of the target's rows
  and prints, below the target table, one note per such target. The note names the target and says that the path is
  kept, that the retention's deletions go on elsewhere, that the `paddock-backup` log names the path, and that the
  operator removes the path by hand. The database stores the class only, so the status cannot name the path.

### B3 Slow S3 listings: probe the endpoint while a page is outstanding (amends the note 2026-11-07, second bullet)

Measured on RustFS 1.0.4 with 55 000 objects: the object count is not the cost (first page 0.55 s). On a versioned
bucket the server walks every deleted object (delete marker and noncurrent versions) that sorts before the next live
key, about 0.5 ms each: 50 000 deleted objects ahead of the first live key delay the first page to 23.6 s, a few
hundred thousand to more than the stall window. The endpoint is alive the whole time.

The sentence "a listing whose next page does not arrive within the stall window fails the mirror" of the note
2026-11-07 is replaced for **S3 targets** by:

| Situation while a listing waits for a page | Result |
| --- | --- |
| No page for 20 s (`listProbeEvery`) | the target sends `HeadBucket` (timeout 10 s, `listProbeTimeout`) and repeats it every 20 s until the page arrives |
| A probe succeeds | counts as progress for the stall watchdog, like a page |
| No page and no successful probe for 2 min (`mirrorStall`, the stall window) | the mirror fails: `no progress for 2m0s while listing the target`, class `io` (unchanged) |
| The endpoint keeps answering, but one page does not arrive within 20 min (`listPageLimit`) | the listing ends: `errStalled`, `no page of the listing for 20m0s`, class `io` |

- **Every listing of an S3 target inside a mirror is under this rule**, not only the listings of step 1 and step 4:
  the listing of a retired path for its newest file (`Target.Newest`, A3 step 1 and G3) MUST report progress per
  page and be probed and bounded the same way, or G3 MUST take the modification times from the step-1 listing so
  that it needs no second listing. Which of the two is the implementer's choice. Retired paths are the large,
  delete-marker-heavy prefixes; a listing outside the rule would stall the mirror exactly when a retired path is due.
- A probe that fails (any error, a 403 included) is no progress. A probe in flight is abandoned as soon as the
  listing returns, and a probe answer never counts after the listing returned.
- **Mounted targets** (`dirTarget`: local, SMB, NFS) are unchanged: the walk reports progress every 1 024 entries,
  and a walk without progress for the stall window fails the mirror.
- The three durations are fields of `s3Target`, set by `NewS3Target` from the constants; no environment variable.
- Trade-off (accepted, residual risk **RR-132** in `docs/compliance/residual-risks.md`, added with this amendment):
  an S3 endpoint that answers `HeadBucket` while one list request hangs holds the role for up to 20 min per page
  instead of 2 min. It is the trade-off of the note 2026-11-07 (PDK-865): listings are not charged against the
  round budget. A round that mirrors still ends only after its targets (RR-127).

### B4 Versioned buckets need an expiry for noncurrent versions (PDK-977, delivered with PDK-972)

On a versioned bucket a deletion of the mirror frees no space: the object stays as a noncurrent version plus a
delete marker, and both slow every later listing (B3). Paddock does not manage an operator's bucket; it states the
requirement and follows it in development.

1. **Requirement (operator):** a versioned backup bucket MUST have a lifecycle rule that expires noncurrent versions
   (30 days, the value the privacy pack and RR-94 name) and removes expired object delete markers.
   `docs/operations/backup.md`, "S3 targets", says so with the reason (space, listing time).
2. **Development bootstrap** (`deploy/compose/scripts/rustfs-backup-bootstrap.sh`): after `put-bucket-versioning` it
   sets, idempotently, this lifecycle configuration on the development bucket:

   ```json
   {"Rules":[{"ID":"paddock-expire-noncurrent","Status":"Enabled","Filter":{"Prefix":""},
     "NoncurrentVersionExpiration":{"NoncurrentDays":1},"Expiration":{"ExpiredObjectDeleteMarker":true}}]}
   ```

   One day is the shortest expiry S3 allows. RustFS 1.0.4 accepts the rule and returns it; that it removes the
   versions after a day is observed on a long-lived development stack and recorded with the release regression.
3. **No `./paddock check` item in alpha.10.** `decisions-alpha10.md` §42 asked for a warning "if that is detectable
   through the S3 API". It is not, with the credential the runbook asks for: list, read, write and delete below the
   prefix grant neither `s3:GetBucketVersioning` nor `s3:GetLifecycleConfiguration`, so the item would report "not
   checked" on every correctly restricted target. `backup.md` therefore says that Paddock cannot check the rule.
   A check for targets whose credential carries the two read-only permissions would change the operator contract
   (two optional permissions in the runbook) and needs a subcommand in the backup role, which alone decrypts target
   credentials; it is an open point (B8), not part of this amendment.

### B5 Document texts (PDK-972 writes them; this amendment's pull request adds RR-132 only)

- `docs/operations/backup.md`, "S3 targets": the lifecycle rule of B4.1 with its reason, and that Paddock cannot
  check it.
- `docs/operations/backup.md`, "Status of a target", class `unknown_path`, and the retention table's row "Anything
  else": the copy and the retention's deletions go on, the path itself is kept until the operator removes it, the
  status notes the target and the log names the path.
- `docs/operations/backup.md`, "Schedule and retention": no change; the sentence on a retired key's repository keeps
  "`retention_full` full intervals", which is the effective full interval in production.
- `docs/compliance/residual-risks.md`: RR-132 (B3's trade-off) is added with this amendment's pull request. RR-127's
  "the target's listings (each page within the stall deadline)" SHOULD become "(each page within 2 minutes of the
  endpoint's last answer, at most 20 minutes, RR-132)" in PDK-972.
- Changelog: `changelog.d/PDK-972.fixed.md` names the listing rule and the unknown-path rule. The keep window and
  the bootstrap rule change nothing an operator of a production installation sees.

### B6 Tests (`server/internal/backuprole` unless stated; the names are those of PDK-972, not binding)

| Rule | Test | Asserts |
| --- | --- | --- |
| B1 | `TestRetiredKeepFollowsEffectiveFullInterval` | the keep window is 336 h without `Config.FullInterval` and 4 h 40 min with 20 min |
| B1, I8, I9 | `TestRetiredPathPruning` (S3 fake and directory target) | replacement without a full, path past the window: kept; replacement complete, path inside the window: kept; replacement complete, path past the window: removed; the active path's files stay in every case |
| B1, I8, I9 | `TestLocalExpireKeepsActiveAndIncompleteReplacement` | the local expire never removes the active path, however old; a retired path only once the active path is complete |
| B1 | `TestMirrorRotationPutsNewPathHoldsOld`, `TestMirrorRotationThenLossKeepsOldPath`, `TestMirrorRetiredPathAgeFromRetiredAt` (A6 L8–L10) | unchanged and green |
| B2 | `TestMirrorUnknownPathHeld` (A6 L11, new expectation) | the unknown path is kept byte for byte, the error names it, a retired path past the window and an expired snapshot are deleted, the newest snapshot of its kind stays |
| B2, I8–I10 | `TestMirrorInvariants` (randomized matrix) | every deletion the D-rules allow is expected with an unknown path present; a stanza without a full on the active path holds every retired path |
| B2 | `TestPrintBackupStatusNamesUnknownPathTarget` (`server/cmd/paddock-server`) | the note for a target with `unknown_path`, none without |
| B3 | `TestSlowFirstPageFromAnsweringEndpointIsNoStall`, `TestSlowFirstPageFromSilentEndpointStalls`, `TestListingPageLimit`, `TestHungListingOnAnsweringEndpointEndsAtPageLimit`, `TestListingEndAbandonsProbeInFlight` | the four rows of B3; a hung target does not keep the round from mirroring the next target |
| B3 | a test for the retired-path listing (name free; PDK-972 review 2 finding 1) | a retired path due for removal on an S3 fake whose newest-file listing answers after more than the stall window while the endpoint answers probes: the mirror succeeds and the path is removed; with a silent endpoint the mirror stalls |
| B3 | `TestHangingListingTripsTheWatchdog`, `TestDirTargetListingTicks` | unchanged assertions; mounted targets unchanged |

The new expectation of `TestMirrorUnknownPathHeld` and of the matrix follows this amendment's rule change and
asserts more than before; it is no weakened test. No acceptance gate changes. The backup gates (`TestBackupRuns`,
`TestBackupRotation`, `TestBackupTargets`) MUST be green on a development stack whose target bucket holds at least
50 000 objects; that run is recorded with PDK-972.

### B7 Acceptance criteria

- **AC-1 (operator):** given a retired key path older than the keep window and an active path with a full of every
  stanza, when a mirror succeeds, then the retired path is gone locally and on the target, and
  `./paddock backup status` shows the target's last success.
- **AC-2 (operator):** given the same with an active path that lacks a full of one stanza, then no retired path
  loses a file, however old it is.
- **AC-3 (developer):** given the development stack with a 20-minute full interval, then a retired key path leaves
  the local set and the development target 4 h 40 min after its rotation at the earliest, not after 14 days.
- **AC-4 (operator):** given a target that holds an unknown path, when a round runs, then expired fulls, WAL,
  snapshots and retired paths are deleted as without it, the unknown path is byte for byte unchanged, the role's log
  names the path, and `./paddock backup status` shows `unknown_path` and the note for that target.
- **AC-5 (operator):** given an S3 target whose listing page (of the whole target or of a retired path) takes longer
  than 2 minutes while the endpoint answers, then the mirror succeeds; given an endpoint that answers nothing, then
  the mirror fails after 2 minutes; given a page that never arrives, then the mirror fails after 20 minutes. Each
  failure shows the class `io`.
- **AC-6 (developer):** given a fresh development stack, then the development backup bucket carries the rule of
  B4.2.

### B8 Decided and open points

Decided with this amendment:

1. **The escrow rule follows the effective full interval too (B1).** `decisions-alpha10.md` §42 names only retired
   paths; PDK-972 review 2 (finding 2) asked for a record. There is one keep window. In development the escrowed
   header of a destroyed device therefore leaves the local set and the targets about 4.7 h (4 h 40 min) after the
   Destroy instead of 14 days; production is unchanged (14 days with the default schedule). A separate window for
   the escrow rule was rejected: it would let the two rules disagree about the span of the retained fulls.
2. **Every D-rule goes on beside an unknown path (B2)**, not only the removal of retired paths.
3. **A target with an unknown path stays failed (B2).** The class, the status row and the alert exist and need no
   schema change, and a stray repository should not go unnoticed. Cost: `LAST SUCCESS` of that target does not
   advance although its copy is current, and the standing alert can hide a second failure.

Open (no work in alpha.10 without a decision of the architect lead):

4. A warning state per target instead of a failed run for an unknown path (a new column and an API field).
5. A `./paddock check --online` warning for versioned buckets without the rule, for targets whose credential may
   read the bucket's versioning and lifecycle (B4.3).
6. RR-126 stays open: after this amendment the first successful mirror of a long-failing target deletes its whole
   backlog in one round; PDK-869 bounds it.

Stop conditions for PDK-972: a second place besides `retention.keep` derives a window from `full_interval_hours`; a
change to `backup_target_status`, the admin API or the portal seems necessary; any need to touch step 6's budget
(PDK-869); RustFS rejects the lifecycle configuration of B4.2.

## Amendment 2026-11-11 — one mirror lane per target; the round never waits for a mirror (A10-26; PDK-989)

Decision (architect lead, `decisions-alpha10.md` §50). Binding language: **MUST** / **MUST NOT** / **SHOULD** /
**MAY**. Ticket: PDK-989 (alpha.10 blocker). Where this amendment contradicts decision 16, A3's "one target, one
round", A7, the notes 2026-11-07 (all three) or B3, it wins. The mirror's steps 0–6, the guard, the D-rules and the
invariants I1–I10 are **unchanged**; only who runs them and when changes.

### C0 Why

A round ran its targets' mirrors itself and ended only after the last one. On the development stack a round that
started at 21:05 UTC mirrored to a versioned bucket with a large backlog of delete markers (left by the first prune
after the amendment 2026-11-10). The listing was slow but alive, so by B3 it was no stall, and the number of pages
is unbounded. For more than 40 minutes the role served nothing else: requested backups (`backup now`) stayed
`requested`, no OpenBao snapshot and no Fleet dump was taken, the effects of a key confirmation and requested target
tests waited, and four acceptance gates timed out. Only what does not depend on the round went on (WAL archiving and
pgBackRest's own fulls).

Options: (a) **a time slice**: the mirror yields after a budget, the listing included, and resumes next round. A
slice cannot interrupt a list page in flight (up to 20 minutes, RR-132); cancelling the page wastes it and the next
round asks for the same page again, so a first page slower than the slice never arrives (livelock). A continuation
token only helps between pages. (b) **a lane per target**: the mirror runs beside the rounds and the round only
starts it and looks at its state. **Decision: (b).**

### C1 Vocabulary

- **Lane** = the one mirror in flight of one target: steps 0–6 of A3 for that target, from start to its result. At
  most one lane per target exists; the number of lanes is bounded by the number of enabled targets.
- **Snapshot** = what a round hands to a lane at its start and the lane uses to its end: the index of the local set
  (`repoIndex`), the retention inputs (A1, B1) with `wal_ok` and `manifestOK`, the kind state, the bytes of the
  local `manifest.json`, and the target record. A lane MUST NOT read the database or the schedule for its decisions.
- **Abandoned lane** = a lane whose watchdog gave up (stall, page limit, trickle) while its call has not returned.
  Its result is recorded; no new lane of that target starts until the call returned.
- **Awaited target** = a target whose lane result a finished run still needs for its phase 2 (C4).

### C2 The round (replaces decision 16 e's place in the round and "after `mirrorAll`" of the note 2026-11-07 b)

In every round, in this order, and **without waiting for any lane**:

1. host states and requested target tests (C6);
2. the key: active key, `schedule.env`, key file (decision 16 a), so the effects of a key confirmation take place
   in the first round after it;
3. the due and the requested runs of every kind, recorded in phase 1 as before (OpenBao snapshot, escrow pass,
   Fleet dump, pgBackRest marker, timeouts);
4. the local expire, `manifest.json`, the index, the metrics of the local set;
5. for every enabled target (C3): start a lane with this round's snapshot, or leave the lane in flight alone;
6. phase 2 for every run whose awaited targets all have a result (C4);
7. the high-water file.

A round's duration therefore no longer depends on any target. A requested run starts at the latest one round
interval (`PADDOCK_BACKUP_ROUND_INTERVAL`, default 1 minute) after the round in flight ended.

### C3 Lanes

1. **Start.** A lane is started only by a round that holds the leader lock, for a target that is enabled, whose
   host state allows a mirror (`mounted` or `n/a`), and that has no lane in flight and no abandoned lane. A target
   in `pending_host` or `unreachable` gets no lane and its result at once (`not_mounted`, `io`), as before.
2. **In flight.** While a lane is in flight the rounds write nothing for that target: no `backup_target_status`, no
   metric change, no error. The error "the previous mirror has not returned" is no longer produced for a running
   lane; it stays for an abandoned one.
3. **Watchdog and limits** run inside the lane, unchanged: the stall window (2 minutes), the probe and the page
   limit of S3 listings (B3), the copy budget (10 minutes, counted from the lane's first copied file) and the
   trickle cap. A lane that used its copy budget ends with the class `continues`; the next round starts a new lane
   with a fresh snapshot. Listings and step 6 are still not bounded by the budget (RR-126, PDK-869).
4. **Deletions stay in the lane.** Step 6 runs in the lane that listed, guarded, copied and verified, after its own
   step 5, on its own snapshot. No other goroutine deletes on a target. I1–I10 hold per lane.
5. **Finish.** When a lane ends (success, error, `continues`, watchdog), it alone writes the target's
   `backup_target_status` per kind, the gauges `paddock_backup_target_reachable` and
   `paddock_backup_target_held_files` of its target, and its result for the runs that await it (C4). The values are
   those the round wrote before (note 2026-11-07 b, "Copy budget" included). A round MUST NOT reset the gauges of
   targets it did not touch.
6. **Per-target state** (`pushed`, the held count, the newest mirrored time per kind) is owned by the target's lane
   or guarded by one mutex; the race detector MUST be clean.
7. **Cancel.** The engine cancels a target's lane when a round finds the target disabled or deleted, when a round
   did not obtain the leader lock, and at shutdown (C7). A cancelled lane writes no status and no run result.
   Other changes of a target take effect with its next lane.
8. **Visibility.** New gauge `paddock_backup_target_mirror_started_timestamp_seconds{target}`: the start of the
   lane in flight, absent without one. The role logs the start of a lane at `Info` when the previous lane of that
   target ran longer than one round interval, and the end of every such lane with its duration and class.

### C4 "Mirrored" is recorded when the lanes finish (replaces phase 2 of the note 2026-11-07 b)

1. Phase 1 is unchanged: a run is recorded right after its local step with `targets = []` and `mirrored_at` NULL.
2. A round **registers** every finished run without `mirrored_at` that it has not registered yet: its awaited
   targets are the targets enabled in that round. A target without a lane (C3.1) gives its result at once.
3. A target's result for a registered run is the result of the **first lane of that target that started in or after
   the registering round**. A lane already in flight at the registration does not count: its snapshot may lack the
   run's files.
4. When every awaited target has a result, the run gets its per-target results, `mirrored_at` and its one audit
   event (`platform.backup_completed` / `platform.backup_failed`), exactly as phase 2 did. A target that was
   disabled or deleted meanwhile is dropped from the awaited targets and from the results.
5. **Await limit: 60 minutes.** A run still awaiting a target 60 minutes after its registration is recorded then;
   every target without a result gets `RunTarget{ok: false, error_class: "continues"}` (the existing class and
   portal text). Reason: one long lane must not hold a run's audit event for hours.
6. The registrations live in memory. After a restart every finished run without `mirrored_at` is registered again
   by the first round, so it gets its results from the first lanes after the restart; the guard
   `mirrored_at IS NULL` of the write keeps "exactly one event per run".
7. The skip list of the note 2026-11-07 c is no longer needed: a run recorded after a round's index is registered
   by the next round. The Fleet watcher of that note MAY be removed, because the next round seals the dump one
   round interval later; if it stays, it MUST NOT wait for a lane.

### C5 A lane reads only completed sets

1. A lane reads from the local repository only paths of its snapshot, plus pgBackRest's label directories under
   the existing rule (skipped until `backup.manifest` exists, A3 step 3). It puts the snapshot's `manifest.json`
   bytes in step 5, never the file a later round wrote.
2. Every file the role itself writes into the set (`openbao/`, `fleet/`, `escrow/`, `manifest.json`) MUST appear
   under its final name only when complete (write to a temporary name in the same directory, then rename).
   pgBackRest writes its own files that way. With that, the snapshot is the lock: no further lock is taken between
   the round and the lanes.
3. A path of the snapshot that a later round's expire removed is skipped (the existing `fs.ErrNotExist` rule). A
   path rewritten meanwhile is verified against the bytes actually put (step 4, unchanged).
4. The D-rules are decided against the snapshot. That is safe while the lane runs: the local set only gains newer
   fulls, and what a rule allowed to delete at the snapshot stays expired; after a lost local repository the lane's
   own puts and verify precede its deletions, so the target keeps a restorable copy (A4 L1–L3 unchanged for the
   next lane, whose guard sees the shrunk set).

### C6 Target tests

A requested connection test runs in the round with its own timeout, opens its own connection and never waits for a
lane, also when the target's lane is in flight. Its result is written by the round as before (decision 11).

### C7 Shutdown and restart

- Shutdown cancels every lane and waits for them at most 10 seconds; a call blocked in a file system returns
  later on its own. Nothing is recorded for a cancelled lane.
- A restart needs no lane state: every step of the mirror is idempotent (A3 step 3), the next lane lists the
  target again, in-place rewritten files are put again once, and the runs are registered again (C4.6).
- With more than one backup role process, only the leader's rounds start lanes (C3.1, C3.7). The supported
  topology stays one process.

### C8 Consequences for earlier texts

- A7: "round budget" reads "the lane's copy budget". The note 2026-11-07: listings and step 6 hold the target's
  lane, not the role. B3's trade-off and RR-132: a hung page holds the lane, not the round.
- RR-127: a key confirmation takes effect in the next round, at most one round interval later; it no longer waits
  for a copy. A lane in flight ends on its snapshot with the previous key's path; the new path follows with the
  target's next lane.
- No schema change, no API change, no portal change, no new dependency.

### C9 Tests (`server/internal/backuprole`; names free, one test per row; all with `-race`)

| # | Asserts |
| --- | --- |
| 1 | With a fake S3 target whose listing hangs while the endpoint answers probes: a round returns within its own work; in the following rounds a requested run of every kind is answered, a due OpenBao snapshot is taken, a key change reaches `schedule.env` and the key file, and a requested target test of that same target gets its result |
| 2 | The same with a listing that is slow but completes: the lane ends, the target status is written once, by the lane |
| 3 | At most one lane per target: ten rounds during one lane start no second one; a second target's lane runs and finishes meanwhile |
| 4 | C4.3: a run recorded while a lane is in flight is not marked mirrored by that lane, but by the next one; its audit event is emitted exactly once |
| 5 | C4.5: a run awaiting a target for 60 minutes (fake clock) is recorded with `continues` for that target |
| 6 | C4.6: an engine created anew with an unmirrored run in the store registers it and records it after the first lanes |
| 7 | C3.7 and C7: disabling a target, a round without the leader lock and shutdown each cancel the lane; a cancelled lane writes no status and no run result; shutdown returns within the wait although a lane's call blocks |
| 8 | C5: a lane puts the snapshot's `manifest.json` although a later round rewrote the local one; a snapshot path removed by a later expire is skipped |
| 9 | The invariants under lanes: the existing mirror tests (A6 L1–L12, `TestMirrorInvariants`, the tests of B6) run unchanged against the lane entry point and stay green; in particular no deletion happens on a listing that did not complete, and none outside the lane |
| 10 | An abandoned lane: its result is recorded, and no new lane starts until its call returned |

Gates after the fix: `TestBackupRuns`, `TestBackupRotation`, `TestBackupTargets`, the key confirmation and restore
plan gates MUST be green on a development stack whose S3 target answers its listing slower than one round interval.
No gate is weakened.

### C10 Acceptance criteria

- **AC-1 (platform administrator):** given a target whose mirror takes longer than an hour, when the administrator
  requests a backup in the portal or with `./paddock backup now`, then every kind's run leaves `requested` within
  two round intervals plus the kind's own duration, and `backup now --wait` returns.
- **AC-2 (platform administrator):** given the same target, when a new backup key is confirmed, then the next full
  backup uses the new key's path within one round interval, and a requested test of any target shows its result
  within the portal's 60 seconds.
- **AC-3 (operator):** given the same target, then OpenBao snapshots and Fleet dumps appear at their intervals in
  `./paddock backup status`, and the gauge of C3.8 shows since when that target's mirror runs.
- **AC-4 (auditor):** every finished run has exactly one `platform.backup_completed` or `platform.backup_failed`,
  at the latest 60 minutes after the round that registered it, also across a restart of the role.
- **AC-5 (operator):** given a restart of the role during a mirror, then the target's copy is completed by the next
  lane, and nothing was deleted on the target that the D-rules do not allow.

### C11 Freedoms, stop conditions, open points

- Free: the type and function names of lanes and of the registration, the shape of the store call that records a
  run's results, whether the Fleet watcher stays (C4.7), the log wording.
- Stop and report: a writer of the set that cannot write by rename (C5.2); a need for a schema, API or portal
  change; any deletion on a target outside its lane; a need to bound step 6 (PDK-869).
- Open, default chosen: (1) the await limit of 60 minutes (C4.5); a longer limit delays audit events, a shorter one
  records more runs with `continues`. (2) A lane in flight is visible to an operator only through the gauge and the
  log; showing it in `./paddock backup status` and the portal needs a column and an API field (later release).

### Correction 2026-11-11 — the lane amendment aligned with PDK-989 as built (commit `f8fbb732`, in review)

The amendment above was written before the implementation existed. PDK-989 solved four points differently; three
are adopted because they are simpler or safer, and two points of the amendment stay binding although the code does
not meet them yet. Where this correction contradicts C3–C11, it wins.

**Adopted from the implementation (replaces the text named):**

1. **C4, mirror passes instead of awaited targets.** A round creates one **mirror pass**: it covers the finished
   runs without `mirrored_at` at that moment, minus the runs an open pass still covers. Per target the pass takes:
   the result of the lane this round started; `continues` at once when the target's lane is still mirroring an
   earlier set (its index lacks the pass's runs); `not_mounted` or `io` at once for a volume that is not mounted or
   unreachable. Phase 2 of a pass (the per-target results, `mirrored_at` and the one audit event of each of its
   runs) runs exactly once, when the last of its lanes ended. A pass stays open until then, so no run is covered
   twice. C4.2–C4.6 and the await limit of 60 minutes (C4.5, C9 row 5, AC-4's bound, open point 1) are **dropped**:
   a run recorded while a target is busy gets `continues` for that target at once and is not held. Only the runs of
   the pass that started a long lane wait for that lane, as they did before lanes.
2. **C5.3, the local expire waits for lanes.** The role's own expire (A2: OpenBao and Fleet files, escrow copies, a
   retired path as a whole) MUST NOT remove a file that the index of a lane in flight holds, nor a retired path
   such an index holds; they go in the first round after that lane ended. pgBackRest's own expire is not held back;
   a file it removed is skipped by the lane as before. This is stricter than "skip what vanished" and replaces it.
3. **C5.1, the manifest.** The lane reads the local `manifest.json` once, at its start, and it must still be the
   file its index holds (size and modification time); if a later round already replaced it, the lane ends with
   `continues` and the next lane takes the newer set. The bytes read at the start are the ones put in step 5.
4. **C3.7 and C7, leader lock and shutdown.** Lanes run outside the round's leader lock and are not cancelled by a
   round that did not obtain it: the backup role is a single instance by construction (one local repository volume,
   one runtime volume), and a lock per lane would need a database connection per lane. At shutdown the lanes are
   cancelled and `Run` returns once they returned; the 10-second bound of C7 is dropped. A shutdown-cancelled lane
   records nothing and its pass is dropped; the first pass after a restart covers every run still without
   `mirrored_at`.
5. **C1 and C9 row 10, abandoned lanes.** A mirror call still blocked in the file system after the watchdog gave up
   is tracked as before: the target's next lane ends at once with "the previous mirror has not returned" (class
   `io`) until the call returned.
6. **C4.7.** The Fleet watcher and the skip list of the note 2026-11-07 c are removed; the next round seals the
   dump. A failed phase-2 write is logged and no longer fails the round.

**Still binding, not in `f8fbb732` (PDK-989 MUST add them before it merges, each with a test):**

7. **C3.7, a disabled or deleted target.** When a round finds a target disabled or deleted whose lane is in flight,
   it cancels that lane. A cancelled lane writes no status and no result; its pass takes no result for that target.
   Reason: an administrator who disables or deletes a target expects Paddock to stop writing to it and deleting on
   it, and a lane can run for hours.
8. **C3.8, the gauge** `paddock_backup_target_mirror_started_timestamp_seconds{target}` (the start of the lane in
   flight, absent without one). It is the only way an operator sees that a target's copy has been running for
   hours; RR-132 names it. `docs/operations/monitoring.md` lists it with the other backup metrics.

**Unchanged:** C0, C2, C3.1–C3.6, C5.2, C5.4, C6, C8, the gates, AC-1 to AC-3 and AC-5. AC-4 reads: every finished
run has exactly one `platform.backup_completed` or `platform.backup_failed`, also across a restart of the role.
Tests as built (`lanes_test.go`): `TestHangingLaneDoesNotDelayTheRound`, `TestSlowTargetDoesNotHoldTheFastOne`,
`TestShutdownCancelsLanesAndRestartResumes`, `TestLocalExpireWaitsForLane`, `TestLanePrunesOnlyByThePDK972Rules`;
they cover C9 rows 1–4 and 6–9 in the form of this correction.
