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
local: path absolute, no "..", ≤ 256 bytes (a host directory; must exist on the host — checked by apply)
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
