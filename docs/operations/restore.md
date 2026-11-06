# Backup and restore

What the control plane backs up, where, and how to bring it back (plan M6a, architecture §20, ADR 0016). The audit
store is **not** part of the routine backup or restore: it is protected by WORM and its replica
(`docs/operations/audit-bucket.md`).

| Data | Method | RPO | RTO |
| --- | --- | --- | --- |
| PostgreSQL `paddock`, Authentik DB | pgBackRest: continuous WAL archive + daily full, 14 full backups kept | 5 min | 4 h |
| OpenBao | encrypted Raft snapshot every 6 h and after every key operation | 6 h | 4 h |
| Fleet MySQL | encrypted daily dump; rebuildable from the devices | 24 h | 8 h |
| Escrow bucket | bucket versioning + replication to the backup site (object store feature) | 15 min | 4 h |
| Bundles bucket, Valkey | not backed up; rebuilt (`paddock-server admin recompile --all`, `admin rebuild-cache`) | – | 1 h |
| RabbitMQ | not backed up; definitions are code, devices re-send | – | – |

Valkey persists with AOF and `appendfsync everysec`, so a Valkey crash can lose up to about one second of writes.
This includes the check-in sequence counters (`seq:<device>`), which can then roll back. A counter that is missing
entirely is restored to `device_status.last_seq`, and its device gets a retryable 503 until then; a counter that
survived is never changed. A rolled-back counter, or one restored from a `last_seq` that lagged behind queued
heartbeats, reissues numbers until it catches up, which weakens clone detection for the device meanwhile. This is
the accepted residual risk RR-97 (PDK-475) and needs no operator action.

## Backup bucket

All backups go to one S3 bucket (default `paddock-backup`) that MUST be outside the control-plane host: another
site's object store or an S3 provider. pgBackRest speaks TLS only, so the endpoint is an `https://` URL. Everything is
encrypted on the control plane before it leaves it, with the key in `.secrets/backup_encryption_key` (written by
`./paddock secrets`). **Keep a copy of that key offline with the OpenBao custodians**: a lost control-plane host takes the
only other copy with it, and without the key no backup can be read.

| Prefix | Written by | Content |
| --- | --- | --- |
| `pgbackrest/` | `pgbackrest`, `pgbackrest-authentik` | pgBackRest repository (stanzas `paddock`, `authentik`), `aes-256-cbc` |
| `openbao/` | `paddock-worker` | `<UTC time>.snap.enc`: Raft snapshot, AES-256-GCM (`paddock-server backup decrypt`) |
| `fleet/` | `fleet-backup`, `fleet-backup-upload` | `<UTC time>.sql.gz.enc`: `mysqldump`, gzip, `openssl enc -aes-256-cbc -pbkdf2` |

Create three credentials with these policies (resources `arn:aws:s3:::paddock-backup/…`):

| Credential (secret files) | Allowed |
| --- | --- |
| `backup_pgbackrest_*` | `s3:PutObject`, `s3:GetObject`, `s3:DeleteObject` below `pgbackrest/` (pgBackRest expires old backups itself); `s3:GetObject` below `openbao/` and `fleet/` (the restore uses this credential); `s3:ListBucket` |
| `backup_worker_*` | `s3:PutObject` below `openbao/`; `s3:ListBucket` (the backup age of every kind) |
| `backup_fleet_*` | `s3:PutObject` below `fleet/` |

Operator steps for the bucket:

1. **Enable versioning, with Object Lock off.** The worker's credential may overwrite objects below `openbao/` and
   pgBackRest's may delete below `pgbackrest/` (it expires old backups itself). With versioning, an overwritten or
   deleted object stays as a noncurrent version, so one compromised container cannot destroy every backup of its
   kind. Object Lock stays off: pgBackRest must be able to expire.
2. **Lifecycle rules:** expire noncurrent versions after 30 days (the window in which a destroyed backup can still be
   recovered), and expire current objects below `openbao/` and `fleet/` after 30 days; pgBackRest keeps 14 full
   backups and the WAL they need. In development, `make up BACKUP=1` creates the bucket on the audit host's RustFS
(`deploy/compose/scripts/rustfs-backup-bootstrap.sh`) and reaches it through the TLS proxy `backup-s3-tls`
(`compose.backup.dev.yaml`); run `make dev-secrets` first.

Settings in `.env`: `PADDOCK_BACKUP_S3_ENDPOINT` (https URL), `PADDOCK_BACKUP_S3_BUCKET`, `PADDOCK_BACKUP_S3_REGION`,
`PADDOCK_BACKUP_S3_CA_FILE` (a CA file inside the containers, only for an endpoint with a private CA).

**Deletion lag.** A row that a retention purge deletes still exists in the backups for up to 30 days (14 full backups,
noncurrent versions and `openbao/`, `fleet/` objects expire after 30 days), and a restore brings it back until the next
purge run deletes it again (ADR 0032, residual risk RR-94).

## How the backups run

The overlay `deploy/compose/compose.backup.yaml` (part of the production configuration of the control plane):

- **PostgreSQL** (`postgres`, `authentik-postgres`) runs with `archive_mode=on` and `archive_timeout=60`. Its image has
  no pgBackRest, so `archive_command` copies every WAL file into a spool volume; `pgbackrest` and
  `pgbackrest-authentik` push it to the repository every 2 seconds and take a full backup when the last one is older
  than 24 hours. They read the data directory and the socket of their database through shared volumes; pgBackRest
  needs the data directory at the path the server reports (`/var/lib/postgresql/18/docker` inside the volume). Every
  full backup is read back with `pgbackrest verify` and counts only when it is intact. The stanza's lock lives in its
  state volume, so a backup taken by hand (`./paddock compose run … pgbackrest backup`) waits for a running scheduled one instead of
  running beside it. When the repository holds the stanza for another cluster (a fresh installation into a kept
  bucket, or a host being restored), the service refuses it, logs why and takes no backup. On a host being restored,
  restore first (section "Restoring the control plane") and never run `stanza-upgrade`; only for a fresh installation
  into a deliberately kept bucket the operator runs `./paddock compose run --rm --no-deps pgbackrest stanza-upgrade`
  once (`pgbackrest-authentik` likewise); the old backups stay until retention expires them and cannot be restored into the new cluster.
- **OpenBao**: `paddock-worker` takes a snapshot when the newest one in the bucket is older than 6 hours (AppRole
  `paddock-backup`, read on `sys/storage/raft/snapshot` only), encrypts it and uploads it. After key operations take
  one by hand (`docs/operations/openbao.md` section 5).
- **Fleet**: `fleet-backup` dumps Fleet's MySQL into a volume when the backup role asks for it; the role seals the dump
  with the backup key into the local set and deletes the plaintext. A dump it cannot seal (repository full, no
  confirmed key) is tried again every 15 minutes and deleted unsealed after 6 hours, so a plaintext dump never lives
  longer; a request `fleet-backup` does not answer within an hour fails as `timeout`.
- **Targets**: the backup role never writes or deletes on a target whose `manifest.json` belongs to another
  installation (error class `foreign_set`), nor on one whose copy the local set could no longer restore, as after a
  lost repository volume (`set_shrunk`; the target counts as unreachable, so `PaddockBackupTargetUnreachable` fires
  after 30 minutes). The check reads what the target actually holds, every key's repository and stanza, not only what
  its `manifest.json` names. What a target loses and when is in the next section. To reuse a target of an old
  installation, empty its `paddock-backup/` directory or prefix first.

### Backup targets: what the mirror copies and what it deletes (plan M15, amendment 2026-11-05)

With plan M15 the backups live in one local repository (`backup-repo`) that the role `paddock-backup` mirrors to
every enabled target. The mirror follows one rule: **a target loses only what the local retention would have
removed from the target's own copy**. The local set is the reference for what is newer; it is never the reason to
delete. In every round and for every target, in this order: it reads the target's `manifest.json` and refuses a
target of another installation (`foreign_set`, nothing written); it lists the target; it checks that writing would
not make the target's copy unrestorable (`set_shrunk`, nothing written, nothing deleted, the target counts as
unreachable and `PaddockBackupTargetUnreachable` fires after 30 minutes); it copies every file the target lacks
(WAL, then full backups with `backup.manifest` last, then snapshots, dumps and escrow objects, then pgBackRest's
info files, then `manifest.json`); it verifies the sizes; and only then it deletes, by these rules:

| Object on the target that the local set lacks | Deleted when | Otherwise |
| --- | --- | --- |
| A completed full backup | the local stanza holds `retention_full` completed full backups newer than it (pgBackRest's own retention) | the target is `set_shrunk` (nothing written, nothing deleted) |
| A WAL segment | the local stanza holds `retention_full` newer fulls, the segment lies below the oldest WAL the local archive holds, and the local archive is contiguous and verified | kept ("held") |
| pgBackRest's info files | never | re-copied when they changed locally |
| An OpenBao snapshot or a Fleet dump | older than its keep days, not the newest of its kind on the target, and the local set holds at least one file of that kind | kept |
| An escrowed LUKS header | the escrow bucket no longer holds it (checked in the same round), the database records a successful Destroy of its device (audit `device.escrow_destroyed`) that is not older than the copy (the escrow object's time recorded in the local set's manifest), and `retention_full` full intervals have passed since that Destroy | kept ("held"); absence from the bucket alone never deletes |
| The repository of a retired backup key | the active key's repository holds a full backup of every stanza and the target's copy is older than `retention_full` full intervals (counted from the rotation at the earliest) | kept |
| Anything else (unknown paths, a repository the database does not know) | never | kept; an unknown repository path marks the target run as `unknown_path` |

The same escrow rule applies to the local set. A bucket listing that lacks all, or more than 10 %, of the local
set's headers without a Destroy behind them (a lost RustFS volume whose bucket was re-created empty, a wrong
`PADDOCK_ESCROW_S3_BUCKET`) is suspicious: the role copies nothing from that bucket, deletes no header anywhere, fails
the escrow run and raises `PaddockBackupEscrowListingSuspicious`. Fewer such absences are held, logged once when they
change and counted in `paddock_backup_escrow_unevidenced_missing`; they never leave the set on their own.

Held objects are counted per target (`paddock_backup_target_held_files{target}`); a hold is not an error and never
stops the copying. Nothing is deleted because `manifest.json` no longer names it. The cases of a lost local
repository are in "Lost local backup repository" below.

Every worker exports `paddock_backup_last_success_timestamp_seconds{kind="postgres|authentik|openbao|fleet"}`, the
time of the newest object of each kind in the bucket; the alert `PaddockBackupStale` fires when one is older than
26 hours (`docs/operations/monitoring.md`).

Commands (in the control plane's bundle directory, `docs/operations/install.md`):

```sh
./paddock compose run --rm --no-deps pgbackrest backup --start-fast # full backup of paddock now (pgbackrest-authentik: Authentik)
./paddock compose run --rm --no-deps pgbackrest info                # pgbackrest info of the stanza
./paddock compose run --rm --no-deps paddock-backup backup now --kind openbao --wait  # OpenBao snapshot now
./paddock compose run --rm --no-deps fleet-backup once              # Fleet dump now; the backup role seals it within a minute
```

## Restoring the control plane

Use this procedure when the control-plane databases or OpenBao are lost, for example after a host failure. The audit
store is not restored; the audit host keeps running. Commands run in the control plane's bundle directory.

1. **Prepare.** A rebuilt host with the repository, `.env` and `.secrets/` as in `docs/operations/install.md`
   (secrets from your secret store, `backup_encryption_key` from the custodians' offline copy). Three OpenBao
   custodians are available. Do not run `./paddock up` before step 3, not even `./paddock up --infra`: it starts
   `pgbackrest` against an empty, freshly initialised cluster. Never run `stanza-upgrade` on a host being restored.
2. **Stop the writers.** `./paddock compose --profile paddock stop` and `./paddock compose stop authentik-server authentik-worker pgbackrest
   pgbackrest-authentik`.
3. **PostgreSQL.** With empty volumes `postgres-data` and `authentik-postgres-data` (remove damaged ones with
   `docker volume rm paddock_postgres-data …`):

   ```sh
   ./paddock compose run --rm --no-deps pgbackrest restore               # latest point of the WAL archive
   ./paddock compose run --rm --no-deps pgbackrest-authentik restore
   ./paddock compose up -d --no-deps postgres authentik-postgres         # replays the staged WAL, then promotes
   ./paddock compose exec postgres psql -U postgres -Atc 'select pg_is_in_recovery()'   # f when done
   ./paddock compose up -d --no-deps pgbackrest pgbackrest-authentik
   ```

4. **OpenBao.** Start a fresh OpenBao (empty `openbao-data`), initialize it with a single temporary share, unseal it
   with that share, and restore the newest snapshot (`openbao/<UTC time>.snap.enc`, downloaded with the pgBackRest
   credential):

   ```sh
   ./paddock compose run --rm --no-deps -T -v "$PWD/snapshot.enc:/in:ro" paddock-worker backup decrypt /in - |
     ./paddock compose exec -T openbao sh -c 'cat >/tmp/snapshot'
   bao operator raft snapshot restore -force /tmp/snapshot     # with the temporary root token
   ./paddock compose exec openbao rm /tmp/snapshot
   ./paddock compose restart openbao
   ```

   The restored node is sealed with the original barrier, but until it restarts it keeps the temporary seal
   configuration (one share) and refuses the original shares ("invalid key size 33"). After the restart three
   custodians unseal it with their shares (`docs/operations/openbao.md` section 2). Policies, AppRoles and keys are those of the snapshot; secret IDs issued
   after it must be issued again.

   With automatic unseal (`docs/operations/openbao.md` section 6), the unsealer's attempts against the temporary
   single-share instance fail with `invalid_share` (alerts and audit events show them) until the restored node
   restarts; then it unseals the node automatically, and no custodian is needed for this unseal.
5. **Paddock.** Start Authentik and the roles except the compiler, then run the restore commands in exactly this order
   (plan M6c decisions 20–22): a restored database can hold older bundle sequence numbers than the devices, which would
   refuse new bundles as downgrades; Valkey's caches and the bundles bucket are rebuilt from PostgreSQL.

   ```sh
   ./paddock compose up -d --no-deps authentik-server authentik-worker
   ./paddock compose --profile paddock up -d paddock-api paddock-gateway paddock-worker paddock-outbox-relay paddock-escrow-reader \
     paddock-revocation-issuer
   ./paddock compose stop paddock-compiler
   ./paddock compose run --rm --no-deps paddock-worker admin bump-bundle-seq --by 1000000
   ./paddock compose start paddock-compiler
   ./paddock compose run --rm --no-deps paddock-worker admin rebuild-cache
   ./paddock compose run --rm --no-deps paddock-worker admin recompile --all
   ```

   On a rebuilt host where the compiler's container was never created, create it first
   (`./paddock compose --profile paddock create paddock-compiler`), so that `start` has a container to start.

6. **Fleet**, if its MySQL is lost: restore the newest `fleet/*.sql.gz.enc` into an empty `fleet-mysql`
   (`openssl enc -d -aes-256-cbc -pbkdf2 -pass file:.secrets/backup_encryption_key -in <file> | gunzip | mysql …`)
   or let the devices rebuild it within 24 hours.
7. **Check.** `./paddock check`, all roles ready (`./paddock compose ps`), no firing alerts, a device checks in and receives a new
   bundle version.

## Lost local backup repository (plan M15, amendment 2026-11-05)

The databases are fine, but the `backup-repo` volume or the pgBackRest state volume is gone. What happens and what to do:

| Loss | What the services do | What the targets keep | What you do |
| --- | --- | --- | --- |
| `backup-repo` lost, pgBackRest state kept | `pgbackrest` finds its stanza marker but no stanza in the repository: every full fails and is retried; the role takes snapshots and dumps into the empty repository | everything (the mirror is `set_shrunk`: it writes nothing and deletes nothing) | `./paddock restore --only backup-repo --from <target>`: copies the target's set back into the volume, resets the pgBackRest markers; the next round takes a full and verifies the stanza |
| pgBackRest state lost, `backup-repo` kept | `stanza-create` on the existing repository (idempotent), a full at once | everything; the new full is copied; the oldest full leaves the targets only once `retention_full` newer ones exist | nothing |
| both lost | a stanza is created in the empty repository and a full taken at once | everything, byte for byte, including snapshots and dumps still inside their keep days and the escrow objects (`set_shrunk` until the repository is rebuilt) | `./paddock restore --only backup-repo --from <target>`; the lone new full is discarded with the empty repository |
| only the WAL archive lost or with a gap | fulls continue; `pgbackrest verify` reports the gap, so the stanza is not marked verified | every WAL segment ("held"); new fulls and new WAL are copied | `restore --only backup-repo` from a target, or let the fulls roll: the hold ends when the local archive is contiguous and verified again |
| `openbao/` or `fleet/` partly or wholly lost | the next due snapshot or dump refills the local set | files inside their keep days ("held"); older ones leave by age; the newest copy never leaves | nothing, or `./paddock backup now --kind openbao` |
| the escrow bucket lost or re-created empty, or `PADDOCK_ESCROW_S3_BUCKET` points to another bucket | the escrow listing is suspicious: nothing is copied or deleted, the escrow run fails, `PaddockBackupEscrowListingSuspicious` fires | every escrowed header, locally and on every target | fix the bucket setting, or put the headers back into the bucket (`./paddock restore --only escrow`); the next escrow run is clean again |
| a key was rotated, then the repository was lost | as "both lost" for the new key's path | the old key's repository stays until the new key's repository holds a full of every stanza and the copy is older than the retention | as "both lost" |

`restore --only backup-repo` touches neither database, OpenBao nor Fleet and needs no restore plan; it refuses to run
while a restore plan is `running`. It records `platform.restore_completed` with `components: [backup-repo]`.

## A restore plan stuck in `running`

A restore plan is `running` from the moment the host starts it (`./paddock restore --plan <id>`) until the host reports
`completed` or `failed`. If that report never arrives (the host crashed, or the database was unreachable when the
restore stopped), the plan stays `running`, and only one plan may be approved or running: every new plan is refused
with 409 `invalid_state`. Cancel accepts only approved plans.

1. Make sure the restore really is over: no `./paddock restore` is running on the host, and the stack is in the state
   you expect (`./paddock check`). If the restore stopped half-way, the components it had already overwritten are
   in an unknown state; plan the next restore for them.
2. A platform administrator abandons the plan after a step-up, typing the word `abandon`:
   `POST /api/platform/v1/backup/restore-plans/{id}/abandon` with `{"confirmation": "abandon"}`. The plan becomes
   `abandoned` with `outcome_detail` `abandoned by <administrator>`, and the audit trail records
   `platform.restore_abandoned`. A plan that is not `running` is refused with 409 `invalid_state`.
3. Approve a new plan.

A report the host sends for the abandoned plan afterwards (`paddock-server backup restore-report`) is refused with
`invalid_state` and recorded as a failed `platform.restore_completed` or `platform.restore_failed` event; it never
changes the plan again.

## Restore drill (quarterly)

`make restore-drill` runs the whole procedure on the development stack (started with `make up BACKUP=1`, dev-seeded):
full backups and an OpenBao snapshot, then it deletes the volumes of both databases, their WAL spools and OpenBao,
restores them (OpenBao unsealed with the stored development shares), runs the restore commands of step 5 and the
acceptance subset `TestDeviceProtocol|TestLoginGate|TestAuditChain|TestOrganizationIsolation`. It prints the time from
the loss until the control plane is ready and until the subset is green.

| Drill | Control plane ready | Subset green (RTO) |
| --- | --- | --- |
| first drill (gate P-3): reference machine (`docs/operations/capacity.md`), 2026-10-09, M6-integration `058e769` | 75 s | 150 s |

The stated RTO of 4 hours covers a rebuilt host, the custodians' arrival and the download of the backups; the drill
measures the technical part.
