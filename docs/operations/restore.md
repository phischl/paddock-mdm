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
- **Fleet**: `fleet-backup` dumps Fleet's MySQL once a day into a volume, `fleet-backup-upload` copies it to the bucket.

Every worker exports `paddock_backup_last_success_timestamp_seconds{kind="postgres|authentik|openbao|fleet"}`, the
time of the newest object of each kind in the bucket; the alert `PaddockBackupStale` fires when one is older than
26 hours (`docs/operations/monitoring.md`).

Commands (in the control plane's bundle directory, `docs/operations/install.md`):

```sh
./paddock compose run --rm --no-deps pgbackrest backup --start-fast # full backup of paddock now (pgbackrest-authentik: Authentik)
./paddock compose run --rm --no-deps pgbackrest info                # pgbackrest info of the stanza
./paddock compose run --rm --no-deps paddock-worker backup openbao  # OpenBao snapshot now
./paddock compose run --rm --no-deps fleet-backup once              # Fleet dump now; fleet-backup-upload uploads it within a minute
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
