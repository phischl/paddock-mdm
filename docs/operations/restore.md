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

## Backup bucket

All backups go to one S3 bucket (default `paddock-backup`) that MUST be outside the control-plane host: another
site's object store or an S3 provider. pgBackRest speaks TLS only, so the endpoint is an `https://` URL. Everything is
encrypted on the control plane before it leaves it, with the key in `.secrets/backup_encryption_key` (written by `make
prod-secrets`). **Keep a copy of that key offline with the OpenBao custodians**: a lost control-plane host takes the
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

Give `openbao/` and `fleet/` a lifecycle rule that expires objects after 30 days; pgBackRest keeps 14 full backups
and the WAL they need. In development, `make up BACKUP=1` creates the bucket on the audit host's RustFS
(`deploy/compose/scripts/rustfs-backup-bootstrap.sh`) and reaches it through the TLS proxy `backup-s3-tls`
(`compose.backup.dev.yaml`); run `make dev-secrets` first.

Settings in `.env`: `PADDOCK_BACKUP_S3_ENDPOINT` (https URL), `PADDOCK_BACKUP_S3_BUCKET`, `PADDOCK_BACKUP_S3_REGION`,
`PADDOCK_BACKUP_S3_CA_FILE` (a CA file inside the containers, only for an endpoint with a private CA).

## How the backups run

The overlay `deploy/compose/compose.backup.yaml` (part of the production configuration of the control plane):

- **PostgreSQL** (`postgres`, `authentik-postgres`) runs with `archive_mode=on` and `archive_timeout=60`. Its image has
  no pgBackRest, so `archive_command` copies every WAL file into a spool volume; `pgbackrest` and
  `pgbackrest-authentik` push it to the repository every 2 seconds and take a full backup when the last one is older
  than 24 hours. They read the data directory and the socket of their database through shared volumes.
- **OpenBao**: `paddock-worker` takes a snapshot when the newest one in the bucket is older than 6 hours (AppRole
  `paddock-backup`, read on `sys/storage/raft/snapshot` only), encrypts it and uploads it. After key operations take
  one by hand (`docs/operations/openbao.md` section 5).
- **Fleet**: `fleet-backup` dumps Fleet's MySQL once a day into a volume, `fleet-backup-upload` copies it to the bucket.

Every worker exports `paddock_backup_last_success_timestamp_seconds{kind="postgres|authentik|openbao|fleet"}`, the
time of the newest object of each kind in the bucket; the alert `PaddockBackupStale` fires when one is older than
26 hours (`docs/operations/monitoring.md`).

Commands (with the control plane's Compose files, `pc` in `docs/operations/install.md`):

```sh
pc run --rm --no-deps pgbackrest backup              # full backup of paddock now (pgbackrest-authentik: Authentik)
pc run --rm --no-deps pgbackrest info                # pgbackrest info of the stanza
pc run --rm --no-deps paddock-worker backup openbao  # OpenBao snapshot now
pc run --rm --no-deps fleet-backup once              # Fleet dump now; fleet-backup-upload uploads it within a minute
```

## Restoring the control plane

Use this procedure when the control-plane databases or OpenBao are lost, for example after a host failure. The audit
store is not restored; the audit host keeps running. Commands use the control plane's Compose files (`pc`).

1. **Prepare.** A rebuilt host with the repository, `.env` and `.secrets/` as in `docs/operations/install.md`
   (secrets from your secret store, `backup_encryption_key` from the custodians' offline copy). Three OpenBao
   custodians are available.
2. **Stop the writers.** `pc --profile paddock stop` and `pc stop authentik-server authentik-worker pgbackrest
   pgbackrest-authentik`.
3. **PostgreSQL.** With empty volumes `postgres-data` and `authentik-postgres-data` (remove damaged ones with
   `docker volume rm paddock_postgres-data …`):

   ```sh
   pc run --rm --no-deps pgbackrest restore               # latest point of the WAL archive
   pc run --rm --no-deps pgbackrest-authentik restore
   pc up -d --no-deps postgres authentik-postgres         # replays the staged WAL, then promotes
   pc exec postgres psql -U postgres -Atc 'select pg_is_in_recovery()'   # f when done
   pc up -d --no-deps pgbackrest pgbackrest-authentik
   ```

4. **OpenBao.** Start a fresh OpenBao (empty `openbao-data`), initialize it with a single temporary share, unseal it
   with that share, and restore the newest snapshot (`openbao/<UTC time>.snap.enc`, downloaded with the pgBackRest
   credential):

   ```sh
   pc run --rm --no-deps -T -v "$PWD/snapshot.enc:/in:ro" paddock-worker backup decrypt /in - |
     pc exec -T openbao sh -c 'cat >/tmp/snapshot'
   bao operator raft snapshot restore -force /tmp/snapshot     # with the temporary root token
   pc exec openbao rm /tmp/snapshot
   ```

   The restored node is sealed with the original barrier: three custodians unseal it with their shares
   (`docs/operations/openbao.md` section 2). Policies, AppRoles and keys are those of the snapshot; secret IDs issued
   after it must be issued again.
5. **Paddock.** Start Authentik and the roles except the compiler, then run the restore commands in exactly this order
   (plan M6c decisions 20–22): a restored database can hold older bundle sequence numbers than the devices, which would
   refuse new bundles as downgrades; Valkey's caches and the bundles bucket are rebuilt from PostgreSQL.

   ```sh
   pc up -d --no-deps authentik-server authentik-worker
   pc --profile paddock up -d paddock-api paddock-gateway paddock-worker paddock-outbox-relay paddock-escrow-reader \
     paddock-revocation-issuer
   pc stop paddock-compiler
   pc run --rm --no-deps paddock-worker admin bump-bundle-seq --by 1000000
   pc start paddock-compiler
   pc run --rm --no-deps paddock-worker admin rebuild-cache
   pc run --rm --no-deps paddock-worker admin recompile --all
   ```

   On a rebuilt host where the compiler's container was never created, create it first
   (`pc --profile paddock create paddock-compiler`), so that `start` has a container to start.

6. **Fleet**, if its MySQL is lost: restore the newest `fleet/*.sql.gz.enc` into an empty `fleet-mysql`
   (`openssl enc -d -aes-256-cbc -pbkdf2 -pass file:.secrets/backup_encryption_key -in <file> | gunzip | mysql …`)
   or let the devices rebuild it within 24 hours.
7. **Check.** `make prod-check`, all roles ready (`pc ps`), no firing alerts, a device checks in and receives a new
   bundle version.

## Restore drill (quarterly)

`make restore-drill` runs the whole procedure on the development stack (started with `make up BACKUP=1`, dev-seeded):
full backups and an OpenBao snapshot, then it deletes the volumes of both databases, their WAL spools and OpenBao,
restores them (OpenBao unsealed with the stored development shares), runs the restore commands of step 5 and the
acceptance subset `TestDeviceProtocol|TestLoginGate|TestAuditChain|TestOrganizationIsolation`. It prints the time from
the loss until the control plane is ready and until the subset is green.

| Drill | Control plane ready | Subset green (RTO) |
| --- | --- | --- |
| first drill (gate P-3) | pending | pending |

The stated RTO of 4 hours covers a rebuilt host, the custodians' arrival and the download of the backups; the drill
measures the technical part.
