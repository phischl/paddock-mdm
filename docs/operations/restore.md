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
