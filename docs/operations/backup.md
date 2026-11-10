# Backups

How the control plane is backed up, where the backups go and how a platform administrator and an operator run them
(plan M15, ADR 0046, architecture §20). Bringing a lost installation back is `docs/operations/restore.md`. The audit
store is **not** part of the backup: it is protected by WORM and its replica (`docs/operations/audit-bucket.md`).

## What is backed up

| Data (kind) | Method | RPO | RTO |
| --- | --- | --- | --- |
| PostgreSQL `paddock` (`postgres`), Authentik database (`authentik`) | pgBackRest: continuous WAL archive and a full backup every 24 hours by default, 14 full backups kept | 5 min | 4 h |
| OpenBao (`openbao`) | encrypted Raft snapshot every 6 hours by default and after every key operation you take by hand | 6 h | 4 h |
| Fleet MySQL (`fleet`) | encrypted dump every 24 hours by default; rebuildable from the devices | 24 h | 8 h |
| Escrowed LUKS headers (`escrow`) | the escrow bucket's objects, copied into the set every hour by default (they are already sealed to `escrow-wrap`) | 1 h | 4 h |
| Bundles bucket, Valkey | not backed up; rebuilt by the restore (`admin recompile --all`, `admin rebuild-cache`) | – | 1 h |
| RabbitMQ | not backed up; definitions are code, devices re-send | – | – |

The RTO figures are the targets that cover a rebuilt host, the custodians' arrival and the copy of the set; the
measured technical part of a restore is in the drill table of `docs/operations/restore.md`.

Valkey persists with AOF and `appendfsync everysec`, so a Valkey crash can lose up to about one second of writes,
including the check-in sequence counters (`seq:<device>`). A counter that is missing entirely is restored to
`device_status.last_seq`, and its device gets a retryable 503 until then; a counter that survived is never changed. A
rolled-back counter reissues numbers until it catches up, which weakens clone detection for the device meanwhile
(residual risk RR-97, no operator action).

## The pieces

- **Local repository.** pgBackRest writes to the Docker volume `backup-repo` of the control-plane host (or of the
  lab host with `PADDOCK_LAB_BACKUP=yes`): the pgBackRest repository, sealed OpenBao snapshots, sealed Fleet dumps and
  the escrow objects. This is the **backup set**.
- **The backup role** `paddock-backup` (`paddock-server serve backup`, database role `paddock_backup`, AppRole
  `paddock-backup`) is the only process that decrypts the backup key. It takes the OpenBao snapshots, seals the Fleet
  dumps, copies the escrow objects into the set, writes `manifest.json` and **mirrors the whole set to every enabled
  target**. It runs a round every minute. Each target is mirrored in its own lane, which the round starts but never
  waits for: a slow or unreachable target never delays the local backups, `backup now`, a key confirmation, a
  connection test or the other targets. Nothing is backed up until a platform administrator has confirmed a key.
- **Targets** are the places that hold a copy of the set: a local directory, an SMB share, an NFS export or an
  S3-compatible bucket. A target outage never touches the WAL archive or the control plane: pgBackRest only ever
  writes to the local repository.
- **The key** protects every backup. Paddock generates it, shows it once and trusts it only after a confirmation.

A platform administrator manages targets, key, schedule and runs in the portal under *Platform* → *Backup* (tabs
*Overview*, *Targets*, *Key*, *Schedule*, *History* and *Restore*), every change with a step-up and audited. The host
commands below are the emergency path that works without the portal.

### The backup set

Every target holds the same directory tree, `paddock-backup/` (format `paddock.backup-set.v1`):

```
paddock-backup/
  manifest.json                              installation, key ID and fingerprint, schema versions, contents
  pgbackrest/<key_id>/archive/<stanza>/…     pgBackRest repository, aes-256-cbc with the key
  pgbackrest/<key_id>/backup/<stanza>/…
  openbao/<UTC time>.snap.enc                Raft snapshot, AES-256-GCM (paddock-server backup decrypt)
  fleet/<UTC time>.sql.gz.enc                mysqldump, gzip, AES-256-GCM (paddock-server backup decrypt)
  escrow/org/<org>/devices/<device>/…        the escrow bucket's objects, unchanged
```

On an S3 target the tree lives below `<prefix>/paddock-backup/` of the bucket. One directory of it, or a tarball
`paddock-backup-set-*.tar` of it, is enough for a restore.

## The backup key

Paddock protects every backup with one AES-256 key. Without it no backup can be read, and a lost control-plane host
takes its copy with it, so **keep a copy outside the server**, with the OpenBao unseal shares: a password manager, a
printed copy in a safe.

1. *Generate.* A platform administrator opens *Backup* → *Key* and starts the dialog (step-up). Paddock shows the key
   (44 base64 characters) **exactly once**, with *Copy* and *Download* (`paddock-backup-key-<id>.txt`). It is never
   shown again, not in the portal, the API, a log or an audit event (`POST /api/platform/v1/backup/key`).
2. *Confirm.* The dialog names six positions of the key and asks for the characters there. The answer proves that the
   copy exists and was readable. After three wrong answers the key is discarded and a new one must be generated; a
   wrong answer is audited with the attempts used. Until a key is confirmed, **no backup of any kind runs**, the
   overview says so, `POST /api/platform/v1/backup/run` is refused with 409 and the alert
   `PaddockBackupKeyUnconfirmed` fires after an hour. The dialog cannot be closed between showing and confirming the
   key without the explicit action *I did not store the key — discard it*.
3. *Rotate.* A new key confirmed while one is active retires the old one (it stays decryptable for old sets). pgBackRest
   cannot change the cipher pass of an existing repository, so a rotation opens a new repository path
   `pgbackrest/<new key_id>/` and takes a full backup at once; the old path stays until its retention has passed
   (below).

The stored key is encrypted with the Transit key `backup-wrap`: the api may only encrypt, the backup role alone
decrypts. The confirmation proves six characters, not a safe place (residual risk RR-100).

**Existing installations and the host key file.** A fresh installation has no host key file: `./paddock secrets` does
not write one, the control plane starts without a key, and a platform administrator generates it on the *Key* tab. An
installation upgraded from 0.1.0-alpha.8 keeps its `.secrets/backup_encryption_key` (copied by `migrate-from`). While
that file exists on a control-plane host or a lab host with backups, `./paddock` adds `compose.backup-legacy-key.yaml`,
which mounts it into `paddock-api`, and the api imports it once at its start, when no key exists, as the key `legacy`,
state `unconfirmed`; the *Key* tab shows it as imported from the host file and asks for the characters at six positions
of the file's text. No backup runs until it is confirmed. Alternatively discard it and generate a new key (only one
unconfirmed key can exist). A file that is present but unreadable, empty or not a key stops the api. After the
confirmation the file is only a second copy of key material on the host, which `./paddock check` lists as the warning
`backup: legacy key import` and the api logs at its start; once a copy of the key is kept outside the host, move the
file off the host and run `./paddock up`, which then leaves the import out. Import happens once and only while no key
exists.

## Targets

*Backup* → *Targets* lists the targets (search, filters, sorting) and adds, edits, tests, enables, disables and
deletes them; delete asks for the target's name. A target's credentials (SMB login, S3 keys) are write-only: stored
encrypted, never shown or returned again. An edit without new credentials keeps the stored ones, but a change of the
host, share, domain, username or options of an SMB target, or of the endpoint, bucket, region or CA of an S3 target,
requires the credentials again (400 otherwise), so stored credentials can never be redirected.

| Type | Fields | The backup role writes to |
| --- | --- | --- |
| `local` | `path`: a **relative subpath** below `PADDOCK_BACKUP_LOCAL_ROOT` on the host (default `/srv/paddock-backup`); no absolute path, no `..` | the directory, mounted as a Docker volume |
| `smb` | host, share, optional path, username, password, optional domain, optional mount options (`vers=3.0`/`3.1.1`, `seal`, `noperm`, `cache=none`/`strict`, `actimeo=N`) | the share, mounted as a Docker volume |
| `nfs` | host, export, optional path, optional mount options (`vers=4`/`4.1`/`4.2`, `hard`, `timeo=N`, `retrans=N`, `nconnect=N`) | the export, mounted as a Docker volume |
| `s3` | endpoint (https, no user information), bucket, region (default `us-east-1`), optional prefix, access key, secret key, optional CA (PEM) | `<prefix>/paddock-backup/` of the bucket |

An S3 endpoint is checked like every outbound address of the api (the deny list of ADR 0031, `docs/operations/notifications.md`
"URLs"): private and link-local addresses are refused, so an S3 endpoint on a private address cannot be a production
target; use a local, SMB or NFS target for storage inside your network. An SMB password must not contain a comma or
whitespace (it travels inside Docker's mount options); the portal refuses it with a message to choose another password.

### The host step for local, SMB and NFS targets

A container cannot mount a share, so these three types need one host step after the portal step. The target is listed
as `pending_host` until it is done:

```sh
./paddock backup-target apply     # renders compose.backup-targets.yaml, mounts every target once as a test
./paddock up                      # recreates paddock-backup with the volumes; the target turns "mounted" within a minute
```

`apply` reads the targets from the database, writes the host-local file `compose.backup-targets.yaml` (mode 0600, **it
holds the SMB passwords**: never copy, commit or print it; `./paddock migrate-from` carries it to a new version and
`./paddock compose config` refuses to print while it is in use), tries every mount before it replaces the previous file,
and removes the volumes of changed and deleted targets once they are unused. A local target's directory must exist
below `PADDOCK_BACKUP_LOCAL_ROOT` (root-owned, not writable by group or others; `./paddock check` verifies it),
every component a real directory and no symlink, and be writable by uid 999. `apply` is refused while a restore plan
runs. Without `compose.backup-targets.yaml` the stack runs, but `paddock-backup` has no volumes for those targets.

Use a dedicated SMB account with write access to the backup share only: members of the `docker` group can read the
password with `docker volume inspect` (residual risk RR-122).

### S3 targets

No host step. The credential needs list, read, write and delete below `<prefix>/` of the bucket (the mirror deletes what
retention removes and the connection test writes and deletes `<prefix>/.paddock-test`). **Object Lock stays off**:
pgBackRest and the mirror must be able to expire. Versioning is welcome (an overwritten or deleted object stays as a
noncurrent version, so one compromised credential cannot destroy every copy); expire noncurrent versions after 30 days
and remove expired delete markers. Without that rule, the bucket never frees the space of what the mirror deletes,
and the listing slows down with every deleted object, because some S3 servers walk them all before they return a
page. Paddock cannot check the rule for you, because the target's credential does not need the bucket-level
permissions to read it.
Keep the credentials of each target separate from every other use.

For a restore without a database, export the target with its credentials and keep the file offline with the key:

```sh
./paddock backup-target export <name|id> <file>      # S3 targets only; the file is 0600, an existing file is refused
```

### Status of a target

Each target shows its host state (`n/a` for S3, `pending_host`, `mounted`, `unreachable`), the result of the last
connection test and, per kind, when the last mirror succeeded. *Test* is asynchronous (the api never decrypts
credentials): the backup role runs it in its next round and the portal polls for up to 60 seconds. A failure shows its
class only, never the remote answer:

| Class | Meaning |
| --- | --- |
| `dns`, `dial`, `tls` | the name does not resolve, the connection fails, the certificate is not trusted |
| `auth`, `forbidden` | the credentials are refused, or valid but not allowed to write there |
| `not_mounted`, `read_only` | the volume is not mounted (run `./paddock backup-target apply` and `./paddock up`), or it is mounted read-only |
| `io` | a write failed, the disk is full, or the target copied slower than the minimum rate past its time budget (below); a mirror that only used its budget is no error and shows *continues next round* |
| `foreign_set` | the target holds the set of another installation: nothing is written or deleted; empty the target's `paddock-backup/` first to reuse it |
| `set_shrunk` | writing would make the target's copy unrestorable (after a lost local repository); nothing is written or deleted (`docs/operations/restore.md`, "Lost local backup repository") |
| `unknown_path` | the target holds a repository path no key names (`./paddock backup status` notes it, the role's log names the path): the copy and the deletions by the rules below go on, the path itself is kept until you remove it by hand |
| `size_mismatch` | a file copied in this round has another size on the target |

**The first copy of a large set is slow.** The role mirrors all targets at the same time, at most one mirror per
target, and a mirror copies for at most 10 minutes (a trickling target is cut off after a little longer). A target that
has not finished stops after the file it is copying, keeps its previous `manifest.json` and **goes on in the next
round**, so the initial sync of a large set over a WAN link spans several rounds. Listing a large target can take
longer than a round; meanwhile the later rounds' backups wait for that target's next mirror, which carries them,
and get their mirror results and audit event when it ended. The target is not current until it has finished: `./paddock backup status`
and the *Overview* grid show per target and kind when its last mirror succeeded. A file the local retention would
remove stays in the local repository while a mirror still copies the set that holds it, and goes in the first round
after that mirror ended.

## Schedule and retention

*Backup* → *Schedule* (`GET`/`PUT /api/platform/v1/backup/schedule`; without a saved schedule the defaults apply):

| Setting | Default | Range |
| --- | --- | --- |
| full backup interval of both databases (`full_interval_hours`) | 24 | 6–168 |
| OpenBao snapshot interval (`openbao_interval_hours`) | 6 | 1–24 |
| Fleet dump interval (`fleet_interval_hours`) | 24 | 6–168 |
| escrow copy interval (`escrow_interval_hours`) | 1 | 1–24 |
| pgBackRest full backups kept (`retention_full`) | 14 | 2–60 |
| days OpenBao snapshots are kept (`openbao_keep_days`) | 30 | 7–365 |
| days Fleet dumps are kept (`fleet_keep_days`) | 30 | 7–365 |

## Running a backup now

Without the portal, in the bundle directory of the control plane (or of a lab host with `PADDOCK_LAB_BACKUP=yes`):

```sh
./paddock backup now [--kind postgres|authentik|openbao|fleet|escrow]… [--label <text>] [--wait]
./paddock backup status
```

`now` requests a run of every kind or the named ones, the same way the portal's *Back up now* does (it is refused
while no key is confirmed); `--wait` follows the runs for up to 30 minutes and exits non-zero naming a failed kind. A
`postgres` or `authentik` run asks pgBackRest for a full backup at once. `status` prints the key, the newest run per
kind and the targets. Take a backup by hand after every OpenBao key operation (`docs/operations/openbao.md` section 5):

```sh
./paddock backup now --kind openbao --wait
```

Single steps of the services, for diagnosis:

```sh
./paddock compose run --rm --no-deps pgbackrest info                # pgBackRest info of the stanza paddock (pgbackrest-authentik: Authentik)
./paddock compose run --rm --no-deps pgbackrest backup --start-fast # a full backup of paddock without the role
./paddock compose run --rm --no-deps pgbackrest verify              # see "How pgBackRest runs" below
./paddock compose run --rm --no-deps fleet-backup once              # Fleet dump now; the backup role seals it within a minute
```

## How the backups run

The overlay `deploy/compose/compose.backup.yaml` is part of the production configuration of the control plane, and of
the lab with `PADDOCK_LAB_BACKUP=yes`.

### How pgBackRest runs

`postgres` and `authentik-postgres` run with `archive_mode=on` and `archive_timeout=60`. Their image has no
pgBackRest, so `archive_command` copies every WAL file into a spool volume; `pgbackrest` and `pgbackrest-authentik`
push it to the local repository every 2 seconds and take a full backup when the last one is older than the full
interval. They read the data directory and the socket of their database through shared volumes; pgBackRest needs the
data directory at the path the server reports (`/var/lib/postgresql/18/docker` inside the volume). They wait for the
key: the backup role hands it to them through a tmpfs volume, and without a confirmed key they take nothing. Every full
backup is read back with `pgbackrest verify` and counts only when it is intact. When the verify of the whole stanza
after a full backup takes longer than 15 minutes, only the new backup is verified and the targets keep every WAL
segment (`PaddockBackupTargetHolding` fires after a week); then run `./paddock compose run --rm --no-deps pgbackrest
verify` (and `pgbackrest-authentik verify`): it waits for a running backup, holds the stanza so that no full backup
starts beside it, verifies the whole stanza without a time limit, and when that reports ok the backup role releases
the held WAL in its next round. The stanza's lock lives in its state volume, so a backup taken by hand waits for a
running scheduled one. When the repository holds the stanza for another cluster (a fresh installation into a kept
repository, or a host being restored), the service refuses it, logs why and takes no backup. On a host being
restored, restore first and never run `stanza-upgrade`.

### The other kinds

- **OpenBao**: the backup role takes a snapshot when the newest one is older than the interval (AppRole
  `paddock-backup`: read on `sys/storage/raft/snapshot` and decrypt with `backup-wrap`), seals it with AES-256-GCM and
  writes `openbao/<UTC time>.snap.enc`.
- **Fleet**: `fleet-backup` dumps Fleet's MySQL into a volume when the backup role asks for it; the role seals the
  dump into the set and deletes the plaintext. A dump it cannot seal (repository full, no confirmed key) is tried again
  every 15 minutes and deleted unsealed after 6 hours, so a plaintext dump never lives longer; a request `fleet-backup`
  does not answer within an hour fails as `timeout`.
- **Escrow**: the role copies the escrow bucket's objects it does not yet hold, with its own read-only credential
  `rustfs_escrow_backup_*`. A header is never deleted from the set because it vanished from the bucket (below).

### What the mirror copies and what it deletes

The mirror follows one rule: **a target loses only what the local retention would have removed from the target's own
copy**. The local set is the reference for what is newer; it is never the reason to delete. In every round and for
every target, in this order: it reads the target's `manifest.json` and refuses a target of another installation
(`foreign_set`, nothing written); it lists the target; it checks that writing would not make the target's copy
unrestorable (`set_shrunk`, nothing written, nothing deleted, the target counts as unreachable and
`PaddockBackupTargetUnreachable` fires after 30 minutes); it copies every file the target lacks (WAL, then full backups
with `backup.manifest` last, then snapshots, dumps and escrow objects, then pgBackRest's info files, then
`manifest.json`); it verifies the sizes; and only then it deletes, by these rules:

| Object on the target that the local set lacks | Deleted when | Otherwise |
| --- | --- | --- |
| A completed full backup | the local stanza holds `retention_full` completed full backups newer than it (pgBackRest's own retention) | the target is `set_shrunk` (nothing written, nothing deleted) |
| A WAL segment | the local stanza holds `retention_full` newer fulls, the segment lies below the oldest WAL the local archive holds, and the local archive is contiguous and verified | kept ("held") |
| pgBackRest's info files | never | re-copied when they changed locally |
| An OpenBao snapshot or a Fleet dump | older than its keep days, not the newest of its kind on the target, and the local set holds at least one file of that kind | kept |
| An escrowed LUKS header | the escrow bucket no longer holds it (checked in the same round), the audit trail records a successful Destroy of its device (`device.escrow_destroyed`) that is not older than the copy (the escrow object's time recorded in the local set's manifest), and `retention_full` full intervals have passed since that Destroy | kept ("held"); absence from the bucket alone never deletes |
| The repository of a retired backup key | the active key's repository holds a full backup of every stanza and the target's copy is older than `retention_full` full intervals (counted from the rotation at the earliest) | kept |
| Anything else (unknown paths, a repository the database does not know) | never | kept; an unknown repository path marks the target run as `unknown_path`, but every other deletion still runs |

The same escrow rule applies to the local set. A bucket listing that lacks all, or more than 10 %, of the local set's
headers without a Destroy behind them (a lost RustFS volume whose bucket was re-created empty, a wrong
`PADDOCK_ESCROW_S3_BUCKET`) is suspicious: the role copies nothing from that bucket, deletes no header anywhere, fails
the escrow run and raises `PaddockBackupEscrowListingSuspicious`. Fewer such absences are held, logged once when they
change and counted in `paddock_backup_escrow_unevidenced_missing`; they never leave the set on their own.

Held objects are counted per target (`paddock_backup_target_held_files{target}`); a hold is not an error and never
stops the copying. Nothing is deleted because `manifest.json` no longer names it. The cases of a lost local
repository are in `docs/operations/restore.md`.

**Deletion lag.** A row that a retention purge deletes still exists in the backups until their retention has passed
(14 full backups by default, OpenBao snapshots and Fleet dumps 30 days), and a restore brings it back until the next
purge run deletes it again (ADR 0032, residual risk RR-94).

## Sizing

The local repository `backup-repo` lives on the control-plane host, so plan its disk
(`docs/operations/capacity.md`, "Backup repository"): about `retention_full` times one full backup of both databases,
plus their WAL, plus the OpenBao snapshots and Fleet dumps of their keep days, plus the escrow objects. A rotation keeps the previous key's repository until its retention has passed (a second full
set meanwhile). The alert `PaddockBackupRepoFull` fires below 10 % free space; pgBackRest and the backup role stop
writing when the volume is full, so free space or lower `retention_full` in *Schedule*. `./paddock check` verifies
that `/backup-repo` is the named volume `backup-repo` everywhere and the local target root. Residual risk RR-102.

## Monitoring

The backup role exports `paddock_backup_last_success_timestamp_seconds{kind,target}` (target `repo` is the local
repository), `paddock_backup_target_reachable{target}`, `paddock_backup_target_held_files{target}`,
`paddock_backup_key_confirmed`, `paddock_backup_runs_total{kind,outcome}`, `paddock_backup_repo_bytes{what}`,
`paddock_backup_wal_last_archived_timestamp_seconds{stanza}`, `paddock_backup_escrow_unevidenced_missing`,
`paddock_backup_escrow_listing_suspicious`, `paddock_backup_leader` (1 while the process holds the role's leader lock)
and `paddock_backup_leader_lost_total`. Only the process that holds the leader lock runs rounds and mirrors; it holds
the lock on one database connection for its whole life. When that connection stops answering, it stops its rounds and
mirrors before writing anything more, logs `backup role lost its leader lock` and takes the lock again once it is
free; the runs it had not finished are mirrored by the next leader. The alerts `PaddockBackupStale`, `PaddockBackupAgeMissing`,
`PaddockWALArchiveLag`, `PaddockWALArchiveLagMissing`, `PaddockBackupKeyUnconfirmed`,
`PaddockBackupTargetUnreachable`, `PaddockBackupTargetHolding`, `PaddockBackupEscrowListingSuspicious` and
`PaddockBackupRepoFull` are in `docs/operations/monitoring.md`.

## Audit

Every portal action and every host action is one audit event; no key, password or access key is ever a parameter.

| Event | When |
| --- | --- |
| `platform.backup_key_generated`, `_confirmed`, `_discarded` | the key flow (also the import of the legacy key, actor `paddock-api`) |
| `platform.backup_target_created`, `_updated`, `_deleted`, `_tested` | target changes (`_tested` means a test was requested) |
| `platform.backup_schedule_changed` | the schedule |
| `platform.backup_run_requested` | the portal's or the host's *back up now* |
| `platform.backup_completed`, `platform.backup_failed` | one per run of a kind, written by the backup role (`paddock-backup`) with the number of targets that succeeded and failed |
| `platform.restore_planned`, `_cancelled`, `_started`, `_completed`, `_failed`, `_abandoned` | restore plans and restores (`docs/operations/restore.md`) |

## API

All under `/api/platform/v1/backup`; platform administrators only (every organization session or token gets 403);
every write needs a step-up, which an API token can never satisfy. Lists follow the list contract.

| Endpoint | Purpose |
| --- | --- |
| `GET /backup` | overview: key state, schedule, targets, repository usage, the newest run per kind |
| `GET /backup/key`, `POST /backup/key`, `POST /backup/key/{id}/confirm`, `POST /backup/key/{id}/discard` | the key flow |
| `GET`, `PUT /backup/schedule` | schedule and retention |
| `GET`, `POST /backup/targets`, `GET`, `PUT`, `DELETE /backup/targets/{id}` | targets |
| `POST /backup/targets/{id}/test`, `/enable`, `/disable` | test (asynchronous), enable, disable |
| `POST /backup/run`, `GET /backup/runs` | request a run (`kinds`, `label`), list runs |
| `GET`, `POST /backup/restore-plans`, `GET /backup/restore-plans/{id}`, `POST …/{id}/cancel`, `POST …/{id}/abandon` | restore plans (`docs/operations/restore.md`) |

## From 0.1.0-alpha.8

The upgrade moves the backup (`docs/operations/upgrade.md`, "0.1.0-alpha.9, from 0.1.0-alpha.8"). In short: the S3
bucket of `PADDOCK_BACKUP_S3_*` is no longer written by anyone; add it, or another bucket, as an S3 target in the
portal and confirm the imported key.
