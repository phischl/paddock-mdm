# Restore

How to bring the control plane back from a backup set with `./paddock restore` (plan M15, ADR 0046, architecture §20).
What is backed up, where the copies live and how the key works is `docs/operations/backup.md`. The audit store is
**not** restored: it is protected by WORM and its replica (`docs/operations/audit-bucket.md`), and the audit host keeps
running. Every command runs in the bundle directory of the control plane (or of the lab host with
`PADDOCK_LAB_BACKUP=yes`) with `sudo ./paddock restore …`: staging a set hands its files to the backup role's uid 999,
which needs root, and `$SUDO_USER` is the operator's name in the audit event.

| Situation | Scenario | Command |
| --- | --- | --- |
| The host or its volumes are lost; the installation is rebuilt from the bundle | [Fresh installation](#scenario-1-fresh-installation) | `./paddock restore --from <set> \| --from-target-file <file>` |
| The installation runs but must go back to an earlier point | [Rollback of a running installation](#scenario-2-rollback-of-a-running-installation-a-restore-plan) | `./paddock restore --plan <id>` |
| One component is damaged | [Partial restore](#scenario-3-partial-restore) | `./paddock restore … --only <component>` |
| Only the local backup repository is lost | [Lost local backup repository](#lost-local-backup-repository-plan-m15-amendment-2026-11-05) | `./paddock restore --only backup-repo --from <target>` |

The backup alerts of `docs/operations/monitoring.md` land here or in `docs/operations/backup.md`: a full repository
(`PaddockBackupRepoFull`) is "Sizing" there, a held or shrunk target is "Lost local backup repository" below.

## What `./paddock restore` does

1. **Asks for the backup key** (44 characters, not echoed) and writes it to `.secrets/restore/backup_key` (0600),
   which no Compose file mounts. The file is deleted on every exit (success, failure, refusal, Ctrl-C) unless you pass
   `--keep-key-file`. The key reaches the containers on standard input only, never on a command line.
2. **Preflight, before anything stops.** The set's `manifest.json` parses; its key fingerprint equals the entered
   key's (a set made with another key is refused, naming both); its schema versions are not newer than this bundle's
   (restore with the bundle of the set's version or newer); both databases, the OpenBao snapshot and the Fleet dump
   the run needs exist at or before `--at`; `--at` is not in the future and not before the oldest database backup (a
   point earlier than the first full backup cannot be restored). Then it prints what it will do, including how OpenBao
   will be unsealed, and waits for the typed word `restore`: this terminal confirmation protects against the wrong
   host, also with `--plan`.
3. **Stops the writers** of the chosen components (for PostgreSQL or OpenBao: the Paddock roles, Authentik, pgBackRest
   and the backup role) and pushes the newest WAL of a running database first, so a restore to the latest point loses
   at most the last `archive_timeout` (60 s).
4. **PostgreSQL** (both databases, always together): empties their volumes, copies the set's
   `pgbackrest/<key_id>/` into the local repository when the source is not the repository itself, runs
   `pgbackrest restore` for both stanzas (`--at` restores to that point, else the latest archived point), starts the
   databases and waits until both left recovery.
5. **OpenBao**: replaces `openbao-data` with the newest snapshot at or before `--at`, decrypted straight into a fresh
   OpenBao (the plain snapshot never touches the host's disk), then unseals it: automatically when
   `PADDOCK_AUTO_UNSEAL=yes` and the shares file exists (`docs/operations/openbao.md` section 6), else **three
   custodians** unseal with `./paddock bao operator unseal` in other terminals while the command waits up to 15
   minutes. The restored node keeps the original barrier and the original shares.
6. **Paddock**: on a fresh installation creates the buckets, starts the roles except the compiler and the backup role,
   raises the bundle sequence with `admin raise-bundle-seq --at-least N` (a restored database can hold older bundle sequence
   numbers than the devices, which would refuse new bundles as downgrades; *Bundle sequence* below), starts the
   compiler, then `admin rebuild-cache` and `admin recompile --all` (Valkey's caches and the bundles bucket are rebuilt
   from PostgreSQL).
7. **Fleet**: loads the newest dump at or before `--at` into an empty `fleet-mysql`.
8. **Escrow**: puts the set's escrowed LUKS headers back into the escrow bucket where it lacks them (below).
9. **Starts the backup role and waits until the stack is healthy**, then records the result (`platform.restore_completed`,
   or `platform.restore_failed` naming the step) with the operator's name, and deletes the key file and the staged set.

Every step prints what it does. The command stops at the first error and names the component. After a failed step
it prints the state of the host: the writers of the chosen components are stopped and the steps before the failed one
replaced their volumes, so **do not run `./paddock up` on these volumes**; fix the cause and run the same command
again, which restores every chosen component again. A run ended by Ctrl-C, `SIGTERM` or a dropped session counts as
failed and is recorded the same way. When the run was interrupted before its first step, nothing changed.

The escrow step runs in the one-off service `backup-restore-escrow` (profile `restore`, never started by
`./paddock up`). It never puts back an escrowed LUKS header whose device has a successful `device.escrow_destroyed`
that is not older than the copy, even when the restore goes back to a point before that Destroy: it reads the evidence
from the audit index on the audit host, which the restore does not touch. It prints one `escrow: skipped device …`
line per such device, and `platform.restore_completed` records their number as `escrow_skipped_destroyed`. If the
audit index cannot be read (audit host down, wrong `db_paddock_audit_reader_url`), the step fails and puts nothing
back; fix the connection and run `./paddock restore --only escrow --from <set>` again.

### Bundle sequence

A device accepts only a bundle with a higher sequence than the last one it applied. Before anything stops, a database
restore reads **H**, the highest bundle sequence of the running stack. After the restore it runs
`admin raise-bundle-seq --at-least H+1000000`, which sets every device to `greatest(sequence + 1, H + 1 000 000)`.
Every device, also one enrolled after the restored point, then lands above anything any device applied and receives
a newer bundle with the recompile. The highest sequence grows by about 1 000 000 per restore, however many restores
and rollbacks follow each other.

When the stack cannot be read (a disaster restore: the database is gone), H comes from the **high-water file**
`bundle-seq/high-water` in the bundle directory. It is outside `.secrets/` and holds one number. The backup role raises
it after every successful round, every restore and rollback raises it too, nothing lowers it, and `./paddock upgrade`
copies it into the new release's directory. When both the stack and the file hold a sequence, the higher one counts.
Without either (a stack without any compiled device counts as none), the restore raises by the plain 1 000 000 with
`admin bump-bundle-seq` and prints `warning: bundle sequence: neither the running stack nor … holds a sequence`.
Devices that applied a sequence above the restored one plus 1 000 000 then receive nothing until enough compiles pass
it. Restore on the host where the file is, or copy `bundle-seq/high-water` from the old host's bundle directory before
you restore on a new one.

An H above 999 999 000 000 is more than any fleet reaches by compiling: it is a corrupt or edited file, and the restore
stops before anything changes and names it. Correct or remove the file, then run the restore again.

The directory is created by the bundle; `postgres` hands it to uid 999 (the backup role's) on every start. Do not edit
the file by hand: a lower number is ignored, and a higher one raises every device to that number plus 1 000 000.

## Scenario 1: fresh installation

The control plane is lost: the host failed, or its volumes are gone. The restore needs the same release, the lost
host's configuration and secrets, the backup key, the set and the custodians' shares.

**Checklist, before the command:**

1. **The bundle of the same release** (or newer) on the rebuilt host, verified as `docs/operations/install.md`
   section 3 describes. A set from a newer release than the bundle is refused.
2. **`.env`** of the lost host (the domain, the interconnect addresses, `PADDOCK_PROJECT`, `PADDOCK_BACKUP_LOCAL_ROOT`,
   `PADDOCK_AUTO_UNSEAL`), from your configuration store.
3. **`.secrets/`** of the lost host, from your secret store. The restored databases, OpenBao and the TLS chain were
   created with them, so freshly generated files would not match. Run `./paddock secrets` afterwards only to fill in
   files that are missing: it never overwrites one.
4. **The backup key**, from the copy you kept outside the server (password manager, safe, the custodians). The host
   file `.secrets/backup_encryption_key` is the key of the set only when the installation confirmed the imported
   key `legacy`; the fingerprint check tells.
5. **The set**, as a directory or tarball on the host, or an S3 target you can reach (below).
6. **Three custodians** with their unseal shares, or automatic unseal set up in `.env` with its shares file in
   `.secrets/openbao/`.
7. **Do not run `./paddock up`** (not even `--infra`) before the restore: it starts pgBackRest against an empty,
   freshly initialised cluster. Never run `stanza-upgrade` on a host being restored.
8. Free disk for the staged copy of the set (the command copies or extracts it into `./restore-staging/` and deletes
   it at the end) and for the restored volumes.

**From a copied or uploaded set** (a mounted share's `paddock-backup/` directory, a directory you copied with `scp`,
or a `paddock-backup-set-*.tar` of it):

```sh
sudo ./paddock restore --from /srv/restore/paddock-backup          # or …/paddock-backup-set-<time>.tar
sudo ./paddock restore --from /srv/restore/paddock-backup --at 2026-11-04T10:00:00Z   # a point in time (RFC 3339)
```

Local, SMB and NFS targets: mount the share on the host and use `--from <path>`.

**From a connected S3 target without a database.** Before the loss, export the target with its credentials and keep
the file offline with the key (`docs/operations/backup.md`, "S3 targets"):

```sh
./paddock backup-target export <name> /secure/offline/paddock-s3-target.json      # before the loss
sudo ./paddock restore --from-target-file /secure/offline/paddock-s3-target.json  # after it
```

The command downloads the set into `./restore-staging/` and goes on as above. A target **name** with `--from` works
only with a running database (`--plan`, or `--only backup-repo`); `--from-target-file` is the form without one.

**Afterwards:** a fresh installation has no plan, so the run records a restore plan of kind `fresh_install` with the
state `completed` or `failed`, and the portal's *Restore* tab shows what happened. Then follow "After every restore".

## Scenario 2: rollback of a running installation (a restore plan)

The installation runs, but the databases must go back to an earlier point, for example after a faulty change or
deletion. A platform administrator plans, the operator executes.

1. **Plan.** *Backup* → *Restore* → *Plan a restore*: the kind (*point in time* or *components*), the source (the local
   repository or a target), the point in time (the newest success of the chosen source is the bound), the components
   and the typed word `restore`, with a step-up (`POST /api/platform/v1/backup/restore-plans`). Paddock checks the
   plan against the successful backups of the source (409 naming the missing kind) and shows the consequence:
   *Restoring replaces the control plane's databases with the backup. Every change after the chosen point is lost.
   Devices keep working and reconnect; the audit log on the audit host is not touched.* One plan can be open at a time
   (`approved` or `running`), and an approved plan **expires after 24 hours**.
2. **Execute.** The plan shows its command with the plan ID and the expiry countdown. On the control-plane host:

   ```sh
   sudo ./paddock restore --plan <id>
   ```

   The command reads the plan (it refuses a plan that is not `approved`, expired, or whose source target was deleted),
   asks for the backup key and the typed word `restore`, marks the plan `running` (audited as
   `platform.restore_started`, once per attempt, refusals included) and runs the steps above with the plan's source,
   point and components. The key is asked for on the host: Paddock never shows it again.
3. **Report.** The plan becomes `completed` or `failed`, with the operator in `platform.restore_completed` /
   `platform.restore_failed`.
4. **Cancel.** An approved plan that is no longer needed is cancelled in the *Restore* tab (`expired`, audited as
   `platform.restore_cancelled`).

A restore plan that stays `running` because the host never reported is handled under "A restore plan stuck in
`running`" below.

**Points in time and earlier restores.** Every restore that replaces the databases starts a new database timeline,
and pgBackRest takes a new full backup on it at once. A point in time is restored from the newest full backup before
it, with the database log of that backup's timeline. A point that lies after a restore but before the first full
backup on the new timeline cannot be restored yet (RR-128): after up to 30 minutes the restore stops with "restore:
postgres did not finish its recovery" instead of restoring a different point; `./paddock compose logs postgres` shows
the cause ("recovery ended before configured recovery target was reached"). Choose a point after that full backup, or the
latest point.

## Scenario 3: partial restore

`--only <component>` (repeatable; default: all four) restores selected components from a set; `backup-repo` is a
component of its own and is restored alone. In the portal, a *components* plan is the planned form.

| Component | What it replaces | Independent? | Why |
| --- | --- | --- | --- |
| `postgres` | the `paddock` and the Authentik databases, always both | **Yes, with a condition** | Nothing else is replaced; OpenBao and Fleet keep their data (stopping the writers stops OpenBao, which comes back sealed: have the unseal path ready). The two databases cannot be restored one by one: users and groups in Authentik and the admin accounts in `paddock` refer to each other. The database pairs with OpenBao's state of the same time (below). |
| `openbao` | `openbao-data` | **Yes, with a condition** | Only OpenBao is replaced, but the databases hold ciphertexts of Transit keys and AppRole IDs: an older snapshot than the databases lacks keys created or rotated since (take a snapshot after every key operation). The Paddock roles and Authentik are stopped for it. |
| `fleet` | Fleet's MySQL | **Yes** | Nothing refers to it; it is rebuildable from the devices within 24 hours. Only Fleet is stopped. |
| `escrow` | the escrowed LUKS headers in the escrow bucket (puts back what is missing) | **Yes** | No database or key is touched; it needs the audit index only to skip destroyed devices. Only the backup role is stopped. |
| `backup-repo` | the local backup repository, from a target | **Yes** | No database, OpenBao or Fleet is touched; no restore plan is needed. "Lost local backup repository" below. |
| One organization | – | **No, never offered** | See below. |

**Why organizations are not independently restorable (ADR 0046).** The rows of one organization span the database
`paddock` (row-level-security tables with cross-references and the bundle sequence), Authentik (its users and groups),
the escrow bucket (object keys) and the devices' own sequence numbers. A row-level restore into a running installation
has no consistent cut: it would resurrect rows that other tables, other organizations' devices or Authentik no longer
know. Partial restore means per component. To get one organization's data back, restore the whole installation to a
point (scenario 2) on a separate host and read it there.

```sh
sudo ./paddock restore --from <set> --only openbao                 # OpenBao alone; the databases are untouched
sudo ./paddock restore --from <set> --only fleet --at 2026-11-04T10:00:00Z
sudo ./paddock restore --from <set> --only escrow
sudo ./paddock restore --only backup-repo --from <target name|set|tar>   # or --from-target-file <file>
```

## After every restore

1. **Check.** `./paddock check --online`, all roles ready (`./paddock ps`), no firing alerts, a device checks in and
   receives a new bundle version. The restore's own healthy wait ends first; this is the check that nothing else is
   left behind.
2. **A point-in-time restore of PostgreSQL alone diverges from OpenBao and Fleet** (residual risk RR-104). OpenBao
   snapshots are taken every 6 hours by default: a restore to 10:17 pairs the 10:00 database with the 06:00 snapshot.
   The restore prints the chosen file of every component. **AppRole secret IDs issued between the snapshot and the
   point must be issued again**: a role that cannot log in to OpenBao (its log names a login failure) gets a new secret
   ID as `docs/operations/openbao.md` section 3 describes, written to `.secrets/approle/<role>/secret_id`, and its
   containers are restarted. Policies, AppRoles and keys are those of the snapshot.
3. **Organizations and devices.** Devices keep working, reconnect and receive a new bundle (`raise-bundle-seq`); changes
   made after the chosen point are lost, including devices enrolled and audit rows of the control-plane database; the
   WORM audit trail on the audit host holds the evidence.
4. **Check the backups run again.** The restore removes pgBackRest's state volumes, so both stanzas take a full backup
   at once; `./paddock backup status` shows it, and a target that fails with `set_shrunk` after the restore is explained
   under "Lost local backup repository".
5. **Records.** `platform.restore_*` events are the evidence; keep the terminal output with the change record.

With automatic unseal on, the unsealer's attempts against the temporary single-share instance during a restore fail
with `invalid_share` (alerts and audit events show them) until the restored node restarts with its own barrier; then
it unseals the node automatically and no custodian is needed.

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
2. A platform administrator abandons the plan after a step-up, typing the word `abandon`: in the portal under
   *Backup*, tab *Restore*, action *Abandon plan* on the running plan, or through the API with
   `POST /api/platform/v1/backup/restore-plans/{id}/abandon` with `{"confirmation": "abandon"}`. The plan becomes
   `abandoned` with `outcome_detail` `abandoned by <administrator>`, and the audit trail records
   `platform.restore_abandoned`. A plan that is not `running` is refused with 409 `invalid_state`.
3. Approve a new plan.

A report the host sends for the abandoned plan afterwards (`paddock-server backup restore-report`) is refused with
`invalid_state` and recorded as a failed `platform.restore_completed` or `platform.restore_failed` event; it never
changes the plan again.

## Restore drill (quarterly)

`make restore-drill` runs the same restore code as `./paddock restore` (`deploy/compose/scripts/restore.sh`) on the
development stack (started with `make up BACKUP=1` and `make dev-seed BACKUP=1`, which confirms a backup key). It
requests every kind with `backup now`, waits until the local development target holds the set, then deletes the volumes
of both databases, their WAL spools, OpenBao, Fleet's MySQL and the local backup repository, rebuilds the repository
from the target and restores **as a fresh installation** (a restore plan lives in the database the drill destroys;
the plan path is covered by the acceptance gate `TestRestorePlan` and the system gate BS4). OpenBao is unsealed with
the stored development shares. It then runs the acceptance subset
`TestDeviceProtocol|TestLoginGate|TestAuditChain|TestOrganizationIsolation` and prints the time from the loss until the
control plane is ready and until the subset is green (the RTO line). The drill guard refuses anything but the
development stack; it destroys the development volumes it names and never touches the audit store.

| Drill | Control plane ready | Subset green (RTO) |
| --- | --- | --- |
| first drill (gate P-3): reference machine (`docs/operations/capacity.md`), 2026-10-09, M6-integration `058e769`, manual runbook | 75 s | 150 s |
| alpha.9 release regression: development host (22 cores, shared with other stacks), 2026-11-07, cluster/alpha9-features `a8095211`, `make restore-drill` with `./paddock restore` | 270 s | 745 s |
| 0.1.0-alpha.9 release regression: development host (22 cores, shared with other stacks), 2026-11-08, main `179fb36f`, `make restore-drill` with `./paddock restore` | 248 s | 653 s |

The stated RTO of 4 hours covers a rebuilt host, the custodians' arrival and the copy of the set; the drill measures the
technical part. The release regression for every release that changes the backup runs the `BACKUP=1` gate sequence and
`make restore-drill` and enters its measured line here.
