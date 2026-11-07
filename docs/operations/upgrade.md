# Upgrade and rollback

How to move an installation from release A to the next release B with the operator bundle: three commands, with a
guarantee behind them (ADR 0047, plan M16). `./paddock upgrade-check <old dir>` tells you what will happen and what is
missing and changes nothing; `./paddock upgrade <old dir>` does the upgrade; `./paddock rollback <old dir>` goes back.
Upgrade the control plane first, the audit host second, and roll out the agents after the servers, except where the
release notes of B say otherwise.

## Before you start

- **The guarantee.** From 0.1.0-alpha.8 on, every release B upgrades from the release directly before it, A, without
  data loss, and rolls back to A. CI proves it for every release candidate: it installs A from its published bundle,
  seeds data, upgrades, probes, restores a backup and rolls back (`docs/operations/testing-strategy.md`). A release
  that could not keep it would not be cut. The guarantee covers one step at a time: `./paddock upgrade-check` refuses
  to skip a release and names the releases to go through first. The first guaranteed pair is 0.1.0-alpha.8 →
  0.1.0-alpha.9. Earlier releases have no guaranteed path (*Archive: releases before the guarantee*, below).
- **Read the release notes of B** (`CHANGELOG.md`, and `RELEASE-NOTES` in the bundle directory, which the commands
  read). Every release section carries three lines, and the commands act on them:
  - `Schema: unchanged` or `Schema: migrations NNNNN–NNNNN (…); audit …` decides the rollback. Without a `Schema:` line
    the commands assume a schema change. Audit migrations also decide whether the old audit writer is stopped.
  - `Upgrade: from <A>: automatic` or `Upgrade: from <A>: steps: <text>`. The check prints it and warns when it names
    steps. Do the steps.
  - `Agents: supports <N-2>, <N-1>, <N>`, the agent window of B.
- **The agent window.** Until 0.1.0, the server supports agents of its own release and the two previous releases
  (ADR 0013, amendment 2026-11-04). A device whose agent is outside the window still checks in. It receives only the
  agent update offer of the current rollout (regardless of its wave) and the safety commands, no configuration bundle
  and no other command, until it runs a supported agent; the portal shows it as `agent_outdated`
  (`docs/operations/agent-releases.md`). The check lists such devices before the upgrade: it fails when more than 1 %
  of the active devices, or more than 5, whichever is larger, would be outside the window of B, and warns below that.
  Residual risk RR-106 covers devices that are offline during the upgrade.
- **A server upgrade never requires an agent upgrade**: the server supports agents of its own release and the two
  previous releases. Upload an agent release only to a server of the same or a newer release.
- **What the check reads.** `./paddock upgrade-check` asks the running stack and the files of both directories; it
  never prints a setting or a secret, only their names. The items are listed under *Upgrade*, below. The same report
  of the server, for the release the server runs, is the card *Upgrade* on the platform administrator's landing page
  in the portal (the support window, the agents outside it, the backup state; no action) and
  `GET /api/platform/v1/upgrade-check?target_version=<release>`.
- **What you need.** B's bundle (downloaded, verified and extracted as `docs/operations/install.md` section 3
  describes) next to the running bundle directory, for example `/opt/paddock/paddock-deploy-<B>/` beside
  `/opt/paddock/paddock-deploy-<A>/`. On the control plane, three custodians of the OpenBao unseal shares when B
  changes OpenBao's image or configuration (below), and a root token in `BAO_TOKEN` when B adds OpenBao keys, policies
  or AppRoles (`docs/operations/openbao.md` section 1; revoke the token afterwards). Free disk space on Docker's data
  root: the check wants the size of B's new images times two plus 2 GiB.
- **Where each command runs.** `upgrade-check`, `upgrade` and `rollback` all run in B's directory. `<old dir>` is
  always the directory of the running release A. Keep `PADDOCK_PROJECT` unchanged, so that B uses the same containers,
  networks and volumes.

## Upgrade (each host)

Do the control plane first, then the audit host, each in its own B directory. A lab host (`PADDOCK_HOST=lab`) runs
both roles and follows the control plane's steps.

1. **Extract B** next to A as described above. Do not create `.env` or `.secrets/` in it: `./paddock upgrade` copies
   them from A.
2. **Check**, in B's directory. This is read-only:

   ```sh
   ./paddock upgrade-check ../paddock-deploy-<A>          # audit host: the same
   ./paddock upgrade-check ../paddock-deploy-<A> --json   # {"items": [{name, status, detail}], "exit": n}
   ```

   | Flag | Effect |
   | --- | --- |
   | `<old dir>` (required) | The directory of the running release A. It must differ from B's directory. |
   | `--json` | Prints `{"items":[{"name","status","detail"}],"exit":<code>}` instead of the table. |

   The exit code is 0 without a FAIL, 1 with at least one FAIL and 2 on a usage error (a missing or unknown
   argument, a missing directory, the same directory twice). The items, in this order:

   | Item | What it checks |
   | --- | --- |
   | `old bundle verified` | `<old dir>/paddock verify` passes: no shipped file of A changed (FAIL otherwise). |
   | `versions adjacent` | A is the release directly before B in the release list of B's bundle (`RELEASES`). FAIL when A is older by more than one release (the detail says which releases to go through first), is not older than B, or is no known release; WARN when B is not a release (a bundle of another channel). |
   | `release notes` | Prints the `Upgrade:` and the `Agents:` line of B. PASS for `automatic`, WARN when the line names steps or is missing. |
   | `env` | FAIL for every key of B's `.env.example` (`.env.lab.example` on a lab) that A's `.env` lacks and the Compose files do not default, with the example's comment; WARN for keys of A's `.env` that B does not know; INFO for keys B's release retired (`RETIRED-SETTINGS` in the bundle), which A keeps for the rollback. |
   | `secrets` | FAIL for secret files that `./paddock secrets` cannot generate and A lacks (`release-production/…`, `approle/…`); INFO for the files it will generate. |
   | `disk` | FAIL when the free space of Docker's data root is below the size of B's new images times two plus 2 GiB; WARN when a size cannot be read (offline). |
   | `images pullable` | `docker manifest inspect` of every image of this host; WARN for those without a manifest (offline, unreachable registry). |
   | `server report` | The server's own report (`paddock-server admin upgrade-check --target-version <B>`) asked through A's stack: `migrations` (the database at or below B's newest migration), `agents` (above), `backups` (an active key; every enabled target with a success of every kind within 26 h, the escrow kind within 3 h), `openbao` (sealed state), `pending` (an open restore plan, a running agent rollout, a halted configuration rollout: WARN) and `sessions`. Printed below the table. With A = 0.1.0-alpha.8, which predates the command, B's image answers against A's database. WARN when A's stack is not running or the report cannot be produced; INFO on the audit host. |
   | `openbao unseal path` | PASS with automatic unseal and its shares file; WARN otherwise (three custodians must be available during `./paddock up`); INFO on the audit host. |
   | `running stack healthy` | Every service of A is healthy or finished cleanly (WARN otherwise). |

   Fix every FAIL before you continue. `./paddock upgrade` runs the same check and stops on a FAIL.
3. **Upgrade**, in B's directory:

   ```sh
   BAO_TOKEN=<root token> ./paddock upgrade ../paddock-deploy-<A> [--yes] [--allow-unsupported-agents] [--skip-backup]
   ```

   Leave `BAO_TOKEN` out when B's release notes name no OpenBao change.

   | Flag | Effect |
   | --- | --- |
   | `<old dir>` (required) | The directory of the running release A. |
   | `--yes` | Does not ask for `yes` on the terminal after the plan. Without it, any other answer stops the run before the next step. |
   | `--allow-unsupported-agents` | Turns the agents FAIL of the server report into an accepted result: those devices stop receiving bundles and commands until their agent is updated. Nothing else is overridable: any other FAIL stops the upgrade. |
   | `--skip-backup` | Takes no pre-upgrade backup. Refused on the control plane and on a lab host with backups unless the release notes say `Schema: unchanged` and `FLEET_IMAGE` is the same in both `versions.env`. On a lab host without backups (`PADDOCK_LAB_BACKUP` is not `yes`) it is required when the schema changes or `FLEET_IMAGE` changes: the rollback is then only `down` and the old `up`, and the data that B migrated stays (`./paddock rollback` refuses after a schema change there). The audit host takes no backup and needs no flag. |

   The command starts in a freshly extracted directory. A directory that already has `.env` or `.secrets/` but no
   `.upgrade-state` is refused (exit 2); so is a directory whose `.upgrade-state` names another old directory. It
   prints the plan, asks for `yes`, and runs these steps, each printing its command first:

   | Step | What it does |
   | --- | --- |
   | `upgrade-check` | The check above; stops on a FAIL. |
   | `migrate-from` | Copies `.env`, `.secrets/` and `compose.backup-targets.yaml` (`cp -a`) from A. A partial copy of an earlier run of this command is removed and copied again. |
   | `secrets` | `./paddock secrets`: generates missing secrets only and prints their names. |
   | `pull` | `./paddock pull`. |
   | `check` | `./paddock check` (`--online` on the audit host and a lab: the audit bucket's Object Lock, read over A's running stack; the backup targets' revisions are compared in the post-checks): every item PASS, else the run stops, and A still runs. |
   | `backup` | On the control plane and on a lab host with backups: `<old dir>/paddock backup now --label pre-upgrade-<B> --wait`. A release without `backup now` (other than 0.1.0-alpha.8, below) is refused before anything changes. |
   | `audit-writer-stop` | Audit host and lab, when B's `Schema:` line names audit migrations (or is missing): `<old dir>/paddock compose stop paddock-audit-writer`. B's writer starts only after the audit migrations, but A's writer would keep running while they hold their table locks; its writes fail and are redelivered until the queue dead-letters them. Stopped, new audit events wait in the queue and `./paddock up` starts B's writer, which writes them. A backfill can take minutes on a large index (`docs/operations/capacity.md`, *Audit index commit sequence backfill*). |
   | `up` | Records the rollback point (below), then `./paddock up`: Compose recreates the containers with B's images and `paddock-migrate` applies the schema migrations. |
   | `openbao` | Control plane and lab: with `BAO_TOKEN` set, `./paddock bootstrap openbao` (idempotent). Without it, the step prints the manual step when B's `Upgrade:` line names OpenBao and is otherwise skipped. |
   | `post-checks` | `./paddock ps` shows every service healthy; the new server's `admin upgrade-check --target-version <B>` reports the `migrations` item at the binary's version (control plane and lab); `./paddock check --online` (audit host and lab). |

   **Unseal.** When B changes the OpenBao image or its configuration, `./paddock up` recreates OpenBao and it starts
   **sealed**. The Paddock roles cannot become healthy until it is unsealed, so `./paddock up` keeps waiting (up to
   15 minutes, then it fails and names OpenBao as sealed). Have three custodians ready: while it waits, they run
   `./paddock bao operator unseal` in a second shell, one share each (`docs/operations/install.md` section 6); if it
   timed out, unseal and run `./paddock upgrade ../paddock-deploy-<A>` again. With automatic unseal on
   (`docs/operations/openbao.md` section 6) the unsealer does this. `./paddock up` never unseals by itself: the shares
   are not on the host.

   **Nothing changes on A's stack before the backup is done.** The steps up to and including `backup` leave A running
   (`audit-writer-stop` stops only its audit writer). A failed step stops the run with the state of the host and the
   one next action. The progress is in `.upgrade-state` (one `done=<step>` line per finished step); running the same
   command again continues at the first unfinished step, and a successful run deletes the file. A failed `up` may
   leave B partly running with its migrations partly applied: fix the cause and run the command again, or roll back.
4. **Watch** the readiness of the roles and the alerts for an hour (`docs/operations/monitoring.md`). Keep A's
   directory until the next upgrade: it is the rollback. A's `.secrets/` stays a full copy of the secrets, including
   the OpenBao shares file `.secrets/openbao/auto-unseal-shares` when automatic unseal is on. When you disable
   automatic unseal later, delete that file in A's directory as well (`docs/operations/openbao.md` section 6,
   *Disabling*): `./paddock auto-unseal disable` deletes only the copy of the directory it runs in. Rotate the shares if
   the host may have been copied. When you delete A's directory, delete its `.secrets/` with it.

Then the audit host, the same way (there is no `backup` step; the audit writer stop applies when B has audit
migrations).

**The rollback point.** Right before the first `./paddock up`, the upgrade writes `.upgrade-rollback` in B's directory:
A's directory, both versions, whether a backup was taken, its label `pre-upgrade-<B>`, the time `at` and a random
attempt ID that `.upgrade-state` carries too. A rollback uses the record only for the upgrade attempt that wrote it. A
later upgrade from A's directory renames A's own record to `.upgrade-rollback.superseded-by-<version>`: a rollback from
there would stop the newer release and restore a point before every change since.

**Agents.** After the servers, roll out B's agent release with the staged rollout (`docs/operations/agent-releases.md`)
unless the release notes of B say agents come first. Devices outside the window of B come back by updating.

## Rollback

`./paddock rollback <old dir> [--yes]`, in B's directory. `--yes` skips the terminal question `yes` (the restore's own
confirmation is answered by it too); `<old dir>` is the directory the upgrade ran from. Migrations only move forward
(`server/migrations/`; there is no down migration), so the rollback depends on B's `Schema:` line:

- **`Schema: unchanged`**: `./paddock down` in B's directory, then `<old dir>/paddock up`. Same project, same volumes,
  A's images by digest from A's `versions.env`.
- **`Schema: migrations …`** (or no `Schema:` line): A cannot run on B's schema. On the control plane and on a lab
  host with backups, the rollback restores PostgreSQL, OpenBao and the escrow bucket (and Fleet when `FLEET_IMAGE`
  differs between the two `versions.env`: Fleet migrated its database, so A's Fleet needs the dump) from the **local**
  backup repository to the point just before the upgrade's first `up` (`up-started`), with A's own `restore.sh`, then
  starts A with `<old dir>/paddock up`. **Every change written after that point is lost**: devices that checked in,
  audit events in the control-plane database, configuration edits. The audit domain's WORM evidence stays. The upgrade
  guarantees the pre-upgrade backup exists at or before that point (`backup now --label` checks it). The key of the
  set is `.secrets/backup_encryption_key` of A's directory when it made the set, otherwise the command asks for it.
- **`Schema: unchanged` but `FLEET_IMAGE` changed**: only Fleet's dump is restored.
- **The audit host** rolls back with `down` and A's `up` only: audit migrations within a guaranteed pair are additive,
  so A's writer inserts into a superset schema.
- **A lab host without backups** (`PADDOCK_LAB_BACKUP` not `yes`) refuses a rollback after a schema change: there is no
  set to restore.

**Before anything stops**, the command checks, in this order: the rollback record belongs to this upgrade attempt and
names a point (else it refuses and points at `./paddock restore`, `docs/operations/restore.md`); the running stack is
B (the version label of its containers; a later upgrade from this directory supersedes the record). It then prints the
steps and *every change after the point is lost* and asks for `yes` (unless `--yes`). Still before `./paddock down`, a
restore checks that the key matches the set's manifest and that A's preflight passes (schema versions, stanzas, the
oldest backup at or before the point, the OpenBao snapshot and the Fleet dump), and asks its own confirmation `restore`
(`--yes` answers it). A failure before `down` leaves the running stack untouched.

**Bundle sequence after a rollback.** Before `./paddock down`, the rollback reads the highest bundle sequence of B's
running stack and records it in B's high-water file (`bundle-seq/high-water`). The rollback to 0.1.0-alpha.8 reads it
right before `down`; any other rollback reads it before A's preflight and confirmation, because A's restore runs with
A's scripts after the `down`, and hands it to that restore. The restore that follows raises
every restored device's sequence to that value plus 1 000 000 or above, so devices that applied a bundle of B, also one
after a restore on B, receive a newer bundle from A without waiting for compiles. When B's stack is already down (a
repeated rollback), the value comes from B's high-water file. `./paddock upgrade` copies A's high-water file into B's
directory (`migrate-from`), so the file never starts empty in a new release's directory. `docs/operations/restore.md`, *Bundle sequence*, has the
rule.

**One rollback per upgrade attempt.** After a successful rollback `.upgrade-rollback` is renamed
`.upgrade-rollback.rolled-back-<attempt>` and `.upgrade-state` gains `rolled-back=<time>`; a second rollback of the
same attempt is refused. A new `./paddock upgrade` starts a new attempt and copies `.env` and `.secrets/` again: A runs
in between and may have been reconfigured. A failed rollback is repeated by running the same command again. If it
failed while it replaced data, A's containers may run on partly restored volumes: do not start B on them.

Never edit the shipped files of a bundle to change behaviour: `./paddock verify` reports it, the check refuses it
(`old bundle verified`), and the next upgrade replaces them. Settings belong in `.env`.

## Per release

One subsection per release from 0.1.0-alpha.8 on, newest first. Each states what B changes for A's installation. The
older notes are in the *Archive*.

### 0.1.0-alpha.9, from 0.1.0-alpha.8

The release notes of this release carry these lines (the lines of `CHANGELOG.md` are authoritative):

```text
Schema: migrations 00100–00109 (control-plane database); audit unchanged
Upgrade: from 0.1.0-alpha.8: steps: BAO_TOKEN for ./paddock upgrade, then ./paddock bootstrap buckets and ./paddock up; confirm the backup key in the portal
Agents: supports 0.1.0-alpha.7, 0.1.0-alpha.8, 0.1.0-alpha.9
```

This is the first guaranteed pair. It is the one upgrade where A lacks what the commands usually rely on: 0.1.0-alpha.8
has no `backup now --label`, no local backup repository and no `restore.sh`. Both commands therefore carry a legacy path
for exactly this pair (below). Control plane, audit host and lab follow *Upgrade* and *Rollback*; this subsection is
what is specific to alpha.9. It has no audit migration, so on the audit host `audit-writer-stop` is skipped.

1. **The steps after the upgrade.** Run `./paddock upgrade` with `BAO_TOKEN` set, so that `bootstrap openbao` runs in
   its step: this release adds the Transit key `backup-wrap` and the policies and AppRole of `paddock-api` and
   `paddock-backup` (`docs/operations/openbao.md` section 1). Then, on the control plane and a lab with backups, run
   `./paddock bootstrap buckets` (the read-only escrow credential `rustfs_escrow_backup_*` of the backup role) and
   `./paddock up` once more. `./paddock secrets` (the upgrade's step `secrets`) adds `db_paddock_backup_password` and
   `db_paddock_backup_url`; the database role `paddock_backup` is created by `db-provision` before the migration.
   `./paddock check` of the upgrade fails when the backup role or one of its secrets is not mounted.
2. **Backups move.** Plan M15, ADR 0046 (`docs/operations/backup.md`, `docs/operations/restore.md`). Backups no longer go
   to the one S3 bucket of `PADDOCK_BACKUP_S3_*`. pgBackRest writes to the local volume `backup-repo`, and the new role
   `paddock-backup` adds the OpenBao snapshots, the Fleet dumps and the escrowed LUKS headers and mirrors the set to
   the targets a platform administrator configures in the portal. The worker no longer takes snapshots,
   `fleet-backup-upload` is gone, and `fleet-backup` writes plaintext dumps that only the backup role seals. **Until a
   platform administrator has confirmed a backup key, nothing is backed up** (the alert `PaddockBackupKeyUnconfirmed`
   fires after an hour).
3. **The key is imported once, then confirmed.** The key of 0.1.0-alpha.8 is the file `.secrets/backup_encryption_key`
   (copied by `migrate-from`); because it exists, `./paddock` adds `compose.backup-legacy-key.yaml`, and the api imports
   it at its first start as the key `legacy`, state `unconfirmed`. In the
   portal under *Platform* → *Backup* → *Key*, a platform administrator types the characters at the six positions shown
   from that file. Keep this key: the backups of 0.1.0-alpha.8 in the old bucket are encrypted with it, and a rollback
   to 0.1.0-alpha.8 needs them. Alternatively discard the imported key and generate a new one: new backups then use the
   new key, and the old key stays necessary for the old bucket.
4. **Removed settings.** `PADDOCK_BACKUP_S3_*` in `.env`, the secrets `backup_{pgbackrest,worker,fleet}_{access,secret}_key`
   and the service `fleet-backup-upload` are not used by this release, and `./paddock check` fails on a service that
   still names the S3 variables. Leave them in A's directory: they are the rollback to 0.1.0-alpha.8, which restores
   from the old bucket. `./paddock upgrade-check` lists them as INFO (retired by this release; kept for the
   rollback). New setting: `PADDOCK_BACKUP_LOCAL_ROOT` (default `/srv/paddock-backup`), the base directory of local
   backup targets; `./paddock check` verifies it. `./paddock upgrade` removes the container of
   `fleet-backup-upload`, which B no longer defines, right before `up` (by hand: `<A>/paddock compose rm -sf
   fleet-backup-upload` after the pre-upgrade backup and before `up`); a rollback to A starts it again.
5. **The old bucket becomes an S3 target.** To keep backing up to the same bucket, add it in the portal under *Backup* →
   *Targets* as an `s3` target with a **new** credential that may list, read, write and delete below the target's
   prefix (the old pgBackRest credential only reaches `pgbackrest/`, `openbao/` and `fleet/`), and give it a prefix such
   as `paddock` so that the new set (`<prefix>/paddock-backup/`) stays apart from the old objects. No host step is
   needed for an S3 target. Do not delete the old objects while a rollback to 0.1.0-alpha.8 is still wanted. The first
   copy of a large set takes several rounds (`docs/operations/backup.md`, "Targets").
6. **Local, SMB and NFS targets** need the host step: `./paddock backup-target apply`, then `./paddock up`. After the
   first full backup, `./paddock backup status` shows the key, a run per kind and each target.
7. **The pre-upgrade backup of 0.1.0-alpha.8 (the step `backup`).** The upgrade runs alpha.8's own backup through
   `<old dir>/paddock compose`, with alpha.8's Compose files and images, while alpha.8 still runs: full pgBackRest
   backups of both databases (`--start-fast`), an OpenBao snapshot and a Fleet dump. It checks in the old bucket that
   all four exist and are the newest (the dump may take up to 5 minutes to appear: the running `fleet-backup-upload`
   uploads it).
8. **The fence (the step `up`).** alpha.8's restore stages every WAL segment the bucket holds, so right before the
   rollback point is recorded the upgrade stops alpha.8's `pgbackrest` and `pgbackrest-authentik` and flushes both. The
   bucket's WAL archive then ends before B touches a database; WAL written afterwards reaches B's local repository
   only. It then checks again that the newest backup of each stanza is still the recorded one (alpha.8's pgBackRest
   takes a full backup of its own once the last is 24 h old, for example while a stopped run waits). On any failure
   it starts alpha.8's pgBackRest again, writes no record and does not run `up`: alpha.8 runs unchanged, and the next
   run repeats the step (and, on a newer backup, takes the backup again).
9. **Rolling back to 0.1.0-alpha.8.** `./paddock rollback` runs alpha.8's documented restore procedure through
   `<old dir>/paddock compose`, from the old bucket. Before anything stops it checks that the record names a valid
   legacy backup; that both directories name the same Compose project (the volumes of this project are deleted and
   alpha.8 starts in its own); that alpha.8's key and pgBackRest credential files exist; that the newest backup of
   each stanza is the recorded one; and that the recorded snapshot and, when `FLEET_IMAGE` changed, the dump download
   and decrypt. Then it stops B (`./paddock down`) and:
   - restores both PostgreSQL clusters with alpha.8's `pgbackrest restore` to the newest WAL alpha.8 archived (the
     fence ended that archive before `up`) and waits for the recovery;
   - restores the snapshot into a fresh OpenBao with one temporary share (`openbao-restore.sh`); the custodians or the
     automatic unseal unseal the restored OpenBao;
   - when Fleet changed, drops Fleet's database and loads the dump;
   - runs the restore commands (`bump-bundle-seq`, `rebuild-cache`, `recompile --all`) in their binding order. The
     raise is not alpha.8's fixed 1 000 000: it is computed from the highest bundle sequence B's stack held right
     before `./paddock down` (see *Bundle sequence after a rollback*), with alpha.8's own `bump-bundle-seq --by`,
     `max(1 000 000, highest + 1 000 000 − lowest restored)`. A highest sequence that would need more than ten calls of
     at most 1 000 000 000 is refused before `down`;
   - starts pgBackRest, then `<old dir>/paddock up`. pgBackRest starts last: with its fresh state it takes a full
     backup at once, which would make a repeated rollback refuse after a later failure.

   **Which volumes are recreated.** Exactly these are deleted and recreated: `postgres-data`,
   `authentik-postgres-data`, both `pgbackrest-spool-*`, both `pgbackrest-state-*` and `openbao-data`. The spools and
   states go so that WAL left behind by B never reaches alpha.8's stanza. Fleet's volume is kept (its database is
   dropped instead). Only the OpenBao whose volume was just emptied is initialized, and only after it reports
   `"initialized": false`. No other volume is touched.

   **What is lost.** The loss window starts at the time the pre-upgrade backup completed at the latest (`legacy-at` in
   `.upgrade-rollback`): the restore reaches the WAL alpha.8 archived until the fence. The escrow bucket is not part
   of alpha.8's restore and is not restored. The legacy path is removed once 0.1.0-alpha.8 leaves the support window.
10. **Agents.** Upgrade the server first, then roll out this release's agent release
    (`docs/operations/agent-releases.md`). Agents of 0.1.0-alpha.7 and 0.1.0-alpha.8 are inside the window and keep
    working against the new server; agents of 0.1.0-alpha.6 and earlier are outside it (above): the check lists them
    and FAILs when they exceed 1 % of the active devices or 5.
11. **Third-party images.** Fleet moves to v4.94.0, a minor release that migrates Fleet's database; the pre-upgrade
    backup of the step `backup` includes the Fleet dump, and a rollback restores it because `FLEET_IMAGE` changed.
    Fleet's own HTTP metric is renamed from `http.server.duration` to `http.server.request.duration` (seconds);
    Paddock neither scrapes nor alerts on it, so only your own Fleet dashboards need the new name. The new hourly
    cleanups concern Windows and Apple MDM commands and removed host certificates, which a Linux-only installation does
    not hold. OpenBao moves to 2.7.2: the step `up` recreates OpenBao and it starts **sealed**, so have three custodians
    ready (or automatic unseal on). Devices install Himmelblau 4.0.8 with their current agent at the next login drift
    pass; that release does not contain the upstream fix for the Hello PIN loss (himmelblau-idm/himmelblau#1886), so
    the agent's `cache_timeout` setting and residual risk RR-40 stay unchanged. It offers the password change at the
    console login of an enrolled device whose Entra ID password has expired. The AWS CLI image of the bucket bootstrap
    scripts (`./paddock bootstrap buckets`, `./paddock bootstrap audit-bucket`, a restore onto a fresh installation)
    moves to 2.39.3. `./paddock pull` does not fetch it, because it is no Compose service: Docker pulls it when one of
    these commands first runs. On a host without registry access, pull `AWS_CLI_IMAGE` of B's `versions.env` beforehand.

### 0.1.0-alpha.8, from 0.1.0-alpha.7

- **Upgrade in place from 0.1.0-alpha.7** with the manual runbook of that release (`docs/operations/upgrade.md` at the tag `v0.1.0-alpha.8`; the commands above replace it from the next pair on); from 0.1.0-alpha.6 or earlier
  there is still no upgrade path (install 0.1.0-alpha.7 or this release fresh, as the Archive says). Only Paddock's own images
  change: no third-party image, Compose file or Authentik blueprint, no new setting in `.env.example`, no new database
  role, OpenBao AppRole or file under `.secrets/`. Schema: migrations 00090–00099 on the control plane (new tables,
  columns and grants; 00097 fills three new device columns from the existing device data, so the upgrade recompiles no
  device), no audit migration: on the audit host the stop of the audit writer does not apply. The rollback is the backup restore of the runbook's step 3 (the restore of alpha.8's own backup bucket).
- What changes for existing data. Devices enrolled before the upgrade get the enrollment method
  `unknown` and stay enforced; only devices adopted later start report-only. Staged configuration rollouts are off in
  every organization until an organization administrator enables them under *Settings*, *Rollouts*
  (`docs/operations/configuration-rollouts.md`). Change sets written before the upgrade have no stored previous state
  and cannot be reverted; every change after it can, for 90 days. The software catalog is empty, and adding a package
  source needs a fresh step-up (`docs/operations/software.md`).
- Devices: upgrade the server first, then roll out this release's agent release
  (`docs/operations/agent-releases.md`). The agent changes (report-only apply, enforcement of software assignments,
  enrollment method and os-release in the check-in); the supervisor and `paddock-revoke` do not, and revocation stays
  disabled. Agents of 0.1.0-alpha.7 keep working against the new server, but they ignore software assignments and
  cannot run report-only: adopt existing laptops and assign software only once the devices run this release's agent
  (`docs/operations/enroll-existing.md`, *Minimum agent release*). With software assignments, the agent writes
  `/etc/apt/sources.list.d/paddock-<slug>.sources`, `/etc/apt/keyrings/paddock-<slug>.gpg` and
  `/etc/apt/preferences.d/51paddock-software`; these files are a protected area: an edited one is restored, a foreign
  `paddock-*` source or keyring is removed, each with `device.tamper_protected_file_changed`. When the last software
  assignment of a device goes away, and when Paddock is removed from it, the agent deletes them again; installed
  applications stay.

## Archive: releases before the guarantee

Notes of the releases before the guarantee (ADR 0047). These installations were upgraded by a manual runbook (`migrate-from`,
`pull`, `check`, backup, `up`; `docs/operations/upgrade.md` at the tag `v0.1.0-alpha.8`), which the three commands above
replace, or installed fresh. Releases before 0.1.0-alpha.8 have no guaranteed path: install the newest release fresh.
"Step N" in this section is a step of that manual runbook, not of *Upgrade* above.

**Binding exception — the release with the managed-file path tiers (ADR 0034, amendment 2026-10-16): agents first,
then the server.** The new server stops shipping managed files on denied paths, and an agent older than that release
deletes every unchanged file that leaves its bundle. Upload B's agent release to the running server of A (same minor
version) and roll it out to every device first; upgrade the control plane only when no active device runs an older
agent (`docs/operations/agent-releases.md`). See residual risk RR-36 for devices that are offline meanwhile. That
release also needs a WebAuthn authenticator for every administrator (the portal enrols one at the first sign-in),
signs every administrator out once and asks for one security review afterwards: follow the four steps in `docs/operations/install.md`, section 12.

**Release 0.1.0-alpha.4: *End all sessions* for the identity provider (ADR 0034 amendment 2026-10-18).** Authentik grants
Paddock's service account the two permissions on authenticated sessions when it applies `paddock-portal.yaml` at its
start: restart Authentik once after the upgrade (`./paddock compose restart authentik-server authentik-worker`), or
*End all sessions* records a failure with `upstream_unavailable` after it ended the portal sessions.

### Notes of the releases from 0.1.0-alpha.4 to 0.1.0-alpha.7

- From 0.1.0-alpha.4: after this upgrade every Authentik sign-in — the portal, Authentik's own user and admin interfaces
  (`akadmin` included) and the device approval page — asks for a second factor and enrols one when missing.
- From 0.1.0-alpha.4: the fix that keeps the Hello PIN working while a user stays signed in is on the device (the
  agent writes `cache_timeout` into `himmelblau.conf`). Roll out the agent release first; devices with an older agent
  keep losing the PIN after a few minutes of use (residual risk RR-40).
- From 0.1.0-alpha.5: upgrade the server first, then roll out the agent release; agents older than this release refuse
  the in-place encryption request as unsupported. Its migration 00067 builds an index on the vulnerability findings;
  on large finding tables the migration step takes a little longer (well under a second at 200 000 findings), and
  vulnerability updates from the inventory sync wait for it.
- From 0.1.0-alpha.6: Fleet moves to v4.93.2. That patch has no database migration, but take the Fleet dump of step 3
  anyway: a rollback restores it like for every Fleet version change. Authentik moves to 2026.8.5; `./paddock up`
  recreates its containers, and it applies the blueprints itself at that start. No extra restart and no manual
  blueprint re-apply is needed.
- From 0.1.0-alpha.6: upgrade the server first, then roll out the agent release. The release changes nothing on the
  device, so the agent rollout only aligns the version; import it with *Check for new release* on the *Agent
  releases* page (or `./paddock agent-release`) and start it with `./paddock agent-rollout <version>` or in the
  portal. Devices install Himmelblau 4.0.7 with their current agent at the next login drift pass after the server
  upgrade. The import needs outbound HTTPS from `paddock-api` to GitHub: set `HTTPS_PROXY` and `NO_PROXY` in `.env`
  if the host uses a proxy, or `PADDOCK_AGENT_RELEASE_SOURCE_REPO=off` on air-gapped installations
  (`docs/operations/agent-releases.md`, "Import from GitHub"). After the upgrade, the first identity sync records the
  current members of every Paddock role once as `admin.role_granted` with `baseline: true`, devices whose clock is
  more than 60 s off appear on the attention list as `clock_drift`, and the nightly audit chain verification starts
  (alerts `PaddockAuditChainBroken`, `PaddockAuditVerifyStale`). Schema: migrations 00068–00071 and audit migrations
  00004–00006 (new tables and columns only; no data rewrite).
- **From 0.1.0-alpha.7: no upgrade path.** This release moves PostgreSQL to 18 (new data directory layout), Valkey
  to 9 and RabbitMQ to 4.4. None of them opens the data of the previous release, and this release ships no
  migration. Install it fresh: in the old bundle directory `./paddock down --volumes` (deletes every volume of the
  project: the databases, OpenBao with its keys, the object stores, Fleet), then follow `docs/operations/install.md`
  for the new release and enrol every device again (`docs/operations/uninstall.md` for the device side). Escrowed
  recovery keys of the old installation are lost with it: before you take it down, make sure no device still needs
  one. A backup bucket may be kept on purpose: until the stanzas are upgraded, `pgbackrest` and
  `pgbackrest-authentik` refuse the old stanzas, log why and take no backup. Once the new installation runs, upgrade
  them once with `./paddock compose run --rm --no-deps pgbackrest stanza-upgrade` and `./paddock compose run --rm
  --no-deps pgbackrest-authentik stanza-upgrade`; the old backups expire with retention and cannot be restored into
  the new clusters. Fleet's MySQL stays on the 8.4 line.
- From 0.1.0-alpha.7: the control plane's `.env` (and a lab host's) must set `PADDOCK_AUDIT_INDEX_RETENTION_DAYS`, the
  audit index retention in days. It has no default there: the worker's retention round deletes finished actions and
  commands, cleared alerts and filled event gaps no earlier than the audit index drops their month, and the worker
  does not start without the variable, or with a value below 400 days or below `PADDOCK_AUDIT_RETENTION_DAYS`. Set
  it to the value the audit host uses (an audit host whose `.env` does not set it uses its
  `PADDOCK_AUDIT_RETENTION_DAYS`, by default 400) and keep both variables the same on both hosts. `./paddock check`
  reports a missing or invalid value (item `audit index retention of the retention round`); `./paddock pull` and the
  other commands keep working until it is set.
- From 0.1.0-alpha.7 (audit host and lab): `./paddock up` creates the new Docker volume `audit-writer-tmp` for the
  audit writer's evidence export temp space (`docs/operations/audit-bucket.md` section 4); nothing to migrate. Check
  that Docker's data-root (`docker info -f '{{.DockerRootDir}}'`) has free space for one export of
  `PADDOCK_AUDIT_EXPORT_MAX_BYTES` (default 4 GiB). A rollback leaves the volume unused; `docker volume rm` removes it.
- From 0.1.0-alpha.7 (control plane and lab): `./paddock up` starts the new role `paddock-notifier`, which delivers
  security notifications to webhooks and e-mail (`docs/operations/notifications.md`). The fresh installation creates
  its database role `paddock_notifier`, its OpenBao AppRole and its files under `.secrets/` (`./paddock secrets`,
  `./paddock bootstrap openbao`); the section *Notifications on a cluster initialized before them* below is only for
  development builds between the two releases. Authentik applies the new blueprint `paddock-mcp.yaml` and the
  updated `paddock-portal.yaml` and `paddock-device.yaml` at its first start: every administrator signs in to the
  portal with a passkey, and the MCP stays off until an administrator saves an MCP policy (`docs/operations/mcp.md`).
- From 0.1.0-alpha.7: new settings in `.env.example`. `PADDOCK_AUDIT_INDEX_RETENTION_DAYS` is required (above).
  `PADDOCK_SMTP_ENABLED` (default `false`; `true` exactly when `PADDOCK_SMTP_HOST` is set) with the commented relay
  settings `PADDOCK_SMTP_HOST`, `PADDOCK_SMTP_PORT`, `PADDOCK_SMTP_TLS`, `PADDOCK_SMTP_USERNAME` and
  `PADDOCK_SMTP_FROM`, the relay password in `.secrets/smtp_password` (`docs/operations/install.md`, *E-mail relay*);
  `PADDOCK_AUDIT_EXPORT_MAX_BYTES` (audit host, default 4 GiB); `PADDOCK_AUTHENTIK_WEB_WORKERS` (default 4, about
  0.5 GiB more RAM for `authentik-server`; `docs/operations/capacity.md`, "Authentik web workers"). The roles read
  further settings that the shipped Compose files set or default: `PADDOCK_NOTIFY_POLL_INTERVAL`,
  `PADDOCK_NOTIFY_STALL_AFTER`, `PADDOCK_NOTIFY_BATCH`, `PADDOCK_SMTP_TIMEOUT` and `PADDOCK_SMTP_CA_FILE`
  (notifier), `PADDOCK_RETENTION_INTERVAL` (worker), `PADDOCK_AUDIT_EXPORT_POLL_INTERVAL` (audit writer),
  `PADDOCK_OIDC_MCP_ISSUER` and `PADDOCK_OIDC_MCP_CLIENT_ID` (api). `./paddock check` refuses
  `PADDOCK_OUTBOUND_DEV_ALLOW_PRIVATE` and `PADDOCK_SMTP_TLS=none`.
- From 0.1.0-alpha.7 (devices): the agent and the supervisor change in this release (watched third-party services,
  a cancelled or failed in-place encryption is disarmed before a restart can encrypt the disk, stuck
  supervisor-upgrade markers no longer hold rollouts, an interrupted self-test no longer fails an update). Because the
  installation is new, there is no upgrade order: remove Paddock from each device while the old server still runs
  (`docs/operations/uninstall.md`), then publish this release's agent release on the new server
  (`docs/operations/agent-releases.md`) and enrol the devices with its packages, never with an older agent. The
  revocation tool `paddock-revoke` is unchanged and stays unsigned; revocation stays disabled.

### Notifications on a cluster initialized before them

The database roles need no manual step: the one-shot service `db-provision` creates every control-plane role whose
password file is mounted (`paddock_notifier` among them) and sets every password again on each `./paddock up`, before
`paddock-migrate` runs (`postgres/provision-roles.sh`; plan M16 decision 8). A cluster initialized before the
notifications (plan M9) therefore only needs the files and the OpenBao bootstrap. On the control plane, in B's
directory, in this order:

1. Right after `./paddock migrate-from` (step 2), run `./paddock secrets`. It adds the notifier's files to the copied
   `.secrets/`: `db_paddock_notifier_password`, `db_paddock_notifier_url`, an empty `smtp_password` and empty
   `approle/paddock-notifier/role_id` and `secret_id`. Until the next step is done, `./paddock check` of step 2
   fails on `approle_notifier_role_id` and `approle_notifier_secret_id` (empty); that is expected.
2. Run `./paddock bootstrap openbao` (below); it fills the AppRole files.
3. Run `./paddock check` again: every item PASS. Only then continue with step 3 of the upgrade.

The OpenBao bootstrap, with A's stack running and OpenBao unsealed: run `./paddock bootstrap openbao` once in B's
directory with a root token (`docs/operations/openbao.md` section 1; revoke the token afterwards). It adds the Transit
keys `notification-wrap` and `notification-pseudonym`, the permissions of `paddock-api` on them, the policy and
AppRole `paddock-notifier`, and keeps every existing secret ID. It writes the notifier's AppRole files to
`.secrets/approle/paddock-notifier/role_id` and `secret_id` of B's directory; the notifier runs on the control plane,
so nothing goes to the audit host. If you ran the bootstrap in another directory, copy that directory's
`.secrets/approle/paddock-notifier/` to B's `.secrets/approle/` (`cp -a`) before step 5: B's `./paddock up` starts the
new role `paddock-notifier` and waits for it, and it cannot become healthy with empty AppRole files.

B's `.env.example` brings new keys; copy them into `.env` before the second `./paddock check`:

- `PADDOCK_SMTP_ENABLED=false`, or, with an SMTP relay for e-mail destinations, `true` together with
  `PADDOCK_SMTP_HOST`, `PADDOCK_SMTP_PORT`, `PADDOCK_SMTP_TLS`, `PADDOCK_SMTP_FROM` and, for a relay with
  authentication, `PADDOCK_SMTP_USERNAME` with the password in `.secrets/smtp_password` (`docs/operations/install.md`,
  *E-mail relay*). `./paddock check` fails while `PADDOCK_SMTP_ENABLED` and `PADDOCK_SMTP_HOST` disagree.

The same release adds the commit sequence of the audit index: its audit migration backfills every existing event, so
stop the audit writer first (step 4). The backfill takes about 1.5 minutes per million events in the index (measured:
1 000 000 events in 1 min 26 s on PostgreSQL 18); count them with `SELECT count(*) FROM audit_event` on
`paddock_audit` (`docs/operations/capacity.md`, *Audit index commit sequence backfill*).

## Upstream version watch

Dependabot proposes updates for Go modules, npm packages and GitHub Actions. It does not see the container images
pinned by tag and digest in `deploy/compose/versions.env`, the Himmelblau version the compiler rolls out
(`PADDOCK_HIMMELBLAU_VERSION` default in `server/cmd/paddock-server/compiler.go`), the fleetd build version (the tag
of `FLEETCTL_IMAGE`, reported as `fleetctl`) and the Fleet NVD release of `FLEET_CPE_DATABASE_URL` (reported as
`fleet_nvd`). The workflow *upstream-watch* (`.github/workflows/upstream-watch.yml`, every Monday 05:17 UTC and on
demand) compares each of them with upstream (ADR 0037 amendment 2026-10-17):

- **What it checks.** Images: the registry's tag list (Docker Hub API; ghcr.io, gcr.io and mcr.microsoft.com through
  the anonymous OCI distribution API). The latest tag is the highest tag of the same shape as the pin (`2.11.6` only
  compares with `x.y.z`, `4.3.6-management` with `x.y.z-management`). The floating `nonroot` tag of `RUNTIME_IMAGE` is
  compared by manifest digest. A pin can follow one line only (`Line` in `tools/upstreamwatch/pins.go`, today Fleet's
  MySQL on `8.4.`); newer lines are not reported for it. Himmelblau: the directory listing of
  `packages.himmelblau-idm.org/stable/`. Fleet NVD: the latest release of `fleetdm/nvd`. Each pin is classified `patch`, `minor`, `major`, `digest`, `ok` or `unknown`
  (a lookup failed; printed in the job log, never an issue).
- **The label.** Every outdated pin gets exactly one open issue with the label `upstream` and the title
  `upstream: <name> <pinned> → <latest>`. The body names the pinned line, the latest version, the classification,
  the release notes and the gates to run before the bump. When upstream moves again the issue is edited; once the pin
  is current the issue gets the comment `pinned <version> now` and is closed.
- **What to do with an issue.** Read the release notes, bump the pin in its own branch (resolve the new digest with
  `docker buildx imagetools inspect <image>:<tag>`), run the gates the issue lists, open a pull request. The
  watch closes the issue on its next run after the merge.
- **Local run.** `make upstream-check` prints one line `<name> <pinned> <latest> <classification>` per pin
  (`go run ./tools/upstreamwatch check --json` for JSON). Docker Hub rate-limits anonymous listings; a pin that
  turns `unknown` locally is retried by the next run.
- **Why issues and not pull requests.** Every pin has a gate a person runs before merging (WORM gate for RustFS,
  `TestIdentityLockAuthentik` for Authentik, the inventory gates for Fleet, the restore drill for Postgres and Caddy,
  the gitleaks default config hash for gitleaks). A bot pull request would suggest a bump is ready when it is not,
  and a bot with repository write access (Renovate) was rejected as a new external dependency. The job has
  `contents: read` and `issues: write` only.
