#!/usr/bin/env bash
# pgBackRest for the control plane's PostgreSQL databases (plan M6a decision 4, plan M15 decision 17,
# docs/operations/restore.md).
#
#   serve     push archived WAL to the repository every 2 s and take a full backup when the last one is older than the
#             interval of schedule.env, when the backup role requested one, or at once after a key rotation, and
#             verify it (the service's command); without the key file it waits and takes nothing
#   backup    take a full backup now (further arguments go to `pgbackrest backup`, e.g. --start-fast), after the
#             service's running backup if there is one, and verify it
#   verify    verify the whole stanza (every backup and the WAL archive) without a time limit and record verify-ok when
#             it reports ok: the operator's path when the verify after a full backup keeps exceeding its 15 minutes and
#             the targets hold WAL (plan M15, amendment 2026-11-05, A7; decisions-alpha9 item 33)
#   flush     push every WAL file still in the spool
#   info      pgbackrest info
#   restore [--at <timestamp>] [--repo-path <pgbackrest/key_id>]
#             restore into the empty data directory and stage the WAL up to the newest archived segment, so that
#             PostgreSQL recovers when it starts: to the latest point, or with --at to that time (then promote);
#             --repo-path restores from another key's repository of the set
#   stanza-upgrade
#             point the stanza at the running cluster when the repository holds it for another cluster (a fresh
#             installation into a kept repository); run once by the operator (docs/operations/upgrade.md)
#
# One container per database (stanza): pgBackRest requires the data directory at the path the server reports
# (/var/lib/postgresql/18/docker). PostgreSQL runs in its own image without pgBackRest, so its archive_command copies each
# WAL file into the spool volume (/pgbackrest-spool/<stanza>) and this container pushes it.
#
# The repository is the local posix directory PADDOCK_BACKUP_REPO_DIR (default /backup-repo, the volume backup-repo);
# the backup role mirrors it to the targets. The role is the only process that decrypts the backup key: it writes the
# key into the runtime tmpfs (PADDOCK_BACKUP_RUNTIME_DIR, default /run/paddock-backup, mounted read-only here) as
# `key`, and `schedule.env` with PADDOCK_BACKUP_REPO_PATH (pgbackrest/<key_id>), PADDOCK_BACKUP_RETENTION_FULL and
# PADDOCK_BACKUP_FULL_INTERVAL_S; `request-<stanza>` holds the time of a requested backup. Every new key starts a new
# repository path; the role expires the old one. The state volume (/var/lib/pgbackrest) keeps the lock, `last-full`,
# `last-full-start`, `last-error` and `verify-ok` (Unix seconds, read by the backup role) and `repo-path`.
#
# Settings: PADDOCK_BACKUP_STANZA (paddock or authentik), PADDOCK_BACKUP_PG_USER (the superuser that connects over
# the socket, default postgres), PADDOCK_BACKUP_REPO_DIR, PADDOCK_BACKUP_RUNTIME_DIR.
set -euo pipefail

STANZA="${PADDOCK_BACKUP_STANZA:?PADDOCK_BACKUP_STANZA is not set}"
SPOOL="/pgbackrest-spool/$STANZA"
STATE=/var/lib/pgbackrest
REPO="${PADDOCK_BACKUP_REPO_DIR:-/backup-repo}"
RUNTIME="${PADDOCK_BACKUP_RUNTIME_DIR:-/run/paddock-backup}"
# After a failed full backup serve waits this long before the next attempt (a request is taken at once).
RETRY_S=900
# The whole-stanza verify after a full backup gets this long; past it only the new backup is verified (plan M15,
# amendment 2026-11-05, A7). The variable exists for the test only.
VERIFY_S="${PADDOCK_BACKUP_VERIFY_S:-900}"

# Options as environment variables: no configuration file with the key on disk.
export PGBACKREST_REPO1_TYPE=posix
export PGBACKREST_REPO1_CIPHER_TYPE=aes-256-cbc
# The 18 image keeps the cluster below the volume mount (/var/lib/postgresql/<major>/docker); pgBackRest needs the
# path the server reports (plan M6d decision 4).
export PGBACKREST_PG1_PATH=/var/lib/postgresql/18/docker
export PGBACKREST_PG1_SOCKET_PATH=/var/run/postgresql
export PGBACKREST_PG1_USER="${PADDOCK_BACKUP_PG_USER:-postgres}"
export PGBACKREST_LOG_LEVEL_CONSOLE=info
export PGBACKREST_LOG_LEVEL_FILE=off
# The lock lives in the stanza's state volume, which the service and every one-off container (`backup`, the restore
# drill) share: with a lock in each container's own /tmp a one-off backup ran beside the service's, and the expire of
# one deleted the files of the other's backup set (restore drill, 2026-10-09).
export PGBACKREST_LOCK_PATH="$STATE/lock"
# pgBackRest's backup lock of the stanza; flock(1) sees it.
STANZA_LOCK="$PGBACKREST_LOCK_PATH/$STANZA-backup-1.lock"
export PGBACKREST_SPOOL_PATH=/tmp/pgbackrest
export PGBACKREST_COMPRESS_TYPE=zst
# The backup waits for its last WAL segment, which reaches the repository through the spool.
export PGBACKREST_ARCHIVE_TIMEOUT=300

# schedule_value <name> prints a value of schedule.env; the file is parsed, never sourced.
schedule_value() { grep -E "^$1=" "$RUNTIME/schedule.env" 2>/dev/null | tail -1 | cut -d= -f2-; }

# load_runtime reads the key and schedule.env of the backup role; it fails while either is missing or invalid.
# repo_path overrides the repository path (restore --repo-path).
load_runtime() {
  local repo_path="${1:-}"
  [[ -s "$RUNTIME/key" && -s "$RUNTIME/schedule.env" ]] || return 1
  REPO_PATH="${repo_path:-$(schedule_value PADDOCK_BACKUP_REPO_PATH)}"
  RETENTION_FULL="$(schedule_value PADDOCK_BACKUP_RETENTION_FULL)"
  FULL_INTERVAL_S="$(schedule_value PADDOCK_BACKUP_FULL_INTERVAL_S)"
  if [[ ! "$REPO_PATH" =~ ^pgbackrest/(bk-[0-9]{8}-[0-9a-f]{8}|legacy)$ || ! "$RETENTION_FULL" =~ ^[0-9]+$ ||
    ! "$FULL_INTERVAL_S" =~ ^[0-9]+$ ]]; then
    echo "pgbackrest: $RUNTIME/schedule.env is invalid" >&2
    return 1
  fi
  export PGBACKREST_REPO1_PATH="$REPO/$REPO_PATH"
  export PGBACKREST_REPO1_RETENTION_FULL="$RETENTION_FULL"
  PGBACKREST_REPO1_CIPHER_PASS="$(cat "$RUNTIME/key")"
  export PGBACKREST_REPO1_CIPHER_PASS
}

# require_runtime is load_runtime for the one-off commands: without the key they fail instead of waiting.
require_runtime() {
  load_runtime "$@" || {
    echo "pgbackrest: no backup key in $RUNTIME (confirm a backup key in the portal; the backup role writes it)" >&2
    exit 3
  }
}

pgb() { pgbackrest --stanza="$STANZA" "$@"; }

# push_spool pushes the WAL files in name order; a failed push keeps the file for the next round.
push_spool() {
  local f
  [[ -f "$STATE/stanza" && "$(cat "$STATE/repo-path" 2>/dev/null)" == "$REPO_PATH" ]] || return 0
  for f in $(ls -1 "$SPOOL" 2>/dev/null | grep -v '^restore$' | sort); do
    [[ -f "$SPOOL/$f" ]] || continue
    if pgb archive-push "$SPOOL/$f" >/dev/null; then
      rm -f "$SPOOL/$f"
    else
      echo "pgbackrest: archive-push of $STANZA/$f failed; retrying" >&2
      return 1
    fi
  done
}

# ensure_stanza creates the stanza once. A repository that holds the stanza for another cluster (other system
# identifier or major) is refused, never upgraded here: on a rebuilt host the service would otherwise start backing up
# the empty new cluster, and its newest set would be what a disaster restore brings back (plan M6d, amendment
# 2026-10-30). The operator runs `stanza-upgrade` once when the bucket is kept on purpose.
ensure_stanza() {
  [[ -f "$STATE/stanza" ]] && return 0
  local rc=0
  pgb stanza-create || rc=$?
  if ((rc == 28)); then
    echo "pgbackrest: the repository holds stanza $STANZA for another cluster; no backups. Restoring this host?" \
      "Restore first (docs/operations/restore.md), never run stanza-upgrade. Only a fresh installation into a" \
      "deliberately kept bucket runs stanza-upgrade once (docs/operations/upgrade.md)" >&2
  fi
  ((rc == 0)) && : >"$STATE/stanza"
}

# full_backup takes a full backup and reads it back with `pgbackrest verify`, so a set with a missing or damaged
# file fails now and not at restore time; verify reports problems in its output only, its exit code stays 0. It
# verifies the whole stanza (every backup and the WAL archive) first: when that reports ok, `verify-ok` records the
# time, and only then does the backup role let WAL leave the targets (plan M15, amendment 2026-11-05, A2). A whole
# verify that reports a problem (a gap in the archive) or does not finish within VERIFY_S leaves `verify-ok` as it is,
# and the new backup alone must pass `verify --set`.
full_backup() {
  local label report started rc=0
  started="$(date +%s)"
  pgb backup --type=full "$@" || return
  label="$(pgb info --output=json | grep -o '"label":"[^"]*"' | tail -1 | cut -d'"' -f4)"
  report="$(timeout "$VERIFY_S" pgbackrest --stanza="$STANZA" verify --output=text --verbose)" || rc=$?
  if ((rc == 0)) && grep -q '^status: ok$' <<<"$report"; then
    echo "pgbackrest: stanza $STANZA verified"
    echo "pgbackrest: backup $label of $STANZA verified"
    date +%s >"$STATE/verify-ok"
    echo "$started" >"$STATE/last-full-start"
    date +%s >"$STATE/last-full"
    return 0
  fi
  if ((rc == 124)); then
    echo "pgbackrest: the verify of stanza $STANZA did not finish within $VERIFY_S seconds; verifying backup" \
      "$label only (WAL stays on the backup targets)" >&2
  else
    echo "pgbackrest: the verify of stanza $STANZA reported a problem (WAL stays on the backup targets):" >&2
    echo "$report" >&2
  fi
  report="$(pgb verify --set="$label" --output=text --verbose)" || return
  if ! grep -q '^status: ok$' <<<"$report"; then
    echo "pgbackrest: backup $label of $STANZA failed verification:" >&2
    echo "$report" >&2
    return 1
  fi
  echo "pgbackrest: backup $label of $STANZA verified"
  echo "$started" >"$STATE/last-full-start"
  date +%s >"$STATE/last-full"
}

# switch_repo_path starts over in a new repository path (a new backup key, plan M15 decision 17): the stanza is
# created there and a full backup taken at once; the old path stays for the backup role's expire.
switch_repo_path() {
  [[ "$(cat "$STATE/repo-path" 2>/dev/null)" == "$REPO_PATH" ]] && return 0
  echo "pgbackrest: repository of $STANZA is now $REPO_PATH; creating the stanza and taking a full backup"
  rm -f "$STATE/stanza" "$STATE/last-full" "$STATE/last-full-start" "$STATE/last-error" "$STATE/verify-ok"
  echo "$REPO_PATH" >"$STATE/repo-path"
}

# full_due reports whether serve takes a full backup now: the interval passed, the backup role requested one after the
# last full started, or the path is new; after a failure it waits RETRY_S unless a newer request came. A full that was
# already running when the request came does not answer it: the request asks for a backup taken from then on, and the
# role answers it only with a full that started at or after it (decisions-alpha9 item 89).
full_due() {
  local now last start failed req
  now="$(date +%s)"
  last="$(cat "$STATE/last-full" 2>/dev/null || echo 0)"
  start="$(cat "$STATE/last-full-start" 2>/dev/null || echo "$last")"
  failed="$(cat "$STATE/last-error" 2>/dev/null || echo 0)"
  req="$(cat "$RUNTIME/request-$STANZA" 2>/dev/null || echo 0)"
  [[ "$req" =~ ^[0-9]+$ ]] || req=0
  if ((failed > last && now - failed < RETRY_S && req <= failed)); then
    return 1
  fi
  ((now - last >= FULL_INTERVAL_S || req > start))
}

# pusher keeps pushing the spool in the background: a backup waits for WAL segments that only the spool delivers.
# A file pushed twice (by the service and a one-off backup) is accepted by pgBackRest with the same checksum.
pusher() {
  while true; do
    if load_runtime "${1:-}" 2>/dev/null; then push_spool || true; fi
    sleep 2
  done
}

case "${1:-serve}" in
  serve)
    pusher &
    waiting=false
    while true; do
      if ! load_runtime; then
        if ! $waiting; then
          echo "$(date -u '+%F %T') INFO: waiting for the backup key; no backup of $STANZA until a key is confirmed"
          waiting=true
        fi
        sleep 10
        continue
      fi
      waiting=false
      switch_repo_path
      if ensure_stanza; then
        if full_due; then
          # The operator's verify holds the lock for as long as it runs: the full waits for it instead of failing.
          # The first full in a new path (a key rotation, switch_repo_path drops last-full) forces the checkpoint:
          # the rotation must not wait up to checkpoint_timeout. Scheduled fulls keep the default (decisions-alpha9
          # item 87).
          fast=()
          [[ -e "$STATE/last-full" ]] || fast=(--start-fast)
          if [[ -e "$STANZA_LOCK" ]] && ! flock -n "$STANZA_LOCK" true; then
            :
          elif ! full_backup "${fast[@]}"; then
            date +%s >"$STATE/last-error"
            echo "pgbackrest: full backup of $STANZA failed; retrying in $((RETRY_S / 60)) minutes" >&2
          fi
        fi
      else
        echo "pgbackrest: stanza $STANZA not ready; retrying" >&2
      fi
      sleep 10
    done
    ;;
  backup)
    require_runtime
    switch_repo_path
    ensure_stanza
    pusher &
    trap 'kill $! 2>/dev/null || true' EXIT
    # The service may be taking its scheduled backup: wait for the stanza's lock for up to 15 minutes. flock(1) sees
    # pgBackRest's lock, so the wait is one log line instead of a failed backup (ERROR [050]) every round; a backup
    # that loses the race to the lock still exits 50 and is retried.
    lock="$STANZA_LOCK"
    waiting=false
    for _ in $(seq 1 90); do
      if [[ -e "$lock" ]] && ! flock -n "$lock" true; then
        if ! $waiting; then
          echo "$(date -u '+%F %T') INFO: waiting for the running backup of $STANZA to finish"
          waiting=true
        fi
        sleep 10
        continue
      fi
      rc=0
      full_backup "${@:2}" || rc=$?
      if ((rc != 50)); then exit "$rc"; fi
      sleep 10
    done
    echo "pgbackrest: the running backup of $STANZA did not finish within 15 minutes" >&2
    exit 50
    ;;
  verify)
    require_runtime
    # verify-ok gets the start time and the backup role trusts it only when it is newer than the newest full, whose
    # time is its label, the full's start. pgBackRest's verify sees only the backups already in backup.info, so a full
    # running beside it would start before verify-ok without being covered: the verify holds the stanza's backup lock
    # throughout (PDK-733 review 1), after the running backup if there is one, as `backup` waits for it.
    mkdir -p "$PGBACKREST_LOCK_PATH"
    locked=false waiting=false
    for _ in $(seq 1 91); do
      exec 9>>"$STANZA_LOCK"
      # pgBackRest removes its lock file on release: a lock on a file no longer at the path would exclude nothing.
      if flock -n 9 && [[ "$STANZA_LOCK" -ef /dev/fd/9 ]]; then
        locked=true
        break
      fi
      exec 9>&-
      if ! $waiting; then
        echo "$(date -u '+%F %T') INFO: waiting for the running backup of $STANZA to finish"
        waiting=true
      fi
      sleep 10
    done
    if ! $locked; then
      echo "pgbackrest: the running backup of $STANZA did not finish within 15 minutes" >&2
      exit 50
    fi
    started="$(date +%s)"
    rc=0
    report="$(pgb verify --output=text --verbose 9>&-)" || rc=$?
    if ((rc == 0)) && grep -q '^status: ok$' <<<"$report"; then
      # serve's own verify may have recorded a later time meanwhile.
      prev="$(cat "$STATE/verify-ok" 2>/dev/null || echo 0)"
      [[ "$prev" =~ ^[0-9]+$ ]] || prev=0
      if ((started > prev)); then echo "$started" >"$STATE/verify-ok"; fi
      echo "pgbackrest: stanza $STANZA verified; the backup role releases the WAL held on the targets in its next round"
      exit 0
    fi
    echo "pgbackrest: the verify of stanza $STANZA failed (exit $rc); WAL stays on the backup targets:" >&2
    echo "$report" >&2
    exit 1
    ;;
  flush)
    require_runtime
    push_spool
    ;;
  info)
    require_runtime
    pgb info
    ;;
  stanza-upgrade)
    require_runtime
    pgb stanza-upgrade
    ;;
  restore)
    at="" repo_path=""
    shift
    while (($#)); do
      case "$1" in
        --at) at="${2:?--at needs a timestamp}"; shift 2 ;;
        --repo-path) repo_path="${2:?--repo-path needs a path}"; shift 2 ;;
        *) echo "usage: paddock-pgbackrest restore [--at <timestamp>] [--repo-path <pgbackrest/key_id>]" >&2; exit 2 ;;
      esac
    done
    require_runtime "$repo_path"
    restore_dir="$SPOOL/restore"
    target=()
    if [[ -n "$at" ]]; then
      target=(--type=time "--target=$at" --target-action=promote)
    fi
    # The restored cluster reads its WAL from the staged directory: PostgreSQL's image has no pgBackRest.
    out="$(pgb restore "${target[@]}" --recovery-option="restore_command=cp $restore_dir/%f %p" 2>&1)" || {
      echo "$out" >&2
      exit 1
    }
    echo "$out"
    rm -rf "$restore_dir" && mkdir -p "$restore_dir"
    # The staging starts at the backup pgBackRest restored, on that backup's timeline: after a restore or a
    # promotion the archive holds several timelines, and the oldest backup's lies before the restored one's
    # (gate BS4; decisions-alpha9 item 89). Without pgBackRest's line the newest backup is the default it restores.
    label="$({ grep -oE 'restore backup set [0-9]{8}-[0-9]{6}F(_[0-9]{8}-[0-9]{6}[DI])?' <<<"$out" || true; } |
      tail -1 | awk '{print $4}')"
    [[ -n "$label" ]] || label="$(pgb info --output=json | grep -o '"label":"[^"]*"' | tail -1 | cut -d'"' -f4)"
    start="$(pgb info --set="$label" --output=json | grep -o '"start":"[0-9A-F]\{24\}"' | head -1 | cut -d'"' -f4)"
    [[ -n "$start" ]] || { echo "pgbackrest: cannot read the WAL start of backup $label" >&2; exit 1; }
    tli="${start:0:8}"
    # The history files of the timelines up to the backup's, so that recovery follows its timeline's parents.
    for ((t = 2; t <= 16#$tli; t++)); do
      h="$(printf '%08X.history' "$t")"
      rc=0
      pgb archive-get "$h" "$restore_dir/$h" >/dev/null 2>&1 || rc=$?
      ((rc == 0 || rc == 1)) || { echo "pgbackrest: archive-get $h failed (exit $rc)" >&2; exit 1; }
    done
    log=$((16#${start:8:8}))
    seg=$((16#${start:16:8}))
    n=0
    # The newest segment the repository holds: staging must reach it, else recovery would end early without an error.
    max="$(pgb info --output=json | grep -o '"max":"[0-9A-F]\{24\}"' | tail -1 | cut -d'"' -f4)"
    last=""
    while true; do
      name="$(printf '%s%08X%08X' "$tli" "$log" "$seg")"
      rc=0
      pgb archive-get "$name" "$restore_dir/$name" >"$restore_dir/.archive-get.log" 2>&1 || rc=$?
      # archive-get exits 1 when the segment is not in the repository: the end of the archive. Any other error (I/O,
      # decryption) fails the restore instead of ending it early.
      if ((rc == 1)); then
        break
      elif ((rc != 0)); then
        cat "$restore_dir/.archive-get.log" >&2
        echo "pgbackrest: archive-get $name failed (exit $rc); the restore is incomplete" >&2
        exit 1
      fi
      last="$name"
      n=$((n + 1))
      seg=$((seg + 1))
      # 16 MB segments: 256 per log file.
      if ((seg > 255)); then
        seg=0
        log=$((log + 1))
      fi
    done
    rm -f "$restore_dir/.archive-get.log"
    if [[ -n "$max" && "${max:0:8}" == "$tli" && "$last" < "$max" ]]; then
      echo "pgbackrest: staged WAL up to ${last:-nothing}, but the archive holds up to $max; the restore is incomplete" >&2
      exit 1
    fi
    echo "restored $STANZA from backup $label; staged $n WAL segments from $start to ${last:-none}"
    ;;
  *)
    echo "usage: paddock-pgbackrest serve|backup|flush|info|restore|stanza-upgrade" >&2
    exit 2
    ;;
esac
