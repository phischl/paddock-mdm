#!/usr/bin/env bash
# pgBackRest for the control plane's PostgreSQL databases (plan M6a decision 4, docs/operations/restore.md).
#
#   serve     push archived WAL to the repository every 2 s and take a full backup when the last one is older than
#             24 h, and verify it (the service's command)
#   backup    take a full backup now (further arguments go to `pgbackrest backup`, e.g. --start-fast), after the
#             service's running backup if there is one, and verify it
#   flush     push every WAL file still in the spool
#   info      pgbackrest info
#   restore   restore the latest backup into the empty data directory and stage the WAL up to the newest archived
#             segment, so that PostgreSQL recovers to the latest point when it starts
#
# One container per database (stanza): pgBackRest requires the data directory at the path the server reports
# (/var/lib/postgresql/data). PostgreSQL runs in its own image without pgBackRest, so its archive_command copies each
# WAL file into the spool volume (/pgbackrest-spool/<stanza>) and this container pushes it.
#
# Settings: PADDOCK_BACKUP_STANZA (paddock or authentik), PADDOCK_BACKUP_PG_USER (the superuser that connects over
# the socket, default postgres), PADDOCK_BACKUP_S3_ENDPOINT (https URL; pgBackRest speaks
# TLS only), PADDOCK_BACKUP_S3_BUCKET, PADDOCK_BACKUP_S3_REGION (default us-east-1), PADDOCK_BACKUP_S3_CA_FILE
# (optional), PADDOCK_BACKUP_S3_ACCESS_KEY_FILE, PADDOCK_BACKUP_S3_SECRET_KEY_FILE, PADDOCK_BACKUP_ENCRYPTION_KEY_FILE
# (the repository is encrypted with aes-256-cbc), PADDOCK_BACKUP_RETENTION_FULL (default 14).
set -euo pipefail

STANZA="${PADDOCK_BACKUP_STANZA:?PADDOCK_BACKUP_STANZA is not set}"
SPOOL="/pgbackrest-spool/$STANZA"
STATE=/var/lib/pgbackrest

need() { [[ -n "${!1:-}" ]] || { echo "pgbackrest: $1 is not set" >&2; exit 2; }; }
for v in PADDOCK_BACKUP_S3_ENDPOINT PADDOCK_BACKUP_S3_BUCKET PADDOCK_BACKUP_S3_ACCESS_KEY_FILE \
  PADDOCK_BACKUP_S3_SECRET_KEY_FILE PADDOCK_BACKUP_ENCRYPTION_KEY_FILE; do
  need "$v"
done
endpoint="${PADDOCK_BACKUP_S3_ENDPOINT#https://}"
if [[ "$endpoint" == "$PADDOCK_BACKUP_S3_ENDPOINT" ]]; then
  echo "pgbackrest: PADDOCK_BACKUP_S3_ENDPOINT must be an https:// URL (pgBackRest speaks TLS only)" >&2
  exit 2
fi
endpoint="${endpoint%%/*}"

# Options as environment variables: no configuration file with the credentials on disk.
export PGBACKREST_REPO1_TYPE=s3
export PGBACKREST_REPO1_PATH=/pgbackrest
export PGBACKREST_REPO1_S3_BUCKET="$PADDOCK_BACKUP_S3_BUCKET"
export PGBACKREST_REPO1_S3_ENDPOINT="${endpoint%%:*}"
if [[ "$endpoint" == *:* ]]; then export PGBACKREST_REPO1_STORAGE_PORT="${endpoint##*:}"; fi
export PGBACKREST_REPO1_S3_REGION="${PADDOCK_BACKUP_S3_REGION:-us-east-1}"
export PGBACKREST_REPO1_S3_URI_STYLE=path
PGBACKREST_REPO1_S3_KEY="$(cat "$PADDOCK_BACKUP_S3_ACCESS_KEY_FILE")"
PGBACKREST_REPO1_S3_KEY_SECRET="$(cat "$PADDOCK_BACKUP_S3_SECRET_KEY_FILE")"
PGBACKREST_REPO1_CIPHER_PASS="$(cat "$PADDOCK_BACKUP_ENCRYPTION_KEY_FILE")"
export PGBACKREST_REPO1_S3_KEY PGBACKREST_REPO1_S3_KEY_SECRET PGBACKREST_REPO1_CIPHER_PASS
if [[ -n "${PADDOCK_BACKUP_S3_CA_FILE:-}" ]]; then export PGBACKREST_REPO1_STORAGE_CA_FILE="$PADDOCK_BACKUP_S3_CA_FILE"; fi
export PGBACKREST_REPO1_CIPHER_TYPE=aes-256-cbc
export PGBACKREST_REPO1_RETENTION_FULL="${PADDOCK_BACKUP_RETENTION_FULL:-14}"
export PGBACKREST_PG1_PATH=/var/lib/postgresql/data
export PGBACKREST_PG1_SOCKET_PATH=/var/run/postgresql
export PGBACKREST_PG1_USER="${PADDOCK_BACKUP_PG_USER:-postgres}"
export PGBACKREST_LOG_LEVEL_CONSOLE=info
export PGBACKREST_LOG_LEVEL_FILE=off
# The lock lives in the stanza's state volume, which the service and every one-off container (`backup`, the restore
# drill) share: with a lock in each container's own /tmp a one-off backup ran beside the service's, and the expire of
# one deleted the files of the other's backup set (restore drill, 2026-10-09).
export PGBACKREST_LOCK_PATH="$STATE/lock"
export PGBACKREST_SPOOL_PATH=/tmp/pgbackrest
export PGBACKREST_COMPRESS_TYPE=zst
# The backup waits for its last WAL segment, which reaches the repository through the spool.
export PGBACKREST_ARCHIVE_TIMEOUT=300

pgb() { pgbackrest --stanza="$STANZA" "$@"; }

# push_spool pushes the WAL files in name order; a failed push keeps the file for the next round.
push_spool() {
  local f
  [[ -f "$STATE/stanza" ]] || return 0
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

ensure_stanza() {
  [[ -f "$STATE/stanza" ]] && return 0
  pgb stanza-create && : >"$STATE/stanza"
}

# full_backup takes a full backup and reads it back with `pgbackrest verify`, so a set with a missing or damaged
# file fails now and not at restore time; verify reports problems in its output only, its exit code stays 0.
full_backup() {
  local label report
  pgb backup --type=full "$@" || return
  label="$(pgb info --output=json | grep -o '"label":"[^"]*"' | tail -1 | cut -d'"' -f4)"
  report="$(pgb verify --set="$label" --output=text --verbose)" || return
  if ! grep -q '^status: ok$' <<<"$report"; then
    echo "pgbackrest: backup $label of $STANZA failed verification:" >&2
    echo "$report" >&2
    return 1
  fi
  echo "pgbackrest: backup $label of $STANZA verified"
  date +%s >"$STATE/last-full"
}

# pusher keeps pushing the spool in the background: a backup waits for WAL segments that only the spool delivers.
# A file pushed twice (by the service and a one-off backup) is accepted by pgBackRest with the same checksum.
pusher() {
  while true; do
    push_spool || true
    sleep 2
  done
}

case "${1:-serve}" in
  serve)
    pusher &
    while true; do
      if ensure_stanza >/dev/null 2>&1; then
        last="$(cat "$STATE/last-full" 2>/dev/null || echo 0)"
        if (($(date +%s) - last >= 86400)); then
          full_backup || echo "pgbackrest: full backup of $STANZA failed; retrying in the next round" >&2
        fi
      else
        echo "pgbackrest: stanza $STANZA not ready (PostgreSQL starting?); retrying" >&2
      fi
      sleep 10
    done
    ;;
  backup)
    ensure_stanza
    pusher &
    trap 'kill $! 2>/dev/null || true' EXIT
    # The service may be taking its scheduled backup: wait for the stanza's lock for up to 15 minutes. flock(1) sees
    # pgBackRest's lock, so the wait is one log line instead of a failed backup (ERROR [050]) every round; a backup
    # that loses the race to the lock still exits 50 and is retried.
    lock="$PGBACKREST_LOCK_PATH/$STANZA-backup-1.lock"
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
  flush)
    push_spool
    ;;
  info)
    pgb info
    ;;
  restore)
    restore_dir="$SPOOL/restore"
    # The restored cluster reads its WAL from the staged directory: PostgreSQL's image has no pgBackRest.
    pgb restore --recovery-option="restore_command=cp $restore_dir/%f %p"
    rm -rf "$restore_dir" && mkdir -p "$restore_dir"
    # Every segment from the backup's first one on, until the repository has no next one.
    label="$(pgb info --output=json | grep -o '"label":"[^"]*"' | tail -1 | cut -d'"' -f4)"
    start="$(pgb info --set="$label" --output=json | grep -o '"start":"[0-9A-F]\{24\}"' | head -1 | cut -d'"' -f4)"
    [[ -n "$start" ]] || { echo "pgbackrest: cannot read the WAL start of backup $label" >&2; exit 1; }
    tli="${start:0:8}"
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
      # archive-get exits 1 when the segment is not in the repository: the end of the archive. Any other error (S3,
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
    echo "usage: paddock-pgbackrest serve|backup|flush|info|restore" >&2
    exit 2
    ;;
esac
