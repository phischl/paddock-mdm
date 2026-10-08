#!/bin/bash
# Daily dump of Fleet's MySQL for the backup bucket (plan M6a decision 6; RPO 24 h, the data is rebuildable from the
# devices). Runs in the pinned MySQL image (mysqldump, gzip, openssl) and writes the encrypted dump into the volume
# /dumps, from which fleet-backup-upload (backup-upload.sh) copies it to the bucket: the image's curl is too old for the
# S3 signature the object store requires.
#
#   backup.sh serve   dump when the last dump is older than 24 h, checked every 10 minutes (the service's command)
#   backup.sh once    dump now
#
# The dump is encrypted with AES-256-CBC (PBKDF2) under the backup encryption key before it leaves the container:
#   openssl enc -d -aes-256-cbc -pbkdf2 -pass file:backup_encryption_key -in <file> | gunzip
# Settings: PADDOCK_BACKUP_ENCRYPTION_KEY_FILE, FLEET_MYSQL_ROOT_PASSWORD_FILE.
set -euo pipefail

STATE=/dumps/.last-dump

dump() {
  local ts out
  ts="$(date -u +%Y%m%dT%H%M%SZ)"
  out="/dumps/$ts.sql.gz.enc"
  # The password goes through a file in the tmpfs, never through the command line.
  printf '[client]\nuser=root\npassword=%s\n' "$(cat "$FLEET_MYSQL_ROOT_PASSWORD_FILE")" >/tmp/my.cnf
  chmod 600 /tmp/my.cnf
  mysqldump --defaults-extra-file=/tmp/my.cnf -h fleet-mysql --single-transaction --routines --triggers \
    --set-gtid-purged=OFF --databases fleet |
    gzip -9 |
    openssl enc -aes-256-cbc -pbkdf2 -salt -pass "file:$PADDOCK_BACKUP_ENCRYPTION_KEY_FILE" -out "/dumps/.$ts.tmp" ||
    { rm -f "/dumps/.$ts.tmp" /tmp/my.cnf; return 1; }
  rm -f /tmp/my.cnf
  # The uploader takes only complete files.
  mv "/dumps/.$ts.tmp" "$out"
  date +%s >"$STATE"
  echo "fleet backup: dumped $(basename "$out")"
}

case "${1:-serve}" in
  once) dump ;;
  serve)
    while true; do
      last="$(cat "$STATE" 2>/dev/null || echo 0)"
      if (($(date +%s) - last >= 86400)); then
        dump || echo "fleet backup: dump failed; retrying in 10 minutes" >&2
      fi
      sleep 600
    done
    ;;
  *)
    echo "usage: backup.sh serve|once" >&2
    exit 2
    ;;
esac
