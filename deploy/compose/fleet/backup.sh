#!/bin/bash
# Dumps of Fleet's MySQL for the backup set (plan M6a decision 6, plan M15 decision 16; RPO 24 h by default, the data is
# rebuildable from the devices). Runs in the pinned MySQL image (mysqldump, gzip) and writes the plaintext dump into the
# volume /dumps; the backup role (paddock-backup, uid 999) seals it with the backup key into the local repository and
# deletes it. This container never holds the key.
#
#   backup.sh serve   dump whenever the backup role asks for one (it writes /dumps/.request when the schedule's Fleet
#                     interval passed or a run was requested), checked every 10 seconds (the service's command)
#   backup.sh once    dump now
#
# Settings: FLEET_MYSQL_ROOT_PASSWORD_FILE.
set -euo pipefail

REQUEST=/dumps/.request
# The backup role runs as uid 999: it reads the dump and deletes it after sealing.
ROLE_UID=999

dump() {
  local ts out
  ts="$(date -u +%Y%m%dT%H%M%SZ)"
  out="/dumps/$ts.sql.gz"
  # The password goes through a file in the tmpfs, never through the command line.
  printf '[client]\nuser=root\npassword=%s\n' "$(cat "$FLEET_MYSQL_ROOT_PASSWORD_FILE")" >/tmp/my.cnf
  chmod 600 /tmp/my.cnf
  (umask 027 && mysqldump --defaults-extra-file=/tmp/my.cnf -h fleet-mysql --single-transaction --routines --triggers \
    --set-gtid-purged=OFF --databases fleet | gzip -9 >"/dumps/.$ts.tmp") ||
    { rm -f "/dumps/.$ts.tmp" /tmp/my.cnf; return 1; }
  rm -f /tmp/my.cnf
  chown "$ROLE_UID:$ROLE_UID" "/dumps/.$ts.tmp"
  # The backup role takes only complete files.
  mv "/dumps/.$ts.tmp" "$out"
  echo "fleet backup: dumped $(basename "$out")"
}

# migrated reports whether Fleet created its schema: on a fresh installation the service starts with fleet-mysql, before
# Fleet's migrations, and a dump then would be an empty database that counts as the day's backup.
migrated() {
  printf '[client]\nuser=root\npassword=%s\n' "$(cat "$FLEET_MYSQL_ROOT_PASSWORD_FILE")" >/tmp/my.cnf
  chmod 600 /tmp/my.cnf
  local n
  n="$(mysql --defaults-extra-file=/tmp/my.cnf -h fleet-mysql -N -B -e \
    "select count(*) from information_schema.tables where table_schema = 'fleet' and table_name = 'migration_status_tables'" \
    2>/dev/null || echo 0)"
  rm -f /tmp/my.cnf
  [[ "$n" == 1 ]]
}

case "${1:-serve}" in
  once) dump ;;
  serve)
    chown "$ROLE_UID:$ROLE_UID" /dumps
    chmod 750 /dumps
    waiting=false
    while true; do
      if [[ -e "$REQUEST" ]]; then
        if ! migrated; then
          if ! $waiting; then echo "fleet backup: Fleet's schema is not there yet; waiting" >&2; fi
          waiting=true
        elif dump; then
          rm -f "$REQUEST"
          waiting=false
        else
          echo "fleet backup: dump failed; retrying in 10 minutes" >&2
          sleep 590
        fi
      fi
      sleep 10
    done
    ;;
  *)
    echo "usage: backup.sh serve|once" >&2
    exit 2
    ;;
esac
