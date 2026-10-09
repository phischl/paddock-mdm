#!/usr/bin/env bash
# Test of the pgBackRest behaviour run.sh relies on (`make test`, needs Docker and the image paddock-pgbackrest:dev,
# built by `make image-pgbackrest`): two containers that share the lock path on a volume cannot back up the same stanza
# at once (the second exits 50, and flock(1) sees the lock), and `verify --output=text --verbose` reports a backup set with a missing file as
# "status: error" while its exit code stays 0. Throwaway PostgreSQL and a posix repository in volumes.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
pg_image="$(grep '^POSTGRES_IMAGE=' "$here/../versions.env" | cut -d= -f2-)"
image="${PADDOCK_PGBACKREST_IMAGE:-paddock-pgbackrest:dev}"
id="paddock-pgbackrest-test-$$"
failures=0
cleanup() {
  kill "${pusher_pid:-}" 2>/dev/null || true
  docker rm -f "$id-pg" >/dev/null 2>&1 || true
  docker volume rm "$id-data" "$id-sock" "$id-repo" "$id-state" >/dev/null 2>&1 || true
}
trap cleanup EXIT
check() { # check <name> <condition result 0|1>
  if [[ "$2" == 0 ]]; then echo "ok   $1"; else echo "FAIL $1"; failures=$((failures + 1)); fi
}

for v in data sock repo state; do docker volume create "$id-$v" >/dev/null; done
docker run --rm -u 0 --entrypoint sh -v "$id-repo:/repo" -v "$id-state:/state" -v "$id-sock:/sock" "$image" \
  -c 'chown 999:999 /repo /state && chmod 777 /sock'
# The archive_command must name pgbackrest (pgBackRest checks it); the spool stands in for compose.backup.yaml's.
docker run -d --name "$id-pg" -e POSTGRES_PASSWORD=test -v "$id-data:/var/lib/postgresql/data" \
  -v "$id-sock:/var/run/postgresql" "$pg_image" -c archive_mode=on \
  -c 'archive_command=mkdir -p /var/run/postgresql/pgbackrest-spool && cp %p /var/run/postgresql/pgbackrest-spool/%f' >/dev/null
for _ in $(seq 1 60); do docker exec "$id-pg" pg_isready -U postgres >/dev/null 2>&1 && break; sleep 1; done
sleep 2
docker exec -u postgres "$id-pg" psql -qc 'create table t as select g, md5(g::text) from generate_series(1, 200000) g'

pgb() {
  docker run --rm -v "$id-data:/var/lib/postgresql/data" -v "$id-sock:/var/run/postgresql" -v "$id-repo:/repo" \
    -v "$id-state:/state" -e PGBACKREST_LOCK_PATH=/state/lock -e PGBACKREST_STANZA=test -e PGBACKREST_REPO1_PATH=/repo \
    -e PGBACKREST_REPO1_RETENTION_FULL=2 -e PGBACKREST_PG1_PATH=/var/lib/postgresql/data \
    -e PGBACKREST_PG1_SOCKET_PATH=/var/run/postgresql -e PGBACKREST_LOG_LEVEL_CONSOLE=error \
    --entrypoint pgbackrest "$image" "$@"
}
pgb stanza-create
(
  while true; do
    for f in $(docker exec "$id-pg" sh -c 'ls /var/run/postgresql/pgbackrest-spool 2>/dev/null'); do
      pgb archive-push "/var/run/postgresql/pgbackrest-spool/$f" >/dev/null 2>&1 &&
        docker exec "$id-pg" rm -f "/var/run/postgresql/pgbackrest-spool/$f"
    done
    sleep 1
  done
) &
pusher_pid=$!

pgb backup --type=full --start-fast >/dev/null 2>&1 &
first=$!
sleep 1
held=0
docker run --rm --entrypoint flock -v "$id-state:/state" "$image" -n /state/lock/test-backup-1.lock true || held=$?
check "flock(1) sees the lock of the running backup (run.sh waits on it)" "$([[ $held != 0 ]] && echo 0 || echo 1)"
second=0
pgb backup --type=full --start-fast >/dev/null 2>&1 || second=$?
first_rc=0
wait "$first" || first_rc=$?
check "a second backup of the stanza waits for the lock (exit $second, want 50)" "$([[ $second == 50 ]] && echo 0 || echo 1)"
check "the first backup completes (exit $first_rc)" "$([[ $first_rc == 0 ]] && echo 0 || echo 1)"

label="$(pgb info --output=json | grep -o '"label":"[^"]*"' | tail -1 | cut -d'"' -f4)"
report="$(pgb verify --set="$label" --output=text --verbose)"
check "verify reports an intact set as status: ok" "$(grep -q '^status: ok$' <<<"$report" && echo 0 || echo 1)"
docker run --rm -u 0 --entrypoint sh -v "$id-repo:/repo" "$image" \
  -c "rm \"\$(find /repo/backup/test/$label/pg_data/base -type f -size +10k | head -1)\""
rc=0
report="$(pgb verify --set="$label" --output=text --verbose)" || rc=$?
check "verify reports a set with a missing file as status: error, exit $rc" \
  "$(grep -q '^status: error$' <<<"$report" && grep -q 'missing: 1' <<<"$report" && echo 0 || echo 1)"

exit "$((failures > 0))"
