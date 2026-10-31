#!/usr/bin/env bash
# Test of the pgBackRest behaviour run.sh relies on (`make test`, needs Docker and the image paddock-pgbackrest:dev,
# built by `make image-pgbackrest`): two containers that share the lock path on a volume cannot back up the same stanza
# at once (the second exits 50, and flock(1) sees the lock), `verify --output=text --verbose` reports a backup set with a missing file as
# "status: error" while its exit code stays 0, and run.sh refuses a repository that holds the stanza for another
# cluster until its `stanza-upgrade` runs. Throwaway PostgreSQL and a posix repository in volumes.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
pg_image="$(grep '^POSTGRES_IMAGE=' "$here/../versions.env" | cut -d= -f2-)"
image="${PADDOCK_PGBACKREST_IMAGE:-paddock-pgbackrest:dev}"
id="paddock-pgbackrest-test-$$"
failures=0
cleanup() {
  kill "${pusher_pid:-}" 2>/dev/null || true
  docker rm -f "$id-pg" "$id-pg2" "$id-serve" >/dev/null 2>&1 || true
  docker volume rm "$id-data" "$id-sock" "$id-repo" "$id-state" "$id-data2" "$id-sock2" "$id-spool2" "$id-state2" \
    "$id-bin" >/dev/null 2>&1 || true
}
trap cleanup EXIT
check() { # check <name> <condition result 0|1>
  if [[ "$2" == 0 ]]; then echo "ok   $1"; else echo "FAIL $1"; failures=$((failures + 1)); fi
}

for v in data sock repo state; do docker volume create "$id-$v" >/dev/null; done
docker run --rm -u 0 --entrypoint sh -v "$id-repo:/repo" -v "$id-state:/state" -v "$id-sock:/sock" "$image" \
  -c 'chown 999:999 /repo /state && chmod 777 /sock'
# The archive_command must name pgbackrest (pgBackRest checks it); the spool stands in for compose.backup.yaml's.
docker run -d --name "$id-pg" -e POSTGRES_PASSWORD=test -v "$id-data:/var/lib/postgresql" \
  -v "$id-sock:/var/run/postgresql" "$pg_image" -c archive_mode=on \
  -c 'archive_command=mkdir -p /var/run/postgresql/pgbackrest-spool && cp %p /var/run/postgresql/pgbackrest-spool/%f' >/dev/null
for _ in $(seq 1 60); do docker exec "$id-pg" pg_isready -U postgres >/dev/null 2>&1 && break; sleep 1; done
sleep 2
docker exec -u postgres "$id-pg" psql -qc 'create table t as select g, md5(g::text) from generate_series(1, 200000) g'

pgb() {
  docker run --rm -v "$id-data:/var/lib/postgresql" -v "$id-sock:/var/run/postgresql" -v "$id-repo:/repo" \
    -v "$id-state:/state" -e PGBACKREST_LOCK_PATH=/state/lock -e PGBACKREST_STANZA=test -e PGBACKREST_REPO1_PATH=/repo \
    -e PGBACKREST_REPO1_RETENTION_FULL=2 -e PGBACKREST_PG1_PATH=/var/lib/postgresql/18/docker \
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

# run.sh against a second cluster of the same major whose stanza name the repository already holds (a rebuilt host
# with a kept bucket). run.sh speaks S3 only: a pgbackrest earlier in PATH points it at the posix repository.
kill "$pusher_pid" 2>/dev/null || true
for v in data2 sock2 spool2 state2 bin; do docker volume create "$id-$v" >/dev/null; done
docker run --rm -i -u 0 --entrypoint sh -v "$id-spool2:/spool" -v "$id-state2:/state" -v "$id-sock2:/sock" \
  -v "$id-bin:/bin-vol" "$image" -c 'chown 999:999 /spool /state && chmod 777 /sock && cat >/bin-vol/pgbackrest &&
    chmod 755 /bin-vol/pgbackrest && echo unused >/bin-vol/secret && chmod 644 /bin-vol/secret' <<'WRAPPER'
#!/bin/sh
unset PGBACKREST_REPO1_S3_BUCKET PGBACKREST_REPO1_S3_ENDPOINT PGBACKREST_REPO1_STORAGE_PORT PGBACKREST_REPO1_S3_REGION \
  PGBACKREST_REPO1_S3_URI_STYLE PGBACKREST_REPO1_S3_KEY PGBACKREST_REPO1_S3_KEY_SECRET PGBACKREST_REPO1_CIPHER_TYPE \
  PGBACKREST_REPO1_CIPHER_PASS
export PGBACKREST_REPO1_TYPE=posix PGBACKREST_REPO1_PATH=/repo
exec /usr/bin/pgbackrest "$@"
WRAPPER
docker run -d --name "$id-pg2" -e POSTGRES_PASSWORD=test -v "$id-data2:/var/lib/postgresql" \
  -v "$id-sock2:/var/run/postgresql" -v "$id-spool2:/pgbackrest-spool/test" "$pg_image" -c archive_mode=on \
  -c 'archive_command=cp %p /pgbackrest-spool/test/%f' >/dev/null
for _ in $(seq 1 60); do docker exec "$id-pg2" pg_isready -U postgres >/dev/null 2>&1 && break; sleep 1; done
sleep 2
run_sh_args=(-v "$id-data2:/var/lib/postgresql" -v "$id-sock2:/var/run/postgresql" -v "$id-repo:/repo"
  -v "$id-spool2:/pgbackrest-spool/test" -v "$id-state2:/var/lib/pgbackrest" -v "$id-bin:/opt/test-bin"
  -e PATH=/opt/test-bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin -e PADDOCK_BACKUP_STANZA=test
  -e PADDOCK_BACKUP_S3_ENDPOINT=https://unused.invalid -e PADDOCK_BACKUP_S3_BUCKET=unused
  -e PADDOCK_BACKUP_S3_ACCESS_KEY_FILE=/opt/test-bin/secret -e PADDOCK_BACKUP_S3_SECRET_KEY_FILE=/opt/test-bin/secret
  -e PADDOCK_BACKUP_ENCRYPTION_KEY_FILE=/opt/test-bin/secret "$image")
sets_before="$(pgb info --output=json | grep -o '"label":"[^"]*"' | wc -l)"
docker run -d --name "$id-serve" "${run_sh_args[@]}" serve >/dev/null
refused=1
for _ in $(seq 1 30); do
  if docker logs "$id-serve" 2>&1 | grep -q "holds stanza test for another cluster"; then refused=0; break; fi
  sleep 1
done
for _ in $(seq 1 30); do
  (($(docker logs "$id-serve" 2>&1 | grep -c "holds stanza test for another cluster") >= 2)) && break
  sleep 1
done
serve_log="$(docker logs "$id-serve" 2>&1)"
docker rm -f "$id-serve" >/dev/null
check "serve refuses a stanza of another cluster and logs it" "$refused"
check "serve logs pgBackRest's own stanza-create error" "$(grep -q 'ERROR: \[028\]' <<<"$serve_log" && echo 0 || echo 1)"
check "serve keeps running after the refusal (a second round logs it again)" \
  "$(($(grep -c 'holds stanza test for another cluster' <<<"$serve_log") >= 2 ? 0 : 1))"
marker=0
docker run --rm --entrypoint test -v "$id-state2:/state" "$image" -e /state/stanza || marker=$?
check "a refused stanza writes no marker" "$([[ $marker != 0 ]] && echo 0 || echo 1)"
sets_after="$(pgb info --output=json | grep -o '"label":"[^"]*"' | wc -l)"
check "a refused stanza takes no backup ($sets_before sets before, $sets_after after)" \
  "$([[ $sets_after == "$sets_before" ]] && echo 0 || echo 1)"
rc=0
docker run --rm "${run_sh_args[@]}" stanza-upgrade >/dev/null 2>&1 || rc=$?
check "the stanza-upgrade subcommand succeeds (exit $rc)" "$([[ $rc == 0 ]] && echo 0 || echo 1)"
rc=0
out="$(docker run --rm "${run_sh_args[@]}" backup --start-fast 2>&1)" || rc=$?
check "after stanza-upgrade a backup of the new cluster verifies (exit $rc)" \
  "$([[ $rc == 0 ]] && grep -q 'pgbackrest: backup .* of test verified' <<<"$out" && echo 0 || echo 1)"

exit "$((failures > 0))"
