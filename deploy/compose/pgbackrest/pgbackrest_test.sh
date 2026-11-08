#!/usr/bin/env bash
# Test of the pgBackRest behaviour run.sh relies on (`make test`, needs Docker and the image paddock-pgbackrest:dev,
# built by `make image-pgbackrest`): two containers that share the lock path on a volume cannot back up the same stanza
# at once (the second exits 50, and flock(1) sees the lock), `verify --output=text --verbose` reports a backup set with a missing file as
# "status: error" while its exit code stays 0; and run.sh on the local posix repository (plan M15 decision 17): serve
# waits without the key file, refuses a repository that holds the stanza for another cluster until its
# `stanza-upgrade` runs, verifies the whole stanza after a full backup and writes verify-ok (the new backup alone when
# the whole verify does not finish in time, then verify-ok stays), starts a new stanza with a full backup at once
# (with --start-fast, a scheduled full without) when schedule.env names a new key's path, `restore` passes --at and --repo-path to pgBackRest, and `verify` writes
# verify-ok only when the whole stanza verifies, after a running backup's lock and never older than the one there. Throwaway PostgreSQL and encrypted posix repositories in
# volumes.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
pg_image="$(grep '^POSTGRES_IMAGE=' "$here/../versions.env" | cut -d= -f2-)"
image="${PADDOCK_PGBACKREST_IMAGE:-paddock-pgbackrest:dev}"
id="paddock-pgbackrest-test-$$"
failures=0
cleanup() {
  kill "${pusher_pid:-}" 2>/dev/null || true
  docker rm -f "$id-pg" "$id-pg2" "$id-serve" "$id-lock" >/dev/null 2>&1 || true
  docker volume rm "$id-data" "$id-sock" "$id-repo" "$id-state" "$id-data2" "$id-sock2" "$id-spool2" "$id-state2" \
    "$id-bin" "$id-brepo" "$id-runtime" "$id-empty" "$id-rec" >/dev/null 2>&1 || true
}
trap cleanup EXIT
# The cipher pass the backup role would write into the runtime tmpfs (any text; pgBackRest derives the key from it).
pass="paddock-pgbackrest-test-pass"
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
    -e PGBACKREST_REPO1_CIPHER_TYPE=aes-256-cbc -e PGBACKREST_REPO1_CIPHER_PASS="$pass" \
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
# The file is moved aside and put back after the check: this repository is the old key's repository below, and a
# damaged set left in it would fail every later whole-stanza verify (plan M15, amendment 2026-11-05, A7).
docker run --rm -u 0 --entrypoint sh -v "$id-repo:/repo" "$image" \
  -c "f=\"\$(find /repo/backup/test/$label/pg_data/base -type f -size +10k | head -1)\"; mv \"\$f\" /repo/aside && echo \"\$f\" >/repo/aside.path"
rc=0
report="$(pgb verify --set="$label" --output=text --verbose)" || rc=$?
check "verify reports a set with a missing file as status: error, exit $rc" \
  "$(grep -q '^status: error$' <<<"$report" && grep -q 'missing: 1' <<<"$report" && echo 0 || echo 1)"
docker run --rm -u 0 --entrypoint sh -v "$id-repo:/repo" "$image" \
  -c 'mv /repo/aside "$(cat /repo/aside.path)" && rm /repo/aside.path'

# run.sh against a second cluster of the same major. The first repository (stanza test of the first cluster) is the
# repository of an older key, mounted at its path in the set; schedule.env and the key file stand in for the backup
# role's runtime tmpfs.
kill "$pusher_pid" 2>/dev/null || true
old_path=pgbackrest/bk-20261104-00000009
new_path=pgbackrest/bk-20261105-00000002
for v in data2 sock2 spool2 state2 bin brepo runtime empty; do docker volume create "$id-$v" >/dev/null; done
docker run --rm -u 0 --entrypoint sh -v "$id-spool2:/spool" -v "$id-state2:/state" -v "$id-sock2:/sock" \
  -v "$id-brepo:/brepo" -v "$id-runtime:/rt" -v "$id-empty:/empty" "$image" \
  -c 'mkdir -p /brepo/pgbackrest && chown -R 999:999 /spool /state /brepo /rt /empty && chmod 777 /sock'
# runtime <repo path> <full interval s>: writes the key file and schedule.env as the backup role does.
runtime() {
  docker run --rm -u 999 --entrypoint sh -v "$id-runtime:/rt" -e PASS="$pass" -e P="$1" -e S="$2" "$image" -c \
    'printf %s "$PASS" >/rt/key && printf "PADDOCK_BACKUP_REPO_PATH=%s\nPADDOCK_BACKUP_RETENTION_FULL=2\nPADDOCK_BACKUP_FULL_INTERVAL_S=%s\n" "$P" "$S" >/rt/schedule.env'
}
docker run -d --name "$id-pg2" -e POSTGRES_PASSWORD=test -v "$id-data2:/var/lib/postgresql" \
  -v "$id-sock2:/var/run/postgresql" -v "$id-spool2:/pgbackrest-spool/test" "$pg_image" -c archive_mode=on \
  -c 'archive_command=cp %p /pgbackrest-spool/test/%f' >/dev/null
for _ in $(seq 1 60); do docker exec "$id-pg2" pg_isready -U postgres >/dev/null 2>&1 && break; sleep 1; done
sleep 2
run_sh_args=(-v "$id-data2:/var/lib/postgresql" -v "$id-sock2:/var/run/postgresql" -v "$id-brepo:/backup-repo"
  -v "$id-repo:/backup-repo/$old_path" -v "$id-spool2:/pgbackrest-spool/test" -v "$id-state2:/var/lib/pgbackrest"
  -v "$id-runtime:/run/paddock-backup:ro" -e PADDOCK_BACKUP_STANZA=test "$image")
sets_before="$(pgb info --output=json | grep -o '"label":"[^"]*"' | wc -l)"

# wait_log <container> <pattern> <seconds>: 0 when the pattern appears in the container's log in time.
wait_log() {
  for _ in $(seq 1 "$3"); do
    if docker logs "$1" 2>&1 | grep -q "$2"; then return 0; fi
    sleep 1
  done
  return 1
}

docker run -d --name "$id-serve" "${run_sh_args[@]}" serve >/dev/null
rc=0
wait_log "$id-serve" "waiting for the backup key" 30 || rc=1
sleep 12
check "serve without the key file waits and says so" "$rc"
check "serve logs the wait once, not every round" \
  "$(($(docker logs "$id-serve" 2>&1 | grep -c 'waiting for the backup key') == 1 ? 0 : 1))"
marker=0
docker run --rm --entrypoint test -v "$id-state2:/state" "$image" -e /state/repo-path || marker=$?
check "without the key serve touches no repository" "$([[ $marker != 0 ]] && echo 0 || echo 1)"

runtime "$old_path" 86400
refused=1
wait_log "$id-serve" "holds stanza test for another cluster" 60 && refused=0
for _ in $(seq 1 30); do
  (($(docker logs "$id-serve" 2>&1 | grep -c "holds stanza test for another cluster") >= 2)) && break
  sleep 1
done
serve_log="$(docker logs "$id-serve" 2>&1)"
docker rm -f "$id-serve" >/dev/null
check "with the key serve reads it and refuses a stanza of another cluster" "$refused"
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
check "a full backup verifies the whole stanza first" \
  "$(grep -q 'pgbackrest: stanza test verified' <<<"$out" && echo 0 || echo 1)"
verify_ok() { docker run --rm --entrypoint cat -v "$id-state2:/state" "$image" /state/verify-ok 2>/dev/null || echo none; }
first_ok="$(verify_ok)"
check "a verified stanza writes verify-ok ($first_ok)" "$([[ $first_ok =~ ^[0-9]+$ ]] && echo 0 || echo 1)"
# A whole-stanza verify that does not finish in time (plan M15, amendment 2026-11-05, A7): the new backup alone is
# verified, the backup succeeds and verify-ok stays, so the backup role keeps the WAL on the targets.
sleep 1
rc=0
out="$(docker run --rm -e PADDOCK_BACKUP_VERIFY_S=0.01 "${run_sh_args[@]}" backup --start-fast 2>&1)" || rc=$?
check "past the verify time the backup alone is verified (exit $rc)" \
  "$([[ $rc == 0 ]] && grep -q 'did not finish within' <<<"$out" && grep -q 'pgbackrest: backup .* of test verified' <<<"$out" && echo 0 || echo 1)"
check "past the verify time verify-ok stays" "$([[ "$(verify_ok)" == "$first_ok" ]] && echo 0 || echo 1)"

# A key rotation: schedule.env names a new path, and serve starts a stanza there with a full backup at once although
# the interval has not passed. A pgbackrest earlier in PATH records the arguments of every backup: the path switch's
# full forces the checkpoint (--start-fast), a scheduled full does not (decisions-alpha9 item 87).
docker volume create "$id-rec" >/dev/null
docker run --rm -i -u 0 --entrypoint sh -v "$id-rec:/rec" "$image" \
  -c 'cat >/rec/pgbackrest && chmod 755 /rec/pgbackrest && chown 999:999 /rec' <<'RECORDER'
#!/bin/sh
case " $* " in *" backup "*) echo "$*" >>/rec/backup-args ;; esac
exec /usr/bin/pgbackrest "$@"
RECORDER
rec_args=(-v "$id-rec:/rec" -e PATH=/rec:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin "${run_sh_args[@]}")
runtime "$new_path" 86400
docker run -d --name "$id-serve" "${rec_args[@]}" serve >/dev/null
switched=1
wait_log "$id-serve" "repository of test is now $new_path" 30 && switched=0
verified=1
wait_log "$id-serve" "pgbackrest: backup .* of test verified" 240 && verified=0
check "serve switches to the new key's repository path" "$switched"
check "serve takes a verified full backup in the new path at once" "$verified"
# The same path with a short interval: the next full is a scheduled one.
runtime "$new_path" 1
scheduled=1
for _ in $(seq 1 240); do
  if (($(docker logs "$id-serve" 2>&1 | grep -c "pgbackrest: backup .* of test verified") >= 2)); then
    scheduled=0
    break
  fi
  sleep 1
done
docker rm -f "$id-serve" >/dev/null
runtime "$new_path" 86400
backups="$(docker run --rm --entrypoint cat -v "$id-rec:/rec" "$image" /rec/backup-args 2>/dev/null || true)"
check "serve takes a scheduled full after the switch" "$scheduled"
check "the path switch's full passes --start-fast" \
  "$(sed -n 1p <<<"$backups" | grep -q -- '--type=full --start-fast' && echo 0 || echo 1)"
check "a scheduled full does not pass --start-fast" \
  "$(sed -n 2p <<<"$backups" | grep -q -- '--type=full' && ! sed -n 2p <<<"$backups" | grep -q -- '--start-fast' && echo 0 || echo 1)"
rc=0
docker run --rm --entrypoint sh -v "$id-brepo:/backup-repo" "$image" -c \
  "ls -d /backup-repo/$new_path/backup/test/*F >/dev/null && test -s /backup-repo/$new_path/archive/test/archive.info" || rc=$?
check "the new path holds the stanza and its full backup" "$rc"
sets_kept="$(pgb info --output=json | grep -o '"label":"[^"]*"' | wc -l)"
check "the old key's repository stays for the role's expire ($sets_kept sets)" \
  "$([[ $sets_kept -gt $sets_before ]] && echo 0 || echo 1)"

# restore --at and --repo-path: a pgbackrest earlier in PATH records what run.sh passes and plays an archive without
# further segments.
docker run --rm -i -u 0 --entrypoint sh -v "$id-bin:/bin-vol" "$image" \
  -c 'cat >/bin-vol/pgbackrest && chmod 755 /bin-vol/pgbackrest && chown 999:999 /bin-vol' <<'WRAPPER'
#!/bin/sh
case " $* " in
  *" restore "*) echo "$PGBACKREST_REPO1_PATH $*" >/opt/test-bin/restore-args ;;
  *" info "*) echo '[{"backup":[{"label":"20261104-100000F","archive":{"start":"000000010000000000000003"}}],"archive":[{"max":"000000020000000000000001"}]}]' ;;
  *" archive-get "*) exit 1 ;;
esac
WRAPPER
restore_args=(-v "$id-bin:/opt/test-bin" -e PATH=/opt/test-bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
  "${run_sh_args[@]}")
rc=0
docker run --rm "${restore_args[@]}" restore --at "2026-11-04 10:30:00+00" --repo-path "$old_path" >/dev/null 2>&1 || rc=$?
args="$(docker run --rm --entrypoint cat -v "$id-bin:/opt/test-bin" "$image" /opt/test-bin/restore-args)"
check "restore --at --repo-path succeeds (exit $rc)" "$([[ $rc == 0 ]] && echo 0 || echo 1)"
check "restore --at restores to that time and promotes" \
  "$(grep -q -- '--type=time --target=2026-11-04 10:30:00+00 --target-action=promote' <<<"$args" && echo 0 || echo 1)"
check "restore --repo-path reads the named key's repository" \
  "$(grep -q "^/backup-repo/$old_path " <<<"$args" && echo 0 || echo 1)"
rc=0
docker run --rm "${restore_args[@]}" restore --repo-path ../../etc >/dev/null 2>&1 || rc=$?
check "restore refuses a repository path outside the set (exit $rc)" "$([[ $rc == 3 ]] && echo 0 || echo 1)"
# The operator's verify (decisions-alpha9 item 33): a verify that reports a problem leaves verify-ok absent, the
# whole-stanza verify without a time limit writes it.
docker run --rm -u 0 --entrypoint rm -v "$id-state2:/state" "$image" -f /state/verify-ok
rc=0
out="$(docker run --rm "${restore_args[@]}" verify 2>&1)" || rc=$?
check "a verify that does not report ok fails (exit $rc)" \
  "$([[ $rc == 1 ]] && grep -q 'WAL stays on the backup targets' <<<"$out" && echo 0 || echo 1)"
check "a failed verify leaves verify-ok absent" "$([[ "$(verify_ok)" == none ]] && echo 0 || echo 1)"
before="$(date +%s)"
rc=0
out="$(docker run --rm "${run_sh_args[@]}" verify 2>&1)" || rc=$?
check "verify checks the whole stanza without a time limit (exit $rc)" \
  "$([[ $rc == 0 ]] && grep -q 'pgbackrest: stanza test verified' <<<"$out" && echo 0 || echo 1)"
ok_at="$(verify_ok)"
check "a successful verify writes verify-ok with its start time ($ok_at)" \
  "$([[ $ok_at =~ ^[0-9]+$ ]] && ((ok_at >= before)) && echo 0 || echo 1)"
# A full that runs beside the verify would be newer than verify-ok without being covered (PDK-733 review 1): the verify
# waits for a running backup's lock and starts after it.
docker run -d --name "$id-lock" --entrypoint flock -v "$id-state2:/var/lib/pgbackrest" "$image" \
  /var/lib/pgbackrest/lock/test-backup-1.lock sleep 6 >/dev/null
sleep 2
rc=0
out="$(docker run --rm "${run_sh_args[@]}" verify 2>&1)" || rc=$?
released="$(docker inspect -f '{{.State.FinishedAt}}' "$id-lock")"
docker rm -f "$id-lock" >/dev/null
lock_ok="$(verify_ok)"
check "verify waits for a running backup's lock (exit $rc)" \
  "$([[ $rc == 0 ]] && grep -q 'waiting for the running backup of test' <<<"$out" && echo 0 || echo 1)"
check "verify-ok is the start after the lock ($lock_ok, lock released $released)" \
  "$([[ $lock_ok =~ ^[0-9]+$ ]] && ((lock_ok >= $(date -d "$released" +%s))) && echo 0 || echo 1)"
# serve's own verify may record a later time than the operator's start: it is never replaced by an older one.
docker run --rm -u 0 --entrypoint sh -v "$id-state2:/state" "$image" -c 'echo 4102444800 >/state/verify-ok'
rc=0
docker run --rm "${run_sh_args[@]}" verify >/dev/null 2>&1 || rc=$?
check "verify keeps a newer verify-ok (exit $rc)" "$([[ $rc == 0 && "$(verify_ok)" == 4102444800 ]] && echo 0 || echo 1)"
rc=0
docker run --rm -v "$id-data2:/var/lib/postgresql" -v "$id-sock2:/var/run/postgresql" -v "$id-brepo:/backup-repo" \
  -v "$id-state2:/var/lib/pgbackrest" -v "$id-empty:/run/paddock-backup:ro" -e PADDOCK_BACKUP_STANZA=test "$image" \
  verify >/dev/null 2>&1 || rc=$?
check "verify without the key file fails (exit $rc)" "$([[ $rc == 3 ]] && echo 0 || echo 1)"
rc=0
docker run --rm -v "$id-data2:/var/lib/postgresql" -v "$id-sock2:/var/run/postgresql" -v "$id-brepo:/backup-repo" \
  -v "$id-state2:/var/lib/pgbackrest" -v "$id-empty:/run/paddock-backup:ro" -e PADDOCK_BACKUP_STANZA=test "$image" \
  backup >/dev/null 2>&1 || rc=$?
check "a one-off backup without the key file fails (exit $rc)" "$([[ $rc == 3 ]] && echo 0 || echo 1)"

exit "$((failures > 0))"
