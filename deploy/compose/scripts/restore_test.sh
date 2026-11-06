#!/usr/bin/env bash
# Tests of restore.sh (`make test`; needs Go, not Docker): fixture backup sets and keys are made at run time, Compose
# and Docker are fakes that log every call, and the backup role's commands (backup manifest, migrate --version) run in
# the real paddock-server binary built from this checkout. Checks the preflight refusals before anything stops, the
# --at choice of snapshot and dump, the components' boundaries, the report, the key file handling and that the key never
# reaches a command line or the output.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$here/../../.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
failures=0
ok() { echo "ok   $1"; }
bad() {
  echo "FAIL $1"
  failures=$((failures + 1))
}

bin="$work/paddock-server"
(cd "$repo_root" && GOTOOLCHAIN=auto go build -o "$bin" ./server/cmd/paddock-server)

COMPOSE_DIR="$work/compose"
SECRETS_DIR="$COMPOSE_DIR/.secrets"
PADDOCK_PROJECT=paddock-restore-test
mkdir -p "$SECRETS_DIR"
calls="$work/calls.log"
# Settings of the fake host; a test changes them for its case.
declare -A host_env=([PADDOCK_HOST]=controlplane [PADDOCK_AUTO_UNSEAL]=no)
env_value() { printf '%s' "${host_env[$1]:-}"; }

# shellcheck source=restore.sh
. "$here/restore.sh"

fail_on=""   # a call matching this pattern fails (a failing step)
report_rc=0  # exit code of backup restore-report
report_fail="" # an outcome whose report fails
check_rc=0   # exit code of backup restore-repo --check (1: a plan is running)
plan_json="" # what backup plan prints
# The markers are paths of their own: the fake may run inside a step's function whose local work shadows the harness's.
report_sleep="" # seconds a failed restore-report takes (touches $reporting first)
reporting="$work/reporting"
export_sleep="" # seconds backup target-export takes after printing (touches $exporting first)
exporting="$work/exporting"
sealed_polls="$work/sealed-polls" # holds how many more bao status calls answer sealed
step_sleep_on="" # a call matching this pattern sleeps step_sleep seconds (touches $stepping first): a slow step
step_sleep=""
stepping="$work/stepping"
fetch_mode="" # backup fetch-set: slow (writes a directory after fetch_sleep seconds; touches $fetching first) or locked
fetch_sleep=""  # (a planted link beside a directory its owner cannot write to)
fetching="$work/fetching"
shred_sleep="" # seconds the first shred takes before it runs (touches $shredding first): a slow key delete
shredding="$work/shredding"
# shred: the real shred, slowed once when shred_sleep is set.
shred() {
  if [[ -n "$shred_sleep" && ! -e "$shredding" ]]; then
    touch "$shredding"
    sleep "$shred_sleep"
  fi
  command shred "$@"
}
cli_log="$work/cli.log"
# cli_check <compose arguments...>: hands the paddock-server arguments after the service name to the real binary without
# a database (PDK-735's CLI): a line that parses fails on the missing PADDOCK_DB_BACKUP_URL_FILE, a line the CLI does
# not accept prints the usage. Logs "accepted" or "REJECTED" with the arguments.
cli_check() {
  local a args=() seen="" res
  for a in "$@"; do
    if [[ -n "$seen" ]]; then args+=("$a"); fi
    [[ "$a" == paddock-backup ]] && seen=1
  done
  res="$(env -i PATH="$PATH" PADDOCK_LOG_LEVEL=error "$bin" "${args[@]}" 2>&1 </dev/null || true)"
  if [[ "$res" == *"configuration incomplete"*PADDOCK_DB_BACKUP_URL_FILE* && "$res" != *"usage: paddock-server"* ]]; then
    echo "accepted ${args[*]}" >>"$cli_log"
  else
    echo "REJECTED ${args[*]}" >>"$cli_log"
  fi
}
# compose: logs the call and answers the few calls whose output the script reads. Calls that receive the key or a
# dump on stdin consume it; nothing else reads stdin, which carries the typed confirmation.
compose() {
  local line="compose $*" mount="" a args=() seen=""
  echo "$line" >>"$calls"
  case "$line" in
    *" paddock-backup backup restore-report "* | *" paddock-backup backup plan "* | *" paddock-backup backup restore-repo --check"*)
      cli_check "$@"
      ;;
  esac
  if [[ -n "$step_sleep_on" && "$line" == *$step_sleep_on* ]]; then
    touch "$stepping"
    sleep "$step_sleep"
  fi
  if [[ -n "$fail_on" && "$line" == *$fail_on* ]]; then
    cat >/dev/null
    return 1
  fi
  case "$line" in
    *" paddock-backup backup manifest "* | *" paddock-backup migrate --version"*)
      for a in "$@"; do
        [[ "$a" == *:/restore-set:ro ]] && mount="${a%:/restore-set:ro}"
        if [[ -n "$seen" && "$a" == /backup-repo ]]; then a="$set_dir"; fi
        if [[ -n "$seen" ]]; then args+=("${a/#\/restore-set/$mount}"); fi
        [[ "$a" == paddock-backup ]] && seen=1
      done
      "$bin" "${args[@]}"
      ;;
    *" backup decrypt "*) cat >/dev/null && echo plain ;;
    *" backup fetch-set "*)
      cat >/dev/null
      for a in "$@"; do [[ "$a" != *:/restore-set ]] || mount="${a%:/restore-set}"; done
      if [[ "$fetch_mode" == slow ]]; then
        touch "$fetching"
        sleep "$fetch_sleep"
        mkdir -p "$mount/late" && echo sealed >"$mount/late/part.enc"
      elif [[ "$fetch_mode" == locked ]]; then
        ln -s /etc/passwd "$mount/planted"
        mkdir -p "$mount/locked" && echo sealed >"$mount/locked/part.enc" && chmod 500 "$mount/locked"
      fi
      [[ -z "$fetch_mode" ]] || cp -R "$set_dir/." "$mount/"
      ;;
    *" backup restore-report "*)
      if [[ -n "$report_sleep" && "$line" == *"--outcome failed"* ]]; then
        touch "$reporting"
        sleep "$report_sleep"
      fi
      [[ -z "$report_fail" || "$line" != *"--outcome $report_fail"* ]] || return 1
      return "$report_rc"
      ;;
    *" backup restore-repo --check"*) return "$check_rc" ;;
    *" backup plan "*)
      printf '%s\n' "$plan_json"
      [[ "$plan_json" == *'"state":"approved"'* ]]
      ;;
    *" backup restore-repo "*) cat >/dev/null && printf 'copied 3 files (9 bytes)\nrepo_path=%s\n' "$set_repo_path" ;;
    *" exec -T postgres psql "* | *" exec -T authentik-postgres psql "*) echo f ;;
    *" openbao bao status "*)
      local n=0
      [[ ! -s "$sealed_polls" ]] || n="$(cat "$sealed_polls")"
      if ((n > 0)); then
        echo $((n - 1)) >"$sealed_polls"
        echo '{"initialized": true, "sealed": true}'
      else
        echo '{"initialized": true, "sealed": false}'
      fi
      ;;
    *" backup target-export "*)
      echo '{"secret_key":"s3cret"}'
      if [[ -n "$export_sleep" ]]; then
        touch "$exporting"
        sleep "$export_sleep"
      fi
      ;;
    *" openbao bao operator init "*)
      printf '{\n  "unseal_keys_b64": [\n    "dGVtcA=="\n  ],\n  "root_token": "s.temporary"\n}\n'
      ;;
    *" backup-restore-escrow backup restore-escrow "*)
      echo "escrow: skipped device d3 (organization o1, escrow destroyed 2026-11-03T00:00:00Z): org/o1/devices/d3/luks-header/h1, org/o1/devices/d3/luks-header/h2"
      echo "escrow: 1 headers put, 0 already present, 2 skipped (device escrow destroyed)"
      ;;
    *" ps --format "*) echo healthy ;;
    *" run "* | *" exec -T openbao sh "* | *" exec -T openbao bao write "*) cat >/dev/null ;;
  esac
}
docker() {
  echo "docker $*" >>"$calls"
  [[ "$1 $2" != "volume inspect" ]] || return 0
}
restore_wait_healthy() { echo "wait-healthy" >>"$calls"; }
restore_bootstrap_buckets() { echo "bootstrap-buckets" >>"$calls"; }
hostname() { echo test-host; }

# Fixtures: a key, a second key and a set made with the first.
head -c 32 /dev/urandom | base64 >"$work/key"
head -c 32 /dev/urandom | base64 >"$work/other-key"
key_text="$(cat "$work/key")"
fingerprint="$(base64 -d <"$work/key" | sha256sum | cut -c1-16)"
key_id=bk-20261104-7f3a9c1e
set_repo_path="pgbackrest/$key_id"
# make_set <dir> [paddock schema version|none] [backup label|none]: a set whose stanzas each hold one backup (the
# full backup of 2026-11-02 01:00 UTC by default).
make_set() {
  local d="$1" schema='{"paddock":'"${2:-100}"'}' stanza
  [[ "${2:-}" != none ]] || schema='{}'
  mkdir -p "$d/openbao" "$d/fleet"
  for stanza in paddock authentik; do
    mkdir -p "$d/$set_repo_path/backup/$stanza"
    [[ "${3:-}" == none ]] || mkdir -p "$d/$set_repo_path/backup/$stanza/${3:-20261102-010000F}"
  done
  printf '{"schema":"paddock.backup-set.v1","installation_id":"6f1c2b0a-4d1e-5a7b-9c3d-2e4f6a8b0c1d","server_version":"0.1.0-test","generated_at":"2026-11-04T12:00:00Z","key_id":"%s","key_fingerprint":"%s","schema_versions":%s,"contents":{"pgbackrest":{"path":"%s","stanzas":[]},"openbao":[],"fleet":[],"escrow":[]}}\n' \
    "$key_id" "$fingerprint" "$schema" "$set_repo_path" >"$d/manifest.json"
  for f in openbao/20261102T000000Z.snap.enc openbao/20261103T060000Z.snap.enc openbao/20261104T060000Z.snap.enc \
    fleet/20261102T030000Z.sql.gz.enc fleet/20261103T030000Z.sql.gz.enc fleet/20261104T030000Z.sql.gz.enc; do
    echo sealed >"$d/$f"
  done
}
set_dir="$work/set"
make_set "$set_dir"

# run_restore <stdin> <restore_run arguments...>: runs restore_run in a subshell; sets rc and out.
run_restore() {
  local input="$1"
  shift
  : >"$calls"
  # Outside an || list, so that set -e holds inside restore_run as it does under ./paddock. The subshell clears the
  # harness's trap: bash still reports it there, and restore_run would run it as the caller's.
  set +e
  out="$( (trap - EXIT && set -e && restore_run "$@") <<<"$input" 2>&1)"
  rc=$?
  set -e
}
called() { grep -qF -- "$1" "$calls"; }
# position <text>: the line number of the first call containing text (0 when none).
position() { grep -nF -- "$1" "$calls" | head -1 | cut -d: -f1 || true; }

export RESTORE_KEY_FILE="$work/key"

# --- Preflight refusals: nothing stops, nothing changes ---------------------------------------------------------------
RESTORE_KEY_FILE="$work/other-key" run_restore restore fresh "$set_dir"
if ((rc != 0)) && [[ "$out" == *"fingerprint $fingerprint"* ]] && ! called " stop" && ! called "docker volume rm" &&
  ! called " rm -sf"; then
  ok "a set made with another key is refused before anything stops"
else
  bad "wrong key: rc $rc, out: $out, calls: $(cat "$calls")"
fi

make_set "$work/set-newer" 99999
run_restore restore fresh "$work/set-newer"
if ((rc != 0)) && [[ "$out" == *"paddock schema is version 99999"* ]] && ! called " stop"; then
  ok "a set whose schema is newer than the bundle's is refused before anything stops"
else
  bad "newer schema: rc $rc, out: $out"
fi

mkdir -p "$work/no-manifest"
run_restore restore fresh "$work/no-manifest"
if ((rc != 0)) && [[ "$out" == *"manifest.json is missing or invalid"* ]] && ! called " stop"; then
  ok "a set without a manifest is refused"
else
  bad "no manifest: rc $rc, out: $out"
fi

echo "not a key" >"$work/bad-key"
RESTORE_KEY_FILE="$work/bad-key" run_restore restore fresh "$set_dir"
if ((rc != 0)) && [[ "$out" == *"not 44 base64 characters"* ]] && ! called " stop"; then
  ok "a key file that is no 32-byte base64 key is refused"
else
  bad "bad key: rc $rc, out: $out"
fi

run_restore nope fresh "$set_dir"
if ((rc != 0)) && [[ "$out" == *"not confirmed"* ]] && ! called " stop"; then
  ok "anything but the typed word restore stops before a change"
else
  bad "confirmation: rc $rc, out: $out"
fi

run_restore restore fresh "$set_dir" --at 2026-11-01T00:00:00Z --only openbao
if ((rc != 0)) && [[ "$out" == *"no OpenBao snapshot at or before 2026-11-01T00:00:00Z"* ]] && ! called " stop"; then
  ok "a point before every snapshot is refused"
else
  bad "point before the snapshots: rc $rc, out: $out"
fi

run_restore restore fresh "$set_dir" --at yesterday
if ((rc == 2)); then ok "an --at that is not RFC 3339 is refused"; else bad "--at yesterday: rc $rc, out: $out"; fi

# The review of PDK-734 (M2, m3, m4): what pgBackRest would refuse only after the volumes are gone.
run_restore restore fresh "$set_dir" --at "$(date -u -d '+1 day' +%Y-%m-%dT%H:%M:%SZ)"
if ((rc != 0)) && [[ "$out" == *"is in the future"* ]] && ! called " stop" && ! called "docker volume rm"; then
  ok "an --at in the future is refused before anything stops"
else
  bad "future --at: rc $rc, out: $out"
fi
run_restore restore fresh "$set_dir" --at 2026-11-02T00:30:00Z --only postgres
if ((rc != 0)) && [[ "$out" == *"oldest backup of paddock started at 2026-11-02T01:00:00Z"* ]] && ! called " stop" &&
  ! called "docker volume rm"; then
  ok "a point before the oldest pgBackRest backup is refused before anything stops"
else
  bad "point before the oldest backup: rc $rc, out: $out"
fi
run_restore restore fresh "$set_dir" --at 2026-11-02T01:00:00Z --only postgres
if ((rc == 0)); then ok "a point at the oldest backup's start is restored"; else bad "point at the oldest backup: rc $rc, out: $out"; fi
make_set "$work/set-no-label" 100 none
run_restore restore fresh "$work/set-no-label" --only postgres
if ((rc != 0)) && [[ "$out" == *"holds no pgBackRest backup of paddock"* ]] && ! called " stop"; then
  ok "a stanza directory without a backup does not count as a backup"
else
  bad "stanza without a backup: rc $rc, out: $out"
fi
make_set "$work/set-no-schema" none
run_restore restore fresh "$work/set-no-schema" --only postgres
if ((rc != 0)) && [[ "$out" == *"names no paddock schema version"* ]] && ! called " stop"; then
  ok "a set without the paddock schema version is refused for a database restore"
else
  bad "no paddock schema: rc $rc, out: $out"
fi
run_restore restore fresh "$work/set-no-schema" --only openbao
if ((rc == 0)); then ok "the paddock schema version is not needed without postgres"; else bad "openbao without schema: rc $rc, out: $out"; fi

# --- A whole restore ---------------------------------------------------------------------------------------------------
run_restore restore fresh "$set_dir" --at 2026-11-03T12:00:00+01:00
order_ok=1
prev=0
for step in "pgbackrest restore" "backup decrypt /restore-set/openbao/" "admin bump-bundle-seq" "--entrypoint bash fleet-backup" \
  "backup restore-escrow" "up -d --no-deps paddock-backup" "wait-healthy" "backup restore-report --outcome completed"; do
  p="$(position "$step")"
  [[ "$step" == "pgbackrest restore" ]] && p="$(position "-c set -euo pipefail")"
  if [[ -z "$p" ]] || ((p <= prev)); then order_ok=0; fi
  prev="${p:-0}"
done
if ((rc == 0)) && ((order_ok)); then
  ok "a whole restore runs postgres, openbao, paddock, fleet, escrow and the report in this order"
else
  bad "whole restore: rc $rc, out: $out, calls: $(cat "$calls")"
fi
if called "backup decrypt /restore-set/openbao/20261103T060000Z.snap.enc" &&
  called "backup decrypt /restore-set/fleet/20261103T030000Z.sql.gz.enc"; then
  ok "--at picks the newest snapshot and dump at or before the point"
else
  bad "--at choice: $(grep decrypt "$calls")"
fi
if called "restore $set_repo_path --at 2026-11-03 11:00:00+00"; then
  ok "--at reaches pgBackRest as UTC"
else
  bad "pgBackRest --at: $(grep 'set -euo' "$calls" | head -1)"
fi
if called "--operator" && called "--components postgres,openbao,fleet,escrow" && called "--at 2026-11-03T11:00:00Z"; then
  ok "the report names the operator, the components and the point"
else
  bad "report: $(grep restore-report "$calls")"
fi
# PDK-831 (decisions-alpha9 item 44): the escrow step runs in its own one-off service of profile restore, which holds the
# audit reader and the gateway credential in its Compose definition; the backup role is not used for it.
escrow_call="$(grep -F "backup restore-escrow" "$calls" || true)"
if [[ "$escrow_call" == "compose --profile restore run --rm --no-deps -T -e PADDOCK_LOG_LEVEL=error -v $set_dir:/restore-set:ro backup-restore-escrow backup restore-escrow /restore-set" ]]; then
  ok "the escrow step runs once in backup-restore-escrow (profile restore) with the set mounted read-only and no extra mount"
else
  bad "escrow call: $escrow_call"
fi
if [[ "$out" == *"escrow: skipped device d3 (organization o1, escrow destroyed 2026-11-03T00:00:00Z): org/o1/devices/d3/luks-header/h1, org/o1/devices/d3/luks-header/h2"* ]] &&
  called "backup restore-report --outcome completed" && grep -F -- "--outcome completed" "$calls" | grep -qF -- "--escrow-skipped-destroyed 2"; then
  ok "the skipped headers reach the terminal, their count the completed report"
else
  bad "escrow skips: out: $out, report: $(grep restore-report "$calls")"
fi
if ! grep -qF -- "$key_text" "$calls" && [[ "$out" != *"$key_text"* ]]; then
  ok "the key appears on no command line and in no output"
else
  bad "the key leaked"
fi
if called "-e PADDOCK_BACKUP_ENCRYPTION_KEY_FILE=/dev/stdin"; then
  ok "the key reaches the decrypting container on stdin"
else
  bad "decrypt key path: $(grep decrypt "$calls" | head -1)"
fi
if called "backup fetch-set --dir /restore-set --path $set_repo_path/ --no-clobber /backup-repo" && called "bootstrap-buckets"; then
  ok "a fresh restore copies the set's repository path and creates the buckets"
else
  bad "fresh restore: $(cat "$calls")"
fi

run_restore restore fresh "$set_dir"
if ((rc == 0)) && called "backup decrypt /restore-set/openbao/20261104T060000Z.snap.enc" && ! called "--at"; then
  ok "without --at the newest snapshot is restored"
else
  bad "latest: rc $rc, $(grep decrypt "$calls")"
fi

# --- Component boundaries ---------------------------------------------------------------------------------------------
run_restore restore fresh "$set_dir" --only openbao
if ((rc == 0)) && called "docker volume rm ${PADDOCK_PROJECT}_openbao-data" && ! called "postgres-data" &&
  ! called "fleet-mysql-data" && ! called "set -euo pipefail" && ! called "bump-bundle-seq" &&
  ! called "restore-escrow"; then
  ok "--only openbao touches no database volume"
else
  bad "--only openbao: rc $rc, $(cat "$calls")"
fi

run_restore restore fresh "$set_dir" --only fleet
if ((rc == 0)) && called "docker volume rm ${PADDOCK_PROJECT}_fleet-mysql-data" && ! called "postgres-data" &&
  ! called "openbao-data" && ! called "--profile paddock stop authentik-server"; then
  ok "--only fleet replaces Fleet's database only"
else
  bad "--only fleet: rc $rc, $(cat "$calls")"
fi

# Review 2 (R2-M2): the postgres step stops OpenBao too, so a restore without openbao states the unseal path and waits.
echo 1 >"$sealed_polls"
run_restore restore fresh "$set_dir" --only postgres
p_up="$(position "--profile observability up -d")"
p_status="$(position "openbao bao status")"
p_bump="$(position "admin bump-bundle-seq")"
if ((rc == 0)) && [[ "$out" == *"OpenBao:     is stopped and comes back sealed"*"three custodians"* ]] &&
  [[ "$out" == *"Three custodians unseal it now"*"OpenBao: unsealed"* ]] && [[ ! -s "$sealed_polls" || "$(cat "$sealed_polls")" == 0 ]] &&
  ((p_status > p_up && p_bump > p_status)); then
  ok "--only postgres names the custodians in the confirmation and waits for the unseal before the restore commands"
else
  bad "postgres without openbao: rc $rc, up $p_up status $p_status bump $p_bump, out: $out"
fi
rm -f "$sealed_polls"
if ! called "restore-escrow" && ! called "--escrow-skipped-destroyed"; then
  ok "without the escrow step the completed report carries no skip count"
else
  bad "skip count without escrow: $(grep -E 'restore-report|escrow' "$calls")"
fi
run_restore restore fresh "$set_dir" --only escrow
if ((rc == 0)) && called "backup-restore-escrow backup restore-escrow /restore-set" && called "--escrow-skipped-destroyed 2" &&
  ! called "paddock-backup backup restore-escrow"; then
  ok "--only escrow runs the escrow service and reports its skip count"
else
  bad "only escrow: rc $rc, $(grep -E 'restore-report|escrow' "$calls")"
fi
fail_on="backup-restore-escrow"
run_restore restore fresh "$set_dir" --only escrow
fail_on=""
if ((rc != 0)) && called "--outcome failed" && called "--component escrow" && ! called "--escrow-skipped-destroyed"; then
  ok "a failed escrow step (an unreadable audit index) stops the run and is reported failed without a count"
else
  bad "escrow failure: rc $rc, $(grep -E 'restore-report|escrow' "$calls")"
fi

run_restore restore plan=11111111-2222-3333-4444-555555555555 repo --only postgres
if ((rc == 0)) && (($(position "--outcome running") < $(position " stop"))) && ! called "fetch-set" &&
  called "--plan 11111111-2222-3333-4444-555555555555" && ! called "bootstrap-buckets"; then
  ok "a plan from the local repository is marked running before the first stop, without a copy"
else
  bad "plan: rc $rc, $(cat "$calls")"
fi

report_rc=1
run_restore restore plan=11111111-2222-3333-4444-555555555555 repo --only postgres
if ((rc != 0)) && ! called " stop" && ! called "--outcome failed"; then
  ok "a plan that cannot be started changes nothing and is not reported as failed"
else
  bad "plan not startable: rc $rc"
fi
report_rc=0

fail_on="fleet-backup -c"
run_restore restore fresh "$set_dir"
fail_on=""
if ((rc != 0)) && called "--outcome failed" && called "--component fleet" && ! called "restore-escrow"; then
  ok "a failed step stops the run and is reported with its component"
else
  bad "failed step: rc $rc, $(grep -E 'restore-report|escrow' "$calls")"
fi
if [[ "$out" == *"Do not run ./paddock up"* && "$out" == *"run the same ./paddock restore command again"* ]]; then
  ok "a failed step tells the operator the host's state and the next steps"
else
  bad "failure help: $out"
fi
fail_on="fleet-backup -c"
report_fail=failed
run_restore restore plan=11111111-2222-3333-4444-555555555555 repo --only fleet
fail_on=""
report_fail=""
if ((rc != 0)) && [[ "$out" == *"stays running"* && "$out" == *"--outcome failed --plan 11111111-2222-3333-4444-555555555555"* ]]; then
  ok "an unrecorded failure of a plan says how to record it"
else
  bad "unrecorded plan failure: rc $rc, out: $out"
fi

# The caller's EXIT trap survives restore_run, on success and on failure (review M1: the drill's key copy).
run_with_trap() {
  rm -f "$work/caller-trap"
  set +e
  # shellcheck disable=SC2064 # expanded now, as restore_trap_chain asks of a caller
  out="$( (trap "touch '$work/caller-trap'" EXIT && set -e && restore_run "$@") <<<restore 2>&1)"
  rc=$?
  set -e
}
run_with_trap fresh "$set_dir" --only openbao
if ((rc == 0)) && [[ -e "$work/caller-trap" ]]; then
  ok "the caller's EXIT trap still runs after a successful restore"
else
  bad "caller trap after success: rc $rc"
fi
fail_on="openbao bao operator init"
run_with_trap fresh "$set_dir" --only openbao
fail_on=""
if ((rc != 0)) && [[ -e "$work/caller-trap" ]]; then
  ok "the caller's EXIT trap runs after a failed restore"
else
  bad "caller trap after failure: rc $rc, out: $out"
fi

# --- backup-repo (amendment 2026-11-05, A5) ---------------------------------------------------------------------------
check_rc=1
run_restore restore fresh target:dev-local --only backup-repo
check_rc=0
if ((rc != 0)) && [[ "$out" == *"a restore plan is running"* ]] && ! called " stop" && ! called "--outcome failed"; then
  ok "--only backup-repo refuses a running plan before anything stops (review m1)"
else
  bad "backup-repo with a running plan: rc $rc, out: $out, $(cat "$calls")"
fi
RESTORE_KEY_FILE="$work/missing" run_restore restore fresh target:dev-local --only backup-repo
if ((rc == 0)) && called "backup restore-repo --target dev-local" && called "printf \"%s\\n\" \"\$1\" >/var/lib/pgbackrest/repo-path" &&
  called "restore $set_repo_path" && ! called "docker volume rm" && ! called "psql" && ! called "openbao" &&
  called "--components backup-repo"; then
  ok "--only backup-repo rebuilds the repository and the markers without a key and without touching a database"
else
  bad "backup-repo: rc $rc, out: $out, $(cat "$calls")"
fi
fail_on="backup restore-repo --target"
run_restore restore fresh target:dev-local --only backup-repo
fail_on=""
if ((rc != 0)) && [[ "$out" == *"no database was touched"* && "$out" == *"WAL piles up"* && "$out" != *"Do not run ./paddock up"* ]]; then
  ok "a failed backup-repo restore states the repository's state, not a half-restored database (review 2, R2-m2)"
else
  bad "backup-repo failure help: rc $rc, out: $out"
fi
run_restore restore fresh target:dev-local --only backup-repo --only postgres
if ((rc == 2)); then ok "backup-repo is restored alone"; else bad "backup-repo with postgres: rc $rc"; fi
run_restore restore fresh target:dev-local --only postgres
if ((rc == 2)); then ok "a target is read directly only for backup-repo"; else bad "target for postgres: rc $rc"; fi

# --- The key prompt and file ------------------------------------------------------------------------------------------
keyfile="$SECRETS_DIR/restore/backup_key"
(
  restore_prompt_key "$keyfile" <<<"$key_text"
  mode="$(stat -c %a "$keyfile")"
  [[ "$mode" == 600 && "$(stat -c %a "$(dirname "$keyfile")")" == 700 && "$(cat "$keyfile")" == "$key_text" ]] || exit 1
  restore_key_cleanup
  [[ ! -e "$keyfile" ]]
) && ok "the entered key is written 0600 and removed afterwards" || bad "key file handling"
rm -f "$keyfile"
(
  restore_prompt_key "$keyfile" <<<"$key_text"
  RESTORE_KEEP_KEY_FILE=1 restore_key_cleanup 2>/dev/null
  [[ "$(cat "$keyfile")" == "$key_text" ]]
) && ok "--keep-key-file keeps the key file" || bad "--keep-key-file"
rm -f "$keyfile"
if (restore_prompt_key "$keyfile" <<<"short") 2>/dev/null; then bad "a short key was accepted"; else
  [[ ! -e "$keyfile" ]] && ok "a key that is not 44 base64 characters is refused and nothing is written" ||
    bad "a refused key was written"
fi

# --- Staging ----------------------------------------------------------------------------------------------------------
export RESTORE_SET_UID
RESTORE_SET_UID="$(id -u)"
RESTORE_STAGING="$work/staging"
tar -cf "$work/set.tar" -C "$set_dir" .
root="$(restore_stage_path "$work/set.tar" 2>/dev/null)"
if [[ "$root" == "$RESTORE_STAGING" && -f "$root/manifest.json" ]]; then
  ok "a tarball with the set at its root is staged"
else
  bad "staging a flat tarball: $root"
fi
mkdir -p "$work/tarroot/paddock-backup" && cp -R "$set_dir/." "$work/tarroot/paddock-backup/"
tar -cf "$work/set2.tar" -C "$work/tarroot" paddock-backup
root="$(restore_stage_path "$work/set2.tar" 2>/dev/null)"
if [[ "$root" == "$RESTORE_STAGING/paddock-backup" && -f "$root/manifest.json" ]]; then
  ok "a tarball with paddock-backup/ as its root is staged"
else
  bad "staging a tarball: $root"
fi
root="$(restore_stage_path "$set_dir" 2>/dev/null)"
if [[ "$root" == "$RESTORE_STAGING" && -f "$root/manifest.json" && -d "$root/$set_repo_path/backup/paddock" ]]; then
  ok "a set directory is copied into the staging directory"
else
  bad "staging a directory: $root"
fi
ln -s /etc/passwd "$work/tarroot/paddock-backup/openbao/20261105T000000Z.snap.enc"
tar -cf "$work/set3.tar" -C "$work/tarroot" paddock-backup
if (restore_stage_path "$work/set3.tar") >/dev/null 2>&1; then bad "a set with a symlink was staged"; else
  ok "a set holding a symlink is refused"
fi

# --- ./paddock restore argument checks ----------------------------------------------------------------------------------
for args in "--from a --from-target-file b" "--plan 11111111-2222-3333-4444-555555555555 --at 2026-11-04T10:00:00Z" \
  "" "--from" "--bogus"; do
  rc=0
  # shellcheck disable=SC2086
  (restore_main $args) >/dev/null 2>&1 || rc=$?
  if ((rc == 2)); then ok "restore $args: usage"; else bad "restore $args: rc $rc, want 2"; fi
done
host_env[PADDOCK_HOST]=lab
rc=0
(restore_main --from "$set_dir") >/dev/null 2>&1 || rc=$?
if ((rc == 2)); then ok "a lab host without PADDOCK_LAB_BACKUP=yes is refused"; else bad "lab without backups: rc $rc"; fi
host_env[PADDOCK_HOST]=controlplane

# --- ./paddock restore and the key file (review B1, M3) -----------------------------------------------------------------
# run_main <stdin> <restore_main arguments...>: as run_restore, for restore_main.
run_main() {
  local input="$1"
  shift
  : >"$calls"
  set +e
  out="$( (trap - EXIT && set -e && restore_main "$@") <<<"$input" 2>&1)"
  rc=$?
  set -e
}
legacy="$SECRETS_DIR/backup_encryption_key"
echo legacy-secret >"$legacy"
legacy_untouched() { [[ "$(cat "$legacy")" == legacy-secret && ! -e "$legacy.pre-restore" ]]; }
no_key_left() { [[ ! -e "$keyfile" && ! -e "$keyfile.tmp" ]]; }
run_main "$key_text" --from "$set_dir" --at yesterday
if ((rc == 2)) && no_key_left && legacy_untouched; then
  ok "an --at that is not RFC 3339 leaves no key file behind"
else
  bad "restore --at yesterday: rc $rc, key left: $(ls "$SECRETS_DIR/restore" 2>&1), out: $out"
fi
run_main "$key_text" --from "$set_dir" --only nope
if ((rc == 2)) && no_key_left; then ok "an unknown --only leaves no key file behind"; else bad "restore --only nope: rc $rc"; fi
plan_json='{"id":"11111111-2222-3333-4444-555555555555","kind":"components","state":"approved","expires_at":"2099-01-01T00:00:00Z","at":null,"source":"repo","source_target_id":null,"source_target_name":null,"components":["backup-repo"],"created_by":"admin"}'
run_main "$key_text" --plan 11111111-2222-3333-4444-555555555555
if ((rc == 2)) && [[ "$out" == *"backup-repo takes no --at and no plan"* ]] && no_key_left && legacy_untouched; then
  ok "a plan the restore refuses after the key prompt leaves no key file behind"
else
  bad "refused plan: rc $rc, key left: $(ls "$SECRETS_DIR/restore" 2>&1), out: $out"
fi
plan_json='{"id":"11111111-2222-3333-4444-555555555555","kind":"components","state":"cancelled","expires_at":null,"at":null,"source":"repo","source_target_id":null,"source_target_name":null,"components":["postgres"],"created_by":"admin"}'
run_main "$key_text" --plan 11111111-2222-3333-4444-555555555555
if ((rc != 0)) && [[ "$out" == *"is cancelled, not approved"* ]] && no_key_left; then
  ok "a plan that is not approved is refused with its state before the key is asked for"
else
  bad "cancelled plan: rc $rc, out: $out"
fi
plan_json='{"id":"11111111-2222-3333-4444-555555555555","kind":"point_in_time","state":"approved","expires_at":"2099-01-01T00:00:00Z","at":"2026-11-03T11:00:00Z","source":"repo","source_target_id":null,"source_target_name":null,"components":["postgres","openbao"],"created_by":"admin"}'
run_main "$key_text"$'\n'restore --plan 11111111-2222-3333-4444-555555555555
if ((rc == 0)) && called "--plan 11111111-2222-3333-4444-555555555555" && called "--at 2026-11-03T11:00:00Z" &&
  called "--components postgres,openbao" && no_key_left; then
  ok "an approved plan runs with its point and components, and the key file is deleted"
else
  bad "approved plan: rc $rc, out: $out, $(grep restore-report "$calls")"
fi
run_main "$key_text"$'\n'restore --from "$set_dir" --only openbao --keep-key-file
if ((rc == 0)) && [[ "$(cat "$keyfile" 2>/dev/null)" == "$key_text" ]] && legacy_untouched &&
  ! grep -qF "$legacy" "$calls"; then
  ok "the key goes to .secrets/restore/backup_key, never to the api's legacy secret; --keep-key-file keeps it"
else
  bad "key path: rc $rc, out: $out"
fi
rm -f "$keyfile"
run_main "$key_text"$'\n'nope --from "$set_dir" --only openbao
if ((rc != 0)) && no_key_left && legacy_untouched; then
  ok "a refused confirmation deletes the key file"
else
  bad "refused confirmation: rc $rc"
fi
if [[ ! -e "$RESTORE_STAGING" ]]; then
  ok "a refused confirmation deletes the staged set (review 2, R2-m3)"
else
  bad "staged set left after a refusal: $(ls "$RESTORE_STAGING")"
fi
run_main "$key_text"$'\n'restore --from "$work/set3.tar" --only openbao
if ((rc != 0)) && [[ "$out" == *"something other than files and directories"* && ! -e "$RESTORE_STAGING" ]]; then
  ok "a set refused while staging is deleted from the staging directory"
else
  bad "refused staging: rc $rc, staging: $(ls "$RESTORE_STAGING" 2>&1), out: $out"
fi

# Review 2 (R2-M1): a TERM during the slow failure report. The key and the caller's key copy are gone before the
# report starts, and the handler still reports and prints the help.
fail_on="openbao bao operator init"
report_sleep=2
rm -f "$reporting" "$work/caller-trap"
: >"$calls"
# shellcheck disable=SC2064 # expanded now, as restore_trap_chain asks of a caller
(trap "touch '$work/caller-trap'" EXIT && set -e && restore_main --from "$set_dir" --only openbao) \
  <<<"$key_text"$'\n'restore >"$work/signal.out" 2>&1 &
pid=$!
for _ in $(seq 1 200); do
  [[ ! -e "$reporting" ]] || break
  sleep 0.1
done
key_at_report=no
no_key_left || key_at_report=yes
kill -TERM "$pid" 2>/dev/null || true
rc=0
wait "$pid" || rc=$?
fail_on="" report_sleep=""
out="$(cat "$work/signal.out")"
if [[ -e "$reporting" && "$key_at_report" == no && -e "$work/caller-trap" ]] && ((rc != 0)) && no_key_left; then
  ok "a signal during the failure report leaves no key file and no caller key copy behind"
else
  bad "signal during the report: rc $rc, key at report: $key_at_report, caller trap: $([[ -e "$work/caller-trap" ]] && echo ran || echo missing), out: $out"
fi
if [[ "$out" == *"run the same ./paddock restore command again"* ]]; then
  ok "the failure help is still printed after a signal during the report"
else
  bad "signal ended the failure handler: $out"
fi

# Review 3 (R3-M1): a signal while a step runs records the step as failed and prints the help. TERM goes to the
# restore's shell alone (kill <pid>, a supervisor); INT goes to its process group, as Ctrl-C does. set -m gives the
# background job a group of its own and keeps INT from being ignored there.
# signal_step <signal> <group|parent>: runs restore_main --only openbao with a slow openbao step, signals it during the
# step and sets rc and out.
signal_step() {
  local target
  step_sleep_on="openbao bao operator init" step_sleep=2
  rm -f "$stepping"
  : >"$calls"
  set -m
  (trap - EXIT && set -e && restore_main --from "$set_dir" --only openbao) \
    <<<"$key_text"$'\n'restore >"$work/signal.out" 2>&1 &
  pid=$!
  set +m
  for _ in $(seq 1 200); do
    [[ ! -e "$stepping" ]] || break
    sleep 0.1
  done
  target="$pid"
  [[ "$2" == parent ]] || target="-$pid"
  kill "-$1" -- "$target" 2>/dev/null || true
  rc=0
  wait "$pid" || rc=$?
  step_sleep_on="" step_sleep=""
  out="$(cat "$work/signal.out")"
}
for sig in TERM:parent INT:group; do
  signal_step "${sig%%:*}" "${sig#*:}"
  if [[ -e "$stepping" ]] && ((rc != 0)) && grep -q -- "--outcome failed .*--component openbao" "$calls" &&
    [[ "$out" == *"run the same ./paddock restore command again"* ]] && no_key_left && [[ ! -e "$RESTORE_STAGING" ]]; then
    ok "SIG${sig%%:*} during a step records the step as failed and prints the failure help"
  else
    bad "SIG${sig%%:*} during a step: rc $rc, reports: $(grep restore-report "$calls" || true), out: $out"
  fi
done

# PDK-837: TERM while the plan is being marked running, before the first step. The handler runs once the report
# ended and cannot tell whether it was accepted: it reports nothing (a refused report would otherwise close another
# run's plan or a lapsed one, Review 1 M1) and prints how to check the plan and record it by hand.
plan_json='{"id":"11111111-2222-3333-4444-555555555555","kind":"components","state":"approved","expires_at":"2099-01-01T00:00:00Z","at":null,"source":"repo","source_target_id":null,"source_target_name":null,"components":["openbao"],"created_by":"admin"}'
for report_rc in 0 1; do
  step_sleep_on="restore-report --outcome running" step_sleep=2
  rm -f "$stepping"
  : >"$calls"
  (trap - EXIT && set -e && restore_main --plan 11111111-2222-3333-4444-555555555555) \
    <<<"$key_text"$'\n'restore >"$work/signal.out" 2>&1 &
  pid=$!
  for _ in $(seq 1 200); do
    [[ ! -e "$stepping" ]] || break
    sleep 0.1
  done
  kill -TERM "$pid" 2>/dev/null || true
  rc=0
  wait "$pid" || rc=$?
  step_sleep_on="" step_sleep=""
  out="$(cat "$work/signal.out")"
  if [[ -e "$stepping" ]] && ((rc != 0)) && ! called "--outcome failed" && ! called " stop" &&
    [[ "$out" == *"nothing on the host was changed"* && "$out" == *"may still be approved"* ]] &&
    [[ "$out" == *"--outcome failed --plan 11111111-2222-3333-4444-555555555555"*"--component start"* ]] &&
    no_key_left; then
    ok "SIGTERM while the plan is marked running (report rc $report_rc) reports nothing and prints the record command"
  else
    bad "SIGTERM during the running report (rc $report_rc): rc $rc, reports: $(grep restore-report "$calls" || true), out: $out"
  fi
done
report_rc=0

# PDK-837: Ctrl-C (INT to the process group) while the success path shreds the key. The handler deletes the rest.
shred_sleep=2
rm -f "$shredding"
: >"$calls"
set -m
(trap - EXIT && set -e && restore_main --from "$set_dir" --only openbao) \
  <<<"$key_text"$'\n'restore >"$work/signal.out" 2>&1 &
pid=$!
set +m
for _ in $(seq 1 200); do
  [[ ! -e "$shredding" ]] || break
  sleep 0.1
done
kill -INT -- "-$pid" 2>/dev/null || true
rc=0
wait "$pid" || rc=$?
shred_sleep=""
if [[ -e "$shredding" ]] && ((rc != 0)) && called "--outcome completed" && no_key_left; then
  ok "SIGINT during the key shred on the success path leaves no key file behind"
else
  bad "SIGINT during the shred: rc $rc, key left: $(ls "$SECRETS_DIR/restore" 2>&1), out: $(cat "$work/signal.out")"
fi
rm -f "$keyfile"

# Review 3 (R3-m1): a signal to the restore's shell alone while the set is being staged. The writer is not signalled
# and keeps writing; the staged set must still be gone afterwards.
echo '{}' >"$work/target.json"
fetch_mode=slow fetch_sleep=2
rm -f "$fetching"
: >"$calls"
(trap - EXIT && set -e && restore_main --from-target-file "$work/target.json") \
  <<<"$key_text"$'\n'restore >"$work/signal.out" 2>&1 &
pid=$!
for _ in $(seq 1 200); do
  [[ ! -e "$fetching" ]] || break
  sleep 0.1
done
kill -TERM "$pid" 2>/dev/null || true
rc=0
wait "$pid" || rc=$?
sleep 2.5
fetch_mode="" fetch_sleep=""
if [[ -e "$fetching" && ! -e "$RESTORE_STAGING" ]] && ((rc != 0)) && no_key_left && ! called "restore-report"; then
  ok "a signal to the restore alone while staging deletes the staged set once the writer ends"
else
  bad "signal while staging: rc $rc, staging: $(find "$RESTORE_STAGING" 2>&1 | head -5), out: $(cat "$work/signal.out")"
fi
chmod -R u+w "$RESTORE_STAGING" 2>/dev/null || true
rm -rf "$RESTORE_STAGING"

# Review 3 (R3-m1): a staged set the cleanup cannot delete ends neither the handler nor the caller's trap.
fetch_mode=locked
rm -f "$work/caller-trap"
: >"$calls"
set +e
# shellcheck disable=SC2064 # expanded now, as restore_trap_chain asks of a caller
out="$( (trap "touch '$work/caller-trap'" EXIT && set -e && restore_main --from-target-file "$work/target.json") \
  <<<"$key_text"$'\n'restore 2>&1)"
rc=$?
set -e
fetch_mode=""
if ((rc != 0)) && [[ -e "$work/caller-trap" && "$out" == *"could not delete the staged set $RESTORE_STAGING"* ]]; then
  ok "a staged set the cleanup cannot delete is named, and the caller's trap still runs"
else
  bad "undeletable staged set: rc $rc, caller trap: $([[ -e "$work/caller-trap" ]] && echo ran || echo missing), out: $out"
fi
chmod -R u+w "$RESTORE_STAGING" 2>/dev/null || true
rm -rf "$RESTORE_STAGING"

# --- ./paddock backup-target export (review 2, R2-m3) -------------------------------------------------------------------
export_dir="$work/export"
mkdir -p "$export_dir"
(trap - EXIT && restore_target_export offsite "$export_dir/target.json") >/dev/null 2>&1
if [[ "$(cat "$export_dir/target.json" 2>/dev/null)" == '{"secret_key":"s3cret"}' && "$(stat -c %a "$export_dir/target.json")" == 600 ]] &&
  ! compgen -G "$export_dir/.backup-target.*" >/dev/null; then
  ok "backup-target export writes the target file 0600 and leaves no temporary file"
else
  bad "export: $(ls -la "$export_dir")"
fi
rm -f "$export_dir/target.json" "$exporting"
export_sleep=2
(trap - EXIT && restore_target_export offsite "$export_dir/target.json") >/dev/null 2>&1 &
pid=$!
for _ in $(seq 1 200); do
  [[ ! -e "$exporting" ]] || break
  sleep 0.1
done
kill -TERM "$pid" 2>/dev/null || true
wait "$pid" || true
export_sleep=""
if [[ -e "$exporting" && ! -e "$export_dir/target.json" ]] && ! compgen -G "$export_dir/.backup-target.*" >/dev/null; then
  ok "an interrupted backup-target export leaves no plain-text credentials behind"
else
  bad "interrupted export: $(ls -la "$export_dir")"
fi

# --- the calls match PDK-735's CLI (AC 4) -------------------------------------------------------------------------------
if [[ -s "$cli_log" ]] && ! grep -q '^REJECTED' "$cli_log" &&
  grep -q '^accepted backup plan ' "$cli_log" &&
  grep -q '^accepted backup restore-repo --check$' "$cli_log" &&
  grep -q '^accepted backup restore-report --outcome running .*--plan .*--at ' "$cli_log" &&
  grep -q '^accepted backup restore-report --outcome completed ' "$cli_log" &&
  grep -q '^accepted backup restore-report --outcome failed .*--component .*--detail ' "$cli_log"; then
  ok "every backup plan and restore-report call parses in the real paddock-server ($(wc -l <"$cli_log") calls)"
else
  bad "calls the real CLI rejects or never saw: $(grep -v '^accepted' "$cli_log" || true) $(cut -d' ' -f1-5 "$cli_log" | sort -u)"
fi
: >"$cli_log"
cli_check run --rm paddock-backup backup restore-report --outcome completed --operator alice --source set \
  --components postgres --duration-s 3
if grep -q '^REJECTED' "$cli_log"; then
  ok "the CLI check rejects a flag paddock-server does not know"
else
  bad "the CLI check accepted --duration-s: $(cat "$cli_log")"
fi

((failures == 0)) || {
  echo "$failures failure(s)"
  exit 1
}
echo "restore_test: all passed"
