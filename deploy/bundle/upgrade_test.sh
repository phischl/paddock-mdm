#!/usr/bin/env bash
# Tests of ./paddock upgrade (PDK-743, `make bundle-test`): the step order of plan M16 decision 6, the stop on a FAIL of
# the check, --allow-unsupported-agents, the --skip-backup rules, the resumable .upgrade-state and the post-checks.
# docker is a stub on PATH and the old bundle's ./paddock is a fake; both write every call to one log, so the test
# reads the order in which the steps ran.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
scripts="$here/../compose/scripts"
fixtures="$here/ci/testdata/upgrade-check"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
failures=0
pass() { echo "ok   $1"; }
fail() {
  echo "FAIL $1" >&2
  failures=$((failures + 1))
}

calls="$work/calls.log"
mkdir -p "$work/bin"
cat >"$work/bin/docker" <<'STUB'
#!/usr/bin/env bash
echo "docker $*" >>"$FIXTURE_CALLS"
case "$1" in
  inspect) printf '%s\n' "${FIXTURE_RUNNING-}" ;;
  manifest) printf '{\n "config": {"size": 1000},\n "layers": [{"size": 1000}]\n}\n' ;;
  info) printf '%s\n' "$FIXTURE_ROOT" ;;
  run) cat >/dev/null; exit "${FIXTURE_CHECK_EXIT:-0}" ;;
  compose)
    case " $* " in
      *" admin upgrade-check "*) printf '%s\n' "${FIXTURE_NEW_REPORT-PASS  migrations  00104 = 00104}" ;;
      *" ps -q"*) echo c ;;
      *" ps "*) printf '%s\n' "${FIXTURE_NEW_PS-paddock-api|running|healthy|0}" ;;
      *" config "*) echo '{}' ;;
      *" up -d"*) exit "${FIXTURE_UP_EXIT:-0}" ;;
    esac
    ;;
esac
exit 0
STUB
chmod +x "$work/bin/docker"
export PATH="$work/bin:$PATH" FIXTURE_ROOT="$work" FIXTURE_CALLS="$calls"

# The old bundle's ./paddock: it answers what upgrade and upgrade-check ask, and prints a usage with or without the
# backup commands (0.1.0-alpha.8 has none). For 0.1.0-alpha.8's own backup it reports what that release's commands
# print, and the bucket (the AWS CLI one-off) answers FIXTURE_S3_EXIT. A one-off's script is logged on the same line.
cat >"$work/old-paddock" <<'FAKE'
#!/usr/bin/env bash
printf 'old %s\n' "${*//$'\n'/ }" >>"$FIXTURE_CALLS"
case "${1:-}" in
  verify) echo "all shipped files unchanged" ;;
  ps) printf '%s\n' "paddock-api|running|healthy|0" "postgres|running|healthy|0" ;;
  compose)
    if [[ "$*" == *"admin upgrade-check"* ]]; then
      printf '%s\n' "${FIXTURE_REPORT-PASS  migrations  ok}"
      exit "${FIXTURE_REPORT_EXIT:-0}"
    fi
    case "$*" in
      *" pgbackrest backup --start-fast")
        echo "pgbackrest: backup 20261106-100000F of paddock verified"
        exit "${FIXTURE_PG_EXIT:-0}"
        ;;
      *" pgbackrest-authentik backup --start-fast") echo "pgbackrest: backup 20261106-100100F of authentik verified" ;;
      *" pgbackrest info") printf 'stanza: paddock\n        full backup: 20261105-000000F\n        full backup: %s\n' "${FIXTURE_NEWEST-20261106-100000F}" ;;
      *" pgbackrest-authentik info") echo "        full backup: ${FIXTURE_NEWEST_AUTHENTIK-20261106-100100F}" ;;
      *" paddock-worker backup openbao")
        [[ -n "${FIXTURE_NO_SNAPSHOT:-}" ]] || echo 'time=2026-11-06T10:02:00Z level=INFO msg="OpenBao snapshot stored" key=openbao/20261106T100200Z.snap.enc'
        ;;
      *" fleet-backup once") echo "fleet backup: dumped 20261106T100300Z.sql.gz.enc" ;;
      *" fleet-backup-upload "*) exit "${FIXTURE_S3_EXIT:-0}" ;;
      *" stop pgbackrest pgbackrest-authentik") exit "${FIXTURE_STOP_EXIT:-0}" ;;
      *" pgbackrest-authentik flush") exit "${FIXTURE_FLUSH_EXIT:-0}" ;;
    esac
    ;;
  backup) exit "${FIXTURE_BACKUP_EXIT:-0}" ;;
  up) ;;
  *)
    echo "usage: ./paddock <command> [arguments]" >&2
    [[ -n "${FIXTURE_OLD_NO_BACKUP:-}" ]] || echo "  backup now [--kind k]... [--label l] [--wait]" >&2
    exit 2
    ;;
esac
FAKE
chmod +x "$work/old-paddock"

# setup <host> <schema line>: a fresh new directory (alpha.10) and an old installation (alpha.9) under $work/t.
setup() {
  local host="$1" schema="$2" s
  rm -rf "$work/t"
  mkdir -p "$work/t/new/scripts" "$work/t/old"
  cp -a "$fixtures/new/." "$work/t/new/"
  cp "$here/paddock" "$work/t/new/paddock"
  for s in lib.sh upgrade-check.sh upgrade.sh rollback.sh legacy-alpha8.sh openbao-restore.sh; do cp "$scripts/$s" "$work/t/new/scripts/$s"; done
  for s in gen-prod-secrets.sh wait-healthy.sh openbao-configure.sh; do
    # shellcheck disable=SC2016 # the stub expands its arguments when it runs
    printf '#!/usr/bin/env bash\necho "script %s $*" >>"$FIXTURE_CALLS"\n' "$s" >"$work/t/new/scripts/$s"
    chmod +x "$work/t/new/scripts/$s"
  done
  sed -i 's/^version=.*/version=0.1.0-alpha.10/' "$work/t/new/VERSION"
  echo 0.1.0-alpha.10 >>"$work/t/new/RELEASES"
  printf '%s\nUpgrade: from 0.1.0-alpha.9: automatic\nAgents: supports 0.1.0-alpha.8, 0.1.0-alpha.9, 0.1.0-alpha.10\n' \
    "$schema" >"$work/t/new/RELEASE-NOTES"
  echo "FLEET_IMAGE=fleetdm/fleet:v4.94.0" >>"$work/t/new/versions.env"
  cp -a "$fixtures/old/." "$work/t/old/"
  cp "$work/old-paddock" "$work/t/old/paddock"
  sed -i 's/^version=.*/version=0.1.0-alpha.9/' "$work/t/old/VERSION"
  sed -i "s/^PADDOCK_HOST=.*/PADDOCK_HOST=$host/" "$work/t/old/.env"
  printf 'PADDOCK_SMTP_HOST=mail.example.org\nPADDOCK_AUTO_UNSEAL=yes\n' >>"$work/t/old/.env"
  cp "$work/t/new/versions.env" "$work/t/old/versions.env"
  mkdir -p "$work/t/old/.secrets/release-production" "$work/t/old/.secrets/approle/paddock-api" "$work/t/old/.secrets/openbao"
  touch "$work/t/old/.secrets/db_password" "$work/t/old/.secrets/release-production/minisign.pub" \
    "$work/t/old/.secrets/approle/paddock-api/role_id" "$work/t/old/.secrets/openbao/auto-unseal-shares"
  : >"$calls"
}

# run <expected exit> <name> <args…>: ./paddock upgrade in the new directory, stdin from $input; output in $out.
input=""
run() {
  local want="$1" name="$2" got=0
  shift 2
  out="$(cd "$work/t/new" && ./paddock upgrade "$@" <<<"$input" 2>&1)" || got=$?
  if [[ "$got" == "$want" ]]; then pass "$name (exit $got)"; else
    fail "$name: exit $got, want $want"
    printf '%s\n' "$out" >&2
  fi
}
has() { if grep -qE -- "$2" <<<"$out"; then pass "$1"; else
  fail "$1: no output line matches '$2'"
  printf '%s\n' "$out" >&2
fi; }
called() { if grep -qE -- "$2" "$calls"; then pass "$1"; else
  fail "$1: no call matches '$2'"
  cat "$calls" >&2
fi; }
hasnt() { if grep -qE -- "$2" <<<"$out"; then
  fail "$1: an output line matches '$2'"
  printf '%s\n' "$out" >&2
else pass "$1"; fi; }
not_called() { if grep -qE -- "$2" "$calls"; then
  fail "$1: a call matches '$2'"
  cat "$calls" >&2
else pass "$1"; fi; }
# line_of <regex>: the line number of the first matching call (0 when none).
line_of() { grep -nE -- "$1" "$calls" | head -n 1 | cut -d: -f1 || echo 0; }
before() {
  local a b
  a="$(line_of "$2")" b="$(line_of "$3")"
  if [[ -n "$a" && -n "$b" && "$a" -gt 0 && "$b" -gt 0 && "$a" -lt "$b" ]]; then pass "$1"; else
    fail "$1: '$2' (line ${a:-0}) is not before '$3' (line ${b:-0})"
    cat "$calls" >&2
  fi
}
UP='^docker compose .* up -d$'
BACKUP='^old backup now --label pre-upgrade-0.1.0-alpha.10 --wait$'

# The whole run on the control plane.
setup controlplane "Schema: migrations 00105–00106 (control-plane database); audit unchanged"
run 0 "upgrade of the control plane" "$work/t/old" --yes
before "migrate-from before secrets" '^script gen-prod-secrets.sh controlplane' ' pull$'
before "pull before the configuration check" ' pull$' '^docker run .*prod-check'
before "configuration check before the backup" '^docker run .*prod-check' "$BACKUP"
before "the backup completes before up uses the pulled images" "$BACKUP" "$UP"
before "up before the post-check report" "$UP" '^docker compose .*admin upgrade-check --target-version 0.1.0-alpha.10'
not_called "only an upgrade from 0.1.0-alpha.8 stops the old pgBackRest" 'compose stop pgbackrest'
if [[ -f "$work/t/new/.env" && -d "$work/t/new/.secrets" ]]; then pass "migrate-from copied .env and .secrets/"; else fail "no .env or .secrets/ here"; fi
if [[ ! -e "$work/t/new/.upgrade-state" ]]; then pass "success deletes .upgrade-state"; else fail ".upgrade-state is left"; fi
rec="$work/t/new/.upgrade-rollback"
if grep -qx "old=$work/t/old" "$rec" && grep -qx 'backup=yes' "$rec" && grep -qx 'label=pre-upgrade-0.1.0-alpha.10' "$rec" &&
  grep -qE '^at=[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$' "$rec" && grep -qx 'from=0.1.0-alpha.9' "$rec" &&
  grep -qx 'to=0.1.0-alpha.10' "$rec" && grep -qE '^attempt=[0-9a-f]{16}$' "$rec"; then pass ".upgrade-rollback names the rollback point and its attempt"; else
  fail ".upgrade-rollback: $(cat "$rec" 2>&1)"
fi
has "every step prints its command" '^\+ \./paddock pull$'
has "the old directory is named as the rollback" "Keep $work/t/old until the next upgrade: it is the rollback"
has "the plan names the versions" 'from 0.1.0-alpha.9 to 0.1.0-alpha.10'
has "without BAO_TOKEN the OpenBao step is skipped" 'skipped: BAO_TOKEN is not set'
not_called "the control plane stops no audit writer" 'paddock-audit-writer'
not_called "the control plane runs no online check" 'prod-check .*--online'

# BAO_TOKEN set: openbao-configure.sh runs after up.
setup controlplane "Schema: unchanged"
BAO_TOKEN=fixture-token run 0 "upgrade with BAO_TOKEN" "$work/t/old" --yes
before "openbao-configure.sh after up" "$UP" '^script openbao-configure.sh'

# A FAIL of the check stops before migrate-from; --allow-unsupported-agents downgrades the agents FAIL only.
setup controlplane "Schema: migrations 00105–00106"
FIXTURE_REPORT=$'FAIL  agents  9 agents outside the window' FIXTURE_REPORT_EXIT=1 run 1 "check FAIL stops" "$work/t/old" --yes
if [[ ! -e "$work/t/new/.env" ]]; then pass "no migrate-from after a FAIL"; else fail "migrate-from ran after a FAIL"; fi
if [[ ! -e "$work/t/new/.upgrade-state" ]]; then pass "a failed check leaves no .upgrade-state"; else fail ".upgrade-state after a failed check"; fi
not_called "no backup after a FAIL" '^old backup'
has "the failure says nothing changed" 'Nothing changed on the running stack'
FIXTURE_REPORT=$'FAIL  agents  9 agents outside the window' FIXTURE_REPORT_EXIT=1 \
  run 0 "--allow-unsupported-agents accepts the agents FAIL" "$work/t/old" --yes --allow-unsupported-agents
has "the accepted FAIL is named" 'the agents FAIL is accepted'
setup controlplane "Schema: migrations 00105–00106"
FIXTURE_REPORT=$'FAIL  agents  9 agents outside the window\nFAIL  migrations  the database is ahead' FIXTURE_REPORT_EXIT=1 \
  run 1 "--allow-unsupported-agents does not accept another server FAIL" "$work/t/old" --yes --allow-unsupported-agents
if [[ ! -e "$work/t/new/.env" ]]; then pass "nothing changed on another FAIL"; else fail "migrate-from ran"; fi
rm -rf "$work/t/old/.secrets/approle"
run 1 "--allow-unsupported-agents does not accept a secrets FAIL" "$work/t/old" --yes --allow-unsupported-agents
has "the blocking item is named" 'the check failed \(secrets\)'

# --skip-backup: refused on the control plane unless Schema: unchanged and Fleet's image stays.
setup controlplane "Schema: migrations 00105–00106"
run 2 "--skip-backup with migrations is refused" "$work/t/old" --yes --skip-backup
not_called "the refusal runs nothing" '^(docker|script|old [a-z])'
setup controlplane "Schema: unchanged"
sed -i 's/^FLEET_IMAGE=.*/FLEET_IMAGE=fleetdm\/fleet:v4.93.2/' "$work/t/old/versions.env"
run 2 "--skip-backup with a Fleet change is refused" "$work/t/old" --yes --skip-backup
setup controlplane "Schema: unchanged"
run 0 "--skip-backup with Schema: unchanged" "$work/t/old" --yes --skip-backup
not_called "no backup with --skip-backup" '^old backup'
if grep -qx 'backup=no' "$work/t/new/.upgrade-rollback"; then pass "the record says no backup"; else fail "record: $(cat "$work/t/new/.upgrade-rollback")"; fi

# An old release other than 0.1.0-alpha.8 without the labelled backup: refused before anything runs.
setup controlplane "Schema: migrations 00105–00106"
FIXTURE_OLD_NO_BACKUP=1 run 1 "an old release without backup now is refused" "$work/t/old" --yes
has "the refusal names the missing command" 'has no ./paddock backup now --label'
not_called "nothing runs for the refused old release" '^(docker|script)'

# 0.1.0-alpha.8 (decisions-alpha9 item 46): its own backup through its own Compose files, checked in the bucket, before
# up; the record names what its restore procedure needs.
LEGACY_PG='^old compose run --rm --no-deps -T pgbackrest backup --start-fast$'
LEGACY_FLEET_HEAD='^old compose run .* fleet-backup-upload .* la8-s3 head fleet/20261106T100300Z\.sql\.gz\.enc$'
FENCE_STOP='^old compose stop pgbackrest pgbackrest-authentik$'
FENCE_FLUSH='^old compose run --rm --no-deps -T pgbackrest flush$'
FENCE_FLUSH_AUTHENTIK='^old compose run --rm --no-deps -T pgbackrest-authentik flush$'
FENCE_RESTART='^old compose start pgbackrest pgbackrest-authentik$'
setup_alpha8() {
  setup controlplane "Schema: migrations 00100–00106"
  sed -i 's/^version=.*/version=0.1.0-alpha.8/' "$work/t/old/VERSION"
  sed -i '/^0\.1\.0-alpha\.10$/d' "$work/t/new/RELEASES"
  sed -i 's/^version=.*/version=0.1.0-alpha.9/' "$work/t/new/VERSION"
}
setup_alpha8
FIXTURE_OLD_NO_BACKUP=1 run 0 "upgrade from 0.1.0-alpha.8 with its own backup" "$work/t/old" --yes
has "the plan names alpha.8's own backup" "0\.1\.0-alpha\.8's own backup through .*/paddock compose"
has "the plan names alpha.8's restore procedure for the rollback" "It runs 0\.1\.0-alpha\.8's restore procedure"
not_called "no backup now for alpha.8" '^old backup'
before "paddock's full backup first" "$LEGACY_PG" '^old compose run --rm --no-deps -T pgbackrest-authentik backup --start-fast$'
before "then authentik's" '^old compose run --rm --no-deps -T pgbackrest-authentik backup --start-fast$' '^old compose run --rm --no-deps -T paddock-worker backup openbao$'
before "then the OpenBao snapshot" '^old compose run --rm --no-deps -T paddock-worker backup openbao$' '^old compose run --rm --no-deps -T fleet-backup once$'
before "then Fleet's dump" '^old compose run --rm --no-deps -T fleet-backup once$' '^old compose run --rm --no-deps -T pgbackrest info$'
before "the snapshot is checked in the bucket" '^old compose run .* la8-s3 head openbao/20261106T100200Z\.snap\.enc$' "$UP"
before "the dump's upload is awaited before up" "$LEGACY_FLEET_HEAD" "$UP"
before "the check before the backup" '^docker run .*prod-check' "$LEGACY_PG"
called "the bucket is read with the pgBackRest credential mounted as files" \
  "-v $work/t/old/\.secrets/backup_pgbackrest_access_key:/run/paddock-legacy/access_key:ro -v $work/t/old/\.secrets/backup_pgbackrest_secret_key:/run/paddock-legacy/secret_key:ro --entrypoint /bin/bash fleet-backup-upload"
rec="$work/t/new/.upgrade-rollback"
if grep -qx 'method=legacy-0.1.0-alpha.8' "$rec" && grep -qx 'legacy-paddock=20261106-100000F' "$rec" &&
  grep -qx 'legacy-authentik=20261106-100100F' "$rec" && grep -qx 'legacy-openbao=openbao/20261106T100200Z.snap.enc' "$rec" &&
  grep -qx 'legacy-fleet=fleet/20261106T100300Z.sql.gz.enc' "$rec" && grep -qE '^legacy-at=[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:]{8}Z$' "$rec" &&
  grep -qx 'from=0.1.0-alpha.8' "$rec" && grep -qx 'backup=yes' "$rec"; then pass "the record names alpha.8's backups"; else
  fail "the record of alpha.8's backups: $(cat "$rec" 2>&1)"
fi
# The bucket's WAL archive ends before up (Review 1, M1): alpha.8's pusher must not push this release's migration WAL.
has "the plan names the fence of alpha.8's WAL archive" 'stop pgbackrest pgbackrest-authentik and flush both \(the backup bucket.s WAL archive ends here\), then \./paddock up'
before "the fence follows the bucket checks" "$LEGACY_FLEET_HEAD" "$FENCE_STOP"
before "alpha.8's pgBackRest stops before the flush" "$FENCE_STOP" "$FENCE_FLUSH"
before "paddock's spool is flushed, then authentik's" "$FENCE_FLUSH" "$FENCE_FLUSH_AUTHENTIK"
before "the fence ends before up" "$FENCE_FLUSH_AUTHENTIK" "$UP"
not_called "a fenced archive is not started again" "$FENCE_RESTART"

# A failed fence: up does not run, no record is written, alpha.8 archives again, and the next run repeats the fence.
setup_alpha8
FIXTURE_OLD_NO_BACKUP=1 FIXTURE_FLUSH_EXIT=1 run 1 "a failed flush of alpha.8's spool" "$work/t/old" --yes
has "the failed fence is named" "cannot end 0\.1\.0-alpha\.8's WAL archive in the backup bucket"
has "a failed fence says that up did not run" '\./paddock up did not run: 0\.1\.0-alpha\.8 still runs unchanged from'
has "a failed fence names the next run" "Fix the cause, then run \./paddock upgrade $work/t/old again\.$"
hasnt "a failed fence does not send to the rollback" 'Roll back|may be partly running'
not_called "no up after a failed fence" "$UP"
called "alpha.8's pgBackRest starts again after a failed fence" "$FENCE_RESTART"
if [[ ! -e "$work/t/new/.upgrade-rollback" ]]; then pass "no record after a failed fence"; else fail "a record after a failed fence"; fi
FIXTURE_OLD_NO_BACKUP=1 run 0 "the second run after a failed fence" "$work/t/old" --yes
if [[ "$(grep -cE "$FENCE_STOP" "$calls")" == 2 ]]; then pass "the second run repeats the fence"; else fail "the fence ran $(grep -cE "$FENCE_STOP" "$calls") times"; fi
if [[ "$(grep -cE "$LEGACY_PG" "$calls")" == 1 ]]; then pass "the second run keeps alpha.8's backup"; else fail "alpha.8's backup ran $(grep -cE "$LEGACY_PG" "$calls") times"; fi
# Review 2, M2: a run stopped between the backup and up leaves alpha.8's pgBackRest running, which takes a newer full
# backup once the last is 24 h old; its restore takes the newest, so the recorded point is checked after the fence.
setup_alpha8
FIXTURE_OLD_NO_BACKUP=1 FIXTURE_FLUSH_EXIT=1 run 1 "a run stopped after alpha.8's backup" "$work/t/old" --yes
: >"$calls"
FIXTURE_OLD_NO_BACKUP=1 FIXTURE_NEWEST=20261107-100000F run 1 "a newer paddock backup since the recorded one" "$work/t/old" --yes
has "the newer backup is named" 'the newest backup of stanza paddock in the bucket is 20261107-100000F, not the recorded pre-upgrade backup 20261106-100000F'
has "the newer backup says that up did not run" '\./paddock up did not run: 0\.1\.0-alpha\.8 still runs unchanged from'
hasnt "a newer backup does not send to the rollback" 'Roll back|may be partly running'
not_called "no up after a newer backup" "$UP"
if [[ ! -e "$work/t/new/.upgrade-rollback" ]]; then pass "no record after a newer backup"; else fail "a record after a newer backup"; fi
if ! grep -qE '^(done=backup|legacy-)' "$work/t/new/.upgrade-state"; then pass "the step backup and its names are forgotten"; else
  fail "state after a newer backup: $(cat "$work/t/new/.upgrade-state")"
fi
before "alpha.8's pgBackRest starts again after the newest check" "$FENCE_FLUSH_AUTHENTIK" "$FENCE_RESTART"
: >"$calls"
FIXTURE_OLD_NO_BACKUP=1 run 0 "the run after a newer backup" "$work/t/old" --yes
called "the run after a newer backup repeats alpha.8's backup" "$LEGACY_PG"
before "the repeated backup precedes up" "$LEGACY_PG" "$UP"
if grep -qx 'legacy-paddock=20261106-100000F' "$work/t/new/.upgrade-rollback"; then pass "the record names the repeated backup"; else
  fail "the record after a repeated backup: $(cat "$work/t/new/.upgrade-rollback" 2>&1)"
fi
setup_alpha8
FIXTURE_OLD_NO_BACKUP=1 FIXTURE_FLUSH_EXIT=1 run 1 "a run stopped after alpha.8's backup (authentik)" "$work/t/old" --yes
: >"$calls"
FIXTURE_OLD_NO_BACKUP=1 FIXTURE_NEWEST_AUTHENTIK=20261107-100100F run 1 "a newer authentik backup since the recorded one" "$work/t/old" --yes
has "the newer authentik backup is named" 'the newest backup of stanza authentik in the bucket is 20261107-100100F'
not_called "no up after a newer authentik backup" "$UP"
if ! grep -qx 'done=backup' "$work/t/new/.upgrade-state"; then pass "the step backup is forgotten (authentik)"; else fail "done=backup kept"; fi

setup_alpha8
FIXTURE_OLD_NO_BACKUP=1 FIXTURE_STOP_EXIT=1 run 1 "alpha.8's pgBackRest does not stop" "$work/t/old" --yes
not_called "no flush when the stop failed" "$FENCE_FLUSH"
not_called "no up when the stop failed" "$UP"

# Every failure of alpha.8's backup stops before up, with nothing changed on the running stack.
setup_alpha8
FIXTURE_OLD_NO_BACKUP=1 FIXTURE_PG_EXIT=1 run 1 "a failed pgBackRest backup of alpha.8" "$work/t/old" --yes
not_called "no up after alpha.8's failed backup" "$UP"
has "nothing changed after alpha.8's failed backup" 'Nothing changed on the running stack'
setup_alpha8
FIXTURE_OLD_NO_BACKUP=1 FIXTURE_NEWEST=20261106-110000F run 1 "a newer backup than alpha.8's pre-upgrade one" "$work/t/old" --yes
has "the newest-backup check is named" 'the newest backup of stanza paddock in the bucket is not 20261106-100000F'
not_called "no up when the newest backup is another" "$UP"
setup_alpha8
FIXTURE_OLD_NO_BACKUP=1 FIXTURE_NO_SNAPSHOT=1 run 1 "alpha.8's snapshot not reported" "$work/t/old" --yes
has "the unreported backup is named" "OpenBao '\?'"
not_called "no up without the snapshot's name" "$UP"
setup_alpha8
FIXTURE_OLD_NO_BACKUP=1 FIXTURE_S3_EXIT=1 LA8_UPLOAD_TIMEOUT=0 run 1 "alpha.8's objects not in the bucket" "$work/t/old" --yes
has "the missing object is named" 'openbao/20261106T100200Z\.snap\.enc is not in the backup bucket'
not_called "no up when an object is missing" "$UP"
if [[ ! -e "$work/t/new/.upgrade-rollback" ]]; then pass "no record without alpha.8's backup"; else fail "a record without alpha.8's backup"; fi

# A failed up after alpha.8's backup: the second run continues at up, without a second backup, and keeps its names.
setup_alpha8
FIXTURE_OLD_NO_BACKUP=1 FIXTURE_UP_EXIT=1 run 1 "up fails after alpha.8's backup" "$work/t/old" --yes
FIXTURE_OLD_NO_BACKUP=1 run 0 "the second run after alpha.8's backup" "$work/t/old" --yes
if [[ "$(grep -cE "$LEGACY_PG" "$calls")" == 1 ]]; then pass "alpha.8's backup ran once"; else fail "alpha.8's backup ran $(grep -cE "$LEGACY_PG" "$calls") times"; fi
if [[ "$(grep -cE "$FENCE_STOP" "$calls")" == 1 ]]; then pass "the fence before the recorded point ran once"; else fail "the fence ran $(grep -cE "$FENCE_STOP" "$calls") times"; fi
if grep -qx 'legacy-openbao=openbao/20261106T100200Z.snap.enc' "$work/t/new/.upgrade-rollback"; then pass "the resumed run's record keeps alpha.8's names"; else
  fail "the resumed record: $(cat "$work/t/new/.upgrade-rollback")"
fi

# A failed backup stops before up; the old stack is untouched.
setup controlplane "Schema: migrations 00105–00106"
FIXTURE_BACKUP_EXIT=1 run 1 "failed backup" "$work/t/old" --yes
not_called "no up after a failed backup" "$UP"
has "the failed backup leaves the old stack running" 'Nothing changed on the running stack: 0.1.0-alpha.9 still runs'

# A failure of up leaves .upgrade-state; the next run continues at up and keeps the first rollback point.
setup controlplane "Schema: migrations 00105–00106"
FIXTURE_UP_EXIT=1 run 1 "up fails" "$work/t/old" --yes
if [[ -f "$work/t/new/.upgrade-state" ]]; then pass "a failed up leaves .upgrade-state"; else fail "no .upgrade-state after a failed up"; fi
has "the failure names the rollback" "Roll back: ./paddock rollback $work/t/old"
hasnt "a failed up gives no second, contradicting instruction" 'Fix the cause, then run'
first_at="$(sed -n 's/^at=//p' "$work/t/new/.upgrade-rollback")"
first_attempt="$(sed -n 's/^attempt=//p' "$work/t/new/.upgrade-rollback")"
if grep -qx "attempt=$first_attempt" "$work/t/new/.upgrade-state" && grep -qx "up-started=$first_at" "$work/t/new/.upgrade-state"; then
  pass ".upgrade-state binds the record to this attempt"
else fail "state: $(cat "$work/t/new/.upgrade-state")"; fi
: >"$calls"
sleep 1
run 0 "the second run continues" "$work/t/old" --yes
not_called "the second run does not pull again" ' pull$'
not_called "the second run takes no second backup" '^old backup'
not_called "the second run does not migrate again" '^script gen-prod-secrets'
called "the second run runs up" "$UP"
has "done steps are reported" '== backup: done in an earlier run'
if [[ "$(sed -n 's/^at=//p' "$work/t/new/.upgrade-rollback")" == "$first_at" &&
  "$(sed -n 's/^attempt=//p' "$work/t/new/.upgrade-rollback")" == "$first_attempt" ]]; then pass "the rollback point stays the first up's"; else fail "the rollback point moved"; fi
if [[ ! -e "$work/t/new/.upgrade-state" ]]; then pass "the completed second run deletes .upgrade-state"; else fail ".upgrade-state left"; fi

# A failed post-check: the next run runs the post-checks only.
setup controlplane "Schema: migrations 00105–00106"
FIXTURE_NEW_REPORT='FAIL  migrations  the database is behind' run 1 "post-check fails without the migrations PASS" "$work/t/old" --yes
if grep -qx 'done=up' "$work/t/new/.upgrade-state"; then pass "up is recorded as done"; else fail "state: $(cat "$work/t/new/.upgrade-state")"; fi
has "a failed post-check continues" "Fix the cause, then run ./paddock upgrade $work/t/old again: it continues at the step post-checks"
hasnt "a failed post-check does not send to the rollback first" '^  Roll back: '

: >"$calls"
run 0 "the post-checks pass on the second run" "$work/t/old" --yes
not_called "up is not repeated" "$UP"
called "the report is read again" '^docker compose .*admin upgrade-check --target-version 0.1.0-alpha.10'
setup controlplane "Schema: migrations 00105–00106"
FIXTURE_NEW_PS='paddock-api|running|unhealthy|0' run 1 "post-check fails on an unhealthy service" "$work/t/old" --yes

# The rollback point cannot be written: up does not run (errexit is off inside a step).
setup controlplane "Schema: migrations 00105–00106"
mkdir "$work/t/new/.upgrade-rollback.tmp"
run 1 "an unwritable rollback point stops before up" "$work/t/old" --yes
not_called "no up without a rollback point" "$UP"
has "the failure names the rollback point" 'cannot record the rollback point'
if ! grep -q '^up-started=' "$work/t/new/.upgrade-state"; then pass "no up-started without a record"; else fail "up-started was recorded"; fi
has "an unwritten record says that up did not run" '\./paddock up did not run: 0\.1\.0-alpha\.9 still runs unchanged from'
hasnt "an unwritten record does not send to the rollback" 'Roll back|may be partly running'
setup_alpha8
mkdir "$work/t/new/.upgrade-rollback.tmp"
FIXTURE_OLD_NO_BACKUP=1 run 1 "an unwritable rollback point after alpha.8's fence" "$work/t/old" --yes
not_called "no up without alpha.8's rollback point" "$UP"
before "alpha.8's pgBackRest starts again after an unwritten record" "$FENCE_FLUSH_AUTHENTIK" "$FENCE_RESTART"

# A partial migrate-from (an interrupted copy) is removed and copied again on the next run.
setup controlplane "Schema: migrations 00105–00106"
printf 'old=%s\ndone=upgrade-check\n' "$work/t/old" >"$work/t/new/.upgrade-state"
echo PARTIAL=1 >"$work/t/new/.env"
mkdir -p "$work/t/new/.secrets"
touch "$work/t/new/.secrets/partial" "$work/t/new/.compose.backup-targets.yaml.AbC123"
run 0 "a partial migrate-from is resumed" "$work/t/old" --yes
if cmp -s "$work/t/old/.env" "$work/t/new/.env" && [[ ! -e "$work/t/new/.secrets/partial" && -e "$work/t/new/.secrets/db_password" &&
  ! -e "$work/t/new/.compose.backup-targets.yaml.AbC123" ]]; then pass "the partial copy is replaced by a full one"; else
  fail "the partial copy stays: $(ls -a "$work/t/new" "$work/t/new/.secrets")"
fi
has "the removal is printed" '^\+ rm -rf \.env \.secrets \.compose\.backup-targets\.yaml\.AbC123 '

# The confirmation: anything but "yes" stops before migrate-from, and the check runs again next time.
setup controlplane "Schema: migrations 00105–00106"
input=no run 1 "not confirmed" "$work/t/old"
if [[ ! -e "$work/t/new/.env" && ! -e "$work/t/new/.upgrade-state" ]]; then pass "nothing changed without yes"; else fail "changed without yes"; fi
input=yes run 0 "confirmed with yes" "$work/t/old"
input=""

# After a rollback (R2-m1, R2-m2): a "no" removes only the check's result, the next run checks and copies .env again,
# and a failed check keeps .upgrade-state.
setup controlplane "Schema: migrations 00105–00106"
cp "$work/t/old/.env" "$work/t/new/.env"
echo STALE=1 >>"$work/t/new/.env"
cp -a "$work/t/old/.secrets" "$work/t/new/.secrets"
printf 'old=%s\nrolled-back=0123456789abcdef\n' "$work/t/old" >"$work/t/new/.upgrade-state"
input=no run 1 "not confirmed after a rollback" "$work/t/old"
if grep -q '^rolled-back=' "$work/t/new/.upgrade-state" && ! grep -q '^done=' "$work/t/new/.upgrade-state"; then
  pass "a no after a rollback removes only the check's result"
else fail ".upgrade-state after a no: $(cat "$work/t/new/.upgrade-state" 2>&1)"; fi
input=""
FIXTURE_REPORT=$'FAIL  migrations  the database is ahead' FIXTURE_REPORT_EXIT=1 run 1 "a failed check after a rollback" "$work/t/old" --yes
if [[ -f "$work/t/new/.upgrade-state" ]]; then pass "a failed check after a rollback keeps .upgrade-state"; else
  fail "a failed check after a rollback deleted .upgrade-state"
fi
run 0 "the upgrade after a rollback" "$work/t/old" --yes
has "the check runs again" '^== upgrade-check$'
has "migrate-from runs again" '^== migrate-from$'
if cmp -s "$work/t/old/.env" "$work/t/new/.env"; then pass "migrate-from copies .env again"; else fail "the stale .env stays"; fi

# A→B→C (R2-M1): the upgrade supersedes the old directory's own rollback point, so a rollback from there is refused
# even where the running version cannot tell (FIXTURE_RUNNING claims the old release).
setup controlplane "Schema: unchanged"
mkdir -p "$work/t/older"
cp "$work/t/old/.env" "$work/t/older/.env"
cp "$work/old-paddock" "$work/t/older/paddock"
sed 's/^version=.*/version=0.1.0-alpha.8/' "$work/t/old/VERSION" >"$work/t/older/VERSION"
cp "$work/t/old/versions.env" "$work/t/older/versions.env"
printf 'old=%s\nfrom=0.1.0-alpha.8\nto=0.1.0-alpha.9\nbackup=yes\nlabel=pre-upgrade-0.1.0-alpha.9\nat=2026-11-01T10:00:00Z\nattempt=0123456789abcdef\n' \
  "$work/t/older" >"$work/t/old/.upgrade-rollback"
run 0 "the upgrade from an upgraded directory" "$work/t/old" --yes
if [[ ! -e "$work/t/old/.upgrade-rollback" && -f "$work/t/old/.upgrade-rollback.superseded-by-0.1.0-alpha.10" ]]; then
  pass "the old directory's rollback point is superseded"
else fail "the old directory's rollback point stays: $(ls -a "$work/t/old")"; fi
cp "$here/paddock" "$work/t/old/paddock"
mkdir -p "$work/t/old/scripts"
for f in lib.sh upgrade-check.sh upgrade.sh rollback.sh legacy-alpha8.sh openbao-restore.sh; do cp "$scripts/$f" "$work/t/old/scripts/$f"; done
for f in compose.yaml compose.prod.yaml compose.backup.yaml; do cp "$fixtures/new/$f" "$work/t/old/$f"; done
echo "Schema: unchanged" >"$work/t/old/RELEASE-NOTES"
: >"$calls"
out="$(cd "$work/t/old" && FIXTURE_RUNNING="Paddock|0.1.0-alpha.9" ./paddock rollback "$work/t/older" --yes 2>&1)" && got=0 || got=$?
if [[ "$got" == 1 ]]; then pass "the rollback from the superseded directory is refused (exit 1)"; else
  fail "the rollback from the superseded directory: exit $got, want 1"
  printf '%s\n' "$out" >&2
fi
has "the refusal names the superseding upgrade" 'superseded by the upgrade to 0.1.0-alpha.10'
not_called "the superseded rollback stops before down" '^docker compose .* down$'
not_called "the superseded rollback starts nothing" '^old up$'
input=""

# The audit host: no backup, the old audit writer stopped before up on audit migrations, check --online afterwards.
setup audit "Schema: migrations 00105 (control-plane database); audit migrations 00011–00012"
run 0 "upgrade of the audit host" "$work/t/old" --yes
not_called "the audit host takes no backup" '^old backup'
before "the old audit writer stops before up" '^old compose stop paddock-audit-writer$' "$UP"
called "the audit host runs the online check" '^docker run .*prod-check .*--online'
not_called "the audit host asks no server report" '^docker compose .*admin upgrade-check'
setup audit "Schema: migrations 00105 (control-plane database); audit unchanged"
run 0 "audit host without audit migrations" "$work/t/old" --yes
not_called "no audit writer stop without audit migrations" 'paddock-audit-writer'

# The audit host without a Schema line: its migrations are unknown, so the writer stops.
setup audit ""
run 0 "audit host without a Schema line" "$work/t/old" --yes
before "the writer stops without a Schema line" '^old compose stop paddock-audit-writer$' "$UP"

# A lab host without backups needs --skip-backup for a schema change or a Fleet change.
setup lab "Schema: migrations 00105–00106"
run 2 "lab without backups and a schema change" "$work/t/old" --yes
not_called "the lab refusal runs nothing" '^(docker|script|old [a-z])'
setup lab "Schema: migrations 00105–00106"
run 0 "lab without backups and --skip-backup" "$work/t/old" --yes --skip-backup
has "the plan states that a rollback restores nothing" 'no pre-upgrade backup exists, so a rollback is only \./paddock down and .*/paddock up'
has "the plan states the data loss" 'The pre-upgrade data is lost'
hasnt "no plain rollback line" '^Rollback afterwards: \./paddock rollback'
not_called "the lab takes no backup" '^old backup'
called "the lab runs the online check" '^docker run .*prod-check .*--online'
setup lab "Schema: unchanged"
sed -i 's/^FLEET_IMAGE=.*/FLEET_IMAGE=fleetdm\/fleet:v4.93.2/' "$work/t/old/versions.env"
run 2 "lab without backups and a Fleet change" "$work/t/old" --yes
has "the Fleet refusal names FLEET_IMAGE" 'FLEET_IMAGE changes'
run 0 "lab without backups, a Fleet change and --skip-backup" "$work/t/old" --yes --skip-backup
has "a Fleet change states that a rollback restores nothing" 'no pre-upgrade backup exists'
# A lab host with backups takes the labelled backup like the control plane.
setup lab "Schema: migrations 00105–00106"
echo PADDOCK_LAB_BACKUP=yes >>"$work/t/old/.env"
run 0 "lab with backups" "$work/t/old" --yes
has "a lab with backups names the rollback" '^Rollback afterwards: \./paddock rollback '
before "the lab backup completes before up" "$BACKUP" "$UP"
called "the lab with backups runs the online check" '^docker run .*prod-check .*--online'

# Usage and preconditions.
setup controlplane "Schema: unchanged"
run 2 "no argument"
run 2 "unknown flag" "$work/t/old" --force
run 2 "this directory" "$work/t/new"
touch "$work/t/new/.env"
run 2 "an existing .env without .upgrade-state" "$work/t/old" --yes
rm -f "$work/t/new/.env"
printf 'old=/elsewhere\n' >"$work/t/new/.upgrade-state"
run 2 "a state of another old directory" "$work/t/old" --yes

# build.sh ships the scripts the commands source.
"$here/build.sh" --version 0.1.0-alpha.7 --channel stable --images local --out "$work/b" >/dev/null 2>&1 || true
for s in upgrade.sh rollback.sh legacy-alpha8.sh; do
  if [[ -f "$work/b/paddock-deploy-0.1.0-alpha.7/scripts/$s" ]]; then pass "bundle ships scripts/$s"; else fail "bundle lacks scripts/$s"; fi
done

if ((failures > 0)); then
  echo "upgrade: $failures check(s) failed" >&2
  exit 1
fi
echo "upgrade: all checks passed"
