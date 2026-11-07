#!/usr/bin/env bash
# Tests of ./paddock rollback (PDK-743, `make bundle-test`): the decision by the Schema: line, the restore of the
# pre-upgrade set through the OLD release's restore.sh (a fake here, which logs what it is asked; restore_test.sh tests
# the real one), the Fleet dump on a changed FLEET_IMAGE, the key choice before anything stops, and the order down →
# restore → old up. docker is a stub on PATH, the old bundle's ./paddock a fake; both log to one file.
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
# The running stack: `ps -q` lists one container, `inspect` its vendor and version labels (FIXTURE_RUNNING, one line
# per container; empty: nothing runs).
cat >"$work/bin/docker" <<'STUB'
#!/usr/bin/env bash
echo "docker $*" >>"$FIXTURE_CALLS"
case "$1 $*" in
  "compose "*" ps -q") [[ -z "$FIXTURE_RUNNING" ]] || sed 's/.*/c/' <<<"$FIXTURE_RUNNING" ;;
  "compose "*" exec -T postgres psql "*"max(bundle_seq)"*) [[ -n "${FIXTURE_STACK_MAX:-}" ]] && echo "$FIXTURE_STACK_MAX" ;;
  inspect*) printf '%s\n' "$FIXTURE_RUNNING" ;;
esac
exit 0
STUB
chmod +x "$work/bin/docker"
export PATH="$work/bin:$PATH" FIXTURE_CALLS="$calls" FIXTURE_RUNNING="Paddock|0.1.0-alpha.10"

cat >"$work/old-paddock" <<'FAKE'
#!/usr/bin/env bash
echo "old $*" >>"$FIXTURE_CALLS"
[[ "${1:-}" != up ]] || exit "${FIXTURE_OLD_UP_EXIT:-0}"
FAKE
chmod +x "$work/old-paddock"

# The old release's restore.sh as far as ./paddock rollback uses it.
cat >"$work/old-restore.sh" <<'FAKE'
# shellcheck shell=bash
RESTORE_KEY_PATH=restore/backup_key
restore_die() { echo "restore: $1" >&2; exit "${2:-1}"; }
# As the real one: a second call while the restore's trap is set returns 1.
restore_trap_set() {
  [[ -z "${FAKE_TRAP:-}" ]] || return 1
  FAKE_TRAP=1
}
restore_trap_reset() { FAKE_TRAP=""; }
restore_set_opts() { echo "restore_set_opts source=$RESTORE_SOURCE dir=$COMPOSE_DIR" >>"$FIXTURE_CALLS"; }
restore_read_set() {
  declare -gA RESTORE_SET=([key_fingerprint]="$FIXTURE_SET_FP" [key_id]=bk-20261101-0a0b0c0d)
  echo "restore_read_set at=$RESTORE_AT" >>"$FIXTURE_CALLS"
}
restore_key_fingerprint() {
  local n
  n="$(base64 -d <"$1" 2>/dev/null | wc -c)" || return 1
  [[ "$n" == 32 ]] || return 1
  base64 -d <"$1" | sha256sum | cut -c1-16
}
restore_prompt_key() {
  local key=""
  IFS= read -r key || true
  mkdir -p "$(dirname "$1")"
  printf '%s\n' "$key" >"$1"
  RESTORE_KEY_WRITTEN="$1"
}
restore_normalize_at() { [[ "$1" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:]{8}Z$ ]] && echo "$1"; }
restore_preflight() {
  echo "restore_preflight at=$RESTORE_AT only=${RESTORE_ONLY[*]} key=${RESTORE_KEY_FILE#"$COMPOSE_DIR"/}" >>"$FIXTURE_CALLS"
  [[ -z "${FIXTURE_PREFLIGHT_FAIL:-}" ]] || restore_die "the backup set's paddock schema is version 106, this bundle knows up to 104"
}
restore_confirm() {
  local answer=""
  IFS= read -r answer || true
  echo "restore_confirm source=$RESTORE_SOURCE_LABEL answer=$answer" >>"$FIXTURE_CALLS"
  [[ "$answer" == restore ]] || restore_die "not confirmed; nothing was changed"
}
restore_flush_wal() { echo "restore_flush_wal only=${RESTORE_ONLY[*]}" >>"$FIXTURE_CALLS"; }
restore_stop_writers() { echo "restore_stop_writers" >>"$FIXTURE_CALLS"; }
restore_run() {
  local confirm=""
  IFS= read -r confirm || true
  restore_trap_set || true
  echo "restore_run $* key=${RESTORE_KEY_FILE#"$COMPOSE_DIR"/} confirm=$confirm" >>"$FIXTURE_CALLS"
  echo "restore_high_water=${RESTORE_HIGH_WATER:-}" >>"$FIXTURE_CALLS"
  [[ "${FIXTURE_RESTORE_EXIT_EARLY:-0}" == 0 ]] || exit "$FIXTURE_RESTORE_EXIT_EARLY"
  restore_stop_writers
  [[ "${FIXTURE_RESTORE_EXIT:-0}" == 0 ]] || exit "$FIXTURE_RESTORE_EXIT"
}
restore_cleanup() {
  [[ -z "${RESTORE_KEY_WRITTEN:-}" ]] || rm -f "$RESTORE_KEY_WRITTEN"
  RESTORE_KEY_WRITTEN=""
}
FAKE

AT=2026-11-06T10:00:00Z
ATTEMPT=0123456789abcdef
# setup <host> <schema line>: an upgraded new directory (alpha.10) and the old one (alpha.9) under $work/t.
setup() {
  local host="$1" schema="$2" s
  rm -rf "$work/t"
  mkdir -p "$work/t/new/scripts" "$work/t/old/scripts" "$work/t/old/.secrets"
  cp -a "$fixtures/new/." "$work/t/new/"
  cp "$here/paddock" "$work/t/new/paddock"
  for s in lib.sh upgrade-check.sh upgrade.sh rollback.sh legacy-alpha8.sh openbao-restore.sh bundle-seq.sh; do cp "$scripts/$s" "$work/t/new/scripts/$s"; done
  sed -i 's/^version=.*/version=0.1.0-alpha.10/' "$work/t/new/VERSION"
  printf '%s\n' "$schema" >"$work/t/new/RELEASE-NOTES"
  echo "FLEET_IMAGE=fleetdm/fleet:v4.94.0" >>"$work/t/new/versions.env"
  cp "$fixtures/old/VERSION" "$work/t/old/VERSION"
  sed -i 's/^version=.*/version=0.1.0-alpha.9/' "$work/t/old/VERSION"
  cp "$work/old-paddock" "$work/t/old/paddock"
  cp "$scripts/lib.sh" "$work/t/old/scripts/lib.sh"
  cp "$work/old-restore.sh" "$work/t/old/scripts/restore.sh"
  cp "$work/t/new/versions.env" "$work/t/old/versions.env"
  sed "s/^PADDOCK_HOST=.*/PADDOCK_HOST=$host/" "$fixtures/old/.env" >"$work/t/old/.env"
  cp "$work/t/old/.env" "$work/t/new/.env"
  head -c 32 /dev/urandom | base64 >"$work/t/old/.secrets/backup_encryption_key"
  chmod 600 "$work/t/old/.secrets/backup_encryption_key"
  FIXTURE_SET_FP="$(base64 -d <"$work/t/old/.secrets/backup_encryption_key" | sha256sum | cut -c1-16)"
  export FIXTURE_SET_FP
  printf 'old=%s\nfrom=0.1.0-alpha.9\nto=0.1.0-alpha.10\nbackup=yes\nlabel=pre-upgrade-0.1.0-alpha.10\nat=%s\nattempt=%s\n' \
    "$work/t/old" "$AT" "$ATTEMPT" >"$work/t/new/.upgrade-rollback"
  : >"$calls"
}

input=""
run() {
  local want="$1" name="$2" got=0
  shift 2
  out="$(cd "$work/t/new" && ./paddock rollback "$@" <<<"$input" 2>&1)" || got=$?
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
line_of() { grep -nE -- "$1" "$calls" | head -n 1 | cut -d: -f1 || echo 0; }
before() {
  local a b
  a="$(line_of "$2")" b="$(line_of "$3")"
  if [[ -n "$a" && -n "$b" && "$a" -gt 0 && "$b" -gt 0 && "$a" -lt "$b" ]]; then pass "$1"; else
    fail "$1: '$2' (line ${a:-0}) is not before '$3' (line ${b:-0})"
    cat "$calls" >&2
  fi
}
DOWN='^docker compose .*/t/new/.* down$'
OLDUP='^old up$'

# Schema: migrations: the key is checked, then down, the restore through the old release's restore.sh, old up.
setup controlplane "Schema: migrations 00105–00106 (control-plane database); audit unchanged"
run 0 "rollback after a schema change" "$work/t/old" --yes
called "the set is read from the local repository with the old directory's libraries" "^restore_set_opts source=repo dir=$work/t/old$"
called "the set is read at the rollback point" "^restore_read_set at=$AT$"
before "the WAL is flushed before down" '^restore_flush_wal only=postgres openbao escrow$' "$DOWN"
before "down before the restore" "$DOWN" '^restore_run '
called "the restore takes the components without Fleet and the legacy key" \
  "^restore_run fresh repo --at $AT --only postgres --only openbao --only escrow key=.secrets/backup_encryption_key confirm=restore$"
before "the restore before the old up" '^restore_run ' "$OLDUP"
has "the loss is stated" "Every change after $AT is lost"
has "the set is named" 'pre-upgrade-0.1.0-alpha.10'
if [[ -f "$work/t/old/.secrets/backup_encryption_key" ]]; then pass "the legacy key file stays"; else fail "the legacy key file was deleted"; fi
if grep -qx "rolled-back=$ATTEMPT" "$work/t/new/.upgrade-state" && ! grep -q '^done=' "$work/t/new/.upgrade-state"; then
  pass "a later upgrade starts again at the check and copies .env and .secrets/ again"
else fail ".upgrade-state: $(cat "$work/t/new/.upgrade-state" 2>&1)"; fi

# The bundle sequence (decisions-alpha9 item 68): the highest is read and recorded before down with this release's
# libraries and handed to the old restore.sh, which runs after down.
setup controlplane "Schema: migrations 00105–00106"
FIXTURE_STACK_MAX=1000003 run 0 "rollback with a readable stack" "$work/t/old" --yes
before "the highest is read before down" '^docker compose .* exec -T postgres psql .*max\(bundle_seq\)' "$DOWN"
# The record script spans several lines of the log: its first names the container, its last the value.
before "the high-water file is written through postgres before down" '^docker compose .* exec -T -u postgres postgres sh -c set -eu$' "$DOWN"
before "the highest is recorded before down" ' bundle-seq /paddock-bundle-seq 1000003$' "$DOWN"
called "the old restore.sh receives the highest" '^restore_high_water=1000003$'
setup controlplane "Schema: migrations 00105–00106"
mkdir -p "$work/t/new/bundle-seq" && echo 1500000 >"$work/t/new/bundle-seq/high-water"
run 0 "rollback with a stopped stack" "$work/t/old" --yes
called "a stopped stack hands over the high-water file's value" '^restore_high_water=1500000$'
setup controlplane "Schema: migrations 00105–00106"
run 0 "rollback without a source" "$work/t/old" --yes
called "without a source the old restore.sh decides" '^restore_high_water=$'
has "the missing source is warned about" 'warning: bundle sequence: neither the running stack nor'

# A changed FLEET_IMAGE adds Fleet's dump.
setup controlplane "Schema: migrations 00105–00106"
sed -i 's/^FLEET_IMAGE=.*/FLEET_IMAGE=fleetdm\/fleet:v4.93.2/' "$work/t/old/versions.env"
run 0 "rollback with a Fleet change" "$work/t/old" --yes
called "Fleet's dump is restored" '^restore_run fresh repo --at .* --only postgres --only openbao --only fleet --only escrow '

# The installation runs on a portal key: the operator enters it before anything stops; it is deleted afterwards.
setup controlplane "Schema: migrations 00105–00106"
portal="$(head -c 32 /dev/urandom | base64)"
FIXTURE_SET_FP="$(base64 -d <<<"$portal" | sha256sum | cut -c1-16)"
input="$portal" run 0 "rollback with an entered key" "$work/t/old" --yes
called "the entered key is used" '^restore_run .* key=.secrets/restore/backup_key confirm=restore$'
if [[ ! -e "$work/t/old/.secrets/restore/backup_key" ]]; then pass "the entered key is deleted"; else fail "the entered key file stays"; fi
setup controlplane "Schema: migrations 00105–00106"
FIXTURE_SET_FP=0123456789abcdef input="$(head -c 32 /dev/urandom | base64)" run 1 "a wrong key is refused" "$work/t/old" --yes
not_called "a wrong key stops before down" "$DOWN"
has "a wrong key changes nothing" 'stopped before any change'

# Without --yes: the rollback asks for yes, the restore for its own word.
setup controlplane "Schema: migrations 00105–00106"
input=no run 1 "not confirmed" "$work/t/old"
not_called "no down without yes" "$DOWN"
setup controlplane "Schema: migrations 00105–00106"
input=$'yes\nrestore' run 0 "confirmed interactively" "$work/t/old"
called "the restore gets the operator's word" '^restore_run .* confirm=restore$'

# A failed restore: the new stack stays down, the old one is not started; the message tells whether volumes changed.
setup controlplane "Schema: migrations 00105–00106"
FIXTURE_RESTORE_EXIT=3 run 3 "failed restore" "$work/t/old" --yes
not_called "no old up after a failed restore" "$OLDUP"
has "a failure after the writers stopped names the partly restored volumes" \
  'failed while it replaced the data.*partly restored volumes; do not start 0.1.0-alpha.10 on them'
if [[ -f "$work/t/new/.upgrade-rollback" ]]; then pass "a failed restore keeps the rollback point"; else fail "a failed restore retired the record"; fi
run 0 "a failed restore can be run again" "$work/t/old" --yes
setup controlplane "Schema: migrations 00105–00106"
FIXTURE_RESTORE_EXIT_EARLY=3 run 3 "restore fails before any volume changed" "$work/t/old" --yes
has "an early failure says the volumes are untouched" 'before it changed any volume.*is down; its volumes are untouched'
has "an early failure offers the new release's up" 'or start 0.1.0-alpha.10 again with ./paddock up'

# Every precondition of the restore and its confirmation come before down (Agent design contract 8).
setup controlplane "Schema: migrations 00105–00106"
FIXTURE_PREFLIGHT_FAIL=1 run 1 "a failed restore preflight" "$work/t/old" --yes
not_called "a failed preflight stops before down" "$DOWN"
has "a failed preflight changes nothing" 'stopped before any change'
setup controlplane "Schema: migrations 00105–00106"
run 0 "the preflight runs with the rollback's settings" "$work/t/old" --yes
called "the preflight gets the point, the components and the key" \
  "^restore_preflight at=$AT only=postgres openbao escrow key=.secrets/backup_encryption_key$"
before "the preflight before down" '^restore_preflight ' "$DOWN"
not_called "--yes answers the restore question" '^restore_confirm '
setup controlplane "Schema: migrations 00105–00106"
input=$'yes\nno' run 1 "the restore question is not confirmed" "$work/t/old"
not_called "no down without the restore word" "$DOWN"
setup controlplane "Schema: migrations 00105–00106"
input=$'yes\nrestore' run 0 "the restore question before down" "$work/t/old"
before "the restore question before down" '^restore_confirm source=the local backup repository answer=restore$' "$DOWN"

# The rollback point holds for its upgrade attempt only: a second rollback, or one after a later attempt, is refused.
setup controlplane "Schema: migrations 00105–00106"
run 0 "the first rollback" "$work/t/old" --yes
if [[ ! -e "$work/t/new/.upgrade-rollback" && -f "$work/t/new/.upgrade-rollback.rolled-back-$ATTEMPT" ]]; then
  pass "a successful rollback retires the record"
else fail "the record was not retired: $(ls -a "$work/t/new")"; fi
: >"$calls"
run 1 "a second rollback is refused" "$work/t/old" --yes
not_called "a second rollback stops before down" "$DOWN"
not_called "a second rollback restores nothing" '^restore_'
has "the refusal says it was rolled back" 'was rolled back already'
setup controlplane "Schema: unchanged"
run 0 "the first rollback without a schema change" "$work/t/old" --yes
: >"$calls"
run 1 "a second rollback without a schema change is refused" "$work/t/old" --yes
not_called "it stops before down" "$DOWN"
setup controlplane "Schema: migrations 00105–00106"
printf 'old=%s\ndone=migrate-from\ndone=upgrade-check\n' "$work/t/old" >"$work/t/new/.upgrade-state"
run 1 "a later attempt that did not reach up does not reuse the record" "$work/t/old" --yes
not_called "the stale record stops before down" "$DOWN"
has "the refusal names the stale record" 'is stale \(it belongs to the upgrade attempt 0123456789abcdef'
setup controlplane "Schema: migrations 00105–00106"
printf 'old=%s\ndone=migrate-from\nattempt=fedcba9876543210\nup-started=%s\n' "$work/t/old" "$AT" >"$work/t/new/.upgrade-state"
run 1 "a record of another attempt is refused" "$work/t/old" --yes
not_called "another attempt's record stops before down" "$DOWN"
setup controlplane "Schema: migrations 00105–00106"
printf 'old=%s\ndone=migrate-from\nattempt=%s\nup-started=%s\n' "$work/t/old" "$ATTEMPT" "$AT" >"$work/t/new/.upgrade-state"
run 0 "the record of the unfinished attempt in .upgrade-state is used" "$work/t/old" --yes
called "it restores that attempt's point" "^restore_run fresh repo --at $AT "
setup controlplane "Schema: migrations 00105–00106"
sed -i 's/^to=.*/to=0.1.0-alpha.11/' "$work/t/new/.upgrade-rollback"
run 1 "a record of other versions is refused" "$work/t/old" --yes
not_called "other versions stop before down" "$DOWN"
setup controlplane "Schema: migrations 00105–00106"
sed -i '/^attempt=/d' "$work/t/new/.upgrade-rollback"
run 1 "a record without an attempt is refused" "$work/t/old" --yes
not_called "no attempt stops before down" "$DOWN"

# A→B→C (R2-M1): the upgrade from this directory (alpha.10) to alpha.11 completed, so alpha.11 runs. The record of
# alpha.9→alpha.10 is intact here, so only the check of the running version refuses.
setup controlplane "Schema: migrations 00105–00106"
FIXTURE_RUNNING="Paddock|0.1.0-alpha.11" run 1 "a rollback while a later release runs is refused" "$work/t/old" --yes
not_called "it stops before down" "$DOWN"
not_called "it restores nothing" '^restore_'
has "the refusal names the running release" 'running stack is not 0.1.0-alpha.10.*running: 0.1.0-alpha.11'
setup controlplane "Schema: unchanged"
FIXTURE_RUNNING="Paddock|0.1.0-alpha.11" run 1 "also without a schema change" "$work/t/old" --yes
not_called "it stops before down without a schema change" "$DOWN"
setup controlplane "Schema: migrations 00105–00106"
FIXTURE_RUNNING="" run 1 "a rollback while nothing runs is refused" "$work/t/old" --yes
not_called "nothing runs: it stops before down" "$DOWN"
setup controlplane "Schema: migrations 00105–00106"
FIXTURE_RUNNING="|" run 1 "images without the version label are refused" "$work/t/old" --yes
has "the version cannot be determined" 'running: no container of a versioned Paddock image'
setup controlplane "Schema: migrations 00105–00106"
FIXTURE_RUNNING="Paddock|0.1.0-alpha.10"$'\n'"Paddock|" run 1 "a container without a version is refused" "$work/t/old" --yes
has "the container without a version is named" 'running: \(no version label\) 0.1.0-alpha.10|running: 0.1.0-alpha.10 \(no version label\)'
setup controlplane "Schema: migrations 00105–00106"
FIXTURE_RUNNING="Paddock|0.1.0-alpha.9" run 1 "the old release running after a completed upgrade is refused" "$work/t/old" --yes
setup controlplane "Schema: migrations 00105–00106"
FIXTURE_RUNNING="Paddock|0.1.0-alpha.10"$'\n'"|17.2" run 0 "third-party containers do not count" "$work/t/old" --yes
# A failed `up` of the unfinished attempt may leave the old release running, or nothing.
setup controlplane "Schema: migrations 00105–00106"
printf 'old=%s\nattempt=%s\nup-started=%s\n' "$work/t/old" "$ATTEMPT" "$AT" >"$work/t/new/.upgrade-state"
FIXTURE_RUNNING="Paddock|0.1.0-alpha.9"$'\n'"Paddock|0.1.0-alpha.10" run 0 "after a failed up the old release may run" "$work/t/old" --yes
setup controlplane "Schema: migrations 00105–00106"
printf 'old=%s\nattempt=%s\nup-started=%s\n' "$work/t/old" "$ATTEMPT" "$AT" >"$work/t/new/.upgrade-state"
FIXTURE_RUNNING="Paddock|0.1.0-alpha.11" run 1 "after a failed up a third release is refused" "$work/t/old" --yes
# A run after a failed rollback finds the stack down: the record notes that this rollback took it down.
setup controlplane "Schema: migrations 00105–00106"
FIXTURE_RESTORE_EXIT=3 run 3 "a rollback that fails in the restore" "$work/t/old" --yes
if grep -q '^rollback-started=' "$work/t/new/.upgrade-rollback"; then pass "the record notes the started rollback"; else
  fail "no rollback-started= in the record"
fi
FIXTURE_RUNNING="" run 0 "its re-run with the stack down" "$work/t/old" --yes
setup controlplane "Schema: migrations 00105–00106"
FIXTURE_PREFLIGHT_FAIL=1 run 1 "a rollback that stops before down" "$work/t/old" --yes
if grep -q '^rollback-started=' "$work/t/new/.upgrade-rollback"; then fail "rollback-started= before down"; else
  pass "no rollback-started= when nothing stopped"
fi

# The rollback point was superseded by an upgrade from this directory (upgrade.sh renames it).
setup controlplane "Schema: unchanged"
mv "$work/t/new/.upgrade-rollback" "$work/t/new/.upgrade-rollback.superseded-by-0.1.0-alpha.11"
run 1 "a superseded rollback point is refused" "$work/t/old" --yes
not_called "a superseded point stops before down" "$DOWN"
has "the refusal names the later release" 'superseded by the upgrade to 0.1.0-alpha.11'

# Schema: unchanged: down and old up only, unless Fleet's image changed.
setup controlplane "Schema: unchanged"
run 0 "rollback without a schema change" "$work/t/old" --yes
before "down before the old up" "$DOWN" "$OLDUP"
not_called "no restore without a schema change" '^restore_'
setup controlplane "Schema: unchanged"
sed -i 's/^FLEET_IMAGE=.*/FLEET_IMAGE=fleetdm\/fleet:v4.93.2/' "$work/t/old/versions.env"
run 0 "rollback of a Fleet change only" "$work/t/old" --yes
called "only Fleet's dump is restored" "^restore_run fresh repo --at $AT --only fleet key="

# The audit host: down and old up, also after audit migrations (additive within a guaranteed pair).
setup audit "Schema: migrations 00105 (control-plane database); audit migrations 00011"
run 0 "rollback of the audit host" "$work/t/old" --yes
not_called "the audit host restores nothing" '^restore_'
called "the audit host starts the old release" "$OLDUP"
setup audit "Schema: migrations 00105 (control-plane database); audit migrations 00011"
FIXTURE_OLD_UP_EXIT=1 run 1 "a failed old up after down and up only" "$work/t/old" --yes
has "nothing restored: the data is the new release's" "nothing was restored, the data is the one 0.1.0-alpha.10 left"
hasnt "no claim of the pre-upgrade state" 'the data is the pre-upgrade state'
setup controlplane "Schema: migrations 00105–00106"
FIXTURE_OLD_UP_EXIT=1 run 1 "a failed old up after a restore" "$work/t/old" --yes
has "restored: the data is the pre-upgrade state" 'the data is the pre-upgrade state'

# Preconditions: nothing stops when the restore cannot run.
setup controlplane "Schema: migrations 00105–00106"
rm "$work/t/new/.upgrade-rollback"
run 1 "no recorded rollback point" "$work/t/old" --yes
not_called "nothing stops without a rollback point" "$DOWN"
setup controlplane "Schema: migrations 00105–00106"
sed -i 's/^backup=.*/backup=no/' "$work/t/new/.upgrade-rollback"
run 1 "an upgrade without backup cannot restore" "$work/t/old" --yes
setup controlplane "Schema: migrations 00105–00106"
rm "$work/t/old/scripts/restore.sh"
run 1 "an old release without restore.sh" "$work/t/old" --yes
not_called "nothing stops without restore.sh" "$DOWN"
setup controlplane "Schema: migrations 00105–00106"
mkdir -p "$work/t/other"
cp -a "$work/t/old/." "$work/t/other/"
run 2 "another old directory than the upgrade's" "$work/t/other" --yes
run 2 "no argument"
run 2 "unknown flag" "$work/t/old" --force
run 2 "this directory" "$work/t/new"

# The rollback to 0.1.0-alpha.8 (decisions-alpha9 items 46 and 49): that release's restore procedure through its own
# ./paddock compose, every precondition before down. The fake alpha.8 ./paddock answers what the procedure asks;
# openbao-restore.sh is a fake as well (openbao-restore_test.sh tests the real one).
cat >"$work/alpha8-paddock" <<'FAKE'
#!/usr/bin/env bash
printf 'old %s\n' "${*//$'\n'/ }" >>"$FIXTURE_CALLS"
case "${1:-}" in
  up) exit "${FIXTURE_OLD_UP_EXIT:-0}" ;;
  compose)
    case "$*" in
      *" pgbackrest info") echo "        full backup: ${FIXTURE_NEWEST-20261106-100000F}" ;;
      *" pgbackrest-authentik info") echo "        full backup: 20261106-100100F" ;;
      *" la8-s3 get "*)
        [[ -z "${FIXTURE_S3_GET_FAIL:-}" ]] || exit 1
        echo "sealed object"
        ;;
      *" backup decrypt /in /dev/null") exit "${FIXTURE_DECRYPT_EXIT:-0}" ;;
      *" backup decrypt /in -") echo "plain snapshot" ;;
      *" la8-fleet check") exit "${FIXTURE_FLEET_CHECK_EXIT:-0}" ;;
      *" exec -T openbao sh -c cat >/tmp/snapshot") cat >/dev/null ;;
      *" psql "*"pg_is_in_recovery()"*) echo f ;;
      *" psql "*"min(bundle_seq)"*) echo "${FIXTURE_LA8_MIN:-2}" ;;
      *" ps --format "*) echo healthy ;;
      *" pgbackrest restore") exit "${FIXTURE_PG_RESTORE_EXIT:-0}" ;;
    esac
    ;;
esac
exit 0
FAKE
cat >"$work/fake-openbao-restore.sh" <<'FAKE'
# shellcheck shell=bash
openbao_status() { printf '{"initialized": %s, "sealed": false}\n' "${FAKE_BAO_INITIALIZED:-${FIXTURE_BAO_INITIALIZED:-false}}"; }
openbao_wait() { echo "openbao_wait" >>"$FIXTURE_CALLS"; }
openbao_restore_sealed() {
  echo "openbao_restore_sealed bao=$(declare -F bao) restart=$(declare -F bao_restart)" >>"$FIXTURE_CALLS"
  echo "temporary root token" >"$1/init.json"
  FAKE_BAO_INITIALIZED=true
}
FAKE
# setup_alpha8 [fleet]: the new directory is 0.1.0-alpha.9, upgraded from an alpha.8 directory by its own backup.
setup_alpha8() {
  setup controlplane "Schema: migrations 00100–00106"
  sed -i 's/^version=.*/version=0.1.0-alpha.9/' "$work/t/new/VERSION"
  sed -i 's/^version=.*/version=0.1.0-alpha.8/' "$work/t/old/VERSION"
  cp "$work/alpha8-paddock" "$work/t/old/paddock"
  echo "PADDOCK_AUTO_UNSEAL=yes" >>"$work/t/old/.env"
  rm "$work/t/old/scripts/restore.sh"
  cp "$work/fake-openbao-restore.sh" "$work/t/new/scripts/openbao-restore.sh"
  [[ "${1:-}" != fleet ]] || sed -i 's/^FLEET_IMAGE=.*/FLEET_IMAGE=fleetdm\/fleet:v4.93.2/' "$work/t/old/versions.env"
  head -c 24 /dev/urandom | base64 >"$work/t/old/.secrets/backup_pgbackrest_access_key"
  head -c 24 /dev/urandom | base64 >"$work/t/old/.secrets/backup_pgbackrest_secret_key"
  printf 'old=%s\nfrom=0.1.0-alpha.8\nto=0.1.0-alpha.9\nbackup=yes\nlabel=pre-upgrade-0.1.0-alpha.9\nat=%s\nattempt=%s\n' \
    "$work/t/old" "$AT" "$ATTEMPT" >"$work/t/new/.upgrade-rollback"
  printf 'method=legacy-0.1.0-alpha.8\nlegacy-paddock=20261106-100000F\nlegacy-authentik=20261106-100100F\n' >>"$work/t/new/.upgrade-rollback"
  printf 'legacy-openbao=openbao/20261106T095900Z.snap.enc\nlegacy-fleet=fleet/20261106T095930Z.sql.gz.enc\nlegacy-at=2026-11-06T09:59:40Z\n' \
    >>"$work/t/new/.upgrade-rollback"
  export FIXTURE_RUNNING="Paddock|0.1.0-alpha.9"
}
VOLRM='^docker volume rm '
setup_alpha8
run 0 "rollback to 0.1.0-alpha.8 by its restore procedure" "$work/t/old" --yes
has "the plan names alpha.8's restore procedure" "0\.1\.0-alpha\.8's restore procedure"
has "the plan names the loss from the backup on" 'Every change after the pre-upgrade backup \(2026-11-06T09:59:40Z\) can be lost'
has "the plan names the custodians" 'unsealed by three custodians or the automatic unseal'
has "the plan names the fence as the archive's end" 'reaches the WAL 0\.1\.0-alpha\.8 archived until the upgrade stopped its pgBackRest right before \./paddock up'
not_called "no restore.sh function" '^restore_'
before "the newest paddock backup is checked before down" '^old compose run --rm --no-deps -T pgbackrest info$' "$DOWN"
before "the newest authentik backup is checked before down" '^old compose run --rm --no-deps -T pgbackrest-authentik info$' "$DOWN"
before "the snapshot is downloaded before down" '^old compose run .* la8-s3 get openbao/20261106T095900Z\.snap\.enc$' "$DOWN"
before "the snapshot decrypts before down" '^old compose run .* paddock-worker backup decrypt /in /dev/null$' "$DOWN"
before "down before the first volume goes" "$DOWN" "$VOLRM"
before "the volumes go before the pgBackRest restore" "${VOLRM}.*_postgres-data$" '^old compose run --rm --no-deps -T pgbackrest restore$'
before "paddock's stanza, then authentik's" '^old compose run --rm --no-deps -T pgbackrest restore$' '^old compose run --rm --no-deps -T pgbackrest-authentik restore$'
before "the databases start after the restore" '^old compose run --rm --no-deps -T pgbackrest-authentik restore$' '^old compose up -d --no-deps postgres authentik-postgres$'
before "OpenBao after PostgreSQL" '^old compose up -d --no-deps postgres authentik-postgres$' "${VOLRM}.*_openbao-data$"
before "the fresh OpenBao starts before its restore" '^old compose up -d --no-deps openbao$' '^openbao_restore_sealed'
called "openbao-restore.sh runs with alpha.8's bao" '^openbao_restore_sealed bao=bao restart=bao_restart$'
before "the snapshot reaches OpenBao before its restore" '^old compose exec -T openbao sh -c cat >/tmp/snapshot$' '^openbao_restore_sealed'
before "OpenBao before the restore commands" '^openbao_restore_sealed' '^old compose run --rm --no-deps -T paddock-worker admin bump-bundle-seq --by 1000000$'
before "the compiler stops before bump-bundle-seq" '^old compose --profile paddock stop paddock-compiler$' 'admin bump-bundle-seq'
before "bump-bundle-seq before the compiler starts" 'admin bump-bundle-seq' '^old compose --profile paddock up -d --no-deps paddock-compiler$'
before "the compiler before rebuild-cache" '^old compose --profile paddock up -d --no-deps paddock-compiler$' 'admin rebuild-cache$'
before "rebuild-cache before recompile" 'admin rebuild-cache$' 'admin recompile --all$'
before "pgBackRest starts after the restore commands" 'admin recompile --all$' '^old compose up -d --no-deps pgbackrest pgbackrest-authentik$'
before "alpha.8 starts last" '^old compose up -d --no-deps pgbackrest pgbackrest-authentik$' "$OLDUP"
called "the automatic unseal starts" '^old compose --profile paddock up -d --no-deps paddock-unsealer$'
deleted="$(grep -E "$VOLRM" "$calls" | sed -E 's/.*_//' | sort | paste -sd' ' -)"
if [[ "$deleted" == "authentik-postgres-data openbao-data pgbackrest-spool-authentik pgbackrest-spool-paddock pgbackrest-state-authentik pgbackrest-state-paddock postgres-data" ]]; then
  pass "exactly the volumes of decisions-alpha9 item 49 are deleted"
else fail "deleted volumes: $deleted"; fi
not_called "no Compose down with volumes" 'down (-v|--volumes)'
not_called "Fleet is untouched when its image stays" 'fleet-mysql|la8-fleet'
if compgen -G "$work/t/new/.rollback-legacy.*" >/dev/null; then fail "the work directory is left"; else pass "the work directory is removed"; fi
if [[ -f "$work/t/new/.upgrade-rollback.rolled-back-$ATTEMPT" ]]; then pass "the alpha.8 record is retired"; else fail "the alpha.8 record is not retired"; fi
for f in backup_pgbackrest_access_key backup_pgbackrest_secret_key backup_encryption_key; do
  if grep -qF -- "$(cat "$work/t/old/.secrets/$f")" "$calls" <<<"$out" || grep -qF -- "$(cat "$work/t/old/.secrets/$f")" <<<"$out"; then
    fail "$f appears in a command or the output"
  else pass "$f appears in no command and no output"; fi
done

# The case of the upgrade job (#488): a restore on alpha.9 after the upgrade raised the sequences to 1000003, which the
# device applied; alpha.8's restore brings back 2. The raise puts the device above 1000003 without a compile.
setup_alpha8
FIXTURE_STACK_MAX=1000003 FIXTURE_LA8_MIN=2 run 0 "rollback to alpha.8 after a restore on alpha.9" "$work/t/old" --yes
before "the highest is read before down" '^docker compose .* exec -T postgres psql .*max\(bundle_seq\)' "$DOWN"
called "the lowest is read from alpha.8's restored database" '^old compose exec -T postgres psql -U postgres -d paddock -Atc select coalesce\(min\(bundle_seq\), 0\) from device$'
called "alpha.8 raises to the highest + 1,000,000" '^old compose run --rm --no-deps -T paddock-worker admin bump-bundle-seq --by 2000001$'
before "the compiler stops before the raise" '^old compose --profile paddock stop paddock-compiler$' 'admin bump-bundle-seq --by 2000001$'
if ((2 + 2000001 > 1000003)); then pass "the device's next bundle (2000003) is newer than the one it applied (1000003)"; else fail "arithmetic"; fi

# A changed FLEET_IMAGE: the dump is downloaded and checked before down, Fleet's database replaced, its volume kept.
setup_alpha8 fleet
run 0 "rollback to alpha.8 with Fleet's dump" "$work/t/old" --yes
before "the dump is downloaded before down" '^old compose run .* la8-s3 get fleet/20261106T095930Z\.sql\.gz\.enc$' "$DOWN"
before "the dump decrypts before down" ' la8-fleet check$' "$DOWN"
before "OpenBao before Fleet" '^openbao_restore_sealed' '^old compose up -d --no-deps fleet-mysql$'
before "fleet-mysql runs before the load" '^old compose up -d --no-deps fleet-mysql$' ' la8-fleet load$'
before "Fleet before the restore commands" ' la8-fleet load$' 'admin bump-bundle-seq'
not_called "fleet-mysql's volume is kept" "${VOLRM}.*fleet"
has "the plan names Fleet's dump" "Fleet's database from fleet/20261106T095930Z\.sql\.gz\.enc"

# Without the automatic unseal: the custodians are asked.
setup_alpha8
sed -i '/^PADDOCK_AUTO_UNSEAL=/d' "$work/t/old/.env"
run 0 "rollback to alpha.8 with custodians" "$work/t/old" --yes
has "the custodians are asked" 'Three custodians unseal it now'
not_called "no unsealer without the automatic unseal" 'paddock-unsealer'

# Every precondition fails before anything stops.
setup_alpha8
FIXTURE_NEWEST=20261106-120000F run 1 "a newer backup in alpha.8's stanza" "$work/t/old" --yes
has "the newer backup is named" 'newest backup of pgbackrest in the bucket is 20261106-120000F, not the pre-upgrade backup 20261106-100000F'
not_called "nothing stops when the newest backup is another" "$DOWN"
has "the stack still runs" 'stopped before any change'
setup_alpha8
FIXTURE_S3_GET_FAIL=1 run 1 "the snapshot cannot be downloaded" "$work/t/old" --yes
has "the download failure is named" 'cannot download openbao/20261106T095900Z\.snap\.enc'
not_called "nothing stops without the snapshot" "$DOWN"
setup_alpha8
FIXTURE_DECRYPT_EXIT=1 run 1 "the snapshot does not decrypt" "$work/t/old" --yes
has "the decryption failure is named" 'the OpenBao snapshot does not decrypt'
not_called "nothing stops with a wrong key" "$DOWN"
setup_alpha8 fleet
FIXTURE_FLEET_CHECK_EXIT=1 run 1 "Fleet's dump does not decrypt" "$work/t/old" --yes
not_called "nothing stops with a broken dump" "$DOWN"
setup_alpha8
rm "$work/t/old/.secrets/backup_pgbackrest_secret_key"
run 1 "alpha.8's pgBackRest credential is missing" "$work/t/old" --yes
has "the missing file is named" 'backup_pgbackrest_secret_key is missing or empty'
not_called "nothing stops without the credential" "$DOWN"
if compgen -G "$work/t/new/.rollback-legacy.*" >/dev/null; then fail "a failed preflight leaves the work directory"; else pass "a failed preflight removes the work directory"; fi
# Both directories must name the project whose volumes go (Review 1, m1): checked before anything stops.
setup_alpha8
echo "PADDOCK_PROJECT=paddock-old" >>"$work/t/old/.env"
run 1 "the old directory names another Compose project" "$work/t/old" --yes
has "the differing projects are named" 'names the project paddock-old, this directory.s \.env paddock'
not_called "nothing stops with differing projects" "$DOWN"
not_called "no volume goes with differing projects" "$VOLRM"
setup_alpha8
echo "PADDOCK_PROJECT=paddock" >>"$work/t/old/.env"
run 0 "the old directory names the default project explicitly" "$work/t/old" --yes
called "the restore runs when the projects match" '^old compose run --rm --no-deps -T pgbackrest restore$'
setup_alpha8
echo "PADDOCK_PROJECT=paddock-old" >>"$work/t/old/.env"
echo "PADDOCK_PROJECT=paddock-old" >>"$work/t/new/.env"
run 0 "both directories name the same project" "$work/t/old" --yes
called "the volumes of the named project go" "${VOLRM}paddock-old_postgres-data$"
setup_alpha8
sed -i '/^legacy-/d; /^method=/d' "$work/t/new/.upgrade-rollback"
run 1 "a record without alpha.8's backup" "$work/t/old" --yes
has "the record's problem is named" "cannot be restored by 0\.1\.0-alpha\.8's procedure \(it records no backup of 0\.1\.0-alpha\.8's own procedure\)"
not_called "nothing runs without alpha.8's backup in the record" '^(old compose|docker compose .* down$)'
setup_alpha8
sed -i 's/^legacy-openbao=.*/legacy-openbao=openbao\/..\/x/' "$work/t/new/.upgrade-rollback"
run 1 "an invalid snapshot name in the record" "$work/t/old" --yes
not_called "nothing runs with an invalid name" '^old compose'

# Failures after down: the message tells the host's state; an initialized OpenBao is never initialized again.
setup_alpha8
FIXTURE_PG_RESTORE_EXIT=1 run 1 "alpha.8's pgBackRest restore fails" "$work/t/old" --yes
has "the partial restore is named" 'the restore failed while it replaced the data'
not_called "alpha.8 is not started on a partial restore" "$OLDUP"
setup_alpha8
FIXTURE_BAO_INITIALIZED=true run 1 "the fresh OpenBao reports initialized" "$work/t/old" --yes
has "the refusal to initialize is named" 'it is not initialized again'
not_called "no second initialization" '^openbao_restore_sealed'
# A repeated rollback after that failure finds the stack down and restores again.
FIXTURE_RUNNING="" run 0 "the repeated rollback to alpha.8" "$work/t/old" --yes
called "the repeated rollback restores OpenBao" '^openbao_restore_sealed'

# The old release's restore.sh is an interface between releases: the real one defines every function rollback.sh
# calls and reads every variable it sets.
contract="$(cd "$scripts/.." && bash -c '. scripts/lib.sh && . scripts/restore.sh && declare -F' 2>&1)" || true
while read -r f; do
  if grep -qx "declare -f $f" <<<"$contract"; then pass "restore.sh defines $f"; else fail "restore.sh lacks $f, which rollback.sh calls"; fi
done < <(grep -oE '\brestore_[a-z_]+' "$scripts/rollback.sh" | sort -u)
while read -r v; do
  if grep -qw -- "$v" "$scripts/restore.sh"; then pass "restore.sh uses $v"; else fail "restore.sh has no $v, which rollback.sh sets"; fi
done < <(grep -oE '\bRESTORE_[A-Z_]+' "$scripts/rollback.sh" | sort -u)
run_body="$(sed -n '/^restore_run() {/,/^}/p' "$scripts/restore.sh")"
# shellcheck disable=SC2016 # the literal restore_$c of restore_run's component loop
if [[ "$(grep -n 'restore_stop_writers' <<<"$run_body" | head -n 1 | cut -d: -f1)" -lt \
  "$(grep -nE 'restore_\$c|restore_backup_repo$|restore_paddock$' <<<"$run_body" | head -n 1 | cut -d: -f1)" ]]; then
  pass "restore_run stops the writers before it replaces any volume"
else fail "restore_run replaces volumes before restore_stop_writers"; fi
if grep -q 'restore_preflight' <<<"$run_body" && grep -q 'restore_confirm' <<<"$run_body"; then
  pass "restore_run asks its preflight and its question (answered by the rollback)"
else fail "restore_run lacks restore_preflight or restore_confirm"; fi

if ((failures > 0)); then
  echo "rollback: $failures check(s) failed" >&2
  exit 1
fi
echo "rollback: all checks passed"
