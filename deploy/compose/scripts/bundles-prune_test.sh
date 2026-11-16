#!/usr/bin/env bash
# Tests of bundles-prune.sh (`make test`, PDK-1099): the selection on fixtures, the batching and the audit calls, against
# a fake aws that serves a listing file and a fake compose that records the admin calls.
# shellcheck disable=SC2015
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=bundles-prune.sh
. "$here/bundles-prune.sh"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
failures=0
ok() { echo "ok   $*"; }
fail() {
  echo "FAIL $*"
  failures=$((failures + 1))
}
expect() { # <name> <want> <got>
  if [[ "$2" == "$3" ]]; then ok "$1"; else fail "$1: want [$2], got [$3]"; fi
}

ORG=aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
DA=00000000-0000-0000-0000-00000000000a DB=00000000-0000-0000-0000-00000000000b DC=00000000-0000-0000-0000-00000000000c
OLD=2026-01-01T00:00:00+00:00 NEW=2026-11-16T06:00:00+00:00 CUT=2026-11-16T05:00:00
key() { echo "org/$ORG/devices/$1/bundles/$2.dsse"; }

fixture() {
  local v
  for v in 1 2 3 10 1000004; do printf '%s\t%s\n' "$(key "$DA" "$v")" "$OLD"; done
  for v in 7 8; do printf '%s\t%s\n' "$(key "$DB" "$v")" "$OLD"; done
  printf '%s\t%s\n' "$(key "$DC" 1)" "$NEW" "$(key "$DC" 2)" "$OLD" "$(key "$DC" 3)" "$OLD" "$(key "$DC" 4)" "$OLD"
  printf '%s\t%s\n' "org/$ORG/icons/x.png" "$OLD" "apt/$ORG/pool/p.deb" "$OLD" "$(key "$DA" latest)" "$OLD"
}

sel() { fixture | bundles_prune_select "$1" "$CUT" | LC_ALL=C sort | tr '\n' ' '; }
expect "keep 2: numeric order keeps 10 and 1000004, short device untouched, the recent version stays, foreign keys never" \
  "$(key "$DA" 1) $(key "$DA" 2) $(key "$DA" 3) $(key "$DC" 2) " "$(sel 2)"
expect "keep 3 deletes only A's two oldest" "$(key "$DA" 1) $(key "$DA" 2) " "$(sel 3)"
# A device whose newest version is the only one the listing holds is never selected, even with the smallest keep.
expect "the newest version of a device is never selected" "" "$(printf '%s\t%s\n' "$(key "$DB" 5)" "$OLD" | bundles_prune_select 2 "$CUT")"
newest="$(fixture | bundles_prune_select 2 "$CUT" | grep -c "/$DA/bundles/1000004.dsse" || true)"
expect "keep 2 never selects a device's newest version" 0 "$newest"
expect "an unreadable time keeps the key" "" "$(printf '%s\t%s\n' "$(key "$DA" 1)" "x" "$(key "$DA" 2)" "" "$(key "$DA" 3)" "x" | bundles_prune_select 2 "$CUT")"
# The key test is exact: a dot is a dot, a UUID has 36 characters, nothing else around the pattern.
odd=""
for k in "org/$ORG/devices/$DA/bundles/1xdsse" "org/$ORG/devices/$DA/bundles/1.dsse.bak" "org/$ORG/devices/$DA/bundles/-1.dsse" \
  "org/${ORG}0/devices/$DA/bundles/1.dsse" "org/$ORG/devices/${DA%?}/bundles/1.dsse" "org/${ORG^^}/devices/$DA/bundles/1.dsse" \
  "x/org/$ORG/devices/$DA/bundles/1.dsse" "org/$ORG/devices/$DA/bundles/sub/1.dsse"; do
  odd+="$(printf '%s\t%s\n' "$k" "$OLD")"$'\n'
done
expect "near misses are no bundle keys" "0 0" "$(printf '%s' "$odd" | bundles_prune_stats)"
expect "stats count bundle keys and devices" "11 3" "$(fixture | bundles_prune_stats)"

for bad in "--keep 1" "--keep 0" "--keep x" "--keep 1001" "--keep" "--bogus"; do
  # shellcheck disable=SC2086
  if (bundles_prune_main $bad) >/dev/null 2>"$work/err"; then rc=0; else rc=$?; fi
  expect "$bad: exit 2" 2 "$rc"
  grep -q '^usage:' "$work/err" && ok "$bad: usage on stderr" || fail "$bad: no usage"
done

# The run: SECRETS_DIR holds the credentials, the fake aws serves LISTING and records the delete calls.
SECRETS_DIR="$work/secrets"
mkdir -p "$SECRETS_DIR"
echo u >"$SECRETS_DIR/rustfs_root_user"
echo p >"$SECRETS_DIR/rustfs_root_password"
PADDOCK_PROJECT=t
AWS_CLI_IMAGE=fake
LISTING="$work/listing" calls="$work/calls" adminlog="$work/admin"
aws() {
  case "$2" in
    list-objects-v2) cat "$LISTING" ;;
    delete-objects)
      local body n
      body="$(cat)"
      n="$(grep -o '"Key"' <<<"$body" | wc -l)"
      echo "delete $n" >>"$calls"
      if [[ -n "${FAKE_AWS_DIES_AT:-}" && "$(grep -c '^delete' "$calls")" == "$FAKE_AWS_DIES_AT" ]]; then return 255; fi
      if [[ -n "${FAKE_ERRORS_AT:-}" && "$(grep -c '^delete' "$calls")" == "$FAKE_ERRORS_AT" ]]; then
        printf '{"Errors":[\n'
        grep -o '"Key":"[^"]*"' <<<"$body" | sed 's/^/ {/;s/$/,"Code":"InternalError"}/'
        printf ']}\n'
      fi
      ;;
  esac
}
compose() {
  echo "$*" >>"$adminlog"
  [[ -z "${FAKE_CHECK_FAILS:-}" || "$*" != *--check* ]] || return 1
  [[ -z "${FAKE_RECORD_FAILS:-}" || "$*" == *--check* ]] || return 1
}
reset() { : >"$calls"; : >"$adminlog"; }
# main runs in a subshell with errexit on, as ./paddock runs it, with its own work directory.
run() {
  local w
  w="$(mktemp -d -p "$work")"
  set +e
  (
    set -e
    BUNDLES_PRUNE_WORK="$w"
    bundles_prune_main "$@"
  ) >"$work/out" 2>"$work/err"
  rc=$?
  set -e
}

# One device with 2 503 versions selects 2 501 keys at keep 2.
big=00000000-0000-0000-0000-0000000000ee
for v in $(seq 1 2503); do printf '%s\t%s\n' "$(key "$big" "$v")" "$OLD"; done >"$LISTING"
printf '%s\t%s\n' "$(key "$DB" 7)" "$OLD" "$(key "$DB" 8)" "$OLD" >>"$LISTING"

reset
run
expect "dry run: exit 0" 0 "$rc"
expect "dry run: the would-delete line" \
  "would delete 2501 of 2505 bundle objects of 2 devices (keeping the newest 2 per device)" "$(cat "$work/out")"
expect "dry run: no delete call" 0 "$(wc -l <"$calls")"
expect "dry run: no admin call at all" 0 "$(wc -l <"$adminlog")"

reset
run --yes
expect "--yes: exit 0" 0 "$rc"
expect "--yes: three batches of 1000, 1000 and 501" "delete 1000 delete 1000 delete 501 " "$(tr '\n' ' ' <"$calls")"
expect "--yes: the printed line" "deleted 2501 of 2505 bundle objects of 2 devices" "$(cat "$work/out")"
expect "--yes: --check precedes the first delete and one record follows" \
  "--profile paddock run --rm --no-deps -T paddock-worker admin record-bundle-prune --check|--profile paddock run --rm --no-deps -T paddock-worker admin record-bundle-prune --keep 2 --listed 2505 --devices 2 --selected 2501 --deleted 2501 --failed 0" \
  "$(paste -sd'|' "$adminlog")"
if grep -qE 'rustfs_root|AWS_SECRET' "$work/out" "$work/err" "$adminlog"; then fail "a credential name leaked"; else ok "no credential in the output"; fi

reset
FAKE_ERRORS_AT=2 run --yes
expect "errors in batch 2: exit 1" 1 "$rc"
expect "errors in batch 2: no third batch" "delete 1000 delete 1000 " "$(tr '\n' ' ' <"$calls")"
expect "errors in batch 2: stderr names deleted and failed" "deleted 1000 of 2505 bundle objects of 2 devices; 1000 keys failed" "$(cat "$work/err")"
expect "errors in batch 2: one record with failed 1000" 1 "$(grep -c 'record-bundle-prune --keep 2 --listed 2505 --devices 2 --selected 2501 --deleted 1000 --failed 1000' "$adminlog")"
expect "errors in batch 2: exactly one record" 1 "$(grep -c -- '--failed' "$adminlog")"

reset
FAKE_AWS_DIES_AT=2 run --yes
expect "aws dies in batch 2: exit 1" 1 "$rc"
expect "aws dies in batch 2: no third batch" "delete 1000 delete 1000 " "$(tr '\n' ' ' <"$calls")"
expect "aws dies in batch 2: stderr names deleted and failed" "deleted 1000 of 2505 bundle objects of 2 devices; 1000 keys failed" "$(cat "$work/err")"
expect "aws dies in batch 2: one record with the counts" 1 "$(grep -c -- 'record-bundle-prune --keep 2 --listed 2505 --devices 2 --selected 2501 --deleted 1000 --failed 1000' "$adminlog")"

reset
FAKE_CHECK_FAILS=1 run --yes
expect "failing --check: exit 1" 1 "$rc"
expect "failing --check: nothing deleted" 0 "$(wc -l <"$calls")"
expect "failing --check: message" "the audit log cannot be written; nothing was deleted" "$(cat "$work/err")"

reset
FAKE_RECORD_FAILS=1 run --yes
expect "failing record: exit 1" 1 "$rc"
expect "failing record: counts on stdout" "deleted 2501 of 2505 bundle objects of 2 devices" "$(cat "$work/out")"
grep -q 'the audit event could not be recorded' "$work/err" && ok "failing record: message and counts on stderr" || fail "failing record: no message"

# Nothing to delete: a confirmed run is still on record, with deleted 0.
printf '%s\t%s\n' "$(key "$DB" 7)" "$OLD" "$(key "$DB" 8)" "$OLD" >"$LISTING"
reset
run --yes
expect "selected 0: exit 0" 0 "$rc"
expect "selected 0: no delete call" 0 "$(wc -l <"$calls")"
expect "selected 0: one record with deleted 0" 1 "$(grep -c -- '--selected 0 --deleted 0 --failed 0' "$adminlog")"

if ((failures)); then
  echo "$failures failures"
  exit 1
fi
echo "bundles-prune: all tests passed"
