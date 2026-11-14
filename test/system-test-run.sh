#!/usr/bin/env bash
# Test run of `make system-test` (PDK-962, plan M19 D4): usage `system-test-run.sh <SUITE|""> <T|"">`.
# Streams `go test -json` through test/system/cmd/testlive (live per-test output, zero-test guard, raw JSON in
# bin/system-test/), runs one suite of test/system/suites.txt, all of them one after another (SUITE=all, each with its
# own timeout, continuing after a failed suite, summary table at the end), or a T regex (no SUITE) or everything.
# PADDOCK_SYSTEM_VMS comes from the caller; SUITES_FILE and GO_TEST override the defaults for the test of this script.
set -euo pipefail

suite="${1:-}" t="${2:-}"
suites_file="${SUITES_FILE:-test/system/suites.txt}"
go_test="${GO_TEST:-go test}"
outdir="${SYSTEM_TEST_OUT:-bin/system-test}"

if [[ -n "$suite" && -n "$t" ]]; then
  echo "system-test: T and SUITE are mutually exclusive" >&2
  exit 1
fi

mkdir -p "$outdir"
live="$outdir/testlive"
if [[ -z "${TESTLIVE:-}" ]]; then
  CGO_ENABLED=0 go build -o "$live" ./test/system/cmd/testlive
else
  live="$TESTLIVE"
fi

# run_one <label> <timeout> <regex or empty>
run_one() {
  local label="$1" timeout="$2" regex="$3" raw rc=0
  raw="$outdir/$label-$(date -u +%Y%m%dT%H%M%SZ).json"
  echo "system-test: $label (timeout $timeout), raw JSON in $raw"
  # shellcheck disable=SC2086
  $go_test -json -count=1 -timeout "$timeout" ${regex:+-run "$regex"} ./test/system/ 2>&1 | "$live" -raw "$raw" || rc=$?
  return "$rc"
}

if [[ "$suite" != "all" ]]; then
  timeout="8h" regex="$t"
  label="${t:+targeted}"
  label="${label:-all}"
  if [[ -n "$suite" ]]; then
    line="$(awk -F'|' -v s="$suite" '$0 !~ /^#/ && $1 == s' "$suites_file")"
    [[ -n "$line" ]] || { echo "system-test: unknown SUITE '$suite' (see $suites_file)" >&2; exit 1; }
    IFS='|' read -r label timeout regex <<<"$line"
  fi
  run_one "$label" "$timeout" "$regex"
  exit $?
fi

failed=0
summary=()
while IFS='|' read -r name timeout regex; do
  [[ -z "$name" || "$name" == \#* ]] && continue
  start=$SECONDS rc=0
  run_one "$name" "$timeout" "$regex" || rc=$?
  status=PASS
  if ((rc != 0)); then status=FAIL; failed=1; fi
  summary+=("$(printf '%-12s %-5s %5ds' "$name" "$status" $((SECONDS - start)))")
done <"$suites_file"

echo
echo "system-test summary"
printf '%s\n' "${summary[@]}"
exit "$failed"
