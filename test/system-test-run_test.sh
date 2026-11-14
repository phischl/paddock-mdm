#!/usr/bin/env bash
# Regression test of test/system-test-run.sh (PDK-962): `go test` is stubbed by a script that prints a canned -json stream
# for the -run regex it receives. Checks the suite selection, the T/SUITE exclusion, SUITE=all (every suite runs, also
# after a failed one, with a summary and a non-zero exit), the zero-test guard and the raw JSON file.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
failures=0

cat >"$work/suites.txt" <<'SUITES'
# comment
alpha|1h|^(TestA)$
beta|2h|^(TestB)$
SUITES

# Stub: TestA passes, TestB fails (exit 1), anything else matches no test. It echoes its arguments as a log line.
cat >"$work/gotest.sh" <<'STUB'
#!/usr/bin/env bash
args="$*"
run=""
while (($#)); do [[ "$1" == "-run" ]] && run="$2"; shift; done
emit() { printf '{"Action":"run","Test":"%s"}\n{"Action":"output","Test":"%s","Output":"=== RUN   %s\\n"}\n{"Action":"output","Test":"%s","Output":"--- %s: %s (0.00s)\\n"}\n' "$1" "$1" "$1" "$1" "$2" "$1"; }
case "$run" in
  '^(TestA)$') emit TestA PASS ;;
  '^(TestB)$') emit TestB FAIL; echo "args: $args" >&2; exit 1 ;;
  TestOnly) emit TestOnly PASS ;;
  '') emit TestA PASS; emit TestB PASS ;;
  *) printf '{"Action":"output","Output":"testing: warning: no tests to run\\n"}\n' ;;
esac
STUB
chmod +x "$work/gotest.sh"
(cd "$root" && CGO_ENABLED=0 go build -o "$work/testlive" ./test/system/cmd/testlive)

# expect <description> <want rc> <text the output must contain> <suite> <t>
expect() {
  local desc="$1" want="$2" text="$3" out rc=0
  out="$(cd "$root" && SUITES_FILE="$work/suites.txt" GO_TEST="$work/gotest.sh" TESTLIVE="$work/testlive" SYSTEM_TEST_OUT="$work/out" bash test/system-test-run.sh "$4" "$5" 2>&1)" || rc=$?
  if [[ "$rc" == "$want" ]] && grep -qF -- "$text" <<<"$out"; then
    echo "ok   $desc (rc $rc)"
  else
    echo "FAIL $desc: rc $rc, want $want with '$text'"
    while IFS= read -r line; do echo "       $line"; done <<<"$out"
    failures=$((failures + 1))
  fi
}

expect "one suite streams its tests" 0 "--- PASS: TestA" alpha ""
expect "a failing suite fails the run" 1 "--- FAIL: TestB" beta ""
expect "unknown suite" 1 "unknown SUITE" nope ""
expect "T and SUITE exclude each other" 1 "mutually exclusive" alpha TestA
expect "T runs the regex" 0 "--- PASS: TestOnly" "" TestOnly
expect "T matching nothing fails" 1 "no test ran" "" Nothing
expect "no filter runs everything" 0 "--- PASS: TestB" "" ""
expect "SUITE=all continues after a failure" 1 "--- PASS: TestA" all ""
expect "SUITE=all prints the summary" 1 "beta         FAIL" all ""
expect "SUITE=all summary lists passed suites" 1 "alpha        PASS" all ""

if ! ls "$work"/out/alpha-*.json >/dev/null 2>&1; then
  echo "FAIL raw JSON of suite alpha not written"
  failures=$((failures + 1))
fi

((failures == 0)) || { echo "$failures failure(s)"; exit 1; }
echo "all ok"
