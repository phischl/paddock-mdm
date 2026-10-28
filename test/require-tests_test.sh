#!/usr/bin/env bash
# Regression test of test/require-tests.sh (PDK-339, `make test`) against canned `go test -v` output: a run whose
# filter matched nothing fails (single and several packages), a run with at least one started test passes, also when
# that test was skipped or failed (the failure itself is go test's exit code), and the output passes through unchanged.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
check="$root/test/require-tests.sh"
failures=0

# expect <description> <want: pass|fail> <text the output must contain> <canned go test output>
expect() {
  local desc="$1" want="$2" text="$3" input="$4" out rc=0 got
  out="$(printf '%s\n' "$input" | bash "$check" 2>&1)" || rc=$?
  if ((rc == 0)); then got=pass; else got=fail; fi
  if [[ "$got" == "$want" ]] && grep -qF -- "$text" <<<"$out"; then
    echo "ok   $desc ($got)"
  else
    echo "FAIL $desc: got $got, want $want with '$text'"
    sed 's/^/       /' <<<"$out"
    failures=$((failures + 1))
  fi
}

expect "filter matched nothing" fail "no test ran" "testing: warning: no tests to run
PASS
ok  	github.com/phischl/paddock-mdm/test/system	0.012s [no tests to run]"

expect "several packages, none matched" fail "no test ran" "?   	github.com/phischl/paddock-mdm/test/acceptance/cmd/devicesim	[no test files]
testing: warning: no tests to run
PASS
ok  	github.com/phischl/paddock-mdm/test/acceptance	0.020s [no tests to run]"

expect "empty output" fail "no test ran" ""

expect "a mention of === RUN inside a log line does not count" fail "no test ran" "    stack.go:12: printed === RUN TestX
ok  	github.com/phischl/paddock-mdm/test/system	0.012s [no tests to run]"

expect "one test passed" pass "--- PASS: TestDiskGates" "=== RUN   TestDiskGates
--- PASS: TestDiskGates (1.00s)
PASS
ok  	github.com/phischl/paddock-mdm/test/system	1.012s"

expect "one subtest selected" pass "=== RUN   TestIdentityGates/paddock-u2604/L1_login" "=== RUN   TestIdentityGates
=== RUN   TestIdentityGates/paddock-u2604/L1_login
--- PASS: TestIdentityGates (2.00s)"

expect "a skipped test still ran" pass "--- SKIP: TestX" "=== RUN   TestX
    x_test.go:9: no VM
--- SKIP: TestX (0.00s)"

expect "a failed test ran (go test reports the failure)" pass "--- FAIL: TestX" "=== RUN   TestX
--- FAIL: TestX (0.00s)
FAIL"

if ((failures > 0)); then
  echo "$failures check(s) failed" >&2
  exit 1
fi
echo "all require-tests checks passed"
