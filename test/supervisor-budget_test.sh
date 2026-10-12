#!/usr/bin/env bash
# Regression test of test/supervisor-budget.sh (PDK-062, `make test`): the supervisor as it is passes; a copy of it
# padded to 801 counted lines fails with the count (mutation proof of the ceiling), at exactly 800 it passes; blank
# lines, // and /* */ comments and _test.go files do not count, code after a closing */ does; directories without Go
# files fail.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
check="$root/test/supervisor-budget.sh"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
failures=0

# expect <description> <want: pass|fail> <text the output must contain> <directory>...
expect() {
  local desc="$1" want="$2" text="$3" out rc=0 got
  shift 3
  out="$(bash "$check" "$@" 2>&1)" || rc=$?
  if ((rc == 0)); then got=pass; else got=fail; fi
  if [[ "$got" == "$want" ]] && grep -qF -- "$text" <<<"$out"; then
    echo "ok   $desc ($got)"
  else
    echo "FAIL $desc: got $got, want $want with '$text'"
    sed 's/^/       /' <<<"$out"
    failures=$((failures + 1))
  fi
}

# counted <directory>...: the count the check reports for a tree within the ceiling.
counted() { bash "$check" "$@" | sed -E 's/^supervisor line budget: ([0-9]+) of.*/\1/'; }

# pad <file> <n>: appends n counted lines.
pad() { for ((i = 0; i < $2; i++)); do echo "var _ = $i"; done >>"$1"; }

expect "the supervisor as it is" pass "of 800 counted lines in"

cp -r "$root/agent/internal/supervisor" "$work/supervisor"
cp -r "$root/agent/cmd/paddock-supervisor" "$work/cmd"
real="$(counted "$work/supervisor" "$work/cmd")"
pad "$work/supervisor/probation.go" $((800 - real))
expect "the supervisor padded to 800 lines" pass "800 of 800 counted lines" "$work/supervisor" "$work/cmd"
pad "$work/cmd/main.go" 1
expect "the supervisor padded to 801 lines" fail "exceeded: 801 counted lines in 4 files, ceiling 800" "$work/supervisor" "$work/cmd"

mkdir "$work/synthetic"
{
  echo "package x"
  echo
  echo "    // an indented comment"
  echo "/* a one-line block comment */"
  echo "/*"
  echo "var notCode = 1"
  echo "*/"
  echo "/* opens"
  echo "   closes */ var afterBlock = 2"
  printf '\t\n'
  echo "var code = 3 // trailing comment"
} >"$work/synthetic/x.go"
pad "$work/synthetic/x_test.go" 900
expect "comments, blanks and tests do not count" pass "3 of 800 counted lines in 1 files" "$work/synthetic"

mkdir "$work/empty"
echo "not go" >"$work/empty/README"
expect "no Go files" fail "no Go files found" "$work/empty"

if ((failures > 0)); then
  echo "$failures check(s) failed" >&2
  exit 1
fi
echo "all supervisor budget checks passed"
