#!/usr/bin/env bash
# Regression test of test/stack-preflight.sh (PDK-353, `make test`) against scratch checkouts: a complete checkout and
# one whose .env and .secrets are symlinks to another checkout pass; a missing or dangling .env or .secrets and a
# secrets directory without the seeded password or with the empty, never filled Caddy root certificate fail.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
check="$root/test/stack-preflight.sh"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
failures=0
n=0

# complete <dir>: a checkout's deploy/compose with .env and the checked secrets.
complete() {
  mkdir -p "$1/.secrets"
  printf 'PADDOCK_ENV=development\n' >"$1/.env"
  printf 'x' >"$1/.secrets/dev_alice_password"
  printf 'x' >"$1/.secrets/caddy-root.crt"
}

# expect <description> <want: pass|fail> <text the output must contain> <setup run in a fresh compose dir>
expect() {
  local desc="$1" want="$2" text="$3" setup="$4" dir out rc=0 got
  n=$((n + 1))
  dir="$tmp/$n/deploy/compose"
  mkdir -p "$dir"
  (cd "$dir" && eval "$setup")
  out="$(bash "$check" "$dir" "$dir/.secrets" 2>&1)" || rc=$?
  if ((rc == 0)); then got=pass; else got=fail; fi
  if [[ "$got" == "$want" ]] && grep -qF -- "$text" <<<"$out"; then
    echo "ok   $desc ($got)"
  else
    echo "FAIL $desc: got $got, want $want with '$text'"
    sed 's/^/       /' <<<"$out"
    failures=$((failures + 1))
  fi
}

complete "$tmp/stack"

expect "complete checkout" pass "" 'complete .'
expect "worktree with symlinks to the stack's checkout" pass "" \
  "ln -s '$tmp/stack/.env' .env; ln -s '$tmp/stack/.secrets' .secrets"
expect "no .env" fail "/.env is missing" 'complete .; rm .env'
expect "dangling .env symlink" fail "/.env is missing" \
  "complete .; rm .env; ln -s '$tmp/gone/.env' .env"
expect "no .secrets" fail "/.secrets is missing" 'printf x >.env'
expect "dangling .secrets symlink" fail "/.secrets is missing" \
  "printf x >.env; ln -s '$tmp/gone/.secrets' .secrets"
expect "secrets without the seeded password" fail "dev_alice_password is missing or empty" \
  'complete .; rm .secrets/dev_alice_password'
expect "Caddy root certificate never filled" fail "caddy-root.crt is missing or empty" \
  'complete .; : >.secrets/caddy-root.crt'
expect "nothing set up: .env reported" fail "/.env is missing" ':'
expect "nothing set up: .secrets reported too" fail "/.secrets is missing" ':'
expect "the hint names the setup" fail "make dev-secrets up dev-seed" ':'

if ((failures > 0)); then
  echo "$failures stack-preflight case(s) failed" >&2
  exit 1
fi
