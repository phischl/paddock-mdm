#!/usr/bin/env bash
# Tests of restore-drill-guard.sh (`make test`): the drill runs only in a development checkout.
set -euo pipefail

guard="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/restore-drill-guard.sh"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
failures=0

# expect <0|1> <name> <setup> [config files]...: runs setup in a fresh compose dir, then the guard.
expect() {
  local want="$1" name="$2" setup="$3" dir got
  shift 3
  dir="$(mktemp -d -p "$work")"
  (cd "$dir" && eval "$setup")
  if PADDOCK_ENV=development bash "$guard" "$dir" "$@" >/dev/null 2>&1; then got=0; else got=1; fi
  if [[ "$got" == "$want" ]]; then
    echo "ok   $name"
  else
    echo "FAIL $name: exit $got, want $want"
    failures=$((failures + 1))
  fi
}

expect 0 "development checkout" 'printf "PADDOCK_ENV=development\n" >.env' \
  /x/compose.yaml /x/compose.audit.yaml /x/compose.dev.yaml
expect 1 "production .env, PADDOCK_ENV=development in the process environment" 'printf "PADDOCK_ENV=production\n" >.env'
expect 1 "no .env" ':'
expect 1 "PADDOCK_ENV missing in .env" 'printf "PADDOCK_DOMAIN=x\n" >.env'
expect 0 "quoted development" "printf 'PADDOCK_ENV=\"development\"\n' >.env"
expect 1 "last PADDOCK_ENV wins" 'printf "PADDOCK_ENV=development\nPADDOCK_ENV=production\n" >.env'
expect 1 "production release keys" 'printf "PADDOCK_ENV=development\n" >.env; mkdir -p .secrets/release-production'
expect 1 "internal CA key" 'printf "PADDOCK_ENV=development\n" >.env; mkdir -p .secrets/internal-ca; : >.secrets/internal-ca/ca.key'
expect 1 "running stack with compose.prod.yaml" 'printf "PADDOCK_ENV=development\n" >.env' \
  /x/compose.yaml /x/compose.prod.yaml /x/compose.backup.yaml
expect 1 "running stack with compose.audit.prod.yaml" 'printf "PADDOCK_ENV=development\n" >.env' \
  /x/compose.audit.yaml /x/compose.audit.prod.yaml

if ((failures > 0)); then
  echo "restore-drill-guard: $failures failure(s)"
  exit 1
fi
echo "restore-drill-guard: all cases passed"
