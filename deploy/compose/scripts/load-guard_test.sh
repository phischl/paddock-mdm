#!/usr/bin/env bash
# Tests of load-guard.sh (`make test`): the load test runs only against a development stack.
set -euo pipefail

guard="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/load-guard.sh"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
failures=0

# expect <0|1> <name> <setup> <gateway PADDOCK_ENV> [config files]...: runs setup in a fresh compose dir, then the guard.
expect() {
  local want="$1" name="$2" setup="$3" gateway_env="$4" dir got
  shift 4
  dir="$(mktemp -d -p "$work")"
  (cd "$dir" && eval "$setup")
  if bash "$guard" "$dir" "$gateway_env" "$@" >/dev/null 2>&1; then got=0; else got=1; fi
  if [[ "$got" == "$want" ]]; then
    echo "ok   $name"
  else
    echo "FAIL $name: exit $got, want $want"
    failures=$((failures + 1))
  fi
}

dev='printf "PADDOCK_ENV=development\n" >.env'
expect 0 "development stack" "$dev" development /x/compose.yaml /x/compose.dev.yaml
expect 1 "production gateway" "$dev" production /x/compose.yaml /x/compose.dev.yaml
expect 1 "no running gateway" "$dev" ""
expect 1 "production .env" 'printf "PADDOCK_ENV=production\n" >.env' development
expect 1 "production release keys" "$dev; mkdir -p .secrets/release-production" development
expect 1 "running stack with compose.prod.yaml" "$dev" development /x/compose.yaml /x/compose.prod.yaml

if ((failures > 0)); then
  echo "load-guard: $failures failure(s)"
  exit 1
fi
echo "load-guard: all cases passed"
