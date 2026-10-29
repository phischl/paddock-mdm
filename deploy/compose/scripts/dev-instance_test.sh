#!/usr/bin/env bash
# Tests of PADDOCK_INSTANCE in gen-dev-secrets.sh and lib.sh (`make test`): a second development stack gets its own
# project, image tags and ports, the first stack's .env stays a copy of .env.example, and a command for another
# instance is refused (docs/operations/local-dev.md, "Running a second dev stack").
set -euo pipefail

src="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
failures=0

check() {
  if [[ "$2" == "$3" ]]; then
    echo "ok   $1"
  else
    echo "FAIL $1: got '$2', want '$3'"
    failures=$((failures + 1))
  fi
}

# checkout <name>: a copy of deploy/compose without .env and .secrets.
checkout() {
  local dir="$work/$1"
  mkdir -p "$dir"
  tar -C "$src" --exclude=./.env --exclude=./.secrets -cf - . | tar -C "$dir" -xf -
  printf '%s' "$dir"
}

setting() { sed -n "s/^$2=//p" "$1/.env" | tail -1; }

first="$(checkout first)"
(unset PADDOCK_INSTANCE; bash "$first/scripts/gen-dev-secrets.sh" >/dev/null)
check "instance 1: .env is .env.example" "$(cmp -s "$first/.env" "$first/.env.example" && echo same)" same

second="$(checkout second)"
PADDOCK_INSTANCE=2 bash "$second/scripts/gen-dev-secrets.sh" >/dev/null
check "instance 2: project" "$(setting "$second" PADDOCK_PROJECT)" paddock2
check "instance 2: image" "$(setting "$second" PADDOCK_IMAGE)" paddock-server:dev-2
check "instance 2: HTTPS port in place" "$(grep -c '^PADDOCK_HTTPS_PORT=' "$second/.env"):$(setting "$second" PADDOCK_HTTPS_PORT)" 1:8543
check "instance 2: admin URL" "$(setting "$second" PADDOCK_PUBLIC_ADMIN_URL)" https://admin.paddock.localhost:8543
check "instance 2: untrusted port" "$(setting "$second" PADDOCK_HTTPS_UNTRUSTED_PORT)" 8544
check "instance 2: PostgreSQL port" "$(setting "$second" PADDOCK_DEV_POSTGRES_PORT)" 5532
check "instance 2: RabbitMQ management port" "$(setting "$second" PADDOCK_DEV_RABBITMQ_MANAGEMENT_PORT)" 15772
check "instance 2: Prometheus port" "$(setting "$second" PADDOCK_DEV_PROMETHEUS_PORT)" 9191
check "instance 2: own secrets" "$(cmp -s "$first/.secrets/postgres_superuser_password" \
  "$second/.secrets/postgres_superuser_password" && echo shared || echo own)" own

before="$(cat "$second/.env")"
PADDOCK_INSTANCE=2 bash "$second/scripts/gen-dev-secrets.sh" >/dev/null
check "instance 2: rerun keeps .env" "$(cat "$second/.env")" "$before"

refused() { if "$@" >/dev/null 2>&1; then echo ran; else echo refused; fi; }
check "instance 2 in the first checkout refused" "$(PADDOCK_INSTANCE=2 refused bash "$first/scripts/gen-dev-secrets.sh")" refused
check "instance 1 in the second checkout refused" "$(PADDOCK_INSTANCE=1 refused bash -c ". '$second/scripts/lib.sh'")" refused
check "lib.sh: project of the second checkout" "$(unset PADDOCK_PROJECT PADDOCK_INSTANCE; bash -c ". '$second/scripts/lib.sh' && echo \$PADDOCK_PROJECT")" paddock2
repo="$(cd "$src/../.." && pwd)"
check "make: another instance refused" "$(PADDOCK_INSTANCE=9 refused make -s -n -C "$repo" down)" refused
check "make: no instance runs" "$(unset PADDOCK_INSTANCE; refused make -s -n -C "$repo" down)" ran
check "invalid instance refused" "$(PADDOCK_INSTANCE=x refused bash "$(checkout third)/scripts/gen-dev-secrets.sh")" refused

if ((failures > 0)); then
  echo "dev-instance: $failures failure(s)"
  exit 1
fi
echo "dev-instance: all cases passed"
