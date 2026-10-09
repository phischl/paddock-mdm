#!/usr/bin/env bash
# Guard of `make load-identities` and `make load-test` (PDK-006 review 1), which talk to the gateway on the Compose
# network paddock_cp, the same network a production control plane runs:
#   load-guard.sh <compose dir> <PADDOCK_ENV of the running gateway> [Compose file of the running stack]...
# Exits 0 only when a gateway runs, its PADDOCK_ENV is not production, and restore-drill-guard.sh accepts the checkout
# as a development one (development .env, no production secrets, no production overlay). An ingest run writes WORM
# audit objects nobody can delete, so the load test never runs against production.
set -euo pipefail

dir="${1:?usage: load-guard.sh <compose dir> <gateway PADDOCK_ENV> [compose file]...}"
gateway_env="${2-}"
shift 2 || true

refuse() {
  echo "refusing the load test: $*" >&2
  exit 1
}

[[ -n "$gateway_env" ]] || refuse "no running paddock-gateway (or it has no PADDOCK_ENV)"
[[ "$gateway_env" != production ]] || refuse "the running paddock-gateway has PADDOCK_ENV=production"
GUARD_ACTION="the load test" exec "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/restore-drill-guard.sh" "$dir" "$@"
