#!/usr/bin/env bash
# Guard of the restore drill (restore-drill.sh), which deletes the databases' and OpenBao's volumes of the Compose
# project paddock, the same project a production host runs:
#   restore-drill-guard.sh <compose dir> [Compose file of the running stack]...
# Exits 0 only for a development checkout: PADDOCK_ENV=development in <compose dir>/.env (the process environment does
# not count, so `PADDOCK_ENV=development make restore-drill` cannot pass on a production host), no production secrets
# (.secrets/release-production/, .secrets/internal-ca/ca.key) and no production overlay among the running stack's files.
# load-guard.sh reuses it for the load test; GUARD_ACTION names the refused action in the message.
set -euo pipefail

dir="${1:?usage: restore-drill-guard.sh <compose dir> [compose file]...}"
shift

refuse() {
  echo "refusing ${GUARD_ACTION:-the restore drill}: $*" >&2
  exit 1
}

[[ -f "$dir/.env" ]] || refuse "no $dir/.env"
env="$( (grep -E '^PADDOCK_ENV=' "$dir/.env" || true) | tail -1 | cut -d= -f2- | tr -d "\"' \r")"
[[ "$env" == development ]] || refuse "PADDOCK_ENV in $dir/.env is '${env:-unset}', not development"
for marker in .secrets/release-production .secrets/internal-ca/ca.key; do
  [[ ! -e "$dir/$marker" ]] || refuse "$dir/$marker exists (production secrets)"
done
for f in "$@"; do
  case "$(basename "$f")" in
    compose.prod.yaml | compose.audit.prod.yaml) refuse "the running stack uses $(basename "$f")" ;;
  esac
done
