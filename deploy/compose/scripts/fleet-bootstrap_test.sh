#!/usr/bin/env bash
# Tests of the token decision of fleet-bootstrap.sh (`make test`, PDK-024 review 1): only a stored token that Fleet
# rejects with 401 replaces the API-only user; no answer or any other status fails without a change.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=fleet-bootstrap.sh
. "$here/fleet-bootstrap.sh"
failures=0

expect() {
  local got
  got="$(fleet_token_action "$2" "$3")"
  if [[ "$got" == "$1" ]]; then echo "ok   $4 -> $got"; else
    echo "FAIL $4: got $got, want $1"
    failures=$((failures + 1))
  fi
}

expect create "" "" "no token stored yet"
expect create "" 401 "no token stored, status ignored"
expect keep token 200 "valid token"
expect rotate token 401 "token rejected with 401"
expect fail token "" "Fleet unreachable (no status)"
expect fail token 500 "server error"
expect fail token 502 "bad gateway"
expect fail token 503 "Fleet starting"
expect fail token 403 "forbidden"
expect fail token 404 "unexpected not found"

if ((failures > 0)); then
  echo "fleet-bootstrap: $failures failure(s)"
  exit 1
fi
echo "fleet-bootstrap: all checks passed"
