#!/usr/bin/env bash
# Bootstrap of Fleet (plan M5a decision 1, M7b decision 19): the initial setup with the admin user (secret
# fleet_admin_password), the API-only user paddock with the global role admin, whose API token is written to
# .secrets/fleet_api_token, and the global enroll secret (secret fleet_enroll_secret). Fleet's settings are applied
# and checked by paddock-worker at every start and sync round (plan M5a decision 2). Idempotent: a valid token is
# kept; only a token Fleet rejects with 401 is replaced by a new API-only user. Any other answer (Fleet unreachable,
# 5xx) stops the script without touching the user (PDK-024 review 1).
set -euo pipefail

# fleet_token_action <stored token> <HTTP status of GET /api/latest/fleet/me with it>: create (no token stored yet),
# keep (200), rotate (401) or fail (anything else, including no answer).
fleet_token_action() {
  if [[ -z "$1" ]]; then
    echo create
    return
  fi
  case "$2" in
    200) echo keep ;;
    401) echo rotate ;;
    *) echo fail ;;
  esac
}

# Sourced by the test for fleet_token_action only.
if [[ "${BASH_SOURCE[0]}" != "$0" ]]; then return 0; fi

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
. "$here/lib.sh"

ADMIN_PASSWORD="$(cat "$SECRETS_DIR/fleet_admin_password")"
ENROLL_SECRET="$(cat "$SECRETS_DIR/fleet_enroll_secret")"
TOKEN="$(cat "$SECRETS_DIR/fleet_api_token" 2>/dev/null || true)"
export ADMIN_PASSWORD ENROLL_SECRET TOKEN

# Secrets travel as inherited environment variables, never as command-line arguments; fleetctl reads EMAIL, NAME,
# PASSWORD and ORG_NAME from the environment. fleetctl speaks plain HTTP only to localhost, hence Fleet's network
# namespace.
fleet="$(compose ps -q fleet)"
[[ -n "$fleet" ]] || { echo "fleet is not running" >&2; exit 1; }
fleetctl_sh() {
  docker run --rm -i --network "container:$fleet" -e HOME=/tmp -e ADMIN_PASSWORD -e ENROLL_SECRET -e TOKEN -e ACTION \
    --entrypoint sh "$FLEETCTL_IMAGE" -s
}

fleetctl_sh <<'SCRIPT'
set -eu
admin=admin@paddock-mdm.invalid
fleetctl config set --address http://localhost:8080 >/dev/null
for _ in $(seq 1 60); do
  if fleetctl api /api/latest/fleet/version >/dev/null 2>&1 || fleetctl api /api/v1/setup >/dev/null 2>&1; then break; fi
  sleep 2
done
if EMAIL="$admin" NAME="Paddock administrator" PASSWORD="$ADMIN_PASSWORD" ORG_NAME=Paddock fleetctl setup >/tmp/setup 2>&1; then
  echo "fleet: initial setup done" >&2
elif ! grep -qi "already been set up\|already been setup" /tmp/setup; then
  cat /tmp/setup >&2
  exit 1
fi
SCRIPT

# The exact status of /me decides; bash's /dev/tcp needs no HTTP client in the image, and the token stays in the
# environment.
status=
if [[ -n "$TOKEN" ]]; then
  status="$(docker run --rm -i --network "container:$fleet" -e TOKEN --entrypoint bash "$FLEETCTL_IMAGE" -c '
    exec 3<>/dev/tcp/127.0.0.1/8080 || exit 0
    printf "GET /api/latest/fleet/me HTTP/1.0\r\nHost: localhost\r\nAuthorization: Bearer %s\r\n\r\n" "$TOKEN" >&3
    head -1 <&3 | cut -d" " -f2' || true)"
fi
ACTION="$(fleet_token_action "$TOKEN" "$status")"
export ACTION
case "$ACTION" in
  keep) echo "fleet: API token of the API-only user paddock is valid" ;;
  rotate) echo "fleet: Fleet rejects the stored API token (401); replacing the API-only user paddock" ;;
  fail)
    echo "fleet: checking the stored API token failed (HTTP status '${status:-none}'); nothing changed" >&2
    exit 1
    ;;
esac

out="$(fleetctl_sh <<'SCRIPT'
set -eu
admin=admin@paddock-mdm.invalid
fleetctl config set --address http://localhost:8080 >/dev/null
EMAIL="$admin" PASSWORD="$ADMIN_PASSWORD" fleetctl login >/dev/null
if [ "$ACTION" != keep ]; then
  # Fleet names API-only users admin+<random>@…, so earlier users of Paddock are found by name; their tokens die with
  # them.
  for id in $(fleetctl api /api/latest/fleet/users | awk -F': ' '
      /"id":/ { id = $2; sub(/,$/, "", id) }
      /"name":/ { name = $2 }
      /"api_only": true/ && name == "\"paddock\"," { print id }'); do
    fleetctl api -X DELETE "/api/latest/fleet/users/$id" >/dev/null
    echo "fleet: deleted the API-only user $id with an unknown token" >&2
  done
  created="$(fleetctl user create --api-only --name paddock --global-role admin)"
  token="$(printf '%s\n' "$created" | sed -n 's/.*API token for your new user is: *//p' | tr -d '[:space:]')"
  if [ -z "$token" ]; then
    echo "fleet: no API token in the output of fleetctl user create" >&2
    exit 1
  fi
  echo "fleet: created the API-only user paddock" >&2
  echo "TOKEN=$token"
fi
printf 'apiVersion: v1\nkind: enroll_secret\nspec:\n  secrets:\n    - secret: "%s"\n' "$ENROLL_SECRET" >/tmp/enroll.yml
fleetctl apply -f /tmp/enroll.yml >/dev/null
echo "fleet: global enroll secret applied" >&2
SCRIPT
)"
token="$(printf '%s\n' "$out" | sed -n 's/^TOKEN=//p')"
if [[ -n "$token" ]]; then
  printf '%s' "$token" >"$SECRETS_DIR/fleet_api_token"
  chmod 644 "$SECRETS_DIR/fleet_api_token"
  echo "wrote .secrets/fleet_api_token; restart paddock-worker if it is running"
fi
