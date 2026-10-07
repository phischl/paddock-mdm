#!/usr/bin/env bash
# Development bootstrap of Fleet (plan M5a decision 1): the initial setup with the admin user (secret
# fleet_admin_password), the API-only user paddock with the global role admin, whose API token is written to
# .secrets/fleet_api_token, and the global enroll secret (secret fleet_enroll_secret). Fleet's settings are applied
# and checked by paddock-worker at every start and sync round (plan M5a decision 2). Idempotent: a valid token is
# kept; an invalid or missing one is replaced by a new API-only user.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
. "$here/lib.sh"

require_development

ADMIN_PASSWORD="$(cat "$SECRETS_DIR/fleet_admin_password")"
ENROLL_SECRET="$(cat "$SECRETS_DIR/fleet_enroll_secret")"
TOKEN="$(cat "$SECRETS_DIR/fleet_api_token" 2>/dev/null || true)"
export ADMIN_PASSWORD ENROLL_SECRET TOKEN

# Secrets travel as inherited environment variables, never as command-line arguments; fleetctl reads EMAIL, NAME,
# PASSWORD and ORG_NAME from the environment. fleetctl speaks plain HTTP only to localhost, hence Fleet's network
# namespace.
fleet="$(compose ps -q fleet)"
[[ -n "$fleet" ]] || { echo "fleet is not running" >&2; exit 1; }
out="$(docker run --rm -i --network "container:$fleet" -e HOME=/tmp -e ADMIN_PASSWORD -e ENROLL_SECRET -e TOKEN \
  --entrypoint sh "$FLEETCTL_IMAGE" -s <<'SCRIPT'
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
EMAIL="$admin" PASSWORD="$ADMIN_PASSWORD" fleetctl login >/dev/null
printf 'contexts:\n  default:\n    address: http://localhost:8080\n    token: "%s"\n' "$TOKEN" >/tmp/paddock.yml
if [ -n "$TOKEN" ] && fleetctl api --config /tmp/paddock.yml /api/latest/fleet/me >/dev/null 2>&1; then
  echo "fleet: API token of the API-only user paddock is valid" >&2
else
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
