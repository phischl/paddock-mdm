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

# read_token_file <file>: the stored token; empty when the file is absent (first install). A file that exists but cannot
# be read fails, so the script never mistakes it for "no token" and replaces a user whose token it holds (PDK-024
# review 2).
read_token_file() {
  [[ -e "$1" ]] || return 0
  [[ -r "$1" ]] || { echo "fleet: cannot read $1; nothing changed" >&2; return 1; }
  cat "$1"
}

# fleet_me_status <port> <timeout seconds>: the HTTP status of GET /api/latest/fleet/me at 127.0.0.1:<port> with
# $TOKEN, empty when there is no answer within the timeout. bash's /dev/tcp needs no HTTP client in the image, and the
# token stays in the environment.
fleet_me_status() {
  timeout "$2" bash -c '
    exec 3<>"/dev/tcp/127.0.0.1/$1" || exit 0
    printf "GET /api/latest/fleet/me HTTP/1.0\r\nHost: localhost\r\nAuthorization: Bearer %s\r\n\r\n" "$TOKEN" >&3
    head -1 <&3 | cut -d" " -f2' _ "$1" 2>/dev/null || true
}

# fleet_healthz_status <port> <timeout seconds>: the HTTP status of GET /healthz at 127.0.0.1:<port>, empty when there
# is no answer within the timeout. It needs no login: `fleetctl api` refuses to run before `fleetctl login`, so the
# earlier probe with it never succeeded and always waited its full 120 s (PDK-517).
fleet_healthz_status() {
  timeout "$2" bash -c '
    exec 3<>"/dev/tcp/127.0.0.1/$1" || exit 0
    printf "GET /healthz HTTP/1.0\r\nHost: localhost\r\n\r\n" >&3
    head -1 <&3 | cut -d" " -f2' _ "$1" 2>/dev/null || true
}

# fleet_wait_healthy <port> <timeout seconds> <delay seconds>: polls /healthz until it answers 200, <delay> seconds
# apart; fails once <timeout> seconds have passed. The deadline, not a poll count, bounds it, so a Fleet that accepts
# connections and never answers cannot stretch the wait (PDK-517 review 1).
fleet_wait_healthy() {
  local deadline=$((SECONDS + $2)) left
  while :; do
    left=$((deadline - SECONDS))
    ((left > 0)) || return 1
    [[ "$(fleet_healthz_status "$1" $((left < 2 ? left : 2)))" == 200 ]] && return 0
    left=$((deadline - SECONDS))
    ((left > 0)) || return 1
    sleep $((left < $3 ? left : $3))
  done
}

# retry <attempts> <delay seconds> <description> <command…>: runs the command until it succeeds, at most <attempts>
# times with <delay> seconds between, and then fails naming <description>. Bounded readiness polling for a Fleet that
# serves /healthz before it accepts the setup or a login (PDK-517); never unbounded.
retry() {
  local attempts="$1" delay="$2" what="$3" i
  shift 3
  for ((i = 1; ; i++)); do
    "$@" && return 0
    if ((i >= attempts)); then
      echo "fleet: $what failed $attempts times, ${delay} s apart; giving up" >&2
      return 1
    fi
    echo "fleet: $what failed (attempt $i of $attempts); retrying in ${delay} s" >&2
    sleep "$delay"
  done
}

# Sourced by the test for the functions above only.
if [[ "${BASH_SOURCE[0]}" != "$0" ]]; then return 0; fi

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
. "$here/lib.sh"

ADMIN_PASSWORD="$(cat "$SECRETS_DIR/fleet_admin_password")"
ENROLL_SECRET="$(cat "$SECRETS_DIR/fleet_enroll_secret")"
TOKEN="$(read_token_file "$SECRETS_DIR/fleet_api_token")"
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

# The 120 s upper bound stays for a standalone `make fleet-bootstrap` right after Fleet started.
if ! docker run --rm --network "container:$fleet" --entrypoint bash "$FLEETCTL_IMAGE" \
  -c "$(declare -f fleet_healthz_status fleet_wait_healthy); fleet_wait_healthy 8080 120 2"; then
  echo "fleet: Fleet did not answer GET /healthz with 200 within 120 s; nothing changed" >&2
  exit 1
fi

fleet_setup() {
  fleetctl_sh <<'SCRIPT'
set -eu
admin=admin@paddock-mdm.invalid
fleetctl config set --address http://localhost:8080 >/dev/null
if EMAIL="$admin" NAME="Paddock administrator" PASSWORD="$ADMIN_PASSWORD" ORG_NAME=Paddock fleetctl setup >/tmp/setup 2>&1; then
  echo "fleet: initial setup done" >&2
elif ! grep -qi "already been set up\|already been setup" /tmp/setup; then
  cat /tmp/setup >&2
  exit 1
fi
SCRIPT
}
retry 5 5 "the initial setup of Fleet" fleet_setup

# The exact status of /me decides; a Fleet that accepts the connection and never answers fails after 10 seconds. Only
# a status that leads to keep or rotate ends the polling, so a Fleet still starting gets a few more seconds.
status=
token_status_decides() {
  status="$(docker run --rm -i --network "container:$fleet" -e TOKEN --entrypoint bash "$FLEETCTL_IMAGE" \
    -c "$(declare -f fleet_me_status); fleet_me_status 8080 10" || true)"
  [[ "$(fleet_token_action "$TOKEN" "$status")" != fail ]]
}
if [[ -n "$TOKEN" ]]; then
  retry 5 5 "checking the stored API token" token_status_decides || true
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

fleet_users() {
  fleetctl_sh <<'SCRIPT'
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
}
# A repeated attempt deletes the user an earlier failed attempt created, so only the last token printed is valid.
out="$(retry 5 5 "setting up the API-only user paddock and the enroll secret" fleet_users)"
token="$(printf '%s\n' "$out" | sed -n 's/^TOKEN=//p' | tail -n 1)"
if [[ -n "$token" ]]; then
  printf '%s' "$token" >"$SECRETS_DIR/fleet_api_token"
  chmod 644 "$SECRETS_DIR/fleet_api_token"
  echo "wrote .secrets/fleet_api_token; restart paddock-worker if it is running"
fi
