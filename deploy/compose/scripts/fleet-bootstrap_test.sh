#!/usr/bin/env bash
# Tests of the token decision of fleet-bootstrap.sh (`make test`, PDK-024 review 1): only a stored token that Fleet
# rejects with 401 replaces the API-only user; no answer or any other status fails without a change. Review 2: a token
# file that cannot be read fails instead of counting as "no token", and the /me probe gives up after its timeout.
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

# check <description> <command…>: the command succeeds.
check() {
  local desc="$1"
  shift
  if "$@"; then echo "ok   $desc"; else
    echo "FAIL $desc"
    failures=$((failures + 1))
  fi
}

tmp="$(mktemp -d)"
listeners=()
cleanup() {
  for pid in "${listeners[@]}"; do kill "$pid" 2>/dev/null || true; done
  chmod -R u+rwx "$tmp"
  rm -rf "$tmp"
}
trap cleanup EXIT

check "absent token file: empty token (first install)" test -z "$(read_token_file "$tmp/absent")"
: >"$tmp/empty"
check "empty token file: empty token (first install)" test -z "$(read_token_file "$tmp/empty")"
printf 'secret-token' >"$tmp/token"
check "readable token file: its token" test "$(read_token_file "$tmp/token")" = secret-token
chmod 000 "$tmp/token"
if [[ -r "$tmp/token" ]]; then
  echo "skip unreadable token file (running as root)"
else
  check "unreadable token file fails" eval '! read_token_file "$tmp/token" >/dev/null 2>&1'
  # The script's own assignment must stop it, not continue with an empty token.
  check "unreadable token file stops the assignment" eval \
    '! bash -c "set -e; . \"$here/fleet-bootstrap.sh\"; t=\"\$(read_token_file \"$tmp/token\")\"; echo reached" 2>/dev/null | grep -q reached'
fi

# listen <reply>: a local TCP server that answers every connection with <reply> (or never answers when it is empty);
# prints its port.
listen() {
  python3 -c '
import socket, sys, time
s = socket.socket(); s.bind(("127.0.0.1", 0)); s.listen(4)
print(s.getsockname()[1], flush=True)
while True:
    c, _ = s.accept()
    if sys.argv[1]:
        c.recv(4096); c.sendall(sys.argv[1].encode()); c.close()
    else:
        time.sleep(60)
' "$1" >"$tmp/port" &
  listeners+=("$!")
  for _ in $(seq 1 50); do [[ -s "$tmp/port" ]] && break; sleep 0.1; done
  cat "$tmp/port"
  : >"$tmp/port"
}

if command -v python3 >/dev/null && command -v timeout >/dev/null; then
  export TOKEN=secret-token
  port="$(listen $'HTTP/1.0 401 Unauthorized\r\n\r\n')"
  check "probe reads the status (401)" test "$(fleet_me_status "$port" 5)" = 401
  port="$(listen $'HTTP/1.0 200 OK\r\n\r\n')"
  check "probe reads the status (200)" test "$(fleet_me_status "$port" 5)" = 200
  port="$(listen "")"
  start=$SECONDS
  got="$(fleet_me_status "$port" 1)"
  check "probe of a Fleet that never answers: no status (-> fail)" test -z "$got"
  check "probe of a Fleet that never answers gives up after its timeout" test $((SECONDS - start)) -le 3
  check "probe of a closed port: no status (-> fail)" test -z "$(fleet_me_status 1 2)"
  unset TOKEN
else
  echo "skip probe tests (python3 or timeout missing)"
fi

if ((failures > 0)); then
  echo "fleet-bootstrap: $failures failure(s)"
  exit 1
fi
echo "fleet-bootstrap: all checks passed"
