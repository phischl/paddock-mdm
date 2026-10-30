#!/usr/bin/env bash
# Tests of the token decision of fleet-bootstrap.sh (`make test`, PDK-024 review 1): only a stored token that Fleet
# rejects with 401 replaces the API-only user; no answer or any other status fails without a change. Review 2: a token
# file that cannot be read fails instead of counting as "no token", and the /me probe gives up after its timeout.
# PDK-517: the readiness probe on /healthz needs no login and is bounded, and retry repeats a failed step a bounded
# number of times.
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
# sets $port. It runs in this shell, not in $(…), so cleanup knows its pid, and it exits on its own after 30 s so an
# aborted run leaks nothing.
listen() {
  python3 -c '
import socket, sys, time
deadline = time.monotonic() + 30
s = socket.socket(); s.bind(("127.0.0.1", 0)); s.listen(4); s.settimeout(1)
print(s.getsockname()[1], flush=True)
while time.monotonic() < deadline:
    try:
        c, _ = s.accept()
    except socket.timeout:
        continue
    if sys.argv[1]:
        c.recv(4096); c.sendall(sys.argv[1].encode()); c.close()
    else:
        time.sleep(max(0, deadline - time.monotonic()))
' "$1" >"$tmp/port" 2>/dev/null </dev/null &
  listeners+=("$!")
  for _ in $(seq 1 50); do [[ -s "$tmp/port" ]] && break; sleep 0.1; done
  port="$(cat "$tmp/port")"
  : >"$tmp/port"
}

if command -v python3 >/dev/null && command -v timeout >/dev/null; then
  export TOKEN=secret-token
  listen $'HTTP/1.0 401 Unauthorized\r\n\r\n'
  check "probe reads the status (401)" test "$(fleet_me_status "$port" 5)" = 401
  listen $'HTTP/1.0 200 OK\r\n\r\n'
  check "probe reads the status (200)" test "$(fleet_me_status "$port" 5)" = 200
  listen ""
  start=$SECONDS
  got="$(fleet_me_status "$port" 1)"
  check "probe of a Fleet that never answers: no status (-> fail)" test -z "$got"
  check "probe of a Fleet that never answers gives up after its timeout" test $((SECONDS - start)) -le 3
  check "probe of a closed port: no status (-> fail)" test -z "$(fleet_me_status 1 2)"
  unset TOKEN
  listen $'HTTP/1.0 200 OK\r\n\r\n'
  check "healthz probe reads the status (200)" test "$(fleet_healthz_status "$port" 5)" = 200
  check "Fleet answering /healthz with 200 is ready at the first poll" fleet_wait_healthy "$port" 5 1
  listen $'HTTP/1.0 503 Service Unavailable\r\n\r\n'
  check "healthz probe reads the status (503)" test "$(fleet_healthz_status "$port" 5)" = 503
  check "Fleet answering /healthz with 503 is not ready" eval '! fleet_wait_healthy "$port" 2 1'
  check "healthz probe of a closed port: no status" test -z "$(fleet_healthz_status 1 2)"
  start=$SECONDS
  check "Fleet that is not listening is not ready" eval '! fleet_wait_healthy 1 3 1'
  check "readiness polling of a closed port stops at its deadline" test $((SECONDS - start)) -le 5
  listen ""
  start=$SECONDS
  check "Fleet that accepts connections and never answers is not ready" eval '! fleet_wait_healthy "$port" 3 1'
  check "readiness polling of a hung Fleet stops at its deadline" test $((SECONDS - start)) -le 5
  check "six listeners are tracked for cleanup" test "${#listeners[@]}" -eq 6
  for pid in "${listeners[@]}"; do kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; done
  alive=0
  for pid in "${listeners[@]}"; do kill -0 "$pid" 2>/dev/null && alive=$((alive + 1)); done
  check "no listener survives cleanup" test "$alive" -eq 0
else
  echo "skip probe tests (python3 or timeout missing)"
fi

# fails_until <n>: fails the first <n> - 1 calls and succeeds from call <n> on; counts its calls in $tmp/calls.
fails_until() {
  local calls
  calls=$(($(cat "$tmp/calls" 2>/dev/null || echo 0) + 1))
  echo "$calls" >"$tmp/calls"
  ((calls >= $1))
}
calls() { cat "$tmp/calls"; }

rm -f "$tmp/calls"
check "retry: a step that succeeds runs once" retry 3 0 "step" fails_until 1
check "retry: ... exactly once" test "$(calls)" = 1
rm -f "$tmp/calls"
check "retry: a step that fails once succeeds at the second attempt" retry 3 0 "step" fails_until 2
check "retry: ... after two calls" test "$(calls)" = 2
rm -f "$tmp/calls"
check "retry: a step that keeps failing fails" eval '! retry 3 0 "the initial setup of Fleet" fails_until 99 2>"$tmp/err"'
check "retry: ... after exactly its attempts" test "$(calls)" = 3
check "retry: ... naming what failed" grep -q "fleet: the initial setup of Fleet failed 3 times, 0 s apart; giving up" "$tmp/err"

if ((failures > 0)); then
  echo "fleet-bootstrap: $failures failure(s)"
  exit 1
fi
echo "fleet-bootstrap: all checks passed"
