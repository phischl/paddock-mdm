#!/usr/bin/env bash
# Tests of the maxmemory of entrypoint.sh (`make test`, plan M17 amendment s point 4.4): the entrypoint runs in the
# pinned Valkey image with a fake cgroup file mounted over /sys/fs/cgroup/memory.max. A numeric limit starts
# valkey-server with maxmemory at 60 % of it; "max" sets none and says so in one log line. A test-only ACL template
# grants the api user CONFIG GET, so the running value can be read.
#   VALKEY_IMAGE=<image> bash deploy/compose/valkey/entrypoint_test.sh
set -euo pipefail

image="${VALKEY_IMAGE:?VALKEY_IMAGE is required}"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
work="$(mktemp -d)"
containers=()
cleanup() {
  for c in "${containers[@]}"; do docker rm -f "$c" >/dev/null 2>&1 || true; done
  rm -rf "$work"
}
trap cleanup EXIT
failures=0

users="api gateway worker compiler escrow_reader revocation_issuer healthcheck"
mkdir -p "$work/secrets"
for u in $users; do
  printf 'pw-%s\n' "$u" >"$work/secrets/valkey_${u}_password"
done
chmod 0644 "$work"/secrets/*
printf 'user default off\nuser api on #{{api}} ~* +@all\n' >"$work/users.acl.tmpl"
chmod 0644 "$work/users.acl.tmpl"

# expect <name> <memory.max content> <want maxmemory> [log line]: starts Valkey with the fake cgroup file and checks
# the maxmemory it runs with and, if given, a log line of the entrypoint.
expect() {
  local name="$1" limit="$2" want="$3" line="${4-}" dir c got logs
  dir="$(mktemp -d -p "$work")"
  printf '%s\n' "$limit" >"$dir/memory.max"
  chmod 0644 "$dir/memory.max"
  local mounts=(-v "$here/entrypoint.sh:/usr/local/bin/paddock-entrypoint.sh:ro"
    -v "$here/valkey.conf:/etc/valkey/valkey.conf:ro" -v "$work/users.acl.tmpl:/etc/valkey/users.acl.tmpl:ro"
    -v "$dir/memory.max:/sys/fs/cgroup/memory.max:ro")
  for u in $users; do
    mounts+=(-v "$work/secrets/valkey_${u}_password:/run/secrets/valkey_${u}_password:ro")
  done
  c="$(docker run -d --tmpfs /run/valkey --tmpfs /data "${mounts[@]}" \
    --entrypoint /usr/local/bin/paddock-entrypoint.sh "$image" valkey-server /etc/valkey/valkey.conf)"
  containers+=("$c")
  for _ in $(seq 1 50); do
    docker logs "$c" 2>&1 | grep -q 'Ready to accept connections' && break
    sleep 0.2
  done
  logs="$(docker logs "$c" 2>&1)"
  got="$(docker exec -e REDISCLI_AUTH=pw-api "$c" valkey-cli --no-auth-warning --user api config get maxmemory | tail -n1 || true)"
  local policy
  policy="$(docker exec -e REDISCLI_AUTH=pw-api "$c" valkey-cli --no-auth-warning --user api config get maxmemory-policy | tail -n1 || true)"
  if [[ "$got" == "$want" && "$policy" == noeviction && (-z "$line" || "$logs" == *"$line"*) ]]; then
    echo "ok   $name"
  else
    echo "FAIL $name: maxmemory $got (want $want), policy $policy (want noeviction)${line:+, log line \"$line\"}"
    echo "$logs" | tail -n 20
    failures=$((failures + 1))
  fi
}

expect "1 GiB limit" 1073741824 644245094
expect "512 MiB limit" 536870912 322122547
expect "no limit" max 0 "paddock-entrypoint: no container memory limit (max), so no maxmemory is set"

if ((failures > 0)); then
  echo "valkey entrypoint: $failures failure(s)"
  exit 1
fi
echo "valkey entrypoint: all cases passed"
