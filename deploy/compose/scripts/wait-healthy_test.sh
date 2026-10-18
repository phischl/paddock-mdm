#!/usr/bin/env bash
# Tests of wait-healthy.sh (`make test`): on timeout it names the last health check output of every unhealthy service
# (plan M8x decision 29). docker is a stub on PATH.
set -euo pipefail

script="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/wait-healthy.sh"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
failures=0

cat >"$work/docker" <<'EOF'
#!/usr/bin/env bash
case "$1" in
  compose)
    printf '%s\n' 'paddock-api|paddock-paddock-api-1|running|unhealthy|0' \
      'paddock-worker|paddock-paddock-worker-1|running|starting|0' 'postgres|paddock-postgres-1|running|healthy|0' ;;
  inspect)
    [[ "${*: -1}" == paddock-paddock-api-1 ]] || exit 1
    printf 'readyz: 503 Service Unavailable: not ready: session keys not loaded\nreadyz: 503 Service Unavailable: not ready: session keys not loaded: OpenBao is sealed or unreachable (docs/operations/openbao.md section 2)\n' ;;
esac
EOF
chmod +x "$work/docker"

# check <name> <pattern> <output>
check() {
  if grep -qF -- "$2" <<<"$3"; then
    echo "ok   $1"
  else
    echo "FAIL $1: output lacks '$2':"
    printf '%s\n' "$3"
    failures=$((failures + 1))
  fi
}

if out="$(PATH="$work:$PATH" PADDOCK_ENV=development WAIT_TIMEOUT=0 bash "$script" 2>&1)"; then
  echo "FAIL timeout: exit 0"
  failures=$((failures + 1))
fi
check "pending services" "still waiting for: paddock-api (unhealthy) paddock-worker (starting)" "$out"
check "reason of the unhealthy service" "paddock-api: readyz: 503 Service Unavailable: not ready: session keys not loaded: OpenBao is sealed or unreachable (docs/operations/openbao.md section 2)" "$out"
if grep -q '^paddock-worker:' <<<"$out"; then
  echo "FAIL starting service: a reason is printed for a service that is not unhealthy"
  failures=$((failures + 1))
fi

if ((failures > 0)); then
  echo "wait-healthy: $failures failure(s)"
  exit 1
fi
echo "wait-healthy: all cases passed"
