#!/usr/bin/env bash
# Tests of assert-hardening.sh (plan M8s decision 37, `make test`): hardened containers pass; a role or Caddy that keeps
# capabilities or may gain privileges, and any container without a pids limit, fail naming the container.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
failures=0
check() {
  if [[ "$2" == "$3" ]]; then echo "ok   $1"; else
    echo "FAIL $1: got '$2', want '$3'"
    failures=$((failures + 1))
  fi
}

# A docker stub: `ps` lists one ID per line of $INSPECT, `inspect` prints $INSPECT.
mkdir -p "$work/bin"
cat >"$work/bin/docker" <<'EOF'
#!/usr/bin/env bash
case "$1" in
  ps) [[ -n "$INSPECT" ]] && awk '{ print NR }' <<<"$INSPECT" ;;
  inspect) printf '%s\n' "$INSPECT" ;;
esac
EOF
chmod +x "$work/bin/docker"
hardened='["no-new-privileges:true"]'
api="/p-paddock-api-1 paddock-api [\"ALL\"] $hardened 256"
caddy="/p-caddy-1 caddy [\"ALL\"] $hardened 256"
postgres="/p-postgres-1 postgres null null 512"
assert() {
  local rc=0
  INSPECT="$1" PATH="$work/bin:$PATH" "$here/assert-hardening.sh" p >/dev/null 2>"$work/err" || rc=$?
  echo "$rc $(head -1 "$work/err")"
}

check "hardened project" "$(assert "$api"$'\n'"$caddy"$'\n'"$postgres")" "0 "
check "role keeps capabilities" "$(assert "/p-paddock-api-1 paddock-api null $hardened 256")" \
  "1 assert-hardening: /p-paddock-api-1 does not drop ALL capabilities"
check "caddy may gain privileges" "$(assert '/p-caddy-1 caddy ["ALL"] null 256')" \
  "1 assert-hardening: /p-caddy-1 lacks no-new-privileges:true"
check "third party without pids limit" "$(assert "/p-postgres-1 postgres null null <nil>")" \
  "1 assert-hardening: /p-postgres-1 has no pids limit (<nil>)"
check "unlimited pids" "$(assert "/p-paddock-api-1 paddock-api [\"ALL\"] $hardened -1")" \
  "1 assert-hardening: /p-paddock-api-1 has no pids limit (-1)"
check "no container" "$(assert "")" "1 assert-hardening: no container in project(s) p"

((failures == 0)) || exit 1
