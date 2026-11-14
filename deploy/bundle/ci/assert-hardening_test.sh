#!/usr/bin/env bash
# Tests of assert-hardening.sh (plan M8s decision 37, plan M12h decision 11, `make test`): the containers of every named
# project go, as `docker inspect`, to `check-containers` of the projects' own server image with the exceptions file;
# its verdict is the script's. The matrix itself is tested in server/internal/prodcheck (containers_test.go).
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

# A docker stub: `ps` lists the IDs of $IDS_<project>, `inspect --format` prints $SUMMARY, `inspect` the JSON
# `[$*]`, and `run` logs its arguments and stdin, prints $RUN_OUT and exits $RUN_RC.
mkdir -p "$work/bin"
cat >"$work/bin/docker" <<'EOF'
#!/usr/bin/env bash
case "$1" in
  ps) project="${*: -1}"; project="${project#label=com.docker.compose.project=}"; var="IDS_${project//-/_}"
    [[ -z "${!var:-}" ]] || printf '%s\n' ${!var} ;;
  inspect) if [[ "$2" == --format ]]; then printf '%s\n' "$SUMMARY"; else printf '[%s]\n' "${*:2}"; fi ;;
  run) printf '%s\n' "$*" >"$RUN_LOG.args"; cat >"$RUN_LOG.stdin"; printf '%s\n' "$RUN_OUT"; exit "${RUN_RC:-0}" ;;
esac
EOF
chmod +x "$work/bin/docker"
export RUN_LOG="$work/run"
exceptions="$(cd "$here/../../compose" && pwd)/hardening-exceptions.yaml"
api='/p-paddock-api-1 paddock-api ghcr.io/x/paddock-server:1.2.3 null ["ALL"] ["no-new-privileges:true"] 256 0'
writer='/a-paddock-audit-writer-1 paddock-audit-writer ghcr.io/x/paddock-server:1.2.3 null ["ALL"] ["no-new-privileges:true"] 256 0'
caddy='/p-caddy-1 caddy caddy:2 ["CAP_NET_BIND_SERVICE"] ["ALL"] ["no-new-privileges:true"] 256 0'
pass='PASS  containers: capabilities and security options match the matrix'
assert() {
  local rc=0
  rm -f "$RUN_LOG".*
  PATH="$work/bin:$PATH" "$here/assert-hardening.sh" "$@" >"$work/out" 2>"$work/err" || rc=$?
  echo "$rc $(head -1 "$work/err")"
}

export IDS_p="a1 a2" IDS_a="b1" SUMMARY="$api"$'\n'"$caddy"$'\n'"$writer" RUN_OUT="$pass"
check "hardened projects" "$(assert p a)" "0 "
check "every container of both projects is inspected" "$(cat "$RUN_LOG.stdin")" "[a1 a2 b1]"
check "the projects' server image checks them with the exceptions file" "$(cat "$RUN_LOG.args")" \
  "run --rm -i --network none --cap-drop ALL --security-opt no-new-privileges:true --read-only -v $exceptions:/paddock/hardening-exceptions.yaml:ro ghcr.io/x/paddock-server:1.2.3 check-containers --exceptions /paddock/hardening-exceptions.yaml"
check "the verdict is printed" "$(tail -1 "$work/out")" "$pass"

check "a finding fails" "$(RUN_RC=1 assert p)" "1 "
check "PADDOCK_IMAGE overrides the image" "$(PADDOCK_IMAGE=local/server:dev assert p >/dev/null; grep -o 'local/server:dev check-containers' "$RUN_LOG.args")" \
  "local/server:dev check-containers"
check "HARDENING_EXCEPTIONS names another file" \
  "$(HARDENING_EXCEPTIONS="$here/assert-hardening_test.sh" assert p >/dev/null; grep -o -- "-v [^ ]*:/paddock" "$RUN_LOG.args")" \
  "-v $here/assert-hardening_test.sh:/paddock"
check "a missing exceptions file" "$(HARDENING_EXCEPTIONS="$work/none.yaml" assert p)" "2 assert-hardening: no exceptions file $work/none.yaml"
check "no server container to take the image from" "$(SUMMARY="$caddy" assert p)" \
  "1 assert-hardening: no paddock-api or paddock-audit-writer container in p; set PADDOCK_IMAGE"
check "no container" "$(assert q)" "1 assert-hardening: no container in project(s) q"
check "no project" "$(assert)" "2 usage: assert-hardening.sh <project>..."
[[ ! -e "$RUN_LOG.args" ]] || check "nothing runs without a container" "ran" "not run"

((failures == 0)) || exit 1
