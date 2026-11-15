#!/usr/bin/env bash
# Tests of rabbitmq-definitions.sh (`make test`, PDK-1017, main §45): ./paddock upgrade imports the definitions into the
# running broker before up with --import, which must neither print nor leave anything of the definitions file (it holds
# the users' passwords) and must not compare the permissions; --check only compares, the default does both.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
failures=0
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

check() {
  local desc="$1"
  shift
  if "$@"; then echo "ok   $desc"; else
    echo "FAIL $desc"
    failures=$((failures + 1))
  fi
}

mkdir -p "$tmp/compose/scripts" "$tmp/compose/.secrets/rabbitmq" "$tmp/compose/rabbitmq" "$tmp/bin"
cp "$here/lib.sh" "$here/rabbitmq-definitions.sh" "$tmp/compose/scripts/"
printf 'PADDOCK_IMAGE=example.org/paddock-server:test\n' >"$tmp/compose/versions.env"
printf 'PADDOCK_HOST=controlplane\n' >"$tmp/compose/.env"
printf '{"users":[{"name":"worker","password":"not-a-real-secret-4711"}]}\n' >"$tmp/compose/.secrets/rabbitmq/definitions.json"
printf '{}\n' >"$tmp/compose/rabbitmq/definitions.json.tmpl"
# The fake docker logs its arguments and what it read on stdin; `exec … import_definitions` echoes stdin as the real
# rabbitmqctl's output would, so a missing redirect would show the password.
cat >"$tmp/bin/docker" <<'FAKE'
#!/usr/bin/env bash
echo "docker $*" >>"$FAKE_LOG"
case "$*" in
  *import_definitions*)
    stdin="$(cat)"
    echo "stdin $stdin" >>"$FAKE_LOG"
    echo "imported $stdin"
    exit "${FAKE_IMPORT_EXIT:-0}"
    ;;
  *list_permissions*) echo '[]' ;;
  *check-broker*)
    cat >/dev/null
    echo "PASS  rabbitmq permissions"
    ;;
esac
FAKE
chmod +x "$tmp/bin/docker"

# run <args…>: the script with the fake docker; output in $out, exit code in $rc, calls in $tmp/log.
run() {
  : >"$tmp/log"
  rc=0
  out="$(cd "$tmp" && PATH="$tmp/bin:$PATH" FAKE_LOG="$tmp/log" "$tmp/compose/scripts/rabbitmq-definitions.sh" "$@" 2>&1)" || rc=$?
}

before="$(cd "$tmp" && find . -type f | sort)"
run --import
check "--import exits 0" test "$rc" = 0
check "--import pipes the definitions into rabbitmqctl import_definitions on stdin" \
  grep -q '^stdin {"users":\[{"name":"worker","password":"not-a-real-secret-4711"}\]}$' "$tmp/log"
check "--import never puts the definitions on a command line" bash -c "! grep '^docker .*not-a-real-secret' '$tmp/log'"
check "--import prints nothing of the definitions" bash -c "! grep -q not-a-real-secret <<<\"\$1\"" _ "$out"
check "--import does not compare the permissions" bash -c "! grep -qE 'list_permissions|check-broker' '$tmp/log'"
check "--import leaves no file behind" test "$(cd "$tmp" && find . -type f ! -name log | sort)" = "$before"

run
check "the default exits 0" test "$rc" = 0
check "the default imports, then compares" bash -c "grep -n import_definitions '$tmp/log' | head -1 | grep -q '^1:' && grep -q check-broker '$tmp/log'"
check "the default prints nothing of the definitions" bash -c "! grep -q not-a-real-secret <<<\"\$1\"" _ "$out"

run --check
check "--check exits 0" test "$rc" = 0
check "--check does not import" bash -c "! grep -q import_definitions '$tmp/log'"
check "--check compares the listing" grep -q check-broker "$tmp/log"

FAKE_IMPORT_EXIT=1 run --import
check "a failed import fails" test "$rc" = 1
check "a failed import names the broker" grep -q 'import_definitions failed' <<<"$out"
check "a failed import prints nothing of the definitions" bash -c "! grep -q not-a-real-secret <<<\"\$1\"" _ "$out"

rm "$tmp/compose/.secrets/rabbitmq/definitions.json"
run --import
check "--import without the rendered definitions fails" test "$rc" = 1
check "and does not reach the broker" bash -c "! grep -q import_definitions '$tmp/log'"

run --bogus
check "an unknown option is a usage error" test "$rc" = 2

if ((failures > 0)); then
  echo "rabbitmq-definitions: $failures check(s) failed"
  exit 1
fi
echo "rabbitmq-definitions: all checks passed"
