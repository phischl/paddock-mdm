#!/usr/bin/env bash
# Tests of rabbitmq-definitions.sh (`make test`, PDK-1017, main §45): ./paddock upgrade imports the definitions into the
# running broker before up with --import, which must neither print nor leave anything of the definitions file (it holds
# the users' passwords) and must not compare the permissions; --check only compares, the default does both and repeats
# the comparison for a few seconds while the broker still applies the import.
#   1. with a fake docker: the calls, the output and the files;
#   2. against a throwaway broker of the pinned image (PDK-1077: the fakes passed while every real import failed):
#      --import applies the definitions to a broker that runs the previous release's, and the broker then has exactly
#      their permissions (assert-broker.sh); no file stays behind in the container.
# Needs Docker and python3, like the rest of `make test`; it fails rather than skips without them.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
failures=0
tmp="$(mktemp -d)"
# Section 2's Compose project of its own, never the stack's "paddock"; set once its broker may run.
project=""
cp_dir="$tmp/cp/compose"
cp_compose() { docker compose --project-directory "$cp_dir" -p "$project" --env-file "$cp_dir/versions.env" "$@"; }
cleanup() {
  [[ -z "$project" ]] || cp_compose down -v --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$tmp"
}
trap cleanup EXIT

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
# The fake docker logs its arguments on one line (the import's container script spans lines, and a secret on any of
# them must show on a line of the call) and what it read on stdin; `exec … import_definitions` echoes stdin as the real
# rabbitmqctl's output would, so a missing redirect would show the password. check-broker fails while the file
# $FAKE_STALE holds a number above 0 and counts it down, as the comparison right after a pending import does; the fake
# sleep only logs, so the repeated comparison costs no time.
cat >"$tmp/bin/docker" <<'FAKE'
#!/usr/bin/env bash
args="$*"
echo "docker ${args//$'\n'/ }" >>"$FAKE_LOG"
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
    stale="$(cat "${FAKE_STALE:-/nonexistent}" 2>/dev/null || echo 0)"
    if ((stale > 0)); then
      echo $((stale - 1)) >"$FAKE_STALE"
      echo "FAIL  rabbitmq permissions: worker: has (^$ ^$ ^$)"
      exit 1
    fi
    echo "PASS  rabbitmq permissions"
    ;;
esac
FAKE
cat >"$tmp/bin/sleep" <<'FAKE'
#!/usr/bin/env bash
echo "sleep $*" >>"$FAKE_LOG"
FAKE
chmod +x "$tmp/bin/docker" "$tmp/bin/sleep"

# run <args…>: the script with the fake docker; output in $out, exit code in $rc, calls in $tmp/log.
run() {
  : >"$tmp/log"
  rc=0
  out="$(cd "$tmp" && PATH="$tmp/bin:$PATH" FAKE_LOG="$tmp/log" "$tmp/compose/scripts/rabbitmq-definitions.sh" "$@" 2>&1)" || rc=$?
}

before="$(cd "$tmp" && find . -type f | sort)"
run --import
check "--import exits 0" test "$rc" = 0
check "--import hands the definitions to the container's import_definitions on stdin" \
  grep -q '^stdin {"users":\[{"name":"worker","password":"not-a-real-secret-4711"}\]}$' "$tmp/log"
check "--import never puts the definitions on a command line" bash -c "! grep '^docker .*not-a-real-secret' '$tmp/log'"
check "--import prints nothing of the definitions" bash -c "! grep -q not-a-real-secret <<<\"\$1\"" _ "$out"
check "--import does not compare the permissions" bash -c "! grep -qE 'list_permissions|check-broker' '$tmp/log'"
check "--import leaves no file behind" test "$(cd "$tmp" && find . -type f ! -name log | sort)" = "$before"

run
check "the default exits 0" test "$rc" = 0
check "the default imports, then compares" bash -c "grep -n import_definitions '$tmp/log' | head -1 | grep -q '^1:' && grep -q check-broker '$tmp/log'"
check "the default prints nothing of the definitions" bash -c "! grep -q not-a-real-secret <<<\"\$1\"" _ "$out"
check "the default compares once when the permissions match" test "$(grep -c check-broker "$tmp/log")" = 1

echo 3 >"$tmp/stale"
FAKE_STALE="$tmp/stale" run
check "the default waits for a pending import" test "$rc" = 0
check "and compares until the permissions match" test "$(grep -c check-broker "$tmp/log")" = 4
check "and prints only the last comparison" bash -c "! grep -q FAIL <<<\"\$1\" && grep -q PASS <<<\"\$1\"" _ "$out"

echo 100 >"$tmp/stale"
FAKE_STALE="$tmp/stale" run
check "the default fails when the permissions never match" test "$rc" = 1
check "after a bounded number of comparisons" test "$(grep -c check-broker "$tmp/log")" = 10
check "and prints the finding" grep -q '^FAIL  rabbitmq permissions' <<<"$out"

run --check
check "--check exits 0" test "$rc" = 0
check "--check does not import" bash -c "! grep -q import_definitions '$tmp/log'"
check "--check compares the listing" grep -q check-broker "$tmp/log"

echo 1 >"$tmp/stale"
FAKE_STALE="$tmp/stale" run --check
check "--check fails at once on a mismatch (no import is pending)" test "$rc" = 1
check "--check compares once" test "$(grep -c check-broker "$tmp/log")" = 1

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

# --- 2. Against a throwaway broker of the pinned image --------------------------------------------------------------

command -v docker >/dev/null || {
  echo "FAIL docker is required"
  exit 1
}
# A copy of the scripts with a Compose file set that holds only the broker, configured as the stack's, so the script
# reaches it exactly as it reaches the stack's.
mkdir -p "$cp_dir/scripts" "$cp_dir/rabbitmq" "$cp_dir/.secrets/rabbitmq"
cp "$here/lib.sh" "$here/rabbitmq-definitions.sh" "$cp_dir/scripts/"
cp "$here/../versions.env" "$cp_dir/"
cp "$here/../rabbitmq/rabbitmq.conf" "$here/../rabbitmq/enabled_plugins" "$here/../rabbitmq/definitions.json.tmpl" \
  "$cp_dir/rabbitmq/"
project="paddock-rmqdef-test-$$"
printf 'PADDOCK_ENV=production\nPADDOCK_HOST=controlplane\nPADDOCK_PROJECT=%s\n' "$project" >"$cp_dir/.env"
cat >"$cp_dir/compose.yaml" <<'YAML'
services:
  rabbitmq:
    image: ${RABBITMQ_IMAGE}
    user: "999:999"
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
    hostname: rabbitmq
    environment:
      PADDOCK_RABBITMQ_MEM_LIMIT: 1g
    volumes:
      - ./rabbitmq/rabbitmq.conf:/etc/rabbitmq/rabbitmq.conf:ro
      - ./rabbitmq/enabled_plugins:/etc/rabbitmq/enabled_plugins:ro
    secrets:
      - source: rabbitmq_definitions
        target: /etc/rabbitmq/definitions.json
    healthcheck:
      test: ["CMD-SHELL", "RABBITMQ_CTL_ERL_ARGS='+S 1:1' rabbitmq-diagnostics -q check_local_alarms"]
      interval: 2s
      timeout: 10s
      retries: 60
secrets:
  rabbitmq_definitions:
    file: ./previous-definitions.json
YAML
printf 'services: {}\n' >"$cp_dir/compose.prod.yaml"
cp "$cp_dir/compose.prod.yaml" "$cp_dir/compose.backup.yaml"
# The definitions with fresh passwords, and the previous release's that the broker boots with: there the audit writer
# may not publish to paddock.offboarding and the worker may not read worker.offboarding (0.1.0-alpha.10).
python3 -I - "$cp_dir/rabbitmq/definitions.json.tmpl" "$cp_dir/.secrets/rabbitmq/definitions.json" \
  "$cp_dir/previous-definitions.json" <<'PY'
import json, re, secrets, sys
text = re.sub(r"@[A-Z_]+_PASSWORD@", lambda _: secrets.token_urlsafe(18), open(sys.argv[1]).read())
open(sys.argv[2], "w").write(text)
d = json.loads(text)
for p in d["permissions"]:
    if p["user"] == "audit_writer":
        p["write"] = "^$"
    if p["user"] == "worker":
        p["read"] = p["read"].replace("|worker\\.offboarding", "")
json.dump(d, open(sys.argv[3], "w"))
PY
chmod 600 "$cp_dir/.secrets/rabbitmq/definitions.json"
# The broker runs as uid 999 and reads its boot definitions from the bind-mounted file.
chmod 644 "$cp_dir/previous-definitions.json"
python3 -I -c 'import json, sys; print("\n".join(u["password"] for u in json.load(open(sys.argv[1]))["users"]))' \
  "$cp_dir/.secrets/rabbitmq/definitions.json" >"$tmp/passwords"

# real_run <args…>: the copied script against the throwaway broker; output in $out, exit code in $rc. The caller's
# environment must not choose another project or file set.
real_run() {
  rc=0
  out="$(env -u PADDOCK_PROJECT -u PADDOCK_ENV -u PADDOCK_HOST -u PADDOCK_COMPOSE_EXTRA -u PADDOCK_AUTO_UNSEAL \
    -u SECRETS_DIR "$cp_dir/scripts/rabbitmq-definitions.sh" "$@" 2>&1 </dev/null)" || rc=$?
}
assert_broker() { "$here/../../bundle/ci/assert-broker.sh" "$project" >"$tmp/assert" 2>&1 </dev/null; }
# matches: assert-broker.sh, repeated for a few seconds as the default mode does while the broker applies an import.
matches() {
  local i
  for i in 1 2 3 4 5 6 7 8 9 10; do
    if assert_broker; then return 0; fi
    ((i == 10)) || sleep 1
  done
  sed 's/^/     /' "$tmp/assert"
  return 1
}
differs() { ! assert_broker; }
no_password() { ! grep -qFf "$tmp/passwords" <<<"$out"; }
tmp_files() { cp_compose exec -T rabbitmq find /tmp -type f </dev/null | sort; }

if cp_compose up -d --wait --quiet-pull rabbitmq >"$tmp/up" 2>&1; then
  echo "ok   the throwaway broker runs with the previous release's definitions"
  check "the previous release's permissions differ from the definitions" differs
  before_files="$(tmp_files)"
  real_run --import
  check "--import against the real broker exits 0" test "$rc" = 0
  [[ "$rc" == 0 ]] || tail -3 <<<"$out" | sed 's/^/     /'
  check "--import against the real broker prints no password" no_password
  check "the broker then has exactly the permissions of the definitions" matches
  check "no file of the import stays in the container" test "$(tmp_files)" = "$before_files"

  cp_compose exec -T rabbitmq rabbitmqctl -q set_permissions -p paddock worker '^$' '^$' '^$' </dev/null >/dev/null
  check "a changed permission differs from the definitions" differs
  real_run --import
  check "a repeated --import exits 0" test "$rc" = 0
  check "and restores the permission" matches
else
  echo "FAIL the throwaway broker did not start:"
  tail -5 "$tmp/up" | sed 's/^/     /'
  failures=$((failures + 1))
fi

if ((failures > 0)); then
  echo "rabbitmq-definitions: $failures check(s) failed"
  exit 1
fi
echo "rabbitmq-definitions: all checks passed"
