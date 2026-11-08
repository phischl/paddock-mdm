#!/usr/bin/env bash
# Regression test (`make test`, PDK-745): postgres/provision-roles.sh, shared by the initdb hook and the one-shot service
# db-provision, creates a missing role, always sets the password again, skips a role without a password file and never
# lets a password reach a command line, the script's output or the SQL text. A fake psql records what it receives, so
# no database is needed; the SQL itself is exercised against a real PostgreSQL by the pgtest-based tests.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
script="$here/../postgres/provision-roles.sh"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/bin" "$work/secrets"
failures=0

cat >"$work/bin/psql" <<'FAKE'
#!/usr/bin/env bash
printf '%s\n' "$@" >"$FAKE_PSQL_DIR/args"
cat >"$FAKE_PSQL_DIR/stdin"
env | grep -E '^(PROVISION_PW_|PGPASSWORD)' | sort >"$FAKE_PSQL_DIR/env" || true
FAKE
chmod +x "$work/bin/psql"

check() {
  local name="$1" cond="$2"
  if ! eval "$cond"; then
    echo "FAIL: $name"
    failures=$((failures + 1))
  fi
}

# run executes the script with the environment given as arguments and leaves output, args, stdin and env in $work.
run() {
  rm -f "$work"/{args,stdin,env,out}
  env -i PATH="$work/bin:$PATH" FAKE_PSQL_DIR="$work" POSTGRES_USER=postgres "$@" bash "$script" >"$work/out" 2>&1
}

secret() { printf '%s' "$2" >"$work/secrets/$1"; }

cp_roles="OWNER API PLATFORM RELAY WORKER COMPILER ESCROW_READER REVOCATION NOTIFIER BACKUP"
cp_env=()
for r in $cp_roles; do
  secret "$r" "pw-${r}-first-9f3"
  cp_env+=("PADDOCK_${r}_PASSWORD_FILE=$work/secrets/$r")
done

run POSTGRES_DB=paddock "${cp_env[@]}"
for role in owner api platform relay worker compiler escrow_reader revocation notifier backup; do
  check "fresh: $role is created when absent" "grep -q \"WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'paddock_$role')\" '$work/stdin'"
  check "fresh: $role gets its password set" "grep -q \"ALTER ROLE %I LOGIN .*'paddock_$role'\" '$work/stdin'"
done
check "fresh: owner bypasses RLS" "grep -q 'BYPASSRLS PASSWORD %L., .paddock_owner' '$work/stdin' && ! grep -q 'NOBYPASSRLS PASSWORD %L., .paddock_owner' '$work/stdin'"
check "fresh: every role is NOCREATEROLE" "! grep -E 'CREATE ROLE' '$work/stdin' | grep -vq NOCREATEROLE"
check "fresh: the backup role gets CONNECT and USAGE" "grep -E '^GRANT (CONNECT|USAGE) ' '$work/stdin' | grep -q paddock_backup"
check "fresh: the owner owns the database" "grep -q 'ALTER DATABASE :\"db\" OWNER TO paddock_owner' '$work/stdin'"
for g in "log_min_duration_statement = -1" "log_min_duration_sample = -1" "log_transaction_sample_rate = 0" "log_statement = 'none'" "log_duration = off" "log_min_error_statement = panic"; do
  check "fresh: statements are not logged ($g)" "head -6 '$work/stdin' | grep -q \"^SET $g;\""
done
check "fresh: all ten roles reported" "grep -q 'roles provisioned: paddock_owner paddock_api .* paddock_backup' '$work/out'"

first_sql="$(cat "$work/stdin")"
run POSTGRES_DB=paddock "${cp_env[@]}"
check "re-run: identical statements (existence checks, no plain CREATE)" "[[ \"\$(cat '$work/stdin')\" == \"\$first_sql\" ]]"
check "re-run: no CREATE ROLE outside its existence check" "[[ \$(grep -c 'CREATE ROLE' '$work/stdin') == \$(grep -c 'WHERE NOT EXISTS' '$work/stdin') ]]"

secret API "rotated-aaaa"
run POSTGRES_DB=paddock "${cp_env[@]}"
check "rotation: the new password reaches psql" "grep -q 'PROVISION_PW_paddock_api=rotated-aaaa' '$work/env'"
check "rotation: the old password is gone" "! grep -q 'pw-API-first-9f3' '$work/env'"

run POSTGRES_DB=paddock "${cp_env[@]}"
rm -f "$work/secrets/NOTIFIER"
if run POSTGRES_DB=paddock "${cp_env[@]}"; then rc=0; else rc=$?; fi
check "unreadable secret file: fails hard naming the variable, not a value" "[[ \$rc != 0 ]] && grep -q 'PADDOCK_NOTIFIER_PASSWORD_FILE is set but not readable' '$work/out' && [[ ! -e '$work/stdin' ]]"
unset_env=()
for e in "${cp_env[@]}"; do [[ "$e" == PADDOCK_NOTIFIER_PASSWORD_FILE=* ]] || unset_env+=("$e"); done
run POSTGRES_DB=paddock "${unset_env[@]}"
check "missing secret: the role is skipped with a message" "grep -q 'role paddock_notifier: skipped' '$work/out'"
check "missing secret: no statement for it" "! grep -q paddock_notifier '$work/stdin'"
check "missing secret: the others are still provisioned" "grep -q 'rolname = .paddock_backup.' '$work/stdin'"

run POSTGRES_DB=paddock
check "no secret at all: nothing is run" "[[ ! -e '$work/stdin' ]] && grep -q 'nothing to provision' '$work/out'"

secret OWNER "pw-OWNER-first-9f3"
secret NOTIFIER "pw-NOTIFIER-first-9f3"
run POSTGRES_DB=paddock "${cp_env[@]}"
for f in args stdin out; do
  check "no password in $f" "! grep -q 'pw-.*-9f3\|pw-API-rotated' '$work/$f'"
done

secret AUDIT_OWNER "pw-audit-owner-1"
secret AUDIT_READER "pw-audit-reader-1"
run POSTGRES_DB=paddock_audit AUDIT_OWNER_PASSWORD_FILE="$work/secrets/AUDIT_OWNER" \
  AUDIT_READER_PASSWORD_FILE="$work/secrets/AUDIT_READER"
check "audit: the reader role is provisioned" "grep -q \"rolname = 'paddock_audit_reader'\" '$work/stdin'"
check "audit: the writer without a password file is skipped" "grep -q 'role paddock_audit_writer: skipped' '$work/out' && ! grep -q paddock_audit_writer '$work/stdin'"
check "audit: the control plane's roles are not touched" "! grep -q paddock_api '$work/stdin'"
check "audit: the owner is audit_owner" "grep -q 'OWNER TO audit_owner' '$work/stdin'"
check "audit: no password on the command line" "! grep -q 'pw-audit' '$work/args'"

secret SUPER "pw-super-1"
run POSTGRES_DB=paddock PGHOST=postgres POSTGRES_PASSWORD_FILE="$work/secrets/SUPER" "${cp_env[@]}"
check "service mode: the superuser password goes through PGPASSWORD only" "grep -q 'PGPASSWORD=pw-super-1' '$work/env' && ! grep -q 'pw-super-1' '$work/args' '$work/out'"

# The one-shot provision services connect over TCP once their database is healthy. The image's initdb runs a temporary
# server that answers on the socket only, so a socket probe can report healthy before the server listens on TCP, and
# the provision fails with "connection refused" (gate BS3 on a loaded host; decisions-alpha9 item 89). Every
# PostgreSQL healthcheck probes TCP.
for f in "$here/../compose.yaml" "$here/../compose.audit.yaml"; do
  probes="$(grep -E 'pg_isready' "$f")"
  check "$(basename "$f"): every pg_isready healthcheck probes TCP" \
    "[[ -n '$probes' ]] && ! grep -v -- '-h 127.0.0.1' <<<'$probes' | grep -q ."
done

if ((failures > 0)); then
  echo "$failures check(s) failed"
  exit 1
fi
echo "provision-roles_test: all checks passed"
