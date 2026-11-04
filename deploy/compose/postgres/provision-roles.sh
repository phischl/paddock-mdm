#!/usr/bin/env bash
# Provisions the PostgreSQL roles of one Paddock database, idempotently (plan M0 §6.1/§6.2, plan M16 decision 8). The
# one source of truth for both callers: the image's initdb hook (mounted as /docker-entrypoint-initdb.d/10-roles.sh,
# runs once on a new cluster) and the one-shot service db-provision (runs on every `./paddock up` and upgrade, so a role
# a release adds exists on a cluster initialized before it). Safe to run any number of times.
#
# The profile follows POSTGRES_DB: paddock_audit provisions the audit database's roles, anything else the control
# plane's. A role is provisioned when its password is available as <NAME>_PASSWORD_FILE (Compose secrets) or
# <NAME>_PASSWORD (tests); otherwise it is skipped with a message. Per run each provisioned role is created when absent
# and always gets its attributes and password set again, so a rotated secret takes effect. The role-level grants
# (CONNECT, USAGE) are here; table grants stay in the migrations.
#
# paddock_owner is the only control-plane role with BYPASSRLS: it owns the tables (FORCE ROW LEVEL SECURITY applies to
# it) and the SECURITY DEFINER function paddock_org_id_by_slug runs as paddock_owner.
#
# Passwords never appear in a command line, in this script's output or in a server log: they reach psql through its
# environment and \set, and the session turns statement logging off first. Never add `set -x` or an echo of a value.
set -euo pipefail

if [[ -n "${PGHOST:-}" && -z "${PGPASSWORD:-}" && -n "${POSTGRES_PASSWORD_FILE:-}" ]]; then
  PGPASSWORD="$(cat "$POSTGRES_PASSWORD_FILE")"
  export PGPASSWORD
fi

# role|variable prefix of the password (<prefix>_FILE)|BYPASSRLS or NOBYPASSRLS; the first entry owns the database.
if [[ "${POSTGRES_DB:?POSTGRES_DB must be set}" == paddock_audit ]]; then
  owner=audit_owner
  roles=(
    "audit_owner|AUDIT_OWNER_PASSWORD|NOBYPASSRLS"
    "paddock_audit_writer|AUDIT_WRITER_PASSWORD|NOBYPASSRLS"
    "paddock_audit_reader|AUDIT_READER_PASSWORD|NOBYPASSRLS"
  )
else
  owner=paddock_owner
  roles=(
    "paddock_owner|PADDOCK_OWNER_PASSWORD|BYPASSRLS"
    "paddock_api|PADDOCK_API_PASSWORD|NOBYPASSRLS"
    "paddock_platform|PADDOCK_PLATFORM_PASSWORD|NOBYPASSRLS"
    "paddock_relay|PADDOCK_RELAY_PASSWORD|NOBYPASSRLS"
    "paddock_worker|PADDOCK_WORKER_PASSWORD|NOBYPASSRLS"
    "paddock_compiler|PADDOCK_COMPILER_PASSWORD|NOBYPASSRLS"
    "paddock_escrow_reader|PADDOCK_ESCROW_READER_PASSWORD|NOBYPASSRLS"
    "paddock_revocation|PADDOCK_REVOCATION_PASSWORD|NOBYPASSRLS"
    "paddock_notifier|PADDOCK_NOTIFIER_PASSWORD|NOBYPASSRLS"
    "paddock_backup|PADDOCK_BACKUP_PASSWORD|NOBYPASSRLS"
  )
fi

# password prints the secret of prefix and returns 1 when neither the file nor the variable is set. A file that is set
# but unreadable returns 2 and the caller stops: skipping would silently initialize a cluster without that role.
password() {
  local var="$1" file_var="${1}_FILE"
  if [[ -n "${!file_var:-}" ]]; then
    [[ -r "${!file_var}" ]] || { echo "role secret ${file_var} is set but not readable" >&2; return 2; }
    cat "${!file_var}"
  elif [[ -n "${!var:-}" ]]; then
    printf '%s' "${!var}"
  else
    return 1
  fi
}

provisioned=()
grantees=()
# The statement text carries the password (CREATE ROLE ... PASSWORD '...'), so every setting that logs statement text
# is switched off for the session before the first password statement. pgaudit and similar extensions are outside
# what a session can disable; an operator who loads one must exclude this role's session.
sql=$'SET log_min_duration_statement = -1;\nSET log_min_duration_sample = -1;\nSET log_transaction_sample_rate = 0;\n'
sql+=$'SET log_statement = \'none\';\nSET log_duration = off;\nSET log_min_error_statement = panic;\n'
for entry in "${roles[@]}"; do
  IFS='|' read -r role prefix bypass <<<"$entry"
  rc=0
  pw="$(password "$prefix")" || rc=$?
  ((rc != 2)) || exit 1
  if ((rc != 0)); then
    echo "role $role: skipped, no password file (${prefix}_FILE is not set)"
    continue
  fi
  export "PROVISION_PW_$role=$pw"
  provisioned+=("$role")
  [[ "$role" == "$owner" ]] || grantees+=("$role")
  sql+="\\set pw_$role \`printf '%s' \"\$PROVISION_PW_$role\"\`"$'\n'
  sql+="SELECT format('CREATE ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE $bypass PASSWORD %L', '$role', :'pw_$role')"
  sql+=" WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '$role') \\gexec"$'\n'
  sql+="SELECT format('ALTER ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE $bypass PASSWORD %L', '$role', :'pw_$role') \\gexec"$'\n'
done

if ((${#provisioned[@]} == 0)); then
  echo "no role has a password file: nothing to provision"
  exit 0
fi

if [[ " ${provisioned[*]} " == *" $owner "* ]]; then
  sql+="ALTER DATABASE :\"db\" OWNER TO $owner;"$'\n'
  sql+="ALTER SCHEMA public OWNER TO $owner;"$'\n'
fi
sql+=$'REVOKE ALL ON DATABASE :"db" FROM PUBLIC;\nREVOKE ALL ON SCHEMA public FROM PUBLIC;\n'
if ((${#grantees[@]} > 0)); then
  list="$(printf '%s, ' "${grantees[@]}")"
  list="${list%, }"
  sql+="GRANT CONNECT ON DATABASE :\"db\" TO $list;"$'\n'
  sql+="GRANT USAGE ON SCHEMA public TO $list;"$'\n'
fi

printf '%s' "$sql" | psql -v ON_ERROR_STOP=1 -q --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" -v db="$POSTGRES_DB" >/dev/null
echo "roles provisioned: ${provisioned[*]}"
