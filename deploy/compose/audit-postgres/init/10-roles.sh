#!/usr/bin/env bash
# Creates the audit database roles (plan M0 §6.2). Runs once on cluster initialization.
# Passwords come from <NAME>_PASSWORD_FILE (Compose secrets) or <NAME>_PASSWORD (tests).
set -euo pipefail

password() {
  local var="$1" file_var="${1}_FILE"
  if [[ -n "${!file_var:-}" ]]; then cat "${!file_var}"; else printf '%s' "${!var:?$var or $file_var must be set}"; fi
}

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
  -v owner_pw="$(password AUDIT_OWNER_PASSWORD)" \
  -v writer_pw="$(password AUDIT_WRITER_PASSWORD)" \
  -v reader_pw="$(password AUDIT_READER_PASSWORD)" \
  -v db="$POSTGRES_DB" <<'SQL'
CREATE ROLE audit_owner          LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE PASSWORD :'owner_pw';
CREATE ROLE paddock_audit_writer LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS PASSWORD :'writer_pw';
CREATE ROLE paddock_audit_reader LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS PASSWORD :'reader_pw';

ALTER DATABASE :"db" OWNER TO audit_owner;
ALTER SCHEMA public OWNER TO audit_owner;
REVOKE ALL ON DATABASE :"db" FROM PUBLIC;
REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT CONNECT ON DATABASE :"db" TO paddock_audit_writer, paddock_audit_reader;
GRANT USAGE ON SCHEMA public TO paddock_audit_writer, paddock_audit_reader;
SQL
