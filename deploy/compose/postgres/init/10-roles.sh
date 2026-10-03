#!/usr/bin/env bash
# Creates the Paddock database roles (plan M0 §6.1). Runs once on cluster initialization.
# Passwords come from <NAME>_PASSWORD_FILE (Compose secrets) or <NAME>_PASSWORD (tests).
set -euo pipefail

password() {
  local var="$1" file_var="${1}_FILE"
  if [[ -n "${!file_var:-}" ]]; then cat "${!file_var}"; else printf '%s' "${!var:?$var or $file_var must be set}"; fi
}

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
  -v owner_pw="$(password PADDOCK_OWNER_PASSWORD)" \
  -v api_pw="$(password PADDOCK_API_PASSWORD)" \
  -v platform_pw="$(password PADDOCK_PLATFORM_PASSWORD)" \
  -v relay_pw="$(password PADDOCK_RELAY_PASSWORD)" \
  -v db="$POSTGRES_DB" <<'SQL'
CREATE ROLE paddock_owner    LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE PASSWORD :'owner_pw';
CREATE ROLE paddock_api      LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS PASSWORD :'api_pw';
CREATE ROLE paddock_platform LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS PASSWORD :'platform_pw';
CREATE ROLE paddock_relay    LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS PASSWORD :'relay_pw';

ALTER DATABASE :"db" OWNER TO paddock_owner;
ALTER SCHEMA public OWNER TO paddock_owner;
REVOKE ALL ON DATABASE :"db" FROM PUBLIC;
REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT CONNECT ON DATABASE :"db" TO paddock_api, paddock_platform, paddock_relay;
GRANT USAGE ON SCHEMA public TO paddock_api, paddock_platform, paddock_relay;
SQL
