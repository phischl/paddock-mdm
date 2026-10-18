#!/usr/bin/env bash
# Creates the PostgreSQL role paddock_unsealer of the automatic unseal of OpenBao (ADR 0035, plan M8u decision 17),
# idempotently: every other role is created once at cluster initialization (postgres/init/10-roles.sh), this one may
# be added to a cluster initialized before it existed. Sets the password of .secrets/db_paddock_unsealer_password and
# grants SELECT and the UPDATE of the report columns on openbao_auto_unseal when the table exists; migration 00050
# grants the same when it runs after the role exists. Run by `make up` and `./paddock auto-unseal enable`.
#
# The password reaches psql through the container's environment and psql's \set, never a command line.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
. "$here/lib.sh"

password_file="$SECRETS_DIR/db_paddock_unsealer_password"
[[ -s "$password_file" ]] || {
  echo "missing $password_file: run the secrets generation first (make dev-secrets or ./paddock secrets)" >&2
  exit 1
}
UNSEALER_PASSWORD="$(cat "$password_file")"
export UNSEALER_PASSWORD

ready=""
for _ in $(seq 1 60); do
  if compose exec -T postgres pg_isready -U postgres -d paddock </dev/null >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 1
done
[[ -n "$ready" ]] || { echo "PostgreSQL does not answer within 60 s" >&2; exit 1; }

compose exec -T -e UNSEALER_PASSWORD postgres psql -v ON_ERROR_STOP=1 -q -U postgres -d paddock >/dev/null <<'SQL'
\set pw `printf '%s' "$UNSEALER_PASSWORD"`
SELECT format('CREATE ROLE paddock_unsealer LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS PASSWORD %L', :'pw')
  WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'paddock_unsealer') \gexec
SELECT format('ALTER ROLE paddock_unsealer PASSWORD %L', :'pw') \gexec
GRANT CONNECT ON DATABASE paddock TO paddock_unsealer;
GRANT USAGE ON SCHEMA public TO paddock_unsealer;
SELECT 'GRANT SELECT ON openbao_auto_unseal TO paddock_unsealer'
  WHERE to_regclass('public.openbao_auto_unseal') IS NOT NULL \gexec
SELECT 'GRANT UPDATE (unsealer_seen_at, unsealer_shares_present, unseal_count, last_unseal_at, failure_count, last_failure_at, last_failure_reason, updated_at) ON openbao_auto_unseal TO paddock_unsealer'
  WHERE to_regclass('public.openbao_auto_unseal') IS NOT NULL \gexec
SQL
echo "PostgreSQL role paddock_unsealer is ready"
