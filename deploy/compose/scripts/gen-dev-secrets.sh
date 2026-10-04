#!/usr/bin/env bash
# Generates random secrets for local development into deploy/compose/.secrets/.
# Idempotent: existing files are never overwritten.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
. "$here/lib.sh"

require_development

umask 022
mkdir -p "$SECRETS_DIR"
chmod 700 "$SECRETS_DIR"

rand() { head -c 32 /dev/urandom | base64 -w0 | tr '+/' '-_' | tr -d '='; }

# secret <name> [value] writes a secret file unless it exists. Files are world-readable inside the 0700 directory
# so that containers running with their own UIDs can read the bind-mounted file.
secret() {
  local f="$SECRETS_DIR/$1"
  if [[ ! -s "$f" ]]; then
    printf '%s' "${2:-$(rand)}" >"$f"
    chmod 644 "$f"
    echo "created .secrets/$1"
  fi
}
read_secret() { cat "$SECRETS_DIR/$1"; }

if [[ ! -f "$COMPOSE_DIR/.env" ]]; then
  cp "$COMPOSE_DIR/.env.example" "$COMPOSE_DIR/.env"
  echo "created deploy/compose/.env from .env.example"
fi

# Control-plane PostgreSQL
secret postgres_superuser_password
for role in paddock_owner paddock_api paddock_platform paddock_relay paddock_worker paddock_compiler; do
  secret "db_${role}_password"
  secret "db_${role}_url" "postgres://${role}:$(read_secret "db_${role}_password")@postgres:5432/paddock?sslmode=disable"
done

# Audit PostgreSQL
secret audit_postgres_superuser_password
for role in audit_owner paddock_audit_writer paddock_audit_reader; do
  secret "db_${role}_password"
  secret "db_${role}_url" "postgres://${role}:$(read_secret "db_${role}_password")@audit-postgres:5432/paddock_audit?sslmode=disable"
done

# Authentik
secret authentik_postgres_password
secret authentik_secret_key "$(rand)$(rand)"
secret authentik_bootstrap_token
secret authentik_bootstrap_password
secret authentik_service_token
secret oidc_client_secret

# Audit object store
secret rustfs_audit_root_user
secret rustfs_audit_root_password
secret rustfs_audit_writer_access_key
secret rustfs_audit_writer_secret_key

# Control-plane object store (bundles)
secret rustfs_root_user
secret rustfs_root_password
for role in compiler gateway; do
  secret "rustfs_bundles_${role}_access_key"
  secret "rustfs_bundles_${role}_secret_key"
done
# Agent artifacts (plan M2b decision 19): the api uploads; the gateway presigns with its bundles credential.
secret rustfs_artifacts_api_access_key
secret rustfs_artifacts_api_secret_key

# Valkey: one password; the server reads it through an included config file.
secret valkey_password
mkdir -p "$SECRETS_DIR/valkey"
secret valkey/auth.conf "requirepass $(read_secret valkey_password)"

# RabbitMQ. The definitions file is derived from the passwords and the template, so it is rewritten whenever the
# template gains users; RabbitMQ imports it again on the next start (definitions.skip_if_unchanged).
for user in provisioner relay audit_writer gateway worker compiler; do
  secret "rabbitmq_${user}_password"
done
mkdir -p "$SECRETS_DIR/rabbitmq"
definitions="$(sed -e "s|@PROVISIONER_PASSWORD@|$(read_secret rabbitmq_provisioner_password)|" \
    -e "s|@RELAY_PASSWORD@|$(read_secret rabbitmq_relay_password)|" \
    -e "s|@AUDIT_WRITER_PASSWORD@|$(read_secret rabbitmq_audit_writer_password)|" \
    -e "s|@GATEWAY_PASSWORD@|$(read_secret rabbitmq_gateway_password)|" \
    -e "s|@WORKER_PASSWORD@|$(read_secret rabbitmq_worker_password)|" \
    -e "s|@COMPILER_PASSWORD@|$(read_secret rabbitmq_compiler_password)|" \
    "$COMPOSE_DIR/rabbitmq/definitions.json.tmpl")"
if [[ "$definitions" != "$(cat "$SECRETS_DIR/rabbitmq/definitions.json" 2>/dev/null)" ]]; then
  printf '%s\n' "$definitions" >"$SECRETS_DIR/rabbitmq/definitions.json"
  chmod 644 "$SECRETS_DIR/rabbitmq/definitions.json"
  echo "wrote .secrets/rabbitmq/definitions.json"
fi

# Development test users (Authentik)
for user in platform_admin alice bob carol; do
  secret "dev_${user}_password"
done

# Placeholder for the Caddy root certificate; the caddy-ca-export service overwrites it.
[[ -e "$SECRETS_DIR/caddy-root.crt" ]] || { : >"$SECRETS_DIR/caddy-root.crt"; chmod 666 "$SECRETS_DIR/caddy-root.crt"; }

# AppRole credential directories are filled by openbao-bootstrap.sh; they must exist for the bind mounts.
for role in paddock-api paddock-audit-writer paddock-compiler; do
  mkdir -p "$SECRETS_DIR/approle/$role"
  for f in role_id secret_id; do
    [[ -e "$SECRETS_DIR/approle/$role/$f" ]] || { : >"$SECRETS_DIR/approle/$role/$f"; chmod 644 "$SECRETS_DIR/approle/$role/$f"; }
  done
done

echo "development secrets ready in deploy/compose/.secrets/"
