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

# set_env <name> <value> sets a setting in .env, in place when the file has it.
set_env() {
  if grep -q "^$1=" "$COMPOSE_DIR/.env"; then
    sed -i "s|^$1=.*|$1=$2|" "$COMPOSE_DIR/.env"
  else
    printf '%s=%s\n' "$1" "$2" >>"$COMPOSE_DIR/.env"
  fi
}

# instance_env <n> makes the new .env the one of the n-th development stack of this host: its own Compose project
# (volumes, networks, containers) and image tags, and every host port 100·(n−1) above the first stack's, so that it
# runs next to that stack from a second checkout (docs/operations/local-dev.md, "Running a second dev stack").
instance_env() {
  local n="$1" off=$((($1 - 1) * 100)) domain var
  domain="$(sed -n 's/^PADDOCK_DOMAIN=//p' "$COMPOSE_DIR/.env" | tail -1)"
  printf '\n# Development stack instance %s of this host (PADDOCK_INSTANCE=%s make dev-secrets).\n' "$n" "$n" \
    >>"$COMPOSE_DIR/.env"
  set_env PADDOCK_INSTANCE "$n"
  set_env PADDOCK_PROJECT "paddock$n"
  set_env PADDOCK_IMAGE "paddock-server:dev-$n"
  set_env PADDOCK_COMPILER_IMAGE "paddock-compiler:dev-$n"
  set_env PADDOCK_PGBACKREST_IMAGE "paddock-pgbackrest:dev-$n"
  set_env PADDOCK_HTTPS_PORT $((8443 + off))
  set_env PADDOCK_HTTPS_UNTRUSTED_PORT $((8444 + off))
  set_env PADDOCK_PUBLIC_ADMIN_URL "https://admin.${domain:-paddock.localhost}:$((8443 + off))"
  set_env PADDOCK_PUBLIC_DEVICE_URL "https://device.${domain:-paddock.localhost}:$((8443 + off))"
  for var in POSTGRES=5432 AUDIT_POSTGRES=5433 RABBITMQ=5672 RABBITMQ_MANAGEMENT=15672 VALKEY=6379 OPENBAO=8200 \
    AUDIT_S3=9001 FLEET=8412 PROMETHEUS=9091; do
    set_env "PADDOCK_DEV_${var%%=*}_PORT" $((${var#*=} + off))
  done
}

if [[ -n "${PADDOCK_INSTANCE:-}" && ! "$PADDOCK_INSTANCE" =~ ^[1-9]$ ]]; then
  echo "PADDOCK_INSTANCE must be a number from 1 to 9 (is '$PADDOCK_INSTANCE')" >&2
  exit 2
fi
if [[ ! -f "$COMPOSE_DIR/.env" ]]; then
  cp "$COMPOSE_DIR/.env.example" "$COMPOSE_DIR/.env"
  echo "created deploy/compose/.env from .env.example"
  if [[ "${PADDOCK_INSTANCE:-1}" != 1 ]]; then
    instance_env "$PADDOCK_INSTANCE"
    echo "deploy/compose/.env: development stack instance $PADDOCK_INSTANCE (project paddock$PADDOCK_INSTANCE)"
  fi
fi
# The worker does not start without the audit index retention (compose.yaml), which a .env copied from an older
# .env.example lacks. Without it the audit writer uses its WORM retention, so the backfill takes that value and keeps
# what the stack's index retention already was.
if ! grep -q '^PADDOCK_AUDIT_INDEX_RETENTION_DAYS=' "$COMPOSE_DIR/.env"; then
  index_days="$(sed -n 's/^PADDOCK_AUDIT_RETENTION_DAYS=//p' "$COMPOSE_DIR/.env" | tail -1)"
  [[ "$index_days" =~ ^[0-9]+$ ]] || index_days=400
  set_env PADDOCK_AUDIT_INDEX_RETENTION_DAYS "$index_days"
  echo "deploy/compose/.env: added PADDOCK_AUDIT_INDEX_RETENTION_DAYS=$index_days"
fi

# Control-plane PostgreSQL
secret postgres_superuser_password
for role in paddock_owner paddock_api paddock_platform paddock_relay paddock_worker paddock_compiler paddock_escrow_reader \
  paddock_revocation paddock_unsealer; do
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
# Disk escrow (plan M4b decision 13): the worker verifies uploaded headers, the api reads them for a recovery; the
# gateway presigns header uploads with its bundles credential.
# The revocation-issuer deletes every header version of a destroyed device (plan M4c decision 9).
for role in worker api revocation; do
  secret "rustfs_escrow_${role}_access_key"
  secret "rustfs_escrow_${role}_secret_key"
done

# Bearer secret between paddock-api and paddock-escrow-reader (plan M4b.1 decision 6); delete the file and run
# make dev-secrets up to rotate it.
secret escrow_reader_token

# Valkey: one password; the server reads it through an included config file.
secret valkey_password
mkdir -p "$SECRETS_DIR/valkey"
secret valkey/auth.conf "requirepass $(read_secret valkey_password)"

# RabbitMQ. The definitions file is derived from the passwords and the template, so it is rewritten whenever the
# template gains users; RabbitMQ imports it again on the next start (definitions.skip_if_unchanged).
for user in provisioner relay audit_writer gateway worker compiler revocation_issuer; do
  secret "rabbitmq_${user}_password"
done
mkdir -p "$SECRETS_DIR/rabbitmq"
definitions="$(sed -e "s|@PROVISIONER_PASSWORD@|$(read_secret rabbitmq_provisioner_password)|" \
    -e "s|@RELAY_PASSWORD@|$(read_secret rabbitmq_relay_password)|" \
    -e "s|@AUDIT_WRITER_PASSWORD@|$(read_secret rabbitmq_audit_writer_password)|" \
    -e "s|@GATEWAY_PASSWORD@|$(read_secret rabbitmq_gateway_password)|" \
    -e "s|@WORKER_PASSWORD@|$(read_secret rabbitmq_worker_password)|" \
    -e "s|@COMPILER_PASSWORD@|$(read_secret rabbitmq_compiler_password)|" \
    -e "s|@REVOCATION_ISSUER_PASSWORD@|$(read_secret rabbitmq_revocation_issuer_password)|" \
    "$COMPOSE_DIR/rabbitmq/definitions.json.tmpl")"
if [[ "$definitions" != "$(cat "$SECRETS_DIR/rabbitmq/definitions.json" 2>/dev/null)" ]]; then
  printf '%s\n' "$definitions" >"$SECRETS_DIR/rabbitmq/definitions.json"
  chmod 644 "$SECRETS_DIR/rabbitmq/definitions.json"
  echo "wrote .secrets/rabbitmq/definitions.json"
fi

# Development test users (Authentik) and the keys of their TOTP authenticators (hex, 20 bytes), which `make dev-seed`
# installs so that the acceptance gates can complete step-up authentications (plan M4a decision 8).
for user in platform_admin alice bob carol dave; do
  secret "dev_${user}_password"
  secret "dev_${user}_totp_key" "$(head -c 20 /dev/urandom | od -An -tx1 | tr -d ' \n')"
done

# Fleet (plan M5a decision 1). Fleet requires a number and a symbol in the admin password. The API token of the
# API-only user paddock is written by fleet-bootstrap.sh; the empty file must exist for the bind mounts.
secret fleet_mysql_root_password
secret fleet_mysql_password
secret fleet_redis_password
mkdir -p "$SECRETS_DIR/fleet-redis"
secret fleet-redis/auth.conf "requirepass $(read_secret fleet_redis_password)"
secret fleet_server_private_key
secret fleet_admin_password "$(rand)1!"
secret fleet_enroll_secret
[[ -e "$SECRETS_DIR/fleet_api_token" ]] || { : >"$SECRETS_DIR/fleet_api_token"; chmod 644 "$SECRETS_DIR/fleet_api_token"; }

# Backups (plan M6a decisions 4–6; compose.backup.yaml, `make up BACKUP=1`): bucket paddock-backup on audit-rustfs,
# one credential each for pgBackRest, the worker's OpenBao snapshots and the Fleet dump, and the encryption key.
secret backup_encryption_key "$(head -c 32 /dev/urandom | base64 -w0)"
for role in pgbackrest worker fleet; do
  secret "backup_${role}_access_key"
  secret "backup_${role}_secret_key"
done

# Placeholder for the Caddy root certificate; the caddy-ca-export service overwrites it.
[[ -e "$SECRETS_DIR/caddy-root.crt" ]] || { : >"$SECRETS_DIR/caddy-root.crt"; chmod 666 "$SECRETS_DIR/caddy-root.crt"; }

# AppRole credential directories are filled by openbao-bootstrap.sh; they must exist for the bind mounts.
for role in paddock-api paddock-audit-writer paddock-compiler paddock-worker paddock-escrow-reader \
  paddock-revocation-issuer paddock-backup; do
  mkdir -p "$SECRETS_DIR/approle/$role"
  for f in role_id secret_id; do
    [[ -e "$SECRETS_DIR/approle/$role/$f" ]] || { : >"$SECRETS_DIR/approle/$role/$f"; chmod 644 "$SECRETS_DIR/approle/$role/$f"; }
  done
done

echo "development secrets ready in deploy/compose/.secrets/"
