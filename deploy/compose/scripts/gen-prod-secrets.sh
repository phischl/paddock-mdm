#!/usr/bin/env bash
# Generates the production secrets of one host into deploy/compose/.secrets/ (plan M6a decision 3):
#   gen-prod-secrets.sh controlplane|audit
# Idempotent: existing files are never overwritten. Prints file names only, never a secret. Two values cross the hosts
# and are copied by the operator (docs/operations/install.md): the audit reader's database password (audit host →
# control plane) and the audit writer's RabbitMQ password (control plane → audit host); the internal CA certificates
# (public) travel both ways. AppRole credentials, the Fleet API token and the release public keys are written during
# the installation; `make prod-check` fails until they are there.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
. "$here/lib.sh"

HOST="${1:-}"
if [[ "$HOST" != controlplane && "$HOST" != audit ]]; then
  echo "usage: $0 controlplane|audit" >&2
  exit 2
fi
if [[ ! -f "$COMPOSE_DIR/.env" ]]; then
  cp "$COMPOSE_DIR/prod.env.example" "$COMPOSE_DIR/.env"
  echo "created deploy/compose/.env from prod.env.example: set the domain, the e-mail and the interconnect addresses, then run again"
  exit 1
fi
if [[ "$(env_value PADDOCK_ENV)" != production ]]; then
  echo "refusing to run: PADDOCK_ENV in deploy/compose/.env is not production" >&2
  exit 1
fi
INTERCONNECT="$(env_value PADDOCK_INTERCONNECT_ADDR)"
if [[ -z "$INTERCONNECT" ]]; then
  echo "set PADDOCK_INTERCONNECT_ADDR (this host's address on the private interconnect) in deploy/compose/.env" >&2
  exit 1
fi
command -v openssl >/dev/null || { echo "openssl is required" >&2; exit 1; }

umask 077
mkdir -p "$SECRETS_DIR"
chmod 700 "$SECRETS_DIR"

rand() { head -c 32 /dev/urandom | base64 -w0 | tr '+/' '-_' | tr -d '='; }

# secret <name> [value] writes a secret file unless it exists. Mode 0644 inside the 0700 directory: no other user of
# the host can reach it, while containers running with their own UIDs read the bind-mounted file.
secret() {
  local f="$SECRETS_DIR/$1"
  mkdir -p "$(dirname "$f")"
  if [[ ! -s "$f" ]]; then
    printf '%s' "${2:-$(rand)}" >"$f"
    chmod 644 "$f"
    echo "created .secrets/$1"
  fi
}
read_secret() { cat "$SECRETS_DIR/$1"; }
placeholder() {
  local f="$SECRETS_DIR/$1"
  mkdir -p "$(dirname "$f")"
  [[ -e "$f" ]] || { : >"$f"; chmod 644 "$f"; echo "created empty .secrets/$1 (filled during the installation)"; }
}

# Internal CA of this host (plan M6a amendment 2026-10-08): it signs the TLS certificates of this host's endpoints on
# the interconnect. Its key never leaves the host; the peer host trusts its certificate (bundle.crt holds both CAs).
CA_DIR="$SECRETS_DIR/internal-ca"
mkdir -p "$CA_DIR" "$SECRETS_DIR/tls"
if [[ ! -s "$CA_DIR/ca.key" ]]; then
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 3650 \
    -subj "/CN=Paddock internal CA ($HOST)" -keyout "$CA_DIR/ca.key" -out "$CA_DIR/ca.crt" 2>/dev/null
  chmod 600 "$CA_DIR/ca.key"
  chmod 644 "$CA_DIR/ca.crt"
  echo "created .secrets/internal-ca/ca.crt (copy it to the other host as .secrets/internal-ca/peer-ca.crt)"
fi

# cert <name> <SAN list> issues a server certificate of the internal CA.
cert() {
  local name="$1" san="$2" dir="$SECRETS_DIR/tls"
  [[ -s "$dir/$name.crt" ]] && return
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=$name" \
    -keyout "$dir/$name.key" -out "$dir/$name.csr" 2>/dev/null
  openssl x509 -req -in "$dir/$name.csr" -CA "$CA_DIR/ca.crt" -CAkey "$CA_DIR/ca.key" -CAcreateserial -days 825 \
    -extfile <(printf 'subjectAltName=%s\nextendedKeyUsage=serverAuth\n' "$san") -out "$dir/$name.crt" 2>/dev/null
  rm -f "$dir/$name.csr"
  chmod 644 "$dir/$name.crt" "$dir/$name.key"
  echo "created .secrets/tls/$name.crt"
}

if [[ "$HOST" == controlplane ]]; then
  cert openbao "DNS:openbao,IP:127.0.0.1,IP:$INTERCONNECT"
  cert rabbitmq "DNS:rabbitmq,IP:$INTERCONNECT"

  secret postgres_superuser_password
  for role in paddock_owner paddock_api paddock_platform paddock_relay paddock_worker paddock_compiler \
    paddock_escrow_reader paddock_revocation; do
    secret "db_${role}_password"
    # Local to this host's internal network.
    secret "db_${role}_url" "postgres://${role}:$(read_secret "db_${role}_password")@postgres:5432/paddock?sslmode=disable"
  done
  if [[ -s "$SECRETS_DIR/db_paddock_audit_reader_password" ]]; then
    audit_addr="$(env_value PADDOCK_AUDIT_ADDR)"
    [[ -n "$audit_addr" ]] || { echo "set PADDOCK_AUDIT_ADDR in deploy/compose/.env" >&2; exit 1; }
    secret db_paddock_audit_reader_url \
      "postgres://paddock_audit_reader:$(read_secret db_paddock_audit_reader_password)@${audit_addr}:5432/paddock_audit?sslmode=verify-full&sslrootcert=/run/secrets/internal_ca_bundle"
  else
    echo "missing .secrets/db_paddock_audit_reader_password: copy it from the audit host and run again"
  fi

  secret authentik_postgres_password
  secret authentik_secret_key "$(rand)$(rand)"
  secret authentik_bootstrap_token
  secret authentik_bootstrap_password
  secret authentik_service_token
  secret oidc_client_secret

  secret rustfs_root_user
  secret rustfs_root_password
  for role in compiler gateway; do
    secret "rustfs_bundles_${role}_access_key"
    secret "rustfs_bundles_${role}_secret_key"
  done
  secret rustfs_artifacts_api_access_key
  secret rustfs_artifacts_api_secret_key
  for role in worker api revocation; do
    secret "rustfs_escrow_${role}_access_key"
    secret "rustfs_escrow_${role}_secret_key"
  done
  secret escrow_reader_token
  secret valkey_password
  secret valkey/auth.conf "requirepass $(read_secret valkey_password)"

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

  secret fleet_mysql_root_password
  secret fleet_mysql_password
  secret fleet_redis_password
  secret fleet-redis/auth.conf "requirepass $(read_secret fleet_redis_password)"
  secret fleet_server_private_key
  secret fleet_admin_password "$(rand)1!"
  secret fleet_enroll_secret
  placeholder fleet_api_token

  for role in paddock-api paddock-compiler paddock-worker paddock-escrow-reader paddock-revocation-issuer; do
    placeholder "approle/$role/role_id"
    placeholder "approle/$role/secret_id"
  done
  mkdir -p "$SECRETS_DIR/release-production"
  [[ -s "$SECRETS_DIR/release-production/minisign.pub" ]] ||
    echo "copy the production release public keys to .secrets/release-production/{minisign,revoke-minisign}.pub"
  echo "copy .secrets/rabbitmq_audit_writer_password to the audit host"
else
  cert audit-postgres "DNS:audit-postgres,IP:$INTERCONNECT"

  secret audit_postgres_superuser_password
  for role in audit_owner paddock_audit_writer paddock_audit_reader; do
    secret "db_${role}_password"
  done
  # Local to the audit host; the api's reader URL is built on the control plane (verify-full).
  for role in audit_owner paddock_audit_writer; do
    secret "db_${role}_url" "postgres://${role}:$(read_secret "db_${role}_password")@audit-postgres:5432/paddock_audit?sslmode=disable"
  done
  secret rustfs_audit_root_user
  secret rustfs_audit_root_password
  secret rustfs_audit_writer_access_key
  secret rustfs_audit_writer_secret_key
  placeholder approle/paddock-audit-writer/role_id
  placeholder approle/paddock-audit-writer/secret_id
  [[ -s "$SECRETS_DIR/rabbitmq_audit_writer_password" ]] ||
    echo "missing .secrets/rabbitmq_audit_writer_password: copy it from the control-plane host"
  echo "copy .secrets/db_paddock_audit_reader_password to the control-plane host"
fi

# Both internal CAs: this host's and, once copied, the peer host's.
bundle="$(cat "$CA_DIR/ca.crt")"
[[ -s "$CA_DIR/peer-ca.crt" ]] && bundle="$bundle"$'\n'"$(cat "$CA_DIR/peer-ca.crt")"
if [[ "$bundle" != "$(cat "$CA_DIR/bundle.crt" 2>/dev/null)" ]]; then
  printf '%s\n' "$bundle" >"$CA_DIR/bundle.crt"
  chmod 644 "$CA_DIR/bundle.crt"
  echo "wrote .secrets/internal-ca/bundle.crt"
fi
[[ -s "$CA_DIR/peer-ca.crt" ]] || echo "missing .secrets/internal-ca/peer-ca.crt: copy ca.crt of the other host and run again"

echo "production secrets of the $HOST host ready in deploy/compose/.secrets/"
