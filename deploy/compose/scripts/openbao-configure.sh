#!/usr/bin/env bash
# Configures an initialized and unsealed OpenBao (plan M7b decision 17; content of plan M0 §6.8, M2a decision 15, M4a
# decisions 2 and 9, M4c decisions 2 and 14, M6a decision 5): the engines transit, secret (kv-v2) and approle, the
# transit keys audit-chain, bundle-signing, command-signing, revocation-signing, time-ticket (ed25519), escrow-wrap
# (rsa-4096) and notification-wrap (aes256-gcm96, plan M9 decision 12), the KV secret secret/paddock/session, the policies and the AppRoles, whose role_id and secret_id are
# written to .secrets/approle/<role>/ (paddock-audit-writer's directory is copied to the audit host). Idempotent: a
# stored non-empty secret_id is kept. Needs the root token in BAO_TOKEN. Development: openbao-bootstrap.sh calls it;
# production: `./paddock bootstrap openbao` after the manual init and unseal (docs/operations/openbao.md).
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
. "$here/lib.sh"

[[ -n "${BAO_TOKEN:-}" ]] || { echo "set BAO_TOKEN to the root token of OpenBao" >&2; exit 2; }
# Secrets never appear on a command line (ps, /proc): the token reaches the container by name from the environment,
# values by stdin.
export BAO_TOKEN

production=
[[ "$(env_value PADDOCK_ENV)" == development ]] || production=1

# OpenBao listens with TLS of the internal CA in production (compose.prod.yaml) and plain HTTP in development.
bao() {
  if [[ -n "$production" ]]; then
    compose exec -T -e BAO_ADDR=https://127.0.0.1:8200 -e BAO_CACERT=/run/secrets/internal_ca_bundle \
      -e BAO_TOKEN openbao bao "$@"
  else
    compose exec -T -e BAO_ADDR=http://127.0.0.1:8200 -e BAO_TOKEN openbao bao "$@"
  fi
}

# Raft needs a moment after unseal to elect itself leader.
for _ in $(seq 1 30); do
  if bao secrets list >/dev/null 2>&1; then break; fi
  sleep 1
done

bao secrets list | grep -q '^transit/' || bao secrets enable transit
bao secrets list | grep -q '^secret/' || bao secrets enable -path=secret kv-v2
bao auth list | grep -q '^approle/' || bao auth enable approle

if ! bao read transit/keys/audit-chain >/dev/null 2>&1; then
  bao write transit/keys/audit-chain type=ed25519 exportable=false allow_plaintext_backup=false >/dev/null
  echo "created transit key audit-chain"
fi

for key in bundle-signing command-signing revocation-signing time-ticket; do
  if ! bao read "transit/keys/$key" >/dev/null 2>&1; then
    bao write "transit/keys/$key" type=ed25519 exportable=false allow_plaintext_backup=false >/dev/null
    echo "created transit key $key"
  fi
done

if ! bao read transit/keys/escrow-wrap >/dev/null 2>&1; then
  bao write transit/keys/escrow-wrap type=rsa-4096 exportable=false allow_plaintext_backup=false >/dev/null
  echo "created transit key escrow-wrap"
fi

# Destination secrets of the notifications (webhook URL and signing secret, pseudonym keys): the api encrypts, the
# notifier alone decrypts (ADR 0031 decision 11).
if ! bao read transit/keys/notification-wrap >/dev/null 2>&1; then
  bao write transit/keys/notification-wrap type=aes256-gcm96 exportable=false allow_plaintext_backup=false >/dev/null
  echo "created transit key notification-wrap"
fi

if ! bao kv get secret/paddock/session >/dev/null 2>&1; then
  printf '{"current":"%s","previous":"%s"}' "$(head -c 32 /dev/urandom | base64 -w0)" \
    "$(head -c 32 /dev/urandom | base64 -w0)" | bao kv put secret/paddock/session - >/dev/null
  echo "created secret/paddock/session"
fi

bao policy write paddock-api - >/dev/null <<'EOF'
path "secret/data/paddock/session" {
  capabilities = ["read"]
}
path "transit/keys/bundle-signing" {
  capabilities = ["read"]
}
path "transit/keys/revocation-signing" {
  capabilities = ["read"]
}
path "transit/encrypt/notification-wrap" {
  capabilities = ["update"]
}
EOF

bao policy write paddock-notifier - >/dev/null <<'EOF'
path "transit/decrypt/notification-wrap" {
  capabilities = ["update"]
}
EOF

bao policy write paddock-compiler - >/dev/null <<'EOF'
path "transit/sign/bundle-signing" {
  capabilities = ["update"]
}
path "transit/sign/time-ticket" {
  capabilities = ["update"]
}
path "transit/keys/time-ticket" {
  capabilities = ["read"]
}
path "transit/keys/bundle-signing" {
  capabilities = ["read"]
}
path "transit/keys/command-signing" {
  capabilities = ["read"]
}
path "transit/keys/revocation-signing" {
  capabilities = ["read"]
}
path "transit/keys/escrow-wrap" {
  capabilities = ["read"]
}
EOF

# Used only by the api's reveal of escrowed secrets after a step-up (plan M4a decision 9).
bao policy write paddock-escrow-reader - >/dev/null <<'EOF'
path "transit/decrypt/escrow-wrap" {
  capabilities = ["update"]
}
EOF

bao policy write paddock-worker - >/dev/null <<'EOF'
path "transit/sign/command-signing" {
  capabilities = ["update"]
}
EOF

# The only role that can sign revocations (plan M4c decision 2); the api and the compiler read the public keys only.
bao policy write paddock-revocation-issuer - >/dev/null <<'EOF'
path "transit/sign/revocation-signing" {
  capabilities = ["update"]
}
path "transit/keys/revocation-signing" {
  capabilities = ["read"]
}
EOF

bao policy write paddock-audit-writer - >/dev/null <<'EOF'
path "transit/sign/audit-chain" {
  capabilities = ["update"]
}
path "transit/keys/audit-chain" {
  capabilities = ["read"]
}
EOF

# Raft snapshots for the backup (plan M6a decision 5); nothing else.
bao policy write paddock-backup - >/dev/null <<'EOF'
path "sys/storage/raft/snapshot" {
  capabilities = ["read"]
}
EOF

for role in paddock-api paddock-audit-writer paddock-compiler paddock-worker paddock-escrow-reader paddock-revocation-issuer \
  paddock-backup paddock-notifier; do
  bao write "auth/approle/role/$role" token_policies="$role" token_ttl=1h token_max_ttl=4h \
    secret_id_ttl=0 token_no_default_policy=false >/dev/null
  dir="$SECRETS_DIR/approle/$role"
  mkdir -p "$dir"
  bao read -field=role_id "auth/approle/role/$role/role-id" | tr -d '\r\n' >"$dir/role_id"
  if [[ ! -s "$dir/secret_id" ]]; then
    bao write -f -field=secret_id "auth/approle/role/$role/secret-id" | tr -d '\r\n' >"$dir/secret_id"
    echo "created AppRole secret-id for $role"
  fi
  chmod 644 "$dir/role_id" "$dir/secret_id"
done

echo "OpenBao configuration complete"
if [[ -n "$production" ]]; then
  echo "copy .secrets/approle/paddock-audit-writer/ to the audit host"
  echo "revoke the root token now: ./paddock bao token revoke -self"
fi
