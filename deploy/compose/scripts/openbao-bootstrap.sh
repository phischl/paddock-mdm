#!/usr/bin/env bash
# Development bootstrap of OpenBao (plan M0 §6.8, M2a decision 15, M4a decision 2): init (5 shares, threshold 3),
# unseal, transit keys audit-chain, bundle-signing, command-signing, revocation-signing (M4c decision 2) and
# escrow-wrap (M4a decision 9), KV
# secret/paddock/session, policies and AppRoles. Idempotent. `openbao-bootstrap.sh unseal` only unseals.
# Production: refuses to run; follow docs/operations/openbao.md.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
. "$here/lib.sh"

require_development

BAO_DIR="$SECRETS_DIR/openbao"
INIT_FILE="$BAO_DIR/init.txt"
mode="${1:-bootstrap}"

bao() {
  compose exec -T -e BAO_ADDR=http://127.0.0.1:8200 ${BAO_TOKEN:+-e BAO_TOKEN="$BAO_TOKEN"} openbao bao "$@"
}

status() { bao status -format=json 2>/dev/null || true; }

wait_for_openbao() {
  for _ in $(seq 1 60); do
    if status | grep -q '"initialized"'; then return; fi
    sleep 1
  done
  echo "OpenBao does not answer; is the stack up (make up)?" >&2
  exit 1
}

unseal() {
  if status | grep -q '"sealed": false'; then
    echo "OpenBao is unsealed"
    return
  fi
  [[ -s "$INIT_FILE" ]] || { echo "no stored unseal shares in $INIT_FILE" >&2; exit 1; }
  for i in 1 2 3; do
    key="$(sed -n "s/^Unseal Key $i: //p" "$INIT_FILE")"
    bao operator unseal "$key" >/dev/null
  done
  status | grep -q '"sealed": false' || { echo "unseal failed" >&2; exit 1; }
  echo "OpenBao unsealed"
}

wait_for_openbao

if [[ "$mode" == "unseal" ]]; then
  unseal
  exit 0
fi

mkdir -p "$BAO_DIR"
chmod 700 "$BAO_DIR"

if status | grep -q '"initialized": false'; then
  bao operator init -key-shares=5 -key-threshold=3 >"$INIT_FILE.tmp"
  mv "$INIT_FILE.tmp" "$INIT_FILE"
  chmod 600 "$INIT_FILE"
  # Secret-ids stored for a previous OpenBao instance (e.g. after `make down V=1`) are invalid now.
  rm -f "$SECRETS_DIR"/approle/*/secret_id
  echo "OpenBao initialized; development shares and root token stored in .secrets/openbao/"
fi
unseal

BAO_TOKEN="$(sed -n 's/^Initial Root Token: //p' "$INIT_FILE")"
export BAO_TOKEN

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

for key in bundle-signing command-signing revocation-signing; do
  if ! bao read "transit/keys/$key" >/dev/null 2>&1; then
    bao write "transit/keys/$key" type=ed25519 exportable=false allow_plaintext_backup=false >/dev/null
    echo "created transit key $key"
  fi
done

if ! bao read transit/keys/escrow-wrap >/dev/null 2>&1; then
  bao write transit/keys/escrow-wrap type=rsa-4096 exportable=false allow_plaintext_backup=false >/dev/null
  echo "created transit key escrow-wrap"
fi

if ! bao kv get secret/paddock/session >/dev/null 2>&1; then
  bao kv put secret/paddock/session \
    current="$(head -c 32 /dev/urandom | base64 -w0)" \
    previous="$(head -c 32 /dev/urandom | base64 -w0)" >/dev/null
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
EOF

bao policy write paddock-compiler - >/dev/null <<'EOF'
path "transit/sign/bundle-signing" {
  capabilities = ["update"]
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

for role in paddock-api paddock-audit-writer paddock-compiler paddock-worker paddock-escrow-reader paddock-revocation-issuer; do
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

echo "OpenBao bootstrap complete"
