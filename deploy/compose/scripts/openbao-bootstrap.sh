#!/usr/bin/env bash
# Development bootstrap of OpenBao (plan M0 §6.8, M7b decision 17): init (5 shares, threshold 3) with the shares and
# the root token stored in .secrets/openbao/init.txt, unseal, then openbao-configure.sh (keys, KV secret, policies and
# AppRoles). Idempotent. `openbao-bootstrap.sh unseal` only unseals.
# Production: refuses to run; follow docs/operations/openbao.md (manual init, then `./paddock bootstrap openbao`).
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
. "$here/lib.sh"

require_development

BAO_DIR="$SECRETS_DIR/openbao"
INIT_FILE="$BAO_DIR/init.txt"
mode="${1:-bootstrap}"

bao() {
  compose exec -T -e BAO_ADDR=http://127.0.0.1:8200 ${BAO_TOKEN:+-e BAO_TOKEN} openbao bao "$@"
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
    # On stdin: an unseal share never appears on a command line.
    printf '%s' "$key" | bao write sys/unseal key=- >/dev/null
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
  # So are the unsealer's shares of the previous instance (written again below).
  rm -f "$BAO_DIR/auto-unseal-shares"
  echo "OpenBao initialized; development shares and root token stored in .secrets/openbao/"
fi
unseal

# The development unsealer's material (plan M8u decision 17): the first three shares, one per line. 0644 inside the
# 0700 directory, as every secret file: the container's user reads it through the Compose secret.
SHARES_FILE="$BAO_DIR/auto-unseal-shares"
if [[ ! -s "$SHARES_FILE" ]]; then
  (umask 077 && for i in 1 2 3; do sed -n "s/^Unseal Key $i: //p" "$INIT_FILE"; done >"$SHARES_FILE.tmp")
  mv "$SHARES_FILE.tmp" "$SHARES_FILE"
  chmod 644 "$SHARES_FILE"
  echo "development shares of the unsealer stored in .secrets/openbao/auto-unseal-shares"
fi

BAO_TOKEN="$(sed -n 's/^Initial Root Token: //p' "$INIT_FILE")"
export BAO_TOKEN

"$here/openbao-configure.sh"
echo "OpenBao bootstrap complete"
