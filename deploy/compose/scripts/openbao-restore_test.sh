#!/usr/bin/env bash
# Test of openbao-restore.sh (`make test`, needs Docker): a snapshot of an OpenBao initialized with 5 shares
# (threshold 3) is restored into a fresh OpenBao, which then unseals with the original shares and serves the original
# data. Throwaway containers on their own network; the target answers to "openbao" like the stack's, which is the
# setup in which the restored node kept the temporary seal configuration until it restarted.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=openbao-restore.sh
. "$here/openbao-restore.sh"
image="$(grep '^OPENBAO_IMAGE=' "$here/../versions.env" | cut -d= -f2-)"
id="paddock-openbao-restore-test-$$"
work="$(mktemp -d)"
cleanup() {
  docker rm -f "$id-src" "$id-dst" >/dev/null 2>&1 || true
  docker network rm "$id" >/dev/null 2>&1 || true
  docker volume rm "$id-src" "$id-dst" >/dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT

docker network create "$id" >/dev/null
start() { # start <name> <volume> [network alias]
  docker run -d --name "$1" --network "$id" ${3:+--network-alias "$3"} --cap-add IPC_LOCK -v "$2:/openbao/file" \
    -v "$here/../openbao/config.hcl:/openbao/config/config.hcl:ro" -v "$here/../openbao/dev.hcl:/openbao/config/dev.hcl:ro" \
    "$image" bao server -config=/openbao/config/config.hcl -config=/openbao/config/dev.hcl >/dev/null
}
target=""
bao() { docker exec -i -e BAO_ADDR=http://127.0.0.1:8200 ${BAO_TOKEN:+-e BAO_TOKEN="$BAO_TOKEN"} "$target" bao "$@"; }
bao_restart() { docker restart "$target" >/dev/null; }

# Source: 5 shares, threshold 3, one secret, a snapshot.
start "$id-src" "$id-src"
target="$id-src"
openbao_wait
bao operator init -key-shares=5 -key-threshold=3 >"$work/init.txt"
for i in 1 2 3; do bao operator unseal "$(sed -n "s/^Unseal Key $i: //p" "$work/init.txt")" >/dev/null; done
openbao_unsealed
root="$(sed -n 's/^Initial Root Token: //p' "$work/init.txt")"
for _ in $(seq 1 30); do BAO_TOKEN="$root" bao secrets enable -path=restore-test kv >/dev/null 2>&1 && break; sleep 1; done
BAO_TOKEN="$root" bao kv put restore-test/probe value=original >/dev/null
BAO_TOKEN="$root" bao operator raft snapshot save /tmp/snapshot
docker exec "$id-src" cat /tmp/snapshot >"$work/snapshot"

# Target: a fresh OpenBao named openbao, restored right after its temporary unseal as in the drill.
start "$id-dst" "$id-dst" openbao
target="$id-dst"
openbao_wait
docker exec -i "$id-dst" sh -c 'cat >/tmp/snapshot' <"$work/snapshot"
openbao_restore_snapshot "$work" "$work/init.txt"
got="$(BAO_TOKEN="$root" bao kv get -field=value restore-test/probe)"
if [[ "$got" != original ]]; then
  echo "FAIL restored secret: got $got"
  exit 1
fi
echo "ok   snapshot restored into a fresh OpenBao and unsealed with the original shares"
