#!/usr/bin/env bash
# Restore drill on the development stack (plan M6a decision 7, gate P-3, docs/operations/restore.md): take a backup,
# lose the control plane's databases and OpenBao, restore them from the backup bucket, run the restore commands of
# plan M6c decision 22 and the acceptance subset. Prints the measured RTO. Requires the stack started with
# `make up BACKUP=1` (dev-seeded); the audit store is not touched. Destroys the development databases' volumes.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
. "$here/lib.sh"

require_development

PROJECT=paddock
REPO_ROOT="$(cd "$COMPOSE_DIR/../.." && pwd)"
export PADDOCK_BACKUP_S3_ENDPOINT="${PADDOCK_BACKUP_S3_ENDPOINT:-https://backup-s3-tls:9443}"
BUCKET="${PADDOCK_BACKUP_S3_BUCKET:-paddock-backup}"
SUBSET='TestDeviceProtocol|TestLoginGate|TestAuditChain|TestOrganizationIsolation'
# The roles the drill stops; the compiler starts only after bump-bundle-seq (plan M6c decision 22).
ROLES=(paddock-api paddock-gateway paddock-worker paddock-outbox-relay paddock-escrow-reader paddock-revocation-issuer)

dc() { compose -f "$COMPOSE_DIR/compose.backup.yaml" -f "$COMPOSE_DIR/compose.backup.dev.yaml" "$@"; }
log() { printf '[%s] %s\n' "$(date -u +%H:%M:%S)" "$*"; }
psql_in() { dc exec -T "$1" psql -U "$2" -d "$3" -Atc "$4"; }

wait_recovered() {
  local svc="$1" user="$2" db="$3"
  for _ in $(seq 1 150); do
    if [[ "$(psql_in "$svc" "$user" "$db" 'select pg_is_in_recovery()' 2>/dev/null)" == f ]]; then return 0; fi
    sleep 2
  done
  echo "restore drill: $svc did not finish recovery" >&2
  exit 1
}

wait_spool_empty() {
  local svc="$1" stanza="$2"
  for _ in $(seq 1 60); do
    if [[ -z "$(dc exec -T "$svc" sh -c "ls /pgbackrest-spool/$stanza | grep -v '^restore$'" 2>/dev/null)" ]]; then return 0; fi
    sleep 2
  done
  echo "restore drill: the WAL spool of $stanza does not drain" >&2
  exit 1
}

bao() { dc exec -T -e BAO_ADDR=http://127.0.0.1:8200 ${BAO_TOKEN:+-e BAO_TOKEN="$BAO_TOKEN"} openbao bao "$@"; }

# --- 1. Backup -------------------------------------------------------------------------------------------------------
log "1. full backups and an OpenBao snapshot"
dc run --rm --no-deps pgbackrest backup
dc run --rm --no-deps pgbackrest-authentik backup
dc --profile paddock run --rm --no-deps paddock-worker backup openbao
devices_before="$(psql_in postgres postgres paddock 'select count(*) from device')"
# Everything written so far reaches the archive: the restore must bring back the latest point, not the full backup.
psql_in postgres postgres paddock 'select pg_switch_wal()' >/dev/null
psql_in authentik-postgres authentik authentik 'select pg_switch_wal()' >/dev/null
wait_spool_empty postgres paddock
wait_spool_empty authentik-postgres authentik

# --- 2. Loss ---------------------------------------------------------------------------------------------------------
start="$(date +%s)"
log "2. losing PostgreSQL, Authentik's database and OpenBao (volumes deleted)"
dc --profile paddock stop "${ROLES[@]}" paddock-compiler authentik-server authentik-worker
dc stop pgbackrest pgbackrest-authentik postgres authentik-postgres openbao
dc rm -f pgbackrest pgbackrest-authentik postgres authentik-postgres openbao
for v in postgres-data authentik-postgres-data pgbackrest-spool-paddock pgbackrest-spool-authentik \
  pgbackrest-state-paddock pgbackrest-state-authentik openbao-data; do
  docker volume rm "${PROJECT}_$v" >/dev/null
done

# --- 3. PostgreSQL ---------------------------------------------------------------------------------------------------
log "3. restoring both databases with pgBackRest (latest point)"
dc run --rm --no-deps pgbackrest restore
dc run --rm --no-deps pgbackrest-authentik restore
dc up -d --no-deps postgres authentik-postgres
wait_recovered postgres postgres paddock
wait_recovered authentik-postgres authentik authentik
devices_after="$(psql_in postgres postgres paddock 'select count(*) from device')"
[[ "$devices_after" == "$devices_before" ]] ||
  { echo "restore drill: $devices_after devices after the restore, $devices_before before" >&2; exit 1; }
dc up -d --no-deps pgbackrest pgbackrest-authentik

# --- 4. OpenBao ------------------------------------------------------------------------------------------------------
log "4. restoring the newest OpenBao snapshot into a fresh OpenBao"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
chmod 755 "$work"  # the worker image (nonroot) reads the encrypted snapshot
AWS_ACCESS_KEY_ID="$(cat "$SECRETS_DIR/backup_pgbackrest_access_key")"
AWS_SECRET_ACCESS_KEY="$(cat "$SECRETS_DIR/backup_pgbackrest_secret_key")"
export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY
aws() {
  docker run --rm --network "${PROJECT}_audit-store" -e AWS_ACCESS_KEY_ID -e AWS_SECRET_ACCESS_KEY \
    -e AWS_DEFAULT_REGION=us-east-1 -e AWS_PAGER= -v "$work:/drill" "$AWS_CLI_IMAGE" \
    --endpoint-url http://audit-rustfs:9000 "$@"
}
snapshot="$(aws s3api list-objects-v2 --bucket "$BUCKET" --prefix openbao/ --query 'max_by(Contents, &LastModified).Key' --output text)"
aws s3 cp --only-show-errors "s3://$BUCKET/$snapshot" /drill/snapshot.enc
dc up -d --no-deps openbao
for _ in $(seq 1 60); do bao status -format=json 2>/dev/null | grep -q '"initialized"' && break; sleep 1; done
# A fresh OpenBao takes the snapshot only after its own initialization; the snapshot then brings back the original
# barrier, which the stored development shares unseal.
bao operator init -key-shares=1 -key-threshold=1 -format=json >"$work/init.json"
tmp_key="$(grep -A1 '"unseal_keys_b64"' "$work/init.json" | tail -1 | tr -d ' ",')"
BAO_TOKEN="$(grep '"root_token"' "$work/init.json" | cut -d'"' -f4)"
bao operator unseal "$tmp_key" >/dev/null
for _ in $(seq 1 30); do bao status -format=json 2>/dev/null | grep -q '"sealed": false' && break; sleep 1; done
# The decrypted snapshot never touches the host's disk: the worker image decrypts it to stdout.
dc --profile paddock run --rm --no-deps -T -v "$work:/drill:ro" paddock-worker backup decrypt /drill/snapshot.enc - |
  dc exec -T openbao sh -c 'cat >/tmp/snapshot'
bao operator raft snapshot restore -force /tmp/snapshot
unset BAO_TOKEN
dc exec -T openbao rm -f /tmp/snapshot
# The restored node is sealed with the original barrier; the stored development shares unseal it.
"$here/openbao-bootstrap.sh" unseal

# --- 5. Paddock ------------------------------------------------------------------------------------------------------
log "5. starting Authentik and the roles; restore commands (plan M6c decisions 20–22)"
dc up -d --no-deps authentik-server authentik-worker
dc --profile paddock start "${ROLES[@]}"
dc stop paddock-compiler
dc --profile paddock run --rm --no-deps paddock-worker admin bump-bundle-seq --by 1000000
dc start paddock-compiler
dc --profile paddock run --rm --no-deps paddock-worker admin rebuild-cache
dc --profile paddock run --rm --no-deps paddock-worker admin recompile --all
"$here/wait-healthy.sh" --profile paddock
ready="$(date +%s)"
log "control plane ready $((ready - start)) s after the loss"

# --- 6. Acceptance subset --------------------------------------------------------------------------------------------
log "6. acceptance subset: $SUBSET"
(cd "$REPO_ROOT" && go test -count=1 -timeout 30m ./test/acceptance/... -run "$SUBSET")
done_at="$(date +%s)"
log "restore drill passed: control plane ready after $((ready - start)) s, acceptance subset green after $((done_at - start)) s (RTO)"
