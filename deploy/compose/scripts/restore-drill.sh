#!/usr/bin/env bash
# Restore drill on the development stack (plan M15 decision 30 and §9 B8, docs/operations/restore.md): back up every
# kind, wait until the local development target holds the set, lose PostgreSQL, Authentik's database, OpenBao, Fleet's
# MySQL and the local backup repository, rebuild the repository from the target and run restore_run of restore.sh
# (the code ./paddock restore runs), then the acceptance subset. Prints the measured RTO. Requires the stack started
# with `make up BACKUP=1` and `make dev-seed BACKUP=1` (which confirms a backup key); the audit store is not touched.
# Destroys the development volumes named above.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export BACKUP=1
# shellcheck source=lib.sh
. "$here/lib.sh"

PROJECT="$PADDOCK_PROJECT"
# Stricter than require_development: .env only, no production secrets, no production overlay in the running stack.
mapfile -t running_files < <(docker ps -a --filter "label=com.docker.compose.project=$PROJECT" \
  --format '{{.Label "com.docker.compose.project.config_files"}}' | tr ',' '\n' | sort -u)
"$here/restore-drill-guard.sh" "$COMPOSE_DIR" "${running_files[@]}"
REPO_ROOT="$(cd "$COMPOSE_DIR/../.." && pwd)"
SUBSET='TestDeviceProtocol|TestLoginGate|TestAuditChain|TestOrganizationIsolation'
TARGET=dev-local

# The development stack: plain HTTP to OpenBao, the stored development shares, the profiles of `make up`.
export RESTORE_BAO_ADDR=http://127.0.0.1:8200 RESTORE_BAO_CACERT="" RESTORE_PROFILES=paddock
export RESTORE_UNSEAL_INIT_FILE="$SECRETS_DIR/openbao/init.txt"
# shellcheck source=restore.sh
. "$here/restore.sh"

log() { printf '[%s] %s\n' "$(date -u +%H:%M:%S)" "$*"; }
psql_in() { compose exec -T "$1" psql -U "$2" -d "$3" -Atc "$4" </dev/null; }

work="$(mktemp -d)"
# Expanded now: restore_run runs this trap after a failed step, inside functions whose locals may be named work.
# shellcheck disable=SC2064
trap "rm -rf '$work'" EXIT
export RESTORE_KEY_FILE="$work/backup_encryption_key"

# --- 1. Backup -------------------------------------------------------------------------------------------------------
log "1. the confirmed backup key, every kind backed up, the set on the target $TARGET"
# The backup role hands the decrypted key to pgBackRest in the runtime tmpfs; the drill takes it from there, as an
# operator types it from the offline copy.
# The role writes the file in its next round (15 s on the development stack) after a key was confirmed.
for _ in $(seq 1 60); do
  (umask 077 && compose exec -T pgbackrest cat /run/paddock-backup/key >"$RESTORE_KEY_FILE" 2>/dev/null </dev/null) && break
  rm -f "$RESTORE_KEY_FILE"
  sleep 1
done
[[ -s "$RESTORE_KEY_FILE" ]] || { echo "restore drill: no confirmed backup key; run make dev-seed BACKUP=1 or confirm one" \
  "in the portal (Platform → Backup)" >&2; exit 1; }
target_id="$(psql_in postgres postgres paddock "select id from backup_target where name = '$TARGET' and deleted_at is null")"
[[ "$target_id" =~ ^[0-9a-f-]{36}$ ]] || { echo "restore drill: no backup target $TARGET (make dev-seed BACKUP=1)" >&2; exit 1; }
target_set="/backup-targets/$target_id/paddock-backup"
devices_before="$(psql_in postgres postgres paddock 'select count(*) from device')"
compose --profile paddock run --rm --no-deps -T paddock-backup backup now --wait </dev/null
# Everything written so far reaches the archive: the restore must bring back the latest point, not the full backup.
psql_in postgres postgres paddock 'select pg_switch_wal()' >/dev/null
psql_in authentik-postgres authentik authentik 'select pg_switch_wal()' >/dev/null
switched="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
for _ in $(seq 1 60); do
  generated="$(compose --profile paddock run --rm --no-deps -T -e PADDOCK_LOG_LEVEL=error paddock-backup \
    backup manifest "$target_set" </dev/null 2>/dev/null | sed -n 's/^generated_at=//p' || true)"
  # Two rounds after the WAL switch: the first may have listed the repository before the segments arrived.
  if [[ -n "$generated" && "$(date -u -d "$generated" +%s)" -gt "$(($(date -u -d "$switched" +%s) + 30))" ]]; then break; fi
  sleep 5
done
[[ -n "$generated" && "$(date -u -d "$generated" +%s)" -gt "$(($(date -u -d "$switched" +%s) + 30))" ]] ||
  { echo "restore drill: the target $TARGET did not receive the set within 5 minutes" >&2; exit 1; }

# --- 2. Loss ---------------------------------------------------------------------------------------------------------
start="$(date +%s)"
log "2. losing PostgreSQL, Authentik's database, OpenBao, Fleet's MySQL and the local backup repository"
compose --profile paddock rm -sf postgres authentik-postgres pgbackrest pgbackrest-authentik openbao fleet fleet-mysql \
  fleet-backup paddock-backup
for v in postgres-data authentik-postgres-data pgbackrest-spool-paddock pgbackrest-spool-authentik \
  pgbackrest-state-paddock pgbackrest-state-authentik openbao-data fleet-mysql-data backup-repo; do
  docker volume rm "${PROJECT}_$v" >/dev/null
done

# --- 3. Restore ------------------------------------------------------------------------------------------------------
log "3. the local repository rebuilt from $TARGET, then restore_run"
compose --profile paddock run --rm --no-deps -T paddock-backup backup fetch-set --dir "$target_set" /backup-repo </dev/null
restore_run fresh repo <<<"restore"
# PDK-831: the escrow step runs in backup-restore-escrow against the audit index and ends with its summary line; without
# the count, restore_escrow did not reach the audit index's Destroy evidence and the drill is not a valid one.
[[ "${RESTORE_ESCROW_SKIPPED:-}" =~ ^[0-9]+$ ]] ||
  { echo "restore drill: the escrow step printed no summary (backup-restore-escrow, audit index)" >&2; exit 1; }
log "escrow: $RESTORE_ESCROW_SKIPPED headers of destroyed devices kept out"
# The decrypted key is not needed for the acceptance subset; restore_run kept this script's trap for the failure paths.
rm -rf "$work"
ready="$(date +%s)"
devices_after="$(psql_in postgres postgres paddock 'select count(*) from device')"
[[ "$devices_after" == "$devices_before" ]] ||
  { echo "restore drill: $devices_after devices after the restore, $devices_before before" >&2; exit 1; }
log "control plane ready $((ready - start)) s after the loss"

# --- 4. Acceptance subset --------------------------------------------------------------------------------------------
log "4. acceptance subset: $SUBSET"
(cd "$REPO_ROOT" && go test -count=1 -timeout 30m ./test/acceptance/... -run "$SUBSET")
done_at="$(date +%s)"
log "restore drill passed: control plane ready after $((ready - start)) s, acceptance subset green after $((done_at - start)) s (RTO)"
