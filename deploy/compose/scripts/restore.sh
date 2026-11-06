# Restore of the control plane from a backup set (plan M15 decisions 23–24, amendment 2026-11-05 A5; replaces the
# manual steps of docs/operations/restore.md). Sourced, not executed: by ./paddock restore (restore_main) and by the
# restore drill (restore-drill.sh, restore_run). Needs lib.sh (compose, env_value, SECRETS_DIR, COMPOSE_DIR).
# shellcheck shell=bash
#
# Every step prints what it does and the run stops at the first error, naming the component. The backup key is read
# from RESTORE_KEY_FILE (./paddock restore: .secrets/restore/backup_key, which no Compose file mounts) and reaches the
# containers on stdin only: never on a command line, in a log, in a mounted file or in the Compose configuration.
# Nothing is stopped or changed before the preflight passed and the operator typed "restore". The library keeps the
# caller's EXIT trap: it runs after the restore's own cleanup.
#
# Settings (environment; the drill sets the development ones):
#   RESTORE_KEY_FILE          the backup key file (0600)
#   RESTORE_BAO_ADDR          OpenBao inside its container (default https://127.0.0.1:8200)
#   RESTORE_BAO_CACERT        its CA file inside the container (default /run/secrets/internal_ca_bundle; empty: none)
#   RESTORE_UNSEAL_INIT_FILE  development only: unseal with the shares of this `bao operator init` output
#   RESTORE_UNSEAL_TIMEOUT    seconds to wait for the unseal (default 900, as ./paddock up waits)
#   RESTORE_SET_UID           owner of the staging directory (default 999, the backup role's and pgBackRest's uid)
#   RESTORE_PROFILES          the Compose profiles the restored stack runs with (default: paddock observability, as
#                             ./paddock up)

# A failing command inside $(...) stops the run like any other (staging, the manifest, the plan).
shopt -s inherit_errexit

restore_here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=openbao-restore.sh
. "$restore_here/openbao-restore.sh"

RESTORE_COMPONENTS_ALL=(postgres openbao fleet escrow)
read -r -a RESTORE_PROFILE_ARGS <<<"$(for p in ${RESTORE_PROFILES:-paddock observability}; do printf -- '--profile %s ' "$p"; done)"
RESTORE_STAGING="$COMPOSE_DIR/restore-staging"
RESTORE_REPO_PATH_RE='^pgbackrest/(bk-[0-9]{8}-[0-9a-f]{8}|legacy)$'
RESTORE_UUID_RE='^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
# The key ./paddock restore asks for: a path of its own, never the legacy Compose secret backup_encryption_key that
# compose.backup.yaml mounts into paddock-api.
RESTORE_KEY_PATH=restore/backup_key

restore_usage() {
  cat >&2 <<'EOF'
usage: ./paddock restore --plan <id> [--keep-key-file]
       ./paddock restore --from <set directory|paddock-backup-set-*.tar> [--at <time>] [--only <component>]...
                         [--keep-key-file]
       ./paddock restore --from-target-file <file> [--at <time>] [--only <component>]... [--keep-key-file]
       ./paddock restore --only backup-repo --from <target name|set directory|tar> | --from-target-file <file>

  --plan <id>               execute a restore plan a platform administrator approved in the portal
  --from <path>             a backup set: its directory (a mounted share's paddock-backup/) or its tarball
  --from-target-file <file> the S3 target file ./paddock backup-target export wrote before the loss
  --at <time>               restore to this point (RFC 3339, e.g. 2026-11-04T10:00:00Z); default: the latest
  --only <component>        postgres, openbao, fleet, escrow (repeatable; default all four), or backup-repo alone:
                            rebuild the local backup repository from a target, touching no database
  --keep-key-file           keep .secrets/restore/backup_key after the run (default: deleted)

The command asks for the backup key (not echoed), checks it and the set, prints what it will do and waits for the
typed word "restore". It replaces the volumes of the chosen components. docs/operations/restore.md describes it.
EOF
  return 2
}

# restore_wait_healthy and restore_bootstrap_buckets run the stack's own scripts (functions, so restore_test.sh can
# replace them).
restore_wait_healthy() { "$restore_here/wait-healthy.sh" "${RESTORE_PROFILE_ARGS[@]}"; }
restore_bootstrap_buckets() {
  "$restore_here/rustfs-bundles-bootstrap.sh" </dev/null
  if [[ "$(env_value PADDOCK_HOST)" == lab ]]; then
    compose up -d --no-deps audit-rustfs
    restore_wait_service_healthy audit-rustfs
    "$restore_here/rustfs-audit-bootstrap.sh" </dev/null
  fi
}

restore_log() { printf '[restore %s] %s\n' "$(date -u +%H:%M:%S)" "$*"; }

restore_die() {
  echo "restore: $1" >&2
  exit "${2:-1}"
}

# restore_has <component>: the run includes the component.
restore_has() {
  local c
  for c in "${RESTORE_ONLY[@]}"; do [[ "$c" == "$1" ]] && return 0; done
  return 1
}

# restore_backup_run [run options...] -- <paddock-server arguments...>: a one-off container of the backup role's image.
restore_backup_run() {
  local opts=()
  while [[ "$1" != -- ]]; do
    opts+=("$1")
    shift
  done
  shift
  # Errors only: the commands print their results on stdout, where the role's JSON log lines would mix in.
  compose --profile paddock run --rm --no-deps -T -e PADDOCK_LOG_LEVEL=error "${opts[@]}" paddock-backup "$@"
}

# restore_admin <arguments...>: paddock-server admin in a one-off worker (plan M6c decision 22).
restore_admin() { compose --profile paddock run --rm --no-deps -T paddock-worker admin "$@" </dev/null; }

# restore_volume_rm <name>: deletes the project's volume, if it exists.
restore_volume_rm() {
  local v="${PADDOCK_PROJECT}_$1"
  if docker volume inspect "$v" >/dev/null 2>&1; then
    restore_log "deleting volume $v"
    docker volume rm "$v" >/dev/null
  fi
}

# restore_set_opts: the run options and the container path of the source set (RESTORE_SET_DIR).
restore_set_opts() {
  if [[ "$RESTORE_SOURCE" == repo ]]; then
    RESTORE_SET_MOUNT=()
    RESTORE_SET_DIR=/backup-repo
  else
    RESTORE_SET_MOUNT=(-v "$RESTORE_SOURCE:/restore-set:ro")
    RESTORE_SET_DIR=/restore-set
  fi
}

# restore_normalize_at <time>: the RFC 3339 time in UTC as YYYY-MM-DDTHH:MM:SSZ; fails on anything else.
restore_normalize_at() {
  [[ "$1" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?(Z|[+-][0-9]{2}:[0-9]{2})$ ]] || return 1
  date -u -d "$1" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null
}

# restore_key_fingerprint <file>: the first 16 hex characters of the SHA-256 of the 32 raw key bytes (backupset
# .Fingerprint); fails for anything that is not a 32-byte base64 key. The key travels through a pipe only.
restore_key_fingerprint() {
  local n
  n="$(base64 -d <"$1" 2>/dev/null | wc -c)" || return 1
  [[ "$n" == 32 ]] || return 1
  base64 -d <"$1" | sha256sum | cut -c1-16
}

# restore_read_set: reads the set's manifest through the backup role's image into RESTORE_SET (name → value).
restore_read_set() {
  local line out
  declare -gA RESTORE_SET=()
  if ! out="$(restore_backup_run "${RESTORE_SET_MOUNT[@]}" -- backup manifest ${RESTORE_AT:+--at "$RESTORE_AT"} \
    "$RESTORE_SET_DIR" </dev/null)"; then
    printf '%s\n' "$out" >&2
    restore_die "the backup set's manifest.json is missing or invalid"
  fi
  while IFS= read -r line; do
    [[ "$line" == *=* ]] && RESTORE_SET["${line%%=*}"]="${line#*=}"
  done <<<"$out"
}

# restore_preflight: everything that can be checked before a change (plan M15 decision 23 step 1). Fails closed.
restore_preflight() {
  local fp name have v bundle stanza oldest
  if [[ -n "$RESTORE_AT" ]] && (($(date -u -d "$RESTORE_AT" +%s) > $(date -u +%s))); then
    restore_die "--at $RESTORE_AT is in the future; nothing was changed"
  fi
  [[ -f "$RESTORE_KEY_FILE" ]] || restore_die "no backup key file $RESTORE_KEY_FILE"
  fp="$(restore_key_fingerprint "$RESTORE_KEY_FILE")" || restore_die "the backup key is not 44 base64 characters (32 bytes)"
  restore_set_opts
  restore_read_set
  [[ "${RESTORE_SET[key_fingerprint]:-}" =~ ^[0-9a-f]{16}$ ]] || restore_die "the manifest names no key fingerprint"
  if [[ "${RESTORE_SET[key_fingerprint]}" != "$fp" ]]; then
    restore_die "the backup set was made with key ${RESTORE_SET[key_id]:-?} (fingerprint ${RESTORE_SET[key_fingerprint]}), the key entered has fingerprint $fp; nothing was changed"
  fi
  [[ "${RESTORE_SET[repo_path]:-}" =~ $RESTORE_REPO_PATH_RE ]] || restore_die "the manifest names no pgBackRest repository"
  declare -A bundle_schema=()
  while read -r name v; do
    [[ "$name" =~ ^[a-z][a-z0-9_]*$ && "$v" =~ ^[0-9]+$ ]] && bundle_schema["$name"]="$v"
  done < <(restore_backup_run -- migrate --version </dev/null) || true
  ((${#bundle_schema[@]} > 0)) || restore_die "cannot read the schema versions of this bundle (paddock-server migrate --version)"
  for name in "${!RESTORE_SET[@]}"; do
    [[ "$name" == schema.* ]] || continue
    have="${RESTORE_SET[$name]}"
    bundle="${bundle_schema[${name#schema.}]:-}"
    if [[ -z "$bundle" || ! "$have" =~ ^[0-9]+$ ]] || ((have > bundle)); then
      restore_die "the backup set's ${name#schema.} schema is version $have, this bundle knows up to ${bundle:-none}: restore with the bundle of version ${RESTORE_SET[server_version]:-of the set} or newer; nothing was changed"
    fi
  done
  if restore_has postgres; then
    [[ -n "${RESTORE_SET[schema.paddock]:-}" ]] ||
      restore_die "the backup set names no paddock schema version; nothing was changed"
    for stanza in paddock authentik; do
      [[ ",${RESTORE_SET[stanzas]:-}," == *",$stanza,"* ]] ||
        restore_die "the backup set holds no pgBackRest backup of $stanza in ${RESTORE_SET[repo_path]}"
      [[ -n "$RESTORE_AT" ]] || continue
      oldest="${RESTORE_SET[oldest.$stanza]:-}"
      # pgBackRest restores a point only from a backup that started before it; checked here, the volumes stay.
      if [[ -z "$oldest" ]] || (($(date -u -d "$oldest" +%s) > $(date -u -d "$RESTORE_AT" +%s))); then
        restore_die "the oldest backup of $stanza started at ${oldest:-?}, after $RESTORE_AT: that point cannot be restored; nothing was changed"
      fi
    done
  fi
  if restore_has openbao && [[ -z "${RESTORE_SET[openbao]:-}" ]]; then
    restore_die "the backup set holds no OpenBao snapshot${RESTORE_AT:+ at or before $RESTORE_AT}"
  fi
  if restore_has fleet && [[ -z "${RESTORE_SET[fleet]:-}" ]]; then
    restore_die "the backup set holds no Fleet dump${RESTORE_AT:+ at or before $RESTORE_AT}"
  fi
}

# restore_unseal_path: how the restored OpenBao is unsealed.
restore_unseal_path() {
  if [[ -n "${RESTORE_UNSEAL_INIT_FILE:-}" ]]; then
    echo "development shares"
  elif [[ "$(env_value PADDOCK_AUTO_UNSEAL)" == yes && -e "$SECRETS_DIR/openbao/auto-unseal-shares" ]]; then
    echo "automatic unseal (the shares file of this host)"
  else
    echo "three custodians with their unseal shares (have them ready)"
  fi
}

# restore_confirm: prints what the run will do and waits for the typed word "restore" (plan M15 decision 24).
restore_confirm() {
  local answer=""
  echo "Restore on this host ($(hostname 2>/dev/null || echo unknown), project $PADDOCK_PROJECT):"
  echo "  source:      ${RESTORE_SOURCE_LABEL}"
  if [[ "${RESTORE_ONLY[*]}" != backup-repo ]]; then
    echo "  backup set:  generated ${RESTORE_SET[generated_at]:-?}, key ${RESTORE_SET[key_id]:-?}, installation ${RESTORE_SET[installation_id]:-?}"
    echo "  point:       ${RESTORE_AT:-latest}"
  fi
  echo "  components:  ${RESTORE_ONLY[*]}"
  restore_has postgres && echo "  PostgreSQL:  replaces the volumes of postgres and authentik-postgres (${RESTORE_SET[repo_path]})"
  restore_has openbao && echo "  OpenBao:     replaces openbao-data with ${RESTORE_SET[openbao]}; unseal: $(restore_unseal_path)"
  # Stopping the databases' writers stops OpenBao too (restore_stop_writers), so it comes back sealed (decision 23 step 1).
  if restore_has postgres && ! restore_has openbao; then
    echo "  OpenBao:     is stopped and comes back sealed (data unchanged); unseal: $(restore_unseal_path)"
  fi
  restore_has fleet && echo "  Fleet:       replaces fleet-mysql-data with ${RESTORE_SET[fleet]}"
  restore_has escrow && echo "  escrow:      puts ${RESTORE_SET[escrow]:-0} escrowed headers back where the bucket lacks them"
  restore_has backup-repo && echo "  backup-repo: empties the local backup repository and copies the set into it"
  IFS= read -r -p 'Type "restore" to continue: ' answer || true
  [[ "$answer" == restore ]] || restore_die "not confirmed; nothing was changed"
}

# restore_operator: the operator's name for the audit event ($SUDO_USER, else $USER).
restore_operator() {
  local who="${SUDO_USER:-${USER:-}}"
  [[ "$who" =~ ^[A-Za-z0-9._@-]{1,64}$ ]] || who=unknown
  printf '%s' "$who"
}

# restore_report <outcome> [failed component]: records the run (paddock-server backup restore-report, plan M15 decision
# 23 step 8). Only "running" is required to succeed; a completed or failed run that cannot be recorded is reported on
# the terminal and returns 1, and the caller goes on, because the data is restored either way.
restore_report() {
  local outcome="$1" component="${2:-}" args
  args=(backup restore-report --outcome "$outcome" --operator "$(restore_operator)" --source "$RESTORE_SOURCE_KIND"
    --components "$(IFS=,; echo "${RESTORE_ONLY[*]}")")
  [[ -n "$RESTORE_PLAN" ]] && args+=(--plan "$RESTORE_PLAN")
  [[ -n "$RESTORE_AT" ]] && args+=(--at "$RESTORE_AT")
  [[ -n "$component" ]] && args+=(--component "$component" --detail "the step $component failed")
  if restore_backup_run -- "${args[@]}" </dev/null; then
    restore_log "recorded the restore as $outcome"
    return 0
  fi
  [[ "$outcome" == running ]] && return 1
  echo "restore: WARNING: the restore could not be recorded as $outcome (platform.restore_$outcome); record it by hand in the change log" >&2
  return 1
}

# restore_failure_help <step> <recorded: yes|no>: the host's state after a failed step and what the operator does next.
restore_failure_help() {
  if restore_has backup-repo; then
    cat >&2 <<HELP
restore: no database was touched, but the local backup repository is empty or partly copied. pgBackRest and the
  backup role are stopped: no backup runs, and the databases' WAL piles up in pgBackRest's spool until they run again.
  - Fix the cause shown above, then run the same ./paddock restore command again: it empties the repository, copies
    the set into it again and starts pgBackRest and the backup role.
HELP
    return 0
  fi
  if [[ "$1" == start ]]; then
    echo "restore: the run stopped before its first step; nothing on the host was changed and the stack runs as before." >&2
  else
    cat >&2 <<HELP
restore: the host is half restored. The writers of ${RESTORE_ONLY[*]} are stopped; the steps before $1 replaced
  their volumes, the step $1 and the ones after it did not finish.
  - Do not run ./paddock up on these volumes: the stack would start on partly restored data.
  - Fix the cause shown above, then run the same ./paddock restore command again: it restores every chosen component
    from the backup set again.
HELP
  fi
  if [[ -n "$RESTORE_PLAN" && "$2" == yes ]]; then
    echo "  - The plan $RESTORE_PLAN is recorded as failed: plan the restore again in the portal, or restore with --from." >&2
  elif [[ -n "$RESTORE_PLAN" && "$1" == start ]]; then
    cat >&2 <<HELP
  - The run was interrupted while it marked the plan $RESTORE_PLAN as running, so it may still be approved or may be
    running. Check it in the portal. If it is approved, nothing needs recording. If it is running, abandon it in the
    portal or record the failure: ./paddock compose --profile paddock run --rm --no-deps -T paddock-backup backup
    restore-report --outcome failed --plan $RESTORE_PLAN --operator $(restore_operator) --source $RESTORE_SOURCE_KIND
    --components $(IFS=,; echo "${RESTORE_ONLY[*]}") --component start --detail "the step start failed"
HELP
  elif [[ -n "$RESTORE_PLAN" ]]; then
    cat >&2 <<HELP
  - The failure could not be recorded, so the plan $RESTORE_PLAN stays running and blocks a new plan. Once PostgreSQL
    runs, record it: ./paddock compose --profile paddock run --rm --no-deps -T paddock-backup backup restore-report
    --outcome failed --plan $RESTORE_PLAN --operator $(restore_operator) --source $RESTORE_SOURCE_KIND
    --components $(IFS=,; echo "${RESTORE_ONLY[*]}") --component $1 --detail "the step $1 failed"
HELP
  fi
}

# restore_cleanup: deletes the entered key (unless --keep-key-file), the run's working directory and the staged set.
restore_cleanup() {
  restore_key_cleanup
  [[ -z "${RESTORE_WORK:-}" ]] || rm -rf "$RESTORE_WORK"
  RESTORE_WORK=""
  # A second try: a staging writer that got no signal of its own (`compose run` or tar) may still have been ending.
  if [[ -n "${RESTORE_STAGED:-}" ]] && ! rm -rf "$RESTORE_STAGED" 2>/dev/null && ! { sleep 1 && rm -rf "$RESTORE_STAGED"; }; then
    echo "restore: WARNING: could not delete the staged set $RESTORE_STAGED; delete it by hand" >&2
  fi
  RESTORE_STAGED=""
}

# _restore_on_exit deletes the key and the caller's key copy (restore_trap_chain) before the failure report, which
# takes seconds: a signal during the report must not end the handler with the key still on disk (decisions-alpha9
# item 38, "deleted on every exit"). INT, TERM and HUP are caught for the rest of the handler, not ignored: an ignored
# signal would be inherited by the report's compose run, which then could not be interrupted. errexit is off here: a
# failing cleanup command must not end the handler before the report (Review 3, R3-m1).
_restore_on_exit() {
  local status=$? recorded=yes
  set +e
  trap : INT TERM HUP
  restore_cleanup
  restore_trap_chain
  if ((status != 0)) && [[ -n "${RESTORE_COMPONENT:-}" && -z "${RESTORE_REPORTED:-}" ]]; then
    RESTORE_REPORTED=1
    if [[ -n "${RESTORE_SIGNAL:-}" ]]; then
      echo "restore: the step $RESTORE_COMPONENT was interrupted (SIG$RESTORE_SIGNAL); the run stopped there" >&2
    else
      echo "restore: the step $RESTORE_COMPONENT failed (exit $status); the run stopped there" >&2
    fi
    # The trap runs before the running report's exit status is used, so whether this run started the plan is unknown:
    # an automatic failed report could close another run's plan or a lapsed approved one (PDK-837, Review 1 M1).
    if [[ "$RESTORE_COMPONENT" == start ]]; then
      recorded=no
    else
      restore_report failed "$RESTORE_COMPONENT" || recorded=no
    fi
    restore_failure_help "$RESTORE_COMPONENT" "$recorded"
  fi
  return "$status"
}

# restore_trap_set: makes _restore_on_exit the EXIT trap and keeps the caller's trap, which runs after it (the drill
# deletes its key copy there). Fails when the trap is ours already, so only the outermost installer resets it. In a
# ( ) subshell bash still reports the parent's trap, which no longer runs there: such a caller sets or clears its
# trap inside the subshell first.
restore_trap_set() {
  local current
  current="$(trap -p EXIT)"
  [[ "$current" != *_restore_on_exit* ]] || return 1
  RESTORE_CALLER_TRAP="$current"
  RESTORE_CALLER_SIGNAL_TRAPS="$(trap -p INT TERM HUP)"
  RESTORE_SIGNAL=""
  trap _restore_on_exit EXIT
  trap 'restore_on_signal INT 130' INT
  trap 'restore_on_signal TERM 143' TERM
  trap 'restore_on_signal HUP 129' HUP
}

# restore_on_signal <name> <status>: marks the run as ended by a signal and exits with 128+n. Without it bash runs the
# EXIT trap of a signal with $? of the last finished command, often 0, and a step in progress went unreported
# (Review 3, R3-M1). While a foreground command runs, bash defers the trap until it ends: a staging copy that got
# no signal of its own finishes before the cleanup deletes it.
restore_on_signal() {
  RESTORE_SIGNAL="$1"
  exit "$2"
}

# restore_trap_reset: puts the caller's EXIT, INT, TERM and HUP traps back.
restore_trap_reset() {
  if [[ -n "${RESTORE_CALLER_TRAP:-}" ]]; then eval "$RESTORE_CALLER_TRAP"; else trap - EXIT; fi
  trap - INT TERM HUP
  [[ -z "${RESTORE_CALLER_SIGNAL_TRAPS:-}" ]] || eval "$RESTORE_CALLER_SIGNAL_TRAPS"
  RESTORE_CALLER_TRAP="" RESTORE_CALLER_SIGNAL_TRAPS=""
}

# restore_trap_chain: runs the caller's EXIT trap command (`trap -p` prints it as trap -- '<command>' EXIT). It may
# run inside a failed step's function, whose locals shadow the caller's variables: a caller's trap names its paths
# expanded, not by variable.
restore_trap_chain() {
  local quoted="${RESTORE_CALLER_TRAP:-}" command=""
  RESTORE_CALLER_TRAP=""
  [[ -n "$quoted" ]] || return 0
  quoted="${quoted#trap -- }"
  eval "command=${quoted% EXIT}"
  eval "$command"
}

# restore_stop_writers: stops what writes to the chosen components (step 2).
restore_stop_writers() {
  RESTORE_COMPONENT=stop
  if restore_has postgres || restore_has openbao; then
    restore_flush_wal
    restore_log "stopping the Paddock roles, Authentik, pgBackRest and the backup role"
    compose --profile paddock stop
    compose --profile paddock stop authentik-server authentik-worker pgbackrest pgbackrest-authentik paddock-backup
  fi
  if restore_has fleet; then
    restore_log "stopping Fleet and removing its database container"
    compose --profile paddock stop fleet fleet-backup paddock-backup
    compose rm -sf fleet-mysql
    restore_volume_rm fleet-mysql-data
  fi
  if restore_has escrow; then
    compose --profile paddock stop paddock-backup
  fi
  if restore_has backup-repo; then
    restore_log "stopping pgBackRest and the backup role"
    compose --profile paddock stop pgbackrest pgbackrest-authentik paddock-backup
  fi
}

# restore_flush_wal: on a running system, pushes the WAL written so far before the databases go (best effort: a
# restore to the latest point then loses at most the last archive_timeout).
restore_flush_wal() {
  restore_has postgres || return 0
  [[ -n "$(compose ps -q --status running postgres 2>/dev/null)" ]] || return 0
  restore_log "pushing the newest WAL of the running databases"
  compose exec -T postgres psql -U postgres -d paddock -Atc 'select pg_switch_wal()' </dev/null >/dev/null 2>&1 || true
  compose exec -T authentik-postgres psql -U authentik -d authentik -Atc 'select pg_switch_wal()' </dev/null >/dev/null 2>&1 || true
  sleep 5
  compose run --rm --no-deps -T pgbackrest flush </dev/null || restore_log "warning: the WAL flush of paddock failed"
  compose run --rm --no-deps -T pgbackrest-authentik flush </dev/null || restore_log "warning: the WAL flush of authentik failed"
}

# The pgBackRest one-off of the restore: the key arrives on stdin and lives in the container's tmpfs only; schedule.env
# names the set's repository path (run.sh restore reads both like the backup role's runtime files).
# shellcheck disable=SC2016
RESTORE_PG_SCRIPT='set -euo pipefail
umask 077
mkdir -p "$PADDOCK_BACKUP_RUNTIME_DIR"
cat >"$PADDOCK_BACKUP_RUNTIME_DIR/key"
printf "PADDOCK_BACKUP_REPO_PATH=%s\nPADDOCK_BACKUP_RETENTION_FULL=1\nPADDOCK_BACKUP_FULL_INTERVAL_S=86400\n" "$1" \
  >"$PADDOCK_BACKUP_RUNTIME_DIR/schedule.env"
shift
exec /usr/local/bin/paddock-pgbackrest restore "$@"'

# restore_wait_recovered <service> <user> <database>
restore_wait_recovered() {
  local deadline=$((SECONDS + ${RESTORE_RECOVERY_TIMEOUT:-1800}))
  while ((SECONDS < deadline)); do
    if [[ "$(compose exec -T "$1" psql -U "$2" -d "$3" -Atc 'select pg_is_in_recovery()' </dev/null 2>/dev/null)" == f ]]; then
      return 0
    fi
    sleep 2
  done
  echo "restore: $1 did not finish its recovery" >&2
  return 1
}

# restore_postgres: both stanzas from the set's repository path, to the latest point or --at (step 3).
restore_postgres() {
  local svc pg_at=()
  RESTORE_COMPONENT=postgres
  restore_log "PostgreSQL: emptying the databases' volumes"
  compose --profile paddock rm -sf postgres authentik-postgres pgbackrest pgbackrest-authentik
  for v in postgres-data authentik-postgres-data pgbackrest-spool-paddock pgbackrest-spool-authentik \
    pgbackrest-state-paddock pgbackrest-state-authentik; do
    restore_volume_rm "$v"
  done
  if [[ "$RESTORE_SOURCE" != repo ]]; then
    restore_log "PostgreSQL: copying ${RESTORE_SET[repo_path]} of the set into the local repository"
    restore_backup_run "${RESTORE_SET_MOUNT[@]}" -- backup fetch-set --dir "$RESTORE_SET_DIR" \
      --path "${RESTORE_SET[repo_path]}/" --no-clobber /backup-repo </dev/null
  fi
  [[ -n "$RESTORE_AT" ]] && pg_at=(--at "$(date -u -d "$RESTORE_AT" '+%Y-%m-%d %H:%M:%S+00')")
  for svc in pgbackrest pgbackrest-authentik; do
    restore_log "PostgreSQL: pgbackrest restore with $svc (${RESTORE_AT:-latest point})"
    compose run --rm --no-deps -T --entrypoint bash -e PADDOCK_BACKUP_RUNTIME_DIR=/tmp/restore-runtime "$svc" \
      -c "$RESTORE_PG_SCRIPT" restore "${RESTORE_SET[repo_path]}" "${pg_at[@]}" <"$RESTORE_KEY_FILE"
  done
  restore_log "PostgreSQL: starting both databases; they replay the staged WAL"
  compose up -d --no-deps postgres authentik-postgres
  restore_wait_recovered postgres postgres paddock
  restore_wait_recovered authentik-postgres authentik authentik
  restore_log "PostgreSQL: both databases recovered"
}

# restore_decrypt <set path>: the plain content of a sealed file of the set on stdout (backup decrypt in the backup
# role's image; the key on stdin).
restore_decrypt() {
  restore_backup_run "${RESTORE_SET_MOUNT[@]}" -e PADDOCK_BACKUP_ENCRYPTION_KEY_FILE=/dev/stdin -- \
    backup decrypt "$RESTORE_SET_DIR/$1" - <"$RESTORE_KEY_FILE"
}

# bao and bao_restart for openbao-restore.sh; BAO_TOKEN reaches the container by name only.
bao() {
  local env=(-e BAO_ADDR) ca="${RESTORE_BAO_CACERT-/run/secrets/internal_ca_bundle}"
  [[ -z "$ca" ]] || env+=(-e BAO_CACERT)
  [[ -z "${BAO_TOKEN:-}" ]] || env+=(-e BAO_TOKEN)
  (
    export BAO_ADDR="${RESTORE_BAO_ADDR:-https://127.0.0.1:8200}" BAO_CACERT="$ca"
    compose exec -T "${env[@]}" openbao bao "$@"
  )
}
bao_restart() { compose restart openbao >/dev/null; }

# restore_wait_unsealed: waits until OpenBao reports unsealed, up to RESTORE_UNSEAL_TIMEOUT.
restore_wait_unsealed() {
  local deadline=$((SECONDS + ${RESTORE_UNSEAL_TIMEOUT:-900}))
  while ((SECONDS < deadline)); do
    if openbao_status | grep -q '"sealed": false'; then return 0; fi
    sleep 5
  done
  echo "restore: OpenBao is still sealed after ${RESTORE_UNSEAL_TIMEOUT:-900} s" >&2
  return 1
}

# restore_unseal: unseals OpenBao by the host's unseal path and waits until it reports unsealed.
restore_unseal() {
  local i
  if [[ -n "${RESTORE_UNSEAL_INIT_FILE:-}" ]]; then
    for i in 1 2 3; do
      openbao_unseal "$(sed -n "s/^Unseal Key $i: //p" "$RESTORE_UNSEAL_INIT_FILE")"
    done
  elif [[ "$(restore_unseal_path)" == automatic* ]]; then
    restore_log "OpenBao: starting the automatic unseal"
    compose --profile paddock up -d --no-deps paddock-unsealer
  else
    restore_log "OpenBao: sealed. Three custodians unseal it now, each in another terminal:" \
      "./paddock bao operator unseal (waiting up to $((${RESTORE_UNSEAL_TIMEOUT:-900} / 60)) minutes)"
  fi
  restore_wait_unsealed
  restore_log "OpenBao: unsealed"
}

# restore_openbao: the chosen snapshot into a fresh OpenBao, then the unseal path (step 4). Only this component ever
# initializes an OpenBao, and only the fresh one whose volume it has just emptied.
restore_openbao() {
  RESTORE_COMPONENT=openbao
  restore_log "OpenBao: replacing openbao-data with ${RESTORE_SET[openbao]}"
  compose --profile paddock rm -sf openbao
  restore_volume_rm openbao-data
  compose up -d --no-deps openbao
  openbao_wait
  # The plain snapshot goes from the decrypting container straight into OpenBao's: it never touches the host's disk.
  restore_decrypt "${RESTORE_SET[openbao]}" | compose exec -T openbao sh -c 'cat >/tmp/snapshot'
  openbao_restore_sealed "$RESTORE_WORK"
  compose exec -T openbao rm -f /tmp/snapshot </dev/null
  restore_unseal
}

# restore_wait_service_healthy <service>
restore_wait_service_healthy() {
  local deadline=$((SECONDS + 600))
  while ((SECONDS < deadline)); do
    [[ "$(compose ps --format '{{.Health}}' "$1" 2>/dev/null)" == healthy ]] && return 0
    sleep 2
  done
  echo "restore: $1 did not become healthy" >&2
  return 1
}

# restore_paddock: brings the stack back and, after a database restore, runs the restore commands in their binding
# order (step 5; plan M6c decisions 20–22). The backup role starts last, once the escrow headers are back, so its
# first escrow listing is not taken from a bucket still being refilled.
restore_paddock() {
  local scale=(--scale paddock-compiler=0 --scale paddock-backup=0)
  RESTORE_COMPONENT=paddock
  restore_has fleet && scale+=(--scale fleet=0 --scale fleet-backup=0)
  if [[ "$RESTORE_MODE" == fresh ]]; then
    restore_log "buckets: creating them where missing (a fresh installation's RustFS is empty)"
    compose up -d --no-deps rustfs
    restore_wait_service_healthy rustfs
    restore_bootstrap_buckets
  fi
  restore_log "starting the stack without the compiler and the backup role"
  compose "${RESTORE_PROFILE_ARGS[@]}" up -d "${scale[@]}"
  # The postgres step's `compose --profile paddock stop` stopped OpenBao as well; restore_openbao unseals its own.
  if restore_has postgres && ! restore_has openbao; then restore_unseal; fi
  if restore_has postgres; then
    restore_log "restore commands: bump-bundle-seq, compiler, rebuild-cache, recompile"
    restore_admin bump-bundle-seq --by 1000000
    compose --profile paddock up -d --no-deps paddock-compiler
    restore_admin rebuild-cache
    restore_admin recompile --all
  else
    compose --profile paddock up -d --no-deps paddock-compiler
  fi
}

# The Fleet one-off: the dump arrives on stdin; the root password goes through a file in the tmpfs, never through a
# command line (as fleet/backup.sh does).
# shellcheck disable=SC2016
RESTORE_FLEET_SCRIPT='set -euo pipefail
printf "[client]\nuser=root\npassword=%s\n" "$(cat "$FLEET_MYSQL_ROOT_PASSWORD_FILE")" >/tmp/my.cnf
chmod 600 /tmp/my.cnf
gunzip | mysql --defaults-extra-file=/tmp/my.cnf -h fleet-mysql
rm -f /tmp/my.cnf'

# restore_fleet: the chosen dump into the empty fleet-mysql (step 6).
restore_fleet() {
  RESTORE_COMPONENT=fleet
  restore_log "Fleet: loading ${RESTORE_SET[fleet]} into the empty fleet-mysql"
  restore_wait_service_healthy fleet-mysql
  restore_decrypt "${RESTORE_SET[fleet]}" |
    compose run --rm --no-deps -T --entrypoint bash fleet-backup -c "$RESTORE_FLEET_SCRIPT"
  compose up -d --no-deps fleet fleet-backup
  restore_log "Fleet: restored"
}

# restore_escrow: the set's escrowed headers back into the escrow bucket (step 7), written with the gateway's
# credential, the only one allowed to put headers.
restore_escrow() {
  RESTORE_COMPONENT=escrow
  restore_log "escrow: putting the set's escrowed headers back into the bucket"
  restore_backup_run "${RESTORE_SET_MOUNT[@]}" \
    -v "$SECRETS_DIR/rustfs_bundles_gateway_access_key:/run/secrets/escrow_restore_access_key:ro" \
    -v "$SECRETS_DIR/rustfs_bundles_gateway_secret_key:/run/secrets/escrow_restore_secret_key:ro" \
    -e PADDOCK_ESCROW_RESTORE_S3_ACCESS_KEY_FILE=/run/secrets/escrow_restore_access_key \
    -e PADDOCK_ESCROW_RESTORE_S3_SECRET_KEY_FILE=/run/secrets/escrow_restore_secret_key \
    -- backup restore-escrow "$RESTORE_SET_DIR" </dev/null
}

# restore_backup_repo: rebuilds the local repository from the source (amendment 2026-11-05, A5) and resets
# pgBackRest's markers, so the next round runs stanza-create, a full and a whole-stanza verify.
restore_backup_repo() {
  local src=() out repo_path svc
  RESTORE_COMPONENT=backup-repo
  case "$RESTORE_SOURCE" in
    target:*) src=(-- backup restore-repo --target "${RESTORE_SOURCE#target:}") ;;
    target-file:*) src=(-- backup restore-repo --target-file -) ;;
    *) src=(-v "$RESTORE_SOURCE:/restore-set:ro" -- backup restore-repo --dir /restore-set) ;;
  esac
  restore_log "backup-repo: emptying the local repository and copying the set into it"
  if [[ "$RESTORE_SOURCE" == target-file:* ]]; then
    out="$(restore_backup_run "${src[@]}" <"${RESTORE_SOURCE#target-file:}")"
  else
    out="$(restore_backup_run "${src[@]}" </dev/null)"
  fi
  sed '/^repo_path=/d' <<<"$out"
  repo_path="$(sed -n 's/^repo_path=//p' <<<"$out")"
  [[ "$repo_path" =~ $RESTORE_REPO_PATH_RE ]] || restore_die "the restored set names no pgBackRest repository"
  for svc in pgbackrest pgbackrest-authentik; do
    # shellcheck disable=SC2016
    compose run --rm --no-deps -T --entrypoint bash "$svc" -c 'set -e
: >/var/lib/pgbackrest/stanza
printf "%s\n" "$1" >/var/lib/pgbackrest/repo-path
rm -f /var/lib/pgbackrest/last-full /var/lib/pgbackrest/verify-ok /var/lib/pgbackrest/last-error' restore "$repo_path" </dev/null
  done
  compose --profile paddock up -d --no-deps pgbackrest pgbackrest-authentik paddock-backup
  restore_log "backup-repo: restored; the next round takes a full backup and verifies the stanzas"
}

# restore_run <fresh|plan=<id>> <repo|set directory|target:<name>|target-file:<file>> [--at <time>]
#   [--only <component>]...
# The restore of plan M15 decision 23. The set directory must be readable by uid 999 (restore_stage prepares one).
restore_run() {
  local mode="$1" c started own_trap=""
  RESTORE_SOURCE="$2"
  shift 2
  RESTORE_AT="" RESTORE_PLAN="" RESTORE_COMPONENT="" RESTORE_REPORTED="" RESTORE_WORK=""
  RESTORE_ONLY=()
  case "$mode" in
    fresh) RESTORE_MODE=fresh ;;
    plan=*)
      RESTORE_MODE=plan RESTORE_PLAN="${mode#plan=}"
      [[ "$RESTORE_PLAN" =~ $RESTORE_UUID_RE ]] || restore_die "invalid plan ID" 2
      ;;
    *) restore_die "restore_run: unknown mode $mode" 2 ;;
  esac
  while (($#)); do
    case "$1" in
      --at)
        RESTORE_AT="$(restore_normalize_at "${2:-}")" || restore_die "--at needs an RFC 3339 time such as 2026-11-04T10:00:00Z" 2
        shift 2
        ;;
      --only)
        case "${2:-}" in
          postgres | openbao | fleet | escrow | backup-repo) ;;
          *) restore_die "--only takes postgres, openbao, fleet, escrow or backup-repo" 2 ;;
        esac
        restore_has "$2" || RESTORE_ONLY+=("$2")
        shift 2
        ;;
      *) restore_die "restore_run: unknown argument $1" 2 ;;
    esac
  done
  ((${#RESTORE_ONLY[@]} > 0)) || RESTORE_ONLY=("${RESTORE_COMPONENTS_ALL[@]}")
  if restore_has backup-repo; then
    ((${#RESTORE_ONLY[@]} == 1)) || restore_die "--only backup-repo restores the backup repository alone" 2
    [[ -z "$RESTORE_AT" && "$RESTORE_MODE" == fresh ]] || restore_die "--only backup-repo takes no --at and no plan" 2
  elif [[ "$RESTORE_SOURCE" == target:* || "$RESTORE_SOURCE" == target-file:* ]]; then
    restore_die "a target is read directly only by --only backup-repo; stage the set first" 2
  fi
  [[ "$RESTORE_SOURCE" == repo || "$RESTORE_SOURCE" == target:* || "$RESTORE_SOURCE" == target-file:* ||
    "$RESTORE_SOURCE" == /* ]] || restore_die "the source must be repo, an absolute directory or a target" 2
  case "$RESTORE_SOURCE" in
    repo) RESTORE_SOURCE_KIND=repo RESTORE_SOURCE_LABEL="the local backup repository" ;;
    target:*) RESTORE_SOURCE_KIND=target RESTORE_SOURCE_LABEL="backup target ${RESTORE_SOURCE#target:}" ;;
    target-file:*) RESTORE_SOURCE_KIND=target RESTORE_SOURCE_LABEL="the target file ${RESTORE_SOURCE#target-file:}" ;;
    *) RESTORE_SOURCE_KIND="${RESTORE_SOURCE_KIND:-set}" RESTORE_SOURCE_LABEL="${RESTORE_SOURCE_LABEL:-$RESTORE_SOURCE}" ;;
  esac
  RESTORE_KEY_FILE="${RESTORE_KEY_FILE:-$SECRETS_DIR/backup_encryption_key}"

  restore_trap_set && own_trap=1
  if restore_has backup-repo; then
    declare -gA RESTORE_SET=()
    restore_backup_run -- backup restore-repo --check </dev/null >/dev/null ||
      restore_die "a restore plan is running; the backup repository is restored only when none runs; nothing was changed"
  else
    restore_preflight
  fi
  restore_confirm
  if [[ -n "$RESTORE_PLAN" ]]; then
    # Set before the report: a signal during it is handled only after the report ended, when the plan may be running;
    # the handler then prints how to check and record it instead of reporting it (PDK-837).
    RESTORE_COMPONENT=start
    restore_report running || {
      RESTORE_COMPONENT=""
      restore_die "the plan $RESTORE_PLAN cannot be started (no longer approved?); nothing was changed"
    }
  fi
  started=$SECONDS
  RESTORE_WORK="$(mktemp -d)"
  restore_stop_writers
  for c in postgres openbao; do
    if restore_has "$c"; then "restore_$c"; fi
  done
  if restore_has backup-repo; then
    restore_backup_repo
  else
    restore_paddock
    if restore_has fleet; then restore_fleet; fi
    if restore_has escrow; then restore_escrow; fi
    RESTORE_COMPONENT=paddock
    compose --profile paddock up -d --no-deps paddock-backup
    restore_wait_healthy
  fi
  RESTORE_COMPONENT=""
  RESTORE_REPORTED=1
  restore_report completed || true
  restore_log "restore completed in $((SECONDS - started)) s: ${RESTORE_ONLY[*]}"
  restore_cleanup
  [[ -z "$own_trap" ]] || restore_trap_reset
}

# restore_prompt_key <file>: reads the backup key from stdin (not echoed), checks it and writes it to file (0600, in a
# directory only its owner reads). The caller installs the cleanup trap first, so every later exit deletes it.
restore_prompt_key() {
  local file="$1" key=""
  IFS= read -rs -p "Backup key (44 characters, not echoed): " key || true
  [[ ! -t 0 ]] || echo >&2
  [[ "$key" =~ ^[A-Za-z0-9+/]{43}=$ ]] || restore_die "the backup key must be the 44 base64 characters shown when it was generated"
  (umask 077 && mkdir -p "$(dirname "$file")")
  RESTORE_KEY_WRITTEN="$file"
  (umask 077 && printf '%s\n' "$key" >"$file.tmp")
  unset key
  chmod 600 "$file.tmp"
  mv "$file.tmp" "$file"
}

# restore_key_cleanup: deletes the entered key file unless RESTORE_KEEP_KEY_FILE.
restore_key_cleanup() {
  local file="${RESTORE_KEY_WRITTEN:-}"
  [[ -n "$file" ]] || return 0
  rm -f "$file.tmp"
  if [[ -n "${RESTORE_KEEP_KEY_FILE:-}" && -e "$file" ]]; then
    RESTORE_KEY_WRITTEN=""
    echo "restore: the backup key stays in $file (--keep-key-file)" >&2
    return 0
  fi
  # Cleared only after the delete: a Ctrl-C during the shred exits through the signal handler, which then deletes the
  # rest of the key (PDK-837).
  if [[ -e "$file" ]]; then
    if command -v shred >/dev/null; then shred -u "$file" 2>/dev/null || rm -f "$file"; else rm -f "$file"; fi
  fi
  RESTORE_KEY_WRITTEN=""
}

# restore_set_root <dir>: the set's root below dir (dir itself or its paddock-backup/), or fails.
restore_set_root() {
  if [[ -f "$1/manifest.json" ]]; then
    printf '%s' "$1"
  elif [[ -f "$1/paddock-backup/manifest.json" ]]; then
    printf '%s' "$1/paddock-backup"
  else
    return 1
  fi
}

# restore_stage_prepare: an empty staging directory owned by the backup role's uid.
restore_stage_prepare() {
  rm -rf "$RESTORE_STAGING"
  mkdir -p "$RESTORE_STAGING"
  chmod 750 "$RESTORE_STAGING"
  chown "${RESTORE_SET_UID:-999}:${RESTORE_SET_UID:-999}" "$RESTORE_STAGING"
}

# restore_stage_finish <dir>: refuses anything but files and directories, hands the tree to the backup role's uid and
# prints the set's root.
restore_stage_finish() {
  local planted root
  planted="$(find "$RESTORE_STAGING" ! -type f ! -type d -print -quit)"
  [[ -z "$planted" ]] || restore_die "the backup set holds something other than files and directories: $planted"
  chown -R "${RESTORE_SET_UID:-999}:${RESTORE_SET_UID:-999}" "$RESTORE_STAGING"
  chmod -R u+rwX,g+rX,o-rwx "$RESTORE_STAGING"
  root="$(restore_set_root "$RESTORE_STAGING")" || restore_die "the backup set has no manifest.json (neither at its root nor in paddock-backup/)"
  printf '%s' "$root"
}

# restore_stage_path <dir|tar>: copies or extracts a set into the staging directory and prints its root there.
restore_stage_path() {
  local from="$1" root
  restore_stage_prepare
  if [[ -d "$from" ]]; then
    root="$(restore_set_root "$from")" || restore_die "$from holds no backup set (no manifest.json)"
    restore_log "staging: copying $root" >&2
    cp -R --no-preserve=ownership "$root/." "$RESTORE_STAGING/"
  else
    restore_log "staging: extracting $from" >&2
    tar -xf "$from" -C "$RESTORE_STAGING" --no-same-owner --no-same-permissions
  fi
  restore_stage_finish
}

# restore_stage_target <--target <id>|--target-file <file>>: downloads a target's set into the staging directory.
restore_stage_target() {
  restore_stage_prepare
  restore_log "staging: downloading the set from the backup target" >&2
  if [[ "$1" == --target-file ]]; then
    restore_backup_run -v "$RESTORE_STAGING:/restore-set" -- backup fetch-set --target-file - /restore-set <"$2" >&2
  else
    restore_backup_run -v "$RESTORE_STAGING:/restore-set" -- backup fetch-set --target "$2" /restore-set </dev/null >&2
  fi
  restore_stage_finish
}

# restore_plan_field <json> <name>: a string field of the plan's JSON ("" for null); the values are IDs, states and
# times, so a strict pattern reads them without a JSON parser.
restore_plan_field() {
  local re="\"$2\"[[:space:]]*:[[:space:]]*\"([A-Za-z0-9:._+-]*)\""
  if [[ "$1" =~ $re ]]; then printf '%s' "${BASH_REMATCH[1]}"; fi
}

# restore_plan_components <json>: the plan's components, one per line.
restore_plan_components() {
  local re='"components"[[:space:]]*:[[:space:]]*\[([^]]*)\]'
  [[ "$1" =~ $re ]] || return 0
  grep -oE '"[a-z-]+"' <<<"${BASH_REMATCH[1]}" | tr -d '"'
}

# restore_main <arguments of ./paddock restore>
restore_main() {
  local plan="" from="" target_file="" at="" keep="" only=() args=() json state expires c source mode own_trap=""
  while (($#)); do
    case "$1" in
      --plan) plan="${2:-}"; shift 2 || restore_usage || return ;;
      --from) from="${2:-}"; shift 2 || restore_usage || return ;;
      --from-target-file) target_file="${2:-}"; shift 2 || restore_usage || return ;;
      --at) at="${2:-}"; shift 2 || restore_usage || return ;;
      --only) only+=("${2:-}"); shift 2 || restore_usage || return ;;
      --keep-key-file) keep=1; shift ;;
      -h | --help) restore_usage; return ;;
      *) restore_usage; return ;;
    esac
  done
  if [[ -n "$plan" ]]; then
    [[ -z "$from$target_file$at" && ${#only[@]} -eq 0 ]] || { restore_usage; return; }
  else
    [[ -n "$from" && -z "$target_file" || -z "$from" && -n "$target_file" ]] || { restore_usage; return; }
  fi
  if [[ "$(env_value PADDOCK_HOST)" == lab && "$(env_value PADDOCK_LAB_BACKUP)" != yes ]]; then
    restore_die "this lab host has no backups (PADDOCK_LAB_BACKUP is not yes)" 2
  fi
  # Refused before the key is asked for; restore_run checks them again, together with the plan's values.
  [[ -z "$at" ]] || restore_normalize_at "$at" >/dev/null ||
    restore_die "--at needs an RFC 3339 time such as 2026-11-04T10:00:00Z" 2
  for c in "${only[@]}"; do
    case "$c" in
      postgres | openbao | fleet | escrow | backup-repo) ;;
      *) restore_die "--only takes postgres, openbao, fleet, escrow or backup-repo" 2 ;;
    esac
  done
  RESTORE_KEEP_KEY_FILE="$keep"
  # The staged set (ciphertext) goes on every exit, as the key does; the trap is installed before staging starts.
  restore_trap_set && own_trap=1
  RESTORE_STAGED="$RESTORE_STAGING"
  [[ -n "$at" ]] && args+=(--at "$at")
  for c in "${only[@]}"; do args+=(--only "$c"); done

  if [[ -n "$plan" ]]; then
    [[ "$plan" =~ $RESTORE_UUID_RE ]] || restore_die "invalid plan ID $plan" 2
    # backup plan prints the plan and exits 1 unless it is approved: the printed state names the refusal.
    json="$(restore_backup_run -- backup plan "$plan" </dev/null)" || true
    state="$(restore_plan_field "$json" state)"
    expires="$(restore_plan_field "$json" expires_at)"
    [[ -n "$state" ]] || restore_die "cannot read the restore plan $plan"
    [[ "$state" == approved ]] || restore_die "the restore plan $plan is $state, not approved"
    [[ -n "$expires" ]] && (($(date -u -d "$expires" +%s 2>/dev/null || echo 0) > $(date -u +%s))) ||
      restore_die "the restore plan $plan expired (24 hours after its approval); plan the restore again in the portal"
    at="$(restore_plan_field "$json" at)"
    [[ -n "$at" ]] && args+=(--at "$at")
    while IFS= read -r c; do [[ -n "$c" ]] && args+=(--only "$c"); done < <(restore_plan_components "$json")
    source="$(restore_plan_field "$json" source_target_id)"
    mode="plan=$plan"
    if [[ -z "$source" ]]; then
      source=repo
    else
      [[ "$source" =~ $RESTORE_UUID_RE ]] || restore_die "the plan names an invalid source target"
      RESTORE_SOURCE_KIND=target RESTORE_SOURCE_LABEL="backup target $(restore_plan_field "$json" source_target_name)"
      source="$(restore_stage_target --target "$source")"
    fi
  else
    mode=fresh
    if [[ " ${only[*]} " == *" backup-repo "* ]]; then
      if [[ -n "$target_file" ]]; then
        [[ -f "$target_file" ]] || restore_die "no target file $target_file" 2
        source="target-file:$target_file"
      elif [[ -e "$from" ]]; then
        RESTORE_SOURCE_LABEL="$from"
        source="$(restore_stage_path "$from")"
      else
        source="target:$from"
      fi
    elif [[ -n "$target_file" ]]; then
      [[ -f "$target_file" ]] || restore_die "no target file $target_file" 2
      RESTORE_SOURCE_KIND=target RESTORE_SOURCE_LABEL="the target file $target_file"
      source="$(restore_stage_target --target-file "$target_file")"
    elif [[ -e "$from" ]]; then
      RESTORE_SOURCE_LABEL="$from"
      source="$(restore_stage_path "$from")"
    else
      restore_die "$from does not exist; a target name is accepted only with --plan or --only backup-repo" 2
    fi
  fi
  RESTORE_KEY_FILE="$SECRETS_DIR/$RESTORE_KEY_PATH"
  if [[ " ${only[*]} " != *" backup-repo "* ]]; then
    restore_prompt_key "$RESTORE_KEY_FILE"
  fi
  restore_run "$mode" "$source" "${args[@]}"
  restore_cleanup
  [[ -z "$own_trap" ]] || restore_trap_reset
}

# restore_target_export <name|id> <file>: writes the S3 target file with its credentials (0600, never to a terminal).
restore_target_export() {
  local file="${2:-}" tmp
  [[ $# -eq 2 && -n "$1" && "$1" != -* && -n "$file" ]] || {
    echo "usage: ./paddock backup-target export <name|id> <file>" >&2
    return 2
  }
  [[ ! -e "$file" ]] || restore_die "$file exists; refusing to overwrite it"
  tmp="$(umask 077 && mktemp "$(dirname "$file")/.backup-target.XXXXXX")"
  # The temporary file holds the S3 credentials in plain text: a failure, Ctrl-C or dropped session removes it. The
  # path is expanded now because the trap may run outside this function; ./paddock sets no EXIT trap of its own.
  # shellcheck disable=SC2064
  trap "rm -f $(printf '%q' "$tmp")" EXIT
  restore_backup_run -- backup target-export "$1" </dev/null >"$tmp" ||
    restore_die "the export of backup target $1 failed"
  mv "$tmp" "$file"
  trap - EXIT
  echo "wrote $file (0600): keep it offline with the backup key; ./paddock restore --from-target-file reads it"
}
