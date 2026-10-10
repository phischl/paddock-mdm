# Shared helpers for the bootstrap scripts and the operator bundle's ./paddock. Sourced, not executed.
# shellcheck shell=bash

COMPOSE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SECRETS_DIR="${SECRETS_DIR:-$COMPOSE_DIR/.secrets}"

# The Compose file sets: the single source of truth for the Makefile, the operator bundle (deploy/bundle/) and
# server/internal/prodcheck/compose_test.go, which read these lines literally (plan M7b decision 18).
DEV_FILES="compose.yaml compose.audit.yaml compose.dev.yaml"
DEV_BACKUP_FILES="compose.backup.yaml compose.backup.dev.yaml"
PROD_FILES_controlplane="compose.yaml compose.prod.yaml compose.backup.yaml"
PROD_FILES_audit="compose.audit.yaml compose.audit.prod.yaml"

# env_value <name>: value from the process environment, else from .env, else from .env.example.
env_value() {
  local name="$1" file
  if [[ -n "${!name:-}" ]]; then
    printf '%s' "${!name}"
    return
  fi
  for file in "$COMPOSE_DIR/.env" "$COMPOSE_DIR/.env.example"; do
    if [[ -f "$file" ]] && grep -q "^${name}=" "$file"; then
      grep "^${name}=" "$file" | tail -1 | cut -d= -f2-
      return
    fi
  done
}

# require_development refuses to run the development-only path in production (plan M0 decision 20).
require_development() {
  local env
  env="$(env_value PADDOCK_ENV)"
  if [[ "$env" != "development" ]]; then
    echo "refusing to run: PADDOCK_ENV is '${env:-unset}', this script is for development only." >&2
    echo "For production follow docs/operations/install.md." >&2
    exit 1
  fi
}

# compose_files prints the Compose files of this host, one per line: the development set (plus the backup files when
# BACKUP is set) or the production set of PADDOCK_HOST, then every path of PADDOCK_COMPOSE_EXTRA (space-separated
# absolute paths; the CI smoke test's overlay, empty otherwise). Returns 2 when a production host has no valid
# PADDOCK_HOST.
compose_files() {
  local files f host
  if [[ "$(env_value PADDOCK_ENV)" == development ]]; then
    files="$DEV_FILES${BACKUP:+ $DEV_BACKUP_FILES}"
  else
    host="$(env_value PADDOCK_HOST)"
    case "$host" in
      controlplane) files="$PROD_FILES_controlplane" ;;
      audit) files="$PROD_FILES_audit" ;;
      *)
        echo "set PADDOCK_HOST to controlplane or audit in .env (is '${host:-unset}')" >&2
        return 2
        ;;
    esac
  fi
  for f in $files; do printf '%s\n' "$COMPOSE_DIR/$f"; done
  for f in ${PADDOCK_COMPOSE_EXTRA:-}; do printf '%s\n' "$f"; done
}

compose() {
  local files f args=()
  files="$(compose_files)" || exit 2
  while IFS= read -r f; do args+=(-f "$f"); done <<<"$files"
  docker compose --project-directory "$COMPOSE_DIR" -p "$PADDOCK_PROJECT" \
    --env-file "$COMPOSE_DIR/versions.env" --env-file "$COMPOSE_DIR/.env" "${args[@]}" "$@"
}

PADDOCK_PROJECT="${PADDOCK_PROJECT:-$(env_value PADDOCK_PROJECT)}"
PADDOCK_PROJECT="${PADDOCK_PROJECT:-paddock}"

# shellcheck disable=SC1091
set -a; . "$COMPOSE_DIR/versions.env"; set +a

# Compose prefers the process environment over its env files, and the line above has just exported versions.env; so
# an operator's .env override of the Paddock images (a mirrored registry, plan M7b decision 12) is applied here.
for _image_var in PADDOCK_IMAGE PADDOCK_COMPILER_IMAGE PADDOCK_PGBACKREST_IMAGE; do
  if [[ -f "$COMPOSE_DIR/.env" ]] && grep -q "^${_image_var}=" "$COMPOSE_DIR/.env"; then
    export "$_image_var=$(grep "^${_image_var}=" "$COMPOSE_DIR/.env" | tail -1 | cut -d= -f2-)"
  fi
done
unset _image_var
