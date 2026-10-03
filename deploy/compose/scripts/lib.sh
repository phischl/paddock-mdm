# Shared helpers for the bootstrap scripts. Sourced, not executed.
# shellcheck shell=bash

COMPOSE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SECRETS_DIR="$COMPOSE_DIR/.secrets"

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
    echo "For production follow docs/operations/openbao.md and docs/operations/audit-bucket.md." >&2
    exit 1
  fi
}

compose() {
  docker compose --project-directory "$COMPOSE_DIR" -p paddock \
    --env-file "$COMPOSE_DIR/versions.env" --env-file "$COMPOSE_DIR/.env" \
    -f "$COMPOSE_DIR/compose.yaml" -f "$COMPOSE_DIR/compose.audit.yaml" -f "$COMPOSE_DIR/compose.dev.yaml" "$@"
}

# shellcheck disable=SC1091
set -a; . "$COMPOSE_DIR/versions.env"; set +a
