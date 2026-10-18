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
PROD_FILES_lab="compose.yaml compose.prod.yaml compose.audit.yaml compose.lab.yaml"
LAB_BACKUP_FILES="compose.backup.yaml"

# redact_tokens replaces the value of every token=<value> field, and of every "token": "<value>" field of the JSON
# lines Authentik writes in a container, in a log stream: Authentik 2026.8.3 logs the raw refresh token of a refused
# refresh ("Refresh token is revoked", providers/oauth2/token/refresh_token.py), and Paddock's rule is that no secret
# is ever printed (RR-63). -u keeps `logs -f` live instead of block-buffered.
redact_tokens() { sed -u -E -e 's/(token=)[A-Za-z0-9._~+\/=-]+/\1<redacted>/g' -e 's/("token": ?")[^"]*/\1<redacted>/g'; }

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
# BACKUP is set) or the production set of PADDOCK_HOST (on a lab host plus the backup file when PADDOCK_LAB_BACKUP is
# yes), then every path of PADDOCK_COMPOSE_EXTRA (space-separated absolute paths; the CI smoke test's overlay, empty
# otherwise). Returns 2 when a production host has no valid PADDOCK_HOST.
compose_files() {
  local files f host
  if [[ "$(env_value PADDOCK_ENV)" == development ]]; then
    files="$DEV_FILES${BACKUP:+ $DEV_BACKUP_FILES}"
  else
    host="$(env_value PADDOCK_HOST)"
    case "$host" in
      controlplane) files="$PROD_FILES_controlplane" ;;
      audit) files="$PROD_FILES_audit" ;;
      # compose.backup.yaml last: its worker secrets add to the !override list of compose.prod.yaml (plan M8a).
      lab)
        files="$PROD_FILES_lab"
        if [[ "$(env_value PADDOCK_LAB_BACKUP)" == yes ]]; then files+=" $LAB_BACKUP_FILES"; fi
        ;;
      *)
        echo "set PADDOCK_HOST to controlplane, audit or lab in .env (is '${host:-unset}')" >&2
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

# export_rc_host <alias> <endpoint> <access key variable> <secret key variable>: exports RC_HOST_<alias>, from which
# the rc client defines the alias, so the RustFS credentials reach the container by name (`-e RC_HOST_<alias>`) and
# never travel on a command line the way `rc alias set` would put them (PDK-036). Both keys are percent-encoded,
# which rc decodes.
export_rc_host() {
  local alias="$1" endpoint="$2" access="${!3}" secret="${!4}"
  export "RC_HOST_$alias=${endpoint%%://*}://$(percent_encode "$access"):$(percent_encode "$secret")@${endpoint#*://}"
}

# percent_encode <value>: the value with every byte outside the URL's unreserved set as %XX.
percent_encode() {
  local LC_ALL=C s="$1" out="" c i
  for ((i = 0; i < ${#s}; i++)); do
    c="${s:i:1}"
    case "$c" in
      [A-Za-z0-9._~-]) out+="$c" ;;
      *) out+="$(printf '%%%02X' "'$c")" ;;
    esac
  done
  printf '%s' "$out"
}

# rc_user_absent <command…>: runs the command, an `rc admin user info` of one user, and succeeds when rc reports the
# user as not found, fails when the user exists and aborts the script on every other error. `rc admin user add` on an
# existing user replaces its secret and keeps its policy (PDK-036 review 1), so a timeout or an auth failure must not
# be taken for a missing user. rc v0.1.36 exits 5 for any missing resource, an unknown alias included, hence the text.
rc_user_absent() {
  local out status=0
  out="$("$@" 2>&1 >/dev/null)" || status=$?
  case "$status" in
    0) return 1 ;;
    5) [[ "$out" == *"User '"*"' not found"* ]] && return 0 ;;
  esac
  printf 'rc admin user info failed (exit %s): %s\n' "$status" "$out" >&2
  exit 1
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
