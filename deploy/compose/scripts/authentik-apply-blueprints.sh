#!/usr/bin/env bash
# Applies Paddock's Authentik blueprints one after another in dependency order, once Authentik is healthy (plan M12h-2
# amendment g). The blueprints no longer nest metaapplyblueprint: concurrent applies of nested blueprints deadlocked
# Authentik's workers until the providers never appeared (CI run 43731878343). The device, step-up, MCP and development
# blueprints refer to the portal's objects with !Find, so the portal goes first. Authentik's own startup discovery still
# applies every file in no order and may fail one; this script applies the files again in order, then checks that the
# objects Paddock needs exist (decisions-alpha11 §69).
# `make up` and `./paddock up` (and so `./paddock upgrade`) call it before they wait for paddock-api, whose readiness
# needs the providers. Exit 1 names the file whose apply failed after its tries (later files are not applied), or the
# objects that are missing afterwards.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
. "$here/lib.sh"

blueprints=(
  paddock/paddock-portal.yaml
  paddock/paddock-device.yaml
  paddock/paddock-stepup.yaml
  paddock/paddock-recovery.yaml
  paddock/paddock-mcp.yaml
)
# Mounted by compose.dev.yaml only.
dev_blueprint=paddock-dev/paddock-dev.yaml
# The objects the stack needs from the blueprints above, checked by name after the applies: paddock-api's readiness
# needs the providers, the sign-in, device and setup-link paths need the flows.
providers=(paddock-portal paddock-portal-stepup paddock-mcp)
applications=(paddock-portal paddock-portal-stepup paddock-mcp)
flows=(paddock-admin-login paddock-device-authentication paddock-device-code paddock-device-authorization paddock-stepup
  paddock-recovery)

tries="${PADDOCK_BLUEPRINT_TRIES:-3}"
delay="${PADDOCK_BLUEPRINT_RETRY_DELAY:-20}"
timeout="${WAIT_TIMEOUT:-900}"

# wait_authentik waits until authentik-server and authentik-worker are healthy; ak apply_blueprint needs the migrated
# database the worker's health implies.
wait_authentik() {
  local deadline=$((SECONDS + timeout)) service state health seen pending
  while :; do
    seen=0
    pending=()
    while IFS='|' read -r service state health; do
      [[ -n "$service" ]] || continue
      seen=$((seen + 1))
      [[ "$state" == running && (-z "$health" || "$health" == healthy) ]] || pending+=("$service ($state${health:+, $health})")
    done < <(compose ps -a --format '{{.Service}}|{{.State}}|{{.Health}}' authentik-server authentik-worker </dev/null)
    if ((seen < 2)); then
      echo "authentik-server and authentik-worker do not both exist; start the stack first" >&2
      exit 1
    fi
    ((${#pending[@]} > 0)) || return 0
    if ((SECONDS > deadline)); then
      echo "timeout after ${timeout}s, Authentik is not healthy: ${pending[*]}" >&2
      exit 1
    fi
    sleep 3
  done
}

# failed_output <output>: whether ak apply_blueprint reported a failure in its output. It exits 1 on an invalid
# blueprint ("Blueprint invalid") and on an exception, but exits 0 when the apply after a passed validation fails: that
# only shows as a warning of the importer (Authentik 2026.8.5, blueprints/management/commands/apply_blueprint.py).
failed_output() {
  grep -qE '^Blueprint invalid$|"level": "(warning|error)", "logger": "authentik\.blueprints\.v1\.importer"' <<<"$1"
}

# summary <output>: the reason of a failed apply, in fixed text only. ak apply_blueprint prints each log event as
# "\t<logger>: <event>: <attributes>", and the attributes are the whole entry with the resolved !Env values (the OIDC
# client secret, the service token, the development passwords); an event's or an exception's message may quote values
# as well. So each event is mapped to one of the importer's fixed messages (Authentik 2026.8.5,
# blueprints/v1/importer.py) and an exception to its class name; nothing else of a line is printed (decisions-alpha11
# §71).
summary() {
  local line text printed=""
  local re_tab=$'^\t([A-Za-z0-9_.]+): (.*)$'
  local re_importer='"level": "(warning|error)", "logger": "authentik\.blueprints\.v1\.importer"'
  local re_event='"event": "(.*)$'
  local re_exception='^([A-Za-z_][A-Za-z0-9_.]*(Error|Exception|Failed|Exceeded|Violation))(:|$)'
  while IFS= read -r line; do
    text=""
    if [[ "$line" == "Blueprint invalid" ]]; then
      text="Blueprint invalid"
    elif [[ "$line" =~ $re_tab ]]; then
      text="$(logger_name "${BASH_REMATCH[1]}"): $(event_text "${BASH_REMATCH[2]}")"
    elif [[ "$line" =~ $re_importer && "$line" =~ $re_event ]]; then
      text="authentik.blueprints.v1.importer: $(event_text "${BASH_REMATCH[1]}")"
    elif [[ "$line" =~ $re_exception ]]; then
      text="$(exception_name "${BASH_REMATCH[1]}")"
    fi
    [[ -n "$text" ]] || continue
    printf '  %s\n' "$text"
    printed=1
  done <<<"$1"
  [[ -n "$printed" ]] || echo "  no reason recognized; see the log of authentik-worker (compose logs authentik-worker)"
}

# logger_name <logger>: the logger as printed, if it is Authentik's own (authentik.*) or None, else a fixed placeholder.
logger_name() {
  if [[ "$1" == None || "$1" =~ ^authentik(\.[a-z0-9_]+)*$ ]]; then printf '%s' "$1"; else printf 'another logger'; fi
}

# exception_name <class>: the class name, if it is one an apply is known to raise, else a fixed placeholder.
exception_name() {
  case "${1##*.}" in
    BlueprintRetrievalFailed | EntryInvalidError | IntegrityError | UniqueViolation | DatabaseError | OperationalError | \
      InternalError | ProgrammingError | LockNotAvailable | DeadlockDetected | TimeLimitExceeded | ValidationError | \
      FileNotFoundError | PermissionError | YAMLError)
      printf '%s' "$1"
      ;;
    *) printf 'an exception this script does not know' ;;
  esac
}

# event_text <event…>: the importer's fixed message the event starts with, plus "Serializer errors" when the entry
# failed its serializer; any other event as a fixed placeholder.
event_text() {
  local known
  for known in "Entry invalid on retry" "Entry invalid" "Integrity error persists on retry" "Blueprint validation failed" \
    "Invalid blueprint version" "Reverting changes due to error"; do
    [[ "$1" == "$known"* ]] || continue
    if [[ "$1" == "$known: Serializer errors"* ]]; then known+=": Serializer errors"; fi
    printf '%s' "$known"
    return
  done
  printf 'an event this script does not know'
}

# apply <file>: one ak apply_blueprint of the file. It runs through the image's entrypoint, which exports the secrets
# the blueprints read with !Env from their files; compose exec does not run the entrypoint by itself.
apply() {
  local file="$1" out status=0
  out="$(compose exec -T authentik-worker /bin/sh /paddock/entrypoint.sh apply_blueprint "/blueprints/$file" </dev/null 2>&1)" ||
    status=$?
  if ((status == 0)) && ! failed_output "$out"; then return 0; fi
  echo "applying the Authentik blueprint $file failed (exit $status):" >&2
  summary "$out" >&2
  return 1
}

# check_objects checks by name that the objects the stack needs exist after the applies, and fails naming the missing
# ones. Authentik's own startup apply may have failed a file before this script applied it, and the instance keeps that
# status until Authentik's hourly discovery, so the objects are checked instead of the instances (decisions-alpha11
# §69). Only names leave the container.
check_objects() {
  local out want=() have=() missing=() name
  if ! out="$(compose exec -T authentik-worker ak shell -c "
from authentik.core.models import Application
from authentik.flows.models import Flow
from authentik.providers.oauth2.models import OAuth2Provider
for n in OAuth2Provider.objects.filter(name__in=$(py_list "${providers[@]}")).values_list('name', flat=True):
    print('paddock-object provider/' + n)
for n in Application.objects.filter(slug__in=$(py_list "${applications[@]}")).values_list('slug', flat=True):
    print('paddock-object application/' + n)
for n in Flow.objects.filter(slug__in=$(py_list "${flows[@]}")).values_list('slug', flat=True):
    print('paddock-object flow/' + n)
" </dev/null 2>/dev/null)"; then
    echo "FAIL  Authentik objects of the blueprints: not checked, ak shell failed" >&2
    exit 1
  fi
  for name in "${providers[@]}"; do want+=("provider/$name"); done
  for name in "${applications[@]}"; do want+=("application/$name"); done
  for name in "${flows[@]}"; do want+=("flow/$name"); done
  mapfile -t have < <(sed -n 's/^paddock-object //p' <<<"$out")
  for name in "${want[@]}"; do
    [[ " ${have[*]} " == *" $name "* ]] || missing+=("$name")
  done
  if ((${#missing[@]} > 0)); then
    echo "FAIL  Authentik objects of the blueprints: missing after the applies" >&2
    printf '      - %s\n' "${missing[@]}" >&2
    exit 1
  fi
  echo "PASS  Authentik objects of the blueprints: ${#want[@]} providers, applications and flows exist"
}

# py_list <name…>: the names as a Python list literal; they are the fixed names above.
py_list() {
  local n out="["
  for n in "$@"; do out+="'$n', "; done
  printf '%s]' "$out"
}

files=("${blueprints[@]}")
if [[ "$(env_value PADDOCK_ENV)" == development ]]; then files+=("$dev_blueprint"); fi

wait_authentik
for file in "${files[@]}"; do
  try=1
  until apply "$file"; do
    if ((try >= tries)); then
      echo "the Authentik blueprint $file failed $tries times; stopped, the blueprints after it were not applied" >&2
      exit 1
    fi
    try=$((try + 1))
    echo "applying $file again in ${delay}s (try $try of $tries); Authentik's own startup apply may still hold it" >&2
    sleep "$delay"
  done
  echo "applied the Authentik blueprint $file"
done
check_objects
