#!/usr/bin/env bash
# Applies Paddock's Authentik blueprints one after another in dependency order, once Authentik is healthy (plan M12h-2
# amendment g). The blueprints no longer nest metaapplyblueprint: concurrent applies of nested blueprints deadlocked
# Authentik's workers until the providers never appeared (CI run 43731878343). The device, step-up, MCP and development
# blueprints refer to the portal's objects with !Find, so the portal goes first. Authentik's own startup discovery still
# applies every file in no order and may fail one; this script applies the files again in order, then has Authentik
# apply every Paddock blueprint instance that is not successful (decisions-alpha11 §68 B1), and checks that the objects
# Paddock needs exist (decisions-alpha11 §69).
# `make up` and `./paddock up` (and so `./paddock upgrade`) call it before they wait for paddock-api, whose readiness
# needs the providers. Exit 1 names the file whose apply failed after its tries (later files are not applied), the
# instances that are not successful afterwards, or the objects that are missing.
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
# Seconds per instance for its pending applies and the one this script sends.
instance_timeout="${PADDOCK_BLUEPRINT_INSTANCE_TIMEOUT:-180}"
if ! [[ "$instance_timeout" =~ ^[0-9]+$ ]]; then
  echo "PADDOCK_BLUEPRINT_INSTANCE_TIMEOUT must be a number of seconds" >&2
  exit 1
fi
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

# apply_instances brings the BlueprintInstance of every applied file to status successful. ak apply_blueprint creates the
# objects but leaves the instance alone, so one that Authentik's startup discovery failed (a !Find before the portal
# existed) would stay in error until the hourly discovery, while the acceptance stack (devseed) reads the instance status
# (decisions-alpha11 §66, §68 B1). For each instance in turn it waits for the applies already queued for it, then, if it
# is not successful, sends the apply_blueprint task the way the API's POST /api/v3/managed/blueprints/<pk>/apply/ does
# and waits for that task (Authentik 2026.8.5, blueprints/api.py and blueprints/v1/tasks.py); the task runs in the
# worker, whose environment holds the secrets the blueprints read with !Env. Only a status and the path of a file of
# this script leave the container, never the instance's context or task logs (decisions-alpha11 §71).
apply_instances() {
  local out status path line failed=() n=0
  local re_line='^paddock-instance ([^ ]+) (.+)$'
  declare -A got=()
  if ! out="$(compose exec -T authentik-worker ak shell -c "
import time
from django.contrib.contenttypes.models import ContentType
from django_dramatiq_postgres.models import TaskState
from authentik.blueprints.models import BlueprintInstance, BlueprintInstanceStatus
from authentik.blueprints.v1.tasks import apply_blueprint
from authentik.tasks.models import Task
kind = ContentType.objects.get_for_model(BlueprintInstance)
def settled(instance, deadline):
    while True:
        if not Task.objects.filter(actor_name=apply_blueprint.actor_name, rel_obj_content_type=kind,
                rel_obj_id=str(instance.pk)).exclude(state__in=[TaskState.DONE, TaskState.REJECTED]).exists():
            return True
        if time.monotonic() > deadline:
            return False
        time.sleep(2)
for path in $(py_list "${files[@]}"):
    deadline = time.monotonic() + $instance_timeout
    instance = BlueprintInstance.objects.filter(path=path).first()
    while instance is None and time.monotonic() < deadline:
        time.sleep(2)
        instance = BlueprintInstance.objects.filter(path=path).first()
    if instance is None:
        print('paddock-instance missing', path)
        continue
    if not settled(instance, deadline):
        print('paddock-instance timeout', path)
        continue
    instance.refresh_from_db()
    if instance.status != BlueprintInstanceStatus.SUCCESSFUL:
        apply_blueprint.send_with_options(args=(instance.pk,), rel_obj=instance)
        if not settled(instance, deadline):
            print('paddock-instance timeout', path)
            continue
        instance.refresh_from_db()
    print('paddock-instance', instance.status, path)
" </dev/null 2>/dev/null)"; then
    echo "FAIL  Authentik blueprint instances: not applied, ak shell failed" >&2
    exit 1
  fi
  while IFS= read -r line; do
    [[ "$line" =~ $re_line ]] || continue
    status="${BASH_REMATCH[1]}" path="${BASH_REMATCH[2]}"
    [[ " ${files[*]} " == *" $path "* ]] || continue
    case "$status" in
      successful | warning | error | orphaned | unknown | missing | timeout) ;;
      *) status=unrecognized ;;
    esac
    got[$path]="$status"
  done <<<"$out"
  for path in "${files[@]}"; do
    status="${got[$path]:-not reported}"
    if [[ "$status" == successful ]]; then n=$((n + 1)); else failed+=("$path: $(instance_reason "$status")"); fi
  done
  if ((${#failed[@]} > 0)); then
    echo "FAIL  Authentik blueprint instances: not successful after Authentik applied them" >&2
    printf '      - %s\n' "${failed[@]}" >&2
    echo "      see the instance under System > Blueprints in Authentik, or compose logs authentik-worker" >&2
    exit 1
  fi
  echo "PASS  Authentik blueprint instances: $n of ${#files[@]} successful"
}

# instance_reason <status>: the fixed text for an instance status that is not successful.
instance_reason() {
  case "$1" in
    missing) printf 'no instance; Authentik did not discover the file' ;;
    timeout) printf 'its apply did not finish within %ss' "$instance_timeout" ;;
    unrecognized) printf 'a status this script does not know' ;;
    "not reported") printf 'no status reported' ;;
    *) printf 'status %s' "$1" ;;
  esac
}

# check_objects checks by name that the objects the stack needs exist after the applies, and fails naming the missing
# ones (decisions-alpha11 §69). Only names leave the container.
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
apply_instances
check_objects
