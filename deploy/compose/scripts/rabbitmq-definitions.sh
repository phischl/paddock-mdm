#!/usr/bin/env bash
# Applies the RabbitMQ users and permissions of .secrets/rabbitmq/definitions.json to the running broker, without a
# restart, and checks the result (PDK-1017, decisions main §44). The broker imports the definitions file only when it
# starts, so a release that changes a user's permissions (0.1.0-alpha.11: the audit writer may publish to
# paddock.offboarding, the worker may read worker.offboarding) would otherwise run with the old ones until the broker
# restarts. `rabbitmqctl import_definitions` sets every user and permission of the file again and changes nothing else;
# repeating it changes nothing. The file holds the users' passwords: it reaches the container on stdin, never on a
# command line, and nothing of it is printed. rabbitmqctl itself cannot read stdin (RabbitMQ 4.4's CLI disables the
# VM's input, PDK-1077), so the container keeps it in a private temporary file (umask 077) for the import by path and
# removes it right after.
#   rabbitmq-definitions.sh            apply, then check
#   rabbitmq-definitions.sh --import   apply only (./paddock upgrade before up, main §45: the old broker may still hold
#                                      users of the old release, which only the exact check after up may judge)
#   rabbitmq-definitions.sh --check    check only: the broker's permissions on vhost paddock against the definitions
# Exit 0: applied, or the broker's permissions match; 1: they do not, or the broker could not be read; 2: usage.
set -euo pipefail

CHECK_ONLY="" IMPORT_ONLY=""
case "${1:-}" in
  "") ;;
  --check) CHECK_ONLY=1 ;;
  --import) IMPORT_ONLY=1 ;;
  *)
    echo "usage: $0 [--import|--check]" >&2
    exit 2
    ;;
esac

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
. "$here/lib.sh"

definitions="$SECRETS_DIR/rabbitmq/definitions.json"
template="$COMPOSE_DIR/rabbitmq/definitions.json.tmpl"
# One scheduler per CLI call, as the container's health check: rabbitmqctl starts an Erlang VM of its own. Passed by
# name, as every variable that reaches a container (secrets-argv_test.sh).
export RABBITMQ_CTL_ERL_ARGS='+S 1:1 +SDcpu 1:1 +SDio 1 +A 1 +sbwt none +sbwtdcpu none +sbwtdio none'

ctl() { compose exec -T -e RABBITMQ_CTL_ERL_ARGS rabbitmq rabbitmqctl "$@"; }
# import_definitions: the definitions on stdin into the broker, by way of a private file in the container; the trap
# names the file as mktemp made it.
# shellcheck disable=SC2016 # $f is the container shell's.
import_definitions() {
  compose exec -T -e RABBITMQ_CTL_ERL_ARGS rabbitmq sh -c 'umask 077 && f="$(mktemp)" || exit 1
trap "rm -f -- \"$f\"" EXIT
cat >"$f" && rabbitmqctl import_definitions --format json "$f"'
}
# The broker applies an import asynchronously now and then, so the check right after it may still see the old
# permissions; it is repeated for a few seconds before it counts (PDK-1077).
CHECK_ATTEMPTS=1

if [[ -z "$CHECK_ONLY" ]]; then
  [[ -f "$definitions" ]] || {
    echo "rabbitmq: $definitions is missing; run ./paddock secrets first" >&2
    exit 1
  }
  echo "rabbitmq: applying the users and permissions of the definitions to the running broker (no restart)"
  import_definitions <"$definitions" >/dev/null || {
    echo "rabbitmq: rabbitmqctl import_definitions failed; is the broker running (./paddock ps rabbitmq)?" >&2
    exit 1
  }
  [[ -z "$IMPORT_ONLY" ]] || exit 0
  CHECK_ATTEMPTS=10
fi
for ((attempt = 1; ; attempt++)); do
  listing="$(ctl -q list_permissions -p paddock --formatter json </dev/null)" || {
    echo "rabbitmq: rabbitmqctl list_permissions failed; is the broker running (./paddock ps rabbitmq)?" >&2
    exit 1
  }
  rc=0
  result="$(docker run --rm -i --network none --cap-drop ALL --read-only \
    -v "$template:/run/paddock/definitions.json.tmpl:ro" "$PADDOCK_IMAGE" \
    check-broker --definitions /run/paddock/definitions.json.tmpl <<<"$listing" 2>&1)" || rc=$?
  if ((rc == 0 || attempt >= CHECK_ATTEMPTS)); then
    printf '%s\n' "$result"
    exit "$rc"
  fi
  sleep 1
done
