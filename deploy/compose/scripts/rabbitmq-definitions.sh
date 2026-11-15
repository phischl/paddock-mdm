#!/usr/bin/env bash
# Applies the RabbitMQ users and permissions of .secrets/rabbitmq/definitions.json to the running broker, without a
# restart, and checks the result (PDK-1017, decisions main §44). The broker imports the definitions file only when it
# starts, so a release that changes a user's permissions (0.1.0-alpha.11: the audit writer may publish to
# paddock.offboarding, the worker may read worker.offboarding) would otherwise run with the old ones until the broker
# restarts. `rabbitmqctl import_definitions` sets every user and permission of the file again and changes nothing else;
# repeating it changes nothing. The file holds the users' passwords: it reaches rabbitmqctl on stdin, never on a
# command line, and nothing of it is printed.
#   rabbitmq-definitions.sh            apply, then check
#   rabbitmq-definitions.sh --check    check only: the broker's permissions on vhost paddock against the definitions
# Exit 0: the broker's permissions match; 1: they do not, or the broker could not be read; 2: usage.
set -euo pipefail

CHECK_ONLY=
case "${1:-}" in
  "") ;;
  --check) CHECK_ONLY=1 ;;
  *)
    echo "usage: $0 [--check]" >&2
    exit 2
    ;;
esac

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
. "$here/lib.sh"

definitions="$SECRETS_DIR/rabbitmq/definitions.json"
template="$COMPOSE_DIR/rabbitmq/definitions.json.tmpl"
# One scheduler per CLI call, as the container's health check: rabbitmqctl starts an Erlang VM of its own.
erl_args='+S 1:1 +SDcpu 1:1 +SDio 1 +A 1 +sbwt none +sbwtdcpu none +sbwtdio none'

ctl() { compose exec -T -e "RABBITMQ_CTL_ERL_ARGS=$erl_args" rabbitmq rabbitmqctl "$@"; }

if [[ -z "$CHECK_ONLY" ]]; then
  [[ -f "$definitions" ]] || {
    echo "rabbitmq: $definitions is missing; run ./paddock secrets first" >&2
    exit 1
  }
  echo "rabbitmq: applying the users and permissions of the definitions to the running broker (no restart)"
  ctl import_definitions --format json <"$definitions" >/dev/null || {
    echo "rabbitmq: rabbitmqctl import_definitions failed; is the broker running (./paddock ps rabbitmq)?" >&2
    exit 1
  }
fi
listing="$(ctl -q list_permissions -p paddock --formatter json </dev/null)" || {
  echo "rabbitmq: rabbitmqctl list_permissions failed; is the broker running (./paddock ps rabbitmq)?" >&2
  exit 1
}
docker run --rm -i --network none --cap-drop ALL --read-only -v "$template:/run/paddock/definitions.json.tmpl:ro" \
  "$PADDOCK_IMAGE" check-broker --definitions /run/paddock/definitions.json.tmpl <<<"$listing"
