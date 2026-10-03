#!/usr/bin/env bash
# Waits until every service of the stack is healthy (or, for one-shot services, exited with code 0).
# `docker compose up --wait` treats exited one-shot services as failures, hence this script.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
. "$here/lib.sh"

timeout="${WAIT_TIMEOUT:-900}"
deadline=$((SECONDS + timeout))

while :; do
  pending=()
  failed=()
  seen=0
  while IFS='|' read -r service state health exit_code; do
    seen=$((seen + 1))
    case "$state" in
      exited)
        [[ "$exit_code" == "0" ]] || failed+=("$service (exit $exit_code)") ;;
      running)
        [[ -z "$health" || "$health" == "healthy" ]] || pending+=("$service ($health)") ;;
      *)
        pending+=("$service ($state)") ;;
    esac
  done < <(compose "$@" ps -a --format '{{.Service}}|{{.State}}|{{.Health}}|{{.ExitCode}}')

  if ((seen == 0)); then
    echo "no services found" >&2
    exit 1
  fi
  if ((${#failed[@]} > 0)); then
    echo "failed: ${failed[*]}" >&2
    exit 1
  fi
  if ((${#pending[@]} == 0)); then
    echo "all services healthy"
    exit 0
  fi
  if ((SECONDS > deadline)); then
    echo "timeout after ${timeout}s, still waiting for: ${pending[*]}" >&2
    exit 1
  fi
  sleep 3
done
