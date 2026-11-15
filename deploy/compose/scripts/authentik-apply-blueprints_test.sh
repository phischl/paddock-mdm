#!/usr/bin/env bash
# Test of authentik-apply-blueprints.sh against a real Authentik (`make authentik-blueprints-test`, CI job
# authentik-blueprints; plan M12h-2 amendment g): a cold first start on a fresh Authentik database, where Authentik's own
# discovery applies every file at once and in no order, then the script twice in a row. Both runs exit 0, the providers
# of the portal, step-up and MCP exist, and the worker log shows no unique violation, lock wait or time limit, which is
# how the nested blueprints' deadlock showed (CI run 43731878343).
# It starts the pinned Authentik images (versions.env) in a Compose project of its own with throwaway secrets, from a
# copy of deploy/compose, and removes the project with its volumes at the end; it never touches another stack.
set -euo pipefail

src="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
work="$(mktemp -d)"
failures=0

check() {
  local desc="$1"
  shift
  if "$@"; then echo "ok   $desc"; else
    echo "FAIL $desc"
    failures=$((failures + 1))
  fi
}

tar -C "$src" --exclude=./.env --exclude=./.secrets -cf - . | tar -C "$work" -xf -
(unset PADDOCK_INSTANCE BACKUP SECRETS_DIR && bash "$work/scripts/gen-dev-secrets.sh" >/dev/null)
# authentik-server without the network edge: the edge subnet is fixed per host and a running stack already holds it.
cat >"$work/test-overlay.yaml" <<'EOF'
services:
  authentik-server:
    networks: !override [authentik]
EOF
export PADDOCK_PROJECT="paddock-akbp-test-$$" PADDOCK_COMPOSE_EXTRA="$work/test-overlay.yaml"
unset PADDOCK_INSTANCE BACKUP SECRETS_DIR
# shellcheck source=lib.sh
tc() { (. "$work/scripts/lib.sh" && compose "$@"); }
cleanup() {
  tc down -v --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT

tc up -d authentik-postgres authentik-server authentik-worker >/dev/null 2>&1
rc=0
"$work/scripts/authentik-apply-blueprints.sh" >"$work/run1.log" 2>&1 || rc=$?
check "the first run after a cold start exits 0" test "$rc" = 0
rc=0
"$work/scripts/authentik-apply-blueprints.sh" >"$work/run2.log" 2>&1 || rc=$?
check "the second run exits 0" test "$rc" = 0
for run in run1 run2; do
  check "$run applies every blueprint, the development one last" \
    test "$(sed -n 's/^applied the Authentik blueprint //p' "$work/$run.log" | paste -sd' ' -)" = \
    "paddock/paddock-portal.yaml paddock/paddock-device.yaml paddock/paddock-stepup.yaml paddock/paddock-recovery.yaml paddock/paddock-mcp.yaml paddock-dev/paddock-dev.yaml"
done

providers="$(tc exec -T authentik-worker ak shell -c '
from authentik.providers.oauth2.models import OAuth2Provider
for p in OAuth2Provider.objects.filter(name__in=["paddock-portal", "paddock-portal-stepup", "paddock-mcp"]).order_by("name"):
    print("paddock-provider", p.name)
' </dev/null 2>/dev/null | sed -n 's/^paddock-provider //p' | paste -sd' ' -)"
check "the providers of the portal, step-up and MCP exist" test "$providers" = "paddock-mcp paddock-portal paddock-portal-stepup"

tc logs --no-color authentik-worker >"$work/worker.log" 2>&1
check "the worker log has lines" test -s "$work/worker.log"
# Counts only: a matching line may carry an entry's attributes with resolved !Env values, and CI logs are public.
problems=()
for pattern in 'duplicate key value' UniqueViolation IntegrityError 'deadlock detected' LockNotAvailable 'lock timeout' \
  'could not obtain lock' TimeLimitExceeded; do
  n="$(grep -cF -- "$pattern" "$work/worker.log" || true)"
  ((n == 0)) || problems+=("$pattern: $n lines")
done
check "no unique violation, lock wait or time limit in the worker log${problems[*]:+ (${problems[*]})}" test "${#problems[@]}" = 0

if ((failures > 0)); then
  for run in run1 run2; do
    echo "--- $run" >&2
    cat "$work/$run.log" >&2
  done
  echo "authentik-apply-blueprints: $failures check(s) failed" >&2
  exit 1
fi
echo "authentik-apply-blueprints: all checks passed"
