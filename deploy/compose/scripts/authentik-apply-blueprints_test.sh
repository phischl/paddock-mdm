#!/usr/bin/env bash
# Test of authentik-apply-blueprints.sh against a real Authentik (`make authentik-blueprints-test`, CI job
# authentik-blueprints; plan M12h-2 amendment g): a cold first start on a fresh Authentik database, where Authentik's own
# discovery applies every file at once and in no order, then the script twice in a row. Both runs exit 0, the providers
# of the portal, step-up and MCP exist, every Paddock blueprint instance is successful (the acceptance stack's devseed reads
# the instance status; CI run 43755153692, PDK-1083), and the worker log shows no unique violation, lock wait or time
# limit, which is how the nested blueprints' deadlock showed (CI run 43731878343). Before the second run two instances
# are set to error, as Authentik's discovery leaves them when a !Find runs before the portal exists, and the second run
# repairs them; a third run with one instance disabled, so its apply cannot succeed, fails naming that instance. No run
# prints a value of the throwaway secrets.
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

# ak_shell <python>: the code in ak shell in the worker, only its lines marked "paddock-test " without the marker.
ak_shell() { tc exec -T authentik-worker ak shell -c "$1" </dev/null 2>/dev/null | sed -n 's/^paddock-test //p'; }
paths=(paddock-dev/paddock-dev.yaml paddock/paddock-device.yaml paddock/paddock-mcp.yaml paddock/paddock-portal.yaml
  paddock/paddock-recovery.yaml paddock/paddock-stepup.yaml)
instances() {
  ak_shell '
from authentik.blueprints.models import BlueprintInstance
for i in BlueprintInstance.objects.filter(path__startswith="paddock"):
    print("paddock-test", i.path, i.status)
' | LC_ALL=C sort | paste -sd' ' -
}
all_successful="$(printf '%s successful\n' "${paths[@]}" | LC_ALL=C sort | paste -sd' ' -)"
set_instances() {
  ak_shell "
from authentik.blueprints.models import BlueprintInstance
print('paddock-test', BlueprintInstance.objects.filter(path__in=['paddock/paddock-mcp.yaml', 'paddock-dev/paddock-dev.yaml']).update($1))
"
}

tc up -d authentik-postgres authentik-server authentik-worker >/dev/null 2>&1
rc=0
"$work/scripts/authentik-apply-blueprints.sh" >"$work/run1.log" 2>&1 || rc=$?
check "the first run after a cold start exits 0" test "$rc" = 0
check "after the first run every Paddock blueprint instance is successful" test "$(instances)" = "$all_successful"
check "two instances are set to error as discovery leaves them" test "$(set_instances "status='error'")" = 2
rc=0
"$work/scripts/authentik-apply-blueprints.sh" >"$work/run2.log" 2>&1 || rc=$?
check "the second run exits 0" test "$rc" = 0
check "the second run brings the instances in error to successful" test "$(instances)" = "$all_successful"
check "an instance is disabled and set to error" test "$(set_instances "status='error', enabled=False")" = 2
rc=0
"$work/scripts/authentik-apply-blueprints.sh" >"$work/run3.log" 2>&1 || rc=$?
check "the third run fails on the instances whose apply cannot succeed" test "$rc" != 0
check "and names them with the fixed message" test \
  "$(sed -n '/^FAIL  Authentik blueprint instances: not successful/,/^      see /p' "$work/run3.log" | sed -n 's/^      - //p' |
    paste -sd' ' -)" = "paddock/paddock-mcp.yaml: status error paddock-dev/paddock-dev.yaml: status error"
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

# Counts only, the values are never printed: every value of the throwaway secrets that is long enough to be one.
leaks=0
while IFS= read -r -d '' secret; do
  value="$(tr -d '\n' <"$secret")"
  ((${#value} >= 8)) || continue
  for run in run1 run2 run3; do
    if grep -qF -- "$value" "$work/$run.log"; then leaks=$((leaks + 1)); fi
  done
done < <(find "$work/.secrets" -type f -print0)
check "no run prints a secret value ($leaks found)" test "$leaks" = 0

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

# The run logs only when no secret value is in them: CI logs are public.
if ((failures > 0 && leaks == 0)); then
  for run in run1 run2 run3; do
    echo "--- $run" >&2
    cat "$work/$run.log" >&2
  done
fi
if ((failures > 0)); then
  echo "authentik-apply-blueprints: $failures check(s) failed" >&2
  exit 1
fi
echo "authentik-apply-blueprints: all checks passed"
