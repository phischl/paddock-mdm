#!/usr/bin/env bash
# Regression test (`make test`, PDK-024 review 1): the bootstrap and bundle scripts never put a secret on a command
# line, where `ps` and /proc show it to every user of the host. A variable reaches a container by name only
# (`-e NAME` with NAME exported), a value of the bao CLI by stdin (`key=-`, `kv put <path> -`).
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
failures=0

files=()
for f in "$root"/deploy/compose/scripts/*.sh "$root"/deploy/compose/fleet/*.sh "$root"/deploy/bundle/paddock \
  "$root"/deploy/bundle/build.sh "$root"/deploy/bundle/ci/*.sh; do
  [[ "$f" == *_test.sh ]] || files+=("$f")
done

# check <description> <extended regular expression>: no script line matches.
check() {
  local hits
  hits="$(grep -nE -e "$2" "${files[@]}" | sed "s|^$root/||" || true)"
  if [[ -z "$hits" ]]; then
    echo "ok   $1"
  else
    echo "FAIL $1:"
    printf '       %s\n' "$hits"
    failures=$((failures + 1))
  fi
}

check "no -e NAME=\$value on a docker command line" "-e [A-Z_][A-Z0-9_]*=[\"']?\\$"
check "no unseal share as an argument" "operator unseal [\"']?\\$"
check "no secret value as an argument of bao write or kv put" "bao (kv put|write) .* (key|current|previous|value|secret_id|token|password)=[\"']?\\$"

# The check itself must see a violation.
sample="$(mktemp)"
trap 'rm -f "$sample"' EXIT
printf '%s\n' 'compose exec -e BAO_TOKEN="$BAO_TOKEN" openbao bao status' >"$sample"
if grep -qE -- "-e [A-Z_][A-Z0-9_]*=[\"']?\\$" "$sample"; then
  echo "ok   the pattern detects -e NAME=\"\$NAME\""
else
  echo "FAIL the pattern misses -e NAME=\"\$NAME\""
  failures=$((failures + 1))
fi

if ((failures > 0)); then
  echo "secrets-argv: $failures failure(s)"
  exit 1
fi
echo "secrets-argv: all checks passed"
