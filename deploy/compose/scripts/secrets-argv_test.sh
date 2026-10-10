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

env_pattern="(-e|--env)[ =][\"']?[A-Z_][A-Z0-9_]*=[\"']?\\$"
unseal_pattern="operator unseal( --)? [\"']?\\$"
kv_pattern="bao (kv put|write) .* (current|previous|value|[a-z_]*(key|secret|secret_id|token|password))=[\"']?\\$"

# scan <extended regular expression> <file…>: the matching lines, with backslash continuations joined so a command
# split over several lines is seen as one.
scan() {
  local pattern="$1" f
  shift
  for f in "$@"; do
    sed ':a;/\\$/N;s/\\\n//;ta' "$f" | grep -nE -e "$pattern" | sed "s|^|${f#"$root"/}:|" || true
  done
}

# check <description> <extended regular expression>: no script line matches.
check() {
  local hits
  hits="$(scan "$2" "${files[@]}")"
  if [[ -z "$hits" ]]; then
    echo "ok   $1"
  else
    echo "FAIL $1:"
    printf '       %s\n' "$hits"
    failures=$((failures + 1))
  fi
}

check "no -e/--env NAME=\$value on a docker command line" "$env_pattern"
check "no unseal share as an argument" "$unseal_pattern"
check "no secret value as an argument of bao write or kv put" "$kv_pattern"

# The checks themselves must see every known form of a violation (review 2: the multi-line kv put of the parent
# commit of fix round 1 went unnoticed).
sample="$(mktemp)"
trap 'rm -f "$sample"' EXIT
# detects <description> <pattern> <sample line…>: scan finds the sample.
detects() {
  local desc="$1" pattern="$2"
  shift 2
  printf '%s\n' "$@" >"$sample"
  if [[ -n "$(scan "$pattern" "$sample")" ]]; then
    echo "ok   the check detects $desc"
  else
    echo "FAIL the check misses $desc"
    failures=$((failures + 1))
  fi
}

# shellcheck disable=SC2016 # the samples are script text, not expansions
{
  detects '-e NAME="$x"' "$env_pattern" 'compose exec -e BAO_TOKEN="$BAO_TOKEN" openbao bao status'
  detects '-e "NAME=$x"' "$env_pattern" 'docker run -e "BAO_TOKEN=$token" image'
  detects '--env NAME=$x' "$env_pattern" 'docker run --env BAO_TOKEN=$token image'
  detects '--env=NAME=$x' "$env_pattern" 'docker run --env=BAO_TOKEN="$token" image'
  detects '-e NAME=$x on a continuation line' "$env_pattern" 'docker run --rm \' '  -e BAO_TOKEN="$t" image'
  detects 'operator unseal $x' "$unseal_pattern" 'bao operator unseal "$share"'
  detects 'operator unseal -- $x' "$unseal_pattern" 'bao operator unseal -- "$share"'
  detects 'kv put key=$x' "$kv_pattern" 'bao kv put secret/paddock/x api_key="$k"'
  detects 'a multi-line kv put' "$kv_pattern" \
    'compose exec -T -e BAO_TOKEN openbao bao kv put secret/paddock/session \' \
    '  current="$(openssl rand -hex 32)" \' \
    '  previous=""'
}

if ((failures > 0)); then
  echo "secrets-argv: $failures failure(s)"
  exit 1
fi
echo "secrets-argv: all checks passed"
