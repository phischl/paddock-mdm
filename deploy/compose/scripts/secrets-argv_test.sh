#!/usr/bin/env bash
# Regression test (`make test`, PDK-024 review 1): the bootstrap and bundle scripts never put a secret on a command
# line, where `ps` and /proc show it to every user of the host. A variable reaches a container by name only
# (`-e NAME` with NAME exported), a value of the bao CLI by stdin (`key=-`, `kv put <path> -`), a RustFS credential of
# the rc client by environment (`RC_HOST_<alias>`, `--password-from-env`, PDK-036).
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
# Positional arguments 3 and 4 of `alias set` are the access and the secret key; the third of `admin user add` is the
# secret key. The only value allowed there is the throwaway `"$(head -c <n> /dev/urandom …)"`, which scan reduces to
# `@` (review 1: a variable, a parameter, `$(cat …)`, `$(<file)` or a prefixed secret all slipped through a denylist).
# A `#` before the command marks a comment, which mentions the command in prose.
alias_pattern='(rc|mc) alias set( +-[^ ]*)*( +[^ -][^ ]*){3}'
user_pattern='^[^#]*(rc|mc) admin user add( +-[^ ]*)*( +[^ -][^ ]*){2} +[^ @>|;&]'
throwaway='\\?"\\?\$\(head -c [0-9]+ /dev/urandom[^)]*\)\\?"'

# scan <extended regular expression> <file…>: the matching lines, with backslash continuations joined so a command
# split over several lines is seen as one, and the throwaway secret as `@`.
scan() {
  local pattern="$1" f
  shift
  for f in "$@"; do
    sed ':a;/\\$/N;s/\\\n//;ta' "$f" | sed -E "s#$throwaway#@#g" | grep -nE -e "$pattern" |
      sed "s|^|${f#"$root"/}:|" || true
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
check "no credential as an argument of rc/mc alias set" "$alias_pattern"
check "no secret key as an argument of rc/mc admin user add" "$user_pattern"

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
  detects 'rc alias set -- <alias> <endpoint> $key $secret in sh -c' "$alias_pattern" \
    '    "rc alias set -- audit $ENDPOINT \"\$AWS_ACCESS_KEY_ID\" \"\$AWS_SECRET_ACCESS_KEY\" >/dev/null && $1"'
  detects 'rc alias set without --' "$alias_pattern" 'rc alias set audit http://rustfs:9000 "$AK" "$SK"'
  detects 'mc alias set with options' "$alias_pattern" 'mc alias set --api S3v4 local http://minio:9000 "$AK" "$SK"'
  detects 'rc admin user add with a "$secret"' "$user_pattern" \
    "  rc 'rc admin user add -- audit \"\$WRITER_ACCESS_KEY\" \"\$WRITER_SECRET_KEY\" >/dev/null'"
  detects 'rc admin user add with an escaped indirect secret' "$user_pattern" \
    '    rc "rc admin user add -- bundles \"\$$1\" \"\$${1/ACCESS/SECRET}\" >/dev/null"'
  detects 'mc admin user add with a bare $secret' "$user_pattern" 'mc admin user add local $AK $SK'
  detects 'rc admin user add with a positional parameter' "$user_pattern" \
    '  rc "rc admin user add -- a \"$1\" \"$2\""'
  detects 'rc admin user add with $(cat …)' "$user_pattern" \
    "rc 'rc admin user add -- a \"\$AK\" \"\$(cat /run/secrets/sk)\"'"
  detects 'rc admin user add with $(<file)' "$user_pattern" "rc 'rc admin user add -- a \"\$AK\" \"\$(<sk)\"'"
  detects 'rc admin user add with a prefixed secret' "$user_pattern" "rc 'rc admin user add -- a \"\$AK\" \"pre\$SK\"'"
  detects 'rc admin user add with a secret appended to the throwaway' "$user_pattern" \
    "rc 'rc admin user add -- a \"\$AK\" \"\$(head -c 24 /dev/urandom)\$SK\"'"
}

# ignores <description> <pattern> <sample line…>: scan does not flag the sample, a form the scripts use.
ignores() {
  local desc="$1" pattern="$2"
  shift 2
  printf '%s\n' "$@" >"$sample"
  if [[ -z "$(scan "$pattern" "$sample")" ]]; then
    echo "ok   the check accepts $desc"
  else
    echo "FAIL the check flags $desc"
    failures=$((failures + 1))
  fi
}

# shellcheck disable=SC2016 # the samples are script text, not expansions
{
  ignores 'rc admin user add with a throwaway $(…) secret' "$user_pattern" \
    "  rc 'rc admin user add -- audit \"\$WRITER_ACCESS_KEY\" \"\$(head -c 24 /dev/urandom | od -An -tx1 | tr -d \" \\n\")\" >/dev/null'"
  ignores 'rc admin user add with an escaped throwaway secret' "$user_pattern" \
    "    rc \"rc admin user add -- bundles \\\"\\\$\$1\\\" \\\"\\\$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \\n')\\\" >/dev/null\""
  ignores 'a comment that mentions rc admin user add' "$user_pattern" \
    '  # Generated keys may start with "-". rc admin user add takes the secret only as an argument, so'
  ignores 'rc admin user passwd --password-from-env' "$user_pattern" \
    "rc 'rc admin user passwd --password-from-env WRITER_SECRET_KEY -- audit \"\$WRITER_ACCESS_KEY\"'"
}

if ((failures > 0)); then
  echo "secrets-argv: $failures failure(s)"
  exit 1
fi
echo "secrets-argv: all checks passed"
