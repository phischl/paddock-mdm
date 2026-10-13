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
# Only pipes into od or tr may follow head; a `;`, `&`, `$` or nested `$(` there could append a real secret (PDK-046).
# od and tr take only options there, tr also a quoted set: any other word is a file operand, which od reads instead
# of stdin (PDK-056). A set holds no `$` or backtick, single-quoted or not: inside an outer `rc "…"` the outer shell
# expands them.
# A `#` that starts a word before the command marks a comment, which mentions the command in prose; `${#x}` or `$#`
# does not, nor does a `#` inside a quoted string (PDK-056). Any whitespace separates arguments, a tab included.
alias_pattern='(rc|mc)[[:space:]]+alias[[:space:]]+set([[:space:]]+-[^[:space:]]*)*([[:space:]]+[^[:space:]-][^[:space:]]*){3}'
user_pattern='^([^#]|"[^"]*"|'"'[^']*'"'|[^[:space:]]#+)*(rc|mc)[[:space:]]+admin[[:space:]]+user[[:space:]]+add([[:space:]]+-[^[:space:]]*)*([[:space:]]+[^[:space:]-][^[:space:]]*){2}[[:space:]]+[^[:space:]@>|;&]'
# shellcheck disable=SC2016 # regular expressions, not expansions
option=' +-[^[:space:]|;&$()<>`"'"'"'\/]*'
# shellcheck disable=SC2016 # regular expressions, not expansions
tr_set=' +"[^"$`]*"| +'"'[^'"'$`]*'"'"
throwaway='\\?"\\?\$\(head -c [0-9]+ /dev/urandom( *\| *(od('"$option"')*|tr('"$option|$tr_set"')*))* *\)\\?"'

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
  detects 'rc admin user add with a command after the throwaway head' "$user_pattern" \
    "rc 'rc admin user add -- a \"\$AK\" \"\$(head -c 24 /dev/urandom; cat /run/secrets/sk)\"'"
  detects 'rc admin user add after a ${#x} on the same line' "$user_pattern" \
    'x=${#AK}; rc admin user add -- a "$AK" "$SK"'
  detects 'rc admin user add with tabs between the arguments' "$user_pattern" \
    $'rc admin user add --\ta\t"$AK"\t"$SK"'
  detects 'rc alias set with tabs between the arguments' "$alias_pattern" \
    $'rc alias set\taudit\thttp://rustfs:9000\t"$AK"\t"$SK"'
  detects 'rc admin user add with a file operand to od in the throwaway' "$user_pattern" \
    "rc 'rc admin user add -- a \"\$AK\" \"\$(head -c 24 /dev/urandom|od -An -tx1 /run/secrets/sk)\"'"
  detects 'rc admin user add with a file operand to tr in the throwaway' "$user_pattern" \
    "rc 'rc admin user add -- a \"\$AK\" \"\$(head -c 24 /dev/urandom | od -An -tx1 | tr -d \" \\n\" /run/secrets/sk)\"'"
  detects "rc admin user add with \$(…) in a single-quoted tr set inside rc \"…\"" "$user_pattern" \
    $'rc "rc admin user add -- b \\"\\$1\\" \\"\\$(head -c 24 /dev/urandom | od -An | tr -d \'$(rc admin user add -- x $AK $SK)\')\\""'
  detects "rc admin user add with \$SK in a single-quoted tr set inside rc \"…\"" "$user_pattern" \
    $'rc "rc admin user add -- b \\"\\$1\\" \\"\\$(head -c 24 /dev/urandom | od -An | tr -d \'$SK\')\\""'
  detects "rc admin user add with a backtick in a single-quoted tr set inside rc \"…\"" "$user_pattern" \
    $'rc "rc admin user add -- b \\"\\$1\\" \\"\\$(head -c 24 /dev/urandom | od -An | tr -d \'`cat sk`\')\\""'
  detects 'rc admin user add after a "#" inside double quotes' "$user_pattern" \
    'echo "a #b"; rc admin user add -- a "$AK" "$SK"'
  detects "rc admin user add after a '#' inside single quotes" "$user_pattern" \
    "echo 'a #b'; rc admin user add -- a \"\$AK\" \"\$SK\""
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
  ignores 'rc admin user add with a throwaway without spaces around the pipes' "$user_pattern" \
    "rc 'rc admin user add -- a \"\$AK\" \"\$(head -c 24 /dev/urandom|od -An -tx1|tr -d \" \\n\")\"'"
  ignores 'a comment with a quoted "#" that mentions rc admin user add' "$user_pattern" \
    '  # The "#" sign: rc admin user add -- a "$AK" "$SK" would put the secret on the command line'
}

# The lab mode of gen-prod-secrets.sh (plan M8a decision 7): one run in a copy of the Compose directory writes both
# parts with a local audit reader link and names files only, never a value.
lab="$(mktemp -d)"
trap 'rm -f "$sample"; rm -rf "$lab"' EXIT
mkdir -p "$lab/scripts" "$lab/rabbitmq"
cp "$root"/deploy/compose/scripts/{lib.sh,gen-prod-secrets.sh} "$lab/scripts/"
cp "$root/deploy/compose/rabbitmq/definitions.json.tmpl" "$lab/rabbitmq/"
cp "$root/deploy/compose/versions.env" "$lab/"
cp "$root/deploy/compose/lab.env.example" "$lab/.env"
# lab_check <description> <command…>: the command succeeds.
lab_check() {
  local desc="$1"
  shift
  if "$@"; then echo "ok   lab secrets: $desc"; else
    echo "FAIL lab secrets: $desc"
    failures=$((failures + 1))
  fi
}
if lab_out="$(env -u SECRETS_DIR -u PADDOCK_HOST -u PADDOCK_ENV -u PADDOCK_INTERCONNECT_ADDR \
  "$lab/scripts/gen-prod-secrets.sh" lab 2>&1)"; then
  echo "ok   lab secrets: gen-prod-secrets.sh lab exits 0"
else
  echo "FAIL lab secrets: gen-prod-secrets.sh lab failed: $lab_out"
  failures=$((failures + 1))
fi
reader_url="$(cat "$lab/.secrets/db_paddock_audit_reader_url" 2>/dev/null || true)"
lab_check "the audit reader URL names audit-postgres without TLS" \
  grep -qE '@audit-postgres:5432/paddock_audit\?sslmode=disable$' <<<"$reader_url"
lab_check "openbao and rabbitmq certificates exist" test -s "$lab/.secrets/tls/openbao.crt" -a -s "$lab/.secrets/tls/rabbitmq.crt"
lab_check "no audit-postgres certificate" test ! -e "$lab/.secrets/tls/audit-postgres.crt"
no_copy_message() { ! grep -qiE "the (audit|control-plane|other) host|peer-ca" <<<"$lab_out"; }
lab_check "nothing is to be copied to or from another host" no_copy_message
leaked=()
while IFS= read -r -d '' f; do
  value="$(cat "$f")"
  [[ ${#value} -ge 8 && "$lab_out" == *"$value"* ]] && leaked+=("${f#"$lab"/}")
done < <(find "$lab/.secrets" -type f -print0)
lab_check "no secret value in the output" test "${#leaked[@]}" -eq 0
((${#leaked[@]} == 0)) || printf '       value of %s printed\n' "${leaked[@]}"

if ((failures > 0)); then
  echo "secrets-argv: $failures failure(s)"
  exit 1
fi
echo "secrets-argv: all checks passed"
