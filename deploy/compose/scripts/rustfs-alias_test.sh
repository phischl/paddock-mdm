#!/usr/bin/env bash
# Regression test (`make test`): generated credentials may begin with "-" (base64url). The bucket bootstraps hand the
# root credentials to rc as RC_HOST_<alias> (PDK-036), which must accept such a key, and pass every other key after
# "--", where rc otherwise parses it as an option.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
. "$here/lib.sh"
failures=0

for pair in audit:rustfs-audit-bootstrap.sh bundles:rustfs-bundles-bootstrap.sh backup:rustfs-backup-bootstrap.sh; do
  name="${pair%%:*}" script="${pair#*:}"
  if grep -q "^export_rc_host $name " "$here/$script" && grep -q -- "-e RC_HOST_$name " "$here/$script"; then
    echo "ok   $script defines the alias $name through RC_HOST_$name"
  else
    echo "FAIL $script: alias $name not defined through export_rc_host and -e RC_HOST_$name"
    failures=$((failures + 1))
  fi
  calls="rc [\"']rc admin user (info|add|passwd) "
  if grep -qE "$calls" "$here/$script" && ! grep -E "$calls" "$here/$script" | grep -qv -- ' -- '; then
    echo "ok   $script passes the user arguments after --"
  else
    echo "FAIL $script: rc admin user without --"
    failures=$((failures + 1))
  fi
  if grep -q "rc admin user info" "$here/$script" &&
    ! grep "rc admin user info" "$here/$script" | grep -qv "if rc_user_absent rc "; then
    echo "ok   $script creates a user only when rc_user_absent confirms it is missing"
  else
    echo "FAIL $script: rc admin user info not checked through rc_user_absent"
    failures=$((failures + 1))
  fi
done

# A failed `user info` that is not "user not found" must abort before `user add`, which would replace the secret of an
# existing user (PDK-036 review 1). The fake rc replays rc v0.1.36 output of a throwaway RustFS 1.0.1.
fake_rc() {
  printf '%s\n' "${2:-}" >&2
  return "$1"
}
# absent <exit status> <stderr>: what the bootstrap does: "add", "keep", or "abort" when it exits before add.
absent() {
  (if rc_user_absent fake_rc "$@"; then echo add; else echo keep; fi) 2>/dev/null || echo abort
}
expect() {
  if [[ "$1" == "$2" ]]; then
    echo "ok   $3: $2"
  else
    echo "FAIL $3: $1, expected $2"
    failures=$((failures + 1))
  fi
}
expect "$(absent 5 "✗ User '-Okey' not found")" add "user not found"
expect "$(absent 0)" keep "user exists"
expect "$(absent 1 "✗ Failed to get user info: Authentication failed: <Code>SignatureDoesNotMatch</Code>")" abort \
  "authentication failure"
expect "$(absent 1 "✗ Failed to get user info: Network error: Request failed: error sending request")" abort \
  "unreachable endpoint"
expect "$(absent 5 "✗ Alias 'audit' not found")" abort "unknown alias (also exit 5)"
expect "$(absent 2)" abort "any other exit status"

# The alias reaches no endpoint here: rc must list it, i.e. accept the URL export_rc_host builds.
KEY=-Oaccess SECRET='-s/e:c@r%e+t='
export_rc_host t http://127.0.0.1:9 KEY SECRET
if docker run --rm -e HOME=/tmp -e RC_HOST_t --entrypoint rc "$RC_IMAGE" alias list --json 2>&1 |
  grep -q '"endpoint": "http://127.0.0.1:9"'; then
  echo "ok   rc accepts RC_HOST with a key beginning with - and reserved characters in the secret"
else
  echo "FAIL rc rejects the RC_HOST value of export_rc_host"
  failures=$((failures + 1))
fi

real_rc() { docker run --rm -e HOME=/tmp -e RC_HOST_t --entrypoint rc "$RC_IMAGE" admin user info -- t -Okey; }
expect "$( (if rc_user_absent real_rc; then echo add; else echo keep; fi) 2>/dev/null || echo abort)" abort \
  "rc against an unreachable endpoint"

# passwd connects to the endpoint, which does not exist here: only a parse error counts as a failure.
passwd() {
  docker run --rm -e HOME=/tmp -e RC_HOST_t -e KEY -e SECRET --entrypoint sh "$RC_IMAGE" \
    -c "rc admin user passwd --password-from-env SECRET $1 t \"\$KEY\"" 2>&1 || true
}
export KEY SECRET
if [[ "$(passwd --)" != *"unexpected argument"* ]]; then
  echo "ok   rc parses a key beginning with - after --"
else
  echo "FAIL rc refuses a key beginning with - after --"
  failures=$((failures + 1))
fi
if [[ "$(passwd "")" == *"unexpected argument"* ]]; then
  echo "ok   without --, rc takes such a key for an option (the case this test guards)"
else
  echo "FAIL rc accepts a key beginning with - without --; the test no longer detects the case"
  failures=$((failures + 1))
fi

if ((failures > 0)); then
  echo "rustfs-alias: $failures failure(s)"
  exit 1
fi
echo "rustfs-alias: all checks passed"
