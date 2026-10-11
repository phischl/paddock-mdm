#!/usr/bin/env bash
# Regression test (`make test`): generated credentials may begin with "-" (base64url), which rc parses as an option
# unless the alias arguments follow "--". Every bucket bootstrap must pass them so, and rc must accept them that way.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
rc_image="$(sed -n 's/^RC_IMAGE=//p' "$here/../versions.env")"
failures=0

for script in rustfs-audit-bootstrap.sh rustfs-bundles-bootstrap.sh rustfs-backup-bootstrap.sh; do
  if grep -q 'rc alias set -- ' "$here/$script" && ! grep -qE 'rc alias set [^-]' "$here/$script"; then
    echo "ok   $script passes the alias arguments after --"
  else
    echo "FAIL $script: rc alias set without --"
    failures=$((failures + 1))
  fi
done

# alias set connects to the endpoint, which does not exist here: only a parse error counts as a failure.
alias_set() {
  docker run --rm -e HOME=/tmp -e KEY=-Oaccess -e SECRET=-secretsecret --entrypoint sh "$rc_image" \
    -c "rc alias set $1 t http://127.0.0.1:9 \"\$KEY\" \"\$SECRET\"" 2>&1 || true
}
if [[ "$(alias_set --)" != *"unexpected argument"* ]]; then
  echo "ok   rc parses credentials beginning with - after --"
else
  echo "FAIL rc refuses credentials beginning with - after --"
  failures=$((failures + 1))
fi
if [[ "$(alias_set "")" == *"unexpected argument"* ]]; then
  echo "ok   without --, rc takes such a credential for an option (the case this test guards)"
else
  echo "FAIL rc accepts a credential beginning with - without --; the test no longer detects the case"
  failures=$((failures + 1))
fi

if ((failures > 0)); then
  echo "rustfs-alias: $failures failure(s)"
  exit 1
fi
echo "rustfs-alias: all checks passed"
