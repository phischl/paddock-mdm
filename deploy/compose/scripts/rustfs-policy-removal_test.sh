#!/usr/bin/env bash
# Regression test (`make test`, PDK-749 review 2 M1): the bucket bootstrap removes the former bucket-wide escrow read
# policy of the api. Only rc's definite "policy not found" may skip the removal; any other rc error aborts the
# bootstrap, because a skipped removal leaves the api reading LUKS-header escrow objects while the bootstrap reports
# success. A rerun after a partial removal completes it.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
. "$here/lib.sh"
failures=0
log="$(mktemp)"
trap 'rm -f "$log"' EXIT

# The fake rc replays the output of rc v0.1.36 against RustFS 1.0.4 (probed on a throwaway instance): `policy info` of
# a missing policy exits 5 with "Policy '<name>' not found", `policy detach` of a policy no longer attached and
# `policy rm` of a missing one exit 0, `policy rm` of an attached one fails with "policy in use".
# Each scenario variable holds "<exit status>|<stdout>|<stderr>" for one rc subcommand.
INFO="" USERINFO="" DETACH="" RM=""
fake_rc() {
  local verb reply
  case "$1" in
    *"admin policy info "*) verb=info reply="$INFO" ;;
    *"admin user info "*) verb=userinfo reply="$USERINFO" ;;
    *"admin policy detach "*) verb=detach reply="$DETACH" ;;
    *"admin policy rm "*) verb=rm reply="$RM" ;;
    *) verb="unexpected:$1" reply="1||" ;;
  esac
  echo "$verb" >>"$log"
  IFS='|' read -r status out err <<<"$reply"
  [[ -n "$out" ]] && printf '%s\n' "$out"
  [[ -n "$err" ]] && printf '%s\n' "$err" >&2
  return "$status"
}

# run: the calls rc_remove_policy made, then "removed", "skipped" or "abort".
run() {
  : >"$log"
  local result
  result="$( (rc_remove_policy fake_rc bundles paddock-escrow-read ESCROW_API_ACCESS_KEY) 2>/dev/null)" && {
    [[ "$result" == *removed* ]] && result=removed || result=skipped
  } || result=abort
  printf '%s %s' "$(paste -sd, "$log")" "$result"
}
expect() {
  if [[ "$1" == "$2" ]]; then
    echo "ok   $3: $2"
  else
    echo "FAIL $3: $1, expected $2"
    failures=$((failures + 1))
  fi
}

attached='{"accessKey":"k","status":"enabled","policies":["paddock-escrow-read"],"memberOf":[]}'
detached='{"accessKey":"k","status":"enabled","policies":["paddock-escrow-api"],"memberOf":[]}'

INFO="0||" USERINFO="0|$attached|" DETACH="0||" RM="0||"
expect "$(run)" "info,userinfo,detach,rm removed" "policy present and attached"
INFO="0||" USERINFO="0|$detached|" DETACH="1||must not run" RM="0||"
expect "$(run)" "info,userinfo,rm removed" "policy present, detached by an earlier run"
INFO="5||✗ Policy 'paddock-escrow-read' not found"
expect "$(run)" "info skipped" "policy absent (fresh stack or completed removal)"
INFO="1||✗ Failed to get policy info: Authentication failed: <Code>SignatureDoesNotMatch</Code>"
expect "$(run)" "info abort" "authentication failure"
INFO="1||✗ Failed to get policy info: Network error: Request failed: error sending request"
expect "$(run)" "info abort" "unreachable endpoint"
INFO="5||✗ Alias 'bundles' not found"
expect "$(run)" "info abort" "unknown alias (also exit 5)"
INFO="2||"
expect "$(run)" "info abort" "any other exit status"
INFO="0||" USERINFO="1||✗ Failed to get user info: Network error" RM="0||"
expect "$(run)" "info,userinfo abort" "user info fails"
INFO="0||" USERINFO="0|$attached|" DETACH="1||✗ Failed to detach policy: Network error" RM="0||"
expect "$(run)" "info,userinfo,detach abort" "detach fails"
INFO="0||" USERINFO="0|$detached|"
RM='1||✗ Failed to remove policy: Network error: HTTP 500: <Error><Code>InternalError</Code><Message>policy in use</Message></Error>'
expect "$(run)" "info,userinfo,rm abort" "rm refused (policy in use)"

bootstrap="$here/rustfs-bundles-bootstrap.sh"
if grep -q '^rc_remove_policy rc bundles paddock-escrow-read ESCROW_API_ACCESS_KEY$' "$bootstrap" &&
  ! grep -q 'rc admin policy \(info\|detach\|rm\)' "$bootstrap"; then
  echo "ok   rustfs-bundles-bootstrap.sh removes paddock-escrow-read only through rc_remove_policy"
else
  echo "FAIL rustfs-bundles-bootstrap.sh: paddock-escrow-read not removed through rc_remove_policy"
  failures=$((failures + 1))
fi

if ((failures > 0)); then
  echo "rustfs-policy-removal: $failures failure(s)"
  exit 1
fi
echo "rustfs-policy-removal: all checks passed"
