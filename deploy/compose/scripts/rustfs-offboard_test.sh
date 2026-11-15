#!/usr/bin/env bash
# Tests of the organization deletion's object-store credentials (`make test`, plan M17 amendment k, PDK-1054):
#   1. the policy documents allow list and delete only, below the organizations' prefixes, and never s3:GetObject;
#   2. against a throwaway RustFS, rustfs-bundles-bootstrap.sh creates both users, and with their keys GetObject is
#      denied, every other prefix is denied and the allowed deletes succeed;
#   3. --add-missing (./paddock upgrade) adds the two users to an installation that predates them and changes nothing
#      else: every other policy, every other user's secret and policies, and every escrowed object version stay as
#      they were; a second run changes nothing at all;
#   4. no key is ever printed;
#   5. --add-missing leaves one user per offboarding policy, the key file's (PDK-1054d): a stale user of either policy is
#      removed after the current user's probe passed, a user of another policy is untouched, a second run changes
#      nothing, and a broken current key file fails loudly and removes nothing.
# Needs Docker and python3, like the rest of `make test`; it fails rather than skips without them.
# The rc commands name keys as $VARIABLES that only the container expands (SC2016); ok never fails (SC2015).
# shellcheck disable=SC2016,SC2015
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
. "$here/lib.sh"
failures=0
ok() { echo "ok   $*"; }
fail() {
  echo "FAIL $*"
  failures=$((failures + 1))
}

# --- 1. Policy documents ---------------------------------------------------------------------------------------------

policy_problems() {
  python3 -c '
import json, sys
kind, doc = sys.argv[1], json.loads(sys.argv[2])
b = "arn:aws:s3:::bkt"
want = {
    "bundles": [
        (["s3:ListBucket"], [b], ["org/*", "apt/*"]),
        (["s3:DeleteObject"], [b + "/org/*", b + "/apt/*"], None),
    ],
    "escrow": [
        (["s3:ListBucket", "s3:ListBucketVersions"], [b], ["org/*"]),
        (["s3:DeleteObject", "s3:DeleteObjectVersion"],
         [b + "/org/*/devices/*/luks-header/*", b + "/org/*/devices/*/diagnostics/*"], None),
    ],
}[kind]
problems = []
actions = [a for st in doc for a in st.get("Action", [])]
if any(a.lower().startswith("s3:get") for a in actions):
    problems.append("grants a read action: %s" % actions)
if any("*" in a for a in actions):
    problems.append("grants a wildcard action: %s" % actions)
if any(st.get("Effect") != "Allow" or "NotAction" in st or "NotResource" in st or "Principal" in st for st in doc):
    problems.append("unexpected statement form")
got = [(st["Action"], st["Resource"], st.get("Condition", {}).get("StringLike", {}).get("s3:prefix")) for st in doc]
if got != want:
    problems.append("statements %s, want %s" % (got, want))
for st in doc:
    if set(st.get("Condition", {})) - {"StringLike"}:
        problems.append("unexpected condition %s" % st["Condition"])
print("; ".join(problems))
' "$1" "$2"
}
command -v python3 >/dev/null || {
  echo "FAIL python3 is required"
  exit 1
}
for kind in bundles escrow; do
  problems="$(policy_problems "$kind" "$("offboard_${kind}_statements" bkt)")"
  if [[ -z "$problems" ]]; then
    ok "$kind offboard policy: list and delete below the organizations' prefixes, no GetObject"
  else
    fail "$kind offboard policy: $problems"
  fi
  # The bootstrap must create the policy from exactly these statements.
  bucket_var=BUCKET
  [[ "$kind" == escrow ]] && bucket_var=ESCROW_BUCKET
  if grep -qF "policy paddock-$kind-offboard \"\$(offboard_${kind}_statements \"\$$bucket_var\")\"" "$here/rustfs-bundles-bootstrap.sh"; then
    ok "the bootstrap creates paddock-$kind-offboard from offboard_${kind}_statements"
  else
    fail "the bootstrap does not create paddock-$kind-offboard from offboard_${kind}_statements"
  fi
done
# A document granting a read must be caught by the check above, or the check proves nothing.
leaky='[{"Effect":"Allow","Action":["s3:ListBucket"],"Resource":["arn:aws:s3:::bkt"],"Condition":{"StringLike":{"s3:prefix":["org/*","apt/*"]}}},{"Effect":"Allow","Action":["s3:DeleteObject","s3:GetObject"],"Resource":["arn:aws:s3:::bkt/org/*","arn:aws:s3:::bkt/apt/*"]}]'
[[ "$(policy_problems bundles "$leaky")" == *"read action"* ]] && ok "the policy check catches a GetObject" ||
  fail "the policy check missed a GetObject"

# --- 2.–4. Against a throwaway RustFS --------------------------------------------------------------------------------

command -v docker >/dev/null || {
  echo "FAIL docker is required"
  exit 1
}
work="$(mktemp -d)"
net="paddock-offboard-test-$$"
store="paddock-offboard-rustfs-$$"
cleanup() {
  docker rm -f "$store" >/dev/null 2>&1 || true
  docker network rm "$net" >/dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT
export SECRETS_DIR="$work/secrets" NETWORK="$net" ENDPOINT="http://rustfs:9000"
mkdir -m 700 "$SECRETS_DIR"
# Keys start with "-" now and then, as generated ones do (rustfs-alias_test.sh).
rand() { head -c 18 /dev/urandom | base64 -w0 | tr '+/' '-_'; }
for name in rustfs_root_user rustfs_root_password; do rand >"$SECRETS_DIR/$name"; done
for role in compiler gateway api worker offboard; do
  for k in access secret; do rand >"$SECRETS_DIR/rustfs_bundles_${role}_${k}_key"; done
done
for k in access secret; do rand >"$SECRETS_DIR/rustfs_artifacts_api_${k}_key"; done
for role in worker api revocation backup offboard; do
  for k in access secret; do rand >"$SECRETS_DIR/rustfs_escrow_${role}_${k}_key"; done
done

RUSTFS_ACCESS_KEY="$(cat "$SECRETS_DIR/rustfs_root_user")" RUSTFS_SECRET_KEY="$(cat "$SECRETS_DIR/rustfs_root_password")"
RC_HOST_t="http://$(percent_encode "$RUSTFS_ACCESS_KEY"):$(percent_encode "$RUSTFS_SECRET_KEY")@rustfs:9000"
export RUSTFS_ACCESS_KEY RUSTFS_SECRET_KEY RC_HOST_t
docker network create "$net" >/dev/null
docker run -d --name "$store" --network "$net" --network-alias rustfs -e RUSTFS_ACCESS_KEY -e RUSTFS_SECRET_KEY \
  -e RUSTFS_CONSOLE_ENABLE=false -e RUSTFS_OBS_LOG_DIRECTORY= "$RUSTFS_IMAGE" >/dev/null

key() { cat "$SECRETS_DIR/$1"; }
# s3 <access key file> <secret key file> <aws arguments…>: the AWS CLI with that credential; keys travel as inherited
# environment variables only.
s3() {
  AWS_ACCESS_KEY_ID="$(key "$1")" AWS_SECRET_ACCESS_KEY="$(key "$2")" \
    docker run --rm -i --network "$net" -e AWS_ACCESS_KEY_ID -e AWS_SECRET_ACCESS_KEY -e AWS_DEFAULT_REGION=us-east-1 \
    -e AWS_PAGER= "$AWS_CLI_IMAGE" --endpoint-url "$ENDPOINT" "${@:3}"
}
root() { s3 rustfs_root_user rustfs_root_password "$@"; }
# rcx <shell command>: rc with the root alias t; the command names keys only as $VARIABLES of its environment.
rcx() {
  docker run --rm -i --network "$net" -e HOME=/tmp -e RC_HOST_t -e K -e S --entrypoint sh "$RC_IMAGE" -c "$1"
}
leaked() {
  local f
  for f in "$SECRETS_DIR"/*; do
    if grep -qF -- "$(cat "$f")" "$1"; then
      basename "$f"
      return 0
    fi
  done
  return 1
}
bootstrap() { "$here/rustfs-bundles-bootstrap.sh" "$@" >"$work/out" 2>&1; }
# shown [lines]: the bootstrap's output, its last lines only when given, with every key replaced, for a failure message.
shown() {
  local t f
  if [[ -n "${1:-}" ]]; then t="$(tail -"$1" "$work/out")"; else t="$(shown)"; fi
  for f in "$SECRETS_DIR"/*; do t="${t//"$(cat "$f")"/<redacted>}"; done
  printf '%s' "$t"
}

if bootstrap; then
  ok "fresh bootstrap"
else
  fail "fresh bootstrap: $(shown 3)"
  exit 1
fi
if name="$(leaked "$work/out")"; then fail "the fresh bootstrap printed the key $name"; else ok "the fresh bootstrap prints no key"; fi
grep -q "organization deletion credential of paddock-bundles verified" "$work/out" &&
  grep -q "organization deletion credential of paddock-escrow verified" "$work/out" &&
  ok "the bootstrap verifies both offboard credentials" || fail "the bootstrap did not verify the offboard credentials"

# Objects of two organizations and outside them.
put() {
  AWS_ACCESS_KEY_ID="$(key rustfs_root_user)" AWS_SECRET_ACCESS_KEY="$(key rustfs_root_password)" BODY="$3" \
    docker run --rm --network "$net" -e AWS_ACCESS_KEY_ID -e AWS_SECRET_ACCESS_KEY -e AWS_DEFAULT_REGION=us-east-1 -e BODY \
    --entrypoint sh "$AWS_CLI_IMAGE" -c "printf %s \"\$BODY\" >/tmp/b && aws --endpoint-url $ENDPOINT s3api put-object --bucket $1 --key $2 --body /tmp/b >/dev/null"
}
A=org/aaaa B=org/bbbb
put paddock-bundles "$A/bundle" a1
put paddock-bundles "apt/aaaa/pool/p.deb" a2
put paddock-bundles "keep/x" k
put paddock-escrow "$A/devices/d1/luks-header/h" v1
put paddock-escrow "$A/devices/d1/luks-header/h" v2
put paddock-escrow "$A/devices/d1/diagnostics/z" diag
put paddock-escrow "$A/devices/d1/other/o" other
put paddock-escrow "$B/devices/d2/luks-header/h" b1

ob=(rustfs_bundles_offboard_access_key rustfs_bundles_offboard_secret_key)
oe=(rustfs_escrow_offboard_access_key rustfs_escrow_offboard_secret_key)
# expect_denied <description> <s3 arguments…>: the call must fail with AccessDenied.
expect_denied() {
  local d="$1" err
  shift
  if err="$(s3 "$@" 2>&1 >/dev/null)"; then
    fail "$d: allowed"
  elif [[ "$err" == *AccessDenied* ]]; then
    ok "$d: AccessDenied"
  else
    fail "$d: failed, but not with AccessDenied: $err"
  fi
}
expect_allowed() {
  local d="$1" err
  shift
  if err="$(s3 "$@" 2>&1 >/dev/null)"; then ok "$d: allowed"; else fail "$d: $err"; fi
}
expect_denied "bundles offboard GetObject org/" "${ob[@]}" s3api get-object --bucket paddock-bundles --key "$A/bundle" /dev/null
expect_denied "bundles offboard GetObject apt/" "${ob[@]}" s3api get-object --bucket paddock-bundles --key apt/aaaa/pool/p.deb /dev/null
expect_denied "bundles offboard PutObject org/" "${ob[@]}" s3api put-object --bucket paddock-bundles --key "$A/new"
expect_denied "bundles offboard list keep/" "${ob[@]}" s3api list-objects-v2 --bucket paddock-bundles --prefix keep/
expect_denied "bundles offboard delete keep/" "${ob[@]}" s3api delete-object --bucket paddock-bundles --key keep/x
expect_denied "bundles offboard list escrow" "${ob[@]}" s3api list-objects-v2 --bucket paddock-escrow --prefix org/
expect_denied "escrow offboard GetObject header" "${oe[@]}" s3api get-object --bucket paddock-escrow --key "$A/devices/d1/luks-header/h" /dev/null
expect_denied "escrow offboard GetObject diagnostics" "${oe[@]}" s3api get-object --bucket paddock-escrow --key "$A/devices/d1/diagnostics/z" /dev/null
expect_denied "escrow offboard PutObject header" "${oe[@]}" s3api put-object --bucket paddock-escrow --key "$A/devices/d1/luks-header/n"
expect_denied "escrow offboard delete other prefix" "${oe[@]}" s3api delete-object --bucket paddock-escrow --key "$A/devices/d1/other/o"
expect_denied "escrow offboard list bundles" "${oe[@]}" s3api list-objects-v2 --bucket paddock-bundles --prefix org/
expect_allowed "bundles offboard list org/" "${ob[@]}" s3api list-objects-v2 --bucket paddock-bundles --prefix "$A/"
expect_allowed "bundles offboard list apt/" "${ob[@]}" s3api list-objects-v2 --bucket paddock-bundles --prefix apt/aaaa/
expect_allowed "escrow offboard list versions org/" "${oe[@]}" s3api list-object-versions --bucket paddock-escrow --prefix "$A/"

# --- 3a. --add-missing removes the known-obsolete paddock-escrow-read, never the api's only escrow grant -------------

api_key="$(key rustfs_escrow_api_access_key)"
api_policies() { K="$api_key" S="" rcx 'rc admin user info --json -- t "$K"'; }
# An installation from before M12 (PDK-749): the api holds the bucket-wide escrow read.
K="$api_key" S="" rcx 'printf "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"s3:GetObject\"],\"Resource\":[\"arn:aws:s3:::paddock-escrow/*\"]}]}" >/tmp/p.json &&
  rc admin policy create t paddock-escrow-read /tmp/p.json >/dev/null && rc admin policy attach t paddock-escrow-read --user="$K" >/dev/null'
# Guard: without paddock-escrow-api the obsolete policy is the api's only grant; --add-missing must refuse loudly.
K="$api_key" S="" rcx 'rc admin policy detach t paddock-escrow-api --user="$K" >/dev/null'
if bootstrap --add-missing; then
  fail "--add-missing removed the api's only escrow grant"
elif grep -q "refusing to remove the former policy paddock-escrow-read: its holder lacks paddock-escrow-api" "$work/out"; then
  ok "--add-missing refuses to remove the api's only escrow grant"
else
  fail "--add-missing failed differently: $(shown 3)"
fi
info="$(api_policies)"
[[ "$info" == *'"paddock-escrow-read"'* ]] && ok "the refused run removed nothing" || fail "the refused run detached paddock-escrow-read"
if name="$(leaked "$work/out")"; then fail "the refused run printed the key $name"; else ok "the refused run prints no key"; fi
# With paddock-escrow-api attached, --add-missing removes the obsolete policy and keeps the api's grant.
K="$api_key" S="" rcx 'rc admin policy attach t paddock-escrow-api --user="$K" >/dev/null'
if bootstrap --add-missing && grep -q "removed the former policy paddock-escrow-read" "$work/out"; then
  ok "--add-missing removes the obsolete paddock-escrow-read"
else
  fail "--add-missing kept paddock-escrow-read: $(shown 3)"
fi
info="$(api_policies)"
[[ "$info" != *'"paddock-escrow-read"'* && "$info" == *'"paddock-escrow-api"'* ]] &&
  ok "the api keeps paddock-escrow-api and loses paddock-escrow-read" || fail "the api's policies after the removal are wrong"
expect_denied "api GetObject outside headers and diagnostics after the removal" rustfs_escrow_api_access_key \
  rustfs_escrow_api_secret_key s3api get-object --bucket paddock-escrow --key "$A/devices/d1/other/o" /dev/null

# --- 3. --add-missing on an installation that predates the offboard users -------------------------------------------

for role in bundles escrow; do
  K="$(key "rustfs_${role}_offboard_access_key")" S="" rcx "rc admin user rm -- t \"\$K\" >/dev/null && rc admin policy rm t paddock-$role-offboard >/dev/null"
done
# The operator's worker secret differs from its file: an upgrade must keep what RustFS holds (it never resets a secret).
K="$(key rustfs_escrow_worker_access_key)" S="kept-by-the-upgrade-$$" rcx 'rc admin user passwd --password-from-env S -- t "$K" >/dev/null'
policies="paddock-bundles-compiler paddock-bundles-gateway paddock-artifacts-api paddock-bundles-api paddock-bundles-worker paddock-escrow-worker paddock-escrow-api paddock-escrow-destroy paddock-escrow-backup"
snapshot() {
  local p f
  for p in $policies; do K="" S="" rcx "rc admin policy info t $p --json"; done
  for f in "$SECRETS_DIR"/rustfs_*_access_key; do
    [[ "$f" == *offboard* ]] && continue
    K="$(cat "$f")" S="" rcx 'rc admin user info --json -- t "$K"'
  done
  root s3api list-object-versions --bucket paddock-escrow --query '[Versions[].[Key,VersionId,ETag,IsLatest],DeleteMarkers]'
  root s3api get-bucket-versioning --bucket paddock-escrow
  root s3api get-bucket-policy --bucket paddock-agent-artifacts
}
snapshot >"$work/before"
# An empty or failed snapshot would compare equal to the next one and prove nothing.
if grep -q '"s3:DeleteObjectVersion"' "$work/before" && grep -q "luks-header/h" "$work/before" &&
  [[ "$(grep -c '"accessKey"' "$work/before")" -eq 9 ]]; then
  ok "the snapshot holds the policies, the nine other users and the escrowed versions"
else
  # The snapshot names access keys, so only its shape is printed.
  fail "the snapshot is incomplete: $(wc -l <"$work/before") lines, $(grep -c '"accessKey"' "$work/before") users"
fi
if bootstrap --add-missing; then ok "--add-missing"; else fail "--add-missing: $(shown 3)"; fi
if name="$(leaked "$work/out")"; then fail "--add-missing printed the key $name"; else ok "--add-missing prints no key"; fi
grep -q "created bundles user for paddock-bundles-offboard" "$work/out" &&
  grep -q "created bundles user for paddock-escrow-offboard" "$work/out" &&
  ok "--add-missing creates both offboard users" || fail "--add-missing did not create the offboard users: $(shown)"
grep -q "versioning of paddock-escrow enabled\|is public-read" "$work/out" &&
  fail "--add-missing reconfigured an existing bucket or policy" || ok "--add-missing leaves the buckets' configuration alone"
snapshot >"$work/after"
if cmp -s "$work/before" "$work/after"; then
  ok "--add-missing keeps every other policy, user and escrowed object version"
else
  fail "--add-missing changed existing state at lines $(diff "$work/before" "$work/after" | grep -E '^[0-9]' | paste -sd, -)"
fi
if AWS_ACCESS_KEY_ID="$(key rustfs_escrow_worker_access_key)" AWS_SECRET_ACCESS_KEY="kept-by-the-upgrade-$$" \
    docker run --rm --network "$net" -e AWS_ACCESS_KEY_ID -e AWS_SECRET_ACCESS_KEY -e AWS_DEFAULT_REGION=us-east-1 \
    "$AWS_CLI_IMAGE" --endpoint-url "$ENDPOINT" s3api list-object-versions --bucket paddock-escrow --max-items 1 >/dev/null 2>&1; then
  ok "--add-missing keeps an existing user's secret"
else
  fail "--add-missing reset an existing user's secret"
fi
if bootstrap --add-missing && ! grep -q "^created\|enabled$\|public-read$" "$work/out"; then
  ok "a second --add-missing creates nothing"
else
  fail "a second --add-missing: $(shown)"
fi
snapshot >"$work/again"
cmp -s "$work/after" "$work/again" && ok "a second --add-missing changes nothing" || fail "a second --add-missing changed state"
expect_denied "escrow offboard GetObject after --add-missing" "${oe[@]}" s3api get-object --bucket paddock-escrow --key "$A/devices/d1/luks-header/h" /dev/null

# The deletes the offboarding step needs, after the upgrade.
# The AWS CLI prints "None" for an empty result.
versions() {
  root s3api list-object-versions --bucket paddock-escrow --prefix "$1" --query 'Versions[].VersionId' --output text |
    sed 's/^None$//'
}
for v in $(versions "$A/devices/d1/luks-header/h"); do
  expect_allowed "escrow offboard delete header version" "${oe[@]}" s3api delete-object --bucket paddock-escrow \
    --key "$A/devices/d1/luks-header/h" --version-id "$v"
done
for v in $(versions "$A/devices/d1/diagnostics/z"); do
  expect_allowed "escrow offboard delete diagnostics version" "${oe[@]}" s3api delete-object --bucket paddock-escrow \
    --key "$A/devices/d1/diagnostics/z" --version-id "$v"
done
[[ -z "$(versions "$A/devices/d1/luks-header/")" ]] && ok "no header version of the organization is left" ||
  fail "header versions left"
[[ -n "$(versions "$B/devices/d2/luks-header/h")" && -n "$(versions "$A/devices/d1/other/o")" ]] &&
  ok "the other organization's header and other prefixes survive" || fail "objects outside the deleted ones are gone"
expect_allowed "bundles offboard delete org/" "${ob[@]}" s3api delete-object --bucket paddock-bundles --key "$A/bundle"
expect_allowed "bundles offboard delete apt/" "${ob[@]}" s3api delete-object --bucket paddock-bundles --key apt/aaaa/pool/p.deb

# A user the bootstrap cannot verify fails it instead of passing as ready.
K="$(key rustfs_escrow_offboard_access_key)" S="not-the-file-$$" rcx 'rc admin user passwd --password-from-env S -- t "$K" >/dev/null'
if bootstrap --add-missing; then
  fail "--add-missing passed with an offboard user whose secret differs from its file"
elif grep -q "cannot list org/ of paddock-escrow: run ./paddock bootstrap buckets" "$work/out"; then
  ok "--add-missing fails on an offboard credential it cannot verify"
else
  fail "--add-missing failed differently: $(shown 3)"
fi
if bootstrap; then ok "a full bootstrap repairs it"; else fail "a full bootstrap: $(shown 3)"; fi

# --- 5. One user per offboarding policy -------------------------------------------------------------------------------

rc_root() { rcx "$1"; }
holders() { rc_policy_holders rc_root t "$1" | sort | paste -sd, -; }
# add_user <access key> <policy>: a user holding only that policy (rc replaces a user's policies on attach).
add_user() {
  K="$1" S="stale-secret-$$-$RANDOM-$RANDOM" rcx 'rc admin user add -- t "$K" "$S" >/dev/null && rc admin policy attach t '"$2"' --user="$K" >/dev/null'
}
cur_b="$(key rustfs_bundles_offboard_access_key)" cur_e="$(key rustfs_escrow_offboard_access_key)"
stale_b1="stale-bundles-one-$$" stale_b2="stale-bundles-two-$$" stale_e1="stale-escrow-one-$$" other="unrelated-user-$$"
add_user "$stale_b1" paddock-bundles-offboard
add_user "$stale_b2" paddock-bundles-offboard
add_user "$stale_e1" paddock-escrow-offboard
add_user "$other" paddock-bundles-gateway
[[ "$(holders paddock-bundles-offboard)" == *"$stale_b1"* && "$(holders paddock-escrow-offboard)" == *"$stale_e1"* ]] &&
  ok "the stale users hold the offboarding policies" || fail "the test setup did not create the stale users"
gateway_before="$(holders paddock-bundles-gateway)"
if bootstrap --add-missing; then ok "--add-missing with stale offboard users"; else fail "--add-missing with stale offboard users: $(shown 4)"; fi
[[ "$(holders paddock-bundles-offboard)" == "$cur_b" ]] && ok "the bundles policy keeps only the key file's user" ||
  fail "the bundles policy is held by: $(holders paddock-bundles-offboard)"
[[ "$(holders paddock-escrow-offboard)" == "$cur_e" ]] && ok "the escrow policy keeps only the key file's user" ||
  fail "the escrow policy is held by: $(holders paddock-escrow-offboard)"
[[ "$(holders paddock-bundles-gateway)" == "$gateway_before" && "$gateway_before" == *"$other"* ]] &&
  ok "a user of another policy is untouched" || fail "a user of another policy changed: $(holders paddock-bundles-gateway)"
for k in "$stale_b1" "$stale_b2" "$stale_e1"; do
  grep -qF "removed the stale" "$work/out" && grep -qF -- " $k " "$work/out" && continue
  fail "the output does not name the removed access key $k"
  k=""
done
[[ -z "${k:-}" ]] || ok "the output names each removed access key"
if grep -qF "$other" "$work/out"; then fail "the output names the unrelated user"; else ok "the output does not name an unrelated user"; fi
if grep -q "stale-secret" "$work/out" || name="$(leaked "$work/out")"; then fail "the pruning run printed a secret"; else ok "the pruning run prints no secret"; fi
expect_allowed "the kept bundles user lists org/" "${ob[@]}" s3api list-objects-v2 --bucket paddock-bundles --prefix org/
expect_allowed "the kept escrow user lists org/" "${oe[@]}" s3api list-object-versions --bucket paddock-escrow --prefix org/
# The listing's order is not stable, its content is.
user_lines() { rc_root 'rc admin user list t' | sort; }
users_before="$(user_lines)"
if bootstrap --add-missing && ! grep -q "removed the stale" "$work/out" &&
    [[ "$(user_lines)" == "$users_before" && "$users_before" == *"$other"* ]]; then
  ok "a second --add-missing removes and changes nothing"
else
  fail "a second --add-missing changed state: $(shown 4)"
fi

# The order: a broken current key file fails the probe, and no stale user is removed (never zero working users).
add_user "$stale_b1" paddock-bundles-offboard
add_user "$stale_e1" paddock-escrow-offboard
K="$cur_e" S="not-the-file-$$" rcx 'rc admin user passwd --password-from-env S -- t "$K" >/dev/null'
if bootstrap --add-missing; then
  fail "--add-missing passed with a broken current key file"
elif grep -q "cannot list org/ of paddock-escrow: run ./paddock bootstrap buckets" "$work/out"; then
  ok "a broken current key file fails the bootstrap loudly"
else
  fail "--add-missing failed differently: $(shown 3)"
fi
if [[ "$(holders paddock-bundles-offboard)" == *"$stale_b1"* && "$(holders paddock-escrow-offboard)" == *"$stale_e1"* ]] &&
    ! grep -q "removed the stale" "$work/out"; then
  ok "the failed probe removed no stale user"
else
  fail "a stale user was removed before the probe passed"
fi
if bootstrap; then ok "a full bootstrap repairs the current user"; else fail "a full bootstrap: $(shown 3)"; fi
if [[ "$(holders paddock-bundles-offboard)" == "$cur_b" && "$(holders paddock-escrow-offboard)" == "$cur_e" ]]; then
  ok "after the repair the stale users are gone and the current ones stay"
else
  fail "after the repair: $(holders paddock-bundles-offboard) / $(holders paddock-escrow-offboard)"
fi

if ((failures > 0)); then
  echo "$failures failure(s)"
  exit 1
fi
echo "all offboard object-store tests passed"
