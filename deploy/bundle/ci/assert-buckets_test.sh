#!/usr/bin/env bash
# Tests of assert-buckets.sh (PDK-1054b, `make test`) against a throwaway RustFS that the real bucket bootstrap set up
# as the previous release did (without the users of organization deletion):
#   1. plant, snapshot, `rustfs-bundles-bootstrap.sh --add-missing` with the candidate's key files, `upgraded` passes
#      and a second --add-missing passes `unchanged`;
#   2. a rewritten policy, a reset user secret, a deleted escrowed version, a removed bucket policy, suspended
#      versioning and a changed key file each fail `unchanged`, named by label; so does an added policy;
#   3. an obsolete policy left in place and a missing offboard user fail `upgraded`;
#   4. a snapshot without an escrowed header version fails, so an empty comparison cannot pass;
#   5. no key or secret is printed, and a snapshot directory holds no key.
# Needs Docker, like rustfs-offboard_test.sh; it fails rather than skips without it.
# The rc commands name keys as $VARIABLES that only the container expands (SC2016); ok never fails (SC2015).
# shellcheck disable=SC2016,SC2015
# shellcheck source-path=SCRIPTDIR
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
scripts="$here/../../compose/scripts"
# shellcheck source=../../compose/scripts/lib.sh
. "$scripts/lib.sh"
failures=0
ok() { echo "ok   $*"; }
fail() {
  echo "FAIL $*"
  failures=$((failures + 1))
}
command -v docker >/dev/null || {
  echo "FAIL docker is required"
  exit 1
}

project="paddock-assert-buckets-$$"
net="${project}_data"
store="${project}-rustfs"
work="$(mktemp -d)"
cleanup() {
  docker rm -f "$store" >/dev/null 2>&1 || true
  docker network rm "$net" >/dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT

# The candidate's bundle holds every key file; the previous release's lacks the two of organization deletion.
cand="$work/cand" prev="$work/prev"
mkdir -p "$cand" "$prev"
mkdir -m 700 "$cand/.secrets"
# Keys start with "-" now and then, as generated ones do (rustfs-alias_test.sh).
rand() { head -c 18 /dev/urandom | base64 -w0 | tr '+/' '-_'; }
for name in rustfs_root_user rustfs_root_password; do rand >"$cand/.secrets/$name"; done
for role in compiler gateway api worker offboard; do
  for k in access secret; do rand >"$cand/.secrets/rustfs_bundles_${role}_${k}_key"; done
done
for k in access secret; do rand >"$cand/.secrets/rustfs_artifacts_api_${k}_key"; done
for role in worker api revocation backup offboard; do
  for k in access secret; do rand >"$cand/.secrets/rustfs_escrow_${role}_${k}_key"; done
done
cp -a "$cand/.secrets" "$prev/.secrets"
rm "$prev/.secrets/"*offboard*

key() { cat "$cand/.secrets/$1"; }
RUSTFS_ACCESS_KEY="$(key rustfs_root_user)" RUSTFS_SECRET_KEY="$(key rustfs_root_password)"
RC_HOST_t="http://$(percent_encode "$RUSTFS_ACCESS_KEY"):$(percent_encode "$RUSTFS_SECRET_KEY")@rustfs:9000"
export RUSTFS_ACCESS_KEY RUSTFS_SECRET_KEY RC_HOST_t
docker network create "$net" >/dev/null
docker run -d --name "$store" --network "$net" --network-alias rustfs -e RUSTFS_ACCESS_KEY -e RUSTFS_SECRET_KEY \
  -e RUSTFS_CONSOLE_ENABLE=false -e RUSTFS_OBS_LOG_DIRECTORY= "$RUSTFS_IMAGE" >/dev/null

# rcx <shell command>: rc with the root alias t; the command names keys only as $VARIABLES of its environment.
rcx() { docker run --rm -i --network "$net" -e HOME=/tmp -e RC_HOST_t -e K -e S --entrypoint sh "$RC_IMAGE" -c "$1"; }
root() {
  AWS_ACCESS_KEY_ID="$RUSTFS_ACCESS_KEY" AWS_SECRET_ACCESS_KEY="$RUSTFS_SECRET_KEY" docker run --rm -i --network "$net" \
    -e AWS_ACCESS_KEY_ID -e AWS_SECRET_ACCESS_KEY -e AWS_DEFAULT_REGION=us-east-1 -e AWS_PAGER= "$AWS_CLI_IMAGE" \
    --endpoint-url http://rustfs:9000 "$@"
}
bootstrap() {
  SECRETS_DIR="$1/.secrets" NETWORK="$net" ENDPOINT=http://rustfs:9000 PADDOCK_PROJECT="$project" \
    "$scripts/rustfs-bundles-bootstrap.sh" "${@:2}" >"$work/bootstrap.out" 2>&1
}
# assert <name> <arguments…>: assert-buckets.sh on the project; its output in $work/<name>.out.
assert() { "$here/assert-buckets.sh" "$project" "${@:2}" >"$work/$1.out" 2>&1; }
said() { grep -qF -- "$2" "$work/$1.out"; }
shown() { tail -n "${2:-5}" "$work/$1.out"; }

# The previous release: the full bootstrap without the users of organization deletion.
if ! bootstrap "$cand"; then
  fail "the full bootstrap: $(tail -3 "$work/bootstrap.out")"
  exit 1
fi
for role in bundles escrow; do
  K="$(key "rustfs_${role}_offboard_access_key")" S="" rcx "rc admin user rm -- t \"\$K\" >/dev/null && rc admin policy rm t paddock-$role-offboard >/dev/null"
done

# --- 4. an empty escrow bucket fails the snapshot -----------------------------------------------------------------------

root s3api create-bucket --bucket ci-empty-escrow >/dev/null
mkdir -p "$work/empty"
cp -a "$prev/.secrets" "$work/empty/.secrets"
echo PADDOCK_ESCROW_S3_BUCKET=ci-empty-escrow >"$work/empty/.env"
if assert empty "$work/empty" snapshot "$work/snap-empty"; then
  fail "a snapshot without an escrowed header version passes"
elif said empty "the escrow bucket holds no header version"; then
  ok "a snapshot without an escrowed header version fails"
else
  fail "empty escrow: $(shown empty)"
fi

# --- 1. the upgrade path ------------------------------------------------------------------------------------------------

if assert plant "$prev" plant; then ok "plant"; else fail "plant: $(shown plant)"; fi
api_policies() { K="$(key rustfs_escrow_api_access_key)" S="" rcx 'rc admin user info --json -- t "$K"'; }
info="$(api_policies)"
[[ "$info" == *'"paddock-escrow-api"'* && "$info" == *'"paddock-escrow-read"'* ]] &&
  ok "the planted api user holds paddock-escrow-api and paddock-escrow-read" || fail "the planted api user's policies are wrong"
if assert before "$prev" snapshot "$work/before"; then ok "snapshot of the previous release"; else fail "snapshot: $(shown before)"; fi
if bootstrap "$cand" --add-missing; then ok "--add-missing"; else fail "--add-missing: $(tail -3 "$work/bootstrap.out")"; fi
if assert upgraded "$cand" upgraded "$work/before" "$work/after"; then
  ok "upgraded holds after --add-missing"
else
  fail "upgraded: $(shown upgraded 8)"
fi
said upgraded "added: user rustfs_bundles_offboard" && said upgraded "added: policy paddock-escrow-offboard" &&
  said upgraded "paddock-escrow-read removed" && said upgraded "lists org/ of paddock-escrow" &&
  ok "upgraded names the added users, the removed policy and the list probe" || fail "upgraded output: $(shown upgraded 20)"
if bootstrap "$cand" --add-missing && assert again "$cand" unchanged "$work/after" "$work/again"; then
  ok "a second --add-missing changes nothing"
else
  fail "second --add-missing: $(shown again)"
fi

# --- 2. every kind of change fails unchanged ---------------------------------------------------------------------------

# A rewritten policy, as a full bootstrap of a later release would leave it.
printf '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject"],"Resource":["arn:aws:s3:::paddock-bundles/*"]}]}' |
  K="" S="" rcx 'cat >/tmp/p.json && rc admin policy create t paddock-bundles-compiler /tmp/p.json >/dev/null'
# A user secret reset in RustFS while its file stayed.
K="$(key rustfs_escrow_worker_access_key)" S="reset-by-the-upgrade-$$" rcx 'rc admin user passwd --password-from-env S -- t "$K" >/dev/null'
# A deleted escrowed version.
v="$(root s3api list-object-versions --bucket paddock-escrow --query 'Versions[0].[Key,VersionId]' --output text)"
root s3api delete-object --bucket paddock-escrow --key "${v%%$'\t'*}" --version-id "${v##*$'\t'}" >/dev/null
root s3api delete-bucket-policy --bucket paddock-agent-artifacts
root s3api put-bucket-versioning --bucket paddock-escrow --versioning-configuration Status=Suspended
rand >"$cand/.secrets/rustfs_bundles_gateway_secret_key"
K="" S="" rcx 'printf "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"s3:ListBucket\"],\"Resource\":[\"arn:aws:s3:::x\"]}]}" >/tmp/p.json && rc admin policy create t ci-added /tmp/p.json >/dev/null'
if assert changed "$cand" unchanged "$work/after" "$work/changed"; then
  fail "unchanged passes after every kind of change"
else
  for label in "changed: policy paddock-bundles-compiler" "changed: auth rustfs_escrow_worker" \
    "changed: escrow versions" "changed: bucket paddock-agent-artifacts policy" \
    "changed: bucket paddock-escrow versioning" "changed: secret rustfs_bundles_gateway_secret_key" \
    "changed: auth rustfs_bundles_gateway" "added: policy ci-added"; do
    said changed "$label" && ok "unchanged fails naming '$label'" || fail "unchanged did not name '$label': $(shown changed 20)"
  done
fi

# --- 3. an obsolete policy left in place and a missing offboard user fail upgraded ---------------------------------------

K="$(key rustfs_escrow_api_access_key)" S="" rcx 'printf "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"s3:GetObject\"],\"Resource\":[\"arn:aws:s3:::paddock-escrow/*\"]}]}" >/tmp/p.json &&
  rc admin policy create t paddock-escrow-read /tmp/p.json >/dev/null && rc admin policy attach t paddock-escrow-api,paddock-escrow-read --user="$K" >/dev/null'
K="$(key rustfs_bundles_offboard_access_key)" S="" rcx 'rc admin user rm -- t "$K" >/dev/null'
if assert broken "$cand" upgraded "$work/before" "$work/broken"; then
  fail "upgraded passes with paddock-escrow-read and without the bundles offboard user"
else
  for label in "the obsolete policy paddock-escrow-read is still there" "the api user still holds paddock-escrow-read" \
    "bucket user(s) whose key file exists are missing in RustFS" \
    "the user rustfs_bundles_offboard does not hold paddock-bundles-offboard" \
    "the organization deletion's credential cannot list org/ of paddock-bundles"; do
    said broken "$label" && ok "upgraded fails naming '$label'" || fail "upgraded did not name '$label': $(shown broken 20)"
  done
fi

# --- 5. no key or secret is printed or kept -------------------------------------------------------------------------------

leaks=0
for f in "$cand/.secrets"/*; do
  value="$(cat "$f")"
  for out in "$work"/*.out "$work"/{before,after,again,changed,broken}/*; do
    [[ -f "$out" ]] || continue
    if grep -qF -- "$value" "$out"; then
      fail "$(basename "$out") holds the value of $(basename "$f")"
      leaks=1
    fi
  done
done
((leaks == 0)) && ok "no output and no snapshot file holds a key or secret"
[[ -z "$(find "$work"/{before,after,again,changed,broken} -name 'raw.*' 2>/dev/null)" ]] &&
  ok "no raw container output is left behind, also after a failed run" || fail "raw container output left behind"

if ((failures > 0)); then
  echo "$failures failure(s)"
  exit 1
fi
echo "all assert-buckets tests passed"
