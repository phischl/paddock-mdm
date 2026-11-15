#!/usr/bin/env bash
# Asserts what the upgrade's bucket bootstrap (`./paddock bootstrap buckets --add-missing`, step buckets of
# ./paddock upgrade) does to a control plane's RustFS (PDK-1054b): it adds the users and policies a release adds and
# changes nothing that exists, apart from the closed list of known-obsolete policies, which it removes.
#   assert-buckets.sh <project> <bundle dir> plant
#       an installation from before M12 (PDK-749): the obsolete paddock-escrow-read attached to the api user, and two
#       versions of an escrowed header, so that a snapshot has escrowed object versions to compare;
#   assert-buckets.sh <project> <bundle dir> snapshot <out dir>
#       checksums of every policy, of every bucket user (its status, policies and groups), of every RustFS key file of
#       <bundle dir>/.secrets, of the escrow bucket's object versions and of the buckets' versioning and bucket policy,
#       plus whether each user signs in with the secret of its file; fails when the snapshot is incomplete;
#   assert-buckets.sh <project> <bundle dir> upgraded <before dir> <out dir>
#       a snapshot that keeps every item of <before dir> unchanged (it may add items), the two users of organization
#       deletion with their policies and able to list org/ of their buckets, paddock-escrow-read gone and the api user
#       still holding paddock-escrow-api;
#   assert-buckets.sh <project> <bundle dir> unchanged <before dir> <out dir>
#       a snapshot identical to <before dir>: nothing added, removed or changed.
# The obsolete policies are left out of every checksum (a user's checksum ignores them too), so that their removal is
# the only change an upgrade may make. Only labels, counts and checksums are printed or written, never a key or a
# secret: the access keys travel to the containers as inherited environment variables. The tool images are the
# repository's (deploy/compose/versions.env), so that the snapshots of two releases compare like with like.
# Exit 0: every assertion holds; 1: a finding (named on stderr); 2: usage.
# The container scripts name keys only as $VARIABLES that the container expands (SC2016).
# shellcheck disable=SC2016
# shellcheck source-path=SCRIPTDIR
set -euo pipefail

usage() {
  echo "usage: assert-buckets.sh <project> <bundle dir> plant | snapshot <out dir> | upgraded|unchanged <before dir> <out dir>" >&2
  exit 2
}
project="${1:-}" bundle="${2:-}" cmd="${3:-}"
[[ "$project" =~ ^[a-z0-9][a-z0-9_-]*$ && -d "$bundle/.secrets" ]] || usage
case "$cmd" in
  plant) (($# == 3)) || usage ;;
  snapshot) (($# == 4)) || usage ;;
  upgraded | unchanged) if (($# != 5)) || [[ ! -f "$4/sums" ]]; then usage; fi ;;
  *) usage ;;
esac

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SECRETS_DIR="$(cd "$bundle/.secrets" && pwd)"
export PADDOCK_PROJECT="$project"
# shellcheck source=../../compose/scripts/lib.sh
. "$here/../../compose/scripts/lib.sh"

# The closed list of policies --add-missing removes (plan M17 addendum 2026-11-15 to amendment k, point 1).
obsolete=(paddock-escrow-read)
net="${project}_data"
endpoint=http://rustfs:9000
# bundle_setting <name> <default>: the setting of the bundle's .env, else the default.
bundle_setting() {
  local v=''
  [[ ! -f "$bundle/.env" ]] || v="$(sed -n "s/^$1=//p" "$bundle/.env" | tail -n 1)"
  printf '%s' "${v:-$2}"
}
bundles_bucket="$(bundle_setting PADDOCK_BUNDLES_S3_BUCKET paddock-bundles)"
artifacts_bucket="$(bundle_setting PADDOCK_ARTIFACTS_S3_BUCKET paddock-agent-artifacts)"
escrow_bucket="$(bundle_setting PADDOCK_ESCROW_S3_BUCKET paddock-escrow)"

failed=0
# The raw container output names access keys; only checksums outlive the run, also after a failure.
raw=''
trap '[[ -z "$raw" ]] || rm -rf "$raw"' EXIT
finding() {
  echo "assert-buckets: $*" >&2
  failed=1
}
die() {
  echo "assert-buckets: $*" >&2
  exit 1
}

AWS_ACCESS_KEY_ID="$(cat "$SECRETS_DIR/rustfs_root_user")"
AWS_SECRET_ACCESS_KEY="$(cat "$SECRETS_DIR/rustfs_root_password")"
export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY
export_rc_host t "$endpoint" AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY

# roles: the bucket users whose keys the control plane holds (rustfs_<bucket>_<role>), as the bucket bootstrap creates
# them; the audit host's RustFS is not this one.
roles() {
  local f r
  for f in "$SECRETS_DIR"/rustfs_{bundles,artifacts,escrow}_*_access_key; do
    [[ -f "$f" ]] || continue
    r="$(basename "$f" _access_key)"
    [[ "$r" =~ ^rustfs_[a-z]+_[a-z]+$ ]] || die "unexpected key file name $(basename "$f")"
    printf '%s\n' "$r"
  done
}

# with_keys <kinds> <command…>: runs the command with K_<n> (and S_<n> for kinds=both) exported for the n-th role of
# roles, read from the key files; nothing reaches a command line.
with_keys() {
  local kinds="$1" n=0 r
  shift
  (
    while read -r r; do
      export "K_$n=$(cat "$SECRETS_DIR/${r}_access_key")"
      [[ "$kinds" != both ]] || export "S_$n=$(cat "$SECRETS_DIR/${r}_secret_key")"
      n=$((n + 1))
    done < <(roles)
    "$@"
  )
}
key_env() {
  local n=0 r
  while read -r r; do
    printf -- '-e\nK_%s\n' "$n"
    [[ "${1:-}" != both ]] || printf -- '-e\nS_%s\n' "$n"
    n=$((n + 1))
  done < <(roles)
}

rcx() {
  local env=()
  mapfile -t env < <(key_env)
  docker run --rm --network "$net" -e HOME=/tmp -e RC_HOST_t "${env[@]}" --entrypoint sh "$RC_IMAGE" -c "$1"
}
awsx() {
  local env=()
  mapfile -t env < <(key_env both)
  docker run --rm --network "$net" -e AWS_ACCESS_KEY_ID -e AWS_SECRET_ACCESS_KEY -e AWS_DEFAULT_REGION=us-east-1 \
    -e AWS_PAGER= "${env[@]}" --entrypoint sh "$AWS_CLI_IMAGE" -c "$1"
}

# --- plant ------------------------------------------------------------------------------------------------------------

plant() {
  local key="org/00000000-0000-4000-8000-00000c1054b0/devices/00000000-0000-4000-8000-00000c1054b1/luks-header/ci-upgrade"
  [[ -f "$SECRETS_DIR/rustfs_escrow_api_access_key" ]] || die "no rustfs_escrow_api_access_key"
  # rc admin policy attach replaces the user's policies with the ones it names: both, so that the api keeps its grant
  # and holds the obsolete one besides, the state the bootstrap's guard lets it remove.
  K_API="$(cat "$SECRETS_DIR/rustfs_escrow_api_access_key")" docker run --rm --network "$net" -e HOME=/tmp \
    -e RC_HOST_t -e K_API --entrypoint sh "$RC_IMAGE" -c "printf '{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"s3:GetObject\"],\"Resource\":[\"arn:aws:s3:::$escrow_bucket/*\"]}]}' >/tmp/p.json &&
    rc admin policy create t ${obsolete[0]} /tmp/p.json >/dev/null &&
    rc admin policy attach t paddock-escrow-api,${obsolete[0]} --user=\"\$K_API\" >/dev/null" || die "cannot plant ${obsolete[0]}"
  awsx "for g in 1 2; do printf 'ci header generation %s' \$g >/tmp/h &&
    aws --endpoint-url $endpoint s3api put-object --bucket $escrow_bucket --key $key --body /tmp/h >/dev/null || exit 1; done" ||
    die "cannot plant the escrowed header"
  local info
  info="$(K_API="$(cat "$SECRETS_DIR/rustfs_escrow_api_access_key")" docker run --rm --network "$net" -e HOME=/tmp \
    -e RC_HOST_t -e K_API --entrypoint sh "$RC_IMAGE" -c 'rc admin user info --json -- t "$K_API"')" ||
    die "rc admin user info failed for the api user"
  [[ "$info" == *'"paddock-escrow-api"'* && "$info" == *"\"${obsolete[0]}\""* ]] ||
    die "the api user does not hold both paddock-escrow-api and ${obsolete[0]} after planting"
  echo "planted ${obsolete[0]} on the api user and two versions of an escrowed header"
}

# --- snapshot ---------------------------------------------------------------------------------------------------------

# sections <raw file> <dir>: splits the "@@ <label>" sections of a container's output into <dir>/<n>, and their
# labels into <dir>/labels.
sections() {
  awk -v dir="$2" '
    /^@@ / { n++; sub(/^@@ /, ""); print n "\t" $0 > (dir "/labels"); printf "" > (dir "/" n); next }
    n { print > (dir "/" n) }
  ' "$1"
  [[ -f "$2/labels" ]] || : >"$2/labels"
}
sum() { sha256sum | cut -c1-64; }
# normalized_user: a user's info without the obsolete policies; commas and blanks go too, so that removing the last
# policy of a list leaves no trace.
normalized_user() {
  local o args=()
  for o in "${obsolete[@]}"; do args+=(-e "/^[[:space:]]*\"$o\",?\$/d"); done
  sed -E "${args[@]}" | tr -d ' \n,'
}
is_obsolete() { printf '%s\n' "${obsolete[@]}" | grep -qxF -- "$1"; }

snapshot() {
  local out="$1" p r n label policies=() i=0
  (umask 077 && mkdir -p "$out")
  raw="$(mktemp -d "$out/raw.XXXXXX")"
  : >"$out/sums.tmp"

  rcx 'rc admin policy list t --json' >"$raw/policy-list" || die "rc admin policy list failed"
  mapfile -t policies < <(sed -n 's/^[[:space:]]*"\([A-Za-z0-9_-]*\)",\{0,1\}$/\1/p' "$raw/policy-list" | sort)
  ((${#policies[@]} > 0)) || die "rc admin policy list returned no policy"
  printf '%s\n' "${policies[@]}" >"$out/policies"
  local script=''
  for p in "${policies[@]}"; do
    is_obsolete "$p" && continue
    script+="echo '@@ policy $p'; rc admin policy info t $p --json || echo '@@ failed policy $p';"
  done
  while read -r r; do
    script+="echo '@@ user $r'; rc admin user info --json -- t \"\$K_$i\" 2>/dev/null || echo absent;"
    i=$((i + 1))
  done < <(roles)
  with_keys access rcx "$script" >"$raw/rc" || die "rc admin policy/user info failed"

  script="echo '@@ escrow versions'; aws --endpoint-url $endpoint s3api list-object-versions --bucket $escrow_bucket --query '[Versions[].[Key,VersionId,ETag],DeleteMarkers[].[Key,VersionId]]' --output json || echo '@@ failed escrow versions';"
  for b in "$bundles_bucket" "$artifacts_bucket" "$escrow_bucket"; do
    script+="echo '@@ bucket $b versioning'; aws --endpoint-url $endpoint s3api get-bucket-versioning --bucket $b --output json || echo '@@ failed bucket $b versioning';"
    script+="echo '@@ bucket $b policy'; aws --endpoint-url $endpoint s3api get-bucket-policy --bucket $b --query Policy --output text 2>/dev/null || echo none;"
  done
  # A user signs in when RustFS answers anything but a signature or key error; its permissions do not matter here.
  i=0
  while read -r r; do
    script+="echo '@@ auth $r'; e=\$(AWS_ACCESS_KEY_ID=\"\$K_$i\" AWS_SECRET_ACCESS_KEY=\"\$S_$i\" aws --endpoint-url $endpoint s3api list-objects-v2 --bucket $escrow_bucket --max-keys 1 2>&1 >/dev/null);"
    script+="case \"\$e\" in '' | *AccessDenied*) echo ok ;; *SignatureDoesNotMatch*) echo SignatureDoesNotMatch ;; *InvalidAccessKeyId*) echo InvalidAccessKeyId ;; *) echo error ;; esac;"
    i=$((i + 1))
  done < <(roles)
  with_keys both awsx "$script" >"$raw/aws" || die "the bucket listing failed"

  for src in rc aws; do
    mkdir "$raw/$src.d"
    sections "$raw/$src" "$raw/$src.d"
    while IFS=$'\t' read -r n label; do
      case "$label" in
        failed\ *) die "${label#failed }: the query failed" ;;
        auth\ *) printf '%s\t%s\n' "$label" "$(tr -d '\n' <"$raw/$src.d/$n")" >>"$out/sums.tmp" ;;
        user\ *)
          # Attached policies are names, never keys: kept for the checks of upgraded.
          awk '/"policies"/ { on = 1; next } on && /\]/ { on = 0 } on { gsub(/[ ",]/, ""); if ($0 != "") print }' \
            "$raw/$src.d/$n" | sed "s/^/${label#user } /" >>"$out/attached"
          printf '%s\t%s\n' "$label" "$(normalized_user <"$raw/$src.d/$n" | sum)" >>"$out/sums.tmp"
          ;;
        *) printf '%s\t%s\n' "$label" "$(sum <"$raw/$src.d/$n")" >>"$out/sums.tmp" ;;
      esac
    done <"$raw/$src.d/labels"
  done
  local headers
  headers="$(grep -c '/luks-header/' "$raw/aws.d/1" || true)"
  for f in "$SECRETS_DIR"/rustfs_root_user "$SECRETS_DIR"/rustfs_root_password \
    "$SECRETS_DIR"/rustfs_{bundles,artifacts,escrow}_*_key; do
    [[ -f "$f" ]] && printf 'secret %s\t%s\n' "$(basename "$f")" "$(sum <"$f")" >>"$out/sums.tmp"
  done
  sort "$out/sums.tmp" >"$out/sums"
  rm -f "$out/sums.tmp"
  touch "$out/attached"

  # An incomplete snapshot would compare equal to the next one and prove nothing.
  local users absent bad
  users="$(grep -c '^user ' "$out/sums" || true)"
  absent="$(grep -c "^user .*	$(printf absent | sum)\$" "$out/sums" || true)"
  bad="$(grep '^auth ' "$out/sums" | grep -v '	ok$' | cut -f1 | paste -sd, - || true)"
  ((users >= 5)) || die "the snapshot holds $users bucket users, expected the bucket bootstrap's"
  ((absent == 0)) || finding "$absent bucket user(s) whose key file exists are missing in RustFS"
  [[ -z "$bad" ]] || finding "users that do not sign in with the secret of their file: $bad"
  ((headers > 0)) || die "the escrow bucket holds no header version (plant runs before the first snapshot)"
  echo "snapshot: $(wc -l <"$out/sums") items: $(grep -c '^policy ' "$out/sums") policies, $users users," \
    "$(grep -c '^secret ' "$out/sums") key files, $headers escrowed header version(s)"
}

# compare <before> <after> <additions allowed: yes|no>: every item of <before> unchanged in <after>.
compare() {
  local label s same=0
  declare -A after=()
  while IFS=$'\t' read -r label s; do after[$label]="$s"; done <"$2/sums"
  while IFS=$'\t' read -r label s; do
    if [[ -z "${after[$label]+x}" ]]; then
      finding "gone: $label"
    elif [[ "${after[$label]}" != "$s" ]]; then
      finding "changed: $label"
    else
      same=$((same + 1))
    fi
    unset "after[$label]"
  done <"$1/sums"
  while read -r label; do
    [[ -n "$label" ]] || continue
    if [[ "$3" == yes ]]; then echo "added: $label"; else finding "added: $label"; fi
  done < <(printf '%s\n' "${!after[@]}" | sort)
  echo "unchanged: $same of $(wc -l <"$1/sums") items"
}

attached() { grep -qxF -- "$1 $2" "$3/attached"; }

upgraded() {
  local before="$1" out="$2" role bucket o
  compare "$before" "$out" yes
  for o in "${obsolete[@]}"; do
    if grep -qxF -- "$o" "$out/policies"; then finding "the obsolete policy $o is still there"; else echo "$o removed"; fi
    if attached rustfs_escrow_api "$o" "$out"; then finding "the api user still holds $o"; fi
  done
  if ! attached rustfs_escrow_api paddock-escrow-api "$out"; then finding "the api user lost paddock-escrow-api"; fi
  for role in bundles escrow; do
    if ! grep -qxF "paddock-$role-offboard" "$out/policies"; then finding "no policy paddock-$role-offboard"; fi
    if ! attached "rustfs_${role}_offboard" "paddock-$role-offboard" "$out"; then
      finding "the user rustfs_${role}_offboard does not hold paddock-$role-offboard"
    fi
  done
  # The list probe of the bootstrap, repeated here with the keys of the files the worker reads.
  for role in bundles escrow; do
    bucket="$bundles_bucket"
    [[ "$role" == bundles ]] || bucket="$escrow_bucket"
    if (
      AWS_ACCESS_KEY_ID="$(cat "$SECRETS_DIR/rustfs_${role}_offboard_access_key")"
      AWS_SECRET_ACCESS_KEY="$(cat "$SECRETS_DIR/rustfs_${role}_offboard_secret_key")"
      docker run --rm --network "$net" -e AWS_ACCESS_KEY_ID -e AWS_SECRET_ACCESS_KEY -e AWS_DEFAULT_REGION=us-east-1 \
        -e AWS_PAGER= "$AWS_CLI_IMAGE" --endpoint-url "$endpoint" s3api list-objects-v2 --bucket "$bucket" \
        --prefix org/ --max-keys 1 >/dev/null 2>&1
    ); then
      echo "the organization deletion's credential lists org/ of $bucket"
    else
      finding "the organization deletion's credential cannot list org/ of $bucket"
    fi
  done
}

case "$cmd" in
  plant) plant ;;
  snapshot) snapshot "$4" ;;
  upgraded)
    snapshot "$5"
    upgraded "$4" "$5"
    ;;
  unchanged)
    snapshot "$5"
    compare "$4" "$5" no
    ;;
esac
((failed == 0)) || exit 1
echo "assert-buckets: $cmd holds"
