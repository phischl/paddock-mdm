#!/usr/bin/env bash
# ./paddock bundles prune (plan M17 amendment t point 3 and its addendum, PDK-1099): removes the superseded versions of
# every device's configuration bundle from the bundles bucket, because RustFS's memory grows with the number of stored
# objects and every recompile adds one per device.
#   bundles-prune.sh [--keep N] [--yes]
# Keeps the N highest versions per device (default 2, at least 2: the newest version is never deleted) and everything
# modified in the last 10 minutes. The versions are read from a listing, never computed from the newest one: the
# sequences have gaps after a restore (admin raise-bundle-seq). Without --yes it only counts. With --yes it first checks
# that the audit event can be written, deletes in batches of 1000, then records one platform.bundle_versions_pruned
# event with the counts; the dry run is not audited. Reads no object and prints no credential.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
. "$here/lib.sh"

BUNDLES_PRUNE_BATCH=1000
BUNDLES_PRUNE_KEY='^org/[0-9a-f-]{36}/devices/[0-9a-f-]{36}/bundles/[0-9]+\.dsse$'

bundles_prune_usage() {
  echo "usage: bundles-prune.sh [--keep N] [--yes]   (N is a number from 2 to 1000, default 2)" >&2
  exit 2
}

# aws <args…>: the AWS CLI against the bundled RustFS; the credentials reach the container by name only.
aws() {
  docker run --rm -i --network "$NETWORK" -e AWS_ACCESS_KEY_ID -e AWS_SECRET_ACCESS_KEY \
    -e AWS_DEFAULT_REGION=us-east-1 -e AWS_PAGER= "$AWS_CLI_IMAGE" --endpoint-url "$ENDPOINT" "$@"
}

# bundles_prune_select <keep> <cutoff>: reads key<TAB>last_modified lines and prints the keys to delete. Only bundle
# keys count. Per device directory the <keep> highest versions (numeric order) stay; so does every key modified at or
# after <cutoff> (UTC, YYYY-MM-DDTHH:MM:SS, compared on the first 19 characters) and every key whose time cannot be
# read: when in doubt a key stays.
bundles_prune_select() {
  local keep="$1" cutoff="$2"
  LC_ALL=C awk -F'\t' -v re="$BUNDLES_PRUNE_KEY" '
    $1 ~ re {
      key = $1
      n = split(key, p, "/")
      dir = substr(key, 1, length(key) - length(p[n]))
      ver = p[n]
      sub(/\.dsse$/, "", ver)
      print dir "\t" ver "\t" key "\t" $2
    }' |
    LC_ALL=C sort -t$'\t' -k1,1 -k2,2nr -k3,3 |
    LC_ALL=C awk -F'\t' -v keep="$keep" -v cutoff="$cutoff" '
      $1 != dir { dir = $1; seen = 0 }
      {
        seen++
        if (seen <= keep) next
        t = substr($4, 1, 19)
        if (t !~ /^[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]$/ || t >= cutoff) next
        print $3
      }'
}

# bundles_prune_stats: reads the same lines and prints "<bundle keys> <device directories>".
bundles_prune_stats() {
  LC_ALL=C awk -F'\t' -v re="$BUNDLES_PRUNE_KEY" '
    $1 ~ re {
      m++
      n = split($1, p, "/")
      dir = substr($1, 1, length($1) - length(p[n]))
      if (!(dir in d)) { d[dir] = 1; c++ }
    }
    END { print m + 0, c + 0 }'
}

# bundles_prune_record <keep> <listed> <devices> <selected> <deleted> <failed>: the audit event, through the API image
# as ./paddock agent-rollout does; --check only proves that the platform database is reachable.
bundles_prune_record() {
  if [[ "$1" == --check ]]; then
    compose run --rm --no-deps -T paddock-api admin record-bundle-prune --check >/dev/null
    return
  fi
  compose run --rm --no-deps -T paddock-api admin record-bundle-prune --keep "$1" --listed "$2" --devices "$3" \
    --selected "$4" --deleted "$5" --failed "$6" >/dev/null
}

bundles_prune_main() {
  local keep=2 yes="" arg
  while (($#)); do
    arg="$1"
    shift
    case "$arg" in
      --yes) yes=1 ;;
      --keep)
        (($#)) || bundles_prune_usage
        keep="$1"
        shift
        ;;
      *) bundles_prune_usage ;;
    esac
  done
  if ! [[ "$keep" =~ ^[0-9]+$ ]] || ((${#keep} > 4 || 10#$keep < 2 || 10#$keep > 1000)); then bundles_prune_usage; fi
  keep=$((10#$keep))

  BUCKET="${PADDOCK_BUNDLES_S3_BUCKET:-paddock-bundles}"
  NETWORK="${NETWORK:-${PADDOCK_PROJECT}_data}"
  ENDPOINT="${ENDPOINT:-http://rustfs:9000}"
  AWS_ACCESS_KEY_ID="$(cat "$SECRETS_DIR/rustfs_root_user")"
  AWS_SECRET_ACCESS_KEY="$(cat "$SECRETS_DIR/rustfs_root_password")"
  export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY

  if [[ -n "$yes" ]] && ! bundles_prune_record --check; then
    echo "the audit log cannot be written; nothing was deleted" >&2
    return 1
  fi

  local work listing selected cutoff listed devices count
  work="$(mktemp -d)"
  # shellcheck disable=SC2064
  trap "rm -rf '$work'" EXIT
  listing="$work/listing" selected="$work/selected"
  aws s3api list-objects-v2 --bucket "$BUCKET" --prefix org/ --query 'Contents[].[Key,LastModified]' \
    --output text </dev/null >"$listing"
  cutoff="$(date -u -d '-10 min' +%Y-%m-%dT%H:%M:%S)"
  read -r listed devices < <(bundles_prune_stats <"$listing")
  bundles_prune_select "$keep" "$cutoff" <"$listing" >"$selected"
  count="$(wc -l <"$selected")"
  count=$((count + 0))

  if [[ -z "$yes" ]]; then
    echo "would delete $count of $listed bundle objects of $devices devices (keeping the newest $keep per device)"
    return 0
  fi

  local deleted=0 failed=0 batch resp
  if ((count > 0)); then
    split -l "$BUNDLES_PRUNE_BATCH" -d -a 6 "$selected" "$work/batch."
    for batch in "$work"/batch.*; do
      resp="$(awk 'BEGIN { printf "{\"Objects\":[" } { printf "%s{\"Key\":\"%s\"}", (NR > 1 ? "," : ""), $0 }
        END { printf "],\"Quiet\":true}\n" }' "$batch" |
        aws s3api delete-objects --bucket "$BUCKET" --delete file:///dev/stdin)"
      if [[ "$resp" == *'"Errors"'* ]]; then
        failed="$(grep -c '"Key"' <<<"$resp" || true)"
        ((failed > 0)) || failed=1
        deleted=$((deleted + $(wc -l <"$batch") - failed))
        break
      fi
      deleted=$((deleted + $(wc -l <"$batch")))
    done
  fi

  local status=0
  if ((failed > 0)); then
    echo "deleted $deleted of $listed bundle objects of $devices devices; $failed keys failed" >&2
    status=1
  else
    echo "deleted $deleted of $listed bundle objects of $devices devices"
  fi
  if ! bundles_prune_record "$keep" "$listed" "$devices" "$count" "$deleted" "$failed"; then
    echo "the audit event could not be recorded: keep=$keep listed=$listed devices=$devices selected=$count deleted=$deleted failed=$failed" >&2
    return 1
  fi
  return "$status"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  bundles_prune_main "$@"
fi
