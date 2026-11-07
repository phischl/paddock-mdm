# The bundle sequence after a restore or a rollback (decisions-alpha9 item 68; ADR 0046, amendment 2026-11-07),
# sourced by restore.sh and, through ./paddock rollback, by rollback.sh and legacy-alpha8.sh.
#
# A device accepts only a bundle newer than the last one it applied, and a restore brings back older sequences. Before
# the stack goes down, a restore or rollback reads H, the running stack's highest device.bundle_seq; afterwards it
# raises every device's sequence by max(1,000,000, H + 1,000,000 - lowest restored), so that every device lands at
# H + 1,000,000 or above. When the stack cannot be read (a disaster restore), H is the value of the high-water file
# bundle-seq/high-water in the bundle directory (when both are readable, the higher one); without either, the raise is
# the plain 1,000,000 with a warning.
#
# The file is written by every restore, every rollback and every successful round of the backup role, and never
# lowered. compose.backup.yaml mounts bundle-seq/ into postgres (at /paddock-bundle-seq, prepared there for uid 999 on
# every start) and into the backup role (uid 999). These scripts write through the running postgres container as that
# uid, so an operator who is not root can run a rollback. Only psql as the database superuser (who is not subject to the
# device table's row-level security) and `admin bump-bundle-seq --by` are used, both of which 0.1.0-alpha.8 has too.
# shellcheck shell=bash

BUNDLE_SEQ_STEP=1000000
# The bound of paddock-server admin bump-bundle-seq --by (plan M6c decision 21).
BUNDLE_SEQ_MAX_BY=1000000000
BUNDLE_SEQ_MOUNT=/paddock-bundle-seq
# 18 digits: every such number fits a bigint and bash's arithmetic.
BUNDLE_SEQ_RE='^[0-9]{1,18}$'

# Runs in the postgres container (sh, uid 999): $1 the mounted directory, $2 the value. The file is replaced, never
# lowered; anything that is no number counts as 0.
# shellcheck disable=SC2016
BUNDLE_SEQ_RECORD_SCRIPT='set -eu
f="$1/high-water" cur=0
if [ -f "$f" ]; then cur="$(head -n 1 "$f")"; fi
case "$cur" in "" | *[!0-9]*) cur=0 ;; esac
[ "$2" -gt "$cur" ] || exit 0
printf "%s\n" "$2" >"$f.tmp"
mv -f "$f.tmp" "$f"'

# bundle_seq_query <sql> <compose command…>: one number from the paddock database, through psql in the running postgres
# container; fails when postgres does not run or the answer is no number.
bundle_seq_query() {
  local sql="$1" v
  shift
  v="$("$@" exec -T postgres psql -U postgres -d paddock -Atc "$sql" </dev/null 2>/dev/null)" || return 1
  [[ "$v" =~ $BUNDLE_SEQ_RE ]] || return 1
  printf '%s' "$((10#$v))"
}
bundle_seq_stack_max() { bundle_seq_query 'select coalesce(max(bundle_seq), 0) from device' "$@"; }
bundle_seq_stack_min() { bundle_seq_query 'select coalesce(min(bundle_seq), 0) from device' "$@"; }

# bundle_seq_file_max <bundle dir>: the high-water file's value; fails when there is none.
bundle_seq_file_max() {
  local v
  v="$(head -n 1 "$1/bundle-seq/high-water" 2>/dev/null)" || return 1
  [[ "$v" =~ $BUNDLE_SEQ_RE ]] || return 1
  printf '%s' "$((10#$v))"
}

# bundle_seq_record <value> <compose command…>: raises the high-water file to value. A failure only warns: the running
# stack is the source of every restore but a disaster restore.
bundle_seq_record() {
  local v="$1"
  shift
  "$@" exec -T -u postgres postgres sh -c "$BUNDLE_SEQ_RECORD_SCRIPT" bundle-seq "$BUNDLE_SEQ_MOUNT" "$v" </dev/null >&2 ||
    echo "warning: bundle sequence: the high-water file was not raised to $v" >&2
}

# bundle_seq_high_water <bundle dir> <compose command…>: prints H, read before the stack goes down: the running stack's
# highest (recorded in the high-water file), else the file's; prints nothing, with a warning, when neither is readable.
# With both, the higher counts: a stack that a failed restore or rollback left on partly restored data reads lower than
# what its devices applied, and the file still holds that.
bundle_seq_high_water() {
  local dir="$1" h f=""
  shift
  f="$(bundle_seq_file_max "$dir")" || f=""
  if h="$(bundle_seq_stack_max "$@")"; then
    echo "bundle sequence: the running stack's highest is $h (high-water file: ${f:-none})" >&2
    bundle_seq_record "$h" "$@"
    if [[ -n "$f" ]] && ((f > h)); then h="$f"; fi
  elif [[ -n "$f" ]]; then
    h="$f"
    echo "bundle sequence: the stack is not readable; the high-water file $dir/bundle-seq/high-water holds $h" >&2
  else
    echo "warning: bundle sequence: neither the running stack nor $dir/bundle-seq/high-water is readable; the restored sequences are raised by the plain $BUNDLE_SEQ_STEP only" >&2
    return 0
  fi
  printf '%s' "$h"
}

# bundle_seq_by <H, empty when unknown> <lowest restored>: the raise that puts every restored sequence at H + 1,000,000
# or above, at least 1,000,000.
bundle_seq_by() {
  local h="$1" min="$2" by=$BUNDLE_SEQ_STEP
  if [[ -n "$h" ]] && ((h + BUNDLE_SEQ_STEP - min > by)); then by=$((h + BUNDLE_SEQ_STEP - min)); fi
  printf '%s' "$by"
}

# bundle_seq_bump <by> <admin command…>: runs `<admin command…> --by <n>` in steps of at most 1,000,000,000.
bundle_seq_bump() {
  local by="$1" n
  shift
  while ((by > 0)); do
    n=$((by > BUNDLE_SEQ_MAX_BY ? BUNDLE_SEQ_MAX_BY : by))
    "$@" --by "$n" </dev/null
    by=$((by - n))
  done
}
