#!/usr/bin/env bash
# The rollback of a host to the release it was upgraded from (plan M16 decision 7, ADR 0047 decision 3), sourced by
# `./paddock rollback <old dir> [--yes]` after lib.sh. It runs in the directory of the NEW bundle and decides by this
# release's `Schema:` line:
#   - Schema: unchanged (or the audit host, whose migrations are additive within a guaranteed pair): down here, up in
#     the old directory; when FLEET_IMAGE changed, Fleet's dump is restored first, because Fleet migrated its MySQL;
#   - Schema: migrations …: down here, the restore of the pre-upgrade set, up in the old directory.
# The restore is the OLD release's restore.sh with the old directory's lib.sh: the restored data is the old schema, so
# the old images restore it and start on it; the new paddock-migrate must never see it. It restores from the local
# backup repository to the point ./paddock upgrade recorded just before its first `up` (.upgrade-rollback), which lies
# after the labelled pre-upgrade backup.
# 0.1.0-alpha.8 has no restore.sh: a rollback to it runs that release's documented procedure (legacy-alpha8.sh).
# shellcheck shell=bash

rb_usage() {
  echo "usage: ./paddock rollback <old bundle directory> [--yes]" >&2
  exit 2
}

rb_die() {
  echo "rollback: $1" >&2
  exit "${2:-1}"
}

rb_value() { grep "^$2=" "$1" 2>/dev/null | tail -n 1 | cut -d= -f2- || true; }

# rb_fleet_changed <new dir> <old dir>: Fleet migrated its MySQL at the upgrade when its image changed.
rb_fleet_changed() { [[ "$(rb_value "$1/versions.env" FLEET_IMAGE)" != "$(rb_value "$2/versions.env" FLEET_IMAGE)" ]]; }

# rb_running_versions <new dir>: the image version (OCI label) of every running container of a Paddock image in this
# host's Compose project, one per line, `?` without the label; fails when docker cannot list or inspect them. The label is set by the release
# build on all three Paddock images; the bundle's VERSION carries the same version.
rb_running_versions() {
  local out ids=() line
  out="$("$1/paddock" ps -q </dev/null)" || return 1
  while IFS= read -r line; do [[ -z "$line" ]] || ids+=("$line"); done <<<"$out"
  ((${#ids[@]} > 0)) || return 0
  out="$(docker inspect --format '{{index .Config.Labels "org.opencontainers.image.vendor"}}|{{index .Config.Labels "org.opencontainers.image.version"}}' "${ids[@]}")" ||
    return 1
  sed -n -e 's/^Paddock|$/?/p' -e 's/^Paddock|//p' <<<"$out"
}

# rb_mark_started: notes in the record, right before the first `down`, that this rollback changes the stack, so that a
# run after a failure finds the stack down or on the old release and may continue.
rb_mark_started() {
  [[ -z "$RB_RECORD" ]] || printf 'rollback-started=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >>"$RB_RECORD"
}

# rb_restore <old dir> <new dir> <at> <yes> <components…>: in a subshell with the old directory's libraries. Every
# precondition of the old release's restore (the key, its preflight: schema versions, stanzas, the oldest backup, the
# OpenBao snapshot and the Fleet dump at the point) and its confirmation run before anything stops (Agent design
# contract 8); RB_PHASE records when the stack went down and when the restore started to replace volumes.
rb_restore() {
  local old="$1" new="$2" at="$3" yes="$4" fp legacy only=() c
  shift 4
  for c in "$@"; do only+=(--only "$c"); done
  trap - EXIT INT TERM HUP
  unset SECRETS_DIR
  # shellcheck source=/dev/null # the old release's library, not this bundle's
  . "$old/scripts/lib.sh"
  # shellcheck source=/dev/null # the old release's library, not this bundle's
  . "$old/scripts/restore.sh"
  restore_trap_set
  # shellcheck disable=SC2034 # read by the old release's restore.sh
  RESTORE_SOURCE=repo RESTORE_SOURCE_LABEL="the local backup repository" RESTORE_ONLY=("$@")
  # shellcheck disable=SC2034 # read by the old release's restore.sh
  RESTORE_AT="$(restore_normalize_at "$at")" || restore_die "the rollback point $at is no RFC 3339 time; nothing was changed"
  restore_set_opts
  restore_read_set
  [[ "${RESTORE_SET[key_fingerprint]:-}" =~ ^[0-9a-f]{16}$ ]] ||
    restore_die "the backup set at $at names no key fingerprint; nothing was changed"
  # The legacy key file of the old directory (PDK-732) when it made the set, else the key the operator enters.
  legacy="$SECRETS_DIR/backup_encryption_key"
  if [[ -f "$legacy" && "$(restore_key_fingerprint "$legacy" || true)" == "${RESTORE_SET[key_fingerprint]}" ]]; then
    RESTORE_KEY_FILE="$legacy"
  else
    RESTORE_KEY_FILE="$SECRETS_DIR/$RESTORE_KEY_PATH"
    echo "The pre-upgrade set was made with backup key ${RESTORE_SET[key_id]:-?} (fingerprint ${RESTORE_SET[key_fingerprint]})."
    restore_prompt_key "$RESTORE_KEY_FILE"
    fp="$(restore_key_fingerprint "$RESTORE_KEY_FILE")" || fp=""
    [[ "$fp" == "${RESTORE_SET[key_fingerprint]}" ]] ||
      restore_die "the key entered has fingerprint ${fp:-invalid}, the set needs ${RESTORE_SET[key_fingerprint]}; nothing was changed"
  fi
  restore_preflight
  [[ -n "$yes" ]] || restore_confirm
  # The WAL the new stack wrote after the rollback point lets the recovery find its end; best effort, as in a restore.
  restore_flush_wal
  # restore_run stops the writers first and only then replaces volumes; the wrapper marks that boundary for the
  # failure message (a copy of the old release's function, which stays its interface).
  declare -F restore_stop_writers >/dev/null ||
    restore_die "the old release's restore.sh has no restore_stop_writers; nothing was changed"
  eval "rb_restore_stop_writers() $(declare -f restore_stop_writers | tail -n +2)"
  # shellcheck disable=SC2317 # called by the old release's restore_run
  restore_stop_writers() {
    echo restore >"$RB_PHASE"
    rb_restore_stop_writers
  }
  rb_mark_started
  echo down >"$RB_PHASE"
  echo "+ ./paddock down"
  "$new/paddock" down </dev/null
  echo "+ restore of ${*} from the local backup repository at $at (the old release's restore.sh)"
  # The operator confirmed above (or passed --yes); restore_run repeats its preflight and its question.
  restore_run fresh repo --at "$at" "${only[@]}" <<<restore
  restore_cleanup
  restore_trap_reset
}

# rb_legacy_restore <old dir> <new dir> <record> <with fleet: yes|no>: the rollback to 0.1.0-alpha.8 by that release's
# restore procedure (legacy-alpha8.sh), in a subshell. Its preconditions run before anything stops; RB_PHASE as in
# rb_restore.
rb_legacy_restore() {
  local old="$1" new="$2" record="$3" fleet="$4"
  trap - EXIT INT TERM HUP
  RB_LEGACY_WORK="$(mktemp -d "$new/.rollback-legacy.XXXXXX")"
  # The downloaded sets and the temporary OpenBao root token of the fresh instance live here only.
  trap 'rm -rf "$RB_LEGACY_WORK"' EXIT
  la8_preflight "$old" "$record" "$RB_LEGACY_WORK" "$fleet" "$PADDOCK_PROJECT"
  rb_mark_started
  echo down >"$RB_PHASE"
  echo "+ ./paddock down"
  "$new/paddock" down </dev/null
  echo restore >"$RB_PHASE"
  la8_restore "$old" "$PADDOCK_PROJECT" "$RB_LEGACY_WORK" "$fleet"
}

# rollback_main <new dir> <arguments of ./paddock rollback>
rollback_main() {
  local new="$1" old="" yes="" arg schema record state at="" attempt="" stale="" old_version new_version components=()
  local answer="" status=0 current superseded running="" lenient="" v bad="" legacy="" fleet=no problem
  shift
  for arg in "$@"; do
    case "$arg" in
      --yes) yes=1 ;;
      -*) rb_usage ;;
      *)
        [[ -z "$old" ]] || rb_usage
        old="$arg"
        ;;
    esac
  done
  [[ -n "$old" && -d "$old" ]] || rb_usage
  old="$(cd "$old" && pwd)"
  [[ "$old" != "$new" ]] || rb_die "<old dir> is this directory" 2
  [[ -x "$old/paddock" && -f "$old/.env" ]] || rb_die "$old is no bundle directory of an installation (no ./paddock or .env)" 2
  old_version="$(sed -n 's/^version=//p' "$old/VERSION" 2>/dev/null | head -n 1)"
  new_version="$(sed -n 's/^version=//p' "$new/VERSION" 2>/dev/null | head -n 1)"
  record="$new/.upgrade-rollback"
  state="$new/.upgrade-state"
  RB_RECORD=""
  # A later upgrade from this directory supersedes its record: a rollback from here would stop that release and
  # restore a point before every change since then (Agent design contract 8).
  if [[ ! -f "$record" ]]; then
    for superseded in "$new"/.upgrade-rollback.superseded-by-*; do
      [[ -e "$superseded" ]] || continue
      rb_die "the rollback point of this directory was superseded by the upgrade to ${superseded##*.superseded-by-} ($(basename "$superseded")): roll back from the directory of the release that runs; nothing was changed"
    done
  fi
  # The record holds only for the upgrade attempt that wrote it: the versions of both directories, and the attempt in
  # .upgrade-state while that attempt is unfinished. A record of an earlier attempt would restore a point that lies
  # before every change since then (Agent design contract 8).
  if [[ -f "$record" ]]; then
    [[ "$(rb_value "$record" old)" == "$old" ]] ||
      rb_die "this directory was upgraded from $(rb_value "$record" old), not from $old (.upgrade-rollback)" 2
    attempt="$(rb_value "$record" attempt)"
    if [[ ! "$attempt" =~ ^[0-9a-f]{16}$ || "$(rb_value "$record" from)" != "$old_version" ||
      "$(rb_value "$record" to)" != "$new_version" ]]; then
      stale="it names no upgrade attempt from $old_version to $new_version"
    elif [[ -f "$state" && "$(rb_value "$state" attempt)" != "$attempt" ]]; then
      current="$(rb_value "$state" attempt)"
      stale="it belongs to the upgrade attempt $attempt, .upgrade-state to ${current:-an attempt that did not reach ./paddock up}"
    else
      at="$(rb_value "$record" at)"
      [[ "$(rb_value "$record" backup)" == yes ]] || at=""
    fi
    [[ -z "$stale" ]] || attempt=""
  fi
  if [[ -z "$attempt" ]] && grep -q '^rolled-back=' "$state" 2>/dev/null; then
    rb_die "this directory was rolled back already and no upgrade attempt reached ./paddock up since: $old_version runs from $old (start it with $old/paddock up if it does not run); nothing was changed"
  fi
  # The running stack must be this directory's release, the record's `to`. While its upgrade attempt is unfinished
  # (a failed `up`) or after this rollback took the stack down, it may also be the old release or down.
  if [[ -n "$attempt" ]]; then
    RB_RECORD="$record"
    if [[ "$(rb_value "$state" attempt)" == "$attempt" ]] || grep -q '^rollback-started=' "$record"; then lenient=1; fi
  fi
  running="$(rb_running_versions "$new")" ||
    rb_die "cannot read the versions of the running containers (docker); nothing was changed"
  while IFS= read -r v; do
    [[ -n "$v" ]] || continue
    [[ "$v" == "$new_version" ]] || [[ -n "$lenient" && "$v" == "$old_version" ]] || bad=1
  done <<<"$running"
  if [[ -z "$running" && -z "$lenient" ]] || [[ -n "$bad" ]]; then
    if [[ -n "$running" ]]; then
      running="$(sort -u <<<"$running" | sed 's/^?$/(no version label)/' | paste -sd ' ' -)"
    else
      running="no container of a versioned Paddock image"
    fi
    rb_die "the running stack is not $new_version, the release this directory rolls back (running: $running): a rollback from here would stop it and restore data from before its changes; roll back from the directory of the release that runs; nothing was changed"
  fi
  schema="$(grep -m1 '^Schema:' "$new/RELEASE-NOTES" 2>/dev/null || true)"

  # What has to be restored (decision 7). No Schema line counts as a schema change: a restore is the safe side.
  if [[ "$PADDOCK_HOST" != audit ]] && backup_host; then
    if [[ "$schema" != "Schema: unchanged" ]]; then
      components=(postgres openbao)
      if rb_fleet_changed "$new" "$old"; then components+=(fleet); fi
      components+=(escrow)
    elif rb_fleet_changed "$new" "$old"; then
      components=(fleet)
    fi
  elif [[ "$PADDOCK_HOST" == lab && "$schema" != "Schema: unchanged" ]]; then
    rb_die "this lab host takes no backups and the release changed the schema (${schema:-no Schema line}): there is no pre-upgrade set to restore; nothing was changed"
  fi
  if ((${#components[@]} > 0)); then
    [[ -z "$stale" ]] ||
      rb_die "the rollback point in .upgrade-rollback is stale ($stale): restoring it would lose every change since that attempt; restore by hand with ./paddock restore (docs/operations/restore.md); nothing was changed"
    [[ -n "$at" ]] ||
      rb_die "no pre-upgrade backup is recorded in .upgrade-rollback (the upgrade did not take one, or did not reach ./paddock up); restore by hand with ./paddock restore (docs/operations/restore.md); nothing was changed"
    if la8_applies "$old_version"; then
      legacy=1
      problem="$(la8_record_problem "$record")"
      [[ -z "$problem" ]] ||
        rb_die "the rollback point in .upgrade-rollback cannot be restored by $old_version's procedure ($problem); restore by hand (docs/operations/restore.md of $old_version); nothing was changed"
      [[ " ${components[*]} " != *" fleet "* ]] || fleet=yes
    else
      [[ -f "$old/scripts/restore.sh" ]] ||
        rb_die "the old release $old_version ships no scripts/restore.sh; follow docs/operations/upgrade.md for this rollback; nothing was changed"
    fi
  fi

  echo "Rollback of this host ($PADDOCK_HOST, project $PADDOCK_PROJECT) from $new_version to $old_version (${schema:-no Schema line}):"
  echo "  1. ./paddock down"
  if [[ -n "$legacy" ]]; then
    echo "  2. $old_version's restore procedure (its docs/operations/restore.md) from the backup bucket:"
    echo "     PostgreSQL to the newest archived WAL after the backups $(rb_value "$record" legacy-paddock) (paddock) and $(rb_value "$record" legacy-authentik) (authentik);"
    echo "     OpenBao from $(rb_value "$record" legacy-openbao) into a fresh OpenBao, unsealed by three custodians or the automatic unseal;"
    if [[ "$fleet" == yes ]]; then echo "     Fleet's database from $(rb_value "$record" legacy-fleet);"; fi
    echo "     then the restore commands (bump-bundle-seq, rebuild-cache, recompile --all). The escrow bucket is not part of it."
    echo "  3. $old/paddock up"
    echo "Every change after the pre-upgrade backup ($(rb_value "$record" legacy-at)) can be lost: the restore reaches the WAL $old_version archived until the upgrade stopped its pgBackRest right before ./paddock up ($at)."
  elif ((${#components[@]} > 0)); then
    echo "  2. restore ${components[*]} from the local backup repository at $at (the pre-upgrade set $(rb_value "$record" label))"
    echo "  3. $old/paddock up"
    echo "Every change after $at is lost."
  else
    echo "  2. $old/paddock up"
  fi
  if [[ -z "$yes" ]]; then
    IFS= read -r -p 'Type "yes" to roll back: ' answer || true
    [[ "$answer" == yes ]] || rb_die "not confirmed; nothing was changed"
  fi

  RB_PHASE="$(mktemp)"
  if ((${#components[@]} > 0)); then
    set +e
    (
      set -e
      if [[ -n "$legacy" ]]; then
        rb_legacy_restore "$old" "$new" "$record" "$fleet"
      else
        rb_restore "$old" "$new" "$at" "$yes" "${components[@]}"
      fi
    )
    status=$?
    set -e
    if ((status != 0)); then
      case "$(cat "$RB_PHASE")" in
        restore)
          echo "rollback: the restore failed while it replaced the data (see above). Containers of $old_version may run on partly restored volumes; do not start $new_version on them." >&2
          echo "  Fix the cause and run ./paddock rollback $old again: it restores the set again." >&2
          ;;
        down)
          echo "rollback: the restore failed before it changed any volume (see above). The stack of $new_version is down; its volumes are untouched." >&2
          echo "  Fix the cause and run ./paddock rollback $old again, or start $new_version again with ./paddock up." >&2
          ;;
        *) echo "rollback: stopped before any change (see above); $new_version still runs." >&2 ;;
      esac
      rm -f "$RB_PHASE"
      exit "$status"
    fi
  else
    rb_mark_started || {
      rm -f "$RB_PHASE"
      rb_die "cannot write to .upgrade-rollback; nothing was changed"
    }
    echo "+ ./paddock down"
    "$new/paddock" down </dev/null || {
      rm -f "$RB_PHASE"
      rb_die "./paddock down failed; run ./paddock rollback $old again"
    }
  fi
  rm -f "$RB_PHASE"
  # The record is retired before the old release starts: the data is the pre-upgrade state now, and a second rollback
  # must not restore it again. A later ./paddock upgrade starts again at the check and copies .env and .secrets/ again:
  # the old release runs in between and may be reconfigured.
  if [[ -n "$attempt" ]]; then mv "$record" "$record.rolled-back-$attempt"; fi
  printf 'old=%s\nrolled-back=%s\n' "$old" "${attempt:-none}" >"$state"
  echo "+ $old/paddock up"
  if ((${#components[@]} > 0)); then
    "$old/paddock" up </dev/null ||
      rb_die "$old/paddock up failed (see above); the data is the pre-upgrade state. Fix the cause and run $old/paddock up again."
  else
    "$old/paddock" up </dev/null ||
      rb_die "$old/paddock up failed (see above); nothing was restored, the data is the one $new_version left. Fix the cause and run $old/paddock up again."
  fi
  echo "rollback: $old_version runs again from $old."
}
