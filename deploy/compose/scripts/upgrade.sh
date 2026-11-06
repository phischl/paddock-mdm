#!/usr/bin/env bash
# The upgrade of a host to this bundle's version (plan M16 decision 6, ADR 0047 decision 3), sourced by
# `./paddock upgrade <old dir> [--yes] [--allow-unsupported-agents] [--skip-backup]` together with upgrade-check.sh. It
# runs in the directory of the NEW bundle, before that directory has a .env, and calls ./paddock of both directories
# for every step, so each step is the command the runbook names and prints it before it runs.
#
# Nothing changes on the running stack before the pre-upgrade backup has completed; a failed step stops the run with
# the host's state and the next command. Progress is kept in .upgrade-state (one `done=<step>` line per finished step),
# so a second run continues at the first unfinished step; a successful run deletes it. .upgrade-rollback keeps what
# ./paddock rollback needs (the old directory, the backup label, the point in time just before the first `up`).
# shellcheck shell=bash

UG_STEPS=(upgrade-check migrate-from secrets pull check backup audit-writer-stop up openbao post-checks)

# UG_RETIRED: the services an earlier release defines and this one no longer does. `up` and `down` without
# --remove-orphans leave their containers running beside this release (PDK-845), so the step up removes them through
# the old directory's Compose files. An explicit list instead of --remove-orphans, which would also remove every other
# container of the project this release's files do not name.
#   fleet-backup-upload  0.1.0-alpha.8's uploader of Fleet's dumps to the backup bucket; 0.1.0-alpha.9 backs Fleet up
#                        into the local repository (plan M15). Its own legacy backup needs it until the step backup is done.
UG_RETIRED=(fleet-backup-upload)

ug_usage() {
  echo "usage: ./paddock upgrade <old bundle directory> [--yes] [--allow-unsupported-agents] [--skip-backup]" >&2
  exit 2
}

ug_die() {
  echo "upgrade: $1" >&2
  exit "${2:-1}"
}

# ug_value <file> <name>: the value of name= in an env file (for decisions only, never printed).
ug_value() { grep "^$2=" "$1" 2>/dev/null | tail -n 1 | cut -d= -f2- || true; }

ug_done() { grep -qx "done=$1" "$UG_STATE" 2>/dev/null; }

# ug_schema <bundle dir>: the Schema: line of the bundle's release notes, empty when it has none.
ug_schema() { grep -m1 '^Schema:' "$1/RELEASE-NOTES" 2>/dev/null || true; }

# ug_fleet_changed <new dir> <old dir>: Fleet migrates its MySQL when its image changes, so a rollback needs its dump.
ug_fleet_changed() { [[ "$(ug_value "$1/versions.env" FLEET_IMAGE)" != "$(ug_value "$2/versions.env" FLEET_IMAGE)" ]]; }

# ug_has_backup_now <old dir>: the old release has the labelled backup of plan M15 (0.1.0-alpha.9 and later).
ug_has_backup_now() {
  local usage
  usage="$("$1/paddock" 2>&1 </dev/null || true)"
  [[ "$usage" == *"backup now"* ]]
}

# ug_fail <step>: the host's state after the failed step and the one next action for it; exits 1.
ug_fail() {
  local step="$1" again="./paddock upgrade $UG_OLD"
  echo "upgrade: the step $step failed (see above)." >&2
  if ! grep -qv '^old=' "$UG_STATE" 2>/dev/null; then
    rm -f "$UG_STATE"
    echo "  Nothing changed on the running stack: $UG_OLD_VERSION still runs from $UG_OLD." >&2
    echo "  Fix the cause, then run $again again." >&2
    exit 1
  fi
  case "$step" in
    audit-writer-stop)
      echo "  The running stack is unchanged except that the old audit writer may be stopped." >&2
      echo "  Fix the cause, then run $again again: it continues at the step $step (.upgrade-state). If you do" >&2
      echo "  not continue now, start the writer again with $UG_OLD/paddock compose start paddock-audit-writer." >&2
      ;;
    up)
      if [[ -n "${UG_UP_NOT_RUN:-}" ]]; then
        echo "  ./paddock up did not run: $UG_OLD_VERSION still runs unchanged from $UG_OLD." >&2
        if [[ -n "$UG_STOP_AUDIT_WRITER" ]] && ug_done audit-writer-stop; then
          echo "  Only its audit writer is stopped; to keep it running, start it with $UG_OLD/paddock compose start paddock-audit-writer." >&2
        fi
        echo "  Fix the cause, then run $again again." >&2
        exit 1
      fi
      echo "  The new release $UG_NEW_VERSION may be partly running, its migrations partly applied." >&2
      echo "  Roll back: ./paddock rollback $UG_OLD (once the cause of a passing failure, such as a port or a pull, is fixed," >&2
      echo "  $again continues at the step up instead)." >&2
      ;;
    openbao | post-checks)
      echo "  The new release $UG_NEW_VERSION runs on the migrated data." >&2
      echo "  Fix the cause, then run $again again: it continues at the step $step (.upgrade-state). Roll back" >&2
      echo "  (./paddock rollback $UG_OLD) only when the new release cannot be fixed." >&2
      ;;
    migrate-from)
      echo "  Nothing changed on the running stack: $UG_OLD_VERSION still runs from $UG_OLD." >&2
      echo "  Fix the cause, then run $again again: it removes the partial copy here and copies again." >&2
      ;;
    *)
      echo "  Nothing changed on the running stack: $UG_OLD_VERSION still runs from $UG_OLD." >&2
      echo "  Fix the cause, then run $again again: it continues at the step $step (.upgrade-state)." >&2
      ;;
  esac
  exit 1
}

# ug_step <step> <command…>: runs the command unless the step is done, prints it first, records it when it succeeds.
ug_step() {
  local step="$1"
  shift
  if ug_done "$step"; then
    echo "== $step: done in an earlier run"
    return 0
  fi
  echo "== $step"
  if "$@"; then
    echo "done=$step" >>"$UG_STATE"
  else
    ug_fail "$step"
  fi
}

# ug_show <command…>: prints a command with this directory written as ./paddock, then runs it.
ug_show() {
  local shown="${*//"$UG_NEW/paddock"/./paddock}"
  echo "+ $shown"
  "$@"
}

# ug_check_step: the read-only check of decision 5; --allow-unsupported-agents accepts the server report's agents FAIL
# and nothing else.
ug_check_step() {
  local status=0 i blocking=() lines
  echo "+ ./paddock upgrade-check $UG_OLD"
  upgrade_check "$UG_NEW" "$UG_OLD" || status=$?
  ((status != 0)) || return 0
  ((status == 1)) || return 1
  for i in "${!uc_names[@]}"; do
    [[ "${uc_status[i]}" == FAIL ]] || continue
    if [[ "${uc_names[i]}" == "server report" && -n "$UG_ALLOW_AGENTS" ]]; then
      lines="$(grep -E '^FAIL[[:space:]]' <<<"${uc_server_lines:-}" || true)"
      if [[ -n "$lines" ]] && ! grep -qvE '^FAIL[[:space:]]+agents[[:space:]]' <<<"$lines"; then
        echo "upgrade: the agents FAIL is accepted (--allow-unsupported-agents): those devices stop receiving bundles and commands until their agent is updated"
        continue
      fi
    fi
    blocking+=("${uc_names[i]}")
  done
  if ((${#blocking[@]} > 0)); then
    echo "upgrade: the check failed (${blocking[*]}); nothing was changed" >&2
    return 1
  fi
}

ug_backup_step() {
  if [[ "$UG_BACKUP" != yes ]]; then
    echo "skipped: $UG_BACKUP"
    return 0
  fi
  if la8_applies "$UG_OLD_VERSION"; then
    la8_backup "$UG_OLD" "$UG_STATE"
    return
  fi
  ug_show "$UG_OLD/paddock" backup now --label "$UG_LABEL" --wait </dev/null
}

ug_audit_writer_step() {
  if [[ -z "$UG_STOP_AUDIT_WRITER" ]]; then
    echo "skipped: no audit migrations, or no audit writer on this host"
    return 0
  fi
  # The old writer would keep writing while the audit migrations hold their locks (docs/operations/upgrade.md step 4).
  ug_show "$UG_OLD/paddock" compose stop paddock-audit-writer </dev/null
}

# ug_up_step records the rollback point before the first `up`: every change after it is lost by a rollback that
# restores, and the pre-upgrade backup has completed before it. The attempt ID binds the record to this attempt
# (.upgrade-state), so ./paddock rollback never takes the point of an earlier one. errexit is off inside a step
# (ug_step runs it as a condition): a failed write stops here explicitly, before `up` migrates anything. The legacy
# backup of 0.1.0-alpha.8 is restored with every WAL segment the bucket holds, so its archive is fenced first; a failed
# fence leaves no record, and the next run repeats it. Its recorded backups must still be the newest after the fence
# (alpha.8 may have taken a newer one while the run was stopped); if not, the step backup is forgotten and runs again.
# Every failure here leaves `up` not run (UG_UP_NOT_RUN), which ug_fail reports apart from a failed `up`.
# The retired services go after the record and on every run of the step: a run that stops before the record leaves
# the old release complete, and from the record on ./paddock rollback starts them again with the old release's `up`.
ug_up_step() {
  local legacy=""
  UG_UP_NOT_RUN=""
  if ! grep -q '^up-started=' "$UG_STATE"; then
    if [[ "$UG_BACKUP" == yes ]] && la8_applies "$UG_OLD_VERSION"; then legacy=1; fi
    if [[ -n "$legacy" ]]; then
      la8_fence "$UG_OLD" || {
        UG_UP_NOT_RUN=1
        return 1
      }
      la8_still_newest "$UG_OLD" "$UG_STATE" || {
        la8_unfence "$UG_OLD"
        ug_forget_backup
        UG_UP_NOT_RUN=1
        return 1
      }
    fi
    ug_record_rollback_point || {
      echo "upgrade: cannot record the rollback point in .upgrade-rollback and .upgrade-state" >&2
      if [[ -n "$legacy" ]]; then la8_unfence "$UG_OLD"; fi
      UG_UP_NOT_RUN=1
      return 1
    }
  fi
  ug_retire || {
    echo "upgrade: cannot remove the services $UG_NEW_VERSION retired; ./paddock up did not run" >&2
    UG_UP_NOT_RUN=1
    return 1
  }
  ug_show "$UG_NEW/paddock" up
}

# ug_retired_in_old: the services of UG_RETIRED that the old directory's Compose files define, one per line.
ug_retired_in_old() {
  local defined svc
  defined="$("$UG_OLD/paddock" compose config --services </dev/null)" || {
    echo "upgrade: cannot read the services of $UG_OLD (./paddock compose config --services)" >&2
    return 1
  }
  for svc in "${UG_RETIRED[@]}"; do
    if grep -qxF "$svc" <<<"$defined"; then echo "$svc"; fi
  done
}

# ug_retire: stops and removes the containers of the retired services, never a volume; without a container it changes
# nothing, so a repeated step is safe.
ug_retire() {
  local list svcs=()
  list="$(ug_retired_in_old)" || return 1
  [[ -n "$list" ]] || return 0
  mapfile -t svcs <<<"$list"
  ug_show "$UG_OLD/paddock" compose rm -sf "${svcs[@]}" </dev/null
}

# ug_forget_backup: removes the step backup and the names it recorded from .upgrade-state, so the next run takes the
# pre-upgrade backup again.
ug_forget_backup() {
  if ! grep -vE '^(done=backup|legacy-[a-z]+=.*)$' "$UG_STATE" >"$UG_STATE.tmp" || ! mv -T "$UG_STATE.tmp" "$UG_STATE"; then
    rm -f "$UG_STATE.tmp"
    echo "upgrade: cannot remove the step backup from .upgrade-state; remove its done=backup and legacy-* lines by hand" >&2
  fi
}

ug_record_rollback_point() {
  local at attempt backup=no
  [[ "$UG_BACKUP" != yes ]] || backup=yes
  at="$(date -u +%Y-%m-%dT%H:%M:%SZ)" || return 1
  attempt="$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')" || return 1
  [[ "$attempt" =~ ^[0-9a-f]{16}$ ]] || return 1
  # The old directory's own record (of the upgrade to it) is superseded before this release changes the stack: a
  # rollback from there would stop this release and restore a point before every change since (Agent design contract
  # 8). First, so that a failure leaves no record of this attempt that would skip it on the next run.
  if [[ -f "$UG_OLD/.upgrade-rollback" ]]; then
    mv -T "$UG_OLD/.upgrade-rollback" "$UG_OLD/.upgrade-rollback.superseded-by-$UG_NEW_VERSION" || return 1
  fi
  {
    printf 'old=%s\nfrom=%s\nto=%s\nbackup=%s\nlabel=%s\nat=%s\nattempt=%s\n' "$UG_OLD" "$UG_OLD_VERSION" \
      "$UG_NEW_VERSION" "$backup" "$UG_LABEL" "$at" "$attempt"
    if [[ "$backup" == yes ]] && la8_applies "$UG_OLD_VERSION"; then la8_record_fields "$UG_STATE"; fi
  } >"$UG_NEW/.upgrade-rollback.tmp" || return 1
  mv -T "$UG_NEW/.upgrade-rollback.tmp" "$UG_NEW/.upgrade-rollback" || return 1
  printf 'attempt=%s\nup-started=%s\n' "$attempt" "$at" >>"$UG_STATE"
}

# ug_migrate_from_step: ./paddock migrate-from refuses an existing .env, .secrets/ or targets file. Before this step
# is done they can only be a partial copy of an earlier run (the first run starts in a directory without them), so they
# are removed and copied again.
ug_migrate_from_step() {
  local leftover=() f
  for f in "$UG_NEW/.env" "$UG_NEW/.secrets" "$UG_NEW/compose.backup-targets.yaml" "$UG_NEW"/.compose.backup-targets.yaml.*; do
    if [[ -e "$f" || -L "$f" ]]; then leftover+=("$f"); fi
  done
  if ((${#leftover[@]} > 0)); then
    echo "+ rm -rf ${leftover[*]#"$UG_NEW"/} (the partial copy of an earlier migrate-from)"
    rm -rf -- "${leftover[@]}" || return 1
  fi
  ug_show "$UG_NEW/paddock" migrate-from "$UG_OLD"
}

ug_openbao_step() {
  if [[ "$UG_HOST" == audit ]]; then
    echo "skipped: the audit host runs no OpenBao"
  elif [[ -n "${BAO_TOKEN:-}" ]]; then
    ug_show "$UG_NEW/paddock" bootstrap openbao </dev/null
  elif grep -qi openbao <<<"$(grep -m1 '^Upgrade:' "$UG_NEW/RELEASE-NOTES" 2>/dev/null || true)"; then
    echo "MANUAL STEP: the release notes name OpenBao changes. With a root token in BAO_TOKEN (docs/operations/openbao.md"
    echo "  section 1; revoke it afterwards) run ./paddock bootstrap openbao in this directory."
  else
    echo "skipped: BAO_TOKEN is not set and the release notes name no OpenBao change"
  fi
}

ug_post_checks_step() {
  local out
  uc_names=() uc_status=() uc_detail=()
  echo "+ ./paddock ps"
  uc_item_running "$UG_NEW"
  echo "${uc_status[-1]}  ${uc_detail[-1]}"
  [[ "${uc_status[-1]}" == PASS ]] || return 1
  if [[ "$UG_HOST" != audit ]]; then
    echo "+ ./paddock compose run --rm --no-deps -T paddock-worker admin upgrade-check --target-version $UG_NEW_VERSION"
    out="$("$UG_NEW/paddock" compose run --rm --no-deps -T paddock-worker admin upgrade-check \
      --target-version "$UG_NEW_VERSION" 2>&1 </dev/null)" || true
    grep -E '^(PASS|WARN|FAIL|INFO)[[:space:]]' <<<"$out" || true
    if ! grep -qE '^PASS[[:space:]]+migrations[[:space:]]' <<<"$out"; then
      echo "upgrade: the new stack's report does not show the migrations at the binary's version" >&2
      return 1
    fi
  fi
  if [[ "$UG_HOST" != controlplane ]]; then
    ug_show "$UG_NEW/paddock" check --online </dev/null || return 1
  fi
}

# ug_plan prints the steps with their state.
ug_plan() {
  local step mark what retired
  echo "Upgrade of this host ($UG_HOST, project $UG_PROJECT) from $UG_OLD_VERSION to $UG_NEW_VERSION:"
  for step in "${UG_STEPS[@]}"; do
    mark=""
    ug_done "$step" && mark=" (done)"
    case "$step" in
      upgrade-check) what="./paddock upgrade-check $UG_OLD (stops on FAIL)" ;;
      migrate-from) what="./paddock migrate-from $UG_OLD" ;;
      secrets) what="./paddock secrets (generates missing secrets only)" ;;
      pull) what="./paddock pull" ;;
      check) what="./paddock check (every item PASS, else stop: the old stack still runs)" ;;
      backup)
        if [[ "$UG_BACKUP" != yes ]]; then
          what="no backup: $UG_BACKUP"
        elif la8_applies "$UG_OLD_VERSION"; then
          what="$UG_OLD_VERSION's own backup through $UG_OLD/paddock compose: pgbackrest and pgbackrest-authentik backup --start-fast, paddock-worker backup openbao, fleet-backup once, each checked in the backup bucket"
        else
          what="$UG_OLD/paddock backup now --label $UG_LABEL --wait"
        fi
        ;;
      audit-writer-stop)
        if [[ -n "$UG_STOP_AUDIT_WRITER" ]]; then what="$UG_OLD/paddock compose stop paddock-audit-writer (audit migrations)"; else continue; fi
        ;;
      up)
        what="./paddock up (the new images; paddock-migrate applies the migrations)"
        retired="$(ug_retired_in_old 2>/dev/null)" || retired="${UG_RETIRED[*]}"
        if [[ -n "$retired" ]]; then
          what="$UG_OLD/paddock compose rm -sf $(paste -sd ' ' <<<"$retired") (services $UG_NEW_VERSION retired), then $what"
        fi
        if [[ "$UG_BACKUP" == yes ]] && la8_applies "$UG_OLD_VERSION"; then
          what="$UG_OLD/paddock compose stop pgbackrest pgbackrest-authentik and flush both (the backup bucket's WAL archive ends here), then $what"
        fi
        ;;
      openbao)
        [[ "$UG_HOST" != audit ]] || continue
        if [[ -n "${BAO_TOKEN:-}" ]]; then what="./paddock bootstrap openbao (BAO_TOKEN is set)"; else what="./paddock bootstrap openbao only as a manual step (BAO_TOKEN is not set)"; fi
        ;;
      post-checks) what="./paddock ps healthy; the new server's report; ./paddock check --online (audit, lab)" ;;
    esac
    printf '  %-18s %s%s\n' "$step" "$what" "$mark"
  done
  if [[ -n "$UG_NO_RESTORE" ]]; then
    echo "Rollback afterwards: no pre-upgrade backup exists, so a rollback is only ./paddock down and $UG_OLD/paddock up."
    echo "  The pre-upgrade data is lost: the old release has to run on the data this release migrated, and"
    echo "  ./paddock rollback refuses after a schema change."
  else
    echo "Rollback afterwards: ./paddock rollback $UG_OLD"
    if [[ "$UG_BACKUP" == yes ]] && la8_applies "$UG_OLD_VERSION"; then
      echo "  It runs $UG_OLD_VERSION's restore procedure: the data comes back from the backup bucket as of this backup"
      echo "  (plus the WAL archived until the step up stops $UG_OLD_VERSION's pgBackRest), and the restored OpenBao is unsealed"
      echo "  by three custodians or the automatic unseal."
    fi
  fi
}

# upgrade_main <new dir> <arguments of ./paddock upgrade>
upgrade_main() {
  local arg yes="" skip="" answer="" schema lab_backup rest
  UG_NEW="$1"
  shift
  UG_OLD="" UG_ALLOW_AGENTS=""
  for arg in "$@"; do
    case "$arg" in
      --yes) yes=1 ;;
      --allow-unsupported-agents) UG_ALLOW_AGENTS=1 ;;
      --skip-backup) skip=1 ;;
      -*) ug_usage ;;
      *)
        [[ -z "$UG_OLD" ]] || ug_usage
        UG_OLD="$arg"
        ;;
    esac
  done
  [[ -n "$UG_OLD" && -d "$UG_OLD" ]] || ug_usage
  UG_OLD="$(cd "$UG_OLD" && pwd)"
  [[ "$UG_OLD" != "$UG_NEW" ]] || ug_die "<old dir> is this directory" 2
  [[ -x "$UG_OLD/paddock" && -f "$UG_OLD/.env" ]] || ug_die "$UG_OLD is no bundle directory of a running installation (no ./paddock or .env)" 2
  UG_STATE="$UG_NEW/.upgrade-state"
  if [[ -f "$UG_STATE" ]]; then
    [[ "$(ug_value "$UG_STATE" old)" == "$UG_OLD" ]] ||
      ug_die "this directory continues an upgrade from $(ug_value "$UG_STATE" old), not from $UG_OLD (.upgrade-state)" 2
  elif [[ -e "$UG_NEW/.env" || -e "$UG_NEW/.secrets" ]]; then
    ug_die "this directory already has .env or .secrets/ but no .upgrade-state: ./paddock upgrade starts in a freshly extracted bundle directory" 2
  fi

  UG_HOST="$(ug_value "$UG_OLD/.env" PADDOCK_HOST)"
  [[ "$UG_HOST" == controlplane || "$UG_HOST" == audit || "$UG_HOST" == lab ]] ||
    ug_die "PADDOCK_HOST in $UG_OLD/.env is not controlplane, audit or lab" 2
  UG_PROJECT="$(ug_value "$UG_OLD/.env" PADDOCK_PROJECT)"
  UG_PROJECT="${UG_PROJECT:-paddock}"
  UG_OLD_VERSION="$(uc_version "$UG_OLD")"
  UG_NEW_VERSION="$(uc_version "$UG_NEW")"
  [[ -n "$UG_OLD_VERSION" && -n "$UG_NEW_VERSION" ]] || ug_die "cannot read the version of this bundle or of $UG_OLD" 2
  UG_LABEL="pre-upgrade-$UG_NEW_VERSION"
  schema="$(ug_schema "$UG_NEW")"
  lab_backup="$(ug_value "$UG_OLD/.env" PADDOCK_LAB_BACKUP)"

  # The backup decision (decision 6): required where the backup role runs, unless nothing a rollback restores changes.
  UG_BACKUP=yes UG_NO_RESTORE=""
  if [[ "$UG_HOST" == audit ]]; then
    UG_BACKUP="the audit host has no backup role; its rollback is down and up"
  elif [[ "$UG_HOST" == lab && "$lab_backup" != yes ]]; then
    if [[ "$schema" != "Schema: unchanged" && -z "$skip" ]]; then
      ug_die "this lab host takes no backups (PADDOCK_LAB_BACKUP is not yes) and the release changes the schema (${schema:-no Schema line}): ./paddock rollback could not restore the data. Pass --skip-backup to accept that." 2
    fi
    if ug_fleet_changed "$UG_NEW" "$UG_OLD" && [[ -z "$skip" ]]; then
      ug_die "this lab host takes no backups (PADDOCK_LAB_BACKUP is not yes) and FLEET_IMAGE changes: the new Fleet migrates its MySQL and ./paddock rollback could not restore Fleet's dump. Pass --skip-backup to accept that." 2
    fi
    UG_BACKUP="this lab host takes no backups (PADDOCK_LAB_BACKUP is not yes)"
    if [[ "$schema" != "Schema: unchanged" ]] || ug_fleet_changed "$UG_NEW" "$UG_OLD"; then UG_NO_RESTORE=1; fi
  elif [[ -n "$skip" ]]; then
    [[ "$schema" == "Schema: unchanged" ]] ||
      ug_die "--skip-backup is refused on this host: the release notes say '${schema:-no Schema line}', so a rollback restores the pre-upgrade backup" 2
    ! ug_fleet_changed "$UG_NEW" "$UG_OLD" ||
      ug_die "--skip-backup is refused on this host: FLEET_IMAGE changes, so a rollback restores Fleet's dump from the pre-upgrade backup" 2
    UG_BACKUP="--skip-backup (Schema: unchanged)"
  elif ! la8_applies "$UG_OLD_VERSION" && ! ug_done backup && ! ug_has_backup_now "$UG_OLD"; then
    ug_die "the running release $UG_OLD_VERSION has no ./paddock backup now --label, so the labelled pre-upgrade backup cannot be taken; nothing was changed. Follow docs/operations/upgrade.md for this upgrade." 1
  fi
  UG_STOP_AUDIT_WRITER=""
  if [[ "$UG_HOST" != controlplane ]] && { [[ -z "$schema" ]] || grep -q 'audit migrations' <<<"$schema"; }; then
    UG_STOP_AUDIT_WRITER=1
  fi

  [[ -f "$UG_STATE" ]] || printf 'old=%s\n' "$UG_OLD" >"$UG_STATE"
  ug_step upgrade-check ug_check_step
  ug_plan
  if [[ -z "$yes" ]]; then
    IFS= read -r -p 'Type "yes" to start the upgrade: ' answer || true
    if [[ "$answer" != yes ]]; then
      # Only the read-only check has run: the next run checks again instead of trusting a stale result.
      rest="$(grep -vx 'done=upgrade-check' "$UG_STATE" || true)"
      if grep -qv -e '^old=' -e '^$' <<<"$rest"; then printf '%s\n' "$rest" >"$UG_STATE"; else rm -f "$UG_STATE"; fi
      ug_die "not confirmed; stopped before the next step"
    fi
  fi
  ug_step migrate-from ug_migrate_from_step
  ug_step secrets ug_show "$UG_NEW/paddock" secrets
  ug_step pull ug_show "$UG_NEW/paddock" pull
  ug_step check ug_show "$UG_NEW/paddock" check
  ug_step backup ug_backup_step
  ug_step audit-writer-stop ug_audit_writer_step
  ug_step up ug_up_step
  ug_step openbao ug_openbao_step
  ug_step post-checks ug_post_checks_step
  rm -f "$UG_STATE"
  echo "upgrade: $UG_OLD_VERSION → $UG_NEW_VERSION completed on this host."
  echo "Keep $UG_OLD until the next upgrade: it is the rollback (./paddock rollback $UG_OLD)."
}
