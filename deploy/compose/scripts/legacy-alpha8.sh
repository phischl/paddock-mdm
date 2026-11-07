#!/usr/bin/env bash
# The pre-upgrade backup and the rollback of the pair 0.1.0-alpha.8 → 0.1.0-alpha.9 (plan M16, amendment 2026-11-06
# "the alpha.8 pair"; decisions-alpha9 items 46 and 49), sourced by upgrade.sh and rollback.sh. 0.1.0-alpha.8 has no
# labelled backup, no local repository and no restore.sh, so this file runs that release's own documented procedure
# (docs/operations/restore.md and upgrade.md step 3 at the tag v0.1.0-alpha.8) through the old directory's ./paddock,
# that is with alpha.8's Compose files and images:
#   - the backup: pgBackRest --start-fast for both stanzas, `paddock-worker backup openbao`, `fleet-backup once`, each
#     checked in the backup bucket; right before this release's `up`, the bucket's WAL archive is fenced (la8_fence);
#   - the rollback: both stanzas restored to the newest WAL archived before that fence, OpenBao from the recorded
#     snapshot into a fresh OpenBao, Fleet's dump when FLEET_IMAGE changed, then the restore commands of step 5.
# Remove this file and its two call sites once 0.1.0-alpha.8 leaves the support window (ADR 0013 amendment: its own
# release plus two).
# shellcheck shell=bash

LA8_RELEASE=0.1.0-alpha.8
LA8_METHOD="legacy-$LA8_RELEASE"
LA8_PG_LABEL='^[0-9]{8}-[0-9]{6}F$'
LA8_OPENBAO_KEY='^openbao/[0-9]{8}T[0-9]{6}Z\.snap\.enc$'
LA8_FLEET_KEY='^fleet/[0-9]{8}T[0-9]{6}Z\.sql\.gz\.enc$'

# la8_applies <old version>: the old release is 0.1.0-alpha.8, decided by the release sequence (its VERSION), never by
# probing the old bundle for features.
la8_applies() { [[ "$1" == "$LA8_RELEASE" ]]; }

la8_log() { printf '[legacy %s] %s\n' "$(date -u +%H:%M:%S)" "$*"; }

# la8_compose <old dir> <args…>: docker compose with the old release's files, project and images.
la8_compose() {
  local old="$1"
  shift
  "$old/paddock" compose "$@"
}

# la8_value <file> <name>
la8_value() { grep "^$2=" "$1" 2>/dev/null | tail -n 1 | cut -d= -f2- || true; }

# Runs in alpha.8's AWS CLI image (the service fleet-backup-upload, with the bucket's endpoint, region and CA) under
# the pgBackRest credential, the one alpha.8 grants s3:GetObject on openbao/ and fleet/ (restore.md, "Backup bucket").
# The credential files are mounted read-only and read into the environment: never on a command line.
# shellcheck disable=SC2016
LA8_S3_SCRIPT='set -euo pipefail
AWS_ACCESS_KEY_ID="$(cat /run/paddock-legacy/access_key)"
AWS_SECRET_ACCESS_KEY="$(cat /run/paddock-legacy/secret_key)"
AWS_DEFAULT_REGION="${PADDOCK_BACKUP_S3_REGION:-us-east-1}"
export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_DEFAULT_REGION AWS_PAGER=
if [[ -n "${PADDOCK_BACKUP_S3_CA_FILE:-}" ]]; then export AWS_CA_BUNDLE="$PADDOCK_BACKUP_S3_CA_FILE"; fi
case "$1" in
  head) aws --endpoint-url "$PADDOCK_BACKUP_S3_ENDPOINT" s3api head-object --bucket "$PADDOCK_BACKUP_S3_BUCKET" --key "$2" >/dev/null ;;
  get) aws --endpoint-url "$PADDOCK_BACKUP_S3_ENDPOINT" s3 cp --only-show-errors "s3://$PADDOCK_BACKUP_S3_BUCKET/$2" - ;;
  *) exit 2 ;;
esac'

# la8_s3 <old dir> head|get <key>: whether the object exists, or its content on stdout.
la8_s3() {
  local old="$1"
  la8_compose "$old" run --rm --no-deps -T \
    -v "$old/.secrets/backup_pgbackrest_access_key:/run/paddock-legacy/access_key:ro" \
    -v "$old/.secrets/backup_pgbackrest_secret_key:/run/paddock-legacy/secret_key:ro" \
    --entrypoint /bin/bash fleet-backup-upload -c "$LA8_S3_SCRIPT" la8-s3 "$2" "$3" </dev/null
}

# la8_pg_newest <old dir> <service>: the label of the newest backup of the service's stanza in the bucket. alpha.8's
# restore always restores the newest one.
la8_pg_newest() {
  local out
  out="$(la8_compose "$1" run --rm --no-deps -T "$2" info </dev/null)" || return 1
  sed -n -E 's/^[[:space:]]*(full|diff|incr) backup: ([0-9]{8}-[0-9]{6}[FDI_0-9-]*)$/\2/p' <<<"$out" | tail -n 1
}

# la8_run <log> <old dir> <compose args…>: one backup command of runbook step 3, printed first; its output goes to the
# terminal once it ends and stays in <log> for the names it reports.
la8_run() {
  local log="$1" old="$2" status=0
  shift 2
  echo "+ $old/paddock compose $*"
  la8_compose "$old" "$@" </dev/null >"$log" 2>&1 || status=$?
  cat "$log"
  return "$status"
}

# la8_backup <old dir> <state file>: runbook step 3 of 0.1.0-alpha.8 while that release still runs, each part checked
# in the bucket; on success it appends what the rollback needs to the state file (one attempt's values; the newest
# line of each name wins on a repeated step).
la8_backup() {
  local old="$1" state="$2" log paddock authentik openbao fleet deadline
  log="$(mktemp)" || return 1
  la8_run "$log" "$old" run --rm --no-deps -T pgbackrest backup --start-fast || { rm -f "$log"; return 1; }
  paddock="$(sed -n -E 's/^pgbackrest: backup ([0-9]{8}-[0-9]{6}F) of paddock verified$/\1/p' "$log" | tail -n 1)"
  la8_run "$log" "$old" run --rm --no-deps -T pgbackrest-authentik backup --start-fast || { rm -f "$log"; return 1; }
  authentik="$(sed -n -E 's/^pgbackrest: backup ([0-9]{8}-[0-9]{6}F) of authentik verified$/\1/p' "$log" | tail -n 1)"
  la8_run "$log" "$old" run --rm --no-deps -T paddock-worker backup openbao || { rm -f "$log"; return 1; }
  openbao="$(grep -oE 'openbao/[0-9]{8}T[0-9]{6}Z\.snap\.enc' "$log" | tail -n 1 || true)"
  la8_run "$log" "$old" run --rm --no-deps -T fleet-backup once || { rm -f "$log"; return 1; }
  fleet="$(sed -n -E 's/^fleet backup: dumped ([0-9]{8}T[0-9]{6}Z\.sql\.gz\.enc)$/fleet\/\1/p' "$log" | tail -n 1)"
  rm -f "$log"
  if [[ ! "$paddock" =~ $LA8_PG_LABEL || ! "$authentik" =~ $LA8_PG_LABEL || ! "$openbao" =~ $LA8_OPENBAO_KEY ||
    ! "$fleet" =~ $LA8_FLEET_KEY ]]; then
    echo "upgrade: a backup command of $LA8_RELEASE did not report its backup (paddock '${paddock:-?}', authentik '${authentik:-?}', OpenBao '${openbao:-?}', Fleet '${fleet:-?}')" >&2
    return 1
  fi
  echo "+ check that the four backups are in the backup bucket (docs/operations/upgrade.md of $LA8_RELEASE, step 3)"
  [[ "$(la8_pg_newest "$old" pgbackrest)" == "$paddock" ]] ||
    { echo "upgrade: the newest backup of stanza paddock in the bucket is not $paddock" >&2; return 1; }
  [[ "$(la8_pg_newest "$old" pgbackrest-authentik)" == "$authentik" ]] ||
    { echo "upgrade: the newest backup of stanza authentik in the bucket is not $authentik" >&2; return 1; }
  la8_s3 "$old" head "$openbao" || { echo "upgrade: $openbao is not in the backup bucket" >&2; return 1; }
  # fleet-backup-upload copies the dump within a minute; uploading it here as well would race with that service.
  deadline=$((SECONDS + ${LA8_UPLOAD_TIMEOUT:-300}))
  until la8_s3 "$old" head "$fleet" 2>/dev/null; do
    if ((SECONDS >= deadline)); then
      echo "upgrade: $fleet did not reach the backup bucket within ${LA8_UPLOAD_TIMEOUT:-300} s (see ./paddock logs fleet-backup-upload in $old)" >&2
      return 1
    fi
    sleep "${LA8_POLL_S:-10}"
  done
  echo "pre-upgrade backup of $LA8_RELEASE: paddock $paddock, authentik $authentik, $openbao, $fleet"
  printf 'legacy-paddock=%s\nlegacy-authentik=%s\nlegacy-openbao=%s\nlegacy-fleet=%s\nlegacy-at=%s\n' "$paddock" \
    "$authentik" "$openbao" "$fleet" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >>"$state"
}

# la8_fence <old dir>: ends the backup bucket's WAL archive before this release's `up`. The rollback restores every
# segment the bucket holds (alpha.8's `pgbackrest restore` stages them until there is no next one), so alpha.8's pusher
# must not live on into `up`, where it would push this release's migration WAL from the shared spool. Stopping both
# services and pushing what the spool holds then makes the archive end before this release touches a database; WAL
# written after that reaches this release's local repository only. A failed fence starts the services again, so that
# alpha.8 keeps archiving, and `up` does not run; the next run repeats the fence.
la8_fence() {
  local old="$1"
  echo "+ $old/paddock compose stop pgbackrest pgbackrest-authentik (the backup bucket's WAL archive ends here)"
  if la8_compose "$old" stop pgbackrest pgbackrest-authentik </dev/null &&
    la8_flush "$old" pgbackrest && la8_flush "$old" pgbackrest-authentik; then
    return 0
  fi
  echo "upgrade: cannot end $LA8_RELEASE's WAL archive in the backup bucket; starting its pgBackRest again" >&2
  la8_unfence "$old"
  return 1
}

# la8_unfence <old dir>: starts alpha.8's pgBackRest again after a fence whose `up` does not follow, so that alpha.8
# keeps archiving WAL and taking its daily full backups.
la8_unfence() {
  echo "+ $1/paddock compose start pgbackrest pgbackrest-authentik"
  la8_compose "$1" start pgbackrest pgbackrest-authentik </dev/null >/dev/null 2>&1 ||
    echo "upgrade: starting pgbackrest and pgbackrest-authentik failed too: run $1/paddock up" >&2
}

# la8_still_newest <old dir> <state file>: the backups recorded by la8_backup are still the newest of both stanzas.
# alpha.8's restore always restores the newest backup, and its pgBackRest takes a full one on its own once the last is
# 24 h old (while a run that stopped between the backup and `up` leaves it running), so a recorded backup that is no
# longer the newest is a rollback point that cannot be restored. Called after la8_fence, when no new backup can arrive.
la8_still_newest() {
  local old="$1" state="$2" svc stanza want got
  echo "+ check that the recorded pre-upgrade backups are still the newest in the backup bucket"
  for svc in pgbackrest pgbackrest-authentik; do
    if [[ "$svc" == pgbackrest ]]; then stanza=paddock want="$(la8_value "$state" legacy-paddock)"; else
      stanza=authentik want="$(la8_value "$state" legacy-authentik)"
    fi
    got="$(la8_pg_newest "$old" "$svc")" || got=""
    if [[ -z "$want" || "$got" != "$want" ]]; then
      echo "upgrade: the newest backup of stanza $stanza in the bucket is ${got:-unreadable}, not the recorded pre-upgrade backup ${want:-?}: $LA8_RELEASE's restore would not restore the recorded point; the next run takes the pre-upgrade backup again" >&2
      return 1
    fi
  done
}

la8_flush() {
  echo "+ $1/paddock compose run --rm --no-deps -T $2 flush"
  la8_compose "$1" run --rm --no-deps -T "$2" flush </dev/null
}

# la8_project_problem <old dir> <project>: why the old directory's Compose project differs from the one whose volumes
# the rollback deletes, empty when they match. The old directory's ./paddock reads PADDOCK_PROJECT from the process
# environment when it is exported, else from its own .env (default paddock), as lib.sh does.
la8_project_problem() {
  local old_project
  old_project="$(printenv PADDOCK_PROJECT || true)"
  [[ -n "$old_project" ]] || old_project="$(la8_value "$1/.env" PADDOCK_PROJECT)"
  old_project="${old_project:-paddock}"
  [[ "$old_project" == "$2" ]] || echo "$1/.env names the project $old_project, this directory's .env $2"
}

# la8_record_fields <state file>: the backup's lines for .upgrade-rollback (empty when the step took none).
la8_record_fields() {
  local name value
  for name in legacy-paddock legacy-authentik legacy-openbao legacy-fleet legacy-at; do
    value="$(la8_value "$1" "$name")"
    [[ -n "$value" ]] || return 0
  done
  printf 'method=%s\n' "$LA8_METHOD"
  for name in legacy-paddock legacy-authentik legacy-openbao legacy-fleet legacy-at; do
    printf '%s=%s\n' "$name" "$(la8_value "$1" "$name")"
  done
}

# la8_record_problem <record>: why the record holds no legacy backup to restore, empty when it holds one.
la8_record_problem() {
  local r="$1"
  if [[ "$(la8_value "$r" method)" != "$LA8_METHOD" ]]; then
    echo "it records no backup of $LA8_RELEASE's own procedure"
  elif [[ ! "$(la8_value "$r" legacy-paddock)" =~ $LA8_PG_LABEL || ! "$(la8_value "$r" legacy-authentik)" =~ $LA8_PG_LABEL ]]; then
    echo "its pgBackRest labels are invalid"
  elif [[ ! "$(la8_value "$r" legacy-openbao)" =~ $LA8_OPENBAO_KEY || ! "$(la8_value "$r" legacy-fleet)" =~ $LA8_FLEET_KEY ]]; then
    echo "its OpenBao snapshot or Fleet dump name is invalid"
  elif [[ ! "$(la8_value "$r" legacy-at)" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]]; then
    echo "its backup time is invalid"
  fi
}

# Runs in alpha.8's fleet-backup image (MySQL client, openssl, gzip). check: the dump decrypts and is a complete gzip
# stream; load: Fleet's database is replaced by the dump. The database is dropped instead of the volume (decisions-alpha9
# item 49 names the only volumes this path may delete); Fleet's grants live in the mysql schema and survive it. The
# root password goes through a file in the tmpfs, as fleet/backup.sh of that release does.
# shellcheck disable=SC2016
LA8_FLEET_SCRIPT='set -euo pipefail
decrypt() { openssl enc -d -aes-256-cbc -pbkdf2 -pass "file:$PADDOCK_BACKUP_ENCRYPTION_KEY_FILE" -in /in; }
case "$1" in
  check) decrypt | gzip -t ;;
  load)
    printf "[client]\nuser=root\npassword=%s\n" "$(cat "$FLEET_MYSQL_ROOT_PASSWORD_FILE")" >/tmp/my.cnf
    chmod 600 /tmp/my.cnf
    mysql --defaults-extra-file=/tmp/my.cnf -h fleet-mysql -e "DROP DATABASE IF EXISTS fleet"
    decrypt | gunzip | mysql --defaults-extra-file=/tmp/my.cnf -h fleet-mysql
    rm -f /tmp/my.cnf
    ;;
  *) exit 2 ;;
esac'

# la8_preflight <old dir> <record> <work dir> <with fleet: yes|no> <project>: every precondition of the restore, before
# anything stops (Agent design contract 8): both directories name the project whose volumes are replaced, the
# credentials and the key, the newest backup of each stanza is the recorded one (alpha.8 restores the newest), and the
# recorded OpenBao snapshot and Fleet dump are downloaded into <work dir> and decrypt with the key.
la8_preflight() {
  local old="$1" record="$2" work="$3" fleet="$4" project="$5" f svc want got problem
  problem="$(la8_project_problem "$old" "$project")"
  if [[ -n "$problem" ]]; then
    echo "rollback: $problem; the restore would delete the volumes of one project and start $LA8_RELEASE in the other. Set the same PADDOCK_PROJECT in both; nothing was changed" >&2
    return 1
  fi
  for f in backup_encryption_key backup_pgbackrest_access_key backup_pgbackrest_secret_key; do
    [[ -s "$old/.secrets/$f" ]] || { echo "rollback: $old/.secrets/$f is missing or empty; nothing was changed" >&2; return 1; }
  done
  for svc in pgbackrest pgbackrest-authentik; do
    if [[ "$svc" == pgbackrest ]]; then want="$(la8_value "$record" legacy-paddock)"; else want="$(la8_value "$record" legacy-authentik)"; fi
    la8_log "checking the newest backup of $svc in the bucket"
    got="$(la8_pg_newest "$old" "$svc")" ||
      { echo "rollback: pgbackrest info of $svc failed; nothing was changed" >&2; return 1; }
    [[ "$got" == "$want" ]] || {
      echo "rollback: the newest backup of $svc in the bucket is ${got:-none}, not the pre-upgrade backup $want; $LA8_RELEASE's restore always takes the newest one. Restore by hand (docs/operations/restore.md of $LA8_RELEASE); nothing was changed" >&2
      return 1
    }
  done
  la8_log "downloading $(la8_value "$record" legacy-openbao)"
  if ! la8_s3 "$old" get "$(la8_value "$record" legacy-openbao)" >"$work/openbao.snap.enc" || [[ ! -s "$work/openbao.snap.enc" ]]; then
    echo "rollback: cannot download $(la8_value "$record" legacy-openbao) from the backup bucket; nothing was changed" >&2
    return 1
  fi
  # A bind-mounted file is opened by the container's user; the private work directory keeps it from the host's users.
  chmod 0644 "$work/openbao.snap.enc"
  la8_compose "$old" run --rm --no-deps -T -v "$work/openbao.snap.enc:/in:ro" paddock-worker backup decrypt /in /dev/null </dev/null ||
    { echo "rollback: the OpenBao snapshot does not decrypt with $old/.secrets/backup_encryption_key; nothing was changed" >&2; return 1; }
  if [[ "$fleet" == yes ]]; then
    la8_log "downloading $(la8_value "$record" legacy-fleet)"
    if ! la8_s3 "$old" get "$(la8_value "$record" legacy-fleet)" >"$work/fleet.sql.gz.enc" || [[ ! -s "$work/fleet.sql.gz.enc" ]]; then
      echo "rollback: cannot download $(la8_value "$record" legacy-fleet) from the backup bucket; nothing was changed" >&2
      return 1
    fi
    chmod 0644 "$work/fleet.sql.gz.enc"
    la8_compose "$old" run --rm --no-deps -T -v "$work/fleet.sql.gz.enc:/in:ro" --entrypoint /bin/bash fleet-backup \
      -c "$LA8_FLEET_SCRIPT" la8-fleet check </dev/null ||
      { echo "rollback: the Fleet dump does not decrypt with $old/.secrets/backup_encryption_key; nothing was changed" >&2; return 1; }
  fi
}

# la8_volume_rm <project> <volume>: only the volumes decisions-alpha9 item 49 names reach this function.
la8_volume_rm() {
  local v="$1_$2"
  if docker volume inspect "$v" >/dev/null 2>&1; then
    la8_log "deleting volume $v"
    docker volume rm "$v" >/dev/null
  fi
}

# la8_wait <seconds> <what> <command…>: polls the command every LA8_POLL_S seconds until it succeeds.
la8_wait() {
  local deadline=$((SECONDS + $1)) what="$2"
  shift 2
  until "$@"; do
    if ((SECONDS >= deadline)); then
      echo "rollback: $what did not happen within the time limit" >&2
      return 1
    fi
    sleep "${LA8_POLL_S:-2}"
  done
}

la8_recovered() { [[ "$(la8_compose "$LA8_OLD" exec -T "$1" psql -U "$2" -d "$3" -Atc 'select pg_is_in_recovery()' </dev/null 2>/dev/null)" == f ]]; }
la8_healthy() { [[ "$(la8_compose "$LA8_OLD" ps --format '{{.Health}}' "$1" 2>/dev/null)" == healthy ]]; }
la8_unsealed() { [[ "$(openbao_status)" == *'"sealed": false'* ]]; }

# la8_bao and la8_bao_restart: bao and bao_restart of openbao-restore.sh in the old release's OpenBao container;
# BAO_TOKEN reaches the container by name only.
la8_bao() {
  local env=(-e BAO_ADDR -e BAO_CACERT)
  [[ -z "${BAO_TOKEN:-}" ]] || env+=(-e BAO_TOKEN)
  (
    export BAO_ADDR=https://127.0.0.1:8200 BAO_CACERT=/run/secrets/internal_ca_bundle
    la8_compose "$LA8_OLD" exec -T "${env[@]}" openbao bao "$@"
  )
}
la8_bao_restart() { la8_compose "$LA8_OLD" restart openbao >/dev/null; }

# la8_restore <old dir> <project> <work dir> <with fleet: yes|no> <H>: steps 3 to 6 of alpha.8's restore.md on a stack
# that is down (step 2), with the files la8_preflight downloaded; H is the highest bundle sequence read before the down
# (bundle-seq.sh; empty when unknown). The old directory's ./paddock up afterwards starts the rest (step 7 is the
# operator's check).
la8_restore() {
  local old="$1" project="$2" work="$3" fleet="$4" hw="${5:-}" v status min by
  LA8_OLD="$old"
  # Defined here, not at load time: the upgrade sources this file too and must not gain a function named bao.
  # shellcheck disable=SC2317 # called by openbao-restore.sh
  bao() { la8_bao "$@"; }
  # shellcheck disable=SC2317 # called by openbao-restore.sh
  bao_restart() { la8_bao_restart; }
  la8_log "PostgreSQL: emptying the databases' volumes (restore.md step 3)"
  la8_compose "$old" --profile paddock rm -sf postgres authentik-postgres pgbackrest pgbackrest-authentik openbao
  # The spools and the state go too: WAL that 0.1.0-alpha.9 left in a spool must never reach alpha.8's stanza, and a
  # fresh state makes pgBackRest take a full backup of the restored cluster at once.
  for v in postgres-data authentik-postgres-data pgbackrest-spool-paddock pgbackrest-spool-authentik \
    pgbackrest-state-paddock pgbackrest-state-authentik; do
    la8_volume_rm "$project" "$v"
  done
  la8_compose "$old" run --rm --no-deps -T pgbackrest restore </dev/null
  la8_compose "$old" run --rm --no-deps -T pgbackrest-authentik restore </dev/null
  la8_compose "$old" up -d --no-deps postgres authentik-postgres
  la8_log "PostgreSQL: waiting for both databases to replay the staged WAL"
  la8_wait "${LA8_RECOVERY_TIMEOUT:-1800}" "the recovery of postgres" la8_recovered postgres postgres postgres
  la8_wait "${LA8_RECOVERY_TIMEOUT:-1800}" "the recovery of authentik-postgres" la8_recovered authentik-postgres authentik authentik

  la8_log "OpenBao: the recorded snapshot into a fresh OpenBao (restore.md step 4)"
  la8_volume_rm "$project" openbao-data
  la8_compose "$old" up -d --no-deps openbao
  openbao_wait
  # Only the OpenBao whose volume was just emptied is ever initialized (decisions-alpha9 item 49).
  if [[ "$(openbao_status)" != *'"initialized": false'* ]]; then
    echo "rollback: the fresh OpenBao reports that it is initialized; it is not initialized again" >&2
    return 1
  fi
  # The plain snapshot goes from the decrypting container straight into OpenBao's: it never touches the host's disk.
  la8_compose "$old" run --rm --no-deps -T -v "$work/openbao.snap.enc:/in:ro" paddock-worker backup decrypt /in - </dev/null |
    la8_compose "$old" exec -T openbao sh -c 'cat >/tmp/snapshot'
  status=("${PIPESTATUS[@]}")
  [[ "${status[0]}" == 0 && "${status[1]}" == 0 ]] || { echo "rollback: the snapshot did not reach OpenBao" >&2; return 1; }
  openbao_restore_sealed "$work"
  rm -f "$work/init.json"
  la8_compose "$old" exec -T openbao rm -f /tmp/snapshot </dev/null
  if [[ "$(la8_value "$old/.env" PADDOCK_AUTO_UNSEAL)" == yes ]]; then
    la8_log "OpenBao: sealed; starting the automatic unseal"
    la8_compose "$old" --profile paddock up -d --no-deps paddock-unsealer
  else
    la8_log "OpenBao: sealed. Three custodians unseal it now, each in another terminal, in $old:" \
      "./paddock bao operator unseal (waiting up to $((${LA8_UNSEAL_TIMEOUT:-3600} / 60)) minutes)"
  fi
  la8_wait "${LA8_UNSEAL_TIMEOUT:-3600}" "the unseal of OpenBao" la8_unsealed
  la8_log "OpenBao: unsealed"

  if [[ "$fleet" == yes ]]; then
    la8_log "Fleet: replacing its database with the dump (restore.md step 6)"
    la8_compose "$old" up -d --no-deps fleet-mysql
    la8_wait 600 "fleet-mysql becoming healthy" la8_healthy fleet-mysql
    la8_compose "$old" run --rm --no-deps -T -v "$work/fleet.sql.gz.enc:/in:ro" --entrypoint /bin/bash fleet-backup \
      -c "$LA8_FLEET_SCRIPT" la8-fleet load </dev/null
  fi

  la8_log "Paddock: the restore commands in their binding order (restore.md step 5)"
  la8_compose "$old" up -d --no-deps authentik-server authentik-worker
  la8_compose "$old" --profile paddock up -d paddock-api paddock-gateway paddock-worker paddock-outbox-relay \
    paddock-escrow-reader paddock-revocation-issuer
  la8_compose "$old" --profile paddock stop paddock-compiler
  # Not alpha.8's fixed 1,000,000: devices may have applied a sequence that a restore on 0.1.0-alpha.9 raised already
  # (decisions-alpha9 item 68). Its binary has the same --by.
  if ! min="$(bundle_seq_stack_min la8_compose "$old")"; then
    la8_log "bundle sequence: the restored lowest is not readable; counting from 0"
    min=0
  fi
  by="$(bundle_seq_by "$hw" "$min")"
  la8_log "bundle sequence: raising every device's by $by (restored lowest $min, highest before the rollback ${hw:-unknown})"
  bundle_seq_bump "$by" la8_compose "$old" run --rm --no-deps -T paddock-worker admin bump-bundle-seq
  la8_compose "$old" --profile paddock up -d --no-deps paddock-compiler
  la8_compose "$old" run --rm --no-deps -T paddock-worker admin rebuild-cache </dev/null
  la8_compose "$old" run --rm --no-deps -T paddock-worker admin recompile --all </dev/null
  # pgBackRest starts last, not in step 3: with its fresh state it takes a full backup at once, and that newer backup
  # would make a repeated rollback after a later failure refuse (alpha.8 restores the newest backup only).
  la8_compose "$old" up -d --no-deps pgbackrest pgbackrest-authentik
}
