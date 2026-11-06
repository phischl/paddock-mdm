#!/usr/bin/env bash
# The upgrade job (plan M16 decisions 10–12, ADR 0047 decision 5): N → N+1 upgrades, restores and rolls back, on one
# machine with the two Compose projects of smoke.sh (paddock-cp, paddock-audit).
#   upgrade.sh <previous tarball> <candidate tarball> --prev-agent-artifacts <dir> [--agent-artifacts <dir>]
#              [--work <dir>]
# The steps, each named in the log and on failure:
#    1  the previous release installed as smoke.sh does, with its agent artifacts (re-signed with throwaway keys);
#    2  seeded (seed.sh) with a device of the previous release's devicesim package (upgradesim built from the previous
#       tag's checkout);
#    3  ./paddock upgrade-check on both hosts: no FAIL, no WARN but the known ones;
#    4  ./paddock upgrade --yes on the control plane, then on the audit host;
#    5  probes: the hosts, the hardening, every seeded object with its ID, the audit count, the chain verification, the
#       API token, the escrowed password revealed with a step-up, the old device's check-in and events, a new device;
#    6  restore drill, backup: a confirmed backup key, the local target, ./paddock backup now --label ci --wait;
#    7  restore drill, loss and restore: ./paddock down --volumes, ./paddock secrets, ./paddock restore --from --at;
#    8  probes again;
#    9  ./paddock rollback --yes on the control plane, then on the audit host (the candidate's audit writer reads what
#       the previous control plane sends, never the other way round);
#   10  probes on the previous release: the pre-upgrade set.
# From 0.1.0-alpha.8, which backs up to S3, the previous release's bucket is the audit project's RustFS behind the CI
# project paddock-ci-s3 (compose.ci-s3.yaml, compose.ci-alpha8.yaml), and step 9 is that release's legacy restore
# (plan M16 amendment 2026-11-06), which recreates volumes and initialises a fresh OpenBao: allowed only in this
# ephemeral job (decisions-alpha9 item 49). A background unsealer gives OpenBao the shares of step 1 whenever it is
# sealed with the threshold 3 of that initialisation; it never touches an OpenBao with another seal configuration.
# Exit 0: every step passed; 1: a step failed (named on stderr, and as a GitHub annotation); 2: usage. Needs what
# smoke.sh needs, plus git with the previous tag and sudo (the local backup target below /srv/paddock-backup).
# Environment: WAIT_TIMEOUT (default 900 s per wait); UPGRADE_CANDIDATE_UNRELEASED=1 for a candidate built from a tree
# (its images are local, its release notes unwritten; check_upgrade); UPGRADE_SKIP_REVEAL=1 skips the escrow reveal while the job is
# being brought up (decisions-alpha9 item 53: on and green before a release tag). The Compose logs of both projects
# (each phase) end up in <work>/logs/.
# shellcheck source-path=SCRIPTDIR
set -euo pipefail

usage() {
  echo "usage: upgrade.sh <previous tarball> <candidate tarball> --prev-agent-artifacts <dir> [--agent-artifacts <dir>] [--work <dir>]" >&2
  exit 2
}

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/../../.." && pwd)"
prev_tarball="${1:-}" cand_tarball="${2:-}"
[[ -f "$prev_tarball" && -f "$cand_tarball" ]] || usage
shift 2
prev_artifacts='' agent_artifacts='' work=''
while (($#)); do
  case "$1" in
    --prev-agent-artifacts) prev_artifacts="${2:-}"; shift 2 || usage ;;
    --agent-artifacts) agent_artifacts="${2:-}"; shift 2 || usage ;;
    --work) work="${2:-}"; shift 2 || usage ;;
    *) usage ;;
  esac
done
[[ -d "$prev_artifacts" && (-z "$agent_artifacts" || -d "$agent_artifacts") ]] || usage
abs() { printf '%s/%s' "$(cd "$(dirname "$1")" && pwd)" "$(basename "$1")"; }
prev_tarball="$(abs "$prev_tarball")" cand_tarball="$(abs "$cand_tarball")"
W="${work:-$(mktemp -d)}"
mkdir -p "$W"
W="$(cd "$W" && pwd)"
export PADDOCK_CI_DIR="$here" WAIT_TIMEOUT="${WAIT_TIMEOUT:-900}" PADDOCK_CI_S3_CA_DIR="$W/ci-s3"
started=$SECONDS
ci_overlay="$here/compose.ci.yaml"
SMOKE_NAME=upgrade CP_DIR="$W/prev/cp" AUDIT_DIR="$W/prev/audit" CP_OVERLAY="$ci_overlay"
# shellcheck source=lib-smoke.sh
. "$here/lib-smoke.sh"
UPGRADE_LIB_ONLY="${UPGRADE_LIB_ONLY:-}"

legacy=false            # the previous release is 0.1.0-alpha.8 (its S3 bucket, its legacy rollback)
phase=prev              # whose Compose logs the next collection names
s3_project=(docker compose -p paddock-ci-s3 -f "$here/compose.ci-s3.yaml" --env-file "$repo/deploy/compose/versions.env")
export UPGRADEPROBE="$W/bin/upgradeprobe"
probe_env() {
  PADDOCK_SECRETS_DIR="$CP_DIR/.secrets" PADDOCK_TEST_ADMIN_URL=https://admin.paddock.localhost \
    PADDOCK_TEST_AUTH_URL=https://auth.paddock.localhost "$@"
}

# use_prev / use_cand: the bundle directories that cp_paddock and audit_paddock run in; both name the same projects.
use_prev() { CP_DIR="$W/prev/cp" AUDIT_DIR="$W/prev/audit"; }
use_cand() { CP_DIR="$W/cand/cp" AUDIT_DIR="$W/cand/audit"; }
# with_legacy_overlay: the overlay set while one process runs both releases' ./paddock (upgrade, rollback).
legacy_overlay() { if $legacy; then CP_OVERLAY="$ci_overlay $here/compose.ci-alpha8.yaml"; else CP_OVERLAY="$ci_overlay"; fi; }

annotate() { [[ -z "${GITHUB_ACTIONS:-}" ]] || echo "::$1 title=upgrade::$2"; }

# --- the unsealer ----------------------------------------------------------------------------------------------------

# unsealer: every 3 s, while <W>/unsealer.run exists, the three shares of <W>/init.json to an OpenBao that reports
# initialised, sealed and threshold 3. A restore's temporary one-share initialisation (threshold 1) is left alone.
unsealer() {
  local status shares share
  smoke_unseal_shares shares
  while [[ -f "$W/unsealer.run" ]]; do
    status="$(cp_paddock bao status -format=json </dev/null 2>/dev/null || true)"
    if grep -q '"initialized": *true' <<<"$status" && grep -q '"sealed": *true' <<<"$status" &&
      grep -Eq '"t": *3[,}[:space:]]' <<<"$status"; then
      echo "unsealer: OpenBao is sealed; giving it the shares of the first initialisation"
      for share in "${shares[@]}"; do printf '%s' "$share" | cp_paddock bao write sys/unseal key=- >/dev/null 2>&1 || true; done
    fi
    sleep 3
  done
}
unsealer_pid=
start_unsealer() {
  : >"$W/unsealer.run"
  (CP_DIR="$CP_DIR" CP_OVERLAY="$CP_OVERLAY" unsealer >>"$W/logs/unsealer.log" 2>&1) &
  unsealer_pid=$!
}
stop_unsealer() {
  rm -f "$W/unsealer.run"
  [[ -z "$unsealer_pid" ]] || wait "$unsealer_pid" 2>/dev/null || true
  unsealer_pid=
}

# --- teardown --------------------------------------------------------------------------------------------------------

finish() {
  local rc=$?
  set +e
  stop_unsealer
  if ((rc != 0)); then
    echo "upgrade: step '$current' failed" >&2
    annotate error "step '$current' failed (logs: the artifact upgrade-logs)"
  fi
  legacy_overlay
  smoke_logs "-$phase"
  [[ ! -f "$W/prev/cp/.env" ]] || (use_prev && smoke_logs "-prev-dir")
  "${s3_project[@]}" logs --no-color >"$W/logs/paddock-ci-s3.log" 2>&1
  smoke_down
  "${s3_project[@]}" down --volumes >/dev/null 2>&1
  [[ ! -d "$W/prev-src" ]] || git -C "$repo" worktree remove --force "$W/prev-src" >/dev/null 2>&1
  echo "upgrade: $( ((rc == 0)) && echo passed || echo failed) after $((SECONDS - started)) s (logs: $W/logs/)"
  exit "$rc"
}

# --- step helpers ----------------------------------------------------------------------------------------------------

# check_upgrade <json>: no FAIL; a WARN only for the item every run shows (custodians unseal OpenBao) and, for a
# candidate built from a tree that is no published release (UPGRADE_CANDIDATE_UNRELEASED=1: a pull request, main),
# the items that judge a published release: its notes and its images in the registry. Output without a single item
# (empty, not JSON) fails: a check that inspected nothing must not pass.
check_upgrade() {
  local json="$1" allowed=("openbao unseal path") name status bad=() items=0
  if [[ "${UPGRADE_CANDIDATE_UNRELEASED:-}" == 1 ]]; then allowed+=("release notes" "images pullable" "disk"); fi
  while IFS=$'\t' read -r name status; do
    items=$((items + 1))
    case "$status" in
      FAIL) bad+=("FAIL $name") ;;
      WARN) printf '%s\n' "${allowed[@]}" | grep -qxF "$name" || bad+=("WARN $name") ;;
    esac
  done < <(grep -o '"name":"[^"]*","status":"[A-Z]*"' <<<"$json" | sed 's/"name":"\([^"]*\)","status":"\([A-Z]*\)"/\1\t\2/')
  ((items > 0)) || fail "upgrade-check: no item in its output"
  ((${#bad[@]} == 0)) || fail "upgrade-check: ${bad[*]}"
}

# prev_artifacts_staged <dir>: the previous release's published agent files under the names smoke_agent_release
# reads (-unsigned): the published ones carry the production signature in a separate .minisig, the bytes are the same.
prev_artifacts_staged() {
  local out="$W/prev-artifacts" deb
  rm -rf "$out"
  mkdir -p "$out"
  cp "$1/paddockd_${version}_linux_amd64" "$out/paddockd_${version}_linux_amd64-unsigned"
  for deb in "$1"/*_amd64.deb; do cp "$deb" "$out/$(basename "$deb" .deb)-unsigned.deb"; done
  cp "$1"/*_amd64-unsigned.deb "$out/"
  printf '%s' "$out"
}

# orphans: containers of paddock-cp whose service the running release does not define (PDK-845: 0.1.0-alpha.8's
# fleet-backup-upload). They are reported and removed, so that the drill and the rollback act on the release's own
# services.
orphans() {
  local services found=() c svc
  services="$(cp_paddock compose --profile '*' config --services </dev/null)"
  while read -r c svc; do
    grep -qxF "$svc" <<<"$services" || found+=("$svc")
    grep -qxF "$svc" <<<"$services" || docker rm -f "$c" >/dev/null
  done < <(docker ps -a --filter label=com.docker.compose.project=paddock-cp \
    --format '{{.ID}} {{.Label "com.docker.compose.service"}}')
  if ((${#found[@]})); then
    echo "upgrade: orphaned containers of the previous release removed: ${found[*]} (PDK-845)" >&2
    annotate warning "orphaned containers after the upgrade: ${found[*]} (PDK-845)"
  else
    echo "no orphaned containers"
  fi
}

# hosts_healthy: the probes of smoke.sh step 8 on the running release.
hosts_healthy() {
  smoke_probes
  grep -qx 'paddock-notifier healthy' <<<"$(cp_paddock ps --format '{{.Service}} {{.Health}}' </dev/null)" ||
    fail "./paddock ps does not list paddock-notifier as healthy"
}

# seeded <label> [probe options]: the seeded set through the admin API (upgradeprobe probe).
seeded() {
  local label="$1"
  shift
  probe_env "$UPGRADEPROBE" probe --state "$W/seed" --label "$label" --since pre "$@"
}
# reveal: the probe option that reveals the escrowed password, unless UPGRADE_SKIP_REVEAL=1 while the job is being
# brought up (decisions-alpha9 item 53).
reveal=(--reveal "$W/seed/device.json")
if [[ "${UPGRADE_SKIP_REVEAL:-}" == 1 ]]; then reveal=(); fi
# device_checks_in <sim> <want>: the seeded device checks in, receives a newer bundle with <want> and reports it.
device_checks_in() { probe_env "$1" checkin --state "$W/seed/device.json" --want "$2"; }

# local_target: the directory the local backup target mirrors to (step 6).
local_target=/srv/paddock-backup/ci
# db_sql <service> <user> <database> <sql>: one statement through psql in the service's container, unaligned.
db_sql() { cp_paddock compose exec -T "$1" psql -U "$2" -d "$3" -Atc "$4" </dev/null; }

# archived_past <service> <user> <database> <segment> <epoch>: polls pg_stat_archiver every 5 s, at most 5 minutes,
# until the WAL segment <segment> and a later archive time than <epoch> are reached; sets archived_at (epoch).
archived_past() {
  local row wal at i
  for ((i = 0; i < 60; i++)); do
    row="$(db_sql "$1" "$2" "$3" "select coalesce(last_archived_wal, ''), coalesce(extract(epoch from last_archived_time)::bigint, 0) from pg_stat_archiver")" || row=''
    IFS='|' read -r wal at <<<"$row"
    [[ "$at" =~ ^[0-9]+$ ]] || at=0
    # The archiver works in segment order, so a later segment name means <segment> is archived too.
    if [[ ! "${wal:0:24}" < "$4" ]] && ((at > $5)); then
      archived_at=$at
      return 0
    fi
    sleep 5
  done
  return 1
}

# wal_max <manifest> <stanza>: the newest archived WAL segment manifest.json records for the stanza.
wal_max() {
  sudo cat "$1" | awk -v want="\"$2\"," '$1 == "\"name\":" { name = $2 } $1 == "\"wal_max\":" && name == want { gsub(/[",]/, "", $2); print $2 }'
}

# drill_point: the restore drill's point in time, as gate BS4 of test/system/backup_test.go does it. drill_at is taken
# first; a second later both databases commit and switch their WAL, because a recovery to a time ends with FATAL
# "recovery ended before configured recovery target was reached" unless a commit after that time reaches it. The wait
# ends once both databases have archived the switched segment after drill_at and a mirror set on the local target was
# generated after those archives and records the segments: a round lists the repository before it writes the
# manifest, so its time alone does not prove the segments are in it. Polled every 5 s, at most 10 minutes for the
# set. Sets drill_at and set_dir.
drill_point() {
  local at spec svc user db stanza seg last=0 want=() manifest generated i ok w
  drill_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  at="$(date -u -d "$drill_at" +%s)"
  sleep 1
  for spec in "postgres postgres paddock paddock" "authentik-postgres authentik authentik authentik"; do
    read -r svc user db stanza <<<"$spec"
    db_sql "$svc" "$user" "$db" 'select txid_current()' >/dev/null
    seg="$(db_sql "$svc" "$user" "$db" 'select pg_walfile_name(pg_switch_wal())')"
    archived_past "$svc" "$user" "$db" "$seg" "$at" ||
      fail "$svc archived no WAL past $drill_at (segment $seg) within 5 minutes"
    ((archived_at <= last)) || last=$archived_at
    want+=("$stanza $seg")
  done
  for ((i = 0; i < 120; i++)); do
    manifest="$(sudo find "$local_target" -maxdepth 3 -name manifest.json -path '*/paddock-backup/*' 2>/dev/null | head -1 || true)"
    generated="$(sudo sed -n 's/.*"generated_at": *"\([^"]*\)".*/\1/p' "${manifest:-/nonexistent}" 2>/dev/null | head -1 || true)"
    if [[ -n "$generated" ]] && (($(date -u -d "$generated" +%s) > last)); then
      ok=true
      for w in "${want[@]}"; do
        read -r stanza seg <<<"$w"
        if [[ "$(wal_max "$manifest" "$stanza")" < "$seg" ]]; then ok=false; fi
      done
      if $ok; then
        set_dir="$(dirname "$manifest")"
        return 0
      fi
    fi
    sleep 5
  done
  fail "the local target holds no backup set with the WAL past $drill_at (${want[*]}) within 10 minutes"
}

# install_traps: finish on every exit. A TERM (the workflow's timeout) or an INT exits non-zero through finish, which
# collects the logs; without these traps bash would run finish with the status 0 of the interrupted command and report
# a pass.
install_traps() {
  trap finish EXIT
  trap 'exit 143' TERM
  trap 'exit 130' INT
}

[[ -z "$UPGRADE_LIB_ONLY" ]] || return 0

mkdir -p "$W/logs" "$W/bin" "$PADDOCK_CI_S3_CA_DIR"
install_traps

# --- 1 previous release ------------------------------------------------------------------------------------------------
step "1.1 previous: extract and verify"
smoke_extract "$prev_tarball"
prev_version="$version"
[[ "$prev_version" != 0.1.0-alpha.8 ]] || legacy=true
echo "previous release $prev_version (legacy S3 backups: $legacy)"
step "1.2 previous: devicesim of v$prev_version"
git -C "$repo" worktree add --detach "$W/prev-src" "v$prev_version" >/dev/null
mkdir -p "$W/prev-src/test/acceptance/cmd/upgradesim"
cp "$repo/test/acceptance/cmd/upgradesim/main.go" "$W/prev-src/test/acceptance/cmd/upgradesim/"
(cd "$W/prev-src/test/acceptance" && GOTOOLCHAIN=auto go build -o "$W/bin/upgradesim-prev" ./cmd/upgradesim)
(cd "$repo/test/acceptance" && go build -o "$W/bin/upgradesim" ./cmd/upgradesim && go build -o "$UPGRADEPROBE" ./cmd/upgradeprobe)
legacy_overlay
step "1.3 previous: settings and secrets"
smoke_settings
if $legacy; then setenv "$CP_DIR/.env" PADDOCK_BACKUP_S3_ENDPOINT http://backup-s3-tls:19100; fi
smoke_secrets
if $legacy; then
  for role in pgbackrest worker fleet; do
    (umask 077 && printf '%s' "ci$(rand | head -c 16)" >"$CP_DIR/.secrets/backup_${role}_access_key" &&
      printf '%s' "$(rand)" >"$CP_DIR/.secrets/backup_${role}_secret_key")
  done
fi
step "1.4 previous: audit host"
smoke_audit_infra
if $legacy; then
  cp "$CP_DIR/.secrets"/backup_*_key "$AUDIT_DIR/.secrets/"
  PADDOCK_ENV=development SECRETS_DIR="$AUDIT_DIR/.secrets" NETWORK=paddock-audit_audit-store \
    "$W/prev-src/deploy/compose/scripts/rustfs-backup-bootstrap.sh"
  "${s3_project[@]}" up -d
  for _ in $(seq 1 60); do [[ -s "$PADDOCK_CI_S3_CA_DIR/root.crt" ]] && break; sleep 1; done
  [[ -s "$PADDOCK_CI_S3_CA_DIR/root.crt" ]] || fail "the CI S3 endpoint wrote no root certificate within 60 s"
fi
step "1.5 previous: control plane"
if $legacy; then
  # The network cp exists once a container of the project does; alpha.8's pgBackRest needs the endpoint from its start.
  cp_paddock compose create postgres
  docker network connect --alias backup-s3-tls paddock-cp_cp "$("${s3_project[@]}" ps -q backup-s3)"
fi
smoke_cp_infra
step "1.6 previous: production checks"
smoke_checks
step "1.7 previous: start both hosts"
smoke_start
step "1.8 previous: probes"
hosts_healthy
if $legacy; then
  cp_paddock compose run --rm --no-deps -T pgbackrest backup --start-fast </dev/null
  cp_paddock compose run --rm --no-deps -T pgbackrest info </dev/null | tee "$W/pgbackrest-info.txt"
  grep -q 'full backup' "$W/pgbackrest-info.txt" || fail "pgbackrest info shows no full backup in the bucket"
fi
smoke_agent_release "$(prev_artifacts_staged "$prev_artifacts")"
start_unsealer

# --- 2 seed ----------------------------------------------------------------------------------------------------------
step "2 seed"
CP_OVERLAY="$CP_OVERLAY" "$here/seed.sh" "$W" "$CP_DIR" "$W/bin/upgradesim-prev"
if ! $legacy; then probe_env "$UPGRADEPROBE" backup-key --state "$W/seed" --key-out "$W/seed/backup.key"; fi

# --- 3 upgrade-check -------------------------------------------------------------------------------------------------
step "3 upgrade-check"
use_cand
smoke_extract "$cand_tarball"
cand_version="$version"
echo "candidate $cand_version"
for host in cp audit; do
  if [[ "$host" == cp ]]; then json="$(cp_paddock upgrade-check "$W/prev/cp" --json </dev/null)" || true; else
    json="$(audit_paddock upgrade-check "$W/prev/audit" --json </dev/null)" || true
  fi
  printf '%s: %s\n' "$host" "$json"
  check_upgrade "$json"
done

# --- 4 upgrade -------------------------------------------------------------------------------------------------------
step "4.1 upgrade: control plane"
phase=upgrade
stop_unsealer
start_unsealer
# BAO_TOKEN lets the upgrade run ./paddock bootstrap openbao for the new release's policies and AppRoles.
BAO_TOKEN="$(sed -n 's/.*"root_token": *"\([^"]*\)".*/\1/p' "$W/init.json")" cp_paddock upgrade "$W/prev/cp" --yes </dev/null
step "4.2 upgrade: audit host"
audit_paddock upgrade "$W/prev/audit" --yes </dev/null
step "4.3 upgrade: the release's bootstrap and orphans"
CP_OVERLAY="$ci_overlay"
cp_paddock bootstrap buckets
cp_paddock up
orphans

# --- 5 probes --------------------------------------------------------------------------------------------------------
step "5.1 probes: hosts"
hosts_healthy
step "5.2 probes: the seeded set"
if ((${#reveal[@]} == 0)); then
  echo "upgrade: the escrow reveal is skipped (UPGRADE_SKIP_REVEAL=1); it must run before a release tag" >&2
  annotate warning "escrow reveal skipped (UPGRADE_SKIP_REVEAL=1)"
fi
seeded upgraded --touch "phase=upgraded" "${reveal[@]}"
step "5.3 probes: the device of v$prev_version"
device_checks_in "$W/bin/upgradesim-prev" "phase=upgraded"
step "5.4 probes: a device of the candidate"
probe_env "$W/bin/upgradesim" enroll --state "$W/seed/device-candidate.json" --hostname ci-upgrade-candidate \
  <"$W/seed/enroll.json"
if [[ -n "$agent_artifacts" ]]; then smoke_agent_release "$agent_artifacts"; fi

# --- 6 restore drill: backup -----------------------------------------------------------------------------------------
step "6 restore drill: backup"
probe_env "$UPGRADEPROBE" backup-key --state "$W/seed" --key-out "$W/seed/backup.key"
sudo install -d -m 0755 -o root -g root /srv/paddock-backup
sudo install -d -m 0750 -o 999 -g 999 "$local_target"
cp_paddock backup-target apply
cp_paddock up
cp_paddock backup now --label ci --wait </dev/null
drill_point

# --- 7 restore drill: loss and restore -------------------------------------------------------------------------------
step "7 restore drill: down --volumes, secrets, restore --from --at $drill_at"
# The set is root's and the backup role's; the operator restores from a copy it can read.
rm -rf "$W/drill-set"
sudo cp -a "$set_dir" "$W/drill-set"
sudo chown -R "$(id -u):$(id -g)" "$W/drill-set"
cp_paddock down --volumes </dev/null
cp_paddock secrets
# The key and the confirmation on stdin, as an operator types them: never on a command line.
{
  cat "$W/seed/backup.key"
  echo restore
} | cp_paddock restore --from "$W/drill-set" --at "$drill_at"

# --- 8 probes after the restore --------------------------------------------------------------------------------------
step "8.1 probes after the restore: hosts"
phase=restore
hosts_healthy
step "8.2 probes after the restore: the seeded set and the device"
seeded restored
device_checks_in "$W/bin/upgradesim-prev" /etc/paddock-ci/upgrade.conf

# --- 9 rollback ------------------------------------------------------------------------------------------------------
step "9.1 rollback: control plane"
phase=rollback
legacy_overlay
cp_paddock rollback "$W/prev/cp" --yes </dev/null
step "9.2 rollback: audit host"
audit_paddock rollback "$W/prev/audit" --yes </dev/null

# --- 10 probes on the previous release -------------------------------------------------------------------------------
step "10.1 previous again: hosts"
use_prev
hosts_healthy
step "10.2 previous again: the pre-upgrade set and the device"
seeded rolled-back "${reveal[@]}"
device_checks_in "$W/bin/upgradesim-prev" /etc/paddock-ci/upgrade.conf

step "done"
