#!/usr/bin/env bash
# Tests of the upgrade job's helpers (deploy/bundle/ci/upgrade.sh, `make bundle-test`) without a stack: the judgement of
# ./paddock upgrade-check, the staging of the previous release's agent files, the unsealer's guard, the restore drill's
# point in time, the orphan report, the S3 endpoint's attachment, the upgrade run again after the rollback and the
# failure report (step named on stderr and as a GitHub annotation, logs collected; also after a TERM). docker, sudo and git are stubs; upgrade.sh is sourced with UPGRADE_LIB_ONLY=1, which
# stops it before the first step.
# The snippets in single quotes run in the shell that sourced upgrade.sh, which also assigns its own `work` there;
# pass and failed always succeed.
# shellcheck disable=SC2016,SC2031,SC2015
# shellcheck source-path=SCRIPTDIR
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
failures=0
pass() { echo "ok   $1"; }
failed() {
  echo "FAIL $1" >&2
  failures=$((failures + 1))
}

mkdir -p "$work/bin" "$work/prev-artifacts" "$work/w"
: >"$work/prev.tar.gz"
: >"$work/cand.tar.gz"
cat >"$work/bin/docker" <<'STUB'
#!/usr/bin/env bash
printf 'docker %s\n' "$*" >>"$STUB_LOG"
case "$*" in
  "ps -a --filter label=com.docker.compose.project=paddock-cp"*) printf '%s\n' postgres ${STUB_ORPHAN:-} paddock-api ;;
  "compose -p paddock-ci-s3 "*" ps -q backup-s3") printf '%s\n' "${STUB_S3_ID:-}" ;;
  "network inspect paddock-cp_cp "*) printf '%s \n' "${STUB_CP_MEMBERS:-}" ;;
esac
exit 0
STUB
chmod +x "$work/bin/docker"
export PATH="$work/bin:$PATH" STUB_LOG="$work/calls.log"
: >"$STUB_LOG"

# lib <command…>: runs the command in a shell that sourced upgrade.sh up to its first step.
lib() {
  (
    set -euo pipefail
    UPGRADE_LIB_ONLY=1
    # shellcheck source=upgrade.sh
    . "$here/upgrade.sh" "$work/prev.tar.gz" "$work/cand.tar.gz" --prev-agent-artifacts "$work/prev-artifacts" --work "$work/w"
    "$@"
  )
}

# --- check_upgrade ---------------------------------------------------------------------------------------------------
item() { printf '{"name":"%s","status":"%s","detail":"d"}' "$1" "$2"; }
doc() { printf '{"items":[%s],"exit":0}' "$(IFS=,; echo "$*")"; }
json="$(doc "$(item "old bundle verified" PASS)" "$(item "openbao unseal path" WARN)" "$(item "secrets" INFO)")"
if out="$(lib check_upgrade "$json" 2>&1)"; then pass "the custodians WARN passes"; else failed "custodians WARN: $out"; fi
json="$(doc "$(item "images pullable" WARN)" "$(item "disk" WARN)" "$(item "release notes" WARN)")"
if out="$(UPGRADE_CANDIDATE_UNRELEASED=1 lib check_upgrade "$json" 2>&1)"; then pass "a candidate from a tree passes the release WARNs"; else
  failed "tree WARNs: $out"
fi
if out="$(lib check_upgrade "$json" 2>&1)"; then failed "a published candidate passes the release WARNs"; elif
  [[ "$out" == *"WARN images pullable"* && "$out" == *"WARN release notes"* ]]; then pass "a published candidate names the release WARNs"; else
  failed "release WARNs: $out"
fi
# A published release whose notes announce manual steps passes that WARN; one without an Upgrade line does not.
steps='{"name":"release notes","status":"WARN","detail":"Upgrade: from 0.1.0-alpha.8: steps: BAO_TOKEN for ./paddock upgrade; Agents: supports 0.1.0-alpha.9"}'
json="$(doc "$steps" "$(item "openbao unseal path" WARN)")"
if out="$(lib check_upgrade "$json" 2>&1)"; then pass "a published release with Upgrade steps passes"; else failed "Upgrade steps: $out"; fi
json="$(doc '{"name":"release notes","status":"WARN","detail":"this bundle carries no Upgrade line: read the release notes of 0.1.0-alpha.9"}')"
if out="$(lib check_upgrade "$json" 2>&1)"; then failed "a published release without an Upgrade line passes"; elif
  [[ "$out" == *"WARN release notes"* ]]; then pass "a published release without an Upgrade line fails"; else failed "no Upgrade line: $out"; fi
json="$(doc "$steps" "$(item "images pullable" WARN)")"
if out="$(lib check_upgrade "$json" 2>&1)"; then failed "Upgrade steps excuse an image WARN"; elif
  [[ "$out" == *"WARN images pullable"* && "$out" != *"WARN release notes"* ]]; then pass "Upgrade steps excuse only the notes"; else
  failed "steps and images: $out"
fi
json="$(doc "$(item "versions adjacent" WARN)" "$(item "running stack healthy" WARN)" "$(item "server report" FAIL)")"
if out="$(UPGRADE_CANDIDATE_UNRELEASED=1 lib check_upgrade "$json" 2>&1)"; then failed "a FAIL passes"; elif
  [[ "$out" == *"upgrade-check: WARN versions adjacent WARN running stack healthy FAIL server report"* ]]; then
  pass "a skipped release, an unknown WARN and a FAIL are named"; else
  failed "FAIL: $out"
fi

for json in '' 'Error: the upgrade-check failed before its report'; do
  if out="$(UPGRADE_CANDIDATE_UNRELEASED=1 lib check_upgrade "$json" 2>&1)"; then failed "output without items passes: '$json'"; elif
    [[ "$out" == *"upgrade-check: no item in its output"* ]]; then pass "output without items fails: '${json:0:12}'"; else
    failed "no items: $out"
  fi
done

# --- prev_artifacts_staged ------------------------------------------------------------------------------------------
v=0.1.0-alpha.8
for f in "paddockd_${v}_linux_amd64" "paddock-agent_${v}_amd64.deb" "paddock-supervisor_${v}_amd64.deb" \
  "paddock-revoke_${v}_amd64-unsigned.deb" "paddockd_${v}_linux_amd64.minisig"; do echo "$f" >"$work/prev-artifacts/$f"; done
staged="$(version=$v lib prev_artifacts_staged "$work/prev-artifacts")"
got="$(find "$staged" -mindepth 1 -printf '%f\n' | LC_ALL=C sort | paste -sd' ')"
if [[ "$got" == "paddock-agent_${v}_amd64-unsigned.deb paddock-revoke_${v}_amd64-unsigned.deb paddock-supervisor_${v}_amd64-unsigned.deb paddockd_${v}_linux_amd64-unsigned" ]]; then
  pass "the published agent files are staged under the names smoke_agent_release reads"
else failed "staged: $got"; fi

# --- unsealer --------------------------------------------------------------------------------------------------------
# lib_unseal <status json>: one round of the unsealer against a stubbed cp_paddock; prints the unseal calls.
lib_unseal() {
  STATUS="$1" lib eval '
    cp_paddock() {
      if [[ "$1 $2" == "bao status" ]]; then printf "%s\n" "$STATUS"; rm -f "$W/unsealer.run"; return 2; fi
      printf "unseal %s\n" "$(cat)" >>"$W/unseal.log"
    }
    rm -f "$W/unseal.log"
    printf "{\"unseal_keys_b64\": [\n  \"s1\",\n  \"s2\",\n  \"s3\",\n  \"s4\",\n  \"s5\"\n], \"root_token\": \"r\"}\n" >"$W/init.json"
    : >"$W/unsealer.run"
    unsealer >/dev/null
    cat "$W/unseal.log" 2>/dev/null || true'
}
out="$(lib_unseal '{"initialized": true, "sealed": true, "t": 3, "n": 5}')"
if [[ "$(grep -c '^unseal ' <<<"$out")" == 3 && "$out" == *"unseal s1"* && "$out" == *"unseal s3"* && "$out" != *"unseal s4"* ]]; then
  pass "a sealed OpenBao of the first initialisation gets three shares on stdin"
else failed "sealed t=3: $out"; fi
out="$(lib_unseal '{"initialized": true, "sealed": true, "t": 1, "n": 1}')"
[[ "$out" != *unseal\ s* ]] && pass "a restore's one-share initialisation is left alone" || failed "t=1: $out"
out="$(lib_unseal '{"initialized": false, "sealed": true, "t": 0}')"
[[ "$out" != *unseal\ s* ]] && pass "an uninitialised OpenBao is left alone" || failed "uninitialised: $out"
out="$(lib_unseal '{"initialized": true, "sealed": false, "t": 3}')"
[[ "$out" != *unseal\ s* ]] && pass "an unsealed OpenBao is left alone" || failed "unsealed: $out"

# --- drill_point -----------------------------------------------------------------------------------------------------
# lib_drill <wal_max paddock> <wal_max authentik> <archived: switched|older> [<snippet>]: drill_point against stubbed
# databases (postgres switches to segment …07, authentik-postgres to …03, each archives it 5 s in the future unless
# "older") and a local target whose manifest.json was generated an hour from now; prints the SQL log, drill_at and
# set_dir. The snippet runs first (a no-op sleep).
lib_drill() {
  rm -rf "$work/w/target" "$work/w/sql.log"
  mkdir -p "$work/w/target/set1/paddock-backup"
  cat >"$work/w/target/set1/paddock-backup/manifest.json" <<JSON
{
  "generated_at": "$(date -u -d '+1 hour' +%Y-%m-%dT%H:%M:%SZ)",
  "contents": {
    "pgbackrest": {
      "stanzas": [
        {
          "name": "paddock",
          "wal_max": "$1"
        },
        {
          "name": "authentik",
          "last_full": "x",
          "wal_max": "$2"
        }
      ]
    }
  }
}
JSON
  ARCHIVED="$3" lib eval "${4:-}"'
    local_target="$W/target"
    sudo() { "$@"; }
    db_sql() {
      local seg=000000010000000000000003
      [[ "$1" != postgres ]] || seg=000000010000000000000007
      printf "%s %s %s\n" "$(date +%s.%N)" "$1" "$4" >>"$W/sql.log"
      case "$4" in
        *pg_switch_wal*) echo "$seg" ;;
        *pg_stat_archiver*)
          [[ "$ARCHIVED" == switched ]] || seg=000000010000000000000002
          echo "$seg|$(($(date +%s) + 5))" ;;
      esac
    }
    drill_point
    cat "$W/sql.log"
    echo "drill_at $drill_at"
    echo "set_dir $set_dir"'
}
seg_p=000000010000000000000007 seg_a=000000010000000000000003
if out="$(lib_drill "$seg_p" "$seg_a" switched 2>&1)"; then
  at="$(date -u -d "$(sed -n 's/^drill_at //p' <<<"$out")" +%s)"
  order="$(awk '{print $2, $3, $4}' <<<"$out" | grep -E '^(postgres|authentik-postgres) select (txid_current|pg_walfile_name)' | paste -sd,)"
  early="$(awk -v at="$at" '$4 == "txid_current()" && $1 < at + 1' <<<"$out")"
  if [[ "$order" == "postgres select txid_current(),postgres select pg_walfile_name(pg_switch_wal()),authentik-postgres select txid_current(),authentik-postgres select pg_walfile_name(pg_switch_wal())" &&
    -z "$early" && "$out" == *"set_dir $work/w/target/set1/paddock-backup"* ]]; then
    pass "the drill's point precedes both databases' commits by a second; their WAL is switched after the commit"
  else failed "drill order (at $at): $out"; fi
else failed "drill_point: $out"; fi
nosleep='sleep() { :; }; '
if out="$(lib_drill 000000010000000000000006 "$seg_a" switched "$nosleep" 2>&1)"; then failed "a set without postgres' segment is taken: $out"; elif
  [[ "$out" == *"the local target holds no backup set with the WAL past"*"paddock $seg_p"* ]]; then
  pass "a mirror set that does not hold a switched segment is not taken"
else failed "older wal_max: $out"; fi
if out="$(lib_drill "$seg_p" "$seg_a" older "$nosleep" 2>&1)"; then failed "an unarchived segment passes: $out"; elif
  [[ "$out" == *"postgres archived no WAL past"*"(segment $seg_p) within 5 minutes"* ]]; then
  pass "a switched segment the archiver has not reached fails the drill"
else failed "unarchived: $out"; fi
if out="$(lib_drill 00000002000000000000000A 00000002000000000000000B switched "$nosleep" 2>&1)"; then
  pass "a set with later segments (a later timeline) is taken"
else failed "later segments: $out"; fi

# --- orphans ---------------------------------------------------------------------------------------------------------
: >"$STUB_LOG"
set +e
out="$(GITHUB_ACTIONS=true STUB_ORPHAN=fleet-backup-upload lib eval '
  smoke_logs() { :; }
  smoke_down() { :; }
  trap finish EXIT
  step "4.3 upgrade: the release'"'"'s bootstrap and orphans"
  cp_paddock() { printf "%s\n" postgres paddock-api; }
  orphans
  echo "not failed"' 2>&1)"
rc=$?
set -e
if ((rc == 1)) && [[ "$out" == *"upgrade: orphaned containers after the upgrade: fleet-backup-upload"* &&
  "$out" == *"::error title=upgrade::step '4.3 upgrade: the release's bootstrap and orphans' failed"* &&
  "$out" != *"not failed"* ]] && ! grep -q 'docker rm' "$STUB_LOG"; then
  pass "an orphaned container fails the step that found it"
else failed "orphans (exit $rc): $out $(cat "$STUB_LOG")"; fi
if out="$(lib eval 'cp_paddock() { printf "%s\n" postgres paddock-api; }; orphans' 2>&1)" && [[ "$out" == *"no orphaned containers"* ]]; then
  pass "without orphans the step passes"
else failed "no orphans: $out"; fi

# --- rollback --------------------------------------------------------------------------------------------------------
# A key-shaped test value built at run time, so no literal key sits in the repository for the secret scanner.
key="$(printf 0123456789abcdef0123456789abcdef | base64)"
# lib_rollback <legacy: true|false> <cp|audit>: step 6 against stubbed hosts; prints the call and what it read on stdin.
lib_rollback() {
  KEY="$key" LEGACY="$1" lib eval '
    legacy=$LEGACY
    mkdir -p "$W/seed"
    printf "%s\n" "$KEY" >"$W/seed/backup.key"
    cp_paddock() { printf "cp %s stdin=[%s]\n" "$*" "$(cat)"; }
    audit_paddock() { printf "audit %s stdin=[%s]\n" "$*" "$(cat)"; }
    rollback_host '"$2"
}
out="$(lib_rollback false cp)"
if [[ "$out" == "cp rollback $work/w/prev/cp --yes stdin=[$key]" ]]; then
  pass "the control plane's rollback to a release with restore.sh gets the backup key on stdin, not on its command line"
else failed "rollback cp: $out"; fi
out="$(lib_rollback true cp)"
if [[ "$out" == "cp rollback $work/w/prev/cp --yes stdin=[]" ]]; then
  pass "the control plane's legacy rollback to 0.1.0-alpha.8 gets no key"
else failed "legacy rollback cp: $out"; fi
out="$(lib_rollback false audit)"
if [[ "$out" == "audit rollback $work/w/prev/audit --yes stdin=[]" ]]; then
  pass "the audit host's rollback, which restores nothing, gets no key"
else failed "rollback audit: $out"; fi

# --- attach_s3 -------------------------------------------------------------------------------------------------------
s3id=0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0
: >"$STUB_LOG"
if STUB_S3_ID=$s3id lib attach_s3 >/dev/null 2>&1 &&
  grep -qx "docker network connect --alias backup-s3-tls paddock-cp_cp $s3id" "$STUB_LOG"; then
  pass "the S3 endpoint is attached to a network cp without it"
else failed "attach_s3, detached: $(cat "$STUB_LOG")"; fi
: >"$STUB_LOG"
if STUB_S3_ID=$s3id STUB_CP_MEMBERS="aaaa $s3id" lib attach_s3 >/dev/null 2>&1 &&
  ! grep -q 'network connect' "$STUB_LOG"; then
  pass "an attached S3 endpoint is not attached twice"
else failed "attach_s3, attached: $(cat "$STUB_LOG")"; fi
if out="$(lib attach_s3 2>&1)"; then failed "attach_s3 without an endpoint passes: $out"; elif
  [[ "$out" == *"the CI S3 endpoint backup-s3 does not run"* ]]; then pass "a missing S3 endpoint fails"
else failed "attach_s3, no endpoint: $out"; fi

# --- upgrade_hosts ---------------------------------------------------------------------------------------------------
# The upgrade again after the rollback (step 8): the same candidate directories, the previous release's as <old dir>,
# the root token for bootstrap openbao, and the step names and log phase of that run.
out="$(lib eval '
  printf "{\"root_token\": \"s.root\"}" >"$W/init.json"
  start_unsealer() { :; }
  use_prev
  cp_paddock() { printf "cp %s %s token=%s\n" "$CP_DIR" "$*" "${BAO_TOKEN:-}"; }
  audit_paddock() { printf "audit %s %s\n" "$AUDIT_DIR" "$*"; }
  orphans() { echo orphans; }
  upgrade_hosts 8 upgrade-again
  echo "phase=$phase"' 2>&1)"
order="*8.1 upgrade-again: control plane*cp $work/w/cand/cp upgrade $work/w/prev/cp --yes token=s.root*"
order+="8.2 upgrade-again: audit host*audit $work/w/cand/audit upgrade $work/w/prev/audit --yes*"
order+="8.3 upgrade-again: the release's bootstrap and orphans*cp $work/w/cand/cp bootstrap buckets*"
order+="cp $work/w/cand/cp up*orphans*phase=upgrade-again*"
# shellcheck disable=SC2053
if [[ "$out" == $order ]]; then
  pass "the upgrade again runs from the previous release's directories into the candidate's"
else failed "upgrade_hosts: $out"; fi

# --- seq_high_water_carried ------------------------------------------------------------------------------------------
# Step 8.4 (PDK-980): the candidate's high-water file holds at least the previous release's value read before step 8.
mkdir -p "$work/w/prev/cp/bundle-seq" "$work/w/cand/cp/bundle-seq"
echo 3000005 >"$work/w/prev/cp/bundle-seq/high-water"
echo 3000007 >"$work/w/cand/cp/bundle-seq/high-water"
if out="$(lib eval 'seq_high_water_carried "$(prev_high_water)"' 2>&1)" && [[ "$out" == *"candidate 3000007, previous 3000005"* ]]; then
  pass "a candidate high-water file at or above the previous release's passes"
else failed "seq_high_water_carried, carried: $out"; fi
echo 2000003 >"$work/w/cand/cp/bundle-seq/high-water"
if out="$(lib eval 'seq_high_water_carried 3000005' 2>&1)"; then failed "a lower candidate high-water file passes: $out"; elif
  [[ "$out" == *"holds '2000003', below the previous release's 3000005"* ]]; then pass "a lower candidate high-water file fails"
else failed "seq_high_water_carried, lower: $out"; fi
rm "$work/w/cand/cp/bundle-seq/high-water"
if out="$(lib eval 'seq_high_water_carried 3000005' 2>&1)"; then failed "a missing candidate high-water file passes: $out"; else
  pass "a missing candidate high-water file fails"
fi
rm "$work/w/prev/cp/bundle-seq/high-water"
if out="$(lib eval 'seq_high_water_carried "$(prev_high_water)"' 2>&1)" && [[ "$out" == *"no high-water file in the previous"* ]]; then
  pass "without a previous high-water file (0.1.0-alpha.8) there is nothing to carry"
else failed "seq_high_water_carried, no previous file: $out"; fi

# --- failure report ----------------------------------------------------------------------------------------------------
: >"$STUB_LOG"
set +e
out="$(GITHUB_ACTIONS=true lib eval '
  smoke_logs() { echo "logs $1"; }
  smoke_down() { echo down; }
  trap finish EXIT
  step "5.2 probes: the seeded set"
  fail "GET /api/v1/managed-files/x: HTTP 404"' 2>&1)"
rc=$?
set -e
if ((rc == 1)) && [[ "$out" == *"upgrade: GET /api/v1/managed-files/x: HTTP 404"* &&
  "$out" == *"upgrade: step '5.2 probes: the seeded set' failed"* &&
  "$out" == *"::error title=upgrade::step '5.2 probes: the seeded set' failed"* && "$out" == *"logs -prev"* &&
  "$out" == *down* && "$out" == *"upgrade: failed after"* ]] && grep -q 'paddock-ci-s3 .* down --volumes' "$STUB_LOG"; then
  pass "a failing probe names its step, annotates it, collects the logs and takes everything down"
else failed "failure report (exit $rc): $out $(cat "$STUB_LOG")"; fi

# --- an interrupted run (the workflow's timeout sends TERM) ----------------------------------------------------------
: >"$STUB_LOG"
set +e
out="$(lib eval '
  smoke_logs() { echo "logs $1"; }
  smoke_down() { echo down; }
  install_traps
  step "6 restore drill: backup"
  kill -TERM "$BASHPID"
  echo "not interrupted"' 2>&1)"
rc=$?
set -e
if ((rc == 143)) && [[ "$out" == *"upgrade: step '6 restore drill: backup' failed"* && "$out" == *"logs -prev"* &&
  "$out" == *down* && "$out" == *"upgrade: failed after"* && "$out" != *"not interrupted"* ]]; then
  pass "a TERM fails the run through finish, which names the step and collects the logs"
else failed "TERM (exit $rc): $out"; fi

((failures == 0)) || { echo "upgrade-ci: $failures check(s) failed" >&2; exit 1; }
echo "upgrade-ci: all checks passed"
