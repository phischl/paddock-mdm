#!/usr/bin/env bash
# Tests of the upgrade job's helpers (deploy/bundle/ci/upgrade.sh, `make bundle-test`) without a stack: the judgement of
# ./paddock upgrade-check, the staging of the previous release's agent files, the unsealer's guard, the orphan report
# and the failure report (step named on stderr and as a GitHub annotation, logs collected). docker, sudo and git are
# stubs; upgrade.sh is sourced with UPGRADE_LIB_ONLY=1, which stops it before the first step.
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
  "ps -a --filter label=com.docker.compose.project=paddock-cp"*) printf '%s\n' "c1 postgres" "c2 fleet-backup-upload" "c3 paddock-api" ;;
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
json="$(doc "$(item "versions adjacent" WARN)" "$(item "running stack healthy" WARN)" "$(item "server report" FAIL)")"
if out="$(UPGRADE_CANDIDATE_UNRELEASED=1 lib check_upgrade "$json" 2>&1)"; then failed "a FAIL passes"; elif
  [[ "$out" == *"upgrade-check: WARN versions adjacent WARN running stack healthy FAIL server report"* ]]; then
  pass "a skipped release, an unknown WARN and a FAIL are named"; else
  failed "FAIL: $out"
fi

# --- prev_artifacts_staged ------------------------------------------------------------------------------------------
v=0.1.0-alpha.8
for f in "paddockd_${v}_linux_amd64" "paddock-agent_${v}_amd64.deb" "paddock-supervisor_${v}_amd64.deb" \
  "paddock-revoke_${v}_amd64-unsigned.deb" "paddockd_${v}_linux_amd64.minisig"; do echo "$f" >"$work/prev-artifacts/$f"; done
staged="$(version=$v lib prev_artifacts_staged "$work/prev-artifacts")"
got="$(find "$staged" -mindepth 1 -printf '%f\n' | sort | paste -sd' ')"
if [[ "$got" == "paddock-agent_${v}_amd64-unsigned.deb paddockd_${v}_linux_amd64-unsigned paddock-revoke_${v}_amd64-unsigned.deb paddock-supervisor_${v}_amd64-unsigned.deb" ]]; then
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

# --- orphans ---------------------------------------------------------------------------------------------------------
: >"$STUB_LOG"
out="$(GITHUB_ACTIONS=true lib eval 'cp_paddock() { printf "%s\n" postgres paddock-api; }; orphans' 2>&1)"
if grep -qx 'docker rm -f c2' "$STUB_LOG" && ! grep -q 'docker rm -f c[13]' "$STUB_LOG" &&
  [[ "$out" == *"orphaned containers of the previous release removed: fleet-backup-upload (PDK-845)"* &&
    "$out" == *"::warning title=upgrade::orphaned containers after the upgrade: fleet-backup-upload"* ]]; then
  pass "an orphaned container is reported, annotated and removed; the release's own are kept"
else failed "orphans: $out $(cat "$STUB_LOG")"; fi

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

((failures == 0)) || { echo "upgrade-ci: $failures check(s) failed" >&2; exit 1; }
echo "upgrade-ci: all checks passed"
