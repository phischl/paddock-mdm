#!/usr/bin/env bash
# Tests of ./paddock upgrade-check (PDK-742, `make bundle-test`): the ten items against the fixture bundles under
# ci/testdata/upgrade-check/, the exit codes, the JSON form, and that the command writes nothing. docker is a stub on
# PATH; the old bundle's ./paddock is a fixture that answers verify, ps and compose.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
fixtures="$here/ci/testdata/upgrade-check"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
failures=0
pass() { echo "ok   $1"; }
fail() {
  echo "FAIL $1" >&2
  failures=$((failures + 1))
}

mkdir -p "$work/bin"
cat >"$work/bin/docker" <<'STUB'
#!/usr/bin/env bash
case "$1" in
  manifest)
    [[ -z "${FIXTURE_OFFLINE:-}" ]] || exit 1
    printf '{\n "config": {"size": 1000},\n "layers": [{"size": %s}]\n}\n' "${FIXTURE_LAYER_SIZE:-1000000}" ;;
  info) printf '%s\n' "$FIXTURE_ROOT" ;;
  *) exit 1 ;;
esac
STUB
chmod +x "$work/bin/docker"
export PATH="$work/bin:$PATH" FIXTURE_ROOT="$work" FIXTURE_COMPOSE_LOG="$work/compose.log"
unset FIXTURE_OFFLINE FIXTURE_LAYER_SIZE FIXTURE_PS FIXTURE_REPORT FIXTURE_REPORT_EXIT

# new_bundle <dir>: this bundle's fixture with the real entry script and check script.
new_bundle() {
  mkdir -p "$1"
  cp -a "$fixtures/new/." "$1/"
  mkdir -p "$1/scripts"
  cp "$here/paddock" "$1/paddock"
  cp "$here/../compose/scripts/upgrade-check.sh" "$1/scripts/upgrade-check.sh"
}
# old_bundle <dir>: a writable copy of the old fixture.
old_bundle() {
  mkdir -p "$1"
  cp -a "$fixtures/old/." "$1/"
}
tree_sum() { (cd "$1" && find . -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum | sha256sum); }

new_bundle "$work/new"
export FIXTURE_REPORT=$'upgrade check for 0.1.0-alpha.9 (agent window: 0.1.0-alpha.7, 0.1.0-alpha.8)\nPASS  migrations  ok\nWARN  agents  2 agents outside the window\nINFO  openbao  unsealed'

# run <expected exit> <name> <args…>: runs in the new directory, keeps the output in $out.
run() {
  local want="$1" name="$2" got=0
  shift 2
  out="$(cd "$work/new" && ./paddock upgrade-check "$@" 2>&1)" || got=$?
  if [[ "$got" == "$want" ]]; then pass "$name (exit $got)"; else
    fail "$name: exit $got, want $want"
    printf '%s\n' "$out" >&2
  fi
}
# has <name> <pattern>: the output of the last run has a line matching the extended regex.
has() { if grep -qE -- "$2" <<<"$out"; then pass "$1"; else
  fail "$1: no line matches '$2'"
  printf '%s\n' "$out" >&2
fi; }
hasnt() { if grep -qE -- "$2" <<<"$out"; then
  fail "$1: a line matches '$2'"
  printf '%s\n' "$out" >&2
else pass "$1"; fi; }

# The fixture directories are only read: checksums before and after (the new one including its copied scripts).
before="$(tree_sum "$fixtures/old")$(tree_sum "$work/new")"
run 1 "fixture upgrade (missing key)" "$fixtures/old"
after="$(tree_sum "$fixtures/old")$(tree_sum "$work/new")"
if [[ "$before" == "$after" ]]; then pass "the command wrote nothing into either directory"; else fail "a directory changed"; fi
[[ -z "$(find "$fixtures/old" -newer "$work/bin/docker" -type f)" ]] || fail "a file of the old fixture is newer than the test start"

has "old bundle verified PASS" '^PASS +old bundle verified'
has "versions adjacent PASS" '^PASS +versions adjacent +0.1.0-alpha.8 is the release directly before 0.1.0-alpha.9'
has "release notes PASS with the lines" '^PASS +release notes +Upgrade: from 0.1.0-alpha.8: automatic; Agents: supports'
has "env FAIL names the key and its comment" '^FAIL +env +add to .env before the upgrade: PADDOCK_SMTP_HOST \(The new mail relay of the notifier\. It must accept TLS\.\)'
hasnt "env does not list keys with a default" 'PADDOCK_LOG_LEVEL \('
has "secrets: files that cannot be generated are a FAIL" '^FAIL +secrets +files that ./paddock secrets cannot generate .*: approle/paddock-api/role_id release-production/minisign.pub'
has "secrets INFO names the generated file" '^INFO +secrets +./paddock secrets will generate: db_password'
hasnt "secrets: an overridden secret's old path is not named" 'release/minisign\.pub'
has "disk PASS" '^PASS +disk '
has "images pullable PASS" '^PASS +images pullable +2 image\(s\)'
has "server report WARN keeps the findings" '^WARN +server report +WARN +agents +2 agents outside the window'
has "unseal path WARN" '^WARN +openbao unseal path +three custodians'
has "running stack PASS" '^PASS +running stack healthy'
has "table ends with the verdict" 'upgrade check: FAIL'
# alpha.8 predates the command: the new image runs it through an override of the worker's image.
if grep -q -- "-f .* run --rm --no-deps -T --entrypoint paddock-server paddock-worker admin upgrade-check --target-version 0.1.0-alpha.9" "$work/compose.log"; then
  pass "the old alpha.8 stack is asked with the new image"
else fail "compose log: $(cat "$work/compose.log")"; fi
hasnt "no secret or setting value is printed" 'paddock.example.org|debug'

# --json: {items, exit}.
run 1 "--json" "$fixtures/old" --json
if [[ "$(head -c 10 <<<"$out")" == '{"items":[' && "$out" == *',"exit":1}' ]] &&
  grep -q '"name":"env","status":"FAIL","detail":"add to .env' <<<"$out"; then pass "--json document"; else
  fail "--json document: $out"
fi

# Old .env complete, plus an unknown key: env WARN, no FAIL left except the generated secrets (provided here).
old_bundle "$work/old2"
mkdir -p "$work/old2/.secrets/release-production" "$work/old2/.secrets/approle/paddock-api"
touch "$work/old2/.secrets/db_password" "$work/old2/.secrets/release-production/minisign.pub" \
  "$work/old2/.secrets/approle/paddock-api/role_id"
printf 'PADDOCK_SMTP_HOST=mail.example.org\nPADDOCK_REMOVED_SETTING=1\nPADDOCK_AUTO_UNSEAL=yes\n' >>"$work/old2/.env"
mkdir -p "$work/old2/.secrets/openbao"
touch "$work/old2/.secrets/openbao/auto-unseal-shares"
run 0 "complete old installation" "$work/old2"
has "unknown old key is a WARN" '^WARN +env +settings this bundle does not know .*: PADDOCK_REMOVED_SETTING'
has "secrets PASS" '^PASS +secrets '
has "auto-unseal with shares PASS" '^PASS +openbao unseal path'
has "table ends with no FAIL" 'upgrade check: no FAIL'
run 0 "--json without FAIL" "$work/old2" --json
if [[ "$out" == *',"exit":0}' ]]; then pass "--json exit 0"; else fail "--json exit: $out"; fi

# Adjacency: a two-step jump names the intermediate release; a newer or equal old version fails.
old_bundle "$work/old3"
sed -i 's/^version=.*/version=0.1.0-alpha.7/' "$work/old3/VERSION"
(cd "$work/old3" && sha256sum paddock VERSION >SHA256SUMS)
run 1 "two-step jump" "$work/old3"
has "intermediate version is named" '^FAIL +versions adjacent +0.1.0-alpha.7 to 0.1.0-alpha.9 skips releases: upgrade through 0.1.0-alpha.8 first'
sed -i 's/^version=.*/version=0.1.0-alpha.9/' "$work/old3/VERSION"
(cd "$work/old3" && sha256sum paddock VERSION >SHA256SUMS)
run 1 "same version" "$work/old3"
has "equal version fails" '^FAIL +versions adjacent +the old version 0.1.0-alpha.9 is not older'
sed -i 's/^version=.*/version=0.1.0-alpha.1/' "$work/old3/VERSION"
(cd "$work/old3" && sha256sum paddock VERSION >SHA256SUMS)
run 1 "unknown old version" "$work/old3"
has "unknown version fails" '^FAIL +versions adjacent +the old version 0.1.0-alpha.1 is not a known release'

# A modified old file: verification fails.
old_bundle "$work/old4"
echo tampered >>"$work/old4/VERSION"
run 1 "old bundle with a changed file" "$work/old4"
has "old bundle verified FAIL" '^FAIL +old bundle verified +VERSION: FAILED'

# Offline: manifests unreadable are WARNs, not FAILs. Disk: not enough space is a FAIL.
FIXTURE_OFFLINE=1 run 1 "offline" "$fixtures/old"
has "disk WARN offline" '^WARN +disk '
has "images pullable WARN offline" '^WARN +images pullable +no manifest for: .*ghcr.io/example/paddock-server'
FIXTURE_LAYER_SIZE=900000000000000 run 1 "images larger than the disk" "$work/old2"
has "disk FAIL" '^FAIL +disk +.* MiB free on .*, .* MiB needed'

# The server report: its FAIL becomes the item's FAIL; a stack that cannot answer is a WARN; a newer old release is
# asked with its own binary.
FIXTURE_REPORT_EXIT=1 FIXTURE_REPORT=$'FAIL  agents  9 agents outside the window' run 1 "server report FAIL" "$work/old2"
has "server report FAIL" '^FAIL +server report +FAIL +agents +9 agents outside the window'
FIXTURE_REPORT='no such service' FIXTURE_REPORT_EXIT=1 run 0 "stack cannot answer" "$work/old2"
has "server report WARN" '^WARN +server report +the report could not be produced \(exit 1\): no such service'
printf '0.1.0-alpha.6\n0.1.0-alpha.7\n0.1.0-alpha.8\n0.1.0-alpha.9\n0.1.0-alpha.10\n' >"$work/new/RELEASES"
sed -i 's/^version=.*/version=0.1.0-alpha.10/' "$work/new/VERSION"
sed -i 's/^version=.*/version=0.1.0-alpha.9/' "$work/old2/VERSION"
(cd "$work/old2" && sha256sum paddock VERSION >SHA256SUMS)
: >"$work/compose.log"
run 0 "release after alpha.9" "$work/old2" >/dev/null
if grep -q -- "^compose run --rm --no-deps -T paddock-worker admin upgrade-check --target-version 0.1.0-alpha.10" "$work/compose.log"; then
  pass "a later old release is asked with its own binary"
else fail "compose log: $(cat "$work/compose.log")"; fi
new_bundle "$work/new"
sed -i 's/^version=.*/version=0.1.0-alpha.8/' "$work/old2/VERSION"
(cd "$work/old2" && sha256sum paddock VERSION >SHA256SUMS)

# Stack health.
FIXTURE_PS=$'paddock-api|running|unhealthy|0\npaddock-worker|exited||2' run 0 "unhealthy stack" "$work/old2"
has "unhealthy services named" '^WARN +running stack healthy +not healthy: paddock-api \(unhealthy\) paddock-worker \(exit 2\)'

# A stopped stack is not asked: compose run would create networks and volumes first.
: >"$work/compose.log"
FIXTURE_PS='' run 0 "stopped stack" "$work/old2"
has "server report skipped" '^WARN +server report +skipped: the old stack is not running'
if [[ ! -s "$work/compose.log" ]]; then pass "no compose run against a stopped stack"; else fail "compose log: $(cat "$work/compose.log")"; fi

# The audit host has no worker and no OpenBao: both items are n/a, and nothing is asked.
old_bundle "$work/old5"
sed -i 's/^PADDOCK_HOST=.*/PADDOCK_HOST=audit/' "$work/old5/.env"
: >"$work/compose.log"
run 1 "audit host" "$work/old5"
has "server report n/a on audit" '^INFO +server report +n/a on the audit host'
has "unseal path n/a on audit" '^INFO +openbao unseal path +n/a on the audit host'
if [[ ! -s "$work/compose.log" ]]; then pass "the audit host's stack is not asked for a report"; else fail "compose log: $(cat "$work/compose.log")"; fi

# Usage: exit 2.
run 2 "no argument"
run 2 "unknown flag" "$fixtures/old" --yaml
run 2 "two directories" "$fixtures/old" "$work/old2"
run 2 "missing directory" "$work/does-not-exist"
run 2 "this directory" "$work/new"
if [[ ! -e "$work/new/.env" ]]; then pass "needs no .env in this directory"; else fail ".env appeared in the new directory"; fi

# build.sh ships what the check reads.
"$here/build.sh" --version 0.1.0-alpha.7 --channel stable --images local --out "$work/b" >/dev/null 2>&1 || true
if [[ -f "$work/b/paddock-deploy-0.1.0-alpha.7/RELEASES" ]]; then
  bd="$work/b/paddock-deploy-0.1.0-alpha.7"
  if [[ -f "$bd/scripts/upgrade-check.sh" ]]; then pass "bundle ships scripts/upgrade-check.sh"; else fail "bundle lacks scripts/upgrade-check.sh"; fi
  if [[ "$(tail -n 1 "$bd/RELEASES")" == 0.1.0-alpha.7 ]]; then pass "RELEASES ends with the stable bundle's version"; else fail "RELEASES: $(tail -n 2 "$bd/RELEASES")"; fi
  if [[ "$(head -n 1 "$bd/RELEASES")" == 0.1.0-alpha.1 ]]; then pass "RELEASES is oldest first"; else fail "RELEASES: $(head -n 1 "$bd/RELEASES")"; fi
  if [[ -f "$bd/RELEASE-NOTES" ]]; then pass "bundle ships RELEASE-NOTES (alpha.7 predates the Upgrade lines, so it is empty)"; else fail "no RELEASE-NOTES"; fi
else
  fail "build.sh produced no RELEASES file"
fi

if ((failures > 0)); then
  echo "upgrade-check: $failures check(s) failed" >&2
  exit 1
fi
echo "upgrade-check: all checks passed"
