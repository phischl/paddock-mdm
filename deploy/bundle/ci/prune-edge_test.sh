#!/usr/bin/env bash
# Tests of prune-edge.sh (plan M7b §6.7, `make test`): the decision per recorded package version, that a dry run
# deletes nothing, that a real run deletes exactly the expired edge versions, and that a failed delete stops with 1.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if ! command -v jq >/dev/null; then
  echo "prune-edge: skipped, jq is not installed"
  exit 0
fi
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
failures=0
check() {
  if [[ "$2" == "$3" ]]; then echo "ok   $1"; else
    echo "FAIL $1: got '$2', want '$3'"
    failures=$((failures + 1))
  fi
}

# A gh stub records every call; GH_FAIL=1 makes DELETE fail.
mkdir -p "$work/bin"
cat >"$work/bin/gh" <<'EOF'
#!/usr/bin/env bash
echo "gh $*" >>"$GH_LOG"
if [[ "$*" == *DELETE* && -n "${GH_FAIL:-}" ]]; then exit 1; fi
EOF
chmod +x "$work/bin/gh"
export GH_LOG="$work/gh.log"
prune() { PATH="$work/bin:$PATH" "$here/prune-edge.sh" --versions-json "$here/testdata/versions.json" \
  --now 2026-10-09T00:00:00Z "$@"; }

: >"$GH_LOG"
out="$(prune --dry-run paddock-server)"
decision() { awk -v id="$1" '$2 == id { print $5 " " $6 }' <<<"$out"; }
check "edge-20260801-abcdef0, 69 days old" "$(decision 101)" "delete expired"
check "edge-20261001-1234567, 8 days old" "$(decision 102)" "keep recent"
check "edge and edge-20260801-0000000 (moving tag)" "$(decision 103)" "keep tagged"
check "1.0.0, 1.0, latest" "$(decision 104)" "keep tagged"
check "edge-20260701-aaaaaaa and 1.1.0 (release)" "$(decision 105)" "keep tagged"
check "untagged, 100 days old" "$(decision 106)" "keep untagged"
check "sha256-….sig (cosign)" "$(decision 107)" "keep tagged"
check "0.1.0-alpha.1 (pre-release)" "$(decision 108)" "keep tagged"
check "line format" "$(awk '$2 == 101' <<<"$out")" "paddock-server 101 2026-08-01T00:00:00Z edge-20260801-abcdef0 delete expired"
check "the dry run calls no API" "$(wc -l <"$GH_LOG" | tr -d ' ')" 0

: >"$GH_LOG"
prune paddock-server paddock-compiler >/dev/null
check "a real run deletes the expired version of each package" "$(cat "$GH_LOG")" \
  "$(printf 'gh api -X DELETE /user/packages/container/paddock-server/versions/101 \ngh api -X DELETE /user/packages/container/paddock-compiler/versions/101 ' | sed 's/ $//')"

: >"$GH_LOG"
set +e
GH_FAIL=1 prune paddock-server >/dev/null 2>&1
rc=$?
set -e
check "a failed delete exits 1" "$rc" 1

set +e
"$here/prune-edge.sh" --dry-run other-package >/dev/null 2>&1
rc=$?
set -e
check "an unknown package is a usage error" "$rc" 2

if ((failures > 0)); then
  echo "prune-edge: $failures failure(s)"
  exit 1
fi
echo "prune-edge: all checks passed"
