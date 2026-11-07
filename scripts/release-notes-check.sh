#!/usr/bin/env bash
# Checks the CHANGELOG.md section of a release (PDK-740, `make release-check`): it must state how to upgrade and which
# agents the release supports, next to the Schema line (ADR 0047 decisions 2 and 4; docs/operations/agent-releases.md).
#
#   release-notes-check.sh <version> [--changelog FILE]
#
# The lines, as `make changelog` writes them from changelog.d/_release.md:
#   Schema: <text>
#   Upgrade: from <previous>: automatic            or      Upgrade: from <previous>: steps: <text>
#   Agents: supports <N-2>, <N-1>, <N>
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
changelog="$root/CHANGELOG.md"
version=""
while (($#)); do
  case "$1" in
    --changelog) changelog="${2-}"; shift ;;
    -*) echo "usage: $0 <version> [--changelog FILE]" >&2; exit 2 ;;
    *) version="$1" ;;
  esac
  shift
done
[[ -n "$version" ]] || { echo "usage: $0 <version> [--changelog FILE]" >&2; exit 2; }
[[ -f "$changelog" ]] || { echo "$changelog: not found" >&2; exit 1; }

section="$(awk -v h="## [$version] - " 'index($0, h) == 1 { on = 1; next } /^## / { on = 0 } on' "$changelog")"
if [[ -z "$section" ]]; then
  echo "release-notes-check: $changelog has no section '## [$version] - <date>' (run make changelog first)" >&2
  exit 1
fi

v='(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-(alpha|beta|rc)\.(0|[1-9][0-9]*))?'
errors=0
grep -qE '^Schema: .+' <<<"$section" || {
  echo "release-notes-check: section [$version] has no 'Schema: ...' line" >&2
  errors=$((errors + 1))
}
grep -qE "^Upgrade: from $v: (automatic|steps: [^[:space:]].*)$" <<<"$section" || {
  echo "release-notes-check: section [$version] has no 'Upgrade: from <previous>: automatic' or '... steps: <text>' line" >&2
  errors=$((errors + 1))
}
grep -qE "^Agents: supports $v, $v, $v$" <<<"$section" || {
  echo "release-notes-check: section [$version] has no 'Agents: supports <N-2>, <N-1>, <N>' line" >&2
  errors=$((errors + 1))
}
((errors == 0))
