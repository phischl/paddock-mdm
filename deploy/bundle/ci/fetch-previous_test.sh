#!/usr/bin/env bash
# Tests of previous_tag in fetch-previous.sh (`make bundle-test`): the previous release of the upgrade job is the tag
# right below the candidate in version order, or the newest tag without a candidate.
# shellcheck source-path=SCRIPTDIR
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=fetch-previous.sh
. "$here/fetch-previous.sh"
failures=0
check() {
  local want="$1" candidate="$2" got
  shift 2
  got="$(printf '%s\n' "$@" | previous_tag "$candidate" || echo "<none>")"
  if [[ "$got" == "$want" ]]; then echo "ok   ${candidate:-tree}: $got"; else
    echo "FAIL ${candidate:-tree}: got $got, want $want" >&2
    failures=$((failures + 1))
  fi
}

check v0.1.0-alpha.8 v0.1.0-alpha.9 v0.1.0-alpha.9 v0.1.0-alpha.8 v0.1.0-alpha.7
check v0.1.0-alpha.9 v0.1.0-alpha.10 v0.1.0-alpha.10 v0.1.0-alpha.9 v0.1.0-alpha.8
check v0.1.0-alpha.9 "" v0.1.0-alpha.9 v0.1.0-alpha.8
check v0.1.0-rc.1 v0.1.0 v0.1.0 v0.1.0-rc.1 v0.1.0-beta.2
check v0.1.0-alpha.8 v0.1.0-alpha.9 v0.1.0-alpha.9 vfoo v0.1.0-alpha.8
check "<none>" v0.1.0-alpha.1 v0.1.0-alpha.1
check "<none>" "" not-a-tag
# The git order the script relies on: versionsort.suffix=- puts a pre-release before its release.
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
order="$(cd "$tmp" && git init -q && git -c user.name=t -c user.email=t@t commit -q --allow-empty -m x &&
  for t in v0.1.0-alpha.9 v0.1.0-alpha.10 v0.1.0 v0.1.0-rc.1; do git tag "$t"; done &&
  git -c versionsort.suffix=- tag -l 'v*' --sort=-v:refname | paste -sd' ')"
if [[ "$order" == "v0.1.0 v0.1.0-rc.1 v0.1.0-alpha.10 v0.1.0-alpha.9" ]]; then echo "ok   git version order"; else
  echo "FAIL git version order: $order" >&2
  failures=$((failures + 1))
fi
((failures == 0)) || { echo "fetch-previous: $failures check(s) failed" >&2; exit 1; }
echo "fetch-previous: all checks passed"
