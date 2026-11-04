#!/usr/bin/env bash
# Tests of release-notes-check.sh (PDK-740, `make test`): a section with the Schema, Upgrade and Agents lines passes,
# each missing or malformed line and a missing section fail with the reason.
set -euo pipefail

script="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/release-notes-check.sh"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
failures=0

fail() {
  echo "FAIL $*" >&2
  failures=$((failures + 1))
}
pass() { echo "ok   $*"; }

schema='Schema: unchanged.'
upgrade='Upgrade: from 0.1.0-alpha.8: automatic'
agents='Agents: supports 0.1.0-alpha.7, 0.1.0-alpha.8, 0.1.0-alpha.9'

# changelog <lines of the 0.1.0-alpha.9 section...>: writes a CHANGELOG.md with that section and an older one that
# has all three lines, so a check that reads the wrong section is caught.
changelog() {
  {
    printf '# Changelog\n\n## [Unreleased]\n\n## [0.1.0-alpha.9] - 2026-11-20\n\n'
    printf '%s\n' "$@"
    printf '\n### Added\n\n- Entry.\n\n## [0.1.0-alpha.8] - 2026-11-04\n\n%s\n%s\n%s\n' "$schema" "$upgrade" "$agents"
  } >"$work/CHANGELOG.md"
}

# accepts <name> <version> <lines...>
accepts() {
  local name="$1" ver="$2"
  shift 2
  changelog "$@"
  if bash "$script" "$ver" --changelog "$work/CHANGELOG.md" 2>"$work/err"; then pass "accepts $name"; else fail "$name: $(cat "$work/err")"; fi
}
# refuses <name> <expected message> <lines...>
refuses() {
  local name="$1" msg="$2"
  shift 2
  changelog "$@"
  if bash "$script" 0.1.0-alpha.9 --changelog "$work/CHANGELOG.md" 2>"$work/err"; then
    fail "accepted $name"
  elif grep -qF -- "$msg" "$work/err"; then
    pass "refuses $name"
  else
    fail "$name: $(cat "$work/err")"
  fi
}

accepts "a complete section" 0.1.0-alpha.9 "$schema" "$upgrade" "$agents"
accepts "steps" 0.1.0-alpha.9 "$schema" 'Upgrade: from 0.1.0-alpha.8: steps: run ./paddock upgrade-check first' "$agents"
refuses "a section without the Upgrade line" "'Upgrade: from" "$schema" "$agents"
refuses "a section without the Agents line" "'Agents: supports" "$schema" "$upgrade"
refuses "a section without the Schema line" "'Schema:" "$upgrade" "$agents"
refuses "an Upgrade line without automatic or steps" "'Upgrade: from" "$schema" 'Upgrade: from 0.1.0-alpha.8: soon' "$agents"
refuses "an Upgrade line with empty steps" "'Upgrade: from" "$schema" 'Upgrade: from 0.1.0-alpha.8: steps: ' "$agents"
refuses "an Agents line with two versions" "'Agents: supports" "$schema" "$upgrade" 'Agents: supports 0.1.0-alpha.8, 0.1.0-alpha.9'

changelog "$schema" "$upgrade" "$agents"
if bash "$script" 0.1.0-alpha.10 --changelog "$work/CHANGELOG.md" 2>"$work/err"; then
  fail "accepted a version without a section"
elif grep -qF "has no section" "$work/err"; then
  pass "refuses a version without a section"
else
  fail "no section: $(cat "$work/err")"
fi
# A prefix of an existing version is not that version.
if bash "$script" 0.1.0-alpha.1 --changelog "$work/CHANGELOG.md" 2>/dev/null; then
  fail "accepted a version that is a prefix of another"
else
  pass "does not match a version by prefix"
fi

if ((failures)); then
  echo "release-notes-check_test: $failures failure(s)" >&2
  exit 1
fi
echo "release-notes-check_test: all passed"
