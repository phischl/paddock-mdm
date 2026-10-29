#!/usr/bin/env bash
# Tests of changelog-assemble.sh (PDK-518, `make test`): fragments of three sections merge into the existing
# [Unreleased] entries of a scratch CHANGELOG.md in a scratch git repository, the preview changes nothing, and the
# check refuses malformed fragments.
set -euo pipefail

script="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/changelog-assemble.sh"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
failures=0

fail() {
  echo "FAIL $*" >&2
  failures=$((failures + 1))
}
pass() { echo "ok   $*"; }

# same <name> <expected file> <actual file>
same() {
  if diff -u "$2" "$3" >"$work/diff"; then pass "$1"; else fail "$1:"; cat "$work/diff" >&2; fi
}

# setup <dir>: a git repository with CHANGELOG.md (existing [Unreleased] entries in Added and Fixed, one release)
# and committed fragments in Added, Changed (missing in CHANGELOG.md) and Security (missing, last).
setup() {
  mkdir -p "$1/changelog.d"
  cat >"$1/CHANGELOG.md" <<'EOF'
# Changelog

Intro.

## [Unreleased]

Entries of merged changes that are not released yet are in `changelog.d/`.

### Added

- Existing added entry, written into CHANGELOG.md by an older pull request.

### Fixed

- Existing fixed entry
  with a continuation line.

## [0.1.0] - 2026-01-01

### Added

- Released entry.
EOF
  printf '# Fragments\n' >"$1/changelog.d/README.md"
  printf -- '- Twelve.\n' >"$1/changelog.d/PDK-12.added.md"
  printf -- '- Nine,\n  continued.\n\n' >"$1/changelog.d/PDK-9.added.md"
  printf -- '- Dependency bump.\n' >"$1/changelog.d/deps-go.added.md"
  printf -- '- Changed one.\n- Changed two.\n' >"$1/changelog.d/PDK-100.changed.md"
  printf -- '- Security fix.\n' >"$1/changelog.d/PDK-3.security.md"
  git -C "$1" init -q
  git -C "$1" add -A
  git -C "$1" -c user.name=t -c user.email=t@example.org commit -qm init
}

cat >"$work/expected-section" <<'EOF'
## [Unreleased]

### Added

- Existing added entry, written into CHANGELOG.md by an older pull request.
- Nine,
  continued.
- Twelve.
- Dependency bump.

### Changed

- Changed one.
- Changed two.

### Fixed

- Existing fixed entry
  with a continuation line.

### Security

- Security fix.
EOF

cat >"$work/expected-changelog" <<'EOF'
# Changelog

Intro.

## [Unreleased]

Entries of merged changes that are not released yet are in `changelog.d/`.

## [1.2.0-rc.1] - 2026-10-29

Schema: migrations 00072–00073.

### Added

- Existing added entry, written into CHANGELOG.md by an older pull request.
- Nine,
  continued.
- Twelve.
- Dependency bump.

### Changed

- Changed one.
- Changed two.

### Fixed

- Existing fixed entry
  with a continuation line.

### Security

- Security fix.

## [0.1.0] - 2026-01-01

### Added

- Released entry.
EOF

# Preview: prints the section and touches nothing.
repo="$work/preview"
setup "$repo"
before="$(cd "$repo" && find . -path ./.git -prune -o -type f -print0 | sort -z | xargs -0 sha256sum)"
bash "$script" --preview --changelog "$repo/CHANGELOG.md" --dir "$repo/changelog.d" >"$work/preview.out"
same "preview prints the assembled section" "$work/expected-section" "$work/preview.out"
after="$(cd "$repo" && find . -path ./.git -prune -o -type f -print0 | sort -z | xargs -0 sha256sum)"
if [[ "$before" == "$after" && -z "$(git -C "$repo" status --porcelain)" ]]; then
  pass "preview leaves the files untouched"
else
  fail "preview changed files"
fi

# Release: writes the section and git rm's the fragments, README.md stays.
repo="$work/release"
setup "$repo"
bash "$script" --version 1.2.0-rc.1 --schema 'migrations 00072–00073.' --date 2026-10-29 \
  --changelog "$repo/CHANGELOG.md" --dir "$repo/changelog.d" 2>/dev/null
same "release assembles the section" "$work/expected-changelog" "$repo/CHANGELOG.md"
removed="$(printf 'D  changelog.d/%s\n' PDK-100.changed.md PDK-12.added.md PDK-3.security.md PDK-9.added.md \
  deps-go.added.md | sort)"
if [[ "$(git -C "$repo" status --porcelain -- changelog.d | sort)" == "$removed" && -f "$repo/changelog.d/README.md" ]]
then
  pass "release git rm's every fragment and keeps README.md"
else
  fail "release fragments: $(git -C "$repo" status --porcelain)"
fi
if bash "$script" --version 1.2.0-rc.1 --schema unchanged --changelog "$repo/CHANGELOG.md" \
  --dir "$repo/changelog.d" 2>"$work/err"; then
  fail "a second release of the same version was accepted"
elif grep -q 'already has a section' "$work/err"; then
  pass "refuses a version that already has a section"
else
  fail "same version: $(cat "$work/err")"
fi

# Refusals of the release mode.
repo="$work/refuse"
setup "$repo"
args=(--changelog "$repo/CHANGELOG.md" --dir "$repo/changelog.d")
cp "$repo/CHANGELOG.md" "$work/refuse.before"
for bad in "--version 1.2.0" "--schema unchanged" "--version v1.2.0 --schema unchanged" \
  "--version 1.2.0 --schema unchanged --date 29.10.2026"; do
  # shellcheck disable=SC2086 # the cases are word lists on purpose
  if bash "$script" $bad "${args[@]}" 2>/dev/null; then fail "accepted: $bad"; else pass "refuses: $bad"; fi
done
same "refusals leave CHANGELOG.md untouched" "$work/refuse.before" "$repo/CHANGELOG.md"

# Regression (review 1): [Unreleased] followed directly by a version heading, and [Unreleased] as the last section.
repo="$work/adjacent"
mkdir -p "$repo/changelog.d"
printf '# Changelog\n\n## [Unreleased]\n## [0.1.0] - 2026-01-01\n\n- Old.\n' >"$repo/CHANGELOG.md"
printf -- '- New.\n' >"$repo/changelog.d/PDK-1.added.md"
adjacent=(--changelog "$repo/CHANGELOG.md" --dir "$repo/changelog.d")
printf '## [Unreleased]\n\n### Added\n\n- New.\n' >"$work/expected-adjacent-preview"
bash "$script" --preview "${adjacent[@]}" >"$work/adjacent-preview.out"
same "preview with a version heading right after [Unreleased]" "$work/expected-adjacent-preview" \
  "$work/adjacent-preview.out"
bash "$script" --version 0.2.0 --schema unchanged --date 2026-10-29 "${adjacent[@]}" 2>/dev/null
cat >"$work/expected-adjacent" <<'EOF'
# Changelog

## [Unreleased]

Entries of merged changes that are not released yet are in `changelog.d/`.

## [0.2.0] - 2026-10-29

Schema: unchanged.

### Added

- New.

## [0.1.0] - 2026-01-01

- Old.
EOF
same "release with a version heading right after [Unreleased]" "$work/expected-adjacent" "$repo/CHANGELOG.md"

repo="$work/last"
mkdir -p "$repo/changelog.d"
printf '# Changelog\n\n## [Unreleased]\n' >"$repo/CHANGELOG.md"
printf -- '- New.\n' >"$repo/changelog.d/PDK-1.fixed.md"
bash "$script" --version 0.1.0 --schema unchanged --date 2026-10-29 --changelog "$repo/CHANGELOG.md" \
  --dir "$repo/changelog.d" 2>/dev/null
cat >"$work/expected-last" <<'EOF'
# Changelog

## [Unreleased]

Entries of merged changes that are not released yet are in `changelog.d/`.

## [0.1.0] - 2026-10-29

Schema: unchanged.

### Fixed

- New.
EOF
same "release with [Unreleased] as the last section ends without a blank line" "$work/expected-last" \
  "$repo/CHANGELOG.md"

# Check: the valid fragments pass; each malformed fragment is refused with its reason.
if bash "$script" --check "${args[@]}"; then
  pass "check accepts valid fragments"
else
  fail "check refused valid fragments"
fi
# reject <name> <file name> <content> <expected message>
reject() {
  local d="$work/check-$1"
  rm -rf "$d" && mkdir -p "$d"
  printf '%b' "$3" >"$d/$2"
  if bash "$script" --check --changelog "$repo/CHANGELOG.md" --dir "$d" 2>"$work/err"; then
    fail "check accepted $1"
  elif grep -qF -- "$4" "$work/err"; then
    pass "check refuses $1"
  else
    fail "check $1: $(cat "$work/err")"
  fi
}
reject "an unknown section" PDK-1.feature.md '- Entry.\n' "unknown section 'feature'"
reject "an upper-case section" PDK-1.Added.md '- Entry.\n' "unknown section 'Added'"
reject "an empty file" PDK-1.added.md '\n \n' 'empty'
reject "a heading" PDK-1.added.md '## [1.0.0]\n- Entry.\n' 'no headings'
reject "a subsection heading" PDK-1.added.md '### Added\n- Entry.\n' 'no headings'
reject "a line that is no bullet" PDK-1.added.md '- Entry.\nloose text\n' 'not a'
reject "a non-bullet start" PDK-1.added.md '  indented only\n' "does not start with a '- ' bullet"
reject "CRLF line endings" PDK-1.added.md '- Entry.\r\n' 'carriage returns'
reject "a bad file name" 'PDK 1.added.md' '- Entry.\n' 'name is not'
reject "a missing section" PDK-1.md '- Entry.\n' 'name is not'

if ((failures)); then
  echo "changelog-assemble_test: $failures failure(s)" >&2
  exit 1
fi
echo "changelog-assemble_test: all passed"
