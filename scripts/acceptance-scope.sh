#!/usr/bin/env bash
# Decides whether a pull request to main changes documentation only, so CI can skip the acceptance stage for it
# (PDK-537). Prints `true` only when every path the pull request changes since the merge base of BASE and HEAD is
# documentation; prints `false` for any other path and on every error (merge base not found, unknown revision, empty
# diff, several merge bases), so a doubtful decision always runs the full stage.
#
#   acceptance-scope.sh BASE HEAD
#
# Documentation is:
#   - docs/**, except docs/assets/** (deploy/compose/Dockerfile copies docs/assets/logo/ into the portal build)
#   - changelog.d/**
#   - a *.md file in the repository root; a .md file in any other directory counts as code
# The script runs in the working directory's git repository. It always exits 0 with a usable answer, except on wrong
# usage (exit 2).
set -uo pipefail

if [ "$#" -ne 2 ] || [ -z "$1" ] || [ -z "$2" ]; then
  echo "usage: $0 BASE HEAD" >&2
  exit 2
fi

full() {
  echo "acceptance-scope: $1; running the full acceptance stage" >&2
  echo false
  exit 0
}

# With several merge bases (criss-cross history) git diffs against one of them only, which can hide a code change;
# an ambiguous base is a doubtful decision.
bases="$(git merge-base --all "$1" "$2" 2>/dev/null)" || full "no merge base of $1 and $2"
[ "$(printf '%s\n' "$bases" | wc -l)" -eq 1 ] || full "$1 and $2 have several merge bases"

list="$(mktemp)" || full "no temporary file"
trap 'rm -f "$list"' EXIT

# check <what>: every NUL-separated path in $list must be documentation; sets count to how many there were. Runs in
# this shell, not a subshell, so full ends the script.
check() {
  local path
  count=0
  while IFS= read -r -d '' path; do
    [ -n "$path" ] || continue
    count=$((count + 1))
    case "$path" in
      docs/assets/*) full "$path ($1) is not documentation" ;;
      docs/* | changelog.d/*) ;;
      */*) full "$path ($1) is not documentation" ;;
      *.md) ;;
      *) full "$path ($1) is not documentation" ;;
    esac
  done <"$list"
}

# --no-renames lists both sides of a rename, so moving code into docs/ is not mistaken for a documentation change;
# -z keeps unusual file names unquoted and unambiguous.
git diff -z --no-renames --name-only "$1...$2" >"$list" 2>/dev/null || full "no diff between $1 and $2"
check diff
files="$count"
[ "$files" -gt 0 ] || full "the diff between $1 and $2 is empty"

# The tree diff is valid only for the base it was computed on: code added and removed again inside the branch
# leaves no trace in it, yet squash-merging after main has taken the addition would remove that code from main
# (External Review 2). So every commit of the branch, merges against each parent (-m), must touch documentation only.
git log -m -z --no-renames --name-only --format= "$1..$2" >"$list" 2>/dev/null || full "no log between $1 and $2"
check commit

echo "acceptance-scope: $files documentation file(s) only; skipping the acceptance stage" >&2
echo true
