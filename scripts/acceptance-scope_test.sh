#!/usr/bin/env bash
# Tests of acceptance-scope.sh (PDK-537, `make test`): each case is a branch of a scratch git repository that changes
# some paths since a common base commit; the script must answer `true` only for documentation-only branches and
# `false` for everything else, including every error.
set -euo pipefail

script="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/acceptance-scope.sh"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
failures=0

fail() {
  echo "FAIL $*" >&2
  failures=$((failures + 1))
}
pass() { echo "ok   $*"; }

repo="$work/repo"
git init -q -b main "$repo"
cd "$repo"
git config user.email test@example.invalid
git config user.name test
git config commit.gpgsign false
mkdir -p docs/operations docs/assets/logo changelog.d server .github/workflows
echo base >README.md
echo base >docs/operations/install.md
echo base >docs/assets/logo/logo.svg
echo base >server/main.go
echo base >server/README.md
echo base >Makefile
echo base >.github/workflows/ci.yml
git add -A
git commit -q -m base
base="$(git rev-parse HEAD)"

# branch <name> <command…>: a branch from the base commit with the command's changes committed (empty commit if none).
branch() {
  local name="$1"
  shift
  git checkout -q -b "$name" "$base"
  "$@"
  git add -A
  git commit -q --allow-empty -m "$name"
}

# expect <name> <expected> <base> <head>
expect() {
  local got
  got="$(bash "$script" "$3" "$4" 2>/dev/null)" || {
    fail "$1: exit status $?"
    return
  }
  if [ "$got" = "$2" ]; then pass "$1 -> $2"; else fail "$1: got '$got', want '$2'"; fi
}

branch docs-only sh -c 'echo x >>docs/operations/install.md; echo y >docs/operations/new.md'
branch changelog-only sh -c 'echo x >changelog.d/PDK-1.changed.md'
branch root-readme sh -c 'echo x >>README.md'
branch root-new-md sh -c 'echo x >SECURITY.md'
branch docs-and-go sh -c 'echo x >>docs/operations/install.md; echo x >>server/main.go'
branch code-dir-readme sh -c 'echo x >>server/README.md'
branch workflow sh -c 'echo x >>.github/workflows/ci.yml'
branch makefile sh -c 'echo x >>Makefile'
branch docs-assets sh -c 'echo x >>docs/assets/logo/logo.svg'
branch rename-code-to-docs git mv server/main.go docs/main.go
branch delete-code git rm -q server/main.go
branch empty true
branch docs-then-revert sh -c 'echo x >>docs/operations/install.md; git commit -qam tmp; git revert --no-edit HEAD >/dev/null'
branch odd-name sh -c 'echo x >"docs/operations/a
server.go"'

expect "docs only" true "$base" docs-only
expect "changelog fragment only" true "$base" changelog-only
expect "root README" true "$base" root-readme
expect "new top-level .md" true "$base" root-new-md
expect "file name with a newline under docs/" true "$base" odd-name
expect "docs/ plus one Go file" false "$base" docs-and-go
expect "server/README.md (code directory)" false "$base" code-dir-readme
expect ".github/workflows/ci.yml" false "$base" workflow
expect "Makefile" false "$base" makefile
expect "docs/assets/ (portal build input)" false "$base" docs-assets
expect "rename of code into docs/" false "$base" rename-code-to-docs
expect "deleted Go file" false "$base" delete-code
expect "empty diff" false "$base" empty
expect "changes that cancel out" false "$base" docs-then-revert
expect "unknown base revision" false 0000000000000000000000000000000000000000 docs-only
expect "unknown head revision" false "$base" no-such-branch

# Stale base (External Review 2): the branch adds code and removes it again, then changes docs. The tree diff shows
# documentation only, but squash-merging after main has taken the addition would remove that code from main.
branch added-reverted sh -c 'echo c >server/y.go'
git rm -q server/y.go
echo z >>docs/operations/install.md
git commit -qam "remove the code again, change docs"
if [ "$(git diff --name-only "$base...added-reverted")" = docs/operations/install.md ]; then
  pass "added-and-reverted precondition: the tree diff shows documentation only"
else
  fail "added-and-reverted precondition: the tree diff is $(git diff --name-only "$base...added-reverted" | tr '\n' ' ')"
fi
expect "code added and reverted inside the branch" false "$base" added-reverted

# A merge commit inside the branch is judged against each parent (-m): merging a code branch in counts as code.
git checkout -q -b merges-code docs-only
git merge -q --no-edit makefile >/dev/null
expect "branch that merges a code branch" false "$base" merges-code

# Criss-cross history (External Review 1): x1 adds code, x2 changes docs; main merges both. The pull request branch
# from x1 merges x2 with a resolution that drops x1's code, then changes docs. git diffs against one merge base only;
# against x2 the diff looks like documentation, yet merging the pull request into main removes the code, so two merge
# bases must mean false. x2 is the newer commit so that git picks it, and the precondition below proves it does.
branch x1 sh -c 'echo c >server/x.go'
GIT_COMMITTER_DATE="2030-01-01T00:00:00Z" branch x2 sh -c 'echo x2 >>docs/operations/install.md'
git checkout -q -b cc-main x1
git merge -q --no-edit x2
git checkout -q -b cc-pr x1
git merge -q --no-commit x2 >/dev/null 2>&1
git rm -q server/x.go
git commit -q --no-edit
echo y >>docs/operations/install.md
git commit -qam "docs on the criss-cross branch"
if [ "$(git diff --name-only cc-main...cc-pr 2>/dev/null)" = docs/operations/install.md ]; then
  pass "criss-cross precondition: the single-base diff shows documentation only"
else
  fail "criss-cross precondition: the single-base diff is $(git diff --name-only cc-main...cc-pr 2>/dev/null | tr '\n' ' ')"
fi
expect "criss-cross history with two merge bases" false cc-main cc-pr

# A base without a common ancestor: the merge base is not found.
git checkout -q --orphan unrelated
git rm -rq --cached .
git clean -fdq
echo x >README.md
git add README.md
git commit -q -m unrelated
expect "no merge base" false "$base" unrelated

# Main moved on after the branch point: only the pull request's own changes count.
git checkout -q -b main-later "$base"
echo x >>server/main.go
git commit -qam "code on main"
expect "code changed on main after the branch point" true main-later docs-only

if bash "$script" "$base" >/dev/null 2>&1; then fail "one argument is accepted"; else pass "one argument -> usage error"; fi

if [ "$failures" -gt 0 ]; then
  echo "$failures failure(s)" >&2
  exit 1
fi
echo "all acceptance-scope tests passed"
