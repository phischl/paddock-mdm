#!/usr/bin/env bash
# Regression test of `make scan-secrets` (PDK-057, `make test`): in a scratch repository, a secret added only in a
# merge resolution and removed by a later commit fails the history scan, in a clean merge and in the resolution of a
# conflict alike; a clean history with merges and a range of clean merges only pass; an octopus merge, a git error
# inside the container, an unresolvable range, a range without commits or an empty non-merge commit (0 scanned)
# fails. The secret is a generated fake GitHub token that is never printed (the scan runs with --redact).
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
failures=0
r="$work/repo"

g() { git -C "$r" -c user.name=test -c user.email=test@example.invalid -c commit.gpgsign=false "$@"; }
token() { python3 -c 'import secrets,string; a=string.ascii_letters+string.digits; print("ghp_"+"".join(secrets.choice(a) for _ in range(36)))'; }

# expect <description> <want: pass|leak|fail> <log options> [<reason> [<repository>]]: runs the recipe against the
# scratch repository (or <repository>); a fail must print <reason> when one is given.
expect() {
  local desc="$1" want="$2" reason="${4:-}" repo="${5:-$r}" rc=0 out got
  out="$(make --no-print-directory -C "$root" scan-secrets GITLEAKS_REPO="$repo" GITLEAKS_LOG_OPTS="$3" 2>&1)" || rc=$?
  out="$(sed -E 's/\x1b\[[0-9;]*m//g' <<<"$out")"
  if ((rc == 0)); then got=pass; elif grep -qE 'leaks found: [1-9]' <<<"$out"; then got=leak; else got=fail; fi
  if [[ "$got" == fail && -n "$reason" ]] && ! grep -qF -- "$reason" <<<"$out"; then got="fail without '$reason'"; fi
  if [[ "$got" == "$want" ]]; then
    echo "ok   $desc ($got)"
  else
    echo "FAIL $desc: got $got, want $want"
    grep -E 'commits scanned|leaks|scan-secrets:' <<<"$out" | sed 's/^/       /'
    failures=$((failures + 1))
  fi
}

mkdir -p "$r"
git init -q -b main "$r"
printf 'one\ntwo\nthree\n' >"$r/notes.txt"
g add notes.txt
g commit -q -m base
base="$(g rev-parse HEAD)"

# A clean merge of a side branch, then the same merge with a credential file added in the merge commit only.
g switch -q -c side
printf 'side\n' >"$r/side.txt"
g add side.txt
g commit -q -m side
g switch -q main
printf 'main\n' >"$r/main.txt"
g add main.txt
g commit -q -m main
g merge -q --no-ff --no-edit side
clean="$(g rev-parse HEAD)"
g reset -q --hard HEAD~1
g merge -q --no-ff --no-commit side >/dev/null 2>&1
printf 'GITHUB_TOKEN=%s\n' "$(token)" >"$r/creds.env"
g add creds.env
g commit -q --no-edit
g rm -q creds.env
g commit -q -m 'remove the credential file'
evil_clean="$(g rev-parse HEAD)"

# A conflicting merge whose resolution adds the token, removed again by a later commit.
g switch -q -c conflict "$base"
printf 'one\nTWO from conflict\nthree\n' >"$r/notes.txt"
g commit -q -am conflict
g switch -q -c resolved "$base"
printf 'one\nTWO from resolved\nthree\n' >"$r/notes.txt"
g commit -q -am resolved
g merge -q --no-edit conflict >/dev/null 2>&1 || true
printf 'one\nTWO\nthree\ntoken=%s\n' "$(token)" >"$r/notes.txt"
g add notes.txt
g commit -q --no-edit
printf 'one\nTWO\nthree\n' >"$r/notes.txt"
g commit -q -am 'drop the token'
evil_conflict="$(g rev-parse HEAD)"

# An empty non-merge commit: gitleaks scans 0 commits although the range holds a commit that is not a merge.
g switch -q -c empty "$clean"
g commit -q --allow-empty -m empty
empty="$(g rev-parse HEAD)"
evil_merge="$(g rev-parse "$evil_clean~1")"

# An octopus merge that adds the token, removed again by a later commit: --remerge-diff shows nothing for it.
for b in x y; do
  g switch -q -c "$b" "$clean"
  printf '%s\n' "$b" >"$r/$b.txt"
  g add "$b.txt"
  g commit -q -m "$b"
done
g switch -q -c octopus "$clean"
g merge -q --no-ff --no-commit x y >/dev/null 2>&1
printf 'GITHUB_TOKEN=%s\n' "$(token)" >"$r/creds.env"
g add creds.env
g commit -q -m octopus
g rm -q creds.env
g commit -q -m 'remove the credential file'
octopus="$(g rev-parse HEAD)"
[[ "$(g rev-list --min-parents=3 --count "$clean..$octopus")" == 1 ]] || { echo "FAIL setup: no octopus merge"; exit 1; }

# A clone that borrows its objects from the scratch repository: git resolves the range on the host, but inside the
# container, where the borrowed objects are not mounted, git fails and gitleaks still exits 0 with 0 commits. The
# range of one clean merge would pass the 0-commit exception, so only the error-line check fails it.
git clone -q --shared --no-checkout "$r" "$work/borrowing"
git -C "$work/borrowing" fetch -q origin main

expect "a clean history with a merge" pass "$clean"
expect "a range of one clean merge commit" pass "$clean ^$clean^1 ^$clean^2"
expect "a range of one merge commit that adds a secret" leak "$evil_merge ^$evil_merge^1 ^$evil_merge^2"
expect "a range of one empty non-merge commit" fail "$clean..$empty"
expect "a secret added in a clean merge and removed later" leak "$evil_clean"
expect "the same, scanned as a pull request range" leak "$clean~1..$evil_clean"
expect "a secret added in a conflict resolution and removed later" leak "$evil_conflict"
expect "an octopus merge that adds a secret, removed later" fail "$clean..$octopus" "octopus merge"
expect "a git error inside the container" fail "$clean ^$clean^1 ^$clean^2" "gitleaks or git reported an error" \
  "$work/borrowing"
expect "a range git cannot resolve" fail "$base..does-not-exist" "cannot resolve"
expect "a range without commits" fail "$clean..$clean" "scanned 0 commits"

if ((failures > 0)); then
  echo "scan-secrets: $failures failure(s)"
  exit 1
fi
echo "scan-secrets: all checks passed"
