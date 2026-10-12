#!/usr/bin/env bash
# Regression test of `make scan-secrets` (PDK-057, `make test`): in a scratch repository, a secret added only in a
# merge resolution and removed by a later commit fails the history scan, in a clean merge and in the resolution of a
# conflict alike; a clean history with merges and a range of clean merges only pass; an octopus merge, a git error
# inside the container, an unresolvable range, a range without commits or an empty non-merge commit (0 scanned)
# fails. Both scans take the configuration from GITLEAKS_CONFIG_REF (PDK-065): a pull request that adds a secret and
# loosens .gitleaks.toml or .gitleaksignore in the same range still fails `make scan-secrets` and
# `make scan-secrets-diff` with the merge base's configuration, while a pull request that only changes the
# configuration passes. An inline `gitleaks:allow` on the secret does not hide it, and a configuration that extends
# another file (`[extend] path`) fails. `make scan-secrets-diff` also scans every blob the range adds (PDK-068): a
# binary file with a secret that the pull request adds and removes again fails it, in a later version of a path as
# well. Both scans run a generated configuration, gitleaks' default without the paths of its global allowlist
# (ADR 0026): a text secret in `src/bootstrap.js`, `d.png/creds.bin` or `javascript.json` fails both scans under its
# own path, and so do `creds.bin`, `creds.png`, `creds.BIN`, `creds.xdll` and the directory `assets.png/` in
# `make scan-secrets-diff`; a base configuration without an `[extend]` table still gets the default rules, one outside
# the parsed whitelist fails both scans before gitleaks runs; a default configuration that does not match its pins
# (sha256 off by one digit, header missing or not unique), whose strip leaves global paths or no rules, or whose
# generated configuration misses the canary fails. Archives are opened one level deep (ADR 0025): a secret inside a
# deflated `creds.zip`, `creds.docx` or `creds.tgz` fails `make scan-secrets-diff`, an archive copy that would
# overwrite another changed file fails it, and a real binary PNG passes with the repository's own configuration. The
# secret is a generated fake GitHub token that is never printed (the scan runs with --redact).
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
# Most cases share a base configuration, and the Go pattern check, the copy of gitleaks and the canary each took
# seconds per case; their results depend only on their inputs, so this run keeps them in its own cache (PDK-072).
# A case with other inputs still runs them, and a failing check is never kept.
export GITLEAKS_TEST_CACHE="$work/cache"
mkdir "$GITLEAKS_TEST_CACHE"
failures=0
r="$work/repo"

g() { git -C "$r" -c user.name=test -c user.email=test@example.invalid -c commit.gpgsign=false "$@"; }
token() { python3 -c 'import secrets,string; a=string.ascii_letters+string.digits; print("ghp_"+"".join(secrets.choice(a) for _ in range(36)))'; }

# verdict <description> <want: pass|leak|fail> <reason> <exit code> <output>: a fail must print <reason> when one is
# given.
verdict() {
  local desc="$1" want="$2" reason="$3" rc="$4" out got
  out="$(sed -E 's/\x1b\[[0-9;]*m//g' <<<"$5")"
  if ((rc == 0)); then got=pass; elif grep -qE 'leaks found: [1-9]' <<<"$out"; then got=leak; else got=fail; fi
  if [[ "$got" == fail && -n "$reason" ]] && ! grep -qF -- "$reason" <<<"$out"; then got="fail without '$reason'"; fi
  if [[ "$got" == "$want" ]]; then
    echo "ok   $desc ($got)"
  else
    echo "FAIL $desc: got $got, want $want"
    grep -E 'commits scanned|leaks|scan-secrets' <<<"$out" | sed 's/^/       /'
    failures=$((failures + 1))
  fi
}

# expect <description> <want> <log options> [<reason> [<repository>]]: runs `make scan-secrets` against the scratch
# repository (or <repository>) with the configuration of its working tree.
expect() {
  local rc=0 out
  out="$(make --no-print-directory -C "$root" scan-secrets GITLEAKS_REPO="${5:-$r}" GITLEAKS_LOG_OPTS="$3" 2>&1)" || rc=$?
  verdict "$1" "$2" "${4:-}" "$rc" "$out"
}

# expect_pr <description> <want> <target> <merge base> [<config ref> [<reason>]]: runs <target> (scan-secrets or
# scan-secrets-diff) over the checked-out branch as a pull request from <merge base>, with the configuration from
# <config ref> (empty: the working tree); a fail must print <reason> when one is given. Further make arguments come
# from the array make_args; the output stays in last_out.
make_args=()
last_out=
expect_pr() {
  local rc=0 out
  out="$(make --no-print-directory -C "$root" "$3" GITLEAKS_REPO="$r" GITLEAKS_LOG_OPTS="$4..HEAD" \
    GITLEAKS_DIFF_BASE="$4" GITLEAKS_CONFIG_REF="${5:-}" "${make_args[@]}" 2>&1)" || rc=$?
  last_out="$out"
  verdict "$1 ($3)" "$2" "${6:-}" "$rc" "$out"
}

mkdir -p "$r"
git init -q -b main "$r"
printf 'one\ntwo\nthree\n' >"$r/notes.txt"
printf '[extend]\nuseDefault = true\n' >"$r/.gitleaks.toml"
g add notes.txt .gitleaks.toml
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
git clone -q --shared "$r" "$work/borrowing"

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

# Pull requests from $base that add a secret and, in the same range, loosen the scan: an allowlist matching the
# secret's file, or a .gitleaksignore with its fingerprints (git mode: commit:path:rule:line, dir mode:
# path:rule:line). Without the merge base's configuration both scans pass, which shows each loosening works.
g switch -q -c pr-allowlist "$base"
printf 'GITHUB_TOKEN=%s\n' "$(token)" >"$r/creds.env"
g add creds.env
g commit -q -m 'add credentials'
cat >>"$r/.gitleaks.toml" <<'EOF'

[[allowlists]]
description = "added by the pull request that adds the secret"
paths = ['''^(b/)?creds\.env$''']
EOF
g commit -q -am 'allowlist the credentials'
for target in scan-secrets scan-secrets-diff; do
  expect_pr "a secret allowlisted in the same pull request, base configuration" leak "$target" "$base" "$base"
  expect_pr "the same with the pull request's own configuration" pass "$target" "$base"
done

g switch -q -c pr-ignore "$base"
printf 'GITHUB_TOKEN=%s\n' "$(token)" >"$r/creds.env"
g add creds.env
g commit -q -m 'add credentials'
printf '%s:creds.env:github-pat:1\ncreds.env:github-pat:1\n' "$(g rev-parse HEAD)" >"$r/.gitleaksignore"
g add .gitleaksignore
g commit -q -m 'ignore the credentials'
for target in scan-secrets scan-secrets-diff; do
  expect_pr "a secret ignored in the same pull request, base configuration" leak "$target" "$base" "$base"
  expect_pr "the same with the pull request's own configuration" pass "$target" "$base"
done

# A pull request that only changes the configuration is scanned with the base's and passes.
g switch -q -c pr-config "$base"
cat >>"$r/.gitleaks.toml" <<'EOF'

[[allowlists]]
description = "a legitimate allowlist change"
paths = ['''^generated/''']
EOF
g commit -q -am 'allowlist generated files'
for target in scan-secrets scan-secrets-diff; do
  expect_pr "a pull request that only changes the configuration" pass "$target" "$base" "$base"
done

# A fingerprint in the base's .gitleaksignore keeps applying to a pull request that changes the ignored file.
g switch -q -c ignored-base "$base"
printf 'GITHUB_TOKEN=%s\n' "$(token)" >"$r/creds.env"
printf 'creds.env:github-pat:1\n' >"$r/.gitleaksignore"
g add creds.env .gitleaksignore
g commit -q -m 'add ignored credentials'
ignored="$(g rev-parse HEAD)"
g switch -q -c pr-on-ignored
printf 'OTHER=1\n' >>"$r/creds.env"
g commit -q -am 'extend the ignored file'
expect_pr "a pull request on a file the base's .gitleaksignore covers" pass scan-secrets-diff "$ignored" "$ignored"

# A secret the pull request marks with an inline allow comment.
g switch -q -c pr-inline-allow "$base"
printf 'GITHUB_TOKEN=%s # gitleaks:allow\n' "$(token)" >"$r/creds.env"
g add creds.env
g commit -q -m 'add allowed credentials'
for target in scan-secrets scan-secrets-diff; do
  expect_pr "a secret with an inline gitleaks:allow" leak "$target" "$base" "$base"
done

# A binary file with a secret that the pull request adds and removes again, then an unrelated edit (PDK-068): the
# history scan skips binary patches and the final tree no longer holds the file, so only the scan of every added blob
# sees it. Two versions of one path land in separate blob layers, and both are scanned.
g switch -q -c pr-binary "$base"
{ printf 'GITHUB_TOKEN=%s\n' "$(token)"; printf '\0\1\2'; } >"$r/creds.env"
g add creds.env
g commit -q -m 'add binary credentials'
g rm -q creds.env
g commit -q -m 'remove the binary credentials'
printf 'four\n' >>"$r/notes.txt"
g commit -q -am 'an unrelated edit'
expect_pr "a binary secret added and removed in the pull request" leak scan-secrets-diff "$base" "$base"
g switch -q -c pr-binary-versions "$base"
{ printf 'harmless\n'; printf '\0'; } >"$r/key.dat"
g add key.dat
g commit -q -m 'add a binary file'
{ printf 'GITHUB_TOKEN=%s\n' "$(token)"; printf '\0'; } >"$r/key.dat"
g commit -q -am 'put credentials into the binary file'
{ printf 'harmless again\n'; printf '\0'; } >"$r/key.dat"
g commit -q -am 'remove the credentials'
expect_pr "a binary secret in an intermediate version of a path" leak scan-secrets-diff "$base" "$base"

# The same under a path with a newline and a space, and under a path that a later commit turns into a directory.
g switch -q -c pr-binary-paths "$base"
{ printf 'GITHUB_TOKEN=%s\n' "$(token)"; printf '\0'; } >"$r/odd"$'\n'"name .env"
{ printf 'GITHUB_TOKEN=%s\n' "$(token)"; printf '\0'; } >"$r/cfg"
g add -A
g commit -q -m 'add binary credentials under odd paths'
g rm -q cfg "odd"$'\n'"name .env"
mkdir "$r/cfg"
printf 'harmless\n' >"$r/cfg/a.env"
g add cfg
g commit -q -m 'replace them with a directory'
expect_pr "binary secrets under a newline path and a path that becomes a directory" leak scan-secrets-diff "$base" \
  "$base"

# A text secret under an extension that gitleaks' default global allowlist skips, which the generated configuration
# drops (ADR 0026): added and removed again, so only a blob layer holds it, and added and kept, so layer 0 holds it as
# well.
g switch -q -c pr-allowlisted-ext "$base"
printf 'GITHUB_TOKEN=%s\n' "$(token)" >"$r/creds.bin"
g add creds.bin
g commit -q -m 'add credentials under .bin'
g rm -q creds.bin
g commit -q -m 'remove them'
expect_pr "a text secret in creds.bin added and removed" leak scan-secrets-diff "$base" "$base"
g switch -q -c pr-allowlisted-ext-kept "$base"
printf 'GITHUB_TOKEN=%s\n' "$(token)" >"$r/creds.png"
g add creds.png
g commit -q -m 'add credentials under .png'
expect_pr "a text secret in creds.png added and kept" leak scan-secrets-diff "$base" "$base"

# The default global allowlist also skips whole directories by extension, ignores case, and its `.dll` has an
# unescaped dot.
g switch -q -c pr-allowlisted-dir "$base"
mkdir "$r/assets.png"
printf 'GITHUB_TOKEN=%s\n' "$(token)" >"$r/assets.png/creds.bin"
g add assets.png
g commit -q -m 'add credentials under an allowlisted directory'
expect_pr "a text secret in assets.png/creds.bin added and kept" leak scan-secrets-diff "$base" "$base"
g rm -q assets.png/creds.bin
g commit -q -m 'remove them'
expect_pr "a text secret in assets.png/creds.bin added and removed" leak scan-secrets-diff "$base" "$base"
for name in creds.BIN creds.xdll; do
  g switch -q -c "pr-ext-$name" "$base"
  printf 'GITHUB_TOKEN=%s\n' "$(token)" >"$r/$name"
  g add "$name"
  g commit -q -m "add credentials in $name"
  expect_pr "a text secret in $name added and kept" leak scan-secrets-diff "$base" "$base"
done

# Names the default global allowlist skips in every scan mode, which no rename could reach (PDK-074): each fails both
# scans. A fingerprint on the file's own path then hides it, so the finding is reported under that path and the file
# was not scanned under another name.
for name in src/bootstrap.js d.png/creds.bin javascript.json; do
  g switch -q -c "pr-default-path-${name//\//-}" "$base"
  mkdir -p "$r/$(dirname "$name")"
  printf 'GITHUB_TOKEN=%s\n' "$(token)" >"$r/$name"
  g add "$name"
  g commit -q -m "add credentials in $name"
  printf '%s:%s:github-pat:1\n%s:github-pat:1\n' "$(g rev-parse HEAD)" "$name" "$name" >"$r/.gitleaksignore"
  for target in scan-secrets scan-secrets-diff; do
    expect_pr "a text secret in $name added and kept" leak "$target" "$base" "$base"
    expect_pr "the same with a fingerprint on $name" pass "$target" "$base"
  done
  rm -- "$r/.gitleaksignore"
done

# A base configuration without an [extend] table: the generated configuration still holds the default rules.
g switch -q -c no-extend "$base"
cat >"$r/.gitleaks.toml" <<'EOF'
[[allowlists]]
description = "an unrelated file"
paths = ['''^unrelated\.txt$''']
EOF
g commit -q -am 'a configuration without [extend]'
no_extend="$(g rev-parse HEAD)"
printf 'GITHUB_TOKEN=%s\n' "$(token)" >"$r/creds.env"
g add creds.env
g commit -q -m 'add credentials'
for target in scan-secrets scan-secrets-diff; do
  expect_pr "a secret with a base configuration without [extend]" leak "$target" "$no_extend" "$no_extend"
done

# The default configuration extracted from the image must match its pins in versions.env: a sha256 off by one hex
# digit, a header line the binary does not hold, and one it holds many times each fail, naming the pins.
g switch -q -c pr-pins "$base"
printf 'harmless\n' >"$r/pins.txt"
g add pins.txt
g commit -q -m 'a harmless change'
pin="$(sed -n 's/^GITLEAKS_DEFAULT_CONFIG_SHA256=//p' "$root/deploy/compose/versions.env")"
last="${pin: -1}"
if [[ "$last" == 0 ]]; then wrong="${pin%?}1"; else wrong="${pin%?}0"; fi
pins="GITLEAKS_DEFAULT_CONFIG_BYTES and GITLEAKS_DEFAULT_CONFIG_SHA256"
for kind in sha header headers; do
  case $kind in
    sha) make_args=("GITLEAKS_DEFAULT_CONFIG_SHA256=$wrong") reason="does not match $pins" ;;
    header) make_args=("GITLEAKS_DEFAULT_CONFIG_HEADER=This file has been auto-generated. Do not edit it manually.")
      reason="occurs 0 times" ;;
    headers) make_args=("GITLEAKS_DEFAULT_CONFIG_HEADER=[[rules]]") reason="not once; check $pins" ;;
  esac
  for target in scan-secrets scan-secrets-diff; do
    expect_pr "a default configuration that does not match its pins ($kind)" fail "$target" "$base" "$base" \
      "$reason"
    if ! grep -qF -- "$pins" <<<"$last_out"; then
      echo "FAIL a default configuration that does not match its pins ($kind, $target): the pins are not named"
      failures=$((failures + 1))
    fi
  done
done
make_args=()

# A secret in a deflated archive, added and removed again: a zip, and an office document that gitleaks only opens
# under the suffix .zip. The token must not appear in clear text in the archive, or the test would prove nothing.
for name in creds.zip creds.docx; do
  g switch -q -c "pr-archive-$name" "$base"
  T="$(token)" python3 -c 'import os, sys, zipfile
with zipfile.ZipFile(sys.argv[1], "w", zipfile.ZIP_DEFLATED) as z:
    z.writestr("inner.env", "GITHUB_TOKEN=" + os.environ["T"] + "\n")' "$r/$name"
  if grep -qa ghp_ "$r/$name"; then echo "FAIL setup: $name holds the token in clear text"; exit 1; fi
  g add "$name"
  g commit -q -m "add credentials in $name"
  g rm -q "$name"
  g commit -q -m "remove $name"
  expect_pr "a secret inside a deflated $name added and removed" leak scan-secrets-diff "$base" "$base"
done

# A changed file whose archive copy would overwrite another changed file fails instead of hiding one of them.
g switch -q -c pr-archive-collision "$base"
printf 'harmless\n' >"$r/creds.docx"
printf 'harmless too\n' >"$r/creds.docx.zip"
g add creds.docx creds.docx.zip
g commit -q -m 'add a file and its archive name'
expect_pr "creds.docx and creds.docx.zip in the final tree" fail scan-secrets-diff "$base" "$base" \
  "cannot write a changed file"

# A gzipped tar under .tgz, which gitleaks opens only under the suffix .tar.gz.
g switch -q -c pr-archive-tgz "$base"
T="$(token)" python3 -c 'import io, os, sys, tarfile
data = ("GITHUB_TOKEN=" + os.environ["T"] + "\n").encode()
info = tarfile.TarInfo("inner.env")
info.size = len(data)
with tarfile.open(sys.argv[1], "w:gz") as t:
    t.addfile(info, io.BytesIO(data))' "$r/creds.tgz"
if grep -qa ghp_ "$r/creds.tgz"; then echo "FAIL setup: creds.tgz holds the token in clear text"; exit 1; fi
g add creds.tgz
g commit -q -m 'add credentials in creds.tgz'
g rm -q creds.tgz
g commit -q -m 'remove creds.tgz'
expect_pr "a secret inside creds.tgz added and removed" leak scan-secrets-diff "$base" "$base"

# A real binary PNG (magic bytes and seeded random bytes) passes with the repository's own configuration: scanning
# it by content adds no false positive.
g switch -q -c pr-real-png "$base"
cp "$root/.gitleaks.toml" "$r/.gitleaks.toml"
g commit -q -am 'the repository configuration'
repo_config="$(g rev-parse HEAD)"
python3 -c 'import random, sys
open(sys.argv[1], "wb").write(b"\x89PNG\r\n\x1a\n" + random.Random(69).randbytes(65536))' "$r/icon.png"
g add icon.png
g commit -q -m 'add an image'
expect_pr "a real binary PNG with the repository configuration" pass scan-secrets-diff "$repo_config" \
  "$repo_config"

# A file over GITLEAKS_MAX_MB fails the scan instead of being skipped (the limit is lowered to 1 MB here).
g switch -q -c pr-large "$base"
head -c 1000001 /dev/zero | tr '\0' a >"$r/large.txt"
g add large.txt
g commit -q -m 'add a large file'
rc=0
out="$(make --no-print-directory -C "$root" scan-secrets-diff GITLEAKS_REPO="$r" GITLEAKS_DIFF_BASE="$base" \
  GITLEAKS_CONFIG_REF="$base" GITLEAKS_MAX_MB=1 2>&1)" || rc=$?
verdict "a file over GITLEAKS_MAX_MB (scan-secrets-diff)" fail "cannot be scanned" "$rc" "$out"

# The generated child is written by a parser from a closed whitelist of the base configuration (ADR 0026, amendment
# 2026-10-12): anything outside it fails before gitleaks reads pull request content. Each case's base configuration
# guards a pull request that adds a token under gen/. Refused: an [extend] that extends another file or holds anything
# but useDefault = true (path as a key and as a dotted key, disabledRules, url, a subtable), the same names in any
# case, quoted or escaped ([Extend], Extend.disabledRules, "EXTEND".path, ["\u0065xtend"]), a byte-order mark, a
# second [extend] header, an unknown top-level key (the second review's stopwords probe, rules), a wrong type, and
# allowlists that act differently than they read (the third review): a pattern that is empty or matches the empty
# string in Go's regexp (also \B and optional POSIX classes), alone or scoped by targetRules (a hidden disabledRules),
# an empty pattern list, a pattern Go's regexp cannot compile (a lookahead), and stopwords, which gitleaks matches as
# case-insensitive substrings of the secret, and an AND allowlist with paths but no or empty targetRules (with regexes,
# paths only, with commits; ADR 0027), whose path alone makes gitleaks' directory scan skip the whole file.
# The first review's probe now fails for its stopwords. Accepted: \pL, valid in RE2, a multi-line basic string and an
# AND allowlist scoped to generic-api-key, whose allowlists then apply exactly as written (none covers the gen/
# token), so both scans find the token.
config_case() {
  case $1 in
    extend-path) printf '[extend] # the default rules and more\nuseDefault = true\n"path" = "extra.toml"\n' ;;
    extend-path-dotted) printf 'extend.path = "extra.toml"\n' ;;
    disabled-rules) printf '[extend]\nuseDefault = true\ndisabledRules = ["github-pat"]\n' ;;
    url) printf '[extend]\nuseDefault = true\nurl = "https://example.invalid/gitleaks.toml"\n' ;;
    subtable) printf '[extend]\nuseDefault = true\n\n[extend.more]\nx = 1\n' ;;
    use-default-false) printf '[extend]\nuseDefault = false\n' ;;
    upper-table) printf '[Extend]\ndisabledRules = ["github-pat"]\n' ;;
    upper-dotted) printf 'Extend.disabledRules = ["github-pat"]\n' ;;
    upper-quoted-path) printf '"EXTEND".path = "extra.toml"\n' ;;
    all-caps) printf '[EXTEND]\nuseDefault = true\ndisabledRules = ["github-pat"]\n' ;;
    escaped) printf '["\\u0065xtend"]\nuseDefault = true\ndisabledRules = ["github-pat"]\n' ;;
    bom) printf '\xef\xbb\xbf[extend]\nuseDefault = true\ndisabledRules = ["github-pat"]\n' ;;
    second-extend)
      printf '[extend]\nuseDefault = true\n\n[[allowlists]]\npaths = [%s]\n\n  [ "extend" ]  # again\n' "'^nothing$'" ;;
    stopwords-probe)
      cat <<'EOF'
stopwords = ["'''", '''
[extend]
[x]
''', "'''"]
EOF
      ;;
    unknown-key) printf '[extend]\nuseDefault = true\n\n[[rules]]\nid = "x"\nregex = %s\n' "'''x'''" ;;
    wrong-type) printf '[extend]\nuseDefault = true\n\n[[allowlists]]\npaths = %s\n' "'''^gen/'''" ;;
    empty-path-scoped)
      printf '[extend]\nuseDefault = true\n\n[[allowlists]]\ndescription = "scoped"\n'
      printf 'targetRules = ["aws-access-token", "generic-api-key"]\npaths = [""]\n' ;;
    empty-regex-scoped)
      printf '[extend]\nuseDefault = true\n\n[[allowlists]]\ntargetRules = ["generic-api-key"]\nregexes = [""]\n' ;;
    match-empty-path) printf '[extend]\nuseDefault = true\n\n[[allowlists]]\npaths = [%s]\n' "'''^.*$'''" ;;
    match-empty-regex) printf '[extend]\nuseDefault = true\n\n[[allowlists]]\nregexes = ["x", "a*"]\n' ;;
    empty-list) printf '[extend]\nuseDefault = true\n\n[[allowlists]]\ndescription = "d"\npaths = []\n' ;;
    unicode-class) printf '[extend]\nuseDefault = true\n\n[[allowlists]]\npaths = [%s]\n' "'''^gen/\\pL+$'''" ;;
    lookahead) printf '[extend]\nuseDefault = true\n\n[[allowlists]]\npaths = [%s]\n' "'''^gen/(?=c)'''" ;;
    not-word-boundary) printf '[extend]\nuseDefault = true\n\n[[allowlists]]\nregexes = [%s]\n' "'''\\B'''" ;;
    posix-class) printf '[extend]\nuseDefault = true\n\n[[allowlists]]\npaths = [%s]\n' "'''[[:alpha:]]?'''" ;;
    negated-posix-class)
      printf '[extend]\nuseDefault = true\n\n[[allowlists]]\npaths = [%s]\n' "'''[[:^alpha:]]?'''" ;;
    stopwords)
      printf '[extend]\nuseDefault = true\n\n[[allowlists]]\ndescription = "Words that mark placeholder values"\n'
      printf 'stopwords = ["example", "live", "kia"]\n' ;;
    review-probe)
      cat <<'EOF'
[extend]
useDefault = true

[[allowlists]]
description = "gen/: only sha256 digests"
paths = ['''^gen/''']
stopwords = ['''
[extend]
''']
condition = "AND"
regexTarget = "secret"
regexes = ['''^[0-9a-f]{64}$''', '''
[x]''']
EOF
      ;;
    multi-line-basic)
      printf '[extend]\nuseDefault = true\n\n[[allowlists]]\ndescription = """two\nlines"""\npaths = [%s]\n' \
        "'^gen/'"
      printf 'condition = "AND"\nregexTarget = "secret"\nregexes = [%s]\ntargetRules = ["generic-api-key"]\n' \
        "'^[0-9a-f]{64}$'"
      ;;
    and-global | and-global-empty-target | and-scoped)
      printf '[extend]\nuseDefault = true\n\n[[allowlists]]\ncondition = "AND"\npaths = [%s]\n' "'''^gen/'''"
      printf 'regexTarget = "secret"\nregexes = [%s]\n' "'''^[0-9a-f]{64}$'''"
      case $1 in
        and-global-empty-target) printf 'targetRules = []\n' ;;
        and-scoped) printf 'targetRules = ["generic-api-key"]\n' ;;
      esac
      ;;
    and-global-paths-only)
      printf '[extend]\nuseDefault = true\n\n[[allowlists]]\ncondition = "AND"\npaths = [%s]\n' "'''^gen/'''" ;;
    and-global-commits)
      printf '[extend]\nuseDefault = true\n\n[[allowlists]]\ncondition = "AND"\npaths = [%s]\n' "'''^gen/'''"
      printf 'commits = ["0123456789abcdef0123456789abcdef01234567"]\n' ;;
  esac
}
for shape in extend-path extend-path-dotted disabled-rules url subtable use-default-false upper-table upper-dotted \
  upper-quoted-path all-caps escaped bom second-extend stopwords-probe unknown-key wrong-type empty-path-scoped \
  empty-regex-scoped match-empty-path match-empty-regex empty-list lookahead not-word-boundary \
  posix-class negated-posix-class stopwords review-probe unicode-class \
  multi-line-basic and-global and-global-paths-only and-global-commits and-global-empty-target and-scoped; do
  g switch -q -c "config-$shape" "$base"
  config_case "$shape" >"$r/.gitleaks.toml"
  g commit -q -am "a base configuration ($shape)"
  shaped="$(g rev-parse HEAD)"
  if [[ "$shape" == and-scoped ]]; then and_scoped="$shaped"; fi
  mkdir -p "$r/gen"
  printf 'GITHUB_TOKEN=%s\n' "$(token)" >"$r/gen/creds.env"
  g add gen/creds.env
  g commit -q -m 'add credentials under gen/'
  case $shape in
    multi-line-basic | unicode-class | and-scoped) want=leak reason= ;;
    and-global*) want=fail reason="with paths but no targetRules" ;;
    review-probe) want=fail reason="allowlists[0] has the key 'stopwords'" ;;
    extend-path* | disabled-rules | url | subtable | use-default-false | escaped) want=fail
      reason="extend must be exactly {useDefault = true}" ;;
    upper-* | all-caps) want=fail reason="is not allowed; allowed are title, extend and allowlists" ;;
    stopwords-probe | unknown-key) want=fail reason="is not allowed; allowed are title, extend and allowlists" ;;
    bom | second-extend) want=fail reason="cannot parse" ;;
    wrong-type) want=fail reason="allowlists[0].paths is not a list of strings" ;;
    empty-path-scoped | match-empty-path | empty-regex-scoped | match-empty-regex | not-word-boundary | *posix-class)
      want=fail reason="is empty or matches the empty string, so it would match everything" ;;
    lookahead) want=fail reason="does not compile in Go's regexp" ;;
    empty-list) want=fail reason="allowlists[0].paths is an empty list" ;;
    stopwords) want=fail reason="allowlists[0] has the key 'stopwords'" ;;
  esac
  for target in scan-secrets scan-secrets-diff; do
    expect_pr "a base configuration ($shape)" "$want" "$target" "$shaped" "$shaped" "$reason"
    if [[ "$want" == fail ]]; then
      if ! grep -qF -- "is outside what the generated configuration accepts" <<<"$last_out"; then
        echo "FAIL a base configuration ($shape, $target): not refused by the whitelist"
        failures=$((failures + 1))
      fi
      if grep -qE 'commits scanned|: layer |leaks found' <<<"$last_out"; then
        echo "FAIL a base configuration ($shape, $target): gitleaks ran"
        failures=$((failures + 1))
      fi
    fi
  done
done

# The rule-targeted AND allowlist under gen/ applies its regexes in both scans (ADR 0027): a 64-hex api_key it allows
# passes, an api_key of the targeted rule that its regexes do not match is reported. The second value alternates letters
# and digits so that no generic-api-key stopword can occur in it.
for kind in hex alnum; do
  g switch -q -c "config-and-scoped-$kind" "$and_scoped"
  mkdir -p "$r/gen"
  case $kind in
    hex) value="$(python3 -c 'import secrets; print(secrets.token_hex(32))')" want=pass ;;
    alnum)
      value="$(python3 -c 'import secrets,string as s; print("".join(secrets.choice(s.ascii_letters)+secrets.choice(s.digits) for _ in range(16)))')"
      want=leak ;;
  esac
  printf 'api_key=%s\n' "$value" >"$r/gen/creds.env"
  g add gen/creds.env
  g commit -q -m "add a $kind api_key under gen/"
  for target in scan-secrets scan-secrets-diff; do
    expect_pr "the $kind api_key under a rule-targeted AND allowlist" "$want" "$target" "$and_scoped" "$and_scoped"
  done
done

# A base allowlist built around the fixed canary paths passes the whitelist and the pattern check, but the canary under
# an ordinary path chosen per run is allowlisted by it, so both scans fail before gitleaks reads the pull request.
g switch -q -c config-canary-tailored "$base"
printf '[extend]\nuseDefault = true\n\n[[allowlists]]\ndescription = "d"\npaths = [%s]\n' "'''^[^nv./]'''" \
  >"$r/.gitleaks.toml"
g commit -q -am 'a base configuration built around the canary paths'
tailored="$(g rev-parse HEAD)"
printf 'harmless\n' >"$r/tailored.txt"
g add tailored.txt
g commit -q -m 'a harmless change'
for target in scan-secrets scan-secrets-diff; do
  rc=0
  last_out="$(make --no-print-directory -C "$root" "$target" GITLEAKS_REPO="$r" GITLEAKS_LOG_OPTS="$tailored..HEAD" \
    GITLEAKS_DIFF_BASE="$tailored" GITLEAKS_CONFIG_REF="$tailored" 2>&1)" || rc=$?
  if ((rc != 0)) && grep -qF "the generated configuration lost its rules or path coverage" <<<"$last_out"; then
    echo "ok   a base allowlist built around the canary paths ($target) (fail)"
  else
    echo "FAIL a base allowlist built around the canary paths ($target): exit $rc, want a failed canary"
    failures=$((failures + 1))
  fi
  if grep -qE 'commits scanned|: layer ' <<<"$last_out"; then
    echo "FAIL a base allowlist built around the canary paths ($target): gitleaks ran on the pull request"
    failures=$((failures + 1))
  fi
done

# The strip of the default's global paths, run on crafted defaults through its test seam: the multi-line array is
# removed and the rest kept; a default whose global allowlist keeps paths in any key form (single-line, dotted, in an
# inline table, in other case) or that has no rules fails.
strip_case() {
  case $1 in
    multi-line) printf '[allowlist]\ndescription = "d"\npaths = [\n    %s,\n    %s,\n]\nregexes = [%s]\n' \
      "'''a[b]'''" "'''c'''" "'''^r$'''" ;;
    single-line) printf '[allowlist]\npaths = [%s]\n' "'''a'''" ;;
    dotted) printf 'allowlist.paths = [%s]\n' "'''a'''" ;;
    inline) printf 'allowlist = { description = "d", "paths" = [%s] }\n' "'''a'''" ;;
    mixed-case) printf 'Allowlist.Paths = [%s]\n' "'''a'''" ;;
    no-rules) printf '[allowlist]\ndescription = "d"\n'; return ;;
  esac
  printf '\n[[rules]]\nid = "x"\nregex = %s\npaths = [%s]\n' "'''x'''" "'''rule-path'''"
}
for kind in multi-line single-line dotted inline mixed-case no-rules; do
  strip_case "$kind" >"$work/default-$kind.toml"
  rc=0
  out="$(make --no-print-directory -C "$root" scan-secrets-strip-default \
    GITLEAKS_STRIP_FILE="$work/default-$kind.toml" 2>&1)" || rc=$?
  if [[ "$kind" == multi-line ]]; then
    if ((rc == 0)) && ! grep -qE "'''(a\\[b\\]|c)'''" <<<"$out" && grep -qF "regexes = ['''^r\$''']" <<<"$out" &&
      grep -qF "paths = ['''rule-path''']" <<<"$out"; then
      echo "ok   the strip removes the global paths and keeps the rest ($kind)"
    else
      echo "FAIL the strip of a default with $kind global paths: exit $rc"
      failures=$((failures + 1))
    fi
  elif ((rc != 0)) && grep -qF "is not a default with rules and without global paths" <<<"$out"; then
    echo "ok   a default with $kind global paths or rules fails the strip check (fail)"
  else
    echo "FAIL a default with $kind global paths or rules: exit $rc, want a failed strip check"
    failures=$((failures + 1))
  fi
done

# The canary through its test seam: a configuration whose default has no rules, or whose default still skips
# node_modules/, fails; one with a GitHub token rule and no path allowlist passes.
for kind in no-rules node-modules-skipped token-rule; do
  dir="$work/canary-$kind"
  mkdir -p "$dir"
  printf '[extend]\npath = "%s/default.toml"\n' "$dir" >"$dir/gitleaks.toml"
  rule="$(printf '[[rules]]\nid = "github-pat"\nregex = %s\n' "'''ghp_[0-9a-zA-Z]{36}'''")"
  case $kind in
    no-rules) printf 'title = "no rules"\n' >"$dir/default.toml" ;;
    node-modules-skipped) printf '[allowlist]\npaths = [%s]\n\n%s\n' "'''node_modules'''" "$rule" >"$dir/default.toml" ;;
    token-rule) printf '%s\n' "$rule" >"$dir/default.toml" ;;
  esac
  rc=0
  out="$(make --no-print-directory -C "$root" scan-secrets-canary GITLEAKS_CANARY_DIR="$dir" 2>&1)" || rc=$?
  if [[ "$kind" == token-rule ]] && ((rc == 0)) && grep -qF "the canary was reported" <<<"$out"; then
    echo "ok   the canary with a default of kind $kind (pass)"
  elif [[ "$kind" != token-rule ]] && ((rc != 0)) && grep -qF "lost its rules or path coverage" <<<"$out"; then
    echo "ok   the canary with a default of kind $kind (fail)"
  else
    echo "FAIL the canary with a default of kind $kind: exit $rc"
    failures=$((failures + 1))
  fi
  if grep -q 'ghp_' <<<"$out"; then
    echo "FAIL the canary with a default of kind $kind printed its token"
    failures=$((failures + 1))
  fi
done

# A Go pattern check that cannot run (here: an image without go) fails the scan with its own message.
gitleaks_image="$(sed -n 's/^GITLEAKS_IMAGE=//p' "$root/deploy/compose/versions.env")"
g switch -q pr-pins
rc=0
out="$(make --no-print-directory -C "$root" scan-secrets-diff GITLEAKS_REPO="$r" GITLEAKS_DIFF_BASE="$base" \
  GITLEAKS_CONFIG_REF="$base" GO_BUILD_IMAGE="$gitleaks_image" 2>&1)" || rc=$?
verdict "a Go pattern check that cannot run (scan-secrets-diff)" fail "the Go pattern check could not run" "$rc" "$out"

# The verdicts of the Go pattern check fail closed: none, too few, or one for another pattern refuse the
# configuration.
printf '["^a$", "^b$"]' >"$work/patterns.json"
: >"$work/verdicts-none.jsonl"
printf '{"index":0,"pattern":"^a$","ok":true}\n' >"$work/verdicts-short.jsonl"
printf '{"index":0,"pattern":"^a$","ok":true}\n{"index":1,"pattern":"^c$","ok":true}\n' >"$work/verdicts-other.jsonl"
for kind in none short other; do
  if python3 "$root/deploy/compose/scripts/gitleaks-child-config.py" patterns "$work/patterns.json" \
    "$work/verdicts-$kind.jsonl" 2>/dev/null; then
    echo "FAIL the pattern verdicts ($kind) are accepted"
    failures=$((failures + 1))
  else
    echo "ok   the pattern verdicts ($kind) refuse the configuration (fail)"
  fi
done

if ((failures > 0)); then
  echo "scan-secrets: $failures failure(s)"
  exit 1
fi
echo "scan-secrets: all checks passed"
