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
# `make scan-secrets-diff`; a base configuration without an `[extend]` table still gets the default rules; a default
# configuration that does not match its pins (sha256 off by one digit, header missing or not unique) fails both
# scans. Archives are opened one level deep (ADR 0025): a secret inside a deflated `creds.zip`, `creds.docx` or
# `creds.tgz` fails `make scan-secrets-diff`, an archive copy that would overwrite another changed file fails it, and
# a real binary PNG passes with the repository's own configuration. The secret is a generated fake GitHub token that
# is never printed (the scan runs with --redact).
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
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

# A base configuration that extends another file: gitleaks would read that file from the scanned pull request's
# files, so the scan refuses it, in the [extend] table and as a dotted key alike.
for form in table dotted; do
  g switch -q -c "extend-$form" "$base"
  if [[ "$form" == table ]]; then
    printf '[extend] # the default rules and more\nuseDefault = true\n"path" = "extra.toml"\n' >"$r/.gitleaks.toml"
  else
    printf 'extend.path = "extra.toml"\n' >"$r/.gitleaks.toml"
  fi
  g commit -q -am "extend another file ($form)"
  extending="$(g rev-parse HEAD)"
  printf 'side\n' >"$r/extend.txt"
  g add extend.txt
  g commit -q -m 'a pull request on the extending base'
  for target in scan-secrets scan-secrets-diff; do
    expect_pr "a base configuration with [extend] path ($form)" fail "$target" "$extending" "$extending" \
      "extends another file"
  done
done

if ((failures > 0)); then
  echo "scan-secrets: $failures failure(s)"
  exit 1
fi
echo "scan-secrets: all checks passed"
