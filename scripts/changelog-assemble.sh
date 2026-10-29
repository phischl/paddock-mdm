#!/usr/bin/env bash
# Assembles the changelog fragments of changelog.d/ into CHANGELOG.md (PDK-518; `make changelog`, `make
# changelog-preview`, `make changelog-check`). Each merged change adds its own fragment file instead of editing the
# [Unreleased] section, so parallel pull requests no longer conflict on the top of CHANGELOG.md.
#
#   changelog-assemble.sh --check                                validate every fragment
#   changelog-assemble.sh --preview [--version V]                print the would-be section, change nothing
#   changelog-assemble.sh --version V --schema TEXT [--date D]   release: write CHANGELOG.md, git rm the fragments
#
# --changelog FILE and --dir DIR override the defaults (CHANGELOG.md and changelog.d/ of the repository) for tests.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
changelog="$root/CHANGELOG.md"
dir="$root/changelog.d"
mode=release
version=""
schema=""
date="$(date -u +%F)"

# Keep a Changelog order; CHANGELOG.md uses the same order for the sections it has.
sections=(added changed deprecated removed fixed security)
# shellcheck disable=SC2016 # the backticks are Markdown, not a command substitution
transition='Entries of merged changes that are not released yet are in `changelog.d/`.'

usage() {
  echo "usage: $0 --check | --preview [--version V] | --version V --schema TEXT [--date YYYY-MM-DD]" >&2
  exit 2
}

while (($#)); do
  case "$1" in
    --check) mode=check ;;
    --preview) mode=preview ;;
    --version) version="${2-}"; shift ;;
    --schema) schema="${2-}"; shift ;;
    --date) date="${2-}"; shift ;;
    --changelog) changelog="${2-}"; shift ;;
    --dir) dir="${2-}"; shift ;;
    *) usage ;;
  esac
  shift
done

title() { printf '%s%s' "$(tr '[:lower:]' '[:upper:]' <<<"${1:0:1}")" "${1:1}"; }

# fragments: the fragment files of changelog.d/ (everything but README.md), one per line, sorted by ticket id
# numerically (version sort orders PDK-99 before PDK-518); slugs without a ticket id sort after them.
fragments() {
  [[ -d "$dir" ]] || return 0
  find "$dir" -mindepth 1 -maxdepth 1 ! -name README.md -printf '%f\n' | LC_ALL=C sort -V
}

check() {
  local f path section errors=0 known
  known="$(IFS='|'; echo "${sections[*]}")"
  while IFS= read -r f; do
    [[ -n "$f" ]] || continue
    path="$dir/$f"
    if [[ ! "$f" =~ ^([A-Z][A-Z0-9]*-[0-9]+|[a-z0-9][a-z0-9-]*)\.([A-Za-z]+)\.md$ ]]; then
      echo "changelog.d/$f: name is not <ticket-id>.<section>.md or <slug>.<section>.md" >&2
      errors=$((errors + 1)); continue
    fi
    section="${BASH_REMATCH[2]}"
    if [[ ! "$section" =~ ^($known)$ ]]; then
      echo "changelog.d/$f: unknown section '$section' (one of ${sections[*]})" >&2
      errors=$((errors + 1)); continue
    fi
    if [[ ! -f "$path" ]]; then
      echo "changelog.d/$f: not a regular file" >&2
      errors=$((errors + 1)); continue
    fi
    if ! grep -q '[^[:space:]]' "$path"; then
      echo "changelog.d/$f: empty" >&2
      errors=$((errors + 1)); continue
    fi
    if grep -q $'\r' "$path"; then
      echo "changelog.d/$f: contains carriage returns (CRLF line endings); use LF" >&2
      errors=$((errors + 1)); continue
    fi
    if grep -n '^#' "$path" | sed "s|^|changelog.d/$f:|; s|$| (no headings in a fragment)|" >&2; then
      errors=$((errors + 1)); continue
    fi
    if grep -nvE '^(- [^[:space:]]|  +[^[:space:]]|[[:space:]]*$)' "$path" |
      sed "s|^|changelog.d/$f:|; s|$| (not a '- ' bullet or an indented continuation)|" >&2; then
      errors=$((errors + 1)); continue
    fi
    if [[ ! "$(grep -m1 '[^[:space:]]' "$path")" =~ ^-\  ]]; then
      echo "changelog.d/$f: does not start with a '- ' bullet" >&2
      errors=$((errors + 1))
    fi
  done < <(fragments)
  if ((errors)); then
    echo "changelog-check: $errors invalid fragment(s); see changelog.d/README.md" >&2
    return 1
  fi
}

# trim: drops leading and trailing blank lines of stdin.
trim() { awk 'NF { for (; blank > 0; blank--) print ""; print; seen = 1; next } seen { blank++ }'; }

rank() {
  local i
  for i in "${!sections[@]}"; do
    [[ "${sections[$i],,}" == "${1,,}" ]] && { echo "$i"; return; }
  done
  echo -1
}

check

[[ -f "$changelog" ]] || { echo "$changelog: not found" >&2; exit 1; }
unreleased="$(grep -n -m1 -x '## \[Unreleased\]' "$changelog" | cut -d: -f1 || true)"
[[ -n "$unreleased" ]] || { echo "$changelog: no '## [Unreleased]' heading" >&2; exit 1; }
next="$(awk -v u="$unreleased" 'NR > u && /^## / { print NR; exit }' "$changelog")"
total="$(wc -l <"$changelog")"
[[ -n "$next" ]] || next=$((total + 1))

if [[ "$mode" == check ]]; then
  exit 0
fi
# The rule of `make release-check` for the stable channel.
n='(0|[1-9][0-9]*)'
if [[ -n "$version" && ! "$version" =~ ^$n\.$n\.$n(-(alpha|beta|rc)\.$n)?$ ]]; then
  echo "version '$version' is not x.y.z or x.y.z-alpha.N, -beta.N, -rc.N (without v)" >&2
  exit 2
fi
if [[ "$mode" == release ]]; then
  [[ -n "$version" && -n "$schema" ]] || usage
  [[ "$date" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]] || { echo "date '$date' is not YYYY-MM-DD" >&2; exit 2; }
  if grep -qF "## [$version]" "$changelog"; then
    echo "$changelog already has a section for $version" >&2
    exit 1
  fi
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# Split the [Unreleased] body into its preamble (without the transition line) and one file per ### subsection, in
# file order; order lists the subsection names.
awk -v a="$unreleased" -v b="$next" 'NR > a && NR < b' "$changelog" | awk -v w="$work" -v t="$transition" '
  /^### / { n++; name = substr($0, 5); if (!seen[name]++) print name > (w "/order"); out = w "/sec." name; next }
  n == 0 { if ($0 != t) print > (w "/pre"); next }
  { print > out }
'
touch "$work/pre" "$work/order"

declare -A has_fragments=()
while IFS= read -r f; do
  [[ -n "$f" ]] || continue
  s="${f%.md}"; s="${s##*.}"
  name="$(title "$s")"
  { trim <"$dir/$f"; } >>"$work/frag.$name"
  has_fragments[$name]=1
done < <(fragments)

# Subsections in output order: the existing ones keep their order; a missing one with fragments goes before the first
# existing subsection that comes later in Keep a Changelog order, or last.
mapfile -t order <"$work/order"
for s in "${sections[@]}"; do
  name="$(title "$s")"
  [[ -n "${has_fragments[$name]-}" ]] || continue
  printf '%s\n' "${order[@]}" | grep -qx -- "$name" && continue
  r="$(rank "$name")"
  placed=()
  inserted=""
  for o in "${order[@]}"; do
    ro="$(rank "$o")"
    if [[ -z "$inserted" && "$ro" -gt "$r" ]]; then
      placed+=("$name"); inserted=1
    fi
    placed+=("$o")
  done
  [[ -n "$inserted" ]] || placed+=("$name")
  order=("${placed[@]}")
done

if [[ "$mode" == release ]]; then
  heading="## [$version] - $date"
else
  heading="## [${version:-Unreleased}]"
fi

{
  echo "$heading"
  echo
  if [[ -n "$(trim <"$work/pre")" ]]; then
    trim <"$work/pre"
    echo
  fi
  if [[ "$mode" == release ]]; then
    echo "Schema: ${schema%.}."
    echo
  fi
  for name in "${order[@]}"; do
    touch "$work/sec.$name" "$work/frag.$name"
    body="$( (trim <"$work/sec.$name"; cat "$work/frag.$name") | trim)"
    [[ -n "$body" ]] || continue
    echo "### $name"
    echo
    printf '%s\n' "$body"
    echo
  done
} >"$work/section"

if [[ "$mode" == preview ]]; then
  trim <"$work/section"
  exit 0
fi

if [[ -z "$(cat "$work"/sec.* "$work"/frag.* 2>/dev/null | tr -d '[:space:]')" ]]; then
  echo "nothing to release: [Unreleased] and changelog.d/ are empty" >&2
  exit 1
fi

{
  head -n "$((unreleased - 1))" "$changelog"
  echo "## [Unreleased]"
  echo
  echo "$transition"
  echo
  if ((next <= total)); then
    cat "$work/section"
    tail -n "+$next" "$changelog"
  else
    trim <"$work/section"
  fi
} >"$work/CHANGELOG.md"
cat "$work/CHANGELOG.md" >"$changelog"

while IFS= read -r f; do
  [[ -n "$f" ]] || continue
  if git -C "$dir" ls-files --error-unmatch -- "$f" >/dev/null 2>&1; then
    git -C "$dir" rm -q -- "$f"
  else
    rm -f -- "$dir/$f"
  fi
done < <(fragments)
echo "CHANGELOG.md: section [$version] - $date assembled; add the release summary under its heading" >&2
