#!/usr/bin/env bash
# Link check of the Claude skill skills/operate-paddock (ADR 0044 decision 9, plan M14 §3.8, `make test`): the front
# matter has name and description, SKILL.md has its six sections, every workflow step names a runbook anchor and a
# tool, every referenced path exists, every #anchor matches a heading of its file (GitHub's rules), and every
# backticked tool name exists in pkg/mcpcatalog/catalog.gen.go, and every operation the catalog marks StepUp (from
# x-paddock-step-up) is named in the table under ## What the assistant cannot do, which names no other operation.
# Prints what it checked; checking nothing fails.
#
# Without an argument it checks the repository and then proves itself on broken scratch copies. With a directory it
# checks only that tree (laid out like the repository).
# SC2016: the single-quoted backticks are Markdown code spans matched literally, not command substitutions.
# SC2001: sed prefixes every line of a multi-line output, which a parameter expansion does not do as plainly.
# shellcheck disable=SC2016,SC2001
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
skill_rel="skills/operate-paddock"
tool_re='^[a-z][a-z0-9]*[A-Z][A-Za-z0-9]*$'

# slugs <file>: the GitHub anchors of the file's headings, fenced code blocks skipped, duplicates numbered.
slugs() {
  awk '
    /^[ \t]*(```|~~~)/ { fence = !fence; next }
    fence || !/^#+[ \t]/ { next }
    {
      h = tolower($0)
      sub(/^#+[ \t]+/, "", h)
      sub(/[ \t]+#*[ \t]*$/, "", h)
      gsub(/[^a-z0-9 _-]/, "", h)
      gsub(/ /, "-", h)
      if (h in seen) { print h "-" seen[h]; seen[h]++ } else { print h; seen[h] = 1 }
    }' "$1"
}

check() {
  local tree="$1" errors=0 paths=0 anchors=0 tools=0 steps=0 stepups=0
  local dir="$tree/$skill_rel" catalog="$tree/pkg/mcpcatalog/catalog.gen.go"
  local skill="$dir/SKILL.md" ref="$dir/references/tools.md"
  fail() { echo "skill check: $*" >&2; errors=$((errors + 1)); }

  for f in "$skill" "$ref" "$catalog"; do
    [[ -f "$f" ]] || { echo "skill check: missing $f" >&2; return 1; }
  done

  local front
  front="$(awk 'NR == 1 && $0 != "---" { exit } NR > 1 && $0 == "---" { exit } NR > 1' "$skill")"
  grep -qE '^name: operate-paddock$' <<<"$front" || fail "front matter: name operate-paddock missing"
  grep -qE '^description: .+' <<<"$front" || fail "front matter: description missing"

  local section
  for section in "When to use" "Connect" "Rules for the assistant" "Workflows" "What the assistant cannot do" \
    "Tool catalog by tag"; do
    grep -qxF "## $section" "$skill" || fail "SKILL.md: section '## $section' missing"
  done

  # Every numbered step under ## Workflows (with its indented continuation lines) names a runbook anchor and a tool.
  local item
  while IFS= read -r item; do
    steps=$((steps + 1))
    grep -qE 'docs/operations/[A-Za-z0-9_.-]+\.md#[a-z0-9_-]+' <<<"$item" ||
      fail "workflow step without a runbook anchor: ${item:0:80}"
    grep -oE '`[^`]+`' <<<"$item" | tr -d '`' | grep -qE "$tool_re" ||
      fail "workflow step without a tool: ${item:0:80}"
  done < <(awk '
    /^## / { in_wf = ($0 == "## Workflows"); next }
    !in_wf { next }
    /^[0-9]+\. / { if (item != "") print item; item = $0; next }
    /^   / && item != "" { item = item " " $0; next }
    { if (item != "") print item; item = "" }
    END { if (item != "") print item }' "$skill")

  # References: Markdown link targets relative to their file, and docs/… mentions relative to the tree.
  local refs file target path anchor base
  refs="$(
    for file in "$skill" "$ref"; do
      grep -oE '\]\([^) ]+\)' "$file" | sed -E 's/^\]\((.*)\)$/\1/' | grep -vE '^[a-z]+:' |
        while IFS= read -r target; do
          path="${target%%#*}"
          if [[ -z "$path" ]]; then path="$file"; else path="$(dirname "$file")/$path"; fi
          [[ "$target" == *"#"* ]] && echo "$path#${target#*#}" || echo "$path"
        done
      grep -oE '(^|[^./A-Za-z0-9_-])docs/[A-Za-z0-9_./-]+\.md(#[A-Za-z0-9_-]+)?' "$file" | sed -E 's/^[^d]//' |
        sed "s|^|$tree/|"
    done | sort -u || true
  )"
  declare -A seen_path=() seen_anchor=()
  while IFS= read -r target; do
    [[ -n "$target" ]] || continue
    path="${target%%#*}"
    base="$(realpath -m --relative-to="$tree" "$path")"
    if [[ -z "${seen_path[$base]:-}" ]]; then
      seen_path[$base]=1
      paths=$((paths + 1))
      [[ -e "$path" ]] || { fail "missing path: $base"; continue; }
    fi
    [[ -e "$path" ]] || continue
    if [[ "$target" == *"#"* ]]; then
      anchor="${target#*#}"
      [[ -z "${seen_anchor[$base#$anchor]:-}" ]] || continue
      seen_anchor[$base#$anchor]=1
      anchors=$((anchors + 1))
      slugs "$path" | grep -qxF -- "$anchor" || fail "no heading for anchor: $base#$anchor"
    fi
  done <<<"$refs"

  local names name
  names="$(sed -nE 's/^[[:space:]]*Name:[[:space:]]*"([^"]+)",$/\1/p' "$catalog")"
  while IFS= read -r name; do
    [[ -n "$name" ]] || continue
    tools=$((tools + 1))
    grep -qxF -- "$name" <<<"$names" || fail "unknown tool: $name"
  done < <(cat "$skill" "$ref" | grep -oE '`[^`]+`' | tr -d '`' | grep -E "$tool_re" | sort -u)

  # The hand-written table names exactly the catalog's step-up operations: a new one cannot be missing there, and an
  # operation an MCP session can be offered is never declined as one.
  local table catalog_stepups
  table="$(awk '
    /^## / { in_sec = ($0 == "## What the assistant cannot do"); next }
    in_sec && /^\|/' "$skill" | grep -oE '`[^`]+`' | tr -d '`' | grep -E "$tool_re" | sort -u || true)"
  catalog_stepups="$(awk '
    match($0, /^[[:space:]]*Name:[[:space:]]*"[^"]+",$/) { split($0, q, "\""); name = q[2]; next }
    /^[[:space:]]*StepUp:[[:space:]]*true,$/ && name != "" { print name }' "$catalog")"
  while IFS= read -r name; do
    [[ -n "$name" ]] || continue
    stepups=$((stepups + 1))
    grep -qxF -- "$name" <<<"$table" || fail "step-up operation missing from the table in SKILL.md: $name"
  done <<<"$catalog_stepups"
  while IFS= read -r name; do
    [[ -n "$name" ]] || continue
    grep -qxF -- "$name" <<<"$catalog_stepups" || fail "not a step-up operation in the table in SKILL.md: $name"
  done <<<"$table"

  echo "skill check: $paths paths, $anchors anchors, $tools tool names, $steps workflow steps, $stepups step-up operations"
  for n in "$paths" "$anchors" "$tools" "$steps" "$stepups"; do
    ((n > 0)) || { echo "skill check: a count is 0, nothing was checked" >&2; return 1; }
  done
  ((errors == 0)) || { echo "skill check: $errors errors" >&2; return 1; }
}

if (($# > 0)); then
  check "$1"
  exit
fi

check "$root"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
failures=0

# copy <name>: a scratch tree with the skill, the runbooks and the catalog.
copy() {
  local t="$work/$1"
  mkdir -p "$t/docs" "$t/pkg/mcpcatalog" "$t/skills"
  cp -r "$root/docs/operations" "$t/docs/"
  cp -r "$root/$skill_rel" "$t/skills/"
  cp "$root/pkg/mcpcatalog/catalog.gen.go" "$t/pkg/mcpcatalog/"
  echo "$t"
}

# expect_fail <description> <text the output must contain> <tree>
expect_fail() {
  local out rc=0
  out="$(bash "${BASH_SOURCE[0]}" "$3" 2>&1)" || rc=$?
  if ((rc != 0)) && grep -qF -- "$2" <<<"$out"; then
    echo "ok   $1 fails naming '$2'"
  else
    echo "FAIL $1: exit $rc, want failure naming '$2'"
    sed 's/^/       /' <<<"$out"
    failures=$((failures + 1))
  fi
}

t="$(copy path)"
sed -i 's|docs/operations/upgrade.md#rollback|docs/operations/upgrades.md#rollback|g' "$t/$skill_rel/SKILL.md"
expect_fail "a broken path" "missing path: docs/operations/upgrades.md" "$t"

t="$(copy anchor)"
sed -i 's|#before-you-start|#before-you-begin|g' "$t/$skill_rel/SKILL.md"
expect_fail "a broken anchor" "no heading for anchor: docs/operations/upgrade.md#before-you-begin" "$t"

t="$(copy tool)"
sed -i 's|`getDeviceDisk`|`getDeviceDisks`|g' "$t/$skill_rel/SKILL.md"
expect_fail "a broken tool name" "unknown tool: getDeviceDisks" "$t"

t="$(copy reftool)"
sed -i 's|`listDevices`|`listDevicez`|' "$t/$skill_rel/references/tools.md"
expect_fail "a broken tool name in references/tools.md" "unknown tool: listDevicez" "$t"

t="$(copy stepup)"
sed -i 's|, `endAllSessions`||' "$t/$skill_rel/SKILL.md"
expect_fail "a step-up operation missing from the table" \
  "step-up operation missing from the table in SKILL.md: endAllSessions" "$t"

t="$(copy notstepup)"
sed -i 's|, `endAllSessions`|, `endAllSessions`, `listDevices`|' "$t/$skill_rel/SKILL.md"
expect_fail "a non-step-up operation in the table" "not a step-up operation in the table in SKILL.md: listDevices" "$t"

t="$(copy front)"
sed -i '/^description: /d' "$t/$skill_rel/SKILL.md"
expect_fail "front matter without description" "front matter: description missing" "$t"

t="$(copy step)"
printf '\n## Workflows\n\n1. A step without a link or a tool.\n' >>"$t/$skill_rel/SKILL.md"
expect_fail "a workflow step without anchor and tool" "workflow step without a runbook anchor: 1. A step" "$t"

t="$(copy empty)"
printf -- '---\nname: operate-paddock\ndescription: x\n---\n' >"$t/$skill_rel/SKILL.md"
: >"$t/$skill_rel/references/tools.md"
expect_fail "a skill that references nothing" "a count is 0" "$t"

if ((failures > 0)); then
  echo "skill_test: $failures failed" >&2
  exit 1
fi
echo "skill_test: all passed"
