#!/usr/bin/env bash
# Line budget of paddock-supervisor (plan M2b decision 15, amendment 2026-10-12; `make lint`): the supervisor must
# stay simple enough to need no updates (design contract 1), so all its non-test Go files together may hold at most
# 800 lines that are neither blank nor comment-only. Without arguments it counts agent/internal/supervisor/ and
# agent/cmd/paddock-supervisor/; arguments replace those directories (test/supervisor-budget_test.sh). It fails with
# the count above the ceiling, and when it finds no file at all, so a moved directory cannot pass unseen.
set -euo pipefail

ceiling=800
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if (($# == 0)); then
  set -- "$root/agent/internal/supervisor" "$root/agent/cmd/paddock-supervisor"
fi

files=()
# -L follows symlinks, so a file or directory linked into the supervisor counts like one copied there.
while IFS= read -r -d '' f; do files+=("$f"); done < <(find -L "$@" -type f -name '*.go' ! -name '*_test.go' -print0 | sort -z)
if ((${#files[@]} == 0)); then
  echo "supervisor line budget: no Go files found in $*" >&2
  exit 1
fi

# A line counts unless it is blank, a // comment, or inside or a whole /* */ comment; code after a closing */ counts.
# The counter does not parse Go: a line inside a raw string literal that starts with // or /* is taken for a comment
# and not counted. The count is a review backstop for the design contract, not a security boundary.
count="$(awk '
  inblock {
    if (!index($0, "*/")) next
    inblock = 0
    $0 = substr($0, index($0, "*/") + 2)
  }
  /^[[:space:]]*\/\*/ {
    rest = substr($0, index($0, "/*") + 2)
    if (!index(rest, "*/")) { inblock = 1; next }
    $0 = substr(rest, index(rest, "*/") + 2)
  }
  /^[[:space:]]*(\/\/.*)?$/ { next }
  { n++ }
  END { print n + 0 }
' "${files[@]}")"

if ((count > ceiling)); then
  echo "supervisor line budget exceeded: $count counted lines in ${#files[@]} files, ceiling $ceiling" >&2
  echo "move code out of the supervisor (into the agent or pkg/), do not split it (plan M2b decision 15)" >&2
  exit 1
fi
echo "supervisor line budget: $count of $ceiling counted lines in ${#files[@]} files"
