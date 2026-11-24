#!/usr/bin/env bash
# The ./paddock check --online item "valkey: memory headroom" (plan M17 amendment s point 4.6):
#   valkey-headroom.sh "<MemUsage>"
# MemUsage is what `docker stats --no-stream --format '{{.MemUsage}}'` prints for the valkey container, e.g.
# "200MiB / 1GiB". PASS at up to 50 % of the limit; WARN above, with the sizing rule of docs/operations/capacity.md: at
# 60 % Valkey refuses writes (maxmemory, noeviction), and the rest is the AOF rewrite's headroom. An empty or unparsable
# usage is a WARN "not checked", never a pass. Always exits 0: the item warns, it does not fail the check.
set -euo pipefail

item="valkey: memory headroom"
rule='PADDOCK_VALKEY_MEM_LIMIT >= 2 x (64 MiB + live devices x 2.0 KB + offboarded devices x 2.3 KB)'
usage="${1-}"

# bytes <value with unit>: prints the value in bytes, or fails for anything but B, KiB, MiB, GiB and TiB (docker stats
# prints binary units). LC_ALL=C: a locale with a decimal comma would read 1.5 as 1.
bytes() {
  LC_ALL=C awk -v v="$1" 'BEGIN {
    if (!match(v, /^[0-9]+(\.[0-9]+)?/)) exit 1
    n = substr(v, 1, RLENGTH); u = substr(v, RLENGTH + 1)
    f["B"] = 1; f["KiB"] = 1024; f["MiB"] = 1024 ^ 2; f["GiB"] = 1024 ^ 3; f["TiB"] = 1024 ^ 4
    if (!(u in f)) exit 1
    printf "%.0f\n", n * f[u]
  }'
}

not_checked() {
  echo "WARN  $item"
  echo "      - not checked: $1"
  exit 0
}

[[ "$usage" == *" / "* ]] || not_checked "no usage of the valkey container (docker stats failed or it does not run): \"$usage\""
used_text="${usage%% / *}" limit_text="${usage##* / }"
used="$(bytes "$used_text")" || not_checked "unreadable usage \"$usage\""
limit="$(bytes "$limit_text")" || not_checked "unreadable usage \"$usage\""
((limit > 0)) || not_checked "unreadable usage \"$usage\""
percent=$((used * 100 / limit))
if ((used * 2 <= limit)); then
  echo "PASS  $item"
  echo "      - $used_text of $limit_text in use ($percent %)"
else
  echo "WARN  $item"
  echo "      - $used_text of $limit_text in use ($percent %), above 50 %: at 60 % Valkey refuses writes"
  echo "      - raise the limit by the rule $rule (docs/operations/capacity.md, \"Memory limits\")"
fi
