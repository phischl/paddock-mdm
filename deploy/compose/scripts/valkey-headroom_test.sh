#!/usr/bin/env bash
# Tests of valkey-headroom.sh (`make test`, plan M17 amendment s point 4.6): PASS up to 50 % of the limit, WARN with the
# sizing rule above, "not checked" for an unparsable usage, and the units of docker stats.
set -euo pipefail

script="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/valkey-headroom.sh"
failures=0

# expect <name> <usage> <pattern>...: every pattern must occur in the output, and the script exits 0.
expect() {
  local name="$1" usage="$2" out p
  shift 2
  if ! out="$(bash "$script" "$usage" 2>&1)"; then
    echo "FAIL $name: exit status not 0"
    failures=$((failures + 1))
    return
  fi
  for p in "$@"; do
    if [[ "$out" != *"$p"* ]]; then
      echo "FAIL $name: no \"$p\" in:"
      echo "$out"
      failures=$((failures + 1))
      return
    fi
  done
  echo "ok   $name"
}

rule='PADDOCK_VALKEY_MEM_LIMIT >= 2 x (64 MiB + live devices x 2.0 KB + offboarded devices x 2.3 KB)'
expect "PASS at 20 %" "200MiB / 1GiB" "PASS  valkey: memory headroom" "200MiB of 1GiB in use (19 %)"
expect "PASS at exactly 50 %" "512MiB / 1GiB" "PASS  valkey: memory headroom"
expect "WARN at 59 %" "600MiB / 1GiB" "WARN  valkey: memory headroom" "600MiB of 1GiB in use (58 %)" "$rule" \
  "docs/operations/capacity.md"
expect "KiB" "524288KiB / 1GiB" "PASS  valkey: memory headroom"
expect "KiB above half" "524289KiB / 1GiB" "WARN  valkey: memory headroom"
expect "fractional GiB" "1.5GiB / 2GiB" "WARN  valkey: memory headroom" "(75 %)"
expect "bytes" "100B / 1KiB" "PASS  valkey: memory headroom"
expect "not checked: empty" "" "WARN  valkey: memory headroom" "not checked"
expect "not checked: unknown unit" "200MB / 1GB" "WARN  valkey: memory headroom" "not checked"
expect "not checked: garbage" "-- / --" "WARN  valkey: memory headroom" "not checked"
expect "not checked: zero limit" "1MiB / 0B" "WARN  valkey: memory headroom" "not checked"

if ((failures > 0)); then
  echo "valkey-headroom: $failures failure(s)"
  exit 1
fi
echo "valkey-headroom: all cases passed"
