#!/usr/bin/env bash
# C6: the login component grants no sudo: after dave's login he is in no sudo/admin group and sudo -l shows no
# rights. Records Himmelblau's group-mapping options as configured.
#
# Usage: checks/c6-sudo.sh <vm>
set -euo pipefail

source "$(dirname "$0")/../lib.sh"
ensure_secrets
vm=${1:?usage: $0 <vm>}
out=$(evidence_dir "$vm" C6)
ensure_running "$vm"

gssh "$vm" '
    echo "--- id"; id dave@acme.test
    echo "--- sudo/admin/wheel groups"; getent group sudo admin wheel
    echo "--- sudo -l"; sudo -l -U dave@acme.test
    echo "--- group mapping options in effect"
    grep -E "^\s*(local_groups|sudo_groups|local_sudo_group|local_groups_reconcile_interval)\b" /etc/himmelblau/himmelblau.conf /usr/lib/himmelblau/himmelblau.conf 2>/dev/null
    echo "--- sudoers mentioning himmelblau users or groups"; sudo grep -rn -E "dave|paddock\.acme|%users" /etc/sudoers /etc/sudoers.d/ || echo none
' >"$out/sudo.txt" 2>&1
verdict=PASS
grep -A1 -- "--- id" "$out/sudo.txt" | grep -q -E "\((sudo|admin|wheel)\)" && verdict=FAIL
grep -q "is not allowed to run sudo" "$out/sudo.txt" || verdict=FAIL
cat "$out/sudo.txt"
echo "$(ts) $vm C6 $verdict" | tee -a "$out/results.txt"
