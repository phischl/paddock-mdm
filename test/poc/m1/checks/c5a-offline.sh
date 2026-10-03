#!/usr/bin/env bash
# C5a: with the VM's network link cut (VBoxManage setlinkstate1 off), dave first logs in offline with his
# cached Hello PIN; then dave is removed from the allow list locally (pam_allow_groups without paddock.acme,
# daemon restart) and the offline login must be refused. SSH shares the cut link, so the steps run inside the
# guest as a transient systemd unit and the log is collected after the link is back.
# Precondition: dave has a Hello PIN (checks/c1-login.sh).
#
# Usage: checks/c5a-offline.sh <vm> [deny-list]   deny-list: also put dave into /etc/paddock/login-deny (C5c)
set -euo pipefail

source "$(dirname "$0")/../lib.sh"
ensure_secrets
vm=${1:?usage: $0 <vm> [deny-list]}
mode=${2:-allow-list}
crit=C5a; [[ "$mode" == deny-list ]] && crit=C5c
out=$(evidence_dir "$vm" "$crit")
ensure_running "$vm"

# Guest-side steps. Phase B removes dave from the allow list (C5a) or adds him to the pam_listfile deny file (C5c).
read -r -d '' guest_script <<'GUEST' || true
#!/bin/bash
exec >/root/poc-offline.log 2>&1
ts() { date -u +%FT%T.%3NZ; }
pin=$(cat /root/poc-pin)
login() {
    echo "$(ts) $1"
    printf '%s\n' "$pin" | timeout 60 pamtester gdm-password dave@acme.test authenticate acct_mgmt
    local rc=$?
    echo "$(ts) rc=$rc"
}
conf=/etc/himmelblau/himmelblau.conf
iface=$(ip -o route get 10.0.2.2 | sed -n 's/.* dev \([^ ]*\).*/\1/p')
for _ in $(seq 1 60); do [ "$(cat /sys/class/net/$iface/carrier)" = 0 ] && break; sleep 1; done
echo "$(ts) $iface carrier=$(cat /sys/class/net/$iface/carrier)"
timeout 5 bash -c '</dev/tcp/10.0.2.2/8443' && echo "$(ts) Authentik REACHABLE" || echo "$(ts) Authentik unreachable"
login "A: offline login, dave in allow list"
if [ "$MODE" = deny-list ]; then
    mkdir -p /etc/paddock && echo dave@acme.test >/etc/paddock/login-deny && echo dave >>/etc/paddock/login-deny
    echo "$(ts) deny file: $(tr '\n' ' ' </etc/paddock/login-deny)"
else
    sed -i 's|^pam_allow_groups *=.*|pam_allow_groups = paddock.suspended|' $conf
    systemctl restart himmelblaud himmelblaud-tasks; sleep 3
    echo "$(ts) $(grep ^pam_allow_groups $conf), himmelblaud $(systemctl is-active himmelblaud)"
fi
login "B: offline login, dave removed"
if [ "$MODE" = deny-list ]; then
    rm -f /etc/paddock/login-deny
    echo "$(ts) deny file removed (fail-safe check)"
else
    sed -i 's|^pam_allow_groups *=.*|pam_allow_groups = paddock.acme|' $conf
    systemctl restart himmelblaud himmelblaud-tasks; sleep 3
    echo "$(ts) $(grep ^pam_allow_groups $conf)"
fi
login "C: offline login after revert"
rm -f /root/poc-pin
echo "$(ts) done"
GUEST

printf '%s' "$guest_script" | gssh "$vm" 'sudo tee /root/poc-offline.sh >/dev/null && sudo chmod 700 /root/poc-offline.sh'
poc_secret hello_pin_dave | gssh "$vm" 'sudo install -m 600 /dev/stdin /root/poc-pin'
gssh "$vm" "sudo rm -f /root/poc-offline.log; sudo systemd-run --quiet --unit poc-offline-$(date +%s) --setenv=MODE=$mode --on-active=5 /root/poc-offline.sh"
echo "$(ts) link off" | tee "$out/timeline.txt"
VBoxManage controlvm "$vm" setlinkstate1 off
sleep 150
VBoxManage controlvm "$vm" setlinkstate1 on
echo "$(ts) link on" | tee -a "$out/timeline.txt"
for _ in $(seq 1 30); do ssh_ready "$(vm_port "$vm")" && break; sleep 2; done
gssh "$vm" 'sudo cat /root/poc-offline.log' | tee "$out/guest.log"
gssh "$vm" 'sudo journalctl -u himmelblaud --since "-4min" --no-pager -o short-iso |
    grep -i -E "offline|network|allowed groups|intersecting|Hello" | cut -c1-250' >"$out/himmelblaud.log" 2>&1 || true

rcs=$(sed -n 's/.* rc=\([0-9]*\)$/\1/p' "$out/guest.log" | tr '\n' ' ')
if [[ "$rcs" =~ ^0\ [1-9][0-9]*\ 0\ $ ]] && grep -q "Authentik unreachable" "$out/guest.log"; then verdict=PASS; else verdict=FAIL; fi
echo "$(ts) $vm $crit $verdict (rc A B C: $rcs)" | tee -a "$out/results.txt"
