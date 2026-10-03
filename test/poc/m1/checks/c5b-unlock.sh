#!/usr/bin/env bash
# C5b: dave has a running GNOME session (checks/gdm.sh); the session is locked (loginctl lock-session), dave is
# removed from the allow list (or, with "deny-list", put into the pam_listfile deny file of C5c), and the unlock
# must be refused - checked through the gdm-password PAM stack (pamtester) and through the real lock screen
# (keyboard + screenshot + LockedHint). Reverts at the end and unlocks.
#
# Usage: checks/c5b-unlock.sh <vm> [deny-list]
set -euo pipefail

source "$(dirname "$0")/../lib.sh"
ensure_secrets
vm=${1:?usage: $0 <vm> [deny-list]}
mode=${2:-allow-list}
crit=C5b; [[ "$mode" == deny-list ]] && crit=C5c
out=$(evidence_dir "$vm" "$crit")
gdm() { "$POC_DIR/checks/gdm.sh" "$vm" "$crit" "$@"; }
verdict=PASS

session=$(gssh "$vm" 'loginctl list-sessions --no-legend | awk "\$3==\"dave\" && \$4==\"seat0\" {print \$1}"')
[[ -n "$session" ]] || die "dave has no graphical session on seat0 (log in with checks/gdm.sh first)"
locked() { gssh "$vm" "loginctl show-session $session -p LockedHint --value"; }

gssh "$vm" "sudo loginctl lock-session $session"
sleep 4
echo "$(ts) after lock-session: LockedHint=$(locked)" | tee "$out/steps.txt"
gdm shot 10-locked >/dev/null

if [[ "$mode" == deny-list ]]; then
    gssh "$vm" 'sudo mkdir -p /etc/paddock && printf "dave@acme.test\ndave\n" | sudo tee /etc/paddock/login-deny >/dev/null'
    echo "$(ts) dave in /etc/paddock/login-deny" | tee -a "$out/steps.txt"
else
    set_allow "$vm" paddock.suspended | tee -a "$out/steps.txt"
    gssh "$vm" 'sudo systemctl restart himmelblaud himmelblaud-tasks'
    sleep 3
fi

if pam "$vm" gdm-password dave@acme.test authenticate acct_mgmt --pin "$(poc_secret hello_pin_dave)" --approve none \
    --timeout 40 >"$out/pamtester-unlock.log" 2>&1; then
    echo "pamtester: ADMITTED" | tee -a "$out/steps.txt"
    verdict=FAIL
else
    echo "pamtester: refused" | tee -a "$out/steps.txt"
fi

gdm key 39 b9 >/dev/null   # Space raises the unlock prompt
sleep 3
gdm shot 11-unlock-prompt >/dev/null
gdm type hello_pin_dave 1 >/dev/null
sleep 6
gdm shot 12-after-unlock-attempt >/dev/null
state=$(locked)
echo "$(ts) lock screen after PIN: LockedHint=$state" | tee -a "$out/steps.txt"
[[ "$state" == yes ]] || verdict=FAIL

if [[ "$mode" == deny-list ]]; then
    gssh "$vm" 'sudo rm -f /etc/paddock/login-deny'
else
    set_allow "$vm" paddock.acme >>"$out/steps.txt"
    gssh "$vm" 'sudo systemctl restart himmelblaud himmelblaud-tasks'
    sleep 3
fi
if [[ "$(locked)" == yes ]]; then
    gdm key 01 81 >/dev/null; sleep 1; gdm key 39 b9 >/dev/null; sleep 3
    gdm type hello_pin_dave 1 >/dev/null
    sleep 6
fi
gdm shot 13-after-revert >/dev/null
echo "$(ts) after revert: LockedHint=$(locked)" | tee -a "$out/steps.txt"
gssh "$vm" 'sudo journalctl --since "-3min" --no-pager -o short-iso | grep -E "allowed groups|intersecting|pam_listfile|gkr-pam|gdm-password" | cut -c1-250' \
    >"$out/journal.log" 2>&1 || true
echo "$(ts) $vm $crit $verdict" | tee -a "$out/results.txt"
