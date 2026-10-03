#!/usr/bin/env bash
# C5c (only if C5a or C5b fail): adds the pam_listfile deny line of architecture §9.5 to /etc/pam.d/common-account
# and repeats C5a and C5b with dave in /etc/paddock/login-deny; with the file absent, logins work (fail safe).
# "remove" takes the line out again.
#
# Usage: checks/c5c-listfile.sh <vm> [install|run|remove]   (default: install + run)
set -euo pipefail

source "$(dirname "$0")/../lib.sh"
ensure_secrets
vm=${1:?usage: $0 <vm> [install|run|remove]}
action=${2:-all}
out=$(evidence_dir "$vm" C5c)
LINE='account required pam_listfile.so item=user sense=deny file=/etc/paddock/login-deny onerr=succeed'

if [[ "$action" == install || "$action" == all ]]; then
    gssh "$vm" "grep -qF 'pam_listfile.so item=user sense=deny' /etc/pam.d/common-account ||
        sudo sed -i '0,/^account/s||$LINE\n&|' /etc/pam.d/common-account
        grep -v '^#' /etc/pam.d/common-account | grep -v '^\s*$'" | tee "$out/common-account.txt"
fi
if [[ "$action" == run || "$action" == all ]]; then
    log "$vm: fail safe - no deny file, dave logs in"
    gssh "$vm" 'sudo rm -f /etc/paddock/login-deny'
    if pam "$vm" gdm-password dave@acme.test authenticate acct_mgmt --pin "$(poc_secret hello_pin_dave)" --approve none \
        --timeout 40 >"$out/failsafe-no-file.log" 2>&1; then
        echo "no deny file: dave admitted"
    else
        echo "no deny file: dave REFUSED"
    fi
    log "$vm: C5a with the deny file"
    "$POC_DIR/checks/c5a-offline.sh" "$vm" deny-list
    log "$vm: C5b with the deny file"
    "$POC_DIR/checks/c5b-unlock.sh" "$vm" deny-list
fi | tee -a "$out/run.txt"
if [[ "$action" == remove ]]; then
    gssh "$vm" "sudo sed -i '\\|pam_listfile.so item=user sense=deny|d' /etc/pam.d/common-account; sudo rm -f /etc/paddock/login-deny"
fi
