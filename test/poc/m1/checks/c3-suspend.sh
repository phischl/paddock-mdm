#!/usr/bin/env bash
# C3: device-wide login suspension by changing only Himmelblau's allow list (pam_allow_groups). Directory users
# are refused, the local admin "paddock" still logs in (gdm-password PAM stack with password, and SSH);
# reverting restores directory logins. Tests whether a daemon restart is needed and what an empty list does.
# Precondition: dave has signed in once (Hello PIN), e.g. checks/c1-login.sh.
#
# Usage: checks/c3-suspend.sh <vm>
set -euo pipefail

source "$(dirname "$0")/../lib.sh"
ensure_secrets
vm=${1:?usage: $0 <vm>}
out=$(evidence_dir "$vm" C3)
pin=$(poc_secret hello_pin_dave)
verdict=PASS
ensure_running "$vm"

dave_login() {  # dave_login <evidence-name>; returns pamtester's result
    pam "$vm" gdm-password dave@acme.test authenticate acct_mgmt --pin "$pin" --approve none --timeout 40 >"$out/$1.log" 2>&1
}
paddock_checks() {  # paddock_checks <evidence-name>; local admin via the GDM PAM stack and via SSH
    pam "$vm" gdm-password paddock authenticate acct_mgmt open_session close_session --password "$PADDOCK_PASSWORD" \
        >"$out/$1-paddock-gdm-password.log" 2>&1 &&
        gssh "$vm" 'echo "ssh as $(id -un) ok"' >"$out/$1-paddock-ssh.log" 2>&1
}

log "$vm: allow list = paddock.acme (baseline)"
set_allow "$vm" paddock.acme >"$out/0-config.txt"
gssh "$vm" 'sudo systemctl restart himmelblaud himmelblaud-tasks'
dave_login 0-dave-baseline || { log "baseline dave login failed"; verdict=FAIL; }

log "$vm: empty allow list after a daemon restart (documented: all users permitted)"
set_allow "$vm" "" >>"$out/0-config.txt"
gssh "$vm" 'sudo systemctl restart himmelblaud himmelblaud-tasks'
if dave_login 1-dave-empty-list; then echo "empty list: dave ADMITTED" ; else echo "empty list: dave refused"; fi | tee "$out/1-result.txt"

log "$vm: suspension = allow list with a group nobody has, no daemon restart"
set_allow "$vm" paddock.acme >>"$out/0-config.txt"
gssh "$vm" 'sudo systemctl restart himmelblaud himmelblaud-tasks'
set_allow "$vm" paddock.suspended >>"$out/0-config.txt"
suspended_at=$(ts)
if dave_login 2-dave-suspended-no-restart; then
    echo "no restart: dave ADMITTED" | tee "$out/2-result.txt"
    log "$vm: restarting himmelblaud"
    gssh "$vm" 'sudo systemctl restart himmelblaud himmelblaud-tasks'
    if dave_login 3-dave-suspended-after-restart; then
        echo "after restart: dave ADMITTED" | tee "$out/3-result.txt"; verdict=FAIL
    else
        echo "after restart: dave refused" | tee "$out/3-result.txt"
    fi
else
    echo "no restart: dave refused ($(ts), config changed $suspended_at)" | tee "$out/2-result.txt"
fi
paddock_checks 4-suspended || { log "local admin refused while suspended"; verdict=FAIL; }

log "$vm: revert allow list"
set_allow "$vm" paddock.acme >>"$out/0-config.txt"
if ! dave_login 5-dave-reverted; then
    gssh "$vm" 'sudo systemctl restart himmelblaud himmelblaud-tasks'
    echo "revert needed a restart" | tee "$out/5-result.txt"
    dave_login 5-dave-reverted-after-restart || { log "dave refused after revert"; verdict=FAIL; }
fi
echo "$(ts) $vm C3 $verdict" | tee -a "$out/results.txt"
