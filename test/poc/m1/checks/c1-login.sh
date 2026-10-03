#!/usr/bin/env bash
# C1 (PAM level): dave signs in through the gdm-password PAM stack with password + TOTP verified by Authentik
# (device authorization, approved from the host), enrolls a Hello PIN, gets a home directory and keeps UID/GID
# across logins; frank (paddock:globex only) is refused. Start from snapshot poc-m1-himmelblau.
# The graphical GDM path is checks/c1-gdm.sh.
#
# Usage: checks/c1-login.sh <vm>
set -euo pipefail

source "$(dirname "$0")/../lib.sh"
ensure_secrets
vm=${1:?usage: $0 <vm>}
out=$(evidence_dir "$vm" C1)
ensure_running "$vm"
pin=$(poc_secret hello_pin_dave)
verdict=PASS

log "$vm: first login of dave (device code, password + TOTP, Hello PIN enrollment)"
pam "$vm" gdm-password dave@acme.test authenticate acct_mgmt open_session close_session --pin "$pin" \
    >"$out/dave-first-login.log" 2>&1 || verdict=FAIL
grep -q "akflow: default-authentication-flow ak-stage-authenticator-validate" "$out/dave-first-login.log" || {
    log "TOTP stage was not part of the Authentik flow"; verdict=FAIL; }
first=$(gssh "$vm" 'getent passwd dave@acme.test')

log "$vm: second login of dave (Hello PIN)"
pam "$vm" gdm-password dave@acme.test authenticate acct_mgmt open_session close_session --pin "$pin" \
    >"$out/dave-second-login.log" 2>&1 || verdict=FAIL
second=$(gssh "$vm" 'getent passwd dave@acme.test')
gssh "$vm" 'getent passwd dave@acme.test; id dave@acme.test; ls -la /home/; sudo ls -la "$(getent passwd dave@acme.test | cut -d: -f6)/"' \
    >"$out/identity.txt" 2>&1
[[ "$first" == "$second" && -n "$first" ]] || { log "passwd entry changed: $first -> $second"; verdict=FAIL; }
gssh "$vm" 'test -d "$(getent passwd dave@acme.test | cut -d: -f6)"' || { log "no home directory"; verdict=FAIL; }

log "$vm: frank@globex.test must be refused"
if pam "$vm" gdm-password frank@globex.test authenticate acct_mgmt --approve frank@globex.test \
    >"$out/frank.log" 2>&1; then
    log "frank was admitted"; verdict=FAIL
fi
gssh "$vm" 'getent passwd frank@globex.test || echo "frank: no passwd entry"' >>"$out/frank.log" 2>&1

gssh "$vm" 'sudo journalctl -u himmelblaud --since "-10min" --no-pager -o short-iso |
    grep -E "allowed groups|intersecting|Authentication successful|denied|expired|error" | cut -c1-300' >"$out/himmelblaud.log" 2>&1 || true
echo "$(ts) $vm C1-pam $verdict" | tee -a "$out/results.txt"
