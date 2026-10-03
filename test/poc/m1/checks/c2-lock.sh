#!/usr/bin/env bash
# C2: a lock in Authentik (membership in paddock:acme:locked + revocation of sessions, refresh and access tokens)
# refuses the next online login of erin; measures API call -> refusal; unlock restores the login.
# Precondition: erin has signed in on the VM once (Hello PIN enrolled), e.g. through checks/gdm.sh or
# checks/pamlogin.py.
#
# Usage: checks/c2-lock.sh <vm>
set -euo pipefail

source "$(dirname "$0")/../lib.sh"
ensure_secrets
vm=${1:?usage: $0 <vm>}
out=$(evidence_dir "$vm" C2)
pin=$(poc_secret hello_pin_erin)
verdict=PASS
ensure_running "$vm"

log "$vm: baseline login of erin"
pam "$vm" gdm-password erin@acme.test authenticate acct_mgmt --pin "$pin" >"$out/1-baseline.log" 2>&1 || {
    log "baseline login failed"; verdict=FAIL; }

log "$vm: lock erin"
"$POC_DIR/authentik-setup.sh" lock erin | tee "$out/2-lock.txt"
lock_start=$(sed -n 's/^lock_api_call_start=//p' "$out/2-lock.txt")

log "$vm: login of erin after the lock (PIN, then device code approved by erin)"
if pam "$vm" gdm-password erin@acme.test authenticate acct_mgmt --pin "$pin" --timeout 200 >"$out/3-after-lock.log" 2>&1; then
    log "erin was admitted after the lock"; verdict=FAIL
fi
refused_at=$(ts)
echo "lock_api_call_start=$lock_start refused_observed=$refused_at" | tee "$out/timing.txt"
python3 - "$lock_start" "$refused_at" <<'PY' | tee -a "$out/timing.txt"
import sys, datetime
p = lambda s: datetime.datetime.strptime(s, "%Y-%m-%dT%H:%M:%S.%fZ")
print("seconds_from_lock_to_refusal=%.1f" % (p(sys.argv[2]) - p(sys.argv[1])).total_seconds())
PY

log "$vm: unlock erin and log in again"
"$POC_DIR/authentik-setup.sh" unlock erin | tee "$out/4-unlock.txt"
pam "$vm" gdm-password erin@acme.test authenticate acct_mgmt --pin "$pin" --timeout 200 >"$out/5-after-unlock.log" 2>&1 || {
    log "login after unlock failed"; verdict=FAIL; }

gssh "$vm" 'sudo journalctl -u himmelblaud --since "-10min" --no-pager -o short-iso |
    grep -E "Refresh token|invalid_grant|Authentication successful|denied|expired|Hello|offline|online" | cut -c1-300' >"$out/himmelblaud.log" 2>&1 || true
echo "$(ts) $vm C2 $verdict" | tee -a "$out/results.txt"
