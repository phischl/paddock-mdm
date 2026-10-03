#!/usr/bin/env bash
# C4: dave signs in with the Hello PIN enrolled at the first login (checks/c1-login.sh); records the Authentik
# provider settings that make it work (refresh token grant, offline_access) and how the PIN is bound to the TPM.
#
# Usage: checks/c4-hello.sh <vm>
set -euo pipefail

source "$(dirname "$0")/../lib.sh"
ensure_secrets
vm=${1:?usage: $0 <vm>}
out=$(evidence_dir "$vm" C4)
verdict=PASS
ensure_running "$vm"

pam "$vm" gdm-password dave@acme.test authenticate acct_mgmt --pin "$(poc_secret hello_pin_dave)" --approve none \
    --timeout 40 >"$out/dave-pin-login.log" 2>&1 || verdict=FAIL
grep -q "Use the Linux Hello PIN" "$out/dave-pin-login.log" || { log "no PIN prompt"; verdict=FAIL; }
grep -q "Scan the QR code" "$out/dave-pin-login.log" && { log "device code requested despite PIN"; verdict=FAIL; }

log "$vm: one wrong PIN is rejected (three would invalidate the PIN: hello_pin_retry_count)"
if pam "$vm" gdm-password dave@acme.test authenticate --pin 99999999 --approve none --timeout 20 --once \
    >"$out/dave-wrong-pin.log" 2>&1; then
    log "wrong PIN accepted"; verdict=FAIL
fi
grep -q "Failed to authenticate with Hello PIN" "$out/dave-wrong-pin.log" || verdict=FAIL
pam "$vm" gdm-password dave@acme.test authenticate --pin "$(poc_secret hello_pin_dave)" --approve none \
    --timeout 40 >"$out/dave-pin-after-wrong.log" 2>&1 || verdict=FAIL

gssh "$vm" '
    echo "--- hsm_type (himmelblau.conf)"; grep -E "^\s*(hsm_type|tpm_tcti_name)" /etc/himmelblau/himmelblau.conf || echo "not set (default tpm_bound_soft_if_possible)"
    echo "--- aad-tool tpm"; sudo aad-tool tpm 2>&1 | sed "s/\x1b\[[0-9;]*m//g"
    echo "--- systemd-creds / TPM"; systemd-creds has-tpm2 2>&1 || true
    echo "--- journal (Hello)"; sudo journalctl -u himmelblaud --since "-2min" --no-pager -o short-iso | grep -i -E "hello|pin|refresh token" | cut -c1-250 | tail -15
' >"$out/binding.txt" 2>&1
"$POC_DIR/authentik-setup.sh" status 2>/dev/null | sed -n '/== provider/,/== application/p' >"$out/provider.json"
echo "$(ts) $vm C4 $verdict" | tee -a "$out/results.txt"
