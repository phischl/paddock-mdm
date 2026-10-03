#!/usr/bin/env bash
# C7/C8 boot tests: reboots the VM and answers the Plymouth prompt ("Please enter LUKS2 token PIN") on the console.
#
# Usage: tpm/boot-test.sh <vm> pin          correct PIN unlocks
#        tpm/boot-test.sh <vm> wrong-pin    one wrong PIN is rejected ("Bad PIN"), then the correct PIN unlocks
#        tpm/boot-test.sh <vm> passphrase   the passphrase typed at the PIN prompt until the disk unlocks
#        tpm/boot-test.sh <vm> recovery     the recovery key (tpm/recovery-key.sh) the same way
#
# Each entry at the PIN prompt that is not the PIN counts as a TPM authorization failure. Once the TPM is in
# dictionary-attack lockout, systemd-cryptsetup falls back to the keyslots and reuses the cached entry. The
# passphrase/recovery modes therefore clear the lockout afterwards (test VMs only: lockout auth is empty).
set -euo pipefail

source "$(dirname "$0")/../lib.sh"
ensure_secrets
vm=${1:?usage: $0 <vm> pin|wrong-pin|passphrase|recovery}
mode=${2:?usage: $0 <vm> pin|wrong-pin|passphrase|recovery}
port=$(vm_port "$vm")
crit=C7; [[ "$mode" == recovery ]] && crit=C8
out=$(evidence_dir "$vm" "$crit")
pin=$(poc_secret tpm_pin)

type_line() {
    VBoxManage controlvm "$vm" keyboardputstring "$1"
    VBoxManage controlvm "$vm" keyboardputscancode 1c 9c
}

# Reboots (or starts) the VM and waits until the PIN prompt is expected.
reboot_to_prompt() {
    if [[ "$(vm_state "$vm")" == running ]] && ssh_ready "$port"; then
        gssh "$vm" 'sudo systemctl reboot' || true
        while ssh_ready "$port"; do sleep 1; done
    elif [[ "$(vm_state "$vm")" != running ]]; then
        VBoxManage startvm "$vm" --type headless >/dev/null
    fi
    sleep 30
    screenshot "$vm" "$out/$mode-prompt.png"
}

wait_ssh() {
    for _ in $(seq 1 "${1:-24}"); do
        ssh_ready "$port" && return 0
        sleep 5
    done
    return 1
}

# Enters $1 at the prompt up to $2 times until SSH answers; prints the number of entries.
enter_until_unlocked() {
    local secret=$1 max=$2 n
    for n in $(seq 1 "$max"); do
        type_line "$secret"
        sleep 10
        screenshot "$vm" "$out/$mode-after-entry-$n.png"
        if wait_ssh 4; then echo "$n"; return 0; fi
    done
    return 1
}

journal_evidence() {
    gssh "$vm" 'sudo journalctl -b -o short-iso-precise --no-pager | grep -E "systemd-cryptsetup|cryptsetup@|tss2" ;
        sudo tpm2_getcap properties-variable | grep -E "inLockout|LOCKOUT_COUNTER"' >"$out/$mode-journal.log" 2>&1 || true
}

started=$(ts)
reboot_to_prompt
result=FAIL
case "$mode" in
    pin)
        prompt_at=$(ts)
        type_line "$pin"
        if wait_ssh; then result=PASS; fi
        ;;
    wrong-pin)
        type_line "00000000"
        sleep 10
        screenshot "$vm" "$out/wrong-pin-after-wrong.png"
        if wait_ssh 2; then
            log "$vm: wrong PIN unlocked the disk"
        else
            type_line "$pin"
            if wait_ssh; then result=PASS; fi
        fi
        ;;
    passphrase)
        if entries=$(enter_until_unlocked "$PADDOCK_LUKS_PASSPHRASE" 6); then result="PASS (entries: $entries)"; fi
        ;;
    recovery)
        if entries=$(enter_until_unlocked "$(poc_secret recovery_key_"$vm")" 6); then result="PASS (entries: $entries)"; fi
        ;;
    *) die "unknown mode $mode" ;;
esac
finished=$(ts)

if ssh_ready "$port"; then
    journal_evidence
    gssh "$vm" 'mokutil --sb-state' >>"$out/$mode-journal.log" 2>&1 || true
    if [[ "$mode" == passphrase || "$mode" == recovery ]]; then
        gssh "$vm" 'sudo tpm2_dictionarylockout --clear-lockout' && log "$vm: cleared TPM DA lockout"
    fi
fi
printf '%s mode=%s started=%s prompt=%s unlocked=%s result=%s\n' "$vm" "$mode" "$started" "${prompt_at:-}" "$finished" "$result" | tee -a "$out/results.txt"
