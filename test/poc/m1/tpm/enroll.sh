#!/usr/bin/env bash
# C7 step 1: enroll a TPM2+PIN token (PCR 7) next to the passphrase slot, make the initramfs try it and rebuild the
# initramfs with dracut. The passphrase slot is kept (it is the recovery path of the test VMs).
# 24.04 must have been switched to dracut first (tpm/dracut-switch.sh).
#
# Usage: tpm/enroll.sh <vm>
set -euo pipefail

source "$(dirname "$0")/../lib.sh"
ensure_secrets
vm=${1:?usage: $0 <vm>}
out=$(evidence_dir "$vm" C7)
pin_file="$POC_SECRETS/tpm_pin"
[[ -s "$pin_file" ]] || die "missing $pin_file (8 digits, created by the README setup)"

dpkg_has_dracut=$(gssh "$vm" 'dpkg-query -W -f="\${Status}" dracut 2>/dev/null || true')
[[ "$dpkg_has_dracut" == *"ok installed"* ]] || die "$vm: dracut is not installed; run tpm/dracut-switch.sh first"

log "$vm: enrolling TPM2+PIN token"
{
    echo "# $(ts) enroll on $vm"
    # Secrets travel over stdin, never on a command line.
    printf '%s\n%s\n' "$PADDOCK_LUKS_PASSPHRASE" "$(cat "$pin_file")" | gssh "$vm" '
        set -euo pipefail
        read -r pass; read -r pin
        dev=$(sudo blkid -t TYPE=crypto_LUKS -o device | head -1)
        echo "device: $dev"
        if sudo cryptsetup luksDump "$dev" | grep -q "systemd-tpm2"; then
            echo "tpm2 token already enrolled"
        else
            sudo env PASSWORD="$pass" NEWPIN="$pin" systemd-cryptenroll --tpm2-device=auto --tpm2-with-pin=yes --tpm2-pcrs=7 "$dev"
        fi
        echo "exit: $?"'
} 2>&1 | tee "$out/enroll.log"

log "$vm: crypttab tpm2-device=auto and initramfs rebuild"
gssh "$vm" '
    set -euo pipefail
    if ! grep -q "tpm2-device=auto" /etc/crypttab; then
        sudo sed -i -E "/^\s*#/! s/^(\S+\s+\S+\s+\S+\s+)(\S+)/\1\2,tpm2-device=auto/" /etc/crypttab
    fi
    echo "--- /etc/crypttab"; cat /etc/crypttab
    sudo dracut -f --regenerate-all 2>&1 | tail -5
    echo "--- initramfs content (tpm2/cryptsetup)"
    sudo lsinitrd "/boot/initrd.img-$(uname -r)" 2>/dev/null | grep -E "libtss2|systemd-cryptsetup|cryptsetup-token-systemd-tpm2|crypttab|tpm_tis|tpm_crb" | awk "{print \$NF}" | sort -u
    echo "--- luksDump"; sudo cryptsetup luksDump "$(sudo blkid -t TYPE=crypto_LUKS -o device | head -1)" | sed -n "/^Keyslots:/,\$p" | grep -E "^\s+[0-9]+: |Keyslot:|tpm2-pcrs|tpm2-pin|tpm2-pcr-bank" ' 2>&1 | tee "$out/initramfs.log"
