#!/usr/bin/env bash
# C7 prerequisite on Ubuntu 24.04: replace initramfs-tools by dracut so the initramfs unlocks LUKS with
# systemd-cryptsetup (TPM2 token support). Records the package transaction and the initramfs content, then
# reboots once with the passphrase to prove the dracut initramfs boots before any TPM enrollment.
#
# Usage: tpm/dracut-switch.sh <vm>
set -euo pipefail

source "$(dirname "$0")/../lib.sh"
ensure_secrets
vm=${1:?usage: $0 <vm>}
port=$(vm_port "$vm")
out=$(evidence_dir "$vm" C7)

log "$vm: installing dracut"
gssh "$vm" '
    set -euo pipefail
    dpkg-query -W -f="\${Package} \${Version} \${Status}\n" | grep " installed$" | sort >/tmp/pkgs-before.txt
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y dracut 2>&1 | grep -E "^(The following|  |Removing|Setting up dracut|Purging)" || true
    dpkg-query -W -f="\${Package} \${Version} \${Status}\n" | grep " installed$" | sort >/tmp/pkgs-after.txt
    echo "--- package diff (before/after)"
    diff /tmp/pkgs-before.txt /tmp/pkgs-after.txt || true
    echo "--- residual config of removed packages (dpkg rc)"
    dpkg -l | awk "/^rc/ {print \$2, \$3}"
    echo "--- /etc/initramfs-tools left behind"
    ls -la /etc/initramfs-tools 2>&1 || true
    echo "--- dracut configuration (distribution defaults)"
    grep -rHv "^\s*#" /usr/lib/dracut/dracut.conf.d/ /etc/dracut.conf.d/ /etc/dracut.conf 2>/dev/null | grep -v ":\s*$" || true
' 2>&1 | tee "$out/dracut-switch.log"

log "$vm: dracut configuration for LUKS + TPM2 and initramfs rebuild"
gssh "$vm" '
    set -euo pipefail
    # hostonly puts /etc/crypttab into the initramfs (the generic image has none, and Ubuntu passes no rd.luks.*
    # on the kernel command line). systemd-cryptsetup (TPM2 token plugin) needs the systemd-based initramfs;
    # tpm2-tss adds the TSS libraries. plymouth is left out: dracut 060 cannot install it on 24.04
    # (plymouth-set-default-theme is not shipped), so the prompt is the text console.
    printf "%s\n" "# Paddock M1 PoC: LUKS unlock via systemd-cryptsetup with TPM2+PIN" "hostonly=\"yes\"" \
        "add_dracutmodules+=\" systemd crypt tpm2-tss lvm \"" | sudo tee /etc/dracut.conf.d/90-paddock-tpm2.conf
    sudo dracut -f --regenerate-all 2>&1 | grep -E "dracut\[[EW]\]" || true
    sudo lsinitrd -f etc/crypttab "/boot/initrd.img-$(uname -r)" | grep -q . || { echo "crypttab missing in initramfs" >&2; exit 1; }
    echo "--- initramfs content (tpm2/cryptsetup)"
    sudo lsinitrd "/boot/initrd.img-$(uname -r)" 2>/dev/null | grep -E "libtss2|systemd-cryptsetup|cryptsetup-token-systemd-tpm2|etc/crypttab" | awk "{print \$NF}" | sort -u
    echo "--- dracut modules"
    sudo lsinitrd -m "/boot/initrd.img-$(uname -r)" 2>/dev/null | sed -n "/dracut modules:/,/^=/p" | tr "\n" " "; echo
' 2>&1 | tee -a "$out/dracut-switch.log"

log "$vm: reboot with passphrase (dracut initramfs, before enrollment)"
gssh "$vm" 'sudo systemctl reboot' || true
while ssh_ready "$port"; do sleep 1; done
unlock_and_wait_ssh "$vm" "$port"
gssh "$vm" 'echo "--- boot after switch"; uname -r; mokutil --sb-state; findmnt -n -o SOURCE /;
    sudo journalctl -b -o short-iso-precise --no-pager | grep -E "systemd-cryptsetup|dracut" | head -10' 2>&1 | tee -a "$out/dracut-switch.log"
