#!/usr/bin/env bash
# Post-install steps for a VM whose autoinstall has finished (VM powered off):
# eject the installer ISO, first boot + LUKS unlock, apply all updates,
# power off and take the snapshot "base-installed".
#
# Usage: finalize-vm.sh <name>
set -euo pipefail

source "$(dirname "$0")/lib.sh"

SNAPSHOT=base-installed

(($# == 1)) || die "usage: $0 <name>"
name=$1
vm_exists "$name" || die "VM '$name' does not exist"
[[ "$(vm_state "$name")" == poweroff ]] || die "VM '$name' must be powered off"
ensure_secrets
port=$(vm_ssh_port "$name")
[[ -n "$port" ]] || die "no ssh port forward on $name"

log "Ejecting installer ISO"
VBoxManage storageattach "$name" --storagectl SATA --port 1 --device 0 --type dvddrive --medium emptydrive

boot_unlocked() {
    VBoxManage startvm "$name" --type headless >/dev/null
    unlock_and_wait_ssh "$name" "$port"
}

if ! has_secure_boot_keys "$name"; then
    log "WARNING: Secure Boot keys missing in NVRAM of $name, enrolling again"
    enroll_secure_boot "$name" || die "Secure Boot enrollment failed"
fi

log "First boot of $name"
boot_unlocked || die "first boot failed"
vm_ssh "$port" 'mokutil --sb-state' | grep -q 'SecureBoot enabled' || die "Secure Boot is not enabled in the guest"

log "Applying updates"
vm_ssh "$port" 'sudo cloud-init status --wait >/dev/null 2>&1 || true;
    export DEBIAN_FRONTEND=noninteractive;
    sudo -E apt-get -o DPkg::Lock::Timeout=900 update -q &&
    sudo -E apt-get -o DPkg::Lock::Timeout=900 -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold full-upgrade -yq &&
    sudo -E apt-get -o DPkg::Lock::Timeout=900 autoremove --purge -yq' \
    || die "apt upgrade failed"

if vm_ssh "$port" 'test -f /var/run/reboot-required'; then
    log "Reboot required after updates"
    vm_ssh "$port" 'sudo systemctl poweroff' || true
    wait_vm_state "$name" poweroff 300 5 || die "VM did not power off"
    boot_unlocked || die "boot after updates failed"
fi

log "Powering off $name"
vm_ssh "$port" 'sudo systemctl poweroff' || true
wait_vm_state "$name" poweroff 300 5 || die "VM did not power off"

if VBoxManage snapshot "$name" list --machinereadable 2>/dev/null | grep -q "=\"$SNAPSHOT\"$"; then
    log "Snapshot $SNAPSHOT already exists, not taking another"
else
    VBoxManage snapshot "$name" take "$SNAPSHOT" --description "Fresh Ubuntu install, LUKS2 passphrase, Secure Boot, updates applied ($(date -I))"
fi
# Make the current state an exact copy of the snapshot (incl. NVRAM/TPM state).
VBoxManage snapshot "$name" restore "$SNAPSHOT"
log "Done: $name (snapshot $SNAPSHOT). Start with: $VBOX_DIR/start-vm.sh $name"
