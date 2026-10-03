#!/usr/bin/env bash
# Safe snapshot handling for the M1 PoC (plan decision 1). Every state change waits until VBoxHeadless has
# exited (VirtualBox 7.2.16 NVRAM pitfall, see test/vms/virtualbox/README.md).
#
# Usage: snapshot.sh shutdown <vm>          power off from inside the guest (falls back to ACPI, then poweroff)
#        snapshot.sh take <vm> <poc-m1-name> [description]
#        snapshot.sh restore <vm> <name>    restore any snapshot (incl. base-installed, which stays unchanged)
#        snapshot.sh list <vm>
set -euo pipefail

source "$(dirname "$0")/lib.sh"
ensure_secrets

shutdown_vm() {
    local vm=$1
    if [[ "$(vm_state "$vm")" == running ]]; then
        log "$vm: shutting down"
        gssh "$vm" 'sudo systemctl poweroff' >/dev/null 2>&1 || VBoxManage controlvm "$vm" acpipowerbutton || true
        if ! wait_vm_state "$vm" poweroff 180 5; then
            log "$vm: no clean shutdown, powering off"
            VBoxManage controlvm "$vm" poweroff || true
            wait_vm_state "$vm" poweroff 60 2
        fi
    fi
    # Also covers a VM that reports poweroff while VBoxHeadless still writes the NVRAM file.
    wait_vm_process_exit "$vm"
}

nvram_ok() {
    local f="$HOME/VirtualBox VMs/$1/$1.nvram"
    file "$f" | grep -q 'tar archive' || die "$1: NVRAM file is not a tar archive ($(file -b "$f"))"
}

cmd=${1:-}; vm=${2:-}
[[ -n "$cmd" && -n "$vm" ]] || die "usage: $0 shutdown|take|restore|list <vm> [name] [description]"
vm_exists "$vm" || die "VM $vm does not exist"

case "$cmd" in
    shutdown)
        shutdown_vm "$vm"
        ;;
    take)
        name=${3:-}
        [[ "$name" == poc-m1-* ]] || die "PoC snapshots must be named poc-m1-<phase>"
        if VBoxManage snapshot "$vm" list --machinereadable 2>/dev/null | grep -q "=\"$name\"$"; then
            die "$vm: snapshot $name exists; delete it manually first if it must be replaced"
        fi
        shutdown_vm "$vm"
        nvram_ok "$vm"
        VBoxManage snapshot "$vm" take "$name" --description "${4:-M1 PoC $name ($(date -I))}"
        # Make the current state an exact copy of the snapshot (as finalize-vm.sh does).
        VBoxManage snapshot "$vm" restore "$name"
        nvram_ok "$vm"
        log "$vm: snapshot $name taken"
        ;;
    restore)
        name=${3:-}
        [[ -n "$name" ]] || die "usage: $0 restore <vm> <name>"
        shutdown_vm "$vm"
        VBoxManage snapshot "$vm" restore "$name"
        nvram_ok "$vm"
        log "$vm: restored $name"
        ;;
    list)
        VBoxManage snapshot "$vm" list
        ;;
    *)
        die "unknown command $cmd"
        ;;
esac
