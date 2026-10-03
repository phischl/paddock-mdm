#!/usr/bin/env bash
# Builds a Paddock test VM: EFI + Secure Boot (MS keys) + TPM 2.0, Ubuntu Desktop
# installed unattended with LUKS2/LVM full-disk encryption, then snapshot "base-installed".
#
# Usage: create-vm.sh [--force] [--no-wait] <name> <iso> <ssh-port>
#   --force    delete an existing VM of the same name first
#   --no-wait  only create and start the installer; skip first boot, upgrade and snapshot
set -euo pipefail

source "$(dirname "$0")/lib.sh"

SNAPSHOT=base-installed
CPUS=2
MEMORY_MB=4096
DISK_MB=40960
VRAM_MB=128
INSTALL_TIMEOUT=$((120 * 60))

force=0
wait_install=1
args=()
for arg in "$@"; do
    case "$arg" in
        --force) force=1 ;;
        --no-wait) wait_install=0 ;;
        -h|--help) sed -n '2,9p' "$0"; exit 0 ;;
        -*) die "unknown option $arg" ;;
        *) args+=("$arg") ;;
    esac
done
((${#args[@]} == 3)) || die "usage: $0 [--force] [--no-wait] <name> <iso> <ssh-port>"
name=${args[0]}
iso=$(realpath "${args[1]}")
port=${args[2]}
[[ -f "$iso" ]] || die "ISO not found: $iso"
[[ "$port" =~ ^[0-9]+$ ]] || die "invalid port: $port"
for tool in VBoxManage xorriso ssh ssh-keygen openssl python3; do
    command -v "$tool" >/dev/null || die "missing tool: $tool"
done

if vm_exists "$name"; then
    ((force)) || die "VM '$name' already exists (use --force to recreate)"
    log "Deleting existing VM $name"
    [[ "$(vm_state "$name")" == running ]] && VBoxManage controlvm "$name" poweroff || true
    wait_vm_process_exit "$name"
    VBoxManage unregistervm "$name" --delete
fi

ensure_secrets

# --- Render autoinstall config and remaster the ISO -------------------------
vm_work="$WORK_DIR/$name"
mkdir -p "$vm_work"
chmod 700 "$vm_work"   # rendered config contains the LUKS passphrase

password_hash=$(openssl passwd -6 "$PADDOCK_PASSWORD")
HOSTNAME_="$name" USERNAME_="$PADDOCK_USER" PASSWORD_HASH_="$password_hash" \
LUKS_="$PADDOCK_LUKS_PASSPHRASE" PUBKEY_="$(cat "$SSH_KEY.pub")" \
python3 - "$VBOX_DIR/autoinstall/autoinstall.yaml.tmpl" "$vm_work/autoinstall.yaml" <<'PY'
import os, sys
text = open(sys.argv[1]).read()
for key, env in [("HOSTNAME", "HOSTNAME_"), ("USERNAME", "USERNAME_"),
                 ("PASSWORD_HASH", "PASSWORD_HASH_"), ("LUKS_PASSPHRASE", "LUKS_"),
                 ("SSH_PUBKEY", "PUBKEY_")]:
    text = text.replace(f"@@{key}@@", os.environ[env])
open(sys.argv[2], "w").write(text)
PY
chmod 600 "$vm_work/autoinstall.yaml"

# Boot straight into the installer with the "autoinstall" flag (no confirmation prompt).
rm -f "$vm_work/grub.cfg.orig"
xorriso -osirrox on -indev "$iso" -extract /boot/grub/grub.cfg "$vm_work/grub.cfg.orig" >/dev/null 2>&1
sed -e 's/^set timeout=.*/set timeout=3/' \
    -e '0,/\/casper\/vmlinuz  *---/s//\/casper\/vmlinuz autoinstall ---/' \
    "$vm_work/grub.cfg.orig" >"$vm_work/grub.cfg"
grep -q 'vmlinuz autoinstall ---' "$vm_work/grub.cfg" || die "could not patch grub.cfg"

install_iso="$vm_work/install.iso"
log "Remastering $iso -> $install_iso"
rm -f "$install_iso"
xorriso -indev "$iso" -outdev "$install_iso" \
    -map "$vm_work/autoinstall.yaml" /autoinstall.yaml \
    -map "$vm_work/grub.cfg" /boot/grub/grub.cfg \
    -boot_image any replay >"$vm_work/xorriso.log" 2>&1 || { tail -20 "$vm_work/xorriso.log"; die "xorriso failed"; }

# --- Create the VM ----------------------------------------------------------
machine_folder=$(VBoxManage list systemproperties | sed -n 's/^Default machine folder: *//p')
disk="$machine_folder/$name/$name.vdi"

log "Creating VM $name"
VBoxManage createvm --name "$name" --ostype Ubuntu_64 --register >/dev/null
VBoxManage modifyvm "$name" \
    --firmware=efi --tpm-type=2.0 \
    --cpus=$CPUS --memory=$MEMORY_MB \
    --graphicscontroller=vmsvga --vram=$VRAM_MB \
    --ioapic=on --rtc-use-utc=on \
    --audio-enabled=off --usb-ohci=off --usb-ehci=off --usb-xhci=off \
    --nic1=nat --natpf1="ssh,tcp,127.0.0.1,$port,,22" \
    --boot1=disk --boot2=dvd --boot3=none --boot4=none
enroll_secure_boot "$name" || die "Secure Boot enrollment failed"

VBoxManage createmedium disk --filename "$disk" --size $DISK_MB --format VDI --variant Standard >/dev/null
VBoxManage storagectl "$name" --name SATA --add sata --controller IntelAhci --portcount 2 --bootable on
VBoxManage storageattach "$name" --storagectl SATA --port 0 --device 0 --type hdd --medium "$disk" --nonrotational on --discard on
VBoxManage storageattach "$name" --storagectl SATA --port 1 --device 0 --type dvddrive --medium "$install_iso"

log "Starting installer for $name (headless)"
VBoxManage startvm "$name" --type headless >/dev/null

if ((!wait_install)); then
    log "Installer running. Finish later with: $VBOX_DIR/finalize-vm.sh $name"
    exit 0
fi

log "Waiting for the installer to power off the VM (up to $((INSTALL_TIMEOUT / 60)) min)"
wait_vm_state "$name" poweroff "$INSTALL_TIMEOUT" 30 || die "installation did not finish"

exec "$VBOX_DIR/finalize-vm.sh" "$name"
