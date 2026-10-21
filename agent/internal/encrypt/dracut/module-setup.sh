#!/bin/bash
# Paddock in-place encryption (plan M8e decision 15): the init step that converts the root partition to LUKS2 at the
# restart after the agent prepared it. The module is part of an initrd only while the host carries the plan and the
# conversion key; dracut sources this file, the functions are its module API.
# shellcheck disable=SC2154 # initdir, moddir, systemdsystemunitdir and SYSTEMCTL are set by dracut

# paddock_layout prints PADDOCK_LAYOUT of the host's plan.
paddock_layout() {
    local _k _v
    while IFS='=' read -r _k _v; do
        if [[ $_k == PADDOCK_LAYOUT ]]; then
            echo "$_v"
            return 0
        fi
    done < "${dracutsysrootdir-}/var/lib/paddock/encrypt/plan.env"
}

check() {
    # Without the plan the module is a no-op in every other initrd build.
    [[ -f ${dracutsysrootdir-}/var/lib/paddock/encrypt/plan.env ]] || return 1
    return 0
}

depends() {
    if [[ $(paddock_layout) == lvm ]]; then
        echo systemd crypt lvm
    else
        echo systemd crypt
    fi
    return 0
}

installkernel() {
    # dracut ignores install()'s status but stops on installkernel()'s and keeps the previous initrd: an initrd with the
    # plan but without the key could neither convert nor open the disk.
    if [[ ! -f ${dracutsysrootdir-}/var/lib/paddock/install-passphrase ]]; then
        dfatal "paddock-encrypt: /var/lib/paddock/install-passphrase is missing"
        return 1
    fi
    # A host without LUKS has no dm-crypt in a hostonly initrd; the conversion needs it and the ciphers.
    hostonly='' instmods dm_crypt dm_mod =crypto
}

install() {
    inst_multiple cryptsetup e2fsck resize2fs dumpe2fs blockdev blkid udevadm mkdir rm sleep readlink
    inst_multiple -o plymouth
    if [[ $(paddock_layout) == lvm ]]; then
        inst_multiple lvm
    fi
    inst_simple /var/lib/paddock/encrypt/plan.env /etc/paddock/encrypt-plan.env
    inst_simple /var/lib/paddock/install-passphrase /etc/paddock/encrypt-key
    chmod 0600 "$initdir/etc/paddock/encrypt-plan.env" "$initdir/etc/paddock/encrypt-key"
    inst_simple "$moddir/paddock-encrypt-init.sh" /usr/libexec/paddock/encrypt-init.sh
    inst_simple "$moddir/paddock-encrypt-init.service" "$systemdsystemunitdir/paddock-encrypt-init.service"
    $SYSTEMCTL -q --root "$initdir" enable paddock-encrypt-init.service
    # dracut's crypt module would otherwise ask for a passphrase for the partition this module opens, holding the boot
    # at a prompt nobody can answer (plan M8e amendment 2026-10-21); the preflight refuses hosts with other LUKS volumes.
    mkdir -p "$initdir/etc/cmdline.d"
    echo "rd.luks=0" > "$initdir/etc/cmdline.d/91paddock-encrypt.conf"
    # Dev builds only (plan M8e decision 19): the marker that lets the init script honour the test delays.
    if [[ -f ${dracutsysrootdir-}/var/lib/paddock/encrypt/test-hooks ]]; then
        inst_simple /var/lib/paddock/encrypt/test-hooks /etc/paddock/encrypt-test
    fi
}
