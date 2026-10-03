#!/usr/bin/env bash
# Prints the baseline facts of a running, unlocked Paddock test VM over SSH.
#
# Usage: verify-vm.sh <name>
set -euo pipefail

source "$(dirname "$0")/lib.sh"

(($# == 1)) || die "usage: $0 <name>"
name=$1
ensure_secrets
port=$(vm_ssh_port "$name")
ssh_ready "$port" || die "$name is not reachable on port $port (run start-vm.sh first)"

vm_ssh "$port" bash -s <<'EOF'
run() { printf '\n$ %s\n' "$*"; bash -c "$*" 2>&1; }
luks=$(lsblk -nrpo NAME,FSTYPE | awk '$2 == "crypto_LUKS" {print $1; exit}')
run lsb_release -a
run cat /proc/cmdline
run lsblk -f
run "sudo cryptsetup luksDump $luks | head -40"
run 'ls /dev/tpm*'
run 'sudo tpm2_getcap properties-fixed | head -20'
run mokutil --sb-state
run systemctl is-active ssh gdm
run timedatectl show -p NTPSynchronized
run 'systemctl is-active systemd-timesyncd chrony 2>/dev/null'
run "ls /usr/lib/dracut 2>/dev/null; dpkg -l | grep -E 'dracut|initramfs-tools'"
EOF
