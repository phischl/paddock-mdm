#!/usr/bin/env bash
# Starts a Paddock test VM headless, types the LUKS passphrase and waits for SSH.
#
# Usage: start-vm.sh [--no-unlock] <name>
#   --no-unlock  only start the VM (e.g. once disk unlock is TPM2-based)
set -euo pipefail

source "$(dirname "$0")/lib.sh"

unlock=1
if [[ "${1:-}" == --no-unlock ]]; then unlock=0; shift; fi
(($# == 1)) || die "usage: $0 [--no-unlock] <name>"
name=$1
vm_exists "$name" || die "VM '$name' does not exist"
ensure_secrets
port=$(vm_ssh_port "$name")

[[ "$(vm_state "$name")" == running ]] || VBoxManage startvm "$name" --type headless >/dev/null
if ((unlock)); then
    unlock_and_wait_ssh "$name" "$port"
fi
echo "ssh -i $SSH_KEY -o IdentitiesOnly=yes -p $port $PADDOCK_USER@127.0.0.1"
