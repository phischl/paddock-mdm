# shellcheck shell=bash
# Shared helpers for the Paddock VirtualBox test VMs. Source, do not execute.

VBOX_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SECRETS_DIR="$VBOX_DIR/.secrets"
WORK_DIR="$VBOX_DIR/work"
SSH_KEY="$SECRETS_DIR/id_ed25519"
CREDENTIALS_FILE="$SECRETS_DIR/credentials.env"

log() { printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*" >&2; }
die() { log "ERROR: $*"; exit 1; }

random_secret() {
    # Alphanumeric only: survives keyboardputstring regardless of special-char scancodes.
    LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c "${1:-24}"
}

# Creates the SSH key and credentials once; later runs reuse them.
ensure_secrets() {
    mkdir -p "$SECRETS_DIR"
    chmod 700 "$SECRETS_DIR"
    # Serialise parallel builds so they do not both generate secrets.
    exec {lock_fd}>"$SECRETS_DIR/.lock"
    flock "$lock_fd"
    if [[ ! -f "$SSH_KEY" ]]; then
        log "Generating SSH key $SSH_KEY"
        ssh-keygen -q -t ed25519 -N '' -C 'paddock-test-vms' -f "$SSH_KEY"
    fi
    if [[ ! -f "$CREDENTIALS_FILE" ]]; then
        log "Generating credentials $CREDENTIALS_FILE"
        umask 077
        cat >"$CREDENTIALS_FILE" <<EOF
# Paddock VirtualBox test VMs - generated $(date -Iseconds). Do not commit.
PADDOCK_USER=paddock
PADDOCK_PASSWORD=$(random_secret 20)
PADDOCK_LUKS_PASSPHRASE=$(random_secret 24)
EOF
    fi
    chmod 600 "$CREDENTIALS_FILE" "$SSH_KEY"
    flock -u "$lock_fd"
    # shellcheck disable=SC1090
    source "$CREDENTIALS_FILE"
}

# Retries once: showvminfo fails transiently while VBoxSVC unregisters another VM.
vm_exists() {
    VBoxManage showvminfo "$1" >/dev/null 2>&1 || { sleep 3; VBoxManage showvminfo "$1" >/dev/null 2>&1; }
}

vm_state() {
    VBoxManage showvminfo "$1" --machinereadable 2>/dev/null | sed -n 's/^VMState="\(.*\)"$/\1/p'
}

# VMState switches to "poweroff" while VBoxHeadless is still tearing down and
# writing the NVRAM file (UEFI variables + TPM state). Snapshotting or changing
# the VM in that window leaves an empty NVRAM behind (VirtualBox 7.2.16), which
# silently drops the Secure Boot keys. Wait for the process to be gone.
wait_vm_process_exit() {
    local vm=$1 waited=0
    while pgrep -f -- "[V]BoxHeadless --comment $vm --startvm" >/dev/null && ((waited < 60)); do
        sleep 1
        waited=$((waited + 1))
    done
    sleep 3
}

# wait_vm_state <vm> <state> <timeout-seconds> [poll-seconds]
wait_vm_state() {
    local vm=$1 want=$2 timeout=$3 poll=${4:-15} waited=0 state
    while :; do
        state=$(vm_state "$vm")
        if [[ "$state" == "$want" ]]; then
            [[ "$want" == poweroff ]] && wait_vm_process_exit "$vm"
            return 0
        fi
        ((waited >= timeout)) && { log "Timeout waiting for $vm to reach '$want' (is '$state')"; return 1; }
        sleep "$poll"
        waited=$((waited + poll))
    done
}

has_secure_boot_keys() {
    VBoxManage modifynvram "$1" listvars 2>/dev/null | grep -q '^PK '
}

# Initialises the UEFI variable store with Microsoft + Oracle keys and enables
# Secure Boot. The VM must be powered off.
enroll_secure_boot() {
    local vm=$1 attempt
    for attempt in 1 2 3; do
        VBoxManage modifynvram "$vm" inituefivarstore
        VBoxManage modifynvram "$vm" enrollmssignatures
        VBoxManage modifynvram "$vm" enrollorclpk
        VBoxManage modifynvram "$vm" secureboot --enable
        has_secure_boot_keys "$vm" && return 0
        log "$vm: Secure Boot keys missing after enrollment (attempt $attempt)"
        sleep 2
    done
    return 1
}

vm_ssh_port() {
    VBoxManage showvminfo "$1" --machinereadable | sed -n 's/^Forwarding([0-9]*)="ssh,tcp,[^,]*,\([0-9]*\),.*/\1/p' | head -1
}

ssh_opts() {
    printf '%s\n' -i "$SSH_KEY" -o IdentitiesOnly=yes -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=5 \
        -o BatchMode=yes
}

# vm_ssh <port> [command...]
vm_ssh() {
    local port=$1; shift
    local -a opts
    mapfile -t opts < <(ssh_opts)
    ssh "${opts[@]}" -p "$port" "${PADDOCK_USER:-paddock}@127.0.0.1" "$@"
}

ssh_ready() { vm_ssh "$1" true >/dev/null 2>&1; }

# Types the LUKS passphrase on the VM console followed by Enter.
type_luks_passphrase() {
    local vm=$1
    VBoxManage controlvm "$vm" keyboardputstring "$PADDOCK_LUKS_PASSPHRASE"
    VBoxManage controlvm "$vm" keyboardputscancode 1c 9c
}

# Boots past the LUKS prompt and waits until SSH answers. The VM must be running.
# Retypes the passphrase if SSH does not come up (prompt not ready yet / keys lost).
unlock_and_wait_ssh() {
    local vm=$1 port=$2 attempt waited
    for attempt in 1 2 3 4 5; do
        sleep 25
        if ssh_ready "$port"; then log "$vm: SSH ready"; return 0; fi
        log "$vm: typing LUKS passphrase (attempt $attempt)"
        type_luks_passphrase "$vm"
        for waited in $(seq 1 18); do
            sleep 5
            if ssh_ready "$port"; then log "$vm: SSH ready"; return 0; fi
        done
    done
    log "$vm: SSH not reachable; inspect with: VBoxManage controlvm $vm screenshotpng /tmp/$vm.png"
    return 1
}
