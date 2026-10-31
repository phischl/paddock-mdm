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

# owner_secrets_dir prints the VM secrets directory of the repository's main checkout when this is a linked worktree
# (empty in the main checkout): the VMs exist once per host and only the checkout that created them knows their LUKS
# passphrase, SSH key and password (PDK-541).
owner_secrets_dir() {
    local common top
    common=$(git -C "$VBOX_DIR" rev-parse --path-format=absolute --git-common-dir 2>/dev/null) || return 0
    top=$(git -C "$VBOX_DIR" rev-parse --show-toplevel 2>/dev/null) || return 0
    [[ "$(dirname "$common")" != "$top" ]] || return 0
    printf '%s' "$(dirname "$common")/${VBOX_DIR#"$top"/}/.secrets"
}

# link_owner_secrets makes .secrets of a linked worktree a symlink to the main checkout's VM secrets. A worktree never
# gets credentials of its own: they would not match the VMs, whose disk unlock then fails on every boot. Refuses when
# the worktree already has credentials of its own that differ from the owner's.
link_owner_secrets() {
    local owner
    owner=$(owner_secrets_dir)
    [[ -n "$owner" && ! -L "$SECRETS_DIR" ]] || return 0
    [[ -f "$owner/credentials.env" ]] ||
        die "no VM secrets in the main checkout ($owner): create the VMs there; a worktree never creates VM credentials"
    if [[ -d "$SECRETS_DIR" && ! -L "$SECRETS_DIR" ]]; then
        # An empty directory or an exact copy of the owner's secrets is replaced; anything else is someone's to look at.
        if [[ -n "$(find "$SECRETS_DIR" -mindepth 1 ! -name .lock -print -quit)" ]] &&
            ! diff -rq -x .lock "$SECRETS_DIR" "$owner" >/dev/null 2>&1; then
            die "$SECRETS_DIR holds VM secrets of its own, which do not match the VMs; move it away and run again (it is then linked to $owner)"
        fi
        rm -rf "$SECRETS_DIR"
    fi
    # Atomic, and never into an existing link: both VMs of `make system-test VM=all` start in parallel, and a second
    # plain `ln -s` would follow the first link and create a link inside the owner's directory.
    ln -s "$owner" "$SECRETS_DIR.tmp.$$"
    mv -T "$SECRETS_DIR.tmp.$$" "$SECRETS_DIR" 2>/dev/null || rm -f "$SECRETS_DIR.tmp.$$"
    [[ -L "$SECRETS_DIR" ]] || die "could not link $SECRETS_DIR to $owner"
    log "Linked $SECRETS_DIR to the VM secrets of the main checkout ($owner)"
}

# Creates the SSH key and credentials once in the main checkout; later runs and linked worktrees reuse them.
ensure_secrets() {
    link_owner_secrets
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

# Seconds between two key events on the console. One keyboardputstring of the whole passphrase lost keystrokes under
# host load (two failed unlocks in one run, PDK-541); one character per call, paced, did not.
KEY_DELAY="${PADDOCK_VM_KEY_DELAY:-0.15}"

# Types the LUKS passphrase on the VM console followed by Enter: first Backspaces clear what an earlier, partly lost
# attempt left in the prompt, then one character at a time.
type_luks_passphrase() {
    local vm=$1 i
    local -a backspaces=()
    for ((i = 0; i < 40; i++)); do backspaces+=(0e 8e); done
    VBoxManage controlvm "$vm" keyboardputscancode "${backspaces[@]}"
    sleep "$KEY_DELAY"
    for ((i = 0; i < ${#PADDOCK_LUKS_PASSPHRASE}; i++)); do
        VBoxManage controlvm "$vm" keyboardputstring "${PADDOCK_LUKS_PASSPHRASE:i:1}"
        sleep "$KEY_DELAY"
    done
    VBoxManage controlvm "$vm" keyboardputscancode 1c 9c
}

# passphrase_fingerprint is a short hash of the LUKS passphrase of the current secrets; start-vm.sh keeps the one of the
# VM in its extradata, so secrets that do not belong to the VM stop the start at once instead of after every unlock
# attempt (PDK-541). The passphrase is random and 24 characters long, so the hash reveals nothing usable.
FINGERPRINT_KEY=paddock/luks-passphrase-sha256
passphrase_fingerprint() { printf '%s' "$PADDOCK_LUKS_PASSPHRASE" | sha256sum | cut -c1-16; }

# vm_fingerprint is empty when none is recorded or VBoxManage fails (VBoxSVC fails transiently, see vm_exists).
vm_fingerprint() {
    { VBoxManage getextradata "$1" "$FINGERPRINT_KEY" 2>/dev/null || true; } | sed -n 's/^Value: //p'
}

# check_passphrase_fingerprint dies when the VM records the fingerprint of another passphrase.
check_passphrase_fingerprint() {
    local vm=$1 want
    want=$(vm_fingerprint "$vm")
    [[ -z "$want" || "$want" == "$(passphrase_fingerprint)" ]] ||
        die "$vm: the LUKS passphrase in $CREDENTIALS_FILE is not the VM's (VM was set up with other secrets); use the secrets of the checkout that created the VM"
}

record_passphrase_fingerprint() {
    VBoxManage setextradata "$1" "$FINGERPRINT_KEY" "$(passphrase_fingerprint)"
}

# console_screenshot <vm> <label> saves the console to work/<vm>/ and prints the path.
console_screenshot() {
    local vm=$1 file
    file="$WORK_DIR/$vm/console-$2-$(date +%Y%m%d-%H%M%S).png"
    mkdir -p "$WORK_DIR/$vm"
    VBoxManage controlvm "$vm" screenshotpng "$file" >/dev/null 2>&1 && printf '%s' "$file"
}

# Boots past the LUKS prompt and waits until SSH answers. The VM must be running.
# Retypes the passphrase if SSH does not come up (prompt not ready yet / keys lost).
# A successful unlock records the passphrase fingerprint (check_passphrase_fingerprint); a failed one leaves a console
# screenshot per attempt.
unlock_and_wait_ssh() {
    local vm=$1 port=$2 attempt waited shot
    check_passphrase_fingerprint "$vm"
    for attempt in 1 2 3 4 5; do
        sleep "${UNLOCK_SETTLE:-25}"
        if ssh_ready "$port"; then unlocked "$vm"; return 0; fi
        if ((attempt > 1)) && shot=$(console_screenshot "$vm" "attempt-$((attempt - 1))"); then
            log "$vm: unlock attempt $((attempt - 1)) failed; console: $shot"
        fi
        log "$vm: typing LUKS passphrase (attempt $attempt)"
        type_luks_passphrase "$vm"
        for waited in $(seq 1 "${UNLOCK_POLLS:-18}"); do
            sleep "${UNLOCK_POLL:-5}"
            if ssh_ready "$port"; then unlocked "$vm"; return 0; fi
        done
    done
    shot=$(console_screenshot "$vm" failed) || shot="(no screenshot: VBoxManage controlvm $vm screenshotpng failed)"
    log "$vm: disk not unlocked after 5 attempts (LUKS passphrase rejected or keystrokes lost); console: $shot"
    return 1
}

unlocked() {
    log "$1: SSH ready"
    [[ -n "$(vm_fingerprint "$1")" ]] || record_passphrase_fingerprint "$1" ||
        log "$1: could not record the passphrase fingerprint"
}
