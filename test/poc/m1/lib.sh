# shellcheck shell=bash
# shellcheck disable=SC2034 # the variables are used by the scripts that source this file
# Shared helpers for the M1 proof of concept (docs/plans/M1-poc-login-and-disk.md). Source, do not execute.

POC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$POC_DIR/../../.." && pwd)"
POC_SECRETS="$POC_DIR/.secrets"
POC_OUT="$POC_DIR/out"
STACK_SECRETS="$REPO_ROOT/deploy/compose/.secrets"
CADDY_ROOT="$STACK_SECRETS/caddy-root.crt"

# shellcheck source=../../vms/virtualbox/lib.sh
source "$REPO_ROOT/test/vms/virtualbox/lib.sh"

# Hostname the VMs use for Authentik (plan decision 5) and the address it resolves to inside the guest.
AUTH_HOST="${AUTH_HOST:-auth.paddock.localhost}"
AUTH_PORT="${AUTH_PORT:-8443}"
AUTH_URL="https://$AUTH_HOST:$AUTH_PORT"
HOST_FROM_GUEST=10.0.2.2

ts() { date -u +%FT%T.%3NZ; }

# vm_port <vm> prints the forwarded SSH port of a VM.
vm_port() {
    case "$1" in
        paddock-u2404) echo 2224 ;;
        paddock-u2604) echo 2226 ;;
        *) die "unknown VM $1" ;;
    esac
}

# gssh <vm> [command...] runs a command in the guest as the local admin "paddock".
gssh() {
    local vm=$1; shift
    vm_ssh "$(vm_port "$vm")" "$@"
}

# evidence_dir <vm> <criterion> creates and prints out/<vm>/<criterion>/.
evidence_dir() {
    local d="$POC_OUT/$1/$2"
    mkdir -p "$d"
    echo "$d"
}

# screenshot <vm> <file> saves the VM console as PNG.
screenshot() { VBoxManage controlvm "$1" screenshotpng "$2" >/dev/null; }

# curl_auth <curl-args...> calls Authentik from the host by the guest-facing hostname (resolved to 127.0.0.1).
curl_auth() {
    curl -sS --cacert "$CADDY_ROOT" --resolve "$AUTH_HOST:$AUTH_PORT:127.0.0.1" "$@"
}

# poc_secret <name> prints a PoC secret written by authentik-setup.sh.
poc_secret() { cat "$POC_SECRETS/$1"; }

# ensure_running <vm> starts the VM headless (typing the LUKS passphrase) unless SSH already answers.
ensure_running() {
    local vm=$1
    ssh_ready "$(vm_port "$vm")" && return 0
    "$REPO_ROOT/test/vms/virtualbox/start-vm.sh" "$1" >/dev/null
}

# pam <vm> <service> <user> <ops...> [--pin P] [--password P] [--approve U] runs pamtester in the guest and
# answers the conversation (checks/pamlogin.py); prints the transcript.
pam() {
    local vm=$1; shift
    "$POC_DIR/checks/pamlogin.py" "$(vm_port "$vm")" "$@"
}

# set_allow <vm> <value> sets pam_allow_groups in the guest's himmelblau.conf (empty value = line "pam_allow_groups =").
set_allow() {
    gssh "$1" "sudo sed -i 's|^pam_allow_groups *=.*|pam_allow_groups = $2|' /etc/himmelblau/himmelblau.conf && grep '^pam_allow_groups' /etc/himmelblau/himmelblau.conf"
}
