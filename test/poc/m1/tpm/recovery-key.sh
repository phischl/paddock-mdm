#!/usr/bin/env bash
# C8 step 1: adds a systemd-cryptenroll recovery key slot and stores the key in .secrets/recovery_key_<vm>.
# Boot test afterwards: tpm/boot-test.sh <vm> recovery.
#
# Usage: tpm/recovery-key.sh <vm>
set -euo pipefail

source "$(dirname "$0")/../lib.sh"
ensure_secrets
vm=${1:?usage: $0 <vm>}
out=$(evidence_dir "$vm" C8)
key_file="$POC_SECRETS/recovery_key_$vm"

if gssh "$vm" 'sudo cryptsetup luksDump "$(sudo blkid -t TYPE=crypto_LUKS -o device | head -1)"' | grep -q systemd-recovery; then
    [[ -s "$key_file" ]] || die "$vm has a recovery slot but $key_file is missing"
    log "$vm: recovery key already enrolled"
else
    umask 077
    # The key is printed on stdout only; the passphrase travels over stdin.
    printf '%s\n' "$PADDOCK_LUKS_PASSPHRASE" | gssh "$vm" '
        set -euo pipefail
        read -r pass
        dev=$(sudo blkid -t TYPE=crypto_LUKS -o device | head -1)
        sudo env PASSWORD="$pass" systemd-cryptenroll --recovery-key "$dev" 2>/dev/null' \
        | grep -E '^[cbdefghijklnrtuv]{8}(-[cbdefghijklnrtuv]{8}){7}$' >"$key_file"
    [[ -s "$key_file" ]] || die "$vm: no recovery key received"
    log "$vm: recovery key stored in $key_file"
fi
gssh "$vm" 'sudo cryptsetup luksDump "$(sudo blkid -t TYPE=crypto_LUKS -o device | head -1)" | sed -n "/^Tokens:/,/^Digests:/p"' \
    | tee "$out/tokens-after-enroll.txt"
