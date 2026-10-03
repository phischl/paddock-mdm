#!/usr/bin/env bash
# C9: keyslot inventory from the LUKS2 JSON metadata and a header backup (kept inside the guest, root only).
#
# Usage: tpm/inventory.sh <vm>
set -euo pipefail

source "$(dirname "$0")/../lib.sh"
ensure_secrets
vm=${1:?usage: $0 <vm>}
out=$(evidence_dir "$vm" C9)

gssh "$vm" 'sudo cryptsetup luksDump --dump-json-metadata "$(sudo blkid -t TYPE=crypto_LUKS -o device | head -1)"' >"$out/metadata.json"

# One line per keyslot: slot, type, the token that references it (none = passphrase/plain keyslot).
jq -r '
  (.tokens // {}) as $t
  | .keyslots | to_entries[]
  | .key as $slot
  | ([$t[] | select(.keyslots | index($slot)) | .type] | first // "none") as $token
  | "keyslot=\($slot) type=\(.value.type) token=\($token) kdf=\(.value.kdf.type)"
' "$out/metadata.json" | tee "$out/inventory.txt"
jq -r '.tokens | to_entries[] | "token=\(.key) type=\(.value.type) keyslots=\(.value.keyslots | join(",")) \(if .value.type == "systemd-tpm2" then "pcrs=\(.value["tpm2-pcrs"] | join(",")) pin=\(.value["tpm2-pin"])" else "" end)"' \
    "$out/metadata.json" | tee -a "$out/inventory.txt"

# Expected: one passphrase keyslot (no token), one systemd-tpm2 (PCR 7, PIN), one systemd-recovery.
expected=$'none\nsystemd-recovery\nsystemd-tpm2'
actual=$(jq -r '(.tokens // {}) as $t | .keyslots | keys[] as $s | [$t[] | select(.keyslots | index($s)) | .type] | first // "none"' "$out/metadata.json" | sort)
tpm_ok=$(jq -r '[.tokens[] | select(.type == "systemd-tpm2" and .["tpm2-pin"] == true and .["tpm2-pcrs"] == [7])] | length' "$out/metadata.json")
if [[ "$actual" == "$expected" && "$tpm_ok" == 1 ]]; then verdict=PASS; else verdict=FAIL; fi

size=$(gssh "$vm" '
    set -euo pipefail
    f=/var/backups/luks-header-$(date -u +%Y%m%d).img
    sudo rm -f "$f"
    sudo cryptsetup luksHeaderBackup "$(sudo blkid -t TYPE=crypto_LUKS -o device | head -1)" --header-backup-file "$f"
    sudo chmod 600 "$f"
    sudo stat -c "%n %s" "$f"')
echo "header backup: $size" | tee -a "$out/inventory.txt"
echo "$(ts) $vm C9 $verdict" | tee -a "$out/results.txt"
