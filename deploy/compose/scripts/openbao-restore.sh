# Restore of an OpenBao Raft snapshot into a fresh OpenBao (restore-drill.sh step 4, openbao-restore_test.sh). Sourced,
# not executed.
# shellcheck shell=bash
#
# The caller defines `bao` (runs the bao CLI in the OpenBao container with BAO_ADDR set and BAO_TOKEN passed when set)
# and `bao_restart` (restarts the container), and has put the plain snapshot at /tmp/snapshot inside the container.

# openbao_status is `bao status` as JSON; its exit code (2 while sealed) would fail a pipeline under pipefail.
openbao_status() { bao status -format=json 2>/dev/null || true; }

# openbao_wait waits until OpenBao answers.
openbao_wait() {
  for _ in $(seq 1 60); do
    if openbao_status | grep -q '"initialized"'; then return 0; fi
    sleep 1
  done
  echo "OpenBao does not answer" >&2
  return 1
}

# openbao_unsealed waits until OpenBao reports unsealed.
openbao_unsealed() {
  for _ in $(seq 1 30); do
    if openbao_status | grep -q '"sealed": false'; then return 0; fi
    sleep 1
  done
  echo "OpenBao is still sealed" >&2
  return 1
}

# openbao_restore_snapshot <workdir> <init file>: initializes the fresh OpenBao with one temporary share, restores
# /tmp/snapshot, restarts it and unseals it with the first three shares of the original init file ("Unseal Key <n>:
# <share>" lines, as `bao operator init` prints them).
openbao_restore_snapshot() {
  local work="$1" init_file="$2" tmp_key i
  # shellcheck disable=SC2034 # the caller's bao reads it (dynamic scope)
  local BAO_TOKEN
  # A fresh OpenBao takes a snapshot only after its own initialization; the snapshot brings back the original
  # barrier and seal configuration.
  bao operator init -key-shares=1 -key-threshold=1 -format=json >"$work/init.json"
  tmp_key="$(grep -A1 '"unseal_keys_b64"' "$work/init.json" | tail -1 | tr -d ' ",')"
  BAO_TOKEN="$(grep '"root_token"' "$work/init.json" | cut -d'"' -f4)"
  bao operator unseal "$tmp_key" >/dev/null
  openbao_unsealed
  bao operator raft snapshot restore -force /tmp/snapshot
  # shellcheck disable=SC2034 # the original shares unseal without the temporary root token
  BAO_TOKEN=
  # After the restore the node seals itself but keeps the temporary seal configuration (one share) in memory, so the
  # original shares are refused ("invalid key size 33"); a restart reads the restored configuration (OpenBao 2.7.1).
  bao_restart
  openbao_wait
  for i in 1 2 3; do
    bao operator unseal "$(sed -n "s/^Unseal Key $i: //p" "$init_file")" >/dev/null
  done
  openbao_unsealed
}
