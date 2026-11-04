#!/usr/bin/env bash
# Regression test (`make test`, PDK-729): openbao-configure.sh creates the Transit key backup-wrap exactly once over two
# runs, non-exportable and without plaintext backup; the api's policy may encrypt with it and never decrypt, the backup
# role's policy may decrypt (plan M15 decision 5). A fake docker plays OpenBao: it keeps keys and policies in a
# directory, so no stack is needed.
# shellcheck disable=SC2016 # check's conditions are expanded by its eval, not where they are written
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/bin" "$work/state" "$work/secrets"
failures=0

cat >"$work/bin/docker" <<'FAKE'
#!/usr/bin/env bash
# docker compose … exec -T [-e …] openbao bao <args>: everything before "openbao bao" is Compose's.
state="$FAKE_BAO_STATE"
while [[ $# -gt 0 && "$1" != openbao ]]; do shift; done
shift 2
case "$1 ${2:-}" in
  "secrets list") printf 'transit/\nsecret/\n' ;;
  "auth list") printf 'approle/\n' ;;
  "kv get") exit 0 ;;
  "policy write") cat >"$state/policy-$3" ;;
  "read -field=derived") echo true ;;
  "read -field=role_id") echo role-id ;;
  "write -f") echo secret-id ;;
  "read transit/keys/"*) [[ -e "$state/key-${2#transit/keys/}" ]] ;;
  "write transit/keys/"*)
    touch "$state/key-${2#transit/keys/}"
    echo "$*" >>"$state/key-writes"
    ;;
  *) : ;;
esac
FAKE
chmod +x "$work/bin/docker"

configure() {
  PATH="$work/bin:$PATH" FAKE_BAO_STATE="$work/state" SECRETS_DIR="$work/secrets" PADDOCK_ENV=development \
    BAO_TOKEN=test-token bash "$here/openbao-configure.sh" >/dev/null
}

check() {
  if eval "$2"; then
    echo "ok   $1"
  else
    echo "FAIL $1"
    failures=$((failures + 1))
  fi
}

configure
configure

writes="$(grep -c '^write transit/keys/backup-wrap ' "$work/state/key-writes" || true)"
check "backup-wrap created once over two runs (got $writes)" '[[ "$writes" == 1 ]]'
check "backup-wrap is aes256-gcm96, not exportable, no plaintext backup, not derived" \
  'grep -qx "write transit/keys/backup-wrap type=aes256-gcm96 exportable=false allow_plaintext_backup=false" "$work/state/key-writes"'
check "paddock-api may encrypt with backup-wrap" \
  'grep -q "^path \"transit/encrypt/backup-wrap\"" "$work/state/policy-paddock-api"'
check "paddock-api has no other path on backup-wrap" \
  '[[ "$(grep -c "backup-wrap" "$work/state/policy-paddock-api")" == 1 ]]'
check "paddock-backup may decrypt with backup-wrap" \
  'grep -q "^path \"transit/decrypt/backup-wrap\"" "$work/state/policy-paddock-backup"'
check "paddock-backup keeps the Raft snapshot" \
  'grep -q "^path \"sys/storage/raft/snapshot\"" "$work/state/policy-paddock-backup"'
for policy in "$work"/state/policy-*; do
  name="${policy##*/policy-}"
  [[ "$name" == paddock-backup ]] && continue
  check "$name cannot decrypt with backup-wrap" '! grep -q "transit/decrypt/backup-wrap" "$policy"'
done

if [[ "$failures" -gt 0 ]]; then
  echo "$failures check(s) failed"
  exit 1
fi
