#!/usr/bin/env bash
# The ./paddock check item for the organization deletion's object-store users (PDK-1054d): each of the two offboarding
# policies is held by exactly one user, the one whose access key is in the key file. Prints one checklist item and exits
# 1 on FAIL. A store that cannot be listed is a WARN (the stack is down), never a pass.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$here/lib.sh"

NETWORK="${NETWORK:-${PADDOCK_PROJECT}_data}"
ENDPOINT="${ENDPOINT:-http://rustfs:9000}"
AWS_ACCESS_KEY_ID="$(cat "$SECRETS_DIR/rustfs_root_user")"
AWS_SECRET_ACCESS_KEY="$(cat "$SECRETS_DIR/rustfs_root_password")"
export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY
export_rc_host bundles "$ENDPOINT" AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY

rc() {
  docker run --rm -i --network "$NETWORK" -e HOME=/tmp -e RC_HOST_bundles --entrypoint sh "$RC_IMAGE" -c "$1"
}

offboard_users_check rc bundles "$(cat "$SECRETS_DIR/rustfs_bundles_offboard_access_key")" \
  "$(cat "$SECRETS_DIR/rustfs_escrow_offboard_access_key")" </dev/null
