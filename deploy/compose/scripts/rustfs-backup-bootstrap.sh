#!/usr/bin/env bash
# Development bootstrap of the backup bucket (plan M6a decision 4): bucket paddock-backup on the audit host's RustFS,
# without Object Lock, and one credential per writer (the same policies docs/operations/restore.md gives for
# production):
#   pgbackrest  everything below pgbackrest/ (pgBackRest expires old backups itself), read below openbao/ and fleet/
#               (the restore uses this credential), list
#   worker      write below openbao/, list (backup age of every kind)
#   fleet       write below fleet/
# Idempotent. Usage: rustfs-backup-bootstrap.sh [project] (default paddock; the restore drill uses its own project).
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
. "$here/lib.sh"

require_development

PROJECT="${1:-paddock}"
BUCKET="${PADDOCK_BACKUP_S3_BUCKET:-paddock-backup}"
NETWORK="${PROJECT}_audit-store"
ENDPOINT="http://audit-rustfs:9000"

AWS_ACCESS_KEY_ID="$(cat "$SECRETS_DIR/rustfs_audit_root_user")"
AWS_SECRET_ACCESS_KEY="$(cat "$SECRETS_DIR/rustfs_audit_root_password")"
export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY

aws() {
  docker run --rm -i --network "$NETWORK" -e AWS_ACCESS_KEY_ID -e AWS_SECRET_ACCESS_KEY \
    -e AWS_DEFAULT_REGION=us-east-1 -e AWS_PAGER= "$AWS_CLI_IMAGE" --endpoint-url "$ENDPOINT" "$@"
}
rc() {
  docker run --rm -i --network "$NETWORK" -e HOME=/tmp -e AWS_ACCESS_KEY_ID -e AWS_SECRET_ACCESS_KEY \
    -e USER_ACCESS_KEY -e USER_SECRET_KEY --entrypoint sh "$RC_IMAGE" -c \
    "rc alias set backup $ENDPOINT \"\$AWS_ACCESS_KEY_ID\" \"\$AWS_SECRET_ACCESS_KEY\" >/dev/null && $1"
}

for _ in $(seq 1 30); do
  if aws s3api list-buckets >/dev/null 2>&1; then break; fi
  sleep 1
done
if aws s3api head-bucket --bucket "$BUCKET" >/dev/null 2>&1; then
  echo "bucket $BUCKET exists"
else
  aws s3api create-bucket --bucket "$BUCKET" >/dev/null
  echo "created bucket $BUCKET"
fi

LIST="{\"Effect\":\"Allow\",\"Action\":[\"s3:ListBucket\",\"s3:GetBucketLocation\"],\"Resource\":[\"arn:aws:s3:::$BUCKET\"]}"
# policy <name> <statement>...: creates or replaces the policy.
policy() {
  local name="$1" IFS=,
  shift
  printf '{"Version":"2012-10-17","Statement":[%s]}' "$*" |
    rc "cat >/tmp/policy.json && rc admin policy create backup $name /tmp/policy.json >/dev/null"
}
objects() { printf '{"Effect":"Allow","Action":%s,"Resource":["arn:aws:s3:::%s/%s*"]}' "$1" "$BUCKET" "$2"; }
policy paddock-backup-pgbackrest "$(objects '["s3:PutObject","s3:GetObject","s3:DeleteObject"]' pgbackrest/)" \
  "$(objects '["s3:GetObject"]' openbao/)" "$(objects '["s3:GetObject"]' fleet/)" "$LIST"
policy paddock-backup-worker "$(objects '["s3:PutObject"]' openbao/)" "$LIST"
policy paddock-backup-fleet "$(objects '["s3:PutObject"]' fleet/)"

for role in pgbackrest worker fleet; do
  USER_ACCESS_KEY="$(cat "$SECRETS_DIR/backup_${role}_access_key")"
  USER_SECRET_KEY="$(cat "$SECRETS_DIR/backup_${role}_secret_key")"
  export USER_ACCESS_KEY USER_SECRET_KEY
  # Generated keys may start with "-", hence "--" before positional arguments and "--user=".
  if ! rc 'rc admin user info -- backup "$USER_ACCESS_KEY"' >/dev/null 2>&1; then
    rc 'rc admin user add -- backup "$USER_ACCESS_KEY" "$USER_SECRET_KEY" >/dev/null'
    echo "created backup user $role"
  fi
  rc "rc admin policy attach backup paddock-backup-$role --user=\"\$USER_ACCESS_KEY\" >/dev/null"
done
echo "backup bucket bootstrap complete"
