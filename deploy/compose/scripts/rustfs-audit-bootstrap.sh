#!/usr/bin/env bash
# Development bootstrap of the WORM audit bucket (plan M0 §6.8): bucket paddock-audit with Object Lock, default
# retention COMPLIANCE / 400 days, writer user restricted to put/get/list/retention. Idempotent.
# Refuses to continue when the bucket exists without Object Lock (Object Lock cannot be enabled afterwards).
# Production: follow docs/operations/audit-bucket.md.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
. "$here/lib.sh"

require_development

BUCKET="${PADDOCK_AUDIT_S3_BUCKET:-paddock-audit}"
DEFAULT_RETENTION_DAYS=400
NETWORK="paddock_audit-store"
ENDPOINT="http://audit-rustfs:9000"

AWS_ACCESS_KEY_ID="$(cat "$SECRETS_DIR/rustfs_audit_root_user")"
AWS_SECRET_ACCESS_KEY="$(cat "$SECRETS_DIR/rustfs_audit_root_password")"
WRITER_ACCESS_KEY="$(cat "$SECRETS_DIR/rustfs_audit_writer_access_key")"
WRITER_SECRET_KEY="$(cat "$SECRETS_DIR/rustfs_audit_writer_secret_key")"
export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY WRITER_ACCESS_KEY WRITER_SECRET_KEY

# Credentials travel as inherited environment variables, never as command-line arguments.
aws() {
  docker run --rm -i --network "$NETWORK" -e AWS_ACCESS_KEY_ID -e AWS_SECRET_ACCESS_KEY \
    -e AWS_DEFAULT_REGION=us-east-1 -e AWS_PAGER= "$AWS_CLI_IMAGE" --endpoint-url "$ENDPOINT" "$@"
}
rc() {
  docker run --rm -i --network "$NETWORK" -e HOME=/tmp -e AWS_ACCESS_KEY_ID -e AWS_SECRET_ACCESS_KEY \
    -e WRITER_ACCESS_KEY -e WRITER_SECRET_KEY --entrypoint sh "$RC_IMAGE" -c \
    "rc alias set audit $ENDPOINT \"\$AWS_ACCESS_KEY_ID\" \"\$AWS_SECRET_ACCESS_KEY\" >/dev/null && $1"
}

for _ in $(seq 1 30); do
  if aws s3api list-buckets >/dev/null 2>&1; then break; fi
  sleep 1
done

if aws s3api head-bucket --bucket "$BUCKET" >/dev/null 2>&1; then
  if ! aws s3api get-object-lock-configuration --bucket "$BUCKET" 2>/dev/null | grep -q '"ObjectLockEnabled": "Enabled"'; then
    echo "refusing: bucket $BUCKET exists WITHOUT Object Lock. It cannot be used for audit evidence." >&2
    echo "Delete it manually (it holds no locked objects) or choose another bucket name." >&2
    exit 1
  fi
  echo "bucket $BUCKET exists with Object Lock"
else
  aws s3api create-bucket --bucket "$BUCKET" --object-lock-enabled-for-bucket >/dev/null
  echo "created bucket $BUCKET with Object Lock"
fi

aws s3api put-object-lock-configuration --bucket "$BUCKET" --object-lock-configuration \
  "{\"ObjectLockEnabled\":\"Enabled\",\"Rule\":{\"DefaultRetention\":{\"Mode\":\"COMPLIANCE\",\"Days\":$DEFAULT_RETENTION_DAYS}}}"
echo "default retention COMPLIANCE / $DEFAULT_RETENTION_DAYS days"

policy=$(cat <<JSON
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["s3:PutObject", "s3:PutObjectRetention", "s3:GetObject", "s3:GetObjectRetention"],
      "Resource": ["arn:aws:s3:::$BUCKET/*"]
    },
    {
      "Effect": "Allow",
      "Action": ["s3:ListBucket", "s3:GetBucketObjectLockConfiguration"],
      "Resource": ["arn:aws:s3:::$BUCKET"]
    }
  ]
}
JSON
)

printf '%s' "$policy" | rc 'cat >/tmp/policy.json && rc admin policy create audit paddock-audit-writer /tmp/policy.json >/dev/null'
# Generated keys may start with "-", hence "--" before positional arguments and "--user=".
if ! rc 'rc admin user info -- audit "$WRITER_ACCESS_KEY"' >/dev/null 2>&1; then
  rc 'rc admin user add -- audit "$WRITER_ACCESS_KEY" "$WRITER_SECRET_KEY" >/dev/null'
  echo "created audit writer user"
fi
rc 'rc admin policy attach audit paddock-audit-writer --user="$WRITER_ACCESS_KEY" >/dev/null'
echo "audit bucket bootstrap complete"
