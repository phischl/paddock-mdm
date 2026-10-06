#!/usr/bin/env bash
# Development bootstrap of the control-plane buckets: paddock-bundles (plan M2a decision 3) and
# paddock-agent-artifacts (plan M2b decision 19; public-read below packages/, plan M4b decision 1), both without
# versioning and without Object Lock, and paddock-escrow (plan M4b decision 13, versioning on, no Object Lock); a
# user for the compiler with read/write on bundles, a user for the api with read/write on artifacts and read on
# escrow, a user for the worker with read on escrow, and a user for the gateway with read-only access to bundles and
# artifacts and write access to escrowed headers only (the gateway only computes presigned URLs with it).
# Idempotent.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
. "$here/lib.sh"

require_development

BUCKET="${PADDOCK_BUNDLES_S3_BUCKET:-paddock-bundles}"
ARTIFACTS_BUCKET="${PADDOCK_ARTIFACTS_S3_BUCKET:-paddock-agent-artifacts}"
ESCROW_BUCKET="${PADDOCK_ESCROW_S3_BUCKET:-paddock-escrow}"
NETWORK="paddock_cp"
ENDPOINT="http://rustfs:9000"

AWS_ACCESS_KEY_ID="$(cat "$SECRETS_DIR/rustfs_root_user")"
AWS_SECRET_ACCESS_KEY="$(cat "$SECRETS_DIR/rustfs_root_password")"
COMPILER_ACCESS_KEY="$(cat "$SECRETS_DIR/rustfs_bundles_compiler_access_key")"
COMPILER_SECRET_KEY="$(cat "$SECRETS_DIR/rustfs_bundles_compiler_secret_key")"
GATEWAY_ACCESS_KEY="$(cat "$SECRETS_DIR/rustfs_bundles_gateway_access_key")"
GATEWAY_SECRET_KEY="$(cat "$SECRETS_DIR/rustfs_bundles_gateway_secret_key")"
ARTIFACTS_ACCESS_KEY="$(cat "$SECRETS_DIR/rustfs_artifacts_api_access_key")"
ARTIFACTS_SECRET_KEY="$(cat "$SECRETS_DIR/rustfs_artifacts_api_secret_key")"
ESCROW_WORKER_ACCESS_KEY="$(cat "$SECRETS_DIR/rustfs_escrow_worker_access_key")"
ESCROW_WORKER_SECRET_KEY="$(cat "$SECRETS_DIR/rustfs_escrow_worker_secret_key")"
ESCROW_API_ACCESS_KEY="$(cat "$SECRETS_DIR/rustfs_escrow_api_access_key")"
ESCROW_API_SECRET_KEY="$(cat "$SECRETS_DIR/rustfs_escrow_api_secret_key")"
export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY COMPILER_ACCESS_KEY COMPILER_SECRET_KEY GATEWAY_ACCESS_KEY GATEWAY_SECRET_KEY \
  ARTIFACTS_ACCESS_KEY ARTIFACTS_SECRET_KEY ESCROW_WORKER_ACCESS_KEY ESCROW_WORKER_SECRET_KEY ESCROW_API_ACCESS_KEY \
  ESCROW_API_SECRET_KEY

# Credentials travel as inherited environment variables, never as command-line arguments.
aws() {
  docker run --rm -i --network "$NETWORK" -e AWS_ACCESS_KEY_ID -e AWS_SECRET_ACCESS_KEY \
    -e AWS_DEFAULT_REGION=us-east-1 -e AWS_PAGER= "$AWS_CLI_IMAGE" --endpoint-url "$ENDPOINT" "$@"
}
rc() {
  docker run --rm -i --network "$NETWORK" -e HOME=/tmp -e AWS_ACCESS_KEY_ID -e AWS_SECRET_ACCESS_KEY \
    -e COMPILER_ACCESS_KEY -e COMPILER_SECRET_KEY -e GATEWAY_ACCESS_KEY -e GATEWAY_SECRET_KEY \
    -e ARTIFACTS_ACCESS_KEY -e ARTIFACTS_SECRET_KEY -e ESCROW_WORKER_ACCESS_KEY -e ESCROW_WORKER_SECRET_KEY \
    -e ESCROW_API_ACCESS_KEY -e ESCROW_API_SECRET_KEY \
    --entrypoint sh "$RC_IMAGE" -c \
    "rc alias set bundles $ENDPOINT \"\$AWS_ACCESS_KEY_ID\" \"\$AWS_SECRET_ACCESS_KEY\" >/dev/null && $1"
}

for _ in $(seq 1 30); do
  if aws s3api list-buckets >/dev/null 2>&1; then break; fi
  sleep 1
done

for b in "$BUCKET" "$ARTIFACTS_BUCKET" "$ESCROW_BUCKET"; do
  if aws s3api head-bucket --bucket "$b" >/dev/null 2>&1; then
    echo "bucket $b exists"
  else
    aws s3api create-bucket --bucket "$b" >/dev/null
    echo "created bucket $b"
  fi
done

# policy <name> <statements>: create or replace a policy.
policy() {
  printf '{"Version":"2012-10-17","Statement":%s}' "$2" |
    rc "cat >/tmp/policy.json && rc admin policy create bundles $1 /tmp/policy.json >/dev/null"
}
# user <access key variable> <policy>: create the user once and attach the policy. Generated keys may start with
# "-", hence "--" before positional arguments and "--user=".
user() {
  if ! rc "rc admin user info -- bundles \"\$$1\"" >/dev/null 2>&1; then
    rc "rc admin user add -- bundles \"\$$1\" \"\$${1/ACCESS/SECRET}\" >/dev/null"
    echo "created bundles user for $2"
  fi
  rc "rc admin policy attach bundles $2 --user=\"\$$1\" >/dev/null"
}

policy paddock-bundles-compiler "[
  {\"Effect\":\"Allow\",\"Action\":[\"s3:PutObject\",\"s3:GetObject\"],\"Resource\":[\"arn:aws:s3:::$BUCKET/*\"]},
  {\"Effect\":\"Allow\",\"Action\":[\"s3:ListBucket\"],\"Resource\":[\"arn:aws:s3:::$BUCKET\"]}]"
policy paddock-bundles-gateway "[
  {\"Effect\":\"Allow\",\"Action\":[\"s3:GetObject\"],\"Resource\":[\"arn:aws:s3:::$BUCKET/*\",\"arn:aws:s3:::$ARTIFACTS_BUCKET/*\"]},
  {\"Effect\":\"Allow\",\"Action\":[\"s3:PutObject\"],\"Resource\":[\"arn:aws:s3:::$ESCROW_BUCKET/org/*/devices/*/luks-header/*\"]}]"
policy paddock-artifacts-api "[
  {\"Effect\":\"Allow\",\"Action\":[\"s3:PutObject\",\"s3:GetObject\"],\"Resource\":[\"arn:aws:s3:::$ARTIFACTS_BUCKET/*\"]}]"
# Escrowed headers keep every version (an overwritten generation stays recoverable); no Object Lock, so a Destroy can
# delete them (architecture §12.4).
aws s3api put-bucket-versioning --bucket "$ESCROW_BUCKET" --versioning-configuration Status=Enabled
echo "versioning of $ESCROW_BUCKET enabled"

# Agent packages are public-read (plan M4b decision 1): anonymous GetObject below packages/ only; listing and every
# other prefix still need credentials or a presigned URL.
printf '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":["*"]},"Action":["s3:GetObject"],"Resource":["arn:aws:s3:::%s/packages/*"]}]}' \
  "$ARTIFACTS_BUCKET" | aws s3api put-bucket-policy --bucket "$ARTIFACTS_BUCKET" --policy file:///dev/stdin
echo "packages/ of $ARTIFACTS_BUCKET is public-read"

user COMPILER_ACCESS_KEY paddock-bundles-compiler
user GATEWAY_ACCESS_KEY paddock-bundles-gateway
policy paddock-escrow-read "[
  {\"Effect\":\"Allow\",\"Action\":[\"s3:GetObject\"],\"Resource\":[\"arn:aws:s3:::$ESCROW_BUCKET/*\"]}]"
user ARTIFACTS_ACCESS_KEY paddock-artifacts-api
user ESCROW_WORKER_ACCESS_KEY paddock-escrow-read
user ESCROW_API_ACCESS_KEY paddock-escrow-read
echo "bundles, agent artifacts and escrow bucket bootstrap complete"
