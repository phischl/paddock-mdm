#!/bin/bash
# Copies the encrypted Fleet dumps of /dumps (fleet/backup.sh) to the backup bucket as fleet/<UTC time>.sql.gz.enc and
# deletes each local copy after its upload (plan M6a decision 6). Runs in the pinned AWS CLI image.
#
#   backup-upload.sh serve   upload every minute (the service's command)
#   backup-upload.sh once    upload now
#
# Settings: PADDOCK_BACKUP_S3_ENDPOINT, PADDOCK_BACKUP_S3_BUCKET, PADDOCK_BACKUP_S3_REGION,
# PADDOCK_BACKUP_S3_CA_FILE (optional), PADDOCK_BACKUP_S3_ACCESS_KEY_FILE, PADDOCK_BACKUP_S3_SECRET_KEY_FILE.
set -euo pipefail

# Credentials as inherited environment variables, never as command-line arguments.
AWS_ACCESS_KEY_ID="$(cat "$PADDOCK_BACKUP_S3_ACCESS_KEY_FILE")"
AWS_SECRET_ACCESS_KEY="$(cat "$PADDOCK_BACKUP_S3_SECRET_KEY_FILE")"
AWS_DEFAULT_REGION="${PADDOCK_BACKUP_S3_REGION:-us-east-1}"
export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_DEFAULT_REGION AWS_PAGER=
if [[ -n "${PADDOCK_BACKUP_S3_CA_FILE:-}" ]]; then export AWS_CA_BUNDLE="$PADDOCK_BACKUP_S3_CA_FILE"; fi

upload() {
  local f
  shopt -s nullglob
  for f in /dumps/*.sql.gz.enc; do
    aws --endpoint-url "$PADDOCK_BACKUP_S3_ENDPOINT" s3 cp --only-show-errors "$f" \
      "s3://$PADDOCK_BACKUP_S3_BUCKET/fleet/$(basename "$f")" || return 1
    rm -f "$f"
    echo "fleet backup: uploaded fleet/$(basename "$f")"
  done
}

case "${1:-serve}" in
  once) upload ;;
  serve)
    while true; do
      upload || echo "fleet backup: upload failed; retrying in a minute" >&2
      sleep 60
    done
    ;;
  *)
    echo "usage: backup-upload.sh serve|once" >&2
    exit 2
    ;;
esac
