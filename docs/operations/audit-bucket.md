# Audit bucket runbook

The audit evidence lives in the bucket `paddock-audit` of the audit domain's object store (RustFS by default,
ADR 0017; Ceph RGW or an external S3 provider with Object Lock are supported alternatives). Every audit object is
written with Object Lock **COMPLIANCE** retention; nobody, including the object store's root account, can delete it
or shorten its retention before the retention date. The acceptance gate `TestWORM` (A1) proves exactly that.

## Why the bucket is created once and correctly

- **Object Lock can only be enabled when a bucket is created.** A bucket created without Object Lock can never hold
  audit evidence; it must be replaced, and objects cannot be moved into a new bucket without rewriting them.
- **COMPLIANCE retention cannot be undone.** Once objects exist, a mistake (wrong bucket, wrong retention, test data
  in production) cannot be cleaned up before the retention date — 400 days by default. Test against a separate
  bucket or object store, never against the production bucket.
- Therefore the production bucket is created by this one-shot procedure and verified before Paddock writes to it.
  `rustfs-audit-bootstrap.sh` refuses to continue when the bucket already exists without Object Lock.

## 1. One-shot creation (production)

Run on the audit host, with the object store's root credentials loaded into the environment from your secret store
(never on the command line). The commands match `deploy/compose/scripts/rustfs-audit-bootstrap.sh`, which does the
same automatically in development and refuses to run with `PADDOCK_ENV=production`.

```sh
export AWS_ACCESS_KEY_ID=… AWS_SECRET_ACCESS_KEY=…   # root credentials of the audit object store
ENDPOINT=https://audit-s3.internal.example.org

# 1. bucket with Object Lock (implies versioning)
aws --endpoint-url "$ENDPOINT" s3api create-bucket --bucket paddock-audit --object-lock-enabled-for-bucket

# 2. default retention: COMPLIANCE, 400 days (the platform minimum; per-object retention may only be longer)
aws --endpoint-url "$ENDPOINT" s3api put-object-lock-configuration --bucket paddock-audit \
  --object-lock-configuration '{"ObjectLockEnabled":"Enabled","Rule":{"DefaultRetention":{"Mode":"COMPLIANCE","Days":400}}}'

# 3. verify
aws --endpoint-url "$ENDPOINT" s3api get-object-lock-configuration --bucket paddock-audit
```

Then create the writer credential with a policy that allows only `s3:PutObject`, `s3:PutObjectRetention`,
`s3:GetObject`, `s3:GetObjectRetention` on `arn:aws:s3:::paddock-audit/*` and `s3:ListBucket` and
`s3:GetBucketObjectLockConfiguration` (read-only; `make prod-check HOST=audit ONLINE=1` verifies the bucket with it) on
`arn:aws:s3:::paddock-audit` (RustFS: `rc admin policy create`, `rc admin user add`, `rc admin policy attach`; see the
development script for the exact policy document). No operator account receives `s3:DeleteObject`,
`s3:BypassGovernanceRetention` or `s3:PutBucketPolicy` on this bucket.

Configure a replication target outside the audit host's failure domain (architecture §14.4) before going live.

## 2. Verification with the WORM gate

Run the acceptance gate against the new bucket **before** pointing the audit writer at it. The gate writes one test
object (`acceptance/worm/<uuid>.bin`, 4 KiB) with a retention of one day and then tries to delete it, shorten and
weaken its retention with the root and the writer credential. That object stays in the bucket until its retention
ends — this is the only test data the production bucket may ever contain.

The gate reads the credentials from files named like the development secrets. Prepare a private directory (mode
0700) on the operator workstation:

```sh
mkdir -m 700 /tmp/worm-check
printf '%s' "$ROOT_ACCESS_KEY"   > /tmp/worm-check/rustfs_audit_root_user
printf '%s' "$ROOT_SECRET_KEY"   > /tmp/worm-check/rustfs_audit_root_password
printf '%s' "$WRITER_ACCESS_KEY" > /tmp/worm-check/rustfs_audit_writer_access_key
printf '%s' "$WRITER_SECRET_KEY" > /tmp/worm-check/rustfs_audit_writer_secret_key

PADDOCK_SECRETS_DIR=/tmp/worm-check \
PADDOCK_TEST_AUDIT_S3_ENDPOINT=https://audit-s3.internal.example.org \
PADDOCK_TEST_AUDIT_S3_BUCKET=paddock-audit \
make acceptance T=TestWORM

shred -u /tmp/worm-check/*; rmdir /tmp/worm-check
```

All subtests must pass. If any fails, the object store does not enforce COMPLIANCE retention: do not use it for audit
evidence (ADR 0017 then requires Ceph RGW or an external provider) and record the result.

Repeat the gate after every upgrade of the object store.

## 3. Operation

- Objects, their index rows (`audit_object.day`) and the daily manifests are dated by the **recording day**: the UTC
  date on which the audit writer stored the object (start of its database transaction), not the events'
  `occurred_at`. The object key `org/<organization_id>/<YYYY>/<MM>/<DD>/<HH>-<event_id>.jsonl.zst` carries the
  recording date and hour.
- **Late events.** An event that reaches the writer after its occurrence day was sealed (for example after a queue
  outage) is stored under the day it is recorded and listed in that day's manifest. Sealed manifests are never
  rewritten. To find an event in the evidence, look it up in the audit log (filtered by occurrence time); its
  `recorded_at` names the manifest day that covers it.
- Every writer transaction is limited to 5 minutes (`transaction_timeout`); a batch that exceeds it is rolled back
  and redelivered. Day *D* is sealed at *D*+1 00:15 UTC, after every transaction that started on *D* has ended.
  `paddock-server audit seal` refuses days that are not sealable yet; only the development-only
  `audit seal --day <day> --org <id>` seals earlier.
- The audit writer sets the retention of every object and manifest to 00:00 UTC of its recording day plus
  `PADDOCK_AUDIT_RETENTION_DAYS` (≥ 400). Raising the value extends retention for new objects only.
- Expired objects are removed by a lifecycle rule that the operator adds once the retention period is known to
  be final; Paddock itself never deletes audit objects.
- `paddock-server audit verify --org <id> --from <day> --to <day>` (run in the audit-writer container) checks the
  signed manifest chain and every object hash of an organization.
