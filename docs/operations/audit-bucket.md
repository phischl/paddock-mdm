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

With the bundled RustFS, run `./paddock bootstrap audit-bucket` on the audit host (`docs/operations/install.md`
section 5): `deploy/compose/scripts/rustfs-audit-bootstrap.sh` creates the bucket with Object Lock, the default
retention and the writer credential from `.secrets/`, and refuses an existing bucket without Object Lock.

For an S3 provider that is not the bundled RustFS, run the same steps by hand on the audit host, with the object
store's root credentials loaded into the environment from your secret store (never on the command line):

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
`s3:GetBucketObjectLockConfiguration` (read-only; `./paddock check --online` verifies the bucket with it) on
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

## 3. Nightly verification

**What runs when.** Every night at 00:45 UTC, 30 minutes after the seal of the previous day (00:15 UTC), the audit
writer verifies for every organization with audit data the last seven sealed days (from the organization's first
audit day at most) and one random older day, if there is one. It checks the same things as
`paddock-server audit verify`: every manifest exists, is signed with `audit-chain`, links to the previous day and
lists exactly the indexed objects, and every object's SHA-256 matches. Only one audit-writer replica verifies at a
time (advisory lock `audit-verify`); the other replicas take the last-run and failed-organizations metrics from the
runs it records. An organization whose verification cannot run (for example the object store is unreachable) is
logged and skipped, and the others are still verified.

**Where the result is visible.** Every run, the nightly window (`trigger: nightly`), the sample day (`sample`) and
every `paddock-server audit verify` (`cli`), is recorded twice:

- as an audit event in the verified organization's own audit log: `audit.chain_verified`, or
  `audit.chain_verification_failed` with `problem_count` and the first 50 problems, actor `system` / `audit-writer`,
  target `audit_chain`; the event is written to the index and the WORM bucket like every other event, under the day
  of the run;
- as a row of `audit_verification_run` in the audit index (run ID, trigger, days, objects, result, problems), which
  `paddock-server audit verify` prints as `run <id>`.

Organization administrators and auditors see both without platform access: the portal page *Evidence integrity*
(*Organization* → *Evidence integrity*, `/audit/integrity`) shows the last sealed day, the number of manifests, the
last verification with its result and the last failure, every verification run with its problems, and every sealed
day with its manifest hash and the result of the newest run covering it. The same data is in the admin API:
`GET /api/v1/audit/integrity`, `GET /api/v1/audit/verification-runs` and `GET /api/v1/audit/manifests`.

The audit writer's `/metrics` exports `paddock_audit_verify_runs_total{trigger,result}`,
`paddock_audit_verify_failed_organizations` and `paddock_audit_verify_last_run_timestamp_seconds`
(`docs/operations/monitoring.md`).

**Other nightly work of the audit writer** (ADR 0032, `docs/compliance/retention.md`):

- **Index purge.** Every night at 01:15 UTC, after the seal and the verification, the audit writer drops every
  monthly partition of the audit index whose events were all recorded more than `PADDOCK_AUDIT_INDEX_RETENTION_DAYS`
  ago (default and minimum: the WORM retention) and records `retention.purged` (store `audit_index`) per partition in
  the platform pseudo-organization. The WORM bucket, `audit_object` and `audit_manifest` are never touched. `paddock-server audit purge --dry-run`
  (audit-writer container) lists every partition with `DROP` or `KEEP` and changes nothing.
- **Evidence exports.** Evidence packages (`POST /api/v1/audit/exports`) are built on the audit host by the audit
  writer and stored in the audit index database, never in the bucket; a package expires 7 days after it is ready and
  the nightly purge deletes it (`retention.purged`, store `audit_exports`). An auditor requests a package for sealed
  days on the portal's *Evidence exports* page (`/audit/exports`) after a step-up; the request is recorded as
  `audit.export_requested`, the finished build as `audit.export_completed` and every download as
  `audit.export_downloaded` (also when refused). A day that is not sealed yet is refused (`day_not_sealed`) and at most
  two exports of an organization are open at a time (`too_many_exports`). The auditor verifies the downloaded package
  without any access to Paddock: `paddockctl audit verify-export <file> --fingerprint <fingerprint>`
  ([paddockctl.md](paddockctl.md#verifying-an-evidence-package)), with the fingerprint of the `audit-chain` key from the
  signing-keys list of the page or from `paddock-server audit keys` on the audit host.

**What to do on `PaddockAuditChainBroken`.** The alert fires as soon as a nightly cycle found a broken or
unreadable chain of at least one organization. A restart of the audit writer does not clear it: at start the writer
counts the organizations whose newest recorded nightly window or sample day failed.

1. Find the organization and the problems: the newest `audit.chain_verification_failed` events (`problems` names
   the day and the object), or the audit writer's log.
2. Run `paddock-server audit verify --org <id> --from <day> --to <day>` in the audit-writer container for the
   affected days and keep its output.
3. `no manifest` for the last day usually means the 00:15 UTC seal did not run (for example OpenBao was sealed):
   unseal OpenBao, run `paddock-server audit seal`, and verify the day again. The alert stays until the next
   nightly cycle verifies the chain.
4. An unreadable or modified object, a signature that does not verify or a broken link is a possible integrity
   incident: check the object store (bucket lock configuration, access logs) and compare the object with the
   replica outside the primary failure domain; Paddock does not verify the replica (RR-75).
5. Record the finding, the cause and the outcome in your ISMS as a security event.

`PaddockAuditVerifyStale` warns when no nightly cycle finished for 36 hours: check that the audit writer runs and
its log for the 00:45 UTC cycle.

## 4. Operation

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
- **Index purge.** The audit index (`paddock_audit.audit_event`, monthly partitions by occurrence time) is purged
  by the audit writer at 01:15 UTC: a partition is dropped only when its month ended and **every** event in it was
  recorded more than `PADDOCK_AUDIT_INDEX_RETENTION_DAYS` ago (default and minimum: `PADDOCK_AUDIT_RETENTION_DAYS`,
  so the index never goes ahead of the WORM retention). A partition with a later recorded event is kept until that
  event expires too. Each drop is recorded as `retention.purged` (store `audit_index`, the partition and the number
  of events) in the platform pseudo-organization, in the index and in the bucket. The purge waits at most 5 s for
  the partition's lock; a partition it could not lock is retried the next night. It never deletes objects,
  `audit_object` or `audit_manifest` rows. `paddock-server audit purge --dry-run` (in the audit-writer container)
  prints `DROP`/`KEEP` per due partition or `nothing to purge`; without `--dry-run` it purges at once and exits 1
  when a partition could not be dropped. `PaddockAuditIndexPurgeStale` warns when no complete purge finished for
  48 hours.
- `paddock-server audit verify --org <id> --from <day> --to <day>` (run in the audit-writer container) checks the
  signed manifest chain and every object hash of an organization.
- **Evidence export size and disk.** The audit writer builds one export at a time. It spools the decoded
  `events.jsonl` of the export in `TMPDIR`, which is the Docker volume `audit-writer-tmp` mounted at
  `/var/lib/paddock/export-tmp`; the file is unlinked as soon as it is created, so it never shows up in a listing
  and nothing is left after a crash, and its space is freed when the build ends. The finished package is stored in
  chunks in the audit index database until it expires. `PADDOCK_AUDIT_EXPORT_MAX_BYTES` (default `4294967296`,
  4 GiB) bounds both `events.jsonl` and the whole package; the package size is computed before its first chunk is
  stored. An export that exceeds it fails with an error starting with `export_too_large` (shown on the *Evidence
  exports* page) and an `audit.export_completed` failure event with `reason: export_too_large`, and leaves no chunks
  behind. Ask the auditor for a shorter range, or raise the limit after checking the disk. An export that the stuck
  check fails after a restart of the writer (`exporter restarted`) carries no `reason`, whatever stopped it.
  Sizing: the volume lives in Docker's data-root (`docker info -f '{{.DockerRootDir}}'`, usually `/var/lib/docker`),
  so it shares that file system with the images, the container logs and the other volumes of the host; it needs free
  space for one `events.jsonl` of the limit per audit-writer replica (each replica builds one export at a time), and
  the audit database for the packages of the open exports (at most two per organization, kept 7 days). A single
  object or manifest larger than 256 MiB is never read into memory: the export fails and the verification reports it
  as unreadable; an object is decompressed as a stream, never as a whole. The volume holds no state and needs no
  backup.
- **The audit writer's writable directories.** The container root is read-only. `/tmp` is a 64 MiB tmpfs mounted
  `noexec,nosuid,nodev`; the export volume at `/var/lib/paddock/export-tmp` is the writer's one writable directory
  that allows executing files (Docker mounts a named volume without `noexec`). Nothing but the unlinked export file
  is written there; `compose.audit.yaml` keeps both, and the bundle test checks them.
- **Signing key fingerprints.** After every seal and every evidence package the audit writer records the public key of
  the `audit-chain` version it signed with in `paddock_audit.audit_signing_key` (insert-only, so a published key never
  changes; the writer reads OpenBao at most every 10 minutes for this and fails the seal or export if the key cannot be
  recorded or differs from the published key of that version: the mismatch is logged at ERROR with both fingerprints
  and stops sealing, which the seal-staleness alert surfaces). Auditors and organization admins read them with
  `GET /api/v1/audit/keys` (`key_version`, `public_key`, `fingerprint` = lowercase hex SHA-256 of the raw 32-byte key).
  `paddock-server audit keys` (in the audit-writer container) prints `audit-chain v<N> <fingerprint>` per version straight from OpenBao, never from the database.
  Record that output out of band (ISMS register, signed hand-over note) when a version first appears and after every
  key rotation: an auditor trusts a package only if its fingerprint equals a value that did not travel with the
  package. Key rotation itself is not covered here.
