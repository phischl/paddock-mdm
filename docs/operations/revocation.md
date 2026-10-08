# Revocation: Lock and Destroy

An organization administrator can **Lock** a device: every keyslot of its encrypted root volume and of every other
LUKS volume listed in its `/etc/crypttab` (also through a detached `header=`) is erased and the device reboots; the
escrowed LUKS header and recovery key restore the root volume (Paddock escrows no other volume). Two organization
administrators can **Destroy** a device: a Lock whose escrow is deleted before the token is issued, so the data
cannot be recovered (architecture §12.3, plans M4c and M4c.1).

> **The revocation path is disabled** (`PADDOCK_REVOCATION_ENABLED=false`, the default) until a second person has
> reviewed `agent/internal/revoke/` and `agent/cmd/paddock-revoke/` and the hardware protocol in
> `docs/operations/revocation-acceptance.md` has passed on a real laptop. Only development and test installations
> enable it. While it is off the revocation endpoints answer 403 `revocation_disabled` (audited as `denied`), the
> revocation-issuer signs nothing, bundles say `revocation.enabled=false` and `paddock-revoke` on the devices refuses
> every token.

## How a revocation is issued

1. An administrator requests a Lock or Destroy on the device page: a fresh step-up, the device's hostname typed as
   confirmation and a reason (`POST /api/v1/devices/{id}/lock|destroy`). The api records the request and the raw
   step-up ID token of the administrator; each step-up token approves one request only.
2. A Destroy waits for a second administrator — another account **and** another Authentik identity — who approves
   it with a step-up of their own (`POST /api/v1/revocation-requests/{id}/approve`). Any administrator can reject a
   waiting Destroy; the requester can cancel a request until it is issued.
3. The approved request reaches the **revocation-issuer** through the outbox (queue `revocation.approved`, single
   active consumer). It verifies every approval's ID token against Authentik's JWKS (issuer and audience of
   `paddock-portal-stepup`, MFA, `auth_time` at most 300 s before the approval, subject and jti as recorded, an
   organization administrator behind the subject, the token unused by any other request), the distinct
   administrators of a Destroy, that the requester is not frozen and the limits below. Then it signs the
   device-bound token (Transit key `revocation-signing`, valid 30 days) and puts it into `cmd:<device_id>`; the device
   receives it with its next check-in.
4. For a Destroy the issuer first deletes every version of every escrowed header object of the device from the
   bucket `paddock-escrow`, then — in the transaction that records the request as issued — every recovery key and
   header generation (audit `device.escrow_destroyed`). The recovery endpoints answer 404 afterwards. A Lock keeps the
   escrow.
5. On the device, `paddock-revoke` terminates the user sessions, erases every keyslot, verifies that none is left,
   posts the confirmation and reboots (audit `device.revocation_confirmed`). An issued request that the device has
   not confirmed is shown as pending with the time since issuance; after 30 days it expires.

The raw step-up tokens are deleted 30 days after their request reached a final state.

## In the portal

- **Device page → *Lock and Destroy*** (organization administrators, devices that are active or quarantined): enter
  the reason, choose *Lock device* or *Destroy device*, complete the step-up and type the hostname in the
  confirmation. The card lists the device's revocations with their progress (requested, approved, issued, delivered,
  confirmed). While the flag is off the card says *Revocation is not enabled on this installation (pending
  acceptance)*.
- ***Revocations*** lists every Lock, Destroy and self-lock of the organization (search, filters for status and
  action). A Destroy waiting for its second administrator offers *Approve* and *Reject* to every other administrator
  and *Cancel request* to its requester; each needs a step-up and the typed hostname.
- ***Dead man's switch*** holds the organization's switch (below).

## Restoring a locked device

A Lock erases every keyslot, also the TPM2+PIN token and the recovery key; the device asks for its PIN at the next
start and no PIN, passphrase or key opens it. The escrow is untouched, so an organization administrator restores it
as for a damaged header (`docs/operations/disk-recovery.md`):

1. Make sure the reason for the Lock is resolved (the device is back with its owner, or with IT). The request on the
   *Revocations* page shows `confirmed` with the device's result (`slots_before`, `slots_after: 0`, and per volume
   in `volumes`; the device page lists every volume and the crypttab entries the device could not erase with certainty; with
   such entries the erasure is incomplete and the request `failed`). Restore
   the root volume as below. Paddock escrows only the root volume: another erased volume can be restored only from a
   header backup taken outside Paddock, otherwise its data is lost.
2. Portal → device → *Disk encryption*: *Download header backup* (the newest stored generation was taken before the
   Lock; the Lock does not escrow a new one) and *Show recovery key*. Both need a step-up and the typed hostname.
3. Boot the device from a live USB system, find the LUKS partition (`lsblk -f`) and restore:

   ```sh
   cryptsetup luksHeaderRestore /dev/<partition> --header-backup-file <hostname>-luks-header-<generation>.img
   cryptsetup open --test-passphrase /dev/<partition>   # type the recovery key: it must succeed
   ```

4. Reboot without the live system. The restored header contains the keyslots of its generation again, including
   TPM2+PIN: the user's PIN unlocks the disk, or the recovery key at the PIN prompt (repeat it until the TPM attempts
   are used up).
5. After the start the agent reports the keyslot change (`device.tamper_keyslot_changed`) and escrows the header
   again. If the person who had the device should no longer open it, set a new boot PIN (`disk-recovery.md`, step 3
   of *Forgotten boot PIN*). The revealed recovery key stays valid: Paddock does not rotate recovery keys yet, so
   keep it as confidential as the escrow.

`paddock-revoke` remembers the tokens it executed and refuses a second revocation within 24 hours, so the restored
device does not lock again by itself. A Destroy cannot be restored: its escrow is gone (the recovery endpoints answer
404).

## Dead man's switch

Portal → *Dead man's switch* (`GET`/`PUT /api/v1/settings/dms`, organization administrators). When it is on, every
active device of the organization locks itself after **period** days of uptime in which it never reached Paddock —
**also when Paddock itself is down for that long**: *If Paddock is unreachable for longer than this period, every
device with the switch enabled locks itself.* Plan the period above the longest outage of the control plane you
would tolerate, and above the longest time a user is offline (vacations); the portal warns below 30 days and the api
refuses below 7 (Himmelblau's offline window).

- **Turning it on** (or changing it while on) needs a step-up and is audited as `settings.dms_changed`. The
  revocation-issuer then gives every active device a `self_lock` token (no approvals, no limits; valid 365 days,
  renewed 60 days before it ends and whenever the period changes). The device stores it and does nothing else.
- **Time tickets.** Every 10 minutes the compiler signs one ticket per organization (Transit key `time-ticket`) and
  every check-in carries it. Each accepted ticket resets the device's count. The device counts uptime only
  (`CLOCK_BOOTTIME`, persisted every minute): a changed wall clock neither defers nor triggers it, and powered-off
  time does not count.
- **Warnings.** At the lead times (`warn_days`, default 3 and 1 days before) the device shows a notification in every
  graphical session and a notice on the login screen and text consoles (`/etc/issue.d/80-paddock-dms.issue`). The next
  ticket removes them.
- **Locking.** When the period ends the agent hands the stored token to `paddock-revoke`, which checks the signature,
  the device and that the counted uptime reaches the token's own period, then runs the same sequence as a Lock (the
  confirmation is posted if the network allows it). Restore it as above.
- **Presumed self-locked.** Every 5 minutes the worker marks devices that have been silent for longer than the period
  while the switch is on (`device.presumed_self_locked`, once per silence); the device page shows it. The mark goes
  when the device checks in again or the switch is turned off.
- **Turning it off** cancels every self-lock token and sends each active device `delete_self_lock`; the device deletes
  its copy and its warnings. A device that is offline at that time deletes it with its next check-in.

The switch only works while the feature flag is on; with the flag off the settings answer 403
`revocation_disabled`.

## Limits (ADR 0014)

| Limit | Value |
| --- | --- |
| per administrator (requester) | 3 Locks or Destroys per hour, 10 per 24 h |
| per organization | 20 per 24 h |
| per device (`paddock-revoke`) | 1 revocation per 24 h |

Windows slide over the issued requests. A request that exceeds a limit is rejected, audited as
`revocation.limit_exceeded` (`denied`) and raises the alert below; the requester's revocations are frozen for 24 h —
the api answers their next request with 403 `revocation_frozen`. Refused proofs (forged, stale or reused tokens, a
single administrator approving a Destroy) are rejected and audited as `revocation.issue_refused` (`denied`).

Alert on `increase(paddock_revocation_refused_total{reason=~"limit_.*"}[5m]) > 0` (metric of the
revocation-issuer); the issuer also logs `ALERT: revocation limit exceeded` at level error.

## Deployment

| Setting | Revocation-issuer |
| --- | --- |
| `PADDOCK_DB_URL_FILE` | DSN of `paddock_revocation` |
| `PADDOCK_AMQP_URL`, `PADDOCK_AMQP_USER`, `PADDOCK_AMQP_PASSWORD_FILE` | RabbitMQ user `revocation_issuer` (read on `revocation.approved` only) |
| `PADDOCK_OPENBAO_ADDR`, `PADDOCK_OPENBAO_ROLE_ID_FILE`, `PADDOCK_OPENBAO_SECRET_ID_FILE` | AppRole `paddock-revocation-issuer` (`docs/operations/openbao.md`) |
| `PADDOCK_VALKEY_ADDR`, `PADDOCK_VALKEY_PASSWORD_FILE` | `cmd:<device_id>` and the used step-up tokens (`revocation-jti:<jti>`) |
| `PADDOCK_OIDC_STEPUP_ISSUER` (`PADDOCK_OIDC_STEPUP_CLIENT_ID`, default `paddock-portal-stepup`) | token verification |
| `PADDOCK_ESCROW_S3_ENDPOINT`, `PADDOCK_ESCROW_S3_BUCKET`, `PADDOCK_ESCROW_S3_ACCESS_KEY_FILE`, `PADDOCK_ESCROW_S3_SECRET_KEY_FILE` | credential that may list and delete header versions of `paddock-escrow` only |
| `PADDOCK_REVOCATION_ENABLED` | the feature flag; set it identically for api, compiler and revocation-issuer |

Run the issuer as one container without published ports; no other role needs to reach it. Deliver the
`paddock-revocation-issuer` AppRole credentials to it alone.

### Database role

New clusters create `paddock_revocation` at initialization (`deploy/compose/postgres/init/10-roles.sh`). An existing
cluster needs it before the database migration `00020` runs; as the PostgreSQL superuser:

```sql
CREATE ROLE paddock_revocation LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS PASSWORD '<password>';
GRANT CONNECT ON DATABASE paddock TO paddock_revocation;
GRANT USAGE ON SCHEMA public TO paddock_revocation;
```

The migration grants access to the revocation tables, `device` and `admin_account` (read), `escrow_secret` (read and
delete) and its own audit events, with row-level security on the organization.

### RabbitMQ and object store

Add the user `revocation_issuer` with read permission on `^revocation\.approved$` and extend the relay's write
permission to `^paddock\.(audit|state|command|revocation)$` (`deploy/compose/rabbitmq/definitions.json.tmpl`);
`paddock-server provision rabbitmq` declares the exchange `paddock.revocation` and the queue. Create an object store
user with `s3:ListBucket` and `s3:ListBucketVersions` on `paddock-escrow` and `s3:DeleteObject` and
`s3:DeleteObjectVersion` on `paddock-escrow/org/*/devices/*/luks-header/*`
(`deploy/compose/scripts/rustfs-bundles-bootstrap.sh`, policy `paddock-escrow-destroy`).
