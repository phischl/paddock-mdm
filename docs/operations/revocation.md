# Revocation: Lock and Destroy

An organization administrator can **Lock** a device: every keyslot of its encrypted root volume is erased and the
device reboots; the escrowed LUKS header and recovery key restore it. Two organization administrators can
**Destroy** a device: a Lock whose escrow is deleted before the token is issued, so the data cannot be recovered
(architecture §12.3, plan M4c).

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
