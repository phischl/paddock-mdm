# Escrow reader

Escrowed secrets — local administrator passwords, LUKS recovery keys and the keys of LUKS header backups — are
decrypted by one role only: `paddock-server serve escrow-reader` (plan M4b.1 decisions 5–7). It holds the OpenBao
AppRole `paddock-escrow-reader` (`update` on `transit/decrypt/escrow-wrap`, nothing else). `paddock-api` holds no
credential that decrypts escrows; code execution in the api container decrypts nothing without a fresh step-up of an
organization administrator.

## What the escrow-reader checks

The api calls `POST /internal/v1/decrypt` with the escrow IDs of one device, the purpose (`local_admin_reveal`,
`disk_recovery_key` or `disk_header`) and the raw ID token of the administrator's step-up. Before it decrypts, the
escrow-reader

1. requires the shared bearer secret (`Authorization: Bearer …`) and signs its answers with an HMAC under the same
   secret, which the api checks;
2. verifies the step-up ID token against Authentik's JWKS (issuer and audience of the provider
   `paddock-portal-stepup`, expiry), requires `auth_time` within the step-up window (300 s; development:
   `PADDOCK_STEPUP_WINDOW`) and MFA in `amr`;
3. requires the token's subject to be an `org_admin` of the organization of the request, reading as database role
   `paddock_escrow_reader` (`SELECT` on `admin_account`, `device` and `escrow_secret` only, row-level security on the
   organization of the request);
4. requires every escrow to belong to the device and the organization and to be of the purpose's kind;
5. allows at most 5 decryptions per token (Valkey counter `stepup-uses:<jti>`, expires with the token).

A refusal is answered with 403 and a code; the api records the action as `denied` with `step_up_required`, so the
administrator steps up again. The escrow-reader never logs tokens or plaintexts.

The api keeps the raw step-up ID token in Valkey under `stepup:<jti>` for the step-up window, written at the step-up
callback; the session cookie carries only the step-up time and jti.

## Deployment

| Setting | Escrow-reader | Api |
| --- | --- | --- |
| `PADDOCK_HTTP_ADDR` | address on the escrow network only, e.g. `escrow-reader:8080` | – |
| `PADDOCK_ESCROW_READER_TOKEN_FILE` | shared bearer secret | same file |
| `PADDOCK_ESCROW_READER_URL` | – | e.g. `http://escrow-reader:8080` |
| `PADDOCK_DB_URL_FILE` | DSN of `paddock_escrow_reader` | – |
| `PADDOCK_OPENBAO_ADDR`, `PADDOCK_OPENBAO_ROLE_ID_FILE`, `PADDOCK_OPENBAO_SECRET_ID_FILE` | AppRole `paddock-escrow-reader` | its own AppRole `paddock-api` |
| `PADDOCK_VALKEY_ADDR`, `PADDOCK_VALKEY_PASSWORD_FILE` | use counter | step-up tokens |
| `PADDOCK_OIDC_STEPUP_ISSUER` (`PADDOCK_OIDC_STEPUP_CLIENT_ID`, default `paddock-portal-stepup`) | token verification | step-up |

Network: run the escrow-reader in its own container. Its HTTP port must be reachable from the api only — the Compose
stack attaches both to the internal network `escrow` and lets the escrow-reader listen on the address of an alias
that exists on that network alone; publish no port. The escrow-reader itself needs PostgreSQL, OpenBao, Valkey and
Authentik (JWKS).

Remove `PADDOCK_OPENBAO_ESCROW_ROLE_ID_FILE` and `PADDOCK_OPENBAO_ESCROW_SECRET_ID_FILE` and both secret files from
the api host, and deliver the `paddock-escrow-reader` AppRole credentials to the escrow-reader instead
(`docs/operations/openbao.md`).

### Database role

New clusters create `paddock_escrow_reader` at initialization (`deploy/compose/postgres/init/10-roles.sh`). An
existing cluster needs it before the database migration `00019` runs; as the PostgreSQL superuser:

```sql
CREATE ROLE paddock_escrow_reader LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS PASSWORD '<password>';
GRANT CONNECT ON DATABASE paddock TO paddock_escrow_reader;
GRANT USAGE ON SCHEMA public TO paddock_escrow_reader;
```

The migration grants the `SELECT`s and creates the row-level security policies.

### Rotating the bearer secret

Write a new random secret (at least 32 bytes) to the secret file of both the api and the escrow-reader and restart
both; requests between the two restarts fail with 502 and are audited as failures. In development: delete
`deploy/compose/.secrets/escrow_reader_token` and run `make dev-secrets up`.
