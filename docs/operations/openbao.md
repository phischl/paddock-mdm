# OpenBao runbook

OpenBao holds Paddock's keys (ADR 0006). In M0 it serves two things:

| Path | Purpose | Used by |
| --- | --- | --- |
| `transit/keys/audit-chain` | Ed25519 key that signs the daily audit manifests (non-exportable) | `audit-writer` (AppRole `paddock-audit-writer`) |
| `secret/paddock/session` (KV v2) | AES-256 keys `current` / `previous` of the portal session cookie | `api` (AppRole `paddock-api`) |

Storage is the integrated Raft backend on the `openbao-data` volume (`deploy/compose/openbao/config.hcl`).

In development, `make up` (`deploy/compose/scripts/openbao-bootstrap.sh`) does all of the following automatically and
stores the unseal shares and the root token in `deploy/compose/.secrets/openbao/`. **The script refuses to run with
`PADDOCK_ENV=production`; production follows this runbook.**

## 1. Production initialization (once)

Five named custodians each receive one unseal share; any three of them unseal OpenBao. Shares are encrypted to
the custodians' PGP keys, so no person ever sees another person's share and no share touches the server disk.

Preparation:

- Five custodians, each with a PGP key pair whose public key is exported as `custodian-N.asc` (base64-encoded,
  binary format, as `bao operator init` expects). Record the assignment (name ↔ share number) in the operations log.
- One additional PGP key for the initial root token (`root.asc`), held by the platform owner.
- OpenBao running and reachable from the operator workstation (`BAO_ADDR`, TLS in production).

```sh
bao operator init -key-shares=5 -key-threshold=3 \
  -pgp-keys="custodian-1.asc,custodian-2.asc,custodian-3.asc,custodian-4.asc,custodian-5.asc" \
  -root-token-pgp-key="root.asc"
```

Hand each encrypted share to its custodian (`Unseal Key N` is encrypted for `custodian-N`). Then three custodians
unseal (section 2), and the root token holder configures OpenBao:

```sh
export BAO_TOKEN=<decrypted root token>
bao secrets enable transit
bao secrets enable -path=secret kv-v2
bao auth enable approle
bao write transit/keys/audit-chain type=ed25519 exportable=false allow_plaintext_backup=false
bao kv put secret/paddock/session current="$(head -c 32 /dev/urandom | base64 -w0)" \
  previous="$(head -c 32 /dev/urandom | base64 -w0)"
```

Policies and AppRoles (identical to the development bootstrap):

```sh
bao policy write paddock-api - <<'EOF'
path "secret/data/paddock/session" { capabilities = ["read"] }
EOF
bao policy write paddock-audit-writer - <<'EOF'
path "transit/sign/audit-chain" { capabilities = ["update"] }
path "transit/keys/audit-chain" { capabilities = ["read"] }
EOF
bao write auth/approle/role/paddock-api token_policies=paddock-api token_ttl=1h token_max_ttl=4h
bao write auth/approle/role/paddock-audit-writer token_policies=paddock-audit-writer token_ttl=1h token_max_ttl=4h
```

Deliver role ID and secret ID of each AppRole to the host of the role (control plane: `paddock-api`; audit host:
`paddock-audit-writer`) as files referenced by `PADDOCK_OPENBAO_ROLE_ID_FILE` / `PADDOCK_OPENBAO_SECRET_ID_FILE`:

```sh
bao read -field=role_id auth/approle/role/paddock-api/role-id
bao write -f -field=secret_id auth/approle/role/paddock-api/secret-id
```

Finally revoke the root token (`bao token revoke -self`). A new root token can be generated later only with three
custodians (`bao operator generate-root`).

## 2. Unseal after a restart

OpenBao starts sealed after every restart of its container or host. Three custodians run, each on their own
workstation:

```sh
bao operator unseal   # prompts for the decrypted share; repeat until "Sealed: false"
```

Check with `bao status` (`Sealed false`, `HA Mode active` for a single node). In development, `make bao-unseal` uses
the stored shares.

### What stops while OpenBao is sealed

| Function | Effect while sealed |
| --- | --- |
| Portal login and sessions | `api` cannot load the session keys after its own restart; it stays not ready (`/readyz` 503) until OpenBao is unsealed. A running `api` keeps the keys it loaded and keeps working; key reloads (every 10 min) fail and are logged. |
| Daily audit seal | The sealer cannot sign; the 00:15 UTC run fails (`paddock_audit_seal_total{result="error"}`) and catches up on the next successful run, because it seals every unsealed day up to yesterday. |
| Audit event ingestion | Continues: the audit writer needs OpenBao only for signing and readiness. Events wait in RabbitMQ if the writer is restarted while OpenBao is sealed (it reports not ready but keeps consuming once running). |
| Everything else in M0 | Unaffected. |

## 3. Rotating an AppRole secret ID

Secret IDs do not expire by default (`secret_id_ttl=0`); rotate them at least yearly and whenever a host is
rebuilt or a secret may have leaked. Without downtime:

```sh
# 1. issue a new secret ID (the old one stays valid)
bao write -f -format=json auth/approle/role/paddock-api/secret-id > new.json
jq -r .data.secret_id new.json   # write to the secret file of the role on its host
jq -r .data.secret_id_accessor new.json
# 2. restart the role's containers so they log in with the new secret ID
docker compose restart paddock-api
# 3. destroy the old secret ID by its accessor
bao list auth/approle/role/paddock-api/secret-id
bao write auth/approle/role/paddock-api/secret-id-accessor/destroy secret_id_accessor=<old accessor>
```

Tokens issued with the old secret ID stay valid until their TTL ends (at most 4 h).

## 4. Rotating the session keys

Write a new `current` and move the old `current` to `previous`:

```sh
old=$(bao kv get -field=current secret/paddock/session)
bao kv put secret/paddock/session current="$(head -c 32 /dev/urandom | base64 -w0)" previous="$old"
```

The `api` role reloads the keys within 10 minutes; sessions encrypted with the previous key keep working until they
expire (8 h at most). Rotate monthly (architecture §9.6).
