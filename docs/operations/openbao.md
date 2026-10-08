# OpenBao runbook

OpenBao holds Paddock's keys (ADR 0006):

| Path | Purpose | Used by |
| --- | --- | --- |
| `transit/keys/audit-chain` | Ed25519 key that signs the daily audit manifests (non-exportable) | `audit-writer` (AppRole `paddock-audit-writer`) |
| `transit/keys/bundle-signing` | Ed25519 key that signs device bundles (non-exportable) | `compiler` (AppRole `paddock-compiler`); `api` reads the public keys |
| `transit/keys/command-signing` | Ed25519 key that signs device commands (non-exportable); its public keys reach devices in their bundles | `worker` (AppRole `paddock-worker`, sign only); `compiler` reads the public keys |
| `transit/keys/revocation-signing` | Ed25519 key that signs revocation tokens (Lock, Destroy, self-lock; non-exportable); its public keys reach devices only in their enrollment configuration (`revocation_keys`, pinned in `/etc/paddock/revoke-trust.json`), never through bundles except once for devices enrolled before it existed | the `revocation-issuer` role only (AppRole `paddock-revocation-issuer`, sign and read); `api` and `compiler` read the public keys |
| `transit/keys/time-ticket` | Ed25519 key that signs the time tickets of the dead man's switch (non-exportable); its public keys reach devices in their bundles | `compiler` (AppRole `paddock-compiler`, sign and read) |
| `transit/keys/escrow-wrap` | RSA-4096 key (non-exportable) devices encrypt escrowed secrets to (RSA-OAEP with SHA-256); its latest public key reaches devices in their bundles | encrypt: devices; decrypt: the `escrow-reader` role only (AppRole `paddock-escrow-reader`, `docs/operations/escrow-reader.md`); `compiler` reads the public key |
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
for key in audit-chain bundle-signing command-signing revocation-signing time-ticket; do
  bao write "transit/keys/$key" type=ed25519 exportable=false allow_plaintext_backup=false
done
bao write transit/keys/escrow-wrap type=rsa-4096 exportable=false allow_plaintext_backup=false
bao kv put secret/paddock/session current="$(head -c 32 /dev/urandom | base64 -w0)" \
  previous="$(head -c 32 /dev/urandom | base64 -w0)"
```

Policies and AppRoles (identical to the development bootstrap):

```sh
bao policy write paddock-api - <<'EOF'
path "secret/data/paddock/session" { capabilities = ["read"] }
path "transit/keys/bundle-signing" { capabilities = ["read"] }
path "transit/keys/revocation-signing" { capabilities = ["read"] }
EOF
bao policy write paddock-audit-writer - <<'EOF'
path "transit/sign/audit-chain" { capabilities = ["update"] }
path "transit/keys/audit-chain" { capabilities = ["read"] }
EOF
bao policy write paddock-compiler - <<'EOF'
path "transit/sign/bundle-signing" { capabilities = ["update"] }
path "transit/keys/bundle-signing" { capabilities = ["read"] }
path "transit/sign/time-ticket" { capabilities = ["update"] }
path "transit/keys/time-ticket" { capabilities = ["read"] }
path "transit/keys/command-signing" { capabilities = ["read"] }
path "transit/keys/revocation-signing" { capabilities = ["read"] }
path "transit/keys/escrow-wrap" { capabilities = ["read"] }
EOF
bao policy write paddock-worker - <<'EOF'
path "transit/sign/command-signing" { capabilities = ["update"] }
EOF
bao policy write paddock-escrow-reader - <<'EOF'
path "transit/decrypt/escrow-wrap" { capabilities = ["update"] }
EOF
# The only role that can sign revocations (plan M4c decision 2).
bao policy write paddock-revocation-issuer - <<'EOF'
path "transit/sign/revocation-signing" { capabilities = ["update"] }
path "transit/keys/revocation-signing" { capabilities = ["read"] }
EOF
# Raft snapshots for the backup and nothing else (plan M6a decision 5; used by paddock-worker).
bao policy write paddock-backup - <<'EOF'
path "sys/storage/raft/snapshot" { capabilities = ["read"] }
EOF
for role in paddock-api paddock-audit-writer paddock-compiler paddock-worker paddock-escrow-reader \
  paddock-revocation-issuer paddock-backup; do
  bao write "auth/approle/role/$role" token_policies="$role" token_ttl=1h token_max_ttl=4h
done
```

Deliver role ID and secret ID of each AppRole to the host of the role (control plane: `paddock-api`,
`paddock-compiler`, `paddock-worker`, `paddock-escrow-reader` to the escrow-reader and never to the api,
`paddock-revocation-issuer` to the revocation-issuer and to no other role, `paddock-backup` to the worker as
`approle/paddock-backup/`; audit host: `paddock-audit-writer`) as files referenced by
`PADDOCK_OPENBAO_ROLE_ID_FILE` / `PADDOCK_OPENBAO_SECRET_ID_FILE`:

```sh
bao read -field=role_id auth/approle/role/paddock-api/role-id
bao write -f -field=secret_id auth/approle/role/paddock-api/secret-id
```

Then take the first snapshot (section 5) and finally revoke the root token (`bao token revoke -self`). A new root token can be generated later only with three
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
| Bundles and commands | The compiler cannot sign new bundles and the worker cannot sign new commands; devices keep their last bundle and receive commands once OpenBao is unsealed (commands that expired meanwhile are never delivered). |
| Daily audit seal | The sealer cannot sign; the 00:15 UTC run fails (`paddock_audit_seal_total{result="error"}`) and catches up on the next successful run, because it seals every unsealed day up to yesterday. |
| Audit event ingestion | Continues: the audit writer needs OpenBao only for signing and readiness. Events wait in RabbitMQ if the writer is restarted while OpenBao is sealed (it reports not ready but keeps consuming once running). |
| Everything else | Unaffected. |

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

## 5. Snapshots after key operations

`paddock-worker` takes an encrypted Raft snapshot every 6 hours (`docs/operations/restore.md`). Key operations are
manual (`bao` CLI), so after every one of them (a new or rotated Transit key, new policies or AppRoles, rotated session
keys or secret IDs) take a snapshot at once, so that a restore never brings back an older key state:

```sh
docker compose … run --rm --no-deps paddock-worker backup openbao
```
