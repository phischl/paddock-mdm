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

In development, `make up` (`deploy/compose/scripts/openbao-bootstrap.sh`) initializes and unseals OpenBao with
stored shares in `deploy/compose/.secrets/openbao/` and then runs `openbao-configure.sh`. **The development bootstrap
refuses to run with `PADDOCK_ENV=production`; production initializes as below and runs the same configuration with
`./paddock bootstrap openbao`.**

## 1. Production initialization (once)

Five named custodians each receive one unseal share; any three of them unseal OpenBao. Shares are encrypted to
the custodians' PGP keys, so no person ever sees another person's share and no share touches the server disk.

Preparation:

- Five custodians, each with a PGP key pair whose public key is exported as `custodian-N.asc` (base64-encoded,
  binary format, as `bao operator init` expects). Record the assignment (name ↔ share number) in the operations log.
- One additional PGP key for the initial root token (`root.asc`), held by the platform owner.
- The control plane's infrastructure running (`./paddock up --infra`, `docs/operations/install.md` section 6).

Initialize from the workstation that holds the public keys, with the bao CLI against the control plane's interconnect
endpoint (`BAO_ADDR=https://<control-plane interconnect address>:8200`, `BAO_CACERT` = the control plane's
`.secrets/internal-ca/bundle.crt`):

```sh
bao operator init -key-shares=5 -key-threshold=3 \
  -pgp-keys="custodian-1.asc,custodian-2.asc,custodian-3.asc,custodian-4.asc,custodian-5.asc" \
  -root-token-pgp-key="root.asc"
```

Hand each encrypted share to its custodian (`Unseal Key N` is encrypted for `custodian-N`). Then three custodians
unseal (section 2), and the root token holder configures OpenBao on the control-plane host, in the bundle directory:

```sh
read -rs BAO_TOKEN && export BAO_TOKEN   # the decrypted root token, typed without echo
./paddock bootstrap openbao
```

It enables `transit`, `secret` (kv-v2) and `approle`, creates the transit keys `audit-chain`, `bundle-signing`,
`command-signing`, `revocation-signing`, `time-ticket` (Ed25519) and `escrow-wrap` (RSA-4096), the KV secret
`secret/paddock/session`, the seven policies and AppRoles of `deploy/compose/scripts/openbao-configure.sh` (the same
as in development: each role reads or signs only with its own keys; `paddock-revocation-issuer` is the only role that
signs revocations, `paddock-backup` may only read Raft snapshots), and writes each AppRole's role ID and secret ID to
`.secrets/approle/<role>/`. It is idempotent: a stored secret ID is kept. The roles read them as files referenced by
`PADDOCK_OPENBAO_ROLE_ID_FILE` / `PADDOCK_OPENBAO_SECRET_ID_FILE`: `paddock-escrow-reader` reaches the escrow-reader
and never the api, `paddock-revocation-issuer` the revocation-issuer and no other role, `paddock-backup` the worker.
Copy `.secrets/approle/paddock-audit-writer/` to the audit host (`docs/operations/install.md` section 4).

Then take the first snapshot (section 5) and finally revoke the root token
(`./paddock bao token revoke -self` with `BAO_TOKEN` still exported, then `unset BAO_TOKEN`). A new root token can be generated later only with three
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
| Portal login and sessions | `api` cannot load the session keys after its own restart; it stays not ready (`/readyz` 503) until OpenBao is unsealed: the sign-in page shows *The server's key store is sealed* until OpenBao is unsealed; `./paddock up` names the reason in its timeout line. A running `api` keeps the keys it loaded and keeps working; key reloads (every 10 min) fail and are logged. |
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

## 6. Automatic unseal

Automatic unseal (ADR 0035) lets a service on the control-plane host, the **unsealer** (`paddock-unsealer`), unseal
OpenBao after every restart instead of three custodians. It is an option: read the risk below before you enable it.

**What it is.** The unsealer keeps three of the five unseal shares in `.secrets/openbao/auto-unseal-shares` (mode 0644
inside the 0700 `.secrets/` directory, mounted as the Compose secret `openbao_auto_unseal_shares` into the unsealer
only). Every 10 s it reads the platform setting from PostgreSQL with its own role `paddock_unsealer` and OpenBao's
seal status; it submits the three shares only while OpenBao is initialized and sealed and the setting is *enabled*.
After a failed attempt it resets the unseal progress and waits 60 s. OpenBao is unsealed within about 20 s of
starting sealed.

**What it is not.** The unsealer has no AppRole, no token and no key: it can unseal, nothing else. OpenBao's seal stays
Shamir 3 of 5; snapshots, restore, rekey and the custodians' own shares are unchanged. Paddock never writes the shares
into a backup.

**The risk (RR-43, `docs/compliance/residual-risks.md`).** Whoever controls the host, a copy of its disk, a VM snapshot
or a copy of `.secrets/` can unseal OpenBao and use every key in it. The custodian threshold no longer gates the
unseal. Record the risk in your ISMS before you enable it; on a production host `./paddock check` warns on every run
(`WARN  openbao auto-unseal`), on a lab host the item passes.

### Enabling

Two people act, in this order:

1. **A platform administrator in the portal**: *Platform* → *OpenBao* → *Enable automatic unseal*. The dialog shows the
   disclaimer (version `2026-10-17`); type the sentence it names (`I understand and accept the risk`, in German `Ich
   verstehe und akzeptiere das Risiko`) and confirm the identity (step-up). The acknowledgement, with the name, the
   time and the disclaimer version, is recorded as `platform.auto_unseal_enabled`. Nothing reaches the host yet; the
   page says that the host step is still open.
2. **The host operator, with three custodians present**, on the control-plane (or lab) host:

   ```sh
   ./paddock auto-unseal enable
   ```

   The command refuses on the audit host, while `PADDOCK_AUTO_UNSEAL=yes` or a shares file exists, and without the
   portal acknowledgement (`automatic unseal is not enabled: a platform administrator enables it in the portal first
   (Platform → OpenBao)`). It creates the PostgreSQL role, then asks three times
   `Unseal share N of 3 (from a custodian, not echoed):`; each custodian types their decrypted share. Nothing is
   echoed and no share is ever on a command line, in e-mail or in chat. Empty shares, shares with whitespace and two
   equal shares are refused. It writes the file, sets `PADDOCK_AUTO_UNSEAL=yes` in `.env` (do not edit it by hand),
   starts the unsealer and prints:

   ```text
   automatic unseal is enabled on this host. Verify it now: ./paddock compose restart openbao, then ./paddock bao status shows "Sealed false" within 30 s. Remove every other unseal automation (for example a cron job) and its copies of the shares.
   ```

   Run `./paddock up` once afterwards, so that Prometheus scrapes the unsealer (`prometheus/scrape/auto-unseal.yml`).

### Verifying

```sh
./paddock compose restart openbao
./paddock bao status        # "Sealed false" within 30 s
./paddock auto-unseal status
```

`./paddock auto-unseal status` prints `PADDOCK_AUTO_UNSEAL`, `shares file: present|absent`, the state of
`paddock-unsealer` and the `Sealed` line; it never prints a share. The portal page shows *Last automatic unseal* with
the time and the count, and within 30 s the audit log shows `platform.openbao_auto_unsealed` (actor `paddock-unsealer`,
recorded by the worker; a failed attempt is recorded with outcome failure and the reason `unreachable`,
`invalid_share` or `still_sealed`). On the host, `paddock-server admin auto-unseal show` prints the setting and the
report (`./paddock compose run --rm --no-deps paddock-worker admin auto-unseal show`).

### Disabling

1. **In the portal**: *Platform* → *OpenBao* → *Disable automatic unseal* (step-up). The unsealer stops unsealing at
   once (`platform.auto_unseal_disabled`, method portal). If the portal is not usable, the host operator runs
   `./paddock compose run --rm --no-deps paddock-worker admin auto-unseal disable` (method cli).
2. **On the host**: `./paddock auto-unseal disable` stops and removes the unsealer, deletes the shares file (`shred -u`
   where available) and sets `PADDOCK_AUTO_UNSEAL=no`. It prints:

   ```text
   the shares are deleted from this host. If the host, its disk or its backups may have been copied while automatic unseal was on, rotate the shares with three custodians (docs/operations/openbao.md section 6). If the portal still shows automatic unseal as enabled, a platform administrator disables it there.
   ```

`shred` does not guarantee erasure on SSDs or copy-on-write file systems. If the host, its disk, its snapshots or its
backups may have been copied while automatic unseal was on, **rekey** with three custodians, which invalidates every
copy of the shares file:

```sh
bao operator rekey -key-shares=5 -key-threshold=3   # three custodians each enter their current share
# hand the five new shares to the custodians, then take a snapshot at once:
./paddock compose run --rm --no-deps paddock-worker backup openbao
```

### Monitoring

| Alert | Fires when | Action |
| --- | --- | --- |
| `PaddockAutoUnsealWithdrawn` (warning) | automatic unseal was disabled in the portal, but the unsealer reported shares on the host for 1 h | `./paddock auto-unseal disable` on the host |
| `PaddockAutoUnsealerDown` (warning) | automatic unseal is enabled, but the unsealer has not reported for 10 min | check `./paddock auto-unseal status` and `./paddock logs paddock-unsealer`; OpenBao stays sealed after the next restart until the unsealer runs or three custodians unseal it |

Metrics: the worker exports `paddock_auto_unseal_enabled`, `paddock_auto_unseal_shares_present` and
`paddock_auto_unseal_unsealer_up`; the unsealer exports `paddock_unsealer_shares_present`,
`paddock_unsealer_setting_enabled` and `paddock_unsealer_unseals_total{result}` (`docs/operations/monitoring.md`).

### Restore

During restore step 4 (`docs/operations/restore.md`) the temporary single-share OpenBao refuses the unsealer's
shares: the unsealer records `invalid_share` failures and backs off. Once the restored node restarts with its own
barrier, the unsealer unseals it automatically; no manual step is needed.
