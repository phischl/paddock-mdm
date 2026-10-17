# 0035 — Automatic unseal of OpenBao, acknowledged in the portal, performed on the host
Status: Accepted (2026-10-17)

## Context

OpenBao starts sealed after every restart of its container or host (ADR 0006: Shamir 3 of 5, shares with named
custodians). While it is sealed, the api cannot load the session keys after its own restart, so the portal login
fails; the compiler cannot sign bundles, the worker cannot sign commands, the escrow reader cannot decrypt, and the
daily audit seal fails (`docs/operations/openbao.md` section 2). Devices keep working (design contract 8).

The maintainer requires an option for the administrator to unseal automatically, configurable in the portal where
possible, with a disclaimer that names the risks and an explicit confirmation that the risk is understood and
accepted. The lab installation (ADR 0029) currently uses a hand-made cron job on the host that keeps three shares in
a file and unseals when OpenBao reports sealed; it is a stop-gap that nothing in Paddock knows about, checks or
audits.

Facts that bound the design (verified 2026-10-17, OpenBao 2.7.1 per `deploy/compose/versions.env`):

- The unseal material cannot come from OpenBao itself, and the api must not reach the host's Compose configuration
  or Docker socket: the api is the most exposed role, and a Docker socket is root on the host.
- OpenBao 2.7.1 ships two built-in auto-unseal seals, `transit` (a second OpenBao) and `static` (a 32-byte
  AES-256 key from a file or an environment variable); every cloud KMS, KMIP and PKCS#11 seal is an external plugin
  since 2.7.0. Switching between Shamir and an auto seal is a *seal migration*: downtime, `bao operator unseal
  -migrate` with the threshold of shares (which become recovery keys), and the reverse with `disabled = "true"`.
  OpenBao's documentation calls the seal mechanism a lifecycle dependency: if its key is permanently lost, the
  cluster cannot be recovered, not even from backups.
- `sys/seal-status` and `sys/unseal` need no token. The `paddock-server` binary already uses the OpenBao Go client
  (`server/internal/platform/bao`), and the worker already polls `sys/health` for `paddock_openbao_sealed`.
- Restore (`docs/operations/restore.md` step 4) relies on the Shamir shares: a restored snapshot is unsealed by the
  custodians after a restart.
- Every PostgreSQL role is created once at cluster initialization (`deploy/compose/postgres/init/10-roles.sh`);
  migrations run as `paddock_owner` (`NOCREATEROLE`).
- Platform routes accept portal sessions only; API tokens have no platform scope (plan M7a decision 16).

## Options

### A. Who performs the unseal

- **A1 — OpenBao's native `static` seal, switched by `./paddock`, reflected in the portal.** + No Paddock code in the
  unseal path; documented upstream. − Enabling and disabling are seal migrations with downtime and three custodians
  each; the static key becomes a lifecycle dependency (lost key = unrecoverable snapshots), so an offline copy of it
  would be mandatory and the restore runbook would change; the portal can never make a disable effective, because
  OpenBao unseals itself regardless of any Paddock setting. Rejected.
- **A2 — OpenBao's `transit` seal against a second OpenBao, or a KMS/PKCS#11 plugin.** − The second OpenBao has the
  same unseal problem; a KMS or HSM is not available (ADR 0006) and would add an external plugin and a cloud
  dependency. Remains, as today, the operator's own option outside the bundle (architecture §13.2). Rejected as the
  bundled mechanism.
- **A3 — A dedicated Paddock role on the host, `paddock-unsealer`, that holds a copy of three shares and submits
  them to `sys/unseal` while a platform setting says "enabled" (chosen).** + Shamir stays the seal: snapshots,
  restore, rekey and the custodians' shares are unchanged; losing the copied shares loses nothing; no downtime to
  enable or disable; the portal setting is effective at once (the unsealer does not act while it is disabled);
  truthful status (the unsealer reports its own state) and an audit event per unseal. − About 300 lines of Paddock
  code in a security-relevant path (poll, compare, submit three strings), one more container, one more PostgreSQL
  role; the material is still a file on the host (as with every auto-unseal that is self-contained).
- **A4 — The portal stores intent only; the operator keeps a script of their own (status quo of the lab).** − No
  gate between intent and material, no status, no audit, no check. Rejected.

### B. Where the gate between the acknowledgement and the material lives

- **B1 — The unsealer reads the setting from PostgreSQL with its own role `paddock_unsealer`** (`SELECT` on one
  table, `UPDATE` on its own status columns) (chosen). + One durable copy of the security decision; least
  privilege; no staleness. − A role added after the first release has to be created on existing clusters: an
  idempotent script that `./paddock auto-unseal enable` runs, plus a conditional grant in the migration.
- **B2 — The api mirrors the setting into Valkey; the unsealer reads Valkey.** + No new PostgreSQL role. − A
  security gate read from a cache that is rebuilt from PostgreSQL by design (ADR 0016); every role shares the Valkey
  password today, so any role could flip the mirrored flag. Rejected.
- **B3 — The unsealer uses the existing `paddock_platform` role.** − The holder of the shares would also hold write
  access to every platform table and to the outbox of every organization. Rejected.

### C. Who records the audit event of an unseal

- **C1 — The unsealer itself through `ActionRunner`.** − Needs `INSERT` on `action` and `outbox` and row-level
  policies for the new role: the holder of the shares could write arbitrary platform audit events. Rejected.
- **C2 — The unsealer counts its unseals and failures in its status columns; the worker, which already probes
  OpenBao every 30 s with the platform role, records one `platform.openbao_auto_unsealed` event per observed change
  through `ActionRunner` (chosen).** + The unsealer writes nothing but its own report; the registry rule "exactly one
  event per attempt" holds per observed unseal. − The event appears up to 30 s after the unseal.

### D. What the portal can do

- **D1 — The portal switches the mechanism.** Impossible without the api reaching the host. Rejected.
- **D2 — The portal records the decision and shows the truth (chosen).** A platform administrator with a fresh
  step-up reads a versioned disclaimer, types the acknowledgement sentence and enables the setting; the host
  operator then runs `./paddock auto-unseal enable`, which refuses without that acknowledgement, collects three
  shares from the custodians and starts the unsealer. The portal shows the setting, who acknowledged which disclaimer
  version and when, whether the unsealer runs and holds shares, and the last automatic unseal. Disabling in the
  portal stops the unsealer's action at once; the shares stay on the host until `./paddock auto-unseal disable`
  removes them, and the portal and an alert say so.

### E. Production

- **E1 — Lab only.** − The maintainer asked for an administrator option, and a feature that is refused in production
  would need no disclaimer. Rejected.
- **E2 — Allowed everywhere, `./paddock check` warns on a production host (`WARN`, not `FAIL`) and passes on a lab
  host; the disclaimer is the same (chosen).** The check gains a `WARN` status for exactly this item; warnings never
  change the exit code.

## Decision

1. **Unsealer role.** `paddock-server serve unsealer` (package `server/internal/unsealer`), Compose service
   `paddock-unsealer` in the overlay `deploy/compose/compose.auto-unseal.yaml`, which `./paddock` adds to the file
   set of a control-plane or lab host when `.env` has `PADDOCK_AUTO_UNSEAL=yes`. Every 10 s it reads the shares file
   `.secrets/openbao/auto-unseal-shares` (exactly three lines, mounted as the Compose secret
   `openbao_auto_unseal_shares` into this service only), reads the setting `openbao_auto_unseal.state` with the
   PostgreSQL role `paddock_unsealer`, reads `sys/seal-status`, and submits the three shares to `sys/unseal` only
   when OpenBao is initialized and sealed, the state is `enabled` and the shares are present. It never logs or
   reports a share. A failed attempt resets the unseal progress and backs off for 60 s. It reports `unsealer_seen_at`,
   `unsealer_shares_present`, `unseal_count`, `last_unseal_at`, `failure_count`, `last_failure_at` and
   `last_failure_reason` in the same row. It has no AppRole, no Valkey, no RabbitMQ and no other database access.
2. **Setting and acknowledgement.** Migration `00049_openbao_auto_unseal.sql` creates the single-row table
   `openbao_auto_unseal` (platform data, role `paddock_platform`; conditional grants to `paddock_unsealer`). A
   platform administrator with a step-up within the last 5 minutes enables it with
   `POST /api/platform/v1/openbao/auto-unseal/enable` carrying `disclaimer_version` (must equal the current version
   `2026-10-17`) and `acknowledgement` (must equal, byte for byte, the English or the German acknowledgement sentence
   of that version), and disables it with `POST /api/platform/v1/openbao/auto-unseal/disable`;
   `GET /api/platform/v1/openbao/auto-unseal` returns the setting, the unsealer's report and OpenBao's seal status.
   Audit codes: `platform.auto_unseal_enabled` (params `disclaimer_version`, `acknowledgement`, `previous_state`),
   `platform.auto_unseal_disabled` (`previous_state`, `method`), `platform.openbao_auto_unsealed` (recorded by the
   worker: `unseals`, `failures`, `last_unseal_at`, `last_failure_at`, `last_failure_reason`). API tokens never
   reach platform routes; `paddock-server admin auto-unseal show|verify|disable` exists for the host, there is no CLI
   enable: enabling is a person's acknowledgement.
3. **Host commands.** `./paddock auto-unseal status|enable|disable`. `enable` runs on a control-plane or lab host
   only, refuses without the portal acknowledgement (`admin auto-unseal verify`), creates the role
   `paddock_unsealer` idempotently, prompts for three shares without echo (stdin, never a command line), writes the
   shares file, sets `PADDOCK_AUTO_UNSEAL=yes` and starts the unsealer. `disable` stops and removes the unsealer,
   deletes the shares file and sets `PADDOCK_AUTO_UNSEAL=no`. Neither command prints a share.
4. **Check.** `./paddock check` gains the item `openbao auto-unseal`: `FAIL` when the unsealer is configured without
   `PADDOCK_AUTO_UNSEAL=yes` or the switch is set without the unsealer, when the shares secret is mounted into any
   other service, when the unsealer mounts an AppRole secret or a database URL other than its own, or when the
   switch is set on the audit host; `WARN` on a control-plane host while automatic unseal is on; `PASS` otherwise.
   The existing items (secret files private, `PADDOCK_ENV=production`, container hardening, TLS links) apply to the
   new service unchanged.
5. **Disclaimer.** One text, versioned by date, in English and German in the portal catalog; the exact text is in
   plan M8u §6.6 and is binding. It names: whoever controls the host or a copy of its disk, snapshots or `.secrets/`
   can unseal and use every key (signing, escrow, audit chain, sessions); the custodian threshold of ADR 0006 no
   longer gates the unseal; copies and backups of the host become as sensitive as the keys; it is a residual risk of
   the ISMS (RR-43); production hosts get a warning on every check. A new version of the text gets a new date; an
   acknowledgement of an older version is shown as such and is not withdrawn automatically.
6. **Backups.** The shares file is never part of a Paddock backup (pgBackRest and the OpenBao snapshot do not read
   `.secrets/`), and no runbook lists it among the files to copy offline. The custodians' shares remain the only
   recovery path; `bao operator rekey` after disabling invalidates every copy of the shares file.
7. **Observability.** Worker metrics `paddock_auto_unseal_enabled`, `paddock_auto_unseal_shares_present`,
   `paddock_auto_unseal_unsealer_up`; alerts `PaddockAutoUnsealWithdrawn` (disabled in the portal but shares still
   on the host, 1 h) and `PaddockAutoUnsealerDown` (enabled but no report for 10 min). The unsealer exports
   `paddock_unsealer_unseals_total{result}` and is scraped through a scrape file the overlay mounts.
8. **Lab migration.** The lab guide replaces the cron stop-gap: enable in the portal, `./paddock auto-unseal enable`,
   remove the cron job and its share file, verify with a restart of the OpenBao container.

## Consequences

- + Restarts of the host or the OpenBao container no longer need three people; the portal is reachable again within
  about 30 s; bundles, commands, escrow and the daily audit seal continue.
- + The decision is a recorded, step-up-protected, versioned acknowledgement in the audit trail, and the mechanism
  cannot exist without it; disabling in the portal is effective at once.
- + Shamir, snapshots, restore and rekey are unchanged; nothing in OpenBao is reconfigured.
- − **The custodian model no longer protects the unseal** while the setting is on: three shares lie on the host.
  Root on the host, a disk image, a VM snapshot or a copy of `.secrets/` unseals OpenBao. Residual risk RR-43.
- − One more container and one more PostgreSQL role; a role created after the first release needs the idempotent
  creation step in `./paddock auto-unseal enable`.
- − The audit event of an unseal is recorded by the worker, up to 30 s after the unseal.
- Follow-ups: the Valkey ACL split (AZ-4) and a per-role scrape discovery are unaffected; a future seal of OpenBao
  by Paddock itself (`sys/seal`) for incident response is a separate decision.
- Amended documents: architecture §13.2 and §25.2 (automatic unseal is the bundled, acknowledged option), ADR 0006
  (amendment pointing here), `docs/compliance/residual-risks.md` (RR-43).
