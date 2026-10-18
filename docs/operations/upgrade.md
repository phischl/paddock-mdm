# Upgrade and rollback

How to move an installation from version A to version B with the operator bundle (plan M7b decisions 27–28,
ADR 0013, ADR 0022). Upgrade the control plane first, the audit host second; agents after the servers — except
where the release notes of B say otherwise.

**Binding exception — the release with the managed-file path tiers (ADR 0034, amendment 2026-10-16): agents first,
then the server.** The new server stops shipping managed files on denied paths, and an agent older than that release
deletes every unchanged file that leaves its bundle. Upload B's agent release to the running server of A (same minor
version) and roll it out to every device first; upgrade the control plane only when no active device runs an older
agent (`docs/operations/agent-releases.md`). See residual risk RR-36 for devices that are offline meanwhile. That
release also needs a WebAuthn authenticator for every administrator before the upgrade, signs every administrator out
once and asks for one security review afterwards: follow the four steps in `docs/operations/install.md`, section 12.

## Before you start

- Read the release notes of every version between A and B (`CHANGELOG.md` of B). Each release states
  `Schema: unchanged` or `Schema: migrations NNNNN–NNNNN` (both databases); that line decides how a rollback works.
- A server upgrade never requires an agent upgrade: the server supports agents of its own and the two previous minor
  versions (ADR 0013). Upload an agent release only to a server of the same or a newer minor version.
- From 0.1.0-alpha.4: after this upgrade every Authentik sign-in — the portal, Authentik's own user and admin interfaces
  (`akadmin` included) and the device approval page — asks for a second factor and enrols one when missing.
- From 0.1.0-alpha.4: the fix that keeps the Hello PIN working while a user stays signed in is on the device (the
  agent writes `cache_timeout` into `himmelblau.conf`). Roll out the agent release first; devices with an older agent
  keep losing the PIN after a few minutes of use (residual risk RR-40).

## Upgrade (each host)

1. Download the bundle of B and its `.sigstore.json` and verify them as `docs/operations/install.md` section 3
   describes. Extract it next to the running bundle directory, for example `/opt/paddock/paddock-deploy-<B>/` beside
   `/opt/paddock/paddock-deploy-<A>/`.
2. In B's directory:

   ```sh
   ./paddock migrate-from ../paddock-deploy-<A>     # copies .env and .secrets/ (cp -a); refuses if they exist here
   ./paddock pull
   ./paddock check                                  # audit host: ./paddock check --online; every item PASS
   ```

   Compare `.env.example` of A and B: new settings of B have defaults; set them in `.env` if your installation needs
   other values. Keep `PADDOCK_PROJECT` unchanged, so that B uses the same containers, networks and volumes.
3. Control plane only: take a backup — full backups of both PostgreSQL databases and an OpenBao snapshot
   (`docs/operations/restore.md`, "How the backups run") — and check that all three are in the backup bucket.
4. Start B:

   ```sh
   ./paddock up        # recreates the containers with B's images; paddock-migrate applies the schema migrations
   ./paddock ps        # before the roles start
   ```

   Control plane: when B changes the OpenBao image or its configuration, `./paddock up` recreates OpenBao and it
   starts **sealed**. The Paddock roles cannot become healthy until it is unsealed, so `./paddock up` keeps waiting
   (up to 15 minutes, then it fails and names OpenBao as sealed). Have three custodians ready: while it waits, they
   run `./paddock bao operator unseal` in a second shell, one share each (`docs/operations/install.md` section 6);
   if it timed out, unseal and run `./paddock up` again. With automatic unseal on (`docs/operations/openbao.md`
   section 6) the unsealer does this. `./paddock up` never unseals by itself: the shares are not on the host.

5. Watch the readiness of the roles and the alerts for an hour (`docs/operations/monitoring.md`). Keep A's directory
   until the next upgrade: it is the rollback. A's `.secrets/` stays a full copy of the secrets, including the
   OpenBao shares file `.secrets/openbao/auto-unseal-shares` when automatic unseal is on. When you disable automatic
   unseal later, delete that file in A's directory as well (`docs/operations/openbao.md` section 6, *Disabling*) —
   `./paddock auto-unseal disable` deletes only the copy of the directory it runs in — and rotate the shares if the
   host may have been copied. When you delete A's directory, delete its `.secrets/` with it.

Then the audit host, the same way without step 3.

## Rollback

Migrations only move forward (`server/migrations/`; there is no down migration), so a rollback depends on the release
notes of B:

- **`Schema: unchanged`**: in B's directory `./paddock down`, then in A's directory `./paddock up`. Same project,
  same volumes, A's images by digest from A's `versions.env`.
- **`Schema: migrations …`**: A cannot run on B's schema. Restore the backup of step 3 with the restore runbook
  (`docs/operations/restore.md`), then `./paddock up` in A's directory. **Every change written after that backup is
  lost** (devices that checked in, audit events in the control-plane database, configuration edits); the audit
  domain's WORM evidence stays.

Never edit the shipped files of a bundle to change behaviour: `./paddock verify` reports it, and the next upgrade
replaces them. Settings belong in `.env`.
