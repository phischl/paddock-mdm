# Upgrade and rollback

How to move an installation from version A to version B with the operator bundle (plan M7b decisions 27–28,
ADR 0013, ADR 0022). Upgrade the control plane first, the audit host second; agents after the servers — except
where the release notes of B say otherwise.

**Binding exception — the release with the managed-file path tiers (ADR 0034, amendment 2026-10-16): agents first,
then the server.** The new server stops shipping managed files on denied paths, and an agent older than that release
deletes every unchanged file that leaves its bundle. Upload B's agent release to the running server of A (same minor
version) and roll it out to every device first; upgrade the control plane only when no active device runs an older
agent (`docs/operations/agent-releases.md`). See residual risk RR-36 for devices that are offline meanwhile.

## Before you start

- Read the release notes of every version between A and B (`CHANGELOG.md` of B). Each release states
  `Schema: unchanged` or `Schema: migrations NNNNN–NNNNN` (both databases); that line decides how a rollback works.
- A server upgrade never requires an agent upgrade: the server supports agents of its own and the two previous minor
  versions (ADR 0013). Upload an agent release only to a server of the same or a newer minor version.

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

5. Watch the readiness of the roles and the alerts for an hour (`docs/operations/monitoring.md`). Keep A's directory
   until the next upgrade: it is the rollback.

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
