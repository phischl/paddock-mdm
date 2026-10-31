# Upgrade and rollback

How to move an installation from version A to version B with the operator bundle (plan M7b decisions 27–28,
ADR 0013, ADR 0022). Upgrade the control plane first, the audit host second; agents after the servers — except
where the release notes of B say otherwise.

**Binding exception — the release with the managed-file path tiers (ADR 0034, amendment 2026-10-16): agents first,
then the server.** The new server stops shipping managed files on denied paths, and an agent older than that release
deletes every unchanged file that leaves its bundle. Upload B's agent release to the running server of A (same minor
version) and roll it out to every device first; upgrade the control plane only when no active device runs an older
agent (`docs/operations/agent-releases.md`). See residual risk RR-36 for devices that are offline meanwhile. That
release also needs a WebAuthn authenticator for every administrator (the portal enrols one at the first sign-in),
signs every administrator out once and asks for one security review afterwards: follow the four steps in `docs/operations/install.md`, section 12.

**Release 0.1.0-alpha.4: *End all sessions* for the identity provider (ADR 0034 amendment 2026-10-18).** Authentik grants
Paddock's service account the two permissions on authenticated sessions when it applies `paddock-portal.yaml` at its
start: restart Authentik once after the upgrade (`./paddock compose restart authentik-server authentik-worker`), or
*End all sessions* records a failure with `upstream_unavailable` after it ended the portal sessions.

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
- From 0.1.0-alpha.5: upgrade the server first, then roll out the agent release; agents older than this release refuse
  the in-place encryption request as unsupported. Its migration 00067 builds an index on the vulnerability findings;
  on large finding tables the migration step takes a little longer (well under a second at 200 000 findings), and
  vulnerability updates from the inventory sync wait for it.
- From 0.1.0-alpha.6: Fleet moves to v4.93.2. That patch has no database migration, but take the Fleet dump of step 3
  anyway: a rollback restores it like for every Fleet version change. Authentik moves to 2026.8.5; `./paddock up`
  recreates its containers, and it applies the blueprints itself at that start. No extra restart and no manual
  blueprint re-apply is needed.
- From 0.1.0-alpha.6: upgrade the server first, then roll out the agent release. The release changes nothing on the
  device, so the agent rollout only aligns the version; import it with *Check for new release* on the *Agent
  releases* page (or `./paddock agent-release`) and start it with `./paddock agent-rollout <version>` or in the
  portal. Devices install Himmelblau 4.0.7 with their current agent at the next login drift pass after the server
  upgrade. The import needs outbound HTTPS from `paddock-api` to GitHub: set `HTTPS_PROXY` and `NO_PROXY` in `.env`
  if the host uses a proxy, or `PADDOCK_AGENT_RELEASE_SOURCE_REPO=off` on air-gapped installations
  (`docs/operations/agent-releases.md`, "Import from GitHub"). After the upgrade, the first identity sync records the
  current members of every Paddock role once as `admin.role_granted` with `baseline: true`, devices whose clock is
  more than 60 s off appear on the attention list as `clock_drift`, and the nightly audit chain verification starts
  (alerts `PaddockAuditChainBroken`, `PaddockAuditVerifyStale`). Schema: migrations 00068–00071 and audit migrations
  00004–00006 (new tables and columns only; no data rewrite).
- **From 0.1.0-alpha.7: no upgrade path.** This release moves PostgreSQL to 18 (new data directory layout), Valkey
  to 9 and RabbitMQ to 4.4. None of them opens the data of the previous release, and this release ships no
  migration. Install it fresh: in the old bundle directory `./paddock down --volumes` (deletes every volume of the
  project: the databases, OpenBao with its keys, the object stores, Fleet), then follow `docs/operations/install.md`
  for the new release and enrol every device again (`docs/operations/uninstall.md` for the device side). Escrowed
  recovery keys of the old installation are lost with it: before you take it down, make sure no device still needs
  one. A backup bucket may be kept on purpose: until the stanzas are upgraded, `pgbackrest` and
  `pgbackrest-authentik` refuse the old stanzas, log why and take no backup. Once the new installation runs, upgrade
  them once with `./paddock compose run --rm --no-deps pgbackrest stanza-upgrade` and `./paddock compose run --rm
  --no-deps pgbackrest-authentik stanza-upgrade`; the old backups expire with retention and cannot be restored into
  the new clusters. Fleet's MySQL stays on the 8.4 line.

## Upgrade (each host)

This section does not apply to the move to 0.1.0-alpha.7, which is a fresh installation ("Before you start").

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
3. Control plane only: take a backup — full backups of both PostgreSQL databases, an OpenBao snapshot and a dump of
   Fleet's MySQL (`docs/operations/restore.md`, "How the backups run") — and check that all four are in the backup
   bucket. Fleet migrates its database when B brings a new Fleet version, so a rollback needs that dump:

   ```sh
   ./paddock compose run --rm --no-deps pgbackrest backup --start-fast
   ./paddock compose run --rm --no-deps pgbackrest-authentik backup --start-fast
   ./paddock compose run --rm --no-deps paddock-worker backup openbao
   ./paddock compose run --rm --no-deps fleet-backup once   # fleet-backup-upload uploads it within a minute
   ```

4. Audit host only, when the release notes of a version between A and B name **audit migrations** (`Schema: … audit
   migrations …`): stop the running audit writer first, in A's directory:

   ```sh
   ./paddock compose stop paddock-audit-writer
   ```

   B's writer starts only after the audit migrations, but A's writer would keep running while they hold their table
   locks; its writes fail and are redelivered until the queue dead-letters them. Stopped, new audit events wait in the
   queue, and `./paddock up` starts B's writer, which writes them. A backfill can take minutes on a large index
   (`docs/operations/capacity.md`, *Audit index commit sequence backfill*).

5. Start B:

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

6. Watch the readiness of the roles and the alerts for an hour (`docs/operations/monitoring.md`). Keep A's directory
   until the next upgrade: it is the rollback. A's `.secrets/` stays a full copy of the secrets, including the
   OpenBao shares file `.secrets/openbao/auto-unseal-shares` when automatic unseal is on. When you disable automatic
   unseal later, delete that file in A's directory as well (`docs/operations/openbao.md` section 6, *Disabling*) —
   `./paddock auto-unseal disable` deletes only the copy of the directory it runs in — and rotate the shares if the
   host may have been copied. When you delete A's directory, delete its `.secrets/` with it.

Then the audit host, the same way without step 3.

## Notifications on a cluster initialized before them

A control-plane cluster creates its database roles once, at initialization (`postgres/init/10-roles.sh`). A cluster
initialized before the notifications (plan M9) lacks the role `paddock_notifier`, and the migration 00085 that
creates the notification tables refuses to run without it. A fresh installation (the move to 0.1.0-alpha.7 is one)
creates the role itself; this section is for clusters that already run a build without it. Before step 5 of the
upgrade, on the control plane in B's directory, after `./paddock secrets` created
`.secrets/db_paddock_notifier_password`:

```sh
./paddock compose up -d postgres
NOTIFIER_PASSWORD="$(cat .secrets/db_paddock_notifier_password)" ./paddock compose exec -T -e NOTIFIER_PASSWORD \
  postgres psql -v ON_ERROR_STOP=1 -q -U postgres -d paddock <<'SQL'
\set pw `printf '%s' "$NOTIFIER_PASSWORD"`
SELECT format('CREATE ROLE paddock_notifier LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS PASSWORD %L', :'pw')
  WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'paddock_notifier') \gexec
GRANT CONNECT ON DATABASE paddock TO paddock_notifier;
GRANT USAGE ON SCHEMA public TO paddock_notifier;
SQL
```

The password reaches `psql` through the container's environment, never a command line. The step is idempotent.
After step 5, run `./paddock bootstrap openbao` once with a root token (`docs/operations/openbao.md` section 1): it
adds the Transit key `notification-wrap`, the encrypt permission of `paddock-api`, the policy and AppRole
`paddock-notifier`, and keeps every existing secret ID. The same release adds the commit sequence of the audit index:
its audit migration backfills every existing event, so stop the audit writer first (step 4; duration in
`docs/operations/capacity.md`, *Audit index commit sequence backfill*).

## Rollback

Migrations only move forward (`server/migrations/`; there is no down migration), so a rollback depends on the release
notes of B:

- **`Schema: unchanged`**: in B's directory `./paddock down`, then in A's directory `./paddock up`. Same project,
  same volumes, A's images by digest from A's `versions.env`.
- **`Schema: migrations …`**: A cannot run on B's schema. Restore the backup of step 3 with the restore runbook
  (`docs/operations/restore.md`), then `./paddock up` in A's directory. **Every change written after that backup is
  lost** (devices that checked in, audit events in the control-plane database, configuration edits); the audit
  domain's WORM evidence stays.
- **B changes the Fleet version** (`FLEET_IMAGE` in `versions.env`): in both cases A's Fleet cannot run on the
  database B's Fleet migrated. Before `./paddock up` in A's directory, restore the Fleet dump of step 3 into an empty
  `fleet-mysql` (`docs/operations/restore.md`, step 6).

Never edit the shipped files of a bundle to change behaviour: `./paddock verify` reports it, and the next upgrade
replaces them. Settings belong in `.env`.

## Upstream version watch

Dependabot proposes updates for Go modules, npm packages and GitHub Actions. It does not see the container images
pinned by tag and digest in `deploy/compose/versions.env`, the Himmelblau version the compiler rolls out
(`PADDOCK_HIMMELBLAU_VERSION` default in `server/cmd/paddock-server/compiler.go`), the fleetd build version (the tag
of `FLEETCTL_IMAGE`, reported as `fleetctl`) and the Fleet NVD release of `FLEET_CPE_DATABASE_URL` (reported as
`fleet_nvd`). The workflow *upstream-watch* (`.github/workflows/upstream-watch.yml`, every Monday 05:17 UTC and on
demand) compares each of them with upstream (ADR 0037 amendment 2026-10-17):

- **What it checks.** Images: the registry's tag list (Docker Hub API; ghcr.io, gcr.io and mcr.microsoft.com through
  the anonymous OCI distribution API). The latest tag is the highest tag of the same shape as the pin (`2.11.6` only
  compares with `x.y.z`, `4.3.6-management` with `x.y.z-management`). The floating `nonroot` tag of `RUNTIME_IMAGE` is
  compared by manifest digest. A pin can follow one line only (`Line` in `tools/upstreamwatch/pins.go`, today Fleet's
  MySQL on `8.4.`); newer lines are not reported for it. Himmelblau: the directory listing of
  `packages.himmelblau-idm.org/stable/`. Fleet NVD: the latest release of `fleetdm/nvd`. Each pin is classified `patch`, `minor`, `major`, `digest`, `ok` or `unknown`
  (a lookup failed; printed in the job log, never an issue).
- **The label.** Every outdated pin gets exactly one open issue with the label `upstream` and the title
  `upstream: <name> <pinned> → <latest>`. The body names the pinned line, the latest version, the classification,
  the release notes and the gates to run before the bump. When upstream moves again the issue is edited; once the pin
  is current the issue gets the comment `pinned <version> now` and is closed.
- **What to do with an issue.** Read the release notes, bump the pin in its own branch (resolve the new digest with
  `docker buildx imagetools inspect <image>:<tag>`), run the gates the issue lists, open a pull request. The
  watch closes the issue on its next run after the merge.
- **Local run.** `make upstream-check` prints one line `<name> <pinned> <latest> <classification>` per pin
  (`go run ./tools/upstreamwatch check --json` for JSON). Docker Hub rate-limits anonymous listings; a pin that
  turns `unknown` locally is retried by the next run.
- **Why issues and not pull requests.** Every pin has a gate a person runs before merging (WORM gate for RustFS,
  `TestIdentityLockAuthentik` for Authentik, the inventory gates for Fleet, the restore drill for Postgres and Caddy,
  the gitleaks default config hash for gitleaks). A bot pull request would suggest a bump is ready when it is not,
  and a bot with repository write access (Renovate) was rejected as a new external dependency. The job has
  `contents: read` and `issues: write` only.
