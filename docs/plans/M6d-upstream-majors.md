# Implementation plan: M6d — Upstream major upgrades for 0.1.0-alpha.7 (PostgreSQL 18, Valkey 9, RabbitMQ 4.4, Fleet's MySQL line)

Status: Ready for implementation · 2026-10-29 · Author: architect
Basis: ADR 0002 (PostgreSQL with RLS), ADR 0003 (RabbitMQ and Valkey), ADR 0009 (Fleet), ADR 0013 (version
compatibility), ADR 0016 (backups; Accepted 2026-10-29), ADR 0022 (operator bundle), ADR 0029 (lab profile), ADR 0037
amendment 2026-10-17 (upstream version watch, plan M8d §14.3); plan M6a decisions 4–7 (pgBackRest, restore drill);
maintainer decision 2026-10-29 (quoted in §2).

Binding language: **MUST** / **MUST NOT** / **SHOULD** / **MAY**.

## 1. Goal

After M6d the stack runs PostgreSQL 18, Valkey 9 and RabbitMQ 4.4 (all three databases of the control plane and the
audit domain included), Fleet's MySQL stays on the 8.4 LTS line that Fleet documents, and the upstream version watch
stops reporting MySQL lines Fleet does not support. Release 0.1.0-alpha.7 is a documented breaking release: an
installation of 0.1.0-alpha.6 is not upgraded but installed fresh. The maintainer's own lab keeps its data — above
all the escrowed LUKS recovery key of the one enrolled laptop — through a manual, lab-only carry-over that is not
part of the product.

## 2. Context (verified in the code on 2026-10-29, `main` at `dbdebe9b`)

**Maintainer decision (2026-10-29, binding):** "We don't need a real upgrade path. We're in alpha, so if in doubt
it's a breaking change. We have exactly 0 users right now." Consequence: no `pg_upgrade` tooling, no migration
container, no operator upgrade path, no rollback story for these four components. The only installation whose data
matters is the maintainer's lab (ADR 0029 profile, one host) with one enrolled laptop whose LUKS recovery key is
escrowed.

**Pins** (`deploy/compose/versions.env`): `POSTGRES_IMAGE=postgres:17.11`, `VALKEY_IMAGE=valkey/valkey:8.1.10`,
`RABBITMQ_IMAGE=rabbitmq:4.3.6-management`, `FLEET_MYSQL_IMAGE=mysql:8.4.11`. Every pin is tag plus digest.

**PostgreSQL users.** `POSTGRES_IMAGE` runs three clusters: `postgres` (database `paddock`) and `authentik-postgres`
(database `authentik`) in `deploy/compose/compose.yaml`, `audit-postgres` (database `paddock_audit`) in
`deploy/compose/compose.audit.yaml`. All three mount their named volume at `/var/lib/postgresql/data`
(`postgres-data`, `authentik-postgres-data`, `audit-postgres-data`). Roles are created once at cluster
initialization by `deploy/compose/postgres/init/10-roles.sh` and `deploy/compose/audit-postgres/init/10-roles.sh`
(`CREATE ROLE … PASSWORD`, which stores SCRAM-SHA-256 since the server default `password_encryption =
scram-sha-256`; nothing in the repository configures `md5`). `deploy/compose/scripts/postgres-unsealer-role.sh`
adds `paddock_unsealer` idempotently (run by `make up` and `./paddock auto-unseal enable`). Integration tests start
the pinned image through testcontainers (`server/internal/testsupport/pgtest/pgtest.go`, `Image(t, "POSTGRES_IMAGE")`)
without a data volume. Row-level security uses `current_setting('paddock.org_id')::uuid` without `missing_ok`;
PostgreSQL 18 changes nothing about `current_setting` or RLS. Existing generated columns are `STORED`
(`server/migrations/paddock/00039_version_key.sql`, `00044_device_status_version_key.sql`). No `COPY … CSV`, no
`pg_stat_wal` or `pg_stat_io` column is read by the server.

**Backups** (`deploy/compose/compose.backup.yaml`, plan M6a decision 4, `docs/operations/restore.md`): PostgreSQL
runs with `archive_mode=on`; `archive_command` copies WAL into a spool volume; one pgBackRest container per stanza
(`pgbackrest` for `paddock`, `pgbackrest-authentik` for `authentik`) mounts the data volume at
`/var/lib/postgresql/data` and pushes the spool. `deploy/compose/pgbackrest/run.sh` sets
`PGBACKREST_PG1_PATH=/var/lib/postgresql/data`, creates the stanza once (`ensure_stanza`: `stanza-create`, then a
marker file in the state volume) and restores with `pgb restore` into the empty data directory.
`deploy/compose/pgbackrest/Dockerfile` installs the Debian trixie package `pgbackrest` (2.55.1-1) on
`COMPILER_RUNTIME_IMAGE` and creates `/var/lib/postgresql/data` for uid 999. `deploy/compose/pgbackrest/pgbackrest_test.sh`
(run by `make test`) starts the pinned PostgreSQL image with `-v …:/var/lib/postgresql/data`. The restore drill
`deploy/compose/scripts/restore-drill.sh` (`make restore-drill`) deletes the volumes `postgres-data`,
`authentik-postgres-data`, the spool and state volumes and `openbao-data`, restores and runs an acceptance subset.
The audit database is not backed up (ADR 0016).

**pgBackRest and PostgreSQL 18.** pgBackRest added PostgreSQL 18 support in 2.55.0 (2025-04-21, before the first
beta; Debian labels it experimental). Verified on 2026-10-29 against the sources: `src/postgres/interface/version.vendor.h`
of `release/2.55.1` defines for PostgreSQL 18 `PG_CONTROL_VERSION 1800` and `XLOG_PAGE_MAGIC 0xD118`; the
PostgreSQL `REL_18_STABLE` branch defines the same two values (`src/include/catalog/pg_control.h`,
`src/include/access/xlog_internal.h`). The catalog version constant differs, but pgBackRest reads the catalog
version from `pg_control` and does not validate it against the constant. No pgBackRest release from 2.55.1 to 2.60.0
(2026-10-18) carries a PostgreSQL 18 fix. The Debian trixie package therefore stays; no PGDG repository is added.

**PostgreSQL 18 official image** (`docker-library/docs`, postgres): from 18 the declared `VOLUME` is
`/var/lib/postgresql` (17 and below: `/var/lib/postgresql/data`) and the default `PGDATA` is version specific,
`/var/lib/postgresql/18/docker`. "Mounts and volumes should be targeted at the updated location." A mount at the old
path without `PGDATA` set would leave the data in an anonymous volume at `/var/lib/postgresql`. Docker Hub has
`postgres:18.6` (Debian trixie based; `18.6-trixie` is the same image). PostgreSQL 18 release notes relevant here:
`initdb` enables data checksums by default; MD5 password authentication is deprecated (warnings on `CREATE ROLE …
PASSWORD` only when an MD5 password is set); a dump/restore or `pg_upgrade` is required to migrate data from any
previous release; generated columns default to virtual (`STORED` keeps the previous behaviour); primary/foreign key
pairs must use deterministic collations (Paddock uses the default collation and `COLLATE "C"`).

**Valkey** (`VALKEY_IMAGE`): `valkey` (cache and nonce store of the control plane) and `fleet-redis` (Fleet's
Redis) in `compose.yaml`, both with `deploy/compose/valkey/valkey.conf` (`appendonly yes`, `appendfsync everysec`,
`dir /data`, `include /run/secrets/valkey_auth_conf` for `requirepass`) and a named volume at `/data`. Client:
`github.com/valkey-io/valkey-go v1.0.79` (`server/go.mod`). ADR 0016: Valkey is not backed up and is rebuilt from
PostgreSQL (`paddock-server admin rebuild-cache`). Docker Hub has `valkey/valkey:9.1.3` (2026-10-26; `9.0.7` and
`8.1.11` are the other current lines). The 9.0.0 release notes list no change to configuration keys, ACLs or the
persistence format that touches this configuration; `requirepass` remains supported. Fleet documents no Redis
version policy; its reference architectures use Redis 6 and 7, and Valkey keeps Redis 7.2 command compatibility.

**RabbitMQ** (`RABBITMQ_IMAGE`): `deploy/compose/rabbitmq/rabbitmq.conf` (definitions import from
`/etc/rabbitmq/definitions.json`, `default_queue_type = quorum`, `loopback_users = none`), `enabled_plugins`
`[rabbitmq_management,rabbitmq_prometheus]`, `tls.conf` for the amqps listener in production, named volume
`rabbitmq-data`. Client `github.com/rabbitmq/amqp091-go v1.16.0`. ADR 0016: RabbitMQ is not backed up. The 4.4.0
release notes (2026-10-19): supports Erlang 28 and 29; removed parsing of `x-amqp-1.0-*` headers and `x-basic-*`
annotations; `GET /api/auth/hash_password/{password}` replaced by `POST`; stricter OAuth 2 discovery validation;
`connection_max`/`channel_max` renamed (old names still work); classic queues write a v2 message store that 4.3
cannot read; no new or required feature flag. Khepri is the default metadata store since 4.2.0; a node started on
an empty volume enables every stable feature flag. Docker Hub has `rabbitmq:4.3.7-management` and
`rabbitmq:4.4.0-management` (Erlang/OTP 29). The 4.3.7 intermediate step only matters for a node whose volume was
written by 4.3.x with Erlang 27; it does not apply to a fresh volume.

**Fleet's MySQL** (`FLEET_MYSQL_IMAGE`): `fleet-mysql` in `compose.yaml` and `fleet-backup` (mysqldump) in
`compose.backup.yaml`. `FLEET_IMAGE=fleetdm/fleet:v4.93.2`. Fleet's reference architecture page (2026-10-29): "Fleet
requires at least MySQL version 8.0.44", "tested using the InnoDB storage engine with versions 8.0.44, 8.4.8, and
9.5.0", "MySQL 9.6.0 is currently incompatible." Docker Hub has `mysql:8.4.13` (newest 8.4), `9.7.4` and `26.10.0`
(the year-based line that the watch reports as `26.7.0 → 26.10.0`; it is not documented by Fleet).

**Upstream version watch** (`tools/upstreamwatch`, plan M8d decisions 57–62): `compare.go` `Latest(pinned, tags)`
picks the highest tag of the pinned tag's *shape* (`8.4.11` → `^\d+\.\d+\.\d+$`), so `26.10.0` is "latest" for
`mysql:8.4.11` and issue #97 can never close while Paddock stays on 8.4. `pins.go` `PinInfo{Name, GitHub, Gates}`;
`check.go` line 52 calls `Latest(p.Pinned, tags)`; `issues.go` `Body(r)` writes the issue body. Tests
`compare_test.go` (`TestShapeAndLatest`, `TestClassify`), `pins_test.go` (`TestEveryPinIsMapped`).

**Lab** (ADR 0029, `docs/operations/lab-install.md`): one host, Compose project `${PADDOCK_PROJECT}` (default
`paddock`), files `compose.yaml compose.prod.yaml compose.audit.yaml compose.lab.yaml` plus `compose.backup.yaml`
when `PADDOCK_LAB_BACKUP=yes`. The bundle entry script `./paddock` offers `compose`, `up`, `down [--volumes]`,
`migrate-from`, `pull`, `check`, `auto-unseal status`. The escrowed recovery key is a row of table `escrow_secret`
in database `paddock` (`server/migrations/paddock/00012_escrow.sql`), encrypted with the OpenBao transit key
`escrow-wrap` (ADR 0006); OpenBao is not changed by this plan. Triggers of the `paddock` schema
(`organization_login_settings_default`, `device_cache_notify`, `outbox_notify`) and of the audit schema
(`audit_object_day_unsealed`) are created by `pg_restore` in the post-data section, after the data is loaded, so a
full dump/restore does not fire them. The audit database uses the extension `pg_trgm`.

**Documentation that names versions:** `docs/architecture.md` line 50 ("PostgreSQL 17"), `docs/adr/0002` line 16
("PostgreSQL 17"), `docs/operations/fleet.md` line 10 ("MySQL 8.4"). `docs/operations/upgrade.md` has one bullet
per release under "Before you start". Changelog entries are fragments in `changelog.d/<ticket>.<section>.md`
(PDK-518).

**Delivery** (`.claude/roadmap/alpha7-plan.md`, cluster E): the four tickets form cluster E2 on the integration
branch `cluster/upstream-majors`; ticket PRs target that branch; the expensive local gates run once on the cluster
head; one PR `cluster/upstream-majors` → `main`.

## 3. Binding decisions

1. **0.1.0-alpha.7 is a breaking release without an upgrade path for these components.** The release notes and
   `docs/operations/upgrade.md` say plainly: an installation of 0.1.0-alpha.6 or earlier is installed fresh
   (`./paddock down --volumes` in the old directory, then `docs/operations/install.md`); all data, including
   escrowed recovery keys and device enrollments, is gone, and devices are enrolled again. Rationale: the
   maintainer decision of 2026-10-29; a `pg_upgrade` container, stanza upgrade tooling and a MySQL dump path would
   be product code for zero users.
2. **One cluster, four tickets, one lab carry-over.** The tickets run on `cluster/upstream-majors` in the order
   PDK-354 (RabbitMQ) → PDK-344 (Valkey) → PDK-345 (MySQL line and watch) → PDK-343 (PostgreSQL, the largest and the
   one that documents the breaking release). The lab carry-over (§3.10) runs once, after the cluster is on `main`.
   Rationale: one fresh install of the lab for four components instead of four; the PostgreSQL ticket is last so
   that its release note describes the final state.
3. **PostgreSQL 18.6.** `POSTGRES_IMAGE=postgres:18.6@sha256:<digest resolved with docker buildx imagetools
   inspect postgres:18.6>`. The same image for all three clusters (`postgres`, `authentik-postgres`,
   `audit-postgres`). Rationale: one pin, one gate set; Authentik's own Helm chart moved to PostgreSQL 18 with
   authentik 2026.8.
4. **The volume layout follows the 18 image: mount at `/var/lib/postgresql`, data directory
   `/var/lib/postgresql/18/docker`.** Every PostgreSQL service mounts its named volume at `/var/lib/postgresql`
   and sets no `PGDATA`; the volume names stay. pgBackRest mounts the same volume at `/var/lib/postgresql` and uses
   `PGBACKREST_PG1_PATH=/var/lib/postgresql/18/docker`. Rationale: a mount at the old path would need an explicit
   `PGDATA` and would still leave the image's anonymous volume; the upstream layout is what the image documents and
   what a future `pg_upgrade --link` needs. Alternative rejected: `PGDATA=/var/lib/postgresql/data` with the old
   mounts (smaller diff, but off the documented path and an anonymous volume per container).
5. **Data checksums stay on (the 18 default).** No `POSTGRES_INITDB_ARGS`. Rationale: pgBackRest verifies page
   checksums during backup, which turns silent corruption into a failed backup; the CPU cost is negligible at
   Paddock's write rate.
6. **pgBackRest from Debian trixie (2.55.1) stays; the stanza handles a changed cluster.** `ensure_stanza` in
   `run.sh` runs `stanza-create` and, when that fails, `stanza-upgrade`, then writes the marker. Rationale: the
   release constants match PostgreSQL 18 (§2); `stanza-upgrade` is what pgBackRest provides when a stanza's cluster
   changes version or system identifier, so a repository that already holds a stanza (the lab's bucket, a reused
   bucket) does not stall the backups with "backup and archive info files exist but do not match the database".
   Backups of the old cluster stay in the repository until retention expires them; they cannot be restored into 18
   and nothing in the product offers to.
7. **Valkey 9.1.3 for `valkey` and `fleet-redis`.** `VALKEY_IMAGE=valkey/valkey:9.1.3@sha256:<digest>`. No change to
   `valkey.conf`. Rationale: the configuration uses only `appendonly`, `appendfsync`, `dir`, `include` and
   `requirepass`, all unchanged in 9; Fleet's Redis use is covered by the inventory gates; a separate pin for
   `fleet-redis` would double the watch surface for no documented Fleet requirement.
8. **RabbitMQ 4.4.0 directly.** `RABBITMQ_IMAGE=rabbitmq:4.4.0-management@sha256:<digest>`. The two-step through
   4.3.7 of the former PDK-354 is dropped. Rationale: the 4.3.7 step protects a volume written by 4.3.x with Erlang
   27; with decision 1 every installation starts on an empty volume, and the lab deletes its RabbitMQ volume
   (§3.10). The removed header parsing, the hash-password endpoint and the OAuth 2 validation do not touch
   Paddock (plain AMQP 0-9-1 publishing, definitions import, no `auth_oauth2`). Configuration keys in
   `rabbitmq.conf` and `tls.conf` are all current in 4.4.
9. **Fleet's MySQL stays on the 8.4 LTS line; the pin moves to the newest 8.4 patch.** `FLEET_MYSQL_IMAGE=
   mysql:8.4.13@sha256:<digest>`. The 26.x line is deferred until Fleet's documentation lists it as tested.
   Rationale: Fleet names 8.0.44+, 8.4.8 and 9.5.0 as tested and 9.6.0 as incompatible; 26.x is not mentioned at
   all; running Fleet on an untested database line to satisfy a version watch inverts the purpose of the watch.
10. **The upstream version watch learns a pinned line.** `PinInfo` gains `Line string`; when set, only tags with
    that prefix are candidates for "latest", and the issue body names the line. `FLEET_MYSQL_IMAGE` gets `Line:
    "8.4."`. Rationale: issue #97 must close when 8.4.13 is pinned, and the next 8.4 patch must still open an issue.
11. **Lab carry-over by dump and restore, outside the product.** The maintainer carries the three PostgreSQL
    databases of the lab (`paddock`, `authentik`, `paddock_audit`) with `pg_dump -Fc` and `pg_restore` into the
    fresh 18 clusters, keeps a tar of the old data volumes as a fallback until the laptop's escrow is verified, and
    deletes the RabbitMQ, Valkey and fleet-redis volumes (rebuildable, ADR 0016). OpenBao, both RustFS stores and
    Fleet's MySQL keep their volumes. The procedure is in §7 step 12 and in ticket PDK-343; it is not in
    `docs/operations/`, not in `./paddock` and not tested by CI. Rationale: the escrowed key is one row in
    `paddock`, encrypted under an OpenBao key that does not change; dump/restore is deterministic and reversible
    (the fallback tar), unlike re-enrolling the laptop and hoping for a fresh escrow; an exported recovery key
    would put the plaintext on the host.
12. **Documentation of versions.** `docs/architecture.md` line 50 is changed to "PostgreSQL 18" by PDK-343 — this
    plan is the architect decision that CLAUDE.md requires for that file (approved 2026-10-29; that single line is
    the only change PDK-343 makes there). ADR 0002 and ADR 0003 carry an "Amendment 2026-10-29" naming the current
    majors; ADR 0016 is set to Accepted with an amendment for decision 6. These amendments ship with this plan;
    nothing else in `docs/adr/` changes.
13. **New generated columns MUST be `STORED`.** Every future migration that adds a generated column writes
    `GENERATED ALWAYS AS (…) STORED`; PostgreSQL 18 makes virtual the default. Rationale: a virtual column cannot be
    indexed the way `version_key` is, and the behaviour must not depend on the server major. (A rule for the plans
    M10, M11 and M13a; no code change in this plan.)

## 4. Non-goals

- No `pg_upgrade`, no migration container, no upgrade path from 0.1.0-alpha.6, no rollback documentation for these
  components, no stanza migration tooling beyond decision 6.
- No change to Authentik, OpenBao, RustFS, Caddy, Prometheus, Fleet (`FLEET_IMAGE`, `FLEETCTL_IMAGE`) or any image
  under "Build and tooling images" in `versions.env`.
- No change to `agent/`, `pkg/`, `cli/`, the OpenAPI contracts, migrations or the server's SQL.
- No MySQL 9.x or 26.x; no separate pin for `fleet-redis`; no change to `valkey.conf`, `rabbitmq.conf`,
  `definitions.json.tmpl` or `enabled_plugins`.
- No change to the restore drill's steps or the restore runbook's procedure beyond paths and the version names.
- No change to the lab installation docs beyond the breaking-release note in `upgrade.md`.

## 5. Files

| Path | Action | Purpose |
| --- | --- | --- |
| `deploy/compose/versions.env` | change | the four pins (decisions 3, 7, 8, 9) |
| `deploy/compose/compose.yaml` | change | `postgres`, `authentik-postgres`: volume mount `/var/lib/postgresql` (decision 4) |
| `deploy/compose/compose.audit.yaml` | change | `audit-postgres`: volume mount `/var/lib/postgresql` |
| `deploy/compose/compose.backup.yaml` | change | `pgbackrest`, `pgbackrest-authentik`: data volume mount `/var/lib/postgresql`; header comment names the 18 layout |
| `deploy/compose/pgbackrest/Dockerfile` | change | create `/var/lib/postgresql/18/docker` instead of `/var/lib/postgresql/data` |
| `deploy/compose/pgbackrest/run.sh` | change | `PGBACKREST_PG1_PATH=/var/lib/postgresql/18/docker`; `ensure_stanza` with `stanza-upgrade` fallback (decision 6) |
| `deploy/compose/pgbackrest/pgbackrest_test.sh` | change | mount the throwaway data volume at `/var/lib/postgresql`; `PGBACKREST_PG1_PATH=/var/lib/postgresql/18/docker` |
| `tools/upstreamwatch/pins.go` | change | `PinInfo.Line`; `FLEET_MYSQL_IMAGE` with `Line: "8.4."` (decision 10) |
| `tools/upstreamwatch/compare.go` | change | `InLine(tags, line)` filter |
| `tools/upstreamwatch/check.go` | change | apply the line filter before `Latest` |
| `tools/upstreamwatch/issues.go` | change | `Body`: the pinned line |
| `tools/upstreamwatch/compare_test.go`, `tools/upstreamwatch/issues_test.go` | change | tests of decision 10 |
| `docs/operations/upgrade.md` | change | "From 0.1.0-alpha.7" bullet: breaking, fresh install; watch section: pinned lines |
| `docs/operations/restore.md` | change | the data directory path where the runbook names it; the stanza-upgrade behaviour |
| `docs/operations/fleet.md` | change | line 10: "MySQL 8.4 LTS line (Fleet's documented line; plan M6d decision 9)" |
| `docs/architecture.md` | change | line 50: "PostgreSQL 18" (decision 12) |
| `changelog.d/PDK-354.changed.md`, `PDK-344.changed.md`, `PDK-345.changed.md`, `PDK-343.changed.md` | new | release notes, PDK-343's entry carries the breaking note |

**MUST NOT be touched:** `docs/adr/`, `docs/reqirements/`, `server/migrations/`, `server/internal/`,
`agent/`, `pkg/`, `cli/`, `api/openapi/`, `deploy/compose/valkey/valkey.conf`, `deploy/compose/rabbitmq/*`,
`deploy/compose/postgres/init/`, `deploy/compose/audit-postgres/init/`, `deploy/compose/scripts/restore-drill.sh`,
`deploy/compose/scripts/postgres-unsealer-role.sh`, `deploy/bundle/paddock`, every other line of `versions.env`.

## 6. Interfaces and formats

### 6.1 Pins (`deploy/compose/versions.env`)

```sh
POSTGRES_IMAGE=postgres:18.6@sha256:<digest>
RABBITMQ_IMAGE=rabbitmq:4.4.0-management@sha256:<digest>
VALKEY_IMAGE=valkey/valkey:9.1.3@sha256:<digest>
# Fleet's MySQL stays on the 8.4 LTS line Fleet documents as tested (plan M6d decision 9); the watch compares
# within that line (pins.go Line "8.4.").
FLEET_MYSQL_IMAGE=mysql:8.4.13@sha256:<digest>
```

Each `<digest>` is the index digest printed by `docker buildx imagetools inspect <image>:<tag>` on the day of the
change. The comment of `VALKEY_IMAGE` ("Cache, nonces and bundle pointers …") and the `FLEET_*` comment block stay.

### 6.2 Compose volume mounts (decision 4)

```yaml
# compose.yaml
  postgres:
    volumes:
      - ./postgres/init:/docker-entrypoint-initdb.d:ro
      - postgres-data:/var/lib/postgresql
  authentik-postgres:
    volumes:
      - authentik-postgres-data:/var/lib/postgresql
# compose.audit.yaml
  audit-postgres:
    volumes:
      - ./audit-postgres/init:/docker-entrypoint-initdb.d:ro
      - audit-postgres-data:/var/lib/postgresql
# compose.backup.yaml
  pgbackrest:
    volumes:
      - postgres-data:/var/lib/postgresql
      - postgres-socket:/var/run/postgresql
      - pgbackrest-spool-paddock:/pgbackrest-spool/paddock
      - pgbackrest-state-paddock:/var/lib/pgbackrest
  pgbackrest-authentik:
    volumes:
      - authentik-postgres-data:/var/lib/postgresql
      - authentik-postgres-socket:/var/run/postgresql
      - pgbackrest-spool-authentik:/pgbackrest-spool/authentik
      - pgbackrest-state-authentik:/var/lib/pgbackrest
```

No `PGDATA` is set anywhere; the image's default `/var/lib/postgresql/18/docker` applies. The `command:` overrides
of `compose.backup.yaml` (archive_mode, archive_command, spool directory) stay unchanged.

### 6.3 pgBackRest (`deploy/compose/pgbackrest/run.sh`, `Dockerfile`)

```sh
# run.sh
# The 18 image keeps the cluster below the volume mount (/var/lib/postgresql/<major>/docker); pgBackRest needs the
# path the server reports (plan M6d decision 4).
export PGBACKREST_PG1_PATH=/var/lib/postgresql/18/docker

# ensure_stanza creates the stanza once. stanza-upgrade is the fallback for a repository that already holds this
# stanza for another cluster (version or system identifier), e.g. after a fresh installation into a kept bucket
# (plan M6d decision 6); it keeps the old backups until retention expires them.
ensure_stanza() {
  [[ -f "$STATE/stanza" ]] && return 0
  { pgb stanza-create || pgb stanza-upgrade; } && : >"$STATE/stanza"
}
```

```dockerfile
# Dockerfile: the data directory of the 18 image layout (plan M6d decision 4)
    && install -d -o 999 -g 999 -m 700 /var/log/pgbackrest /var/lib/pgbackrest /tmp/pgbackrest \
       /var/lib/postgresql/18/docker /pgbackrest-spool/paddock /pgbackrest-spool/authentik \
```

`pgbackrest_test.sh`: `-v "$id-data:/var/lib/postgresql"` on the PostgreSQL container and on every `pgb` call;
`-e PGBACKREST_PG1_PATH=/var/lib/postgresql/18/docker`.

### 6.4 Upstream version watch (`tools/upstreamwatch`)

```go
// pins.go
// PinInfo is the table row of one pin: its reported name, the GitHub repository whose releases carry the release
// notes ("" when none), the line the pin stays on ("" when any newer tag counts; a tag prefix such as "8.4." when
// only that line is followed, plan M6d decision 10) and the gates to run before the bump.
type PinInfo struct {
	Name   string
	GitHub string
	Line   string
	Gates  []string
}

"FLEET_MYSQL_IMAGE": {Name: "fleet_mysql", Line: "8.4.", Gates: []string{gateFleet}},

// compare.go
// InLine returns the tags that start with line; every tag when line is empty.
func InLine(tags []string, line string) []string

// check.go (line 52)
if latest = Latest(p.Pinned, InLine(tags, p.Info.Line)); latest == "" { … }

// issues.go, Body: after the Classification line, only when r.Pin.Info.Line != "":
fmt.Fprintf(&b, "**Line:** this pin follows the `%s` line only; newer lines are not reported (plan M6d decision 10).\n\n", r.Pin.Info.Line)
```

The error text of `check.go` for an empty result stays `no tag of the shape %s`; when a line is set it reads
`no tag of the shape %s in line %s`.

### 6.5 Release notes (`changelog.d/`)

`changelog.d/PDK-343.changed.md`:

```markdown
- **Breaking: 0.1.0-alpha.7 has no upgrade path from earlier releases.** PostgreSQL moves from 17 to 18 for the
  control plane, Authentik's database and the audit database, and the data directory layout follows the PostgreSQL
  18 image (`/var/lib/postgresql/18/docker` inside the volume). An installation of 0.1.0-alpha.6 or earlier is
  installed fresh (`docs/operations/upgrade.md`, "From 0.1.0-alpha.7"): every database, OpenBao's keys, escrowed
  recovery keys and device enrollments of the old installation are gone, and every device is enrolled again. The
  pgBackRest stanza is upgraded in place when the backup repository already holds one for the same stanza name.
```

`PDK-354.changed.md`: "- RabbitMQ moves to 4.4.0 (Erlang/OTP 29). Fresh installations only (see the breaking note of
this release)." `PDK-344.changed.md`: "- Valkey moves to 9.1.3 for the control plane's cache and for Fleet's Redis.
Fresh installations only." `PDK-345.changed.md`: "- Fleet's MySQL stays on the 8.4 LTS line Fleet documents and moves
to 8.4.13; the upstream version watch follows that line only."

### 6.6 `docs/operations/upgrade.md`, "Before you start"

```markdown
- **From 0.1.0-alpha.7: no upgrade path.** This release moves PostgreSQL to 18 (new data directory layout), Valkey
  to 9 and RabbitMQ to 4.4. None of them opens the data of the previous release, and this release ships no
  migration. Install it fresh: in the old bundle directory `./paddock down --volumes` (deletes every volume of the
  project: the databases, OpenBao with its keys, the object stores, Fleet), then follow `docs/operations/install.md`
  for the new release and enrol every device again (`docs/operations/uninstall.md` for the device side). Escrowed
  recovery keys of the old installation are lost with it: before you take it down, make sure no device still needs
  one. A backup bucket may be kept; the pgBackRest stanza is upgraded for the new cluster at the first backup and
  the old backups expire with retention. Fleet's MySQL stays on the 8.4 line.
```

The "Upgrade (each host)" and "Rollback" sections stay as they are (they describe later releases); a one-sentence
pointer at the top of "Upgrade (each host)" says that it does not apply to the move to 0.1.0-alpha.7.
The "Upstream version watch" section gains, in the "What it checks" bullet: "A pin can follow one line only
(`Line` in `tools/upstreamwatch/pins.go`, today Fleet's MySQL on `8.4.`); newer lines are not reported for it."

## 7. Steps

Steps 1–3 are ticket PDK-354, step 4 PDK-344, steps 5–6 PDK-345, steps 7–11 PDK-343; step 12 is the cluster gate;
step 13 the lab carry-over (maintainer). Every ticket PR targets `cluster/upstream-majors`; CI runs the full
acceptance on every PR.

1. **RabbitMQ pin.** Do: `RABBITMQ_IMAGE=rabbitmq:4.4.0-management@sha256:<digest>`; fragment
   `changelog.d/PDK-354.changed.md`. Result: a fresh stack runs 4.4.0. Check: `make down V=1 && make up && make
   dev-seed`; `docker exec paddock-rabbitmq-1 rabbitmqctl version` prints `4.4.0`; `docker exec paddock-rabbitmq-1
   rabbitmqctl -q list_feature_flags name state stability | awk '$3=="stable" && $2!="enabled"'` prints nothing;
   `make acceptance T='TestDeviceProtocol|TestAuditChain'` green locally, full acceptance in CI.
2. **RabbitMQ definitions and TLS unchanged.** Do: nothing in `deploy/compose/rabbitmq/`. Result: the definitions
   import and the amqps listener work on 4.4. Check: `docker exec paddock-rabbitmq-1 rabbitmqctl list_users` lists
   the seven users of `definitions.json.tmpl`; the production overlay's TLS listener is covered by the bundle smoke
   test in CI (`deploy/bundle/ci/smoke-lab.sh`).
3. **PDK-354 PR** against `cluster/upstream-majors`.
4. **Valkey pin.** Do: `VALKEY_IMAGE=valkey/valkey:9.1.3@sha256:<digest>`; fragment `PDK-344.changed.md`. Result:
   `valkey` and `fleet-redis` run 9.1.3 with the unchanged `valkey.conf`. Check: `make down V=1 && make up && make
   dev-seed`; `docker exec paddock-valkey-1 valkey-cli -a "$(cat deploy/compose/.secrets/valkey_password)" INFO
   server | grep valkey_version` prints `9.1.3`; `make acceptance T='TestDeviceProtocol|TestFleet|TestInventory'`
   green locally; full acceptance in CI. PR.
5. **Watch line filter.** Do: §6.4 in `pins.go`, `compare.go`, `check.go`, `issues.go`; tests: `TestShapeAndLatest`
   gains the case `{"8.4.11", InLine([]string{"8.4.13", "9.7.4", "26.10.0", "8.4.12"}, "8.4."), "8.4.13"}` and a
   case without a line that yields `26.10.0`; `TestClassify` gains `{"8.4.11", "8.4.13", ClassPatch}`;
   `issues_test.go` asserts the `**Line:**` paragraph for a pin with a line and its absence without one;
   `TestEveryPinIsMapped` stays green. Result: `go run ./tools/upstreamwatch check` reports `fleet_mysql 8.4.11
   8.4.13 patch`. Check: `GOTOOLCHAIN=auto go test -count=1 ./tools/upstreamwatch/...`; `make upstream-check | grep
   fleet_mysql`.
6. **MySQL pin.** Do: `FLEET_MYSQL_IMAGE=mysql:8.4.13@sha256:<digest>` with the comment of §6.1; `docs/operations/fleet.md`
   line 10; `docs/operations/upgrade.md` watch sentence; fragment `PDK-345.changed.md`. Result: `make upstream-check`
   reports `fleet_mysql 8.4.13 8.4.13 ok`. Check: `make down V=1 && make up && make dev-seed`; `make acceptance
   T='TestFleet|TestInventory'` green locally; CI. PR.
7. **PostgreSQL mounts.** Do: §6.2 in `compose.yaml`, `compose.audit.yaml`, `compose.backup.yaml`. Result: with the
   old pin still in place the stack does not start correctly (17 would initialize into the mounted parent); this
   step and step 8 are one commit. Check: none alone.
8. **PostgreSQL pin and pgBackRest.** Do: `POSTGRES_IMAGE=postgres:18.6@sha256:<digest>`; §6.3 in `run.sh`,
   `Dockerfile`, `pgbackrest_test.sh`. Result: a fresh stack runs 18.6 with data at
   `/var/lib/postgresql/18/docker` inside the named volumes. Check: `make down V=1 && make image-pgbackrest && make up
   BACKUP=1 && make dev-seed`; `docker exec paddock-postgres-1 psql -U postgres -Atc 'show server_version'` starts
   with `18.6`; `docker exec paddock-postgres-1 psql -U postgres -Atc 'show data_directory'` prints
   `/var/lib/postgresql/18/docker`; `docker exec paddock-postgres-1 psql -U postgres -Atc 'show data_checksums'`
   prints `on`; `docker run --rm -v paddock_postgres-data:/v postgres:18.6 ls /v/18/docker/PG_VERSION` prints the
   file; `docker inspect paddock-postgres-1 --format '{{range .Mounts}}{{.Type}} {{.Destination}} {{.Name}}{{"\n"}}{{end}}'`
   lists only named volumes (`volume /var/lib/postgresql paddock_postgres-data`, the socket and spool volumes) and
   no entry with an empty or 64-hex name (an anonymous volume);
   `docker compose … logs pgbackrest` shows `backup … verified` within 2 minutes after `./paddock compose run --rm
   --no-deps pgbackrest backup --start-fast` (`make` equivalent: `BACKUP=1 docker compose … run`).
9. **Stanza fallback.** Do: with the stack of step 8 running and one backup taken, `docker compose … stop postgres
   pgbackrest`, `docker volume rm paddock_postgres-data paddock_pgbackrest-state-paddock`, `docker compose … up -d
   postgres pgbackrest` (a new cluster, same bucket). Result: `pgbackrest` logs `stanza-upgrade` once and the next
   full backup verifies. Check: `docker compose … run --rm --no-deps pgbackrest info` shows the stanza with `db
   (current)` of the new system id and the older backup set listed under the previous one. This is a manual check
   recorded in the result document; the restore drill of step 12 is the automated gate. Restore the dev stack
   afterwards with `make down V=1 && make up BACKUP=1 && make dev-seed`.
10. **Tests and docs.** Do: `make test` (runs `pgbackrest_test.sh` and the testcontainers integration tests against
    18.6); `docs/operations/restore.md` (the sentence "pgBackRest needs the data directory at the path the server
    reports" gains "(`/var/lib/postgresql/18/docker` in the volume)"; "How the backups run" gains one sentence on
    stanza-upgrade); `docs/operations/upgrade.md` §6.6; `docs/architecture.md` line 50; fragment
    `PDK-343.changed.md`. Result: every doc that names the version or path is current. Check: `make lint`
    (includes `changelog-check`), `make test`, `grep -rn "postgresql/data" deploy docs --include=*.yaml
    --include=*.sh --include=*.md` prints only historical plan text under `docs/plans/`.
11. **PDK-343 PR** against `cluster/upstream-majors`.
12. **Cluster gate** (once, on the cluster head, dev stack rebuilt from scratch, serial with the VMs): `make down
    V=1 && make image image-compiler image-pgbackrest && make up BACKUP=1 && make dev-seed`; `make restore-drill`
    passes and prints the RTO; `make system-test VM=all`; `make e2e`; `PADDOCK_ACCEPTANCE_DISRUPTIVE=1 make
    acceptance T='TestSessionsEndAll|TestAutoUnsealRestart'`; `make acceptance T='TestFleet|TestInventory'` 3×. Then
    one PR `cluster/upstream-majors` → `main`.
13. **Lab carry-over (maintainer, once, after step 12 is on `main` and an edge or release bundle of it exists; not
    product).** Written for the bundle directories A (running, alpha.6) and B (new), project `paddock`, and the
    laptop's escrow in database `paddock`:
    1. **Check first, in A.** The lab's settings are read on the host at execution time, never assumed:
       `grep '^PADDOCK_LAB_BACKUP=' .env` (`yes` → the backup branches of steps 13.5 and 13.11 apply) and
       `./paddock auto-unseal status` (`PADDOCK_AUTO_UNSEAL=yes` or `shares file: present` → step 13.7 applies).
       Then `n=$(./paddock compose exec -T postgres psql -U postgres -d paddock -Atc "select count(*) from
       escrow_secret where status='stored'")`; note `n` (must be ≥ 1).
    2. In A, stop the producers and let the audit queue drain: `./paddock compose --profile paddock stop
       paddock-api paddock-gateway paddock-worker paddock-compiler paddock-outbox-relay paddock-escrow-reader
       paddock-revocation-issuer`; wait until `./paddock compose exec -T rabbitmq rabbitmqctl -q list_queues
       messages | awk '$1!=0'` prints nothing; then `./paddock compose --profile paddock stop paddock-audit-writer
       authentik-server authentik-worker fleet`.
    3. In A, dump: `mkdir -p ~/paddock-carry && chmod 700 ~/paddock-carry`;
       `./paddock compose exec -T postgres pg_dump -U postgres -Fc paddock > ~/paddock-carry/paddock.dump`;
       `./paddock compose exec -T authentik-postgres pg_dump -U authentik -Fc authentik > ~/paddock-carry/authentik.dump`;
       `./paddock compose exec -T audit-postgres pg_dump -U postgres -Fc paddock_audit > ~/paddock-carry/audit.dump`.
       Check: `./paddock compose exec -T postgres pg_restore -l /dev/stdin < ~/paddock-carry/paddock.dump | grep -c
       'TABLE DATA public escrow_secret'` prints `1`.
    4. In A, fallback tar of the three data volumes with the old image: for `v` in `postgres-data
       authentik-postgres-data audit-postgres-data`: `docker run --rm -v paddock_$v:/from:ro -v
       ~/paddock-carry:/to $(grep ^POSTGRES_IMAGE= versions.env | cut -d= -f2-) tar -C /from -czf /to/$v.tgz .`.
    5. In A: `./paddock down` (keeps volumes). Delete only the volumes that are rebuilt or restored: `docker volume
       rm paddock_postgres-data paddock_authentik-postgres-data paddock_audit-postgres-data paddock_rabbitmq-data
       paddock_valkey-data paddock_fleet-redis-data`, plus `paddock_pgbackrest-spool-paddock
       paddock_pgbackrest-spool-authentik paddock_pgbackrest-state-paddock paddock_pgbackrest-state-authentik` when
       step 13.1 showed `PADDOCK_LAB_BACKUP=yes`. Keep `openbao-data`, the RustFS volumes, `fleet-mysql-data`, Caddy and Prometheus
       volumes.
    6. In B: `./paddock migrate-from ../<A>`; `./paddock pull`; `./paddock check`; `./paddock compose up -d
       --no-deps postgres authentik-postgres audit-postgres`; wait until all three are healthy (`./paddock ps`).
       The init scripts create the roles and empty databases.
    7. In B, when step 13.1 showed auto-unseal in use: `scripts/postgres-unsealer-role.sh` (creates
       `paddock_unsealer`, which the dump's grants reference). Otherwise skip.
    8. In B, restore: `./paddock compose exec -T postgres pg_restore -U postgres -d paddock <
       ~/paddock-carry/paddock.dump`; `./paddock compose exec -T authentik-postgres pg_restore -U authentik -d
       authentik < ~/paddock-carry/authentik.dump`; `./paddock compose exec -T audit-postgres pg_restore -U postgres
       -d paddock_audit < ~/paddock-carry/audit.dump`. Acceptable errors in the output: `already exists` for schema
       `public` and extension `pg_trgm`; any other error stops here (volumes of step 5 can be recreated from the
       tars of step 4 with the old bundle A).
    9. In B: `./paddock up` (migrations run forward from the restored schema version; RabbitMQ imports its
       definitions into a fresh node; Fleet reconnects to its unchanged MySQL); then `./paddock compose run --rm
       --no-deps paddock-worker admin rebuild-cache` (Valkey was deleted; ADR 0016). No `bump-bundle-seq`: the
       database is not older than the devices.
    10. Verify: `./paddock compose exec -T postgres psql -U postgres -d paddock -Atc "select count(*) from
        escrow_secret where status='stored'"` prints `n`; the laptop checks in (device page shows a fresh check-in);
        on the device's disk page the recovery key reveal with a step-up succeeds and shows a key (escrow-reader
        decrypts it with OpenBao's unchanged `escrow-wrap` key); the portal sign-in works (Authentik data); the audit
        trail lists events from before the carry-over. Then `rm -rf ~/paddock-carry` after one week of normal
        operation.
    11. When step 13.1 showed `PADDOCK_LAB_BACKUP=yes`: `./paddock compose run --rm --no-deps pgbackrest info` lists
        the stanza with the new cluster as current after the first backup (decision 6).

## 8. Tests

- **Unit (Go):** `tools/upstreamwatch`: `InLine` (empty line returns all; prefix filter), `Latest` on filtered tags,
  `Classify` `8.4.11 → 8.4.13 = patch`, `Body` with and without a line, `TestEveryPinIsMapped` unchanged.
- **Integration (Go, testcontainers, `make test`):** every `pgtest`-based test runs against `postgres:18.6`
  (RLS fail-closed tests in `server/internal/platform/db`, migrations, repositories) — no new test, the existing
  suite is the gate for the server against 18.
- **Script test:** `deploy/compose/pgbackrest/pgbackrest_test.sh` against 18.6 with the new mount and path (lock
  behaviour and `verify` reporting unchanged).
- **Acceptance (CI on every PR; local subsets as listed in §7):** full suite on the new images; `TestFleet|TestInventory`
  (F0–F4) for Valkey 9 under Fleet and MySQL 8.4.13; `TestDeviceProtocol|TestAuditChain` for RabbitMQ 4.4;
  `TestOrganizationIsolation` for RLS on 18.
- **Restore drill (`make restore-drill`, cluster gate):** backup, loss, restore into `/var/lib/postgresql/18/docker`,
  recovery to the latest point, device count equal, acceptance subset green.
- **System (`make system-test VM=all`, cluster gate):** agents against the stack on the new images.
- **Manual, recorded in the PDK-343 result document:** step 9 (stanza-upgrade on a kept bucket).

## 9. Acceptance criteria

| ID | Given / When / Then | Ticket | Who sees it |
| --- | --- | --- | --- |
| AC-1 | Given a fresh `make up`, when `rabbitmqctl version` runs in the broker, then it prints `4.4.0`, and every stable feature flag is `enabled` | PDK-354 | implementer, reviewer (dev stack); operator (`./paddock compose exec rabbitmq rabbitmqctl version`) |
| AC-2 | Given a fresh stack on 4.4.0, when CI runs the acceptance suite, then it is green, and `rabbitmqctl list_users` lists the seven definition users | PDK-354 | reviewer (CI) |
| AC-3 | Given a fresh `make up`, when `INFO server` runs in `valkey` and in `fleet-redis`, then `valkey_version:9.1.3`; the acceptance suite and F0–F4 are green | PDK-344 | implementer, reviewer |
| AC-4 | Given `FLEET_MYSQL_IMAGE=mysql:8.4.13`, when `make upstream-check` runs, then the line is `fleet_mysql 8.4.13 8.4.13 ok`; given the fixture tags `8.4.13 9.7.4 26.10.0` with pin `8.4.11` and line `8.4.`, then latest is `8.4.13` and class `patch` | PDK-345 | implementer (tests), maintainer (issue #97 closes on the next watch run) |
| AC-5 | Given a watch issue for a pin with a line, when its body is built, then it contains the `**Line:**` paragraph; a pin without a line has none | PDK-345 | implementer (test) |
| AC-6 | Given a fresh `make up BACKUP=1`, when `show server_version`, `show data_directory`, `show data_checksums` run in `postgres`, `authentik-postgres` and `audit-postgres`, then `18.6…`, `/var/lib/postgresql/18/docker`, `on`; and `docker inspect` of each container lists only named volume mounts (no anonymous volume) | PDK-343 | implementer, reviewer |
| AC-7 | Given the stack of AC-6, when `pgbackrest backup --start-fast` runs for both stanzas, then both log `verified` and `pgbackrest info` shows `status: ok` | PDK-343 | implementer; operator (`docs/operations/restore.md` commands) |
| AC-8 | Given a backup in the bucket and a recreated empty `postgres-data` plus state volume, when `pgbackrest` starts, then it runs `stanza-upgrade` once and the next backup verifies (manual, recorded) | PDK-343 | implementer, reviewer (result document) |
| AC-9 | Given the cluster head, when `make restore-drill` runs, then it passes and prints the RTO | PDK-343 (cluster gate) | reviewer, maintainer |
| AC-10 | Given the cluster head, when `make test`, `make system-test VM=all`, `make e2e` and CI's acceptance run, then all are green without any weakened test | all (cluster gate) | reviewer, maintainer |
| AC-11 | Given `docs/operations/upgrade.md`, when an operator reads "Before you start", then the first bullet of 0.1.0-alpha.7 states that there is no upgrade path, what `./paddock down --volumes` deletes (escrowed keys and enrollments included) and that devices are enrolled again | PDK-343 | operator |
| AC-12 | Given `docs/architecture.md` line 50 and `docs/operations/fleet.md` line 10, then they read "PostgreSQL 18" and "MySQL 8.4 LTS line" | PDK-343, PDK-345 | reader |
| AC-13 | Given the lab after step 13, when the maintainer reveals the laptop's recovery key with a step-up, then the escrow-reader returns it and the stored count equals the count before | lab (maintainer) | maintainer |

## 10. Degrees of freedom

- Names of the new Go helper (`InLine`) and of its test cases; whether the line filter lives in `compare.go` or
  `check.go` as long as `Latest` keeps its signature.
- Wording of comments in `versions.env`, `run.sh` and the Dockerfile as long as they name the reason and the plan.
- The exact wording of the changelog fragments of PDK-354, PDK-344 and PDK-345 (PDK-343's breaking paragraph is
  fixed in §6.5).
- The order of the local check commands within a step.

## 11. Stop conditions

Stop and report (do not decide alone) when:

- `pgbackrest stanza-create`, `backup` or `restore` fails against PostgreSQL 18.6 with an error that names the
  PostgreSQL version, the control file or the WAL magic (then the Debian package is not enough and a package
  source decision is needed).
- The PostgreSQL 18 image refuses to start with the volume mounted at `/var/lib/postgresql` or reports a data
  directory other than `/var/lib/postgresql/18/docker`.
- A testcontainers-based test fails only on 18.6 (a server-side incompatibility; the plan assumes none).
- Fleet logs a MySQL or Redis compatibility error with Valkey 9.1.3 or MySQL 8.4.13, or F0–F4 fail twice.
- RabbitMQ 4.4.0 rejects a key of `rabbitmq.conf`, `tls.conf` or an entry of the definitions file.
- The restore drill fails for a reason other than a flake already tracked by a ticket.
- Any change would be needed in a file listed under "MUST NOT be touched" in §5, in `docs/adr/`, or in the agent.
- A newer patch tag than the ones named here exists on the day of the change (18.7, 9.1.4, 4.4.1, 8.4.14): pin
  the newer patch of the **same** line and note it in the result document; a newer minor or major is not taken.

## 12. Risks and open points

| Risk | Mitigation |
| --- | --- |
| pgBackRest 2.55.1 is labelled experimental for 18 by Debian | constants verified identical to 18 stable (§2); `make test` runs `pgbackrest_test.sh` against 18.6 in CI; the restore drill is the cluster gate; stop condition in §11 |
| Fleet on Valkey 9 is undocumented by Fleet | F0–F4 in CI on every PR and 3× locally at the cluster gate; `fleet-redis` holds only caches, live-query state and sessions |
| Authentik on PostgreSQL 18 is not named in Authentik's docs | the Helm chart of authentik 2026.8 ships PostgreSQL 18; `TestIdentityLockAuthentik`, `TestStepUpFactorClaim` and the e2e suite run on the cluster head |
| Lab carry-over loses the escrow | the stored count is compared before and after, the reveal is tested, and the tar fallback plus the old bundle A stay for a week |
| Lab RabbitMQ volume deletion drops in-flight audit events | producers are stopped first and the queues drained to zero before the writer stops (step 13.2) |
| The dev stacks of other agents still hold 17 volumes | every agent on the cluster branch starts with `make down V=1`; the cluster gate rebuilds from scratch |
| PostgreSQL 19 and later change the data path again (`/var/lib/postgresql/19/docker`) | the path is named in exactly two product files (`run.sh`, `Dockerfile`) with a comment pointing here |

Open points — all resolved on 2026-10-29:

1. Lab settings (`PADDOCK_LAB_BACKUP`, auto-unseal): read on the host at execution time (step 13.1); the runbook
   branches on what it finds. No input needed beforehand.
2. ADR 0002 and ADR 0003 carry an "Amendment 2026-10-29" naming the current majors; shipped with this plan.
3. ADR 0016 is set to Accepted with an amendment for decision 6; shipped with this plan.
4. Issue #113 (RabbitMQ) closes via the watch after PDK-354; the former two-step is dropped.
5. Timing of the lab carry-over: once, after `cluster/upstream-majors` is on `main` and an edge bundle of it exists.
