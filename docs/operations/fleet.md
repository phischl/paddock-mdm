# Fleet: inventory and vulnerabilities

Paddock uses the free edition of [Fleet](https://fleetdm.com) for software inventory and vulnerability matching
(architecture §15, ADR 0009, plan M5a). Fleet is an internal component: organization administrators never see it;
the portal shows its data from Paddock's own tables, isolated per organization.

| Service | Image (`deploy/compose/versions.env`) | Networks | Purpose |
| --- | --- | --- | --- |
| `fleet` | `FLEET_IMAGE` | `cp`, `fleet` | Fleet server; migrates its database at every start (`fleet prepare db`) |
| `fleet-mysql` | `FLEET_MYSQL_IMAGE` (MySQL 8.4) | `fleet` (internal) | Fleet's database (volume `fleet-mysql-data`) |
| `fleet-redis` | `VALKEY_IMAGE` | `fleet` (internal) | Fleet's cache and live-query channel (Valkey speaks the Redis protocol) |

Vulnerability feeds (NVD, OSV) are downloaded by Fleet into the volume `fleet-vulndb`; Fleet needs outbound HTTPS
for them.

## What is published

Caddy publishes `fleet.<domain>` with the device endpoints only:

| Path | Used by |
| --- | --- |
| `/api/osquery/*`, `/api/v1/osquery/*` | osquery (enrollment, configuration, distributed queries of Fleet's detail queries and Paddock's policies, status logs) |
| `/api/fleet/orbit/*` | fleetd (enrollment, configuration, ping) |

Every other path — Fleet's UI, its admin API, setup, health check and file carving (`…/osquery/carve/*`) — answers
404 at the proxy. Devices need no other Fleet path: fleetd updates come from Paddock's package store, not from
Fleet's update server.

## Access for platform operators

Fleet's UI and API are reachable on the internal network `cp` only (`http://fleet:8080`). Platform operators who need
the UI forward a local port to it, for example from their workstation through the Docker host:

```sh
ip=$(ssh docker-host docker inspect -f '{{(index .NetworkSettings.Networks "paddock_cp").IPAddress}}' paddock-fleet-1)
ssh -N -L 127.0.0.1:8412:"$ip":8080 docker-host
# then open http://127.0.0.1:8412 and sign in as admin@paddock-mdm.invalid (password: secret fleet_admin_password)
```

The development stack publishes the port on `127.0.0.1:8412` of the development host (`compose.dev.yaml`). Changes
made in the UI to the settings below are reset by `paddock-worker` within one round.

## Bootstrap

In development, `make up` runs `deploy/compose/scripts/fleet-bootstrap.sh` (also `make fleet-bootstrap`), which
refuses to run with `PADDOCK_ENV=production`. It is idempotent:

1. Fleet's initial setup with the admin user `admin@paddock-mdm.invalid` (password from `.secrets/fleet_admin_password`).
2. The API-only user `paddock` with the global role `admin`; its API token is written to `.secrets/fleet_api_token`.
   A valid token is kept; otherwise every earlier API-only user named `paddock` is deleted (which revokes its token)
   and a new one is created. Restart `paddock-worker` after a new token.
3. The global enroll secret from `.secrets/fleet_enroll_secret`.

Production does the same with `fleetctl` against Fleet's internal address (`fleetctl` speaks plain HTTP only to
`localhost`, so run it in Fleet's network namespace):

```sh
docker run --rm -it --network container:paddock-fleet-1 -e HOME=/tmp --entrypoint sh "$FLEETCTL_IMAGE"
fleetctl config set --address http://localhost:8080
fleetctl setup --email admin@<your domain> --name "Paddock administrator" --org-name Paddock
fleetctl user create --api-only --name paddock --global-role admin   # store the token as PADDOCK_FLEET_TOKEN_FILE
printf 'apiVersion: v1\nkind: enroll_secret\nspec:\n  secrets:\n    - secret: "%s"\n' "<enroll secret>" >/tmp/s.yml
fleetctl apply -f /tmp/s.yml
```

## Settings Paddock enforces

`paddock-worker` (`PADDOCK_FLEET_URL`, `PADDOCK_FLEET_TOKEN_FILE`, `PADDOCK_FLEET_PUBLIC_URL`) checks Fleet's
settings at start and every inventory round (`PADDOCK_INVENTORY_SYNC_INTERVAL`, default 5 minutes) and resets drift
(log message `inventory settings drifted; reset`):

- `server_settings`: `server_url` = `PADDOCK_FLEET_PUBLIC_URL`; live queries, query reports, scripts and AI features
  off; usage statistics to fleetdm.com (`enable_analytics`) off.
- `features`: host users off, software inventory on, no additional queries, and Paddock's detail query overrides
  (see `docs/compliance/privacy.md`): Linux software from the system package managers only, no network interfaces,
  no last-use times of packages, no software from users' home directories.
- `webhook_settings`: every webhook off (activities, host status, failing policies, vulnerabilities).
- No scheduled queries and no query packs: they are deleted. Saved queries without a schedule stay; they could only
  run live, and live queries are off.

Fleet's round intervals are environment variables of the `fleet` service: `FLEET_OSQUERY_POLICY_UPDATE_INTERVAL`
(default 10 minutes), `FLEET_OSQUERY_DETAIL_UPDATE_INTERVAL` (1 hour) and `FLEET_VULNERABILITIES_PERIODICITY`
(1 hour); the development stack uses 30 seconds, 2 minutes and 5 minutes.

## Backups

Back up `fleet-mysql` daily (`mysqldump`); everything in it can be rebuilt from the devices within a day
(architecture §20).
