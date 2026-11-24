# Fleet: inventory and vulnerabilities

Paddock uses the free edition of [Fleet](https://fleetdm.com) for software inventory and vulnerability matching
(architecture §15, ADR 0009, plan M5a). Fleet is an internal component: organization administrators never see it;
the portal shows its data from Paddock's own tables, isolated per organization.

| Service | Image (`deploy/compose/versions.env`) | Networks | Purpose |
| --- | --- | --- | --- |
| `fleet` | `FLEET_IMAGE` | `cp`, `fleet` | Fleet server; migrates its database at every start (`fleet prepare db`) |
| `fleet-mysql` | `FLEET_MYSQL_IMAGE` (MySQL 8.4 LTS line, Fleet's documented line; plan M6d decision 9) | `fleet` (internal) | Fleet's database (volume `fleet-mysql-data`) |
| `fleet-redis` | `VALKEY_IMAGE` | `fleet` (internal) | Fleet's cache and live-query channel (Valkey speaks the Redis protocol) |

Vulnerability feeds (NVD, OSV) are downloaded by Fleet into the volume `fleet-vulndb`, mounted on the home directory
of the image's `fleet` user, which Fleet runs as; Fleet needs outbound HTTPS for them.

In production Fleet finds the latest CPE dictionary, CPE translations and NVD feeds through GitHub's API without a
token (60 requests per hour and address). Development and CI stacks skip that lookup (ADR 0009 amendment
2026-10-12): `compose.dev.yaml` sets `FLEET_VULNERABILITIES_CPE_DATABASE_URL` and
`FLEET_VULNERABILITIES_CPE_TRANSLATIONS_URL` to one pinned `fleetdm/nvd` release (`FLEET_CPE_DATABASE_URL`,
`FLEET_CPE_TRANSLATIONS_URL` in the development and CI section at the end of `deploy/compose/versions.env`, which
the operator bundle does not ship) and `FLEET_VULNERABILITIES_CVE_FEED_PREFIX_URL` to the
latest `fleetdm/vulnerabilities` release, so a shared CI runner over GitHub's limit still gets the data the
inventory gates need. No GitHub token is passed to Fleet. Fleet's MSRC, Mac Office, OVAL and OSV syncs still use the
API; their failures are logged and do not affect the gates. When upgrading `FLEET_IMAGE`, check that the three
variables still exist and move the pin to a current `fleetdm/nvd` release (its asset `cpe-<sha256>.sqlite.gz` and
`cpe_translations.json`). Fleet skips its once-a-day check when the CPE URL is set and downloads the database on
every vulnerability run, which is why the development period stays at 1 hour (see the round intervals below); if the
pinned release is ever pruned, the inventory gates fail with Fleet's download error
and the pin is moved the same way.

## What is published

Caddy publishes `fleet.<domain>` with the device endpoints only:

| Path | Used by |
| --- | --- |
| `/api/osquery/*`, `/api/v1/osquery/*` | osquery (enrollment, configuration, distributed queries of Fleet's detail queries and Paddock's policies, status logs) |
| `/api/fleet/orbit/*` | fleetd (enrollment, configuration, ping) |

Every other path — Fleet's UI, its admin API, setup, health check and file carving (`…/osquery/carve/*`) — answers
404 at the proxy. Devices need no other Fleet path: fleetd updates come from Paddock's package store, not from
Fleet's update server.

## fleetd on devices

fleetd (orbit and osquery) is built per agent release with `make fleetd-deb` (`fleetctl package` of `FLEETCTL_IMAGE`:
scripts, Fleet Desktop and auto-updates off; no Fleet URL and no enroll secret in the package, because `fleetctl`
accepts a URL only together with a secret) and uploaded as the package `fleet-osquery` of the release
(`packages/<release>/fleet-osquery_<fleetd version>_amd64.deb`, `docs/operations/agent-releases.md`). The compiler puts
the package of the newest published release that has one (and whose rollout is not halted), Fleet's public URL
(`PADDOCK_FLEET_PUBLIC_URL`) and the global enroll secret (`PADDOCK_FLEET_ENROLL_SECRET_FILE`) into the `inventory`
section of every v2 bundle. The agent of an amd64 device then:

1. writes `/opt/orbit/secret.txt` (the enroll secret, 0600), `/etc/paddock/orbit.env` (Fleet URL, path of the secret,
   the system trust store `/etc/ssl/certs/ca-certificates.crt`, updates, scripts and Fleet Desktop off; 0600) and the
   drop-in `/etc/systemd/system/orbit.service.d/90-paddock.conf`, which makes `orbit.service` read `orbit.env` after
   the package's `/etc/default/orbit`. `orbit.env` also sets `ORBIT_HOST_IDENTIFIER=instance`. On a device whose fleetd
   was enrolled before, the agent re-enrolls fleetd once (it stops `orbit.service` and removes orbit's node key, device
   token and osquery database);
2. downloads the package from `https://bundles.<domain>/<path>` (derived from the agent's `device.<domain>` server
   URL), checks its SHA-256 and installs it with `dpkg -i` (killed after 15 minutes like every package run of the
   agent, then retried after a back-off);
3. keeps `orbit.service` enabled and running.

fleetd and these paths are a protected area: a changed file is restored at the next drift pass and reported as
`device.tamper_protected_file_changed`; a stopped `orbit.service` is started again and reported as
`device.tamper_service_stopped` (the agent's half of the mutual watch). Managed files and units cannot touch
`/opt/orbit/`, `/etc/default/orbit`, `/etc/systemd/system/orbit*` or units named `orbit*` or `fleet*`.

## Inventory sync and mutual watch

Every inventory round (`PADDOCK_INVENTORY_SYNC_INTERVAL`, default 5 minutes; one worker replica at a time)
`paddock-worker`:

1. pushes Paddock's policies (`server/internal/inventory/policies/*.sql`: `paddock_agent_running`,
   `disk_encrypted`, and `paddock_agent_binary_known`, which the worker builds from the SHA-256 of every published
   agent artifact; ADR 0056) as global Fleet policies for Linux; they return pass or fail, never rows. Applying them is
   idempotent, so a release published since the previous round reaches Fleet in this round;
2. reads the hosts whose details, software or policy results changed since the previous round, and every host after a
   start, whenever Fleet's set of vulnerable software versions changed (Fleet matches vulnerabilities on its own
   schedule, about hourly, without marking hosts as changed) and every 12th round;
3. binds each device to the host its agent named (fleetd's device token, resolved through Fleet's device endpoint) and
   stores only that host for the device. A device whose agent has not named a host yet keeps the host Paddock already
   stores for it while Fleet lists it with the device's hardware UUID (the lowest Fleet ID when none is stored yet). A
   host that already speaks for another device is never bound to a device (`result="host_in_use"`); retire a device's
   previous record before you enroll the machine again. A host a device no longer speaks from (its previous stored
   host, or a stored host Fleet lists with another hardware UUID) stays reserved for that device and is removed from
   Fleet in the same or the next round (`device.inventory_host_removed`, `paddock_inventory_previous_hosts_total`).
   After a Fleet rebuild or restore, such a host ID can name another machine's record; the record is removed and the
   machine's fleetd enrolls again under a new ID. Retiring a device reserves its stored host in the same way; the next
   inventory round removes it from Fleet. Paddock's copy of the retired device's inventory follows the retention
   period. Hosts that do not speak for a device are counted in the log attribute `ignored`;
   `paddock_inventory_host_bindings_total` counts the binding decisions by `result`. Hosts that map to no device are
   never stored and are counted in the metric `paddock_inventory_unmapped_hosts` (ops port, `/metrics`). A retired
   device keeps its hardware UUID until retention has purged its inventory (`retired_inventory_days`) or it was retired
   as uninstalled. Meanwhile, a device with the same UUID whose agent has not named its inventory host yet stores
   nothing. That includes a machine enrolled again, in the same or another organization. A device whose agent runs
   0.1.0-alpha.11 or later binds its own host and is not affected. To release the UUID earlier, uninstall the old
   device before you retire it (`POST /api/v1/devices/{id}/uninstall`), or let its organization lower
   `retired_inventory_days` (`PUT /api/v1/settings/privacy`, minimum 1 day; this applies to all of its retired devices,
   and the retention round runs every 6 hours);
4. stores, per mapped device and under its organization, the OS version, the fleetd (or osquery) version, the last
   time Fleet saw the host, its hardware facts (manufacturer, model, serial number, processor and physical cores,
   memory size, total disk size; ADR 0037 decision 7), the installed packages, the matched CVEs and the policy results;
   what the host no longer reports is deleted. Fleet's host IDs appear only in `device_inventory_ref.external_id`.
   Free disk space, uptime and network addresses are not copied. The device page shows the hardware facts in its
   identity panel, and the device search matches the serial number;
5. reports, once per failure, `device.tamper_agent_not_running` for every active device whose `paddock_agent_running`
   policy fails while it has not checked in for 15 minutes, or fails in evaluations at least 15 minutes apart although
   it keeps checking in — then something other than the genuine agent may check in with the device's credentials
   (fleetd's half of the mutual watch). With the default policy interval of 10 minutes the second case is reported
   within about 40 minutes. The agent must run from `/opt/paddock/agent/` as installed; a device whose `/opt` is a
   symbolic link to another place fails `paddock_agent_running` and is reported. The reported failure
   stays on the attention page and on the device as *Agent not running* (kind `agent_not_running`) until the policy
   passes again. It also reports, once per failure, `device.tamper_agent_binary_changed` for every active device whose
   `paddock_agent_binary_known` policy fails: a running agent process (named `paddockd`, running a file named
   `paddockd` or a file below `/opt/paddock/agent/`, or started by `paddock-supervisor`) runs an executable that
   matches no published release. Only an evaluation made at least 2 minutes after the worker applied the current hash set
   counts, so a host that has not yet evaluated a newly published release is not reported; a round in which a release
   was published skips these reports. The failure opens a tamper finding on the device. A genuine older published
   release passes (RR-149). If no release is published, the policy always passes. A failure that Fleet resets after a
   new definition stays reported until the host answers again, so a publish does not repeat the event. If the device
   was repaired and a publish reset its passing result before the worker read it, a new tamper is reported only after
   the policy has passed again. A host that evaluated a Paddock policy's current definition without an answer (the
   query failed there) is counted in `paddock_inventory_policy_unanswered_hosts{policy}` each full round and logged
   as a warning. A device
   installed from packages whose `paddockd` is not a published release (a local build or a draft release) fails this
   policy as soon as any release is published; publish that build or install a published release. The worker logs the
   number of accepted hashes whenever it changes and warns above 1,000, because Fleet must accept the whole query;
6. reports, once per episode, `device.tamper_fleet_host_claimed` when another host reports a device's hardware UUID
   and keeps contacting Fleet for 15 minutes, or when the device's host was enrolled again. After a re-enrollment, agent
   reports from Fleet wait 60 minutes. A Fleet database restore re-enrolls many hosts at once; the worker then holds
   the re-enrollment reports of the affected binding mode (`claim_majority`, label `binding`). A bound host that Fleet
   no longer lists with the device's hardware UUID suspends the device's binding until the device names its new host
   (`paddock_inventory_bindings_suspended`). The worker resolves at most 200 device tokens per round: more than about
   1,500 agent updates per hour can leave a device unresolved for longer than 60 minutes, which then raises one false
   `second_host` report, so keep rollout waves below that rate.

Fleet free reports CVEs without CVSS score, severity or fixed version (Fleet Premium only). Paddock adds Ubuntu's
priority, the fixed version and the CVSS vector from Ubuntu's OSV data when it stores a host's findings
(`docs/operations/vulnerability-data.md`). Findings Ubuntu has not rated keep severity `unknown` (filter
`severity=unknown`) and sort last; the start page tile counts the devices with critical or high findings and, next to
it, the devices with findings of unknown severity. Treat a finding of unknown severity as worth checking: the CVE links
to its entry in the National Vulnerability Database.

## Portal and admin API

Organization members see, per device, the tabs *Software* and *Vulnerabilities*, and, per organization, the pages
*Software* (per package and version with the number of devices) and *Vulnerabilities* (per CVE with the affected
devices). The admin API offers the same as read-only list endpoints: `GET /api/v1/devices/{id}/software`,
`GET /api/v1/devices/{id}/vulnerabilities`, `GET /api/v1/software`, `GET /api/v1/vulnerabilities`,
`GET /api/v1/vulnerabilities/{cve}/devices` and `GET /api/v1/vulnerabilities/summary`. Reads are not audited. The
organization-wide views and the tile count active and quarantined devices only; a retired device keeps its last
inventory on its own tabs until the worker's retention round deletes it, together with its host in Fleet,
`retired_inventory_days` after retirement (privacy settings, default 30; one `device.inventory_purged` event per device).
While Fleet is unavailable the inventory stays and the device is retried in the next round (after three failures in
a row of Fleet itself, `upstream_unavailable`: server errors, timeouts, connection errors, the round stops asking
Fleet until the next round; a proxy in front of Fleet that answers every host with a 4xx of its own, or a redirect,
counts the same, since Paddock does not follow redirects); when Fleet itself refuses to delete one host
(`invalid_state`, a 4xx with Fleet's own error body), only that device fails and is retried. A host that a device of
any organization still references stays in Fleet. The host also stays with the retired device's host reference while
a device of the same hardware is enrolled again but has not synced its inventory yet (`fleet_host_kept` `hardware`),
or while the host still checks in to Fleet after the retirement, within the last 7 days (`seen_recently`: fleetd still
runs on the retired machine or a successor uses the host); the retired device's other rows go and it is checked again
every round. An event is recorded only when that answer changes, or the device was reactivated and retired again;
rounds with the same answer only log `retired device keeps its Fleet host`, and after 30 such rounds one
`device.inventory_host_kept` event notes that the host is still kept (uninstall fleetd from a retired machine that is
still running). When Fleet cannot answer the check-in lookup of such a device, the device is skipped that round
without an event (the round logs the failure and it counts toward the three failures in a row). A failure to load the privacy settings or list
the retired devices records one `retention.purged` failure (`store` `retired_inventory`). The
lists show the state of the last inventory round, so a package change on a device appears after fleetd's next
software report (hourly by default) and the next round.

## Access for platform operators

Fleet's UI and API are reachable on the network `edge` only (`http://fleet:8080`; Caddy publishes the device paths
alone). Platform operators who need
the UI forward a local port to it, for example from their workstation through the Docker host:

```sh
ip=$(ssh docker-host docker inspect -f '{{(index .NetworkSettings.Networks "paddock_edge").IPAddress}}' paddock-fleet-1)
ssh -N -L 127.0.0.1:8412:"$ip":8080 docker-host
# then open http://127.0.0.1:8412 and sign in as admin@paddock-mdm.invalid (password: secret fleet_admin_password)
```

The development stack publishes the port on `127.0.0.1:8412` of the development host (`compose.dev.yaml`). Changes
made in the UI to the settings below are reset by `paddock-worker` within one round.

Fleet's logs can contain device-token URLs of failed lookups (RR-151): give access to Fleet's logs only to platform
operators.

## Bootstrap

`deploy/compose/scripts/fleet-bootstrap.sh` sets Fleet up; development runs it in `make up` (also
`make fleet-bootstrap`), production with `./paddock bootstrap fleet` on the control plane
(`docs/operations/install.md` section 7). It is idempotent:

1. Fleet's initial setup with the admin user `admin@paddock-mdm.invalid` (password from `.secrets/fleet_admin_password`;
   Fleet's UI is never published, so the address needs no real mailbox).
2. The API-only user `paddock` with the global role `admin`; its API token is written to `.secrets/fleet_api_token`.
   A valid token is kept; otherwise every earlier API-only user named `paddock` is deleted (which revokes its token)
   and a new one is created. Restart `paddock-worker` after a new token.
3. The global enroll secret from `.secrets/fleet_enroll_secret`.

## When the inventory claim watch is suppressed

The alert `PaddockInventoryClaimWatchSuppressed` and the log message `inventory claim watch suppressed`
(`reason=claim_majority`, `binding`) mean that more than half of the devices of one binding mode (`device` or `first`)
have an open episode with a re-enrollment, so the worker reports no re-enrollment of that mode. Claims of another host
are reported, except for a device whose agent has not named its inventory host yet and whose open episode also saw a
re-enrollment: that claim counts as a re-enrollment and is held as well (RR-22). The gauge
`paddock_inventory_claim_watch_suppressed{binding}` counts the claims held.

1. Check whether Fleet was restored or upgraded. The episodes end 60 minutes after the last re-enrollment, and the
   alert clears.
2. Otherwise list the Fleet hosts per hardware UUID. Several live hosts per UUID without such a cause need a security
   review of the devices concerned.

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
- `FLEET_OSQUERY_HOST_IDENTIFIER=provided` (compose): Fleet identifies a host by the identifier fleetd provides.
- No scheduled queries and no query packs: they are deleted. Saved queries without a schedule stay; they could only
  run live, and live queries are off.

Fleet's round intervals are environment variables of the `fleet` service: `FLEET_OSQUERY_POLICY_UPDATE_INTERVAL`
(default 10 minutes), `FLEET_OSQUERY_DETAIL_UPDATE_INTERVAL` (1 hour) and `FLEET_VULNERABILITIES_PERIODICITY`
(1 hour); the development stack uses 30 seconds, 2 minutes and 1 hour. Keep the development vulnerability period at
1 hour or longer: with `FLEET_VULNERABILITIES_CPE_DATABASE_URL` set, Fleet downloads the 146 MB CPE database on every
run. The inventory gates trigger the runs they need (`fleetctl trigger --name vulnerabilities` or Fleet's
`POST /api/latest/fleet/trigger`), at most every 2 minutes while they wait; Fleet refuses a trigger while a run is
pending.

## Backups

`fleet-backup` dumps `fleet-mysql` daily (`mysqldump`, plaintext); the backup role seals the dump into the backup set
and mirrors it to the backup targets (`docs/operations/backup.md`, `docs/operations/restore.md`). Everything in it can
be rebuilt from the devices within a day (architecture §20).
