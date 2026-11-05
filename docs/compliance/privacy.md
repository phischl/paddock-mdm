# Privacy: what Paddock collects from devices

Paddock collects what it needs to manage and secure a device, and nothing else (concept C9, "Privacy by design";
plan M5a decisions 2 and 11). This document lists everything the Paddock agent and fleetd (Fleet's agent: orbit and
osquery) send, what Paddock stores of it, and what is never collected.

## Never collected (negative list, binding)

Neither the Paddock agent nor fleetd collects, and Paddock never stores:

- executed commands or shell history,
- process lists,
- network connections,
- browser or application data (history, cookies, documents, application settings),
- keystrokes,
- screen content,
- location.

Fleet's features that could collect such data are switched off and kept off by `paddock-worker`
(`docs/operations/fleet.md`): live queries, scheduled queries and query packs, query reports, scripts, file carving
(also refused at the edge), host user lists, additional queries, webhooks and usage statistics to fleetdm.com.

## Paddock agent

| What | When | Stored |
| --- | --- | --- |
| Enrollment: hostname (refreshed at every check-in from the health report, plan M8h), hardware UUID (`/sys/class/dmi/id/product_uuid`), machine ID, `/etc/os-release`, agent version, public identity key | once | device record |
| Check-in: applied bundle version, agent version, bundle schema versions, architecture, health (agent status and last error, sudo implementation, disk encryption state with the kinds of the LUKS keyslots and, per encrypted volume, its device path, LUKS UUID and keyslot count, the capabilities of `paddock-revoke`, the current hostname), whether a reboot is required, the highest event sequence number the agent assigned (`event_seq_high`), the signed request timestamp, from which the server derives the device's clock offset (stored as one number per device with the start of an open drift episode; `device.clock_drift` above 60 s, `device.clock_drift_cleared` at 30 s or less) | every check-in (5 minutes) | device status |
| Events of the agent's own work: bundle applied or rejected (resource IDs and error messages; per resource its outcome - resource ID, status, error message - and, while a device is in report-only mode, the planned change lines: file names, unit names, user and group names, package names, and the kind of change, never file contents), configuration drift corrected, agent updated or rolled back, login and sudo configuration applied or failed, locks and suspensions applied | when they happen | audit log (error list and mode only); the per-resource outcomes and planned change lines in the apply status of the device (`device_resource_status`: the newest outcome per resource, replaced by the next report; `device_bundle_report`: outcome, mode and counts per bundle version), see `docs/compliance/retention.md` |
| Update runs (`updates.run`): kind (security or regular), start and end, result, number of upgraded packages, held-back package names, reboot required | after each run | audit log, device update status |
| Software status (plan M13a, ADR 0042): per assigned catalog entry the catalog entry, package name, intent, state, installed version, reason and an error text that may name paths; the software events (installed, reinstalled, removed, apply failed) with package name, version, intent, catalog entry, source and reason | with the check-in when the status changed and at least daily; events when they happen | software status of the device (`device_software_status`: the current state only, replaced by the device's next report); events in the audit log |
| Revocation results: per volume the device path and the keyslot counts before and after, unresolved crypttab entries, refusals with their reason | after a Lock, Destroy or refused token | audit log, revocation request |
| Tamper events: changed sudoers files or privileged group members (file names, user names, hashes), changed protected files (file name), changed LUKS keyslots (kinds), changed local administrator account (which field), a stopped `orbit.service` (unit name), a stopped or missing watched third-party unit (unit name and state) | when they happen | audit log |
| `session.login`: the directory user's name and the time, at most once per user and 24 hours; every session start while the organization's login history is on | at a directory user's login | device_user_seen (no session, terminal or remote host), kept 365 days after the last login (ADR 0032); while the login history is on also `device_login_event` |
| Login history (`device_login_event`, ADR 0037 decision 6): user name, device and start time of every session of a directory user | only while the organization has switched the login history on (off by default), and only sessions that started after the switch-on; a start time in the future is capped at the server's time plus 5 minutes | `login_history_days` (7–365, default 90), deleted by the worker every 6 hours (`retention.purged`); switching it off deletes every row of the organization at once |
| `local_admin.login`: the PAM service and the time of a login of the managed local administrator | at such a login | audit log (no terminal or remote host) |
| Escrowed secrets: LUKS recovery key and header, local administrator password, encrypted to `escrow-wrap` | when they change | escrow (decrypted only after a step-up) |

The login history is personal data of employees and allows monitoring when people work. An organization switches it
on (*Login & privileges* → *Login history*) only with the agreement of its works council or the equivalent body, and
informs the users; the setting shows this notice. User locks do not depend on it.

## fleetd (inventory and vulnerabilities)

fleetd answers Fleet's detail queries and Paddock's policies. Paddock changes Fleet's detail queries so that they read
nothing outside the list below (`server/internal/adapters/fleet/settings.go`):

| Fleet detail query | What it reads | Paddock's change |
| --- | --- | --- |
| `os_version`, `os_unix_like` | OS name, version, kernel | – |
| `osquery_info`, `osquery_flags`, `orbit_info` | versions and configuration of osquery and orbit | – |
| `system_info` | hostname, hardware UUID, serial number, vendor, model, CPU type, memory | – |
| `uptime` | time since boot | – |
| `disk_space_unix` | free and total disk space | – |
| `disk_encryption_linux` | whether the root file system is encrypted | – |
| `software_linux` | installed packages of the system package managers (deb, rpm): name, version, source | replaced: Fleet's query also reads npm packages and browser extensions from every user's home directory |
| `software_python_packages` | system-wide Python packages (osquery before 5.16 only) | – |
| `software_linux_fleetd_pacman` | pacman packages | – |
| `network_interface_unix` | IP and MAC addresses | switched off |
| `software_deb_last_opened_at`, `software_rpm_last_opened_at` | last access time of each package's executables (usage) | switched off |
| `software_python_packages_with_users_dir`, `software_vscode_extensions`, `software_jetbrains_plugins`, `software_go_binaries` | software in users' home directories | switched off |
| `users` | local user accounts | off (Fleet setting `enable_host_users = false`) |

Fleet also evaluates its built-in labels (platform membership, such as "Ubuntu Linux") on the device and stores the
membership only. Fleet itself records the time a host was last seen and the address requests come from (behind Caddy,
the proxy's address). Fleet matches the packages against public vulnerability feeds (NVD, OSV) on the server.

### Policies

Paddock defines **policies only** (`server/internal/inventory/policies/*.sql`). A policy is an osquery query that
returns rows when a host passes; osquery and Fleet turn the answer into **pass or fail** — the rows never leave the
device and are never stored:

| Policy | Passes when |
| --- | --- |
| `paddock_agent_running` | a process named `paddockd` runs from `/opt/paddock/agent/`. The query reads the process table on the device to answer one yes/no question; it is not a process list, and no process name, command line or user is collected. |
| `disk_encrypted` | the root file system is on an encrypted (dm-crypt) device |

There is no time synchronization policy: osquery has no table for it on Linux; Paddock measures drift from the check-in instead (*Paddock agent* table).

### What Paddock stores of it

`paddock-worker` copies, for every Fleet host that maps to exactly one device by hardware UUID, into tables of the
device's organization (row-level security, `docs/operations/fleet.md`):

| Table | Content |
| --- | --- |
| `device_inventory_ref` | Fleet's host ID, last seen, OS version, fleetd (or osquery) version |
| `device_inventory_ref` (hardware facts, ADR 0037 decision 7) | manufacturer, model, serial number, processor and its physical cores, memory size, total disk size; kept and purged with the inventory reference of the device (ADR 0032 amendment 2026-10-17) |
| `installed_software` | name, version and source of each installed package |
| `vulnerability_finding` | CVE, package name and version, first seen; CVSS score where the inventory system knows it (Fleet free does not); severity, fixed version and CVSS vector from Ubuntu's data for the device's release |
| `inventory_policy_result` | pass or fail per policy, when it last changed |

Hosts that map to no device or to several are never stored. Free disk space, uptime and network addresses stay in
Fleet; free disk space and uptime are, on request, also in a diagnostics bundle (below). The serial number identifies a person's laptop indirectly; it is shown to and searchable by every member of the
device's organization (residual risk RR-49). Inventory of a retired device is deleted, in Paddock and in Fleet,
`retired_inventory_days` after retirement (default 30).

Fleet free matches CVEs but reports no CVSS score, severity or fixed version. Paddock fills severity and fixed version
from Ubuntu's public vulnerability data (OSV), which the server downloads (`docs/operations/vulnerability-data.md`):
the request carries no device, organization or inventory data, devices never contact OSV, and no additional data is
collected from devices. Findings Ubuntu has not rated show severity "unknown".

The api role contacts GitHub (`api.github.com`, `github.com`, `*.githubusercontent.com`, or the configured release
source) only when a platform administrator checks for or imports an agent release (`docs/operations/agent-releases.md`
"Import from GitHub", ADR 0043): the request carries the installation's public IP address and the user agent
`paddock-server`, and with a configured token that token; it carries no device, organization, user or inventory
data. `PADDOCK_AGENT_RELEASE_SOURCE_REPO=off` switches it off.

Organization members see the stored inventory of their organization's devices in the portal (*Software* and
*Vulnerabilities*); reading it is recorded as `device.inventory_viewed` when the organization switches *Record
inventory views* on (`/api/v1/settings/privacy`), coalesced per administrator, device and day; the list of devices affected by a CVE is recorded as `vulnerability.devices_viewed` (CVE and device count, once per administrator, CVE and hour). Fleet's own UI and API are not published; only platform operators reach
them, through a local port forward (`docs/operations/fleet.md`).

## Diagnostics bundle (on request only)

A diagnostics bundle is collected only when an organization administrator or operator asks for it for one device,
with a reason (ADR 0048). It exists so that an operator can understand a device on which Paddock does not behave
without asking the user to copy logs by hand. Nothing is collected on a schedule, and nothing outside the closed list
below ever enters the bundle; extending the list is a change of this document.

**What it holds** (ADR 0048 decision 2, with the correction of its amendment 2026-11-05 for the bundle file):
Paddock's own state: the health report of the agent socket, `state.json` without `identity`, `managed.json`,
`probation.json`, `update-result.json`, `updates-result.json`, the supervisor upgrade result,
`bundle-redacted.json` (the applied configuration bundle with its secrets and managed-file contents replaced by
`<redacted>`), `trust.json`, `agent.yml`; the journals of `paddock-supervisor`, `paddockd`, `paddock-encrypt`,
`paddock-uninstall`, `himmelblaud` and `himmelblaud-tasks` of the last 7 days (newest first, cut at 8 MiB per unit);
`systemctl status` of those units and of `orbit`, `systemctl list-units --failed`; the Paddock-managed configuration:
`/etc/sudoers`, `/etc/sudoers.d/*`, `/etc/pam.d/common-*`, `/etc/nsswitch.conf`, `/etc/himmelblau/himmelblau.conf`
with the values of keys matching `(?i)secret|password|key` replaced by `<redacted>`,
`/etc/apt/sources.list.d/paddock-*`, `/etc/apt/preferences.d/5*paddock*`, `/etc/crypttab`, `/etc/fstab`; the system
facts `os-release`, `uname -a`, `timedatectl show`, `df -h / /boot /boot/efi`, `uptime -p`,
`lsblk -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINT`, `cryptsetup luksDump` of every LUKS volume the agent manages, the
presence of `/dev/tpm0` and `/dev/tpmrm0`, `dpkg -l 'paddock*' 'himmelblau*' 'fleet*'`, `ip -brief link` (link state,
no addresses), `resolvectl status` (resolver configuration), `/var/log/apt/history.log` (package operations: names
and versions, no users), and the result of one `GET <server_url>/healthz`. Never: process lists, `auth.log`, other
units' journals, home directories, shell history, network connections, addresses, user files. Every entry is a file
in a tar.gz with a `manifest.json` (entry, bytes, SHA-256, `truncated`), the archive is cut at 32 MiB sealed.

The negative list above applies to the bundle as well. The journals and the managed configuration name people: user
principal names in Himmelblau's journal, the names of locked users and of sudo rules in the agent's journal and in
the sudoers files. A bundle is therefore personal data of the device's users ([residual-risks.md](residual-risks.md),
RR-108).

The agent's list, entry by entry (`agent/internal/diagnostics` `Entries()`; a unit test fails when the first two columns of this table and the
code differ):

| Archive file | Read from | Content |
| --- | --- | --- |
| `paddock/health.json` | `/run/paddock/agent.sock` | the agent's health report, the same that every check-in sends |
| `paddock/state.json` | `/var/lib/paddock/state/state.json` | the agent's state without identity fields and without the hash of the local administrator's password |
| `paddock/managed.json` | `/var/lib/paddock/state/managed.json` | the files and units Paddock manages |
| `paddock/probation.json` | `/var/lib/paddock/state/probation.json` | the probation state of an agent update |
| `paddock/update-result.json` | `/var/lib/paddock/state/update-result.json` | the result of the last agent update |
| `paddock/updates-result.json` | `/var/lib/paddock/state/updates-result.json` | the result of the last package update run |
| `paddock/supervisor-upgrade-result.json` | `/var/lib/paddock/state/supervisor-upgrade-result.json` | the result of the last supervisor upgrade |
| `paddock/bundle-redacted.json` | `/var/lib/paddock/state/bundle.dsse` | the applied configuration bundle: only fields the agent knows to be public; the Fleet enroll secret, managed-file contents, every unknown field and URL credentials are `<redacted>`; its signatures do not verify against the rendering |
| `paddock/trust.json` | `/etc/paddock/trust.json` | the agent's trusted signing keys (public keys) |
| `paddock/agent.yml` | `/etc/paddock/agent.yml` | the agent's configuration; credentials in URLs (a proxy) are `<redacted>` |
| `systemd/status.txt` | `systemctl show --property=ActiveState,SubState,Result,ExecMainStatus,StateChangeTimestamp,ActiveEnterTimestamp,ActiveExitTimestamp,InactiveEnterTimestamp,ExecMainStartTimestamp,ExecMainExitTimestamp paddock-supervisor.service paddock-supervisor-upgrade.service paddock-encrypt-resume.service paddock-uninstall.service himmelblaud.service himmelblaud-tasks.service orbit.service` | the state of Paddock's, Himmelblau's and Fleet's units, one block per unit in the order of the command, with only the properties `ActiveState`, `SubState`, `Result`, `ExecMainStatus`, `StateChangeTimestamp`, `ActiveEnterTimestamp`, `ActiveExitTimestamp`, `InactiveEnterTimestamp`, `ExecMainStartTimestamp`, `ExecMainExitTimestamp`; no processes, command lines or journal lines (every other line of the output is dropped) |
| `systemd/failed-units.txt` | `systemctl list-units --failed --no-pager --plain` | the names of failed units |
| `etc/sudoers` | `/etc/sudoers` | the sudo configuration |
| `etc/sudoers.d` | `/etc/sudoers.d/*` | every file of the directory (symbolic links are not followed) |
| `etc/pam.d` | `/etc/pam.d/common-*` | the shared PAM configuration |
| `etc/nsswitch.conf` | `/etc/nsswitch.conf` | the name service configuration |
| `etc/himmelblau/himmelblau.conf` | `/etc/himmelblau/himmelblau.conf` | Himmelblau's configuration; every line matching `secret`, `password` or `key` (comments too) keeps its key and gets `<redacted>` as value (a matching line without `=` or `:` becomes `<redacted>` entirely) |
| `etc/apt/sources.list.d` | `/etc/apt/sources.list.d/paddock-*` | Paddock's package sources |
| `etc/apt/preferences.d` | `/etc/apt/preferences.d/5*paddock*` | Paddock's package pins |
| `etc/crypttab` | `/etc/crypttab` | the encrypted volumes; `password=`, `pass=` and `pwd=` options are `<redacted>` |
| `etc/fstab` | `/etc/fstab` | the mounted file systems; `password=`, `pass=` and `pwd=` options (network shares) are `<redacted>` |
| `system/os-release` | `/usr/lib/os-release` | the operating system and its version |
| `system/uname.txt` | `uname -a` | kernel version and architecture |
| `system/timedatectl.txt` | `timedatectl show` | time zone and time synchronization |
| `system/df.txt` | `df -h / /boot /boot/efi` | free and total space of the three file systems |
| `system/uptime.txt` | `uptime -p` | time since boot |
| `system/lsblk.txt` | `lsblk -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINT` | disks, partitions and their file systems |
| `system/luksDump` | `cryptsetup luksDump` | one file `luksDump-<uuid>.txt` per LUKS volume of the agent's health report: the header's keyslots and tokens, never key material |
| `system/tpm.txt` | `/dev/tpm0 /dev/tpmrm0` | one line per device node: present or not; nothing is read from the devices |
| `system/dpkg.txt` | `dpkg -l paddock* himmelblau* fleet*` | the installed versions of Paddock's, Himmelblau's and Fleet's packages |
| `system/ip-link.txt` | `ip -brief link` | network interfaces and their link state; hardware addresses are removed |
| `system/resolvectl.txt` | `resolvectl status --no-pager` | the resolver configuration (DNS servers and search domains) |
| `system/apt-history.log` | `/var/log/apt/history.log` | package operations with names and versions; the user in each `Requested-By:` line is `<redacted>` |
| `system/server-healthz.txt` | `/healthz` | the status line and at most 4 KiB of the answer of the Paddock server's `/healthz` |
| `journal/paddockd.log` | `paddock-supervisor.service` | the journal of the agent and its supervisor (the agent runs inside this unit) |
| `journal/paddock-supervisor.log` | `paddock-supervisor-upgrade.service` | the journal of the supervisor's own upgrade |
| `journal/paddock-encrypt.log` | `paddock-encrypt*` | the journal of the disk encryption units |
| `journal/paddock-uninstall.log` | `paddock-uninstall.service` | the journal of an uninstallation |
| `journal/himmelblaud.log` | `himmelblaud.service` | the journal of Himmelblau's daemon |
| `journal/himmelblaud-tasks.log` | `himmelblaud-tasks.service` | the journal of Himmelblau's task daemon |

Each journal holds the last 7 days, newest first, cut at 8 MiB; the content of all entries together is cut at about
24 MiB. An entry the device lacks (for example `/etc/crypttab` on an unencrypted device) is listed in `manifest.json`
with an error instead of a file.

**How it leaves the device.** The agent writes the archive to `/var/lib/paddock/diagnostics` (readable by root only),
seals it with a random key that only the escrow-reader can unwrap (the same protection as a disk recovery key),
uploads the sealed object to the escrow bucket and deletes the local file. Nobody with access to the bucket can read
the content. The api decrypts it only for one download by an organization administrator or operator after a step-up:
for that download the escrow-reader unwraps the key and the api opens the object, so the api holds the plaintext for
the duration of that request and does not keep it.

**Who requests and who reads it.** Organization administrators and operators request a bundle in the portal (device
tab *Diagnostics*) or with an API token, and must give a reason (2 to 500 characters). Only organization
administrators and operators download a bundle, each time after a fresh identity confirmation (step-up); an API token
never downloads. Auditors see the audit events of a bundle but never the bundle, the list or the tab; platform
administrators have no access. Organization administrators can delete (purge) a bundle at any time.

**What the user is told.** Before collecting, the agent shows a desktop notification in every active graphical session
of the device, in German when the device's locale is German and in English otherwise. The administrator's name is not
shown:

- English, title *Paddock: diagnostic data collected*, text:
  `Paddock collected diagnostic data from this device for your administrator. Reason: <reason>. What was collected: Paddock's own logs and configuration, no personal files.`
- German, title *Paddock: Diagnosedaten erfasst*, text:
  `Paddock hat für Ihre Administration Diagnosedaten von diesem Gerät erfasst. Grund: <reason>. Erfasst wurden: die eigenen Protokolle und die Konfiguration von Paddock, keine persönlichen Dateien.`

`<reason>` is the administrator's text. The notice is best effort: a device without a graphical session, or one where
the desktop cannot show notifications, shows nothing; the number of sessions reached is recorded with the bundle
(RR-109). Name the diagnostics bundle in the organization's information to employees.

**How long it is kept.** The sealed bundle is deleted 7 days after it was stored, together with its key material
(`retention.purged`, store `device_diagnostics`), or at once when an administrator purges it. What stays is the record
of the request for the retention of the organization's actions: who asked, when, the reason, the device, the state,
the size, the SHA-256 and how often and when it was last downloaded; who downloaded it is in the audit trail.

**What the audit trail holds.** Every step is one audit event: `device.diagnostics_requested` (with the reason),
`device.diagnostics_collected` (the SHA-256, size, file count and the number of sessions notified),
`device.diagnostics_downloaded` (with the SHA-256) and `device.diagnostics_purged`. The audit trail and the WORM store
hold the hash of a bundle, never its content.

## Administrators

Paddock stores of its administrators the account (user name, display name, organization, role, portal language),
and in every audit event of their actions the actor's name, the client IP address and whether the action had a
step-up. API tokens (`paddockctl`) are stored only as hashes, with their name, creator and expiry. Audit events are kept for
the retention of the WORM store (at least 400 days) and cannot be deleted earlier. Searches of the audit log are
recorded as `audit.searched` when the organization switches it on; opening the access review report is recorded as `access_review.viewed` (once per actor and day) under the same
switch; evidence exports are always recorded (`audit.export_requested`, `audit.export_downloaded`), and so is every
export of the access review (`access_review.exported`, `platform.access_review_exported`; the platform administrators'
view is `platform.access_review_viewed`, always recorded). How long each store is kept: `docs/compliance/retention.md`.

Paddock snapshots the membership of its portal role groups (`paddock.<slug>.admins`, `.operators`, `.auditors`,
`paddock.platform.admins`) and the set of Authentik superusers every 5 minutes: user name and Authentik ID per role,
and an audit event for every change.

### AI assistants on the administrator's machine (MCP)

An administrator who connects an AI assistant with `paddockctl mcp` (`docs/operations/mcp.md`) gives it what that
administrator's role reads in the portal, limited by the MCP policy of the scope: device inventory, user and group
names, managed-file contents, audit events and the other data of the admin API, including personal data of device
users. The MCP server runs on the administrator's machine; Paddock sends the tool results only to that process, and they
leave the administrator's machine only through the MCP client the administrator chose (for example to the model
provider of a hosted assistant). Whether that is allowed is the organization's decision: keep the MCP switched off,
or restrict it to *Selected tools only*, where it is not. Paddock stores of an MCP session the same as of a portal
session (the session record in Valkey, `admin.login` with `channel: mcp`) plus the MCP client's name and version in the
audit events of its changes (`actor.client`); reads through the MCP are not recorded per call (RR-89). The session
file on the workstation holds Authentik tokens of the administrator, not data of devices or users.

## What leaves the server

Paddock's server sends data to a third party only where the operator or an administrator configured it. Besides the
two outbound calls named above (Ubuntu's vulnerability data and the agent release source, neither carries device,
organization, user or inventory data), these are the paths for audit data. They forward **audit events that already
exist**; nothing is collected for them, and the negative list (never collected, above) is not widened by them:
`device_user_seen`, the inventory and every other table that is not an audit event are never forwarded.

| Path | Started by | What is sent | Recipient |
| --- | --- | --- | --- |
| **Webhook destination** (`docs/operations/notifications.md`) | an organization or platform administrator, with a step-up | per delivery a signed JSON message with the audit events that match the destination's filter (the security preset, all events or the selected codes): event ID, time, code, outcome, the actor (type, ID, display name, client IP), the target (type, ID, display name: a hostname or a user or account name) and **all parameters** of the event, plus a portal link per device event. Never a secret: audit parameters carry none | the webhook receiver at the URL the administrator entered; the URL itself is stored encrypted and never shown again |
| **E-mail destination** | the same | per delivery one plain-text message per batch: time, code, outcome, device or target display name, actor display name, a portal link for device events and, only with *Include event parameters*, the parameters; at most 50 events in detail | the listed addresses (1 to 20), through the **SMTP relay** the operator configured (`PADDOCK_SMTP_*`); the relay and every mail system behind it see the message |
| **Heartbeat and test message** | the notifier, or the administrator's *Send test* | organization ID and slug (`platform` for the platform), delivery ID, destination ID and sequence numbers; no audit events | as above |
| **Audit cursor feed** (`docs/operations/siem.md`) | a SIEM or auditor's tool holding an API token with the role `org_auditor` or `org_admin` | the organization's stored audit events as in the audit log (actor, target, parameters), read by the caller | the holder of the token: the SIEM operator |

Who receives what is therefore decided by the administrator who creates the destination, and it is recorded: every
creation, change, secret replacement and test is an audit event (`notification.destination_*`, `notification.test_*`),
and so is every successful delivery (`notification.delivered`, with the range of forwarded events, never their content).

**Pseudonymization.** An organization destination can replace user names with a pseudonym (`u_` and 24 hexadecimal
characters of an HMAC with a key of the organization) in the actor and target display names and in the parameters
`username`, `user`, `display_name`, `requested_by`, `approved_by`, `created_by`, `members` and `users`, and it removes
the client IP and ID of administrators from the actor. Host names, device names and every other parameter stay. The
pseudonym is stable inside the organization, so it is pseudonymous data, not anonymous data: an organization
administrator can resolve it (`notification.pseudonym_resolved`, with a step-up), and whoever holds both the
notifications and the organization's user list can resolve it too. A platform destination receives platform events,
which carry no end-user names.

**Recipients are processors or controllers of their own.** The operator of a webhook receiver, of the SMTP relay and of
the mail systems behind the recipients' addresses receives personal data (administrator names and IP addresses, device
host names, user names) in clear unless pseudonymized, and an e-mail is not end-to-end encrypted. Treat each of them as a
recipient in your records of processing: conclude a data processing agreement where the recipient processes on your
behalf (GDPR Art. 28), check transfers outside the EEA (Chapter V), and keep to the purpose of the notification (A.8.16
monitoring and A.5.25–26 incident handling, [iso27001-mapping.md](iso27001-mapping.md)). Paddock cannot recall a message
once it left; a webhook receiver's retention is its own ([residual-risks.md](residual-risks.md), RR-98).

**The negative list binds Paddock's own components.** The statement "never collected" above covers the Paddock agent,
fleetd and the server roles. A third-party agent on the device (an EDR or SIEM agent) is configured by the
organization and is not bound by it; `docs/operations/third-party-agents.md` shows how to keep such an agent to the same
bounds, and Paddock's watched-unit report (*Tamper events* above) is the only thing Paddock asks of it.

How long Paddock keeps the notification tables themselves: [retention.md](retention.md).
