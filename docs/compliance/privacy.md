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
| Events of the agent's own work: bundle applied or rejected (resource IDs and error messages), configuration drift corrected, agent updated or rolled back, login and sudo configuration applied or failed, locks and suspensions applied | when they happen | audit log |
| Update runs (`updates.run`): kind (security or regular), start and end, result, number of upgraded packages, held-back package names, reboot required | after each run | audit log, device update status |
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
Fleet. The serial number identifies a person's laptop indirectly; it is shown to and searchable by every member of the
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

## Administrators

Paddock stores of its administrators the account (user name, display name, organization, role, portal language),
and in every audit event of their actions the actor's name, the client IP address and whether the action had a
step-up. API tokens (`paddockctl`) are stored only as hashes, with their name, creator and expiry. Audit events are kept for
the retention of the WORM store (at least 400 days) and cannot be deleted earlier. Searches of the audit log are
recorded as `audit.searched` when the organization switches it on; evidence exports are always recorded
(`audit.export_requested`, `audit.export_downloaded`). How long each store is kept: `docs/compliance/retention.md`.

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
