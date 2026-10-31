> Template. Not legal advice. Complete the fields in [brackets] and have your data protection officer and works
> council review the result. Facts about Paddock in this document are taken from docs/compliance/privacy.md and
> docs/compliance/retention.md as of [Paddock version].

# Information on the processing of your data by the device management Paddock

Information for employees under Art. 13 GDPR. It covers the Linux workstations of [Organization] that are managed
with Paddock.

## Controller and data protection officer

- **Controller:** [Organization], [address], [contact for privacy questions].
- **Data protection officer:** [name or function], [e-mail address], [postal address].

## Purposes

[Organization] uses Paddock to:

1. **Manage devices:** enroll your workstation, distribute signed configuration, install updates and keep the
   software inventory.
2. **Keep devices secure:** manage logins and sudo rights, encrypt the disk and keep its recovery key, detect
   vulnerabilities and changes to protected configuration (tampering), and lock a lost or stolen device.
3. **Keep evidence:** record every privileged action and every security-relevant event in a tamper-proof audit log, as
   required for information security (ISO/IEC 27001) and data protection accountability.

[Organization] does not use Paddock to evaluate your performance or behaviour (works council annex, section 2). [Reference to the works council agreement, if any].

## Which data Paddock processes

**From your device (Paddock agent):**

- device identity at enrollment: hostname, hardware UUID, machine ID, operating system release, agent version, the
  device's public key;
- device status every 5 minutes: the time of the last check-in, applied configuration and agent versions,
  architecture, health (agent status, sudo implementation, disk encryption state, current hostname), whether a reboot
  is required, and the clock offset;
- events of the agent's own work: configuration applied or rejected, drift corrected, agent updated, login and sudo
  configuration applied, locks applied;
- update runs: kind, start and end, result, number of upgraded packages, held-back package names, reboot required;
- results of a lock or destroy of the disk (per volume the device path and keyslot counts);
- tamper events: changed sudoers files or privileged group members (file names, user names, hashes), changed
  protected files (file name), changed disk keyslots (kinds), changed local administrator account (which field), a
  stopped inventory agent (unit name);
- your logins: your directory user name, the device and the time of your login, at most once per user and 24 hours
  (`session.login`);
- the login history, only if [Organization] has switched it on: your user name, the device and the start time of
  every session (see *Login history* below);
- logins of the managed local administrator account: the PAM service and the time;
- escrowed secrets: the disk recovery key and header and the local administrator password, stored encrypted.

**From the directory and from administrators:**

- your user account as Paddock copies it from the directory or as an administrator created it: user name, display
  name, e-mail address, group memberships, and whether and since when it is locked;
- the devices you own or may log in to, and the permission profiles that give you sudo rights.

**From your device (inventory agent fleetd, a component of Paddock):**

- operating system name, version and kernel; versions of osquery and orbit;
- hostname, hardware UUID, serial number, vendor, model, CPU type, memory, disk size;
- time since boot and free disk space (kept in the inventory component, not copied into Paddock); the total disk
  size is copied (see hardware above);
- whether the root file system is encrypted;
- installed packages of the system package managers (deb, rpm, pacman) and system-wide Python packages: name,
  version, source;
- known vulnerabilities (CVEs) of those packages, matched on the server;
- pass or fail of two checks: the Paddock agent runs, and the disk is encrypted.

**About administrators** (if you administer Paddock): your account (user name, display name, organization, role,
portal language and theme, time of the last sign-in, whether AI assistants may make changes for you), your actions
with your name, client IP address and whether you confirmed them with a second factor, your API tokens (stored as
hashes), and your membership in the portal role groups.

## What Paddock never collects

Neither the Paddock agent nor fleetd collects, and Paddock never stores:

- executed commands or shell history,
- process lists,
- network connections,
- browser or application data (history, cookies, documents, application settings),
- keystrokes,
- screen content,
- location.

## Recipients

- Administrators of [Organization] with the roles organization administrator, operator and auditor, each to the
  extent of their role.
- The platform operator [Operator], who runs Paddock [as a processor under Art. 28 GDPR | as an internal
  department]. The platform administrator role has no access to your organization's data in the portal or the API;
  the operator's technical access to the servers is governed by [agreement].
- Fleet, the inventory component, runs as a part of Paddock on the operator's servers; it is not a separate
  recipient.
- [SIEM or security operations centre, if configured].
- [AI assistant provider, if the organization allows administrators to use AI assistants with Paddock (MCP)].

Paddock downloads public vulnerability data and agent releases from the internet; these requests carry no data about
devices, users or the organization. Transfer to a third country: [none unless the operator hosts abroad].

## How long data is kept

| Data | Retention |
| --- | --- |
| Audit events (actions, device events, tamper events, logins of the local administrator, update runs, revocation results) | At least `PADDOCK_AUDIT_RETENTION_DAYS` from the recording day, at least 400 days: [configured days]; cannot be deleted earlier. Paddock itself never deletes them; afterwards they are deleted by [the operator's lifecycle rule on the audit store, after n days | not deleted]. The searchable copy (audit index and `action`) is kept for `PADDOCK_AUDIT_INDEX_RETENTION_DAYS`, never less: [configured days] |
| Your last login per device (`device_user_seen`) | 365 days after your last login on that device |
| Login history (`device_login_event`) | `login_history_days` after the login (7–365, default 90): [configured days | switched off]; switching it off deletes every entry at once |
| Inventory of a retired device (packages, vulnerabilities, check results, hardware facts, the host in Fleet) | `retired_inventory_days` after retirement (1–365, default 30): [configured days] |
| Inventory of an active device | while the device is active; replaced at every inventory sync |
| Device record (identity, status, applied versions) | lifetime of the organization in Paddock |
| Escrowed disk recovery keys and headers | until a Destroy of the disk; otherwise with the device record |
| Escrowed local administrator password | with the device record (not deleted by Paddock yet) |
| Your user account, group memberships, device ownership and login and sudo assignments | until you are removed from the directory or deleted in Paddock |
| Finished commands, cleared alerts, finished revocation requests, role-group snapshots | `PADDOCK_AUDIT_INDEX_RETENTION_DAYS` (at least the audit event retention): [configured days] |
| Evidence packages for auditors | 7 days after they are ready |
| Container logs (client IPs, hostnames, user names in messages) | rotation at 50 MiB × 10 files per container |
| Backups | 14 full backups (14 days) plus WAL; bucket noncurrent versions and `openbao/`, `fleet/` objects 30 days |

Deleted data survives in backups for up to 30 days [or the backup expiry you configured].

## Your rights

You have the right of access (Art. 15), rectification (Art. 16), erasure (Art. 17), restriction of processing
(Art. 18), and to object to processing based on legitimate interests (Art. 21). Audit events are evidence that
[Organization] must keep (Art. 17(3)(b) and (e) GDPR); a request to erase them is answered by **restriction**: the
events stay until their retention ends, and only administrators and auditors of [Organization] can read them. You
can lodge a complaint with a supervisory authority, for example [competent supervisory authority].

## Recording of reads

According to [Organization]'s privacy settings, Paddock records in the audit log:

- views of a device's *Software* and *Vulnerabilities* pages: [recorded, the first view per administrator, device and
  day | not recorded];
- views of the list of devices affected by a vulnerability (CVE): [recorded, the first view per administrator, CVE and
  hour, with the CVE and the number of affected devices | not recorded];
- searches of the audit log: [recorded, the first search per administrator, hour and set of filters, with its filters
  but without a search term | not recorded].

Only the first access per window is recorded: further views of the same device on the same day, and further searches
with the same filters in the same hour, leave no entry in the audit log. The audit log therefore shows that and when
an administrator first read your data in a window, not how often.

Other reads, for example of the device overview or of the logins on a device, are not recorded. Every request and
every download of an evidence export for auditors is recorded.

## Dead man's switch

The dead man's switch is [enabled, period: n days | disabled]. When it is enabled, your device locks itself
after the period of uptime in which it never reached Paddock, also when Paddock itself is unreachable for that long.
The device warns you [3 and 1] days before (default 3 and 1). Powered-off time does not count. Restoring a locked
device needs [contact].

## Login history

The login history is [switched on, kept n days | switched off]. When it is on, Paddock records the start
time of every session of a directory user on a managed device; it allows seeing when people work. [Organization]
switches it on only with the agreement of [works council or equivalent body].

## How to see what Paddock knows about you

Ask [administrator contact] for:

- the device page of your workstation (overview, software, vulnerabilities, logins, login and sudo rights), and
- the audit events with your user name (audit log, searched by your user name).

[Organization] answers within one month (Art. 12(3) GDPR).
