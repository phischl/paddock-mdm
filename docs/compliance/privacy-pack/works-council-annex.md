> Template. Not legal advice. Complete the fields in [brackets] and have your data protection officer and works
> council review the result. Facts about Paddock in this document are taken from docs/compliance/privacy.md and
> docs/compliance/retention.md as of [Paddock version].

# Annex to the works council agreement: Paddock

Annex [number] to the agreement [title of the agreement] between [Organization] and [works council] under § 87(1)
no. 6 BetrVG on the introduction and use of the device management Paddock. It lists exhaustively the data Paddock
processes about employees, the evaluations it offers, who may see them and the agreed settings.

## 1. Permitted purposes

Paddock may be used only to:

1. manage the Linux workstations of [Organization] (enrollment, configuration, updates, inventory);
2. keep them secure (logins and sudo rights, disk encryption, vulnerabilities, tamper detection, locking a lost or
   stolen device);
3. keep the evidence required for information security and data protection (audit log).

## 2. Prohibition of performance and behaviour evaluation

The data in this annex must not be used to monitor or evaluate the performance or behaviour of employees, in
particular not their working times, presence, working speed or the software they use. Searches of the audit log or of
the login history by an employee's name are permitted only for [permitted occasions, for example a security incident
concerning the device or account] and [procedure, for example with the involvement of the works council].
Evidence obtained against this prohibition must not be used for measures under employment law [ ].

## 3. Data processed

### 3.1 Never collected

Neither the Paddock agent nor fleetd collects, and Paddock never stores: executed commands or shell history, process
lists, network connections, browser or application data (history, cookies, documents, application settings),
keystrokes, screen content, location.

### 3.2 Paddock agent

| What | When | Stored | Deleted |
| --- | --- | --- | --- |
| Enrollment: hostname, hardware UUID, machine ID, `/etc/os-release`, agent version, public identity key | once | device record | Lifetime of the organization; a retired device stays as the anchor of its audit trail |
| Check-in: time of the last check-in, applied bundle and agent versions, bundle schema versions, architecture, health (agent status and last error, sudo implementation, disk encryption state with the keyslot kinds and per encrypted volume device path, LUKS UUID and keyslot count, capabilities of `paddock-revoke`, current hostname), reboot required, `event_seq_high`, clock offset | every check-in (5 minutes) | device status | Lifetime of the organization |
| Events of the agent's own work: bundle applied or rejected (resource IDs and error messages), configuration drift corrected, agent updated or rolled back, login and sudo configuration applied or failed, locks and suspensions applied | when they happen | audit log | WORM retention (at least 400 days): [configured days] |
| Update runs (`updates.run`): kind, start and end, result, number of upgraded packages, held-back package names, reboot required | after each run | audit log, device update status | WORM retention |
| Revocation results: per volume the device path and the keyslot counts before and after, unresolved crypttab entries, refusals with their reason | after a Lock, Destroy or refused token | audit log, revocation request | WORM retention; revocation request: index retention after it finished |
| Tamper events: changed sudoers files or privileged group members (file names, user names, hashes), changed protected files (file name), changed LUKS keyslots (kinds), changed local administrator account (which field), a stopped `orbit.service` (unit name) | when they happen | audit log | WORM retention |
| `session.login`: the directory user's name and the time, at most once per user and 24 hours | at a directory user's login | `device_user_seen` (no session, terminal or remote host) | 365 days after the last login |
| Login history (`device_login_event`): user name, device and start time of every session of a directory user | only while the login history is switched on (off by default), and only sessions that started after the switch-on | `device_login_event` | `login_history_days` after the login (7–365, default 90); switching it off deletes every row at once |
| `local_admin.login`: the PAM service and the time of a login of the managed local administrator | at such a login | audit log (no terminal or remote host) | WORM retention |
| Escrowed secrets: LUKS recovery key and header, local administrator password, encrypted to `escrow-wrap` | when they change | escrow (decrypted only after a step-up) | LUKS recovery keys and headers: until a Destroy, otherwise with the device record; local administrator password: with the device record (not deleted by Paddock yet) |

### 3.3 fleetd (inventory and vulnerabilities)

What fleetd reads on the device:

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
| `users` | local user accounts | off |

Fleet also stores the membership in its built-in labels, the time a host was last seen and the proxy's address. Two
checks return pass or fail only: `paddock_agent_running` and `disk_encrypted`. Free disk space, uptime and the
proxy's address stay in Fleet.

What Paddock stores of it:

| Table | Content | Deleted |
| --- | --- | --- |
| `device_inventory_ref` | Fleet's host ID, last seen, OS version, fleetd (or osquery) version | While the device is active; `retired_inventory_days` after retirement |
| `device_inventory_ref` (hardware facts) | manufacturer, model, serial number, processor and its physical cores, memory size, total disk size | As the inventory reference of the device |
| `installed_software` | name, version and source of each installed package | Replaced by every sync round; `retired_inventory_days` after retirement |
| `vulnerability_finding` | CVE, package name and version, first seen; CVSS score, severity, fixed version and CVSS vector | As `installed_software` |
| `inventory_policy_result` | pass or fail per check, when it last changed | As `installed_software` |

The host in Fleet of a retired device is deleted with the inventory.

### 3.4 Users and configuration

| What | Stored | Deleted |
| --- | --- | --- |
| User account, copied from the directory or created in Paddock: user name, display name, e-mail address, source, lock state and the time of the lock | `app_user` | When the user is removed from the directory or deleted in Paddock |
| Group memberships, device owners (with who assigned them and when), login assignments, sudo profile assignments | configuration | With the user, or when an administrator removes them |

### 3.5 Administrators

The account (user name, display name, organization, role, portal language and theme, time of the last sign-in,
whether AI assistants may make changes for the administrator); in every audit event of their actions the actor's
name, the client IP address and whether the action had a step-up; API tokens as hashes with name, role, creator,
expiry and time of last use; snapshots of the portal role groups every 5 minutes. An administrator who connects an AI
assistant (`paddockctl mcp`) passes what the role reads to that assistant: [permitted | not permitted | permitted
for selected tools only].

## 4. Evaluations: portal pages with data about persons

| Page | Shows about persons | Roles |
| --- | --- | --- |
| *Devices* and the device page (*Overview*, *Software*, *Vulnerabilities*, *Login & sudo*, *Logins*, *Configuration*, *Commands*, *Audit*) | hostname, serial number, owner, installed software, vulnerabilities, assigned users and sudo rights, last logins per user and, if switched on, the login history, commands of the device; its audit events for administrators and auditors only | organization administrator, operator, auditor |
| *Users*, user page (*Devices owned*), *Groups* | user names, group memberships, owned devices, locks | organization administrator, operator, auditor |
| *Permission profiles* | users and groups with sudo rights | organization administrator, operator, auditor |
| *Software*, *Vulnerabilities* | which devices have a package or a vulnerability | organization administrator, operator, auditor |
| *Overview*, *Attention* | silent, presumed lost or non-compliant devices by hostname | organization administrator, operator, auditor |
| *Revocations* | locks and destroys with requesting and approving administrators and reasons | organization administrator |
| *Change sets*, *API tokens* | which administrator changed what, tokens with their creators | organization administrator, operator, auditor |
| *Audit log*, *Evidence integrity*, evidence exports | every audit event with user names, hostnames, actor names and client IP addresses | organization administrator, auditor |

[Pages added by later Paddock versions are added to this annex before they are used.]

## 5. Roles with access

| Role | Access |
| --- | --- |
| Organization administrator (`org_admin`) | Everything in the organization, including reveal of secrets, Lock and Destroy approval |
| Operator (`org_operator`) | Devices, users, profiles, commands; no reveal, user lock, Lock or Destroy |
| Auditor (`org_auditor`) | Read-only: the pages of section 4 except *Revocations*, including the audit log, evidence integrity and evidence export |
| Platform operator [Operator] | The platform administrator role creates organizations and manages releases and has **no** access to organization data in the portal or the API. It cannot change or delete audit events (WORM store). Technical access to servers, databases and the Fleet UI (only through a local port forward) is governed by [agreement]. |

Persons holding each role: [list or reference to the role concept]. Role changes are audit events
(`admin.role_granted`, `admin.role_revoked`).

## 6. Configurable switches and agreed values

| Switch | Where | Default | Agreed value |
| --- | --- | --- | --- |
| `audit_search_recorded`: the first search of the audit log per administrator, hour and set of filters is recorded as `audit.searched` with its filters (range, codes, outcomes, actor types, target device of the organization) and whether a free-text term was used, not the term itself; further searches with the same filters in the same hour, whatever their term, are not recorded; a refused search is recorded as failure | *Privacy* (`settings.privacy`) | off | [ ] |
| `inventory_view_recorded`: views of a device's *Software* and *Vulnerabilities* tabs are recorded as `device.inventory_viewed`, once per administrator, device and day, and the list of devices affected by a CVE as `vulnerability.devices_viewed` (the CVE and the number of devices, once per administrator, CVE and hour); the device overview (hardware facts, serial number), the device's logins and the organization-wide *Software* and *Vulnerabilities* pages are not recorded | *Privacy* (`settings.privacy`) | off | [ ] |
| `retired_inventory_days`: days after retirement until the inventory of a device is deleted (1–365) | *Privacy* (`settings.privacy`) | 30 | [ ] |
| `login_history_enabled`: record every session start of a directory user | *Login & privileges* → *Login history* (`settings.login`) | off | [ ] |
| `login_history_days`: days the login history is kept (7–365) | *Login & privileges* → *Login history* (`settings.login`) | 90 | [ ] |
| Dead man's switch: devices lock themselves after the period of uptime without contact to Paddock (at least 7 days; warnings by default 3 and 1 days before, configurable) | *Dead man's switch* | off | [ ] (enabled, period in days, or disabled) |

## 7. Deletion periods

| Data | Deleted after |
| --- | --- |
| Audit events in the WORM store | Kept at least `PADDOCK_AUDIT_RETENTION_DAYS` (at least 400) from the recording day: [configured days]; Paddock never deletes them, the operator's lifecycle rule on the bucket does: [after n days | not deleted]; erasure requests are answered by restriction |
| Audit index and `action` (searchable copy of the audit events) | `PADDOCK_AUDIT_INDEX_RETENTION_DAYS` (default = WORM retention, never less): [configured days]; erasure requests are answered by restriction |
| Last login per user and device (`device_user_seen`) | 365 days after the last login |
| Login history (`device_login_event`) | `login_history_days` after the login (7–365, default 90); at once when switched off |
| Inventory of a retired device, its hardware facts and its Fleet host | `retired_inventory_days` after retirement (default 30, 1–365) |
| Inventory of an active device | while the device is active; replaced by every sync round |
| Finished commands, cleared alerts, finished revocation requests with approvals, role-group snapshots, device event gaps | `PADDOCK_AUDIT_INDEX_RETENTION_DAYS` (default = WORM retention, never less): [configured days] |
| Read-access coalescing keys (`read_audit_window`) | 48 hours |
| Evidence packages | 7 days after `ready` |
| Container logs | Docker `json-file` rotation: 50 MiB × 10 files per container |
| Backups | 14 full backups (14 days) plus WAL; bucket noncurrent versions and `openbao/`, `fleet/` objects 30 days |
| User accounts, group memberships, device owners, login and sudo assignments | when the user is removed from the directory or deleted in Paddock |
| Device record, escrowed secrets of retired devices, configuration, change sets, administrator accounts, API tokens | not deleted by Paddock yet ([retention.md](../retention.md), "What is not purged yet") |

Every deletion by Paddock's retention jobs is recorded as `retention.purged` or `device.inventory_purged` and can be
shown to the works council on request. The expiry of backups, container logs and WORM objects (lifecycle rule) is not
recorded in the audit log.

## 8. Change procedure

- A new data category, a new evaluation (portal page or report with data about persons), a new purpose, a changed
  role, or a changed value of a switch in section 6 is a change of this annex and needs [the works council's prior
  agreement].
- Paddock records every change of the switches as an audit event: `settings.privacy_changed` (privacy settings),
  `settings.login_changed` (login history), `settings.dms_changed` (dead man's switch). A change of the privacy
  settings through the declarative configuration (`paddockctl apply`) is recorded as `config.applied` with the section
  `settings.privacy` and its change set. [Organization] gives the
  works council [the list of these events every n months | access on request].
- A Paddock update that adds a data category or an evaluation is installed only after this annex has been updated;
  [Organization] checks the changelog and [privacy.md](../privacy.md) of the new version for such changes before
  installing it.

## 9. Information rights of employees

Employees are informed with the transparency notice [reference to transparency-notice.md as issued]. Each employee
can ask [administrator contact] for the device page of their workstation and the audit events with their user name
(Art. 15 GDPR). Rectification, restriction and objection follow the transparency notice; audit events are restricted,
not erased, on request.

Place, date, signatures: [ ]
