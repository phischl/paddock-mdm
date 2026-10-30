> Template. Not legal advice. Complete the fields in [brackets] and have your data protection officer and works
> council review the result. Facts about Paddock in this document are taken from docs/compliance/privacy.md and
> docs/compliance/retention.md as of [Paddock version].

# Record of processing activities: Paddock

Input for the record of processing activities under Art. 30(1) GDPR of [Organization]. One table per processing
activity; one row per data category, with the retention and legal basis of the store that holds it
([retention.md](../retention.md)). TOMs point to the rows of [iso27001-mapping.md](../iso27001-mapping.md).

## Common entries

- **Controller:** [Organization], [address]; representative [name]; data protection officer [name, contact].
- **Processor:** platform operator [Operator] [Art. 28 agreement of date | internal department].
- **Recipients**, unless a row says otherwise: administrators of [Organization] by portal role (organization
  administrator, operator, auditor); [Operator] with technical access to the servers, not through the portal (the
  platform administrator role has no access to organization data); [SIEM or security operations centre, if
  configured]. Fleet is a component of Paddock on the operator's servers, not a recipient.
- **Third-country transfer:** [none unless the operator hosts abroad].
- **Data subjects:** "Users" are the employees and other persons who sign in to managed devices with a directory
  account; "administrators" are the persons with a portal role or API token.
- **WORM retention** is `PADDOCK_AUDIT_RETENTION_DAYS` (at least 400 days): [configured days]. **Index retention**
  is `PADDOCK_AUDIT_INDEX_RETENTION_DAYS` (default = WORM retention, never less): [configured days].
- **Backups** hold copies of every store except the WORM bucket: 14 full backups (14 days) plus WAL; bucket
  noncurrent versions and `openbao/`, `fleet/` objects 30 days (residual risk RR-94).

## Device management

| Data categories | Purpose | Data subjects | Recipients | Third-country transfer | Retention | TOMs | Legal basis |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Enrollment: hostname, hardware UUID, machine ID, `/etc/os-release`, agent version, public identity key (device record) | Identify and authenticate the managed device | Users of the device | Common | [none unless the operator hosts abroad] | Lifetime of the organization; a retired device stays as the anchor of its audit trail | A.8.1, A.8.24 | Art. 6(1)(c)/(f) [interest: secure operation of work devices] |
| Check-in: applied bundle and agent versions, schema versions, architecture, health (agent status and last error, sudo implementation, disk encryption state, capabilities of `paddock-revoke`, current hostname), reboot required, `event_seq_high`, clock offset (device status) | Keep the device configured, updated and its clock trustworthy | Users of the device | Common | [none unless the operator hosts abroad] | Lifetime of the organization (device record) | A.8.1, A.8.9, A.8.17 | Art. 6(1)(c)/(f) |
| Events of the agent's own work: bundle applied or rejected, drift corrected, agent updated or rolled back, login and sudo configuration applied or failed, locks and suspensions applied | Prove the configuration state of the device | Users of the device | Common | [none unless the operator hosts abroad] | WORM retention from the recording day; audit index and `action` per index retention | A.8.9, A.8.15 | Art. 6(1)(c) with A.5.33/A.8.15 duties, Art. 6(1)(f) |
| Update runs (`updates.run`): kind, start and end, result, number of upgraded packages, held-back package names, reboot required | Keep devices patched and prove it | Users of the device | Common | [none unless the operator hosts abroad] | WORM retention (audit log); device update status with the device record | A.8.8, A.8.15 | Art. 6(1)(c)/(f) |
| Apply status per resource (`device_bundle_report`, `device_resource_status`): resource IDs, error messages (may name local users and paths) | Show why a configuration did not apply | Users of the device | Common | [none unless the operator hosts abroad] | Current state only, replaced by the next report; rows of a retired device stay with the device record | A.8.9 | Art. 6(1)(f) |
| Commands and alerts (`device_command`, `device_alert`): actor references, hostnames, reasons | Operate the device and explain audit events | Users of the device, administrators | Common | [none unless the operator hosts abroad] | Index retention after `finished_at` or `cleared_at`; open alerts never | A.8.9, A.8.16 | Art. 6(1)(f) (A.8.9, A.8.32) |
| Configuration: user names in profiles and groups; managed file contents before a change (`change_set.before`) | Distribute configuration and revert changes | Users named in configuration | Common | [none unless the operator hosts abroad] | Configuration: lifetime of the organization; `change_set.before`: 90 days after `applied_at` | A.8.9 | Art. 6(1)(f) (A.8.32 revert) |

## Identity and login

| Data categories | Purpose | Data subjects | Recipients | Third-country transfer | Retention | TOMs | Legal basis |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `session.login`: the directory user's name, the device and the time, at most once per user and 24 hours (`device_user_seen`, no session, terminal or remote host) | Lock users on devices that cache their credentials | Users | Common | [none unless the operator hosts abroad] | 365 days after the last login; deletion per row | A.8.5, A.5.18 | Art. 6(1)(f): lock coverage of cached credentials; Art. 32 |
| Login history (`device_login_event`): user name, device and start time of every session of a directory user; only while the organization has switched it on (off by default) | [purpose agreed with the works council] | Users | Common | [none unless the operator hosts abroad] | `login_history_days` after the login (7–365, default 90): [configured days]; switching it off deletes every row at once | A.5.34, A.8.10 | Art. 6(1)(f) with the organization's works council agreement; Art. 88 |
| `local_admin.login`: PAM service and time of a login of the managed local administrator (no terminal or remote host) | Detect use of the emergency administrator account | Persons who use the local administrator account | Common | [none unless the operator hosts abroad] | WORM retention (audit log) | A.8.2, A.8.15 | Art. 6(1)(c)/(f) |

## Privileged access (sudo)

| Data categories | Purpose | Data subjects | Recipients | Third-country transfer | Retention | TOMs | Legal basis |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Permission profiles and their assignments to user names and groups | Grant sudo rights by role | Users with sudo rights | Common | [none unless the operator hosts abroad] | Lifetime of the organization | A.8.2 | Art. 6(1)(f) |
| Tamper events: changed sudoers files or privileged group members (file names, user names, hashes), changed protected files (file name), changed local administrator account (which field), a stopped `orbit.service` (unit name) | Detect changes to privileged access outside Paddock | Users of the device, persons named in the changed files | Common | [none unless the operator hosts abroad] | WORM retention (audit log) | A.8.2, A.8.16 | Art. 6(1)(c)/(f) |
| Local administrator password (escrowed, encrypted to `escrow-wrap`) | Emergency access to the device | Users of the device | Common (revealed only after a step-up) | [none unless the operator hosts abroad] | Until a Destroy or until the device row is deleted | A.8.2, A.8.24 | Art. 6(1)(f) |

## Disk encryption and escrow

| Data categories | Purpose | Data subjects | Recipients | Third-country transfer | Retention | TOMs | Legal basis |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Disk encryption state: kinds of the LUKS keyslots, per volume device path, LUKS UUID and keyslot count; changed keyslots (kinds) | Prove and keep the disk encrypted | Users of the device | Common | [none unless the operator hosts abroad] | Device status: lifetime of the organization; events: WORM retention | A.8.1, A.8.24 | Art. 6(1)(c)/(f), Art. 32 |
| Escrowed secrets: LUKS recovery key and header (encrypted to `escrow-wrap`, decrypted only after a step-up) | Recover the data of a device the organization owns | Users of the device | Common (revealed only after a step-up) | [none unless the operator hosts abroad] | Until a Destroy (`device.escrow_destroyed`) or until the device row is deleted | A.8.13, A.8.24 | Art. 6(1)(f): data recovery of a device the organization still owns |
| Revocation results: per volume the device path and the keyslot counts before and after, unresolved crypttab entries, refusals with their reason; revocation requests and approvals (actor references, hostnames, reasons) | Lock or destroy a lost device and prove it | Users of the device, administrators | Common | [none unless the operator hosts abroad] | Events: WORM retention; `revocation_request` with approvals: index retention after `finished_at`, unfinished requests never | A.8.1, A.8.10 | Art. 6(1)(f) (A.8.9, A.8.32) |
| Dead man's switch: self-lock token on the device, presumed self-lock (`device.presumed_self_locked`) | Lock devices that stay unreachable for the agreed period | Users of the device | Common | [none unless the operator hosts abroad] | Events: WORM retention | A.8.1 | Art. 6(1)(f) [only if enabled] |

## Inventory and vulnerabilities

| Data categories | Purpose | Data subjects | Recipients | Third-country transfer | Retention | TOMs | Legal basis |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Fleet detail queries read on the device: OS name, version, kernel; osquery and orbit versions and configuration; hostname, hardware UUID, serial number, vendor, model, CPU type, memory; uptime; free and total disk space; root file system encrypted; installed packages (deb, rpm, pacman, system-wide Python); built-in label membership; Fleet's last seen time and the request address (the proxy's) | Asset and vulnerability management | Users of the device | Common (Fleet's UI only for [Operator] through a local port forward) | [none unless the operator hosts abroad] | Active hosts: as the inventory; retired hosts: deleted by the inventory purge | A.8.8 | Art. 6(1)(f) |
| `device_inventory_ref`: Fleet host ID, last seen, OS version, fleetd version; hardware facts (manufacturer, model, serial number, processor and physical cores, memory size, total disk size) | Asset management, theft reports | Users of the device | Common (every member of the organization, residual risk RR-49) | [none unless the operator hosts abroad] | While the device is active; `retired_inventory_days` after retirement (1–365, default 30): [configured days] | A.8.8, A.8.10 | Art. 6(1)(f) (asset management, theft reports), Art. 5(1)(c) |
| `installed_software`: name, version and source of each installed package | Vulnerability management | Users of the device | Common | [none unless the operator hosts abroad] | While the device is active, replaced by every sync round; `retired_inventory_days` after retirement | A.8.8, A.8.10 | Art. 6(1)(f) (A.8.8), Art. 5(1)(c) |
| `vulnerability_finding`: CVE, package name and version, first seen, CVSS score, severity, fixed version, CVSS vector | Vulnerability management | Users of the device | Common | [none unless the operator hosts abroad] | As `installed_software` | A.8.8, A.8.10 | Art. 6(1)(f) (A.8.8), Art. 5(1)(c) |
| `inventory_policy_result`: pass or fail of `paddock_agent_running` and `disk_encrypted`, when it last changed | Prove the agent runs and the disk is encrypted | Users of the device | Common | [none unless the operator hosts abroad] | As `installed_software` | A.8.1, A.8.16 | Art. 6(1)(f) |

Vulnerability data (OSV) and agent releases (GitHub) are downloaded by the server; these requests carry no device,
organization, user or inventory data.

## Audit trail

| Data categories | Purpose | Data subjects | Recipients | Third-country transfer | Retention | TOMs | Legal basis |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Audit events in the WORM bucket `paddock-audit`: actor display name, IP, step-up; user names, hostnames; never secrets | Tamper-proof evidence of every privileged action and security event | Users, administrators | Common (organization administrators and auditors read the audit log) | [none unless the operator hosts abroad] | WORM retention from the recording day; Object Lock COMPLIANCE; expiry by the operator's lifecycle rule; erasure requests are answered by restriction | A.5.33, A.8.15 | Art. 6(1)(c) with A.5.33/A.8.15 duties, Art. 6(1)(f); Art. 17(3)(b) and (e) |
| Audit index (`paddock_audit.audit_event`) and the control-plane origin `action`: same as the WORM events | Search and display the audit log | Users, administrators | Common | [none unless the operator hosts abroad] | Index retention; a partition is dropped only when every event in it is older; `action` never ahead of the index | A.5.33, A.8.10 | As the WORM events |
| Read-access events: `audit.searched` and `device.inventory_viewed` (coalesced per administrator, device and day), each only when the organization switches it on; their coalescing keys (`read_audit_window`) | Evidence of who read personal data | Administrators | Common | [none unless the operator hosts abroad] | Events: WORM retention; `read_audit_window`: 48 hours | A.5.34, A.8.15 | Art. 6(1)(f) |
| Evidence exports (`audit_export`, `audit_export_chunk`): package with events, objects, manifests; requester identity and purpose | Hand evidence to auditors | Users, administrators | Organization administrators and auditors; [external auditor] (residual risk RR-95) | [none unless the operator hosts abroad] | 7 days after `ready`; failed and expired rows keep metadata (no package) for the WORM retention | A.5.28 | Art. 6(1)(c)/(f) (A.5.28 evidence collection) |
| Device event gaps (`device_event_dropped`, `device_event_gap`): device IDs, sequence ranges | Prove missing device events | Users of the device | Common | [none unless the operator hosts abroad] | Index retention after `recorded_at` | A.8.15 | Art. 6(1)(f) |
| Container logs (Caddy access log, `slog` of the roles): client IPs, hostnames, user names in messages; never secrets | Operate and troubleshoot the service | Users, administrators | [Operator] | [none unless the operator hosts abroad] | Docker `json-file` rotation: 50 MiB × 10 files per container | A.8.15 | Art. 6(1)(f) |

## Administrator access

| Data categories | Purpose | Data subjects | Recipients | Third-country transfer | Retention | TOMs | Legal basis |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Administrator account (`admin_account`): user name, display name, organization, role, portal language | Authenticate and authorize administrators | Administrators | Common | [none unless the operator hosts abroad] | Follows Authentik (synced); the audit trail keeps the name | A.5.18, A.8.5 | Art. 6(1)(b)/(f) |
| API tokens (`api_token`): hash, name, creator, expiry | Authenticate `paddockctl` | Administrators | Common | [none unless the operator hosts abroad] | Until revoked or expired, then kept as metadata for `api_token.use_denied` | A.8.5 | Art. 6(1)(b)/(f) |
| Actor data in every audit event: name, client IP address, step-up | Accountability of administrators | Administrators | Common | [none unless the operator hosts abroad] | WORM retention | A.8.15 | Art. 6(1)(c)/(f) |
| Role-group snapshots (`organization_role_member`, `platform_role_member`): user name and Authentik ID per role, Authentik superusers, every 5 minutes | Review access rights | Administrators | Common | [none unless the operator hosts abroad] | Index retention after `taken_at`, keeping the newest snapshot of every group | A.5.18 | Art. 6(1)(c)/(f) (A.5.18) |
| Sessions: session record in Valkey, `admin.login` with `channel`; MCP client name and version in the audit events of its changes (`actor.client`) | Sign-in and session control | Administrators | Common | [none unless the operator hosts abroad] | Session record: Valkey TTLs per key; events: WORM retention | A.8.5 | Art. 6(1)(b)/(f) |
| Tool results of an AI assistant connected with `paddockctl mcp` (what the administrator's role reads, including personal data of device users) | [purpose, if the organization allows MCP] | Users, administrators | [AI assistant provider, if the organization allows MCP] | [country of the AI assistant provider, if any] | Not stored by Paddock; reads through the MCP are not recorded per call (RR-89) | A.5.34 | [legal basis, if the organization allows MCP] |
| Identity provider (Authentik database): accounts, groups, sessions, Authentik events | Sign-in | Administrators, users | [Operator] | [none unless the operator hosts abroad] | Authentik's own settings: [configured retention] | A.8.5 | Operator's processing |
