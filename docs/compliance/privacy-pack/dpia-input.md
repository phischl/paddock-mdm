> Template. Not legal advice. Complete the fields in [brackets] and have your data protection officer and works
> council review the result. Facts about Paddock in this document are taken from docs/compliance/privacy.md and
> docs/compliance/retention.md as of [Paddock version].

# Data protection impact assessment: input for Paddock

Input for the data protection impact assessment (DPIA) under Art. 35 GDPR of [Organization]. It covers the threshold
assessment, the risks to employees, the mitigations Paddock provides and the residual risks [Organization] accepts.
What Paddock processes: [record-of-processing.md](record-of-processing.md) and [privacy.md](../privacy.md).

## Threshold assessment

| Criterion (Art. 35(3) GDPR, EDPB WP248 rev.01) | Applies to Paddock | Assessment |
| --- | --- | --- |
| Systematic monitoring | Paddock records events of employees' work devices continuously: logins once per user and 24 hours, tamper events, update runs; optionally every session start (login history) | Applies |
| Data of vulnerable data subjects (employees in a dependent relationship) | The data subjects are employees of [Organization] | Applies |
| Evaluation or scoring | Paddock does not score persons; the audit log can be searched by user name (risk "Behaviour evaluation through audit search" below) | [ ] |
| Large scale | [number of devices and employees] | [ ] |
| Matching or combining data sets | Device inventory, login trace and audit events are linked by device and user name | [ ] |
| Innovative use of technology | Standard device management | [ ] |
| Processing that prevents data subjects from exercising a right or using a service | A lock or the dead man's switch makes a device unusable until it is restored | [ ] |

**Result:** systematic monitoring of employees; a DPIA is likely required. [Decision of the data protection officer,
date].

## Risks from the employee's perspective

Likelihood and severity are left for [Organization] to assess (for example low, medium, high).

| Risk | What it means for the employee | Paddock's mitigation | Likelihood | Severity |
| --- | --- | --- | --- | --- |
| **RR-01 Root bypass** | Employees keep local administrator rights. Evidence collected on the device ends where root starts: a colleague with root on a shared device, or the employee, can change what the device reports, so an event in the audit log may be incomplete or wrong, and a silent device may lead to wrong conclusions about the employee. | Events are shipped in near real time; a missing heartbeat, a stopped agent and a gap in the device's event numbering are themselves audit events; everything stored on the server is out of the user's reach. | [ ] | [ ] |
| **RR-06 Offline login window** | An offline login uses the cached PIN without a second factor; a locked employee's PIN keeps working on an offline device until its next contact. A stolen device can therefore be used with the employee's identity for that window. | A lock acts in the identity provider at once and on the device at its next check-in (≤ 6 minutes with jitter); offline emergency access is off by default. | [ ] | [ ] |
| **RR-15 Dead man's switch** | If enabled, the employee's device locks itself after the agreed period without contact to Paddock, also when Paddock is down or the employee is on leave; unsaved work is lost and the employee cannot work until the device is restored. | The period is at least 7 days (portal warns below 30); warnings by default 3 and 1 days before (configurable, can be switched off); only uptime counts; turning it off cancels the tokens; `device.presumed_self_locked`. | [ ] | [ ] |
| **RR-20 Data loss on revocation** | A Lock or a `terminate` user lock ends the employee's sessions; unsaved work is lost. A Destroy makes the disk unreadable. | Confirmation with typed hostname; Destroy needs a second administrator; limits per administrator (3 per hour, 10 per 24 h), per organization (20 per 24 h) and per device (1 per 24 h). | [ ] | [ ] |
| **RR-94 Deletion lag in backups** | Data that the retention schedule deletes stays in backups for up to 30 days and in the audit event that proves its deletion; the employee's data lives longer than the stated period. | Backups are encrypted and outside the control-plane host and expire after 30 days; every purge is recorded (`retention.purged`, `device.inventory_purged`). | [ ] | [ ] |
| **RR-95 Evidence export** | An evidence package for an auditor holds every audit event of the requested range with the employee's user name and the administrators' names and client addresses; it leaves Paddock as a file. | The request needs a step-up and a purpose and is audited (`audit.export_requested`); every download is audited (`audit.export_downloaded`); only organization administrators and auditors can request and download; the package expires 7 days after it is ready. | [ ] | [ ] |
| **Behaviour evaluation through audit search** | An administrator or auditor searches the audit log by an employee's user name, or reads the login history and the device inventory, to evaluate when and how the employee works. | The switch `audit_search_recorded` records the first search of the audit log per administrator and hour as `audit.searched` with its filters and whether a free-text term was used, not the term itself, so further searches in that hour and the searched name stay invisible; `inventory_view_recorded` records views of a device's *Software* and *Vulnerabilities* tabs as `device.inventory_viewed`, once per administrator, device and day; reads of the device overview (hardware facts, serial number), the device's logins and the organization-wide *Software* and *Vulnerabilities* pages are not recorded; the login history is off by default; roles limit who can read. | [ ] | [ ] |

## Mitigations provided by Paddock

- **Negative list:** executed commands, shell history, process lists, network connections, browser or application
  data, keystrokes, screen content and location are never collected ([privacy.md](../privacy.md)).
- **Data minimisation in the inventory:** Fleet's queries that read users' home directories, network addresses and
  software usage are switched off; free disk space and uptime stay in Fleet.
- **Recorded reads, coalesced:** audit searches (`audit.searched`, the first per administrator and hour) and views of
  a device's *Software* and *Vulnerabilities* tabs (`device.inventory_viewed`, once per administrator, device and day)
  are recorded when the organization switches them on.
- **Purge jobs with evidence:** login trace 365 days, login history `login_history_days`, inventory of retired devices
  `retired_inventory_days`, operational history per index retention; each deletion is recorded
  ([retention.md](../retention.md)).
- **Step-up:** reveal of secrets, Lock, Destroy, approvals and evidence exports require a fresh second factor
  (WebAuthn).
- **Two administrators for Destroy:** a Destroy needs the approval of a second administrator.
- **Separation of roles:** operators cannot reveal secrets, lock or destroy; auditors read only; the platform
  administrator role has no access to organization data.
- **Tamper-proof audit trail:** every privileged action is an audit event in a WORM store that no administrator can
  change or delete before its retention ends.

## Residual risks accepted by the organization

| Risk | Accepted | Additional measures of [Organization] | Owner |
| --- | --- | --- | --- |
| RR-01 Root bypass | [ ] | [ ] | [ ] |
| RR-06 Offline login window | [ ] | [ ] | [ ] |
| RR-15 Dead man's switch | [ ] | [ ] | [ ] |
| RR-20 Data loss on revocation | [ ] | [ ] | [ ] |
| RR-94 Deletion lag in backups | [ ] | [ ] | [ ] |
| RR-95 Evidence export | [ ] | [ ] | [ ] |
| Behaviour evaluation through audit search | [ ] | [ ] | [ ] |

Consultation of the works council: [date, result]. Consultation of the supervisory authority under Art. 36 GDPR:
[required | not required].
