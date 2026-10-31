# Third-party agents: EDR and SIEM agents next to Paddock

Many organizations run an endpoint detection or SIEM agent (Wazuh, an EDR) on the same laptops as the Paddock agent.
Paddock does not deploy, update or configure such an agent. It does two things: it can **report when one stops**
(the presence policy), and it tells you which paths and data to keep out of the other agent's collection so that the two
do not disagree or duplicate each other. The privacy guarantees of [privacy.md](../compliance/privacy.md) bind
Paddock's own components, the Paddock agent and fleetd; whatever a third-party agent collects is that agent's
configuration and your decision, not Paddock's.

## Deploy the agent with your own tooling

Install and update the third-party agent the way you install any other software of the organization: your own package
repository or software distribution, an image baked into your autoinstall, or configuration management. Paddock stays out
of it: it never installs, starts, stops, enables, disables or masks a third-party unit. Two consequences:

- A device is protected by that agent only if your tooling got it there. Paddock's report that the unit is *missing*
  tells you when it is not.
- To keep the unit running, let your own tooling (or a managed unit of the organization)
  own that, not the presence policy.

## The presence policy: report a stopped agent

*Security* → *Watched units* (`/settings/watched-units`) lists the third-party systemd services the organization wants
watched, for example `wazuh-agent.service` or `falcon-sensor.service`. Every device receives the list with its
configuration and checks the units on every apply and on every drift pass (every 5 minutes). It reads each unit with
`systemctl show` and reports a unit that is not running as the audit event `device.tamper_service_stopped` with the
parameters `unit` and `state`:

| `state` | Meaning |
| --- | --- |
| `inactive` | the unit is loaded and not running |
| `failed` | the unit failed (for a crash loop systemd shows `auto-restart`; the agent reports it as `failed` once it still sees it on the next pass, so a single restart is not reported) |
| `missing` | systemd does not know the unit (the package is not installed or was removed) |

Rules of the report:

- **Once per stop.** A unit that stays stopped is reported once; a unit that runs again and stops later is reported
  again. The agent holds the reported state in memory, so a unit that is still stopped is reported once more after the
  Paddock agent restarts. A unit that changes from stopped to missing produces no second event.
- **Transitions are not stops.** A plain start or stop in progress (`activating`, `deactivating`) keeps the previous
  state and reports nothing. A failing query for one unit is logged on the device, keeps the previous state and does not
  stop the other units.
- **Report only.** The agent runs no `systemctl start`, `stop`, `enable`, `disable` or `mask` and installs nothing; the
  report is not a change and never fails an apply.
- **A tamper event like any other.** It is part of the security preset ([notifications.md](notifications.md)), opens a
  finding with the unit as its subject (*Findings*: acknowledge, assign, close with a reason) and appears in the audit
  log and the [feed](siem.md).

Editing the list needs an organization administrator and a step-up. Up to 32 units, each ending in `.service`, no
duplicates; the server refuses (422 `unit_not_allowed`, naming the unit) a name that is not a service and the units of
Paddock and the identity stack: names starting with `paddock`, `himmelblau`, `fleet`, `orbit`, `ssh`, `gdm` or
`systemd-`. Every change is audited as `settings.watched_units_changed` (parameters `added`, `removed`, `units`). The
same list is the key `settings.watched_units` of `paddock.yml` (`paddockctl apply`). An empty list switches the
watching off.

## A privacy-minimal Wazuh agent

A SIEM agent can collect far more than Paddock does: process lists, listening ports, the commands users run. If your
works council or privacy notice relies on Paddock's negative list, configure the third-party agent to the same bounds.
This `ossec.conf` excerpt of the Wazuh agent keeps what a SIEM needs and leaves the rest off (check the element names
against the Wazuh version you run):

```xml
<ossec_config>
  <!-- Inventory: hardware and operating system, but no process list and no listening ports. -->
  <wodle name="syscollector">
    <disabled>no</disabled>
    <interval>1h</interval>
    <scan_on_start>yes</scan_on_start>
    <hardware>yes</hardware>
    <os>yes</os>
    <network>no</network>
    <packages>yes</packages>
    <ports all="no">no</ports>
    <processes>no</processes>
  </wodle>

  <!-- File integrity: system binaries only; Paddock's own areas are excluded (see below). -->
  <syscheck>
    <disabled>no</disabled>
    <frequency>43200</frequency>
    <directories check_all="yes">/usr/bin,/usr/sbin,/boot</directories>
    <ignore>/etc/sudoers</ignore>
    <ignore>/etc/sudoers.d</ignore>
    <ignore>/etc/pam.d</ignore>
    <ignore>/etc/himmelblau</ignore>
    <ignore>/etc/paddock</ignore>
    <ignore>/opt/paddock</ignore>
    <ignore>/etc/security</ignore>
  </syscheck>

  <!-- Logs: system logs only; no user shell history, no application logs. -->
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/syslog</location>
  </localfile>
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/auth.log</location>
  </localfile>
</ossec_config>
```

What the excerpt leaves out on purpose:

- **No auditd `execve` rules** (no `-a always,exit … -S execve` in `/etc/audit/rules.d/`): they record every command of
  every user, which is the executed-commands data Paddock never collects.
- **No `command`/`full_command` wodles** that run `ps`, `netstat`, `ss` or `last`, and no `localfile` for shell
  history, browsers or application logs.
- **`<packages>`** can be set to `no` as well: Paddock already inventories installed packages through fleetd, per
  organization and with deletion rules ([retention.md](../compliance/retention.md)).

### File integrity: exclude what Paddock owns

Paddock re-checks these areas itself and records every unexpected change as a tamper event (architecture §11.5), and the
agent rewrites them on its own schedule, so a second integrity monitor only produces noise and, with `report_changes`,
copies their contents (user names, group members, identity configuration) into the SIEM:

| Path | Why |
| --- | --- |
| `/etc/sudoers.d/` (and `/etc/sudoers`) | generated from the permission profiles; sudoers hash and files are tamper-checked |
| `/etc/pam.d/` | the agent keeps the deny-list lines of `common-auth` and `common-account`; changes are tamper events |
| `/etc/himmelblau/` | rendered by the agent and re-rendered by the drift loop |
| `/etc/paddock/` | the agent's configuration, keys and bundle state |
| `/opt/paddock/` | the agent and supervisor releases (A/B directories and the active symlink) |
| `/etc/security/` | a protected area of the identity configuration |

Add the paths of the organization's managed files and managed units that carry secrets or personal data to the same
exclusion list. Do not exclude them in order to hide anything from the SIEM: ship Paddock's own events instead
(the [audit feed](siem.md) or a [notification destination](notifications.md)), so the SIEM sees the tamper event, who
changed what and the finding that followed.
