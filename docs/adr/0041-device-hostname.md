# 0041 — Device name set from the platform: desired name, reported hostname, `hostname` section
Status: Accepted (architect, 2026-10-18; plan `docs/plans/M8h-device-hostname.md`)

## Context

The maintainer wants to name a device centrally from the portal: the name becomes the device's hostname, applied
without a reboot, and a local change is corrected like any other managed resource. Today `device.hostname` is the
name the agent reported once at enrollment (`EnrollRequest.hostname`, `os.Hostname()`); nothing updates it later, so a
laptop renamed by hand keeps its enrollment name in Paddock forever. The autoinstall takes a hostname at generation
time (`autoinstall.Validate`, RFC 1123 label) but the token is not bound to the device that will enroll with it.

Facts that bound the design (verified 2026-10-18 in `main` at `177c234` and upstream):

- **Bundles.** New capabilities are optional top-level sections, never new entries of `resources[]`: an agent rejects a
  bundle whose resource type it does not know (`apply.CheckTypes`, `unknown_resource_type`), but ignores an unknown
  top-level field (`bundle.VerifyVersions` decodes without `DisallowUnknownFields`); `updates` and `inventory` are
  the precedents (architecture §11.3, amendment 2026-10-08). The agent turns a section into one internal resource
  and reports it under its ID in `bundle.applied` and `config.drift_corrected` (`apply.Applier.sorted`,
  `agent/internal/agent/bundles.go::drift`). The drift loop re-plans the cached bundle every
  `config.DefaultDriftInterval` (300 s).
- **Events.** `protocol.EventTypes` is closed; a new type blocks the spool of a newer agent against an older server
  (ADR 0024). A local change of a managed resource is reported as `config.drift_corrected{version, resource_ids}`.
- **Reported state.** `CheckinRequest.Health` is `health.Report`, stored in `device_status.health`; M8d adds
  `supervisor_version` to it (plan M8d §6.2). `app.DeviceReports.RecordStatus` is the single writer of the
  heartbeat (coalesced per `devicecache.HeartbeatInterval`); the worker has `UPDATE` on `device`.
- **Fleet.** Paddock maps Fleet hosts by hardware UUID only (`app.InventorySync.MapHosts`, `host.UUID`); fleetd
  runs osquery with `--host_identifier=uuid` hard-coded (Fleet forum, maintainer statement; `fleetctl package`
  accepts `uuid` or `instance` only). A rename therefore neither duplicates nor unmaps a host.
- **Himmelblau.** Paddock runs Himmelblau in generic OIDC mode against Authentik (ADR 0019); `himmelblau.conf` as the
  agent renders it (`reconcile/login.go::renderHimmelblauConf`) has no hostname- or device-name-derived key; Entra
  device registration and Intune enrollment do not apply in that mode. A rename does not touch the login path.
- **systemd.** `hostnamectl hostname NAME` sets the static, transient and pretty hostname at once (man
  `hostnamectl(1)`: "By default, this will alter the pretty, the static, and the transient hostname alike"); the
  static and transient names are limited to 64 characters. `hostnamectl --json=short` prints `Hostname`,
  `StaticHostname` and `PrettyHostname`. Ubuntu 24.04 ships systemd 255, 26.04 a newer one.
- **NetworkManager.** `hostname-mode` affects the transient hostname only; "If a valid static hostname is set,
  NetworkManager will skip the update of the hostname despite the value of this option"; the system hostname is sent
  in DHCP requests by default (`ipv4.dhcp-send-hostname`, `NetworkManager.conf(5)`). Nothing re-sends it before the
  next lease renewal or reconnect.
- **Avahi.** `avahi-daemon` reads the host name once at startup ("If omitted defaults to the system host name as set
  with the sethostname() system call", `avahi-daemon.conf(5)`); `avahi-daemon/main.c` has no runtime check of the
  system hostname and SIGHUP does not reload it. After a rename the daemon keeps announcing the old name until it is
  restarted.
- **sudo.** sudo resolves the local hostname at every invocation; Ubuntu's installer writes `127.0.1.1 <hostname>` into
  `/etc/hosts` for that. systemd-resolved synthesizes the local hostname as well, but `/etc/hosts` is the convention
  that survives a stopped resolver.
- **Path policy.** `/etc/hostname`, `/etc/hosts` and `/etc/machine-info` are neither denied nor sensitive in
  `pkg/policy` (plan M8s §6.2); an organization could ship them as managed files. Adding them to the denied catalog
  would reverse the release's upgrade order (ADR 0013 amendment 2026-10-16 (2): agents first), which M8d's
  "server first" note in the same release batch forbids.
- **Portal.** Typed confirmations (uninstall, enforce, escrow reveal) compare against `device.hostname`
  (`lib/deviceDetailPage.ts::confirmation`, `app/disk.go::confirmedEscrow`); the header and the list show
  `d.hostname`.

## Options

### A. Where the name lives

- **A1 — `device.name` (desired, nullable) next to `device.hostname` (reported), the latter refreshed from the
  agent's health at every check-in (chosen).** + Desired and reported state are both visible, "pending" and
  "applied" are derivable without a new event; the list, search, audit targets and typed confirmations keep using the
  reported name, which is what the device actually is on the network. − Two columns that are usually equal.
- **A2 — Overwrite `device.hostname` with the desired name.** − Paddock would show a name the device may never
  have taken; typed confirmations would compare against a name the user does not see on the laptop. Rejected.
- **A3 — A naming template per organization or device group (`{org}-{serial}`, `{owner}-{nn}`).** + One rule
  for the fleet. − The inputs are not reliably available when the name is needed: the serial arrives with M8d's
  hardware facts after the first Fleet sync, owners are assigned by hand after enrollment; a template needs a
  collision counter with its own ordering rules, and it is a second source of truth next to the explicit name.
  Deferred: not in M8h; revisited once M8d's hardware facts are in the lab and a request for bulk naming exists.

### B. How the name reaches the device

- **B1 — Optional top-level bundle section `hostname: {name}` mapped to one internal resource `hostname`
  (chosen).** + Older agents ignore it (ADR 0013 holds); the agent reports it under the ID `hostname` in
  `bundle.applied` and `config.drift_corrected` without any new event type (ADR 0024 holds); the compiler renders it
  per device from one column. − One more section and reconciler.
- **B2 — A `file` resource for `/etc/hostname` plus a command.** − Does not set the transient or pretty name, does
  not reach hostnamed, and would need the F-11 change triggers that do not exist. Rejected.
- **B3 — A signed command `set_hostname`.** − Commands are one-shot; a local rename would not be corrected. Rejected.

### C. What the agent does

- **C1 — `hostnamectl hostname <name>` (all three names), the `127.0.1.1` line of `/etc/hosts`, a restart of
  `avahi-daemon.service` when it is active (chosen).** + Live, no reboot, GNOME and NetworkManager see the change
  through hostnamed, Avahi announces the new name, sudo resolves it. − A restart of a third-party service; bounded
  to the one daemon that provably needs it.
- **C2 — Write `/etc/hostname` and call `sethostname(2)` directly.** − Bypasses hostnamed (no D-Bus signal for GNOME
  and NetworkManager, no pretty name, no `/etc/machine-info`). Rejected.

### D. Drift and tamper

- **D1 — Drift like every managed resource: the drift loop re-plans every 300 s and corrects, reported as
  `config.drift_corrected` with `resource_ids: ["hostname"]` (chosen).** + No new event type; the device page and
  the audit log show it. − A local rename is not a tamper event; the hostname is not a protected area.
- **D2 — A new tamper event.** − New event type (ADR 0024); a hostname is not security-relevant enough to be a
  protected area. Rejected.

### E. Managed files on the hostname's files

- **E1 — The server refuses new managed files at `/etc/hostname` and `/etc/machine-info` (400 `invalid_request`);
  the agent's hostname reconciler leaves `/etc/hosts` alone when the same bundle carries `file:/etc/hosts`
  (chosen).** + No change of `pkg/policy` tiers, so the release's upgrade order stays "server first"; a managed
  `/etc/hosts` (static intranet entries) stays possible and the administrator then owns the `127.0.1.1` line. − One
  documented interplay.
- **E2 — Add the three paths to the denied catalog.** − Reverses the upgrade order of the whole release batch (ADR
  0013 amendment). Rejected for M8h.

### F. Permissions and confirmation

- **F1 — `RolesWrite` (organization administrator, operator), no step-up, no typed confirmation, inline save in the
  overview (chosen).** A rename is reversible, reveals no secret and has a small blast radius, like
  `device.groups_changed` and M8d's `device.owners_changed`. The audit event carries the previous and the new name.
- **F2 — Step-up or typed confirmation.** − Would make a routine inventory task heavier than a group change. Rejected.

## Decision

1. **Data model.** `device.name text NULL` with `CHECK (name ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$' AND name <>
   'localhost')` and a partial unique index on `(organization_id, name) WHERE name IS NOT NULL AND state <> 'retired'`.
   `device.hostname` keeps its meaning "reported" and is refreshed from `health.hostname` at every check-in. The
   single validation is `bundle.ValidHostname` in `pkg/bundle`; `server/internal/autoinstall` uses it too.
2. **API and audit.** `PUT /api/v1/devices/{id}/name` with `{name: string | null}` (`RolesWrite`, no step-up), audited
   as `device.name_changed` with params `hostname`, `name`, `previous_name`; 409 `conflict` on a name another
   non-retired device of the organization holds; a change recompiles the device. `Device` gains `name` and the derived
   `name_state` (`unmanaged | pending | applied`). `GET /api/v1/devices?q=` matches `name` as well as `hostname`.
3. **Bundle.** Schema v2 gains the optional section `hostname: {name}`; rendered when `device.name` is not null;
   absent otherwise. The agent maps it to the internal resource `hostname` (type `hostname`), applied first.
4. **Agent.** Plan reads `hostnamectl --json=short`; it changes when the static, transient or pretty name differs
   from `name`, or when `/etc/hosts` lacks the line `127.0.1.1 <name>`. Apply runs `hostnamectl hostname <name>`,
   rewrites exactly the first `127.0.1.1` line of `/etc/hosts` (inserting one after the `127.0.0.1` line when
   missing; creating the file with both lines when absent; untouched when the bundle carries `file:/etc/hosts`),
   and restarts `avahi-daemon.service` when it is active. Failures are resource errors; nothing else changes; the
   device keeps working (contract 8). The agent reports `os.Hostname()` in `health.hostname` at every check-in. A
   cleared name (`null`) means unmanaged: the agent does nothing and the device keeps whatever name it has.
5. **Drift.** The existing loop corrects a local rename within the drift interval and reports
   `config.drift_corrected` with `resource_ids: ["hostname"]`; no tamper event, no new event type.
6. **Managed files.** New managed files at `/etc/hostname` and `/etc/machine-info` are refused; the reconciler
   skips `/etc/hosts` when it is a managed file of the same bundle.
7. **Units.** `ProtectHostname=` is never set on `paddock-supervisor.service` or `paddockd` (roadmap AG-2 lists it as
   a candidate): with it the agent would report a stale `os.Hostname()` from its own UTS namespace.
8. **Not decided here.** Naming templates (A3), bulk renames, a hostname-mismatch attention kind.

## Consequences

+ An administrator names a device from the portal; the device takes the name at its next check-in without a reboot;
  a local rename is reverted within five minutes and is visible in the audit log; Fleet, Himmelblau and enrollment
  are unaffected; `device.hostname` finally follows the device.
+ ADR 0005 and 0013 hold (one additive optional section); ADR 0024 holds (no new event type); ADR 0018 holds (no
  modal for a reversible change, list contract unchanged but for `q`).
− Name registration on the network is not Paddock's: DHCP and dynamic DNS learn the new name at the next lease
  renewal or reconnect; stale records of the old name are the operator's (RR-67). A local rename is drift, not
  tampering (RR-68). Uniqueness is per organization inside Paddock, not on the LAN (RR-69). A managed `/etc/hosts`
  takes the `127.0.1.1` line away from Paddock (RR-70).
− One restart of `avahi-daemon.service` per applied rename on devices that run it.
Follow-ups: plan `docs/plans/M8h-device-hostname.md` (PDK-329 to PDK-332); architecture §7.2, §11.3, §16.1 and
§17.1 amendments in PDK-332; naming templates as an open question for the maintainer.

## Amendment 2026-10-18 — the pretty hostname after `hostnamectl hostname` (architect, M8h review 1)

The context's systemd fact is incomplete. `hostnamectl hostname NAME` without `--static`, `--transient` or `--pretty`
sets the pretty hostname only when `NAME` is not itself a valid host name; for a valid one it **clears** the pretty
hostname (systemd `hostnamectl.c::set_hostname`: `p = ""` when `arg_static && hostname_is_valid(...)`). Every managed
name is a valid host name (decision 1), so after the agent's rename the pretty hostname is empty.

Decision 4 is refined accordingly: Plan changes when the static or transient hostname differs from `name`, or when
the pretty hostname is neither empty nor `name`. An empty pretty hostname is in sync. The agent does not pass
explicit flags to keep a pretty hostname. Without this refinement every drift pass would rename again, restart
Avahi and report `config.drift_corrected` (decision 5 would never converge). Gate S-HN1 accepts an empty or equal
pretty hostname and checks that two consecutive drift passes after a correction change nothing.
