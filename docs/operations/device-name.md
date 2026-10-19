# Device name: naming a device from the portal

An organization administrator or operator gives a device a **managed name** on its page (*Overview* → *Device
name*) or through `PUT /api/v1/devices/{id}/name`. The device takes the name as its hostname and keeps it (ADR 0041,
plan M8h). This page says what that changes on the device, what it does not change on the network, and how to find
out why a name is not applied.

## The name

- One lowercase DNS label: 1–63 letters, digits or hyphens, not starting or ending with a hyphen, not `localhost`.
  Uppercase is refused, not converted (400 `invalid_request`).
- Unique among the organization's devices that are not retired (409 `conflict`). A retired device keeps its name for
  the audit trail and does not block its reuse; a retired device cannot be named (409 `invalid_state`).
- No step-up and no confirmation: a rename is reversible. Every attempt is audited as `device.name_changed` with the
  reported `hostname`, the new `name` and the `previous_name` (`""` when none or when cleared).
- *Clear name* (`{"name": null}`) stops managing the name. The device keeps the name it has, and a later local rename
  is not corrected.

## On the device

The name is applied at the device's next check-in (at most 5 minutes, earlier after an event-triggered check-in),
without a reboot and without a logout. The agent:

1. runs `hostnamectl hostname <name>`, which sets the static and transient hostname and clears the pretty hostname,
   because the name is a valid host name (hostnamed writes `/etc/hostname` and `/etc/machine-info`; GNOME's *About*
   page and NetworkManager see the change at once); an empty pretty hostname counts as in sync;
2. restarts `avahi-daemon.service` when it is running, because Avahi reads the host name only at startup and would
   keep announcing the old one; a failed restart is retried at the next pass;
3. keeps the line `127.0.1.1 <name>` in `/etc/hosts` so that sudo resolves the host without a warning: on the first
   `127.0.1.1` line it renames the old short name and the old `<name>.<domain>` (keeping the domain) and keeps every
   other alias, or sets the first host name when the old name is not on the line; it inserts a line after the
   `127.0.0.1` line when there is none, or creates the file with both lines; every other line stays as it is. A
   symlinked `/etc/hosts` is left alone and logged once (RR-70).

Open shells keep their old prompt until a new shell starts.

A name changed by hand on the device (`hostnamectl hostname other`) is **drift**, not tampering: the drift check
restores the managed name within 5 minutes and the device reports `config.drift_corrected` with
`resource_ids: ["hostname"]`, shown in the audit log as `device.config_drift_corrected`. The hostname is not a
protected area (RR-68).

The device page shows the state of the name:

| State | Meaning |
| --- | --- |
| *Not managed* | No managed name; the device keeps its own hostname. |
| *Pending* | The device still reports another hostname (it has not checked in since, or the rename failed). The device list marks it with *Name pending*. |
| *Applied* | The device reports the managed name. |

The hostname Paddock lists for a device is the one the device reports at every check-in (agents of this release and
newer); older agents keep the name they reported at enrollment, and they ignore the managed name.

## On the network

Paddock does **not** register names on the network (RR-67):

- **DHCP and dynamic DNS** learn the new name at the next lease renewal or reconnect: NetworkManager sends the static
  hostname in its DHCP requests (`ipv4.dhcp-send-hostname`, on by default) and never overrides a valid static
  hostname. Records of the old name stay until you remove them; Paddock never updates DNS. Include the DNS cleanup in
  your rename process.
- **Avahi** announces the new name after the restart. A device outside Paddock on the same network with the same name
  makes Avahi announce `<name>-2`; uniqueness is checked only among the organization's devices in Paddock (RR-69).
- **Himmelblau** (generic OIDC mode) has no hostname-derived setting and registers no device: device logins are
  unaffected.
- **Fleet** identifies hosts by hardware UUID: the inventory mapping stays, and the Fleet host record shows the new
  name after osquery's next detail query.

## `/etc/hosts` as a managed file

An organization may ship `/etc/hosts` as a managed file (static intranet entries). The device name then leaves the
file alone, and the managed file owns the `127.0.1.1` line: keep it at the device's name, or sudo prints
"unable to resolve host" (sudo still works; RR-70). `/etc/hostname` and `/etc/machine-info` cannot be managed files
(400 `invalid_request`, *path is owned by the device name policy*): hostnamed owns them.

## Systemd units

`ProtectHostname=` must never be set on `paddock-supervisor.service` or any unit that runs `paddockd`: the agent
would run in its own UTS namespace and report a stale hostname. A unit test of the agent fails when a Paddock unit
sets it.

## Troubleshooting

| Symptom | Cause and fix |
| --- | --- |
| *Pending* for longer than a check-in; `device.bundle_applied` lists an error for `hostname`: `hostnamed unavailable: …` | `systemd-hostnamed` cannot be reached (D-Bus down, the unit masked). Check `hostnamectl` on the device; unmask or start `systemd-hostnamed.service`. The rest of the bundle is applied; the name is retried at every drift check. |
| Error `hostnamectl hostname <name>: exit 1 …` | hostnamed refused the change (for example a policy that forbids it). The error text is hostnamed's. |
| Error `avahi-daemon restart failed: …` | The name is set, but Avahi still announces the old name. Check `journalctl -u avahi-daemon`. |
| Error `/etc/hosts is not a regular file` | `/etc/hosts` is a symlink or a directory; the agent does not replace it. Make it a regular file or manage it as a file. |
| sudo prints "unable to resolve host" | `/etc/hosts` is a managed file without the `127.0.1.1` line of the current name (see above). |
| The list shows the old hostname | The device has an agent older than this release (it does not report its hostname), or it has not checked in since the rename. |
