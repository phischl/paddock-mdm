# Enrolling an existing device

Most fleets exist before Paddock does. This runbook adopts a laptop that is already installed, without reinstalling
it. For new devices use the [autoinstall](autoinstall.md).

## 1. When to use it

Use it for an installed Ubuntu 24.04 or 26.04 laptop that runs systemd. Adoption installs the Paddock packages and
enrolls the device; it does not reinstall anything.

- **What adoption does:** the device receives its configuration, reports its inventory and is managed like any other
  device. It records that it was adopted (`enrollment_method` `adopted`), not autoinstalled, and starts in the
  report-only phase (section 6).
- **What it does not do:** the disk stays `unmanaged` (RR-04): Paddock reports an existing LUKS volume but does not
  take over its keyslots, and an unencrypted disk is reported `not_encrypted`. Only a reinstall with the autoinstall
  gives a Paddock-managed disk.
- **Report-only first apply:** a freshly adopted device first computes what the configuration would change and reports
  it without changing anything (section 6) until an administrator enables enforcement (section 7).
- **Minimum agent release:** report-only mode needs the agent release **0.1.0-alpha.8** or later. An agent from an
  older release does not send the enrollment method: its device is recorded as `unknown` and is enforced at once, as
  before. Install the packages of a release that is not older (section 4).
- **What enforcement changes:** Paddock alone grants sudo. Files in `/etc/sudoers.d` that are not Paddock's are
  quarantined, members of `sudo` and `admin` that are no break-glass account are removed, and managed files, units,
  packages and the login configuration are applied (section 7).

## 2. Prerequisites

- UEFI is not required. A TPM 2.0 is optional; without it the disk unlock relies on a passphrase.
- Network access from the device to `device.<domain>` and `bundles.<domain>` over HTTPS.
- A root shell on the device.
- The existing local administrators of the device are entered as break-glass accounts in *Login & privileges*
  ([device login](device-login.md)) **before** the device is enforced; otherwise the first enforced apply takes sudo
  from them.

## 3. Pre-flight

Copy the release asset `paddockd_<version>_linux_<arch>` to the device, make it executable and run it as root (a
copied binary is not on `PATH`; after section 4 the installed `paddockd` is). It only reads; nothing on the device
changes.

```sh
chmod +x paddockd_<version>_linux_<arch>
sudo ./paddockd_<version>_linux_<arch> preflight [--json] [--config /root/paddock-enroll.json] [--proxy URL]
```

It prints one line per check; `--json` prints `[{"name","status","detail"}]`. The exit code is 1 if and only if a
check is `fail`. `--config` adds the server check once you have the enrollment configuration (section 5); `--proxy` is the proxy for
that check, as for `paddockd enroll` (`sudo` drops `HTTPS_PROXY`).

| Check | Result | Meaning and what to fix |
| --- | --- | --- |
| `os` | `fail` unless Ubuntu 24.04 or 26.04 | Other releases are not supported. Upgrade the device first. |
| `systemd` | `fail` unless systemd is the running init | Paddock needs systemd units. |
| `root` | `fail` unless the effective user is root | Run with `sudo`. |
| `sudo` | `fail` if the sudo implementation cannot be determined; detail: `classic` or `sudo-rs` | Repair the sudo installation (`/usr/bin/sudo`, `visudo`). |
| `tpm2` | `warn` without a TPM 2.0 | The device works; disk unlock stays passphrase-only. |
| `luks` | `warn` unless the root file system is on LUKS; detail: the disk state the agent will report | Adoption never changes the disk. `unmanaged` is expected for an encrypted laptop. |
| `sssd` | `warn` when package `sssd` is installed | It conflicts with Himmelblau's NSS and PAM configuration. Remove it before enforcement. |
| `himmelblau` | `info`: installed version or `not installed; the agent installs it` | Nothing to fix. |
| `sudoers_d` | `warn` listing every entry of `/etc/sudoers.d` except `paddock-u-*` and `README`; the first enforced apply quarantines each of them unless the organization allows it | To keep a file, add it to the *sudoers.d allow list* in *Login & privileges* ([device login](device-login.md)); otherwise accept the quarantine. |
| `privileged_groups` | `warn` listing every member of `sudo` and `admin` | The organization's break-glass accounts are unknown before enrollment, so all members are listed. Members that are no break-glass account lose these groups when enforced. |
| `server` | `fail` unless the Paddock device gateway at `server_url` answers within 10 s (TLS succeeds and the answer is a Paddock problem response); `info` (skipped) without `--config` | Check DNS, TLS trust, proxy (`--proxy`) and firewall to `device.<domain>`; a captive portal or proxy error page fails the check. |
| `clock` | `warn` when time synchronization is off | Enable NTP (`timedatectl set-ntp true`); a wrong clock fails enrollment with `clock_skew`. |

Fix every `fail` before you continue. A `warn` does not block adoption but tells you what will happen.

## 4. Install the packages

These are the steps of the system test harness, in the same order; the harness still keeps the enrollment
configuration at a temporary path instead of `/root/paddock-enroll.json` (section 5).

1. Download the packages of the release you want to roll out; `<arch>` is `amd64` or `arm64`:
   `https://bundles.<domain>/packages/<version>/paddock-supervisor_<version>_<arch>.deb`,
   `https://bundles.<domain>/packages/<version>/paddock-agent_<version>_<arch>.deb` and, if the organization uses
   the revocation path, `https://bundles.<domain>/packages/<version>/paddock-revoke_<version>_<arch>.deb`.
2. Verify the SHA-256 of each file against the release page of the portal (`/platform/agent-releases/<version>`) or
   `GET /api/platform/v1/agent-releases/<version>`:

   ```sh
   sha256sum paddock-*_<version>_<arch>.deb
   ```

3. Install them together and check that the supervisor is enabled and the agent is linked:

   ```sh
   sudo dpkg -i paddock-agent_*.deb paddock-revoke_*.deb paddock-supervisor_*.deb \
     && systemctl is-enabled paddock-supervisor && readlink /opt/paddock/agent/current
   ```

   Leave out `paddock-revoke_*.deb` if you did not download it.

## 5. Enroll

1. In the portal, create an enrollment token (*Enrollment tokens*, or `POST /api/v1/enrollment-tokens`) and keep the
   enrollment configuration it shows once.
2. On the device, write the configuration to `/root/paddock-enroll.json`, readable by root only. Never put it at
   `/etc/paddock/enroll.json`: that path belongs to the autoinstall, and the agent enrolls from it on its own.

   ```sh
   sudo install -m 0600 /dev/null /root/paddock-enroll.json
   sudo tee /root/paddock-enroll.json >/dev/null   # paste the configuration, end with Ctrl-D
   sudo paddockd preflight --config /root/paddock-enroll.json
   ```

3. Enroll and remove the configuration afterwards:

   ```sh
   sudo paddockd enroll --config /root/paddock-enroll.json --remove-config
   ```

The device reports itself as `adopted` and starts in the report-only phase (section 6). It reports `autoinstall`, and
is enforced at once, only if it carries the marker the Paddock autoinstall leaves (`/etc/paddock/autoinstall.marker`);
a local administrator who creates that marker by hand only opts their own device into immediate enforcement. The
enrollment configuration at `/root/paddock-enroll.json` is outside the path of the daemon's own autoinstall enrollment,
so the daemon never picks it up; `paddockd enroll` and the daemon share one lock, so a device never sends two
enrollment requests at once.

Exit codes: `0` active, `2` pending (the token is not auto-approve: approve the device in the portal, *Devices*),
`3` rejected, `1` error. With `--no-wait` the command returns 2 while it waits for approval.

## 6. Report-only phase

Available from the agent release 0.1.0-alpha.8 (section 1). Until enforcement is enabled, the device is **report-only**:
at each new bundle the agent computes, for every resource of the bundle, what it would change, and reports that. It
changes nothing.

**Where to look**

- *Devices*: the device carries the chips *Adopted* and *Report-only*. The device list filters by *Enrollment method*
  and *Configuration mode* (`paddockctl devices list --config-mode report_only`, `--enrollment-method adopted`).
- The attention list shows the item *Report-only, waiting for enforcement* (kind `report_only`) for every device in this
  phase, and raises a finding for it like any attention condition.
- The device page, tab *Apply status*, carries the banner *This device is in report-only mode* and lists one row per
  resource (`GET /api/v1/devices/{id}/config-status`). The *Bundle history* below it shows each version with its mode.

**How to read a row**

| Status | Meaning |
| --- | --- |
| `applied` | the resource already matches the configuration; enforcement changes nothing |
| `pending` | enforcement would change it. Expand the row for the planned changes |
| *Plan error* (`failed` in a report-only report) | the agent could not plan the resource. It is not a failed apply and never counts toward a [configuration rollout](configuration-rollouts.md) |

A `pending` row lists the planned change lines the agent sends: file names, unit names, user and group names and
package names, never file contents. Examples: `quarantine <file>` (a foreign sudoers file), `remove <user> from sudo`,
`keep <user> in <group> (last administrator)`, `write paddock-u-…`, `systemctl enable <unit>`,
`apt-mark hold <package>`, `package`, `config` and `deny_list` (the login component), `content` or `mode 0644 → 0600`
(a managed file). At most 50 lines per resource are sent, each at most 256 bytes; a longer list ends with `… and N more`.
A stale managed file is `pending` with the line `remove`.

Review the planned changes, enter the break-glass accounts you need ([device login](device-login.md)), add files to
the *sudoers.d allow list* that must stay, and repeat until nothing unexpected is planned. A new bundle (for example
after you changed the configuration) produces a new report at the next check-in.

**What report-only does not stop.** The device still checks in and otherwise behaves like an enrolled device:

- Paddock's own updates (the agent and the supervisor install new releases),
- revocation (lock and destroy) and the dead man's switch, if the organization enabled it,
- the LUKS tick of the agent, commands, session tracking and the other events (the disk stays `unmanaged` for an
  adopted device, section 1),
- the rotation of the managed local administrator is not run; the command `rotate_admin_password` is answered
  `failed` with the reason `report_only`.

What it does stop: every change of a resource (no file, unit, package, update, login or sudo change, no stale-file
removal, no local administrator management) and the drift loop with the tamper checks of the apply and drift rounds.
Everything outside the bundle, such as other watchers of the agent, is unchanged.

## 7. Enable enforcement

Available from the agent release 0.1.0-alpha.8. Open the device (*Devices* → the device → *Overview*) and use *Enable
enforcement*. The dialog names what will change and asks you to type the device's hostname. Organization administrators
and operators can do it; it is not offered to an assistant (MCP). The API call is `POST /api/v1/devices/{id}/enforce`
with `{"hostname": "<hostname>"}`: 400 `invalid_request` for a different hostname, 409 `invalid_state` unless the device
is active and report-only. It is recorded as `device.enforcement_enabled` (parameters `hostname`,
`enrollment_method`, `report_only_since`). There is no way back to report-only for the same device.

At its next check-in the device receives an enforced bundle and applies it:

- **Foreign sudoers files** in `/etc/sudoers.d` are quarantined to `/var/lib/paddock/quarantine/sudoers.d/` (mode 0600, kept for
  your review) unless the organization allows them. Each file records the tamper event
  `device.tamper_sudoers_d_file` (parameters `file`, `quarantined_as`).
- **Unexpected members of `sudo` and `admin`** are removed, but only from a group that has a break-glass member (never
  the last administrator). Each removal records `device.tamper_sudo_group_member` with `removed: true`; a member kept
  because the group has no break-glass account is recorded once with `removed: false` and the reason `last_admin`.
- Managed files, units, package holds, the update settings and the login configuration are applied. The login
  component (Himmelblau) is installed when the organization configures a domain.
- The managed local administrator is created when the organization configures one; it joins `sudo`.

These tamper events are expected for an adopted device: they are the removals you reviewed in section 6. A change to
`/etc/sudoers` is not recorded at the first apply, which only records its hash. From then on the device is an ordinary
enforced device, takes part in [configuration rollouts](configuration-rollouts.md) and corrects drift every 5 minutes.

## 8. Rollback of an adoption

1. A device that is active: in the portal use *Danger zone* → *Remove Paddock* with mode `leave`
   ([uninstall](uninstall.md)). It removes Paddock's sudoers files, apt holds, login deny list, notices and
   `fleet-osquery` and keeps the quarantine copy. Retiring the device first makes this impossible.
2. A device that never became active or is unreachable: retire it in the portal and remove the packages by hand,
   `sudo apt remove paddock-agent paddock-supervisor` (add `paddock-revoke` only if you installed it).
3. Left on the device: after step 1, `/root/paddock-uninstall/` (`result.json` and the quarantine copy in
   `quarantine/`, from which you restore sudoers files by hand); after step 2, `/var/lib/paddock/quarantine/` and
   `/var/lib/paddock`. Remove them when you no longer need them.

## 9. Troubleshooting

- `sudo paddockd preflight` shows what is wrong on the device itself.
- `journalctl -u paddock-supervisor` shows the supervisor and the agent it starts.
- `invalid_token`: the token is expired, used up or revoked, or has not reached the gateway yet. Create a new one.
- `clock_skew`: the device clock differs from the server's. Enable NTP and retry.
- An autoinstalled device whose first-boot enrollment failed and that you recover with `paddockd enroll` is `adopted`
  from then on: it starts in report-only mode until you enable enforcement ([autoinstall](autoinstall.md)).
