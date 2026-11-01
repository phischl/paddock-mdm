# Enrolling an existing device

Most fleets exist before Paddock does. This runbook adopts a laptop that is already installed, without reinstalling
it. For new devices use the [autoinstall](autoinstall.md).

## 1. When to use it

Use it for an installed Ubuntu 24.04 or 26.04 laptop that runs systemd. Adoption installs the Paddock packages and
enrolls the device; it does not reinstall anything.

- **What adoption does:** the device receives its configuration, reports its inventory and is managed like any other
  device. From the agent release that ships PDK-160 the device also records that it was adopted, not autoinstalled;
  devices enrolled with an older agent have an `unknown` method and are enforced at once.
- **What it does not do:** the disk stays `unmanaged` (RR-04): Paddock reports an existing LUKS volume but does not
  take over its keyslots, and an unencrypted disk is reported `not_encrypted`. Only a reinstall with the autoinstall
  gives a Paddock-managed disk.
- **Report-only first apply:** from the agent release that ships PDK-161 a freshly adopted device first computes what
  the configuration would change and reports it without changing anything (section 6). Older agents enforce at once.
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
is enforced at once, only if it carries the marker the Paddock autoinstall leaves; a local administrator who creates
that marker by hand only opts their own device into immediate enforcement.

Exit codes: `0` active, `2` pending (the token is not auto-approve: approve the device in the portal, *Devices*),
`3` rejected, `1` error. With `--no-wait` the command returns 2 while it waits for approval.

## 6. Report-only phase

Available from the agent release that ships PDK-161. Agents older than that are enforced at once; skip to section 7.

The first apply of an adopted device changes nothing. The device detail page, tab *Apply status*, lists every
resource. A resource that would change shows as `pending` with its planned changes (files to write, units to
enable, packages to install, sudoers files to quarantine, group members to remove). The fleet attention list shows
the item `report_only` for every device in this phase. Review the planned changes, add the break-glass accounts you
need, and repeat until nothing unexpected is planned.

## 7. Enable enforcement

Available from the agent release that ships PDK-161. Enable enforcement for the device in the portal; the dialog
names what will change.

- The first enforced apply records tamper events (`device.tamper_sudoers_d_file`,
  `device.tamper_sudo_group_member`) for every foreign sudoers file and group member it removes. They are expected
  for an adopted device; the files are kept in `/var/lib/paddock/quarantine/`.
- The login component (Himmelblau) is installed by the agent when the organization configures a domain.
- The managed local administrator is created when the organization configures one; it joins `sudo`.

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
