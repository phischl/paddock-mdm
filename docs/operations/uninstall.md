# Removing Paddock from a device

An organization administrator removes Paddock from a device with *Danger zone* → *Remove Paddock* on the device
page (ADR 0037 decision 4). The portal asks for a step-up, the mode, a reason and the typed hostname; the server
issues the signed command `uninstall` (lifetime 7 days) and records `device.uninstall_requested`. The device carries
out the removal at its next check-in, reports it once (`device.uninstalled`, actor the device) and is retired by that
report (`device.retired` with the param `reason: uninstalled`, actor the system). User data is never deleted in
either mode, and the disk encryption, its keyslots, `/etc/crypttab`, `/etc/fstab`, the ESP and the boot loader are
never changed.

API: `POST /api/v1/devices/{id}/uninstall` (`org_admin`, step-up, body `{mode, confirm_hostname, reason, clear_tpm,
keep_local_admin}`) and `POST /api/v1/devices/{id}/uninstall/cancel`.

## Preconditions

- The device is `active`; no other removal is requested; no Lock or Destroy is pending for it (409 `invalid_state`).
- `clear_tpm` and `keep_local_admin` belong to mode `reset` (422 `invalid_request` with `leave`).
- `clear_tpm` is refused while the device's last report lists a `tpm2` or `tpm2+pin` keyslot on any volume (409
  `tpm_in_use_by_disk`): clearing the TPM would leave only the recovery key. The device checks this again before it
  clears anything.
- On the device the command is refused (`failed`, reason `revocation_pending`) while a Lock or Destroy token was handed
  to `paddock-revoke` within the last 24 hours.
- A Lock or Destroy requested while the removal is pending cancels it (recorded on `revocation.requested` as
  `uninstall_cancelled` and `uninstall_command_id`): a command without a result is withdrawn like a cancel; when the device had already received it, the
  device page warns that it may already have removed `paddock-revoke` (`docs/operations/revocation.md`).

## The two modes

The agent accepts the command (result `{accepted: true}`), writes the plan and a copy of itself to
`/run/paddock/uninstall/` and, once the server accepted the result, starts `paddockd uninstall` in the transient unit
`paddock-uninstall.service`, outside the supervisor. The helper runs these steps in order; a failed step never stops
the following ones and is reported as `failed:<message>`:

| Step | `leave` | `reset` |
| --- | --- | --- |
| `stop_services` | Stops and disables `paddock-supervisor.service` (and with it the agent), stops `paddock-updates.timer` and `paddock-disk-setup.service`. | same |
| `update_configuration` | Releases Paddock's package holds (`apt-mark unhold`), removes Paddock's apt pin, unattended-upgrades and timer configuration and `paddock-updates.service`/`.timer`. | same |
| `sudoers_and_notices` | Removes `/etc/sudoers.d/paddock-u-*` (then `visudo -c`; a failing check puts the file removed last back), the login deny list and the login notices (SSH, console, GDM). | same |
| `quarantine_copy` | Copies `/var/lib/paddock/quarantine/` to `/root/paddock-uninstall/quarantine/`; nothing is restored to `/etc/sudoers.d/`. | same |
| `managed_files` | skipped | Removes managed files whose content is unchanged; changed files and files on paths the policy denies stay. |
| `himmelblau` | skipped | Purges the Himmelblau packages and removes `/etc/himmelblau/`, `/var/cache/himmelblau/`, `/var/lib/himmelblau/` and Paddock's Himmelblau apt source. Home directories stay; directory users can no longer sign in. |
| `local_admin` | skipped (`local_admin: kept`) | Removes the managed local administrator (`userdel`, its home directory stays) unless it is the last local administrator or `keep_local_admin` is set. |
| `packages` | Purges `fleet-osquery`, `paddock-revoke`, `paddock-agent` and `paddock-supervisor`; removes `/opt/orbit/`, `/opt/paddock/` and Paddock's package, staging and rollback directories. | same |
| `tpm` | skipped (`tpm: not_requested`) | With `clear_tpm` only (see below). |

Afterwards the helper sends the events left in the agent's spool and `agent.uninstalled` with the outcome of every
step (`completed` when every step is `done` or `skipped`, else `partial`), retrying for up to 30 minutes. Delivered or
not, it then removes `/var/lib/paddock/` and `/etc/paddock/`, logs a summary to the journal
(`journalctl -u paddock-uninstall`) and writes `/root/paddock-uninstall/result.json` (0600).

What stays in both modes: every local account other than the removed managed administrator, every home directory,
`/srv`, the disk encryption with its PIN and recovery key, the break-glass accounts' sudo rights, and the escrowed
secrets of the device on the server (the recovery key may still be needed; Destroy is the way to make data
unrecoverable).

## The last-administrator guard

In mode `reset` the managed local administrator is removed only when another local account can still administer the
device: an account in `/etc/passwd` with a UID from 1000 to 59999, a login shell (not `nologin` or `false`), a usable
password hash in `/etc/shadow` (not empty, not starting with `!` or `*`) and membership in `sudo`, `admin` or `wheel`
(as its primary group or as a member). Only the local files count, never directory accounts. Without such an account
the administrator stays (`local_admin: kept_last_admin`) and its escrowed password remains revealable for the retired
device.

## Clearing the TPM

With `clear_tpm` the helper inspects the root volume and every LUKS volume of `/etc/crypttab` again; a `tpm2` or
`tpm2+pin` keyslot, or a volume it cannot read, leaves the TPM untouched (`tpm: skipped_in_use`). Otherwise it runs
`tpm2_clear -c l` (lockout hierarchy, empty authorization): `tpm: cleared`. When the TPM refuses the authorization (a
lockout authorization is set), the helper writes `5` to `/sys/class/tpm/tpm0/ppi/request` and the firmware asks
whoever is at the device to confirm the clear at the next boot (`tpm: requested_at_next_boot`). Any other failure is
`tpm: failed`.

## Cancelling

*Cancel request* in the danger zone (`POST …/uninstall/cancel`) withdraws the removal while the command is `pending`,
`failed` or `expired`; the command becomes `cancelled` and leaves the delivery queue at once
(`device.uninstall_cancelled`). A device that fetched the command before the cancel gets its result refused and does
not start the removal. Once the server recorded that the device received the command (`delivered`) the removal cannot
be cancelled — until the removal report is 24 hours overdue (see below). When the agent could not start the helper it reports `outcome: helper_failed`: nothing was removed, the
request ends and can be made again.

## Afterwards

The retired device shows the line "Paddock was removed on … (mode); local administrator: …; TPM: …" in its header.
While the removal is pending the attention page lists the device as *Removal of Paddock pending* (`uninstall_pending`,
detail `mode:status`).

## When the report never arrived

A device that removed Paddock but could not reach the server within 30 minutes stays `active` in the portal and on
the attention page. On the device, `/root/paddock-uninstall/result.json` is the evidence of what happened (mode,
outcome, every step, local administrator and TPM result, `"delivered": false`). Check it, then retire the device by
hand in the portal (*Retire*); the retirement revokes its identity keys. If the helper never ran (no result file, the
packages still installed — for example a reboot during the removal lost the helper, which runs from `/run`), cancel
the request or request it again once the report is 24 hours overdue (counted from the device's command result, or
from the delivery when there is none; audited with `report_overdue`), or remove the packages by hand. A command the
device received but has not answered yet (`delivered`) is cancelled with the request: a device that comes back with
it gets its result refused and does not start the removal. A late report of the withdrawn command no longer retires
the device.
