# In-place encryption of an installed device

An organization administrator can encrypt an adopted, unencrypted Ubuntu device from the portal without reinstalling
it (ADR 0039, plan M8e). The device converts its root partition to LUKS2 at one restart and encrypts the rest in the
background while the user works. Afterwards it is managed like a device installed with the Paddock autoinstall
(`autoinstall.md`, `disk-recovery.md`): `compliant`, TPM2 + boot PIN (or TPM2 alone under the unlock mode *TPM only*),
a recovery key and the LUKS header escrowed. It differs in details: the initrd is built by dracut, the mapping is
called `dm_crypt-0`, and GRUB names root as `/dev/mapper/dm_crypt-0`. Paddock never starts a conversion on its own initiative.

## How it works

1. **Request.** On the device page, *Disk encryption → Encrypt this device…* (organization administrators, after a
   step-up): the administrator confirms that a current backup exists, gives a reason and types the hostname. The
   device receives the signed command `encrypt_disk` at its next check-in (at most about 6 minutes).
2. **Preparation (nothing on the disk changes).** The device checks its layout again, generates the *conversion key*,
   stores it in Paddock as recovery-key generation 1 and waits until the server confirms it. Only then it switches
   to dracut where needed, adds the Paddock module `99paddock-encrypt` with the plan and the key to every initrd and
   reports `prepared`. Signed-in users see a desktop notification asking them to restart (at every login and every 4
   hours).
3. **Restart (the init step).** At the next restart, before the root file system is mounted, the module checks the
   file system, shrinks it by 64 MiB (32 MiB for the LUKS2 header, the rest as margin), writes the LUKS2 header and
   opens the partition. The device then boots on dm-crypt.
4. **Background phase.** `paddockd encrypt-resume` encrypts the remaining data while the device is in use. No keyslot
   can be added while the encryption is unfinished, so nothing asks for a PIN yet (the device reports
   `enrollment_deferred`).
5. **Boot PIN after completion.** When the background encryption has completed, the device asks the user to restart
   (desktop notification *Disk encryption completed — please restart*). At that start it asks for the boot PIN on the
   text console (unlock mode *TPM + boot PIN*) or enrolls the TPM without a dialogue (*TPM only*), as after an
   autoinstall. Then the agent rebuilds every initrd without the module and the key, enrolls and escrows a new
   recovery key (generation 2) and the header, and removes the conversion key's keyslot. The device becomes
   `compliant`.

## Supported layouts and preflight reasons

The device reports whether it can be converted; the portal lists every failing reason. Supported are Ubuntu 24.04 and
26.04 with UEFI, a TPM 2.0, a separate `/boot` partition, and ext4 root either directly on a GPT partition
(*plain*) or on the only logical volume at the end of the only physical volume of a volume group on a GPT partition
(*lvm*, the installer's guided LVM layout). Only the root partition is encrypted: `/boot`, the EFI system partition,
swap partitions and other data partitions stay unencrypted.

| Reason | Meaning | What to do |
| --- | --- | --- |
| `release_unsupported` | Not Ubuntu 24.04 or 26.04. | Upgrade, or reinstall with the autoinstall. |
| `no_uefi` | The device boots in BIOS mode. | Reinstall in UEFI mode. |
| `no_tpm2` | No TPM 2.0 (or it is switched off in the firmware). | Enable the TPM in the firmware setup; otherwise reinstall is not possible either. |
| `no_separate_boot` | `/boot` is not on a partition of its own (Ubuntu Desktop's default layout). | Reinstall with the autoinstall. |
| `boot_on_root_device` | `/boot` lies on the root partition. | Reinstall. |
| `root_not_ext4` | The root file system is not ext4 (btrfs, xfs, ZFS). | Reinstall. |
| `root_layout_unsupported` | RAID, several physical volumes, an MBR partition table or another stack below root. | Reinstall. |
| `pv_tail_in_use` | Another logical volume (for example swap) lies at the end of the physical volume. | Reinstall, or move the volume away by hand and check again. |
| `low_free_space` | Less than 1 GiB free on the root file system. | Free space; the device checks again within 10 minutes. |
| `root_reference_unsupported` | fstab or the kernel command line name root by a device path other than its UUID or LVM name. | Refer to root by `UUID=` (fstab) or the LVM path and run `update-grub`. |
| `already_encrypted` | The root volume is LUKS already. | Nothing; see `disk-recovery.md`. |
| `dm_crypt_missing` | The kernel cannot load `dm_crypt` (reported at the preparation). | Install the distribution kernel. |
| `other_luks_present` | Another LUKS volume exists; the init step would leave it closed. | Remove it or reinstall. |
| `hibernation_configured` | `resume=` is set (kernel command line, `/etc/cmdline.d`, a dracut `kernel_cmdline`) or a hibernation image is announced. | Remove the hibernation setting, rebuild the initrd and restart. |
| `lvm_devicesfile` | LVM uses `/etc/lvm/devices/system.devices`; the moved physical volume would not be found. | Not supported yet; reinstall. |
| `lvm_filter` | `lvm.conf` sets `filter` or `global_filter`. | Remove the filter or reinstall. |
| `lvm_unknown` | The LVM configuration could not be read. | Check `lvm config` on the device. |
| `initrd_tools_missing` | dracut is installed but `lsinitrd` cannot read the running kernel's initrd. | Install the package that provides `3cpio` or `dracut-extractinitrd` (26.04). |
| `cleanup_pending` | The device is still removing an abandoned conversion from its initrds. | See "A cleanup that does not finish". |

## What the user sees

- **Before the restart:** the desktop notification *Disk encryption is ready — please restart*. Nothing else changes.
  On a device that still uses initramfs-tools (every 24.04, a 26.04 upgraded from 24.04) the preparation installs
  dracut; this removes `initramfs-tools` and usually `brltty` (the console braille support), and the graphical
  boot splash is replaced by a text console from then on. The portal's dialogue names the packages the device
  reported.
- **At the restart:** the text console shows the module's steps (`paddock-encrypt: …`). The init step takes seconds
  to a few minutes (a full `e2fsck` of the root file system and the move of 32 MiB); a laptop must be on mains power,
  otherwise the device boots unencrypted and the conversion fails with reason `on_battery`.
- **During the background phase** the device works as usual; restarts open the disk without input.
- **After the background phase** the device asks for one more restart. Under *TPM + boot PIN* that start shows the
  boot PIN dialogue on the text console; the user may skip it (Enter twice), and the device then asks again at every
  start. Until the PIN is chosen (or, under *TPM only*, until that restart) the portal shows that the disk is encrypted
  but not protected at rest: the key that unlocks it lies in the initrd on the unencrypted `/boot`.

## Background phase

The background encryption runs at the disk's sequential speed with idle I/O priority, typically 100–300 MB/s on a
device with AES-NI (about one hour per 500 GB). The device page shows the progress and the estimated time left. On
battery it pauses and resumes on mains power. A restart or a power cut costs nothing but the resume: the next boot
opens the partition with the key and the encryption continues where it stopped.

## Escrowed recovery keys

| Generation | Key | When it opens the disk |
| --- | --- | --- |
| 1 | The conversion key, stored at the preparation | From the restart until the device is `compliant`. |
| 2 | The recovery key enrolled after the background phase | From then on, like any recovery key. |

*Show recovery key* reveals the newest stored generation: generation 1 until generation 2 is stored.

## The device does not come back after the restart

When the initrd cannot open the partition (the journal of that boot says `paddock-encrypt: result failed open …`),
the boot stops in dracut's emergency shell: "Entering emergency mode … Press Enter for maintenance". Press Enter;
the shell opens without a password. Open the partition with the revealed recovery key of the conversion (*Show
recovery key*; generation 1 while the device has not reached `compliant`) under the device's mapping name and
continue the boot:

```sh
cryptsetup open /dev/disk/by-partuuid/<partuuid> dm_crypt-0    # type the revealed key at the prompt
lvm vgchange -ay                                               # lvm layout only: activate the volume group
exit
```

The PARTUUID is the one of the root partition (`ls -l /dev/disk/by-partuuid/` in the shell lists the partitions;
on the running device, `partition` in `/var/lib/paddock/state/state.json` names it). The device boots on dm-crypt and
the background encryption resumes. Alternatively, choose an older kernel under *Advanced options* in the GRUB menu:
until the conversion has finished, the initrd of every installed kernel carries the module and the key.

To reach that shell on purpose, for example when the init step itself misbehaves, add
`rd.systemd.unit=emergency.target` to the kernel command line in the GRUB menu (`e`). That shell starts without udev,
so start it first, open the partition as above and continue with `systemctl default` (the init step then finds the
mapping open and leaves it as it is; the boot continues after about 90 seconds, while systemd stops the emergency
shell):

```sh
systemctl start systemd-udevd.service systemd-udev-trigger.service && udevadm settle
cryptsetup open /dev/disk/by-partuuid/<partuuid> dm_crypt-0
lvm vgchange -ay                                               # lvm layout only
systemctl default
```

A kernel parameter `systemd.mask=paddock-encrypt-init.service` does **not** stop the init step: the initrd enables the
unit itself.

## Aborting at the device: `paddockd encrypt-abort`

Before the restart, an operator at the device can abandon a prepared conversion:

```sh
sudo paddockd encrypt-abort
```

The command asks the running agent to remove the module, rebuild the initrds and delete the conversion key and the
plan. Exit status 0: aborted; 2: refused (for example the device has restarted already and the disk is LUKS); 1: no
agent answered within 60 seconds, nothing was changed. The device reports `device.disk_conversion_aborted` with
`by: operator`. The portal's *Cancel encryption* does the same through a signed command at the next check-in.

## Aborting without a running agent

`paddockd encrypt-abort` only asks the agent. When no agent answers within 60 seconds, the command prints *no running
Paddock agent answered; nothing was changed* and exits with 1. Start the agent first if you can
(`sudo systemctl start paddock-supervisor`) and run `encrypt-abort` again. If the agent cannot run and the device must
not convert at its next restart, remove the module from the boot files by hand, in this order — the key and the plan
go last, because an initrd that still carries the module needs them at the next boot:

```sh
sudo rm -f /etc/dracut.conf.d/91-paddock-encrypt.conf
sudo rm -rf /usr/lib/dracut/modules.d/99paddock-encrypt
sudo dracut -f --regenerate-all
# every initrd must show 0 entries
for f in /boot/initrd.img-*; do echo "$f: $(sudo lsinitrd "$f" | grep -v '^Arguments:' | grep -c paddock-encrypt)"; done
# only when every initrd shows 0:
sudo rm -f /var/lib/paddock/install-passphrase /var/lib/paddock/encrypt/plan.env /var/lib/paddock/encrypt/plan.json \
  /var/lib/paddock/encrypt/test-hooks /etc/paddock/disk-setup.json /var/lib/paddock/disk-setup-pending
```

The device now restarts unencrypted. When the agent runs again it still reports the conversion `prepared`; cancel it
from the portal (*Cancel encryption*): the device confirms the abort, finishes its own clean-up and is eligible again.

## A cleanup that does not finish

After an abort or a failure before the restart the device removes the module from every initrd before it deletes the
conversion key and the plan. While an initrd still carries the module the device reports the preflight reason
`cleanup_pending` (with the reason of the last attempt as `cleanup_error`), keeps the key and the plan, and retries at
every check-in; meanwhile the device refuses an uninstall (`conversion_pending`): the command fails and the request
stays open until you cancel it (the removal's *Cancel request* on the device page). A restart in that state may still convert the disk through the
old initrd: the device then adopts the conversion (`device.disk_conversion_started`) and continues as if it had been
started normally. Typical causes and remedies:

- `dracut` fails (a broken configuration in `/etc/dracut.conf.d/`, a full `/boot`): fix it; the next check-in finishes
  the cleanup.
- An initrd the device cannot rebuild still carries the module (a foreign kernel's initrd, or one built by another
  tool): rebuild that initrd with the tool in use, or remove that kernel; the next check-in finishes the cleanup.

## Completing the encryption without the agent

Only when the agent is gone for good (it normally resumes the encryption itself after every restart): stop it, then
resume the reencryption with the revealed recovery key of the conversion (*Show recovery key* while the device is
encrypting reveals generation 1, the conversion key):

```sh
sudo systemctl stop paddock-supervisor
sudo systemctl stop paddock-encrypt-resume.service   # "not loaded" means the helper is not running
sudo sh -c 'umask 077; read -r k; printf %s "$k" > /run/key'   # paste the revealed key, Enter (no newline is stored)
sudo cryptsetup reencrypt --resume-only --key-file /run/key /dev/disk/by-partuuid/<partuuid>
sudo shred -u /run/key
```

`cryptsetup` finds the open mapping on its own ("Auto-detected active dm device") and shows the progress; Ctrl-C
interrupts it safely ("Reencryption interrupted") and the same command continues later. The partition's PARTUUID is
the one `lsblk -o NAME,FSTYPE,PARTUUID` shows next to `crypto_LUKS`. Afterwards the device still unlocks only with the
conversion key until a TPM keyslot and a regenerated initrd exist; reinstall the agent or enroll the device again so
that it finishes the setup.

## After the conversion: GRUB names the mapping

Once the root file system lies on the mapping, `update-grub` (run by every kernel update) writes
`root=/dev/mapper/dm_crypt-0` (the device's mapping name) into the boot entries instead of `root=UUID=…`. That is
expected: the initrd opens the partition under exactly that name.

## Removing Paddock during a conversion

Removing Paddock (*Uninstall*) is refused while the conversion is active: a requested, prepared or encrypting
conversion, a device whose health still reports `encrypting`, and a completed conversion until the device reports
`compliant` (until then the initrd carries the Paddock module and the conversion key, and the removal would delete
what the device needs to unlock its disk at the next start). Cancel a requested or prepared conversion first; an
encrypting device finishes on mains power; a completed one needs the boot PIN (the dialogue at the next start) so
that the agent can rebuild the initrd. When the agent is gone for another reason, complete the encryption by hand
(above).

## Lock and Destroy during a conversion

Lock and Destroy are never blocked. Before the restart the device is not encrypted and refuses them (`not_encrypted`).
During the background phase the agent stops the background encryption and hands the revocation over;
`paddock-revoke` erases every keyslot that holds a key. The reencryption keyslot holds none and stays in the header;
the confirmation reports `erased: true`, `slots_after: 0` and the remaining keyless slot as `other_slots_after: 1`
(plan M8e amendment item 23). The device no longer boots.
The header is not escrowed yet, so a Lock cannot be undone with a stored header, and the part the encryption has not
reached stays readable as plaintext (residual risk RR-57).

## Never run `cryptsetup reencrypt` by hand while the agent runs

The agent's helper owns the reencryption. A second `cryptsetup reencrypt` on the same device competes for the
header lock and confuses the progress and the completion. Use the manual completion only when the agent is gone.
