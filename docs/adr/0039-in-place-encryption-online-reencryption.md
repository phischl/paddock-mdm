# 0039 — In-place encryption of an installed device by LUKS2 online reencryption after one restart
Status: Accepted (architect, 2026-10-17; plan `docs/plans/M8e-in-place-encryption.md`). Replaces decision 4 (option
B3, "offline conversion from a rescue system") of ADR 0038.

## Context

Lab finding L31: a device that was installed without encryption shall be encrypted later from the portal,
comparable to BitLocker and FileVault. ADR 0038 bounded the problem (a TPM unlock needs an unencrypted `/boot`;
ext4 cannot be shrunk while mounted; `cryptsetup reencrypt --encrypt` needs free space at the end of the device)
and chose an offline conversion from a rescue system, deferred to M8e. The maintainer's direction for M8e
(ticket PDK-240) is a shorter offline window: one restart during which an early-boot step shrinks the file system
and initialises the LUKS2 header, then the bulk encryption in the background while the user works, resumable
after a power cut. This ADR records the verification of that direction and the decisions it leads to.

### What was verified (sources, 2026-10-17)

| Claim | Source |
| --- | --- |
| `cryptsetup reencrypt --encrypt --init-only --reduce-device-size 32m <device> <name>` initialises in-place encryption and activates `<name>` at once ("not yet encrypted"); `cryptsetup reencrypt --resume-only <device>` or `--active-name <name>` resumes it online. | `man/cryptsetup-reencrypt.8.adoc`, cryptsetup v2.7.0, section EXAMPLES, "LUKS2 ENCRYPTION EXAMPLES" 3 and 4. |
| LUKS2 reencryption runs online on an active mapping; with a device argument cryptsetup detects the mapping and takes the online path. The last 32 MiB of the plaintext device must be unused. | same page, DESCRIPTION and example 1. |
| "Recommended minimal size is twice the default LUKS2 header size (--reduce-device-size 32M) for encryption mode." The data-shift resilience is implied by `--reduce-device-size` and cannot be changed afterwards. | `man/common_options.adoc`, v2.7.0, `--reduce-device-size`, `--resilience`. |
| `--init-only` fails when a reencryption is already initialised; `--resume-only` fails when none is. `--uuid` sets the UUID of the new header in encryption mode. | `man/common_options.adoc`, v2.7.0. |
| Encryption and decryption need "a short offline window, because the kernel cannot add or remove the dm-crypt layer while the device is online"; the header carries the requirement `online-reencrypt` while the operation is unfinished; an interrupted operation is recovered on the next activation (`open`) or by `repair`, and continues only when `reencrypt` is run again. A full backup is advised. | `docs/v2.2.0-ReleaseNotes` (LUKS2 online reencryption), cryptsetup repository tag v2.7.0; `cryptsetup-reencrypt.8.adoc` "Interrupted reencryption". |
| SIGINT and SIGTERM interrupt a reencryption safely, "including when systemd stops the system". | `cryptsetup-reencrypt.8.adoc`, v2.7.0. |
| Resuming reads the passphrase once (`tools_get_key`, `--key-file`) and passes `--key-slot` (default: any slot) to `crypt_reencrypt_init_by_passphrase`; the restriction "Key file can be used only with --key-slot or with exactly one key slot active" lives in `reencrypt_luks2_init` (volume-key change of an existing LUKS2 device), not in the encrypt or resume paths. `--init-only` with a name activates through `crypt_activate_by_passphrase`. | `src/utils_reencrypt.c`, cryptsetup v2.7.0 (`reencrypt_luks2_load`, `fill_keyslot_passwords`, `encrypt_luks2_init`). |
| libcryptsetup refuses, during a reencryption, only `crypt_set_data_device` ("Illegal operation with reencryption in-progress") and the activation while the reencryption lock is held; `crypt_keyslot_add_by_keyslot_context` (used by `systemd-cryptenroll`), `crypt_keyslot_destroy` and `crypt_header_backup` carry no reencryption check. | `lib/setup.c`, cryptsetup v2.7.0. |
| While a reencryption is unfinished the LUKS2 metadata holds a keyslot `"type": "reencrypt"` (mode, direction, resilience area); it cannot be unlocked and disappears when the operation finishes. | `lib/luks2/luks2_keyslot_reenc.c`, cryptsetup v2.7.0 (`reenc_keyslot`). |
| `--progress-json` prints one JSON line per interval with `device`, `device_bytes`, `device_size`, `speed`, `eta_ms`, `time_ms` (numbers as strings). | `man/common_options.adoc`, v2.7.0. |
| Ubuntu 24.04 (noble): cryptsetup 2:2.7.0-1ubuntu4.2, systemd 255.4-1ubuntu8.18, dracut 060+5-1ubuntu3.4 (`Conflicts: initramfs-tools`, `Provides: linux-initramfs-tool`), initramfs-tools 0.142ubuntu25.8, e2fsprogs 1.47.0-2.4~exp1ubuntu4.1, lvm2 2.03.16-3ubuntu3.2. Ubuntu 26.04 (resolute): cryptsetup 2:2.8.4-1ubuntu4, systemd 259.5-0ubuntu3.4, dracut 110-11ubuntu0.1, e2fsprogs 1.47.2-3ubuntu4, lvm2 2.03.31-2ubuntu3. | Launchpad API `getPublishedSources` (pockets Release/Updates/Security); `apt-cache show dracut` on Ubuntu 24.04.5. |
| `systemd-cryptenroll` works on LUKS2 only; `--unlock-key-file` since v252, `--tpm2-with-pin` since v251, `--recovery-key` since v248. | `man/systemd-cryptenroll.xml`, systemd v255. |
| `resize2fs` shrinks an unmounted file system only; online resizing is growing only. `pvresize --setphysicalvolumesize` "will refuse to shrink a PV if it has allocated extents beyond the new end". XFS: "Only shrinking the last AG without removing it is implemented". | man pages resize2fs(8), pvresize(8), xfs_growfs(8). |
| Subiquity's guided `lvm` layout always creates a separate ext4 `/boot` (`guided_lvm`: `FileSystemSpec(fstype="ext4", mount="/boot")`); the guided `direct` layout creates only the root partition. The `lvm` layout sizes the root LV by `sizing-policy` (`scaled` default: half of the VG between 20 and 200 GiB; `all`). | `subiquity/server/controllers/storage.py` (main); Subiquity autoinstall reference, "storage". |
| Dracut hook order: cmdline, pre-udev, pre-trigger, udev trigger, main loop (initqueue, initqueue/settled, initqueue/finished), pre-mount, mount, pre-pivot, cleanup; modules install hooks with `inst_hook` and files with `inst_simple`/`inst_multiple`. | dracut.modules(7). |
| Desktop notification from root to a user's session: GNOME Shell 46 serves `org.freedesktop.Notifications` (`Notify susssasa{sv}i`) on the user bus `/run/user/<uid>/bus` (socket mode 0666 in a 0700 runtime directory); `busctl` and `systemd-run` ship in the `systemd` package; `systemd-stdio-bridge`, which `busctl --machine=<user>@.host` needs, is not installed on Ubuntu Desktop 24.04. | `busctl --user introspect org.freedesktop.Notifications …` and `GetServerInformation` (`"gnome-shell" "GNOME" "46.0" "1.2"`), `dpkg -S` on Ubuntu 24.04.5; busctl(1) v255 `--machine=`. |

Corrections to the ticket's direction:

1. **Not an initramfs-tools hook.** Ubuntu 24.04's initramfs-tools cannot unlock systemd TPM2 tokens (plan M4b,
   PoC M1 C7); the autoinstall already replaces it with dracut on 24.04 (`user-data.24.04.yaml.tmpl`), and 26.04
   ships dracut. The early-boot step is therefore a **dracut module**, and a 24.04 device switches to dracut
   before the restart, exactly as the autoinstall and the system gate `PrepareDisk` do today.
2. **The first data shift is part of the init step, not of the background phase.** The datashift mode moves data
   during initialisation and activation; the recommended `--reduce-device-size` is 32 MiB. The file system is
   shrunk by 64 MiB (margin for the LVM extent and `pe_start` rounding), never by "a few MB".
3. **The PIN can be enrolled during the reencryption.** libcryptsetup does not refuse keyslot additions while a
   reencryption is unfinished, so the existing first-boot dialogue (`paddock-disk-setup.service`) runs at the
   conversion boot; the user restarts once. A header escrow during the reencryption is pointless (the metadata
   changes with every hot zone), so Paddock escrows the header only after completion.

## Options

- **C1 — Rescue system (ADR 0038 option B3).** + Everything offline, simplest crash model. − A second boot medium
  or a long initramfs run with the device unusable for hours; a laptop user cannot work; the lab asked for the
  BitLocker experience.
- **C2 — Online reencryption after one restart (this ADR).** The agent prepares everything on the running system
  (preflight, recovery-key escrow, dracut module, initrd). At the next restart a dracut unit, before `sysroot` is
  mounted, shrinks the root file system by 64 MiB, initialises LUKS2 in place (`--init-only
  --reduce-device-size 32M`, UUID chosen in advance) and activates the mapping; the system boots on dm-crypt, the
  user chooses the boot PIN in the known dialogue, and the agent's helper encrypts the rest in the background,
  resumable after any interruption. + Minutes of downtime, no second medium, the existing M4b flow takes over after
  completion, every step is idempotent and verified by `cryptsetup` itself. − A dracut module, an initrd with the
  conversion key on the unencrypted `/boot` until the TPM keyslot exists, a shrink step that is not crash-safe for
  a few seconds, and two throwaway VMs for the gates. **Chosen.**
- **C3 — Fully online with a detached header on `/boot`.** `cryptsetup reencrypt --encrypt --header <file>` needs
  no device shrink, but the mounted root still cannot get a dm-crypt layer underneath (release notes v2.2.0), the
  header on `/boot` must be kept in sync with every escrow and `systemd-cryptenroll`, and a lost `/boot` loses
  the disk. − Rejected.
- **C4 — Reinstall only (status quo, ADR 0038 B2).** − Rejected by the maintainer (L31).

## Decision

1. **Approach C2.** In-place encryption is a signed device command `encrypt_disk` (lifetime 7 days) issued by an
   organization administrator with a step-up, a typed hostname, a reason and an explicit backup acknowledgement.
   Paddock never starts it on its own initiative; no bundle field triggers it.
2. **Supported layouts** (reported by the agent as `health.disk.conversion.eligible` with reasons): UEFI boot
   (`/sys/firmware/efi` present), TPM 2.0 present, Ubuntu 24.04 or 26.04, a separate `/boot` on its own
   partition, root file system ext4 with at least 1 GiB free, root either (`lvm`) a logical volume in a volume
   group with exactly one physical volume on one GPT partition whose last extents are free or belong to the root
   LV, or (`plain`) ext4 directly on one GPT partition; `/etc/fstab` and the kernel command line refer to root by
   `UUID=` or by the LV's mapper path. Everything else — no separate `/boot`, xfs, btrfs, ZFS, md RAID, several
   physical volumes, BIOS boot, no TPM, already encrypted (`unmanaged`) — stays "reinstall needed".
3. **Preconditions enforced twice.** On the server at the request (device `active`, last health `not_encrypted`
   and `eligible`, no open conversion, uninstall or revocation request; `backup_confirmed` true) and on the device
   before anything changes (the same preflight again, dracut available, the escrow of the conversion key
   `stored`). The init step additionally requires mains power when the device reports a battery, and is skipped
   fail safe — the device boots unencrypted and reports — when any check fails.
4. **Escrow before the first byte.** The agent generates the conversion key (256 bit, the `systemd-cryptenroll`
   recovery-key format: 8 groups of 8 modhex characters) as the install passphrase of the device
   (`/var/lib/paddock/install-passphrase`), uploads it as escrow kind `luks_recovery_key` generation 1 for the
   LUKS UUID chosen in advance, and builds the initrd only once the server reports `stored`. The portal's *Show
   recovery key* reveals it from then on; after the conversion the existing M4b flow enrolls a systemd recovery
   key (generation 2), TPM2 + PIN or TPM2 per the unlock mode of the device's bundle (ADR 0038), escrows the
   header and removes the conversion key's keyslot.
5. **Dracut module `99paddock-encrypt`**, embedded in `paddockd` and written out at preparation: a systemd unit in
   the initrd, ordered after udev's coldplug and before `initrd-root-device.target`, `sysroot.mount` and
   `cryptsetup.target`, runs an idempotent POSIX shell script with the plan (`/etc/paddock/encrypt-plan.env`) and
   the conversion key (`/etc/paddock/encrypt-key`, 0600) from the initrd: mains check, `e2fsck -f`, `resize2fs`
   (and `lvreduce`, `pvresize`, `vgchange -an` for `lvm`), `cryptsetup reencrypt --encrypt --type luks2 --init-only
   --reduce-device-size 32M --uuid <uuid> --key-file … --batch-mode <partition> <mapping>`, reactivation of the
   volume group, and the result in `/run/paddock/encrypt-boot.env` for the agent. A partition that already carries
   the LUKS header is only opened (cryptsetup recovers an interrupted operation at activation). The module and
   the key leave the initrd when the agent regenerates it after the TPM keyslot exists; `/etc/crypttab` gets the
   same line the autoinstall produces (`<mapping> UUID=<uuid> none luks,tpm2-device=auto`).
6. **Background phase.** `paddockd encrypt-resume`, started by the agent in a transient unit outside the
   supervisor's cgroup after every boot while the header carries a `reencrypt` keyslot, runs `cryptsetup
   reencrypt --resume-only --batch-mode --key-file <install passphrase> --progress-json --progress-frequency 5
   <partition>` with lowered CPU and I/O priority, writes the progress to `/var/lib/paddock/encrypt/progress.json`,
   stops the operation with SIGTERM when mains power is lost and resumes it when it returns. The agent reports the
   progress in `health.disk.conversion` and the phase changes as events (`disk.conversion_prepared`,
   `disk.conversion_started`, `disk.conversion_completed`, `disk.conversion_failed`); a new disk state
   `encrypting` sits between `not_encrypted` and `unmanaged`. The `luks` reconciler changes no keyslot and escrows
   no header while the `reencrypt` keyslot exists.
7. **Server and portal.** Table `device_disk_conversion` (one row per request, phases `requested → prepared →
   encrypting → completed | failed | cancelled`), endpoints `POST /api/v1/devices/{id}/encrypt` and
   `…/encrypt/cancel` (step-up; cancels the undelivered command, or — once the device received the command —
   issues the signed command `encrypt_disk_abort`, which the agent executes only while it is still preparing or
   `prepared`, never after the restart), the conversion in `GET /devices/{id}` and `…/disk`, the *Encrypt this
   device* dialogue with the checklist and the typed hostname, a progress panel on the disk card, attention kind
   `disk_conversion_failed`. Audit codes `device.encrypt_requested`, `device.encrypt_cancelled`,
   `device.disk_conversion_prepared`, `device.disk_conversion_started`, `device.disk_conversion_completed`,
   `device.disk_conversion_failed`, `device.disk_conversion_aborted`. `paddockd encrypt-abort` at the device
   stays for the operator (maintainer decision 2026-10-17).
9. **Restart notification (maintainer decision 2026-10-17).** While a conversion is `prepared`, the agent shows a
   desktop notification to every graphical user session on the device ("Disk encryption is ready — please
   restart"), at the start of every new graphical session and every 4 hours per session; it never restarts the
   device. Mechanism: a transient unit as the session's user (`systemd-run --uid=<uid> --gid=<gid>
   --setenv=XDG_RUNTIME_DIR=/run/user/<uid> …`) runs `busctl --user call org.freedesktop.Notifications
   /org/freedesktop/Notifications org.freedesktop.Notifications Notify …` on the user bus — only tools of the
   `systemd` package, no `libnotify-bin`, no `--machine=` (needs `systemd-stdio-bridge`, absent on Ubuntu
   Desktop). Without a graphical session nothing is shown; a failure is logged, never reported as an event.
8. **Gates.** Two throwaway VMs installed unencrypted from the stock ISOs (26.04 `lvm` layout, 24.04 plain root
   with a separate `/boot`), the full flow on each, a hard power-off during the background reencryption, and hard
   power-offs during the init step at the two stage boundaries the dev-only kernel parameter
   `paddock.encrypt.testdelay=<stage>:<seconds>` exposes (after the shrink before the LUKS init; after the init
   before the reactivation). Every gate ends `compliant` with the keyslot set of the device's unlock mode, the
   conversion key no longer opening the disk and the escrowed recovery key opening it.

## Consequences

+ An adopted fleet can be encrypted from the portal with minutes of downtime per device; the user is told on
  the desktop to restart and an administrator can still cancel from the portal until the restart; the result is
  indistinguishable from an autoinstalled device (same unlock stack, keyslots, escrows, runbooks); every step is
  idempotent and the failure modes are reported.
− The shrink is not crash-safe for seconds (RR-56); the conversion key lies in the initrd on the unencrypted
  `/boot` until the agent regenerates the initrd after the TPM keyslot exists (minutes after the PIN dialogue), and
  the data is partly plaintext until the reencryption completes; until then an attacker with the device reads the
  key from `/boot` or the unencrypted remainder from the partition (RR-57);
  24.04 devices switch irreversibly from initramfs-tools to dracut and lose the Plymouth splash (RR-58); a laptop
  that is only ever on battery never completes (RR-59); unsupported layouts stay unencrypted (RR-61).
Follow-ups: plan M8e, tickets PDK-241 … PDK-248; architecture §12.4 amendment; ADR 0038 decision 4 superseded.

## Amendment 2026-10-20 — initramfs generator, executable paths, interplay with the device lifecycle

Decided by the architect on 2026-10-20 while refreshing plan M8e against `main` at `727fb7c5` (plan M8e §14); the
decisions above stand, three are made precise:

1. **Decision 5, the generator (correction 1 made precise).** The early-boot step stays a dracut module; a device
   that does not have dracut installed (`dpkg-query`, the one source of truth for the detection and the switch)
   switches to it at preparation whatever its release — Ubuntu 24.04, and a 26.04 upgraded in place that kept
   initramfs-tools. The agent simulates the installation (`apt-get -s install dracut`) in its preflight and again
   before the switch, reports the simulated removal set in `health.disk.conversion.initramfs_removes` so that the
   portal's dialogue names what leaves (initramfs-tools, and `brltty` — the console braille support), refuses the
   conversion (`failed`, stage `prepare`, reason `dracut_removes:<packages>`) when anything but `initramfs-tools`,
   `initramfs-tools-core`, `initramfs-tools-bin` and `brltty` would be removed, and fails the preparation when
   what really left differs from the simulation (`dracut_removed_differs:<packages>`); extending the list is an
   architect decision. Architecture open question O4 ("no in-place switch on existing 24.04 devices") is
   superseded by this bounded switch.
2. **Decisions 5 and 6, where executables live (lesson of ADR 0037 amendment 2026-10-19).** Nothing of the
   conversion executes from `/run`, `/tmp`, `/var/tmp`, `/dev/shm` or `/var/lib/paddock`: the init script runs
   from inside the initramfs, the dracut module from `/usr/lib/dracut/modules.d/`, the background helper from the
   agent's slot `/opt/paddock/agent/current/paddockd`, the notification through the system's `busctl`;
   `/run/paddock/encrypt-boot.env` and the files below `/var/lib/paddock/encrypt/` are data. Before the agent
   starts the helper's transient unit it checks the slot directory with `statfs` (`ST_NOEXEC`) as the uninstall
   does, and reports `helper_not_running` instead of launching when the check fails.
3. **Decision 7, the lifecycle (ADR 0037 mirrored).** A conversion is *active* while its row is `requested`,
   `prepared` or `encrypting`, while the device's last health reports `disk.state = encrypting` (a server-side
   `failed` after a resume failure never hides a reencryption the device still carries), or while the row is
   `completed` and the device is not yet `compliant` (the reencryption may finish before the user chose the boot
   PIN; the initrd with the Paddock module and the conversion key is then the only unlock path). Until the agent
   has regenerated the initrd without the module it keeps the conversion key's keyslot and runs the regeneration
   also after `completed`. Three boot-path invariants bind every rule (plan M8e §14.10, with the state × event
   table a reviewer walks): I1 — while the root partition is LUKS and the initrd was not regenerated, nothing
   removes the module, its configuration, the plan, the key or the conversion keyslot, and every initrd build
   keeps the module; the module leaves only together with a crypttab line that unlocks through the TPM, verified
   on every installed initrd. I2 — the disk decides the phase, for a device that holds a conversion and only then: a LUKS root with the
   conversion keyslot or an unfinished reencryption is adopted as `encrypting`, whatever a state file, a queued
   preparation or a boot result says, and a module a cleanup had removed is reinstalled before anything else.
   I3 — a cleanup after an abandoned conversion removes the module first, regenerates, and counts as done only
   when the initrd of no installed kernel carries the module; the key and the plan are deleted only after that
   check, so that a device which converts through a stale initrd meanwhile is adopted, not lost; until then the
   cleanup is retried, the device is not eligible again and not removable. A user who skips the boot PIN on a converted
   device is asked again at every start (never blocked); until the PIN exists the key lies on the unencrypted
   `/boot`, which the device reports (`key_on_boot`), the portal shows and RR-57 records. Removing Paddock is
   refused while a conversion is active — on the server (409) and on
   the device (`conversion_pending` while the agent holds a conversion whose initrd was not regenerated yet, except
   one that failed on a still unencrypted disk, or while the root volume carries a `reencrypt` keyslot): the
   removal would purge the plan and the conversion key such a device needs to open its root volume. No
   supervisor upgrade starts while the device prepares, and the preparation waits while a supervisor upgrade runs
   (bounded by the 30 minutes after which the agent counts the upgrade as failed). Lock, Destroy and Retire are
   never blocked by a conversion: they withdraw an undelivered `encrypt_disk` command and record it on their own
   audit event; a prepared or running conversion is left alone on the server, the device refuses a Lock or Destroy
   while unencrypted, and the dialogues warn that a Lock during `encrypting` erases a header that is not escrowed.
   Before the agent hands a revocation to `paddock-revoke` it records the hand-over, stops the background
   encryption unit (bounded; the hand-over proceeds when the bound runs out — the Lock always wins) and does not
   restart the unit for 24 hours; the revocation path's code is unchanged (two-person rule), and the expected result of
   a Lock on a reencrypting header — every keyslot erased, the `reencrypt` keyslot counted like any other — is
   verified once by hand before the milestone closes; a deviation stops the milestone and is an architect decision.

Consequences: + the switch to dracut is bounded and visible; the conversion cannot be broken by a `noexec` mount,
by a removal of Paddock or by the device's other lifecycle actions; the two-person rule's path stays untouched.
− Paddock cannot be removed from a device until its conversion completed or was cancelled; a Lock during
`encrypting` is unrestorable (RR-57).
