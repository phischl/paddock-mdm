# Disk encryption and recovery

Devices installed with the Paddock autoinstall (`autoinstall.md`) encrypt their disk with LUKS2. At every start
the disk unlocks with the TPM 2.0 and a **boot PIN**; a high-entropy **recovery key** and the **LUKS header** are
escrowed in Paddock (plan M4b, architecture §12.4). This runbook covers the boot PIN, the states the portal shows,
and how an organization administrator recovers a device.

## Boot PIN (first boot)

At the first boot, after the disk passphrase from the user-data, the device asks on the text console — before the
login screen — for the boot PIN, twice. It needs at least `boot_pin_min_length` characters (*Login & privileges →
Disk encryption*, default 8). The PIN is enrolled with `systemd-cryptenroll --tpm2-device=auto --tpm2-with-pin=yes
--tpm2-pcrs=7` and never leaves the device.

- **Skip:** pressing Enter twice without a PIN skips it. The device starts as usual, keeps the install passphrase
  and is reported `tpm_pin_missing`.
- **No TPM 2.0:** the device starts with the passphrase and is reported `tpm_missing`.
- If enrolling fails three times, the device starts without a PIN and asks again at the next start.

Then the agent (`luks` reconciler) enrolls a recovery key, escrows it, escrows the LUKS header, removes the install
passphrase keyslot, deletes `/var/lib/paddock/install-passphrase` and escrows the header again. A device with a
skipped PIN keeps its passphrase keyslot (otherwise only the recovery key would unlock it).

Once the root volume is escrowed, the agent escrows the header of every other LUKS1 or LUKS2 volume of
`/etc/crypttab` as well — the volumes `paddock-revoke` erases on a Lock — one per pass, each with its LUKS UUID. It
adds no recovery key to them and never changes their keyslots: their own passphrases or key files open them after a
header restore. Header generations count across all volumes of a device.

## States

The device page (*Disk encryption*) and the device list filter show the state of the last check-in:

| State | Meaning |
| --- | --- |
| `compliant` | Only TPM2+PIN and the recovery key unlock the root volume; the recovery key and the current header of every LUKS volume are escrowed. |
| `escrow_pending` | Being set up (recovery key or a header not escrowed yet, install passphrase still present), the keyslots of the root volume differ from TPM2+PIN and recovery key — for example after a keyslot was added locally —, or another volume's current header is not escrowed (also a volume whose LUKS UUID cannot be read). |
| `tpm_pin_missing` | The boot PIN was skipped; the disk keeps the install passphrase. |
| `unlock_mode_mismatch` | The root volume is enrolled for the other unlock mode than the device's policy (a `tpm2` keyslot under `tpm_pin`, or a `tpm2+pin` keyslot under `tpm_only`); see "Changing the unlock mode". |
| `tpm_missing` | The device has no TPM 2.0. |
| `unmanaged` | Encrypted, but not installed with the Paddock autoinstall (no in-place conversion). |
| `not_encrypted` | The root file system is not encrypted. |

The *Disk encryption* card lists every LUKS volume with its device, keyslots and whether its current header is
escrowed, and the `/etc/crypttab` entries the agent could not classify (for example `LABEL=` sources); those are not
escrowed and do not keep the device from being `compliant`.

The agent records the keyslots of every volume. Any other change — a keyslot added or removed outside Paddock — is
reported as `device.tamper_keyslot_changed` (the volume's LUKS UUID, keyslot kinds before and after), shown on the
device page, and that volume's header is escrowed again. The agent never wipes a keyslot it did not create.

## Changing the unlock mode

The unlock mode (*Login & privileges → Disk encryption → Disk unlock mode*, overridable per device group) is either
`tpm_pin` (TPM2 + boot PIN, the default) or `tpm_only` (the TPM alone while Secure Boot is unchanged; ADR 0038). The
autoinstall embeds the mode of the token's device group, else the organization's, in `/etc/paddock/disk-setup.json`:
a `tpm_only` device asks for no PIN at its first boot and enrolls `systemd-cryptenroll --tpm2-device=auto
--tpm2-pcrs=7` instead. A change of the setting applies to new installations only; the agent never enrolls or wipes a
TPM keyslot of an installed device. An installed device whose keyslots do not match its policy is reported
`unlock_mode_mismatch` (attention *Disk encryption not compliant*, detail `unlock_mode_mismatch`). An operator
converts it at the device with the recovery key (reveal it first, see below):

From TPM + PIN to TPM only:

```sh
systemd-cryptenroll --wipe-slot=tpm2 --tpm2-device=auto --tpm2-pcrs=7 /dev/<luks partition>
# asks for an existing key: type the recovery key
```

From TPM only to TPM + PIN:

```sh
systemd-cryptenroll --wipe-slot=tpm2 --tpm2-device=auto --tpm2-with-pin=yes --tpm2-pcrs=7 /dev/<luks partition>
# asks for an existing key (the recovery key), then twice for the new boot PIN
```

The agent reports the keyslot change as `device.tamper_keyslot_changed` (expected after a conversion), escrows the
header again and reports `compliant` with the keyslots of the new mode (`recovery` and `tpm2`, or `recovery` and
`tpm2+pin`). Check before the next reboot that the new keyslot exists (`cryptsetup luksDump`); the recovery key still
opens the disk if it does not.

## Recovering a device

Removing Paddock from a device (`docs/operations/uninstall.md`) never changes a keyslot, `/etc/crypttab` or the boot
loader: the PIN, the TPM and the recovery key keep unlocking the disk, and the escrowed recovery key and headers stay
revealable for the retired device.

Both actions need an organization administrator, a step-up (MFA within the last 5 minutes) and the device's
hostname typed as confirmation. Each is recorded once in the audit log (`disk.recovery_key_revealed`,
`disk.header_downloaded`, with the generation and, for a header, the volume, never the secret).

### Forgotten boot PIN: the recovery key

1. Portal → device → *Disk encryption* → *Show recovery key* (`POST /api/v1/devices/{id}/disk/recovery-key`). The
   key looks like `cbdefghi-…` (8 groups of 8 characters) and is hidden again after 60 seconds.
2. At the boot prompt **"Please enter LUKS2 token PIN"**, type the recovery key instead of the PIN and press Enter.
   The device first spends its TPM PIN attempts: **repeat the recovery key until the disk unlocks** (PoC M1: 3 or 4
   entries). Each wrong entry counts as a TPM authorization failure.
3. Set a new boot PIN on the device as root:
   `systemd-cryptenroll --wipe-slot=tpm2 --tpm2-device=auto --tpm2-with-pin=yes --tpm2-pcrs=7 <device>` (it asks
   for the recovery key to unlock). The agent reports the keyslot change and escrows the new header.

**TPM lockout.** After too many wrong entries the TPM refuses PIN attempts for a while (dictionary-attack
protection; on the emulated TPM of the test VMs 3 failures and 1000 seconds per failure). The recovery key still
works once the attempts are used up. The lockout survives reboots; it ends by itself, or an administrator with the
TPM's lockout authorization clears it (`tpm2_dictionarylockout --clear-lockout`).

**Firmware or Secure Boot updates.** The TPM token is bound to PCR 7 (Secure Boot state). After a change of the
Secure Boot databases (dbx update, firmware update, key enrollment) the TPM no longer releases the key, and the
device asks for the recovery key. Re-enroll TPM2+PIN as in step 3.

### Damaged header: restore from the escrow

1. Portal → *Download header of <device>* (`POST /api/v1/devices/{id}/disk/header`, optional `volume` — the LUKS
   UUID, default the root volume — and `generation` in the body; default the newest stored one). The file is
   `<hostname>-luks-header-<volume>-<generation>.img`; a root volume header escrowed before PDK-009 is
   `<hostname>-luks-header-<generation>.img` and counts as the root volume's.
2. Boot the device from a live system, identify the LUKS partition (`lsblk -f`, `cryptsetup luksUUID`), and restore:

   ```sh
   cryptsetup luksHeaderRestore /dev/<partition> --header-backup-file <hostname>-luks-header-<volume>-<generation>.img
   cryptsetup open --test-passphrase /dev/<partition>   # root: the recovery key; other volumes: their passphrase
   ```

   A header generation only contains the keyslots that existed when it was taken: the recovery key of a generation
   always opens it. Choose an older generation if the newest one was taken after a tampering you want to undo.

## Escrow storage

- Recovery keys are RSA-OAEP-encrypted to the OpenBao Transit key `escrow-wrap` and stored in PostgreSQL
  (`escrow_secret`, kind `luks_recovery_key`).
- Headers are compressed and encrypted on the device with AES-256-GCM under a random key, which is wrapped to
  `escrow-wrap`. The device uploads the sealed object with a presigned PUT (valid 10 minutes) to the bucket
  `paddock-escrow` under `org/<organization>/devices/<device>/luks-header/<volume UUID>/<generation>.bin`; the key
  is chosen by the server. Root volume headers escrowed before PDK-009 stay under
  `org/<organization>/devices/<device>/luks-header/<generation>.bin` (no copy); the database gives them the root
  volume's UUID with the device's first check-in that reports it (migration `00035`). The worker marks a generation
  `stored` once the object has the announced size and SHA-256 (it fails after 15 minutes without the object). A
  device escrows the headers of at most 32 volumes; a header of a 33rd is refused (`device.header_escrow_refused`,
  escrow status `refused`), shown as *header not escrowed* on the card, and not uploaded again for 24 hours unless
  the volumes of `/etc/crypttab` change. A volume with the LUKS UUID of another volume or of the root volume (a cloned
  header) is shown as sharing its UUID: it is not escrowed, and the device is not `compliant`.
- The bucket keeps every version and has no Object Lock, so a Destroy can delete it. Credentials: the gateway's
  bundles credential may only `s3:PutObject` below `org/*/devices/*/luks-header/*`; the worker and the api have
  read-only credentials (`PADDOCK_ESCROW_S3_*`). Only the `paddock-escrow-reader` role can unwrap the header key,
  after it verified the administrator's step-up itself (`docs/operations/escrow-reader.md`).

### Header object of another size

The presigned upload URL binds the size the device announced, so the object store refuses a header upload of any
other size. If an object of another size is in the bucket anyway, it was written outside the device's upload path
(for example with an administrative credential of the object store). The worker then checks only its size, never
reads it, marks the escrow generation `failed` and records `device.header_object_rejected` with the announced and
the stored size. The worker's credential is read-only, so the object stays in the bucket:

1. Find the event in the audit log (*Audit* → `device.header_object_rejected`) and note the device, the generation and
   the volume.
2. Examine the object with the object store's administrative credential, for example
   `aws s3api list-object-versions --bucket paddock-escrow --prefix org/<org>/devices/<device>/luks-header/`, and find
   out how it was written.
3. Remove it (`aws s3api delete-object --bucket paddock-escrow --key <key> --version-id <version>`) once it is no
   longer needed for the investigation. Until then, an escrow of the same generation can find this object before
   the device's own upload arrives and fail as well.
