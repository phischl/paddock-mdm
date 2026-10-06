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

## States

The device page (*Disk encryption*) and the device list filter show the state of the last check-in:

| State | Meaning |
| --- | --- |
| `compliant` | Only TPM2+PIN and the recovery key unlock the disk; both the recovery key and the current header are escrowed. |
| `escrow_pending` | Being set up (recovery key or header not escrowed yet, install passphrase still present), or the keyslots differ from TPM2+PIN and recovery key — for example after a keyslot was added locally. |
| `tpm_pin_missing` | The boot PIN was skipped; the disk keeps the install passphrase. |
| `tpm_missing` | The device has no TPM 2.0. |
| `unmanaged` | Encrypted, but not installed with the Paddock autoinstall (no in-place conversion). |
| `not_encrypted` | The root file system is not encrypted. |

The agent records the keyslots it expects. Any other change — a keyslot added or removed outside Paddock — is
reported as `device.tamper_keyslot_changed` (keyslot kinds before and after), shown on the device page, and the
header is escrowed again. The agent never wipes a keyslot it did not create.

## Recovering a device

Both actions need an organization administrator, a step-up (MFA within the last 5 minutes) and the device's
hostname typed as confirmation. Each is recorded once in the audit log (`disk.recovery_key_revealed`,
`disk.header_downloaded`, with the generation, never the secret).

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

1. Portal → *Download header backup* (`POST /api/v1/devices/{id}/disk/header`, optional `generation` in the body;
   default the newest stored one). The file is `<hostname>-luks-header-<generation>.img`.
2. Boot the device from a live system, identify the LUKS partition (`lsblk -f`), and restore:

   ```sh
   cryptsetup luksHeaderRestore /dev/<partition> --header-backup-file <hostname>-luks-header-<generation>.img
   cryptsetup open --test-passphrase /dev/<partition>   # type the recovery key
   ```

   A header generation only contains the keyslots that existed when it was taken: the recovery key of a generation
   always opens it. Choose an older generation if the newest one was taken after a tampering you want to undo.

## Escrow storage

- Recovery keys are RSA-OAEP-encrypted to the OpenBao Transit key `escrow-wrap` and stored in PostgreSQL
  (`escrow_secret`, kind `luks_recovery_key`).
- Headers are compressed and encrypted on the device with AES-256-GCM under a random key, which is wrapped to
  `escrow-wrap`. The device uploads the sealed object with a presigned PUT (valid 10 minutes) to the bucket
  `paddock-escrow` under `org/<organization>/devices/<device>/luks-header/<generation>.bin`; the key is chosen by
  the server. The worker marks a generation `stored` once the object has the announced size and SHA-256 (it fails
  after 15 minutes without the object).
- The bucket keeps every version and has no Object Lock, so a Destroy can delete it. Credentials: the gateway's
  bundles credential may only `s3:PutObject` below `org/*/devices/*/luks-header/*`; the worker and the api have
  read-only credentials (`PADDOCK_ESCROW_S3_*`). Only the `paddock-escrow-reader` role can unwrap the header key,
  after it verified the administrator's step-up itself (`docs/operations/escrow-reader.md`).
