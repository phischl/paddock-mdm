# Installing devices with the Paddock autoinstall

The Paddock autoinstall installs Ubuntu Desktop 24.04 or 26.04 with full-disk encryption, the Paddock agent and
everything the device needs to enroll itself (plan M4b, architecture §12.4). The disk ends up unlocked by TPM2 and
a boot PIN, with a high-entropy recovery key and the LUKS header escrowed in Paddock.

## Generate the user-data

1. Create an enrollment token (portal *Enrollment tokens*, or `POST /api/v1/enrollment-tokens`) and keep the
   enrollment configuration it shows once.
2. Generate the user-data for one device (organization administrators and operators):

   ```sh
   curl -sS -X POST https://admin.<domain>/api/v1/autoinstall \
     -H 'Content-Type: application/json' -H 'X-Paddock-CSRF: 1' --cookie <portal session> \
     -d '{"enrollment_config": <the configuration>, "release": "26.04", "hostname": "laptop-0042",
          "locale": "en_US.UTF-8", "keyboard_layout": "us", "timezone": "Europe/Berlin"}' > user-data
   ```

   The answer is `text/yaml`. Every call creates a new random disk passphrase; nothing is stored on the server.
   The audit log records `autoinstall.generated` with the release and the agent version, never the passphrase or
   the token. Errors: 404 `not_found` (the configuration is not one of your organization), 422 `token_revoked`,
   `token_expired`, `token_exhausted`, 409 `invalid_state` (no published agent release has both Debian packages —
   see `agent-releases.md`).

**The user-data is a secret**: it contains the temporary disk passphrase and the enrollment token. Store it only as
long as the installation needs it.

What it does:

- LVM inside LUKS2 with a random temporary passphrase of 32 alphanumeric characters.
- The installer account `paddock-install` with a locked password, hidden from the login screen. The managed local
  administrator (`local-admin.md`) becomes the device's administrator.
- Downloads `paddock-supervisor` and `paddock-agent` of the newest published agent release from
  `https://bundles.<domain>/packages/…` and refuses them unless their SHA-256 matches the values in the user-data.
  The device must be able to reach that host during the installation.
- Writes `/etc/paddock/enroll.json` (0600), `/var/lib/paddock/install-passphrase` (0600),
  `/etc/paddock/disk-setup.json` (the organization's `boot_pin_min_length`, *Login & privileges → Disk
  encryption*, default 8) and the marker `/var/lib/paddock/disk-setup-pending`.
- Adds `tpm2-device=auto` to the LUKS entry in `/etc/crypttab` and rebuilds the initramfs. On 24.04 it first
  replaces initramfs-tools by dracut with `/etc/dracut.conf.d/90-paddock-tpm2.conf` (`hostonly="yes"`,
  `add_dracutmodules+=" systemd crypt tpm2-tss lvm "`); the PIN prompt there is a text prompt (no Plymouth).
- Powers the device off when it is done.

## Install

Put the user-data on the installation medium as `/autoinstall.yaml` (or serve it as cloud-init user-data) and add
`autoinstall` to the kernel command line, or confirm the autoinstall prompt of the installer. The device needs
UEFI with Secure Boot and a TPM 2.0.

## First boot

1. **Disk passphrase:** the disk asks for its passphrase once. Type the value of `storage.layout.password` from the
   user-data.
2. **Boot PIN:** before the login screen appears, the device asks on the text console for the boot PIN (twice). See
   `disk-recovery.md` for how it is enrolled, what skipping means, and how a forgotten PIN is recovered.
3. The agent enrolls the device with `/etc/paddock/enroll.json` (and deletes it), creates a recovery key, escrows
   the recovery key and the LUKS header, and then removes the temporary passphrase. From the next boot on, the
   device asks only for the boot PIN.
