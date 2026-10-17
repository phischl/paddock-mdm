# 0038 — Disk unlock mode as a policy, and in-place encryption of installed devices
Status: Accepted for the unlock mode (architect, 2026-10-17; plan `docs/plans/M8d-device-lifecycle.md`).
Proposed for in-place encryption: the approach is decided here, the implementation is deferred to its own
milestone (M8e) and gated as described below.

## Context

Plan M4b (architecture §12.4, decided 2026-10-05) encrypts devices installed with the Paddock autoinstall with
LUKS2 and enrolls **TPM2 + PIN** bound to PCR 7 at the first boot (`paddockd disk-setup`,
`systemd-cryptenroll --tpm2-device=auto --tpm2-with-pin=yes --tpm2-pcrs=7`), a recovery key, and escrows both.
The `luks` reconciler (`agent/internal/reconcile/luks.go`) treats exactly `{recovery, tpm2+pin}` as the compliant
keyslot set (`compliantKeyslots`), removes the install passphrase only once a `tpm2+pin` keyslot exists, and reports
`tpm_pin_missing` when the PIN was skipped. The organization setting `boot_pin_min_length`
(`organization_login_settings`, migration 00016) is embedded in the autoinstall (`/etc/paddock/disk-setup.json`).

Devices that were not installed with the autoinstall are `unmanaged` (encrypted otherwise) or `not_encrypted`;
architecture §12.4 says "no in-place conversion", and the portal shows the state without a way forward (lab finding
L31). Lab finding L30 asks for the unlock mode as a policy per device group: `tpm_only` (the disk unlocks without a
PIN, bound to Secure Boot through PCR 7) for shared or kiosk devices, `tpm_pin` for personal laptops, with the
default chosen in the setup wizard.

Facts that bound the design:

- The agent holds no unlock secret after the install passphrase is removed: the PIN never leaves the user's head
  and the recovery key is in memory only until the server stored it. Changing a TPM2 keyslot therefore needs either
  the install passphrase (first boot only) or a person with the PIN or the recovery key at the device.
- `systemd-cryptenroll --tpm2-device=auto --tpm2-pcrs=7` without `--tpm2-with-pin` enrolls a token that unlocks
  automatically while the Secure Boot state (PCR 7) is unchanged; the kernel command line is not measured into
  PCR 7, and Ubuntu's signed GRUB lets anyone edit it at boot unless a GRUB password is set.
- Ubuntu Desktop's default layout (no LUKS) is one ESP plus one ext4 root without a separate `/boot`; Ubuntu Server's
  default has a separate `/boot`. GRUB can read a LUKS2 root only with `GRUB_ENABLE_CRYPTODISK` and a passphrase typed
  at GRUB, which defeats a TPM unlock; a TPM unlock needs an unencrypted `/boot`. ext4 cannot be shrunk while
  mounted, and `cryptsetup reencrypt --encrypt` needs free space at the end of the device (`--reduce-device-size`)
  and must start with the device unmounted. In-place encryption of a running root file system is therefore an
  offline operation with partition changes on desktop layouts.

## Options

### A. Unlock mode

- **A1 — Keep TPM2 + PIN only.** − Shared devices and kiosks have nobody to type a PIN; the lab asked for the option.
- **A2 — Per-organization setting only.** − One organization mixes personal laptops and shared devices.
- **A3 — Organization default with an optional device-group override; applied at the first-boot disk setup (through
  the enrollment token's device group in the generated autoinstall) and checked by the `luks` reconciler against the
  bundle's `disk.unlock_mode` for enrolled devices; a device whose keyslots do not match its policy is reported, never
  converted by the agent (it has no unlock secret); the conversion is an operator step with the recovery key,
  documented in `disk-recovery.md`.** + Honest about what the agent can do; the policy still determines every new
  installation and the compliance picture; a mismatch is visible on the attention list. − Changing the mode of an
  installed fleet is manual work per device. **Chosen.** When groups disagree, `tpm_pin` wins (the stricter mode).

### B. In-place encryption

- **B1 — Online re-encryption by the agent (`cryptsetup reencrypt --encrypt` on the mounted root).** − Not possible
  for the initial encryption of a mounted ext4 root (shrink, header space); a power cut mid-way without a
  resumable, journaled state loses the device.
- **B2 — Never; reinstall only (status quo).** + Zero risk in Paddock. − A fleet adopted with M11 stays unencrypted
  until every device is reinstalled.
- **B3 — Offline conversion from a Paddock rescue system (the Paddock autoinstall ISO booted in "convert" mode, or a
  dracut/initramfs hook on the device that runs before the root file system is mounted), only for layouts with a
  separate unencrypted `/boot` (or where `/boot` can be carved out of free space without moving the root
  partition's start), with LUKS2 online-reencryption's resumable metadata, an explicit administrator trigger with
  typed confirmation and a declared backup, and VM gates that cut the power during the conversion and resume it.
  Everything else stays "reinstall needed".** + The only approach that can be made resumable and verifiable;
  bounded to layouts where the TPM unlock can work afterwards. − A milestone of its own: a rescue image or initramfs
  hook, partition logic, recovery-key escrow from the rescue environment, two VM layouts, power-cut gates.
  **Chosen as the approach; deferred to M8e.** M8d ships only the detection of the layout (`health.disk.boot_separate`)
  and the portal message that names the way forward.

## Decision

1. **Unlock modes** are `tpm_pin` (default) and `tpm_only`. Settings: `organization_login_settings.disk_unlock_mode`
   and `device_group.disk_unlock_mode` (nullable override; `tpm_pin` wins when a device's groups disagree). The
   autoinstall embeds the effective mode of the enrollment token's device group (else the organization's) in
   `/etc/paddock/disk-setup.json` as `unlock_mode`. `paddockd disk-setup` enrolls `tpm2+pin` with the console
   dialogue for `tpm_pin`, and `tpm2` without a dialogue for `tpm_only` (`systemd-cryptenroll --tpm2-device=auto
   --tpm2-pcrs=7`); skipping stays possible for `tpm_pin` only; an enrollment failure keeps the install passphrase and
   asks again at the next boot in both modes.
2. **Bundle and reconciler.** The optional top-level section `disk: {unlock_mode}` (schema v2) tells the `luks`
   reconciler the policy. The compliant keyslot set is `{recovery, tpm2+pin}` under `tpm_pin` and
   `{recovery, tpm2}` under `tpm_only`; the install passphrase is removed only once the keyslot of the policy's kind
   exists. A root volume that carries the TPM2 keyslot of the other mode is reported as the new disk state
   `unlock_mode_mismatch` (between `tpm_pin_missing` and `escrow_pending`); `tpm_pin_missing` keeps its name and now
   means "the TPM keyslot of the policy is not enrolled; the install passphrase remains". The agent never changes a
   TPM2 keyslot of an enrolled device. `health.disk.unlock_mode` reports the policy the agent applied.
3. **Security notice.** `tpm_only` protects data at rest against a removed disk only: with the device in hand the
   disk unlocks at boot and the login screen is the remaining barrier. The portal shows this notice at the setting,
   and `docs/compliance/residual-risks.md` records it (RR-44). `boot_pin_min_length` applies to `tpm_pin` only.
4. **In-place encryption** follows option B3 in milestone M8e with its own plan, ADR amendment and VM gates (power
   cut mid-way, resume, recovery-key escrow, Lock after conversion). Until then the portal says, for a
   `not_encrypted` device, "reinstall with the Paddock autoinstall needed" and, when the agent reports a separate
   `/boot`, that an in-place conversion is planned for such layouts. M8d adds `health.disk.boot_separate` (reported
   only for `not_encrypted` devices) and nothing that changes a disk.

## Consequences

+ New installations follow one policy per fleet segment; shared devices and kiosks can be encrypted without a PIN;
  the compliance picture names mismatches instead of hiding them; the dangerous conversion is designed, bounded and
  deferred instead of improvised.
− Changing the unlock mode of installed devices is manual (recovery key at the device, documented); `tpm_only`
  weakens protection against an attacker with the device (RR-44); unencrypted adopted devices stay so until M8e or a
  reinstall (RR-52).
Follow-ups: plan M8d PDK-231 to PDK-233; milestone M8e (in-place encryption); the setup wizard (M8g) chooses the
organization default; `docs/operations/disk-recovery.md` gains the mode conversion steps.

## Amendment 2026-10-17 (ADR 0039)

Decision 4 and option B3 are superseded by ADR 0039: the in-place encryption of M8e is not an offline conversion
from a rescue system but a LUKS2 online reencryption initialised by a dracut unit during one restart and completed
in the background (`cryptsetup reencrypt --encrypt --init-only --reduce-device-size 32M`, then `--resume-only`).
The verification of the facts in the context section above was repeated there: ext4 is shrunk offline in the
initrd, the free space at the end of the device comes from that shrink, and the keyslot operations of this ADR
(TPM2 + PIN or TPM2 per unlock mode, recovery key, header escrow) run unchanged once the reencryption has
completed — the PIN dialogue itself already runs at the conversion boot. The unlock mode decisions 1–3 and
`health.disk.boot_separate` stand. The portal message of decision 4 is replaced by the *Encrypt this device*
action for eligible devices and by the "reinstall needed" message with the reasons for the others.
