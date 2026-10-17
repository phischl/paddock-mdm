# Implementierungsplan: M8e — In-place encryption of an installed device (LUKS2 online reencryption after one restart)

Status: Ready for implementation after M8d · 2026-10-17 · Author: architect
Basis: ADR 0039 (in-place encryption by LUKS2 online reencryption; supersedes ADR 0038 decision 4); ADR 0038
(unlock modes, `health.disk.boot_separate`); ADR 0037 (signed command with cancel before delivery, transient units
outside the supervisor's cgroup); ADR 0013 (additive protocol changes); ADR 0018 (lists and dialogs); ADR 0024 (no
event type an older server could receive from a newer agent); ADR 0028 (per-device derivations on read paths);
plans M4b (disk encryption, first-boot disk setup, escrow), M4b.1 (keyslot rules), M8d (§3.8 uninstall command
pattern, §3.9 unlock mode, §3.10); lab finding L31; ticket PDK-240.

Binding language: **MUST** / **MUST NOT** / **SHOULD** / **MAY**.

This plan is written against the M8d branch (`origin/M8d-device-lifecycle`, PR #79) and assumes PDK-231, PDK-232
and PDK-233 (unlock mode, `boot_separate`, the deferred message) are merged before PDK-242 starts. §11 names what
to do when they are not.

## 1. Goal

After M8e an organization administrator encrypts an adopted, unencrypted Ubuntu device from the portal: after a
step-up, a typed hostname and a backup acknowledgement, the device prepares itself, the recovery key is escrowed
before a single byte is encrypted, the user restarts the device once and chooses the boot PIN (or none, under
`tpm_only`), and the remaining encryption runs in the background while the user works — resumable after a power
cut, with the progress visible on the device page. The result is a device that is indistinguishable from one
installed with the Paddock autoinstall: `compliant`, TPM2 + PIN or TPM2 plus a recovery key, header escrowed.
Paddock never starts the conversion on its own initiative.

## 2. Context (verified in the code on 2026-10-17, M8d branch at `968b03b`; upstream sources in ADR 0039)

- **Disk reconciler.** `agent/internal/reconcile/luks.go`: `LUKS.Tick(ctx, keys, full)` → `pass()` →
  `luks.Root` (`findmnt` + `lsblk --inverse`; `ErrNotEncrypted` → state `not_encrypted`), `luks.Dump`
  (`cryptsetup luksDump --dump-json-metadata`), `md.Kinds()` (a keyslot without a token is `password`), the
  `disk-setup-pending` marker (`Layout.DiskSetupPending()`) suppresses steps, `step()` enrolls the recovery key
  while the install passphrase (`Layout.InstallPassphrase()` = `/var/lib/paddock/install-passphrase`, written
  without a trailing newline) exists, escrows the header, removes the install passphrase once the keyslot of the
  unlock mode exists (M8d decision 48). `luks.Tools` runs only `findmnt`, `lsblk`, `cryptsetup`,
  `systemd-cryptenroll` (`agent/internal/luks/os.go`, 2-minute timeout). `luks.Metadata.Keyslots` is
  `map[string]json.RawMessage`; the keyslot `type` is not read today.
- **First-boot disk setup.** `packaging/systemd/paddock-disk-setup.service` (`ConditionPathExists=
  /var/lib/paddock/disk-setup-pending`, `After=cryptsetup.target local-fs.target`, `Before=display-manager.service
  getty@tty1.service paddock-supervisor.service`, tty1) runs `paddockd disk-setup` (`agent/internal/disksetup`):
  reads `/etc/paddock/disk-setup.json` (`boot_pin_min_length`, M8d: `unlock_mode`), asks the PIN twice, enrolls
  with `luks.EnrollTPM2PIN` (`systemd-cryptenroll --tpm2-device=auto --tpm2-with-pin=yes --tpm2-pcrs=7
  --unlock-key-file=<install passphrase>`), removes the marker.
- **Escrow from the device.** `reconcile.LUKSEscrow{Upload, UploadHeader, Status}` implemented by
  `agent.escrowClient`; `escrow.Encrypt(pub, secret)` with the bundle's `keys.escrow_wrap`; kinds
  `luks_recovery_key`, `luks_header`; status `pending | stored | failed | refused`; the server's `Escrow.Store`
  (`app/escrow.go`) enforces generations per kind (`LatestEscrowGeneration`). `app/disk.go::RevealRecoveryKey`
  reveals the newest stored `luks_recovery_key`.
- **Autoinstall on 24.04** (`server/internal/autoinstall/templates/user-data.24.04.yaml.tmpl`): `apt-get install
  -y dracut`, `/etc/dracut.conf.d/90-paddock-tpm2.conf` = `hostonly="yes"` + `add_dracutmodules+=" systemd crypt
  tpm2-tss lvm "`, `sed` adds `,tpm2-device=auto` to the LUKS line of `/etc/crypttab`, `dracut -f
  --regenerate-all`. The system gate helper `test/system/disk.go::PrepareDisk` does the same on the 24.04 VM.
  Ubuntu 26.04 ships dracut.
- **Commands.** `pkg/command` (closed registry `lifetimes`, `Verify`), the agent's handlers map in
  `agent/internal/agent/agent.go:New`, `commands.Handler` returns `succeeded | failed | Deferred`; M8d decision 35–39
  (`uninstall`: `UninstallAccepted{accepted, reason}`, the plan file and the transient unit launched after
  `postResults`), decision 38 (cancel before delivery: command `cancelled`, `ListCancelledDeviceCommands`,
  `cache.DeleteCommand`). The in-process background worker pattern: `agent/internal/agent/osupdates.go`
  (`installJobs`, `runInstalls`).
- **Health.** `health.Report.Disk *protocol.DiskHealth`; `protocol.DiskStates` (closed, ordered); the server keeps
  the whole health JSON in `device_status.health` and derives `disk_state` on read (`queries/device.sql`);
  `app.diskHealth` rejects an unknown state; the attention view `attention_condition` (last recreated by migration
  00042) lists `disk_not_compliant` for state ≠ `compliant`.
- **Events.** `pkg/protocol.EventTypes` (closed); `app/devicereports.go::eventCodes`, `eventEntry`;
  `audit.deviceEventParams` allow list (`codes.go:175`).
- **Bundle.** M8d decision 46: `bundle.DiskSpec{UnlockMode}` (schema v2) from `EffectiveUnlockMode`.
- **Portal.** `components/DiskEncryptionCard.vue` (state, volumes, reveal/download after step-up; PDK-233 adds the
  `notEncrypted.*` alerts), `lib/disk.ts`, `lib/status.ts::encryptionStatus`, `lib/deviceDetailPage.ts`
  (`startStepUp`/`resumeStepUp` pattern), `components/ConfirmDialog.vue` (`requireTypedText`), M8d's
  `UninstallDialog.vue` pattern.
- **Gates.** `test/system/autoinstall.go::buildAIVM` (throwaway VM from an ISO, EFI + Secure Boot + TPM 2.0, name
  and SSH port are constants `aiVMName`, `aiSSHPort`), `test/vms/virtualbox/autoinstall/autoinstall.yaml.tmpl` (the
  test VMs' user-data: `storage.layout.name: lvm` with a LUKS password, SSH access), `VM.PowerOff`, `Shot`,
  `RebootWithPIN`, `AnswerDiskSetup`, `Keyslots`, `Opens`, `Device.WaitDisk`, `WaitEvent`, `Health`.
- **Migrations.** Last on `main`: 00048; M8d adds eight (`<next>` numbering). M8e continues after them.

## 3. Binding decisions

### 3.1 Vocabulary

- **Conversion**: one in-place encryption of one device, from the request to `completed`, `failed` or
  `cancelled`. **Conversion key**: the random passphrase of the first LUKS keyslot; it is the device's install
  passphrase from then on. **Init step**: what the dracut unit does at the conversion boot. **Background phase**:
  the reencryption by `paddockd encrypt-resume`. **Layouts**: `lvm` (root LV in one VG on one PV on one partition)
  and `plain` (ext4 directly on one partition).
- Phases of a conversion (server and agent use the same words): `requested` (command issued, not delivered),
  `prepared` (escrow stored, initrd built, waiting for the restart), `encrypting` (the init step succeeded, the
  background phase runs or is paused), `completed`, `failed`, `cancelled`.

### 3.2 Eligibility and preflight (agent; PDK-242)

1. New package `agent/internal/encrypt` with

   ```go
   // Preflight reports whether the device's disk can be encrypted in place (ADR 0039 decision 2). It reads the layout
   // with findmnt, lsblk and lvm only and changes nothing.
   func Preflight(ctx context.Context, sys System, root string) Layout
   // Layout is the result of a preflight; Reasons is empty when Eligible.
   type Layout struct {
       Eligible  bool
       Reasons   []string // closed set below, sorted
       Kind      string   // "lvm" | "plain" | "" when not eligible for a layout reason
       Partition string   // /dev/disk/by-partuuid/<uuid> of the root partition (the future LUKS device)
       PartUUID  string
       VG, LV    string   // lvm only
       FSUUID    string   // the ext4 UUID of the root file system
       Release   string   // VERSION_ID of /etc/os-release
       PartitionBytes, FSBytes, FSFreeBytes int64
   }
   ```

   `System` is a small interface in the package (`Command(ctx, name, args...) (stdout, stderr string, exit int,
   err error)`, `ReadFile(path) ([]byte, error)`, `Stat(path) (bool, error)`), implemented by `encrypt.OS` for the
   tools `findmnt`, `lsblk`, `blkid`, `lvm`, `blockdev`, `dumpe2fs`, `systemctl`, `dracut`, `lsinitrd`, `apt-get`,
   `udevadm`, `systemd-run`, `cryptsetup`, `nice` (2-minute timeout except where a decision names another). Tests
   fake it.
2. Reasons (closed set; the agent reports every failing one, sorted): `release_unsupported` (VERSION_ID not
   `24.04` or `26.04`), `no_uefi` (`/sys/firmware/efi` absent), `no_tpm2` (`luks.TPM2Present` false),
   `no_separate_boot` (`findmnt --noheadings --output TARGET --target /boot` ≠ `/boot`, or `/boot` is not on its own
   partition of type `part`), `boot_on_root_device` (`/boot`'s partition is the root partition), `root_not_ext4`
   (`findmnt -no FSTYPE /` ≠ `ext4`), `root_layout_unsupported` (the `lsblk --inverse --json --paths --output
   NAME,TYPE,FSTYPE,PKNAME,PARTUUID,SIZE` chain of `/` is neither `lvm → part → disk` with exactly one PV in the VG
   (`lvm pvs --noheadings -o pv_name,vg_name`) nor `part → disk`; raid, crypt, loop, several PVs, partition tables
   other than GPT (`blkid -p -o value -s PTTYPE <disk>` ≠ `gpt`)), `pv_tail_in_use` (lvm only: the last allocated
   extent segment of the PV (`lvm pvs --segments --noheadings --units b -o pv_name,pvseg_start,pvseg_size,lv_name`)
   belongs to an LV other than the root LV), `low_free_space` (`findmnt -bno AVAIL /` < 1 GiB),
   `root_reference_unsupported` (`findmnt --fstab -no SOURCE /` is neither `UUID=<fs uuid>` nor
   `/dev/mapper/<vg>-<lv>` nor `/dev/<vg>/<lv>`, or `root=` on `/proc/cmdline` is neither `UUID=<fs uuid>` nor one
   of those paths), `already_encrypted` (the `luks` reconciler's state is not `not_encrypted`), `dm_crypt_missing`
   (`/sys/module/dm_crypt` absent and `modprobe dm_crypt` fails; checked at preparation only, decision 7).
3. `protocol.DiskHealth` gains `Conversion *DiskConversion json:"conversion,omitempty"`:

   ```go
   // DiskConversion is the in-place encryption of the root volume in health.disk (ADR 0039): the eligibility of an
   // unencrypted device and, from the preparation on, the phase and the progress.
   type DiskConversion struct {
       Eligible     bool       `json:"eligible"`
       Reasons      []string   `json:"reasons,omitempty"`
       Release      string     `json:"release,omitempty"`       // VERSION_ID of /etc/os-release (24.04 or 26.04)
       Layout       string     `json:"layout,omitempty"`        // lvm | plain
       Phase        string     `json:"phase,omitempty"`         // prepared | encrypting | completed | failed
       DataBytes    int64      `json:"data_bytes,omitempty"`    // bytes to encrypt (the partition minus the header)
       DoneBytes    int64      `json:"done_bytes,omitempty"`
       ETASeconds   int64      `json:"eta_s,omitempty"`
       PausedReason string     `json:"paused_reason,omitempty"` // on_battery | helper_not_running
       FailureStage string     `json:"failure_stage,omitempty"` // preflight | prepare | init | resume
       FailureReason string    `json:"failure_reason,omitempty"`
       UpdatedAt    *time.Time `json:"updated_at,omitempty"`
   }
   ```

   `protocol.DiskStates` gains `DiskEncrypting = "encrypting"` directly after `DiskNotEncrypted`. The `luks`
   reconciler's `pass()`:
   - in state `not_encrypted` it sets `Conversion` from `encrypt.Preflight` (run at most once per 10 minutes and
     on every full pass that follows a bundle change; the result is cached in the reconciler) and from the
     conversion state of decision 9 (`prepared` or a `failed` whose stage is `preflight`, `prepare` or `init`);
   - when `luks.Dump` succeeds and `md.Reencrypting()` (decision 4) is true, it reports state `encrypting` with
     `Tokens` = `md.Kinds()` (the `reencrypt` keyslot excluded), `Conversion` from `encrypt.Progress` (decision 14)
     and returns before `watch`, `step` and `volumes`: no keyslot is recorded, changed, escrowed or reported as
     tampering while the reencryption is unfinished;
   - after completion the existing flow continues unchanged (`watch` records the keyslots it sees first, the
     install passphrase is the conversion key, `step` enrolls the recovery key, escrows the header, removes the
     conversion key's keyslot once the keyslot of the unlock mode exists).
4. `luks.Metadata` learns the keyslot type: `kind()` returns `KindReencrypt = "reencrypt"` for a keyslot whose JSON
   `type` is `reencrypt`; `Kinds()` and `Slots()` exclude that kind; `func (m Metadata) Reencrypting() bool` reports
   whether one exists. `Inspect` (other volumes) is unchanged.

### 3.3 Trigger (server; PDK-241)

5. `pkg/command`: `TypeEncryptDisk = "encrypt_disk"`, lifetime 7 days, with

   ```go
   // EncryptDiskParams are the params of encrypt_disk (ADR 0039 decision 1). The device takes the unlock mode and
   // the boot PIN length from its bundle, never from the command.
   type EncryptDiskParams struct {
       ConversionID string `json:"conversion_id"`
   }
   // EncryptDiskAccepted is the command result the agent posts when it starts the preparation, or the refusal.
   type EncryptDiskAccepted struct {
       Accepted bool     `json:"accepted"`
       Reason   string   `json:"reason,omitempty"`  // invalid_params, revocation_pending, uninstall_pending, not_eligible
       Reasons  []string `json:"reasons,omitempty"` // the preflight reasons for not_eligible
   }
   ```

6. Migration `disk_conversion` (next free number after M8d's):

   ```sql
   CREATE TABLE device_disk_conversion (
     id uuid PRIMARY KEY, organization_id uuid NOT NULL, device_id uuid NOT NULL,
     command_id uuid NOT NULL REFERENCES device_command (id),
     requested_at timestamptz NOT NULL DEFAULT now(), requested_by uuid, reason text NOT NULL,
     phase text NOT NULL CHECK (phase IN ('requested','prepared','encrypting','completed','failed','cancelled')),
     layout text CHECK (layout IN ('lvm','plain')), luks_uuid uuid, data_bytes bigint,
     failure_stage text, failure_reason text, phase_at timestamptz NOT NULL DEFAULT now(), finished_at timestamptz,
     FOREIGN KEY (organization_id, device_id) REFERENCES device (organization_id, id)
   );
   CREATE INDEX device_disk_conversion_device_idx ON device_disk_conversion (organization_id, device_id, requested_at DESC);
   CREATE UNIQUE INDEX device_disk_conversion_open_idx ON device_disk_conversion (device_id)
     WHERE phase IN ('requested','prepared','encrypting');
   -- ENABLE and FORCE ROW LEVEL SECURITY; policy on current_setting('paddock.org_id')::uuid; paddock_api SELECT,
   -- INSERT, UPDATE; paddock_worker SELECT, UPDATE (the event claim).
   ```

   The attention view is recreated with

   ```sql
   UNION ALL
   SELECT 'disk_conversion_failed', d.id, d.hostname, c.phase_at, coalesce(c.failure_stage, '') || ':' || coalesce(c.failure_reason, '')
   FROM device_disk_conversion c JOIN device d ON d.id = c.device_id
   WHERE d.state = 'active' AND c.phase = 'failed'
     AND c.id = (SELECT id FROM device_disk_conversion WHERE device_id = d.id ORDER BY requested_at DESC LIMIT 1)
   ```

   (severity `warn`; the entry disappears with the next request or when the device becomes `compliant`,
   because the device's last conversion row is then `completed` — a `failed` row stays until a new request
   replaces it as the latest).
7. `POST /api/v1/devices/{id}/encrypt` (tag `devices`, `x-paddock-audit: device.encrypt_requested`, body
   `DeviceEncryptRequest{confirm_hostname (required), reason (required, 2–500), backup_confirmed (boolean,
   required)}`, 200 `Device`, 403 `step_up_required|forbidden`, 404, 409 `invalid_state`, 422 `invalid_request`):
   `app.DiskConversions.Request(ctx, deviceID, in DiskConversionInput)` (new `app/diskconversion.go`),
   `ActionSpec{AllowedRoles: RolesAdmin, RequiresStepUp: true}`, target the device, params `hostname`, `reason`,
   `backup_confirmed`, `command_id`, `conversion_id`:
   - locks the device; state `active` else 409 `invalid_state` (detail `only active devices can be encrypted`);
   - `confirm_hostname` equals the hostname else 422 `invalid_request` (detail `confirm_hostname does not match`);
     `backup_confirmed` false → 422 (detail `backup_confirmed must be true`);
   - the last health must report `disk.state = not_encrypted` and `disk.conversion.eligible = true` else 409
     `invalid_state` (detail `the device does not report an eligible disk layout`; the reasons joined with `, `
     when present);
   - an open conversion (`phase IN ('requested','prepared','encrypting')`) → 409 (detail `a conversion is already
     open`); an open uninstall (M8d decision 37) → 409 (detail `an uninstall is pending`); an open revocation
     request → 409 (detail `a lock or destroy is pending for this device`);
   - inserts the row (`phase = requested`, `id = uuidv7`) and issues the command (`issueCommand`, type
     `encrypt_disk`, params `{conversion_id}`).
8. `POST /api/v1/devices/{id}/encrypt/cancel` (`x-paddock-audit: device.encrypt_cancelled`, `RolesAdmin`, no
   step-up, 200 `Device`, 404, 409 `invalid_state`): allowed while the latest conversion is `requested` and its
   command's status is `pending`, `failed` or `expired` (409 detail `the device already received the command`
   otherwise, `no conversion is open` without one); sets the command `cancelled` (as M8d decision 38, same cache
   removal) and the row `cancelled` (`finished_at = now()`). Params `hostname`, `command_id`, `conversion_id`.
9. Device events (`pkg/protocol`, closed set gains four; each carries `conversion_id`):

   ```go
   EventDiskConversionPrepared  = "disk.conversion_prepared"  // data: {conversion_id, layout, volume, data_bytes}
   EventDiskConversionStarted   = "disk.conversion_started"   // data: {conversion_id, volume, init_s}
   EventDiskConversionCompleted = "disk.conversion_completed" // data: {conversion_id, volume, data_bytes, duration_s}
   EventDiskConversionFailed    = "disk.conversion_failed"    // data: {conversion_id, stage, reason, volume}
   ```

   `eventCodes` maps them to `device.disk_conversion_prepared | _started | _completed | _failed`;
   `audit.deviceEventParams` gains `conversion_id`, `layout`, `data_bytes`, `duration_s`, `init_s`. The claim of
   `eventEntry` updates the row named by `conversion_id` (query `UpdateDiskConversionPhase`): `prepared` sets
   `layout`, `luks_uuid`, `data_bytes`; `started` sets `encrypting`; `completed` sets `completed` and `finished_at`;
   `failed` sets `failed`, `failure_stage`, `failure_reason`, `finished_at`. An event for a row of another device
   or an unknown row is recorded as an audit event and changes no row. The command result `{accepted: false}` sets
   the row `failed` with stage `preflight` and the result's reason (in the existing command-result path of
   `app/commands.go`, keyed on the command id). A `failed` row with stage `preflight`, `prepare` or `init` leaves
   the device unencrypted; a new request is possible at once.
10. `Device` (API) gains `disk_conversion` (nullable `DeviceDiskConversion{id, phase, requested_at, command_id,
    command_status, layout, luks_uuid, data_bytes, done_bytes, eta_s, paused_reason, progress_at, failure_stage,
    failure_reason, finished_at, reason}`): the latest row, with `done_bytes`, `eta_s`, `paused_reason`,
    `progress_at` read from `device_status.health → disk → conversion` on read (ADR 0028) when the row is
    `encrypting`. `DiskEncryption` (`GET /devices/{id}/disk`) gains the same object as `conversion`. `DiskState`
    (`DiskHealth` in the admin and device contracts) gains `conversion` (`DiskConversionHealth`) and the enum
    value `encrypting`. The device list filter `disk_state` accepts `encrypting`.
11. `pkg/bundle.DiskSpec` gains `BootPINMinLength int json:"boot_pin_min_length,omitempty"`; the compiler sets it
    from `organization_login_settings.boot_pin_min_length` on every v2 bundle (part of `ContentSHA256`).

### 3.4 Preparation (agent; PDK-243)

12. Command handler `agent/internal/agent/encrypt.go::encryptDiskCommand`: validates the params (`conversion_id`
    must be a UUID → else `failed {accepted: false, reason: invalid_params}`); refuses with `revocation_pending`
    while a revocation envelope was handed to `paddock-revoke` within 24 h (`state.HandedRevocations`), with
    `uninstall_pending` while `state.PendingUninstall` is set, with `not_eligible` and the reasons when
    `encrypt.Preflight` fails or the reconciler's state is not `not_encrypted`; otherwise it stores
    `state.Conversion = &state.DiskConversion{ID, CommandID, Phase: "preparing", RequestedAt}` (new state struct,
    §6.3), queues the preparation on the agent's conversion worker (one goroutine, the `installJobs` pattern:
    channel `conversionJobs`, capacity 1) and returns `succeeded {accepted: true}`.
13. `encrypt.Prepare(ctx, deps)` runs the steps below in order; every step is idempotent (a restarted agent with
    `Phase: "preparing"` queues the job again at start-up and the steps skip what exists); a failing step sets
    `state.Conversion.Phase = "failed"`, `FailureStage = "prepare"`, `FailureReason` (the closed reasons below or
    the first line of the tool's stderr, cut at 200 runes) and emits `disk.conversion_failed`:
    1. Preflight again (decision 2) → reason `not_eligible:<reasons>`.
    2. Choose the LUKS UUID (random v4) and the mapping name: `dm_crypt-0`, or `dm_crypt-<n>` with the smallest
       `n` whose `/dev/mapper/<name>` does not exist; write `/var/lib/paddock/encrypt/plan.json` (0600, §6.3) with
       the layout, the targets (decision 16) and `BootPINMinLength`/`UnlockMode` copied from the applied bundle's
       `Disk` (defaults 8 and `tpm_pin` when absent).
    3. Conversion key: when `/var/lib/paddock/install-passphrase` does not exist, generate 32 random bytes,
       encode them as 64 modhex characters in 8 groups of 8 joined with `-` (the `systemd-cryptenroll`
       recovery-key alphabet `cbdefghijklnrtuv`, so that the portal and the runbook treat it like a recovery key),
       and write it there (0600, no trailing newline). When the file exists and
       `state.Conversion.KeyEscrowGeneration > 0`, skip.
    4. Escrow: `escrow.Encrypt(pub, key)` with the bundle's escrow key, `Escrow.Upload(escrow.Request{EscrowID,
       Kind: luks_recovery_key, Generation: state.LUKS.RecoveryAttempted + 1, Volume: <luks uuid>, KeyVersion,
       Ciphertext})`, then poll `Status` every 30 s for at most 15 min (the reconciler's constants). On `stored`:
       `state.LUKS.RecoveryAttempted = state.LUKS.RecoveryStored = generation`,
       `state.Conversion.KeyEscrowGeneration = generation`. On `failed`, `refused` or timeout → reason
       `escrow_not_stored` (the key file is shredded; the next attempt generates a new key). The server stores the
       key like any recovery key; *Show recovery key* reveals it from then on.
    5. `/etc/paddock/disk-setup.json` = `{"boot_pin_min_length": n, "unlock_mode": "<mode>"}` from the plan;
       `touch /var/lib/paddock/disk-setup-pending`.
    6. Dracut: on 24.04 when `dpkg-query -W dracut` fails, `apt-get install -y dracut` with
       `DEBIAN_FRONTEND=noninteractive`, bounded 15 min, killed with its process group (the `DpkgWithin` path of
       `reconcile.OS`); failure → reason `dracut_install_failed`. Then write
       `/etc/dracut.conf.d/90-paddock-tpm2.conf` with exactly the three lines of the autoinstall template when the
       file is absent.
    7. Module: write the embedded files (§6.4) to `/usr/lib/dracut/modules.d/99paddock-encrypt/` (0755 directory,
       scripts 0755, unit 0644), `/etc/dracut.conf.d/91-paddock-encrypt.conf` = `add_dracutmodules+=" paddock-encrypt "`,
       the plan as `/var/lib/paddock/encrypt/plan.env` (0600, §6.3, the shell form of `plan.json`).
    8. `dracut -f --regenerate-all` (bounded 15 min; stdout and stderr to the journal); then for the running kernel
       `lsinitrd /boot/initrd.img-$(uname -r)` must list `etc/paddock/encrypt-plan.env`, `etc/paddock/encrypt-key`,
       `usr/lib/systemd/system/paddock-encrypt-init.service` and the binaries `cryptsetup`, `e2fsck`, `resize2fs`
       (and `lvm` for `lvm`); otherwise reason `initrd_incomplete`. `chmod 0600` every `/boot/initrd.img-*`.
    9. `state.Conversion.Phase = "prepared"`, `PreparedAt = now`; emit `disk.conversion_prepared{conversion_id,
       layout, volume: <luks uuid>, data_bytes}` where `data_bytes = PartitionBytes − 32 MiB`.
    The preparation never writes `/etc/crypttab`, `/etc/fstab`, the GRUB configuration or the kernel command line.
14. `paddockd encrypt-abort` (new subcommand, root only, for the operator at the device while the phase is
    `prepared` and the device has not restarted): removes `91-paddock-encrypt.conf` and the module directory,
    `/var/lib/paddock/encrypt/`, the conversion key and the two disk-setup files, runs `dracut -f
    --regenerate-all`, sets `state.Conversion.Phase = "failed"`, `FailureStage = "prepare"`, `FailureReason =
    "aborted"` and emits `disk.conversion_failed` through the running agent's spool (the subcommand writes the
    event with the next `event_seq` into the spool file under the agent's lock, as `paddockd uninstall` does in
    M8d decision 40 step 10). It refuses in any other phase (exit 2, message on stderr).

### 3.5 The init step (dracut module; PDK-244)

15. Module `99paddock-encrypt` (files embedded in `paddockd`, `agent/internal/encrypt/dracut/`, §6.4):
    `module-setup.sh` (`check()` returns 0 only when `/var/lib/paddock/encrypt/plan.env` exists on the host,
    so that the module is a no-op in every other initrd build; `depends()` echoes `systemd crypt` and, when the plan
    says `lvm`, `lvm`; `install()`: `inst_multiple cryptsetup e2fsck resize2fs blockdev udevadm` plus `lvm` for
    `lvm`; `inst_simple /var/lib/paddock/encrypt/plan.env /etc/paddock/encrypt-plan.env`; `inst_simple
    /var/lib/paddock/install-passphrase /etc/paddock/encrypt-key`; `inst_simple "$moddir/paddock-encrypt-init.sh"
    /usr/libexec/paddock/encrypt-init.sh`; `inst_simple "$moddir/paddock-encrypt-init.service"
    "$systemdsystemunitdir/paddock-encrypt-init.service"`; `$SYSTEMCTL -q --root "$initdir" enable
    paddock-encrypt-init.service`; when the host file `/var/lib/paddock/encrypt/test-hooks` exists (dev builds
    only, decision 19) `inst_simple` it as `/etc/paddock/encrypt-test`).
16. The unit and the script (binding content in §6.4). The script's stages, each skipped when its result is
    already there:
    1. Wait up to 60 s (`udevadm settle`, then poll) for `/dev/disk/by-partuuid/$PADDOCK_PART_UUID`; absent →
       `result failed init device_missing` (the boot goes on; without the partition nothing can be mounted anyway).
    2. Mains: when any `/sys/class/power_supply/*/type` is `Battery` and no supply of type `Mains` has `online`
       = `1` → `result skipped init on_battery` and exit 0 (the boot continues unencrypted; the agent reports the
       failure with stage `init`, reason `on_battery`, and the conversion is `failed` — a new request is needed,
       decision 9).
    3. Already LUKS (`cryptsetup isLuks "$dev"`): log `paddock-encrypt: header found, opening`; `cryptsetup open
       --key-file /etc/paddock/encrypt-key "$dev" "$PADDOCK_MAPPING"` (cryptsetup recovers an interrupted
       reencryption at activation), then for `lvm` `lvm vgchange -ay "$PADDOCK_VG"`; `result ok open`; exit 0. Failure → `result failed open <stderr line>`;
       exit 0 (the boot ends in dracut's emergency shell because root is missing; the runbook's recovery applies).
    4. Shrink (`lvm`): `lvm vgchange -ay "$PADDOCK_VG"`; `e2fsck -f -y "/dev/$PADDOCK_VG/$PADDOCK_LV"` (exit 0 or 1
       accepted; else `result failed init fsck_<exit>`, `lvm vgchange -an`, exit 0); when `blockdev --getsize64` of
       the LV > `$PADDOCK_FS_TARGET_BYTES`: `resize2fs "/dev/$PADDOCK_VG/$PADDOCK_LV" "${PADDOCK_FS_TARGET_SECTORS}s"`
       then `lvm lvreduce -f -L "${PADDOCK_FS_TARGET_BYTES}b" "/dev/$PADDOCK_VG/$PADDOCK_LV"`; when the PV size
       (`lvm pvs --noheadings --units b -o pv_size "$dev"`) > `$PADDOCK_PV_TARGET_BYTES`: `lvm pvresize -y
       --setphysicalvolumesize "${PADDOCK_PV_TARGET_BYTES}b" "$dev"`; `lvm vgchange -an "$PADDOCK_VG"` (failure →
       `result failed init vg_busy`, `lvm vgchange -ay`, exit 0). Shrink (`plain`): `e2fsck -f -y "$dev"` (as
       above), then `resize2fs "$dev" "${PADDOCK_FS_TARGET_SECTORS}s"` when the file system (`dumpe2fs -h`: block
       count × block size) is larger than the target. A skipped resize logs `paddock-encrypt: file system already
       at target`; the stage ends with the log line `paddock-encrypt: shrink done` in every case.
    5. Test hook `init` (decision 19). Init: `cryptsetup reencrypt --encrypt --type luks2 --init-only
       --reduce-device-size 32M --uuid "$PADDOCK_LUKS_UUID" --key-file /etc/paddock/encrypt-key --batch-mode
       "$dev" "$PADDOCK_MAPPING"`. Failure → `result failed init luks_init_<exit>`; for `lvm` `lvm vgchange -ay`;
       exit 0 (when the header was not written, the device boots unencrypted; otherwise the emergency shell and
       the runbook). Success logs `paddock-encrypt: init done`.
    6. Test hook `open` (decision 19). `udevadm settle`; `lvm vgchange -ay "$PADDOCK_VG"` for `lvm`; the root
       device (`/dev/$PADDOCK_VG/$PADDOCK_LV` or `/dev/disk/by-uuid/$PADDOCK_FS_UUID`) must exist within 30 s →
       `result ok init <seconds>`; else `result failed init root_missing`.
    `result` writes `/run/paddock/encrypt-boot.env` (`PADDOCK_BOOT_STATUS=ok|failed|skipped`,
    `PADDOCK_BOOT_STAGE=…`, `PADDOCK_BOOT_REASON=…`, `PADDOCK_BOOT_SECONDS=…`); `/run` survives the switch to the
    real root. The script writes nothing else outside the partition it converts, never touches `/boot`, the ESP or
    any other block device, and logs every command it runs (without the key) to the journal.
17. Targets computed by the agent at preparation (bytes; `P` = `blockdev --getsize64` of the partition, `PE` =
    4 MiB, the VG's extent size read from `lvm vgs --noheadings --units b -o vg_extent_size`):
    `PADDOCK_PV_TARGET_BYTES = P − 32 MiB`; for `lvm`, when the PV's last allocated segment belongs to the root LV,
    `PADDOCK_FS_TARGET_BYTES = LVsize − 16 × PE` (64 MiB at 4 MiB extents), else `LVsize` (nothing to shrink);
    for `plain`, `PADDOCK_FS_TARGET_BYTES = P − 64 MiB`. `PADDOCK_FS_TARGET_SECTORS = FS_TARGET_BYTES / 512`.
    `data_bytes = P − 32 MiB`.

### 3.6 After the conversion boot and the background phase (agent; PDK-245)

18. At every start the agent reads `/run/paddock/encrypt-boot.env` when `state.Conversion` is `prepared` or
    `encrypting` and the file exists (and removes it afterwards):
    - `ok`: when the phase was `prepared`, set `encrypting`, `StartedAt = now`, emit `disk.conversion_started
      {conversion_id, volume, init_s}`; then decision 20 (initrd regeneration) and decision 21 (resume).
    - `failed` or `skipped`: set `failed`, stage `init`, the reason; emit `disk.conversion_failed`; remove the
      module conf and directory, the plan files and (only when the partition is not LUKS) the conversion key and
      the disk-setup files; `dracut -f --regenerate-all`. When the partition *is* LUKS (a failure after the init),
      the phase is `encrypting` nonetheless once the agent finds `md.Reencrypting()` true — the device booted on
      dm-crypt, and decision 21 continues.
    Without the file (the device booted from an initrd without the module, or the user has not restarted yet), a
    `prepared` conversion stays `prepared`; an `encrypting` one continues with decision 21.
19. Dev-only test hooks: the embedded script honours `paddock.encrypt.testdelay=<stage>:<seconds>` on the kernel
    command line (`init`: sleep after the line `shrink done`, before stage 5; `open`: sleep after the line `init
    done`, before stage 6; the `isLuks` path of stage 3 never sleeps) only when `/etc/paddock/encrypt-test` exists in
    the initrd; the agent writes `/var/lib/paddock/encrypt/test-hooks` at preparation only when
    `buildinfo.Dev` is set (the `paddock_dev` tag). A release build never installs the marker; `make agent-release`
    and `make release-packages` refuse the tag as they do today.
20. Initrd regeneration after the keyslot of the unlock mode exists (checked at every full pass while
    `state.Conversion.Phase == "encrypting"` and `!state.Conversion.InitrdRegenerated`): when `luks.Dump` shows a
    `tpm2+pin` or `tpm2` keyslot, the agent appends `<mapping> UUID=<luks uuid> none luks,tpm2-device=auto` to
    `/etc/crypttab` (unless a line with that UUID exists), removes `91-paddock-encrypt.conf` and
    `/usr/lib/dracut/modules.d/99paddock-encrypt/`, runs `dracut -f --regenerate-all` (15 min bound) and verifies
    with `lsinitrd` that the running kernel's initrd contains `etc/crypttab` with the UUID and no
    `paddock-encrypt`; then `InitrdRegenerated = true`. A failure is logged and retried at the next full pass; the
    device keeps booting with the module (the keyfile opens the disk) until it succeeds. The conversion key stays
    on disk until the `luks` reconciler removes it after completion (decision 3).
21. Background phase: `paddockd encrypt-resume` (new `agent/internal/encrypt/resume.go`, root only, runs inside
    the transient unit `paddock-encrypt-resume.service` started by the agent with `systemd-run --unit
    paddock-encrypt-resume --collect --no-block --property=KillMode=mixed --property=Nice=10
    --property=IOSchedulingClass=idle /opt/paddock/agent/current/paddockd encrypt-resume`) whenever the phase is
    `encrypting`, `md.Reencrypting()` is true and `systemctl is-active paddock-encrypt-resume.service` is not
    `active` (checked at every full pass; a launch failure is logged and retried). The helper:
    1. Reads the plan and the partition; verifies `cryptsetup isLuks` and the `reencrypt` keyslot; exits 0 at once
       when the reencryption is already complete.
    2. Loop: when the device has a battery and no mains supply is online, writes `progress.json` with
       `paused_reason: on_battery` and waits (poll every 30 s); else runs `cryptsetup reencrypt --resume-only
       --batch-mode --key-file /var/lib/paddock/install-passphrase --progress-json --progress-frequency 5
       <partition>`, parses every JSON line (`device_bytes`, `device_size`, `speed`, `eta_ms`) and writes
       `/var/lib/paddock/encrypt/progress.json` atomically (§6.3) at most every 5 s; when mains power is lost it
       sends SIGTERM to cryptsetup (safe, man page), waits for it, and goes back to the start of the loop.
    3. cryptsetup exit 0 and no `reencrypt` keyslot left → `result.json {outcome: completed, finished_at,
       data_bytes, duration_s}` (duration = the sum of the running intervals) and exit 0. Non-zero exit that is
       not a SIGTERM the helper sent → `result.json {outcome: failed, reason: resume_exit_<n>:<first stderr
       line>}` and exit 1. SIGTERM from systemd (shutdown) → the helper forwards it, writes no result and exits 143.
22. The agent's full pass, while `encrypting`: reads `progress.json` into `health.disk.conversion` (`DoneBytes`,
    `DataBytes`, `ETASeconds`, `PausedReason`, `UpdatedAt`; `paused_reason: helper_not_running` when the unit is
    not active and no result exists); reads `result.json`: `completed` → `state.Conversion.Phase = "completed"`,
    `CompletedAt`, emit `disk.conversion_completed{conversion_id, volume, data_bytes, duration_s}`, remove
    `/var/lib/paddock/encrypt/` except nothing else — the `luks` reconciler now sees a LUKS2 root without the
    `reencrypt` keyslot, the install passphrase and the disk-setup marker (already removed by the PIN dialogue) and
    runs the M4b flow to `compliant`; `failed` → emit `disk.conversion_failed{stage: resume, reason}`, count
    `ResumeFailures`; up to 3 relaunches per boot, then wait for the next boot (the device keeps working on
    dm-crypt; the header stays recoverable). `state.Conversion` is cleared once the device reports `compliant`
    or `escrow_pending` for the first time after `completed`.
23. `health.Report` gains nothing beyond `Disk.Conversion`. The health state `encrypting` is reported with the
    `Tokens` of the real keyslots (`password` for the conversion key, `tpm2+pin` once enrolled), `LUKSVersion` 2,
    and `Volumes` with the root volume only (`Escrowed: false`).

### 3.7 Portal (PDK-246)

24. `DiskEncryptionCard.vue`, state `not_encrypted`: when `disk.conversion.eligible` is true, the card shows the
    panel `devices.disk.convert.eligible` and, for organization administrators of active devices, the button
    *Encrypt this device…* (`devices.disk.convert.label`); when false, the existing reinstall alert
    (`devices.disk.notEncrypted.reinstall`) plus the list `devices.disk.convert.reasons.<reason>` (one line per
    reason; `devices.disk.notEncrypted.conversionPlanned` of PDK-233 is removed). The flow is the step-up first
    (`startStepUp('disk-convert', deviceId)`), then `components/EncryptDiskDialog.vue` built on `ConfirmDialog`'s
    layout: the explanation `devices.disk.convert.explanation`, the checklist (`devices.disk.convert.check.backup`
    as a required checkbox — the confirm button stays disabled until it is checked —, the information lines
    `devices.disk.convert.check.restart`, `.check.power`, `.check.pin` (or `.check.tpmOnly` when the device's
    unlock mode is `tpm_only`), `.check.duration` with the estimate `ceil(disk_total_bytes / 150 MB/s)` from the
    hardware facts (M8d) rounded to 10 minutes, or `.check.durationUnknown`; `.check.ubuntu2404` when
    `disk.conversion.release` is `24.04`), the reason field (2–500), the typed hostname (`requireTypedText`),
    destructive styling, confirm label `devices.disk.convert.confirmLabel`.
25. Progress panel (same card) while `disk_conversion` is open: the phase line `devices.disk.convert.phases.<phase>`
    with `requested` (command status), `prepared` (waiting for the restart), `encrypting` (a `v-progress-linear`
    with `done_bytes / data_bytes`, the percentage, `devices.disk.convert.eta` or `devices.disk.convert.paused.<reason>`,
    `devices.disk.convert.progressAt`), `completed` (`devices.disk.convert.phases.completed` until the state
    becomes `compliant`, then nothing), `failed` (`v-alert` type `error`: `devices.disk.convert.failed` with the
    stage and reason texts `devices.disk.convert.failures.<stage>` and the reason verbatim, a link to the runbook
    `docs/operations/in-place-encryption.md`, and the button *Encrypt this device…* again). While `requested` the
    button *Cancel request* (`devices.disk.convert.cancel.label`, `ConfirmDialog` `devices.disk.convert.cancel.*`)
    for administrators. The device list and the header status chip map `encrypting` to *Partial* with the label
    `devices.disk.states.encrypting`. Attention kind `disk_conversion_failed` (`attention.kinds.disk_conversion_failed`,
    severity `warn`, detail `stage:reason`).

### 3.8 Documents, residual risks, regression (PDK-248)

26. New runbook `docs/operations/in-place-encryption.md` (binding contents: how it works in five steps; the
    supported layouts and every preflight reason with what to do; the preconditions and what the user sees at the
    conversion boot (text console, the PIN dialogue, the time the init step takes); the background phase (speed,
    battery pause, what a restart does); the escrowed generations (generation 1 = the conversion key, generation
    2 = the recovery key enrolled afterwards; both revealed by *Show recovery key*, the newest first); recovery
    when the device does not come back after the restart (dracut emergency shell: `cryptsetup open --key-file -`
    with the revealed key typed, `vgchange -ay`, `exit`; or boot the previous kernel entry — the initrd of every
    installed kernel carries the module); `paddockd encrypt-abort`; the manual completion when the agent is gone
    (`cryptsetup reencrypt --resume-only <partition>` with the revealed key); never run `cryptsetup reencrypt`
    by hand on a device whose agent is running). `docs/operations/disk-recovery.md`: the state `encrypting` in the
    states table and the sentence that the conversion key is the first revealed generation.
    `docs/operations/autoinstall.md` "Encrypting an installed device": replace PDK-233's three statements by the
    pointer to the runbook and the supported layouts. `docs/architecture.md` §12.4 amendment (dated 2026-10-17,
    ADR 0039): the conversion in one paragraph, the new state and events; §11.4 (command `encrypt_disk`, 7 d);
    §16.1 (`device_disk_conversion`); §17.1 (the endpoints). `docs/compliance/residual-risks.md`: RR-56 … RR-61
    (§12). `docs/compliance/glossary-de.md`: *Nachträgliche Verschlüsselung* (in-place encryption),
    *Umwandlungsschlüssel* (conversion key), *Umwandlung* (conversion). `CHANGELOG.md` `[Unreleased]`: one
    operator-visible line per ticket.

## 4. Non-goals

- Layouts without a separate `/boot`, carving a `/boot` out of free space, moving partitions, xfs, btrfs, ZFS, md
  RAID, several physical volumes, BIOS boot, devices without TPM 2.0, LUKS1 or already encrypted (`unmanaged`)
  devices: all stay "reinstall needed" (ADR 0039 decision 2).
- Encrypting other volumes than the root volume (swap partitions, data partitions): never in M8e.
- Restarting the device from Paddock, prompting the user on the desktop, or scheduling the restart: the restart is
  the user's or the administrator's action outside Paddock (open point 1).
- Cancelling a conversion after the device received the command from the portal (open point 3);
  `paddockd encrypt-abort` at the device covers the `prepared` phase.
- A GRUB password, Plymouth for dracut on 24.04, kernel command line measurement (RR-44 stands).
- Any change to `agent/internal/revoke/`, `agent/cmd/paddock-revoke/`, `pkg/revocation/`, the device API path
  version, `docs/adr/0001…0037`, M8d's migrations once merged.
- Decryption (reverting a conversion): never.

## 5. Affected files

| Path | Action | Purpose |
| --- | --- | --- |
| `docs/adr/0039-in-place-encryption-online-reencryption.md`, `docs/adr/0038-…` (amendment) | new / amended (done) | decisions |
| `server/migrations/paddock/<next>_disk_conversion.sql` | new | §3.3 decision 6 |
| `server/internal/adapters/postgres/queries/disk_conversion.sql` (new), `device.sql`, `command.sql`, `attention.sql`; `pgstore` (gen) | new / change | queries |
| `server/internal/domain/audit/codes.go`, `docs/compliance/audit-codes.md` (gen), `server/web/src/lib/auditCodes.gen.ts` (gen) | change | §6.5 |
| `pkg/command/command.go`, `pkg/bundle/bundle.go`, `pkg/protocol/types.go`, `api/openapi/device.yaml` | change | §6.2, §6.3, decision 5, 11 |
| `server/internal/app/diskconversion.go` (new), `app/devices.go`, `app/disk.go`, `app/devicereports.go`, `app/commands.go`, `app/attention.go`; `server/internal/compiler/disk.go` | new / change | use cases, events, bundle |
| `server/internal/transport/http/admin/handlers_devices.go`, `handlers.go` (`privileged`), `spec_test.go`; `api/openapi/admin.yaml`; generated Go/TS | change | §6.1 |
| `agent/internal/encrypt/` (new: `preflight.go`, `prepare.go`, `resume.go`, `plan.go`, `os.go`, `dracut/module-setup.sh`, `dracut/paddock-encrypt-init.sh`, `dracut/paddock-encrypt-init.service`, `embed.go`), `agent/internal/luks/luks.go`, `agent/internal/reconcile/luks.go`, `agent/internal/agent/{agent,encrypt}.go` (new `encrypt.go`), `agent/internal/state/state.go`, `agent/internal/health/health.go` (no change expected), `agent/cmd/paddockd/main.go`, `agent/internal/buildinfo/` | new / change | §3.2, §3.4–§3.6 |
| `server/web/src/components/{DiskEncryptionCard,EncryptDiskDialog}.vue` (new dialog), `lib/{disk,status,devices,deviceHealth}.ts`, `views/{Devices,Attention}.vue`, `locales/{en,de}.json` | change / new | §3.7 |
| `test/acceptance/diskconversion_test.go` (new), `test/acceptance/devicesim`; `test/system/{autoinstall,encrypt_test,disk}.go`, `test/vms/virtualbox/autoinstall/{unencrypted-lvm,unencrypted-plain}.yaml.tmpl` (new) | new / change | §9 |
| `docs/operations/in-place-encryption.md` (new), `docs/operations/{disk-recovery,autoinstall}.md`, `docs/architecture.md`, `docs/compliance/{residual-risks,glossary-de}.md`, `CHANGELOG.md` | new / change | §3.8 |

MUST NOT be touched: `agent/internal/revoke/`, `agent/cmd/paddock-revoke/`, `pkg/revocation/`,
`packaging/nfpm/paddock-revoke.yaml`, `server/migrations/paddock/00001…00048` and M8d's migrations once merged,
`docs/adr/0001…0037`, `deploy/compose/compose.prod.yaml`, `deploy/compose/compose.lab.yaml`, the device API path
version, `test/vms/virtualbox/*.sh` (the VM scripts are used, never changed), any file of plans M9–M11 and their
tickets, `server/internal/autoinstall/` (the autoinstall is not changed by M8e).

## 6. Interfaces and formats

### 6.1 Admin API (additions to `api/openapi/admin.yaml`)

```yaml
# schemas
Device:               + disk_conversion (DeviceDiskConversion, nullable)
DeviceDiskConversion: {id: uuid, phase: enum[requested,prepared,encrypting,completed,failed,cancelled], requested_at: date-time,
                       reason: string, command_id: uuid, command_status: string, layout: string nullable (lvm|plain),
                       luks_uuid: uuid nullable, data_bytes: integer int64 nullable, done_bytes: integer int64 nullable,
                       eta_s: integer nullable, paused_reason: string nullable, progress_at: date-time nullable,
                       failure_stage: string nullable, failure_reason: string nullable, finished_at: date-time nullable}
DeviceEncryptRequest: {confirm_hostname (required), reason (required, 2–500), backup_confirmed (boolean, required)}
DiskEncryption:       + conversion (DeviceDiskConversion, nullable)
DiskState / DiskHealth: + conversion (DiskConversionHealth); state enum + encrypting
DiskConversionHealth: {eligible: boolean, reasons: [string], release: string, layout: string, phase: string, data_bytes, done_bytes: integer int64,
                       eta_s: integer, paused_reason: string, failure_stage: string, failure_reason: string, updated_at: date-time}
AttentionKind:        + disk_conversion_failed

# operations
POST /api/v1/devices/{id}/encrypt         x-paddock-audit: device.encrypt_requested  200 Device · 403 step_up_required|forbidden · 404 · 409 invalid_state · 422 invalid_request
POST /api/v1/devices/{id}/encrypt/cancel  x-paddock-audit: device.encrypt_cancelled  200 Device · 403 · 404 · 409 invalid_state
GET  /api/v1/devices                      filter disk_state accepts encrypting
```

Both `POST` routes go into `privileged`; `TestOpenAPISpec` MUST pass unchanged in its assertions.

### 6.2 Device protocol (`pkg/protocol/types.go`, `api/openapi/device.yaml`; additive, ADR 0013)

```go
// DiskHealth gains:
Conversion *DiskConversion `json:"conversion,omitempty"` // §3.2 decision 3
// DiskStates gains, directly after DiskNotEncrypted:
DiskEncrypting = "encrypting"
// Event types (closed set gains four; data as in §3.3 decision 9):
EventDiskConversionPrepared  = "disk.conversion_prepared"
EventDiskConversionStarted   = "disk.conversion_started"
EventDiskConversionCompleted = "disk.conversion_completed"
EventDiskConversionFailed    = "disk.conversion_failed"
```

### 6.3 Agent state and files

```go
// state.State gains:
Conversion *DiskConversion `json:"conversion,omitempty"`
// DiskConversion is the in-place encryption in progress on this device (ADR 0039). Secrets are never stored here.
type DiskConversion struct {
    ID, CommandID        string     `json:"id"` / `json:"command_id"`
    Phase                string     `json:"phase"` // preparing | prepared | encrypting | completed | failed
    RequestedAt          time.Time  `json:"requested_at"`
    PreparedAt, StartedAt, CompletedAt *time.Time
    Layout, LUKSUUID, Mapping, Partition string
    DataBytes            int64      `json:"data_bytes,omitempty"`
    KeyEscrowGeneration  int64      `json:"key_escrow_generation,omitempty"`
    InitrdRegenerated    bool       `json:"initrd_regenerated,omitempty"`
    ResumeFailures       int        `json:"resume_failures,omitempty"`
    FailureStage, FailureReason string
}
```

Files (all 0600 root, directory `/var/lib/paddock/encrypt/` 0700):

```
plan.json      {"conversion_id","layout","partition","part_uuid","luks_uuid","mapping","vg","lv","fs_uuid",
                "fs_target_bytes","pv_target_bytes","data_bytes","unlock_mode","boot_pin_min_length","created_at"}
plan.env       PADDOCK_LAYOUT=lvm|plain  PADDOCK_PART_UUID=  PADDOCK_LUKS_UUID=  PADDOCK_MAPPING=  PADDOCK_VG=  PADDOCK_LV=
               PADDOCK_FS_UUID=  PADDOCK_FS_TARGET_BYTES=  PADDOCK_FS_TARGET_SECTORS=  PADDOCK_PV_TARGET_BYTES=
               (every value validated by the agent against ^[A-Za-z0-9_.-]+$; the file is sourced by the init script)
progress.json  {"done_bytes","data_bytes","speed_bps","eta_s","paused_reason","updated_at"}
result.json    {"outcome":"completed|failed","reason","data_bytes","duration_s","finished_at"}
test-hooks     (dev builds only, empty)
/run/paddock/encrypt-boot.env   PADDOCK_BOOT_STATUS=ok|failed|skipped PADDOCK_BOOT_STAGE=init|open PADDOCK_BOOT_REASON= PADDOCK_BOOT_SECONDS=
/var/lib/paddock/install-passphrase  the conversion key (0600, 71 characters, no newline)
```

### 6.4 Dracut module (embedded; `agent/internal/encrypt/dracut/`)

`paddock-encrypt-init.service` (binding):

```ini
[Unit]
Description=Paddock in-place disk encryption (init step)
DefaultDependencies=no
ConditionPathExists=/etc/paddock/encrypt-plan.env
After=systemd-udev-trigger.service systemd-udevd.service
Before=initrd-root-device.target sysroot.mount cryptsetup.target dracut-initqueue.service
Wants=systemd-udev-trigger.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/libexec/paddock/encrypt-init.sh
StandardOutput=journal+console
StandardError=journal+console
TimeoutStartSec=2h

[Install]
WantedBy=initrd.target
```

`paddock-encrypt-init.sh`: POSIX `sh`, `set -u`, sources `/etc/paddock/encrypt-plan.env`, implements decision 16
stage by stage with one function per stage, a `log()` to the journal (`echo "paddock-encrypt: …"`), a `result()`
that writes `/run/paddock/encrypt-boot.env` and never exits non-zero (a non-zero exit would fail the unit and
block the boot). The key file is referenced by path only; the script never echoes it. The dev hook
(decision 19): `getarg paddock.encrypt.testdelay=` (dracut-lib) — only when `/etc/paddock/encrypt-test` exists.

### 6.5 Audit codes (closed registry; descriptions verbatim; device events use `deviceOutcomes`)

| Code | Description | Params |
| --- | --- | --- |
| `device.encrypt_requested` | An organization administrator asked, with a step-up and a backup acknowledgement, to encrypt the disk of an unencrypted device in place; the device prepares itself and converts at its next restart. | `hostname`, `reason`, `backup_confirmed`, `command_id`, `conversion_id` |
| `device.encrypt_cancelled` | An organization administrator cancelled an in-place encryption before the device received the command. | `hostname`, `command_id`, `conversion_id` |
| `device.disk_conversion_prepared` | The device escrowed the conversion key and built the initrd for its in-place encryption; it waits for a restart (actor: the device). | `conversion_id`, `layout`, `volume`, `data_bytes` |
| `device.disk_conversion_started` | The device initialised LUKS2 on its root partition at the restart and encrypts the remaining data in the background (actor: the device). | `conversion_id`, `volume`, `init_s` |
| `device.disk_conversion_completed` | The device finished encrypting its root partition; the recovery key, the TPM unlock and the header escrow follow as for a newly installed device (actor: the device). | `conversion_id`, `volume`, `data_bytes`, `duration_s` |
| `device.disk_conversion_failed` | The in-place encryption of a device failed or was skipped at the named stage; stages preflight, prepare and init leave the device unencrypted, stage resume leaves it bootable with the encryption unfinished (actor: the device). | `conversion_id`, `stage`, `reason`, `volume` |

Message keys `audit.<code>` in `en.json` and `de.json`.

### 6.6 Portal texts (binding; English `en.json`, German `de.json`; ICU where values appear)

| Key | English | German |
| --- | --- | --- |
| `devices.disk.states.encrypting` | Encryption in progress | Verschlüsselung läuft |
| `devices.disk.convert.label` | Encrypt this device… | Dieses Gerät verschlüsseln … |
| `devices.disk.convert.eligible` | This device is not encrypted. Its disk layout allows encrypting it in place: the device prepares itself, the recovery key is stored in Paddock first, the user restarts once and chooses the boot PIN, and the rest is encrypted in the background. | Dieses Gerät ist nicht verschlüsselt. Sein Festplattenlayout erlaubt die nachträgliche Verschlüsselung: Das Gerät bereitet sich vor, der Wiederherstellungsschlüssel wird zuerst in Paddock hinterlegt, der Benutzer startet einmal neu und wählt die Boot-PIN, der Rest wird im Hintergrund verschlüsselt. |
| `devices.disk.convert.title` | Encrypt {hostname} in place | {hostname} nachträglich verschlüsseln |
| `devices.disk.convert.explanation` | Paddock encrypts the root partition of this device without reinstalling it. Nothing changes until the device restarts; the recovery key is stored in Paddock before the first byte is encrypted. Data outside the root partition (other partitions, swap partitions) is not encrypted. | Paddock verschlüsselt die Root-Partition dieses Geräts ohne Neuinstallation. Bis zum Neustart ändert sich nichts; der Wiederherstellungsschlüssel wird in Paddock hinterlegt, bevor das erste Byte verschlüsselt wird. Daten außerhalb der Root-Partition (andere Partitionen, Swap-Partitionen) werden nicht verschlüsselt. |
| `devices.disk.convert.check.backup` | I confirm that a current backup of this device exists. The file system is shrunk at the restart; a power cut in those seconds can damage it. | Ich bestätige, dass eine aktuelle Sicherung dieses Geräts existiert. Das Dateisystem wird beim Neustart verkleinert; ein Stromausfall in diesen Sekunden kann es beschädigen. |
| `devices.disk.convert.check.restart` | The user must restart the device once. Until then nothing is encrypted. The restart takes a few minutes longer than usual. | Der Benutzer muss das Gerät einmal neu starten. Bis dahin wird nichts verschlüsselt. Der Neustart dauert einige Minuten länger als üblich. |
| `devices.disk.convert.check.power` | A laptop must be on mains power at that restart; the background encryption pauses on battery. | Ein Laptop muss bei diesem Neustart am Netzteil hängen; die Verschlüsselung im Hintergrund pausiert im Akkubetrieb. |
| `devices.disk.convert.check.pin` | At the restart the device asks the user for a boot PIN on a text console (unlock mode: TPM + boot PIN). The PIN never reaches Paddock. | Beim Neustart fragt das Gerät den Benutzer auf einer Textkonsole nach einer Boot-PIN (Entsperrmodus: TPM + Boot-PIN). Die PIN gelangt nie zu Paddock. |
| `devices.disk.convert.check.tpmOnly` | The device unlocks with its TPM without a PIN (unlock mode: TPM only). | Das Gerät entsperrt sich mit seinem TPM ohne PIN (Entsperrmodus: Nur TPM). |
| `devices.disk.convert.check.duration` | The background encryption takes about {duration} on this disk; the device stays usable meanwhile. | Die Verschlüsselung im Hintergrund dauert auf dieser Festplatte etwa {duration}; das Gerät bleibt währenddessen nutzbar. |
| `devices.disk.convert.check.durationUnknown` | The background encryption takes minutes to hours depending on the disk size; the device stays usable meanwhile. | Die Verschlüsselung im Hintergrund dauert je nach Festplattengröße Minuten bis Stunden; das Gerät bleibt währenddessen nutzbar. |
| `devices.disk.convert.check.ubuntu2404` | On Ubuntu 24.04 the device switches its early-boot system from initramfs-tools to dracut; the graphical boot splash is replaced by a text console. | Auf Ubuntu 24.04 wechselt das Gerät sein Frühstartsystem von initramfs-tools zu dracut; der grafische Startbildschirm wird durch eine Textkonsole ersetzt. |
| `devices.disk.convert.confirmLabel` | Encrypt at the next restart | Beim nächsten Neustart verschlüsseln |
| `devices.disk.convert.typed` | Type the hostname to confirm. | Geben Sie den Hostnamen zur Bestätigung ein. |
| `devices.disk.convert.requested` | Encryption requested. | Verschlüsselung angefordert. |
| `devices.disk.convert.phases.requested` | Encryption requested — {status}. The device prepares itself at its next check-in. | Verschlüsselung angefordert — {status}. Das Gerät bereitet sich beim nächsten Check-in vor. |
| `devices.disk.convert.phases.prepared` | Prepared since {at}: the recovery key is stored. Waiting for the user to restart the device. | Vorbereitet seit {at}: Der Wiederherstellungsschlüssel ist hinterlegt. Warten auf den Neustart durch den Benutzer. |
| `devices.disk.convert.phases.encrypting` | Encrypting in the background: {percent} % of {total} | Verschlüsselung im Hintergrund: {percent} % von {total} |
| `devices.disk.convert.phases.completed` | Encryption completed on {at}; the recovery key and the TPM unlock are being set up. | Verschlüsselung am {at} abgeschlossen; Wiederherstellungsschlüssel und TPM-Entsperrung werden eingerichtet. |
| `devices.disk.convert.eta` | about {duration} left | noch etwa {duration} |
| `devices.disk.convert.progressAt` | last report {at} | letzte Meldung {at} |
| `devices.disk.convert.paused.on_battery` | paused: the device runs on battery | pausiert: Das Gerät läuft im Akkubetrieb |
| `devices.disk.convert.paused.helper_not_running` | paused: the encryption helper is not running; it starts again at the next check-in or restart | pausiert: Der Verschlüsselungshelfer läuft nicht; er startet beim nächsten Check-in oder Neustart erneut |
| `devices.disk.convert.failed` | The encryption failed at stage "{stage}": {reason}. See the runbook. | Die Verschlüsselung ist in der Phase „{stage}“ fehlgeschlagen: {reason}. Siehe Runbook. |
| `devices.disk.convert.failures.preflight` | preflight (the device refused the request; nothing was changed) | Vorprüfung (das Gerät hat die Anforderung abgelehnt; nichts wurde geändert) |
| `devices.disk.convert.failures.prepare` | preparation (nothing on the disk was changed) | Vorbereitung (auf der Festplatte wurde nichts geändert) |
| `devices.disk.convert.failures.init` | restart (the device boots unencrypted; see the runbook when it does not boot) | Neustart (das Gerät startet unverschlüsselt; siehe Runbook, falls es nicht startet) |
| `devices.disk.convert.failures.resume` | background encryption (the device works; the encryption is unfinished and resumes at the next restart) | Hintergrundverschlüsselung (das Gerät funktioniert; die Verschlüsselung ist unvollständig und wird beim nächsten Neustart fortgesetzt) |
| `devices.disk.convert.reasonsTitle` | In-place encryption is not possible on this device: | Eine nachträgliche Verschlüsselung ist auf diesem Gerät nicht möglich: |
| `devices.disk.convert.reasons.release_unsupported` | the Ubuntu release is not 24.04 or 26.04 | das Ubuntu-Release ist nicht 24.04 oder 26.04 |
| `devices.disk.convert.reasons.no_uefi` | the device does not boot with UEFI | das Gerät startet nicht mit UEFI |
| `devices.disk.convert.reasons.no_tpm2` | the device has no TPM 2.0 | das Gerät hat keinen TPM 2.0 |
| `devices.disk.convert.reasons.no_separate_boot` | /boot is not on its own partition | /boot liegt nicht auf einer eigenen Partition |
| `devices.disk.convert.reasons.boot_on_root_device` | /boot shares the root partition | /boot teilt sich die Root-Partition |
| `devices.disk.convert.reasons.root_not_ext4` | the root file system is not ext4 | das Root-Dateisystem ist nicht ext4 |
| `devices.disk.convert.reasons.root_layout_unsupported` | the root partition layout is not supported (RAID, several volumes, no GPT or an unknown stack) | das Layout der Root-Partition wird nicht unterstützt (RAID, mehrere Volumes, kein GPT oder ein unbekannter Aufbau) |
| `devices.disk.convert.reasons.pv_tail_in_use` | the end of the LVM physical volume is used by a volume other than root | das Ende des physischen LVM-Volumes wird von einem anderen Volume als root belegt |
| `devices.disk.convert.reasons.low_free_space` | less than 1 GiB is free on the root file system | auf dem Root-Dateisystem ist weniger als 1 GiB frei |
| `devices.disk.convert.reasons.root_reference_unsupported` | fstab or the kernel command line refer to root by a device path | fstab oder die Kernel-Kommandozeile verweisen über einen Gerätepfad auf root |
| `devices.disk.convert.reasons.already_encrypted` | the root volume is already encrypted | das Root-Volume ist bereits verschlüsselt |
| `devices.disk.convert.reasons.dm_crypt_missing` | the kernel has no dm-crypt | der Kernel hat kein dm-crypt |
| `devices.disk.convert.cancel.label` | Cancel request | Anforderung zurückziehen |
| `devices.disk.convert.cancel.title` | Cancel the encryption | Verschlüsselung zurückziehen |
| `devices.disk.convert.cancel.confirm` | Cancel the encryption of {hostname}? Only possible while the device has not received the command. | Verschlüsselung von {hostname} zurückziehen? Nur möglich, solange das Gerät den Befehl nicht erhalten hat. |
| `devices.disk.convert.cancelled` | Request cancelled. | Anforderung zurückgezogen. |
| `attention.kinds.disk_conversion_failed` | In-place encryption failed | Nachträgliche Verschlüsselung fehlgeschlagen |
| `devices.disk.notEncrypted.reinstall` | (unchanged) | (unverändert) |

`devices.disk.notEncrypted.conversionPlanned` is removed from both catalogs. The first revealed generation of the
recovery key on a converted device is the conversion key; the reveal dialog is unchanged.

## 7. Host and operator notes (binding figures for the documents)

- The init step takes seconds to a few minutes (`e2fsck -f` of the root file system plus the move of 32 MiB);
  the background phase runs at the disk's sequential speed minus the idle I/O class, typically 100–300 MB/s with
  AES-NI: about 1 hour per 500 GB. A restart during the background phase costs nothing but the resume.
- The conversion key is escrowed as recovery-key generation 1 and lies in the initrd on `/boot` until the TPM
  keyslot exists and the initrd is regenerated (minutes after the conversion boot when the PIN is set at once;
  until the user completes the dialogue otherwise); the data is partly plaintext until `completed`.
- On 24.04 the switch to dracut is permanent; kernel updates build their initrd with dracut from then on; the
  Plymouth splash is gone (as on autoinstalled 24.04 devices).
- A failed conversion at stage `preflight`, `prepare` or `init` leaves an unencrypted device and can be requested
  again at once; at stage `resume` the device works on dm-crypt and the helper retries after the next restart.

## 8. Steps (tickets, in order)

1. **PDK-241 — Server: conversion model, command, API, events, bundle field.** §3.3 (decisions 5–11), §6.1, §6.2,
   §6.5. Verify: `make gen` no diff; `go test ./server/internal/app/ ./pkg/command/ ./pkg/protocol/
   ./server/internal/compiler/`; `make acceptance T=TestDiskConversion`; the isolation gate.
2. **PDK-242 — Agent: preflight, eligibility in health, reencrypt-aware metadata.** §3.2 (decisions 1–4).
   Verify: `go test ./agent/internal/encrypt/ ./agent/internal/luks/ ./agent/internal/reconcile/` (table tests
   with recorded `lsblk`/`lvm`/`findmnt` outputs for `lvm`, `plain`, `direct`, raid, btrfs, two PVs, swap LV at
   the tail).
3. **PDK-243 — Agent: command handler, preparation, abort.** §3.4 (decisions 12–14), §6.3. Verify: `go test
   ./agent/...` (fake system for every step, idempotent re-run, escrow failure, dracut failure).
4. **PDK-244 — Dracut module and init script.** §3.5 (decisions 15–17), §6.4. Verify: `go test
   ./agent/internal/encrypt/` (the embedded files exist, `shellcheck -s sh` on the script in `make lint` — stop
   condition S4 when shellcheck is absent); the script's stage logic tested with a fake toolchain (`PATH` with
   stub scripts recording calls) in `agent/internal/encrypt/dracut_test.go`.
5. **PDK-245 — Agent: boot result, resume helper, progress, initrd regeneration, completion.** §3.6 (decisions
   18–23). Verify: `go test ./agent/...` (progress parsing from recorded `--progress-json` lines, pause/resume on
   battery, result handling, phase transitions).
6. **PDK-246 — Portal.** §3.7, §6.6. Verify: `make web`; component tests over visible text; `make e2e`.
7. **PDK-247 — System gates and runbook.** §9 S-IE1 … S-IE3, the throwaway VM templates, `docs/operations/
   in-place-encryption.md`. Verify: `PADDOCK_SYSTEM_VMS=paddock-ie-2404,paddock-ie-2604 make system-test
   T='TestInPlaceEncryption'`.
8. **PDK-248 — Documents, residual risks, CHANGELOG, regression.** §3.8, §12, the full regression (`make lint
   test`, `make acceptance`, `make e2e`, `make system-test VM=all`, the two throwaway gates, `make bundle-test`),
   `make scan-secrets`.

PDK-241 and PDK-242 MAY run in parallel. PDK-243 depends on PDK-242 and on PDK-241's protocol types; PDK-244 on
PDK-243; PDK-245 on PDK-244; PDK-246 on PDK-241; PDK-247 on PDK-245 and PDK-246; PDK-248 is last.

## 9. Tests and gates

Unit and integration tests per ticket follow the project's rules (business logic → unit; persistence, RLS →
integration with testcontainers; portal components with behaviour → component tests over the user's view).
Positive and negative tests for every role and tenant rule; every tool interaction of the agent behind the
`System` fake.

Acceptance (`test/acceptance`, `make acceptance`; roles **A** org_admin with step-up, **O** org_operator, **U**
org_auditor; "event" = exactly one audit event found with `expectOneEvent`):

| # | Given / When / Then | Role sees |
| --- | --- | --- |
| A1 `TestDiskConversion` | A devicesim reporting `disk{state: not_encrypted, boot_separate: true, conversion{eligible: true, layout: lvm}}`: A without step-up → 403 `step_up_required`; with step-up and wrong hostname → 422; `backup_confirmed: false` → 422 (detail `backup_confirmed must be true`); valid → 200, `disk_conversion{phase: requested, command_status: pending}`, event `device.encrypt_requested` with `backup_confirmed: true`, the device's commands list has type `encrypt_disk` with params `{conversion_id}`; a second request → 409; a device reporting `eligible: false, reasons: [no_separate_boot]` → 409 with the reason in the detail; O → 403; cancel → 200, command `cancelled`, row `cancelled`, event `device.encrypt_cancelled`; request again, devicesim checks in (delivered) → cancel 409; devicesim posts the result `{accepted: true}` and the events `disk.conversion_prepared{layout, volume, data_bytes}` → row `prepared` with them; `disk.conversion_started{init_s}` → `encrypting`; a check-in with `conversion{phase: encrypting, done_bytes: 50, data_bytes: 100, eta_s: 60}` → `GET /devices/{id}` shows `done_bytes: 50`, `eta_s: 60`; `disk.conversion_completed` → `completed`, `finished_at`; a new request after a `failed` row (devicesim posts `{accepted: false, reason: not_eligible, reasons: [low_free_space]}`) succeeds; a `disk.conversion_failed{stage: init, reason: on_battery}` → row `failed`, attention `disk_conversion_failed` detail `init:on_battery`; an uninstall pending → 409; a Lock pending → 409; globex → 404 on both routes. | A, O, U |
| A2 `TestDiskConversionBundle` | `boot_pin_min_length` 10 on the organization → the v2 bundle's `disk.boot_pin_min_length` is 10; the default → 8. | A |
| A3 `TestListContractM8e` | `GET /devices?disk_state=encrypting` lists a devicesim reporting that state; the list contract tests pass unchanged. | — |

System (`test/system`; the two throwaway VMs run only with `PADDOCK_SYSTEM_VMS=paddock-ie-2404,paddock-ie-2604`,
as gate D-AI does; ISOs from `PADDOCK_SYSTEM_ISO_2404` / `PADDOCK_SYSTEM_ISO_2604`; `buildAIVM` is generalised to
take the VM name, the SSH port (2229, 2230) and the ISO; the VMs are built from
`test/vms/virtualbox/autoinstall/unencrypted-lvm.yaml.tmpl` (26.04: `storage.layout.name: lvm`, no password,
`sizing-policy: all`) and `unencrypted-plain.yaml.tmpl` (24.04: curtin `storage.config` with GPT, a 1 GiB ESP, a
2 GiB ext4 `/boot` and ext4 `/` on the rest), then `Install` as on the base VMs):

| # | Gate | Content |
| --- | --- | --- |
| S-IE1 `TestInPlaceEncryptionLVM` | 26.04, `lvm`, `tpm_pin`; power cut after the init before the reactivation; power cut in the background phase | After `Install`: health `disk.conversion.eligible: true, layout: lvm` within one full pass; the request through the API → within 10 min `device.disk_conversion_prepared{layout: lvm}`, `GET /devices/{id}/disk` shows one stored recovery key (generation 1), `lsinitrd` of the running kernel lists `paddock-encrypt-init.service` and `etc/paddock/encrypt-key`, `/etc/crypttab` is unchanged. The test sets `paddock.encrypt.testdelay=open:60` in `GRUB_CMDLINE_LINUX` of `/etc/default/grub` and runs `update-grub` (over SSH), then `sudo systemctl reboot`. Boot 1: the console shows `paddock-encrypt: init done` (screenshot polling every 5 s); the test calls `VM.PowerOff` during the following sleep. Boot 2 (parameter still set; the `open` path does not sleep): the console shows the PIN dialogue (screenshot contains "Paddock disk encryption setup") → `AnswerDiskSetup`; SSH back; `lsblk` shows `crypto_LUKS` on the partition and root on `dm_crypt-0`; journal lines `paddock-encrypt: header found, opening`; `device.disk_conversion_started`; health state `encrypting` with `done_bytes` increasing between two check-ins. The test removes the parameter (`/etc/default/grub`, `update-grub`), waits until `done_bytes` is between 10 % and 90 % of `data_bytes`, and calls `VM.PowerOff`. Boot 3: `RebootWithPIN` → SSH; `done_bytes` ≥ the last value within 5 min and increasing; `device.disk_conversion_completed`; then `compliant` within 15 min with tokens `[recovery, tpm2+pin]`, two stored recovery-key generations, the header stored, `/var/lib/paddock/install-passphrase` gone, the revealed generation 1 no longer opening the disk (`Opens`), the revealed generation 2 opening it; `lsinitrd` shows `etc/crypttab` with the LUKS UUID and no `paddock-encrypt`; `cryptsetup luksDump` lists no `reencrypt` keyslot and no requirement; `RebootWithPIN` works; `/boot` is mounted; the root file system is smaller than before the conversion by 64 MiB (`findmnt -bno SIZE /` before and after). |
| S-IE2 `TestInPlaceEncryptionPlain` | 24.04, `plain`, `tpm_only`; abort; power cut after the shrink before the init | The organization set to `tpm_only` for the run (restored on cleanup). After `Install`: eligibility `layout: plain`. Part A (abort): the request → `prepared` (dracut installed: `dpkg -l dracut` installed, `initramfs-tools` gone; `lsinitrd` lists the module); `sudo paddockd encrypt-abort` → `device.disk_conversion_failed{stage: prepare, reason: aborted}`, `lsinitrd` no longer lists the module, `/var/lib/paddock/install-passphrase` gone, `sudo systemctl reboot` boots unencrypted (SSH back, `lsblk` without `crypto_LUKS`), health `eligible: true` again, attention `disk_conversion_failed` detail `prepare:aborted`. Part B: a new request → `prepared`; the test sets `paddock.encrypt.testdelay=init:120` (`/etc/default/grub`, `update-grub`), then `sudo systemctl reboot`. Boot 1: the console shows `paddock-encrypt: shrink done`; the test calls `VM.PowerOff` during the following sleep. Boot 2 (parameter still set): the console shows `paddock-encrypt: file system already at target`, then after the sleep `paddock-encrypt: init done`; no PIN dialogue; SSH back on dm-crypt; `device.disk_conversion_started`; `encrypting`. The test removes the parameter and reboots once more (boot 3, the `open` path): SSH back within the normal boot time, the reencryption resumes (`done_bytes` increasing); `device.disk_conversion_completed`; `compliant` with tokens `[recovery, tpm2]` and `unlock_mode: tpm_only`; a reboot unlocks without input; the revealed generation 1 no longer opens the disk, generation 2 does; `lsinitrd` as in S-IE1. |
| S-IE3 `TestInPlaceEncryptionNotEligible` | base VMs `paddock-u2404` and `paddock-u2604` (LUKS) | After `Install` on the base VM, health reports `disk.state: unmanaged` or the M4b flow's state, `conversion` absent or `eligible: false` with `already_encrypted`; `POST /devices/{id}/encrypt` → 409 `invalid_state` with `already_encrypted` in the detail. Runs inside `TestDiskGates`' VM loop (`forEachVM`), not on a throwaway VM. |

The console lines the gates wait for are binding output of the init script (§6.4): `paddock-encrypt: shrink done`,
`paddock-encrypt: file system already at target`, `paddock-encrypt: init done`, `paddock-encrypt: header found,
opening`. The test hooks sleep after `shrink done` (`init`) and after `init done` (`open`). Both throwaway VMs are
deleted at the end of their gates.

Regression: `make acceptance`, `make e2e`, `make system-test VM=all` (every existing gate, in particular
`TestDiskGates` and `TestDiskUnlockMode`), `make bundle-test`.

## 10. Acceptance criteria

| # | Given / When / Then | Req. | Observed by |
| --- | --- | --- | --- |
| AC1 | Given an unencrypted adopted device with a supported layout, then the device page says it can be encrypted in place and offers the action to organization administrators; given an unsupported layout, then the page names every reason and offers no action. | L31 | Org admin |
| AC2 | Given the action, when the administrator passes the step-up, acknowledges the backup, gives a reason and types the hostname, then exactly one `device.encrypt_requested` is recorded, the device receives a signed `encrypt_disk` command, and the request can be cancelled until the device received it. | L31 | Org admin, auditor |
| AC3 | Given the command, when the device prepares itself, then the conversion key is stored in Paddock as recovery-key generation 1 before anything on the disk changes, the device reports `prepared`, and *Show recovery key* reveals that key. | L31 | Org admin |
| AC4 | Given a prepared device, when the user restarts it on mains power, then the device shrinks the file system, initialises LUKS2, boots on dm-crypt within minutes, asks for the boot PIN (unless `tpm_only`), and reports `encrypting` with increasing progress while the user works. | L31 | User at device, org admin |
| AC5 | Given the background phase, when the power is cut or the device is restarted, then the device boots again (with the PIN), the reencryption resumes where it stopped, and the progress continues. | L31 | User at device, org admin |
| AC6 | Given a completed reencryption, then the device becomes `compliant` with the keyslot set of its unlock mode, a second recovery-key generation and the header escrowed, the conversion key no longer opens the disk, and the initrd no longer carries the module or the key. | L31 | Org admin, auditor |
| AC7 | Given a failing precondition at any stage before the LUKS header exists (battery, fsck, busy volume group, escrow not stored, dracut), then the device stays unencrypted and bootable, reports the stage and the reason, and the portal shows them with the runbook link. | L31 | Org admin, user at device |
| AC8 | Given a device on battery, then the background encryption pauses and the page says so; given mains power again, it resumes. | L31 | Org admin |
| AC9 | Given any bundle or policy change without an administrator's request, then no device ever starts a conversion. | contract 8 | Auditor |

## 11. Stop conditions

- S1: M8d (PDK-231 … PDK-233) is not merged when PDK-242 starts: implement against the M8d branch and report; do
  not re-implement `boot_separate` or the unlock mode.
- S2: `systemd-cryptenroll` on either release refuses to add a keyslot while the `reencrypt` keyslot exists
  (message mentioning reencryption): report the output; the fallback design (the PIN dialogue after `completed`,
  marker set by the agent at completion instead of at preparation) is an architect decision, not an implementer's.
- S3: `cryptsetup reencrypt --encrypt --init-only … <device> <name>` on the test VM's kernel refuses the
  activation or the LVM reactivation finds no PV on the mapping: report the journal of the conversion boot.
- S4: `shellcheck` is not available in CI for the init script: report; do not drop the check silently.
- S5: `dracut -f --regenerate-all` on 24.04 fails inside the agent's bound or produces an initrd without the
  module although the host files exist: report the dracut output; do not fall back to initramfs-tools hooks.
- S6: the dev-only kernel parameter cannot be set on the throwaway VM without touching `test/vms/virtualbox/*.sh`:
  report; the GRUB edit runs over SSH inside the guest only.
- S7: any change seems necessary in `agent/internal/revoke/`, `agent/cmd/paddock-revoke/`, `pkg/revocation/`,
  the device API path version or `server/internal/autoinstall/`.
- S8: a new Go module, npm package or container image seems necessary (none is expected: `cryptsetup`, `lvm2`,
  `e2fsprogs`, `dracut`, `tpm2-tools` are Ubuntu packages already used by the autoinstall path).
- S9: the throwaway VM's `lvm` layout from the stock 26.04 ISO does not place the root LV at the end of the PV and
  `pv_tail_in_use` is reported: report the `pvs --segments` output before changing the rule of decision 2.
- S10: the measured init step on the 40 GB throwaway VM exceeds 10 minutes: report the journal timings.

## 12. Residual risks and open points

Residual risks (`docs/compliance/residual-risks.md`, numbered after RR-55, which M8d's amendment of 2026-10-17 uses for the component targets and the version watch; PDK-248 writes the rows):

- **RR-56 The shrink is not crash-safe.** `resize2fs` and `lvreduce` run for seconds at the conversion boot; a
  power cut in that window can leave the root file system damaged. Mitigation: mains power required when a
  battery exists, `e2fsck -f` before, the backup acknowledgement in the dialogue, idempotent stages. Record: the
  backup policy for devices that are converted.
- **RR-57 Interim exposure of the conversion key and of plaintext data.** From the preparation until the agent
  regenerates the initrd, the conversion key lies as `/etc/paddock/encrypt-key` inside every
  `/boot/initrd.img-*` on the unencrypted `/boot` partition (file mode 0600 protects it only on the running
  system). The initrd copy is removed at the first full pass after the TPM keyslot exists (decision 20: `dracut -f
  --regenerate-all` without the module, verified with `lsinitrd`) — minutes after the PIN dialogue of the
  conversion boot, or as long as the user leaves that dialogue open. The on-disk copy
  `/var/lib/paddock/install-passphrase` and its LUKS keyslot are removed by the `luks` reconciler once the
  reencryption has completed and the recovery key and header of generation 2 are stored (M4b flow); the escrowed
  generation 1 then no longer opens the disk. What an attacker with physical access gains in the window: with
  the initrd copy present, the disk unlocks without PIN or TPM (read the key from `/boot`, `cryptsetup open`), so
  the device is as unprotected as before the conversion; after the regeneration but before completion, the data
  that the reencryption has not reached yet is readable as plaintext from the partition without any key, and
  the already encrypted part only with the PIN, the TPM of this device or an escrowed key. Mitigation: the PIN
  dialogue at the conversion boot and the regeneration minutes later, the background phase at disk speed,
  `encrypting` visible on the device page and the attention list, `encrypt-abort` for a device that will not be
  restarted soon. Record: devices in `encrypting` or `prepared` for longer than a day; the rule that a converted
  laptop is not taken off premises before `compliant`.
- **RR-58 24.04 switches to dracut irreversibly.** initramfs-tools is removed; kernel updates use dracut; no
  Plymouth splash. Mitigation: the dialogue says so; the same stack as autoinstalled 24.04 devices. Record: the
  support statement for converted 24.04 devices.
- **RR-59 Battery-only devices never complete.** The background phase pauses on battery. Mitigation: the pause is
  shown; `encrypting` keeps the device on the attention list (`disk_not_compliant`). Record: who follows up.
- **RR-60 Only the root partition is encrypted.** Swap partitions, data partitions and `/boot` stay plaintext;
  hibernation images on an unencrypted swap partition contain memory. Mitigation: the dialogue says so; the
  preflight does not refuse such layouts. Record: whether devices with extra partitions are converted or
  reinstalled.
- **RR-61 Unsupported layouts stay unencrypted.** No separate `/boot` (Ubuntu Desktop's default), xfs, btrfs,
  RAID, no TPM: reinstall remains the path. Mitigation: the reasons are shown per device. Record: the reinstall
  deadline (as RR-52).

Open points (default chosen):

1. Should Paddock prompt the user to restart (desktop notification, login notice) or offer *Restart now*?
   **Default: no** — the administrator informs the user; the portal shows "waiting for the restart". A later
   ticket can add the hint through the existing login-notice mechanism.
2. Should the battery pause be a setting (for example "continue on battery above 50 %")? **Default: no** — fixed
   behaviour, mains only; revisit with lab feedback.
3. Cancel after delivery from the portal (a second signed command)? **Default: no** — `paddockd encrypt-abort`
   at the device while `prepared`; after the init there is nothing to cancel.
4. Should devices without a TPM be convertible to a passphrase-only LUKS (the user chooses a passphrase at the
   conversion boot)? **Default: no** — they would be `tpm_missing` forever and the keyfile in the initrd would be
   the only unlock path.
5. Should the conversion key be its own escrow kind (`luks_conversion_key`) instead of `luks_recovery_key`
   generation 1? **Default: reuse** — the reveal dialog and the runbook work unchanged; generations tell them apart.
6. btrfs root (can shrink online)? **Default: not in M8e** — Ubuntu's default is ext4; open for a later milestone.
7. Should the two throwaway gates run in `make system-test VM=all`? **Default: no** — opt-in through
   `PADDOCK_SYSTEM_VMS` like D-AI (each about an hour); the release regression (PDK-248) runs them once.

## 13. CHANGELOG rule for M8e

Every ticket adds its operator-visible line under `[Unreleased]` in `### Added` or `### Changed` in operator
language, for example "An unencrypted device with a separate /boot can be encrypted in place from the portal:
the recovery key is stored first, the user restarts once and chooses the boot PIN, and the rest is encrypted in
the background." The upgrade note says: server first, then the agents (every change is additive; older agents
ignore `disk.boot_pin_min_length` and never receive `encrypt_disk` because older agents fail it with
`unsupported_type`, which the portal shows as a failed command).
