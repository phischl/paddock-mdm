# Implementierungsplan: M8e — In-place encryption of an installed device (LUKS2 online reencryption after one restart)

Status: Ready for implementation · 2026-10-17, refreshed against `main` on 2026-10-20 (§14) · Author: architect
Basis: ADR 0039 (in-place encryption by LUKS2 online reencryption; supersedes ADR 0038 decision 4); ADR 0038
(unlock modes, `health.disk.boot_separate`); ADR 0037 (signed command with cancel before delivery, transient units
outside the supervisor's cgroup); ADR 0013 (additive protocol changes); ADR 0018 (lists and dialogs); ADR 0024 (no
event type an older server could receive from a newer agent); ADR 0028 (per-device derivations on read paths);
plans M4b (disk encryption, first-boot disk setup, escrow), M4b.1 (keyslot rules), M8d (§3.8 uninstall command
pattern, §3.9 unlock mode, §3.10); lab finding L31; ticket PDK-240.

Binding language: **MUST** / **MUST NOT** / **SHOULD** / **MAY**.

This plan was written against the M8d branch (`origin/M8d-device-lifecycle`, PR #79). M8d is merged (PR #87, with
PDK-231, PDK-232 and PDK-233: unlock mode, `boot_separate`, the deferred message), as are M8x, M8u, M8f, M8h, the
M8d regression fixes (PR #109) and release v0.1.0-alpha.4. The amendment of 2026-10-20 (§14) verified §2 and §5
against `main` at `727fb7c5`, corrected the facts in place (the corrections are listed in §14.2) and amended the
decisions where `main` or the lessons of PR #109 require it. Where §14 and an earlier section disagree, §14 wins.

## 1. Goal

After M8e an organization administrator encrypts an adopted, unencrypted Ubuntu device from the portal: after a
step-up, a typed hostname and a backup acknowledgement, the device prepares itself, the recovery key is escrowed
before a single byte is encrypted, the users of the device see a desktop notification asking for a restart, the
administrator can still cancel from the portal until that restart, the user restarts the device once and chooses
the boot PIN (or none, under `tpm_only`), and the remaining encryption runs in the background while the user works — resumable after a power
cut, with the progress visible on the device page. The result is a device that is indistinguishable from one
installed with the Paddock autoinstall: `compliant`, TPM2 + PIN or TPM2 plus a recovery key, header escrowed.
Paddock never starts the conversion on its own initiative.

## 2. Context (verified 2026-10-17 at M8d `968b03b`; re-verified 2026-10-20 at `main` `727fb7c5`, §14.2)

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
  `cache.DeleteCommand`; since M8d §15.4 the cancel claims the result as `cancelled` in its transaction —
  `UninstallCache.ClaimResult`, 409 when the device reported first —, runs `WithdrawDeviceCommand` and deletes the
  cache entry after the commit: `withdrawUninstallCommand` in `app/uninstall.go`). The in-process background worker
  pattern: `agent/internal/agent/osupdates.go` (`installJobs`, `runInstalls`). The uninstall helper runs from a
  binary copy in `/root/paddock-uninstall/` (`paths.Layout.UninstallBinary()`, `UninstallPlan()`), never below
  `/run`: initramfs-tools mounts `/run` `noexec` (ADR 0037 amendment 2026-10-19, PR #109); before `systemd-run` the
  agent checks the directory with `Deps.NoExec` (`statfs`, `ST_NOEXEC`; `noexec()` in
  `agent/internal/agent/uninstall.go`). The removal waits while `/var/lib/paddock/state/supervisor-upgrade.json`
  exists (`supervisorUpgradeRuns`, bounded by `supervisorpkg.StaleAfter` = 30 min), and no supervisor upgrade starts
  while `state.PendingUninstall` is set (`busy` in `agent/internal/agent/supervisor.go`). The agent's `uninstall`
  handler refuses with `UninstallAccepted{accepted: false, reason}` (`invalid_params`, `revocation_pending`,
  `helper_failed`). Lock and Destroy are never blocked by an uninstall: `Revocations.Request` withdraws an
  undelivered uninstall command and records it as the params `uninstall_cancelled`, `uninstall_command_id` of its one
  `revocation.requested` event (`cancelUninstall` in `app/revocations.go`). Device states on `main`: `pending`,
  `active`, `rejected`, `quarantined`, `retired` (`server/internal/domain/device`).
- **Health.** `health.Report.Disk *protocol.DiskHealth`; `protocol.DiskStates` (closed, ordered); the server keeps
  the whole health JSON in `device_status.health` and derives `disk_state` on read (`queries/device.sql`);
  `app.diskHealth` rejects an unknown state; the attention view `attention_condition` (last recreated by migration
  `00064_attention_config_behind.sql`; six columns `kind, device_id, hostname, since, detail, id`, the last a
  per-row key such as `'uninstall_pending:' || d.id::text`) lists `disk_not_compliant` for state ≠ `compliant`.
- **Events.** `pkg/protocol.EventTypes` (closed); `app/devicereports.go::eventCodes`, `eventEntry`;
  `audit.deviceEventParams` allow list (`codes.go:191`; it already contains `stage`, `reason`, `volume`,
  `command_id`, `mode`).
- **Bundle.** M8d decision 46: `bundle.DiskSpec{UnlockMode}` (schema v2) from `EffectiveUnlockMode`.
- **Portal.** `components/DiskEncryptionCard.vue` (state, volumes, reveal/download after step-up; PDK-233 adds the
  `notEncrypted.*` alerts), `lib/disk.ts`, `lib/status.ts::encryptionStatus`, `lib/stepUp.ts`
  (`startStepUp`/`resumeStepUp`, used by `lib/deviceDetailPage.ts`), `components/ConfirmDialog.vue`
  (`requireTypedText`), M8d's `UninstallDialog.vue` pattern; `components/DangerZone.vue` holds the Lock, Destroy and
  uninstall rows (`devices.danger.lock.*`, `devices.danger.destroy.*`, `devices.danger.uninstall.*`).
- **Gates.** `test/system/autoinstall.go::buildAIVM(t, root, iso, userData)` (throwaway VM from an ISO, EFI +
  Secure Boot + TPM 2.0, a 40 960 MB dynamic VDI in the VirtualBox machine folder; name and SSH port are the
  constants `aiVMName`, `aiSSHPort`), the ISOs are the Ubuntu **Desktop** images (`PADDOCK_SYSTEM_ISO_2604`,
  default `~/Downloads/ubuntu-26.04.1-desktop-amd64.iso`), `test/vms/virtualbox/autoinstall/autoinstall.yaml.tmpl`
  (the test VMs' user-data: `storage.layout.name: lvm` with a LUKS password, SSH access), `VM.PowerOff`, `Shot`,
  `RebootWithPIN`, `Keyslots`, `Opens`, `Device.AnswerDiskSetup`, `Device.PrepareDisk`, `Device.WaitDisk`,
  `WaitEvent`, `Health`. `make system-test VM=<vm|all> [T=<regex>]` sets `PADDOCK_SYSTEM_VMS` from `VM`;
  `forEachVM` runs a gate as parallel subtests on every VM of the run with a shared `vmGroup`
  (`test/system/parallel.go`: `Together`, `Share`, `AfterAll`); every gate retracts the release it published
  (`retractRelease`, `test/system/retract.go`). Gate S-DU1 (`TestDiskUnlockModeTPMOnly`) runs on the throwaway VM
  `paddock-ai-2604` only and had not been run on a VM when this amendment was written.
- **Migrations.** Last on `main`: `00065_device_name.sql` (M8d `00053`–`00063`, M8f `00064`, M8h `00065`). M8e's
  migration is `00066_disk_conversion.sql`.

## 3. Binding decisions

### 3.1 Vocabulary

- **Conversion**: one in-place encryption of one device, from the request to `completed`, `failed` or
  `cancelled`. **Conversion key**: the random passphrase of the first LUKS keyslot; it is the device's install
  passphrase from then on. **Init step**: what the dracut unit does at the conversion boot. **Background phase**:
  the reencryption by `paddockd encrypt-resume`. **Layouts**: `lvm` (root LV in one VG on one PV on one partition)
  and `plain` (ext4 directly on one partition).
- Phases of a conversion (server and agent use the same words): `requested` (command issued, not delivered),
  `prepared` (escrow stored, initrd built, waiting for the restart), `encrypting` (the init step succeeded, the
  background phase runs or is paused), `completed`, `failed`, `cancelled` (the command was cancelled before
  delivery, or the device aborted the conversion on an administrator's or an operator's request before the
  restart).

### 3.2 Eligibility and preflight (agent; PDK-242)

1. New package `agent/internal/encrypt` with

   ```go
   // Preflight reports whether the device's disk can be encrypted in place (ADR 0039 decision 2). It reads the layout
   // with findmnt, lsblk, blkid and lvm, asks dpkg-query for dracut and, without dracut, apt-get -s for what the
   // switch would remove (plan §14.4 decision 34), and changes nothing.
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
   (`/sys/module/dm_crypt` absent and `modprobe dm_crypt` fails; checked at preparation only, decision 7),
   `cleanup_pending` (`state.Conversion.CleanupPending` is true: an initrd still carries the module of an
   abandoned conversion, invariant I3 of §14.10; reported alone, the other checks are skipped).
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
   - after completion the existing flow continues (`watch` records the keyslots it sees first, the install
     passphrase is the conversion key, `step` enrolls the recovery key, escrows the header) with one hold
     (invariant I1 of §14.10; §14.5 decision 36, review finding B1′): while `state.Conversion` exists and
     `!state.Conversion.InitrdRegenerated`,
     `step` does not remove the conversion key's keyslot or the install passphrase and the state reported is at
     most `escrow_pending`, never `compliant` — the initrd still carries the Paddock module and the key as the
     only unlock path until decision 20 has replaced it. Once `InitrdRegenerated` is true the removal of the
     conversion key's keyslot follows the M4b rule (the keyslot of the unlock mode exists).
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
   // TypeEncryptDiskAbort cancels a conversion the device has received but not executed at a restart (§3.9).
   const TypeEncryptDiskAbort = "encrypt_disk_abort" // lifetime 7 days
   // EncryptDiskAbortParams name the conversion to abort.
   type EncryptDiskAbortParams struct {
       ConversionID string `json:"conversion_id"`
   }
   // EncryptDiskAbortResult is the command result of encrypt_disk_abort.
   type EncryptDiskAbortResult struct {
       Aborted bool   `json:"aborted"`
       Reason  string `json:"reason,omitempty"` // when not aborted: invalid_params, unknown_conversion, not_abortable
   }
   ```

6. Migration `server/migrations/paddock/00066_disk_conversion.sql` (the next free number after M8h's `00065`):

   ```sql
   CREATE TABLE device_disk_conversion (
     id uuid PRIMARY KEY, organization_id uuid NOT NULL, device_id uuid NOT NULL,
     command_id uuid NOT NULL REFERENCES device_command (id),
     requested_at timestamptz NOT NULL DEFAULT now(), requested_by uuid, reason text NOT NULL,
     phase text NOT NULL CHECK (phase IN ('requested','prepared','encrypting','completed','failed','cancelled')),
     layout text CHECK (layout IN ('lvm','plain')), luks_uuid uuid, data_bytes bigint,
     failure_stage text, failure_reason text, phase_at timestamptz NOT NULL DEFAULT now(), finished_at timestamptz,
     abort_command_id uuid REFERENCES device_command (id), abort_refused_reason text,
     FOREIGN KEY (organization_id, device_id) REFERENCES device (organization_id, id)
   );
   CREATE INDEX device_disk_conversion_device_idx ON device_disk_conversion (organization_id, device_id, requested_at DESC);
   CREATE UNIQUE INDEX device_disk_conversion_open_idx ON device_disk_conversion (device_id)
     WHERE phase IN ('requested','prepared','encrypting');
   -- ENABLE and FORCE ROW LEVEL SECURITY; policy on current_setting('paddock.org_id')::uuid; paddock_api SELECT,
   -- INSERT, UPDATE; paddock_worker SELECT, UPDATE (the event claim).
   ```

   The attention view is recreated (`CREATE OR REPLACE VIEW attention_condition WITH (security_invoker = true)`,
   every other branch, the columns and the grants exactly as in `00064_attention_config_behind.sql`) with

   ```sql
   UNION ALL
   SELECT 'disk_conversion_failed', d.id, d.hostname, c.phase_at,
     coalesce(c.failure_stage, '') || ':' || coalesce(c.failure_reason, ''), 'disk_conversion_failed:' || c.id::text
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
8. `POST /api/v1/devices/{id}/encrypt/cancel` (`x-paddock-audit: device.encrypt_cancelled`, `ActionSpec{AllowedRoles:
   RolesAdmin, RequiresStepUp: true}`, body `DeviceEncryptCancelRequest{confirm_hostname (required)}`, 200
   `Device`, 403 `step_up_required|forbidden`, 404, 409 `invalid_state`, 422 `invalid_request`), use case
   `app.DiskConversions.Cancel`, params `hostname`, `command_id`, `conversion_id`, `mode`:
   - no open conversion → 409 (detail `no conversion is open`); `confirm_hostname` mismatch → 422;
   - phase `requested` and the `encrypt_disk` command's status `pending`, `failed` or `expired` → `mode:
     command_cancelled`: the command becomes `cancelled` (as M8d decision 38, same cache removal) and the row
     `cancelled` (`finished_at = now()`);
   - phase `requested` with the command `delivered` or `succeeded`, or phase `prepared`, and no open abort
     (`abort_command_id IS NULL` or that command `failed`/`expired`) → `mode: abort_sent`: issues the command
     `encrypt_disk_abort` with params `{conversion_id}` (decision 5), stores `abort_command_id`, clears
     `abort_refused_reason`; the row keeps its phase until the device answers (decision 9);
   - an open abort command (`pending` or `delivered`) → 409 (detail `a cancellation is already on its way`);
   - phase `encrypting` → 409 (detail `the device already started the encryption; it cannot be cancelled`);
     `completed`, `failed`, `cancelled` → 409 (detail `no conversion is open`).
9. Device events (`pkg/protocol`, closed set gains five; each carries `conversion_id`):

   ```go
   EventDiskConversionPrepared  = "disk.conversion_prepared"  // data: {conversion_id, layout, volume, data_bytes}
   EventDiskConversionStarted   = "disk.conversion_started"   // data: {conversion_id, volume, init_s, init_result}
   //                                                           init_result: ok | <stage>:<reason> | unknown (dec. 18)
   EventDiskConversionCompleted = "disk.conversion_completed" // data: {conversion_id, volume, data_bytes, duration_s}
   EventDiskConversionFailed    = "disk.conversion_failed"    // data: {conversion_id, stage, reason, volume}
   EventDiskConversionAborted   = "disk.conversion_aborted"   // data: {conversion_id, by}  by: admin | operator
   ```

   (the closed set gains five.) `eventCodes` maps them to `device.disk_conversion_prepared | _started |
   _completed | _failed | _aborted`; `audit.deviceEventParams` gains `conversion_id`, `layout`, `data_bytes`,
   `duration_s`, `init_s`, `init_result`, `by`. The claim of `eventEntry` updates the row named by `conversion_id`
   (query
   `UpdateDiskConversionPhase`): `prepared` sets `layout`, `luks_uuid`, `data_bytes`; `started` sets
   `encrypting` from `requested`, `prepared`, `failed` or `cancelled` (the device adopted a conversion whose
   initrd converted the disk, plan §14.10 I2; refused and audited only when another row of the device is open,
   `device_disk_conversion_open_idx`), clearing `failure_stage`, `failure_reason` and `finished_at`; `completed` sets
   `completed` and `finished_at`; `failed` sets `failed`, `failure_stage`,
   `failure_reason`, `finished_at`; `aborted` sets `cancelled` and `finished_at`. The result of an
   `encrypt_disk_abort` command with `{aborted: false, reason}` stores `abort_refused_reason = reason` and
   leaves the phase (the command-result path of `app/commands.go`, keyed on `abort_command_id`). An event for a row of another device
   or an unknown row is recorded as an audit event and changes no row. The command result `{accepted: false}` sets
   the row `failed` with stage `preflight` and the result's reason (in the existing command-result path of
   `app/commands.go`, keyed on the command id). A `failed` row with stage `preflight`, `prepare` or `init` leaves
   the device unencrypted; a new request is possible at once.
10. `Device` (API) gains `disk_conversion` (nullable `DeviceDiskConversion{id, phase, requested_at, command_id,
    command_status, layout, luks_uuid, data_bytes, done_bytes, eta_s, paused_reason, progress_at, failure_stage,
    failure_reason, finished_at, reason, abort_command_id, abort_command_status, abort_refused_reason}`): the latest row, with `done_bytes`, `eta_s`, `paused_reason`,
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
    the first line of the tool's stderr, cut at 200 runes) and emits `disk.conversion_failed`; a failure at step 7
    or later (the module files exist) first runs the cleanup of `encrypt.Abort` (decision 14: the module
    directory, `91-paddock-encrypt.conf`, `/var/lib/paddock/encrypt/`, the conversion key, the disk-setup files,
    `dracut -f --regenerate-all`) so that a failed preparation — an `initrd_incomplete` in particular — can never
    convert the disk at the next boot (review finding N2) — under invariant I3 of §14.10: `CleanupPending` until
    `lsinitrd` of every installed initrd shows no `paddock-encrypt`, retried at every full pass:
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
    6. Dracut (as amended by §14.4 decisions 32 and 33): when `dpkg-query -W -f='${db:Status-Status}' dracut`
       does not print `installed`, simulate with `apt-get -s -o Debug::NoLocking=true install dracut` (the `Remv `
       packages MUST all be `initramfs-tools`, `initramfs-tools-core`, `initramfs-tools-bin` or `brltty`, else
       reason `dracut_removes:<packages>` and nothing is installed), then `apt-get install -y dracut` with
       `DEBIAN_FRONTEND=noninteractive`, bounded 15 min, killed with its process group (the `DpkgWithin` path of
       `reconcile.OS`); failure → reason `dracut_install_failed`; afterwards the packages that really left
       (`dpkg-query -W -f='${Package}\n'` before and after) MUST equal the simulated set, else reason
       `dracut_removed_differs:<packages>`. Then write
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
    --regenerate-all` (all of this is `encrypt.Abort(ctx, deps)`, shared with decision 27), sets
    `state.Conversion.Phase = "cancelled"` and emits `disk.conversion_aborted{conversion_id, by: operator}`
    through the running agent's spool (the subcommand writes the event with the next `event_seq` into the spool
    file under the agent's lock, as `paddockd uninstall` does in M8d decision 40 step 10). It refuses in any
    other phase (exit 2, message on stderr). `encrypt.Abort` runs under invariant I3 of §14.10 in this order
    (review round 4, X1): (1) remove only the module directory and `91-paddock-encrypt.conf`; (2) `dracut -f
    --regenerate-all`; (3) `lsinitrd` of the initrd of every installed kernel (`/boot/initrd.img-<v>` for every
    `<v>` that has `/boot/vmlinuz-<v>` or `/lib/modules/<v>` — every GRUB entry) must show no `paddock-encrypt`;
    (4) only after (3) passed: delete the conversion key,
    `plan.json`, `plan.env`, `test-hooks` and the two disk-setup files, clear `CleanupPending`. While (2) or (3)
    fails, `state.Conversion.CleanupPending` stays true and the agent re-runs (1)–(3) at every full pass — the
    key and the plan stay on disk, because an initrd that still carries the module converts the disk at the next
    boot and the device then needs them (I2 adoption, decision 18). The state is cleared only once (4) ran. It
    never runs while the partition is LUKS (I1; decision 27 refuses with `not_abortable`).

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

18. At every start — before decision 13 re-queues a `preparing` job, before the cleanup retries of I3 and before
    anything else of this plan — and at every full pass, while `state.Conversion != nil` (any phase until the
    state is cleared; a device without a conversion is never touched, review round 4 Y2), the agent reads
    `/run/paddock/encrypt-boot.env` if it exists (and removes it afterwards) and runs `cryptsetup isLuks
    <partition>` on the partition of `plan.json`. The disk decides, not the file (invariant I2, §14.10):
    - The partition is LUKS (the file says `ok`, or it says `failed`/`skipped` after the header was written, or
      the file is missing because the device booted through the module once more, or a reboot during or after
      step 8 of decision 13 — or during a cleanup with the module still in an initrd — converted the disk): the
      conversion is **adopted**. When the phase is not `encrypting` or `completed`: set `encrypting`, `StartedAt =
      now`, drop a queued `preparing` job and clear `CleanupPending`, emit `disk.conversion_started{conversion_id,
      volume, init_s, init_result}` with `init_result` = `ok` or `<stage>:<reason>` from the file (`unknown`
      without a file; cut at 200 runes). Then, before anything else: when the module directory or
      `91-paddock-encrypt.conf` is missing (a cleanup removed them), rewrite both from the embedded copy, render
      `plan.env` from `plan.json` when it is missing, run `dracut -f --regenerate-all` and verify with `lsinitrd`
      that the initrd of every installed kernel lists `paddock-encrypt` (I1: a kernel update must keep booting the
      device); a failure is logged and retried at the next full pass. No cleanup of any kind (I1); then
      decision 20 (initrd regeneration) and decision 21 (resume). The device booted on dm-crypt through the
      module; an init failure is a log line and the event param, never a `failed` phase.
    - The partition is not LUKS and the file says `failed` or `skipped`: set `failed`, stage `init`, the reason;
      emit `disk.conversion_failed`; run the cleanup of decision 14 in its order (module directory and conf first,
      regenerate, verify the initrd of every installed kernel, only then the key, the plan files and the
      disk-setup files) under invariant I3: `state.Conversion.CleanupPending = true` until the verification
      passed; retried at every full pass; the state is not cleared before.
    - The partition is not LUKS and the file is missing: a `prepared` conversion stays `prepared` (the user has
      not restarted yet, or the device booted from an initrd without the module).
    Without the file (the device booted from an initrd without the module, or the user has not restarted yet), a
    `prepared` conversion stays `prepared`; an `encrypting` one continues with decision 21.
19. Dev-only test hooks: the embedded script honours `paddock.encrypt.testdelay=<stage>:<seconds>` on the kernel
    command line (`init`: sleep after the line `shrink done`, before stage 5; `open`: sleep after the line `init
    done`, before stage 6; the `isLuks` path of stage 3 never sleeps) only when `/etc/paddock/encrypt-test` exists in
    the initrd; the agent writes `/var/lib/paddock/encrypt/test-hooks` at preparation only when
    `buildinfo.Dev` is set (the `paddock_dev` tag). A release build never installs the marker; `make agent-release`
    and `make release-packages` refuse the tag as they do today.
20. Initrd regeneration after the keyslot of the unlock mode exists (checked at every full pass while
    `state.Conversion.Phase` is `encrypting` **or `completed`** and `!state.Conversion.InitrdRegenerated` — the
    reencryption may finish before the user chose the PIN, review finding B1′): when `luks.Dump` shows a
    `tpm2+pin` or `tpm2` keyslot, the agent, in this order (invariant I1, §14.10: the module leaves the initrd
    only together with a crypttab line that opens the volume with the TPM keyslot): (1) appends `<mapping>
    UUID=<luks uuid> none luks,tpm2-device=auto` to `/etc/crypttab` (unless a line with that UUID exists); (2)
    removes `91-paddock-encrypt.conf` and `/usr/lib/dracut/modules.d/99paddock-encrypt/`; (3) runs `dracut -f
    --regenerate-all` (15 min bound); (4) verifies with `lsinitrd` that the initrd of **every installed kernel**
    (`/boot/initrd.img-<v>` for every `<v>` that has `/boot/vmlinuz-<v>` or `/lib/modules/<v>`, so that every GRUB
    entry is checked) contains `etc/crypttab` with the UUID and no
    `paddock-encrypt` (I3); (5) only then removes `plan.env`, `plan.json`
    and `test-hooks` from `/var/lib/paddock/encrypt/` and sets `InitrdRegenerated = true`. A failure at (3) or
    (4) is logged and retried at the next full pass — from (2) on, by re-running (2) to (4) — while the device
    keeps booting with the module (the keyfile opens the disk; a kernel update in between builds an initrd that
    unlocks through the crypttab line of (1)). The conversion key stays on disk until the `luks` reconciler
    removes it after `InitrdRegenerated` (decision 3). Dev builds remove `test-hooks` here too.
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
    **only** `progress.json` and `result.json` (`plan.env`, `plan.json`, the module and the conf stay until
    decision 20 has verified the regenerated initrds — invariant I1, §14.10; review finding B-1) — the `luks`
    reconciler now sees a LUKS2 root without the `reencrypt` keyslot, the install passphrase and the disk-setup
    marker (removed by the PIN dialogue, or re-armed by decision 52 while the PIN is skipped) and runs the M4b flow
    under the hold of decision 3; `failed` → emit `disk.conversion_failed{stage: resume, reason}`, count
    `ResumeFailures`; up to 3 relaunches per boot, then wait for the next boot (the device keeps working on
    dm-crypt; the header stays recoverable). `state.Conversion` is cleared once `InitrdRegenerated` is true
    **and** the device reports `compliant` or `escrow_pending` for the first time after `completed` (decision 3's
    hold: the conversion keyslot stays until the initrd no longer needs it).
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
    hardware facts (M8d) rounded to 10 minutes, or `.check.durationUnknown`; `.check.initramfsSwitch` when
    `disk.conversion.initramfs` is `initramfs-tools`, §14.4), the reason field (2–500), the typed hostname
    (`requireTypedText`),
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

### 3.9 Cancel after delivery and the restart notification (maintainer decisions 2026-10-17; PDK-243, PDK-246, PDK-247)

27. Command handler `encryptDiskAbortCommand` (`agent/internal/agent/encrypt.go`) for `encrypt_disk_abort`:
    params without a UUID → `failed {aborted: false, reason: invalid_params}`; no `state.Conversion` or another
    `ID` → `failed {reason: unknown_conversion}`; phase `encrypting`, `completed`, `failed` or `cancelled` →
    `failed {reason: not_abortable}`; phase `preparing` → sets `state.Conversion.AbortRequested = true` and
    returns `Deferred` — the conversion worker checks the flag before every step of decision 13 and, when set,
    runs `encrypt.Abort` instead of the next step and posts `succeeded {aborted: true}`; phase `prepared` → runs
    `encrypt.Abort` at once and returns `succeeded {aborted: true}`. `encrypt.Abort` emits
    `disk.conversion_aborted{conversion_id, by: admin}` when called from the handler. An abort that arrives after
    the restart (the device is `encrypting`) is refused with `not_abortable`; the device never undoes an
    initialised header.
28. Restart notification (`agent/internal/encrypt/notify.go`): while `state.Conversion.Phase == "prepared"`, the
    agent notifies every graphical user session — `sessions.List` entries with `Class` `user` whose
    `loginctl show-session <id> -p Type` is `wayland` or `x11` (the `Type` property is added to `sessions.Session`)
    — once when the session is first seen with the conversion `prepared` (this covers a login and the agent's
    start) and again every 4 hours per session (`state.Conversion.Notified map[string]time.Time` keyed by the
    session ID, pruned with the session). It runs, bounded by 30 s:

    ```
    systemd-run --quiet --wait --collect --uid=<uid> --gid=<gid> --setenv=XDG_RUNTIME_DIR=/run/user/<uid>
      --unit=paddock-notify-<session id>-<unix time> --
      busctl --user call org.freedesktop.Notifications /org/freedesktop/Notifications org.freedesktop.Notifications
        Notify susssasa{sv}i Paddock 0 drive-harddisk "<summary>" "<body>" 0 1 urgency y 1 0
    ```

    (`uid` and `gid` from `sessions.Session.UID` and the user's primary group; `expire_timeout 0` keeps the
    notification in GNOME's list until the user dismisses it; `urgency` 1 = normal.) The summary and the body are
    the texts of §6.7 in the device's language: German when `LANG` in `/etc/default/locale` starts with `de`,
    English otherwise; the body's PIN sentence is appended only under unlock mode `tpm_pin`. Without a graphical
    session nothing runs; a non-zero exit or timeout is logged at info level once per session and 4 hours, never
    reported as an event; the agent never restarts the device. The notification stops with the phase.

## 4. Non-goals

- Layouts without a separate `/boot`, carving a `/boot` out of free space, moving partitions, xfs, btrfs, ZFS, md
  RAID, several physical volumes, BIOS boot, devices without TPM 2.0, LUKS1 or already encrypted (`unmanaged`)
  devices: all stay "reinstall needed" (ADR 0039 decision 2).
- Encrypting other volumes than the root volume (swap partitions, data partitions): never in M8e.
- Restarting the device from Paddock or scheduling the restart: the notification of decision 28 asks; the
  restart stays the user's action.
- Cancelling a conversion after the restart: once the header exists there is nothing to cancel (decision 27).
- A GRUB password, Plymouth for dracut on a device that switched from initramfs-tools, kernel command line
  measurement (RR-44 stands).
- Removing Paddock from a device while a conversion is active: refused (§14.5 decision 36), not supported.
- Any change to `agent/internal/revoke/`, `agent/cmd/paddock-revoke/`, `pkg/revocation/`, the device API path
  version, `docs/adr/0001…0041` (amendments are the architect's), `server/migrations/paddock/00001…00065`.
- Decryption (reverting a conversion): never.

## 5. Affected files

| Path | Action | Purpose |
| --- | --- | --- |
| `docs/adr/0039-in-place-encryption-online-reencryption.md`, `docs/adr/0038-…` (amendment) | new / amended (done) | decisions |
| `server/migrations/paddock/00066_disk_conversion.sql` | new | §3.3 decision 6 |
| `server/internal/adapters/postgres/queries/disk_conversion.sql` (new), `device.sql`, `command.sql`, `attention.sql`; `pgstore` (gen) | new / change | queries |
| `server/internal/domain/audit/codes.go`, `docs/compliance/audit-codes.md` (gen), `server/web/src/lib/auditCodes.gen.ts` (gen) | change | §6.5 |
| `pkg/command/command.go`, `pkg/bundle/bundle.go`, `pkg/protocol/types.go`, `api/openapi/device.yaml` | change | §6.2, §6.3, decision 5, 11 |
| `server/internal/app/diskconversion.go` (new), `app/devices.go`, `app/disk.go`, `app/devicereports.go`, `app/commands.go`, `app/attention.go`, `app/uninstall.go`, `app/revocations.go`; `server/internal/compiler/disk.go` | new / change | use cases, events, bundle, the interactions of §14.5 |
| `server/internal/transport/http/admin/handlers_devices.go`, `handlers.go` (`privileged`), `spec_test.go`; `api/openapi/admin.yaml`; generated Go/TS | change | §6.1 |
| `agent/internal/encrypt/` (new: `preflight.go`, `prepare.go`, `resume.go`, `plan.go`, `os.go`, `dracut/module-setup.sh`, `dracut/paddock-encrypt-init.sh`, `dracut/paddock-encrypt-init.service`, `embed.go`), `agent/internal/luks/luks.go`, `agent/internal/reconcile/luks.go`, `agent/internal/agent/{agent,encrypt,uninstall,supervisor,revocation}.go` (new `encrypt.go`), `agent/internal/sessions/sessions.go`, `agent/internal/state/state.go`, `agent/internal/health/health.go` (no change expected), `agent/cmd/paddockd/main.go`, `agent/internal/buildinfo/` | new / change | §3.2, §3.4–§3.6, §14.3–§14.5 |
| `server/web/src/components/{DiskEncryptionCard,EncryptDiskDialog,UninstallDialog,DangerZone}.vue` (new dialog), `lib/{disk,status,devices,deviceHealth}.ts`, `views/{Devices,Attention}.vue`, `locales/{en,de}.json` | change / new | §3.7, §14.5 |
| `test/acceptance/diskconversion_test.go` (new), `test/acceptance/devicesim`; `test/system/{autoinstall,encrypt_test,disk}.go`, `test/vms/virtualbox/autoinstall/{unencrypted-lvm,unencrypted-plain}.yaml.tmpl` (new) | new / change | §9 |
| `docs/operations/in-place-encryption.md` (new), `docs/operations/{disk-recovery,autoinstall}.md`, `docs/architecture.md`, `docs/compliance/{residual-risks,glossary-de}.md`, `CHANGELOG.md` | new / change | §3.8 |

MUST NOT be touched: `agent/internal/revoke/`, `agent/cmd/paddock-revoke/`, `pkg/revocation/`,
`packaging/nfpm/paddock-revoke.yaml`, `server/migrations/paddock/00001…00065`, `docs/adr/0001…0041` (amendments
are the architect's), `deploy/compose/compose.prod.yaml`, `deploy/compose/compose.lab.yaml`, the device API path
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
                       failure_stage: string nullable, failure_reason: string nullable, finished_at: date-time nullable,
                       abort_command_id: uuid nullable, abort_command_status: string nullable, abort_refused_reason:
                       string nullable,
                       active: boolean}  # §14.5 decision 36: phase in requested|prepared|encrypting, or the last
                                         # health disk.state = encrypting, or completed with health ≠ compliant
DeviceEncryptRequest: {confirm_hostname (required), reason (required, 2–500), backup_confirmed (boolean, required)}
DeviceEncryptCancelRequest: {confirm_hostname (required)}
DiskEncryption:       + conversion (DeviceDiskConversion, nullable)
DiskState / DiskHealth: + conversion (DiskConversionHealth); state enum + encrypting
DiskConversionHealth: {eligible: boolean, reasons: [string], release: string, layout: string, phase: string, data_bytes, done_bytes: integer int64,
                       eta_s: integer, paused_reason: string, failure_stage: string, failure_reason: string, updated_at:
                       date-time,
                       initramfs: string (dracut | initramfs-tools), initramfs_removes: [string],  # §14.4 decision 34
                       key_on_boot: boolean}  # §14.6 decision 52
AttentionKind:        + disk_conversion_failed

# operations
POST /api/v1/devices/{id}/encrypt         x-paddock-audit: device.encrypt_requested  200 Device · 403 step_up_required|forbidden · 404 · 409 invalid_state · 422 invalid_request
POST /api/v1/devices/{id}/encrypt/cancel  x-paddock-audit: device.encrypt_cancelled  200 Device · 403 step_up_required|forbidden · 404 · 409 invalid_state · 422 invalid_request
GET  /api/v1/devices                      filter disk_state accepts encrypting
```

Both `POST` routes go into `privileged`; `TestOpenAPISpec` MUST pass unchanged in its assertions.

### 6.2 Device protocol (`pkg/protocol/types.go`, `api/openapi/device.yaml`; additive, ADR 0013)

```go
// DiskHealth gains:
Conversion *DiskConversion `json:"conversion,omitempty"` // §3.2 decision 3
// DiskStates gains, directly after DiskNotEncrypted:
DiskEncrypting = "encrypting"
// Event types (closed set gains five; data as in §3.3 decision 9):
EventDiskConversionPrepared  = "disk.conversion_prepared"
EventDiskConversionStarted   = "disk.conversion_started"
EventDiskConversionCompleted = "disk.conversion_completed"
EventDiskConversionFailed    = "disk.conversion_failed"
EventDiskConversionAborted   = "disk.conversion_aborted"
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
    AbortRequested       bool                 `json:"abort_requested,omitempty"` // decision 27, while preparing
    Notified             map[string]time.Time `json:"notified,omitempty"`        // decision 28, by session ID
    CleanupPending       bool                 `json:"cleanup_pending,omitempty"` // §14.10 I3: cleanup unfinished
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
TimeoutStartSec=infinity

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
| `device.encrypt_cancelled` | An organization administrator cancelled an in-place encryption with a step-up: the undelivered command was withdrawn, or the device was sent a signed abort that it executes only before its restart. | `hostname`, `command_id`, `conversion_id`, `mode` (command_cancelled, abort_sent) |
| `device.disk_conversion_prepared` | The device escrowed the conversion key and built the initrd for its in-place encryption; it waits for a restart (actor: the device). | `conversion_id`, `layout`, `volume`, `data_bytes` |
| `device.disk_conversion_started` | The device initialised LUKS2 on its root partition at the restart and encrypts the remaining data in the background (actor: the device). | `conversion_id`, `volume`, `init_s`, `init_result` |
| `device.disk_conversion_completed` | The device finished encrypting its root partition; the recovery key, the TPM unlock and the header escrow follow as for a newly installed device (actor: the device). | `conversion_id`, `volume`, `data_bytes`, `duration_s` |
| `device.disk_conversion_failed` | The in-place encryption of a device failed or was skipped at the named stage; stages preflight, prepare and init leave the device unencrypted, stage resume leaves it bootable with the encryption unfinished (actor: the device). | `conversion_id`, `stage`, `reason`, `volume` |
| `device.disk_conversion_aborted` | The device abandoned a prepared in-place encryption before its restart on an administrator's cancel from the portal or an operator's command at the device; the disk is unchanged and the device unencrypted (actor: the device). | `conversion_id`, `by` |

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
| `devices.disk.convert.check.initramfsSwitch` | The device switches its early-boot system from initramfs-tools to dracut. The device reports that this removes the packages {packages} — initramfs-tools itself and, where listed, brltty, the console braille support for blind users — and replaces the graphical boot splash by a text console. | Das Gerät wechselt sein Frühstartsystem von initramfs-tools zu dracut. Das Gerät meldet, dass dabei die Pakete {packages} entfernt werden — initramfs-tools selbst und, sofern aufgeführt, brltty, die Braille-Unterstützung auf der Konsole für blinde Benutzer — und der grafische Startbildschirm wird durch eine Textkonsole ersetzt. |
| `devices.disk.convert.check.initramfsSwitchUnknown` | The device switches its early-boot system from initramfs-tools to dracut; it could not report which packages leave with initramfs-tools (brltty, the console braille support for blind users, usually does). The device checks this again before it prepares itself. The graphical boot splash is replaced by a text console. | Das Gerät wechselt sein Frühstartsystem von initramfs-tools zu dracut; es konnte nicht melden, welche Pakete mit initramfs-tools entfernt werden (üblicherweise brltty, die Braille-Unterstützung auf der Konsole für blinde Benutzer). Das Gerät prüft dies erneut, bevor es sich vorbereitet. Der grafische Startbildschirm wird durch eine Textkonsole ersetzt. |
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
| `devices.disk.convert.reasons.cleanup_pending` | the device is still removing an abandoned encryption from its boot files; try again after its next check-in | das Gerät entfernt noch eine abgebrochene Verschlüsselung aus seinen Startdateien; nach dem nächsten Check-in erneut versuchen |
| `devices.disk.convert.cancel.label` | Cancel encryption | Verschlüsselung abbrechen |
| `devices.disk.convert.cancel.title` | Cancel the encryption of {hostname} | Verschlüsselung von {hostname} abbrechen |
| `devices.disk.convert.cancel.confirm` | Possible until the device restarts. If the device has already prepared itself, it receives a signed cancellation at its next check-in and discards the preparation; the stored recovery key stays in Paddock. Type the hostname to confirm. | Möglich, bis das Gerät neu startet. Hat sich das Gerät bereits vorbereitet, erhält es beim nächsten Check-in einen signierten Abbruch und verwirft die Vorbereitung; der hinterlegte Wiederherstellungsschlüssel bleibt in Paddock. Geben Sie den Hostnamen zur Bestätigung ein. |
| `devices.disk.convert.cancel.confirmLabel` | Cancel encryption | Verschlüsselung abbrechen |
| `devices.disk.convert.cancelled` | Encryption cancelled. | Verschlüsselung abgebrochen. |
| `devices.disk.convert.cancelSent` | Cancellation sent {at}; the device confirms it at its next check-in unless it has already restarted. | Abbruch gesendet {at}; das Gerät bestätigt ihn beim nächsten Check-in, sofern es nicht bereits neu gestartet hat. |
| `devices.disk.convert.cancelRefused` | The device refused the cancellation: {reason}. | Das Gerät hat den Abbruch abgelehnt: {reason}. |
| `devices.disk.convert.abortReasons.not_abortable` | it had already restarted and started the encryption | es hatte bereits neu gestartet und die Verschlüsselung begonnen |
| `devices.disk.convert.abortReasons.unknown_conversion` | it knows no such request | es kennt keine solche Anforderung |
| `devices.disk.convert.phases.cancelled` | Encryption cancelled on {at}; the disk is unchanged. | Verschlüsselung am {at} abgebrochen; die Festplatte ist unverändert. |
| `problems.conversion_not_cancellable` | The device already started the encryption; it cannot be cancelled. | Das Gerät hat die Verschlüsselung bereits begonnen; sie kann nicht abgebrochen werden. |
| `attention.kinds.disk_conversion_failed` | In-place encryption failed | Nachträgliche Verschlüsselung fehlgeschlagen |
| `devices.disk.notEncrypted.reinstall` | (unchanged) | (unverändert) |

`devices.disk.notEncrypted.conversionPlanned` is removed from both catalogs. The first revealed generation of the
recovery key on a converted device is the conversion key; the reveal dialog is unchanged.

### 6.7 Desktop notification texts (binding; plain text, shown by the agent, decision 28)

| Part | English (`LANG` not `de*`) | German (`LANG` = `de*`) |
| --- | --- | --- |
| summary | Disk encryption is ready — please restart | Festplattenverschlüsselung bereit — bitte neu starten |
| body | Your IT department has switched on disk encryption for this device. It starts at the next restart, which takes a few minutes longer than usual. Save your work and restart when it suits you; keep the device on mains power during the restart. | Ihre IT-Abteilung hat die Festplattenverschlüsselung für dieses Gerät eingeschaltet. Sie beginnt beim nächsten Neustart, der einige Minuten länger dauert als üblich. Speichern Sie Ihre Arbeit und starten Sie neu, wenn es Ihnen passt; lassen Sie das Gerät während des Neustarts am Netzteil. |
| body, appended under `tpm_pin` | At the restart you will be asked to choose a boot PIN that you type every time the device starts. | Beim Neustart werden Sie gebeten, eine Boot-PIN zu wählen, die Sie bei jedem Start des Geräts eingeben. |

## 7. Host and operator notes (binding figures for the documents)

- The init step takes seconds to a few minutes (`e2fsck -f` of the root file system plus the move of 32 MiB);
  the background phase runs at the disk's sequential speed minus the idle I/O class, typically 100–300 MB/s with
  AES-NI: about 1 hour per 500 GB. A restart during the background phase costs nothing but the resume.
- The conversion key is escrowed as recovery-key generation 1 and lies in the initrd on `/boot` until the TPM
  keyslot exists and the initrd is regenerated (minutes after the conversion boot when the PIN is set at once;
  until the user completes the dialogue otherwise); the data is partly plaintext until `completed`.
- On a device that had initramfs-tools (every 24.04, a 26.04 upgraded in place) the switch to dracut is
  permanent; initramfs-tools and `brltty` are removed; kernel updates build their initrd with dracut from then
  on; the Plymouth splash is gone (as on autoinstalled 24.04 devices).
- A failed conversion at stage `preflight`, `prepare` or `init` leaves an unencrypted device and can be requested
  again at once; at stage `resume` the device works on dm-crypt and the helper retries after the next restart.
- Cancel from the portal works until the device restarts: before delivery the command is withdrawn at once;
  afterwards a signed abort reaches the device at its next check-in (≤ 6 minutes) and is refused when the device
  has restarted in between. The desktop notification repeats at every login and every 4 hours until the restart
  or the cancel.

## 8. Steps (tickets, in order)

1. **PDK-241 — Server: conversion model, commands, API, events, bundle field.** §3.3 (decisions 5–11), §6.1, §6.2,
   §6.5, the cancel semantics of decision 8 and the abort command type. Verify: `make gen` no diff; `go test ./server/internal/app/ ./pkg/command/ ./pkg/protocol/
   ./server/internal/compiler/`; `make acceptance T=TestDiskConversion`; the isolation gate.
2. **PDK-242 — Agent: preflight, eligibility in health, reencrypt-aware metadata.** §3.2 (decisions 1–4).
   Verify: `go test ./agent/internal/encrypt/ ./agent/internal/luks/ ./agent/internal/reconcile/` (table tests
   with recorded `lsblk`/`lvm`/`findmnt` outputs for `lvm`, `plain`, `direct`, raid, btrfs, two PVs, swap LV at
   the tail).
3. **PDK-243 — Agent: command handlers, preparation, abort, restart notification.** §3.4 (decisions 12–14),
   §3.9 (decisions 27–28), §6.3, §6.7. Verify: `go test ./agent/...` (fake system for every step, idempotent
   re-run, escrow failure, dracut failure, abort in every phase, the notification's command line and timing).
4. **PDK-244 — Dracut module and init script.** §3.5 (decisions 15–17), §6.4. Verify: `go test
   ./agent/internal/encrypt/` (the embedded files exist, `shellcheck -s sh` on the script in `make lint` — stop
   condition S4 when shellcheck is absent); the script's stage logic tested with a fake toolchain (`PATH` with
   stub scripts recording calls) in `agent/internal/encrypt/dracut_test.go`.
5. **PDK-245 — Agent: boot result, resume helper, progress, initrd regeneration, completion.** §3.6 (decisions
   18–23). Verify: `go test ./agent/...` (progress parsing from recorded `--progress-json` lines, pause/resume on
   battery, result handling, phase transitions).
6. **PDK-246 — Portal.** §3.7, §6.6 (with the cancel-after-delivery states of decision 8). Verify: `make web`; component tests over visible text; `make e2e`.
7. **PDK-247 — System gates and runbook.** §9 S-IE1 … S-IE3, the throwaway VM templates, `docs/operations/
   in-place-encryption.md`. Verify (one gate per run, in this order, §14.6): `make system-test VM=paddock-ai-2604
   T='^TestDiskUnlockModeTPMOnly$$'` (S-DU1 first), `make system-test VM=paddock-ie-2604
   T='^TestInPlaceEncryptionLVM$$'`, `make system-test VM=paddock-ie-2404 T='^TestInPlaceEncryptionPlain$$'`,
   `make system-test VM=all T='^TestDiskGates$$'` (S-IE3).
8. **PDK-248 — Documents, residual risks, CHANGELOG, regression.** §3.8, §12, the full regression (`make lint
   test`, `make acceptance`, `make e2e`, `make system-test VM=all`, the two throwaway gates one after the other as
   in step 7, `make bundle-test`), `make scan-secrets`.

PDK-241 and PDK-242 MAY run in parallel. PDK-243 depends on PDK-242 and on PDK-241's protocol types; PDK-244 on
PDK-243; PDK-245 on PDK-244; PDK-246 on PDK-241; PDK-247 on PDK-245 and PDK-246; PDK-248 is last. PDK-353 (the
worktree `.env` preflight of `make system-test`) SHOULD be done before PDK-247 (§14.6).

## 9. Tests and gates

Unit and integration tests per ticket follow the project's rules (business logic → unit; persistence, RLS →
integration with testcontainers; portal components with behaviour → component tests over the user's view).
Positive and negative tests for every role and tenant rule; every tool interaction of the agent behind the
`System` fake.

Acceptance (`test/acceptance`, `make acceptance`; roles **A** org_admin with step-up, **O** org_operator, **U**
org_auditor; "event" = exactly one audit event found with `expectOneEvent`):

| # | Given / When / Then | Role sees |
| --- | --- | --- |
| A1 `TestDiskConversion` | A devicesim reporting `disk{state: not_encrypted, boot_separate: true, conversion{eligible: true, layout: lvm}}`: A without step-up → 403 `step_up_required`; with step-up and wrong hostname → 422; `backup_confirmed: false` → 422 (detail `backup_confirmed must be true`); valid → 200, `disk_conversion{phase: requested, command_status: pending}`, event `device.encrypt_requested` with `backup_confirmed: true`, the device's commands list has type `encrypt_disk` with params `{conversion_id}`; a second request → 409; a device reporting `eligible: false, reasons: [no_separate_boot]` → 409 with the reason in the detail; O → 403; cancel → 200, command `cancelled`, row `cancelled`, event `device.encrypt_cancelled`; request again, devicesim checks in (delivered) → cancel 409; devicesim posts the result `{accepted: true}` and the events `disk.conversion_prepared{layout, volume, data_bytes}` → row `prepared` with them; `disk.conversion_started{init_s}` → `encrypting`; a check-in with `conversion{phase: encrypting, done_bytes: 50, data_bytes: 100, eta_s: 60}` → `GET /devices/{id}` shows `done_bytes: 50`, `eta_s: 60`; `disk.conversion_completed` → `completed`, `finished_at`; a new request after a `failed` row (devicesim posts `{accepted: false, reason: not_eligible, reasons: [low_free_space]}`) succeeds; a `disk.conversion_failed{stage: init, reason: on_battery}` → row `failed`, attention `disk_conversion_failed` detail `init:on_battery`; cancel after delivery: a new request, devicesim checks in (delivered), cancel without step-up → 403, with step-up and the hostname → 200 `mode: abort_sent`, `abort_command_id` set, the commands list has `encrypt_disk_abort{conversion_id}`, event `device.encrypt_cancelled{mode: abort_sent}`; a second cancel → 409 (`a cancellation is already on its way`); devicesim posts `disk.conversion_aborted{by: admin}` → row `cancelled`; a further request, prepared, cancel, devicesim answers the abort with `{aborted: false, reason: not_abortable}` and posts `disk.conversion_started` → `abort_refused_reason: not_abortable`, phase `encrypting`, cancel → 409; an uninstall pending → 409; a Lock pending → 409; globex → 404 on both routes. | A, O, U |
| A2 `TestDiskConversionBundle` | `boot_pin_min_length` 10 on the organization → the v2 bundle's `disk.boot_pin_min_length` is 10; the default → 8. | A |
| A3 `TestListContractM8e` | `GET /devices?disk_state=encrypting` lists a devicesim reporting that state; the list contract tests pass unchanged. | — |

System (`test/system`; the two throwaway VMs run only with `make system-test VM=paddock-ie-2604 T=…` and
`VM=paddock-ie-2404 T=…`, one gate per run, as gate D-AI does; ISOs from `PADDOCK_SYSTEM_ISO_2404` /
`PADDOCK_SYSTEM_ISO_2604` (Ubuntu Desktop images, §14.6); `buildAIVM` is generalised to take the VM name, the SSH
port (2229, 2230), the disk size (16 384 MB for both throwaway VMs, §14.6) and the ISO; the VMs are built from
`test/vms/virtualbox/autoinstall/unencrypted-lvm.yaml.tmpl` (26.04: `storage.layout.name: lvm`, no password,
`sizing-policy: all`) and `unencrypted-plain.yaml.tmpl` (24.04: curtin `storage.config` with GPT, a 1 GiB ESP, a
2 GiB ext4 `/boot` and ext4 `/` on the rest), then `Install` as on the base VMs):

| # | Gate | Content |
| --- | --- | --- |
| S-IE1 `TestInPlaceEncryptionLVM` | 26.04, `lvm`, `tpm_pin`; power cut after the init before the reactivation; power cut in the background phase | After `Install`: health `disk.conversion.eligible: true, layout: lvm` within one full pass; the request through the API → within 10 min `device.disk_conversion_prepared{layout: lvm}`, `GET /devices/{id}/disk` shows one stored recovery key (generation 1), `lsinitrd` of the running kernel lists `paddock-encrypt-init.service` and `etc/paddock/encrypt-key`, `/etc/crypttab` is unchanged; the throwaway template logs the test user in automatically (GDM `AutomaticLogin`), so within 2 minutes of `prepared` a screenshot contains "Disk encryption is ready" and the journal has one `paddock-notify-` transient unit per graphical session; `systemctl list-units 'paddock-notify-*'` shows none left running. The test sets `paddock.encrypt.testdelay=open:60` in `GRUB_CMDLINE_LINUX` of `/etc/default/grub` and runs `update-grub` (over SSH), then `sudo systemctl reboot`. Boot 1: the console shows `paddock-encrypt: init done` (screenshot polling every 5 s); the test calls `VM.PowerOff` during the following sleep. Boot 2 (parameter still set; the `open` path does not sleep): the console shows the PIN dialogue (screenshot contains "Paddock disk encryption setup") → `AnswerDiskSetup`; SSH back; `lsblk` shows `crypto_LUKS` on the partition and root on `dm_crypt-0`; journal lines `paddock-encrypt: header found, opening`; `device.disk_conversion_started`; health state `encrypting` with `done_bytes` increasing between two check-ins. The test removes the parameter (`/etc/default/grub`, `update-grub`), waits until `done_bytes` is between 10 % and 90 % of `data_bytes`, and calls `VM.PowerOff`. Boot 3: `RebootWithPIN` → SSH; `done_bytes` ≥ the last value within 5 min and increasing; `device.disk_conversion_completed`; then `compliant` within 15 min with tokens `[recovery, tpm2+pin]`, two stored recovery-key generations, the header stored, `/var/lib/paddock/install-passphrase` gone, the revealed generation 1 no longer opening the disk (`Opens`), the revealed generation 2 opening it; `lsinitrd` shows `etc/crypttab` with the LUKS UUID and no `paddock-encrypt`; `cryptsetup luksDump` lists no `reencrypt` keyslot and no requirement; `RebootWithPIN` works; `/boot` is mounted; the root file system is smaller than before the conversion by 64 MiB (`findmnt -bno SIZE /` before and after). |
| S-IE2 `TestInPlaceEncryptionPlain` | 24.04, `plain`, `tpm_only`; abort; power cut after the shrink before the init | The organization set to `tpm_only` for the run (restored on cleanup). After `Install`: eligibility `layout: plain`. Part A (aborts): the request → `prepared` (dracut installed: `dpkg -l dracut` installed, `initramfs-tools` gone; `lsinitrd` lists the module); `sudo paddockd encrypt-abort` → `device.disk_conversion_aborted{by: operator}`, row `cancelled`, `lsinitrd` no longer lists the module, `/var/lib/paddock/install-passphrase` gone, `sudo systemctl reboot` boots unencrypted (SSH back, `lsblk` without `crypto_LUKS`), health `eligible: true` again. Then a second request → `prepared`; the portal cancel through the API with step-up and the hostname → 200 `mode: abort_sent`; within 10 min `device.disk_conversion_aborted{by: admin}`, row `cancelled`, the abort command `succeeded` with `{aborted: true}`, the module gone from the initrd, the key file gone, the escrowed recovery key generation 1 still listed as stored, a reboot boots unencrypted, health eligible again. Part B: a new request → `prepared`; the test sets `paddock.encrypt.testdelay=init:120` (`/etc/default/grub`, `update-grub`), then `sudo systemctl reboot`. Boot 1: the console shows `paddock-encrypt: shrink done`; the test calls `VM.PowerOff` during the following sleep. Boot 2 (parameter still set): the console shows `paddock-encrypt: file system already at target`, then after the sleep `paddock-encrypt: init done`; no PIN dialogue; SSH back on dm-crypt; `device.disk_conversion_started`; `encrypting`. The test removes the parameter and reboots once more (boot 3, the `open` path): SSH back within the normal boot time, the reencryption resumes (`done_bytes` increasing); `device.disk_conversion_completed`; `compliant` with tokens `[recovery, tpm2]` and `unlock_mode: tpm_only`; a reboot unlocks without input; the revealed generation 1 no longer opens the disk, generation 2 does; `lsinitrd` as in S-IE1. |
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
| AC10 | Given a prepared device with a graphical session, then the signed-in user sees the desktop notification asking for a restart (in the device's language, with the PIN sentence under `tpm_pin`) at login and every 4 hours, and the device never restarts on its own. | maintainer Q1 | User at device |
| AC11 | Given a conversion the device has received but not executed at a restart, when an administrator cancels from the portal with a step-up, then the device discards its preparation, reports it, the row is `cancelled` and the disk is unchanged; given a device that already restarted, then the cancel is refused and the page says so. | maintainer Q2 | Org admin, auditor |

## 11. Stop conditions

- S1: void since 2026-10-20 — M8d (PDK-231 … PDK-233) is merged in PR #87.
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
  `encrypting` visible on the device page and the attention list, the portal cancel or `encrypt-abort` for a
  device that will not be restarted soon, the desktop notification that asks for the restart. Record: devices in `encrypting` or `prepared` for longer than a day; the rule that a converted
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

1. Restart prompt: **decided by the maintainer on 2026-10-17 — yes, a desktop notification** (decision 28), no
   *Restart now*; the restart stays the user's action.
2. Should the battery pause be a setting (for example "continue on battery above 50 %")? **Default: no** — fixed
   behaviour, mains only; revisit with lab feedback.
3. Cancel after delivery: **decided by the maintainer on 2026-10-17 — yes, through the signed command
   `encrypt_disk_abort`** until the restart (decisions 8 and 27); `paddockd encrypt-abort` at the device stays.
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

## 14. Amendment 2026-10-20 — refresh against `main` at `727fb7c5` (architect)

Written before implementation started; nothing of this plan is implemented. §2 and §5 were re-verified against
`main` at `727fb7c5` (PR #116) and corrected in place (§14.2). The decisions below amend §3, §8, §9, §11 and §12;
where they disagree with an earlier section, this amendment wins. ADR 0039 (amendment 2026-10-20) records the
architecture of §14.3–§14.5; ADR 0037 (amendment 2026-10-20) records the uninstall precondition of §14.5.

### 14.1 Basis

- M8d is merged (PR #87) with its amendments of 2026-10-18 and 2026-10-19 (plan M8d §15, ADR 0037 amendments):
  unlock mode, `boot_separate`, the deferred message of PDK-233, the uninstall with the helper in
  `/root/paddock-uninstall/`, the supervisor-upgrade deferral, Lock and Destroy never blocked by an uninstall.
  Stop condition S1 is void.
- Also merged since the plan was written: M8x (PR #82), M8u (PR #85), M8f (PR #86), M8h (PR #89), the M8d
  VM-regression fixes (PR #109), release v0.1.0-alpha.4 (PR #110), the dependency update (PR #116).
- Numbering: migrations end at `00065_device_name.sql`; M8e's is `00066_disk_conversion.sql`. Residual risks end at
  RR-70 (M8h); `docs/compliance/residual-risks.md` reserves **RR-56 to RR-61 for M8e** (its note below the devices
  table) — the reservation stands, M8e needs no further number. ADRs end at 0041; M8e adds none, it amends 0039
  and 0037.

### 14.2 Corrections applied in place (what changed on `main` since `968b03b`)

| Plan text (2026-10-17) | `main` (2026-10-20) | Applied in |
| --- | --- | --- |
| last migration `00048`, M8e after M8d's eight `<next>` | last `00065`; M8e = `00066_disk_conversion.sql` | §2, §3.3 decision 6, §5 |
| attention view last recreated by `00042`, five columns in the `UNION` branch | last by `00064`; six columns (`… , id` = `'disk_conversion_failed:' \|\| c.id::text`) | §2, §3.3 decision 6 |
| `audit.deviceEventParams` at `codes.go:175` | `codes.go:191`; `volume`, `stage`, `reason`, `command_id`, `mode` already listed | §2 |
| `startStepUp`/`resumeStepUp` in `lib/deviceDetailPage.ts` | defined in `lib/stepUp.ts`, used by `deviceDetailPage.ts` | §2 |
| `AnswerDiskSetup` listed with the `VM` methods | `(*Device).AnswerDiskSetup`, `(*Device).PrepareDisk` (`test/system/disk.go`) | §2 |
| M8d decision 38 cancel = command `cancelled` + `cache.DeleteCommand` | plus `ClaimResult(cancelled)` in the transaction (409 when the device reported first), `WithdrawDeviceCommand`, `DeleteCommand` after the commit (`withdrawUninstallCommand`) | §2; decision 8 as amended in §14.5 |
| uninstall helper below `/run/paddock/uninstall/` (M8d decision 39) | `/root/paddock-uninstall/` with the `statfs` `noexec` check (`Deps.NoExec`); `/run` is `noexec` under initramfs-tools | §2, §14.3 |
| — | the uninstall defers while `supervisor-upgrade.json` exists; no supervisor upgrade starts while an uninstall is pending | §2, §14.5 |
| — | `Revocations.Request` withdraws an undelivered uninstall (`uninstall_cancelled` params on `revocation.requested`) | §2, §14.5 |
| `buildAIVM` takes name and port from constants; ISOs unspecified | `buildAIVM(t, root, iso, userData)`, 40 960 MB VDI; the ISOs are Ubuntu **Desktop** images (`ubuntu-26.04.1-desktop-amd64.iso`) | §2, §9, §14.6 |
| `PADDOCK_SYSTEM_VMS=… make system-test T=…` | `make system-test VM=<vm> T=<regex>` (`VM` is required and sets `PADDOCK_SYSTEM_VMS`) | §8, §9 |
| `.check.ubuntu2404` keyed on `release = 24.04` | `.check.initramfsSwitch` keyed on `disk.conversion.initramfs = initramfs-tools` (§14.4) | §3.7 decision 24, §6.6 |
| MUST NOT touch `00001…00048` and M8d's migrations, `docs/adr/0001…0037` | `00001…00065`, `docs/adr/0001…0041` | §5 |
| — | `docs/operations/autoinstall.md` "Encrypting an installed device" carries PDK-233's wording; `docs/operations/disk-recovery.md` row `unmanaged` says "(no in-place conversion)"; `docs/architecture.md` open question O4 says "no in-place switch on existing 24.04 devices" | PDK-248 rewrites all three (decision 26; O4 gets the note "superseded by ADR 0039, bounded by plan M8e §14.4") |

### 14.3 Executables and `noexec` mounts (lesson of PR #109) — decisions 13, 15, 16, 21, 28 amended

Finding: M8e executes nothing from `/run`. `/run/paddock/encrypt-boot.env` (decision 16) is a data file the init
script writes and the agent reads; the dracut initrd with the `systemd` module mounts `/run` without `noexec`, and
the file survives the switch to the real root as data. Every executable of M8e and where it runs from:

| What | Path | File system |
| --- | --- | --- |
| init script (decision 16) | `/usr/libexec/paddock/encrypt-init.sh` inside the initramfs, `ExecStart` of `paddock-encrypt-init.service` | the initramfs root (rootfs); never `noexec` |
| `module-setup.sh` (decision 15) | `/usr/lib/dracut/modules.d/99paddock-encrypt/module-setup.sh`, sourced by `dracut` | root file system |
| background helper (decision 21) | `/opt/paddock/agent/current/paddockd encrypt-resume` in `paddock-encrypt-resume.service` | the agent's slot on the root file system |
| notification (decision 28) | `systemd-run … busctl` from `PATH` (`/usr/bin`) | root file system |
| operator commands (decisions 14, 26) | `/usr/bin/paddockd encrypt-abort` (the package's symlink to the slot) | root file system |
| tools | `dracut`, `lsinitrd`, `apt-get`, `cryptsetup`, `lvm`, `e2fsck`, `resize2fs`, `systemd-run`, `systemctl` from `PATH` | root file system |

29. **No executable below a mount that may be `noexec`.** M8e MUST NOT place a binary copy, a script or a
    helper below `/run`, `/tmp`, `/var/tmp`, `/dev/shm` or `/var/lib/paddock` and MUST NOT run anything from
    there; those paths carry data files only (`plan.json`, `plan.env`, `progress.json`, `result.json`,
    `test-hooks`, `encrypt-boot.env`). Reason: initramfs-tools mounts `/run` `noexec` and hardened hosts mount the
    others `noexec`; `systemd` then fails the unit with an opaque "Permission denied" (gate S-UN1, PR #109).
30. **`statfs` preflight before every transient unit that runs `paddockd`.** Before `systemd-run` of decision 21
    the agent resolves `/opt/paddock/agent/current` (`filepath.EvalSymlinks`) and calls `Deps.NoExec(dir)` on the
    slot directory (the function of `agent/internal/agent/uninstall.go`, reused unchanged). `noexec` or an error →
    no launch; the reason is logged at error level once per boot, `health.disk.conversion.paused_reason` is
    `helper_not_running`, and the launch is retried at the next full pass. The helper runs from the slot, not from a
    copy: the slot is never purged while the agent runs, and an uninstall is refused while a conversion is active
    (§14.5 decision 36).
    The notification of decision 28 needs no check (`busctl` is the system's). The init script needs none (it is
    inside the initramfs).
31. **Unit files unchanged.** `paddock-encrypt-init.service` keeps `ExecStart=/usr/libexec/paddock/encrypt-init.sh`
    (§6.4); the transient units keep the properties of decisions 21 and 28.

### 14.4 Initramfs generator: initramfs-tools and dracut — decisions 2, 3, 13 amended (ADR 0039 amendment)

The plan does not assume dracut everywhere: ADR 0039 correction 1 switches a device to dracut at preparation, as the
autoinstall and `Device.PrepareDisk` do on Ubuntu 24.04, and the module is only built after that switch. Not a
blocker. What changes:

32. **The switch is keyed on the installed generator, not on the release.** One source of truth for the preflight
    (decision 34) and for step 6: "dracut installed" means `dpkg-query -W -f='${db:Status-Status}' dracut` prints
    `installed` (exit 0); any other output or exit means "not installed". When it is not installed — on 24.04, and
    on a 26.04 that was upgraded in place from 24.04 and kept initramfs-tools — decision 13 step 6 installs
    dracut; the `24.04` condition of step 6 is removed (§3.4 corrected in place). `lsinitrd` and `dracut` come
    with the package.
33. **The removal set is closed, shown beforehand and checked afterwards.** The simulation
    `apt-get -s -o Debug::NoLocking=true install dracut` (bounded 2 minutes; the packages of its `Remv ` lines,
    sorted) runs in the preflight (decision 34) whenever dracut is not installed, and again as the first action of
    step 6. Every package of the set MUST be in the allow list `initramfs-tools`, `initramfs-tools-core`,
    `initramfs-tools-bin`, `brltty`; otherwise step 6 fails with `FailureStage: prepare`, reason
    `dracut_removes:<packages outside the list, sorted, joined by +, cut at 200 runes>` and installs nothing
    (stop condition S11). After `apt-get install -y dracut` succeeded, step 6 compares what really left: the
    packages whose `${db:Status-Status}` was `installed` before the installation
    (`dpkg-query -W -f='${Package} ${db:Status-Status}\n'`) and is not `installed` afterwards MUST equal the
    simulated set — a package left in state `rc` (configuration files remain) counts as removed, a package that
    was not `installed` before never counts (review finding N1); any difference fails the step with reason
    `dracut_removed_differs:<symmetric difference, sorted, joined by +, cut at 200 runes>` (the device stays
    unencrypted with dracut installed; a retry simulates afresh). Reason: `dracut` conflicts with initramfs-tools,
    and architecture O4 recorded that the switch also removes `brltty` on Desktop installs; a metapackage or
    anything else leaving with it is an architect decision, never an implementer's.
34. **The generator and the removal set are reported.** `protocol.DiskConversion` (decision 3) gains
    `Initramfs string json:"initramfs,omitempty"` — `dracut` when the `dpkg-query` of decision 32 prints
    `installed`, else `initramfs-tools` — and `InitramfsRemoves []string json:"initramfs_removes,omitempty"`, the
    simulated removal set of decision 33, reported only while `Initramfs` is `initramfs-tools` (empty when the
    simulation failed; the reasons of decision 2 are not affected). `Preflight` therefore runs `dpkg-query` and,
    on a device without dracut, `apt-get -s`, besides `findmnt`, `lsblk`, `blkid`, `lvm`; the result is cached with
    the preflight (at most every 10 minutes). Cost, accepted: on every `not_encrypted` device one `dpkg-query`
    per preflight (milliseconds), and on a device still on initramfs-tools one `apt-get -s` per preflight (about
    a second of CPU and the apt cache read, no lock, no network, at most every 10 minutes and only while the
    device is unencrypted); the §3.2 doc comment of `Preflight` names both. `DiskConversionHealth` (§6.1) gains
    `initramfs: string` and `initramfs_removes: [string]`. The dialogue (decision 24) shows
    `devices.disk.convert.check.initramfsSwitch` worded from the reported set (`{packages}`, joined with `, `)
    when `initramfs` is `initramfs-tools` and the set is not empty, and
    `devices.disk.convert.check.initramfsSwitchUnknown` when the set is empty (the simulation failed or reported
    nothing); the runbook names the switch and the set under "what the user sees".
35. **RR-58 is reworded** (PDK-248): "24.04 switches to dracut irreversibly" becomes "A device on initramfs-tools
    switches to dracut irreversibly. initramfs-tools and `brltty` are removed; kernel updates use dracut; no
    Plymouth splash; the dracut initrd is built with `hostonly` and verified with `lsinitrd` before the restart, but
    a hardware driver dracut leaves out would stop the boot before anything is encrypted. Mitigation: the dialogue
    says so; the allow list of decision 33 refuses any other removal; the same stack as autoinstalled 24.04
    devices; gate S-IE2 proves the switch on a Desktop install; the runbook's recovery (boot the previous kernel
    entry; every installed kernel's initrd carries the module). Record: the support statement for converted
    devices and the allow list."

### 14.5 Interactions with M8d — decisions 7, 8, 12, 13, 21, 22, 24 amended (ADR 0037 and 0039 amendments)

36. **Uninstall and conversion: refused while a conversion is active** (review of PR #117, finding B1: a removal
    during `encrypting` purges `plan.env` and the conversion key with `/var/lib/paddock/`, and a device whose
    initrd was not regenerated yet has no way to open its root volume at the next boot).
    - **Active conversion** (one definition for every rule and alert of §14.5, review finding M1): a conversion is
      active when the device's latest conversion row is in phase `requested`, `prepared` or `encrypting`, **or**
      the device's last health reports `disk.state = encrypting` — whatever the row says —, **or** the latest row
      is `completed` and the last health reports a `disk.state` other than `compliant` (review finding B1′: the
      reencryption may finish before the TPM keyslot exists, and the initrd with the Paddock module and the key
      is then the only unlock path until decision 20 has run). The health half covers a row the server set
      `failed` with stage `resume` (decision 9) while the device still carries the `reencrypt` keyslot and resumes
      at its next boot (decision 22). `DeviceDiskConversion` (decision 10, §6.1) gains `active: boolean`, derived
      on read (ADR 0028) from the row and `device_status.health → disk → state`; the portal keys the alerts below
      on it. Decision 9 is unchanged: a stage-`resume` failure stays a terminal row so that the attention list
      names it; `active` is what says the device is still encrypting.
    - Server, `Uninstalls.Request` (`app/uninstall.go`): an active conversion → 409 `invalid_state`, detail
      `an in-place encryption is open; cancel it first` when the row is `requested` or `prepared`, detail
      `the in-place encryption is unfinished; wait for its completion` in every other active case (checked under
      the device's row lock, after the open-uninstall check). The encrypt request keeps refusing an open
      uninstall (decision 7).
    - Agent, `uninstallCommand` (`agent/internal/agent/uninstall.go`): refuses with
      `{accepted: false, reason: conversion_pending}` when `(state.Conversion != nil &&
      !state.Conversion.InitrdRegenerated && phase ∉ {cancelled, failed-while-unencrypted}) ||
      state.Conversion.CleanupPending || md.Reencrypting()` of the root volume's `luks.Dump` — where
      *failed-while-unencrypted* is a `failed` phase whose `FailureStage` is `preflight`, `prepare` or `init`
      with the partition not LUKS (decision 18) and whose cleanup is done (I3: no initrd carries the module), so
      that a failed conversion on an unencrypted device never blocks a removal once nothing can convert it at the
      next boot (review finding N2), while a `completed` conversion blocks it until the initrd no longer carries
      the module and the key (invariant I1, §14.10). `UninstallAccepted.Reason`
      gains the value; the server stores and shows it as it does `revocation_pending`. The uninstall helper
      (`agent/internal/uninstall/`) is not changed.
    - Portal, `UninstallDialog.vue`: while `device.disk_conversion.active` is true the dialogue shows the alert
      `devices.danger.uninstall.conversionOpen` (§14.8) and keeps its confirm button disabled; the `DangerZone.vue`
      row is shown as today.
    - Retire, Lock and Destroy stay available (decisions 38, 39). The runbook section "Removing Paddock during a
      conversion" (decision 26) states the rule exactly as above: refused while the conversion is active — a
      `requested`, `prepared` or `encrypting` conversion, a device whose health still reports `encrypting`, and a
      `completed` conversion until the device reports `compliant` (the initrd must no longer carry the Paddock
      module and the conversion key); cancel a `requested` or `prepared` conversion first; an `encrypting` device
      finishes on mains power; a `completed` one needs the boot PIN chosen (the dialogue of the next boot) so that
      the agent can regenerate the initrd; the manual completion of the runbook applies when the agent is gone for
      another reason.
37. **Supervisor upgrade and conversion** (the rule of plan M8d §15.4 decision 39, mirrored).
    - No supervisor upgrade starts while the preparation runs: `busy` in `agent/internal/agent/supervisor.go`
      is also true while `state.Conversion != nil && state.Conversion.Phase == "preparing"` (step 6 holds the dpkg
      lock, and a supervisor restart would interrupt the worker).
    - The conversion worker does not start a step of decision 13 while `supervisor-upgrade.json` exists: before
      every step it reads `supervisorpkg.ReadMarker`; while a marker exists it waits (poll every 30 s), bounded by
      `supervisorpkg.StaleAfter` (30 min) from the marker's `started_at` (or the file's mtime when unreadable, as
      `supervisorUpgradeRuns` does), then continues. Logged once per job at info level; no event.
    - An agent A/B update during a conversion needs no rule: `state.Conversion` is shared, a restarted agent
      re-queues a `preparing` job (decision 13), the helper's unit outlives the agent (own cgroup) and keeps its
      binary, and the next launch resolves `current` anew (decision 30).
38. **Lifecycle states.** `encrypt` needs `active` (decision 7, unchanged). A later state change does not stop the
    device: it converts fail-safe as prepared, and the server records its conversion events in every state in which
    the gateway accepts reports; the attention entry `disk_conversion_failed` is for `active` devices only
    (decision 6). `Devices.Retire` (`app/devices.go`) withdraws an undelivered `encrypt_disk` command exactly as
    decision 8's `command_cancelled` does, sets the row `cancelled` and records `conversion_cancelled:
    before_delivery` and `conversion_id` as params of its one `device.retired` event; a delivered command or a
    `prepared` conversion is left alone (params `conversion_id`, `conversion_phase`). Retire is never refused for a
    conversion (a presumed-lost device must stay retirable). The registry entries of `device.retired` and
    `revocation.requested` (`codes.go`) gain the params `conversion_cancelled`, `conversion_id`, `conversion_phase`
    (closed values: `before_delivery`; `requested | prepared | encrypting`).
39. **Lock and Destroy precedence** (plan M8d §15.4 decision 37, mirrored). Lock and Destroy are never blocked by
    a conversion. `Revocations.Request` (`app/revocations.go`), in its transaction and under the device's row lock:
    an undelivered `encrypt_disk` command is withdrawn as in decision 8 (`ClaimResult(cancelled)`,
    `WithdrawDeviceCommand`, `DeleteCommand` after the commit; the row `cancelled`), recorded as the params
    `conversion_cancelled: before_delivery` and `conversion_id` of the one `revocation.requested` event; a delivered
    command, a `prepared` or an `encrypting` conversion is left alone and recorded as `conversion_id`,
    `conversion_phase`. No second audit event. The revocation path's code (`agent/internal/revoke/`,
    `agent/cmd/paddock-revoke/`, `pkg/revocation/`) is not changed: `paddock-revoke` refuses a Lock or Destroy of
    an unencrypted root (`revocation_refused`, reason `not_encrypted`); during `encrypting` the root is LUKS2 with
    the `reencrypt` keyslot and no escrowed header.
    - **The agent stops the background helper before the hand-over** (review finding M2). In the agent's
      revocation hand-over (`agent/internal/agent/revocation.go`), in this order: (1) the envelope's hash is
      recorded in `state.HandedRevocations` and the state saved — from then on no pass relaunches the helper;
      (2) the agent runs `systemctl stop paddock-encrypt-resume.service` and waits until `systemctl is-active` is
      not `active`, bounded 60 s (SIGTERM is safe for `cryptsetup reencrypt`, ADR 0039 sources; a missing unit is
      no error); (3) `Deps.Revoke` is called — also when the bound ran out, logged at warning level with the unit's
      state: the Lock always wins over the helper. The launch condition of decision 21 gains: no entry of
      `state.HandedRevocations` younger than `revocationWindow` (24 h, the constant of `uninstall.go`) exists;
      `paused_reason` is `helper_not_running`. A refused revocation (`not_encrypted`, `malformed`, …) keeps the
      entry and therefore the pause for 24 h; that is accepted (RR-57).
    - **Expected result of a Lock during `encrypting`** (binding for the hand test of PDK-247): `paddock-revoke`
      counts keyslots as `len(luks.Metadata.Keyslots)` of `cryptsetup luksDump --dump-json-metadata` — the raw
      map, so the `reencrypt` keyslot counts as one — and erases with `cryptsetup luksErase --batch-mode`; it
      reports `erased: true` only with `slots_after = 0`. Expected: `revocation.executed` with `erased: true`,
      `slots_before` = the number of keyslots the dump listed (the conversion key's `password` slot, the
      `reencrypt` slot, plus `tpm2+pin` or `tpm2` once enrolled), `slots_after: 0`; the device does not boot
      afterwards. Stop condition S14: `paddock-revoke` reports `erased: false` (a `reencrypt` keyslot that
      `luksErase` leaves behind, or `cryptsetup` refusing the operation under the `online-reencrypt` requirement)
      — stop and report the transcript; any change to the revocation path goes through the two-person rule and an
      architect decision, never through an M8e ticket.
    - The Lock and Destroy dialogues (`DangerZone.vue`) show, while `device.disk_conversion.active` is true
      (decision 36), the alert `devices.danger.revoke.conversionWarning.<kind>` (§14.8) with `kind` =
      `unencrypted` for the rows `requested` and `prepared` without health `encrypting` (the device is not
      encrypted yet and refuses the action) and `kind` = `encrypting` otherwise (the header is not escrowed, the
      Lock cannot be restored, and data the encryption has not reached stays readable). RR-57 records it (§14.7).
40. **Revocation handed over during the preparation.** Decision 12's refusal (`revocation_pending`, 24 hours)
    stays an acceptance check only; the worker does not abort a running preparation for a revocation, because the
    device refuses Lock and Destroy while unencrypted and the conversion cannot harm the organization's position.

### 14.6 Tests and gates (§9) amended

41. **Commands and the `$$` pitfall.** The gates run one per `make` invocation: `make system-test
    VM=paddock-ie-2604 T='^TestInPlaceEncryptionLVM$$'` and `make system-test VM=paddock-ie-2404
    T='^TestInPlaceEncryptionPlain$$'` (`$$` is make's escape for `$`; a bare `$` at the end of a command-line
    variable is dropped by make, so `T='^TestDiskGates$'` becomes the prefix match `^TestDiskGates` and also runs
    every test whose name starts so; a `$/` inside a pattern is expanded and the pattern then matches nothing,
    PDK-339). A run whose log lacks `--- PASS: TestInPlaceEncryption…` is not green, whatever its exit code
    (PDK-339: a filter that matches no test ends green). S-IE3 runs inside `make system-test VM=all
    T='^TestDiskGates$$'`. `PADDOCK_SYSTEM_VMS` MUST NOT name a throwaway VM together with a base VM: `forEachVM`
    would try to run every base gate on the throwaway name.
42. **Throwaway VM size and disk headroom.** `buildAIVM` is generalised to `buildAIVM(t, root, spec aiSpec,
    userData)` with `type aiSpec struct { Name, SSHPort string; DiskMB int }`; D-AI and S-DU1 keep
    `paddock-ai-2604`, `2228`, `40960`; `paddock-ie-2604` is `2229` and `paddock-ie-2404` is `2230`, both with
    `DiskMB = 16384`. Reason: the
    reencryption writes every sector of the root partition, so a dynamic VDI grows to the full disk size — two
    40 GB VMs would need 80 GB, and the laptop had 36 GB free on 2026-10-20 with the VirtualBox machine folder on
    the same file system. With 16 GB the background phase on a VM also finishes in minutes instead of a quarter
    of an hour. Before `buildAIVM` creates the disk, the gate reads `statfs` of the VirtualBox machine folder
    (`VBoxManage list systemproperties`, line `Default machine folder`) and fails (`t.Fatalf`, not `Skip`) when
    less than 24 GiB are free, naming the figure. The two gates are separate top-level tests without
    `t.Parallel`, so they run one after the other; each deletes its VM in its cleanup (as D-AI does). Operator
    note for the runs: `df -h /` and `docker builder prune` first (the development host is usually near full).
43. **ISOs.** `PADDOCK_SYSTEM_ISO_2604` (default `~/Downloads/ubuntu-26.04.1-desktop-amd64.iso`, as D-AI) and
    `PADDOCK_SYSTEM_ISO_2404` (default `~/Downloads/ubuntu-24.04.5.1-desktop-amd64.iso`); a missing file fails the
    gate with the path. Both throwaway VMs are Ubuntu Desktop installs — the only images the harness uses — which
    is what makes GDM `AutomaticLogin` and the dracut removal set of decision 33 relevant.
44. **Progress assertions read the device, not the API.** `done_bytes increasing between two check-ins` becomes
    "between two reads of the device's health over SSH (`Device.Health()`) 10 s apart"; the API shows the value of
    the last check-in and is asserted once at the end (`GET /devices/{id}` has `done_bytes`, `eta_s`). The
    10 %–90 % window for the power cut is found the same way (poll every 5 s).
45. **Notification assertion.** GNOME hides a banner after seconds whatever `expire_timeout` says, so a screenshot
    is evidence, not the assertion. S-IE1 asserts within 2 minutes of `prepared` that the journal shows one
    `paddock-notify-<session>-<ts>.service: Deactivated successfully` per graphical session
    (`journalctl -o cat _COMM=systemd | grep paddock-notify-`) and that `systemctl list-units 'paddock-notify-*'`
    shows none; it takes a screenshot every 2 s for 90 s from `prepared` on, keeps them in
    `bin/system-evidence/`, and logs whether "Disk encryption is ready" was seen. The desktop itself is
    PDK-243's manual verification 2 on the lab device.
46. **S-DU1 first.** `TestDiskUnlockModeTPMOnly` (M8d) has not been run on a VM yet and S-IE2 relies on
    `tpm_only`. PDK-247 MUST run `make system-test VM=paddock-ai-2604 T='^TestDiskUnlockModeTPMOnly$$'` before
    S-IE2 and record the result; a failure there is an M8d finding (ticket stub, stop condition S13), not fixed
    inside M8e.
47. **Organization-wide settings.** S-IE2 sets the organization's unlock mode to `tpm_only` (restored in its
    cleanup); it therefore MUST run alone, never concurrently with `VM=all` gates. S-IE3 shares nothing and needs
    no `Together`.
48. **Harness rules of PR #109 apply.** The throwaway gates publish their release with `Install` and MUST retract
    it in their cleanup (`retractRelease`); they run from a worktree only with `deploy/compose/.env` and
    `deploy/compose/.secrets` present (PDK-353 adds the preflight; until then check by hand before the run).
49. **Stop conditions added.** S11: `apt-get -s install dracut` on a throwaway or lab device would remove a package
    outside the allow list of decision 33 — report the simulation output; the architect extends the list. S12:
    the 16 GB throwaway VM leaves the root file system with less than 1 GiB free after the Desktop install, so that
    the preflight reports `low_free_space`, or the Desktop installer refuses or fails the autoinstall on a 16 GB
    disk — report `findmnt -bno AVAIL /` or the installer's log; the size is an architect decision. S13: S-DU1
    fails on `paddock-ai-2604` — report, open a ticket stub against M8d, do not change `disksetup` or the
    reconciler inside M8e. S14: the Lock hand test of decision 39 reports `erased: false` — stop and report.
50. **Gate coverage of the uninstall refusal** (decision 36). S-IE1, while the device is `encrypting` (after
    `device.disk_conversion_started`): `POST /devices/{id}/uninstall` with step-up, the typed hostname, mode
    `leave` → 409 `invalid_state` with the detail `the in-place encryption is unfinished; wait for its
    completion`; `GET /devices/{id}` shows `disk_conversion.active: true`. Acceptance A1 gains: a devicesim whose
    row is `failed` (stage `resume`) but whose check-in reports `disk{state: encrypting}` → `active: true`,
    uninstall → 409; the same devicesim reporting `compliant` → `active: false`, uninstall → 200; while
    `requested` → 409 with the detail `an in-place encryption is open; cancel it first`; a `completed` row with
    health `tpm_pin_missing` → `active: true`, uninstall → 409; with health `compliant` → `active: false`.
51. **Gate coverage of the deferred PIN** (decisions 3, 20, 36; review finding B1′). S-IE1 (`tpm_pin`) is
    changed at its boot 2: the test does not answer the PIN dialogue but chooses *skip* (the M4b dialogue's skip
    under `tpm_pin`, `Device.AnswerDiskSetup` gains a skip variant), so the device boots without a TPM keyslot and
    the reencryption runs to `completed` while the health reports `tpm_pin_missing`. Boot 3 after the background
    power cut is then a plain reboot (no PIN prompt; the module opens the disk with the key). After
    `device.disk_conversion_completed`: `GET /devices/{id}` shows `disk_conversion{phase: completed, active:
    true}`, the uninstall request → 409, `lsinitrd` still lists `paddock-encrypt-init.service` and
    `etc/paddock/encrypt-key`, `cryptsetup luksDump` still lists the conversion key's keyslot, the health is
    `tpm_pin_missing` (never `compliant`), `health.disk.conversion.key_on_boot` is true, and
    `/var/lib/paddock/disk-setup-pending` exists again (decision 52's re-arm). While the PIN is still skipped the
    test runs `sudo dracut -f --regenerate-all` and `sudo systemctl reboot`: the dialogue returns and is skipped
    once more; SSH back on dm-crypt (invariant I1: every initrd build keeps the module while the partition is LUKS
    and `InitrdRegenerated` is false; `lsinitrd` lists the module and the key again). Then `sudo systemctl
    reboot` once more: the dialogue returns by the re-arm alone (no manual marker), `AnswerDiskSetup` with the
    PIN; SSH back; within 15 minutes the device is `compliant` with `[recovery, tpm2+pin]`, `lsinitrd` of every
    installed initrd shows `etc/crypttab` with the UUID and no `paddock-encrypt`, `/var/lib/paddock/encrypt/`
    holds no `plan.env`, `key_on_boot` is false, `active: false`, uninstall request → 200 (the test cancels that
    uninstall at once through `POST …/uninstall/cancel` so that the gate's remaining assertions run on an
    installed device); then `RebootWithPIN` opens the root volume, and the revealed generation 1 no longer opens
    the disk, generation 2 does — the remaining assertions of S-IE1 (§9) unchanged. S-IE2 (`tpm_only`) keeps its
    sequence: there is no PIN to defer.
52. **A skipped PIN on a converted device: the dialogue returns at every boot** (review finding M-2). While
    `state.Conversion.Phase` is `encrypting` or `completed` and `!InitrdRegenerated` (no TPM keyslot yet) the agent, at
    every
    start and at every full pass, re-creates `/var/lib/paddock/disk-setup-pending` when it is missing, so that
    `paddock-disk-setup.service` asks for the PIN at the next boot; the user can still skip (fail safe, the boot
    is never blocked). `protocol.DiskConversion` (decision 3) gains `KeyOnBoot bool json:"key_on_boot,omitempty"`,
    true from `prepared` until `InitrdRegenerated` (the conversion key lies in the initrd on the unencrypted
    `/boot`); `DiskConversionHealth` (§6.1) gains `key_on_boot: boolean`. The portal shows, while `key_on_boot` is
    true and the phase is `encrypting` or `completed`, the alert `devices.disk.convert.keyOnBoot` (§14.8) on the
    disk card: the disk is not protected at rest until the user chooses the boot PIN; the device asks at every
    start. RR-57 records the exposure (§14.7). Under `tpm_only` the keyslot is enrolled without a dialogue at the
    conversion boot, so the re-arm covers only a failed enrollment, which the dialogue of decision 1 of ADR 0038
    already retries at the next boot.

53. **Gate S-IE4 `TestInPlaceEncryptionCleanupAdopt`** (review round 4, X1 (4); the `cancelled` and
    `failed:prepare` rows of §14.10). Its own run on a fresh `paddock-ie-2404` (plain layout, `tpm_only`, after
    S-IE2; `make system-test VM=paddock-ie-2404 T='^TestInPlaceEncryptionCleanupAdopt$$'`; like S-IE2 it sets
    the organization's unlock mode to `tpm_only`, restores it in its cleanup and runs alone, decision 47): after
    `Install`
    and the request → `prepared`; the test makes dracut fail without a product hook — `sudo dpkg-divert --add
    --rename --divert /usr/bin/dracut.real /usr/bin/dracut` and a stub `/usr/bin/dracut` (`#!/bin/sh`, `exit 1`,
    0755); `sudo paddockd encrypt-abort` → exit 0, `device.disk_conversion_aborted{by: operator}`, row
    `cancelled`, within one full pass health `disk.conversion{eligible: false, reasons: [cleanup_pending]}`, the
    module directory gone, `/var/lib/paddock/encrypt/plan.env` and `/var/lib/paddock/install-passphrase` still
    present (I3 order), `lsinitrd` of the running kernel still lists `paddock-encrypt-init.service`;
    `POST /devices/{id}/uninstall` → 200 (the server accepted the request: the row is `cancelled`); the device
    answers `{accepted: false, reason: conversion_pending}`, the command is `failed` with that reason in the
    device's commands list, and the server has ended the request (`EndFailedUninstall`,
    `queries/uninstall.sql`): `GET /devices/{id}` shows no open uninstall — nothing to cancel; `sudo
    systemctl reboot` → the console shows `paddock-encrypt: init done` (the stale initrd converts); SSH back on
    dm-crypt; `device.disk_conversion_started{init_result: ok}`, `GET /devices/{id}` shows the same conversion
    id with `phase: encrypting`, health `encrypting`; within one full pass the module directory and the conf
    exist again (I2 adoption) — the stub dracut still fails, so the agent logs the rebuild failure and retries;
    the test removes the diversion (`sudo rm /usr/bin/dracut; sudo dpkg-divert --remove --rename
    /usr/bin/dracut`); within two full passes the agent's rebuild succeeds and `lsinitrd` of every installed
    kernel lists `paddock-encrypt`; the test then stands in for a kernel update with `sudo dracut -f
    --regenerate-all` and `sudo systemctl reboot` → SSH back on dm-crypt (I1); the reencryption resumes and
    completes; `compliant` with `[recovery, tpm2]`, `lsinitrd` without `paddock-encrypt`, a reboot unlocks
    without input. The VM is deleted at the end; the run costs one more throwaway build (decision 42's headroom
    and the one-gate-per-run rule apply).

### 14.7 Residual risks (§12) amended

- RR-57 gains the sentences: "A Lock or Destroy during `encrypting` erases a header that is not escrowed; the
  encrypted part is lost for good, the rest stays readable until the reencryption would have reached it. The
  dialogue says so; the agent stops the background encryption before it hands the revocation over and does not
  restart it for 24 hours, also after a refused revocation; the device-side result on a header with the
  `online-reencrypt` requirement was verified once on a VM (PDK-247)." and "A user who skips the boot PIN on a
  converted device leaves the conversion key in the initrd on the unencrypted `/boot` for as long as the PIN is
  skipped — the disk is then encrypted but not protected at rest; the device asks for the PIN at every start
  (plan M8e decision 52), the device page and the health say so (`key_on_boot`), and the attention list keeps
  the device under `disk_not_compliant`. Record: devices whose `key_on_boot` stays true for longer than a day."
- RR-58 as reworded in decision 35.
- RR-56, RR-59, RR-60, RR-61 unchanged (removing Paddock is refused while a conversion is active, decision 36).

### 14.8 Texts added to §6.6 (binding; `en.json` / `de.json`)

| Key | English | German |
| --- | --- | --- |
| `devices.danger.uninstall.conversionOpen` | Paddock cannot be removed while this device is being encrypted in place: the removal would delete what the device needs to unlock its disk at the next start. Cancel a requested or prepared encryption first; a running encryption finishes on mains power. | Paddock kann nicht entfernt werden, solange dieses Gerät nachträglich verschlüsselt wird: Die Entfernung würde löschen, was das Gerät beim nächsten Start zum Entsperren seiner Festplatte braucht. Brechen Sie eine angeforderte oder vorbereitete Verschlüsselung zuerst ab; eine laufende Verschlüsselung wird am Netzteil abgeschlossen. |
| `devices.danger.revoke.conversionWarning.unencrypted` | This device is not encrypted yet; it refuses a Lock or Destroy until the encryption has started. | Dieses Gerät ist noch nicht verschlüsselt; es lehnt Sperren und Zerstören ab, bis die Verschlüsselung begonnen hat. |
| `devices.danger.revoke.conversionWarning.encrypting` | The in-place encryption is unfinished: the header is not stored in Paddock, so this action cannot be undone with a stored header, and data the encryption has not reached stays readable. The background encryption is stopped before the device acts. | Die nachträgliche Verschlüsselung ist unvollständig: Der Header ist nicht in Paddock hinterlegt, diese Aktion lässt sich also nicht mit einem hinterlegten Header rückgängig machen, und Daten, die die Verschlüsselung noch nicht erreicht hat, bleiben lesbar. Die Verschlüsselung im Hintergrund wird angehalten, bevor das Gerät handelt. |

| `devices.disk.convert.keyOnBoot` | The disk is encrypted but not protected at rest yet: until the user chooses the boot PIN, the key that unlocks it lies on the unencrypted boot partition. The device asks for the PIN at every start. | Die Festplatte ist verschlüsselt, aber noch nicht im Ruhezustand geschützt: Bis der Benutzer die Boot-PIN wählt, liegt der Schlüssel, der sie entsperrt, auf der unverschlüsselten Boot-Partition. Das Gerät fragt bei jedem Start nach der PIN. |

`devices.disk.convert.check.ubuntu2404` is replaced by `devices.disk.convert.check.initramfsSwitch` (§6.6, with
the ICU parameter `{packages}` from `disk.conversion.initramfs_removes`) and its fallback
`devices.disk.convert.check.initramfsSwitchUnknown` for an empty set (decision 34).

### 14.9 Tickets

PDK-241 … PDK-248 were updated on 2026-10-20 (scope and references). Which ticket owns which decision of §14: PDK-241
— 36 (server refusal, `active`), 38, 39 (server withdrawal and event params), `initramfs` and `initramfs_removes`,
`key_on_boot` and `init_result` in the contracts, the A1 cases of decision 50; PDK-242 — 34, the reason
`cleanup_pending` (§14.10); PDK-243 — 13 (the cleanup after step 7 under I3), 29, 32, 33, 36 (agent refusal), 37;
PDK-244 — 29, 31; PDK-245 — 3 and 22 (the hold until `InitrdRegenerated`), 18 (I2), 20 (also while `completed`, the
order of I1, `plan.env` last), 30, 39 (the stop before the hand-over and the launch condition), 52 (the re-arm,
`key_on_boot`), the I2 adoption of decision 18 and §14.10; PDK-246 — 34 (the dialogue lines), 36 and 39 (the alerts),
52 (the `keyOnBoot` alert), §14.8; PDK-247 — 41–53 (S-IE4 of decision 53), S11–S14, the Lock hand test of decision 39;
PDK-248 — 35, §14.7, the O4 note of §14.2. Every ticket of the agent and the gates cites §14.10 (invariants and the
state × event table).

### 14.10 Boot-path invariants and the state × event table (binding; review round 3 of PR #117)

Three invariants bind every decision of this plan; a decision that contradicts them is wrong, not the invariant.

- **I1 — the unlock path is never removed before its replacement works.** While the root partition is LUKS and
  `state.Conversion.InitrdRegenerated` is false, no step, cleanup, uninstall, abort or keyslot change MAY remove
  the module directory, `91-paddock-encrypt.conf`, `plan.env`, the conversion key or the conversion key's
  keyslot, and every initrd build (a kernel update's, `dracut -f --regenerate-all` by anyone) keeps the module
  (the module's `check()` sees `plan.env`). The only sequence that removes them is decision 20, which first
  writes the crypttab line that opens the volume with the TPM keyslot, then verifies every installed initrd, and
  removes `plan.env` last. Consequences: decision 3's hold, decision 22's "only `progress.json` and
  `result.json`", decision 36's refusal, decision 27's `not_abortable` after the restart.
- **I2 — the disk decides the phase.** While `state.Conversion != nil` — in any phase, until the state is
  cleared; never on a device without a conversion (an autoinstalled first boot, a `tpm_pin_missing` device) — at
  every start, before decision 13's re-queue and before any cleanup retry, and at every full pass, the agent
  derives the phase from the disk before it trusts the state file or the boot result: when
  `/run/paddock/encrypt-boot.env` says `ok`, or `md.Reencrypting()` holds, or the partition of `plan.json` is
  LUKS and `luks.Dump` shows the conversion key's keyslot (`KeySlot(install passphrase)` succeeds), and the phase
  is not `encrypting` or `completed`, the agent **adopts** the conversion: sets `encrypting`, drops a queued
  `preparing` job, clears `CleanupPending`, emits `disk.conversion_started` once (the server row moves to
  `encrypting` from `requested`, `prepared`, `failed` or `cancelled`) — whatever the phase says (`preparing`,
  `prepared`, `failed`, `cancelled`, or a state file restored from a backup) — and, when a cleanup had removed
  the module directory or the conf, reinstalls both from the embedded copy (and `plan.env` from `plan.json`) and
  rebuilds the initrds before anything else, so that the next kernel update keeps the unlock path (I1).
  Consequences: decision 18, decision 36's `md.Reencrypting()` term.
- **I3 — a cleanup is done when no initrd carries the module.** A cleanup (decision 14's `encrypt.Abort`,
  decision 13's failure after step 7, decision 18's unencrypted failure) removes first only the module directory
  and the conf, regenerates, and counts as done only when `lsinitrd` of the initrd of every installed kernel
  (`/boot/initrd.img-<v>` for every `<v>` that has `/boot/vmlinuz-<v>` or `/lib/modules/<v>` — every GRUB entry,
  the one definition for decisions 14, 18 and 20) shows no `paddock-encrypt`; only after that check it
  deletes the key, `plan.json`, `plan.env` and the disk-setup files. Until then `state.Conversion.CleanupPending`
  is true, the cleanup is retried at every full pass, the phase stays non-final (the state is not cleared, the
  preflight reports the reason `cleanup_pending` and `eligible: false`, the uninstall is refused with
  `conversion_pending`), and `disk.conversion_aborted`/`_failed` is emitted once at the first attempt. A device
  that reboots meanwhile may convert its disk through a stale initrd; I2 then adopts the conversion with the key
  and the plan still on disk. `state.DiskConversion` (§6.3) gains `CleanupPending bool
  json:"cleanup_pending,omitempty"`.

State × event table (rows: the agent's phase and, for `failed`, the stage; columns: what happens; each cell the
outcome and the invariant that holds). *LUKS* = the root partition carries the LUKS2 header.

| Phase | Reboot | Kernel update / initrd rebuild | PIN set / skipped | Uninstall request | Lock / Destroy | Cleanup failure |
| --- | --- | --- | --- | --- | --- | --- |
| `preparing` (steps 1–9 running) | I2 runs first: a reboot during or after step 8 built an initrd with the module, the device converted at that boot, the partition is LUKS → adopted as `encrypting`, the queued job is dropped, `disk.conversion_started` moves the row from `requested` to `encrypting`; not LUKS (reboot before step 8, or the module did not run) → the worker re-queues the job, steps skip what exists (decision 13), boots as before | before step 7 nothing of M8e in the initrd; from step 7 the module is included (I1 is not yet in force, not LUKS) | n/a (no dialogue: the marker is written at step 5, the unit runs at the next boot) | server 409 (row `requested`); device `conversion_pending` (decision 36) | server withdraws an undelivered command; a delivered one: the device refuses the Lock (`not_encrypted`); the worker continues (decision 40) | a failure ≥ step 7 sets `failed:prepare` and starts the cleanup under I3 |
| `prepared` | the module runs: shrink, init → LUKS, boots on dm-crypt; at the next agent start I2 → `encrypting` | the module is included (`plan.env` exists); still bootable unencrypted | n/a until the conversion boot | server 409 (`cancel it first`); device `conversion_pending` | as `preparing`; the conversion stays `prepared` (device refuses, `not_encrypted`) | n/a |
| `encrypting` | the module (or, after decision 20, crypttab + TPM) opens the volume; the helper resumes (decision 21); I2 keeps `encrypting` | before decision 20: the module is included (I1); after: crypttab + TPM (decision 20 step 1 precedes the removal) | set: TPM keyslot → decision 20 regenerates, `key_on_boot` false; skipped: `tpm_pin_missing`, module stays, `key_on_boot` true | server 409 (`wait for its completion`); device `conversion_pending` (I1) | server leaves the conversion; agent records the hand-over, stops the helper, hands over; `paddock-revoke` erases every keyslot (decision 39; S14 if not) | n/a (no cleanup in this phase) |
| `completed`, `!InitrdRegenerated` | as `encrypting` (the module opens the volume); decision 52 re-arms the PIN dialogue every boot | the module is included (I1: `plan.env` still exists) | set: decision 20 → `InitrdRegenerated`, then M4b removes the conversion keyslot, `compliant`; skipped: dialogue again next boot (decision 52), `key_on_boot` true, at most `escrow_pending` | server 409 (`active`: `completed` and not `compliant`); device `conversion_pending` (I1) | as `encrypting`; header not escrowed, unrestorable (RR-57) | decision 20's steps (2)–(4) are retried every full pass; during the retry the unlock path is the crypttab line of step (1) plus the TPM keyslot, and the initrds not yet rebuilt still carry the module (I1; I3 applied to the regeneration) |
| `completed`, `InitrdRegenerated` (state cleared on `compliant`/`escrow_pending`) | crypttab + TPM opens the volume; `RebootWithPIN` | crypttab + TPM | n/a (set) | server 200 once `compliant`; device accepts (`Conversion == nil`) | as any compliant device (header escrowed after completion) | n/a |
| `failed:preflight` (not LUKS, nothing written) | boots as before | nothing of M8e | n/a | server 200 (row `failed`, health `not_encrypted`); device accepts | normal (device refuses, `not_encrypted`) | n/a |
| `failed:prepare` before step 7 (not LUKS) | boots as before | nothing of M8e in the initrd | n/a | as `failed:preflight` | normal | n/a |
| `failed:prepare` at or after step 7 (not LUKS) | cleanup done: boots as before. `CleanupPending` (an initrd of an installed kernel still carries the module, `plan.env` and the key still on the host, I3 order): the module runs at that boot and converts the disk; at the next agent start I2 adopts: `encrypting`, `disk.conversion_started` moves the row from `failed` to `encrypting`, the module and conf are reinstalled and the initrds rebuilt before anything else (I1), then decision 20/21 | during `CleanupPending` the module directory is gone, so a rebuild drops the module from the rebuilt initrd only; `plan.env` stays until (3) passed, so an adopted conversion can reinstall the module (I2) | n/a | server 200 (row `failed`); device `conversion_pending` while `CleanupPending`, accepts once (4) ran (I3) | normal | (1)–(3) retried every full pass; the key, `plan.*` and the disk-setup files stay until (3) passed; `cleanup_pending` in the preflight; the phase stays non-final (I3) |
| `failed:init`, partition not LUKS (`on_battery`, `fsck_*`, `vg_busy`, `luks_init_*` before the header) | as the row above (cleanup done: boots as before; `CleanupPending`: a stale initrd converts, I2 adopts) | as the row above | n/a | as the row above | normal | as the row above |
| `failed:init` reported but partition LUKS (`root_missing`, a failure after the header) | never a `failed` phase: I2 → `encrypting` at the next agent start, `init_result` names the stage | the module is included (I1) | as `encrypting` | as `encrypting` | as `encrypting` | n/a (no cleanup: I1, decision 18) |
| `failed:resume` (row `failed` on the server, device still LUKS with the `reencrypt` keyslot) | the module or crypttab opens the volume; I2 → the agent's phase is `encrypting` and the helper relaunches up to 3× per boot (decision 22) | as `encrypting` | as `encrypting` | server 409 (`active` through health `encrypting`); device `conversion_pending` (`md.Reencrypting()`) | as `encrypting` | n/a |
| `cancelled` (abort before the restart, decision 14/27) | cleanup done: boots as before. `CleanupPending`: a stale initrd converts the disk at that boot; I2 adopts at the next agent start — `encrypting`, `disk.conversion_started` moves the row from `cancelled` to `encrypting` (refused and audited only when the device has another open row), module and conf reinstalled, initrds rebuilt (I1) — gate S-IE4 (decision 53) | during `CleanupPending` a rebuild drops the module from the rebuilt initrd only; `plan.env` stays until (3) passed | n/a | device `conversion_pending` while `CleanupPending`, accepts once (4) ran; server 200 (row `cancelled`) | normal | (1)–(3) retried every full pass; the key and `plan.*` stay until (3) passed; `cleanup_pending` in the preflight; the row stays `cancelled` on the server until an adoption |

### Amendment 2026-10-21 — row ordering of decisions 6 and 36 (decided by the orchestrator as architect)

Found in the review of PDK-241: decision 9 lets the device adopt an older `failed` or `cancelled` row (I2), so the
newest row by `requested_at` is not always the conversion the disk carries. Invariant I1 is binding over the literal
"latest row" wording of decisions 6 and 36:

- The server's **latest conversion** of a device (`Device.disk_conversion`, `DiskEncryption.disk_conversion`, the
  open-conversion checks of decisions 7, 8, 38, 39 and the `disk_conversion_failed` attention entry of decision 6) is
  the open one first, then the one whose phase changed last: ordering `(phase IN ('requested','prepared','encrypting'))
  DESC, phase_at DESC, id DESC`, in `GetLatestDiskConversion` (`queries/disk_conversion.sql`) and in the attention view's
  subquery. Migration `00066_disk_conversion.sql` (not yet merged) carries it directly.
- **Active** (decision 36, replaced by the architect lead on 2026-10-21; it supersedes "completed + health ≠
  `compliant`"): `DeviceDiskConversion.active` is true iff (a) the latest row is open (`requested`, `prepared`,
  `encrypting`), or (b) the last health reports `disk.state = encrypting`, or (c) the last health reports
  `disk.conversion.key_on_boot = true`, whatever the rows say (widened in the second review round of PDK-241: also a
  `failed` row or no `completed` row; exactly the `!InitrdRegenerated` window of decision 52, which encodes I1), or (d)
  fail safe: the device's latest completed row — the latest row or an adopted older one — is
  less than 30 days old and the health is missing or carries no `conversion` block. Otherwise it is not active: a
  long-converted device that later reports `escrow_pending` or `tpm_pin_missing` does not block the uninstall.
  Confirmed by the orchestrator as architect: "latest completed row" is the device's latest completed row, whether
  or not it is the latest row; and a health with state `compliant` counts as not active, also within the 30 days of
  (d), because the agent never reports `compliant` before the initrd was regenerated (decision 3), so I1 holds, and
  gate S-IE1 expects `active: false` at `compliant` (decision 51).
- Decision 9: `disk.conversion_completed` also moves a `cancelled` row (an adoption refused while another row was
  open) to `completed`.
- The admin API's `DeviceCommand` gains `params` (what gate A1 asserts); command params never carry secrets — a
  command that needs one references it and never embeds it (`pkg/command.Command`, `admin.yaml`).

### Amendment 2026-10-21 — encrypt-abort handshake (decision 14; decided by the orchestrator as architect)

Found while implementing PDK-243: decision 14 has `paddockd encrypt-abort` act on the device itself, but the agent is
the only writer of `state.json` and the event spool and no agent lock exists. Decision 14 is corrected as follows:

- `paddockd encrypt-abort` never writes `state.json` or the spool; the agent stays the only writer.
- The subcommand writes a root-only request `/var/lib/paddock/encrypt-abort.request` (0600, atomically through a
  temporary file and a rename) carrying a nonce, the `conversion_id` and `by=operator`. On its session tick the agent
  claims the request by renaming it, runs the `encrypt_disk_abort` path (decision 14, the I3 order with
  `CleanupPending`), answers in `/var/lib/paddock/encrypt-abort.response` with the same nonce, and removes the request.
  The agent ignores and removes a request older than 30 minutes.
- Exit codes: 0 aborted; 2 refused (for example the disk is LUKS already, I1); 1 when no agent claimed the request
  within 60 s. The subcommand then withdraws the request and nothing on the disk has changed. If the agent claimed
  the request but the subcommand stopped waiting (interrupt or timeout), it also exits 1 and says the outcome is
  unknown. It never claims "nothing changed" once a claim is possible.
- The runbook section "Aborting without a running agent" follows in PDK-247.
- `state.Conversion` carries `module_written`. The agent saves it before step 7 writes the first module file, so a
  cleanup in this or any later run knows that an initrd may carry the module and the key.
- Once step 7 has started, the X1 cleanup deletes the conversion key and the plan only after every installed kernel's
  initrd has been verified clean (`lsinitrd`, falling back to `lsinitramfs`) or no initrd exists. Otherwise
  `CleanupPending` stays set and the cleanup is retried at every full pass.
- Operator remedy for a `cleanup_pending` that does not clear because a foreign or old dracut-built initrd still
  carries the module: rebuild that initrd with the initramfs tool in use (or remove that kernel); the agent's next
  retry then completes the cleanup. The full runbook text follows in PDK-247.

### Amendment 2026-10-21 — dracut catch-all and rd.luks=0 (decided by the orchestrator as architect)

Found while implementing PDK-244. The binding text of decisions 2, 15 and 16 is corrected as follows:

- **dracut's catch-all LUKS rule.** Decision 15 makes the module depend on `crypt`. On a host without a crypttab and
  without `rd.luks.uuid`, the `crypt` module's `parse-crypt.sh` installs a udev rule that, for every `crypto_LUKS`
  device, runs `crypt-run-generator` in the settled initqueue. The initqueue runs after the init unit, which is
  `Before=dracut-initqueue.service`. The generator adds `luks-<uuid> <dev> none` to the initrd's crypttab and starts
  `cryptsetup.target`. `systemd-cryptsetup` then asks for a passphrase on the console before it finds the partition
  held by `<mapping>`, both at the conversion boot (the udev watch change event after the header write) and at every
  later open boot, so the boot waits at a prompt nobody can answer.
- **Decision 15, addition.** `install()` also writes `rd.luks=0` to `$initdir/etc/cmdline.d/91paddock-encrypt.conf`.
  dracut's `parse-crypt.sh` reads it with `getarg` and removes its `70-luks.rules`, which takes away the prompt. It
  does not affect `systemd-cryptsetup-generator`, which reads only `/proc/cmdline`. It is safe under I1 and decision
  20: step (2) removes the module before (3) rebuilds, so no initrd keeps the module once the crypttab line with the
  TPM keyslot takes over. An initrd that carries both (a kernel update between (1) and (2)) runs
  `systemd-cryptsetup@<mapping>` and the script side by side. That race is benign: whichever opens first wins, the
  script counts an existing mapping as opened, and `systemd-cryptsetup` succeeds on an active volume.
- **Decision 15, `check()` and the key.** `check()` tests only `plan.env`, as written. `installkernel()` fails (dracut
  `dfatal`) when `/var/lib/paddock/install-passphrase` is missing. dracut ignores the status of `install()` but stops
  on `installkernel()` and keeps the previous initrd, so no initrd is built with the plan but without the key. This is
  safer than having `check()` drop the module: a module that is silently dropped while the partition is LUKS leaves
  an initrd with no unlock path (I1). `install()` also installs `blkid` and `readlink`, and `plymouth` when the host
  has it (`inst_multiple -o`).
- **§6.4, the unit.** `TimeoutStartSec=infinity` replaces `2h` (corrected in place above). A timeout that kills
  `resize2fs` or the header write is worse than a slow boot.
- **Decision 2, new reasons `hibernation_configured`, `lvm_devicesfile`, `lvm_filter`, `lvm_unknown`.**
  - `hibernation_configured`: `resume=` on `/proc/cmdline`, in `/etc/cmdline.d/*.conf` or in a `kernel_cmdline` of
    `/etc/dracut.conf.d/*.conf` or `/usr/lib/dracut/dracut.conf.d/*.conf`, `/sys/power/resume` other
    than `0:0`, or the `HibernateLocation-8cf2644b-…` EFI variable. Nothing orders the module against
    `systemd-hibernate-resume`, so a resumed kernel would write over the shrunk file system and the header. The init
    script also skips with `PADDOCK_BOOT_STATUS=skipped`, reason `resume_set`, when dracut's `getarg resume=` finds
    one. This check comes after the `isLuks`/open stage and before the mains check.
  - For the `lvm` layout only: `lvm_devicesfile` when `lvm config --typeconfig full devices/use_devicesfile` prints
    `use_devicesfile=1` and `/etc/lvm/devices/system.devices` exists; `lvm_filter` when `lvm config --typeconfig diff
    devices` prints a `filter=` or `global_filter=` line (the command for the two nodes alone exits 5 when they are
    unset, the default: review 2 of PDK-244). In both cases LVM would not see the PV once it moves onto
    the mapping. `lvm_unknown` when either `lvm config` call fails or prints something unexpected (not
    `use_devicesfile=0|1`; output that does not start with `devices {`). Empty output of the second call means
    nothing differs from the defaults. The `lvm config` commands and the `dracut.conf.d` resume scan were confirmed by the
    orchestrator as architect, 2026-10-21. Supporting the devices file (`lvmdevices --adddev`/`--deldev`)
    is a later feature; PDK-247 checks the 26.04 default on the throwaway VM.
  - The portal texts for these reasons are relayed to PDK-246.
- **Decision 16, `e2fsck -f -p`** replaces `-f -y`. Exit 0 or 1 continues; any other exit is reported as `fsck_<exit>`.
  The script never repairs more than a preen does.
- **Decision 16, splash.** When `plymouth --ping` succeeds, the script runs `plymouth display-message --text="Encrypting
  the disk - do not switch off"` before the shrink and again before the LUKS init.
- **Decision 2, new reason `other_luks_present`.** Because `rd.luks=0` also leaves every other LUKS volume closed,
  the preflight lists `lsblk --noheadings --list --paths --output NAME,FSTYPE` and fails with `other_luks_present`
  when a `crypto_LUKS` device lies outside the root chain. A failing `lsblk` fails closed with the same reason.
  Portal text (binding, §6.6): `devices.disk.convert.reasons.other_luks_present`: en "another encrypted volume is
  present on the device", de "auf dem Gerät ist ein weiteres verschlüsseltes Volume vorhanden".
- **Decision 16, stage order.** The stages run in this order: (1) device wait; (3) `cryptsetup isLuks` and the open
  path; (2) mains; then (4)–(6). A header on the disk decides before anything else (I2): a LUKS device that boots on
  battery must still be opened. `on_battery` is written before any tool that changes the disk; only `udevadm settle`
  and `cryptsetup isLuks` run earlier. A mapping that already exists counts as opened. After the mains check and
  before the shrink, the script checks that the partition named by the PARTUUID is the plan's: `blkid -p -s UUID -o
  value` must print `$PADDOCK_FS_UUID` (plain), or `lvm pvs --noheadings -o vg_name` must print `$PADDOCK_VG` (lvm),
  and `blkid -o device -t PARTUUID=…` must name exactly one device.
  Otherwise it reports `device_mismatch` and changes nothing, so a cloned disk is never touched.
- **Decision 16, stage 6.** The script first waits up to 30 s for `/dev/mapper/$PADDOCK_MAPPING`, which it otherwise
  reports as `mapping_missing`, and then up to 30 s for the root device. The plain root's
  `/dev/disk/by-uuid/$PADDOCK_FS_UUID` link already exists before the conversion, pointing at the raw partition, so
  for `plain` it must also resolve to a `dm-*` device.
- **Decision 16, stage 4.** After an `e2fsck` failure the script runs `lvm vgchange -ay "$PADDOCK_VG"`, not `-an`.
  `-an` would take the root LV away from the unencrypted boot.
- **Decision 16, stage 5.** After a failing init the script runs `cryptsetup isLuks` again. If the header exists,
  it opens the mapping and continues with stage 6 as an online reencryption. Otherwise it reports `luks_init_<exit>`.
- **Closed reasons added** (stage `init` unless noted): `resize2fs_<exit>`, `lvreduce_<exit>`, `pvresize_<exit>`,
  `vg_activate_<exit>` (stage `init` or `open`), `size_unknown` (`blockdev`, `lvm pvs` or `dumpe2fs` gave no
  number), `plan_invalid` (the plan is missing or lacks a value), `device_mismatch`, `mapping_missing`,
  `resume_set` (status `skipped`), `isluks_<exit>` (`cryptsetup isLuks` neither said
  yes nor no), and `script_<exit>` (the script's main part ended without a result). The open stage's reason
  (`<stderr line>`) is reduced to `[A-Za-z0-9_.:-]` (other characters become `_`) and cut at 200 characters.
- **Residual, accepted.** The binding unit is not ordered against `systemd-fsck-root.service`. `e2fsck` and
  `resize2fs` open the device exclusively, so a concurrent fsck ends this conversion fail-safe with `fsck_8`,
  `resize2fs_<exit>` or `vg_busy`. `systemd-fsck` ignores its own exit 8.
- **RR-56 reworded (PDK-248 carries it into `residual-risks.md`).** "The shrink is not crash-safe. `e2fsck -f`,
  `resize2fs` and `lvreduce` run at the conversion boot before the system starts. They take minutes, and longer the
  larger and slower the disk (a full check and an inode move on a spinning disk can take well over ten minutes). A
  power cut or a forced power-off in that window can damage the root file system. Mitigation: mains power required
  when a battery exists; the splash says "Encrypting the disk - do not switch off" and the console shows each step;
  the unit has no timeout; `e2fsck -f -p` before; the backup acknowledgement in the dialogue; idempotent stages.
  Record: the backup policy for devices that are converted."
- **RR-59, addition.** A laptop whose only charger is USB-C (power supply type `USB`, no ACPI `Mains` supply) is always
  seen as on battery, so its init step always skips with `on_battery`. This fails safe, but such a device can never
  be converted.
- **Verification items for PDK-247 (VM gates).** (a) On a device in the decision-20 window, an initrd that carries
  both the crypttab line and the module boots: `systemd-cryptsetup@<mapping>` and the script race, and one opens
  the volume. (b) `systemctl show -p After systemd-fsck-root.service` in the initrd shows whether the fsck can run
  concurrently with the module at all. (c) Whether 26.04 has the LVM devices file enabled by default. (d) A
  `resume=` set only through `kernel_cmdline` in `/etc/dracut.conf.d` is refused by the preflight
  (`hibernation_configured`); if one slips through, the init step skips with `resume_set`.

### Amendment 2026-10-21 — resume and completion interpretations (decided by the orchestrator as architect)

Found while implementing PDK-245. The binding text of decisions 3, 18, 21, 22 and 52 is made precise as follows:

1. **Decision 3/52, health while unencrypted.** While the disk is `not_encrypted`, `health.disk.conversion` carries
   `phase` and `key_on_boot` from the conversion state next to the preflight (so `key_on_boot` is true from
   `prepared`). The failure fields of decision 3 stay with PDK-364.
2. **Decision 18, a failed or skipped init step on a partition that is not LUKS** fails the conversion at stage `init`
   and starts the I3 cleanup only in phase `preparing` or `prepared`. In `cancelled` or `failed` (a stale initrd ran
   during an unfinished cleanup) the boot result is logged and removed; the phase is kept, no second
   `disk.conversion_failed` is emitted, and the running cleanup goes on.
3. **Decision 52, the re-arm** of `/var/lib/paddock/disk-setup-pending` happens only while the root volume has no
   `tpm2` or `tpm2+pin` keyslot. Once a TPM keyslot exists the marker would make the dialogue enroll again at every
   boot and hold the `luks` reconciler, which waits while the marker exists.
4. **Decision 22, "per boot".** `ResumeFailures` is reset at every agent start; after 3 failed results the helper is
   not relaunched until the next start.
5. **Decision 21, `duration_s`** is the sum of the intervals in which cryptsetup ran during this helper run. Waits on
   battery do not count, and `progress.json` carries nothing across helper runs.
6. **Decision 22, clearing.** `state.Conversion` is cleared once the phase is `completed`, `InitrdRegenerated` is true,
   no cleanup is pending and the disk reports `compliant` or `escrow_pending`. Decision 3's hold ends with
   `InitrdRegenerated`.
7. **Decisions 20 and 21, plan.json** (review 1 of PDK-245, B1). Decision 20 may run while the conversion is still
   encrypting (the TPM keyslot exists from the conversion boot under `tpm_only`, or once the PIN is set), and the
   helper reads the plan. Step (5) therefore removes plan.json only when the phase is `completed`; otherwise it stays
   until the conversion is cleared (item 6), which removes it before `state.Conversion` is cleared. As a second
   guard the agent passes the partition to the helper: `paddockd encrypt-resume --partition <partition>`. The helper
   resumes without plan.json and fails with `resume_plan_mismatch` when both name different partitions.
8. **Decision 20, the rebuild** (adversarial review of PDK-245, M1; invariant I1). No working initrd is replaced by
   one that was not verified. The order becomes:
   (1) the crypttab line;
   (2) for every bootable kernel (`/boot/vmlinuz-<v>`, or a current `/boot/initrd.img-<v>`; a leftover
   `/lib/modules/<v>` without either has no boot entry), `dracut -f --omit paddock-encrypt <tmp> <v>` into
   `/boot/.initrd.img-<v>.paddock`. The new initrd is verified with `lsinitrd`: the crypttab line for the volume,
   `systemd-cryptsetup` and the TPM2 libraries (`libtss2`), and none of the module, the key or the plan. Only when every
   kernel passed are the files renamed into place;
   (3) only then are the module's configuration and directory, test-hooks and plan.json (item 7) removed, plan.env last.
   While (2) fails, the current initrds and the host files stay, the temporary files are removed, and the next full
   pass retries.
9. **Decision 21, exit 0 as mains is lost.** When cryptsetup ends just as the helper stopped it for a lost mains
   supply, the helper checks the header first; without a `reencrypt` keyslot it writes `completed` instead of waiting
   on battery.
10. **Decisions 39 and 22, after a revocation hand-over** (replaced in fix round 2; not a 24-hour window). A
    revocation handed to paddock-revoke at any time after the conversion started encrypting (`StartedAt`) makes the
    conversion terminal on the device until `state.Conversion` is cleared (re-enrollment or reset). The helper is not
    relaunched, a disk without the `reencrypt` keyslot is not reported `completed`, and a result the helper wrote is
    discarded without an event. The initrd work of decisions 18, 20 and 52 (PIN re-arm, rebuild) does not run, at
    start, at a full pass, or from a job the worker had queued before the hand-over. The hand-over is recorded as `state.Conversion.RevokedAt` in the same save as the
    envelope's hash, so the pruning of `HandedRevocations` after 31 days does not end it. A hand-over before
    `StartedAt` (refused, the disk was unencrypted) does not count. `activating`, `reloading` and `deactivating`
    count as running, both for the launch check and for the stop before the hand-over.
11. **I2 for a state that says converted, and helper runs without a result** (adversarial review m3). When the state
    says `encrypting` or `completed` but `cryptsetup isLuks` says the partition is not LUKS and `luksDump` fails as
    well, the conversion fails at stage `init` with reason `not_luks`, and the cleanup of invariant I3 runs. A helper
    run that ends without a result counts as a failed run (`resume_no_result`) toward the limit of item 4.
12. **Item 8, reading lsinitrd** (review 2 of PDK-245). lsinitrd prints dracut's command line (`Arguments: -f --omit
    'paddock-encrypt'`, from `build-parameter.txt`). That line is not content and is skipped when an initrd is checked
    for the module, here and in the I3 cleanup. A systemctl that cannot say whether the helper runs counts as running
    for the launch, but never as a helper that ended without a result. Item 10 also holds at the agent's start. The
    verification of item 8 reads dracut's module list with `lsinitrd -m` and the file entries by exact path (no
    module, `etc/crypttab`, a file named `systemd-cryptsetup`, a `libtss2-*` library, none of the module's files).
13. **"Not LUKS" needs positive evidence** (adversarial review round 2 of PDK-245, B1; invariant I1). A cleanup may
    remove the unlock path only when the partition is known not to be LUKS. `encrypt.IsLUKS`, the one helper for the
    adoption, the not-converted check of item 11, the cleanup retry, the abort and the init-failure path, answers
    LUKS when `cryptsetup isLuks` exits 0. It answers "not LUKS" only when all of these hold:
    - the conversion's `/dev/mapper/<mapping>` is not active;
    - no `/dev/disk/by-uuid/<luks uuid>` exists;
    - `blkid -o device -t PARTUUID=<uuid>` names exactly one device (a cloned unencrypted disk plugged in makes the
      link ambiguous);
    - `cryptsetup isLuks` exits exactly 1.
    Anything else is unknown, which never cleans up and is retried. After a boot result `ok` no "not LUKS" leads to a
    cleanup until the agent's next start. After the renames of item 8 the bootable kernels are listed again and
    every initrd is verified once more: a kernel installed during the rebuild keeps `InitrdRegenerated` false, and the
    next full pass rebuilds it.
14. **dpkg's locks and the helper's unit state** (adversarial review round 3 of PDK-245; invariants I1 and I3). A
    kernel package's own dracut run (postinst) could otherwise finish after a verified rename and write an initrd
    with the module and the key but without the crypttab line, or rebuild one with the module after the I3 check.
    Decision 20's steps (1) to (3) and the cleanup's steps (1) to (4) therefore hold dpkg's locks, taken as apt takes
    them: fcntl write locks on `/var/lib/dpkg/lock-frontend`, then `/var/lib/dpkg/lock`, without waiting. While a
    package run holds them, nothing changes and the next full pass retries; the agent never waits while it holds the
    state. Under the locks, every installed kernel's initrd is verified again right before the module leaves the host
    (item 13). The I3 check right before (4) is that verification for the cleanup. The cleanup removes the module's
    configuration before its directory, so that an interrupted removal never leaves a configuration naming a missing
    module, which would fail every dracut run. `systemctl is-active` counts as stopped only with `inactive` or
    `failed` on stdout. Any other answer (an error, empty output, an unknown state) is unknown: running for the
    launch, never a failed run.
15. **Initrd tools, the kernel set, and boot ok first** (adversarial review round 4 of PDK-245).
    - Decision 2 gains the reason `initrd_tools_missing`: with dracut installed, `lsinitrd` must list the running
      kernel's initrd (dracut-ng's lsinitrd needs 3cpio or dracut-extractinitrd). Under initramfs-tools, lsinitrd
      arrives with dracut, so step 8 of decision 13 checks it (`initrd_incomplete`). PDK-247 checks the 26.04 case on
      the throwaway VM, and PDK-248 adds the portal text.
    - The kernels the conversion rebuilds and requires to pass (item 8 and the reinstall of decision 18) are the set
      `dracut --regenerate-all` builds (corrected by item 17): every `/lib/modules/<v>` with `modules.dep` or
      `modules.dep.bin`. A leftover initrd or
      module directory of a removed kernel is ignored there. The I3 check of a cleanup still reads every initrd it
      finds.
    - A boot result `ok` is recorded before any look at the disk. During that start no "not LUKS" answer leads to a
      cleanup, in any phase.
    - A worker job re-checks item 10 before each change it makes.
    - PDK-247 asserts on the VMs that the cancelled and failed:init cleanups finish, because the not-LUKS rule needs
      blkid's PARTUUID lookup as root.
16. **dpkg's locks without blocking apt, the supervisor upgrade, and a hand-over during the work** (final adversarial
    review and PDK-374). These amend item 14.
    - Decision 20's new initrds are built and verified without dpkg's locks. Under the locks come only these steps:
      the check that no bootable kernel was added or removed and that no current initrd changed since its build
      started (size and mtime), the renames, the final verification and the removal from the host. A change means
      nothing is replaced and the next attempt rebuilds.
    - The reinstall of decision 18 and step 8 of decision 13 run their `dracut --regenerate-all` and verification
      under the locks. The reinstall re-lists the kernels after verifying.
    - A busy lock is a transient error. The agent backs off every failed cleanup, reinstall or regeneration: 5
      minutes, doubling, at most 6 hours. A success resets it, and an agent start retries at once. The PIN re-arm of
      decision 52 is not delayed.
    - Within the agent one section holds the locks at a time (an in-process mutex, since fcntl locks belong to the
      process).
    - Decision 37, extended: no supervisor upgrade starts while the conversion worker runs or a cleanup is unfinished.
      An upgrade that dpkg refuses because another package run holds its lock is `deferred`, a device-local outcome:
      no event, no failure and no attempt counted, retried after 10 minutes, doubling up to 6 hours.
    - A revocation hand-over cancels a regeneration the worker runs. Item 10 is checked again before every change and
      before `InitrdRegenerated` is saved, and a cancelled regeneration replaces no initrd and leaves no temporary
      file. The reinstall's `--regenerate-all` is not killed, because it writes initrds in place.
17. **Review 6 of PDK-245** (decided by the orchestrator as architect). It amends items 15 and 16.
    - A busy dpkg lock is no failure. Step 8 of decision 13 waits and counts no transient retry, because an apt run
      may hold the locks for many minutes. The cleanup, the reinstall and the regeneration retry at the next pass,
      and their backoff (item 16) grows only on real failures.
    - Decision 37's busy rule covers only the conversion worker, not an unfinished cleanup. A cleanup may never
      finish, and it must not hold supervisor upgrades back silently. The same holds for the whole
      `!InitrdRegenerated` window: a skipped PIN can last weeks and must not block supervisor updates. A lock
      collision only defers the upgrade (item 16).
    - The kernel set of item 15 is what dracut 060's `--regenerate-all` builds: every `/lib/modules/<v>` with
      `modules.dep` or `modules.dep.bin`. A vmlinuz is not required.
    - A cleanup that does not finish logs its reason at warning level. The health reports the reason of the last
      attempt as `disk.conversion.cleanup_error` (first line, at most 200 runes) next to the reason
      `cleanup_pending`. The server and the portal show it with PDK-379 (see item 18).
    - At every agent start, under dpkg's locks, the agent removes temporary initrds a killed regeneration left
      (`/boot/.initrd.img-<v>.paddock`, that pattern only). While a package run holds the locks they stay until the
      next start, and a later regeneration overwrites them.
    - The conversion worker runs no cleanup, reinstall or regeneration while a supervisor upgrade runs
      (`supervisor-upgrade.json`, younger than 30 minutes; review 7 of PDK-245). The upgrade's rollback restarts
      the supervisor and kills the agent, and with it a `--regenerate-all` writing an initrd in place. The next
      full pass retries, without a backoff. The upgrade itself is not held back.
    - Item 10's re-check before the reinstall of decision 18 is dropped. Only the PIN re-arm's file write lies
      between it and the re-check after the keyslot dump. The re-checks after the dump, before the regeneration
      and before `InitrdRegenerated` is saved remain.
18. **Review 7 of PDK-245 and the following adversarial reviews** (decided by the orchestrator as architect).
    - A supervisor upgrade and the conversion's initrd work exclude each other in both directions. While a
      conversion step runs, no upgrade starts (decision 37 and item 17). While `supervisor-upgrade.json` exists, no
      cleanup, reinstall or regeneration runs: they are deferred, not failed. In addition, the cleanup of decision
      14 and the reinstall of decision 18 rebuild like decision 20: every bootable kernel's initrd is built into
      `/boot/.initrd.img-<v>.paddock` (`dracut -f <file> <v>`), verified, and renamed into place only when every
      one passed, never an in-place `--regenerate-all`. A killed rebuild leaves only temporary files, which the
      start removes (item 17). Step 8 of decision 13 keeps its in-place rebuild, because the disk is still
      unencrypted then.
    - Decision 20 probes dpkg's locks before its builds: while a package run holds them it builds nothing and
      retries at the next pass.
    - Step 8 waits for a held lock without a time limit, because the conversion simply stays `preparing`: a
      failure after step 7 would start a cleanup that needs the same lock. The health reports `paused_reason:
      packages_busy` with `paused_since`, the start of the wait, in its health and the conversion state. The server
      and the portal do not show it yet: the server drops `paused_reason` outside `encrypting` and does not read
      `cleanup_error`, `initrd_issue` or the boot-space fields. Their display is PDK-379, a separate ticket before
      the alpha.5 release. Decision 37's hold applies only while the worker runs a step, not to a
      preparation that waits between its passes. The wait has no upper bound, and holding upgrades during it would
      let a foreign dpkg process block the agent's update channel, the only way to ship a fix to that device,
      indefinitely. That conflicts with fail safe. A lock collision only defers the upgrade (item 16). A new agent
      version picks the waiting preparation up from `plan.json` and the conversion state (decision 13's idempotent
      steps).
    - The cleanup's reason is kept in the conversion's state (`cleanup_error`) and cleared whenever `CleanupPending`
      is set or cleared, so the health never shows the reason of an earlier cleanup.
    - The start takes dpkg's locks only when a temporary initrd is left over.
19. **Room in /boot and stuck initrd work** (review 8 of PDK-245, decided by the orchestrator as architect). This
    amends items 16 to 18.
    - Every rebuild (decision 20, the cleanup, the reinstall) works through the kernels strictly one at a time:
      build the temporary file, verify it, and rename it into place, then the next kernel. At most one temporary
      initrd exists in `/boot` at any moment. Decision 20 renames under dpkg's locks with its stamp check per kernel
      and verifies every initrd again before the module leaves the host.
    - Before each build, the file system holding `/boot` must have 1.5 times the size of that kernel's current
      initrd free (the largest existing initrd when it has none), plus 32 MiB. Otherwise nothing is built. The health
      reports `initrd_issue: boot_space_low` with `boot_space_needed` and `boot_space_free`, the step stays pending
      and is retried with the backoff of item 16. It is never a failure of the conversion.
    - A build that runs out of space, or any other failed build or verification, removes its temporary file and
      leaves the current initrd untouched: the rename is the only write to the real file. A build that runs out of
      space also reports `boot_space_low`.
    - `InitrdRegenerated`, a finished cleanup and a finished reinstall are recorded only once every kernel has its
      verified new initrd. I1 holds, because an existing initrd is never replaced by an unverified one.
    - Without a kernel that `--regenerate-all` would build, the cleanup, the reinstall and the regeneration report
      `initrd_issue: no_bootable_kernel` and stay pending with the backoff.
    - `PackagesBusySince` ends on every path that leaves the wait: step 8 takes the lock, an abort, a failure, an
      adoption, or a revocation hand-over.
    - (g) **Orphan initrds.** A kernel without `/lib/modules/<v>/modules.dep` (or `modules.dep.bin`) can neither
      boot nor be rebuilt. When its initrd carries the module, the cleanup overwrites and removes that initrd
      (otherwise the key would stay on the unencrypted `/boot` for good), logs a warning with the kernel version, and
      reports `initrd_issue: orphan_initrd_removed` once (it stays until the conversion ends). An orphan initrd
      without the module stays, and a kernel with `modules.dep` is never touched this way. The cleanup and every
      rebuild also remove every temporary initrd (`/boot/.initrd.img-*.paddock`) under the locks, before and after
      their builds. A cleanup finishes only when none is left, because one a killed reinstall left (of a kernel
      removed since) would carry the key.
    - (h) **Step 8 as well.** Step 8 of decision 13 rebuilds through the same path: per kernel, the room checked,
      a temporary file, verified (all files of the init step), renamed. Too little room reports
      `initrd_issue: boot_space_low` and waits like `packages_busy` (no retry counted), and the original initrd
      stays. No Paddock path runs an in-place `dracut --regenerate-all` any more. Item 18's reason for an exception
      (the disk is still unencrypted) did not cover a full `/boot`.
    - Every Paddock dracut call passes `--no-uefi`, so the output is a plain initrd whatever `uefi=yes` the host
      configured. The verification also rejects a file that starts with the PE signature `MZ`.
    - A build first removes the same kernel's own temporary file a kill left, so it does not count against the room.
      The room is the file system's free blocks (`Bfree`, not `Bavail`): the agent runs as root and may use the
      blocks reserved for root, and the margin of 1.5 times plus 32 MiB is the buffer.
    - The initrd issue is updated when an attempt of the initrd work ran. A pass that does not attempt it (dpkg busy,
      not due yet, a supervisor upgrade) keeps the last issue until the next attempt.
    - (i) **Stray initrds.** The kernels a cleanup checks (I3) include every regular file `/boot/initrd.img-<v>`, not
      only the kernels with a vmlinuz or a module directory. An initrd left by a kernel removed without it is found
      that way. When it carries the module and its kernel is not bootable, it is removed like an orphan (g).
      Symlinks are never looked at or followed. A non-bootable kernel whose initrd is a symlink keeps the cleanup
      pending instead.
    - (j) Decision 20's regeneration removes the temporary initrds at its start (under the probe of the locks) and
      in its final locked section, before the host files go.
    - (k) **Bootable and buildable.** A kernel is *bootable* with `/lib/modules/<v>/modules.dep` or
      `modules.dep.bin`. A bootable kernel's initrd is never removed by the orphan rule, because it boots with it. A
      kernel is *buildable* with `modules.dep`. Before a rebuild (step 8, the cleanup, the reinstall, the
      regeneration) builds anything, every bootable kernel must be buildable. Otherwise nothing is built, the
      kernel's initrd stays, the health reports `initrd_issue: kernel_not_buildable` with `initrd_issue_kernel`, and
      the step stays pending with its backoff (step 8 waits without counting a retry). This narrows item 15's kernel
      set, which counted `modules.dep.bin` as buildable.
    - (i, continued) Every regular file counts. An unreadable file (a failed listing, a remnant, a truncated build) of
      a version without a kernel image (`vmlinuz-<v>`, `vmlinux-<v>`, `kernel-<v>` or a kept `vmlinuz-<v>.old`),
      `modules.dep` and `modules.dep.bin` is an orphan: it is removed, with a warning naming the file and the listing
      error, and reported as `orphan_initrd_removed`. A version with any of them is no stray: a listing error stays an
      error, and its initrd is never deleted. With no lister installed, no file is an orphan.
    - **Hard links and symlinks.** Every overwrite opens the file with `O_NOFOLLOW` and checks the open handle
      (`f.Stat()`), so that a name swapped after a check cannot redirect the zeros.
      - Rule A, pure key material (the conversion key, `install-passphrase`): always overwritten, whatever its link
        count, then unlinked; more than one link is logged as a warning. No bootable file shares it, so zeroing it
        erases the key under every name. Anything but a regular file is not written to, and the step fails closed.
      - Rule B, initrd-type files (orphans, strays, temporary initrds): the listed names are every regular
        `/boot/initrd.img-*` and `/boot/.initrd.img-*.paddock`, grouped by device and inode. A `/boot/initrd.img-*`
        symlink to a regular file is a reference to that file's group (a dangling link is ignored). For each file:
        (0) when a bootable kernel's symlink refers to it, nothing is written or unlinked, not even the target, so the
        link never dangles. The kernel stays among those carrying the module until its verified rebuild renames over
        the link. Where no rebuild runs (dracut in `config-files`, verify only), the step stays pending, and the health
        reports `initrd_issue: key_material_shared_bootable` with `initrd_issue_kernel`. (1) When every listed name of
        the file is to be removed and they are all its links, the file is overwritten once and every name is
        unlinked. (2) When a listed name of a bootable kernel shares the file, only the names to remove are unlinked
        and nothing is written; that kernel's verified rebuild replaces the file. (3) When the file has links outside
        the listed names, nothing is written or unlinked. The step stays pending, and the health reports
        `initrd_issue: key_material_hardlinked`, with path, inode and link count in the cleanup error and a warning
        in the log. Once the outside link is gone, the next attempt finishes. Every file is handled; one kept file
        does not keep the others from going (the errors are joined).
      - An orphan name that is a symlink goes with the file it refers to, by the same rules. One that points outside
        the listed names stays and keeps the step pending. At a temporary path, a symlink or FIFO is unlinked
        without any write; a directory is not removed and the step fails closed. Right before dracut runs, nothing
        may be at its temporary path. Every temporary initrd that does not go into place is removed by rule B, never
        by a plain unlink; a test checks the sources for that.
      - Overwrites write zeros only over the allocated ranges of a file (SEEK_DATA/SEEK_HOLE), in chunks of 1 MiB,
        so they allocate nothing and cannot fill `/boot`. On btrfs nothing is written (copy-on-write would allocate
        new blocks and keep the old ones); the names are only unlinked, with a warning. A failed write (no space left,
        any other error) empties the file (`ftruncate` to 0) and the names are unlinked, with a warning: no partly
        overwritten file keeps taking room.
      - A finished cleanup clears every initrd issue and its fields, except `orphan_initrd_removed`, which stays
        until the conversion ends. A cleanup that stops for another reason clears `key_material_hardlinked` and
        `key_material_shared_bootable`.
      - **Residual risk (RR-71, reserved; PDK-248 writes the row).** Freed blocks of the unencrypted `/boot` can hold
        the conversion key: blocks freed by a rename over an older initrd or by unlinking a name are not zeroed;
        zeroing does not reliably erase data on copy-on-write file systems (btrfs is not even written), on SSDs (wear
        levelling, TRIM) or with ext4 `data=journal`. The key is worthless once its keyslot (the install keyslot) is
        wiped. Right after `InitrdRegenerated` is recorded, the worker runs the M4b luks reconciler's own pass on the
        run loop, which wipes the keyslot and then shreds the key file, with every precondition unchanged. The window is
        therefore normally seconds; after a crash in between, or while a precondition of the reconciler does not hold
        (its error in the health), it lasts until the next successful pass. This is far smaller than the window that
        exists by design: the key lies in the live initrd on `/boot` for the whole conversion (`key_on_boot`). The abort
        path is not affected: no keyslot ever existed for that key.
    - Waiting for room in `/boot` or for a buildable kernel is not waiting for dpkg's locks. It counts no retry,
      leaves `PackagesBusySince` and `packages_busy` alone, and sets all four initrd-issue fields, clearing the
      ones that do not apply.

### Amendment 2026-10-22 — enrollment after completion (stop condition S2; decided by the architect lead)

Stop condition S2 (§11) was hit in PDK-247, gate S-IE2 on Ubuntu 24.04 (cryptsetup 2.7.0, systemd 255), on
2026-10-22: at the conversion boot — boot 2 after the shrink, the header written, root on `dm_crypt-0` —
`paddock-disk-setup` under `tpm_only` ran `systemd-cryptenroll --tpm2-device=auto` three times, and every attempt
ended with `Operation incompatible with device marked for LUKS2 reencryption. Aborting. Failed to add new TPM2 key
to /dev/sda3: Invalid argument`. The unit ended, the boot went on fail safe, the marker stayed, so every later boot
repeated the three attempts; the agent reported `encrypting`, `initrd_regenerated: false`, the reencryption ran.
libcryptsetup refuses a keyslot addition while the header carries the `online-reencrypt` requirement — the claim
of ADR 0039 (correction 3, "the PIN can be enrolled during the reencryption") was wrong; ADR 0039 amendment
2026-10-22 records it. Gate S-IE1 (26.04, `tpm_pin`) never exercised the enrollment during `encrypting` because
decision 51 skips the PIN at the conversion boot; the same rule most likely holds there (PDK-247's probe
`probeEnrollWhileEncrypting`, which enrolls into a copy of the header on a loop device, is the evidence). The
fallback design named in S2 is adopted:

22. **The enrollment — the PIN dialogue under `tpm_pin`, the automatic TPM enrollment under `tpm_only` — happens
    only after `completed`.** Binding changes:
    - **Decision 13 step 5** writes only `/etc/paddock/disk-setup.json`; it no longer creates
      `/var/lib/paddock/disk-setup-pending` (`agent/internal/encrypt/prepare.go::(*Preparer).diskSetup`). The
      conversion boot and every boot during `encrypting` run no dialogue and no enrollment.
    - **The marker is set at `completed`.** The agent arms `/var/lib/paddock/disk-setup-pending`
      (`encrypt.RearmDiskSetup`, called from `agent/internal/agent/encrypt.go::(*Agent).finishConversion`) only
      while `state.Conversion.Phase == "completed"` and the root volume has no `tpm2` or `tpm2+pin` keyslot —
      never while `encrypting`. Decision 52's "encrypting or completed" becomes "completed"; the re-arm at every
      start and full pass stays, so a skipped PIN is asked again at every boot. Under `tpm_only` the first boot
      after completion enrolls the TPM without a dialogue (`disksetup.enrollTPMOnly`); under `tpm_pin` the
      dialogue appears at that boot and the user may still skip.
    - **`paddockd disk-setup` makes no attempt while the header is marked for reencryption**
      (`agent/internal/disksetup/disksetup.go::Run`): after `luks.Root` and before any dialogue text or
      enrollment, it reads `luks.Dump` and, when `md.ReencryptRequired()` or `md.Reencrypting()` is true, prints
      one line on the console — `Paddock disk encryption setup is deferred until the background encryption has
      completed.` —, logs one info line (`disk setup deferred: the volume is marked for reencryption`), keeps the
      marker and returns nil. No error, no `MaxEnrollFailures` counting, no attempt, in both unlock modes.
      `luks.Metadata` gains `Config` (`config.requirements.mandatory []string`, read from the dump's JSON) and
      `func (m Metadata) ReencryptRequired() bool`, true when a mandatory requirement starts with
      `online-reencrypt` — the condition libcryptsetup checks; `Reencrypting()` (the `reencrypt` keyslot) is the
      second test, so a header with either mark defers. The agent uses the same two tests (next bullet).
    - **Health.** `protocol.DiskConversion` (decision 3) gains `EnrollmentDeferred string
      json:"enrollment_deferred,omitempty"` with the single closed value `reencrypt`: set by the agent's
      `conversionHealth` while the phase is `encrypting`, the dump shows `ReencryptRequired()` or
      `Reencrypting()` and no TPM keyslot exists; empty otherwise (and after `completed`). The device and admin
      contracts (`api/openapi/device.yaml`, `admin.yaml`: `DiskConversionHealth.enrollment_deferred`, enum
      `[reencrypt]`) carry it (the admin schema is PDK-390's file; PDK-397 adds the field in both contracts and
      regenerates). The portal's progress panel (decision 25, state `encrypting`) shows the line
      `devices.disk.convert.enrollmentDeferred` (texts below) while it is `reencrypt`.
    - **Restart after completion.** At the transition to `completed`, while the marker is armed and no TPM
      keyslot exists, the agent shows the desktop notification of decision 28 once per graphical session (the same
      mechanism, the same 4-hour repeat, keyed in `state.Conversion.Notified` with the prefix `completed:`) with
      the texts of the `completed` row below; it stops once a TPM keyslot exists. The restart stays the user's
      action; the device never restarts on its own. Without the restart a `tpm_only` device stays `key_on_boot`
      and `active` (the uninstall refused) for good — the portal alert `devices.disk.convert.keyOnBoot` says so
      (text amended below).
    - **Consequences stated.** Decision 20 keeps its trigger (a `tpm2+pin` or `tpm2` keyslot) and therefore runs
      only after `completed` and a successful enrollment; `InitrdRegenerated` is set only after that enrollment and
      the verified rebuild, as before. The keyslot wipe right after the regeneration (amendment 2026-10-21,
      item 19; RR-71) stays tied to `InitrdRegenerated`. Decision 3's hold now spans the completion, the
      enrollment at the next boot and the regeneration. The `key_on_boot` window grows by the time between
      `completed` and the first boot after it (plus the time a user keeps skipping the PIN); RR-57 is extended
      (below). The gate that proves it needs no new VM: S-IE1, S-IE2 part B and S-IE4 assert no dialogue and no
      attempt at the conversion boot and during `encrypting` (`requireNoDiskSetup`, `requireNoFailedEnrollment`),
      the marker present after `completed`, the enrollment at the first boot after it, and the probe as evidence
      on both releases. Decision 51's "skip at boot 2" is void — nothing asks at boot 2 — and its first skip moves
      to the first boot after `completed`. The dracut module and the init script are not affected (they never
      touch the marker). The abort cleanup (decision 14) still removes the marker and `disk-setup.json`.
    - **Upgrade.** A device that is `encrypting` with a marker armed by an older agent: the new `disk-setup`
      defers without an attempt, the marker stays, and the flow continues at `completed`; the three-attempt loop
      ends with the agent update. No migration, no state change.
    - **§14.10.** I1 is unchanged in letter; made explicit: the key in the initrd and the conversion keyslot stay
      until the enrollment has succeeded (a TPM keyslot exists) and the rebuild without the module is verified.
      Table, row `encrypting`, column "PIN set / skipped": no dialogue and no attempt — the marker is not armed
      while `encrypting`; a leftover marker makes `disk-setup` return without an attempt and the health reports
      `enrollment_deferred: reencrypt`. Row `completed`, `!InitrdRegenerated`, column "Reboot": the marker armed at
      completion runs the dialogue (`tpm_pin`) or the enrollment (`tpm_only`) at this boot; a `tpm_only` device
      needs this one restart. Row `prepared`, column "Reboot": the conversion boot runs no dialogue.
    - **Stop conditions.** S2 is closed by this item. S15: `systemd-cryptenroll` refuses the enrollment after
      `completed` (the dump shows no `online-reencrypt` requirement and no `reencrypt` keyslot) on either release —
      report the dump and the output; do not retry in a loop.
    - **RR-57, extension** (PDK-248 carries it): "Because a keyslot cannot be added while the header is marked for
      reencryption, the boot PIN or the TPM unlock is enrolled only at the first start after the background
      encryption completed; until then, and for as long as a user keeps skipping the PIN, the conversion key in
      the initrd on `/boot` is the only unlock path. The device reports `key_on_boot` and `enrollment_deferred`,
      the portal says so, and the device asks the user to restart once the encryption completed."
    - **Texts (binding; `en.json` / `de.json`; §6.6 and §6.7).**

      | Key | English | German |
      | --- | --- | --- |
      | `devices.disk.convert.enrollmentDeferred` | The boot PIN or the TPM unlock is set up at the first start after the background encryption has completed; it cannot be added while the encryption is unfinished. | Die Boot-PIN bzw. die TPM-Entsperrung wird beim ersten Start nach Abschluss der Verschlüsselung im Hintergrund eingerichtet; während die Verschlüsselung unvollständig ist, kann sie nicht hinzugefügt werden. |
      | `devices.disk.convert.keyOnBoot` (replaces §14.8) | The disk is encrypted but not protected at rest yet: the key that unlocks it lies on the unencrypted boot partition until the background encryption has completed, the device has been restarted and the boot PIN or TPM unlock has been set up. The device asks for the restart and, under TPM + PIN, for the PIN at every start. | Die Festplatte ist verschlüsselt, aber noch nicht im Ruhezustand geschützt: Der Schlüssel, der sie entsperrt, liegt auf der unverschlüsselten Boot-Partition, bis die Verschlüsselung im Hintergrund abgeschlossen ist, das Gerät neu gestartet wurde und die Boot-PIN bzw. die TPM-Entsperrung eingerichtet ist. Das Gerät bittet um den Neustart und fragt unter TPM + PIN bei jedem Start nach der PIN. |
      | §6.7, `completed` summary | Disk encryption completed — please restart | Festplattenverschlüsselung abgeschlossen — bitte neu starten |
      | §6.7, `completed` body | The background encryption of this device has completed. Restart the device to finish the setup; under TPM + PIN you will be asked to choose a boot PIN at that start. Until then the disk is not fully protected. | Die Verschlüsselung dieses Geräts im Hintergrund ist abgeschlossen. Starten Sie das Gerät neu, um die Einrichtung abzuschließen; unter TPM + PIN werden Sie bei diesem Start gebeten, eine Boot-PIN zu wählen. Bis dahin ist die Festplatte nicht vollständig geschützt. |

    - **Ticket.** PDK-397 implements this item (agent, protocol and contracts, portal texts, unit tests); the VM
      evidence is PDK-247's gates S-IE1, S-IE2 part B and S-IE4 as amended above; PDK-248 carries RR-57, the
      runbook and the architecture note; PDK-390 takes the admin schema change if it lands first.

### Amendment 2026-10-22 — a Lock on a header marked for reencryption (stop condition S14; decided by the maintainer)

Stop condition S14 (§14.5 decision 39) was hit in PDK-247's hand test on 2026-10-22: a Lock during `encrypting`
(Ubuntu 24.04, `plain` layout, 2.5 % progress) ended with the result `{"erased": false, "slots_before": 2,
"slots_after": 1}`. Before the Lock the header held keyslot 0 of type `luks2` (the conversion key) and keyslot 1 of
type `reencrypt` (key_size 1, area type `datashift`, no key material, no data; requirement `online-reencrypt-v2`).
After `cryptsetup luksErase` the key-bearing keyslot was gone — the device no longer unlocks (dracut emergency
shell, the by-uuid link missing), and no header of this conversion is escrowed — but the `reencrypt` keyslot stayed,
so `paddock-revoke` (`agent/internal/revoke/revoke.go::eraseVolume`, `keyslots()`) counted `len(m.Keyslots)` of the
raw dump as 1 and reported the erasure as incomplete. The data was erased as a Lock intends; the report was wrong.
Decision 39's expected result ("the `reencrypt` keyslot counts as one … `slots_after: 0`") assumed that `luksErase`
removes the `reencrypt` keyslot; it does not. Side finding: ADR 0039's source table also claimed that
`crypt_keyslot_add_by_keyslot_context` carries no reencryption check, which the S2 evidence (amendment 2026-10-22,
item 22) contradicts; ADR 0039 amendment 2026-10-22 (S14) corrects both rows.

The maintainer decided on 2026-10-22 that `paddock-revoke` is changed now, before alpha.5, so that only key-bearing
keyslots count. This is a change to the revocation path under the two-person rule: the maintainer's decision is
the approval of the change; the verification on real hardware that the rule requires is part of PDK-399 and needs
the maintainer's separate approval before it runs (it is destructive on the device it runs on).

23. **Only key-bearing keyslots count** (`agent/internal/revoke/revoke.go`, the change of PDK-399):
    - **Definition.** A *key-bearing keyslot* is a LUKS2 keyslot whose JSON `type` is `luks2` — the only keyslot
      type of LUKS2 that holds key material — or, on LUKS1, an enabled keyslot (`Key Slot N: ENABLED`). Every other
      LUKS2 keyslot type (`reencrypt` today; any type cryptsetup adds later) holds no key material and is a
      *non-key keyslot*. The counting is the revoke package's own (`keyslots()` reads the `type` of every entry of
      `Metadata.Keyslots`); it does not use `luks.Metadata.Kinds()`, whose exclusion of `reencrypt` serves the
      reconciler's inventory and may change with it.
    - **Result.** `VolumeErasure.SlotsBefore` and `SlotsAfter` count key-bearing keyslots only; `Erased` is true
      iff `luksErase` exited 0 and `SlotsAfter == 0`; `Erasure.SlotsBefore`, `SlotsAfter` and `Erased` sum and
      combine the volumes as today (an unknown count stays `-1`, never erased). Additively, `VolumeErasure` gains
      `OtherSlotsAfter int json:"other_slots_after,omitempty"`: the number of non-key keyslots left on the volume
      after the erasure (the `reencrypt` keyslot of an unfinished conversion), so that the confirmation shows what
      stayed; it never affects `Erased`. `luksErase` stays the only erase command — `paddock-revoke` does not kill
      the `reencrypt` keyslot (it holds no key; `cryptsetup` may refuse a `luksKillSlot` on it under the
      requirement) — and the sequence of volumes, the time bounds and every refusal reason are unchanged.
    - **Server.** `server/internal/domain/revocation/confirmation.go::AllErased` is unchanged: it reads `erased`,
      `volumes[].erased` and `volumes[].slots_after`, which now carry the key-bearing counts; the parser ignores
      `other_slots_after` until the portal shows it (PDK-399 adds it to `VolumeConfirmation` and to
      `RevocationRequest.result.volumes[]` in `api/openapi/admin.yaml` as an optional integer, with the
      description of `result` corrected to "no key-bearing keyslot left"). The audit event
      `revocation.executed` keeps its params (`erased`, `slots_before`, `slots_after`, `volumes`, …); its
      description and note in `server/internal/domain/audit/codes.go` say "key-bearing keyslot" instead of
      "keyslot" (the code is unchanged; the generated `docs/compliance/audit-codes.md` follows). Older agents
      report the raw count as before; a server does not distinguish them — a Lock on an unconverted device gives
      the same numbers under both rules.
    - **Portal.** `DangerZone.vue` shows `slots_before`/`slots_after` as today (now key-bearing); when
      `other_slots_after` is present and greater than 0 it adds the line `devices.danger.revoke.otherSlotsLeft`
      (texts below) under the volume.
    - **Expected result of a Lock during `encrypting`** (replaces decision 39's): `revocation.executed` with
      `erased: true`, `slots_before` = the key-bearing keyslots the dump listed before (the conversion key's `luks2`
      slot, plus `tpm2+pin` or `tpm2` once enrolled — after amendment item 22 the enrollment follows the
      completion, so during `encrypting` it is 1), `slots_after: 0`, `volumes[0].other_slots_after: 1` (the
      `reencrypt` keyslot); the device does not boot afterwards. S14 is closed by this item; S16: after the change
      a Lock on a header marked for reencryption still reports `erased: false`, or `luksErase` leaves a `luks2`
      keyslot behind — stop and report the dump and the output.
    - **RR-57, extension** (PDK-248 carries it): "A Lock or Destroy during `encrypting` erases the key-bearing
      keyslot and leaves the key-less `reencrypt` keyslot behind; the confirmation counts key-bearing keyslots only
      and reports the leftover separately. The volume is unrecoverable — no header of the conversion is escrowed —
      and the data the reencryption had not reached stays readable. Verified on a throwaway VM and on real hardware
      (PDK-399)."
    - **§14.10 table**, rows `encrypting`, `completed !InitrdRegenerated` and `failed:resume`, column "Lock /
      Destroy": "`paddock-revoke` erases the key-bearing keyslots and reports `erased: true` with
      `other_slots_after: 1` (the `reencrypt` keyslot stays; item 23)".
    - **Texts (binding; `en.json` / `de.json`).** `devices.danger.revoke.otherSlotsLeft`: en "{count} key-less
      keyslot(s) of an unfinished reencryption remain on the volume; they hold no key and do not make the erasure
      incomplete.", de "{count} schlüssellose Keyslots einer unvollständigen Neuverschlüsselung verbleiben auf dem
      Volume; sie enthalten keinen Schlüssel und machen die Löschung nicht unvollständig." (ICU plural on
      `count`).
    - **Evidence required by the two-person rule (PDK-399).** (a) The PDK-247 hand test repeated on a throwaway VM
      with the changed `paddock-revoke` (expected result above; transcript in the result document). (b) A test on
      real hardware: the `paddock_revoke_testtarget` build against a dedicated LUKS2 volume on a USB disk or a
      spare partition of the test laptop that was put into an unfinished reencryption by hand (`cryptsetup
      reencrypt --encrypt --init-only --reduce-device-size 32M`, then `--resume-only` interrupted with SIGTERM
      after a few percent), named in `/etc/paddock/revoke-test-target` — never the system disk; the result shows
      `erased: true`, `slots_after: 0`, `other_slots_after: 1`, and the volume no longer opens with its key. (b)
      is destructive on the device it runs on and MUST NOT be carried out before the maintainer has approved it
      separately for the specific device and disk; `docs/operations/revocation-acceptance.md` gains the case as a
      row of its protocol.
