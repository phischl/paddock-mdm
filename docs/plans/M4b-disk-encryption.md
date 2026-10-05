# Implementierungsplan: M4b — Disk encryption: Paddock autoinstall, TPM2+PIN, recovery key, header escrow

Status: Ready for implementation (after M4a) · 2026-10-05 · Author: architect
Basis: architecture v1.7 §12.4 (decided: boot PIN set at installation), §11.5 keyslot inventory, §13 keys; concept
"Disk encryption", "Keyslot policy", C5; PoC M1 C7–C9 (`docs/poc/M1-report.md`, `test/poc/m1/tpm/*`); M4a (escrow
endpoints, `escrow-wrap` key, step-up, commands)

Binding language: **MUST** / **MUST NOT** / **SHOULD** / **MAY**.

## 1. Goal

An operator generates a Paddock autoinstall for Ubuntu 24.04 or 26.04 from an enrollment config; a device installed
with it is encrypted with LUKS2, asks for the boot PIN once at first boot, enrolls TPM2+PIN, gets a high-entropy
recovery key, escrows recovery key and LUKS header, removes the installer passphrase, enrolls itself in Paddock, and
reports its keyslot state continuously. An org admin can retrieve recovery key and header (step-up) for a device.

## 2. Context

- PoC M1: TPM2+PIN works with `systemd-cryptenroll --tpm2-device=auto --tpm2-with-pin=yes --tpm2-pcrs=7` and
  `tpm2-device=auto` in crypttab; 26.04 out of the box (dracut 110); 24.04 needs dracut 060 instead of initramfs-tools
  (`hostonly="yes"`, explicit modules, config `/etc/dracut.conf.d/90-paddock-tpm2.conf` as in the report, no Plymouth,
  text prompt); recovery key via `systemd-cryptenroll --recovery-key`; passphrase/recovery key are accepted at the PIN
  prompt only after the TPM PIN attempts are used up; header backup 16 MiB.
- M4a: `/v1/escrow` (small secrets via queue), `escrow_secret` table, `escrow-wrap` RSA-4096 key in bundles
  (`keys.escrow_wrap`), `paddock-escrow-reader` AppRole, step-up, commands framework.
- No Paddock apt repository exists yet; agent artifacts live in RustFS bucket `paddock-agent-artifacts`.

## 3. Binding decisions

### 3.1 Packages for installation
1. The platform publishes the two Debian packages per agent release into bucket `paddock-agent-artifacts` under
   `packages/<version>/<name>_<version>_<arch>.deb` (`make agent-release` uploads them through the platform API,
   artifact kind `deb`). Objects under `packages/` are **public-read** through `bundles.<domain>/packages/…` (packages
   contain no secrets); integrity comes from SHA-256 values embedded in the generated autoinstall.

### 3.2 Autoinstall generator
2. `POST /api/v1/autoinstall` (org_admin, operator; audited `autoinstall.generated {release, agent_version}` without
   secrets) body `{enrollment_config (the JSON from token creation), release: "24.04"|"26.04", hostname: string,
   locale, keyboard_layout, timezone}` → `200 text/yaml` (`user-data` for Ubuntu autoinstall). Stateless: the server
   validates the config (organization = caller's organization, token hash exists and is usable) but stores nothing.
3. The rendered autoinstall (template `server/internal/autoinstall/templates/user-data.<release>.yaml.tmpl`) MUST:
   - use storage layout `lvm` with LUKS2 and a **random temporary passphrase** (≥ 32 random alphanumeric characters,
     generated per render);
   - not create any user with a password except the installer-required identity, whose password is locked in a
     late-command (the managed local admin from M4a becomes the only local admin account);
   - in late-commands (in the target, `curtin in-target`): download both debs from `bundles.<domain>/packages/…`,
     verify SHA-256, install; write `/etc/paddock/enroll.json` (0600) from the enrollment config; write the temporary
     passphrase to `/var/lib/paddock/install-passphrase` (0600 root); create `/var/lib/paddock/disk-setup-pending`;
     on 24.04 install `dracut`, write the PoC dracut configuration, set `tpm2-device=auto` in crypttab, rebuild the
     initramfs; on both releases add `tpm2-device=auto` to the root entry in `/etc/crypttab`;
   - install `tpm2-tools` and `cryptsetup`.
   Unit tests render both releases and validate them against the Ubuntu autoinstall JSON schema (vendored copy of
   the schema, approved as test data).
4. The organization setting `boot_pin_min_length` (6–32, default 8) is embedded in the autoinstall
   (`/etc/paddock/disk-setup.json`).

### 3.3 First-boot disk setup (`paddockd disk-setup`, unit `paddock-disk-setup.service`)
5. Unit in the `paddock-agent` package: `ConditionPathExists=/var/lib/paddock/disk-setup-pending`,
   `Before=display-manager.service getty@tty1.service`, `After=systemd-cryptsetup@*.service`, runs on `tty1`
   (`StandardInput=tty`, `TTYPath=/dev/tty1`), `Type=oneshot`, timeout 30 min.
6. Dialogue (English, plain text): explains that this PIN unlocks the disk at every boot and that IT cannot recover a
   forgotten PIN without the recovery key; asks twice; enforces the minimum length; allows **skip** by entering an
   empty PIN twice (fail safe: boot continues; device later reported `tpm_pin_missing`). On a correct entry it runs
   `systemd-cryptenroll --tpm2-device=auto --tpm2-with-pin=yes --tpm2-pcrs=7 --unlock-key-file=<install-passphrase>`
   (PIN passed via `NEWPIN` environment variable, never on the command line), then removes the pending marker. Without
   a TPM 2.0: message, skip, `tpm_missing`.
7. After disk setup, `paddock-supervisor` starts as usual; the agent enrolls from `/etc/paddock/enroll.json` on first
   start if not yet enrolled (`paddockd enroll --config … --remove-config`, done by the supervisor's start sequence
   once).

### 3.4 Agent `luks` reconciler (runs every drift pass; order: after `local_admin`)
8. **Inventory:** root LUKS device from `/etc/crypttab` + `lsblk`; `cryptsetup luksDump --dump-json-metadata`; derive
   `{luks_version, tokens: [tpm2(+pin), recovery, password…], keyslots: n}`. Reported in check-in `health.disk`:
   `state` ∈ `not_encrypted | unmanaged | tpm_missing | tpm_pin_missing | escrow_pending | compliant`.
   `unmanaged` = encrypted but no install-passphrase file and no recovery slot (not installed by Paddock).
9. **Recovery key:** if the install-passphrase file exists and no recovery token exists: `systemd-cryptenroll
   --recovery-key --unlock-key-file=<install-passphrase>`; capture the key from stdout in memory only.
10. **Escrow:** (a) recovery key → `/v1/escrow` kind `luks_recovery_key` (RSA-OAEP to `escrow_wrap`); (b) header →
    `cryptsetup luksHeaderBackup` to a tmpfs file (`/run/paddock/`), gzip, AES-256-GCM with a random DEK, DEK
    RSA-OAEP-wrapped; `POST /v1/escrow` kind `luks_header` `{escrow_id, generation, key_version, wrapped_dek, nonce,
    sha256, size}` → response `{upload_url}` (presigned PUT, TTL 10 min, object key fixed by the server
    `org/<org>/devices/<dev>/luks-header/<generation>.bin`); device uploads; worker verifies object size + SHA-256
    (escrow bucket read) → `stored`. Device polls `/v1/escrow/{id}` as for admin passwords. Header file deleted
    immediately.
11. **Remove the installer passphrase:** only after recovery key **and** header generation are `stored`:
    `systemd-cryptenroll --wipe-slot=password --unlock-key-file=<install-passphrase>`; verify via luksDump that exactly
    `tpm2` and `recovery` remain; escrow the header again (new generation); delete the install-passphrase file
    (overwrite, unlink). If a TPM PIN was skipped, the passphrase slot is **kept** (otherwise only the recovery key would
    unlock) and the state is `tpm_pin_missing`.
12. **Keyslot tamper:** the expected token set is stored in `state.json`; any difference → `tamper.keyslot_changed
    {before, after}` and a new header escrow generation. The agent never wipes slots it did not create, except the
    installer passphrase in decision 11.
13. Server: `escrow_secret.kind` extended with `luks_recovery_key`, `luks_header` (+ columns `object_key`,
    `wrapped_dek`, `nonce`, `sha256`, `size` for headers); escrow bucket `paddock-escrow` on the control-plane RustFS
    (versioning on, no Object Lock); credentials: gateway presign-PUT only on `org/*/devices/*/luks-header/*`, worker
    read, api reader for recovery.

### 3.5 Recovery for operators
14. `POST /api/v1/devices/{id}/disk/recovery-key` (org_admin, **step-up**, typed hostname) → recovery key (decrypted
    via `paddock-escrow-reader`), `no-store`; audit `disk.recovery_key_revealed`. `POST /api/v1/devices/{id}/disk/header`
    (same guards) → streams the decrypted header (`application/octet-stream`, filename
    `<hostname>-luks-header-<generation>.img`); audit `disk.header_downloaded`. Portal: *Disk encryption* card on the
    device detail (state, tokens, last escrow generations, actions); fleet list filter by disk state.
15. `docs/operations/disk-recovery.md`: how to unlock with the recovery key at the PIN prompt (enter it after the PIN
    attempts are used up — PoC finding), how to restore a header (`cryptsetup luksHeaderRestore`), TPM lockout notes.

## 4. Non-goals
Lock/Destroy and revocation (M4c); in-place conversion of existing installations; Secure Boot enrollment; PCR policies
beyond PCR 7; Plymouth on 24.04; arm64; a Paddock apt repository.

## 5. Affected files
Server: platform release artifacts (kind `deb`), `server/internal/autoinstall/` (+ templates, vendored schema),
admin API, escrow extensions, migration `00011_disk_escrow.sql`, compiler (`boot_pin_min_length` not in bundle — only
in autoinstall), portal. Agent: `cmd/paddockd disk-setup`, `internal/reconcile/luks.go`, `internal/escrow` (headers),
packaging (unit file, depends on `cryptsetup`, `tpm2-tools`). Tests: `test/acceptance` (generator, escrow, recovery API),
`test/system/disk_test.go`, new VM build helper in `test/system` that **uses** `test/vms/virtualbox/lib.sh` functions to
create a throwaway VM `paddock-ai-2604` from a Paddock autoinstall. Docs, CHANGELOG.

## 6. Gates

| ID | Gate | Content |
| --- | --- | --- |
| D-AI | Autoinstall (26.04, full) | generate user-data via API; build a throwaway VM (EFI, Secure Boot, TPM 2.0, like the test VMs) from the 26.04 ISO with it; at first boot type the PIN twice via `keyboardputstring`; device enrolls itself, reaches `compliant`; reboot unlocks with the PIN; installer passphrase no longer works; recovery key from the API unlocks (after exhausting PIN attempts as documented); VM deleted at the end |
| D-24 | 24.04 LUKS flow (from `base-installed`) | test prep converts to dracut as the autoinstall would and places the install-passphrase file + pending marker (simulating the autoinstall); disk-setup with PIN; reconciler reaches `compliant`; PIN unlock after reboot |
| D-ESC | Escrow | recovery key and header generations stored; header download via API restores (`cryptsetup luksHeaderRestore` on a loop-device copy in the test) and the recovery key opens it; every reveal/download audited once; step-up enforced |
| D-TAMP | Keyslot tamper | adding a passphrase keyslot locally → `tamper.keyslot_changed` + new header generation; portal shows the change |
| D-SKIP | Skip PIN | empty PIN twice → boot continues, state `tpm_pin_missing`, passphrase slot kept |
| regression | existing | acceptance, e2e, system-test VM=all (L*, P*, S*, LA*, N1) |

## 7. Steps
1. Package publishing (decision 1). 2. Autoinstall generator + unit/schema tests. 3. Agent disk-setup + unit.
4. Agent luks reconciler + header escrow + server escrow extensions. 5. Recovery API + portal + docs. 6. Gates
D-24, D-ESC, D-TAMP, D-SKIP, then D-AI. 7. Regression from reset. One commit per step, Conventional Commits.

## 8. Acceptance criteria
| # | Given / When / Then | Req. | Observed by |
| --- | --- | --- | --- |
| AC1 | Given a device installed with the Paddock autoinstall, then it boots with TPM2+PIN, has no low-entropy keyslot, and its recovery key and header are escrowed | C5, keyslot policy | Org admin (portal) |
| AC2 | Given a forgotten PIN, then an org admin with step-up can retrieve the recovery key and unlock the device | §12.4 | Org admin, user at device |
| AC3 | Given someone adds a keyslot, then it is reported and the escrowed header is refreshed | F9 | Org admin, auditor |
| AC4 | Given a skipped PIN or a missing TPM, then the device still boots and is reported non-compliant | Fail safe | Org admin |

## 9. Freedoms
Template structure, dialogue wording, test helper design, portal layout.

## 10. Stop conditions
S1 `systemd-cryptenroll` cannot take the PIN non-interactively in the needed way; S2 the autoinstall cannot be made to
use LVM+LUKS with a generated passphrase on one release; S3 the presigned PUT cannot be restricted to the server-chosen
key; S4 a step would require changing `test/vms/**`; plus M0 §11 S2/S6/S7/S8.

## 11. Risks
| # | Item | Default |
| --- | --- | --- |
| R1 | Emulated TPM ≠ hardware (lockout, PCR 7 after firmware updates) | Real-hardware test in the M4c acceptance protocol |
| R2 | Install passphrase on disk until escrow completes | Root-only, removed after escrow; device not compliant until then |
| R3 | PCR 7 binding breaks after Secure Boot DB/DBX updates | Recovery key path documented; re-enrollment command in a later milestone |
