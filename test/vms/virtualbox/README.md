# Paddock VirtualBox test VMs

Reproducible Ubuntu Desktop VMs for the Paddock PoC (Himmelblau login, GNOME
screen unlock, TPM2+PIN disk unlock) and later agent system tests.

| VM              | ISO                                 | SSH (host → guest 22) |
|-----------------|-------------------------------------|-----------------------|
| `paddock-u2404` | `ubuntu-24.04.5.1-desktop-amd64.iso` | `127.0.0.1:2224`      |
| `paddock-u2604` | `ubuntu-26.04.1-desktop-amd64.iso`   | `127.0.0.1:2226`      |

Each VM: EFI with Secure Boot (Microsoft + Oracle keys enrolled), TPM 2.0,
2 vCPU, 4 GB RAM, 40 GB dynamic VDI on SATA, VMSVGA/128 MB, NAT with an SSH
port forward (the guest reaches the host as `10.0.2.2`). Ubuntu Desktop
(minimal selection, GNOME/GDM) on LVM inside **LUKS2, unlocked by passphrase**.
The passphrase keyslot is intentional; the PoC replaces it with TPM2+PIN.

User `paddock` (sudo, passwordless), SSH key login plus password, keyboard
layout `us`, timezone Europe/Berlin, `openssh-server`, `tpm2-tools`,
`cryptsetup`, all updates applied.

Release differences (stock defaults, not changed by these scripts):

|                | 24.04 (noble)                          | 26.04 (resolute)          |
|----------------|----------------------------------------|---------------------------|
| initramfs      | `initramfs-tools` (`dracut` not installed; only `dracut-install`, a dependency of `initramfs-tools-core`) | `dracut` |
| time sync      | `systemd-timesyncd`                    | `chrony`                  |
| kernel         | 7.0 HWE                                | 7.0                       |

## Prerequisites

- VirtualBox 7.2+ (`VBoxManage`), `xorriso`, `openssl`, `python3`, OpenSSH client
- ~15 GB free per VM in `work/` (remastered ISO) plus the VM disk

## Layout

```
create-vm.sh              create VM, remaster ISO, unattended install, then finalize-vm.sh
finalize-vm.sh            eject ISO, first boot + unlock, apt full-upgrade, snapshot base-installed
start-vm.sh               start headless, type LUKS passphrase, wait for SSH
verify-vm.sh              print the baseline facts (LUKS, TPM, Secure Boot, services, initramfs)
lib.sh                    shared helpers
autoinstall/autoinstall.yaml.tmpl   subiquity autoinstall template
.secrets/                 (git-ignored) id_ed25519, id_ed25519.pub, credentials.env
work/<vm>/                (git-ignored) rendered autoinstall.yaml, grub.cfg, install.iso
```

## Usage

```sh
cd test/vms/virtualbox
./create-vm.sh paddock-u2404 ~/Downloads/ubuntu-24.04.5.1-desktop-amd64.iso 2224
./create-vm.sh paddock-u2604 ~/Downloads/ubuntu-26.04.1-desktop-amd64.iso 2226
```

Both can run in parallel (each takes ~15–25 min depending on mirror speed).
An existing VM of the same name is refused; `--force` deletes and recreates it.
`--no-wait` only starts the installer; run `./finalize-vm.sh <vm>` once the VM
has powered itself off.

How it works:

1. `.secrets/` is created on first run: a dedicated ed25519 key and
   `credentials.env` (`PADDOCK_USER`, `PADDOCK_PASSWORD`,
   `PADDOCK_LUKS_PASSPHRASE`, alphanumeric so they can be typed via
   `keyboardputstring`). Both VMs share these secrets.
2. The template is rendered to `work/<vm>/autoinstall.yaml` and a copy of the
   ISO is remastered with `xorriso` (original ISO untouched): `/autoinstall.yaml`
   is added at the ISO root and `autoinstall` is added to the GRUB kernel
   command line (timeout 3 s), so the desktop installer runs unattended without
   a confirmation prompt and powers off when done (`shutdown: poweroff`).
3. The VM is created (`modifynvram inituefivarstore`, `enrollmssignatures`,
   `enrollorclpk`, `secureboot --enable`, `--tpm-type=2.0`) and booted headless.
4. `finalize-vm.sh` ejects the ISO, boots, types the LUKS passphrase, waits for
   SSH, checks `mokutil --sb-state`, runs `apt-get full-upgrade` (reboots if
   required), powers off and takes snapshot `base-installed`.

Progress can be watched with `VBoxManage showvminfo <vm> | grep State` or
`VBoxManage controlvm <vm> screenshotpng /tmp/<vm>.png`.

## Starting a VM and unlocking the disk

The LUKS passphrase has to be typed on the console at every boot (Plymouth
prompt). Headless:

```sh
./start-vm.sh paddock-u2404        # starts, unlocks, waits for SSH, prints ssh command
```

Manually:

```sh
source .secrets/credentials.env
VBoxManage startvm paddock-u2404 --type headless
# wait ~20 s until the passphrase prompt is shown (check with screenshotpng)
VBoxManage controlvm paddock-u2404 keyboardputstring "$PADDOCK_LUKS_PASSPHRASE"
VBoxManage controlvm paddock-u2404 keyboardputscancode 1c 9c    # Enter (make/break)
```

`keyboardputstring` sends US-layout scancodes; that is why the guest keyboard
layout is `us`. For other keys use `keyboardputscancode` with set-1 scancodes
(e.g. `0e 8e` Backspace, `01 81` Escape). Once the disk is unlocked via TPM2
(after the PoC), use `./start-vm.sh --no-unlock <vm>`; a TPM2 PIN can be typed
the same way.

## SSH

```sh
ssh -i .secrets/id_ed25519 -o IdentitiesOnly=yes -p 2224 paddock@127.0.0.1   # 24.04
ssh -i .secrets/id_ed25519 -o IdentitiesOnly=yes -p 2226 paddock@127.0.0.1   # 26.04
```

The host key changes when a VM is rebuilt; add
`-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null` to avoid
polluting `~/.ssh/known_hosts`.

## Snapshots

```sh
VBoxManage snapshot paddock-u2404 list
VBoxManage controlvm paddock-u2404 poweroff                 # if running
VBoxManage snapshot paddock-u2404 restore base-installed    # back to a clean install
VBoxManage snapshot paddock-u2404 take <name> --description "..."
```

Snapshots include the NVRAM file (UEFI variables incl. Secure Boot keys, and
the emulated TPM's state), so restoring `base-installed` also discards TPM
enrollments made later (e.g. by `systemd-cryptenroll --tpm2-device=auto`).

**Pitfall (VirtualBox 7.2.16):** `VBoxManage showvminfo` reports `poweroff`
while `VBoxHeadless` is still writing the NVRAM file. A snapshot taken (or a
setting changed) in that window leaves the VM with an *empty* NVRAM: Secure
Boot ends up disabled ("Platform is in Setup Mode"), the TPM is reset, and
`modifynvram listvars` may even crash VBoxSVC (taking running VMs down). So:

- shut down from inside the guest (or `controlvm poweroff`), then wait until
  the `VBoxHeadless --comment <vm>` process has exited (+ a few seconds)
  before `snapshot take` (`lib.sh: wait_vm_state ... poweroff` does that);
- after taking a snapshot, `snapshot restore` it once (finalize-vm.sh does),
  so the current state is guaranteed to equal the snapshot;
- a healthy NVRAM file of a VM that has booted is a tar archive
  (`file "~/VirtualBox VMs/<vm>/<vm>.nvram"` → `POSIX tar archive`);
- if Secure Boot was lost: power off, `source lib.sh; enroll_secure_boot <vm>`
  (re-initialises the variable store; the shim fallback recreates the boot
  entry on the next boot).

## Recreating

```sh
./create-vm.sh --force paddock-u2404 ~/Downloads/ubuntu-24.04.5.1-desktop-amd64.iso 2224
```

`--force` only touches the VM with exactly that name (unregister + delete its
disks). Secrets in `.secrets/` are reused; delete them to rotate.
