# M1 proof of concept: login component and TPM2+PIN

Scripts of plan `docs/plans/M1-poc-login-and-disk.md`. The results are in `docs/poc/M1-report.md`. Evidence is
written to `out/<vm>/<criterion>/` (git-ignored); secrets live in `.secrets/` (git-ignored).

## Prerequisites

- The test VMs of `test/vms/virtualbox/` with snapshot `base-installed` (read that README first, in particular the
  NVRAM pitfall). Never take or restore snapshots by hand while `VBoxHeadless` still runs; use `snapshot.sh`.
- Host tools: `VBoxManage`, `ssh`, `curl`, `jq`, `python3` (stdlib only), Docker for the dev stack and shellcheck.
- The dev stack: `make dev-secrets up dev-seed` (repository root). Authentik must be reachable at
  `https://auth.paddock.localhost:8443`.

All commands below run from `test/poc/m1/`. `<vm>` is `paddock-u2404` or `paddock-u2604`.

## Phase 1: Authentik objects

```sh
./authentik-setup.sh setup     # provider/application paddock-device-acme, policy, device code flow, users + TOTP
./authentik-setup.sh status    # provider, application, policy binding, users, TOTP devices, discovery document
```

The script is idempotent and talks only to the Authentik API (bootstrap token from
`deploy/compose/.secrets/authentik_bootstrap_token`). It writes `password_<user>` and `totp_<user>` (TOTP secret
captured from the real setup flow) to `.secrets/`. Other subcommands: `lock <user> [group-only]`, `unlock <user>`,
`approve <user> <user_code>` (approves a device code with password + TOTP, like a user in a browser).

Create the Hello PINs used by the checks once:

```sh
for u in dave erin; do (umask 077; head -c 32 /dev/urandom | od -An -tu1 | tr -dc 0-9 | cut -c1-8 > .secrets/hello_pin_$u); done
```

## Phase 2: TPM2+PIN (C7-C9), from `base-installed`

```sh
(umask 077; head -c 32 /dev/urandom | od -An -tu1 | tr -dc 0-9 | cut -c1-8 > .secrets/tpm_pin)
./snapshot.sh restore <vm> base-installed
../../vms/virtualbox/start-vm.sh <vm>
./tpm/dracut-switch.sh paddock-u2404      # 24.04 only: initramfs-tools -> dracut, boots once with the passphrase
./tpm/enroll.sh <vm>                      # TPM2+PIN token on PCR 7, crypttab tpm2-device=auto, dracut -f
./tpm/boot-test.sh <vm> pin               # reboot, PIN unlocks
./tpm/boot-test.sh <vm> wrong-pin         # one wrong PIN rejected, then the PIN unlocks
./tpm/boot-test.sh <vm> passphrase        # passphrase typed at the PIN prompt until it unlocks
./tpm/recovery-key.sh <vm>                # C8: recovery key slot, key in .secrets/recovery_key_<vm>
./tpm/boot-test.sh <vm> recovery          # C8: recovery key at boot
./tpm/inventory.sh <vm>                   # C9: keyslot inventory + header backup (kept in the guest)
./snapshot.sh take <vm> poc-m1-tpm "..."  # snapshot, restore, then:
./tpm/boot-test.sh <vm> pin               # TPM unlock still works after the restore; prints Secure Boot state
./snapshot.sh shutdown <vm>
```

The passphrase and recovery modes leave the emulated TPM in dictionary-attack lockout and clear it afterwards
(`tpm2_dictionarylockout --clear-lockout`, possible because the test VMs have no lockout authorization).

## Phase 3: Himmelblau (C1-C6), from `base-installed`

```sh
./snapshot.sh restore <vm> base-installed
../../vms/virtualbox/start-vm.sh <vm>
./vm-prepare.sh <vm>       # hosts entry + Caddy CA, Himmelblau 4.0.4 (signed repo), himmelblau.conf, pamtester
./snapshot.sh take <vm> poc-m1-himmelblau "..."
```

Then, in this order (each check starts the VM if needed and writes `out/<vm>/<criterion>/results.txt`):

```sh
./checks/c1-login.sh <vm>       # dave: device code + password + TOTP + Hello enrollment, PIN login, frank refused
# C1 graphical, erin's first login at GDM (the device code is read from the screenshot):
./checks/gdm.sh <vm> C1 user erin@acme.test 1      # tabs = number of users listed on the greeter
./checks/gdm.sh <vm> C1 shot code                  # open the PNG, read the code
./checks/gdm.sh <vm> C1 approve erin <code>
./checks/gdm.sh <vm> C1 type hello_pin_erin 2      # New PIN + Confirm PIN
./checks/gdm.sh <vm> C1 sessions
./checks/c2-lock.sh <vm>        # lock/unlock erin, timing
./checks/c3-suspend.sh <vm>     # allow list suspension, local admin still works
./checks/c4-hello.sh <vm>       # Hello PIN login, wrong PIN, TPM binding
./checks/c6-sudo.sh <vm>        # no sudo
./checks/c5a-offline.sh <vm>    # link cut, offline PIN login, allow-list removal refuses offline
# C5b needs dave's graphical session: log erin out (sudo loginctl terminate-session <id>), then
./checks/gdm.sh <vm> C5b user dave@acme.test 2
./checks/gdm.sh <vm> C5b type hello_pin_dave 1
./checks/c5b-unlock.sh <vm>     # lock, remove from allow list, unlock via pamtester and the lock screen
./checks/c5c-listfile.sh <vm>   # only if C5a/C5b fail: pam_listfile deny line, repeats C5a and C5b
./checks/c5c-listfile.sh <vm> remove
./snapshot.sh shutdown <vm>
```

`checks/pamlogin.py` drives pamtester over SSH with a pseudo terminal and answers the PAM conversation; the
transcripts never contain secrets.

## Linting

```sh
# koalaman/shellcheck:stable = 0.11.0 on 2026-10-03
docker run --rm -v "$PWD/../../..:/mnt" -w /mnt/test/poc/m1 koalaman/shellcheck@sha256:bb596a0d169b85ddd81d8b6d3a2ff6d5baf5fca10b97f575ebc647c3dff62b3d -x *.sh checks/*.sh tpm/*.sh
```
