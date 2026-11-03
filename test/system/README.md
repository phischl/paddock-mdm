# Agent system tests

The system tests install the agent packages on the VirtualBox test VMs (`test/vms/virtualbox`, used through its
scripts and never changed) and run the gates of the agent milestones against the running development stack.

```sh
make up dev-seed                           # the development stack
make system-test VM=all                    # every gate on both VMs
make system-test VM=paddock-u2604 T='TestDiskGates'
```

`VM` is `paddock-u2404`, `paddock-u2604`, both comma-separated, or `all`. `make system-test` builds the packages as
version 0.1.0 with the `paddock_dev` tag into `bin/deb/` and fleetd into `bin/fleetd/` (`make fleetd-deb`, needs
outbound HTTPS to Fleet's update server) first; `TestInventoryGates` publishes that fleetd package once per run in a
release without rollout. Every test starts from the snapshot `base-installed`
and restores it, powered off, when it ends; with `PADDOCK_SYSTEM_KEEP=1` a failed test leaves its VM running for
inspection. Screenshots are kept in `bin/system-evidence/<vm>/`.

## Worktrees

`make system-test`, `make acceptance` and `make e2e` need the checkout's `deploy/compose/.env` and
`deploy/compose/.secrets` (git-ignored, so a fresh worktree has neither) and stop up front without them
(`test/stack-preflight.sh`). A worktree that runs the gates against a stack started from another checkout links both
to that checkout:

```sh
stack=/path/to/the/checkout/the/stack/runs/from
ln -s "$stack/deploy/compose/.env" deploy/compose/.env
ln -s "$stack/deploy/compose/.secrets" deploy/compose/.secrets
```

The check never reads the secrets; it wants `.env`, `.secrets/dev_alice_password` (`make dev-secrets`) and a non-empty
`.secrets/caddy-root.crt` (filled by `make up`). `make e2e` mounts the resolved secrets directory into the Playwright
container at `/secrets`, so the symlink works there too.

## Both VMs in parallel

The per-VM subtests of every gate (`TestAgentGates`, `TestIdentityGates`, `TestLocalAdminGates`, `TestDiskGates`,
`TestNoticeGate`, `TestInventoryGates`, `TestWatchGate`, `TestPreflight`, `TestAdoptionGates`, `TestConfigRolloutGates`,
`TestSoftwareGates`) run in parallel, one subtest per VM (`forEachVM`, plan M4b.1 step 5), so `make system-test VM=all`
takes about as long as the slower VM instead of both together. A VM is never used by two tests at a time: the test
functions themselves still run one after another. Gate S5 (`TestRolloutAutoStop`) drives both VMs itself.

Whatever a gate creates on the server carries the run's unique suffix (device groups, managed files and units,
enrollment tokens, permission profiles, Authentik users), so the VMs never share a fixture. State that every device or
the whole organization shares is coordinated through the VMs' `vmGroup` (`parallel.go`):

- `Together` runs a step once for all VMs when each of them reached it: the stack outage of S3 (`make down`,
  `make up`, with `BACKUP=1` when the running stack uses the backup overlay and `BACKUP` is not set), the releases of S4, S-UP1, S-UP2 and S-UP3 (a release
  with `--halt-running` halts every other rollout, so the VMs share one), the update policy of S-UP1 and S-UP3, the
  login history of LH1, the watched units of N12 and the stopped worker of LA1. A VM whose gate ended early (a failure) is no longer waited for.
  `Share` and `Shared` hand each VM's input to the step, such as the rollout buckets that S-UP1's first wave must
  stay below.
- `Exclusive` and `Lock` let one VM at a time through a section: the organization's login notice (N1) and reading the
  device code the greeter shows (`gdmLogin`, the newest pending code of the organization).
- `AfterAll` undoes a shared step once every VM's subtest ended, never under a VM still in the gate: the update
  policy, the login history (switching it off deletes every row of the organization), the watched units of N12 and every release a gate starts
  (`retractRelease`), so that no gate's release stays the one later gates' devices update to: a
  release's single wave lasts a day, so its rollout stays running and is halted by hand; a gate that needs a completed
  rollout (S-UP3) starts it with the failure threshold 1, and a simulated device reports a failed update to halt it.

A new gate that changes shared state uses one of them; anything else it creates gets the run's suffix.

## Adoption and staged configuration (plan M11)

`Install` enrolls with `paddockd enroll` from `/root/paddock-enroll.json`, which creates an adopted, report-only device
(it asserts `adopted`/`report_only`), and then enforces it (`POST /api/v1/devices/{id}/enforce` with the hostname) so
that every gate sees applied resources. `Install(..., ReportOnly())` skips the enforcement and the drift interval; the
gate calls `Enforce` and `SetDriftInterval` itself. The autoinstall gate asserts `autoinstall`/`enforce` and the marker
`/etc/paddock/autoinstall.marker`.

| Gate | What it proves | Shared state |
| --- | --- | --- |
| `TestPreflight` | `paddockd preflight --json` on an unenrolled VM: `sudoers_d` and `privileged_groups` warn after a foreign sudoers file and a sudo member are seeded, nothing changes | none |
| `TestAdoptionGates` | report-only apply leaves the seeded file and group untouched and lists `quarantine`/`remove` as pending; enforcement quarantines, removes the member, writes the managed files, audits both tamper events | none (per VM) |
| `TestConfigRolloutGates` | waves `[1,100]` with VM A's group as canary: a staged file reaches A only until `complete`; a staged missing unit fails on A, the worker halts the rollout (one event), the revert ends it | the organization's rollout settings and its single open rollout (`Together`); needs `VM=all`; no other gate in parallel; the file is staged again under a new path (at most 3 draws, a revert in between) until the VM outside the canary group has a bucket of 1 or more for the rollout, so the split is always testable; the staged unit reaches the other VM only when its bucket is 0 |

The rollout gate restores the rollout settings and completes any open rollout in its cleanup; a killed run leaves them
in place (switch rollouts off under *Settings* and complete or revert the rollout).

## Software catalog (plan M13a)

`TestSoftwareGates` (SW1–SW8) builds a signed APT repository **on each VM**, so the gate needs no outside repository:
a throwaway Ed25519 signing key (`gpg --quick-gen-key`, private key only on the VM), the packages `paddock-gate-app`
1.0 and 1.1 and `paddock-gate-anchor` 1.0 (`dpkg-deb --build`), `Packages` and `Release` from `apt-ftparchive`, a
clearsigned `InRelease`, a throwaway CA in `/usr/local/share/ca-certificates/paddock-gate.crt` with a server
certificate for `127.0.0.1`, and a TLS `http.server` as the transient unit `paddock-gate-repo` on
`https://127.0.0.1:8443/` (all below `/srv/paddock-gate`). The VM needs `gpg`, `openssl` and `python3` (a missing one
fails the gate, never skips it); `apt-utils` (`apt-ftparchive`) is installed when it is missing. Each VM gets its own
source (`gate-<run>`), catalog entry and assignment to its own device group, so the VMs share nothing; everything goes
with the snapshot and the run's cleanup.

| Gate | What it proves |
| --- | --- |
| SW1 | `required pinned 1.0` installs 1.0 with the rendered source file, the keyring, the 1001 pin and `device.software_installed` |
| SW2 | a local `apt-get remove` is undone within the drift interval, `device.software_reinstalled{reason: locally_removed}` |
| SW3 | `forbid` removes it and pins it to −1 while `paddock-gate-anchor` (required from here on) keeps the source, so `apt-get install` fails with *no installation candidate*, and a `dpkg -i` is undone with a second `device.software_removed` |
| SW4 | a hold keeps 1.0 through the regular run (`updates.run` held back; the anchor keeps the source, which a hold alone drops); `required latest` is upgraded only by the next regular run |
| SW5 | with the stack blocked (`iptables`) and `last-checkin` 20 minutes old, a forbidden `dpkg -i` stays `pending/deferred_offline`; removed after unblocking |
| SW6 | a held dpkg lock (`fcntl`, transient unit `gate-lock`) gives `pending/dpkg_locked` without a failure event; installed after the lock ends |
| SW7 | after the repository's key rotation apt refuses the signature (`NO_PUBKEY` with gpgv, `Missing key` or `No good signature` with sqv, with a `W:`/`E:` line); the key change needs a step-up (denied event without), records both fingerprints, reaches the keyring, and 1.1 installs |
| SW8 | an edited source file and a rogue `paddock-rogue.sources` are corrected with two `device.tamper_protected_file_changed` |

SW4 runs `paddock-updates.service` twice; on a VM with many pending updates the first regular run takes as long as
U3's.

## Throwaway VMs

Some gates install a VM of their own from an Ubuntu Desktop ISO and delete it when they end; they never run with
`VM=all` and are opted into through `VM`, one gate per `make` invocation:

| VM | Gates | ISO |
| --- | --- | --- |
| `paddock-ai-2604` (SSH 2228, 40 GiB) | D-AI `TestAutoinstallGate`, S-DU1 `TestDiskUnlockModeTPMOnly` | `PADDOCK_SYSTEM_ISO_2604` |
| `paddock-ie-2604` (SSH 2229, 16 GiB) | S-IE1 `TestInPlaceEncryptionLVM` | `PADDOCK_SYSTEM_ISO_2604` |
| `paddock-ie-2404` (SSH 2230, 16 GiB) | S-IE2 `TestInPlaceEncryptionPlain`, S-IE4 `TestInPlaceEncryptionCleanupAdopt` | `PADDOCK_SYSTEM_ISO_2404` |

```sh
make system-test VM=paddock-ai-2604 T='^TestDiskUnlockModeTPMOnly$$'
make system-test VM=paddock-ie-2604 T='^TestInPlaceEncryptionLVM$$'
make system-test VM=paddock-ie-2404 T='^TestInPlaceEncryptionPlain$$'
make system-test VM=paddock-ie-2404 T='^TestInPlaceEncryptionCleanupAdopt$$'
```

The ISOs default to `~/Downloads/ubuntu-26.04.1-desktop-amd64.iso` and `~/Downloads/ubuntu-24.04.5.1-desktop-amd64.iso`.
`T` reaches `go test -run` verbatim: anchors work as written, also inside subtest patterns
(`T='^TestIdentityGates$/.*/^L1_login$'`), and the `$$` above is equivalent (`$$` in a Go pattern is a doubled `$`
anchor). Leave out the `$` and the pattern becomes a prefix match that also runs every test whose name starts the same.
A run whose filter matches no test fails with `no test ran` (`go test` itself would report it as passed); a run whose
log lacks `--- PASS:` for its gate is still not green, whatever its exit code. Never name a throwaway VM together with a base VM in `VM`: the base
gates would run on the throwaway name. The in-place encryption gates (plan M8e §9) install their VM without disk
encryption from `test/vms/virtualbox/autoinstall/unencrypted-lvm.yaml.tmpl` (26.04, guided LVM) or
`unencrypted-plain.yaml.tmpl` (24.04, ext4 on a partition), with GDM logging the test user in, and then install the
packages like the base gates. S-IE2 and S-IE4 set the organization's unlock mode to `tpm_only` for their run, so no
other gate may run at the same time; a killed run leaves it, and the release it rolled out, in place (set the mode
back under *Login & privileges* and halt the rollout). A gate fails before it creates its VM when the VirtualBox machine folder has
less than 24 GiB free: the reencryption grows the dynamic disk to its full size (`df -h`, `docker builder prune`
first). The VM's serial console is written to `bin/system-ai/<vm>/serial.log` (the gates read the init step's
console lines there), and its disk is throttled while the background reencryption runs, so that a power cut lands in
its middle; the limit is set only while the VM is powered off (a change at runtime did not take effect), so a gate
lifts it with a clean restart.
