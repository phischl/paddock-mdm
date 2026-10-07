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

## Both VMs in parallel

The per-VM subtests of every gate (`TestAgentGates`, `TestIdentityGates`, `TestLocalAdminGates`, `TestDiskGates`,
`TestNoticeGate`, `TestInventoryGates`) run in parallel, one subtest per VM (`forEachVM`, plan M4b.1 step 5), so `make system-test VM=all`
takes about as long as the slower VM instead of both together. A VM is never used by two tests at a time: the test
functions themselves still run one after another. Gate S5 (`TestRolloutAutoStop`) drives both VMs itself.

Whatever a gate creates on the server carries the run's unique suffix (device groups, managed files and units,
enrollment tokens, permission profiles, Authentik users), so the VMs never share a fixture. State that every device or
the whole organization shares is coordinated through the VMs' `vmGroup` (`parallel.go`):

- `Together` runs a step once for all VMs when each of them reached it: the stack outage of S3 (`make down`,
  `make up`), the releases of S4 (a rollout reaches every device) and the stopped worker of LA1. A VM whose gate
  ended early (a failure) is no longer waited for.
- `Exclusive` and `Lock` let one VM at a time through a section: the organization's login notice (N1) and reading the
  device code the greeter shows (`gdmLogin`, the newest pending code of the organization).

A new gate that changes shared state uses one of them; anything else it creates gets the run's suffix.
