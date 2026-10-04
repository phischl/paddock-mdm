# Compiler image

Every Paddock role runs from the distroless image `paddock-server` (`RUNTIME_IMAGE`), except the compiler.
`paddock-compiler` runs the same binary from its own image, built from the Dockerfile target `compiler`
(`deploy/compose/Dockerfile`) on `COMPILER_RUNTIME_IMAGE`, a pinned Debian 13 slim image.

## Why Debian

The compiler checks every rendered sudo entry with `visudo -cf -` before it signs a bundle (plan M3a decision 17):
an entry that fails blocks the device's new bundle, and the device keeps its previous one. `visudo` comes with the
Debian `sudo` package and needs a C library and a passwd entry for the user it runs as. The distroless static image
has neither and no package manager.

## Hardening

- Only the `sudo` package is added (`--no-install-recommends`); the apt lists are removed.
- All setuid and setgid bits are removed, so `sudo` cannot elevate privileges; the compiler never runs it.
- The compiler runs as `nonroot` (uid and gid 65532, as in distroless) with a read-only root file system.
- `PADDOCK_VISUDO` sets the path of `visudo` (default `/usr/sbin/visudo`); the compiler refuses to start without it.

## Upgrades

`COMPILER_RUNTIME_IMAGE` is pinned by tag and digest in `deploy/compose/versions.env` like every other image.
The `sudo` package is installed from Debian's repositories at build time, so a rebuild picks up Debian's security
updates. `make lint` builds the compiler target, and gate P1 (`make acceptance T=TestEffectiveProfileGate`) checks
rendered entries with the `visudo` of the running compiler container.
