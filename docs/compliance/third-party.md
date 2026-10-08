# Third-party software and licenses

Paddock is MIT-licensed (`LICENSE`). This page lists what Paddock links, bundles or uses to build, and under which
license (plan M6b decision 3, concept C8 "Licensing").

## Linked dependencies: checked by the license gate

`make lint-licenses` (part of `make lint`, so CI runs it on every pull request) fails with the package name on any
dependency whose license is not in the allow list:

`MIT`, `ISC`, `BSD-2-Clause`, `BSD-3-Clause`, `Apache-2.0`, `MPL-2.0`, `BlueOak-1.0.0`, `0BSD`, `CC0-1.0`,
`Python-2.0`, `Unlicense`

| Scope | Checked by | Covers |
| --- | --- | --- |
| Go modules | `go-licenses check` (v2.0.1, run with `go run` in the pinned Go image) | every package imported by the non-test code of every workspace module (`server`, `agent`, `cli`, `pkg`, `test/acceptance`, `test/load`, `test/system`); test-only imports are not checked; imports are resolved for linux/amd64 only, so an import that only an arm64 build uses is not checked; Paddock's own packages are skipped (MIT) |
| npm | `license-checker-rseidelsohn --production --json` (dev dependency of the portal), evaluated by `server/web/scripts/check-licenses.ts` | every production dependency of the portal, which is compiled into `paddock-server`; each license is read as an SPDX expression: `AND` needs every license allowed, `OR` one; `SEE LICENSE IN …`, `UNKNOWN`, guessed and missing licenses fail |

Run `cd server && go run github.com/google/go-licenses/v2@v2.0.1 report --ignore github.com/phischl/paddock-mdm ./...`
or `npx license-checker-rseidelsohn --production` in `server/web` for the full per-package list of a release.

The agent binaries (`paddockd`, `paddock-supervisor`, `paddock-revoke`) link only `aead.dev/minisign` (MIT),
`github.com/godbus/dbus/v5` (BSD-2-Clause), `github.com/gowebpki/jcs` (Apache-2.0) and the Go extended libraries
`golang.org/x/crypto` and `golang.org/x/sys` (BSD-3-Clause), besides the Go standard library (BSD-3-Clause).

## Bundled services: separate processes, not linked

The Compose stack runs these images as their own containers. Paddock talks to them over the network (HTTP, AMQP,
the PostgreSQL and S3 protocols) and does not link, modify or embed them; each keeps its own license. Images and
digests are pinned in `deploy/compose/versions.env`.

| Service | Image | License |
| --- | --- | --- |
| Caddy (edge, TLS) | `caddy` | Apache-2.0 |
| PostgreSQL (control plane, audit, Authentik) | `postgres` | PostgreSQL License |
| RabbitMQ | `rabbitmq` (management) | MPL-2.0 |
| OpenBao | `openbao/openbao` | MPL-2.0 |
| Authentik | `ghcr.io/goauthentik/server` | MIT for the core; the enterprise features are licensed separately, Paddock needs none of them |
| RustFS (bundles, escrow, WORM audit store) | `rustfs/rustfs` | Apache-2.0 |
| RustFS admin CLI (bootstrap) | `rustfs/rc` | Apache-2.0 |
| Valkey (cache, Fleet's Redis) | `valkey/valkey` | BSD-3-Clause |
| Fleet (free edition) | `fleetdm/fleet` | MIT for the core; the `ee/` features need a Fleet license key, Paddock uses Fleet free without one |
| MySQL (Fleet's database) | `mysql` | GPL-2.0 with the Universal FOSS Exception 1.0 |
| AWS CLI (bucket bootstrap, backups) | `amazon/aws-cli` | Apache-2.0 |
| Prometheus (profile `observability`) | `prom/prometheus` | Apache-2.0 |

## Images Paddock builds and publishes

| Image | Contents | Licenses |
| --- | --- | --- |
| `ghcr.io/phischl/paddock-server` | `paddock-server` (MIT, with the dependencies above) on `gcr.io/distroless/static-debian12` | MIT; the distroless base holds Debian's `base-files`, `netbase`, `tzdata` and `ca-certificates` under their Debian licenses (`/usr/share/doc/*/copyright` in the image) |
| `ghcr.io/phischl/paddock-compiler` | `paddock-server` on `debian` slim with the `sudo` package (for `visudo`) | MIT; Debian packages under their own licenses, `sudo` under the ISC-style sudo license |
| `paddock-pgbackrest` (built locally, not published) | Debian slim with the `pgbackrest` package | pgBackRest MIT; Debian packages under their own licenses |

Every published image carries an SBOM (SPDX, generated with `syft`) as a release asset and as a signed cosign
attestation (`docs/operations/agent-releases.md`, section *Server release*), so the full package list of an image
can be checked per release.

## Software Paddock installs on devices

| Software | How it reaches the device | License |
| --- | --- | --- |
| `paddock-agent`, `paddock-supervisor`, `paddock-revoke` | Debian packages of the Paddock release | MIT |
| fleetd (`fleet-osquery`: orbit and osquery) | built with `fleetctl package` from Fleet's update server and distributed with the agent release (`make fleetd-deb`) | orbit MIT (Fleet); osquery Apache-2.0 or GPL-2.0 (dual-licensed) |
| Himmelblau | installed by the agent from the upstream repository `packages.himmelblau-idm.org`; Paddock does not redistribute it | GPL-3.0; runs as its own services and PAM/NSS modules, Paddock only writes its configuration file |

## Tools used only to build and test (not distributed)

| Tool | Use | License |
| --- | --- | --- |
| Go (`golang` image) | build | BSD-3-Clause |
| Node.js (`node` image) | portal build and tests | MIT |
| golangci-lint | lint | GPL-3.0 (tool output only, nothing of it is linked) |
| govulncheck | vulnerability check | BSD-3-Clause |
| go-licenses | license gate | Apache-2.0 |
| license-checker-rseidelsohn | license gate (npm dev dependency) | BSD-3-Clause |
| nfpm | Debian packages | MIT |
| fleetctl | fleetd package | MIT |
| Playwright | end-to-end tests | Apache-2.0 |
| gitleaks | secret scan | MIT |
| Trivy | vulnerability scan | Apache-2.0 |
| grafana/k6 | load test (`test/load/`) | AGPL-3.0 (run as a separate tool against a test stack, never shipped or linked) |
| syft | SBOM | Apache-2.0 |
| cosign | image signing (keyless, Sigstore public good instance) | Apache-2.0 |
| minisign (`aead.dev/minisign`) | agent release signing | MIT |
