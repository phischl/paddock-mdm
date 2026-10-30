# Third-party software and licenses

Paddock is MIT-licensed (`LICENSE`). This page lists what Paddock links, bundles or uses to build, and under which
license (plan M6b decision 3, concept C8 "Licensing").

## Linked dependencies: checked by the license gate

`make lint-licenses` (part of `make lint`, so CI runs it on every pull request) fails with the package name on any
dependency whose license is not in the allow list:

`MIT`, `MIT-0`, `ISC`, `BSD-2-Clause`, `BSD-3-Clause`, `Apache-2.0`, `MPL-2.0`, `BlueOak-1.0.0`, `0BSD`, `CC0-1.0`,
`Python-2.0`, `Unlicense`

One module is exempt from the Go check because go-licenses cannot classify its license: `github.com/segmentio/asm`
(v1.2.1) is `MIT-0` (MIT No Attribution, OSI-approved, more permissive than MIT; approved by the maintainer on
2026-10-28). `paddockctl` links it through `github.com/modelcontextprotocol/go-sdk` → `github.com/segmentio/encoding`;
goose raises it to v1.2.1 in workspace mode. The exemption is `GO_LICENSES_IGNORE` in the `Makefile`; no other module
is ignored.

| Scope | Checked by | Covers |
| --- | --- | --- |
| Go modules | `go-licenses check` (v2.0.1, run with `go run` in the pinned Go image) | every package imported by the non-test code of every workspace module (`server`, `agent`, `cli`, `pkg`, `test/acceptance`, `test/load`, `test/system`); test-only imports are not checked; imports are resolved for linux/amd64 only, so an import that only an arm64 build uses is not checked; Paddock's own packages are skipped (MIT) |
| npm | `license-checker-rseidelsohn --production --json` (dev dependency of the portal), evaluated by `server/web/scripts/check-licenses.ts` | every production dependency of the portal, which is compiled into `paddock-server`; each license is read as an SPDX expression: `AND` needs every license allowed, `OR` one; `SEE LICENSE IN …`, `UNKNOWN`, guessed and missing licenses fail |

Run `cd server && go run github.com/google/go-licenses/v2@v2.0.1 report --ignore github.com/phischl/paddock-mdm ./...`
or `npx license-checker-rseidelsohn --production` in `server/web` for the full per-package list of a release.

The agent binaries (`paddockd`, `paddock-supervisor`, `paddock-revoke`) link only `aead.dev/minisign` (MIT),
`github.com/godbus/dbus/v5` (BSD-2-Clause), `github.com/gowebpki/jcs` (Apache-2.0) and the Go extended libraries
`golang.org/x/crypto` and `golang.org/x/sys` (BSD-3-Clause), besides the Go standard library (BSD-3-Clause).

Direct dependencies of `paddockctl` beyond the Go standard library and the shared `pkg` module:

| Module | Version | License | Use |
| --- | --- | --- | --- |
| `github.com/modelcontextprotocol/go-sdk` | v1.8.0 | MIT / Apache-2.0 (the repository's documentation: CC-BY-4.0, not linked) | stdio MCP server of `paddockctl mcp` (ADR 0044) |
| `github.com/google/jsonschema-go` | v0.4.3 | MIT | input schemas of the MCP tools (part of the SDK's tree) |
| `golang.org/x/oauth2` | v0.35.0 (v0.37.0 in the workspace build) | BSD-3-Clause | device authorization grant and token refresh of `paddockctl mcp login` |

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
| `ghcr.io/phischl/paddock-pgbackrest` | Debian slim with the `pgbackrest` package | pgBackRest MIT; Debian packages under their own licenses |

Every published image carries an SBOM (SPDX, generated with `syft`) as a release asset and as a signed cosign
attestation (`docs/operations/agent-releases.md`, section *Server release*), so the full package list of an image
can be checked per release.

## Software Paddock installs on devices

| Software | How it reaches the device | License |
| --- | --- | --- |
| `paddock-agent`, `paddock-supervisor`, `paddock-revoke` | Debian packages of the Paddock release | MIT |
| fleetd (`fleet-osquery`: orbit and osquery) | built with `fleetctl package` from Fleet's update server and distributed with the agent release (`make fleetd-deb`) | orbit MIT (Fleet); osquery Apache-2.0 or GPL-2.0 (dual-licensed) |
| Himmelblau | installed by the agent from the upstream repository `packages.himmelblau-idm.org`; Paddock does not redistribute it | GPL-3.0; runs as its own services and PAM/NSS modules, Paddock only writes its configuration file |

## Vendored fonts and icons (checked by `check-vendored.ts`)

The portal ships its fonts and icons as files under `server/web/src/assets/` (ADR 0023): no font or icon package, no CDN,
no request leaves the portal origin. Every file was downloaded once from the official GitHub release named below and is
committed unmodified with the upstream licence text next to it; `server/web/src/assets/vendored.json` pins the release
and the SHA-256 of every file, and `server/web/scripts/check-vendored.ts` (part of `make lint`) fails on any file that
is missing, changed, unlisted, under another licence or not recorded here.

### IBM Plex Sans — OFL-1.1

Source: https://github.com/IBM/plex, release `@ibm/plex-sans@1.1.0` (asset `ibm-plex-sans.zip`), directory `fonts/ibm-plex-sans`, licence file `LICENSE.txt`.

| File | Weight / subset | SHA-256 |
| --- | --- | --- |
| `IBMPlexSans-Medium-Latin1.woff2` | 500 / Latin1 | `b5610af04d0d4b5a14a621d96d974b993e945a065db1a8861918f69ef9321934` |
| `IBMPlexSans-Medium-Latin2.woff2` | 500 / Latin2 | `46fbe4f398e7ff3cc7773a1156b1efef0f81e4d034f682369c221de587f443ca` |
| `IBMPlexSans-Regular-Latin1.woff2` | 400 / Latin1 | `b5ad7bd39f996144915f0ad9849a90183b27d8c28ad97ed98af5b1bebc51f6b1` |
| `IBMPlexSans-Regular-Latin2.woff2` | 400 / Latin2 | `fcfa82e0d46ed01a8df38610b451860ca7e7518770c52fdd2a1d136247c40f28` |
| `IBMPlexSans-SemiBold-Latin1.woff2` | 600 / Latin1 | `fff0ab3a88b0b4aa0b693e4f0201359a15183b08e3fa5696d1918d8f0ade8ad5` |
| `IBMPlexSans-SemiBold-Latin2.woff2` | 600 / Latin2 | `2bc85a8e53540c4c211f7af36e806bb045ba7da8946bb221d87144c12c83d577` |
| `LICENSE.txt` | licence text | `7e6b2818edbd8f6a01ae80641cc8f16a51080d08fb4e532be3a0b6f74adb07da` |

### JetBrains Mono — OFL-1.1

Source: https://github.com/JetBrains/JetBrainsMono, release `v2.304` (asset `JetBrainsMono-2.304.zip`), directory `fonts/jetbrains-mono`, licence file `OFL.txt`.

| File | Weight / subset | SHA-256 |
| --- | --- | --- |
| `JetBrainsMono-Medium.woff2` | 500 / full | `086c48dfbea9ddaff1320f7e09399b8e2924e88ce67453721255db3bdbb5a353` |
| `JetBrainsMono-Regular.woff2` | 400 / full | `a9cb1cd82332b23a47e3a1239d25d13c86d16c4220695e34b243effa999f45f2` |
| `OFL.txt` | licence text | `30f0c136e3c88e422d0791acd97238870f9054a9729bc34cf2ff0d4ed8cac4ad` |

### Lucide — ISC

Source: https://github.com/lucide-icons/lucide, release `1.55.0` (asset `lucide-icons-1.55.0.zip`), directory `icons/lucide`, licence file `LICENSE`.
Icons the plan names by their former Lucide name: `building-2` → `building-complex`, `filter` → `funnel`, `circle-help` → `circle-question-mark`.

47 icons: `arrow-left`, `bell`, `bug`, `building-complex`, `check`, `chevron-down`, `chevron-left`, `chevron-right`, `circle-check`, `circle-question-mark`, `circle-x`, `cog`, `copy`, `diff`, `ellipsis`, `external-link`, `file-text`, `folder`, `funnel`, `globe-lock`, `hard-drive`, `inbox`, `info`, `key`, `keyboard`, `laptop`, `layout-dashboard`, `lock`, `log-in`, `menu`, `monitor`, `moon`, `package-search`, `package`, `panel-left`, `refresh-cw`, `rocket`, `scroll-text`, `search`, `shield-check`, `sun`, `ticket`, `timer`, `triangle-alert`, `user`, `users`, `x`. Checksums per file: `vendored.json`; licence file SHA-256 `b495047bd93a9b06913511076f504daba17d5bbeb3e0650f3bb53a4220329c57`.

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
