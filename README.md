# Paddock

Open-source management for Linux workstations that keeps local administrator rights with their users.

Status: milestone M2a (device control plane): control plane, audit domain, admin portal with organizations, device
groups, audit log, devices, enrollment tokens and managed files and units; device API (enrollment, check-in, signed
bundles) proven by the reference client `test/acceptance/devicesim`. The device agent follows in M2b. Architecture: `docs/architecture.md`, decisions: `docs/adr/`, plans: `docs/plans/`, binding rules for
contributors and AI agents: `CLAUDE.md`.

## Quick start (local development)

Prerequisites: Docker Engine with Compose v2, GNU make, Go 1.21 or newer (fetches the declared Go 1.27.1 toolchain
automatically). Node is not needed on the host. Free ports: `8443` and the loopback ports listed in
`docs/operations/local-dev.md`.

```sh
make dev-secrets   # random secrets in deploy/compose/.secrets/ and settings in deploy/compose/.env
make up            # builds the paddock-server image, starts everything, initializes OpenBao and the buckets
make dev-seed      # creates the organizations acme and globex and assigns the test users
```

`make up` takes a few minutes on the first run (image pulls, Authentik migrations). It is idempotent; after a
restart of the machine run it again (it also unseals OpenBao). `make bao-bootstrap`, `make audit-bootstrap` and
`make bundles-bootstrap` exist as separate targets but are already part of `make up`.

Open <https://admin.paddock.localhost:8443>. Devices talk to <https://device.paddock.localhost:8443> and download
bundles from <https://bundles.paddock.localhost:8443>. The certificate comes from Caddy's internal CA
(`deploy/compose/.secrets/caddy-root.crt`); accept the warning or import that certificate.

### Test accounts

Passwords are generated per checkout; read them from `deploy/compose/.secrets/`.

| User | Role | Password file |
| --- | --- | --- |
| `platform-admin@paddock.test` | Platform administrator | `dev_platform_admin_password` |
| `alice@acme.test` | Administrator of `acme` | `dev_alice_password` |
| `bob@acme.test` | Auditor of `acme` | `dev_bob_password` |
| `carol@globex.test` | Administrator of `globex` | `dev_carol_password` |

The Authentik admin interface is at <https://auth.paddock.localhost:8443/if/admin/> (user `akadmin`, password in
`authentik_bootstrap_password`).

## Make targets

| Target | Purpose |
| --- | --- |
| `make lint` | golangci-lint, `go vet`, OpenAPI contract lint, ESLint and vue-tsc for the portal |
| `make test` | Go unit and integration tests (Docker test containers) and portal unit tests |
| `make gen` | sqlc, oapi-codegen, audit code document (`docs/compliance/audit-codes.md`), TypeScript API types |
| `make web` | Builds the portal into `server/web/dist` (in the pinned Node container) |
| `make image` | Builds the `paddock-server:dev` image |
| `make acceptance` | Acceptance gates against the running stack (`T=<regex>` to select, e.g. `T=TestWORM`) |
| `make e2e` | Playwright end-to-end tests against the running stack (builds `bin/devicesim` and `bin/agentrelease` first) |
| `make agent` / `make deb` | Builds `paddockd` and `paddock-supervisor` (amd64, arm64) / the Debian packages for amd64 (`VERSION=`, `TAGS=`) |
| `make agent-release VERSION=x.y.z` | Builds, signs (development release key) and uploads an agent release (`TAGS=` for test builds) |
| `make system-test VM=<vm\|all>` | Agent system tests on the VirtualBox VMs of `test/vms/virtualbox` against the running stack (`T=<regex>`) |
| `make fuzz` | Fuzz tests of `pkg` (`FUZZTIME=30s` per target by default) |
| `make logs` / `make down` | Logs of the stack / stop it (`make down V=1` also deletes all volumes) |

`make ci` runs `lint test web`. The acceptance gates are the definition of done (`CLAUDE.md`); run
`make up dev-seed acceptance` before declaring a milestone finished.

## Repository layout

```
api/openapi/admin.yaml   admin API contract (source of truth)
api/openapi/device.yaml  device API contract
server/                  paddock-server (Go): cmd, internal packages, migrations, web/ (Vue portal)
pkg/                     Go module shared with the agent: device protocol, DSSE, canonical JSON, bundle schema, path policy
agent/                   paddockd (agent) and paddock-supervisor (Go, static binaries)
packaging/               nfpm configurations, systemd unit and maintainer scripts of the agent packages
deploy/compose/          Compose stack, pinned image versions, bootstrap scripts
test/acceptance/         acceptance gates, the reference device client devicesim and the release uploader
test/system/             system tests of the agent packages on the test VMs
docs/                    architecture, ADRs, plans, operations runbooks, compliance
```

## License

MIT
