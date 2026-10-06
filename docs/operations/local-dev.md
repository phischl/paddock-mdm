# Local development stack

The Compose stack in `deploy/compose/` runs the Paddock control plane and the audit domain on one machine.
It is driven by `make`; every command below runs from the repository root.

## Prerequisites

- Docker Engine with Compose v2 (`docker compose`), GNU make, Go 1.21 or newer (for `make dev-seed`,
  `make acceptance`). The repository declares Go 1.27.1 (`toolchain` line in `go.work` and every `go.mod`); an older
  host Go downloads that toolchain automatically on first use (`GOTOOLCHAIN=auto`, the Go default, set by the
  Makefile; for `go` commands outside make, unset a `GOTOOLCHAIN=local` from your environment). Container builds
  use the pinned `GO_BUILD_IMAGE` from `deploy/compose/versions.env`.
- Free host ports: `8443` (Caddy, configurable through `PADDOCK_HTTPS_PORT` in `deploy/compose/.env`),
  `127.0.0.1:5432`, `5433`, `5672`, `6379`, `15672`, `8200`, `9001` (development port mappings).
- Node is not needed on the host; the portal is built in a container.

## Start

```sh
make dev-secrets     # random secrets in deploy/compose/.secrets/ and deploy/compose/.env (idempotent)
make up              # infrastructure, OpenBao and bucket bootstraps, then the Paddock roles; waits until healthy
make dev-seed        # organizations acme and globex, test users in their groups (idempotent)
```

`make up` runs `make bao-bootstrap` (initialize/unseal OpenBao, keys, policies, AppRoles), `make audit-bootstrap`
(WORM bucket and writer credential) and `make bundles-bootstrap` (bundles bucket, compiler and gateway credentials)
itself; all are idempotent and can also be run on their own.

## Files and services

| Path | Purpose |
| --- | --- |
| `compose.yaml` | Control plane: Caddy, PostgreSQL, RabbitMQ, Valkey, RustFS (bundles), OpenBao, Authentik, Paddock roles (`api`, `gateway`, `worker`, `compiler`, `outbox-relay`) |
| `compose.audit.yaml` | Audit domain: `audit-postgres`, `audit-rustfs`, audit writer |
| `compose.dev.yaml` | Development overrides: `PADDOCK_ENV=development`, dev blueprint, loopback port mappings |
| `versions.env` | Pinned images (tag and digest) |
| `.env` | Non-secret settings (copied from `.env.example`) |
| `.secrets/` | Development secrets, OpenBao unseal shares, AppRole credentials, Caddy root certificate (git-ignored) |

Paddock services carry the Compose profile `paddock`.

Development-only test hooks (empty = off, honoured only with `PADDOCK_ENV=development`): `PADDOCK_TEST_EXTERNAL_DELAY`
(paddock-api delays external calls) and `PADDOCK_REAPER_THRESHOLD` (outbox relay finalizes stuck actions sooner).
The acceptance gate A3 sets them while it runs.

## Hostnames and TLS

`*.localhost` resolves to `127.0.0.1` in browsers and in most resolvers, so no DNS setup is needed on the host:

- `https://admin.paddock.localhost:8443` – portal and admin API
- `https://auth.paddock.localhost:8443` – Authentik
- `https://device.paddock.localhost:8443` – device API (gateway)
- `https://bundles.paddock.localhost:8443` – bundles bucket; only presigned `GET`/`HEAD` below `/paddock-bundles/`
  pass, everything else is answered 403 by Caddy

Inside containers `.localhost` does not resolve. Caddy therefore carries the network aliases
`admin.paddock.localhost`, `auth.paddock.localhost`, `device.paddock.localhost` and `bundles.paddock.localhost` on
network `cp` and listens on the public port inside the
container as well, so containers use exactly the same URLs as the browser (the OIDC issuer must match).

Caddy uses its internal CA (`tls internal`). The one-shot service `caddy-ca-export` copies the root certificate to
`.secrets/caddy-root.crt`; Paddock containers trust it through `SSL_CERT_FILE`. Browsers show a warning unless you
import that certificate.

## Valkey

Valkey holds caches, nonces and bundle pointers of the device control plane; it is never a source of truth
(architecture §8.3). The password is in `.secrets/valkey_password`, e.g.
`REDISCLI_AUTH="$(cat deploy/compose/.secrets/valkey_password)" valkey-cli -h 127.0.0.1 ping`.

Losing Valkey's data is harmless apart from a short interruption: the worker rewrites the enrollment token and
device key caches (`et:`, `dk:`) and restores sequence numbers (`seq:`) from PostgreSQL every 60 s, and the compiler
rewrites the bundle pointers (`bp:`) every 60 s. Until then devices get 401 `invalid_signature` and retry. Lost
nonces only reopen the ±300 s replay window for that time.

## Trying the device API

There is no agent yet (M2b). The reference client of the acceptance gates enrolls a simulated device: create an
enrollment token in the portal (*Enrollment tokens*), copy the enrollment configuration into a file and run

```sh
go run ./test/acceptance/cmd/devicesim enroll --hostname lt-test-01 < enrollment-config.json
```

The device appears under *Devices* (pending unless the token approves automatically).

## OpenBao after a restart

OpenBao seals itself on every restart. In development `make bao-unseal` unseals it with the stored shares in
`.secrets/openbao/`. Paddock roles that need OpenBao report not ready while it is sealed.
Production never stores unseal shares on disk; see `docs/operations/openbao.md`.

## Development-only shortcuts

Only active with `PADDOCK_ENV=development` (scripts refuse otherwise):

- OpenBao unseal shares and the root token are stored in `.secrets/openbao/`.
- The dev blueprint `authentik/dev/paddock-dev.yaml` creates the test users and skips the authenticator validation
  stage of the admin login flow (a failing policy on that stage binding).
- Loopback port mappings for databases, RabbitMQ (incl. management UI), Valkey, OpenBao and the audit RustFS.
- A shorter step-up: `PADDOCK_STEPUP_WINDOW` (default 300s; the dev stack sets 30s) is how long a step-up satisfies a
  privileged action, `PADDOCK_STEPUP_MAX_AUTH_AGE` (default 60s; the dev stack sets 15s) the oldest Authentik login a
  step-up accepts (`max_age`). Both are Go durations for `paddock-api`; with `PADDOCK_ENV=production` either variable
  stops the start with a configuration error. `GET /api/v1/me` then also returns `step_up` (the session's last
  step-up and both values), which the acceptance gates use instead of the client clock.

## Useful commands

```sh
make logs                                   # last 300 log lines of all services
make down                                   # stop (keeps volumes)
make down V=1                               # stop and delete all volumes (fresh start: also delete .secrets/)
docker compose -p paddock exec openbao bao status
```

Management UI of RabbitMQ: `http://127.0.0.1:15672` (users from `.secrets/rabbitmq_*_password`; no user has the
`management` tag by default).
