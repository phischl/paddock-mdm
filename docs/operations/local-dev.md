# Local development stack

The Compose stack in `deploy/compose/` runs the Paddock control plane and the audit domain on one machine.
It is driven by `make`; every command below runs from the repository root.

## Prerequisites

- Docker Engine with Compose v2 (`docker compose`), GNU make, Go 1.21 or newer (for `make dev-seed`,
  `make acceptance`). The repository declares Go 1.27.3 (`toolchain` line in `go.work` and every `go.mod`); an older
  host Go downloads that toolchain automatically on first use (`GOTOOLCHAIN=auto`, the Go default, set by the
  Makefile; for `go` commands outside make, unset a `GOTOOLCHAIN=local` from your environment). Container builds
  use the pinned `GO_BUILD_IMAGE` from `deploy/compose/versions.env`.
- Free host ports: `8443` and `8444` (Caddy, configurable through `PADDOCK_HTTPS_PORT` and
  `PADDOCK_HTTPS_UNTRUSTED_PORT` in `deploy/compose/.env`), `127.0.0.1:5432`, `5433`, `5672`, `6379`, `15672`, `8200`,
  `9001`, `8412`, `9091` (development port mappings, `PADDOCK_DEV_*_PORT`; see "Running a second dev stack").
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

The Paddock images are built from source by the `build:` sections of `compose.dev.yaml` and
`compose.backup.dev.yaml`; the production Compose files reference images only, so that the operator bundle
(`deploy/bundle/`, ADR 0022) is a plain copy of them. `make bundle-test` checks that the bundle renders the same
production configuration as `deploy/compose/`. The Compose file sets of every host live in
`deploy/compose/scripts/lib.sh`.

## Files and services

| Path | Purpose |
| --- | --- |
| `compose.yaml` | Control plane: Caddy, PostgreSQL, RabbitMQ, Valkey, RustFS (bundles), OpenBao, Authentik, Paddock roles (`api`, `gateway`, `worker`, `compiler`, `outbox-relay`, `escrow-reader`) |
| `compose.audit.yaml` | Audit domain: `audit-postgres`, `audit-rustfs`, audit writer |
| `compose.dev.yaml` | Development overrides: `PADDOCK_ENV=development`, dev blueprint, loopback port mappings |
| `versions.env` | Pinned images (tag and digest); `PLAYWRIGHT_IMAGE` and `@playwright/test` (`server/web/package.json`) are one version |
| `.env` | Non-secret settings (copied from `.env.example`) |
| `.secrets/` | Development secrets, OpenBao unseal shares, AppRole credentials, Caddy root certificate (git-ignored) |

`@playwright/test` (`server/web/package.json`) and `PLAYWRIGHT_IMAGE` (`versions.env`) are one version: the image
ships the browsers of exactly that package. Dependabot ignores the package; bump both by hand and run `make e2e`,
which refuses a mismatch (`make e2e-check-playwright`).

Paddock services carry the Compose profile `paddock`.

Development-only test hooks (empty = off, honoured only with `PADDOCK_ENV=development`): `PADDOCK_TEST_EXTERNAL_DELAY`
(paddock-api delays external calls) and `PADDOCK_REAPER_THRESHOLD` (outbox relay finalizes stuck actions sooner).
The acceptance gate A3 sets them while it runs. `PADDOCK_TEST_IP_ALLOWLIST_WINDOW` (default 20s in the dev stack,
10m in production) shortens the aggregation window of the IP allow list denials for gate A1 (plan M7a).

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

### Edge allow list and client address in development

The development Caddy applies the same guards as production (`caddy/guards.caddy`, `docs/operations/ip-allowlist.md`)
with defaults made for the gates: `PADDOCK_ADMIN_ALLOWED_CIDRS` admits the private ranges (the host) and the
documentation networks `198.51.100.0/24`, `192.0.2.0/24` and `2001:db8::/32`, while `203.0.113.0/24` is refused at
the edge. Caddy trusts the host as a proxy (`PADDOCK_EDGE_TRUSTED_PROXIES=private_ranges`) and reads both
`CF-Connecting-IP` and `X-Forwarded-For` (the first non-empty one wins), so a request with such a header simulates a
client behind a proxy: Caddy's `client_ip` matcher, its access log and — through `X-Paddock-Client-IP` — the api and
the gateway all see that address, and `GET /api/v1/me` returns it as `client_ip`. The untrusted case is the second
listener `https://admin.paddock.localhost:8444` (`PADDOCK_HTTPS_UNTRUSTED_PORT`): there no peer is trusted and every
such header is ignored. The application allow list is managed in the portal as in production; the gates leave it
empty, and `(. deploy/compose/scripts/lib.sh && compose run --rm --no-deps paddock-worker admin allowlist disable)`,
run from the repository root, switches it off after a failed run.

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
  privileged action, `PADDOCK_STEPUP_MAX_AUTH_AGE` (default 20s; the dev stack sets 15s) the oldest Authentik login a
  step-up accepts (`max_age`). Both are Go durations for `paddock-api`; with `PADDOCK_ENV=production` either variable
  stops the start with a configuration error. `PADDOCK_STEPUP_MFA_CLASS` (the dev stack sets
  `authentik_stages_authenticator_totp.totpdevice`) replaces the WebAuthn class a step-up must validate, so the dev
  users step up with TOTP; it is development-only as well. `GET /api/v1/me` then also returns `step_up` (the session's last
  step-up and both values), which the acceptance gates use instead of the client clock.
- A TOTP step-up: the shipped step-up flow accepts WebAuthn only; the development blueprint skips that stage and adds
  `paddock-dev-stepup-mfa` (WebAuthn or TOTP), so the test users complete step-ups with their seeded TOTP keys
  (`docs/operations/step-up.md`, "Development stack").

## Running the acceptance gates locally

The acceptance gates in `test/acceptance/` run against the running stack. There are two ways to run the whole suite:

- **Serially in one run:** `make acceptance`. The gates take more than two hours in a row (~131 min on a GitHub
  runner, measured 2026-10-29), so without `SHARD` and `T` the run gets a 180-minute timeout; with `SHARD` or `T` it
  is 120 minutes. `ACCEPTANCE_TIMEOUT=<duration>` overrides both. The overall verdict comes only at the end.
- **Shard by shard:** `make acceptance SHARD=i/N` for i = 1 … N, one after another against the same stack, for
  example with N = 4:

  ```sh
  for i in 1 2 3 4; do make acceptance SHARD=$i/4 || break; done
  ```

  This is the partition CI uses: every gate lands in exactly one shard, and the target checks that before each run,
  so running every shard once covers the whole suite. Prefer it when you want an early verdict: a failing gate shows
  up after about 30 minutes instead of at the end, and only the failed shard needs to run again.

`make acceptance T=<regex>` runs selected gates only.

## Running a second dev stack

Two development stacks can run side by side on one host, for example so that two work streams run `make acceptance`
and `make e2e` at the same time. Each stack runs from its own checkout (a second `git worktree`); its
`deploy/compose/.env` and `deploy/compose/.secrets/` belong to that stack alone. Create the second one with
`PADDOCK_INSTANCE`, once, in the new checkout:

```sh
git worktree add ../paddock-2 origin/main && cd ../paddock-2
PADDOCK_INSTANCE=2 make dev-secrets   # new .env for instance 2 and the stack's own secrets
make up BACKUP=1                      # BACKUP=1 is optional, as for the first stack
make dev-seed
make acceptance T='^TestLoginGate$'   # every make target of this checkout reaches instance 2
make e2e SPEC=e2e/devices.spec.ts  # one spec; without SPEC all of them
```

`PADDOCK_INSTANCE=<n>` (2 to 9) only takes effect while `make dev-secrets` creates `.env`; it writes these settings
into it, every port 100·(n−1) above the first stack's (instance 2 below). All of them are ordinary `.env` settings
and can also be set one by one; unset, they keep the first stack's values.

| Setting | First stack | Instance 2 |
| --- | --- | --- |
| `PADDOCK_PROJECT` (Compose project: containers, volumes, networks) | `paddock` | `paddock2` |
| `PADDOCK_IMAGE`, `PADDOCK_COMPILER_IMAGE`, `PADDOCK_PGBACKREST_IMAGE` (built tags) | `paddock-*:dev` | `paddock-*:dev-2` |
| `PADDOCK_HTTPS_PORT`, `PADDOCK_HTTPS_UNTRUSTED_PORT` (Caddy) | `8443`, `8444` | `8543`, `8544` |
| `PADDOCK_PUBLIC_ADMIN_URL`, `PADDOCK_PUBLIC_DEVICE_URL` | `https://admin.paddock.localhost:8443`, … | `…:8543` |
| `PADDOCK_DEV_POSTGRES_PORT`, `PADDOCK_DEV_AUDIT_POSTGRES_PORT` | `5432`, `5433` | `5532`, `5533` |
| `PADDOCK_DEV_RABBITMQ_PORT`, `PADDOCK_DEV_RABBITMQ_MANAGEMENT_PORT` | `5672`, `15672` | `5772`, `15772` |
| `PADDOCK_DEV_VALKEY_PORT`, `PADDOCK_DEV_OPENBAO_PORT` | `6379`, `8200` | `6479`, `8300` |
| `PADDOCK_DEV_AUDIT_S3_PORT`, `PADDOCK_DEV_FLEET_PORT`, `PADDOCK_DEV_PROMETHEUS_PORT` | `9001`, `8412`, `9091` | `9101`, `8512`, `9191` |

The `make` targets (`up`, `down`, `logs`, `bao-unseal`, the bootstraps, `dev-seed`, `acceptance`, `e2e`, the load
test) and the acceptance gates read the project and the ports from the checkout's `.env`, so they need no extra
variables; a variable set in the environment wins over `.env`, as it does for Compose. A command run with a
`PADDOCK_INSTANCE` that is not the one of the checkout's `.env` stops before it touches a stack, so
`PADDOCK_INSTANCE=2 make down` in the first stack's checkout does nothing. The hostnames stay `*.paddock.localhost`
and only the port differs; browsers share cookies across ports, so use a separate browser profile per stack.
`docker compose -p paddock2 …` addresses the second stack directly. The system gates on the VMs (`make system-test`)
still expect the first stack.

## Useful commands

```sh
make logs                                   # last 300 log lines of all services
make down                                   # stop (keeps volumes)
make down V=1                               # stop and delete all volumes (fresh start: also delete .secrets/)
docker compose -p paddock exec openbao bao status
```

Management UI of RabbitMQ: `http://127.0.0.1:15672` (users from `.secrets/rabbitmq_*_password`; no user has the
`management` tag by default).
