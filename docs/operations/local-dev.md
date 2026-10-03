# Local development stack

The Compose stack in `deploy/compose/` runs the Paddock control plane and the audit domain on one machine.
It is driven by `make`; every command below runs from the repository root.

## Prerequisites

- Docker Engine with Compose v2 (`docker compose`), GNU make, Go 1.25 (for `make dev-seed`, `make acceptance`).
- Free host ports: `8443` (Caddy, configurable through `PADDOCK_HTTPS_PORT` in `deploy/compose/.env`),
  `127.0.0.1:5432`, `5433`, `5672`, `15672`, `8200`, `9001` (development port mappings).
- Node is not needed on the host; the portal is built in a container.

## Start

```sh
make dev-secrets     # random secrets in deploy/compose/.secrets/ and deploy/compose/.env (idempotent)
make up              # starts all services and waits until they are healthy
make bao-bootstrap   # initializes and unseals OpenBao, creates keys, policies and AppRoles (idempotent)
make audit-bootstrap # creates the WORM audit bucket and the writer credential (idempotent)
```

## Files and services

| Path | Purpose |
| --- | --- |
| `compose.yaml` | Control plane: Caddy, PostgreSQL, RabbitMQ, OpenBao, Authentik, Paddock roles |
| `compose.audit.yaml` | Audit domain: `audit-postgres`, `audit-rustfs`, audit writer |
| `compose.dev.yaml` | Development overrides: `PADDOCK_ENV=development`, dev blueprint, loopback port mappings |
| `versions.env` | Pinned images (tag and digest) |
| `.env` | Non-secret settings (copied from `.env.example`) |
| `.secrets/` | Development secrets, OpenBao unseal shares, AppRole credentials, Caddy root certificate (git-ignored) |

Paddock services carry the Compose profile `paddock`.

## Hostnames and TLS

`*.localhost` resolves to `127.0.0.1` in browsers and in most resolvers, so no DNS setup is needed on the host:

- `https://admin.paddock.localhost:8443` – portal and admin API
- `https://auth.paddock.localhost:8443` – Authentik

Inside containers `.localhost` does not resolve. Caddy therefore carries the network aliases
`admin.paddock.localhost` and `auth.paddock.localhost` on network `cp` and listens on the public port inside the
container as well, so containers use exactly the same URLs as the browser (the OIDC issuer must match).

Caddy uses its internal CA (`tls internal`). The one-shot service `caddy-ca-export` copies the root certificate to
`.secrets/caddy-root.crt`; Paddock containers trust it through `SSL_CERT_FILE`. Browsers show a warning unless you
import that certificate.

## OpenBao after a restart

OpenBao seals itself on every restart. In development `make bao-unseal` unseals it with the stored shares in
`.secrets/openbao/`. Paddock roles that need OpenBao report not ready while it is sealed.
Production never stores unseal shares on disk; see `docs/operations/openbao.md`.

## Development-only shortcuts

Only active with `PADDOCK_ENV=development` (scripts refuse otherwise):

- OpenBao unseal shares and the root token are stored in `.secrets/openbao/`.
- The dev blueprint `authentik/dev/paddock-dev.yaml` creates the test users and skips the authenticator validation
  stage of the admin login flow (a failing policy on that stage binding).
- Loopback port mappings for databases, RabbitMQ (incl. management UI), OpenBao and the audit RustFS.

## Useful commands

```sh
make logs                                   # last 300 log lines of all services
make down                                   # stop (keeps volumes)
make down V=1                               # stop and delete all volumes (fresh start; also delete .secrets/openbao)
docker compose -p paddock exec openbao bao status
```

Management UI of RabbitMQ: `http://127.0.0.1:15672` (users from `.secrets/rabbitmq_*_password`; no user has the
`management` tag by default).
