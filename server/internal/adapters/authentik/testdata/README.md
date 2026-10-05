Responses recorded from Authentik 2026.8.3 (`ghcr.io/goauthentik/server:2026.8.3`, the version pinned in
`deploy/compose/versions.env`) with the `paddock-service` token on 2026-10-04 by `TestLiveAuthentik`
(`live_test.go`). The file name is `<method>_<path>[_<status>].json` of the first response per endpoint; the
recorded organization slug is replaced by `fixture-org`, client secrets and link tokens are redacted.

`get_core_brands.json` (paddock-service token) and `patch_core_brands_id.json` (admin token) were added on 2026-10-05
with curl. `TestLiveAuthentik` records the PATCH only when the default brand's flows had to be set, i.e. against a
fresh stack before `paddock-worker` set them.

The in-memory fake of the unit tests (`fake_test.go`) answers with these bodies, filled with its own state.

Re-record them when the pinned Authentik version changes (development stack running, `make dev-seed` done):

    cd server && R=$(cd .. && pwd)/deploy/compose/.secrets && PADDOCK_AUTHENTIK_RECORD=1 \
      PADDOCK_AUTHENTIK_LIVE_URL=https://auth.paddock.localhost:8443 \
      PADDOCK_AUTHENTIK_LIVE_TOKEN_FILE=$R/authentik_service_token \
      PADDOCK_AUTHENTIK_LIVE_ADMIN_TOKEN_FILE=$R/authentik_bootstrap_token \
      SSL_CERT_FILE=$R/caddy-root.crt go test -count=1 -run TestLiveAuthentik ./internal/adapters/authentik/

Without `PADDOCK_AUTHENTIK_RECORD` the same command only runs the adapter against the real instance.
