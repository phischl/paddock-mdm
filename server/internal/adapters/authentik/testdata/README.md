Responses recorded from Authentik 2026.8.3 (`ghcr.io/goauthentik/server:2026.8.3`, the version pinned in
`deploy/compose/versions.env`) with the `paddock-service` token on 2026-10-03:

- `groups_list_empty.json` – `GET /api/v3/core/groups/?name=paddock.fixture-org&include_users=false`, no match
- `groups_list_found.json` – the same request after the group was created
- `groups_create.json` – `POST /api/v3/core/groups/ {"name":"paddock.fixture-org"}` (201)
- `groups_create_child.json` – `POST` of `paddock.fixture-org.admins` with `parents` (201)
- `groups_create_duplicate.json` – `POST` of an existing name (400)

The group names were switched to the dot-separated scheme on 2026-10-04 (plan M0.3); the response shapes are
unchanged.

Re-record them when the pinned Authentik version changes.
