# API tokens

API tokens let automation act in one organization through the admin API: `paddockctl` in a CI pipeline, a script
that lists devices. A token is a scoped, expiring and audited credential (architecture §17.3, plan M6c §3.1). Tokens
are managed on the portal page *API tokens* or through `/api/v1/api-tokens`.

## Model

- **One organization, one role.** A token belongs to the organization of the administrator who created it and carries
  exactly one organization role: `org_admin`, `org_operator` or `org_auditor`. It is authorized everywhere exactly like
  a portal session with that role. There are no platform tokens. Restore commands run on the host as
  `paddock-server admin …` (see [paddockctl.md](paddockctl.md#restore-commands)).
- **Role ceiling.** An organization administrator creates tokens of every organization role; an operator creates
  operator and auditor tokens; an auditor creates none. An organization administrator creates auditor tokens for
  auditors. A role above the creator's is refused (403 `forbidden`).
- **Step-up for every creation.** A token lets its holder act without MFA until it expires, so creating one needs a
  step-up of the last 5 minutes, like revealing a password ([step-up.md](step-up.md)). A token never has a step-up, so
  a token cannot create tokens (403 `step_up_required`). For the same reason, a token cannot assign a full permission
  profile or change a profile to full, also not through `PUT /api/v1/config`. Make those changes in the portal.
- **Expiry is required:** between 1 hour and 365 days after creation (portal default: 90 days). Expired tokens stay
  listed with status *expired*.
- **The secret is shown once.** It has the form `pdk_` and 43 characters (32 random bytes). Paddock stores only its
  SHA-256, and lists show its first 12 characters (*prefix*). The secret is never logged and never recorded in the
  audit log. Store it like a password; a lost secret cannot be shown again. Create a new token instead.

## Use

Send the secret as `Authorization: Bearer <secret>` instead of the session cookie. Mutating requests carry
`X-Paddock-CSRF: 1` like portal requests; `paddockctl` does it for you. `GET /api/v1/me` with a token describes the
token (`api_token: {id, name, expires_at}`). *Last used* is updated at most once a minute.

## Revocation

An organization administrator revokes any token of the organization, and an operator the tokens it created. A request
made with a token cannot revoke tokens. Revocation applies from the next request on, because every request is checked
against PostgreSQL and nothing is cached. Revoking a revoked token is 409 `invalid_state`. A revoked token's name is
free for a new token.

## Audit

| Code | When |
| --- | --- |
| `api_token.created` | A token was created, or its creation was refused (`step_up_required`, `forbidden`, `invalid_request`, `name_taken`). Params `name`, `role`, `expires_at`, `prefix`; never the secret. |
| `api_token.revoked` | A token was revoked, or the revocation was refused. Params `name`, `role`, `created_by`. |
| `api_token.use_denied` | A request with a revoked or expired token was refused (401). Actor anonymous with the token's name, param `reason` = `revoked` or `expired`. |

Everything a token does is recorded with actor type `api_token`, the token's ID and name and source `api`. The token's
`created_by` leads to the administrator who created it; the audit log filters by actor type *API token*. Unknown or
malformed secrets are refused with 401 without an audit event. They are counted in the metric
`paddock_api_token_auth_total{result="unknown"}` (also `ok`, `revoked`, `expired`), and the api logs a warning
without the secret.

## Residual risks

- **A token outlives its creator's access.** It keeps working when the administrator who created it loses the role or
  is locked in Authentik. Mitigation: the mandatory expiry, revocation by an organization administrator, and the
  *Created by* column. Review the tokens when an administrator leaves.
- **Unknown secrets are not rate-limited.** Guessing a 256-bit secret is not practical; the metric above shows
  attempts.
- **A token in a CI system is only as safe as that system.** Give CI the narrowest role it needs. A pipeline that only
  previews changes (`apply --dry-run`) still needs `org_operator` or `org_admin`, because a dry run checks the same
  rules as an apply.
