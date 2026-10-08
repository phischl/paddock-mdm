-- API tokens (plan M6c decision 1). Forward-only: there is no Down migration.
-- A token is a scoped, expiring credential of one organization that acts with one organization role. Only the SHA-256
-- of the secret is stored. The api looks a token up before an organization context exists through the SECURITY
-- DEFINER function paddock_api_token_lookup, which reveals nothing but the token's own row.
-- +goose Up

CREATE TABLE api_token (
  id              uuid PRIMARY KEY,
  organization_id uuid NOT NULL REFERENCES organization(id),
  name            text NOT NULL CHECK (name ~ '^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$'),
  role            text NOT NULL CHECK (role IN ('org_admin', 'org_operator', 'org_auditor')),
  secret_sha256   bytea NOT NULL UNIQUE,
  prefix          text NOT NULL CHECK (char_length(prefix) = 12),
  created_by      uuid NOT NULL REFERENCES admin_account(id),
  created_at      timestamptz NOT NULL DEFAULT now(),
  expires_at      timestamptz NOT NULL,
  last_used_at    timestamptz,
  revoked_at      timestamptz,
  revoked_by      uuid REFERENCES admin_account(id)
);
CREATE UNIQUE INDEX api_token_org_name_live_idx ON api_token (organization_id, name) WHERE revoked_at IS NULL;
CREATE INDEX api_token_org_created_idx ON api_token (organization_id, created_at);
ALTER TABLE api_token ENABLE ROW LEVEL SECURITY;
ALTER TABLE api_token FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON api_token TO paddock_api
  USING (organization_id = current_setting('paddock.org_id')::uuid)
  WITH CHECK (organization_id = current_setting('paddock.org_id')::uuid);
GRANT SELECT, INSERT, UPDATE ON api_token TO paddock_api;

-- The listed form of a token: its status and the display name of the creating administrator. security_invoker keeps
-- the row-level security of both tables.
CREATE VIEW api_token_listed WITH (security_invoker = true) AS
SELECT t.id, t.organization_id, t.name, t.role, t.prefix, t.created_by, a.display_name AS created_by_display,
       t.created_at, t.expires_at, t.last_used_at, t.revoked_at, t.revoked_by,
       (CASE WHEN t.revoked_at IS NOT NULL THEN 'revoked' WHEN t.expires_at <= now() THEN 'expired' ELSE 'active' END)::text AS status
FROM api_token t JOIN admin_account a ON a.id = t.created_by;
GRANT SELECT ON api_token_listed TO paddock_api;

-- Lookup before an organization context exists (same pattern as paddock_org_id_by_slug). Touches last_used_at at most
-- once per 60 s and only for a usable token. Returns no row for an inactive organization.
-- +goose StatementBegin
CREATE FUNCTION paddock_api_token_lookup(p_hash bytea)
  RETURNS TABLE (id uuid, organization_id uuid, name text, role text, created_by uuid, expires_at timestamptz, revoked_at timestamptz)
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = public AS $$
BEGIN
  RETURN QUERY
    UPDATE api_token t SET last_used_at = now()
    FROM organization o
    WHERE t.secret_sha256 = p_hash AND o.id = t.organization_id AND o.status = 'active'
      AND t.revoked_at IS NULL AND t.expires_at > now()
      AND (t.last_used_at IS NULL OR t.last_used_at < now() - interval '60 seconds')
    RETURNING t.id, t.organization_id, t.name, t.role, t.created_by, t.expires_at, t.revoked_at;
  IF NOT FOUND THEN
    RETURN QUERY
      SELECT t.id, t.organization_id, t.name, t.role, t.created_by, t.expires_at, t.revoked_at
      FROM api_token t JOIN organization o ON o.id = t.organization_id
      WHERE t.secret_sha256 = p_hash AND o.status = 'active';
  END IF;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION paddock_api_token_lookup(bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION paddock_api_token_lookup(bytea) TO paddock_api;
