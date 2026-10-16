-- The bearer authentication reads the state of the token's creator in its one lookup (PDK-184): a token stops working
-- once its creator's account is disabled or lost the role the token needs, without a second transaction per request.
-- The function keeps its contract otherwise (one row of the token, last_used_at at most once per 60 s, no row for an
-- inactive organization) and adds creator_role (NULL when the account is gone) and creator_disabled. Changing the
-- result type needs DROP and CREATE; the grant is restored. Forward-only: there is no Down migration.
-- +goose Up
DROP FUNCTION paddock_api_token_lookup(bytea);

-- +goose StatementBegin
CREATE FUNCTION paddock_api_token_lookup(p_hash bytea)
  RETURNS TABLE (id uuid, organization_id uuid, name text, role text, created_by uuid, expires_at timestamptz,
    revoked_at timestamptz, creator_role text, creator_disabled boolean)
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = public, pg_temp AS $$
BEGIN
  RETURN QUERY
    WITH used AS (
      UPDATE api_token t SET last_used_at = now()
      FROM organization o
      WHERE t.secret_sha256 = p_hash AND o.id = t.organization_id AND o.status = 'active'
        AND t.revoked_at IS NULL AND t.expires_at > now()
        AND (t.last_used_at IS NULL OR t.last_used_at < now() - interval '60 seconds')
      RETURNING t.id, t.organization_id, t.name, t.role, t.created_by, t.expires_at, t.revoked_at)
    SELECT u.id, u.organization_id, u.name, u.role, u.created_by, u.expires_at, u.revoked_at, a.role,
      coalesce(a.disabled_at IS NOT NULL, false)
    FROM used u LEFT JOIN admin_account a ON a.id = u.created_by AND a.organization_id = u.organization_id;
  IF NOT FOUND THEN
    RETURN QUERY
      SELECT t.id, t.organization_id, t.name, t.role, t.created_by, t.expires_at, t.revoked_at, a.role,
        coalesce(a.disabled_at IS NOT NULL, false)
      FROM api_token t JOIN organization o ON o.id = t.organization_id
        LEFT JOIN admin_account a ON a.id = t.created_by AND a.organization_id = t.organization_id
      WHERE t.secret_sha256 = p_hash AND o.status = 'active';
  END IF;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION paddock_api_token_lookup(bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION paddock_api_token_lookup(bytea) TO paddock_api;
