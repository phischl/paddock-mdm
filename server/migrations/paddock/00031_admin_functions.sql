-- Restore commands of paddock-server admin (plan M6c decision 21). Forward-only: there is no Down migration.
-- After a PostgreSQL restore, devices run bundle versions newer than the restored device.bundle_seq; bumping every
-- sequence lets the next bundle be newer than anything a device already accepted. UPDATE device(bundle_seq) is
-- otherwise the compiler's alone, so the bump runs only through this function, which only paddock_platform may call.
-- +goose Up

CREATE FUNCTION paddock_admin_bump_bundle_seq(p_by bigint) RETURNS bigint
  LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = public AS
  $$ WITH u AS (UPDATE device SET bundle_seq = bundle_seq + p_by RETURNING 1) SELECT count(*) FROM u $$;
REVOKE ALL ON FUNCTION paddock_admin_bump_bundle_seq(bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION paddock_admin_bump_bundle_seq(bigint) TO paddock_platform;
