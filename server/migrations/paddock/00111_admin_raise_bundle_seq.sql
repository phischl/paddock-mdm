-- paddock-server admin raise-bundle-seq --at-least N (decisions-alpha9 item 71; ADR 0046, amendment 2026-11-07).
-- Forward-only: there is no Down migration. A restore raises every device's bundle sequence to at least N, the highest
-- sequence the stack held before it went down plus 1,000,000, and every device by at least one. Unlike
-- paddock_admin_bump_bundle_seq's fixed step, the highest sequence then grows by about 1,000,000 per restore instead of
-- doubling when a device enrolled since the last raise is at 0. UPDATE device(bundle_seq) is otherwise the compiler's
-- alone, so the raise runs only through this function, which only paddock_platform may call.
-- +goose Up

CREATE FUNCTION paddock_admin_raise_bundle_seq(p_at_least bigint) RETURNS bigint
  LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = public AS
  $$ WITH u AS (UPDATE device SET bundle_seq = greatest(bundle_seq + 1, p_at_least) RETURNING 1) SELECT count(*) FROM u $$;
REVOKE ALL ON FUNCTION paddock_admin_raise_bundle_seq(bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION paddock_admin_raise_bundle_seq(bigint) TO paddock_platform;
