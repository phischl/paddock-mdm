-- The SECURITY DEFINER functions of M6c get the search path the M5c review set for such functions (review 1 of
-- PDK-008): pg_temp last, so a caller that may create temporary objects cannot shadow api_token, organization or
-- device inside them. Forward-only: there is no Down migration. 00033 belongs to PDK-009.
-- +goose Up

ALTER FUNCTION paddock_api_token_lookup(bytea) SET search_path = public, pg_temp;
ALTER FUNCTION paddock_admin_bump_bundle_seq(bigint) SET search_path = public, pg_temp;
