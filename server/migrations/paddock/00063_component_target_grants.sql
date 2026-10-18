-- Least privilege for component_target (PDK-328, PDK-234 review 1 finding 10). Migration 00060 gave paddock_compiler
-- and paddock_worker every write on every row of the platform table, and paddock_component_targets() a search_path
-- without pg_temp. The writers are:
--   - paddock_platform: the worker's rollout round writes and deletes the release-derived rows (paddockd,
--     paddock_supervisor, paddock_revoke, fleetd) through the platform pool; it keeps its grants;
--   - paddock_compiler: only the himmelblau row, now through paddock_set_himmelblau_target(), and no direct access;
--   - paddock_worker: none — the worker's organization pool reads the targets through paddock_component_targets()
--     like the api; its rollout round runs as paddock_platform.
-- Forward-only: there is no Down migration.
-- +goose Up
ALTER FUNCTION paddock_component_targets() SET search_path = public, pg_temp;

REVOKE ALL ON component_target FROM paddock_compiler, paddock_worker;

-- +goose StatementBegin
CREATE FUNCTION paddock_set_himmelblau_target(target_version text, target_source text) RETURNS void
  LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = public, pg_temp AS
  $$ INSERT INTO component_target (component, version, source) VALUES ('himmelblau', target_version, target_source)
     ON CONFLICT (component) DO UPDATE SET version = EXCLUDED.version, source = EXCLUDED.source, updated_at = now()
     WHERE component_target.version <> EXCLUDED.version OR component_target.source <> EXCLUDED.source $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION paddock_set_himmelblau_target(text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION paddock_set_himmelblau_target(text, text) TO paddock_compiler;

-- +goose Down
