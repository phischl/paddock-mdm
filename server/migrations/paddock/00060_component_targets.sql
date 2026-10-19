-- Component versions per device (ADR 0037 amendment 2026-10-17, plan M8d decisions 53–55, PDK-235): the versions the
-- devices should run — the current release for paddockd, the supervisor and paddock-revoke, the newest fleetd package,
-- the compiler's Himmelblau version. The table is platform-wide like agent_release; the platform role writes the
-- release-derived rows in the rollout round, the compiler the Himmelblau row. The api and the worker read it through
-- paddock_component_targets(). device_status.components_outdated is computed at every heartbeat. Forward-only: there
-- is no Down migration.
-- +goose Up
CREATE TABLE component_target (
  component text PRIMARY KEY CHECK (component IN ('paddockd','paddock_supervisor','paddock_revoke','himmelblau','fleetd')),
  version text NOT NULL, source text NOT NULL, updated_at timestamptz NOT NULL DEFAULT now()
);
GRANT SELECT, INSERT, UPDATE, DELETE ON component_target TO paddock_compiler, paddock_worker, paddock_platform;

-- +goose StatementBegin
CREATE FUNCTION paddock_component_targets() RETURNS SETOF component_target
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$ SELECT * FROM component_target $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION paddock_component_targets() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION paddock_component_targets() TO paddock_api, paddock_worker;

ALTER TABLE device_status ADD COLUMN components_outdated text[] NOT NULL DEFAULT '{}';
CREATE INDEX device_status_org_outdated_idx ON device_status (organization_id) WHERE cardinality(components_outdated) > 0;

-- +goose Down
