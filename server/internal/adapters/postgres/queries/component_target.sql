-- Component targets (plan M8d decisions 53–55).

-- name: UpsertComponentTarget :exec
INSERT INTO component_target (component, version, source) VALUES (@component, @version, @source)
ON CONFLICT (component) DO UPDATE SET version = EXCLUDED.version, source = EXCLUDED.source, updated_at = now()
WHERE component_target.version <> EXCLUDED.version OR component_target.source <> EXCLUDED.source;

-- name: SetHimmelblauTarget :exec
-- The compiler's only write to the platform table (migration 00063).
SELECT paddock_set_himmelblau_target(@version::text, @source::text);

-- name: DeleteComponentTargets :exec
DELETE FROM component_target WHERE component = ANY(@components::text[]);

-- name: ListComponentTargets :many
-- The targets as the api and the worker read them (organization roles, through the function).
SELECT component::text, version::text, source::text, updated_at::timestamptz FROM paddock_component_targets() ORDER BY component;

-- name: ListPlatformComponentTargets :many
SELECT * FROM component_target ORDER BY component;

-- name: NewestFleetdPackageVersion :one
-- The fleet-osquery package of the newest published release that is not halted (as paddock_fleetd_package selects).
SELECT p.package_version::text
FROM agent_package p JOIN agent_release r USING (version)
WHERE p.name = 'fleet-osquery' AND r.status = 'published'
  AND NOT EXISTS (SELECT 1 FROM agent_rollout ro WHERE ro.version = r.version AND ro.status = 'halted')
ORDER BY r.published_at DESC, r.version_key DESC
LIMIT 1;

-- name: ReleaseHasPackage :one
SELECT EXISTS (SELECT 1 FROM agent_package WHERE version = @version AND name = @name)::boolean;
