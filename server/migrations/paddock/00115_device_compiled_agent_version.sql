-- The agent version a device's latest compile saw (PDK-799, plan M13b decision 15, A10-6): the software section is
-- gated on it, so the compiler's reconcile loop recompiles an active device whose agent version no longer matches it,
-- as it does for a changed architecture or os-release (00097). An upgrade past the gate then gains the available and
-- Flatpak content, and a rollback or reinstall below it drops them again. The version is stored, not the gate, so the
-- version comparison stays in one place (server/internal/buildinfo). Existing devices start in sync, so the upgrade
-- recompiles no fleet. Forward-only: there is no Down migration.
-- +goose Up
ALTER TABLE device ADD COLUMN compiled_agent_version text NOT NULL DEFAULT '';

UPDATE device d SET compiled_agent_version = coalesce((SELECT s.agent_version FROM device_status s WHERE s.device_id = d.id), '');

GRANT UPDATE (compiled_agent_version) ON device TO paddock_compiler;

-- +goose Down
