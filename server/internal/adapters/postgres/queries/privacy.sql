-- Privacy settings (ADR 0032 §2, plan M10 decisions 7–8). The trigger of migration 00074 creates the row of every
-- organization; the upsert covers a row that is missing anyway.

-- name: GetPrivacySettings :one
SELECT * FROM organization_privacy_settings;

-- name: UpsertPrivacySettings :one
INSERT INTO organization_privacy_settings (organization_id, retired_inventory_days, audit_search_recorded,
  inventory_view_recorded, updated_at, updated_by)
VALUES (@organization_id, @retired_inventory_days, @audit_search_recorded, @inventory_view_recorded, now(),
  sqlc.narg(updated_by))
ON CONFLICT (organization_id) DO UPDATE
SET retired_inventory_days = excluded.retired_inventory_days, audit_search_recorded = excluded.audit_search_recorded,
    inventory_view_recorded = excluded.inventory_view_recorded, updated_at = excluded.updated_at,
    updated_by = excluded.updated_by
RETURNING *;
