-- Presence policy (plan M9 decision 38). The tenant policy limits every statement to the organization of the
-- transaction.

-- name: ListWatchedUnits :many
SELECT unit, created_at FROM watched_unit ORDER BY unit;

-- name: DeleteWatchedUnits :exec
DELETE FROM watched_unit;

-- name: InsertWatchedUnit :exec
INSERT INTO watched_unit (organization_id, unit) VALUES (@organization_id, @unit);
