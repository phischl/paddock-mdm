-- Retention of the control-plane origin of audit events (ADR 0032 amendments 2026-10-18 and 2026-10-31, PDK-180).
-- The worker's retention round calls these per organization inside OrgPool.InOrg and once per round for the platform
-- pseudo-organization inside PlatformPool.InPlatform, whose role sees every organization's rows; the explicit
-- organization filter keeps that pass to the pseudo-organization.

-- name: HasExpiredActions :one
-- Whether the retention round has a batch of finished actions to delete (DeleteExpiredActions).
SELECT EXISTS (
  SELECT 1 FROM action
  WHERE organization_id = @organization_id AND status = 'finished' AND finished_at < @cutoff::timestamptz
);

-- name: DeleteExpiredActions :execrows
-- One batch of actions that finished before the cutoff. A started action is the outbox reaper's input and never
-- matches. The retention round runs each batch in its own transaction until one deletes fewer than 1 000 rows (plan M10
-- amendment 2026-10-30).
DELETE FROM action WHERE id IN (
  SELECT a.id FROM action a
  WHERE a.organization_id = @organization_id AND a.status = 'finished' AND a.finished_at < @cutoff::timestamptz
  LIMIT 1000
);
