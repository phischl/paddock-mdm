-- Retired organizations (plan M17 decision 16, ADR 0052 decision 6), audit writer only.

-- name: InsertAuditOrgRetired :exec
INSERT INTO audit_org_retired (organization_id) VALUES (@organization_id) ON CONFLICT (organization_id) DO NOTHING;

-- name: RecordAuditOrgRetiredVerification :exec
UPDATE audit_org_retired SET final_verified_at = now(), final_outcome = @final_outcome
WHERE organization_id = @organization_id AND final_verified_at IS NULL;

-- name: GetAuditOrgRetired :one
SELECT * FROM audit_org_retired WHERE organization_id = @organization_id;

-- name: ListAuditOrgRetiredIDs :many
SELECT organization_id FROM audit_org_retired ORDER BY organization_id;

-- The retirement of an organization whose acknowledgement the broker has not confirmed yet (plan M17 amendment o point
-- 5).
-- name: ListAuditOrgRetiredUnacknowledged :many
SELECT * FROM audit_org_retired
WHERE final_verified_at IS NOT NULL AND ack_published_at IS NULL
ORDER BY organization_id;

-- name: MarkAuditOrgRetiredAcknowledged :exec
UPDATE audit_org_retired SET ack_published_at = now()
WHERE organization_id = @organization_id AND final_verified_at IS NOT NULL AND ack_published_at IS NULL;

-- name: IsAuditOrgRetired :one
SELECT EXISTS (SELECT 1 FROM audit_org_retired WHERE organization_id = @organization_id) AS retired;

-- The day of an organization's newest object: after the final verification of a retired organization, the day of
-- its last event, which the sealer seals as the organization's last day (amendment o point 7).
-- name: LastAuditObjectDay :one
SELECT day FROM audit_object WHERE organization_id = @organization_id ORDER BY day DESC LIMIT 1;

-- Retired organizations whose final verification is not recorded yet (plan M17 amendment o, review 1 M1): the
-- retirement loop completes them, also after a crash.
-- name: ListAuditOrgRetiredPending :many
SELECT organization_id FROM audit_org_retired WHERE final_verified_at IS NULL ORDER BY retired_at, organization_id;

-- Organizations whose retirement was requested (an indexed organization.audit_retirement_requested of the platform
-- pseudo-organization since @since) but that have no audit_org_retired row: the consumer failed to insert it, and the
-- retirement loop does it instead, so a request is never lost to a redelivery limit.
-- name: ListAuditRetirementRequestsWithoutRow :many
SELECT DISTINCT (e.params ->> 'organization_id')::uuid AS organization_id
FROM audit_event e
WHERE e.organization_id = @platform_organization_id AND e.code = 'organization.audit_retirement_requested'
  AND e.outcome = 'success' AND e.occurred_at >= @since
  AND e.params ->> 'organization_id' ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
  AND e.params ->> 'organization_id' <> @platform_organization_id::text
  AND NOT EXISTS (SELECT 1 FROM audit_org_retired r WHERE r.organization_id::text = e.params ->> 'organization_id');
