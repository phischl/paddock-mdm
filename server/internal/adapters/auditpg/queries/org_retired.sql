-- Retired organizations (plan M17 decision 16, ADR 0052 decision 6), audit writer only.

-- name: InsertAuditOrgRetired :exec
INSERT INTO audit_org_retired (organization_id) VALUES (@organization_id) ON CONFLICT (organization_id) DO NOTHING;

-- name: RecordAuditOrgRetiredVerification :exec
UPDATE audit_org_retired SET final_verified_at = now(), final_outcome = @final_outcome
WHERE organization_id = @organization_id;

-- name: GetAuditOrgRetired :one
SELECT * FROM audit_org_retired WHERE organization_id = @organization_id;

-- name: ListAuditOrgRetiredIDs :many
SELECT organization_id FROM audit_org_retired ORDER BY organization_id;
