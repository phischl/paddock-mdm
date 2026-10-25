-- Audited role membership (plan M8b decisions 34 and 35, PDK-111, worker and platform pool).

-- name: ListOrganizationRoleMembers :many
SELECT * FROM organization_role_member ORDER BY role, authentik_pk;

-- name: InsertOrganizationRoleMember :exec
INSERT INTO organization_role_member (organization_id, role, authentik_pk, username, first_seen_at)
VALUES (@organization_id, @role, @authentik_pk, @username, now());

-- name: DeleteOrganizationRoleMember :exec
DELETE FROM organization_role_member WHERE role = @role AND authentik_pk = @authentik_pk;

-- A member missed by a listing is marked (missing = true) and revoked only when the next successful listing misses it
-- again; a listing that shows it clears the mark.
-- name: SetOrganizationRoleMemberMissing :exec
UPDATE organization_role_member SET missing_since = CASE WHEN @missing::boolean THEN coalesce(missing_since, now()) END
WHERE role = @role AND authentik_pk = @authentik_pk;

-- The roles of the caller's organization that had their first comparison (baseline ended).
-- name: ListOrganizationRoleSnapshots :many
SELECT role FROM organization_role_snapshot ORDER BY role;

-- name: InsertOrganizationRoleSnapshot :exec
INSERT INTO organization_role_snapshot (organization_id, role, taken_at) VALUES (@organization_id, @role, now()) ON CONFLICT DO NOTHING;

-- name: ListPlatformRoleMembers :many
SELECT * FROM platform_role_member ORDER BY role, authentik_pk;

-- name: InsertPlatformRoleMember :exec
INSERT INTO platform_role_member (role, authentik_pk, username, first_seen_at) VALUES (@role, @authentik_pk, @username, now());

-- name: DeletePlatformRoleMember :exec
DELETE FROM platform_role_member WHERE role = @role AND authentik_pk = @authentik_pk;

-- name: SetPlatformRoleMemberMissing :exec
UPDATE platform_role_member SET missing_since = CASE WHEN @missing::boolean THEN coalesce(missing_since, now()) END
WHERE role = @role AND authentik_pk = @authentik_pk;

-- name: ListPlatformRoleSnapshots :many
SELECT role FROM platform_role_snapshot ORDER BY role;

-- name: InsertPlatformRoleSnapshot :exec
INSERT INTO platform_role_snapshot (role, taken_at) VALUES (@role, now()) ON CONFLICT DO NOTHING;
