-- Escrowed secrets (plan M4a decisions 11 and 12).

-- name: GetEscrowSecret :one
SELECT * FROM escrow_secret WHERE id = @id;

-- name: ActiveEscrowGeneration :one
SELECT coalesce(max(generation), 0)::int FROM escrow_secret
WHERE device_id = @device_id AND kind = @kind AND status = 'active';

-- name: InsertEscrowSecret :execrows
-- A generation that exists already (another upload of the same generation) is not overwritten.
INSERT INTO escrow_secret (id, organization_id, device_id, kind, generation, status, ciphertext, key_version, created_at)
VALUES (@id, @organization_id, @device_id, @kind, @generation, 'stored', @ciphertext, @key_version, @created_at)
ON CONFLICT DO NOTHING;

-- name: OrganizationHasActiveLocalAdmin :one
-- Whether any device of the organization has an active local administrator password (the account name is then
-- locked, plan M4a decision 13).
SELECT EXISTS (SELECT 1 FROM escrow_secret WHERE kind = 'admin_password' AND status = 'active');

-- name: ListLocalAdminSecrets :many
-- The active generation and the stored generations above it: the passwords a reveal returns.
SELECT * FROM escrow_secret
WHERE device_id = @device_id::uuid AND kind = 'admin_password'
  AND (status = 'active' OR (status = 'stored' AND generation > (
    SELECT coalesce(max(generation), 0) FROM escrow_secret a
    WHERE a.device_id = @device_id::uuid AND a.kind = 'admin_password' AND a.status = 'active')))
ORDER BY generation;

-- name: ActivateEscrowGeneration :execrows
-- The device applied generation: it becomes active, every other active or stored generation below it superseded.
WITH activated AS (
  UPDATE escrow_secret SET status = 'active', activated_at = @activated_at::timestamptz
  WHERE device_id = @device_id::uuid AND kind = @kind::text AND generation = @generation::int AND status IN ('stored','active')
  RETURNING generation
)
UPDATE escrow_secret SET status = 'superseded'
WHERE device_id = @device_id::uuid AND kind = @kind::text AND generation < @generation::int AND status IN ('stored','active')
  AND EXISTS (SELECT 1 FROM activated);
