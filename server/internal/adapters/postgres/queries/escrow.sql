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

-- Disk encryption escrow (plan M4b decisions 10 and 13).

-- name: LatestEscrowGeneration :one
-- The highest generation of a kind that did not fail: a new LUKS generation must be above it.
SELECT coalesce(max(generation), 0)::int FROM escrow_secret
WHERE device_id = @device_id AND kind = @kind AND status <> 'failed';

-- name: InsertEscrowHeader :execrows
-- A header generation waits as pending until the worker found its object.
INSERT INTO escrow_secret (id, organization_id, device_id, kind, generation, status, key_version, object_key, wrapped_dek,
                           nonce, sha256, size, created_at)
VALUES (@id, @organization_id, @device_id, 'luks_header', @generation, 'pending', @key_version, @object_key, @wrapped_dek,
        @nonce, @sha256, @size, @created_at)
ON CONFLICT DO NOTHING;

-- name: ListPendingEscrowHeaders :many
SELECT * FROM escrow_secret WHERE status = 'pending' ORDER BY created_at, id LIMIT 100;

-- name: FinishEscrowHeader :execrows
UPDATE escrow_secret SET status = @status WHERE id = @id AND status = 'pending';

-- name: ListDiskEscrows :many
-- The LUKS generations of a device, newest first.
SELECT * FROM escrow_secret
WHERE device_id = @device_id AND kind IN ('luks_recovery_key', 'luks_header')
ORDER BY kind, generation DESC;

-- name: LatestStoredEscrow :one
-- The newest stored generation of a LUKS kind, or the requested one (generation 0: the newest).
SELECT * FROM escrow_secret
WHERE device_id = @device_id AND kind = @kind AND status = 'stored'
  AND (@generation::int = 0 OR generation = @generation::int)
ORDER BY generation DESC
LIMIT 1;

-- name: GetEscrowSecrets :many
-- The escrows of one decryption of the escrow-reader, which checks their device and kind (plan M4b.1 decision 6).
SELECT * FROM escrow_secret WHERE id = ANY(@ids::uuid[]);
