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
