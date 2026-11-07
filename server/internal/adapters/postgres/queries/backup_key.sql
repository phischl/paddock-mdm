-- The backup key (plan M15 decision 7). Written by the platform role (paddock_platform) only; the reads for the API
-- (ActiveBackupKeyID, ListBackupKeyStates) are in backup.sql. Only the use cases that confirm or discard a key lock the
-- whole row.

-- name: PendingBackupKeyID :one
SELECT key_id FROM backup_key WHERE state = 'unconfirmed';

-- The legacy import decides on an empty table while no other writer can insert (plan M15 decision 9).
-- name: LockBackupKeys :exec
LOCK TABLE backup_key IN SHARE ROW EXCLUSIVE MODE;

-- name: CountBackupKeys :one
SELECT count(*) FROM backup_key;

-- name: GetBackupKeyChallenge :one
SELECT challenge_sha256 FROM backup_key WHERE key_id = $1;

-- name: GetBackupKeyForUpdate :one
SELECT * FROM backup_key WHERE key_id = $1 FOR UPDATE;

-- name: InsertBackupKey :one
INSERT INTO backup_key (key_id, state, ciphertext, fingerprint, challenge_positions, challenge_sha256, legacy, created_by)
VALUES (@key_id, 'unconfirmed', @ciphertext, @fingerprint, @challenge_positions, @challenge_sha256, @legacy, @created_by)
RETURNING *;

-- The third failed confirmation discards the key (plan M15 decision 5 of 2026-11-04).
-- name: RecordBackupKeyMismatch :one
UPDATE backup_key
SET attempts = attempts + 1,
    state = CASE WHEN attempts + 1 >= @max_attempts::int THEN 'discarded' ELSE state END
WHERE key_id = @key_id AND state = 'unconfirmed'
RETURNING *;

-- name: RetireConfirmedBackupKey :many
UPDATE backup_key SET state = 'retired', retired_at = now() WHERE state = 'confirmed' RETURNING key_id;

-- name: ConfirmBackupKey :one
UPDATE backup_key SET state = 'confirmed', confirmed_at = now(), confirmed_by = @confirmed_by
WHERE key_id = @key_id AND state = 'unconfirmed'
RETURNING *;

-- name: DiscardBackupKey :one
UPDATE backup_key SET state = 'discarded' WHERE key_id = @key_id AND state = 'unconfirmed' RETURNING *;
