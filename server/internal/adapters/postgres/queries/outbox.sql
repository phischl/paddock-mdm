-- name: ClaimOutboxBatch :many
SELECT * FROM outbox
WHERE published_at IS NULL
ORDER BY id
LIMIT @max_rows
FOR UPDATE SKIP LOCKED;

-- name: MarkOutboxPublished :execrows
UPDATE outbox SET published_at = now() WHERE id = ANY(@ids::bigint[]);

-- name: DeletePublishedOutbox :execrows
DELETE FROM outbox WHERE published_at IS NOT NULL AND published_at < @published_before;

-- name: CountUnpublishedOutbox :one
SELECT count(*) FROM outbox WHERE published_at IS NULL;
