-- Only app.ActionRunner (server/internal/app/action.go) and the outbox package may call these queries.

-- name: InsertAction :exec
INSERT INTO action (id, organization_id, code, status, outcome, actor, target, params, error_code, correlation_id,
                    started_at, finished_at)
VALUES (@id, @organization_id, @code, @status, sqlc.narg(outcome), @actor, sqlc.narg(target), @params,
        sqlc.narg(error_code), @correlation_id, @started_at, sqlc.narg(finished_at));

-- name: FinishAction :execrows
UPDATE action
SET status = 'finished', outcome = @outcome, error_code = sqlc.narg(error_code), target = sqlc.narg(target),
    params = @params, organization_id = @organization_id, finished_at = @finished_at
WHERE id = @id AND status = 'started';

-- name: GetAction :one
SELECT * FROM action WHERE id = @id;

-- name: ListStaleActions :many
SELECT * FROM action
WHERE status = 'started' AND started_at < @started_before
ORDER BY started_at
LIMIT @max_rows
FOR UPDATE SKIP LOCKED;

-- name: InsertOutbox :exec
INSERT INTO outbox (organization_id, subject, msg_id, payload)
VALUES (@organization_id, @subject, @msg_id, @payload);
