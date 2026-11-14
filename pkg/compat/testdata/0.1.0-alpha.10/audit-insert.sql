INSERT INTO audit_event (event_id, organization_id, occurred_at, recorded_at, code, outcome, source, actor, target,
                         params, correlation_id, object_key, commit_seq)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9,
        $10, $11, $12, $13)
ON CONFLICT DO NOTHING
RETURNING event_id
