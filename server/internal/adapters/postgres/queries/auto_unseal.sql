-- Automatic unseal of OpenBao (ADR 0035, plan M8u decision 3). One row (id = 1). The setting is written by the
-- platform role (paddock_platform); the report columns by the unsealer's role (paddock_unsealer), which may update
-- only those.

-- name: GetAutoUnseal :one
SELECT * FROM openbao_auto_unseal WHERE id = 1;

-- name: GetAutoUnsealForUpdate :one
SELECT * FROM openbao_auto_unseal WHERE id = 1 FOR UPDATE;

-- name: EnableAutoUnseal :exec
UPDATE openbao_auto_unseal
SET state = 'enabled',
    disclaimer_version = @disclaimer_version,
    acknowledgement = @acknowledgement,
    acknowledged_by = @acknowledged_by,
    acknowledged_by_subject = @acknowledged_by_subject,
    acknowledged_at = now(),
    disabled_by = NULL,
    disabled_at = NULL,
    updated_at = now()
WHERE id = 1;

-- The acknowledgement columns stay: the portal shows who enabled it and which disclaimer they acknowledged.
-- name: DisableAutoUnseal :exec
UPDATE openbao_auto_unseal
SET state = 'disabled', disabled_by = @disabled_by, disabled_at = now(), updated_at = now()
WHERE id = 1;

-- name: ReportUnsealer :exec
UPDATE openbao_auto_unseal
SET unsealer_seen_at = now(), unsealer_shares_present = @shares_present, updated_at = now()
WHERE id = 1;

-- name: RecordUnseal :exec
UPDATE openbao_auto_unseal
SET unseal_count = unseal_count + 1, last_unseal_at = now(), updated_at = now()
WHERE id = 1;

-- name: RecordUnsealFailure :exec
UPDATE openbao_auto_unseal
SET failure_count = failure_count + 1, last_failure_at = now(), last_failure_reason = @reason, updated_at = now()
WHERE id = 1;

-- name: MarkAutoUnsealAudited :exec
UPDATE openbao_auto_unseal
SET audited_unseal_count = @audited_unseal_count, audited_failure_count = @audited_failure_count
WHERE id = 1;
