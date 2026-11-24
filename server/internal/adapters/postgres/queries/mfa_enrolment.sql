-- name: StartMfaEnrolmentSeed :one
-- The seed's row (ADR 0053 decision 4), created at the first attempt; a later attempt keeps the first attempt's time.
INSERT INTO platform_mfa_enrolment (id, first_attempt_at) VALUES (true, @now)
ON CONFLICT (id) DO UPDATE SET first_attempt_at = platform_mfa_enrolment.first_attempt_at
RETURNING first_attempt_at, seeded_at;

-- name: GetMfaEnrolmentSeededAt :one
-- When the seed completed; no row or NULL means it has not.
SELECT seeded_at FROM platform_mfa_enrolment WHERE id;

-- name: MarkMfaEnrolmentSeeded :exec
-- Records the completed seed once; a second call keeps the first time.
UPDATE platform_mfa_enrolment SET seeded_at = coalesce(seeded_at, greatest(@now::timestamptz, first_attempt_at)) WHERE id;
