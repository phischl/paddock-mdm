-- Platform backup and recovery (plan M15 §3.2 decisions 3 and 4, §6.6; ADR 0046): the backup key, the targets and their
-- mirror status, the schedule, the runs and the restore plans. They are platform data without organization_id, and
-- therefore without RLS (the pattern of platform_role_member, 00070): reachable through paddock_platform (the api's
-- InPlatform) and the backup role paddock_backup only. The api's organization role paddock_api has no grant on any of
-- them. Key material and target credentials are stored only as Transit ciphertext of backup-wrap, which the api
-- encrypts and the backup role alone decrypts.
-- Retention class (plan M15 §7, ADR 0032 amendment 2026-11-04): backup_run and backup_restore_plan are operational
-- evidence (400 days, purged by the backup role); backup_key, backup_target, backup_target_status and backup_schedule
-- are state, never purged.
-- The backup role records its audit events (platform.backup_completed, platform.backup_failed) through ActionRunner in
-- the platform pseudo-organization only: its policies on action and outbox require both the organization context
-- (missing context fails closed) and the nil organization, so it can never write into an organization's audit trail.
-- The role must exist before this migration runs: 10-roles.sh creates it on a fresh cluster.
-- Forward-only: there is no Down migration.
-- +goose Up
CREATE TABLE backup_key (
  key_id text PRIMARY KEY CHECK (key_id ~ '^(bk-[0-9]{8}-[0-9a-f]{8}|legacy)$'),
  state text NOT NULL CHECK (state IN ('unconfirmed','confirmed','retired','discarded')),
  ciphertext text NOT NULL,            -- transit backup-wrap of the 32-byte key
  fingerprint text NOT NULL,
  challenge_positions int[] NOT NULL CHECK (cardinality(challenge_positions) = 6),
  challenge_sha256 bytea NOT NULL,
  attempts int NOT NULL DEFAULT 0,
  legacy boolean NOT NULL DEFAULT false,
  created_by text NOT NULL, created_at timestamptz NOT NULL DEFAULT now(),
  confirmed_by text, confirmed_at timestamptz, retired_at timestamptz
);
CREATE UNIQUE INDEX backup_key_one_active_idx ON backup_key ((true)) WHERE state = 'confirmed';
CREATE UNIQUE INDEX backup_key_one_pending_idx ON backup_key ((true)) WHERE state = 'unconfirmed';
CREATE TABLE backup_target (
  id uuid PRIMARY KEY, name text NOT NULL UNIQUE,
  type text NOT NULL CHECK (type IN ('local','smb','nfs','s3')),
  enabled boolean NOT NULL DEFAULT true,
  settings jsonb NOT NULL,             -- type-specific, no secrets (plan M15 §6.1)
  credentials_ciphertext text,         -- transit backup-wrap; smb and s3
  host_state text NOT NULL CHECK (host_state IN ('n/a','pending_host','mounted','unreachable')),
  host_revision int NOT NULL DEFAULT 1,
  test_requested_at timestamptz, last_test_at timestamptz, last_test_ok boolean, last_test_error text,
  created_by text NOT NULL, created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
  deleted_at timestamptz
);
CREATE TABLE backup_target_status (
  target_id uuid NOT NULL REFERENCES backup_target(id) ON DELETE CASCADE,
  kind text NOT NULL CHECK (kind IN ('postgres','authentik','openbao','fleet','escrow')),
  last_success_at timestamptz, last_error text, last_error_at timestamptz, bytes bigint NOT NULL DEFAULT 0,
  PRIMARY KEY (target_id, kind)
);
CREATE TABLE backup_schedule (
  singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
  full_interval_hours int NOT NULL DEFAULT 24 CHECK (full_interval_hours BETWEEN 6 AND 168),
  openbao_interval_hours int NOT NULL DEFAULT 6 CHECK (openbao_interval_hours BETWEEN 1 AND 24),
  fleet_interval_hours int NOT NULL DEFAULT 24 CHECK (fleet_interval_hours BETWEEN 6 AND 168),
  escrow_interval_hours int NOT NULL DEFAULT 1 CHECK (escrow_interval_hours BETWEEN 1 AND 24),
  retention_full int NOT NULL DEFAULT 14 CHECK (retention_full BETWEEN 2 AND 60),
  openbao_keep_days int NOT NULL DEFAULT 30 CHECK (openbao_keep_days BETWEEN 7 AND 365),
  fleet_keep_days int NOT NULL DEFAULT 30 CHECK (fleet_keep_days BETWEEN 7 AND 365),
  updated_by text, updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE backup_run (
  id uuid PRIMARY KEY, kind text NOT NULL, label text NOT NULL DEFAULT '' CHECK (char_length(label) <= 64),
  state text NOT NULL CHECK (state IN ('requested','running','finished')),
  outcome text CHECK (outcome IN ('succeeded','failed')),
  requested_by text, started_at timestamptz, finished_at timestamptz, bytes bigint NOT NULL DEFAULT 0,
  error_class text, targets jsonb NOT NULL DEFAULT '[]',
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX backup_run_kind_started_idx ON backup_run (kind, started_at DESC);
CREATE TABLE backup_restore_plan (
  id uuid PRIMARY KEY,
  kind text NOT NULL CHECK (kind IN ('point_in_time','components','fresh_install')),
  source_target_id uuid REFERENCES backup_target(id) ON DELETE SET NULL, source text NOT NULL,
  at timestamptz, components text[] NOT NULL,
  state text NOT NULL CHECK (state IN ('approved','running','completed','failed','expired')),
  created_by text NOT NULL, created_at timestamptz NOT NULL DEFAULT now(), expires_at timestamptz,
  started_at timestamptz, finished_at timestamptz, outcome_detail text
);
CREATE UNIQUE INDEX backup_restore_plan_one_open_idx ON backup_restore_plan ((true)) WHERE state IN ('approved','running');

GRANT SELECT, INSERT, UPDATE, DELETE ON backup_key, backup_target, backup_target_status, backup_schedule, backup_run,
  backup_restore_plan TO paddock_platform;
GRANT SELECT ON backup_key, backup_target, backup_schedule TO paddock_backup;
GRANT UPDATE (host_state, test_requested_at, last_test_at, last_test_ok, last_test_error) ON backup_target
  TO paddock_backup;
GRANT SELECT, INSERT, UPDATE, DELETE ON backup_target_status, backup_run TO paddock_backup;
GRANT SELECT, INSERT, UPDATE ON backup_restore_plan TO paddock_backup;

CREATE POLICY backup ON action TO paddock_backup
  USING (organization_id = current_setting('paddock.org_id')::uuid
    AND organization_id = '00000000-0000-0000-0000-000000000000'::uuid)
  WITH CHECK (organization_id = current_setting('paddock.org_id')::uuid
    AND organization_id = '00000000-0000-0000-0000-000000000000'::uuid);
CREATE POLICY backup ON outbox TO paddock_backup
  USING (organization_id = current_setting('paddock.org_id')::uuid
    AND organization_id = '00000000-0000-0000-0000-000000000000'::uuid)
  WITH CHECK (organization_id = current_setting('paddock.org_id')::uuid
    AND organization_id = '00000000-0000-0000-0000-000000000000'::uuid);
GRANT SELECT, INSERT ON action, outbox TO paddock_backup;

-- +goose Down
