-- Paddock audit index schema (plan M0 §6.2). Forward-only: there is no Down migration.
-- +goose Up
CREATE TABLE audit_event (
  event_id        uuid NOT NULL,
  organization_id uuid NOT NULL,
  occurred_at     timestamptz NOT NULL,
  recorded_at     timestamptz NOT NULL,
  code            text NOT NULL,
  outcome         text NOT NULL CHECK (outcome IN ('success','failure','denied','unknown')),
  source          text NOT NULL,
  actor           jsonb NOT NULL,
  target          jsonb,
  params          jsonb NOT NULL,
  correlation_id  text NOT NULL,
  object_key      text NOT NULL,
  PRIMARY KEY (event_id, occurred_at)
) PARTITION BY RANGE (occurred_at);
CREATE INDEX audit_event_org_time_idx ON audit_event (organization_id, occurred_at DESC);

CREATE TABLE audit_object (
  object_key      text PRIMARY KEY,
  organization_id uuid NOT NULL,
  day             date NOT NULL,
  event_count     int  NOT NULL,
  sha256          bytea NOT NULL,
  created_at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX audit_object_org_day_idx ON audit_object (organization_id, day);

CREATE TABLE audit_manifest (
  organization_id uuid NOT NULL,
  day             date NOT NULL,
  sha256          bytea NOT NULL,
  prev_sha256     bytea,
  signature       text NOT NULL,          -- OpenBao transit signature string "vault:vN:..."
  key_version     int  NOT NULL,
  object_key      text NOT NULL,
  PRIMARY KEY (organization_id, day)
);

ALTER TABLE audit_event ENABLE ROW LEVEL SECURITY; ALTER TABLE audit_event FORCE ROW LEVEL SECURITY;
CREATE POLICY reader ON audit_event TO paddock_audit_reader
  USING (organization_id = current_setting('paddock.org_id')::uuid);
CREATE POLICY writer ON audit_event TO paddock_audit_writer USING (true) WITH CHECK (true);

ALTER TABLE audit_object ENABLE ROW LEVEL SECURITY; ALTER TABLE audit_object FORCE ROW LEVEL SECURITY;
CREATE POLICY writer ON audit_object TO paddock_audit_writer USING (true) WITH CHECK (true);
ALTER TABLE audit_manifest ENABLE ROW LEVEL SECURITY; ALTER TABLE audit_manifest FORCE ROW LEVEL SECURITY;
CREATE POLICY writer ON audit_manifest TO paddock_audit_writer USING (true) WITH CHECK (true);

GRANT SELECT ON audit_event TO paddock_audit_reader;
GRANT SELECT, INSERT ON audit_event, audit_object, audit_manifest TO paddock_audit_writer;
-- No UPDATE or DELETE grant to any non-owner role.

-- +goose StatementBegin
CREATE FUNCTION audit_ensure_partition(p_month date) RETURNS void
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  start_ts date := date_trunc('month', p_month)::date;
  end_ts   date := (date_trunc('month', p_month) + interval '1 month')::date;
  part     text := format('audit_event_%s', to_char(start_ts, 'YYYY_MM'));
BEGIN
  EXECUTE format('CREATE TABLE IF NOT EXISTS %I PARTITION OF audit_event FOR VALUES FROM (%L) TO (%L)',
                 part, start_ts, end_ts);
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION audit_ensure_partition(date) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION audit_ensure_partition(date) TO paddock_audit_writer;

-- +goose Down
