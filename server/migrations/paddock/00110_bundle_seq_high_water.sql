-- The backup role's read of the highest bundle sequence (decisions-alpha9 item 68; ADR 0046, amendment 2026-11-07).
-- After every successful round the backup role records it in the host-side high-water file, from which a restore that
-- cannot read the running stack raises the restored sequences. paddock_backup has no grant on device: this function
-- returns that one number and nothing else. Forward-only: there is no Down migration.
-- +goose Up

CREATE FUNCTION paddock_backup_bundle_seq_high_water() RETURNS bigint
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS
  $$ SELECT coalesce(max(bundle_seq), 0)::bigint FROM device $$;
REVOKE ALL ON FUNCTION paddock_backup_bundle_seq_high_water() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION paddock_backup_bundle_seq_high_water() TO paddock_backup;
