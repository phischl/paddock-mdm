-- A running restore plan a platform administrator abandoned because its host never reported the end (PDK-832) gets its
-- own state. Reusing failed with a marker in outcome_detail could be forged by a host failure report, whose detail is
-- free text; a separate state cannot. Forward-only: there is no Down migration.
-- +goose Up
ALTER TABLE backup_restore_plan DROP CONSTRAINT backup_restore_plan_state_check,
  ADD CONSTRAINT backup_restore_plan_state_check
    CHECK (state IN ('approved','running','completed','failed','expired','abandoned'));

-- +goose Down
