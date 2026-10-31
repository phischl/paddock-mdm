-- A finished action is the control-plane origin of an audit event and is never changed again (ADR 0032 amendment
-- 2026-10-31, PDK-180). The permissive policies let the platform and relay roles update every action and the
-- organization roles every action of their organization, so without these restrictive policies a role could move a
-- finished organization action into the platform pseudo-organization (or rewrite its params and outcome) and then
-- delete it through the restrictive DELETE policies of 00081. Every non-owner role with UPDATE on action may update a
-- started action only, and only into started or finished: FinishAction and the outbox reaper keep working, a finished
-- row is read-only. The residual (a started action can still be finished, moved and deleted before its use case
-- finishes it) is named in the ADR 0032 amendment.
-- Forward-only: there is no Down migration.
-- +goose Up
CREATE POLICY finished_immutable ON action AS RESTRICTIVE FOR UPDATE
  TO paddock_api, paddock_platform, paddock_relay, paddock_worker, paddock_compiler, paddock_revocation
  USING (status = 'started')
  WITH CHECK (status IN ('started', 'finished'));
-- +goose Down
