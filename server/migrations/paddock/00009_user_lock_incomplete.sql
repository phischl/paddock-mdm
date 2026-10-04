-- Incomplete user locks (plan M3a decision 7, ADR 0007 amendment). Forward-only: there is no Down migration.
-- A lock marks the user locked for the devices before Authentik is called; lock_incomplete stays true until Authentik
-- confirmed the group membership and the token revocation, so the portal can offer to retry the lock.
-- +goose Up

ALTER TABLE app_user ADD COLUMN lock_incomplete boolean NOT NULL DEFAULT false;

-- +goose Down
