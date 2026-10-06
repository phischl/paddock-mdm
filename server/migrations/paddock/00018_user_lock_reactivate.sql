-- A lock keeps the user's previous activation state (plan M4b.1 decision 1). Forward-only: there is no Down migration.
-- lock_reactivate is the user's is_active in Authentik read before the lock deactivated it: only a user that was active
-- is activated again by the lock (and by an unlock that completes an interrupted lock). NULL means not read yet. Locks
-- from before this migration always reactivated the user, so they keep that behavior.
-- +goose Up

ALTER TABLE app_user ADD COLUMN lock_reactivate boolean;
UPDATE app_user SET lock_reactivate = true WHERE locked;

-- +goose Down
