-- The organization index of user_group_member for the deletion (plan M17 amendment 2026-11-16 q point 1, ticket PDK-1068): the
-- EXISTS of paddock_offboard_delete_batch_from and paddock_offboard_finalize becomes an index lookup instead of a scan
-- of the whole table. Built concurrently, outside a transaction, so the table keeps serving writes. A build that fails
-- leaves an INVALID index and goose does not record the version; the re-run drops that leftover and builds it again.
-- A valid index of this name never exists before this migration, so the drop removes only a failed attempt.
-- Forward-only: there is no Down migration.
-- +goose NO TRANSACTION
-- +goose Up
DROP INDEX CONCURRENTLY IF EXISTS user_group_member_org_idx;
CREATE INDEX CONCURRENTLY user_group_member_org_idx ON user_group_member (organization_id);

-- +goose Down
