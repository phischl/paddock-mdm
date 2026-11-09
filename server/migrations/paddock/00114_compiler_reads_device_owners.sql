-- The compiler reads the device owners (plan M13b decision 8, PDK-799): an assignment to a user or a user group
-- applies to a device when the user, or a member of the group, owns it, and the audience of an available package names
-- the owners' user names. The compiler only reads; the tenant policy gains its role, so a missing organization context
-- still fails closed. Forward-only: there is no Down migration.
-- +goose Up
GRANT SELECT ON device_owner TO paddock_compiler;
ALTER POLICY tenant ON device_owner TO paddock_api, paddock_worker, paddock_compiler;

-- +goose Down
