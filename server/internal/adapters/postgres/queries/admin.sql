-- Restore commands of paddock-server admin (plan M6c decision 21).

-- Raises the bundle sequence of every device by @by and returns the number of devices.
-- name: BumpBundleSeq :one
SELECT paddock_admin_bump_bundle_seq(@by::bigint)::bigint AS devices;

-- Raises the bundle sequence of every device to greatest(bundle_seq + 1, @at_least) and returns the number of devices.
-- name: RaiseBundleSeq :one
SELECT paddock_admin_raise_bundle_seq(@at_least::bigint)::bigint AS devices;
