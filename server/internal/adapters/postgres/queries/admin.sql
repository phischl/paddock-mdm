-- Restore commands of paddock-server admin (plan M6c decision 21).

-- Raises the bundle sequence of every device by @by and returns the number of devices.
-- name: BumpBundleSeq :one
SELECT paddock_admin_bump_bundle_seq(@by::bigint)::bigint AS devices;
