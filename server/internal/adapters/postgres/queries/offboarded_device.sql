-- The records of offboarded devices (plan M17 decision 15) as the cache sync reads them (platform pool).

-- One keyset page of the records, so a restore never holds every record in one transaction (plan M17 amendment s
-- point 4.2).
-- name: ListOffboardedDevicesPage :many
SELECT * FROM offboarded_device WHERE device_id > @after_device::uuid ORDER BY device_id LIMIT @max_rows;
