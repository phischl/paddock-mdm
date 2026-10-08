-- Ubuntu's OSV data (plan M5c decisions 1, 2 and 4): the import replaces the platform tables in one transaction
-- (platform pool); the enrichment updates the findings of an organization (worker pool).

-- name: GetOSVSyncState :one
SELECT etag, data_version, entries, last_success_at, last_attempt_at, last_error, stale_alerted_at, created_at
FROM osv_sync_state WHERE source = 'ubuntu';

-- name: DeleteOSVData :exec
DELETE FROM osv_ubuntu;

-- name: DeleteOSVBinaries :exec
DELETE FROM osv_ubuntu_binary;

-- The arrays are parallel; empty strings stand for unknown values.
-- name: InsertOSVEntries :exec
INSERT INTO osv_ubuntu (cve, release, package, priority, fixed_version, cvss_vector, modified)
SELECT k.cve, k.release, k.package, k.priority, NULLIF(k.fixed, ''), NULLIF(k.vector, ''), k.modified
FROM (SELECT unnest(@cves::text[]) AS cve, unnest(@releases::text[]) AS release, unnest(@packages::text[]) AS package,
             unnest(@priorities::text[]) AS priority, unnest(@fixed::text[]) AS fixed, unnest(@vectors::text[]) AS vector,
             unnest(@modified::timestamptz[]) AS modified) k;

-- name: InsertOSVBinaries :exec
INSERT INTO osv_ubuntu_binary (release, binary_name, package)
SELECT unnest(@releases::text[]), unnest(@binaries::text[]), unnest(@packages::text[])
ON CONFLICT DO NOTHING;

-- name: MarkOSVImported :exec
UPDATE osv_sync_state
SET etag = @etag, data_version = data_version + 1, entries = @entries, last_success_at = now(), last_attempt_at = now(),
    last_error = '', stale_alerted_at = NULL
WHERE source = 'ubuntu';

-- A 304 confirms the data: a success without a new import.
-- name: MarkOSVNotModified :exec
UPDATE osv_sync_state SET last_success_at = now(), last_attempt_at = now(), last_error = '', stale_alerted_at = NULL
WHERE source = 'ubuntu';

-- name: MarkOSVFailed :exec
UPDATE osv_sync_state SET last_attempt_at = now(), last_error = @last_error WHERE source = 'ubuntu';

-- name: MarkOSVStaleAlerted :exec
UPDATE osv_sync_state SET stale_alerted_at = now() WHERE source = 'ubuntu';

-- Enrichment (plan M5c decision 2): every finding of the organization, or of one device, gets Ubuntu's severity, fixed
-- version and CVSS vector for the release of the device's OS. A finding Ubuntu has no priority or no entry for (any
-- more) shows the inventory system's own severity and fixed version. Only changed rows are written.
-- name: EnrichFindings :execrows
UPDATE vulnerability_finding f
SET severity = m.severity, fixed_version = m.fixed_version, cvss_vector = m.cvss_vector
FROM (
  SELECT g.device_id, g.cve, g.software_name, g.software_version, coalesce(x.osv_severity, g.fleet_severity) AS severity,
         coalesce(x.osv_fixed, g.fleet_fixed_version) AS fixed_version, x.osv_vector AS cvss_vector
  FROM vulnerability_finding g
  JOIN device_inventory_ref r ON r.device_id = g.device_id
  LEFT JOIN LATERAL paddock_osv_match(substring(r.os_version from '[0-9]{2}\.[0-9]{2}'), g.cve, g.software_name)
    AS x(osv_severity, osv_fixed, osv_vector) ON true
  WHERE sqlc.narg(device_id)::uuid IS NULL OR g.device_id = sqlc.narg(device_id)::uuid
) m
WHERE f.device_id = m.device_id AND f.cve = m.cve AND f.software_name = m.software_name
  AND f.software_version = m.software_version
  AND (f.severity, f.fixed_version, f.cvss_vector) IS DISTINCT FROM (m.severity, m.fixed_version, m.cvss_vector);
