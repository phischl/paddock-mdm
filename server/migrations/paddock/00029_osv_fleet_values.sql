-- Review of plan M5c: the findings keep the inventory system's own severity and fixed version next to the values the
-- enrichment shows, so that a CVE Ubuntu drops or has not prioritized falls back to them; paddock_osv_match gets the
-- search path SECURITY DEFINER functions should have. Forward-only: there is no Down migration.
-- +goose Up

ALTER TABLE vulnerability_finding
  ADD COLUMN fleet_severity text CHECK (fleet_severity IN ('critical','high','medium','low')),
  ADD COLUMN fleet_fixed_version text;

-- Findings enriched before this migration lost Fleet's values; the CVSS score is Fleet's own and gives its severity
-- back (the scale of inventory.Severity), the next inventory sync writes both columns again.
UPDATE vulnerability_finding SET
  fleet_severity = CASE WHEN cvss_score >= 9 THEN 'critical' WHEN cvss_score >= 7 THEN 'high'
                        WHEN cvss_score >= 4 THEN 'medium' WHEN cvss_score > 0 THEN 'low' END,
  fleet_fixed_version = CASE WHEN cvss_vector IS NULL THEN fixed_version END;

ALTER FUNCTION paddock_osv_match(text, text, text) SET search_path = public, pg_temp;

-- +goose Down
