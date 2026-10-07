-- The Paddock agent runs (mutual watch, plan M5a decision 8): passes while a process named paddockd runs from an A/B
-- slot below /opt/paddock/agent/. A policy returns pass or fail only, never the process table.
SELECT 1 FROM processes WHERE name = 'paddockd' AND path LIKE '/opt/paddock/agent/%';
