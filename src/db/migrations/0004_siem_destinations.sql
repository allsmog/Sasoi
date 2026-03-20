-- SIEM integration: format type for notification destinations
-- Guard: CREATE TABLE IF NOT EXISTS ensures idempotency if destinations table
-- was previously created. D1 migration framework prevents double-execution of this file.

CREATE TABLE IF NOT EXISTS destinations (
  destination_id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  type TEXT NOT NULL,
  config_ref TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

ALTER TABLE destinations ADD COLUMN format_type TEXT DEFAULT NULL;
ALTER TABLE destinations ADD COLUMN siem_config TEXT DEFAULT '{}';
