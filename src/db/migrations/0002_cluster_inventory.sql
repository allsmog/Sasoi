-- Cluster inventory for environment-aware honeypot generation
-- Note: D1 migration framework tracks applied migrations and prevents double-execution.

CREATE TABLE IF NOT EXISTS cluster_inventories (
  inventory_id TEXT PRIMARY KEY,
  cluster_id TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  services TEXT NOT NULL DEFAULT '[]',
  naming_patterns TEXT DEFAULT '{}',
  collected_at TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_cluster_inv_tenant ON cluster_inventories(tenant_id, collected_at DESC);

-- Tenant config additions for inventory opt-in
ALTER TABLE tenant_agent_config ADD COLUMN inventory_enabled INTEGER NOT NULL DEFAULT 0;
ALTER TABLE tenant_agent_config ADD COLUMN inventory_namespaces TEXT NOT NULL DEFAULT '[]';
