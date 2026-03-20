-- Cloud deception: multi-cloud connectors and decoy resources

CREATE TABLE IF NOT EXISTS cloud_connectors (
  connector_id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  provider TEXT NOT NULL CHECK (provider IN ('aws', 'azure', 'gcp')),
  account_ref TEXT NOT NULL,
  enabled_regions TEXT DEFAULT '[]',
  allowed_decoy_types TEXT DEFAULT '[]',
  status TEXT NOT NULL DEFAULT 'active',
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_cloud_connectors_tenant ON cloud_connectors(tenant_id, provider);

CREATE TABLE IF NOT EXISTS cloud_decoys (
  decoy_id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  connector_id TEXT NOT NULL REFERENCES cloud_connectors(connector_id),
  provider TEXT NOT NULL,
  decoy_type TEXT NOT NULL,
  resource_ref TEXT,
  region TEXT,
  monitoring_status TEXT DEFAULT 'pending',
  status TEXT NOT NULL DEFAULT 'active',
  access_count INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_cloud_decoys_tenant ON cloud_decoys(tenant_id, status);
