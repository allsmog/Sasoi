-- Honeytokens: fake credentials deployed as K8s Secrets

CREATE TABLE IF NOT EXISTS honeytokens (
  honeytoken_id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  token_type TEXT NOT NULL CHECK (token_type IN
    ('aws_access_key','api_key','db_connection_string','github_pat','slack_webhook','jwt_secret','k8s_service_account')),
  token_value TEXT NOT NULL,
  deployment_method TEXT NOT NULL CHECK (deployment_method IN ('k8s_secret','config_map','env_var')),
  deployment_ref TEXT,
  cluster_id TEXT,
  namespace TEXT,
  placement_reasoning TEXT,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','accessed','rotated','retired')),
  access_count INTEGER NOT NULL DEFAULT 0,
  last_accessed_at TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_honeytokens_tenant ON honeytokens(tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_honeytokens_value ON honeytokens(token_value);

CREATE TABLE IF NOT EXISTS honeytoken_access_log (
  access_id TEXT PRIMARY KEY,
  honeytoken_id TEXT NOT NULL REFERENCES honeytokens(honeytoken_id),
  tenant_id TEXT NOT NULL,
  source_ip TEXT,
  source_service TEXT,
  access_context TEXT DEFAULT '{}',
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_honeytoken_access_log ON honeytoken_access_log(honeytoken_id, created_at);
