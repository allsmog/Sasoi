-- Response actions: track IP blocks and attacker redirects

CREATE TABLE IF NOT EXISTS response_actions (
  action_id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  action_type TEXT NOT NULL CHECK (action_type IN ('block_ip', 'redirect_attacker')),
  target TEXT NOT NULL,
  config TEXT NOT NULL DEFAULT '{}',
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'expired', 'revoked')),
  ttl_seconds INTEGER,
  expires_at TEXT,
  created_by_session TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_response_actions_tenant ON response_actions(tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_response_actions_target ON response_actions(target, action_type);
