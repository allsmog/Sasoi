-- Tenant-scoped API keys and proposal execution failure state

PRAGMA foreign_keys = OFF;

ALTER TABLE agent_proposals RENAME TO agent_proposals_old;

CREATE TABLE agent_proposals (
  proposal_id TEXT PRIMARY KEY,
  session_id TEXT REFERENCES agent_sessions(session_id),
  agent_type TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  action_type TEXT NOT NULL,
  action_payload TEXT NOT NULL DEFAULT '{}',
  reasoning TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'rejected', 'expired', 'executed', 'execution_failed')),
  reviewed_by TEXT,
  reviewed_at TEXT,
  review_note TEXT,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL
);

INSERT INTO agent_proposals (
  proposal_id,
  session_id,
  agent_type,
  tenant_id,
  action_type,
  action_payload,
  reasoning,
  status,
  reviewed_by,
  reviewed_at,
  review_note,
  expires_at,
  created_at
)
SELECT
  proposal_id,
  session_id,
  agent_type,
  tenant_id,
  action_type,
  action_payload,
  reasoning,
  status,
  reviewed_by,
  reviewed_at,
  review_note,
  expires_at,
  created_at
FROM agent_proposals_old;

DROP TABLE agent_proposals_old;

CREATE INDEX IF NOT EXISTS idx_agent_proposals_pending ON agent_proposals(tenant_id, status);

CREATE TABLE IF NOT EXISTS tenant_api_keys (
  tenant_id TEXT PRIMARY KEY,
  key_hash TEXT NOT NULL UNIQUE,
  key_prefix TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked')),
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  last_used_at TEXT,
  revoked_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_tenant_api_keys_status ON tenant_api_keys(status);
CREATE INDEX IF NOT EXISTS idx_tenant_api_keys_prefix ON tenant_api_keys(key_prefix);

PRAGMA foreign_keys = ON;
