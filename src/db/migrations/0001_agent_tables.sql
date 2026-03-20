-- Agent tables for agentic-hop (Cloudflare D1 / SQLite)

CREATE TABLE IF NOT EXISTS agent_sessions (
  session_id TEXT PRIMARY KEY,
  agent_type TEXT NOT NULL CHECK (agent_type IN ('enricher', 'investigator', 'strategist', 'responder')),
  trigger_type TEXT NOT NULL CHECK (trigger_type IN ('cron', 'realtime', 'http', 'escalation')),
  trigger_source TEXT NOT NULL,
  tenant_id TEXT,
  status TEXT NOT NULL DEFAULT 'running' CHECK (status IN ('running', 'completed', 'failed', 'timeout')),
  tokens_used INTEGER DEFAULT 0,
  error_message TEXT,
  started_at TEXT NOT NULL,
  completed_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_agent_sessions_tenant ON agent_sessions(tenant_id, started_at);
CREATE INDEX IF NOT EXISTS idx_agent_sessions_status ON agent_sessions(status);

CREATE TABLE IF NOT EXISTS agent_proposals (
  proposal_id TEXT PRIMARY KEY,
  session_id TEXT REFERENCES agent_sessions(session_id),
  agent_type TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  action_type TEXT NOT NULL,
  action_payload TEXT NOT NULL DEFAULT '{}',
  reasoning TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'rejected', 'expired', 'executed')),
  reviewed_by TEXT,
  reviewed_at TEXT,
  review_note TEXT,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_agent_proposals_pending ON agent_proposals(tenant_id, status);

CREATE TABLE IF NOT EXISTS agent_tool_invocations (
  invocation_id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL REFERENCES agent_sessions(session_id),
  tool_name TEXT NOT NULL,
  tool_args TEXT NOT NULL DEFAULT '{}',
  result TEXT,
  is_error INTEGER NOT NULL DEFAULT 0,
  duration_ms INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_agent_tool_invocations_session ON agent_tool_invocations(session_id, created_at);

CREATE TABLE IF NOT EXISTS investigations (
  investigation_id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  session_id TEXT REFERENCES agent_sessions(session_id),
  title TEXT NOT NULL,
  summary TEXT,
  severity TEXT NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
  status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'in_progress', 'resolved', 'closed')),
  findings TEXT NOT NULL DEFAULT '[]',
  iocs TEXT NOT NULL DEFAULT '[]',
  mitre_techniques TEXT DEFAULT '[]',
  event_ids TEXT DEFAULT '[]',
  report_markdown TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_investigations_tenant ON investigations(tenant_id, created_at);

CREATE TABLE IF NOT EXISTS campaigns (
  campaign_id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  investigation_id TEXT REFERENCES investigations(investigation_id),
  name TEXT NOT NULL,
  description TEXT,
  attacker_ips TEXT NOT NULL DEFAULT '[]',
  affected_honeypots TEXT DEFAULT '[]',
  event_ids TEXT DEFAULT '[]',
  mitre_chain TEXT DEFAULT '[]',
  confidence REAL NOT NULL DEFAULT 0.0,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'monitoring', 'concluded')),
  first_seen TEXT,
  last_seen TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_campaigns_tenant ON campaigns(tenant_id, status);

CREATE TABLE IF NOT EXISTS tenant_agent_config (
  tenant_id TEXT PRIMARY KEY,
  autonomy_level INTEGER NOT NULL DEFAULT 0,
  enabled_agents TEXT NOT NULL DEFAULT '["enricher"]',
  rate_limits TEXT NOT NULL DEFAULT '{"enricher":100,"investigator":20,"strategist":5,"responder":10}',
  responder_opt_in INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS agent_escalations (
  escalation_id TEXT PRIMARY KEY,
  source_agent TEXT NOT NULL,
  target_agent TEXT NOT NULL,
  event_id TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  reason TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_agent_escalations_target ON agent_escalations(target_agent, created_at);
