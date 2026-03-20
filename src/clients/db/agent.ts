import type { Env } from '../../config.js'
import { logger } from '../../config.js'

// --- Row types ---

export interface AgentSessionRow {
  session_id: string
  agent_type: string
  trigger_type: string
  trigger_source: string
  tenant_id: string | null
  status: string
  tokens_used: number
  error_message: string | null
  started_at: string
  completed_at: string | null
}

// --- Agent session tracking ---

export async function createAgentSession(
  db: D1Database,
  params: {
    agent_type: string
    trigger_type: string
    trigger_source: string
    tenant_id?: string
  },
): Promise<string> {
  const sessionId = crypto.randomUUID()
  await db
    .prepare(
      `INSERT INTO agent_sessions (session_id, agent_type, trigger_type, trigger_source, tenant_id, status, started_at)
       VALUES (?, ?, ?, ?, ?, 'running', datetime('now'))`,
    )
    .bind(sessionId, params.agent_type, params.trigger_type, params.trigger_source, params.tenant_id ?? null)
    .run()

  return sessionId
}

export async function completeAgentSession(
  db: D1Database,
  sessionId: string,
  result: { status: 'completed' | 'failed' | 'timeout'; tokens_used?: number; error_message?: string },
) {
  await db
    .prepare(
      `UPDATE agent_sessions SET status = ?, tokens_used = ?, error_message = ?, completed_at = datetime('now')
       WHERE session_id = ?`,
    )
    .bind(result.status, result.tokens_used ?? 0, result.error_message ?? null, sessionId)
    .run()
}

// --- Tool invocation audit logging ---

export async function logToolInvocation(
  db: D1Database,
  params: {
    session_id: string
    tool_name: string
    tool_args: Record<string, unknown>
    result?: unknown
    is_error: boolean
    duration_ms: number
  },
) {
  try {
    await db
      .prepare(
        `INSERT INTO agent_tool_invocations (invocation_id, session_id, tool_name, tool_args, result, is_error, duration_ms, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))`,
      )
      .bind(
        crypto.randomUUID(),
        params.session_id,
        params.tool_name,
        JSON.stringify(params.tool_args),
        params.result ? JSON.stringify(params.result) : null,
        params.is_error ? 1 : 0,
        params.duration_ms,
      )
      .run()
  } catch (err) {
    logger.error({ err }, 'Failed to log tool invocation')
  }
}

// --- Agent proposals (human-in-the-loop) ---

export async function createProposal(
  db: D1Database,
  env: Env,
  params: {
    session_id?: string | null
    agent_type: string
    tenant_id: string
    action_type: string
    action_payload: Record<string, unknown>
    reasoning: string
  },
): Promise<string> {
  const proposalId = crypto.randomUUID()
  const expiryHours = parseInt(env.PROPOSAL_EXPIRY_HOURS ?? '24', 10) || 24
  const expiresAt = new Date(Date.now() + expiryHours * 60 * 60 * 1000).toISOString()

  await db
    .prepare(
      `INSERT INTO agent_proposals (proposal_id, session_id, agent_type, tenant_id, action_type, action_payload, reasoning, status, expires_at, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', ?, datetime('now'))`,
    )
    .bind(
      proposalId,
      params.session_id ?? null,
      params.agent_type,
      params.tenant_id,
      params.action_type,
      JSON.stringify(params.action_payload),
      params.reasoning,
      expiresAt,
    )
    .run()

  return proposalId
}

// --- Tenant agent config ---

export interface TenantAgentConfig {
  tenant_id: string
  autonomy_level: number
  enabled_agents: string[]
  rate_limits: Record<string, number>
  responder_opt_in: boolean
  inventory_enabled: boolean
  inventory_namespaces: string[]
}

export async function getTenantAgentConfig(db: D1Database, env: Env, tenantId: string): Promise<TenantAgentConfig> {
  const row = await db
    .prepare('SELECT * FROM tenant_agent_config WHERE tenant_id = ?')
    .bind(tenantId)
    .first()

  if (!row) {
    return {
      tenant_id: tenantId,
      autonomy_level: parseInt(env.DEFAULT_AUTONOMY_LEVEL ?? '0', 10),
      enabled_agents: ['enricher'],
      rate_limits: { enricher: 100, investigator: 20, strategist: 5, responder: 10 },
      responder_opt_in: false,
      inventory_enabled: false,
      inventory_namespaces: [],
    }
  }

  let enabled_agents: string[]
  let rate_limits: Record<string, number>
  let inventory_namespaces: string[]
  try {
    enabled_agents = JSON.parse(row.enabled_agents as string)
  } catch {
    logger.error({ tenantId }, 'Corrupted enabled_agents config, using defaults')
    enabled_agents = ['enricher']
  }
  try {
    rate_limits = JSON.parse(row.rate_limits as string)
  } catch {
    logger.error({ tenantId }, 'Corrupted rate_limits config, using defaults')
    rate_limits = { enricher: 100, investigator: 20, strategist: 5, responder: 10 }
  }
  try {
    inventory_namespaces = JSON.parse((row.inventory_namespaces as string) ?? '[]')
  } catch {
    logger.error({ tenantId }, 'Corrupted inventory_namespaces config, using defaults')
    inventory_namespaces = []
  }

  return {
    tenant_id: row.tenant_id as string,
    autonomy_level: Math.max(0, Math.min(3, Number(row.autonomy_level) || 0)),
    enabled_agents,
    rate_limits,
    responder_opt_in: Boolean(row.responder_opt_in),
    inventory_enabled: Boolean(row.inventory_enabled),
    inventory_namespaces,
  }
}

// --- Escalations ---

export async function insertEscalation(
  db: D1Database,
  params: { source_agent: string; target_agent: string; event_id: string; tenant_id: string; reason: string },
) {
  const id = crypto.randomUUID()
  await db
    .prepare(
      `INSERT INTO agent_escalations (escalation_id, source_agent, target_agent, event_id, tenant_id, reason, created_at)
       VALUES (?, ?, ?, ?, ?, ?, datetime('now'))`,
    )
    .bind(id, params.source_agent, params.target_agent, params.event_id, params.tenant_id, params.reason)
    .run()
  return id
}
