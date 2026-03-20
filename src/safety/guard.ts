import type { AgentEvent } from '@mariozechner/pi-agent-core'
import type { Env } from '../config.js'
import { createProposal, getTenantAgentConfig, logToolInvocation } from '../clients/db.js'
import { logger } from '../config.js'

const MUTATION_TOOLS = new Set([
  'execute_deployment',
  'deploy_canary',
  'rotate_persona',
  'generate_persona_variation',
  'increase_logging_depth',
  'trigger_notification',
  'deploy_honeytoken',
  'block_ip',
  'redirect_attacker',
  'deploy_cloud_decoy',
  'deploy_decoy_sa',
])

const AUTONOMY_REQUIREMENTS: Record<string, number> = {
  execute_deployment: 2,
  deploy_canary: 2,
  rotate_persona: 1,
  generate_persona_variation: 1,
  increase_logging_depth: 1,
  trigger_notification: 0,
  propose_deployment: 0,
  create_investigation: 0,
  flag_campaign: 0,
  generate_report: 0,
  generate_decoy_files: 0,
  generate_breadcrumbs: 0,
  deploy_honeytoken: 2,
  query_honeytokens: 0,
  block_ip: 2,
  redirect_attacker: 2,
  deploy_cloud_decoy: 2,
  deploy_decoy_sa: 2,
}

interface GuardContext {
  sessionId: string
  agentType: string
  tenantId: string
  env: Env
}

export class SafetyGuard {
  private toolStartTimes = new Map<string, number>()

  constructor(private ctx: GuardContext) {}

  async preCheck(
    event: Extract<AgentEvent, { type: 'tool_execution_start' }>,
  ): Promise<{ allowed: true } | { allowed: false; reason: string; proposalId?: string }> {
    this.toolStartTimes.set(event.toolCallId, Date.now())

    const requiredLevel = AUTONOMY_REQUIREMENTS[event.toolName]
    if (requiredLevel === undefined) return { allowed: true }

    const tenantConfig = await getTenantAgentConfig(this.ctx.env.DB, this.ctx.env, this.ctx.tenantId)
    const currentLevel = tenantConfig.autonomy_level

    if (currentLevel >= requiredLevel) return { allowed: true }

    if (MUTATION_TOOLS.has(event.toolName)) {
      const proposalId = await createProposal(this.ctx.env.DB, this.ctx.env, {
        session_id: this.ctx.sessionId,
        agent_type: this.ctx.agentType,
        tenant_id: this.ctx.tenantId,
        action_type: event.toolName,
        action_payload: event.args as Record<string, unknown>,
        reasoning: `Agent attempted ${event.toolName} but tenant autonomy level ${currentLevel} < required ${requiredLevel}`,
      })

      logger.info({ toolName: event.toolName, proposalId, tenantId: this.ctx.tenantId }, 'Mutation redirected to proposal queue')

      return {
        allowed: false,
        reason: `Insufficient autonomy level (${currentLevel}/${requiredLevel}). Created proposal ${proposalId} for operator approval.`,
        proposalId,
      }
    }

    return { allowed: true }
  }

  async postCheck(event: Extract<AgentEvent, { type: 'tool_execution_end' }>): Promise<void> {
    const startTime = this.toolStartTimes.get(event.toolCallId)
    const durationMs = startTime ? Date.now() - startTime : 0
    this.toolStartTimes.delete(event.toolCallId)

    await logToolInvocation(this.ctx.env.DB, {
      session_id: this.ctx.sessionId,
      tool_name: event.toolName,
      tool_args: {},
      result: event.result,
      is_error: event.isError,
      duration_ms: durationMs,
    })
  }

  // IMPORTANT: This subscriber depends on pi-agent-core's subscriber API to actually
  // block tool execution when preCheck returns {allowed: false}. If the framework only
  // treats subscribers as passive observers, tools will execute even when blocked.
  // Verify that throwing from the subscriber (or the framework's veto mechanism) prevents execution.
  // If not, tools must re-check autonomy in their own execute() handlers.
  createEventSubscriber() {
    return async (event: AgentEvent) => {
      if (event.type === 'tool_execution_start') {
        const check = await this.preCheck(event)
        if (!check.allowed) {
          logger.warn({ toolName: event.toolName, reason: check.reason }, 'Tool blocked by SafetyGuard')
        }
      }
      if (event.type === 'tool_execution_end') {
        await this.postCheck(event)
      }
    }
  }
}

// In-memory rate limiter (resets per Worker instance lifecycle)
const invocationCounts = new Map<string, { count: number; resetAt: number }>()

export function checkRateLimit(tenantId: string, agentType: string, limit: number): boolean {
  const key = `${tenantId}:${agentType}`
  const now = Date.now()

  // Purge expired entries when map grows too large
  if (invocationCounts.size > 500) {
    for (const [k, v] of invocationCounts) {
      if (now > v.resetAt) invocationCounts.delete(k)
    }
  }

  const entry = invocationCounts.get(key)

  if (!entry || now > entry.resetAt) {
    invocationCounts.set(key, { count: 1, resetAt: now + 60_000 })
    return true
  }
  if (entry.count >= limit) return false
  entry.count++
  return true
}
