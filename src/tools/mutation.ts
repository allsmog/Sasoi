import type { AgentTool, AgentToolResult } from '@mariozechner/pi-agent-core'
import type { Static, TSchema } from '@sinclair/typebox'
import type { Env } from '../config.js'
import { createProposal, getTenantAgentConfig } from '../clients/db.js'
import { AUTONOMY_REQUIREMENTS } from '../safety/autonomy.js'

export interface MutationContext {
  env: Env
  tenantId: string
  sessionId: string
  agentType: string
}

interface MutationGuardOptions<TParameters extends TSchema> {
  actionType?: string
  buildProposalPayload?: (params: Static<TParameters>, signal?: AbortSignal) => Promise<Record<string, unknown>>
  buildReasoning?: (params: Static<TParameters>) => string
}

function createBlockedResult(
  proposalId: string,
  currentLevel: number,
  requiredLevel: number,
): AgentToolResult<{ blocked: true; proposal_id: string; current_level: number; required_level: number }> {
  return {
    content: [{
      type: 'text' as const,
      text: `Created proposal ${proposalId}. Tenant autonomy level ${currentLevel} is below required level ${requiredLevel}.`,
    }],
    details: {
      blocked: true,
      proposal_id: proposalId,
      current_level: currentLevel,
      required_level: requiredLevel,
    },
  }
}

export function withMutationGuard<TParameters extends TSchema, TDetails>(
  tool: AgentTool<TParameters, TDetails>,
  ctx: MutationContext,
  options: MutationGuardOptions<TParameters> = {},
): AgentTool<TParameters, TDetails | { blocked: true; proposal_id: string; current_level: number; required_level: number }> {
  return {
    ...tool,
    execute: async (toolCallId, params, signal, onUpdate) => {
      const requiredLevel = AUTONOMY_REQUIREMENTS[tool.name]
      if (requiredLevel === undefined) {
        return tool.execute(toolCallId, params, signal, onUpdate)
      }

      const tenantConfig = await getTenantAgentConfig(ctx.env.DB, ctx.env, ctx.tenantId)
      if (tenantConfig.autonomy_level >= requiredLevel) {
        return tool.execute(toolCallId, params, signal, onUpdate)
      }

      const actionPayload = options.buildProposalPayload
        ? await options.buildProposalPayload(params, signal)
        : (params as Record<string, unknown>)

      const proposalId = await createProposal(ctx.env.DB, ctx.env, {
        session_id: ctx.sessionId,
        agent_type: ctx.agentType,
        tenant_id: ctx.tenantId,
        action_type: options.actionType ?? tool.name,
        action_payload: actionPayload,
        reasoning: options.buildReasoning?.(params)
          ?? `Agent attempted ${tool.name} but tenant autonomy level ${tenantConfig.autonomy_level} < required ${requiredLevel}`,
      })

      return createBlockedResult(proposalId, tenantConfig.autonomy_level, requiredLevel)
    },
  }
}
