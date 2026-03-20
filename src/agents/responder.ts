import { Agent } from '@mariozechner/pi-agent-core'
import { getModel } from '@mariozechner/pi-ai'
import type { Env } from '../config.js'
import { logger } from '../config.js'
import { createQueryEventsTool } from '../tools/events.js'
import { createQueryFleetTool } from '../tools/fleet.js'
import { createRotatePersonaTool, createGenerateVariationTool } from '../tools/persona.js'
import { createDeployCanaryTool } from '../tools/deployment.js'
import { createIncreaseLoggingDepthTool, createTriggerNotificationTool } from '../tools/notification.js'
import { createBlockIPTool, createRedirectAttackerTool } from '../tools/response.js'
import { SafetyGuard } from '../safety/guard.js'
import { sanitizeForPrompt } from '../safety/sanitize.js'
import { createAgentSession, completeAgentSession, getTenantAgentConfig } from '../clients/db.js'

const RESPONDER_SYSTEM_PROMPT = `You are the Responder Agent for the Honeypot Orchestration Platform (HOP).

Your role is to adapt honeypots in real-time to maximize intelligence collection from active attackers. You do NOT block attackers — you make honeypots more attractive and informative.

## Core Principle: Maximize Intelligence, Never Block

## Response Playbook

### Campaign detected:
1. Increase logging on affected honeypots.
2. Notify operators.
3. Deploy canary honeypots to entice lateral movement.
4. Rotate personas on fingerprinted honeypots.

### Same IP hits 3+ honeypots:
1. Increase logging on all affected deployments.
2. Generate persona variations.
3. Notify operators if high-value target.

### Honeytoken accessed:
1. ALWAYS escalate — highest fidelity signal.
2. Run threat intel on source IP.
3. Block IP if confirmed malicious (requires responder_opt_in + autonomy >= 2).
4. Redirect attacker to higher-interaction honeypot.

### Active Response (requires responder_opt_in + autonomy >= 2):
- block_ip: Apply NetworkPolicy via orchestrator. Max 24h TTL.
- redirect_attacker: Funnel attacker to higher-interaction honeypot.

## Safety Constraints

All persona changes go through svc-ai-blueprint safety validation. Canary deployments go through proposal queue at autonomy < 2. Block/redirect require double opt-in: responder_opt_in AND autonomy >= 2.`

export async function runResponder(
  env: Env,
  params: {
    tenantId: string
    trigger: 'campaign_detected' | 'multi_honeypot_hit' | 'http'
    context: {
      campaignId?: string
      campaignName?: string
      attackerIps?: string[]
      affectedDeployments?: string[]
      reason?: string
    }
  },
): Promise<void> {
  const tenantConfig = await getTenantAgentConfig(env.DB, env, params.tenantId)

  if (!tenantConfig.responder_opt_in) {
    logger.info({ tenantId: params.tenantId }, 'Responder not opted-in, notification only')
  }

  const sessionId = await createAgentSession(env.DB, {
    agent_type: 'responder',
    trigger_type: params.trigger === 'http' ? 'http' : 'realtime',
    trigger_source: params.context.campaignId ? `campaign:${params.context.campaignId}` : `trigger:${params.trigger}`,
    tenant_id: params.tenantId,
  })

  const guard = new SafetyGuard({ sessionId, agentType: 'responder', tenantId: params.tenantId, env })

  const tools = tenantConfig.responder_opt_in
    ? [
        createQueryEventsTool(env),
        createQueryFleetTool(env),
        createRotatePersonaTool(env),
        createGenerateVariationTool(env),
        createDeployCanaryTool(env),
        createIncreaseLoggingDepthTool(env),
        createTriggerNotificationTool(env),
        ...(tenantConfig.autonomy_level >= 2 ? [
          createBlockIPTool(env),
          createRedirectAttackerTool(env),
        ] : []),
      ]
    : [createTriggerNotificationTool(env)]

  const agent = new Agent({
    initialState: {
      systemPrompt: RESPONDER_SYSTEM_PROMPT,
      model: getModel('anthropic', 'claude-sonnet-4-20250514'),
      tools,
      messages: [],
      thinkingLevel: 'medium',
    },
    getApiKey: async (provider) => {
      if (provider === 'anthropic') return env.ANTHROPIC_API_KEY
      return undefined
    },
  })

  agent.subscribe(guard.createEventSubscriber())

  try {
    const optInNote = tenantConfig.responder_opt_in ? 'Tenant has opted in to adaptive response.' : 'Tenant has NOT opted in. Only send notifications.'
    let prompt: string

    if (params.trigger === 'campaign_detected') {
      prompt = `Campaign detected for tenant ${sanitizeForPrompt(params.tenantId)}.\n\n<event_data>\nCampaign: ${sanitizeForPrompt(params.context.campaignName)} (ID: ${sanitizeForPrompt(params.context.campaignId)})\nAttacker IPs: ${sanitizeForPrompt(params.context.attackerIps?.join(', '))}\nAffected Deployments: ${sanitizeForPrompt(params.context.affectedDeployments?.join(', '))}\n</event_data>\n\n${optInNote}\n\nAdapt deception to maximize intelligence collection.`
    } else if (params.trigger === 'multi_honeypot_hit') {
      prompt = `IP has hit 3+ honeypots for tenant ${sanitizeForPrompt(params.tenantId)}.\n\n<event_data>\nAttacker IPs: ${sanitizeForPrompt(params.context.attackerIps?.join(', '))}\n</event_data>\n\n${optInNote}\n\nRespond to maximize intelligence collection.`
    } else {
      prompt = `${sanitizeForPrompt(params.context.reason, 500) || `Manual response for tenant ${params.tenantId}.`}\n\n${optInNote}`
    }

    await agent.prompt(prompt)
    await agent.waitForIdle()
    await completeAgentSession(env.DB, sessionId, { status: 'completed' })
    logger.info({ sessionId, tenantId: params.tenantId }, 'Responder agent completed')
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err)
    try {
      await completeAgentSession(env.DB, sessionId, { status: 'failed', error_message: message })
    } catch (dbErr) {
      logger.error({ dbErr, sessionId }, 'Failed to record responder session failure')
    }
    logger.error({ err, sessionId }, 'Responder agent failed')
    throw err
  }
}
