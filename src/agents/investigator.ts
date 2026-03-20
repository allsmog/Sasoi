import { Agent } from '@mariozechner/pi-agent-core'
import { getModel } from '@mariozechner/pi-ai'
import type { Env } from '../config.js'
import { logger } from '../config.js'
import { createQueryEventsTool, createCorrelateSessionsTool } from '../tools/events.js'
import { createQueryFleetTool } from '../tools/fleet.js'
import { createThreatIntelLookupTool } from '../tools/enrichment.js'
import { createCreateInvestigationTool, createFlagCampaignTool, createGenerateReportTool } from '../tools/investigation.js'
import { SafetyGuard } from '../safety/guard.js'
import { sanitizeForPrompt } from '../safety/sanitize.js'
import { createAgentSession, completeAgentSession } from '../clients/db.js'

const INVESTIGATOR_SYSTEM_PROMPT = `You are the Investigator Agent for the Honeypot Orchestration Platform (HOP).

Your role is to correlate events across honeypots, identify multi-stage attack campaigns, and produce actionable threat intelligence.

## Investigation Process

1. **Correlate sessions**: Use correlate_sessions to find IPs hitting multiple honeypots within a time window.
2. **Analyze patterns**: Query events for each correlated IP to understand the attack timeline and progression.
3. **Identify campaigns**: Group related attacker IPs and events into campaigns.
4. **Produce intelligence**: Create investigation records with findings, IOCs, and MITRE mappings.

## MITRE ATT&CK Mapping

- T1078: Valid account usage | T1110: Brute force | T1046: Network scanning
- T1068: Privilege escalation | T1548: Elevation abuse | T1041: Exfiltration
- T1059: Command interpreter | T1071: Application protocol abuse

## Campaign Detection

Flag a campaign when: same IP hits 3+ honeypots, multiple IPs from same subnet, attack progression follows kill chain, or tool signatures match known actors.

## Falco Event Correlation

Falco runtime alerts correlate with network-level events to reconstruct full kill chains:
  login_attempt -> falco:shell_spawned -> falco:sensitive_file_access -> falco:lateral_movement
  = Complete compromise from initial access through lateral movement.

When you see Falco events, always query_events for the same deployment_id to find preceding
network events (login attempts, brute force) that led to shell access. This gives the full timeline.

Container escape attempts (falco rule "Container Escape Attempt") should ALWAYS produce a
campaign flag and report — this indicates a sophisticated attacker trying to break the sandbox.

## Output

Always create an investigation record. If you identify a coordinated campaign, flag it. Generate a report for high/critical investigations.`

export async function runInvestigator(
  env: Env,
  params: {
    tenantId: string
    trigger: 'cron' | 'escalation' | 'http' | 'high_severity_event'
    context?: { eventId?: string; reason?: string; srcIp?: string }
  },
): Promise<void> {
  const sessionId = await createAgentSession(env.DB, {
    agent_type: 'investigator',
    trigger_type: params.trigger === 'cron' ? 'cron' : params.trigger === 'http' ? 'http' : 'realtime',
    trigger_source: params.context?.eventId ? `event:${params.context.eventId}` : `trigger:${params.trigger}`,
    tenant_id: params.tenantId,
  })

  const guard = new SafetyGuard({ sessionId, agentType: 'investigator', tenantId: params.tenantId, env })

  const agent = new Agent({
    initialState: {
      systemPrompt: INVESTIGATOR_SYSTEM_PROMPT,
      model: getModel('anthropic', 'claude-sonnet-4-20250514'),
      tools: [
        createQueryEventsTool(env),
        createCorrelateSessionsTool(env),
        createQueryFleetTool(env),
        createThreatIntelLookupTool(env),
        createCreateInvestigationTool(env),
        createFlagCampaignTool(env),
        createGenerateReportTool(env),
      ],
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
    let prompt: string
    if (params.trigger === 'cron') {
      prompt = `Perform a routine threat sweep for tenant ${params.tenantId}.\n\n1. Correlate sessions from the last 24 hours.\n2. Investigate correlated groups.\n3. Create investigations and flag campaigns for coordinated activity.\n4. Generate reports for high/critical findings.`
    } else if (params.trigger === 'escalation' || params.trigger === 'high_severity_event') {
      prompt = `Investigate an escalated event for tenant ${sanitizeForPrompt(params.tenantId)}.\n\n<event_data>\nEvent ID: ${sanitizeForPrompt(params.context?.eventId)}\nSource IP: ${sanitizeForPrompt(params.context?.srcIp)}\nReason: ${sanitizeForPrompt(params.context?.reason, 500)}\n</event_data>\n\n1. Query recent events from this source IP.\n2. Correlate with other sessions.\n3. Check threat intel.\n4. Create investigation with findings, IOCs, MITRE mappings.\n5. Flag campaign if part of larger attack.`
    } else {
      prompt = `${sanitizeForPrompt(params.context?.reason, 500) || `Investigation requested for tenant ${params.tenantId}.`}\n\nCorrelate sessions, identify campaigns, produce threat intelligence.`
    }

    await agent.prompt(prompt)
    await agent.waitForIdle()
    await completeAgentSession(env.DB, sessionId, { status: 'completed' })
    logger.info({ sessionId, tenantId: params.tenantId }, 'Investigator agent completed')
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err)
    try {
      await completeAgentSession(env.DB, sessionId, { status: 'failed', error_message: message })
    } catch (dbErr) {
      logger.error({ dbErr, sessionId }, 'Failed to record investigator session failure')
    }
    logger.error({ err, sessionId }, 'Investigator agent failed')
    throw err
  }
}
