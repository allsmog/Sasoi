import { Agent } from '@mariozechner/pi-agent-core'
import { getModel } from '@mariozechner/pi-ai'
import type { Env } from '../config.js'
import { logger } from '../config.js'
import { createGeoipLookupTool, createThreatIntelLookupTool, createMlPredictTool, createUpdateEventEnrichmentTool, createEscalateToInvestigatorTool } from '../tools/enrichment.js'
import { SafetyGuard } from '../safety/guard.js'
import { sanitizeForPrompt } from '../safety/sanitize.js'
import { createAgentSession, completeAgentSession } from '../clients/db.js'

const ENRICHER_SYSTEM_PROMPT = `You are the Enricher Agent for the Honeypot Orchestration Platform (HOP).

Your role is to intelligently enrich honeypot events with contextual threat data. You decide WHICH enrichment steps to run for each event based on its characteristics.

## Decision Guidelines

- **Known scanners** (Shodan, Censys, common bot UAs): Skip expensive threat intel lookups, just do GeoIP.
- **First-time IPs on high-value honeypots**: Run full enrichment (GeoIP + threat intel + ML prediction).
- **Repeated low-severity events** (login_attempt from same IP): Skip if already enriched recently.
- **High-severity events** (root_shell_access, privilege_escalation, data_exfiltration): Always run full enrichment AND escalate to investigator.
- **Brute force patterns** (many events from same IP): Run threat intel, then escalate if abuse score is high.

## Tool Usage Limits

You MUST complete within 3 tool calls maximum. Prioritize the most valuable enrichment steps.

## Escalation Criteria

Escalate to the investigator agent when:
1. Threat intel shows abuse confidence > 80%
2. IP is flagged as known malware/botnet
3. Event severity is high or critical
4. Same IP has hit 3+ different honeypots
5. ML prediction shows anomalous behavior

## Falco Runtime Alerts (signal: falco_runtime_alert)

Falco events are HIGH-FIDELITY detections from inside the honeypot container — actual
attacker behavior (process execution, file access, network attempts), not just network probes.

For Falco events:
- NEVER run geoip_lookup (src_ip is 127.0.0.1 — runtime event, not network).
- ALWAYS run ml_predict with the process/command data for behavioral analysis.
- ALWAYS escalate_to_investigator — Falco detections represent active compromise.
- Update enrichment with ML prediction results.

Critical Falco rules (always escalate immediately):
- "Reverse Shell Detected" — attacker establishing C2.
- "Container Escape Attempt" — attempting to break sandbox.
- "Lateral Movement" — pivoting to real infrastructure.

## Honeytoken Access Events (signal: honeytoken_accessed)

Highest-fidelity signal — a fake credential was actively used.
- ALWAYS escalate to investigator immediately.
- ALWAYS run threat_intel_lookup on source IP.
- NEVER false positives — someone found and used a planted credential.

## Cloud Decoy Access Events (signal: cloud_decoy_accessed)

High-fidelity signal — a cloud deception resource was accessed.
- ALWAYS escalate to investigator immediately.
- ALWAYS run threat_intel_lookup on source IP.
- Indicates attacker has moved to cloud environment.

## Output

After enriching, update the event's enrichment field with your findings. Always explain your reasoning for which enrichments you chose to run or skip.`

export async function runEnricher(
  env: Env,
  params: {
    tenantId: string
    eventId: string
    eventData: {
      src_ip: string
      signal: string
      severity: string
      hp_type?: string
      ua?: string
      deployment_id?: string
      enrichment?: Record<string, unknown>
    }
  },
): Promise<void> {
  const sessionId = await createAgentSession(env.DB, {
    agent_type: 'enricher',
    trigger_type: 'realtime',
    trigger_source: `event:${params.eventId}`,
    tenant_id: params.tenantId,
  })

  const guard = new SafetyGuard({ sessionId, agentType: 'enricher', tenantId: params.tenantId, env })

  const agent = new Agent({
    initialState: {
      systemPrompt: ENRICHER_SYSTEM_PROMPT,
      model: getModel('anthropic', 'claude-haiku-4-5-20251001'),
      tools: [
        createGeoipLookupTool(env),
        createThreatIntelLookupTool(env),
        createMlPredictTool(env),
        createUpdateEventEnrichmentTool(env),
        createEscalateToInvestigatorTool(env),
      ],
      messages: [],
      thinkingLevel: 'off',
    },
    getApiKey: async (provider) => {
      if (provider === 'anthropic') return env.ANTHROPIC_API_KEY
      return undefined
    },
  })

  agent.subscribe(guard.createEventSubscriber())

  try {
    await agent.prompt(`Enrich the following honeypot event:

<event_data>
Event ID: ${sanitizeForPrompt(params.eventId)}
Tenant ID: ${sanitizeForPrompt(params.tenantId)}
Source IP: ${sanitizeForPrompt(params.eventData.src_ip)}
Signal: ${sanitizeForPrompt(params.eventData.signal)}
Severity: ${sanitizeForPrompt(params.eventData.severity)}
Honeypot Type: ${sanitizeForPrompt(params.eventData.hp_type)}
User Agent: ${sanitizeForPrompt(params.eventData.ua)}
Deployment ID: ${sanitizeForPrompt(params.eventData.deployment_id)}
Existing Enrichment: ${JSON.stringify(params.eventData.enrichment ?? {})}
</event_data>

Decide which enrichment steps to run based on this event's characteristics. Remember: max 3 tool calls.`)

    await agent.waitForIdle()
    await completeAgentSession(env.DB, sessionId, { status: 'completed' })
    logger.info({ sessionId, eventId: params.eventId }, 'Enricher agent completed')
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err)
    try {
      await completeAgentSession(env.DB, sessionId, { status: 'failed', error_message: message })
    } catch (dbErr) {
      logger.error({ dbErr, sessionId }, 'Failed to record enricher session failure')
    }
    logger.error({ err, sessionId, eventId: params.eventId }, 'Enricher agent failed')
    throw err
  }
}
