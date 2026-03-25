import { Hono } from 'hono'
import type { AppEnv } from '../config.js'
import { logger } from '../config.js'
import { runEnricher } from '../agents/enricher.js'
import { runInvestigator } from '../agents/investigator.js'
import { runResponder } from '../agents/responder.js'
import { getTenantAgentConfig, upsertClusterInventory, createAgentSession, completeAgentSession, getHoneytokenById, recordHoneytokenAccess } from '../clients/db.js'
import type { InventoryService } from '../clients/db.js'
import { checkRateLimit } from '../safety/guard.js'
import { webhookAuth } from '../middleware/webhook-auth.js'

// Webhook endpoints — called by HOP services or external systems
// Replaces Supabase Realtime subscriptions

export const webhookRoutes = new Hono<AppEnv>()

// All webhook routes require HMAC signature verification
webhookRoutes.use('/webhooks/*', webhookAuth)

// Called by api-ingestor when a new event is ingested
webhookRoutes.post('/webhooks/event-ingested', async (c) => {
  let event: {
    event_id: string
    tenant_id: string
    src_ip: string
    signal: string
    severity: string
    hp_type?: string
    ua?: string
    deployment_id?: string
    enrichment?: Record<string, unknown>
  }
  try {
    event = JSON.parse(c.get('rawBody'))
  } catch {
    return c.json({ error: 'Invalid JSON body' }, 400)
  }

  const env = c.env
  const tenantConfig = await getTenantAgentConfig(env.DB, env, event.tenant_id)

  if (!(tenantConfig.enabled_agents).includes('enricher')) {
    return c.json({ status: 'skipped', reason: 'enricher not enabled' })
  }

  if (!checkRateLimit(event.tenant_id, 'enricher', tenantConfig.rate_limits.enricher ?? 100)) {
    return c.json({ status: 'rate_limited' }, 429)
  }

  // Fire and forget — Workers will keep the request alive via waitUntil
  c.executionCtx.waitUntil(
    runEnricher(env, {
      tenantId: event.tenant_id,
      eventId: event.event_id,
      eventData: event,
    }).catch((err) => logger.error({ err, eventId: event.event_id }, 'Enricher webhook failed')),
  )

  // Also trigger investigator for high-severity events
  if (event.severity === 'high' && tenantConfig.enabled_agents.includes('investigator')) {
    if (checkRateLimit(event.tenant_id, 'investigator', tenantConfig.rate_limits.investigator ?? 20)) {
      c.executionCtx.waitUntil(
        runInvestigator(env, {
          tenantId: event.tenant_id,
          trigger: 'high_severity_event',
          context: { eventId: event.event_id, srcIp: event.src_ip, reason: `High severity ${event.signal} from ${event.src_ip}` },
        }).catch((err) => logger.error({ err, eventId: event.event_id }, 'Investigator webhook failed')),
      )
    }
  }

  return c.json({ status: 'accepted', event_id: event.event_id })
})

// Called when a campaign is flagged (self-trigger or external)
webhookRoutes.post('/webhooks/campaign-created', async (c) => {
  let campaign: {
    campaign_id: string
    tenant_id: string
    name: string
    attacker_ips: string[]
    affected_honeypots: string[]
    confidence: number
  }
  try {
    campaign = JSON.parse(c.get('rawBody'))
  } catch {
    return c.json({ error: 'Invalid JSON body' }, 400)
  }

  const env = c.env
  const tenantConfig = await getTenantAgentConfig(env.DB, env, campaign.tenant_id)

  if (!tenantConfig.enabled_agents.includes('responder')) {
    return c.json({ status: 'skipped', reason: 'responder not enabled' })
  }

  if (!checkRateLimit(campaign.tenant_id, 'responder', tenantConfig.rate_limits.responder ?? 10)) {
    return c.json({ status: 'rate_limited' }, 429)
  }

  c.executionCtx.waitUntil(
    runResponder(env, {
      tenantId: campaign.tenant_id,
      trigger: 'campaign_detected',
      context: {
        campaignId: campaign.campaign_id,
        campaignName: campaign.name,
        attackerIps: campaign.attacker_ips,
        affectedDeployments: campaign.affected_honeypots,
      },
    }).catch((err) => logger.error({ err, campaignId: campaign.campaign_id }, 'Responder webhook failed')),
  )

  return c.json({ status: 'accepted', campaign_id: campaign.campaign_id })
})

// Called by cluster-agent when inventory scan completes
webhookRoutes.post('/webhooks/cluster-inventory', async (c) => {
  let payload: {
    cluster_id: string
    tenant_id: string
    services: InventoryService[]
    collected_at: string
  }
  try {
    payload = JSON.parse(c.get('rawBody'))
  } catch {
    return c.json({ error: 'Invalid JSON body' }, 400)
  }

  if (!payload.tenant_id || !payload.cluster_id) {
    return c.json({ error: 'tenant_id and cluster_id required' }, 400)
  }

  const env = c.env
  const tenantConfig = await getTenantAgentConfig(env.DB, env, payload.tenant_id)

  // Gate 1: inventory must be explicitly enabled for this tenant
  if (!tenantConfig.inventory_enabled) {
    return c.json({ error: 'Inventory not enabled for this tenant' }, 403)
  }

  const allowedNamespaces = new Set(tenantConfig.inventory_namespaces)
  if (allowedNamespaces.size === 0) {
    return c.json({ error: 'No namespaces in allowlist' }, 403)
  }

  // Gate 2: reject any service from a namespace not in the allowlist
  const disallowed = payload.services.filter((s) => !allowedNamespaces.has(s.namespace))
  if (disallowed.length > 0) {
    const rejected = [...new Set(disallowed.map((s) => s.namespace))]
    return c.json({ error: `Namespace(s) not in allowlist: ${rejected.join(', ')}` }, 403)
  }

  // Gate 3: strip any fields that should never be stored (defense in depth)
  const sanitized = payload.services.map((s) => ({
    name: s.name,
    namespace: s.namespace,
    image: s.image,
    tag: s.tag,
    ports: s.ports,
    replicas: s.replicas,
    size: s.size,
  }))

  // Derive naming patterns from service names
  const namingPatterns = deriveNamingPatterns(sanitized)

  const inventoryId = await upsertClusterInventory(env.DB, {
    cluster_id: payload.cluster_id,
    tenant_id: payload.tenant_id,
    services: sanitized,
    naming_patterns: namingPatterns,
    collected_at: payload.collected_at,
  })

  // Audit trail: log as inventory_scan session
  const sessionId = await createAgentSession(env.DB, {
    agent_type: 'strategist',
    trigger_type: 'realtime',
    trigger_source: `inventory:${payload.cluster_id}`,
    tenant_id: payload.tenant_id,
  })
  await completeAgentSession(env.DB, sessionId, { status: 'completed' })

  logger.info({ inventoryId, tenantId: payload.tenant_id, serviceCount: sanitized.length }, 'Cluster inventory stored')
  return c.json({ status: 'accepted', inventory_id: inventoryId, services_stored: sanitized.length })
})

// Called when a honeytoken is accessed — highest fidelity signal
webhookRoutes.post('/webhooks/honeytoken-accessed', async (c) => {
  let payload: {
    honeytoken_id: string
    tenant_id: string
    source_ip?: string
    source_service?: string
    access_context?: Record<string, unknown>
  }
  try {
    payload = JSON.parse(c.get('rawBody'))
  } catch {
    return c.json({ error: 'Invalid JSON body' }, 400)
  }

  if (!payload.honeytoken_id || !payload.tenant_id) {
    return c.json({ error: 'honeytoken_id and tenant_id required' }, 400)
  }

  const env = c.env

  // Validate honeytoken exists and belongs to tenant
  const honeytoken = await getHoneytokenById(env.DB, payload.honeytoken_id)
  if (!honeytoken) {
    return c.json({ error: 'Honeytoken not found' }, 404)
  }
  if (honeytoken.tenant_id !== payload.tenant_id) {
    return c.json({ error: 'Tenant mismatch' }, 403)
  }

  // Record access
  const accessId = await recordHoneytokenAccess(env.DB, {
    honeytoken_id: payload.honeytoken_id,
    tenant_id: payload.tenant_id,
    source_ip: payload.source_ip,
    source_service: payload.source_service,
    access_context: payload.access_context,
  })

  const tenantConfig = await getTenantAgentConfig(env.DB, env, payload.tenant_id)

  // Trigger enricher if enabled
  if (tenantConfig.enabled_agents.includes('enricher')) {
    c.executionCtx.waitUntil(
      runEnricher(env, {
        tenantId: payload.tenant_id,
        eventId: accessId,
        eventData: {
          src_ip: payload.source_ip ?? 'unknown',
          signal: 'honeytoken_accessed',
          severity: 'high',
          hp_type: 'honeytoken',
          deployment_id: payload.honeytoken_id,
        },
      }).catch((err) => logger.error({ err, honeytokenId: payload.honeytoken_id }, 'Enricher failed for honeytoken access')),
    )
  }

  // Trigger investigator if enabled — honeytoken access is never a false positive
  if (tenantConfig.enabled_agents.includes('investigator')) {
    c.executionCtx.waitUntil(
      runInvestigator(env, {
        tenantId: payload.tenant_id,
        trigger: 'high_severity_event',
        context: {
          eventId: accessId,
          srcIp: payload.source_ip,
          reason: `Honeytoken accessed: ${honeytoken.token_type} (${payload.honeytoken_id})`,
        },
      }).catch((err) => logger.error({ err, honeytokenId: payload.honeytoken_id }, 'Investigator failed for honeytoken access')),
    )
  }

  logger.info({ honeytokenId: payload.honeytoken_id, accessId, sourceIp: payload.source_ip }, 'Honeytoken accessed')
  return c.json({ status: 'accepted', access_id: accessId })
})

// Called when a cloud decoy is accessed (via provider monitoring pipelines)
webhookRoutes.post('/webhooks/cloud-decoy-accessed', async (c) => {
  let payload: {
    decoy_id: string
    tenant_id: string
    provider: string
    source_ip?: string
    access_type?: string
    access_context?: Record<string, unknown>
  }
  try {
    payload = JSON.parse(c.get('rawBody'))
  } catch {
    return c.json({ error: 'Invalid JSON body' }, 400)
  }

  if (!payload.decoy_id || !payload.tenant_id) {
    return c.json({ error: 'decoy_id and tenant_id required' }, 400)
  }

  const env = c.env
  const tenantConfig = await getTenantAgentConfig(env.DB, env, payload.tenant_id)

  // Trigger enricher if enabled
  if (tenantConfig.enabled_agents.includes('enricher')) {
    c.executionCtx.waitUntil(
      runEnricher(env, {
        tenantId: payload.tenant_id,
        eventId: payload.decoy_id,
        eventData: {
          src_ip: payload.source_ip ?? 'unknown',
          signal: 'cloud_decoy_accessed',
          severity: 'high',
          hp_type: `cloud_${payload.provider}`,
          deployment_id: payload.decoy_id,
        },
      }).catch((err) => logger.error({ err, decoyId: payload.decoy_id }, 'Enricher failed for cloud decoy access')),
    )
  }

  // Trigger investigator if enabled
  if (tenantConfig.enabled_agents.includes('investigator')) {
    c.executionCtx.waitUntil(
      runInvestigator(env, {
        tenantId: payload.tenant_id,
        trigger: 'high_severity_event',
        context: {
          eventId: payload.decoy_id,
          srcIp: payload.source_ip,
          reason: `Cloud decoy accessed: ${payload.provider} ${payload.access_type ?? 'unknown'} on ${payload.decoy_id}`,
        },
      }).catch((err) => logger.error({ err, decoyId: payload.decoy_id }, 'Investigator failed for cloud decoy access')),
    )
  }

  logger.info({ decoyId: payload.decoy_id, provider: payload.provider, sourceIp: payload.source_ip }, 'Cloud decoy accessed')
  return c.json({ status: 'accepted', decoy_id: payload.decoy_id })
})

function deriveNamingPatterns(services: InventoryService[]): Record<string, unknown> {
  const patterns: Record<string, string[]> = {}
  for (const svc of services) {
    const parts = svc.name.split('-')
    if (parts.length >= 2) {
      const prefix = parts[0]
      if (!patterns[prefix]) patterns[prefix] = []
      patterns[prefix].push(svc.name)
    }
  }
  return {
    prefixes: Object.keys(patterns),
    examples: Object.fromEntries(
      Object.entries(patterns).map(([k, v]) => [k, v.slice(0, 3)]),
    ),
    total_services: services.length,
  }
}
