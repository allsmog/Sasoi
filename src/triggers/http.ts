import { Hono } from 'hono'
import type { Env } from '../config.js'
import { logger } from '../config.js'
import { runEnricher } from '../agents/enricher.js'
import { runInvestigator } from '../agents/investigator.js'
import { runStrategist } from '../agents/strategist.js'
import { runResponder } from '../agents/responder.js'
import { getTenantAgentConfig, computeTenantMetrics, insertCloudConnector, queryCloudConnectors } from '../clients/db.js'
import { checkRateLimit } from '../safety/guard.js'
import * as orchestrator from '../clients/orchestrator.js'
import { apiAuth } from '../middleware/api-auth.js'

export const httpRoutes = new Hono<{ Bindings: Env }>()

// All HTTP API routes require Bearer token authentication
httpRoutes.use('/*', apiAuth)

// --- Manual agent triggers ---

httpRoutes.post('/agents/enricher/run', async (c) => {
  const { tenant_id, event_id, event_data } = await c.req.json()
  if (!tenant_id || !event_id || !event_data) return c.json({ error: 'tenant_id, event_id, and event_data required' }, 400)
  if (!checkRateLimit(tenant_id, 'enricher', 100)) return c.json({ error: 'Rate limited' }, 429)

  c.executionCtx.waitUntil(
    runEnricher(c.env, { tenantId: tenant_id, eventId: event_id, eventData: event_data })
      .catch((err) => logger.error({ err, event_id }, 'Manual enricher failed')),
  )
  return c.json({ status: 'started', agent: 'enricher', event_id })
})

httpRoutes.post('/agents/investigator/run', async (c) => {
  const { tenant_id, event_id, reason, src_ip } = await c.req.json()
  if (!tenant_id) return c.json({ error: 'tenant_id required' }, 400)
  if (!checkRateLimit(tenant_id, 'investigator', 20)) return c.json({ error: 'Rate limited' }, 429)

  c.executionCtx.waitUntil(
    runInvestigator(c.env, { tenantId: tenant_id, trigger: 'http', context: { eventId: event_id, reason, srcIp: src_ip } })
      .catch((err) => logger.error({ err, tenant_id }, 'Manual investigator failed')),
  )
  return c.json({ status: 'started', agent: 'investigator', tenant_id })
})

httpRoutes.post('/agents/strategist/run', async (c) => {
  const { tenant_id, cluster_id, reason } = await c.req.json()
  if (!tenant_id) return c.json({ error: 'tenant_id required' }, 400)
  if (!checkRateLimit(tenant_id, 'strategist', 5)) return c.json({ error: 'Rate limited' }, 429)

  c.executionCtx.waitUntil(
    runStrategist(c.env, { tenantId: tenant_id, trigger: 'http', context: { clusterId: cluster_id, reason } })
      .catch((err) => logger.error({ err, tenant_id }, 'Manual strategist failed')),
  )
  return c.json({ status: 'started', agent: 'strategist', tenant_id })
})

httpRoutes.post('/agents/responder/run', async (c) => {
  const body = await c.req.json()
  if (!body.tenant_id) return c.json({ error: 'tenant_id required' }, 400)
  if (!checkRateLimit(body.tenant_id, 'responder', 10)) return c.json({ error: 'Rate limited' }, 429)

  c.executionCtx.waitUntil(
    runResponder(c.env, {
      tenantId: body.tenant_id,
      trigger: 'http',
      context: {
        campaignId: body.campaign_id,
        campaignName: body.campaign_name,
        attackerIps: body.attacker_ips,
        affectedDeployments: body.affected_deployments,
        reason: body.reason,
      },
    }).catch((err) => logger.error({ err }, 'Manual responder failed')),
  )
  return c.json({ status: 'started', agent: 'responder', tenant_id: body.tenant_id })
})

// --- Proposals ---

httpRoutes.get('/proposals', async (c) => {
  const tenantId = c.req.query('tenant_id')
  if (!tenantId) return c.json({ error: 'tenant_id query param required' }, 400)

  const { results } = await c.env.DB.prepare(
    'SELECT * FROM agent_proposals WHERE tenant_id = ? AND status = ? ORDER BY created_at DESC',
  ).bind(tenantId, 'pending').all()

  return c.json(results)
})

httpRoutes.post('/proposals/:proposalId/approve', async (c) => {
  const { proposalId } = c.req.param()
  const { reviewed_by, note, tenant_id } = await c.req.json()

  if (!tenant_id) return c.json({ error: 'tenant_id required in request body' }, 400)

  const proposal = await c.env.DB.prepare(
    'SELECT * FROM agent_proposals WHERE proposal_id = ? AND status = ?',
  ).bind(proposalId, 'pending').first()

  if (!proposal) return c.json({ error: 'Proposal not found or already processed' }, 404)

  // Cross-tenant authorization: caller's tenant must match proposal's tenant
  if (proposal.tenant_id !== tenant_id) {
    return c.json({ error: 'Tenant mismatch: not authorized to approve this proposal' }, 403)
  }
  if (new Date(proposal.expires_at as string) < new Date()) {
    await c.env.DB.prepare('UPDATE agent_proposals SET status = ? WHERE proposal_id = ?').bind('expired', proposalId).run()
    return c.json({ error: 'Proposal has expired' }, 410)
  }

  // Parse action_payload BEFORE marking approved to avoid stuck state on malformed data
  const actionType = proposal.action_type as string
  let actionPayload: Record<string, unknown>
  try {
    actionPayload = JSON.parse(proposal.action_payload as string)
  } catch {
    return c.json({ error: 'Proposal has malformed action_payload' }, 422)
  }

  // Atomic status transition — prevents double-approval race condition
  const updateResult = await c.env.DB.prepare(
    'UPDATE agent_proposals SET status = ?, reviewed_by = ?, reviewed_at = ?, review_note = ? WHERE proposal_id = ? AND status = ?',
  ).bind('approved', reviewed_by ?? null, new Date().toISOString(), note ?? null, proposalId, 'pending').run()

  if (!updateResult.meta.changes) {
    return c.json({ error: 'Proposal was already processed by another request' }, 409)
  }

  // Execute approved action
  try {
    if (actionType === 'deploy_honeypot' || actionType === 'deploy_canary') {
      await orchestrator.createDeployment(c.env, actionPayload)
      await c.env.DB.prepare('UPDATE agent_proposals SET status = ? WHERE proposal_id = ?').bind('executed', proposalId).run()
    }
  } catch (err) {
    logger.error({ err, proposalId }, 'Failed to execute approved proposal')
  }

  return c.json({ status: 'approved', proposal_id: proposalId })
})

httpRoutes.post('/proposals/:proposalId/reject', async (c) => {
  const { proposalId } = c.req.param()
  const { reviewed_by, note, tenant_id } = await c.req.json()

  if (!tenant_id) return c.json({ error: 'tenant_id required in request body' }, 400)

  // Tenant isolation: only allow rejection by the owning tenant
  await c.env.DB.prepare(
    'UPDATE agent_proposals SET status = ?, reviewed_by = ?, reviewed_at = ?, review_note = ? WHERE proposal_id = ? AND tenant_id = ? AND status = ?',
  ).bind('rejected', reviewed_by ?? null, new Date().toISOString(), note ?? null, proposalId, tenant_id, 'pending').run()

  return c.json({ status: 'rejected', proposal_id: proposalId })
})

// --- Agent activity ---

httpRoutes.get('/sessions', async (c) => {
  const tenantId = c.req.query('tenant_id')
  if (!tenantId) return c.json({ error: 'tenant_id query param required' }, 400)
  const parsedLimit = parseInt(c.req.query('limit') ?? '50', 10)
  const limit = Math.min(Number.isNaN(parsedLimit) ? 50 : parsedLimit, 1000)

  const { results } = await c.env.DB.prepare(
    'SELECT * FROM agent_sessions WHERE tenant_id = ? ORDER BY started_at DESC LIMIT ?',
  ).bind(tenantId, limit).all()

  return c.json(results)
})

// --- Tenant config ---

httpRoutes.get('/config/:tenantId', async (c) => {
  const config = await getTenantAgentConfig(c.env.DB, c.env, c.req.param('tenantId'))
  return c.json(config)
})

// --- Metrics ---

httpRoutes.get('/metrics/:tenantId', async (c) => {
  const tenantId = c.req.param('tenantId')
  if (!tenantId) return c.json({ error: 'tenant_id required' }, 400)

  const since = c.req.query('since')
  const until = c.req.query('until')

  if (since && isNaN(Date.parse(since))) return c.json({ error: 'Invalid since date format' }, 400)
  if (until && isNaN(Date.parse(until))) return c.json({ error: 'Invalid until date format' }, 400)

  const metrics = await computeTenantMetrics(c.env.DB, tenantId, since, until)
  return c.json(metrics)
})

// --- Cloud connectors ---

httpRoutes.post('/cloud-connectors', async (c) => {
  const body = await c.req.json()
  if (!body.tenant_id || !body.provider || !body.account_ref) {
    return c.json({ error: 'tenant_id, provider, and account_ref required' }, 400)
  }

  const connectorId = await insertCloudConnector(c.env.DB, {
    tenant_id: body.tenant_id,
    provider: body.provider,
    account_ref: body.account_ref,
    enabled_regions: body.enabled_regions,
    allowed_decoy_types: body.allowed_decoy_types,
  })

  return c.json({ status: 'created', connector_id: connectorId }, 201)
})

httpRoutes.get('/cloud-connectors', async (c) => {
  const tenantId = c.req.query('tenant_id')
  if (!tenantId) return c.json({ error: 'tenant_id query param required' }, 400)

  const { results } = await queryCloudConnectors(c.env.DB, tenantId)
  return c.json(results)
})

httpRoutes.put('/config/:tenantId', async (c) => {
  const tenantId = c.req.param('tenantId')
  const body = await c.req.json()

  // Validate autonomy_level if provided
  if (body.autonomy_level !== undefined) {
    const level = body.autonomy_level
    if (typeof level !== 'number' || !Number.isInteger(level) || level < 0 || level > 3) {
      return c.json({ error: 'autonomy_level must be an integer between 0 and 3' }, 400)
    }
  }

  // Validate enabled_agents if provided
  const VALID_AGENTS = new Set(['enricher', 'investigator', 'strategist', 'responder'])
  if (body.enabled_agents !== undefined) {
    if (!Array.isArray(body.enabled_agents) || body.enabled_agents.some((a: unknown) => typeof a !== 'string' || !VALID_AGENTS.has(a))) {
      return c.json({ error: `enabled_agents must be an array of valid agent types: ${[...VALID_AGENTS].join(', ')}` }, 400)
    }
  }

  const existing = await getTenantAgentConfig(c.env.DB, c.env, tenantId)

  await c.env.DB.prepare(
    `INSERT OR REPLACE INTO tenant_agent_config (tenant_id, autonomy_level, enabled_agents, rate_limits, responder_opt_in, inventory_enabled, inventory_namespaces, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))`,
  ).bind(
    tenantId,
    body.autonomy_level ?? existing.autonomy_level,
    JSON.stringify(body.enabled_agents ?? existing.enabled_agents),
    JSON.stringify(body.rate_limits ?? existing.rate_limits),
    body.responder_opt_in !== undefined ? (body.responder_opt_in ? 1 : 0) : (existing.responder_opt_in ? 1 : 0),
    body.inventory_enabled !== undefined ? (body.inventory_enabled ? 1 : 0) : (existing.inventory_enabled ? 1 : 0),
    JSON.stringify(body.inventory_namespaces ?? existing.inventory_namespaces),
  ).run()

  return c.json({ status: 'updated' })
})
