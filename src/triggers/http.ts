import { Hono } from 'hono'
import type { Context } from 'hono'
import type { AppEnv } from '../config.js'
import { logger } from '../config.js'
import { runEnricher } from '../agents/enricher.js'
import { runInvestigator } from '../agents/investigator.js'
import { runStrategist } from '../agents/strategist.js'
import { runResponder } from '../agents/responder.js'
import { getTenantAgentConfig, computeTenantMetrics, insertCloudConnector, queryCloudConnectors } from '../clients/db.js'
import { checkRateLimit } from '../safety/guard.js'
import { apiAuth } from '../middleware/api-auth.js'
import { getProposalActionDefinition, ProposalActionError } from '../proposals/actions.js'

export const httpRoutes = new Hono<AppEnv>()

// All HTTP API routes require Bearer token authentication
httpRoutes.use('/*', apiAuth)

function getAuthenticatedTenantId(c: Context<AppEnv>): string {
  return c.get('authenticatedTenantId')
}

function resolveTenantAccess(
  c: Context<AppEnv>,
  suppliedTenantId?: string,
  label = 'tenant_id',
): { tenantId: string } | { response: Response } {
  const authenticatedTenantId = getAuthenticatedTenantId(c)
  if (suppliedTenantId && suppliedTenantId !== authenticatedTenantId) {
    return {
      response: c.json({ error: `Tenant mismatch: ${label} must match authenticated tenant` }, 403),
    }
  }
  return { tenantId: authenticatedTenantId }
}

function appendExecutionError(note: string | undefined, errorMessage: string): string {
  return note ? `${note}\n\nExecution error: ${errorMessage}` : `Execution error: ${errorMessage}`
}

// --- Manual agent triggers ---

httpRoutes.post('/agents/enricher/run', async (c) => {
  const body = await c.req.json<Record<string, unknown>>()
  const tenantResolution = resolveTenantAccess(c, typeof body.tenant_id === 'string' ? body.tenant_id : undefined)
  if ('response' in tenantResolution) return tenantResolution.response
  if (!body.event_id || !body.event_data) return c.json({ error: 'event_id and event_data required' }, 400)

  const tenantId = tenantResolution.tenantId
  const eventId = body.event_id as string
  const eventData = body.event_data as {
    src_ip: string
    signal: string
    severity: string
    hp_type?: string
    ua?: string
    deployment_id?: string
    enrichment?: Record<string, unknown>
  }

  if (!checkRateLimit(tenantId, 'enricher', 100)) return c.json({ error: 'Rate limited' }, 429)

  c.executionCtx.waitUntil(
    runEnricher(c.env, { tenantId, eventId, eventData })
      .catch((err) => logger.error({ err, event_id: eventId }, 'Manual enricher failed')),
  )
  return c.json({ status: 'started', agent: 'enricher', event_id: eventId })
})

httpRoutes.post('/agents/investigator/run', async (c) => {
  const body = await c.req.json<Record<string, unknown>>()
  const tenantResolution = resolveTenantAccess(c, typeof body.tenant_id === 'string' ? body.tenant_id : undefined)
  if ('response' in tenantResolution) return tenantResolution.response
  const tenantId = tenantResolution.tenantId

  if (!checkRateLimit(tenantId, 'investigator', 20)) return c.json({ error: 'Rate limited' }, 429)

  c.executionCtx.waitUntil(
    runInvestigator(c.env, {
      tenantId,
      trigger: 'http',
      context: {
        eventId: typeof body.event_id === 'string' ? body.event_id : undefined,
        reason: typeof body.reason === 'string' ? body.reason : undefined,
        srcIp: typeof body.src_ip === 'string' ? body.src_ip : undefined,
      },
    }).catch((err) => logger.error({ err, tenant_id: tenantId }, 'Manual investigator failed')),
  )
  return c.json({ status: 'started', agent: 'investigator', tenant_id: tenantId })
})

httpRoutes.post('/agents/strategist/run', async (c) => {
  const body = await c.req.json<Record<string, unknown>>()
  const tenantResolution = resolveTenantAccess(c, typeof body.tenant_id === 'string' ? body.tenant_id : undefined)
  if ('response' in tenantResolution) return tenantResolution.response
  const tenantId = tenantResolution.tenantId

  if (!checkRateLimit(tenantId, 'strategist', 5)) return c.json({ error: 'Rate limited' }, 429)

  c.executionCtx.waitUntil(
    runStrategist(c.env, {
      tenantId,
      trigger: 'http',
      context: {
        clusterId: typeof body.cluster_id === 'string' ? body.cluster_id : undefined,
        reason: typeof body.reason === 'string' ? body.reason : undefined,
      },
    }).catch((err) => logger.error({ err, tenant_id: tenantId }, 'Manual strategist failed')),
  )
  return c.json({ status: 'started', agent: 'strategist', tenant_id: tenantId })
})

httpRoutes.post('/agents/responder/run', async (c) => {
  const body = await c.req.json<Record<string, unknown>>()
  const tenantResolution = resolveTenantAccess(c, typeof body.tenant_id === 'string' ? body.tenant_id : undefined)
  if ('response' in tenantResolution) return tenantResolution.response
  const tenantId = tenantResolution.tenantId

  if (!checkRateLimit(tenantId, 'responder', 10)) return c.json({ error: 'Rate limited' }, 429)

  c.executionCtx.waitUntil(
    runResponder(c.env, {
      tenantId,
      trigger: 'http',
      context: {
        campaignId: typeof body.campaign_id === 'string' ? body.campaign_id : undefined,
        campaignName: typeof body.campaign_name === 'string' ? body.campaign_name : undefined,
        attackerIps: Array.isArray(body.attacker_ips) ? body.attacker_ips as string[] : undefined,
        affectedDeployments: Array.isArray(body.affected_deployments) ? body.affected_deployments as string[] : undefined,
        reason: typeof body.reason === 'string' ? body.reason : undefined,
      },
    }).catch((err) => logger.error({ err }, 'Manual responder failed')),
  )
  return c.json({ status: 'started', agent: 'responder', tenant_id: tenantId })
})

// --- Proposals ---

httpRoutes.get('/proposals', async (c) => {
  const tenantResolution = resolveTenantAccess(c, c.req.query('tenant_id') ?? undefined)
  if ('response' in tenantResolution) return tenantResolution.response
  const tenantId = tenantResolution.tenantId

  const { results } = await c.env.DB.prepare(
    'SELECT * FROM agent_proposals WHERE tenant_id = ? AND status = ? ORDER BY created_at DESC',
  ).bind(tenantId, 'pending').all()

  return c.json(results)
})

httpRoutes.post('/proposals/:proposalId/approve', async (c) => {
  const { proposalId } = c.req.param()
  const body = await c.req.json<Record<string, unknown>>()
  const reviewedBy = typeof body.reviewed_by === 'string' ? body.reviewed_by : undefined
  const note = typeof body.note === 'string' ? body.note : undefined
  const tenantResolution = resolveTenantAccess(c, typeof body.tenant_id === 'string' ? body.tenant_id : undefined)
  if ('response' in tenantResolution) return tenantResolution.response
  const tenantId = tenantResolution.tenantId

  const proposal = await c.env.DB.prepare(
    'SELECT * FROM agent_proposals WHERE proposal_id = ? AND status = ?',
  ).bind(proposalId, 'pending').first()

  if (!proposal) return c.json({ error: 'Proposal not found or already processed' }, 404)

  // Cross-tenant authorization: caller's tenant must match proposal's tenant
  if (proposal.tenant_id !== tenantId) {
    return c.json({ error: 'Tenant mismatch: not authorized to approve this proposal' }, 403)
  }
  if (new Date(proposal.expires_at as string) < new Date()) {
    await c.env.DB.prepare('UPDATE agent_proposals SET status = ? WHERE proposal_id = ? AND status = ?').bind('expired', proposalId, 'pending').run()
    return c.json({ error: 'Proposal has expired' }, 410)
  }

  const actionType = proposal.action_type as string
  const actionDefinition = getProposalActionDefinition(actionType)
  if (!actionDefinition) {
    return c.json({ error: `Unsupported proposal action_type: ${actionType}` }, 422)
  }

  let rawPayload: unknown
  try {
    rawPayload = JSON.parse(proposal.action_payload as string)
  } catch {
    return c.json({ error: 'Proposal has malformed action_payload' }, 422)
  }

  const parsedPayload = actionDefinition.schema.safeParse(rawPayload)
  if (!parsedPayload.success) {
    return c.json({
      error: 'Proposal payload failed validation',
      details: parsedPayload.error.flatten(),
    }, 422)
  }

  const reviewedAt = new Date().toISOString()
  const updateResult = await c.env.DB.prepare(
    'UPDATE agent_proposals SET status = ?, reviewed_by = ?, reviewed_at = ?, review_note = ? WHERE proposal_id = ? AND status = ?',
  ).bind('approved', reviewedBy ?? null, reviewedAt, note ?? null, proposalId, 'pending').run()

  if (!updateResult.meta.changes) {
    return c.json({ error: 'Proposal was already processed by another request' }, 409)
  }

  try {
    const result = await actionDefinition.execute({ env: c.env, tenantId }, parsedPayload.data)
    await c.env.DB.prepare(
      'UPDATE agent_proposals SET status = ? WHERE proposal_id = ?',
    ).bind('executed', proposalId).run()

    return c.json({ status: 'executed', proposal_id: proposalId, result })
  } catch (err) {
    const errorMessage = err instanceof Error ? err.message : String(err)
    const httpStatus = (err instanceof ProposalActionError ? err.httpStatus : 502) as 403 | 404 | 502
    await c.env.DB.prepare(
      'UPDATE agent_proposals SET status = ?, review_note = ?, reviewed_by = ?, reviewed_at = ? WHERE proposal_id = ?',
    ).bind('execution_failed', appendExecutionError(note, errorMessage), reviewedBy ?? null, reviewedAt, proposalId).run()

    logger.error({ err, proposalId }, 'Failed to execute approved proposal')
    return c.json({ status: 'execution_failed', proposal_id: proposalId, error: errorMessage }, httpStatus)
  }
})

httpRoutes.post('/proposals/:proposalId/reject', async (c) => {
  const { proposalId } = c.req.param()
  const body = await c.req.json<Record<string, unknown>>()
  const reviewedBy = typeof body.reviewed_by === 'string' ? body.reviewed_by : undefined
  const note = typeof body.note === 'string' ? body.note : undefined
  const tenantResolution = resolveTenantAccess(c, typeof body.tenant_id === 'string' ? body.tenant_id : undefined)
  if ('response' in tenantResolution) return tenantResolution.response
  const tenantId = tenantResolution.tenantId

  // Tenant isolation: only allow rejection by the owning tenant
  await c.env.DB.prepare(
    'UPDATE agent_proposals SET status = ?, reviewed_by = ?, reviewed_at = ?, review_note = ? WHERE proposal_id = ? AND tenant_id = ? AND status = ?',
  ).bind('rejected', reviewedBy ?? null, new Date().toISOString(), note ?? null, proposalId, tenantId, 'pending').run()

  return c.json({ status: 'rejected', proposal_id: proposalId })
})

// --- Agent activity ---

httpRoutes.get('/sessions', async (c) => {
  const tenantResolution = resolveTenantAccess(c, c.req.query('tenant_id') ?? undefined)
  if ('response' in tenantResolution) return tenantResolution.response
  const tenantId = tenantResolution.tenantId
  const parsedLimit = parseInt(c.req.query('limit') ?? '50', 10)
  const limit = Math.min(Number.isNaN(parsedLimit) ? 50 : parsedLimit, 1000)

  const { results } = await c.env.DB.prepare(
    'SELECT * FROM agent_sessions WHERE tenant_id = ? ORDER BY started_at DESC LIMIT ?',
  ).bind(tenantId, limit).all()

  return c.json(results)
})

// --- Tenant config ---

httpRoutes.get('/config/:tenantId', async (c) => {
  const tenantResolution = resolveTenantAccess(c, c.req.param('tenantId'), 'tenantId')
  if ('response' in tenantResolution) return tenantResolution.response
  const config = await getTenantAgentConfig(c.env.DB, c.env, tenantResolution.tenantId)
  return c.json(config)
})

// --- Metrics ---

httpRoutes.get('/metrics/:tenantId', async (c) => {
  const tenantResolution = resolveTenantAccess(c, c.req.param('tenantId'), 'tenantId')
  if ('response' in tenantResolution) return tenantResolution.response
  const tenantId = tenantResolution.tenantId

  const since = c.req.query('since')
  const until = c.req.query('until')

  if (since && isNaN(Date.parse(since))) return c.json({ error: 'Invalid since date format' }, 400)
  if (until && isNaN(Date.parse(until))) return c.json({ error: 'Invalid until date format' }, 400)

  const metrics = await computeTenantMetrics(c.env.DB, tenantId, since, until)
  return c.json(metrics)
})

// --- Cloud connectors ---

httpRoutes.post('/cloud-connectors', async (c) => {
  const body = await c.req.json<Record<string, unknown>>()
  const tenantResolution = resolveTenantAccess(c, typeof body.tenant_id === 'string' ? body.tenant_id : undefined)
  if ('response' in tenantResolution) return tenantResolution.response
  if (!body.provider || !body.account_ref) {
    return c.json({ error: 'provider and account_ref required' }, 400)
  }

  const connectorId = await insertCloudConnector(c.env.DB, {
    tenant_id: tenantResolution.tenantId,
    provider: body.provider as string,
    account_ref: body.account_ref as string,
    enabled_regions: Array.isArray(body.enabled_regions) ? body.enabled_regions as string[] : undefined,
    allowed_decoy_types: Array.isArray(body.allowed_decoy_types) ? body.allowed_decoy_types as string[] : undefined,
  })

  return c.json({ status: 'created', connector_id: connectorId }, 201)
})

httpRoutes.get('/cloud-connectors', async (c) => {
  const tenantResolution = resolveTenantAccess(c, c.req.query('tenant_id') ?? undefined)
  if ('response' in tenantResolution) return tenantResolution.response
  const tenantId = tenantResolution.tenantId

  const { results } = await queryCloudConnectors(c.env.DB, tenantId)
  return c.json(results)
})

httpRoutes.put('/config/:tenantId', async (c) => {
  const tenantResolution = resolveTenantAccess(c, c.req.param('tenantId'), 'tenantId')
  if ('response' in tenantResolution) return tenantResolution.response
  const tenantId = tenantResolution.tenantId
  const body = await c.req.json<Record<string, unknown>>()

  if (typeof body.tenant_id === 'string' && body.tenant_id !== tenantId) {
    return c.json({ error: 'Tenant mismatch: tenant_id must match authenticated tenant' }, 403)
  }

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
