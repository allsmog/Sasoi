import { describe, it, expect, vi, beforeEach } from 'vitest'
import { Hono } from 'hono'

vi.mock('../../src/clients/db.js', () => ({
  getTenantAgentConfig: vi.fn().mockResolvedValue({
    tenant_id: 'tenant-1',
    autonomy_level: 0,
    enabled_agents: ['enricher', 'investigator'],
    rate_limits: { enricher: 100, investigator: 20 },
    responder_opt_in: false,
    inventory_enabled: false,
    inventory_namespaces: [],
  }),
}))
vi.mock('../../src/agents/enricher.js', () => ({ runEnricher: vi.fn().mockResolvedValue(undefined) }))
vi.mock('../../src/agents/investigator.js', () => ({ runInvestigator: vi.fn().mockResolvedValue(undefined) }))
vi.mock('../../src/agents/responder.js', () => ({ runResponder: vi.fn().mockResolvedValue(undefined) }))
vi.mock('../../src/safety/guard.js', () => ({ checkRateLimit: vi.fn().mockReturnValue(true) }))
vi.mock('../../src/config.js', () => ({
  logger: { info: vi.fn(), error: vi.fn(), warn: vi.fn(), debug: vi.fn() },
}))
vi.mock('../../src/middleware/webhook-auth.js', () => ({
  webhookAuth: vi.fn(async (c: { set: (k: string, v: string) => void; req: { text: () => Promise<string> } }, next: () => Promise<void>) => {
    c.set('rawBody', await c.req.text())
    await next()
  }),
}))

const mockEnv = {
  DB: {} as D1Database,
  ANTHROPIC_API_KEY: 'test-key',
  INTERNAL_API_SECRET: 'test',
  HOP_ORCHESTRATOR_URL: 'http://localhost:3001',
  HOP_INGESTOR_URL: 'http://localhost:3002',
  HOP_BLUEPRINT_URL: 'http://localhost:3003',
  HOP_ENRICHMENT_URL: 'http://localhost:3004',
  HOP_ML_URL: 'http://localhost:8000',
  DEFAULT_AUTONOMY_LEVEL: '0',
  PROPOSAL_EXPIRY_HOURS: '24',
  API_KEY: 'test-api-key',
}

function requestWithCtx(app: Hono, path: string, init: RequestInit, env: Record<string, unknown>) {
  const req = new Request(`http://localhost${path}`, init)
  return app.fetch(req, env, { waitUntil: vi.fn(), passThroughOnException: vi.fn() })
}

describe('POST /webhooks/cloud-decoy-accessed', () => {
  let app: Hono

  beforeEach(async () => {
    vi.clearAllMocks()
    const { webhookRoutes } = await import('../../src/triggers/webhook.js')
    app = new Hono()
    app.route('/', webhookRoutes)
  })

  it('returns 400 for malformed JSON body', async () => {
    const res = await requestWithCtx(
      app,
      '/webhooks/cloud-decoy-accessed',
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: '{{{{bad json',
      },
      mockEnv,
    )
    expect(res.status).toBe(400)
  })

  it('returns 400 when decoy_id is missing', async () => {
    const res = await requestWithCtx(
      app,
      '/webhooks/cloud-decoy-accessed',
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ tenant_id: 'tenant-1', provider: 'aws' }),
      },
      mockEnv,
    )
    expect(res.status).toBe(400)
    const body = await res.json()
    expect(body.error).toContain('decoy_id')
  })

  it('returns 400 when tenant_id is missing', async () => {
    const res = await requestWithCtx(
      app,
      '/webhooks/cloud-decoy-accessed',
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ decoy_id: 'decoy-1', provider: 'aws' }),
      },
      mockEnv,
    )
    expect(res.status).toBe(400)
  })

  it('triggers enricher and investigator on valid access', async () => {
    const { runEnricher } = await import('../../src/agents/enricher.js')
    const { runInvestigator } = await import('../../src/agents/investigator.js')

    const res = await requestWithCtx(
      app,
      '/webhooks/cloud-decoy-accessed',
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          decoy_id: 'decoy-1',
          tenant_id: 'tenant-1',
          provider: 'aws',
          source_ip: '10.0.0.1',
          access_type: 'GetObject',
        }),
      },
      mockEnv,
    )

    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.status).toBe('accepted')
    expect(body.decoy_id).toBe('decoy-1')
    expect(runEnricher).toHaveBeenCalled()
    expect(runInvestigator).toHaveBeenCalled()
  })

  it('skips agents when not in enabled_agents', async () => {
    const { getTenantAgentConfig } = await import('../../src/clients/db.js')
    vi.mocked(getTenantAgentConfig).mockResolvedValueOnce({
      tenant_id: 'tenant-1',
      autonomy_level: 0,
      enabled_agents: [],
      rate_limits: {},
      responder_opt_in: false,
      inventory_enabled: false,
      inventory_namespaces: [],
    })

    const { runEnricher } = await import('../../src/agents/enricher.js')
    const { runInvestigator } = await import('../../src/agents/investigator.js')

    const res = await requestWithCtx(
      app,
      '/webhooks/cloud-decoy-accessed',
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          decoy_id: 'decoy-1',
          tenant_id: 'tenant-1',
          provider: 'aws',
        }),
      },
      mockEnv,
    )

    expect(res.status).toBe(200)
    expect(runEnricher).not.toHaveBeenCalled()
    expect(runInvestigator).not.toHaveBeenCalled()
  })
})
