import { describe, it, expect, vi, beforeEach } from 'vitest'
import { Hono } from 'hono'

vi.mock('../../src/clients/db.js', () => ({
  getTenantAgentConfig: vi.fn(),
  getHoneytokenById: vi.fn(),
  recordHoneytokenAccess: vi.fn().mockResolvedValue('access-1'),
  upsertClusterInventory: vi.fn(),
  createAgentSession: vi.fn().mockResolvedValue('session-1'),
  completeAgentSession: vi.fn(),
}))

vi.mock('../../src/agents/enricher.js', () => ({ runEnricher: vi.fn().mockResolvedValue(undefined) }))
vi.mock('../../src/agents/investigator.js', () => ({ runInvestigator: vi.fn().mockResolvedValue(undefined) }))
vi.mock('../../src/agents/responder.js', () => ({ runResponder: vi.fn() }))
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
  ANTHROPIC_API_KEY: 'test',
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

// Helper to make a request with executionCtx (needed for waitUntil)
function requestWithCtx(app: Hono, path: string, init: RequestInit, env: Record<string, unknown>) {
  const req = new Request(`http://localhost${path}`, init)
  return app.fetch(req, env, { waitUntil: vi.fn(), passThroughOnException: vi.fn() })
}

describe('POST /webhooks/honeytoken-accessed', () => {
  let app: Hono

  beforeEach(async () => {
    vi.clearAllMocks()
    const { webhookRoutes } = await import('../../src/triggers/webhook.js')
    app = new Hono()
    app.route('/', webhookRoutes)
  })

  it('rejects missing honeytoken_id', async () => {
    const res = await app.request(
      '/webhooks/honeytoken-accessed',
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ tenant_id: 'tenant-1' }),
      },
      mockEnv,
    )
    expect(res.status).toBe(400)
  })

  it('rejects when honeytoken not found', async () => {
    const { getHoneytokenById } = await import('../../src/clients/db.js')
    vi.mocked(getHoneytokenById).mockResolvedValueOnce(null)

    const res = await app.request(
      '/webhooks/honeytoken-accessed',
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ honeytoken_id: 'ht-999', tenant_id: 'tenant-1' }),
      },
      mockEnv,
    )
    expect(res.status).toBe(404)
  })

  it('rejects tenant mismatch', async () => {
    const { getHoneytokenById } = await import('../../src/clients/db.js')
    vi.mocked(getHoneytokenById).mockResolvedValueOnce({
      honeytoken_id: 'ht-1',
      tenant_id: 'tenant-other',
      token_type: 'api_key',
    })

    const res = await app.request(
      '/webhooks/honeytoken-accessed',
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ honeytoken_id: 'ht-1', tenant_id: 'tenant-1' }),
      },
      mockEnv,
    )
    expect(res.status).toBe(403)
  })

  it('accepts valid honeytoken access and records it', async () => {
    const { getHoneytokenById, recordHoneytokenAccess, getTenantAgentConfig } = await import('../../src/clients/db.js')
    vi.mocked(getHoneytokenById).mockResolvedValueOnce({
      honeytoken_id: 'ht-1',
      tenant_id: 'tenant-1',
      token_type: 'api_key',
    })
    vi.mocked(getTenantAgentConfig).mockResolvedValueOnce({
      tenant_id: 'tenant-1',
      autonomy_level: 0,
      enabled_agents: ['enricher', 'investigator'],
      rate_limits: { enricher: 100, investigator: 20 },
      responder_opt_in: false,
      inventory_enabled: false,
      inventory_namespaces: [],
    })

    const res = await requestWithCtx(
      app,
      '/webhooks/honeytoken-accessed',
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          honeytoken_id: 'ht-1',
          tenant_id: 'tenant-1',
          source_ip: '1.2.3.4',
          source_service: 'api-gateway',
        }),
      },
      mockEnv,
    )

    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.status).toBe('accepted')
    expect(body.access_id).toBe('access-1')

    expect(recordHoneytokenAccess).toHaveBeenCalledWith(mockEnv.DB, expect.objectContaining({
      honeytoken_id: 'ht-1',
      tenant_id: 'tenant-1',
      source_ip: '1.2.3.4',
    }))
  })

  it('triggers enricher and investigator on access', async () => {
    const { getHoneytokenById, getTenantAgentConfig } = await import('../../src/clients/db.js')
    const { runEnricher } = await import('../../src/agents/enricher.js')
    const { runInvestigator } = await import('../../src/agents/investigator.js')

    vi.mocked(getHoneytokenById).mockResolvedValueOnce({
      honeytoken_id: 'ht-1',
      tenant_id: 'tenant-1',
      token_type: 'api_key',
    })
    vi.mocked(getTenantAgentConfig).mockResolvedValueOnce({
      tenant_id: 'tenant-1',
      autonomy_level: 0,
      enabled_agents: ['enricher', 'investigator'],
      rate_limits: { enricher: 100, investigator: 20 },
      responder_opt_in: false,
      inventory_enabled: false,
      inventory_namespaces: [],
    })

    await requestWithCtx(
      app,
      '/webhooks/honeytoken-accessed',
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          honeytoken_id: 'ht-1',
          tenant_id: 'tenant-1',
          source_ip: '1.2.3.4',
        }),
      },
      mockEnv,
    )

    expect(runEnricher).toHaveBeenCalledWith(
      mockEnv,
      expect.objectContaining({
        tenantId: 'tenant-1',
        eventData: expect.objectContaining({
          signal: 'honeytoken_accessed',
          severity: 'high',
        }),
      }),
    )
    expect(runInvestigator).toHaveBeenCalledWith(
      mockEnv,
      expect.objectContaining({
        tenantId: 'tenant-1',
        trigger: 'high_severity_event',
      }),
    )
  })
})
