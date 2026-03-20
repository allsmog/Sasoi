import { describe, it, expect, vi, beforeEach } from 'vitest'
import { Hono } from 'hono'

vi.mock('../../src/clients/db.js', () => ({
  getTenantAgentConfig: vi.fn().mockResolvedValue({
    tenant_id: 'tenant-1',
    autonomy_level: 1,
    enabled_agents: ['enricher', 'investigator'],
    rate_limits: { enricher: 100, investigator: 20, strategist: 5, responder: 10 },
    responder_opt_in: false,
    inventory_enabled: false,
    inventory_namespaces: [],
  }),
  computeTenantMetrics: vi.fn().mockResolvedValue({}),
  insertCloudConnector: vi.fn().mockResolvedValue('conn-1'),
  queryCloudConnectors: vi.fn().mockResolvedValue({ results: [] }),
}))
vi.mock('../../src/agents/enricher.js', () => ({ runEnricher: vi.fn() }))
vi.mock('../../src/agents/investigator.js', () => ({ runInvestigator: vi.fn() }))
vi.mock('../../src/agents/strategist.js', () => ({ runStrategist: vi.fn() }))
vi.mock('../../src/agents/responder.js', () => ({ runResponder: vi.fn() }))
vi.mock('../../src/safety/guard.js', () => ({ checkRateLimit: vi.fn().mockReturnValue(true) }))
vi.mock('../../src/clients/orchestrator.js', () => ({ createDeployment: vi.fn() }))
vi.mock('../../src/config.js', () => ({
  logger: { info: vi.fn(), error: vi.fn(), warn: vi.fn(), debug: vi.fn() },
}))
vi.mock('../../src/middleware/api-auth.js', () => ({
  apiAuth: vi.fn(async (_c: unknown, next: () => Promise<void>) => await next()),
}))

const mockRun = vi.fn().mockResolvedValue(undefined)

const mockEnv = {
  DB: {
    prepare: vi.fn().mockReturnValue({
      bind: vi.fn().mockReturnValue({
        run: mockRun,
      }),
    }),
  } as unknown as D1Database,
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

describe('PUT /config/:tenantId', () => {
  let app: Hono

  beforeEach(async () => {
    vi.clearAllMocks()
    const { httpRoutes } = await import('../../src/triggers/http.js')
    app = new Hono()
    app.route('/', httpRoutes)
  })

  it('accepts valid config update', async () => {
    const res = await app.request(
      '/config/tenant-1',
      {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ autonomy_level: 2, enabled_agents: ['enricher', 'investigator'] }),
      },
      mockEnv,
    )

    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.status).toBe('updated')
  })

  it('rejects invalid autonomy_level (too high)', async () => {
    const res = await app.request(
      '/config/tenant-1',
      {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ autonomy_level: 5 }),
      },
      mockEnv,
    )

    expect(res.status).toBe(400)
    const body = await res.json()
    expect(body.error).toContain('autonomy_level')
  })

  it('rejects invalid autonomy_level (negative)', async () => {
    const res = await app.request(
      '/config/tenant-1',
      {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ autonomy_level: -1 }),
      },
      mockEnv,
    )

    expect(res.status).toBe(400)
  })

  it('rejects invalid autonomy_level (non-integer)', async () => {
    const res = await app.request(
      '/config/tenant-1',
      {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ autonomy_level: 1.5 }),
      },
      mockEnv,
    )

    expect(res.status).toBe(400)
  })

  it('rejects invalid enabled_agents values', async () => {
    const res = await app.request(
      '/config/tenant-1',
      {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled_agents: ['enricher', 'not_a_real_agent'] }),
      },
      mockEnv,
    )

    expect(res.status).toBe(400)
    const body = await res.json()
    expect(body.error).toContain('enabled_agents')
  })

  it('accepts partial body (only autonomy_level)', async () => {
    const res = await app.request(
      '/config/tenant-1',
      {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ autonomy_level: 0 }),
      },
      mockEnv,
    )

    expect(res.status).toBe(200)
  })
})

describe('POST /proposals/:proposalId/approve — cross-tenant auth', () => {
  let app: Hono

  beforeEach(async () => {
    vi.clearAllMocks()
    const { httpRoutes } = await import('../../src/triggers/http.js')
    app = new Hono()
    app.route('/', httpRoutes)
  })

  it('returns 400 when tenant_id missing from body', async () => {
    const res = await app.request(
      '/proposals/prop-1/approve',
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ reviewed_by: 'admin' }),
      },
      mockEnv,
    )

    expect(res.status).toBe(400)
    const body = await res.json()
    expect(body.error).toContain('tenant_id')
  })

  it('returns 403 when tenant_id mismatches proposal', async () => {
    const futureDate = new Date(Date.now() + 86400_000).toISOString()
    const mockFirst = vi.fn().mockResolvedValue({
      proposal_id: 'prop-1',
      tenant_id: 'tenant-owner',
      status: 'pending',
      expires_at: futureDate,
      action_type: 'deploy_honeypot',
      action_payload: '{}',
    })
    const mockDB = {
      prepare: vi.fn().mockReturnValue({
        bind: vi.fn().mockReturnValue({
          first: mockFirst,
          run: vi.fn(),
        }),
      }),
    }

    const res = await app.request(
      '/proposals/prop-1/approve',
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ reviewed_by: 'admin', tenant_id: 'tenant-attacker' }),
      },
      { ...mockEnv, DB: mockDB as unknown as D1Database },
    )

    expect(res.status).toBe(403)
    const body = await res.json()
    expect(body.error).toContain('Tenant mismatch')
  })
})

describe('GET /sessions — NaN limit fallback', () => {
  let app: Hono

  beforeEach(async () => {
    vi.clearAllMocks()
    const { httpRoutes } = await import('../../src/triggers/http.js')
    app = new Hono()
    app.route('/', httpRoutes)
  })

  it('uses default 50 when limit=abc', async () => {
    const mockAll = vi.fn().mockResolvedValue({ results: [] })
    const mockBind = vi.fn().mockReturnValue({ all: mockAll })
    const mockDB = {
      prepare: vi.fn().mockReturnValue({ bind: mockBind }),
    }

    const res = await app.request(
      '/sessions?tenant_id=t1&limit=abc',
      { method: 'GET' },
      { ...mockEnv, DB: mockDB as unknown as D1Database },
    )

    expect(res.status).toBe(200)
    // The second bind argument should be 50 (the default, not NaN)
    expect(mockBind).toHaveBeenCalledWith('t1', 50)
  })
})

describe('POST /cloud-connectors — 201 status', () => {
  let app: Hono

  beforeEach(async () => {
    vi.clearAllMocks()
    const { httpRoutes } = await import('../../src/triggers/http.js')
    app = new Hono()
    app.route('/', httpRoutes)
  })

  it('returns 201 for successful creation', async () => {
    const res = await app.request(
      '/cloud-connectors',
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          tenant_id: 'tenant-1',
          provider: 'aws',
          account_ref: '123456789012',
        }),
      },
      mockEnv,
    )

    expect(res.status).toBe(201)
  })
})
