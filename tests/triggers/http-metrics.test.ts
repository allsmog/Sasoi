import { describe, it, expect, vi, beforeEach } from 'vitest'
import { Hono } from 'hono'

vi.mock('../../src/clients/db.js', () => ({
  getTenantAgentConfig: vi.fn().mockResolvedValue({
    tenant_id: 'tenant-1',
    autonomy_level: 0,
    enabled_agents: ['enricher'],
    rate_limits: { enricher: 100 },
    responder_opt_in: false,
    inventory_enabled: false,
    inventory_namespaces: [],
  }),
  computeTenantMetrics: vi.fn().mockResolvedValue({
    mean_time_to_detect_minutes: 0,
    total_deployments: 0,
    healthy_deployments: 0,
    service_type_coverage: {},
    coverage_gaps: [],
    total_events: 0,
    unique_attacker_ips: 0,
    events_by_severity: { low: 0, medium: 0, high: 0, critical: 0 },
    active_campaigns: 0,
    total_investigations: 0,
    attacker_dwell_time_minutes: 0,
    active_honeytokens: 0,
    honeytoken_accesses: 0,
  }),
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

describe('GET /metrics/:tenantId', () => {
  let app: Hono

  beforeEach(async () => {
    vi.clearAllMocks()
    const { httpRoutes } = await import('../../src/triggers/http.js')
    app = new Hono()
    app.route('/', httpRoutes)
  })

  it('returns structured metrics for tenant', async () => {
    const res = await app.request('/metrics/tenant-1', { method: 'GET' }, mockEnv)
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body).toHaveProperty('total_deployments')
    expect(body).toHaveProperty('total_events')
    expect(body).toHaveProperty('events_by_severity')
    expect(body).toHaveProperty('active_honeytokens')
  })

  it('returns zeroed metrics for empty tenant', async () => {
    const res = await app.request('/metrics/empty-tenant', { method: 'GET' }, mockEnv)
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.total_deployments).toBe(0)
    expect(body.total_events).toBe(0)
    expect(body.active_campaigns).toBe(0)
    expect(body.active_honeytokens).toBe(0)
  })

  it('passes time range parameters', async () => {
    const { computeTenantMetrics } = await import('../../src/clients/db.js')

    await app.request(
      '/metrics/tenant-1?since=2026-03-01&until=2026-03-20',
      { method: 'GET' },
      mockEnv,
    )

    expect(computeTenantMetrics).toHaveBeenCalledWith(
      mockEnv.DB,
      'tenant-1',
      '2026-03-01',
      '2026-03-20',
    )
  })
})

describe('GET /metrics without tenantId', () => {
  it('returns 404 for missing tenant param', async () => {
    const { httpRoutes } = await import('../../src/triggers/http.js')
    const app = new Hono()
    app.route('/', httpRoutes)

    const res = await app.request('/metrics/', { method: 'GET' }, mockEnv)
    // Route won't match without param, so 404
    expect(res.status).toBe(404)
  })
})

describe('POST /proposals/:proposalId/approve', () => {
  let app: Hono

  beforeEach(async () => {
    vi.clearAllMocks()
    const { httpRoutes } = await import('../../src/triggers/http.js')
    app = new Hono()
    app.route('/', httpRoutes)
  })

  it('returns 404 when proposal not found', async () => {
    const mockDB = {
      prepare: vi.fn().mockReturnValue({
        bind: vi.fn().mockReturnValue({
          first: vi.fn().mockResolvedValue(null),
          run: vi.fn().mockResolvedValue(undefined),
        }),
      }),
    }

    const res = await app.request(
      '/proposals/nonexistent/approve',
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ reviewed_by: 'admin', tenant_id: 'tenant-1' }),
      },
      { ...mockEnv, DB: mockDB as unknown as D1Database },
    )

    expect(res.status).toBe(404)
    const body = await res.json()
    expect(body.error).toContain('not found')
  })

  it('returns 410 for expired proposal', async () => {
    const pastDate = new Date(Date.now() - 86400_000).toISOString()
    const mockRun = vi.fn().mockResolvedValue(undefined)
    const mockFirst = vi.fn().mockResolvedValue({
      proposal_id: 'prop-expired',
      tenant_id: 'tenant-1',
      status: 'pending',
      expires_at: pastDate,
      action_type: 'deploy_honeypot',
      action_payload: '{}',
    })

    const mockDB = {
      prepare: vi.fn().mockReturnValue({
        bind: vi.fn().mockReturnValue({
          first: mockFirst,
          run: mockRun,
        }),
      }),
    }

    const res = await app.request(
      '/proposals/prop-expired/approve',
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ reviewed_by: 'admin', tenant_id: 'tenant-1' }),
      },
      { ...mockEnv, DB: mockDB as unknown as D1Database },
    )

    expect(res.status).toBe(410)
    const body = await res.json()
    expect(body.error).toContain('expired')
  })

  it('approves valid pending proposal and executes deployment', async () => {
    const { createDeployment } = await import('../../src/clients/orchestrator.js')
    const futureDate = new Date(Date.now() + 86400_000).toISOString()
    const mockRun = vi.fn().mockResolvedValue({ meta: { changes: 1 } })
    const mockFirst = vi.fn().mockResolvedValue({
      proposal_id: 'prop-1',
      tenant_id: 'tenant-1',
      status: 'pending',
      expires_at: futureDate,
      action_type: 'deploy_honeypot',
      action_payload: JSON.stringify({ blueprint_id: 'bp-1', config: {} }),
    })

    const mockDB = {
      prepare: vi.fn().mockReturnValue({
        bind: vi.fn().mockReturnValue({
          first: mockFirst,
          run: mockRun,
        }),
      }),
    }

    const res = await app.request(
      '/proposals/prop-1/approve',
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ reviewed_by: 'admin', note: 'Looks good', tenant_id: 'tenant-1' }),
      },
      { ...mockEnv, DB: mockDB as unknown as D1Database },
    )

    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.status).toBe('approved')
    expect(body.proposal_id).toBe('prop-1')
    expect(createDeployment).toHaveBeenCalled()
  })
})

describe('POST /proposals/:proposalId/reject', () => {
  let app: Hono

  beforeEach(async () => {
    vi.clearAllMocks()
    const { httpRoutes } = await import('../../src/triggers/http.js')
    app = new Hono()
    app.route('/', httpRoutes)
  })

  it('rejects a pending proposal', async () => {
    const mockRun = vi.fn().mockResolvedValue(undefined)
    const mockDB = {
      prepare: vi.fn().mockReturnValue({
        bind: vi.fn().mockReturnValue({
          run: mockRun,
        }),
      }),
    }

    const res = await app.request(
      '/proposals/prop-2/reject',
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ reviewed_by: 'admin', note: 'Not needed', tenant_id: 'tenant-1' }),
      },
      { ...mockEnv, DB: mockDB as unknown as D1Database },
    )

    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.status).toBe('rejected')
    expect(body.proposal_id).toBe('prop-2')
    expect(mockRun).toHaveBeenCalled()
  })
})

describe('POST /cloud-connectors', () => {
  let app: Hono

  beforeEach(async () => {
    vi.clearAllMocks()
    const { httpRoutes } = await import('../../src/triggers/http.js')
    app = new Hono()
    app.route('/', httpRoutes)
  })

  it('creates a cloud connector with valid params', async () => {
    const { insertCloudConnector } = await import('../../src/clients/db.js')

    const res = await app.request(
      '/cloud-connectors',
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          tenant_id: 'tenant-1',
          provider: 'aws',
          account_ref: '123456789012',
          enabled_regions: ['us-east-1'],
          allowed_decoy_types: ['s3_bucket'],
        }),
      },
      mockEnv,
    )

    expect(res.status).toBe(201)
    const body = await res.json()
    expect(body.status).toBe('created')
    expect(body.connector_id).toBe('conn-1')
    expect(insertCloudConnector).toHaveBeenCalledWith(
      mockEnv.DB,
      expect.objectContaining({
        tenant_id: 'tenant-1',
        provider: 'aws',
        account_ref: '123456789012',
      }),
    )
  })

  it('rejects when required fields are missing', async () => {
    const res = await app.request(
      '/cloud-connectors',
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ tenant_id: 'tenant-1' }),
      },
      mockEnv,
    )

    expect(res.status).toBe(400)
    const body = await res.json()
    expect(body.error).toContain('required')
  })
})
