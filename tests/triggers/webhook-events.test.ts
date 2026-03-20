import { describe, it, expect, vi, beforeEach } from 'vitest'
import { Hono } from 'hono'

vi.mock('../../src/clients/db.js', () => ({
  getTenantAgentConfig: vi.fn().mockResolvedValue({
    tenant_id: 'tenant-1',
    autonomy_level: 0,
    enabled_agents: ['enricher', 'investigator'],
    rate_limits: { enricher: 100, investigator: 20, responder: 10 },
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

describe('POST /webhooks/event-ingested', () => {
  let app: Hono

  beforeEach(async () => {
    vi.clearAllMocks()
    const { webhookRoutes } = await import('../../src/triggers/webhook.js')
    app = new Hono()
    app.route('/', webhookRoutes)
  })

  it('triggers enricher for normal events', async () => {
    const { runEnricher } = await import('../../src/agents/enricher.js')

    const res = await requestWithCtx(
      app,
      '/webhooks/event-ingested',
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          event_id: 'evt-1',
          tenant_id: 'tenant-1',
          src_ip: '10.0.0.1',
          signal: 'login_attempt',
          severity: 'low',
        }),
      },
      mockEnv,
    )

    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.status).toBe('accepted')
    expect(runEnricher).toHaveBeenCalledWith(
      mockEnv,
      expect.objectContaining({
        tenantId: 'tenant-1',
        eventId: 'evt-1',
      }),
    )
  })

  it('triggers investigator for high-severity events', async () => {
    const { runInvestigator } = await import('../../src/agents/investigator.js')

    await requestWithCtx(
      app,
      '/webhooks/event-ingested',
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          event_id: 'evt-high-1',
          tenant_id: 'tenant-1',
          src_ip: '10.0.0.5',
          signal: 'brute_force',
          severity: 'high',
        }),
      },
      mockEnv,
    )

    expect(runInvestigator).toHaveBeenCalledWith(
      mockEnv,
      expect.objectContaining({
        tenantId: 'tenant-1',
        trigger: 'high_severity_event',
        context: expect.objectContaining({ eventId: 'evt-high-1', srcIp: '10.0.0.5' }),
      }),
    )
  })

  it('skips when enricher is disabled', async () => {
    const { getTenantAgentConfig } = await import('../../src/clients/db.js')
    vi.mocked(getTenantAgentConfig).mockResolvedValueOnce({
      tenant_id: 'tenant-1',
      autonomy_level: 0,
      enabled_agents: ['investigator'],
      rate_limits: { enricher: 100, investigator: 20 },
      responder_opt_in: false,
      inventory_enabled: false,
      inventory_namespaces: [],
    })

    const { runEnricher } = await import('../../src/agents/enricher.js')

    const res = await requestWithCtx(
      app,
      '/webhooks/event-ingested',
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          event_id: 'evt-skip-1',
          tenant_id: 'tenant-1',
          src_ip: '10.0.0.1',
          signal: 'scan',
          severity: 'low',
        }),
      },
      mockEnv,
    )

    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.status).toBe('skipped')
    expect(runEnricher).not.toHaveBeenCalled()
  })

  it('returns 400 for malformed JSON body', async () => {
    const res = await requestWithCtx(
      app,
      '/webhooks/event-ingested',
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: '{not valid json!!!',
      },
      mockEnv,
    )

    expect(res.status).toBe(400)
    const body = await res.json()
    expect(body.error).toContain('Invalid JSON')
  })

  it('returns 429 when rate limited', async () => {
    const { checkRateLimit } = await import('../../src/safety/guard.js')
    vi.mocked(checkRateLimit).mockReturnValueOnce(false)

    const res = await requestWithCtx(
      app,
      '/webhooks/event-ingested',
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          event_id: 'evt-rate-1',
          tenant_id: 'tenant-1',
          src_ip: '10.0.0.1',
          signal: 'scan',
          severity: 'low',
        }),
      },
      mockEnv,
    )

    expect(res.status).toBe(429)
  })
})
