import { describe, it, expect, vi, beforeEach } from 'vitest'
import { Hono } from 'hono'

vi.mock('../../src/clients/db.js', () => ({
  getTenantAgentConfig: vi.fn(),
  upsertClusterInventory: vi.fn().mockResolvedValue('inv-1'),
  createAgentSession: vi.fn().mockResolvedValue('session-1'),
  completeAgentSession: vi.fn().mockResolvedValue(undefined),
}))

vi.mock('../../src/agents/enricher.js', () => ({ runEnricher: vi.fn() }))
vi.mock('../../src/agents/investigator.js', () => ({ runInvestigator: vi.fn() }))
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

describe('POST /webhooks/cluster-inventory', () => {
  let app: Hono

  beforeEach(async () => {
    vi.clearAllMocks()
    const { webhookRoutes } = await import('../../src/triggers/webhook.js')
    app = new Hono()
    app.route('/', webhookRoutes)
  })

  it('rejects when inventory is not enabled', async () => {
    const { getTenantAgentConfig } = await import('../../src/clients/db.js')
    vi.mocked(getTenantAgentConfig).mockResolvedValueOnce({
      tenant_id: 'tenant-1',
      autonomy_level: 0,
      enabled_agents: ['enricher'],
      rate_limits: { enricher: 100 },
      responder_opt_in: false,
      inventory_enabled: false,
      inventory_namespaces: [],
    })

    const res = await app.request(
      '/webhooks/cluster-inventory',
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          cluster_id: 'cluster-1',
          tenant_id: 'tenant-1',
          services: [{ name: 'redis', namespace: 'staging', image: 'redis', tag: '7.2.4', ports: [6379], replicas: 1, size: 'small' }],
          collected_at: '2026-03-20T00:00:00Z',
        }),
      },
      mockEnv,
    )

    expect(res.status).toBe(403)
    const body = await res.json()
    expect(body.error).toContain('not enabled')
  })

  it('rejects namespaces not in allowlist', async () => {
    const { getTenantAgentConfig } = await import('../../src/clients/db.js')
    vi.mocked(getTenantAgentConfig).mockResolvedValueOnce({
      tenant_id: 'tenant-1',
      autonomy_level: 0,
      enabled_agents: ['enricher'],
      rate_limits: { enricher: 100 },
      responder_opt_in: false,
      inventory_enabled: true,
      inventory_namespaces: ['staging'],
    })

    const res = await app.request(
      '/webhooks/cluster-inventory',
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          cluster_id: 'cluster-1',
          tenant_id: 'tenant-1',
          services: [
            { name: 'redis', namespace: 'staging', image: 'redis', tag: '7.2.4', ports: [6379], replicas: 1, size: 'small' },
            { name: 'api-prod', namespace: 'production', image: 'api', tag: '1.0.0', ports: [8080], replicas: 2, size: 'large' },
          ],
          collected_at: '2026-03-20T00:00:00Z',
        }),
      },
      mockEnv,
    )

    expect(res.status).toBe(403)
    const body = await res.json()
    expect(body.error).toContain('production')
  })

  it('strips extra fields and stores sanitized inventory', async () => {
    const { getTenantAgentConfig, upsertClusterInventory } = await import('../../src/clients/db.js')
    vi.mocked(getTenantAgentConfig).mockResolvedValueOnce({
      tenant_id: 'tenant-1',
      autonomy_level: 0,
      enabled_agents: ['enricher'],
      rate_limits: { enricher: 100 },
      responder_opt_in: false,
      inventory_enabled: true,
      inventory_namespaces: ['staging'],
    })

    const res = await app.request(
      '/webhooks/cluster-inventory',
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          cluster_id: 'cluster-1',
          tenant_id: 'tenant-1',
          services: [
            {
              name: 'redis-primary',
              namespace: 'staging',
              image: 'redis',
              tag: '7.2.4',
              ports: [6379],
              replicas: 3,
              size: 'medium',
              // These fields should be stripped (defense in depth)
              env_vars: { SECRET_KEY: 'leaked' },
              labels: { team: 'platform' },
              ip: '10.0.0.5',
            },
          ],
          collected_at: '2026-03-20T00:00:00Z',
        }),
      },
      mockEnv,
    )

    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.status).toBe('accepted')
    expect(body.services_stored).toBe(1)

    // Verify sanitized data was stored (no env_vars, labels, ip)
    expect(upsertClusterInventory).toHaveBeenCalledWith(
      mockEnv.DB,
      expect.objectContaining({
        services: [
          {
            name: 'redis-primary',
            namespace: 'staging',
            image: 'redis',
            tag: '7.2.4',
            ports: [6379],
            replicas: 3,
            size: 'medium',
          },
        ],
      }),
    )

    // Verify stripped fields are NOT in the stored data
    const storedServices = vi.mocked(upsertClusterInventory).mock.calls[0][1].services
    expect(storedServices[0]).not.toHaveProperty('env_vars')
    expect(storedServices[0]).not.toHaveProperty('labels')
    expect(storedServices[0]).not.toHaveProperty('ip')
  })

  it('accepts valid inventory with allowed namespaces', async () => {
    const { getTenantAgentConfig } = await import('../../src/clients/db.js')
    vi.mocked(getTenantAgentConfig).mockResolvedValueOnce({
      tenant_id: 'tenant-1',
      autonomy_level: 0,
      enabled_agents: ['enricher'],
      rate_limits: { enricher: 100 },
      responder_opt_in: false,
      inventory_enabled: true,
      inventory_namespaces: ['staging', 'data'],
    })

    const res = await app.request(
      '/webhooks/cluster-inventory',
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          cluster_id: 'cluster-1',
          tenant_id: 'tenant-1',
          services: [
            { name: 'redis-primary', namespace: 'staging', image: 'redis', tag: '7.2.4', ports: [6379], replicas: 3, size: 'medium' },
            { name: 'kafka-broker-0', namespace: 'data', image: 'kafka', tag: '3.6.1', ports: [9092], replicas: 3, size: 'large' },
          ],
          collected_at: '2026-03-20T00:00:00Z',
        }),
      },
      mockEnv,
    )

    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.status).toBe('accepted')
    expect(body.services_stored).toBe(2)
  })
})
