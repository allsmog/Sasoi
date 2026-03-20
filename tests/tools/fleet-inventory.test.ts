import { describe, it, expect, vi, beforeEach } from 'vitest'

vi.mock('../../src/clients/db.js', () => ({
  queryDeployments: vi.fn().mockResolvedValue({ results: [] }),
  queryClusters: vi.fn().mockResolvedValue({ results: [] }),
  getLatestInventory: vi.fn().mockResolvedValue(null),
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

describe('createQueryInventoryTool', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('has correct metadata', async () => {
    const { createQueryInventoryTool } = await import('../../src/tools/fleet.js')
    const tool = createQueryInventoryTool(mockEnv)
    expect(tool.name).toBe('query_inventory')
    expect(tool.label).toBe('Query Cluster Inventory')
  })

  it('returns not-available when no inventory exists', async () => {
    const { createQueryInventoryTool } = await import('../../src/tools/fleet.js')
    const tool = createQueryInventoryTool(mockEnv)
    const result = await tool.execute('call-1', { tenant_id: 'tenant-1' })

    expect(result.content[0].text).toContain('No cluster inventory available')
    expect(result.details).toEqual({ available: false })
  })

  it('returns inventory data when available', async () => {
    const { getLatestInventory } = await import('../../src/clients/db.js')
    vi.mocked(getLatestInventory).mockResolvedValueOnce({
      inventory_id: 'inv-1',
      cluster_id: 'cluster-1',
      tenant_id: 'tenant-1',
      services: JSON.stringify([
        { name: 'redis-primary', namespace: 'staging', image: 'redis', tag: '7.2.4', ports: [6379], replicas: 3, size: 'medium' },
      ]),
      naming_patterns: JSON.stringify({ prefixes: ['redis'], total_services: 1 }),
      collected_at: '2026-03-20T00:00:00Z',
      created_at: '2026-03-20T00:00:00Z',
    })

    const { createQueryInventoryTool } = await import('../../src/tools/fleet.js')
    const tool = createQueryInventoryTool(mockEnv)
    const result = await tool.execute('call-2', { tenant_id: 'tenant-1' })

    const data = JSON.parse(result.content[0].text)
    expect(data.cluster_id).toBe('cluster-1')
    expect(data.services).toHaveLength(1)
    expect(data.services[0].name).toBe('redis-primary')
    expect(data.services[0].image).toBe('redis')
    expect(result.details).toEqual({ service_count: 1, collected_at: '2026-03-20T00:00:00Z' })
  })
})
