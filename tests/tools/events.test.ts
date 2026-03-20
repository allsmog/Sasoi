import { describe, it, expect, vi, beforeEach } from 'vitest'

const mockAll = vi.fn().mockResolvedValue({ results: [] })
const mockBind = vi.fn().mockReturnValue({ all: mockAll })
const mockPrepare = vi.fn().mockReturnValue({ bind: mockBind })

vi.mock('../../src/clients/db.js', () => ({
  queryEvents: vi.fn().mockResolvedValue({ results: [] }),
  correlateSessionsQuery: vi.fn().mockResolvedValue({ results: [] }),
}))

const mockEnv = {
  DB: { prepare: mockPrepare } as unknown as D1Database,
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

describe('createQueryEventsTool', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('has correct metadata', async () => {
    const { createQueryEventsTool } = await import('../../src/tools/events.js')
    const tool = createQueryEventsTool(mockEnv)
    expect(tool.name).toBe('query_events')
    expect(tool.label).toBe('Query Events')
  })

  it('queries events with tenant_id', async () => {
    const { queryEvents } = await import('../../src/clients/db.js')
    vi.mocked(queryEvents).mockResolvedValueOnce({
      results: [{ event_id: 'e1', signal: 'login_attempt', severity: 'low' }],
      success: true,
      meta: {} as any,
    })

    const { createQueryEventsTool } = await import('../../src/tools/events.js')
    const tool = createQueryEventsTool(mockEnv)
    const result = await tool.execute('call-1', { tenant_id: 'tenant-1' })

    expect(result.content[0].type).toBe('text')
    expect(result.details).toEqual({ count: 1 })
  })
})

describe('createCorrelateSessionsTool', () => {
  it('calls correlateSessionsQuery', async () => {
    const { correlateSessionsQuery } = await import('../../src/clients/db.js')
    vi.mocked(correlateSessionsQuery).mockResolvedValueOnce({
      results: [{ src_ip: '192.168.1.1', event_count: 5, honeypots_hit: 3 }],
      success: true,
      meta: {} as any,
    })

    const { createCorrelateSessionsTool } = await import('../../src/tools/events.js')
    const tool = createCorrelateSessionsTool(mockEnv)
    const result = await tool.execute('call-2', { tenant_id: 'tenant-1', time_window_hours: 12, min_events: 3 })

    expect(result.details).toEqual({ correlations: 1 })
  })
})
