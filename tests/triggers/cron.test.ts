import { describe, it, expect, vi, beforeEach } from 'vitest'

vi.mock('../../src/agents/investigator.js', () => ({
  runInvestigator: vi.fn().mockResolvedValue(undefined),
}))
vi.mock('../../src/agents/strategist.js', () => ({
  runStrategist: vi.fn().mockResolvedValue(undefined),
}))
vi.mock('../../src/safety/guard.js', () => ({
  checkRateLimit: vi.fn().mockReturnValue(true),
}))
vi.mock('../../src/config.js', () => ({
  logger: { info: vi.fn(), error: vi.fn(), warn: vi.fn(), debug: vi.fn() },
}))

const mockDB = {
  prepare: vi.fn().mockReturnValue({
    all: vi.fn().mockResolvedValue({
      results: [
        { tenant_id: 'tenant-1', enabled_agents: '["enricher","investigator","strategist"]' },
        { tenant_id: 'tenant-2', enabled_agents: '["enricher"]' },
      ],
    }),
  }),
}

const mockEnv = {
  DB: mockDB as unknown as D1Database,
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

describe('handleScheduled', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockDB.prepare.mockReturnValue({
      all: vi.fn().mockResolvedValue({
        results: [
          { tenant_id: 'tenant-1', enabled_agents: '["enricher","investigator","strategist"]' },
          { tenant_id: 'tenant-2', enabled_agents: '["enricher"]' },
        ],
      }),
    })
  })

  it('investigator cron runs for tenants with investigator enabled', async () => {
    const { handleScheduled } = await import('../../src/triggers/cron.js')
    const { runInvestigator } = await import('../../src/agents/investigator.js')

    await handleScheduled({ cron: '*/30 * * * *', scheduledTime: Date.now(), type: 'scheduled' } as ScheduledEvent, mockEnv as any)

    expect(runInvestigator).toHaveBeenCalledWith(
      mockEnv,
      expect.objectContaining({ tenantId: 'tenant-1', trigger: 'cron' }),
    )
  })

  it('strategist cron runs for tenants with strategist enabled', async () => {
    const { handleScheduled } = await import('../../src/triggers/cron.js')
    const { runStrategist } = await import('../../src/agents/strategist.js')

    await handleScheduled({ cron: '0 */6 * * *', scheduledTime: Date.now(), type: 'scheduled' } as ScheduledEvent, mockEnv as any)

    expect(runStrategist).toHaveBeenCalledWith(
      mockEnv,
      expect.objectContaining({ tenantId: 'tenant-1', trigger: 'cron' }),
    )
  })

  it('rate limiting skips tenant when rate limit exceeded', async () => {
    const { checkRateLimit } = await import('../../src/safety/guard.js')
    vi.mocked(checkRateLimit)
      .mockReturnValueOnce(false)

    // Make both tenants have investigator enabled
    mockDB.prepare.mockReturnValue({
      all: vi.fn().mockResolvedValue({
        results: [
          { tenant_id: 'tenant-1', enabled_agents: '["investigator"]' },
          { tenant_id: 'tenant-2', enabled_agents: '["investigator"]' },
        ],
      }),
    })

    const { handleScheduled } = await import('../../src/triggers/cron.js')
    const { runInvestigator } = await import('../../src/agents/investigator.js')

    await handleScheduled({ cron: '*/30 * * * *', scheduledTime: Date.now(), type: 'scheduled' } as ScheduledEvent, mockEnv as any)

    // First tenant rate-limited (skipped), second tenant runs
    expect(runInvestigator).toHaveBeenCalledTimes(1)
    expect(runInvestigator).toHaveBeenCalledWith(
      mockEnv,
      expect.objectContaining({ tenantId: 'tenant-2' }),
    )
  })

  it('error in one tenant does not stop others', async () => {
    const { runInvestigator } = await import('../../src/agents/investigator.js')
    vi.mocked(runInvestigator).mockRejectedValueOnce(new Error('Agent crash'))

    // Make both tenants have investigator enabled
    mockDB.prepare.mockReturnValue({
      all: vi.fn().mockResolvedValue({
        results: [
          { tenant_id: 'tenant-1', enabled_agents: '["investigator"]' },
          { tenant_id: 'tenant-2', enabled_agents: '["investigator"]' },
        ],
      }),
    })

    const { handleScheduled } = await import('../../src/triggers/cron.js')

    await handleScheduled({ cron: '*/30 * * * *', scheduledTime: Date.now(), type: 'scheduled' } as ScheduledEvent, mockEnv as any)

    expect(runInvestigator).toHaveBeenCalledTimes(2)
    expect(runInvestigator).toHaveBeenCalledWith(
      mockEnv,
      expect.objectContaining({ tenantId: 'tenant-2' }),
    )
  })

  it('getActiveTenants filters by agent type', async () => {
    const { handleScheduled } = await import('../../src/triggers/cron.js')
    const { runInvestigator } = await import('../../src/agents/investigator.js')

    await handleScheduled({ cron: '*/30 * * * *', scheduledTime: Date.now(), type: 'scheduled' } as ScheduledEvent, mockEnv as any)

    // tenant-2 has only enricher, so investigator should only run for tenant-1
    expect(runInvestigator).toHaveBeenCalledTimes(1)
    expect(runInvestigator).toHaveBeenCalledWith(
      mockEnv,
      expect.objectContaining({ tenantId: 'tenant-1' }),
    )
  })

  it('skips tenants with corrupted enabled_agents JSON', async () => {
    mockDB.prepare.mockReturnValue({
      all: vi.fn().mockResolvedValue({
        results: [
          { tenant_id: 'tenant-corrupt', enabled_agents: 'NOT VALID JSON' },
          { tenant_id: 'tenant-good', enabled_agents: '["investigator"]' },
        ],
      }),
    })

    const { handleScheduled } = await import('../../src/triggers/cron.js')
    const { runInvestigator } = await import('../../src/agents/investigator.js')

    await handleScheduled({ cron: '*/30 * * * *', scheduledTime: Date.now(), type: 'scheduled' } as ScheduledEvent, mockEnv as any)

    // Corrupted tenant skipped, good tenant still runs
    expect(runInvestigator).toHaveBeenCalledTimes(1)
    expect(runInvestigator).toHaveBeenCalledWith(
      mockEnv,
      expect.objectContaining({ tenantId: 'tenant-good' }),
    )
  })

  it('unknown cron pattern does nothing', async () => {
    const { handleScheduled } = await import('../../src/triggers/cron.js')
    const { runInvestigator } = await import('../../src/agents/investigator.js')
    const { runStrategist } = await import('../../src/agents/strategist.js')

    await handleScheduled({ cron: '0 0 * * *', scheduledTime: Date.now(), type: 'scheduled' } as ScheduledEvent, mockEnv as any)

    expect(runInvestigator).not.toHaveBeenCalled()
    expect(runStrategist).not.toHaveBeenCalled()
  })
})
