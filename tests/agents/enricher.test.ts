import { describe, it, expect, vi } from 'vitest'

vi.mock('@mariozechner/pi-agent-core', () => ({
  Agent: vi.fn().mockImplementation(() => ({
    subscribe: vi.fn(),
    prompt: vi.fn().mockResolvedValue(undefined),
    waitForIdle: vi.fn().mockResolvedValue(undefined),
  })),
}))

vi.mock('@mariozechner/pi-ai', () => ({
  getModel: vi.fn().mockReturnValue({ id: 'claude-haiku-4-5-20251001', provider: 'anthropic' }),
}))

vi.mock('../../src/clients/db.js', () => ({
  createAgentSession: vi.fn().mockResolvedValue('session-enricher-1'),
  completeAgentSession: vi.fn().mockResolvedValue(undefined),
  getTenantAgentConfig: vi.fn().mockResolvedValue({
    autonomy_level: 0,
    enabled_agents: ['enricher'],
    rate_limits: { enricher: 100 },
    responder_opt_in: false,
  }),
  createProposal: vi.fn().mockResolvedValue('proposal-1'),
  logToolInvocation: vi.fn().mockResolvedValue(undefined),
  getEventEnrichment: vi.fn(),
  updateEventEnrichment: vi.fn(),
  insertEscalation: vi.fn(),
}))

vi.mock('../../src/config.js', () => ({
  logger: { info: vi.fn(), error: vi.fn(), warn: vi.fn(), debug: vi.fn() },
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

describe('runEnricher', () => {
  it('creates an agent session and runs enrichment', async () => {
    const { runEnricher } = await import('../../src/agents/enricher.js')
    const { createAgentSession, completeAgentSession } = await import('../../src/clients/db.js')
    const { Agent } = await import('@mariozechner/pi-agent-core')
    const { getModel } = await import('@mariozechner/pi-ai')

    await runEnricher(mockEnv, {
      tenantId: 'tenant-1',
      eventId: 'evt-1',
      eventData: { src_ip: '10.0.0.1', signal: 'login_attempt', severity: 'low', hp_type: 'ssh' },
    })

    expect(createAgentSession).toHaveBeenCalledWith(
      mockEnv.DB,
      expect.objectContaining({ agent_type: 'enricher', tenant_id: 'tenant-1' }),
    )
    expect(Agent).toHaveBeenCalledWith(
      expect.objectContaining({ initialState: expect.objectContaining({ thinkingLevel: 'off' }) }),
    )
    expect(getModel).toHaveBeenCalledWith('anthropic', 'claude-haiku-4-5-20251001')
    expect(completeAgentSession).toHaveBeenCalledWith(mockEnv.DB, 'session-enricher-1', { status: 'completed' })
  })

  it('marks session as failed on error', async () => {
    const { Agent } = await import('@mariozechner/pi-agent-core')
    vi.mocked(Agent).mockImplementationOnce(
      () =>
        ({
          subscribe: vi.fn(),
          prompt: vi.fn().mockRejectedValue(new Error('LLM timeout')),
          waitForIdle: vi.fn(),
        }) as any,
    )

    const { runEnricher } = await import('../../src/agents/enricher.js')
    const { completeAgentSession } = await import('../../src/clients/db.js')

    await expect(
      runEnricher(mockEnv, {
        tenantId: 'tenant-1',
        eventId: 'evt-2',
        eventData: { src_ip: '10.0.0.2', signal: 'brute_force', severity: 'high' },
      }),
    ).rejects.toThrow('LLM timeout')

    expect(completeAgentSession).toHaveBeenCalledWith(
      mockEnv.DB,
      expect.any(String),
      expect.objectContaining({ status: 'failed', error_message: 'LLM timeout' }),
    )
  })
})
