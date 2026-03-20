import { describe, it, expect, vi } from 'vitest'

vi.mock('@mariozechner/pi-agent-core', () => ({
  Agent: vi.fn().mockImplementation(() => ({
    subscribe: vi.fn(),
    prompt: vi.fn().mockResolvedValue(undefined),
    waitForIdle: vi.fn().mockResolvedValue(undefined),
  })),
}))

vi.mock('@mariozechner/pi-ai', () => ({
  getModel: vi.fn().mockReturnValue({ id: 'claude-sonnet-4-20250514', provider: 'anthropic' }),
}))

vi.mock('../../src/clients/db.js', () => ({
  createAgentSession: vi.fn().mockResolvedValue('session-inv-falco-1'),
  completeAgentSession: vi.fn().mockResolvedValue(undefined),
  getTenantAgentConfig: vi.fn().mockResolvedValue({
    autonomy_level: 0,
    enabled_agents: ['investigator'],
    rate_limits: { investigator: 20 },
    responder_opt_in: false,
    inventory_enabled: false,
    inventory_namespaces: [],
  }),
  createProposal: vi.fn().mockResolvedValue('proposal-1'),
  logToolInvocation: vi.fn().mockResolvedValue(undefined),
  queryEvents: vi.fn().mockResolvedValue({ results: [] }),
  correlateSessionsQuery: vi.fn().mockResolvedValue({ results: [] }),
  queryDeployments: vi.fn().mockResolvedValue({ results: [] }),
  insertInvestigation: vi.fn().mockResolvedValue('inv-1'),
  insertCampaign: vi.fn().mockResolvedValue('camp-1'),
  getInvestigation: vi.fn(),
  updateInvestigationReport: vi.fn(),
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

describe('Investigator Falco correlation', () => {
  it('system prompt includes Falco event correlation guidance', async () => {
    const { Agent } = await import('@mariozechner/pi-agent-core')
    const { runInvestigator } = await import('../../src/agents/investigator.js')

    await runInvestigator(mockEnv, {
      tenantId: 'tenant-1',
      trigger: 'escalation',
      context: { eventId: 'evt-falco-1', reason: 'Falco: Shell Spawned in Container' },
    })

    // Verify the system prompt contains Falco correlation guidance
    expect(Agent).toHaveBeenCalledWith(
      expect.objectContaining({
        initialState: expect.objectContaining({
          systemPrompt: expect.stringContaining('Falco Event Correlation'),
        }),
      }),
    )

    const agentCall = vi.mocked(Agent).mock.calls[0][0]
    const systemPrompt = agentCall.initialState.systemPrompt as string
    expect(systemPrompt).toContain('Container Escape Attempt')
    expect(systemPrompt).toContain('kill chain')
    expect(systemPrompt).toContain('query_events for the same deployment_id')
  })

  it('includes Falco context in escalation prompt', async () => {
    const { Agent } = await import('@mariozechner/pi-agent-core')
    const mockPrompt = vi.fn().mockResolvedValue(undefined)
    vi.mocked(Agent).mockImplementationOnce(
      () =>
        ({
          subscribe: vi.fn(),
          prompt: mockPrompt,
          waitForIdle: vi.fn().mockResolvedValue(undefined),
        }) as any,
    )

    const { runInvestigator } = await import('../../src/agents/investigator.js')

    await runInvestigator(mockEnv, {
      tenantId: 'tenant-1',
      trigger: 'escalation',
      context: {
        eventId: 'evt-falco-escape',
        srcIp: '127.0.0.1',
        reason: 'Falco: Container Escape Attempt detected',
      },
    })

    expect(mockPrompt).toHaveBeenCalledWith(
      expect.stringContaining('Container Escape Attempt'),
    )
  })
})
