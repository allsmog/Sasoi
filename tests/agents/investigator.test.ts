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
  createAgentSession: vi.fn().mockResolvedValue('session-inv-1'),
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

vi.mock('../../src/tools/events.js', () => ({
  createQueryEventsTool: vi.fn().mockReturnValue({ name: 'query_events' }),
  createCorrelateSessionsTool: vi.fn().mockReturnValue({ name: 'correlate_sessions' }),
}))
vi.mock('../../src/tools/fleet.js', () => ({
  createQueryFleetTool: vi.fn().mockReturnValue({ name: 'query_fleet' }),
}))
vi.mock('../../src/tools/enrichment.js', () => ({
  createThreatIntelLookupTool: vi.fn().mockReturnValue({ name: 'threat_intel_lookup' }),
}))
vi.mock('../../src/tools/investigation.js', () => ({
  createCreateInvestigationTool: vi.fn().mockReturnValue({ name: 'create_investigation' }),
  createFlagCampaignTool: vi.fn().mockReturnValue({ name: 'flag_campaign' }),
  createGenerateReportTool: vi.fn().mockReturnValue({ name: 'generate_report' }),
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

describe('runInvestigator', () => {
  it('creates agent session on start', async () => {
    const { runInvestigator } = await import('../../src/agents/investigator.js')
    const { createAgentSession } = await import('../../src/clients/db.js')

    await runInvestigator(mockEnv, {
      tenantId: 'tenant-1',
      trigger: 'cron',
    })

    expect(createAgentSession).toHaveBeenCalledWith(
      mockEnv.DB,
      expect.objectContaining({ agent_type: 'investigator', tenant_id: 'tenant-1' }),
    )
  })

  it('uses cron prompt when trigger is cron', async () => {
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
      trigger: 'cron',
    })

    expect(mockPrompt).toHaveBeenCalledWith(
      expect.stringContaining('Correlate sessions'),
    )
  })

  it('uses escalation prompt with event details when trigger is escalation', async () => {
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
      context: { eventId: 'evt-99', srcIp: '10.0.0.5', reason: 'Brute force detected' },
    })

    expect(mockPrompt).toHaveBeenCalledWith(
      expect.stringContaining('evt-99'),
    )
    expect(mockPrompt).toHaveBeenCalledWith(
      expect.stringContaining('10.0.0.5'),
    )
    expect(mockPrompt).toHaveBeenCalledWith(
      expect.stringContaining('Brute force detected'),
    )
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

    const { runInvestigator } = await import('../../src/agents/investigator.js')
    const { completeAgentSession } = await import('../../src/clients/db.js')

    await expect(
      runInvestigator(mockEnv, {
        tenantId: 'tenant-1',
        trigger: 'escalation',
        context: { eventId: 'evt-fail', reason: 'Test failure' },
      }),
    ).rejects.toThrow('LLM timeout')

    expect(completeAgentSession).toHaveBeenCalledWith(
      mockEnv.DB,
      expect.any(String),
      expect.objectContaining({ status: 'failed', error_message: 'LLM timeout' }),
    )
  })
})
