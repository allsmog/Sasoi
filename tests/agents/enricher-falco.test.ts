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
  createAgentSession: vi.fn().mockResolvedValue('session-falco-1'),
  completeAgentSession: vi.fn().mockResolvedValue(undefined),
  getTenantAgentConfig: vi.fn().mockResolvedValue({
    autonomy_level: 0,
    enabled_agents: ['enricher'],
    rate_limits: { enricher: 100 },
    responder_opt_in: false,
    inventory_enabled: false,
    inventory_namespaces: [],
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

describe('Enricher Falco handling', () => {
  it('system prompt includes Falco runtime alert guidance', async () => {
    const { Agent } = await import('@mariozechner/pi-agent-core')
    const { runEnricher } = await import('../../src/agents/enricher.js')

    await runEnricher(mockEnv, {
      tenantId: 'tenant-1',
      eventId: 'evt-falco-1',
      eventData: {
        src_ip: '127.0.0.1',
        signal: 'falco_runtime_alert',
        severity: 'high',
        hp_type: 'ssh',
        deployment_id: 'deploy-1',
        enrichment: { falco_rule: 'Shell Spawned in Container', falco_priority: 'Warning' },
      },
    })

    // Verify the Agent was constructed with a system prompt containing Falco guidance
    expect(Agent).toHaveBeenCalledWith(
      expect.objectContaining({
        initialState: expect.objectContaining({
          systemPrompt: expect.stringContaining('Falco Runtime Alerts'),
        }),
      }),
    )

    // Verify key Falco instructions are in the system prompt
    const agentCall = vi.mocked(Agent).mock.calls[0][0]
    const systemPrompt = agentCall.initialState.systemPrompt as string
    expect(systemPrompt).toContain('NEVER run geoip_lookup')
    expect(systemPrompt).toContain('ALWAYS run ml_predict')
    expect(systemPrompt).toContain('ALWAYS escalate_to_investigator')
    expect(systemPrompt).toContain('Reverse Shell Detected')
    expect(systemPrompt).toContain('Container Escape Attempt')
    expect(systemPrompt).toContain('Lateral Movement')
  })

  it('passes Falco event data to agent prompt', async () => {
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

    const { runEnricher } = await import('../../src/agents/enricher.js')

    await runEnricher(mockEnv, {
      tenantId: 'tenant-1',
      eventId: 'evt-falco-2',
      eventData: {
        src_ip: '127.0.0.1',
        signal: 'falco_runtime_alert',
        severity: 'high',
        enrichment: { falco_rule: 'Reverse Shell Detected' },
      },
    })

    expect(mockPrompt).toHaveBeenCalledWith(
      expect.stringContaining('falco_runtime_alert'),
    )
    expect(mockPrompt).toHaveBeenCalledWith(
      expect.stringContaining('127.0.0.1'),
    )
  })
})
