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
  createAgentSession: vi.fn().mockResolvedValue('session-resp-1'),
  completeAgentSession: vi.fn().mockResolvedValue(undefined),
  getTenantAgentConfig: vi.fn().mockResolvedValue({
    tenant_id: 'tenant-1',
    autonomy_level: 0,
    enabled_agents: ['responder'],
    rate_limits: { responder: 10 },
    responder_opt_in: false,
    inventory_enabled: false,
    inventory_namespaces: [],
  }),
  createProposal: vi.fn().mockResolvedValue('proposal-1'),
  logToolInvocation: vi.fn().mockResolvedValue(undefined),
}))

vi.mock('../../src/config.js', () => ({
  logger: { info: vi.fn(), error: vi.fn(), warn: vi.fn(), debug: vi.fn() },
}))

vi.mock('../../src/tools/events.js', () => ({
  createQueryEventsTool: vi.fn().mockReturnValue({ name: 'query_events' }),
}))
vi.mock('../../src/tools/fleet.js', () => ({
  createQueryFleetTool: vi.fn().mockReturnValue({ name: 'query_fleet' }),
}))
vi.mock('../../src/tools/persona.js', () => ({
  createRotatePersonaTool: vi.fn().mockReturnValue({ name: 'rotate_persona' }),
  createGenerateVariationTool: vi.fn().mockReturnValue({ name: 'generate_persona_variation' }),
}))
vi.mock('../../src/tools/deployment.js', () => ({
  createDeployCanaryTool: vi.fn().mockReturnValue({ name: 'deploy_canary' }),
}))
vi.mock('../../src/tools/notification.js', () => ({
  createIncreaseLoggingDepthTool: vi.fn().mockReturnValue({ name: 'increase_logging_depth' }),
  createTriggerNotificationTool: vi.fn().mockReturnValue({ name: 'trigger_notification' }),
}))
vi.mock('../../src/tools/response.js', () => ({
  createBlockIPTool: vi.fn().mockReturnValue({ name: 'block_ip' }),
  createRedirectAttackerTool: vi.fn().mockReturnValue({ name: 'redirect_attacker' }),
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

describe('runResponder', () => {
  it('responder_opt_in=false gets only notification tool', async () => {
    const { Agent } = await import('@mariozechner/pi-agent-core')
    const { runResponder } = await import('../../src/agents/responder.js')

    await runResponder(mockEnv, {
      tenantId: 'tenant-1',
      trigger: 'campaign_detected',
      context: { campaignId: 'camp-1', campaignName: 'Test Campaign' },
    })

    expect(Agent).toHaveBeenCalledWith(
      expect.objectContaining({
        initialState: expect.objectContaining({
          tools: [expect.objectContaining({ name: 'trigger_notification' })],
        }),
      }),
    )
  })

  it('responder_opt_in=true gets full tool set', async () => {
    const { getTenantAgentConfig } = await import('../../src/clients/db.js')
    vi.mocked(getTenantAgentConfig).mockResolvedValueOnce({
      tenant_id: 'tenant-1',
      autonomy_level: 0,
      enabled_agents: ['responder'],
      rate_limits: { responder: 10 },
      responder_opt_in: true,
      inventory_enabled: false,
      inventory_namespaces: [],
    })

    const { Agent } = await import('@mariozechner/pi-agent-core')
    const { runResponder } = await import('../../src/agents/responder.js')

    await runResponder(mockEnv, {
      tenantId: 'tenant-1',
      trigger: 'campaign_detected',
      context: { campaignId: 'camp-2', campaignName: 'Advanced Campaign' },
    })

    const agentCall = vi.mocked(Agent).mock.calls[vi.mocked(Agent).mock.calls.length - 1][0]
    const tools = agentCall.initialState.tools as { name: string }[]
    // At autonomy 0 with opt-in: query_events, query_fleet, rotate_persona, generate_persona_variation,
    // deploy_canary, increase_logging_depth, trigger_notification (7 tools, no block/redirect)
    expect(tools.length).toBe(7)
    expect(tools.map((t) => t.name)).not.toContain('block_ip')
    expect(tools.map((t) => t.name)).not.toContain('redirect_attacker')
  })

  it('autonomy>=2 adds block/redirect tools', async () => {
    const { getTenantAgentConfig } = await import('../../src/clients/db.js')
    vi.mocked(getTenantAgentConfig).mockResolvedValueOnce({
      tenant_id: 'tenant-1',
      autonomy_level: 2,
      enabled_agents: ['responder'],
      rate_limits: { responder: 10 },
      responder_opt_in: true,
      inventory_enabled: false,
      inventory_namespaces: [],
    })

    const { Agent } = await import('@mariozechner/pi-agent-core')
    const { runResponder } = await import('../../src/agents/responder.js')

    await runResponder(mockEnv, {
      tenantId: 'tenant-1',
      trigger: 'campaign_detected',
      context: { campaignId: 'camp-3' },
    })

    const agentCall = vi.mocked(Agent).mock.calls[vi.mocked(Agent).mock.calls.length - 1][0]
    const tools = agentCall.initialState.tools as { name: string }[]
    expect(tools.length).toBe(9)
    expect(tools.map((t) => t.name)).toContain('block_ip')
    expect(tools.map((t) => t.name)).toContain('redirect_attacker')
  })

  it('uses campaign prompt with campaign details', async () => {
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

    const { runResponder } = await import('../../src/agents/responder.js')

    await runResponder(mockEnv, {
      tenantId: 'tenant-1',
      trigger: 'campaign_detected',
      context: {
        campaignId: 'camp-4',
        campaignName: 'APT28 Recon',
        attackerIps: ['1.2.3.4', '5.6.7.8'],
        affectedDeployments: ['deploy-1', 'deploy-2'],
      },
    })

    expect(mockPrompt).toHaveBeenCalledWith(
      expect.stringContaining('APT28 Recon'),
    )
    expect(mockPrompt).toHaveBeenCalledWith(
      expect.stringContaining('1.2.3.4'),
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

    const { runResponder } = await import('../../src/agents/responder.js')
    const { completeAgentSession } = await import('../../src/clients/db.js')

    await expect(
      runResponder(mockEnv, {
        tenantId: 'tenant-1',
        trigger: 'campaign_detected',
        context: { campaignId: 'camp-fail' },
      }),
    ).rejects.toThrow('LLM timeout')

    expect(completeAgentSession).toHaveBeenCalledWith(
      mockEnv.DB,
      expect.any(String),
      expect.objectContaining({ status: 'failed', error_message: 'LLM timeout' }),
    )
  })
})
