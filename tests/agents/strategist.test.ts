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
  createAgentSession: vi.fn().mockResolvedValue('session-strat-1'),
  completeAgentSession: vi.fn().mockResolvedValue(undefined),
  getTenantAgentConfig: vi.fn().mockResolvedValue({
    tenant_id: 'tenant-1',
    autonomy_level: 0,
    enabled_agents: ['strategist'],
    rate_limits: { strategist: 5 },
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

vi.mock('../../src/tools/events.js', () => ({ createQueryEventsTool: vi.fn().mockReturnValue({ name: 'query_events' }) }))
vi.mock('../../src/tools/fleet.js', () => ({
  createQueryFleetTool: vi.fn().mockReturnValue({ name: 'query_fleet' }),
  createQueryClustersTool: vi.fn().mockReturnValue({ name: 'query_clusters' }),
  createQueryInventoryTool: vi.fn().mockReturnValue({ name: 'query_inventory' }),
}))
vi.mock('../../src/tools/enrichment.js', () => ({ createThreatIntelLookupTool: vi.fn().mockReturnValue({ name: 'threat_intel_lookup' }) }))
vi.mock('../../src/tools/persona.js', () => ({ createGeneratePersonaTool: vi.fn().mockReturnValue({ name: 'generate_persona' }) }))
vi.mock('../../src/tools/deployment.js', () => ({
  createProposeDeploymentTool: vi.fn().mockReturnValue({ name: 'propose_deployment' }),
  createExecuteDeploymentTool: vi.fn().mockReturnValue({ name: 'execute_deployment' }),
}))
vi.mock('../../src/tools/decoy-files.js', () => ({ createGenerateDecoyFilesTool: vi.fn().mockReturnValue({ name: 'generate_decoy_files' }) }))
vi.mock('../../src/tools/breadcrumbs.js', () => ({ createGenerateBreadcrumbsTool: vi.fn().mockReturnValue({ name: 'generate_breadcrumbs' }) }))
vi.mock('../../src/tools/honeytokens.js', () => ({
  createDeployHoneytokenTool: vi.fn().mockReturnValue({ name: 'deploy_honeytoken' }),
  createQueryHoneytokensTool: vi.fn().mockReturnValue({ name: 'query_honeytokens' }),
}))
vi.mock('../../src/tools/cloud-deception.js', () => ({ createDeployCloudDecoyTool: vi.fn().mockReturnValue({ name: 'deploy_cloud_decoy' }) }))
vi.mock('../../src/tools/identity-deception.js', () => ({ createDeployDecoyServiceAccountTool: vi.fn().mockReturnValue({ name: 'deploy_decoy_sa' }) }))

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

describe('runStrategist', () => {
  it('tools array includes deception tools at autonomy 0', async () => {
    const { Agent } = await import('@mariozechner/pi-agent-core')
    const { runStrategist } = await import('../../src/agents/strategist.js')

    await runStrategist(mockEnv, {
      tenantId: 'tenant-1',
      trigger: 'cron',
    })

    const agentCall = vi.mocked(Agent).mock.calls[vi.mocked(Agent).mock.calls.length - 1][0]
    const tools = agentCall.initialState.tools as { name: string }[]
    const toolNames = tools.map((t) => t.name)
    expect(toolNames).toContain('generate_decoy_files')
    expect(toolNames).toContain('generate_breadcrumbs')
    expect(toolNames).toContain('query_honeytokens')
    // Mutation tools should NOT be present at autonomy 0
    expect(toolNames).not.toContain('execute_deployment')
    expect(toolNames).not.toContain('deploy_honeytoken')
    expect(toolNames).not.toContain('deploy_cloud_decoy')
    expect(toolNames).not.toContain('deploy_decoy_sa')
  })

  it('autonomy>=2 adds mutation tools', async () => {
    const { getTenantAgentConfig } = await import('../../src/clients/db.js')
    vi.mocked(getTenantAgentConfig).mockResolvedValueOnce({
      tenant_id: 'tenant-1',
      autonomy_level: 2,
      enabled_agents: ['strategist'],
      rate_limits: { strategist: 5 },
      responder_opt_in: false,
      inventory_enabled: false,
      inventory_namespaces: [],
    })

    const { Agent } = await import('@mariozechner/pi-agent-core')
    const { runStrategist } = await import('../../src/agents/strategist.js')

    await runStrategist(mockEnv, {
      tenantId: 'tenant-1',
      trigger: 'cron',
    })

    const agentCall = vi.mocked(Agent).mock.calls[vi.mocked(Agent).mock.calls.length - 1][0]
    const tools = agentCall.initialState.tools as { name: string }[]
    const toolNames = tools.map((t) => t.name)
    expect(toolNames).toContain('execute_deployment')
    expect(toolNames).toContain('deploy_honeytoken')
    expect(toolNames).toContain('deploy_cloud_decoy')
    expect(toolNames).toContain('deploy_decoy_sa')
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

    const { runStrategist } = await import('../../src/agents/strategist.js')

    await runStrategist(mockEnv, {
      tenantId: 'tenant-1',
      trigger: 'cron',
    })

    expect(mockPrompt).toHaveBeenCalledWith(
      expect.stringContaining('strategic analysis'),
    )
  })
})
