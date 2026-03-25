import { describe, it, expect, vi, beforeEach } from 'vitest'
import { Type } from '@sinclair/typebox'

vi.mock('../../src/clients/db.js', () => ({
  getTenantAgentConfig: vi.fn(),
  createProposal: vi.fn(),
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
}

describe('withMutationGuard', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('creates a proposal and does not invoke the inner tool when autonomy is insufficient', async () => {
    const { getTenantAgentConfig, createProposal } = await import('../../src/clients/db.js')
    vi.mocked(getTenantAgentConfig).mockResolvedValue({
      tenant_id: 'tenant-1',
      autonomy_level: 0,
      enabled_agents: ['responder'],
      rate_limits: { responder: 10 },
      responder_opt_in: true,
      inventory_enabled: false,
      inventory_namespaces: [],
    })
    vi.mocked(createProposal).mockResolvedValue('proposal-123')

    const execute = vi.fn().mockResolvedValue({
      content: [{ type: 'text' as const, text: 'executed' }],
      details: { executed: true },
    })

    const { withMutationGuard } = await import('../../src/tools/mutation.js')
    const guardedTool = withMutationGuard({
      name: 'increase_logging_depth',
      label: 'Increase Logging',
      description: 'test',
      parameters: Type.Object({ deployment_id: Type.String(), reason: Type.String() }),
      execute,
    }, {
      env: mockEnv,
      tenantId: 'tenant-1',
      sessionId: 'session-1',
      agentType: 'responder',
    }, {
      buildReasoning: (params) => params.reason,
    })

    const result = await guardedTool.execute('call-1', {
      deployment_id: 'dep-1',
      reason: 'Investigate attacker activity',
    })

    expect(execute).not.toHaveBeenCalled()
    expect(createProposal).toHaveBeenCalledWith(
      mockEnv.DB,
      mockEnv,
      expect.objectContaining({
        action_type: 'increase_logging_depth',
        action_payload: { deployment_id: 'dep-1', reason: 'Investigate attacker activity' },
      }),
    )
    expect(result.details).toEqual(expect.objectContaining({ blocked: true, proposal_id: 'proposal-123' }))
  })

  it('calls the inner tool unchanged when autonomy is sufficient', async () => {
    const { getTenantAgentConfig } = await import('../../src/clients/db.js')
    vi.mocked(getTenantAgentConfig).mockResolvedValue({
      tenant_id: 'tenant-1',
      autonomy_level: 2,
      enabled_agents: ['strategist'],
      rate_limits: { strategist: 5 },
      responder_opt_in: false,
      inventory_enabled: false,
      inventory_namespaces: [],
    })

    const execute = vi.fn().mockResolvedValue({
      content: [{ type: 'text' as const, text: 'executed' }],
      details: { executed: true },
    })

    const { withMutationGuard } = await import('../../src/tools/mutation.js')
    const guardedTool = withMutationGuard({
      name: 'execute_deployment',
      label: 'Execute Deployment',
      description: 'test',
      parameters: Type.Object({ blueprint_id: Type.String() }),
      execute,
    }, {
      env: mockEnv,
      tenantId: 'tenant-1',
      sessionId: 'session-1',
      agentType: 'strategist',
    })

    const result = await guardedTool.execute('call-2', { blueprint_id: 'bp-1' })

    expect(execute).toHaveBeenCalledWith('call-2', { blueprint_id: 'bp-1' }, undefined, undefined)
    expect(result.details).toEqual({ executed: true })
  })
})
