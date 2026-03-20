import { describe, it, expect, vi, beforeEach } from 'vitest'

vi.mock('../../src/clients/db.js', () => ({
  createProposal: vi.fn().mockResolvedValue('proposal-789'),
}))
vi.mock('../../src/clients/orchestrator.js', () => ({
  createDeployment: vi.fn().mockResolvedValue({ deployment_id: 'dep-1', status: 'deploying' }),
}))
vi.mock('../../src/clients/blueprint.js', () => ({
  generatePersona: vi.fn().mockResolvedValue({ persona: { service_type: 'ssh', port: 22 } }),
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

describe('createProposeDeploymentTool', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('creates proposal with correct action_type', async () => {
    const { createProposal } = await import('../../src/clients/db.js')

    const { createProposeDeploymentTool } = await import('../../src/tools/deployment.js')
    const tool = createProposeDeploymentTool(mockEnv)
    await tool.execute('call-1', {
      tenant_id: 'tenant-1',
      blueprint_id: 'bp-1',
      reasoning: 'High-value target detected',
    })

    expect(createProposal).toHaveBeenCalledWith(
      mockEnv.DB,
      mockEnv,
      expect.objectContaining({
        action_type: 'deploy_honeypot',
      }),
    )
  })

  it('includes blueprint_id and reasoning in payload', async () => {
    const { createProposal } = await import('../../src/clients/db.js')

    const { createProposeDeploymentTool } = await import('../../src/tools/deployment.js')
    const tool = createProposeDeploymentTool(mockEnv)
    await tool.execute('call-2', {
      tenant_id: 'tenant-1',
      blueprint_id: 'bp-42',
      reasoning: 'Network gap identified',
    })

    expect(createProposal).toHaveBeenCalledWith(
      mockEnv.DB,
      mockEnv,
      expect.objectContaining({
        action_payload: expect.objectContaining({
          blueprint_id: 'bp-42',
        }),
        reasoning: 'Network gap identified',
      }),
    )
  })
})

describe('createExecuteDeploymentTool', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('calls orchestrator.createDeployment directly', async () => {
    const orchestrator = await import('../../src/clients/orchestrator.js')

    const { createExecuteDeploymentTool } = await import('../../src/tools/deployment.js')
    const tool = createExecuteDeploymentTool(mockEnv)
    const result = await tool.execute('call-3', {
      blueprint_id: 'bp-1',
    })

    expect(orchestrator.createDeployment).toHaveBeenCalledWith(
      mockEnv,
      expect.objectContaining({
        blueprint_id: 'bp-1',
      }),
    )
    const parsed = JSON.parse(result.content[0].text)
    expect(parsed.deployment_id).toBe('dep-1')
    expect(parsed.status).toBe('deploying')
  })
})

describe('createDeployCanaryTool', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('generates persona before creating proposal', async () => {
    const blueprintClient = await import('../../src/clients/blueprint.js')
    const { createProposal } = await import('../../src/clients/db.js')

    const { createDeployCanaryTool } = await import('../../src/tools/deployment.js')
    const tool = createDeployCanaryTool(mockEnv)
    await tool.execute('call-4', {
      tenant_id: 'tenant-1',
      service_type: 'ssh',
      target_ips: ['10.0.0.1'],
      reasoning: 'Track attacker lateral movement',
    })

    expect(blueprintClient.generatePersona).toHaveBeenCalledBefore(vi.mocked(createProposal))
    expect(createProposal).toHaveBeenCalledWith(
      mockEnv.DB,
      mockEnv,
      expect.objectContaining({
        action_type: 'deploy_canary',
      }),
    )
  })

  it('includes target IPs in proposal payload', async () => {
    const { createProposal } = await import('../../src/clients/db.js')

    const { createDeployCanaryTool } = await import('../../src/tools/deployment.js')
    const tool = createDeployCanaryTool(mockEnv)
    await tool.execute('call-5', {
      tenant_id: 'tenant-1',
      service_type: 'redis',
      target_ips: ['10.0.0.1', '10.0.0.2'],
      reasoning: 'Known attacker IPs',
    })

    expect(createProposal).toHaveBeenCalledWith(
      mockEnv.DB,
      mockEnv,
      expect.objectContaining({
        action_payload: expect.objectContaining({
          target_ips: ['10.0.0.1', '10.0.0.2'],
        }),
      }),
    )
  })
})
