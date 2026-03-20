import { describe, it, expect, vi, beforeEach } from 'vitest'

vi.mock('../../src/clients/blueprint.js', () => ({
  generatePersona: vi.fn().mockResolvedValue({ persona: { service: 'ssh', egress: 'deny', sandbox: true, user: 'honeypot' }, buildPlan: {}, safety_validated: true }),
  generateVariation: vi.fn().mockResolvedValue({ variation: { id: 'var-1' } }),
}))
vi.mock('../../src/clients/orchestrator.js', () => ({
  rotatePersona: vi.fn().mockResolvedValue(undefined),
}))
vi.mock('../../src/safety/schemas.js', () => ({
  validatePersonaSafety: vi.fn().mockReturnValue({ valid: true, violations: [] }),
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

describe('createGeneratePersonaTool', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('calls blueprint client with params', async () => {
    const blueprintClient = await import('../../src/clients/blueprint.js')

    const { createGeneratePersonaTool } = await import('../../src/tools/persona.js')
    const tool = createGeneratePersonaTool(mockEnv)
    const result = await tool.execute('call-1', {
      service_type: 'ssh',
      complexity: 'high',
    })

    expect(blueprintClient.generatePersona).toHaveBeenCalledWith(
      mockEnv,
      expect.objectContaining({
        service_type: 'ssh',
        complexity: 'high',
      }),
    )
    expect(result.details).toEqual({ safe: true, service_type: 'ssh' })
  })

  it('rejects unsafe persona', async () => {
    const { validatePersonaSafety } = await import('../../src/safety/schemas.js')
    vi.mocked(validatePersonaSafety).mockReturnValueOnce({ valid: false, violations: ['egress not denied', 'running as root'] })

    const { createGeneratePersonaTool } = await import('../../src/tools/persona.js')
    const tool = createGeneratePersonaTool(mockEnv)
    const result = await tool.execute('call-2', {
      service_type: 'http',
    })

    expect(result.content[0].text).toContain('unsafe persona')
    expect(result.content[0].text).toContain('egress not denied')
    expect(result.details).toEqual({ safe: false, violations: ['egress not denied', 'running as root'] })
  })
})

describe('createRotatePersonaTool', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('calls orchestrator with deployment_id', async () => {
    const orchestratorClient = await import('../../src/clients/orchestrator.js')

    const { createRotatePersonaTool } = await import('../../src/tools/persona.js')
    const tool = createRotatePersonaTool(mockEnv)
    const result = await tool.execute('call-3', {
      deployment_id: 'dep-42',
    })

    expect(orchestratorClient.rotatePersona).toHaveBeenCalledWith(mockEnv, 'dep-42')
    expect(result.content[0].text).toContain('dep-42')
    expect(result.details).toEqual({ deployment_id: 'dep-42' })
  })
})
