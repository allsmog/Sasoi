import { describe, it, expect, vi, beforeEach } from 'vitest'

vi.mock('../../src/clients/db.js', () => ({
  insertHoneytoken: vi.fn().mockResolvedValue('ht-sa-123'),
}))
vi.mock('../../src/clients/orchestrator.js', () => ({
  createServiceAccount: vi.fn().mockResolvedValue({ token: 'k8s-token-xyz' }),
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

describe('createDeployDecoyServiceAccountTool', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('generates SA name when not provided', async () => {
    const { createDeployDecoyServiceAccountTool } = await import('../../src/tools/identity-deception.js')
    const tool = createDeployDecoyServiceAccountTool(mockEnv)
    const result = await tool.execute('call-1', {
      tenant_id: 'tenant-1',
      cluster_id: 'cluster-1',
      namespace: 'default',
    })

    const data = JSON.parse(result.content[0].text)
    expect(data.service_account_name).toMatch(/^svc-/)
  })

  it('uses provided SA name', async () => {
    const { createDeployDecoyServiceAccountTool } = await import('../../src/tools/identity-deception.js')
    const tool = createDeployDecoyServiceAccountTool(mockEnv)
    const result = await tool.execute('call-2', {
      tenant_id: 'tenant-1',
      cluster_id: 'cluster-1',
      namespace: 'default',
      service_account_name: 'my-custom-sa',
    })

    const data = JSON.parse(result.content[0].text)
    expect(data.service_account_name).toBe('my-custom-sa')
  })

  it('calls orchestrator.createServiceAccount with correct params', async () => {
    const { createDeployDecoyServiceAccountTool } = await import('../../src/tools/identity-deception.js')
    const { createServiceAccount } = await import('../../src/clients/orchestrator.js')
    const tool = createDeployDecoyServiceAccountTool(mockEnv)

    await tool.execute('call-3', {
      tenant_id: 'tenant-1',
      cluster_id: 'cluster-1',
      namespace: 'production',
      service_account_name: 'svc-decoy',
    })

    expect(createServiceAccount).toHaveBeenCalledWith(mockEnv, {
      cluster_id: 'cluster-1',
      namespace: 'production',
      name: 'svc-decoy',
    })
  })

  it('stores as k8s_service_account honeytoken type via insertHoneytoken', async () => {
    const { createDeployDecoyServiceAccountTool } = await import('../../src/tools/identity-deception.js')
    const { insertHoneytoken } = await import('../../src/clients/db.js')
    const tool = createDeployDecoyServiceAccountTool(mockEnv)

    await tool.execute('call-4', {
      tenant_id: 'tenant-1',
      cluster_id: 'cluster-1',
      namespace: 'production',
      service_account_name: 'svc-decoy',
    })

    expect(insertHoneytoken).toHaveBeenCalledWith(
      mockEnv.DB,
      expect.objectContaining({
        tenant_id: 'tenant-1',
        token_type: 'k8s_service_account',
        token_value: 'k8s-token-xyz',
        deployment_method: 'k8s_secret',
        cluster_id: 'cluster-1',
        namespace: 'production',
      }),
    )
  })
})
