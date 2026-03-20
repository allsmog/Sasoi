import { describe, it, expect, vi, beforeEach } from 'vitest'

vi.mock('../../src/clients/db.js', () => ({
  insertHoneytoken: vi.fn().mockResolvedValue('ht-123'),
  queryHoneytokens: vi.fn().mockResolvedValue({ results: [] }),
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

describe('createDeployHoneytokenTool', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('has correct metadata', async () => {
    const { createDeployHoneytokenTool } = await import('../../src/tools/honeytokens.js')
    const tool = createDeployHoneytokenTool(mockEnv)
    expect(tool.name).toBe('deploy_honeytoken')
    expect(tool.label).toBe('Deploy Honeytoken')
  })

  it('generates aws_access_key format correctly', async () => {
    const { createDeployHoneytokenTool } = await import('../../src/tools/honeytokens.js')
    const { insertHoneytoken } = await import('../../src/clients/db.js')
    const tool = createDeployHoneytokenTool(mockEnv)

    await tool.execute('call-1', {
      tenant_id: 'tenant-1',
      token_type: 'aws_access_key',
      deployment_method: 'k8s_secret',
    })

    expect(insertHoneytoken).toHaveBeenCalledWith(
      mockEnv.DB,
      expect.objectContaining({
        tenant_id: 'tenant-1',
        token_type: 'aws_access_key',
        deployment_method: 'k8s_secret',
      }),
    )

    const call = vi.mocked(insertHoneytoken).mock.calls[0]
    expect(call[1].token_value).toMatch(/^AKIA[A-Za-z0-9]{16}$/)
  })

  it('generates api_key format correctly', async () => {
    const { createDeployHoneytokenTool } = await import('../../src/tools/honeytokens.js')
    const { insertHoneytoken } = await import('../../src/clients/db.js')
    const tool = createDeployHoneytokenTool(mockEnv)

    await tool.execute('call-2', {
      tenant_id: 'tenant-1',
      token_type: 'api_key',
      deployment_method: 'env_var',
    })

    const call = vi.mocked(insertHoneytoken).mock.calls[0]
    expect(call[1].token_value).toMatch(/^sk-/)
  })

  it('generates github_pat format correctly', async () => {
    const { createDeployHoneytokenTool } = await import('../../src/tools/honeytokens.js')
    const { insertHoneytoken } = await import('../../src/clients/db.js')
    const tool = createDeployHoneytokenTool(mockEnv)

    await tool.execute('call-3', {
      tenant_id: 'tenant-1',
      token_type: 'github_pat',
      deployment_method: 'k8s_secret',
    })

    const call = vi.mocked(insertHoneytoken).mock.calls[0]
    expect(call[1].token_value).toMatch(/^ghp_[A-Za-z0-9]{36}$/)
  })

  it('generates db_connection_string format correctly', async () => {
    const { createDeployHoneytokenTool } = await import('../../src/tools/honeytokens.js')
    const { insertHoneytoken } = await import('../../src/clients/db.js')
    const tool = createDeployHoneytokenTool(mockEnv)

    await tool.execute('call-4', {
      tenant_id: 'tenant-1',
      token_type: 'db_connection_string',
      deployment_method: 'config_map',
    })

    const call = vi.mocked(insertHoneytoken).mock.calls[0]
    expect(call[1].token_value).toMatch(/^postgresql:\/\//)
  })

  it('stores honeytoken in DB and returns details', async () => {
    const { createDeployHoneytokenTool } = await import('../../src/tools/honeytokens.js')
    const tool = createDeployHoneytokenTool(mockEnv)
    const result = await tool.execute('call-5', {
      tenant_id: 'tenant-1',
      token_type: 'jwt_secret',
      deployment_method: 'k8s_secret',
      cluster_id: 'cluster-1',
      namespace: 'production',
      placement_reasoning: 'Near database services',
    })

    const data = JSON.parse(result.content[0].text)
    expect(data.honeytoken_id).toBe('ht-123')
    expect(data.status).toBe('active')
    expect(result.details).toEqual({ honeytoken_id: 'ht-123', token_type: 'jwt_secret' })
  })

  it('generates slack_webhook format correctly', async () => {
    const { createDeployHoneytokenTool } = await import('../../src/tools/honeytokens.js')
    const { insertHoneytoken } = await import('../../src/clients/db.js')
    const tool = createDeployHoneytokenTool(mockEnv)

    await tool.execute('call-6', {
      tenant_id: 'tenant-1',
      token_type: 'slack_webhook',
      deployment_method: 'env_var',
    })

    const call = vi.mocked(insertHoneytoken).mock.calls[0]
    expect(call[1].token_value).toMatch(/^https:\/\/hooks\.slack\.com\/services\//)
  })
  it('rejects unknown token_type', async () => {
    const { createDeployHoneytokenTool } = await import('../../src/tools/honeytokens.js')
    const { insertHoneytoken } = await import('../../src/clients/db.js')
    const tool = createDeployHoneytokenTool(mockEnv)

    const result = await tool.execute('call-invalid-type', {
      tenant_id: 'tenant-1',
      token_type: 'totally_fake_type',
      deployment_method: 'k8s_secret',
    })

    const data = JSON.parse(result.content[0].text)
    expect(data.error).toContain('Unknown token_type')
    expect(result.details).toEqual({ error: 'invalid_token_type' })
    expect(insertHoneytoken).not.toHaveBeenCalled()
  })
})

describe('createQueryHoneytokensTool', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('has correct metadata', async () => {
    const { createQueryHoneytokensTool } = await import('../../src/tools/honeytokens.js')
    const tool = createQueryHoneytokensTool(mockEnv)
    expect(tool.name).toBe('query_honeytokens')
  })

  it('queries honeytokens for tenant and redacts token_value', async () => {
    const { queryHoneytokens } = await import('../../src/clients/db.js')
    vi.mocked(queryHoneytokens).mockResolvedValueOnce({
      results: [{ honeytoken_id: 'ht-1', token_type: 'api_key', token_value: 'sk-secret-key-123', status: 'active' }],
    } as never)

    const { createQueryHoneytokensTool } = await import('../../src/tools/honeytokens.js')
    const tool = createQueryHoneytokensTool(mockEnv)
    const result = await tool.execute('call-1', { tenant_id: 'tenant-1' })

    const data = JSON.parse(result.content[0].text)
    expect(data).toHaveLength(1)
    expect(data[0].honeytoken_id).toBe('ht-1')
    expect(data[0]).not.toHaveProperty('token_value')
    expect(queryHoneytokens).toHaveBeenCalledWith(mockEnv.DB, 'tenant-1', undefined)
  })

  it('passes status filter', async () => {
    const { queryHoneytokens } = await import('../../src/clients/db.js')
    vi.mocked(queryHoneytokens).mockResolvedValueOnce({ results: [] } as never)

    const { createQueryHoneytokensTool } = await import('../../src/tools/honeytokens.js')
    const tool = createQueryHoneytokensTool(mockEnv)
    await tool.execute('call-2', { tenant_id: 'tenant-1', status: 'accessed' })

    expect(queryHoneytokens).toHaveBeenCalledWith(mockEnv.DB, 'tenant-1', 'accessed')
  })
})
