import { describe, it, expect, vi, beforeEach } from 'vitest'

vi.mock('../../src/clients/db.js', () => ({
  getCloudConnector: vi.fn(),
  insertCloudDecoy: vi.fn().mockResolvedValue('decoy-123'),
}))
vi.mock('../../src/clients/orchestrator.js', () => ({
  createCloudDecoy: vi.fn().mockResolvedValue({ resource_ref: 'arn:aws:s3:::decoy-bucket', monitoring_status: 'active' }),
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

const validConnector = {
  connector_id: 'conn-1',
  tenant_id: 'tenant-1',
  provider: 'aws',
  status: 'active',
  enabled_regions: '["us-east-1"]',
  allowed_decoy_types: '["s3_bucket","iam_role"]',
}

describe('createDeployCloudDecoyTool', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('returns error when connector not found', async () => {
    const { getCloudConnector } = await import('../../src/clients/db.js')
    vi.mocked(getCloudConnector).mockResolvedValueOnce(null)

    const { createDeployCloudDecoyTool } = await import('../../src/tools/cloud-deception.js')
    const tool = createDeployCloudDecoyTool(mockEnv)
    const result = await tool.execute('call-1', {
      tenant_id: 'tenant-1',
      connector_id: 'conn-missing',
      decoy_type: 's3_bucket',
    })

    expect(result.content[0].text).toContain('Cloud connector not found')
    expect(result.details).toEqual({ error: 'connector_not_found' })
  })

  it('returns error when tenant mismatch', async () => {
    const { getCloudConnector } = await import('../../src/clients/db.js')
    vi.mocked(getCloudConnector).mockResolvedValueOnce({
      ...validConnector,
      tenant_id: 'other-tenant',
    })

    const { createDeployCloudDecoyTool } = await import('../../src/tools/cloud-deception.js')
    const tool = createDeployCloudDecoyTool(mockEnv)
    const result = await tool.execute('call-2', {
      tenant_id: 'tenant-1',
      connector_id: 'conn-1',
      decoy_type: 's3_bucket',
    })

    expect(result.content[0].text).toContain('does not belong to this tenant')
    expect(result.details).toEqual({ error: 'tenant_mismatch' })
  })

  it('returns error when connector inactive', async () => {
    const { getCloudConnector } = await import('../../src/clients/db.js')
    vi.mocked(getCloudConnector).mockResolvedValueOnce({
      ...validConnector,
      status: 'disabled',
    })

    const { createDeployCloudDecoyTool } = await import('../../src/tools/cloud-deception.js')
    const tool = createDeployCloudDecoyTool(mockEnv)
    const result = await tool.execute('call-3', {
      tenant_id: 'tenant-1',
      connector_id: 'conn-1',
      decoy_type: 's3_bucket',
    })

    expect(result.content[0].text).toContain('not active')
    expect(result.details).toEqual({ error: 'connector_inactive' })
  })

  it('returns error when region not in allowlist', async () => {
    const { getCloudConnector } = await import('../../src/clients/db.js')
    vi.mocked(getCloudConnector).mockResolvedValueOnce(validConnector)

    const { createDeployCloudDecoyTool } = await import('../../src/tools/cloud-deception.js')
    const tool = createDeployCloudDecoyTool(mockEnv)
    const result = await tool.execute('call-4', {
      tenant_id: 'tenant-1',
      connector_id: 'conn-1',
      decoy_type: 's3_bucket',
      region: 'eu-west-1',
    })

    expect(result.content[0].text).toContain('not in connector\'s allowed regions')
    expect(result.details).toEqual({ error: 'region_not_allowed' })
  })

  it('returns error when decoy type not in allowed types', async () => {
    const { getCloudConnector } = await import('../../src/clients/db.js')
    vi.mocked(getCloudConnector).mockResolvedValueOnce(validConnector)

    const { createDeployCloudDecoyTool } = await import('../../src/tools/cloud-deception.js')
    const tool = createDeployCloudDecoyTool(mockEnv)
    const result = await tool.execute('call-5', {
      tenant_id: 'tenant-1',
      connector_id: 'conn-1',
      decoy_type: 'lambda_function',
      region: 'us-east-1',
    })

    expect(result.content[0].text).toContain('not in connector\'s allowed types')
    expect(result.details).toEqual({ error: 'decoy_type_not_allowed' })
  })

  it('deploys successfully with valid params', async () => {
    const { getCloudConnector } = await import('../../src/clients/db.js')
    vi.mocked(getCloudConnector).mockResolvedValueOnce(validConnector)

    const { createDeployCloudDecoyTool } = await import('../../src/tools/cloud-deception.js')
    const tool = createDeployCloudDecoyTool(mockEnv)
    const result = await tool.execute('call-6', {
      tenant_id: 'tenant-1',
      connector_id: 'conn-1',
      decoy_type: 's3_bucket',
      region: 'us-east-1',
    })

    const data = JSON.parse(result.content[0].text)
    expect(data.decoy_id).toBe('decoy-123')
    expect(data.provider).toBe('aws')
    expect(data.decoy_type).toBe('s3_bucket')
    expect(data.resource_ref).toBe('arn:aws:s3:::decoy-bucket')
    expect(data.monitoring_status).toBe('active')
    expect(result.details).toEqual({ decoy_id: 'decoy-123', provider: 'aws' })
  })

  it('stores decoy in DB after successful deployment', async () => {
    const { getCloudConnector, insertCloudDecoy } = await import('../../src/clients/db.js')
    vi.mocked(getCloudConnector).mockResolvedValueOnce(validConnector)

    const { createDeployCloudDecoyTool } = await import('../../src/tools/cloud-deception.js')
    const tool = createDeployCloudDecoyTool(mockEnv)
    await tool.execute('call-7', {
      tenant_id: 'tenant-1',
      connector_id: 'conn-1',
      decoy_type: 's3_bucket',
      region: 'us-east-1',
    })

    expect(insertCloudDecoy).toHaveBeenCalledWith(
      mockEnv.DB,
      expect.objectContaining({
        tenant_id: 'tenant-1',
        connector_id: 'conn-1',
        provider: 'aws',
        decoy_type: 's3_bucket',
        resource_ref: 'arn:aws:s3:::decoy-bucket',
        region: 'us-east-1',
        monitoring_status: 'active',
      }),
    )
  })
})
