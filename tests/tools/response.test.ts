import { describe, it, expect, vi, beforeEach } from 'vitest'

vi.mock('../../src/clients/db.js', () => ({
  insertResponseAction: vi.fn().mockResolvedValue('action-123'),
}))
vi.mock('../../src/clients/orchestrator.js', () => ({
  blockIP: vi.fn().mockResolvedValue(undefined),
  redirectAttacker: vi.fn().mockResolvedValue(undefined),
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

describe('createBlockIPTool', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('has correct metadata', async () => {
    const { createBlockIPTool } = await import('../../src/tools/response.js')
    const tool = createBlockIPTool(mockEnv)
    expect(tool.name).toBe('block_ip')
    expect(tool.label).toBe('Block IP')
  })

  it('caps TTL at 86400 when higher value passed', async () => {
    const { createBlockIPTool } = await import('../../src/tools/response.js')
    const { blockIP } = await import('../../src/clients/orchestrator.js')
    const tool = createBlockIPTool(mockEnv)

    const result = await tool.execute('call-1', {
      tenant_id: 'tenant-1',
      ip: '10.0.0.1',
      cluster_id: 'cluster-1',
      ttl_seconds: 999999,
      reason: 'test block',
    })

    expect(blockIP).toHaveBeenCalledWith(mockEnv, {
      ip: '10.0.0.1',
      cluster_id: 'cluster-1',
      ttl_seconds: 86400,
    })

    const data = JSON.parse(result.content[0].text)
    expect(data.ttl_seconds).toBe(86400)
  })

  it('uses default TTL of 3600 when not specified', async () => {
    const { createBlockIPTool } = await import('../../src/tools/response.js')
    const { blockIP } = await import('../../src/clients/orchestrator.js')
    const tool = createBlockIPTool(mockEnv)

    await tool.execute('call-2', {
      tenant_id: 'tenant-1',
      ip: '10.0.0.2',
      cluster_id: 'cluster-1',
      reason: 'test block',
    })

    expect(blockIP).toHaveBeenCalledWith(mockEnv, {
      ip: '10.0.0.2',
      cluster_id: 'cluster-1',
      ttl_seconds: 3600,
    })
  })

  it('rejects invalid IPv4 address', async () => {
    const { createBlockIPTool } = await import('../../src/tools/response.js')
    const { blockIP } = await import('../../src/clients/orchestrator.js')
    const tool = createBlockIPTool(mockEnv)

    const result = await tool.execute('call-invalid-1', {
      tenant_id: 'tenant-1',
      ip: '999.999.999.999',
      cluster_id: 'cluster-1',
      reason: 'test',
    })

    const data = JSON.parse(result.content[0].text)
    expect(data.error).toContain('Invalid IP')
    expect(blockIP).not.toHaveBeenCalled()
  })

  it('rejects hostname strings', async () => {
    const { createBlockIPTool } = await import('../../src/tools/response.js')
    const { blockIP } = await import('../../src/clients/orchestrator.js')
    const tool = createBlockIPTool(mockEnv)

    const result = await tool.execute('call-invalid-2', {
      tenant_id: 'tenant-1',
      ip: 'my-service.internal',
      cluster_id: 'cluster-1',
      reason: 'test',
    })

    const data = JSON.parse(result.content[0].text)
    expect(data.error).toContain('Invalid IP')
    expect(blockIP).not.toHaveBeenCalled()
  })

  it('rejects empty string IP', async () => {
    const { createBlockIPTool } = await import('../../src/tools/response.js')
    const tool = createBlockIPTool(mockEnv)

    const result = await tool.execute('call-invalid-3', {
      tenant_id: 'tenant-1',
      ip: '',
      cluster_id: 'cluster-1',
      reason: 'test',
    })

    expect(result.details).toEqual({ error: 'invalid_ip' })
  })

  it('accepts valid IPv6 address', async () => {
    const { createBlockIPTool } = await import('../../src/tools/response.js')
    const { blockIP } = await import('../../src/clients/orchestrator.js')
    const tool = createBlockIPTool(mockEnv)

    await tool.execute('call-ipv6', {
      tenant_id: 'tenant-1',
      ip: '2001:db8::1',
      cluster_id: 'cluster-1',
      reason: 'test',
    })

    expect(blockIP).toHaveBeenCalledWith(mockEnv, expect.objectContaining({ ip: '2001:db8::1' }))
  })

  it('persists action in DB via insertResponseAction', async () => {
    const { createBlockIPTool } = await import('../../src/tools/response.js')
    const { insertResponseAction } = await import('../../src/clients/db.js')
    const tool = createBlockIPTool(mockEnv)

    const result = await tool.execute('call-3', {
      tenant_id: 'tenant-1',
      ip: '10.0.0.3',
      cluster_id: 'cluster-1',
      ttl_seconds: 600,
      reason: 'suspicious activity',
    })

    expect(insertResponseAction).toHaveBeenCalledWith(
      mockEnv.DB,
      expect.objectContaining({
        tenant_id: 'tenant-1',
        action_type: 'block_ip',
        target: '10.0.0.3',
        ttl_seconds: 600,
      }),
    )

    const data = JSON.parse(result.content[0].text)
    expect(data.action_id).toBe('action-123')
  })
})

describe('createRedirectAttackerTool', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('calls orchestrator with correct params', async () => {
    const { createRedirectAttackerTool } = await import('../../src/tools/response.js')
    const { redirectAttacker } = await import('../../src/clients/orchestrator.js')
    const tool = createRedirectAttackerTool(mockEnv)

    const result = await tool.execute('call-4', {
      tenant_id: 'tenant-1',
      source_deployment_id: 'dep-low',
      target_deployment_id: 'dep-high',
      attacker_ip: '192.168.1.100',
      reason: 'escalate monitoring',
    })

    expect(redirectAttacker).toHaveBeenCalledWith(mockEnv, {
      source_deployment_id: 'dep-low',
      target_deployment_id: 'dep-high',
      attacker_ip: '192.168.1.100',
    })

    const data = JSON.parse(result.content[0].text)
    expect(data.attacker_ip).toBe('192.168.1.100')
    expect(data.from).toBe('dep-low')
    expect(data.to).toBe('dep-high')
  })

  it('rejects invalid attacker IP', async () => {
    const { createRedirectAttackerTool } = await import('../../src/tools/response.js')
    const { redirectAttacker } = await import('../../src/clients/orchestrator.js')
    const tool = createRedirectAttackerTool(mockEnv)

    const result = await tool.execute('call-invalid-redir', {
      tenant_id: 'tenant-1',
      source_deployment_id: 'dep-low',
      target_deployment_id: 'dep-high',
      attacker_ip: 'not-an-ip',
      reason: 'test',
    })

    const data = JSON.parse(result.content[0].text)
    expect(data.error).toContain('Invalid IP')
    expect(redirectAttacker).not.toHaveBeenCalled()
  })

  it('persists action in DB', async () => {
    const { createRedirectAttackerTool } = await import('../../src/tools/response.js')
    const { insertResponseAction } = await import('../../src/clients/db.js')
    const tool = createRedirectAttackerTool(mockEnv)

    const result = await tool.execute('call-5', {
      tenant_id: 'tenant-1',
      source_deployment_id: 'dep-low',
      target_deployment_id: 'dep-high',
      attacker_ip: '192.168.1.100',
      reason: 'escalate monitoring',
    })

    expect(insertResponseAction).toHaveBeenCalledWith(
      mockEnv.DB,
      expect.objectContaining({
        tenant_id: 'tenant-1',
        action_type: 'redirect_attacker',
        target: '192.168.1.100',
      }),
    )

    const data = JSON.parse(result.content[0].text)
    expect(data.action_id).toBe('action-123')
  })
})
