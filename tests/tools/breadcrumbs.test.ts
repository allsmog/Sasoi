import { describe, it, expect, vi, beforeEach } from 'vitest'

vi.mock('../../src/clients/db.js', () => ({
  queryDeploymentsByCluster: vi.fn().mockResolvedValue({ results: [] }),
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

describe('createGenerateBreadcrumbsTool', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('has correct metadata', async () => {
    const { createGenerateBreadcrumbsTool } = await import('../../src/tools/breadcrumbs.js')
    const tool = createGenerateBreadcrumbsTool(mockEnv)
    expect(tool.name).toBe('generate_breadcrumbs')
    expect(tool.label).toBe('Generate Breadcrumbs')
  })

  it('returns empty when no sibling deployments exist', async () => {
    const { createGenerateBreadcrumbsTool } = await import('../../src/tools/breadcrumbs.js')
    const tool = createGenerateBreadcrumbsTool(mockEnv)
    const result = await tool.execute('call-1', {
      tenant_id: 'tenant-1',
      source_deployment_id: 'dep-1',
    })
    expect(result.content[0].text).toContain('No sibling deployments')
    expect(result.details).toEqual({ count: 0 })
  })

  it('filters out source deployment from targets', async () => {
    const { queryDeploymentsByCluster } = await import('../../src/clients/db.js')
    vi.mocked(queryDeploymentsByCluster).mockResolvedValueOnce({
      results: [
        { deployment_id: 'dep-1', service_type: 'ssh', hostname: 'hp-source', tenant_id: 'tenant-1' },
        { deployment_id: 'dep-2', service_type: 'redis', hostname: 'hp-target', tenant_id: 'tenant-1', port: 6379 },
      ],
    } as never)

    const { createGenerateBreadcrumbsTool } = await import('../../src/tools/breadcrumbs.js')
    const tool = createGenerateBreadcrumbsTool(mockEnv)
    const result = await tool.execute('call-2', {
      tenant_id: 'tenant-1',
      source_deployment_id: 'dep-1',
    })
    const breadcrumbs = JSON.parse(result.content[0].text)
    // All breadcrumbs should reference dep-2, not dep-1
    for (const bc of breadcrumbs) {
      expect(bc.target_deployment_id).toBe('dep-2')
    }
  })

  it('respects max_breadcrumbs limit', async () => {
    const { queryDeploymentsByCluster } = await import('../../src/clients/db.js')
    vi.mocked(queryDeploymentsByCluster).mockResolvedValueOnce({
      results: [
        { deployment_id: 'dep-2', service_type: 'ssh', hostname: 'hp-2', tenant_id: 'tenant-1' },
        { deployment_id: 'dep-3', service_type: 'redis', hostname: 'hp-3', tenant_id: 'tenant-1' },
      ],
    } as never)

    const { createGenerateBreadcrumbsTool } = await import('../../src/tools/breadcrumbs.js')
    const tool = createGenerateBreadcrumbsTool(mockEnv)
    const result = await tool.execute('call-3', {
      tenant_id: 'tenant-1',
      source_deployment_id: 'dep-1',
      max_breadcrumbs: 2,
    })
    const breadcrumbs = JSON.parse(result.content[0].text)
    expect(breadcrumbs.length).toBeLessThanOrEqual(2)
  })

  it('generates type-appropriate content for SSH targets', async () => {
    const { queryDeploymentsByCluster } = await import('../../src/clients/db.js')
    vi.mocked(queryDeploymentsByCluster).mockResolvedValueOnce({
      results: [
        { deployment_id: 'dep-2', service_type: 'ssh', hostname: 'hp-target', tenant_id: 'tenant-1', port: 22 },
      ],
    } as never)

    const { createGenerateBreadcrumbsTool } = await import('../../src/tools/breadcrumbs.js')
    const tool = createGenerateBreadcrumbsTool(mockEnv)
    const result = await tool.execute('call-4', {
      tenant_id: 'tenant-1',
      source_deployment_id: 'dep-1',
      breadcrumb_types: ['ssh_config'],
    })
    const breadcrumbs = JSON.parse(result.content[0].text)
    expect(breadcrumbs.length).toBe(1)
    expect(breadcrumbs[0].type).toBe('ssh_config')
    expect(breadcrumbs[0].content).toContain('Host')
    expect(breadcrumbs[0].placement_path).toBe('~/.ssh/config')
  })

  it('passes cluster_id to DB query', async () => {
    const { queryDeploymentsByCluster } = await import('../../src/clients/db.js')
    vi.mocked(queryDeploymentsByCluster).mockResolvedValueOnce({ results: [] } as never)

    const { createGenerateBreadcrumbsTool } = await import('../../src/tools/breadcrumbs.js')
    const tool = createGenerateBreadcrumbsTool(mockEnv)
    await tool.execute('call-5', {
      tenant_id: 'tenant-1',
      source_deployment_id: 'dep-1',
      cluster_id: 'cluster-1',
    })

    expect(queryDeploymentsByCluster).toHaveBeenCalledWith(
      mockEnv.DB,
      'tenant-1',
      'cluster-1',
    )
  })

  it('generates multiple breadcrumb types per target', async () => {
    const { queryDeploymentsByCluster } = await import('../../src/clients/db.js')
    vi.mocked(queryDeploymentsByCluster).mockResolvedValueOnce({
      results: [
        { deployment_id: 'dep-2', service_type: 'mysql', hostname: 'db-1', tenant_id: 'tenant-1' },
      ],
    } as never)

    const { createGenerateBreadcrumbsTool } = await import('../../src/tools/breadcrumbs.js')
    const tool = createGenerateBreadcrumbsTool(mockEnv)
    const result = await tool.execute('call-6', {
      tenant_id: 'tenant-1',
      source_deployment_id: 'dep-1',
      breadcrumb_types: ['bash_history', 'cached_credentials'],
      max_breadcrumbs: 10,
    })
    const breadcrumbs = JSON.parse(result.content[0].text)
    expect(breadcrumbs.length).toBe(2)
    const types = breadcrumbs.map((b: { type: string }) => b.type)
    expect(types).toContain('bash_history')
    expect(types).toContain('cached_credentials')
  })

  it('handles empty fleet gracefully', async () => {
    const { queryDeploymentsByCluster } = await import('../../src/clients/db.js')
    vi.mocked(queryDeploymentsByCluster).mockResolvedValueOnce({ results: [] } as never)

    const { createGenerateBreadcrumbsTool } = await import('../../src/tools/breadcrumbs.js')
    const tool = createGenerateBreadcrumbsTool(mockEnv)
    const result = await tool.execute('call-7', {
      tenant_id: 'tenant-1',
      source_deployment_id: 'dep-1',
    })
    expect(result.content[0].text).toContain('No sibling deployments')
  })
})
