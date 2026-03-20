import { describe, it, expect, vi, beforeEach } from 'vitest'

vi.mock('../../src/clients/db.js', () => ({
  queryDestinations: vi.fn().mockResolvedValue({ results: [] }),
  updateDeploymentMetadata: vi.fn().mockResolvedValue(undefined),
}))
vi.mock('../../src/tools/siem.js', () => ({
  formatForDestination: vi.fn().mockReturnValue('formatted-output'),
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

const mockDestinations = [
  { type: 'slack', config_ref: 'https://hooks.slack.com/test', format_type: null },
  { type: 'webhook', config_ref: 'https://webhook.test', format_type: 'cef' },
]

describe('createTriggerNotificationTool', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: true }))
  })

  it('sends to all destinations when channel is all', async () => {
    const { queryDestinations } = await import('../../src/clients/db.js')
    vi.mocked(queryDestinations).mockResolvedValueOnce({ results: mockDestinations } as never)

    const { createTriggerNotificationTool } = await import('../../src/tools/notification.js')
    const tool = createTriggerNotificationTool(mockEnv)
    const result = await tool.execute('call-1', {
      tenant_id: 'tenant-1',
      severity: 'critical',
      title: 'Intrusion Detected',
      message: 'Brute force from 1.2.3.4',
      channel: 'all',
    })

    expect(fetch).toHaveBeenCalledTimes(2)
    expect(result.details).toEqual({ sent: ['slack', 'webhook'] })
  })

  it('filters destinations by channel type', async () => {
    const { queryDestinations } = await import('../../src/clients/db.js')
    vi.mocked(queryDestinations).mockResolvedValueOnce({ results: mockDestinations } as never)

    const { createTriggerNotificationTool } = await import('../../src/tools/notification.js')
    const tool = createTriggerNotificationTool(mockEnv)
    const result = await tool.execute('call-2', {
      tenant_id: 'tenant-1',
      severity: 'warning',
      title: 'Suspicious Activity',
      message: 'Port scan detected',
      channel: 'slack',
    })

    expect(fetch).toHaveBeenCalledTimes(1)
    expect(result.details).toEqual({ sent: ['slack'] })
  })

  it('uses SIEM format when destination has format_type', async () => {
    const { queryDestinations } = await import('../../src/clients/db.js')
    vi.mocked(queryDestinations).mockResolvedValueOnce({ results: mockDestinations } as never)

    const { formatForDestination } = await import('../../src/tools/siem.js')

    const { createTriggerNotificationTool } = await import('../../src/tools/notification.js')
    const tool = createTriggerNotificationTool(mockEnv)
    await tool.execute('call-3', {
      tenant_id: 'tenant-1',
      severity: 'high',
      title: 'Alert',
      message: 'Test message',
      channel: 'all',
    })

    expect(formatForDestination).toHaveBeenCalledWith(
      'cef',
      expect.objectContaining({
        signal: 'Alert',
        severity: 'high',
      }),
    )
  })
})

describe('createIncreaseLoggingDepthTool', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('updates deployment metadata with logging override', async () => {
    const { updateDeploymentMetadata } = await import('../../src/clients/db.js')

    const { createIncreaseLoggingDepthTool } = await import('../../src/tools/notification.js')
    const tool = createIncreaseLoggingDepthTool(mockEnv)
    const result = await tool.execute('call-4', {
      deployment_id: 'dep-1',
      level: 'verbose',
      duration_minutes: 30,
      reason: 'Active investigation',
    })

    expect(updateDeploymentMetadata).toHaveBeenCalledWith(
      mockEnv.DB,
      'dep-1',
      expect.objectContaining({
        logging_override: expect.objectContaining({
          level: 'verbose',
          reason: 'Active investigation',
        }),
      }),
    )
    expect(result.content[0].text).toContain('dep-1')
    expect(result.details).toEqual({ deployment_id: 'dep-1' })
  })

  it('caps duration at 60 minutes', async () => {
    const { createIncreaseLoggingDepthTool } = await import('../../src/tools/notification.js')
    const tool = createIncreaseLoggingDepthTool(mockEnv)

    // The Zod schema has maximum: 60, so we verify the tool schema enforces it
    expect(tool.parameters.properties.duration_minutes.maximum).toBe(60)
  })
})
