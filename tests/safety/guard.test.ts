import { describe, it, expect, vi, beforeEach } from 'vitest'
import { SafetyGuard, checkRateLimit } from '../../src/safety/guard.js'

vi.mock('../../src/clients/db.js', () => ({
  logToolInvocation: vi.fn().mockResolvedValue(undefined),
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

describe('SafetyGuard', () => {
  let guard: SafetyGuard

  beforeEach(() => {
    guard = new SafetyGuard({
      sessionId: 'session-123',
      agentType: 'strategist',
      tenantId: 'test-tenant',
      env: mockEnv,
    })
  })

  it('records tool arguments for audit logging', async () => {
    const { logToolInvocation } = await import('../../src/clients/db.js')

    guard.preCheck({
      type: 'tool_execution_start',
      toolCallId: 'call-1',
      toolName: 'execute_deployment',
      args: { blueprint_id: 'bp-1', cluster_id: 'cluster-1' },
    })

    await guard.postCheck({
      type: 'tool_execution_end',
      toolCallId: 'call-1',
      toolName: 'execute_deployment',
      result: { ok: true },
      isError: false,
    })

    expect(logToolInvocation).toHaveBeenCalledWith(
      mockEnv.DB,
      expect.objectContaining({
        tool_name: 'execute_deployment',
        tool_args: { blueprint_id: 'bp-1', cluster_id: 'cluster-1' },
      }),
    )
  })
})

describe('checkRateLimit', () => {
  it('allows requests under limit', () => {
    expect(checkRateLimit('tenant-cf-1', 'enricher', 5)).toBe(true)
    expect(checkRateLimit('tenant-cf-1', 'enricher', 5)).toBe(true)
  })

  it('blocks requests over limit', () => {
    const tenantId = 'tenant-cf-2'
    for (let i = 0; i < 3; i++) checkRateLimit(tenantId, 'test', 3)
    expect(checkRateLimit(tenantId, 'test', 3)).toBe(false)
  })

  it('isolates by tenant and agent type', () => {
    expect(checkRateLimit('tenant-cf-3', 'enricher', 1)).toBe(true)
    expect(checkRateLimit('tenant-cf-3', 'investigator', 1)).toBe(true)
    expect(checkRateLimit('tenant-cf-4', 'enricher', 1)).toBe(true)
  })
})
