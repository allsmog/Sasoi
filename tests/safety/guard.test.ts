import { describe, it, expect, vi, beforeEach } from 'vitest'
import { SafetyGuard, checkRateLimit } from '../../src/safety/guard.js'

// Mock db module
vi.mock('../../src/clients/db.js', () => ({
  getTenantAgentConfig: vi.fn().mockResolvedValue({
    tenant_id: 'test-tenant',
    autonomy_level: 0,
    enabled_agents: ['enricher', 'investigator'],
    rate_limits: { enricher: 100, investigator: 20, strategist: 5, responder: 10 },
    responder_opt_in: false,
  }),
  createProposal: vi.fn().mockResolvedValue('proposal-123'),
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
  API_KEY: 'test-api-key',
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

  it('allows non-restricted tools', async () => {
    const result = await guard.preCheck({
      type: 'tool_execution_start',
      toolCallId: 'call-1',
      toolName: 'query_events',
      args: {},
    })
    expect(result.allowed).toBe(true)
  })

  it('blocks mutation tools at insufficient autonomy level', async () => {
    const result = await guard.preCheck({
      type: 'tool_execution_start',
      toolCallId: 'call-2',
      toolName: 'execute_deployment',
      args: { blueprint_id: 'bp-1' },
    })
    expect(result.allowed).toBe(false)
    if (!result.allowed) {
      expect(result.proposalId).toBe('proposal-123')
      expect(result.reason).toContain('Insufficient autonomy level')
    }
  })

  it('allows mutation tools at sufficient autonomy level', async () => {
    const { getTenantAgentConfig } = await import('../../src/clients/db.js')
    vi.mocked(getTenantAgentConfig).mockResolvedValueOnce({
      tenant_id: 'test-tenant',
      autonomy_level: 2,
      enabled_agents: ['enricher', 'investigator', 'strategist'],
      rate_limits: { enricher: 100, investigator: 20, strategist: 5, responder: 10 },
      responder_opt_in: false,
    })

    const result = await guard.preCheck({
      type: 'tool_execution_start',
      toolCallId: 'call-3',
      toolName: 'execute_deployment',
      args: { blueprint_id: 'bp-1' },
    })
    expect(result.allowed).toBe(true)
  })

  it('allows notification tools at level 0', async () => {
    const result = await guard.preCheck({
      type: 'tool_execution_start',
      toolCallId: 'call-4',
      toolName: 'trigger_notification',
      args: {},
    })
    expect(result.allowed).toBe(true)
  })

  it('logs tool execution via postCheck', async () => {
    const { logToolInvocation } = await import('../../src/clients/db.js')

    await guard.preCheck({
      type: 'tool_execution_start',
      toolCallId: 'call-5',
      toolName: 'query_events',
      args: {},
    })

    await guard.postCheck({
      type: 'tool_execution_end',
      toolCallId: 'call-5',
      toolName: 'query_events',
      result: { events: [] },
      isError: false,
    })

    expect(logToolInvocation).toHaveBeenCalledWith(
      mockEnv.DB,
      expect.objectContaining({
        session_id: 'session-123',
        tool_name: 'query_events',
        is_error: false,
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

describe('SafetyGuard mutation tools', () => {
  let guard: SafetyGuard

  beforeEach(() => {
    guard = new SafetyGuard({
      sessionId: 'session-123',
      agentType: 'strategist',
      tenantId: 'test-tenant',
      env: mockEnv,
    })
  })

  it('blocks deploy_honeytoken at autonomy < 2', async () => {
    const result = await guard.preCheck({
      type: 'tool_execution_start',
      toolCallId: 'call-ht',
      toolName: 'deploy_honeytoken',
      args: { tenant_id: 'test-tenant', token_type: 'api_key' },
    })
    expect(result.allowed).toBe(false)
    if (!result.allowed) {
      expect(result.proposalId).toBe('proposal-123')
    }
  })

  it('blocks block_ip at autonomy < 2', async () => {
    const result = await guard.preCheck({
      type: 'tool_execution_start',
      toolCallId: 'call-block',
      toolName: 'block_ip',
      args: { ip: '1.2.3.4' },
    })
    expect(result.allowed).toBe(false)
    if (!result.allowed) {
      expect(result.proposalId).toBe('proposal-123')
    }
  })

  it('blocks redirect_attacker at autonomy < 2', async () => {
    const result = await guard.preCheck({
      type: 'tool_execution_start',
      toolCallId: 'call-redirect',
      toolName: 'redirect_attacker',
      args: { attacker_ip: '1.2.3.4' },
    })
    expect(result.allowed).toBe(false)
    if (!result.allowed) {
      expect(result.proposalId).toBe('proposal-123')
    }
  })

  it('blocks deploy_cloud_decoy at autonomy < 2', async () => {
    const result = await guard.preCheck({
      type: 'tool_execution_start',
      toolCallId: 'call-cloud',
      toolName: 'deploy_cloud_decoy',
      args: { connector_id: 'conn-1' },
    })
    expect(result.allowed).toBe(false)
    if (!result.allowed) {
      expect(result.proposalId).toBe('proposal-123')
    }
  })

  it('blocks deploy_decoy_sa at autonomy < 2', async () => {
    const result = await guard.preCheck({
      type: 'tool_execution_start',
      toolCallId: 'call-sa',
      toolName: 'deploy_decoy_sa',
      args: { cluster_id: 'cluster-1' },
    })
    expect(result.allowed).toBe(false)
    if (!result.allowed) {
      expect(result.proposalId).toBe('proposal-123')
    }
  })
})
