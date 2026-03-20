import { describe, it, expect, vi, beforeEach } from 'vitest'

vi.mock('../../src/clients/db.js', () => ({
  insertInvestigation: vi.fn().mockResolvedValue('inv-123'),
  insertCampaign: vi.fn().mockResolvedValue('camp-456'),
  getInvestigation: vi.fn().mockResolvedValue({
    investigation_id: 'inv-789',
    title: 'Redis Exploitation Campaign',
    severity: 'critical',
    status: 'open',
    summary: 'Attackers exploiting exposed Redis instances',
    findings: JSON.stringify([{ type: 'exploitation', description: 'Redis CONFIG SET used for RCE' }]),
    iocs: JSON.stringify([{ type: 'ip', value: '10.0.0.5', context: 'C2 server' }]),
    mitre_techniques: JSON.stringify(['T1190', 'T1059']),
    event_ids: JSON.stringify(['evt-10', 'evt-11']),
    created_at: '2025-01-01T00:00:00Z',
  }),
  updateInvestigationReport: vi.fn().mockResolvedValue(undefined),
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

describe('createCreateInvestigationTool', () => {
  beforeEach(() => { vi.clearAllMocks() })

  it('creates an investigation record', async () => {
    const { createCreateInvestigationTool } = await import('../../src/tools/investigation.js')
    const tool = createCreateInvestigationTool(mockEnv)

    const result = await tool.execute('call-1', {
      tenant_id: 'tenant-1',
      title: 'SSH Brute Force Campaign',
      summary: 'Coordinated brute force attack',
      severity: 'high',
      findings: [{ type: 'credential_spray', description: 'Multiple IPs attempting same creds' }],
      iocs: [{ type: 'ip', value: '192.168.1.1', context: 'Primary attacker' }],
      mitre_techniques: ['T1110', 'T1078'],
      event_ids: ['evt-1', 'evt-2'],
    })

    const text = (result.content[0] as { type: string; text: string }).text
    expect(text).toContain('inv-123')
  })
})

describe('createFlagCampaignTool', () => {
  it('creates a campaign record', async () => {
    const { createFlagCampaignTool } = await import('../../src/tools/investigation.js')
    const tool = createFlagCampaignTool(mockEnv)

    const result = await tool.execute('call-2', {
      tenant_id: 'tenant-1',
      name: 'Operation ShadowForce',
      description: 'Multi-stage campaign',
      attacker_ips: ['10.0.0.1', '10.0.0.2'],
      affected_honeypots: ['deploy-1', 'deploy-2'],
      event_ids: ['evt-1', 'evt-2'],
      mitre_chain: ['T1046', 'T1110'],
      confidence: 0.85,
    })

    const text = (result.content[0] as { type: string; text: string }).text
    expect(text).toContain('camp-456')
  })
})

describe('createGenerateReportTool', () => {
  it('generates markdown report', async () => {
    const { createGenerateReportTool } = await import('../../src/tools/investigation.js')
    const tool = createGenerateReportTool(mockEnv)

    const result = await tool.execute('call-3', { investigation_id: 'inv-789' })

    const text = (result.content[0] as { type: string; text: string }).text
    expect(text).toContain('# Threat Investigation Report')
    expect(text).toContain('Redis Exploitation Campaign')
    expect(text).toContain('T1190')
    expect(text).toContain('10.0.0.5')
    expect(text).toContain('agentic-hop Investigator Agent')
  })
})
