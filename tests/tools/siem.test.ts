import { describe, it, expect } from 'vitest'
import { formatCEF, formatLEEF, formatSyslog, splunkHECPayload, sentinelPayload, formatForDestination } from '../../src/tools/siem.js'

const baseEvent = {
  signal: 'login_attempt',
  title: 'SSH Login Attempt',
  severity: 'high',
  message: 'Brute force detected from 1.2.3.4',
  tenant_id: 'tenant-1',
  src_ip: '1.2.3.4',
  deployment_id: 'dep-1',
  timestamp: '2026-03-20T10:00:00Z',
}

describe('formatCEF', () => {
  it('produces correct pipe-delimited CEF format', () => {
    const result = formatCEF(baseEvent)
    expect(result).toMatch(/^CEF:0\|HOP\|AgenticHOP\|1\.0\|/)
    expect(result).toContain('login_attempt')
    expect(result).toContain('SSH Login Attempt')
    expect(result).toContain('|7|') // high severity = 7
  })

  it('maps severity correctly', () => {
    expect(formatCEF({ ...baseEvent, severity: 'low' })).toContain('|3|')
    expect(formatCEF({ ...baseEvent, severity: 'medium' })).toContain('|5|')
    expect(formatCEF({ ...baseEvent, severity: 'high' })).toContain('|7|')
    expect(formatCEF({ ...baseEvent, severity: 'critical' })).toContain('|10|')
  })

  it('includes source IP in extension', () => {
    expect(formatCEF(baseEvent)).toContain('src=1.2.3.4')
  })

  it('includes tenant ID as custom string', () => {
    expect(formatCEF(baseEvent)).toContain('cs1=tenant-1')
  })
})

describe('formatLEEF', () => {
  it('produces LEEF 2.0 format', () => {
    const result = formatLEEF(baseEvent)
    expect(result).toMatch(/^LEEF:2\.0\|HOP\|AgenticHOP\|1\.0\|/)
    expect(result).toContain('login_attempt')
  })

  it('includes severity number', () => {
    expect(formatLEEF(baseEvent)).toContain('sev=7')
  })
})

describe('formatSyslog', () => {
  it('produces RFC 5424 format', () => {
    const result = formatSyslog(baseEvent)
    expect(result).toMatch(/^<\d+>1 /)
    expect(result).toContain('agentic-hop')
    expect(result).toContain('hop')
    expect(result).toContain('login_attempt')
  })

  it('includes structured data with tenant and deployment', () => {
    const result = formatSyslog(baseEvent)
    expect(result).toContain('tenantId="tenant-1"')
    expect(result).toContain('deploymentId="dep-1"')
  })
})

describe('splunkHECPayload', () => {
  it('produces valid Splunk HEC JSON', () => {
    const result = JSON.parse(splunkHECPayload(baseEvent))
    expect(result.source).toBe('agentic-hop')
    expect(result.sourcetype).toBe('hop:event')
    expect(result.event.signal).toBe('login_attempt')
    expect(result.event.severity_num).toBe(7)
    expect(result.time).toBeGreaterThan(0)
  })
})

describe('sentinelPayload', () => {
  it('produces Microsoft Sentinel Log Analytics JSON', () => {
    const result = JSON.parse(sentinelPayload(baseEvent))
    expect(result.SourceSystem).toBe('AgenticHOP')
    expect(result.Signal_s).toBe('login_attempt')
    expect(result.SeverityNum_d).toBe(7)
    expect(result.TenantId_g).toBe('tenant-1')
  })
})

describe('formatForDestination', () => {
  it('delegates to correct formatter', () => {
    expect(formatForDestination('cef', baseEvent)).toMatch(/^CEF:0/)
    expect(formatForDestination('leef', baseEvent)).toMatch(/^LEEF:2\.0/)
    expect(formatForDestination('syslog', baseEvent)).toMatch(/^<\d+>1/)
    expect(formatForDestination('splunk_hec', baseEvent)).toContain('"source":"agentic-hop"')
    expect(formatForDestination('sentinel', baseEvent)).toContain('"SourceSystem":"AgenticHOP"')
  })

  it('falls back to JSON for unknown format', () => {
    const result = formatForDestination('unknown', baseEvent)
    const parsed = JSON.parse(result)
    expect(parsed.signal).toBe('login_attempt')
  })

  it('handles missing fields gracefully', () => {
    const minimal = { signal: 'test', title: 'Test', severity: 'info', message: 'test msg' }
    expect(() => formatCEF(minimal)).not.toThrow()
    expect(() => formatLEEF(minimal)).not.toThrow()
    expect(() => formatSyslog(minimal)).not.toThrow()
    expect(() => splunkHECPayload(minimal)).not.toThrow()
    expect(() => sentinelPayload(minimal)).not.toThrow()
  })
})
