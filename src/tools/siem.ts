// SIEM formatters — pure functions, not agent tools.
// Used by notification.ts to format events for enterprise SIEMs.

interface SIEMEvent {
  signal: string
  title: string
  severity: string
  message: string
  tenant_id?: string
  src_ip?: string
  deployment_id?: string
  timestamp?: string
  metadata?: Record<string, unknown>
}

const SEVERITY_MAP: Record<string, number> = {
  info: 1,
  low: 3,
  medium: 5,
  warning: 5,
  high: 7,
  critical: 10,
}

function severityNum(severity: string): number {
  return SEVERITY_MAP[severity] ?? 5
}

function escapeField(val: string): string {
  return val.replace(/\\/g, '\\\\').replace(/\|/g, '\\|')
}

export function formatCEF(event: SIEMEvent): string {
  const sev = severityNum(event.severity)
  const ext = [
    event.src_ip ? `src=${event.src_ip}` : '',
    event.tenant_id ? `cs1=${event.tenant_id} cs1Label=TenantId` : '',
    event.deployment_id ? `cs2=${event.deployment_id} cs2Label=DeploymentId` : '',
    event.timestamp ? `rt=${new Date(event.timestamp).getTime()}` : `rt=${Date.now()}`,
    `msg=${escapeField(event.message)}`,
  ].filter(Boolean).join(' ')

  return `CEF:0|HOP|AgenticHOP|1.0|${escapeField(event.signal)}|${escapeField(event.title)}|${sev}|${ext}`
}

export function formatLEEF(event: SIEMEvent): string {
  const attrs = [
    event.src_ip ? `src=${event.src_ip}` : '',
    event.tenant_id ? `tenantId=${event.tenant_id}` : '',
    event.deployment_id ? `deploymentId=${event.deployment_id}` : '',
    `sev=${severityNum(event.severity)}`,
    `msg=${event.message}`,
  ].filter(Boolean).join('\t')

  return `LEEF:2.0|HOP|AgenticHOP|1.0|${event.signal}|${attrs}`
}

export function formatSyslog(event: SIEMEvent): string {
  // RFC 5424 format
  const pri = severityNum(event.severity) <= 3 ? 134 : severityNum(event.severity) <= 5 ? 132 : severityNum(event.severity) <= 7 ? 131 : 130
  const ts = event.timestamp ?? new Date().toISOString()
  const hostname = 'agentic-hop'
  const appName = 'hop'
  const msgId = event.signal
  const structured = `[hop tenantId="${event.tenant_id ?? '-'}" deploymentId="${event.deployment_id ?? '-'}"]`

  return `<${pri}>1 ${ts} ${hostname} ${appName} - ${msgId} ${structured} ${event.title}: ${event.message}`
}

export function splunkHECPayload(event: SIEMEvent): string {
  return JSON.stringify({
    time: event.timestamp ? new Date(event.timestamp).getTime() / 1000 : Date.now() / 1000,
    source: 'agentic-hop',
    sourcetype: 'hop:event',
    host: 'agentic-hop',
    event: {
      signal: event.signal,
      title: event.title,
      severity: event.severity,
      severity_num: severityNum(event.severity),
      message: event.message,
      tenant_id: event.tenant_id,
      src_ip: event.src_ip,
      deployment_id: event.deployment_id,
      ...(event.metadata ?? {}),
    },
  })
}

export function sentinelPayload(event: SIEMEvent): string {
  return JSON.stringify({
    TimeGenerated: event.timestamp ?? new Date().toISOString(),
    SourceSystem: 'AgenticHOP',
    Signal_s: event.signal,
    Title_s: event.title,
    Severity_s: event.severity,
    SeverityNum_d: severityNum(event.severity),
    Message_s: event.message,
    TenantId_g: event.tenant_id,
    SourceIP_s: event.src_ip,
    DeploymentId_s: event.deployment_id,
  })
}

export function formatForDestination(formatType: string, event: SIEMEvent): string {
  switch (formatType) {
    case 'cef': return formatCEF(event)
    case 'leef': return formatLEEF(event)
    case 'syslog': return formatSyslog(event)
    case 'splunk_hec': return splunkHECPayload(event)
    case 'sentinel': return sentinelPayload(event)
    default: return JSON.stringify(event)
  }
}
