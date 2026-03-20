// --- Row types ---

export interface InvestigationRow {
  investigation_id: string
  tenant_id: string
  title: string
  summary: string
  severity: string
  status: string
  findings: string
  iocs: string
  mitre_techniques: string
  event_ids: string
  report_markdown: string | null
  created_at: string
  updated_at: string
}

export interface CampaignRow {
  campaign_id: string
  tenant_id: string
  investigation_id: string | null
  name: string
  description: string
  attacker_ips: string
  affected_honeypots: string
  event_ids: string
  mitre_chain: string
  confidence: number
  status: string
  first_seen: string
  last_seen: string
  created_at: string
  updated_at: string
}

// --- Investigations ---

export async function insertInvestigation(
  db: D1Database,
  params: {
    tenant_id: string
    title: string
    summary: string
    severity: string
    findings: unknown[]
    iocs: unknown[]
    mitre_techniques: string[]
    event_ids: string[]
  },
) {
  const id = crypto.randomUUID()
  await db
    .prepare(
      `INSERT INTO investigations (investigation_id, tenant_id, title, summary, severity, status, findings, iocs, mitre_techniques, event_ids, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, 'open', ?, ?, ?, ?, datetime('now'), datetime('now'))`,
    )
    .bind(
      id,
      params.tenant_id,
      params.title,
      params.summary,
      params.severity,
      JSON.stringify(params.findings),
      JSON.stringify(params.iocs),
      JSON.stringify(params.mitre_techniques),
      JSON.stringify(params.event_ids),
    )
    .run()
  return id
}

export async function getInvestigation(db: D1Database, investigationId: string) {
  return db.prepare('SELECT * FROM investigations WHERE investigation_id = ?').bind(investigationId).first()
}

export async function updateInvestigationReport(db: D1Database, investigationId: string, report: string) {
  await db
    .prepare('UPDATE investigations SET report_markdown = ?, updated_at = datetime(\'now\') WHERE investigation_id = ?')
    .bind(report, investigationId)
    .run()
}

// --- Campaigns ---

export async function insertCampaign(
  db: D1Database,
  params: {
    tenant_id: string
    investigation_id?: string
    name: string
    description: string
    attacker_ips: string[]
    affected_honeypots: string[]
    event_ids: string[]
    mitre_chain: string[]
    confidence: number
  },
) {
  const id = crypto.randomUUID()
  const now = new Date().toISOString()
  await db
    .prepare(
      `INSERT INTO campaigns (campaign_id, tenant_id, investigation_id, name, description, attacker_ips, affected_honeypots, event_ids, mitre_chain, confidence, status, first_seen, last_seen, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?, ?, ?)`,
    )
    .bind(
      id,
      params.tenant_id,
      params.investigation_id ?? null,
      params.name,
      params.description,
      JSON.stringify(params.attacker_ips),
      JSON.stringify(params.affected_honeypots),
      JSON.stringify(params.event_ids),
      JSON.stringify(params.mitre_chain),
      params.confidence,
      now,
      now,
      now,
      now,
    )
    .run()
  return id
}
