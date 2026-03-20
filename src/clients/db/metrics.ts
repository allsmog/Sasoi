import { logger } from '../../config.js'

// --- Row types ---

export interface ResponseActionRow {
  action_id: string
  tenant_id: string
  action_type: string
  target: string
  config: string
  ttl_seconds: number | null
  expires_at: string | null
  status: string
  created_at: string
  updated_at: string
}

// --- Response actions ---

export async function insertResponseAction(
  db: D1Database,
  params: {
    tenant_id: string
    action_type: string
    target: string
    config: Record<string, unknown>
    ttl_seconds?: number
    expires_at?: string
  },
): Promise<string> {
  const id = crypto.randomUUID()
  await db
    .prepare(
      `INSERT INTO response_actions (action_id, tenant_id, action_type, target, config, ttl_seconds, expires_at, status, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, 'active', datetime('now'), datetime('now'))`,
    )
    .bind(
      id,
      params.tenant_id,
      params.action_type,
      params.target,
      JSON.stringify(params.config),
      params.ttl_seconds ?? null,
      params.expires_at ?? null,
    )
    .run()
  return id
}

// --- Risk metrics ---

export async function computeTenantMetrics(
  db: D1Database,
  tenantId: string,
  since?: string,
  until?: string,
) {
  const timeConditions: string[] = []
  const timeBinds: unknown[] = []
  if (since) {
    timeConditions.push('time >= ?')
    timeBinds.push(since)
  }
  if (until) {
    timeConditions.push('time <= ?')
    timeBinds.push(until)
  }
  const timeClause = timeConditions.length > 0 ? ` AND ${timeConditions.join(' AND ')}` : ''

  // Deployments
  const deployments = await db
    .prepare('SELECT COUNT(*) as total, SUM(CASE WHEN status = ? THEN 1 ELSE 0 END) as healthy FROM deployments WHERE tenant_id = ?')
    .bind('healthy', tenantId)
    .first<{ total: number; healthy: number }>()

  // Service type coverage
  const serviceTypes = await db
    .prepare('SELECT service_type, COUNT(*) as count FROM deployments WHERE tenant_id = ? AND status = ? GROUP BY service_type')
    .bind(tenantId, 'healthy')
    .all<{ service_type: string; count: number }>()

  // Events
  const eventStats = await db
    .prepare(
      `SELECT
        COUNT(*) as total_events,
        COUNT(DISTINCT src_ip) as unique_attacker_ips
      FROM events WHERE tenant_id = ?${timeClause}`,
    )
    .bind(tenantId, ...timeBinds)
    .first<{ total_events: number; unique_attacker_ips: number }>()

  // Events by severity
  const severityStats = await db
    .prepare(
      `SELECT severity, COUNT(*) as count FROM events WHERE tenant_id = ?${timeClause} GROUP BY severity`,
    )
    .bind(tenantId, ...timeBinds)
    .all<{ severity: string; count: number }>()

  // Investigations & campaigns
  const investigationCount = await db
    .prepare('SELECT COUNT(*) as total FROM investigations WHERE tenant_id = ?')
    .bind(tenantId)
    .first<{ total: number }>()

  const activeCampaigns = await db
    .prepare('SELECT COUNT(*) as active FROM campaigns WHERE tenant_id = ? AND status = ?')
    .bind(tenantId, 'active')
    .first<{ active: number }>()

  // MTTD: avg(investigation_created - first_event_time)
  const mttd = await db
    .prepare(
      `SELECT AVG(
        (julianday(i.created_at) - julianday(MIN(e.time))) * 1440
      ) as mttd_minutes
      FROM investigations i
      LEFT JOIN events e ON e.tenant_id = i.tenant_id
      WHERE i.tenant_id = ?`,
    )
    .bind(tenantId)
    .first<{ mttd_minutes: number | null }>()

  // Attacker dwell time: avg(last - first event per IP)
  const dwellTime = await db
    .prepare(
      `SELECT AVG(
        (julianday(MAX(time)) - julianday(MIN(time))) * 1440
      ) as dwell_minutes
      FROM events WHERE tenant_id = ?${timeClause}
      GROUP BY src_ip
      HAVING COUNT(*) >= 2`,
    )
    .bind(tenantId, ...timeBinds)
    .first<{ dwell_minutes: number | null }>()

  // Honeytokens (safe to query even before migration — will return 0 or error is caught)
  let activeHoneytokens = 0
  let honeytokenAccesses = 0
  try {
    const htStats = await db
      .prepare('SELECT COUNT(*) as active, SUM(access_count) as accesses FROM honeytokens WHERE tenant_id = ?')
      .bind(tenantId)
      .first<{ active: number; accesses: number | null }>()
    activeHoneytokens = htStats?.active ?? 0
    honeytokenAccesses = htStats?.accesses ?? 0
  } catch (err) {
    if (!(err instanceof Error && err.message.includes('no such table'))) {
      logger.error({ err, tenantId }, 'Failed to query honeytoken metrics')
    }
  }

  const sevMap: Record<string, number> = { low: 0, medium: 0, high: 0, critical: 0 }
  for (const row of severityStats?.results ?? []) {
    sevMap[row.severity] = row.count
  }

  const coverageMap: Record<string, number> = {}
  for (const row of serviceTypes?.results ?? []) {
    coverageMap[row.service_type] = row.count
  }

  return {
    mean_time_to_detect_minutes: mttd?.mttd_minutes ?? 0,
    total_deployments: deployments?.total ?? 0,
    healthy_deployments: deployments?.healthy ?? 0,
    service_type_coverage: coverageMap,
    coverage_gaps: [],
    total_events: eventStats?.total_events ?? 0,
    unique_attacker_ips: eventStats?.unique_attacker_ips ?? 0,
    events_by_severity: sevMap,
    active_campaigns: activeCampaigns?.active ?? 0,
    total_investigations: investigationCount?.total ?? 0,
    attacker_dwell_time_minutes: dwellTime?.dwell_minutes ?? 0,
    active_honeytokens: activeHoneytokens,
    honeytoken_accesses: honeytokenAccesses,
  }
}
