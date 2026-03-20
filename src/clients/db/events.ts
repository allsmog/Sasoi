// --- Row types ---

export interface EventRow {
  event_id: string
  tenant_id: string
  src_ip: string
  signal: string
  severity: string
  hp_type: string | null
  ua: string | null
  deployment_id: string | null
  enrichment: string | null
  time: string
}

// --- Event queries ---

export async function queryEvents(
  db: D1Database,
  params: {
    tenant_id: string
    since?: string
    severity?: string
    src_ip?: string
    deployment_id?: string
    signal?: string
    limit?: number
  },
) {
  const conditions = ['tenant_id = ?']
  const binds: unknown[] = [params.tenant_id]

  if (params.since) {
    conditions.push('time >= ?')
    binds.push(params.since)
  }
  if (params.severity) {
    conditions.push('severity = ?')
    binds.push(params.severity)
  }
  if (params.src_ip) {
    conditions.push('src_ip = ?')
    binds.push(params.src_ip)
  }
  if (params.deployment_id) {
    conditions.push('deployment_id = ?')
    binds.push(params.deployment_id)
  }
  if (params.signal) {
    conditions.push('signal = ?')
    binds.push(params.signal)
  }

  binds.push(params.limit ?? 50)

  const sql = `SELECT * FROM events WHERE ${conditions.join(' AND ')} ORDER BY time DESC LIMIT ?`
  return db.prepare(sql).bind(...binds).all()
}

export async function correlateSessionsQuery(
  db: D1Database,
  params: { tenant_id: string; time_window_hours: number; min_events: number },
) {
  const since = new Date(Date.now() - params.time_window_hours * 3600_000).toISOString()

  return db
    .prepare(
      `SELECT
        src_ip,
        COUNT(*) as event_count,
        COUNT(DISTINCT deployment_id) as honeypots_hit,
        GROUP_CONCAT(DISTINCT deployment_id) as deployment_ids,
        GROUP_CONCAT(event_id) as event_ids,
        GROUP_CONCAT(DISTINCT signal) as signals,
        MIN(time) as first_seen,
        MAX(time) as last_seen
      FROM events
      WHERE tenant_id = ? AND time >= ?
      GROUP BY src_ip
      HAVING COUNT(*) >= ? AND COUNT(DISTINCT deployment_id) >= 2
      ORDER BY event_count DESC`,
    )
    .bind(params.tenant_id, since, params.min_events)
    .all()
}

export async function getEventEnrichment(db: D1Database, eventId: string) {
  return db.prepare('SELECT enrichment FROM events WHERE event_id = ?').bind(eventId).first()
}

export async function updateEventEnrichment(db: D1Database, eventId: string, enrichment: Record<string, unknown>) {
  await db
    .prepare('UPDATE events SET enrichment = ? WHERE event_id = ?')
    .bind(JSON.stringify(enrichment), eventId)
    .run()
}
