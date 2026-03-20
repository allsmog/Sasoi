// --- Row types ---

export interface HoneytokenRow {
  honeytoken_id: string
  tenant_id: string
  token_type: string
  token_value: string
  deployment_method: string
  cluster_id: string | null
  namespace: string | null
  placement_reasoning: string | null
  status: string
  access_count: number
  last_accessed_at: string | null
  created_at: string
  updated_at: string
}

// --- Honeytokens ---

export async function insertHoneytoken(
  db: D1Database,
  params: {
    tenant_id: string
    token_type: string
    token_value: string
    deployment_method: string
    cluster_id?: string
    namespace?: string
    placement_reasoning?: string
  },
): Promise<string> {
  const id = crypto.randomUUID()
  await db
    .prepare(
      `INSERT INTO honeytokens (honeytoken_id, tenant_id, token_type, token_value, deployment_method, cluster_id, namespace, placement_reasoning, status, access_count, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'active', 0, datetime('now'), datetime('now'))`,
    )
    .bind(
      id,
      params.tenant_id,
      params.token_type,
      params.token_value,
      params.deployment_method,
      params.cluster_id ?? null,
      params.namespace ?? null,
      params.placement_reasoning ?? null,
    )
    .run()
  return id
}

export async function queryHoneytokens(db: D1Database, tenantId: string, status?: string) {
  if (status) {
    return db
      .prepare('SELECT * FROM honeytokens WHERE tenant_id = ? AND status = ? LIMIT 500')
      .bind(tenantId, status)
      .all()
  }
  return db.prepare('SELECT * FROM honeytokens WHERE tenant_id = ? LIMIT 500').bind(tenantId).all()
}

export async function getHoneytokenByValue(db: D1Database, tokenValue: string) {
  return db.prepare('SELECT * FROM honeytokens WHERE token_value = ?').bind(tokenValue).first()
}

export async function getHoneytokenById(db: D1Database, honeytokenId: string) {
  return db.prepare('SELECT * FROM honeytokens WHERE honeytoken_id = ?').bind(honeytokenId).first()
}

export async function recordHoneytokenAccess(
  db: D1Database,
  params: {
    honeytoken_id: string
    tenant_id: string
    source_ip?: string
    source_service?: string
    access_context?: Record<string, unknown>
  },
) {
  const accessId = crypto.randomUUID()
  const insertStmt = db
    .prepare(
      `INSERT INTO honeytoken_access_log (access_id, honeytoken_id, tenant_id, source_ip, source_service, access_context, created_at)
       VALUES (?, ?, ?, ?, ?, ?, datetime('now'))`,
    )
    .bind(
      accessId,
      params.honeytoken_id,
      params.tenant_id,
      params.source_ip ?? null,
      params.source_service ?? null,
      JSON.stringify(params.access_context ?? {}),
    )

  const updateStmt = db
    .prepare(
      `UPDATE honeytokens SET status = 'accessed', access_count = access_count + 1, last_accessed_at = datetime('now'), updated_at = datetime('now')
       WHERE honeytoken_id = ?`,
    )
    .bind(params.honeytoken_id)

  await db.batch([insertStmt, updateStmt])

  return accessId
}
