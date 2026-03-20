// --- Row types ---

export interface CloudConnectorRow {
  connector_id: string
  tenant_id: string
  provider: string
  account_ref: string
  enabled_regions: string
  allowed_decoy_types: string
  status: string
  created_at: string
}

export interface CloudDecoyRow {
  decoy_id: string
  tenant_id: string
  connector_id: string
  provider: string
  decoy_type: string
  resource_ref: string | null
  region: string | null
  monitoring_status: string
  status: string
  access_count: number
  created_at: string
}

// --- Cloud connectors ---

export async function getCloudConnector(db: D1Database, connectorId: string) {
  return db.prepare('SELECT * FROM cloud_connectors WHERE connector_id = ?').bind(connectorId).first()
}

export async function queryCloudConnectors(db: D1Database, tenantId: string) {
  return db.prepare('SELECT * FROM cloud_connectors WHERE tenant_id = ? AND status = ? LIMIT 500').bind(tenantId, 'active').all()
}

export async function insertCloudConnector(
  db: D1Database,
  params: {
    tenant_id: string
    provider: string
    account_ref: string
    enabled_regions?: string[]
    allowed_decoy_types?: string[]
  },
): Promise<string> {
  const id = crypto.randomUUID()
  await db
    .prepare(
      `INSERT INTO cloud_connectors (connector_id, tenant_id, provider, account_ref, enabled_regions, allowed_decoy_types, status, created_at)
       VALUES (?, ?, ?, ?, ?, ?, 'active', datetime('now'))`,
    )
    .bind(
      id,
      params.tenant_id,
      params.provider,
      params.account_ref,
      JSON.stringify(params.enabled_regions ?? []),
      JSON.stringify(params.allowed_decoy_types ?? []),
    )
    .run()
  return id
}

// --- Cloud decoys ---

export async function insertCloudDecoy(
  db: D1Database,
  params: {
    tenant_id: string
    connector_id: string
    provider: string
    decoy_type: string
    resource_ref?: string
    region?: string
    monitoring_status?: string
  },
): Promise<string> {
  const id = crypto.randomUUID()
  await db
    .prepare(
      `INSERT INTO cloud_decoys (decoy_id, tenant_id, connector_id, provider, decoy_type, resource_ref, region, monitoring_status, status, access_count, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'active', 0, datetime('now'))`,
    )
    .bind(
      id,
      params.tenant_id,
      params.connector_id,
      params.provider,
      params.decoy_type,
      params.resource_ref ?? null,
      params.region ?? null,
      params.monitoring_status ?? 'pending',
    )
    .run()
  return id
}
