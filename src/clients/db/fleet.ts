// --- Row types ---

export interface DeploymentRow {
  deployment_id: string
  tenant_id: string
  cluster_id: string | null
  service_type: string
  status: string
  metadata: string | null
  created_at: string
}

export interface InventoryService {
  name: string
  namespace: string
  image: string
  tag: string
  ports: number[]
  replicas: number
  size: string
}

// --- Fleet queries ---

export async function queryDeployments(db: D1Database, tenantId: string, status?: string) {
  if (status) {
    return db
      .prepare('SELECT * FROM deployments WHERE tenant_id = ? AND status = ? LIMIT 500')
      .bind(tenantId, status)
      .all()
  }
  return db.prepare('SELECT * FROM deployments WHERE tenant_id = ? LIMIT 500').bind(tenantId).all()
}

export async function getDeploymentById(db: D1Database, deploymentId: string) {
  return db
    .prepare('SELECT * FROM deployments WHERE deployment_id = ?')
    .bind(deploymentId)
    .first<DeploymentRow>()
}

export async function queryClusters(db: D1Database, tenantId: string, status?: string) {
  if (status) {
    return db
      .prepare('SELECT * FROM clusters WHERE tenant_id = ? AND status = ? LIMIT 500')
      .bind(tenantId, status)
      .all()
  }
  return db.prepare('SELECT * FROM clusters WHERE tenant_id = ? LIMIT 500').bind(tenantId).all()
}

export async function getClusterById(db: D1Database, clusterId: string) {
  return db
    .prepare('SELECT * FROM clusters WHERE cluster_id = ?')
    .bind(clusterId)
    .first<{ cluster_id: string; tenant_id: string; status: string | null }>()
}

export async function queryDestinations(db: D1Database, tenantId: string) {
  return db.prepare('SELECT * FROM destinations WHERE tenant_id = ? AND enabled = 1').bind(tenantId).all()
}

export async function updateDeploymentMetadata(db: D1Database, deploymentId: string, metadata: Record<string, unknown>) {
  await db
    .prepare('UPDATE deployments SET metadata = ? WHERE deployment_id = ?')
    .bind(JSON.stringify(metadata), deploymentId)
    .run()
}

// --- Cluster inventory ---

export async function upsertClusterInventory(
  db: D1Database,
  params: {
    cluster_id: string
    tenant_id: string
    services: InventoryService[]
    naming_patterns?: Record<string, unknown>
    collected_at: string
  },
) {
  const id = crypto.randomUUID()
  await db
    .prepare(
      `INSERT INTO cluster_inventories (inventory_id, cluster_id, tenant_id, services, naming_patterns, collected_at, created_at)
       VALUES (?, ?, ?, ?, ?, ?, datetime('now'))`,
    )
    .bind(
      id,
      params.cluster_id,
      params.tenant_id,
      JSON.stringify(params.services),
      JSON.stringify(params.naming_patterns ?? {}),
      params.collected_at,
    )
    .run()
  return id
}

export async function getLatestInventory(db: D1Database, tenantId: string) {
  return db
    .prepare(
      'SELECT * FROM cluster_inventories WHERE tenant_id = ? ORDER BY collected_at DESC LIMIT 1',
    )
    .bind(tenantId)
    .first()
}

// --- Deployments by cluster (for breadcrumbs) ---

export async function queryDeploymentsByCluster(db: D1Database, tenantId: string, clusterId?: string) {
  if (clusterId) {
    return db
      .prepare('SELECT * FROM deployments WHERE tenant_id = ? AND cluster_id = ? AND status = ? LIMIT 500')
      .bind(tenantId, clusterId, 'healthy')
      .all()
  }
  return db
    .prepare('SELECT * FROM deployments WHERE tenant_id = ? AND status = ? LIMIT 500')
    .bind(tenantId, 'healthy')
    .all()
}
