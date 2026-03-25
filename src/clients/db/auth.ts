export interface TenantApiKeyRow {
  tenant_id: string
  key_hash: string
  key_prefix: string
  status: string
  created_at: string
  last_used_at: string | null
  revoked_at: string | null
}

export async function getTenantApiKeyByHash(db: D1Database, keyHash: string) {
  return db
    .prepare('SELECT * FROM tenant_api_keys WHERE key_hash = ? AND status = ?')
    .bind(keyHash, 'active')
    .first<TenantApiKeyRow>()
}

export async function touchTenantApiKey(db: D1Database, keyHash: string): Promise<void> {
  await db
    .prepare("UPDATE tenant_api_keys SET last_used_at = datetime('now') WHERE key_hash = ?")
    .bind(keyHash)
    .run()
}
