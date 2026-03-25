import type { Context, Next } from 'hono'
import type { AppEnv } from '../config.js'
import { getTenantApiKeyByHash, touchTenantApiKey } from '../clients/db.js'

async function sha256Hex(input: string): Promise<string> {
  const encoder = new TextEncoder()
  const digest = await crypto.subtle.digest('SHA-256', encoder.encode(input))
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, '0')).join('')
}

export async function apiAuth(c: Context<AppEnv>, next: Next) {
  const authHeader = c.req.header('Authorization')
  if (!authHeader) {
    return c.json({ error: 'Missing Authorization header' }, 401)
  }

  const parts = authHeader.split(' ')
  if (parts.length !== 2 || parts[0] !== 'Bearer') {
    return c.json({ error: 'Invalid Authorization format. Expected: Bearer <API_KEY>' }, 401)
  }

  const token = parts[1]
  if (!token) {
    return c.json({ error: 'Invalid API key' }, 401)
  }

  const keyHash = await sha256Hex(token)
  const apiKeyRecord = await getTenantApiKeyByHash(c.env.DB, keyHash)
  if (!apiKeyRecord) {
    return c.json({ error: 'Invalid API key' }, 401)
  }

  await touchTenantApiKey(c.env.DB, keyHash)

  c.set('authenticatedTenantId', apiKeyRecord.tenant_id)
  c.set('tenantId', apiKeyRecord.tenant_id)
  await next()
}
