import type { Context, Next } from 'hono'
import type { Env } from '../config.js'

function constantTimeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false
  const encoder = new TextEncoder()
  const ab = encoder.encode(a)
  const bb = encoder.encode(b)
  let mismatch = 0
  for (let i = 0; i < ab.length; i++) {
    mismatch |= ab[i] ^ bb[i]
  }
  return mismatch === 0
}

export async function apiAuth(c: Context<{ Bindings: Env }>, next: Next) {
  if (!c.env.API_KEY) {
    return c.json({ error: 'Server misconfigured: API_KEY not set' }, 500)
  }

  const authHeader = c.req.header('Authorization')
  if (!authHeader) {
    return c.json({ error: 'Missing Authorization header' }, 401)
  }

  const parts = authHeader.split(' ')
  if (parts.length !== 2 || parts[0] !== 'Bearer') {
    return c.json({ error: 'Invalid Authorization format. Expected: Bearer <API_KEY>' }, 401)
  }

  const token = parts[1]
  if (!token || !constantTimeEqual(token, c.env.API_KEY)) {
    return c.json({ error: 'Invalid API key' }, 401)
  }

  // Store optional tenant context for downstream authorization checks
  const tenantHeader = c.req.header('X-Tenant-ID')
  if (tenantHeader) {
    c.set('tenantId', tenantHeader)
  }

  await next()
}
