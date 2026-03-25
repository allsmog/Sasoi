import type { Context, Next } from 'hono'
import type { AppEnv } from '../config.js'
import { verifyHmac } from '../clients/hmac.js'

export async function webhookAuth(c: Context<AppEnv>, next: Next) {
  const signature = c.req.header('X-HOP-Signature')
  if (!signature) {
    return c.json({ error: 'Missing X-HOP-Signature header' }, 401)
  }

  const body = await c.req.text()
  const valid = await verifyHmac(c.env.INTERNAL_API_SECRET, body, signature)
  if (!valid) {
    return c.json({ error: 'Invalid signature' }, 401)
  }

  // Store raw body for downstream handlers since we consumed it
  c.set('rawBody', body)
  await next()
}
