import { Hono } from 'hono'
import type { Env } from './config.js'
import { httpRoutes } from './triggers/http.js'
import { webhookRoutes } from './triggers/webhook.js'
import { handleScheduled } from './triggers/cron.js'

const app = new Hono<{ Bindings: Env }>()

// Health check
app.get('/healthz', (c) => {
  return c.json({ status: 'ok', service: 'agentic-hop', runtime: 'cloudflare-workers', timestamp: new Date().toISOString() })
})

// Readiness check
app.get('/readyz', async (c) => {
  const checks: Record<string, string> = {}

  try {
    await c.env.DB.prepare('SELECT 1').first()
    checks.d1 = 'ok'
  } catch {
    checks.d1 = 'error'
  }

  const allOk = checks.d1 === 'ok'
  return c.json({ status: allOk ? 'ready' : 'not_ready', checks }, allOk ? 200 : 503)
})

// Agent API routes
app.route('/v1', httpRoutes)

// Webhook routes (event-driven triggers)
app.route('/v1', webhookRoutes)

// Cloudflare Workers export
export default {
  fetch: app.fetch,
  scheduled: handleScheduled,
}
