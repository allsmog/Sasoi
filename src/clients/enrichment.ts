import { hmacHeaders } from './hmac.js'
import type { Env } from '../config.js'
import { logger } from '../config.js'

export async function enrichIP(env: Env, ip: string, signal?: string): Promise<unknown> {
  const url = `${env.HOP_ENRICHMENT_URL}/v1/enrich`
  const body = JSON.stringify({ ip, signal })
  const headers = await hmacHeaders(env.INTERNAL_API_SECRET, body)
  const res = await fetch(url, {
    method: 'POST',
    headers,
    body,
  })
  if (!res.ok) {
    const text = await res.text()
    logger.error({ status: res.status, body: text.slice(0, 500) }, 'Enrichment API error')
    throw new Error(`Enrichment failed: ${res.status}`)
  }
  return res.json()
}
