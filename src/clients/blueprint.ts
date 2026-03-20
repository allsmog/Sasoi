import { hmacHeaders } from './hmac.js'
import type { Env } from '../config.js'
import { logger } from '../config.js'

async function request(env: Env, path: string, opts: RequestInit = {}): Promise<unknown> {
  const url = `${env.HOP_BLUEPRINT_URL}${path}`
  const body = typeof opts.body === 'string' ? opts.body : ''
  const headers = await hmacHeaders(env.INTERNAL_API_SECRET, body)
  const res = await fetch(url, {
    ...opts,
    headers: { ...headers, ...opts.headers },
  })
  if (!res.ok) {
    const text = await res.text()
    logger.error({ status: res.status, path, body: text.slice(0, 500) }, 'Blueprint API error')
    throw new Error(`Blueprint ${path} failed: ${res.status}`)
  }
  return res.json()
}

export async function generatePersona(
  env: Env,
  params: {
    service_type: string
    complexity?: string
    target_environment?: string
    cve_hints?: string[]
  },
) {
  return request(env, '/v1/personas/generate', {
    method: 'POST',
    body: JSON.stringify(params),
  })
}

export async function generateVariation(env: Env, personaId: string) {
  return request(env, `/v1/personas/${personaId}/variations`, {
    method: 'POST',
    body: JSON.stringify({}),
  })
}
