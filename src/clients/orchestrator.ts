import { hmacHeaders } from './hmac.js'
import type { Env } from '../config.js'
import { logger } from '../config.js'

async function request(env: Env, path: string, opts: RequestInit = {}): Promise<unknown> {
  const url = `${env.HOP_ORCHESTRATOR_URL}${path}`
  const body = typeof opts.body === 'string' ? opts.body : ''
  const headers = await hmacHeaders(env.INTERNAL_API_SECRET, body)
  const res = await fetch(url, {
    ...opts,
    headers: { ...headers, ...opts.headers },
  })
  if (!res.ok) {
    const text = await res.text()
    logger.error({ status: res.status, path, body: text.slice(0, 500) }, 'Orchestrator API error')
    throw new Error(`Orchestrator ${path} failed: ${res.status}`)
  }
  return res.json()
}

export async function createDeployment(
  env: Env,
  params: {
    blueprint_id: string
    config: Record<string, unknown>
    deployment_location?: string
    connector_id?: string
    cluster_id?: string
  },
) {
  return request(env, '/v1/deployments', {
    method: 'POST',
    body: JSON.stringify(params),
  })
}

export async function rotatePersona(env: Env, deploymentId: string) {
  return request(env, `/v1/deployments/${deploymentId}/rotate`, { method: 'POST' })
}

export async function blockIP(
  env: Env,
  params: { ip: string; cluster_id: string; ttl_seconds: number },
) {
  return request(env, '/v1/network-policies/block', {
    method: 'POST',
    body: JSON.stringify(params),
  })
}

export async function redirectAttacker(
  env: Env,
  params: { source_deployment_id: string; target_deployment_id: string; attacker_ip: string },
) {
  return request(env, '/v1/redirects', {
    method: 'POST',
    body: JSON.stringify(params),
  })
}

export async function createCloudDecoy(
  env: Env,
  params: {
    connector_id: string
    provider: string
    decoy_type: string
    region?: string
    config: Record<string, unknown>
  },
) {
  return request(env, '/v1/cloud-decoys', {
    method: 'POST',
    body: JSON.stringify(params),
  })
}

export async function teardownCloudDecoy(env: Env, decoyId: string) {
  return request(env, `/v1/cloud-decoys/${decoyId}`, { method: 'DELETE' })
}

export async function createServiceAccount(
  env: Env,
  params: { cluster_id: string; namespace: string; name: string },
) {
  return request(env, '/v1/service-accounts', {
    method: 'POST',
    body: JSON.stringify(params),
  })
}
