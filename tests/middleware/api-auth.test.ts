import { describe, it, expect, vi, beforeEach } from 'vitest'
import { Hono } from 'hono'
import { apiAuth } from '../../src/middleware/api-auth.js'

const mockEnv = {
  DB: {} as D1Database,
  ANTHROPIC_API_KEY: 'test',
  INTERNAL_API_SECRET: 'test-secret',
  API_KEY: 'test-api-key',
  HOP_ORCHESTRATOR_URL: 'http://localhost:3001',
  HOP_INGESTOR_URL: 'http://localhost:3002',
  HOP_BLUEPRINT_URL: 'http://localhost:3003',
  HOP_ENRICHMENT_URL: 'http://localhost:3004',
  HOP_ML_URL: 'http://localhost:8000',
  DEFAULT_AUTONOMY_LEVEL: '0',
  PROPOSAL_EXPIRY_HOURS: '24',
}

describe('apiAuth middleware', () => {
  let app: Hono

  beforeEach(() => {
    vi.clearAllMocks()

    app = new Hono()
    app.use('*', apiAuth)
    app.get('/test', (c) => c.json({ ok: true }))
  })

  it('returns 401 when Authorization header is missing', async () => {
    const res = await app.request('/test', {
      method: 'GET',
    }, mockEnv)

    expect(res.status).toBe(401)
    const json = await res.json()
    expect(json).toEqual({ error: 'Missing Authorization header' })
  })

  it('returns 401 when format is not "Bearer <token>"', async () => {
    const res = await app.request('/test', {
      method: 'GET',
      headers: {
        Authorization: 'Basic some-token',
      },
    }, mockEnv)

    expect(res.status).toBe(401)
    const json = await res.json()
    expect(json).toEqual({ error: 'Invalid Authorization format. Expected: Bearer <API_KEY>' })
  })

  it('returns 401 when Authorization header has too many parts', async () => {
    const res = await app.request('/test', {
      method: 'GET',
      headers: {
        Authorization: 'Bearer token extra',
      },
    }, mockEnv)

    expect(res.status).toBe(401)
    const json = await res.json()
    expect(json).toEqual({ error: 'Invalid Authorization format. Expected: Bearer <API_KEY>' })
  })

  it('returns 401 when API key does not match', async () => {
    const res = await app.request('/test', {
      method: 'GET',
      headers: {
        Authorization: 'Bearer wrong-api-key',
      },
    }, mockEnv)

    expect(res.status).toBe(401)
    const json = await res.json()
    expect(json).toEqual({ error: 'Invalid API key' })
  })

  it('returns 500 when API_KEY is not configured', async () => {
    const res = await app.request('/test', {
      method: 'GET',
      headers: { Authorization: 'Bearer some-key' },
    }, { ...mockEnv, API_KEY: '' })

    expect(res.status).toBe(500)
    const json = await res.json()
    expect(json.error).toContain('API_KEY not set')
  })

  it('stores X-Tenant-ID header in context', async () => {
    let capturedTenantId: string | undefined

    const tenantApp = new Hono()
    tenantApp.use('*', apiAuth)
    tenantApp.get('/test', (c) => {
      capturedTenantId = c.get('tenantId')
      return c.json({ ok: true })
    })

    await tenantApp.request('/test', {
      method: 'GET',
      headers: {
        Authorization: 'Bearer test-api-key',
        'X-Tenant-ID': 'my-tenant-123',
      },
    }, mockEnv)

    expect(capturedTenantId).toBe('my-tenant-123')
  })

  it('passes through when API key is valid', async () => {
    const res = await app.request('/test', {
      method: 'GET',
      headers: {
        Authorization: 'Bearer test-api-key',
      },
    }, mockEnv)

    expect(res.status).toBe(200)
    const json = await res.json()
    expect(json).toEqual({ ok: true })
  })
})
