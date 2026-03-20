import { describe, it, expect, vi, beforeEach } from 'vitest'
import { Hono } from 'hono'

vi.mock('../../src/clients/hmac.js', () => ({
  verifyHmac: vi.fn(),
  hmacSign: vi.fn(),
}))

import { verifyHmac, hmacSign } from '../../src/clients/hmac.js'
import { webhookAuth } from '../../src/middleware/webhook-auth.js'

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

describe('webhookAuth middleware', () => {
  let app: Hono

  beforeEach(() => {
    vi.clearAllMocks()

    app = new Hono()
    app.use('*', webhookAuth)
    app.post('/test', (c) => c.json({ ok: true }))
  })

  it('returns 401 when X-HOP-Signature header is missing', async () => {
    const res = await app.request('/test', {
      method: 'POST',
      body: JSON.stringify({ data: 'test' }),
    }, mockEnv)

    expect(res.status).toBe(401)
    const json = await res.json()
    expect(json).toEqual({ error: 'Missing X-HOP-Signature header' })
  })

  it('returns 401 when signature is invalid', async () => {
    vi.mocked(verifyHmac).mockResolvedValue(false)

    const res = await app.request('/test', {
      method: 'POST',
      body: JSON.stringify({ data: 'test' }),
      headers: {
        'X-HOP-Signature': 'invalid-signature',
      },
    }, mockEnv)

    expect(res.status).toBe(401)
    const json = await res.json()
    expect(json).toEqual({ error: 'Invalid signature' })
    expect(verifyHmac).toHaveBeenCalledWith('test-secret', JSON.stringify({ data: 'test' }), 'invalid-signature')
  })

  it('passes through and sets rawBody when signature is valid', async () => {
    vi.mocked(verifyHmac).mockResolvedValue(true)

    let capturedRawBody: string | undefined

    app = new Hono()
    app.use('*', webhookAuth)
    app.post('/test', (c) => {
      capturedRawBody = c.get('rawBody')
      return c.json({ ok: true })
    })

    const body = JSON.stringify({ data: 'test' })

    const res = await app.request('/test', {
      method: 'POST',
      body,
      headers: {
        'X-HOP-Signature': 'valid-signature',
      },
    }, mockEnv)

    expect(res.status).toBe(200)
    const json = await res.json()
    expect(json).toEqual({ ok: true })
    expect(capturedRawBody).toBe(body)
    expect(verifyHmac).toHaveBeenCalledWith('test-secret', body, 'valid-signature')
  })

  it('handles sha256= prefix in signature', async () => {
    vi.mocked(verifyHmac).mockResolvedValue(true)

    const body = JSON.stringify({ data: 'test' })

    const res = await app.request('/test', {
      method: 'POST',
      body,
      headers: {
        'X-HOP-Signature': 'sha256=abc123',
      },
    }, mockEnv)

    expect(res.status).toBe(200)
    expect(verifyHmac).toHaveBeenCalledWith('test-secret', body, 'sha256=abc123')
  })
})

describe('webhookAuth integration — real hmacSign + verifyHmac', () => {
  it('round-trips sign → verify successfully', async () => {
    // Use real implementations for this test
    const { hmacSign: realSign } = await vi.importActual<typeof import('../../src/clients/hmac.js')>('../../src/clients/hmac.js')
    const { verifyHmac: realVerify } = await vi.importActual<typeof import('../../src/clients/hmac.js')>('../../src/clients/hmac.js')

    const secret = 'integration-test-secret'
    const body = JSON.stringify({ event_id: 'evt-1', tenant_id: 'tenant-1' })

    const signature = await realSign(secret, body)
    const isValid = await realVerify(secret, body, `sha256=${signature}`)
    expect(isValid).toBe(true)

    // Tampered body should fail
    const isTampered = await realVerify(secret, body + 'tampered', `sha256=${signature}`)
    expect(isTampered).toBe(false)
  })
})
