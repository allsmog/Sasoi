import { describe, it, expect, vi, beforeEach } from 'vitest'
import { Hono } from 'hono'
import { apiAuth } from '../../src/middleware/api-auth.js'

async function sha256Hex(input: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(input))
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, '0')).join('')
}

function createMockEnv(foundRecord?: { tenant_id: string; key_hash: string }) {
  const selectFirst = vi.fn().mockResolvedValue(foundRecord ?? null)
  const updateRun = vi.fn().mockResolvedValue(undefined)

  const prepare = vi.fn((sql: string) => {
    if (sql.includes('SELECT * FROM tenant_api_keys')) {
      return {
        bind: vi.fn().mockReturnValue({
          first: selectFirst,
        }),
      }
    }

    if (sql.includes('UPDATE tenant_api_keys SET last_used_at')) {
      return {
        bind: vi.fn().mockReturnValue({
          run: updateRun,
        }),
      }
    }

    throw new Error(`Unexpected SQL in apiAuth test: ${sql}`)
  })

  return {
    DB: { prepare } as unknown as D1Database,
    ANTHROPIC_API_KEY: 'test',
    INTERNAL_API_SECRET: 'test-secret',
    HOP_ORCHESTRATOR_URL: 'http://localhost:3001',
    HOP_INGESTOR_URL: 'http://localhost:3002',
    HOP_BLUEPRINT_URL: 'http://localhost:3003',
    HOP_ENRICHMENT_URL: 'http://localhost:3004',
    HOP_ML_URL: 'http://localhost:8000',
    DEFAULT_AUTONOMY_LEVEL: '0',
    PROPOSAL_EXPIRY_HOURS: '24',
  }
}

describe('apiAuth middleware', () => {
  let app: Hono

  beforeEach(() => {
    vi.clearAllMocks()

    app = new Hono()
    app.use('*', apiAuth)
    app.get('/test', (c) => c.json({ ok: true, tenant_id: c.get('authenticatedTenantId') }))
  })

  it('returns 401 when Authorization header is missing', async () => {
    const res = await app.request('/test', { method: 'GET' }, createMockEnv())

    expect(res.status).toBe(401)
    expect(await res.json()).toEqual({ error: 'Missing Authorization header' })
  })

  it('returns 401 when format is not "Bearer <token>"', async () => {
    const res = await app.request(
      '/test',
      {
        method: 'GET',
        headers: { Authorization: 'Basic some-token' },
      },
      createMockEnv(),
    )

    expect(res.status).toBe(401)
    expect(await res.json()).toEqual({ error: 'Invalid Authorization format. Expected: Bearer <API_KEY>' })
  })

  it('returns 401 when API key does not match an active tenant key', async () => {
    const res = await app.request(
      '/test',
      {
        method: 'GET',
        headers: { Authorization: 'Bearer wrong-api-key' },
      },
      createMockEnv(),
    )

    expect(res.status).toBe(401)
    expect(await res.json()).toEqual({ error: 'Invalid API key' })
  })

  it('stores authenticated tenant id in context and updates last_used_at', async () => {
    const token = 'tenant-secret-key'
    const tokenHash = await sha256Hex(token)
    const env = createMockEnv({ tenant_id: 'tenant-123', key_hash: tokenHash })

    const res = await app.request(
      '/test',
      {
        method: 'GET',
        headers: {
          Authorization: `Bearer ${token}`,
        },
      },
      env,
    )

    expect(res.status).toBe(200)
    expect(await res.json()).toEqual({ ok: true, tenant_id: 'tenant-123' })
    expect(env.DB.prepare).toHaveBeenCalledTimes(2)
  })
})
