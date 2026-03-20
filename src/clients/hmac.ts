// Web Crypto API HMAC — works in Cloudflare Workers (no Node.js crypto)

export async function hmacSign(secret: string, body: string): Promise<string> {
  const encoder = new TextEncoder()
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  )
  const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(body))
  return Array.from(new Uint8Array(signature))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
}

export async function hmacHeaders(secret: string, body: string): Promise<Record<string, string>> {
  const signature = await hmacSign(secret, body)
  return {
    'Content-Type': 'application/json',
    'X-Hub-Signature-256': `sha256=${signature}`,
  }
}

export async function verifyHmac(secret: string, body: string, signature: string): Promise<boolean> {
  const expected = await hmacSign(secret, body)
  // Strip sha256= prefix if present
  const provided = signature.startsWith('sha256=') ? signature.slice(7) : signature
  if (expected.length !== provided.length) return false
  // Constant-time comparison
  const encoder = new TextEncoder()
  const a = encoder.encode(expected)
  const b = encoder.encode(provided)
  let mismatch = 0
  for (let i = 0; i < a.length; i++) {
    mismatch |= a[i] ^ b[i]
  }
  return mismatch === 0
}
