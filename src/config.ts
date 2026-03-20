// Cloudflare Workers environment bindings
export interface Env {
  // D1 database
  DB: D1Database

  // HOP service URLs
  HOP_ORCHESTRATOR_URL: string
  HOP_INGESTOR_URL: string
  HOP_BLUEPRINT_URL: string
  HOP_ENRICHMENT_URL: string
  HOP_ML_URL: string

  // Secrets (set via `wrangler secret put`)
  ANTHROPIC_API_KEY: string
  INTERNAL_API_SECRET: string
  API_KEY: string

  // Config vars
  DEFAULT_AUTONOMY_LEVEL: string
  PROPOSAL_EXPIRY_HOURS: string
}

export const logger = {
  info: (data: unknown, msg?: string) => console.log(msg ?? '', JSON.stringify(data)),
  error: (data: unknown, msg?: string) => console.error(msg ?? '', JSON.stringify(data)),
  warn: (data: unknown, msg?: string) => console.warn(msg ?? '', JSON.stringify(data)),
  debug: (data: unknown, msg?: string) => console.debug(msg ?? '', JSON.stringify(data)),
}
