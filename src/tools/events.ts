import { Type } from '@sinclair/typebox'
import type { AgentTool } from '@mariozechner/pi-agent-core'
import type { Env } from '../config.js'
import { queryEvents as dbQueryEvents, correlateSessionsQuery } from '../clients/db.js'

// Tool factories — accept env so they can access D1

export function createQueryEventsTool(env: Env): AgentTool<typeof QueryEventsParams> {
  return {
    name: 'query_events',
    label: 'Query Events',
    description:
      'Query honeypot events from the database with filtering by tenant, time range, severity, source IP, deployment, and signal type. Returns enriched events with MITRE mappings.',
    parameters: QueryEventsParams,
    execute: async (_toolCallId, params) => {
      const { results } = await dbQueryEvents(env.DB, params)
      return {
        content: [{ type: 'text' as const, text: JSON.stringify(results, null, 2) }],
        details: { count: results?.length ?? 0 },
      }
    },
  }
}

export function createCorrelateSessionsTool(env: Env): AgentTool<typeof CorrelateSessionsParams> {
  return {
    name: 'correlate_sessions',
    label: 'Correlate Sessions',
    description:
      'Find IPs that have hit multiple honeypots within a time window. Returns correlated sessions with event counts, affected honeypots, signals, and time ranges. Useful for identifying multi-stage attack campaigns.',
    parameters: CorrelateSessionsParams,
    execute: async (_toolCallId, params) => {
      const { results } = await correlateSessionsQuery(env.DB, {
        tenant_id: params.tenant_id,
        time_window_hours: params.time_window_hours ?? 24,
        min_events: params.min_events ?? 3,
      })
      return {
        content: [{ type: 'text' as const, text: JSON.stringify(results, null, 2) }],
        details: { correlations: results?.length ?? 0 },
      }
    },
  }
}

// --- Schemas ---

const QueryEventsParams = Type.Object({
  tenant_id: Type.String({ description: 'Tenant UUID to query events for' }),
  since: Type.Optional(Type.String({ description: 'ISO datetime to filter events after' })),
  severity: Type.Optional(Type.String({ description: 'Filter by severity: low, med, high' })),
  src_ip: Type.Optional(Type.String({ description: 'Filter by source IP address' })),
  deployment_id: Type.Optional(Type.String({ description: 'Filter by deployment UUID' })),
  signal: Type.Optional(Type.String({ description: 'Filter by signal type (e.g. brute_force, login_attempt)' })),
  limit: Type.Optional(Type.Number({ description: 'Max events to return (default 50)', minimum: 1, maximum: 500 })),
})

const CorrelateSessionsParams = Type.Object({
  tenant_id: Type.String({ description: 'Tenant UUID' }),
  time_window_hours: Type.Optional(
    Type.Number({ description: 'Time window in hours to look back (default 24)', minimum: 1, maximum: 168 }),
  ),
  min_events: Type.Optional(
    Type.Number({ description: 'Minimum events per IP to include (default 3)', minimum: 2 }),
  ),
})
