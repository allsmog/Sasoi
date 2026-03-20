import { Type } from '@sinclair/typebox'
import type { AgentTool } from '@mariozechner/pi-agent-core'
import type { Env } from '../config.js'
import { queryDeployments, queryClusters, getLatestInventory } from '../clients/db.js'

export function createQueryFleetTool(env: Env): AgentTool<typeof QueryFleetParams> {
  return {
    name: 'query_fleet',
    label: 'Query Fleet',
    description:
      'Query all honeypot deployments for a tenant. Returns deployment details including blueprint, status, location, and rotation schedule. Use to understand current honeypot coverage.',
    parameters: QueryFleetParams,
    execute: async (_toolCallId, params) => {
      const { results } = await queryDeployments(env.DB, params.tenant_id, params.status)
      return {
        content: [{ type: 'text' as const, text: JSON.stringify(results, null, 2) }],
        details: { count: results?.length ?? 0 },
      }
    },
  }
}

export function createQueryClustersTool(env: Env): AgentTool<typeof QueryClustersParams> {
  return {
    name: 'query_clusters',
    label: 'Query Clusters',
    description:
      'Query Kubernetes clusters registered for a tenant. Returns cluster details including mode (customer_managed/hop_managed), status, and metadata.',
    parameters: QueryClustersParams,
    execute: async (_toolCallId, params) => {
      const { results } = await queryClusters(env.DB, params.tenant_id, params.status)
      return {
        content: [{ type: 'text' as const, text: JSON.stringify(results, null, 2) }],
        details: { count: results?.length ?? 0 },
      }
    },
  }
}

export function createQueryInventoryTool(env: Env): AgentTool<typeof QueryInventoryParams> {
  return {
    name: 'query_inventory',
    label: 'Query Cluster Inventory',
    description:
      'Query the latest cluster inventory for a tenant. Returns anonymized service data (names, images, ports, replica counts, naming patterns). Use this to generate environment-aware honeypots that blend in with real infrastructure.',
    parameters: QueryInventoryParams,
    execute: async (_toolCallId, params) => {
      const row = await getLatestInventory(env.DB, params.tenant_id)
      if (!row) {
        return {
          content: [{ type: 'text' as const, text: 'No cluster inventory available for this tenant. Inventory collection may not be enabled.' }],
          details: { available: false },
        }
      }
      let services: unknown[]
      let namingPatterns: Record<string, unknown>
      try {
        services = JSON.parse(row.services as string)
      } catch {
        services = []
      }
      try {
        namingPatterns = JSON.parse((row.naming_patterns as string) ?? '{}')
      } catch {
        namingPatterns = {}
      }
      return {
        content: [
          {
            type: 'text' as const,
            text: JSON.stringify({
              cluster_id: row.cluster_id,
              collected_at: row.collected_at,
              services,
              naming_patterns: namingPatterns,
            }, null, 2),
          },
        ],
        details: { service_count: services.length, collected_at: row.collected_at },
      }
    },
  }
}

const QueryInventoryParams = Type.Object({
  tenant_id: Type.String({ description: 'Tenant UUID' }),
})

const QueryFleetParams = Type.Object({
  tenant_id: Type.String({ description: 'Tenant UUID' }),
  status: Type.Optional(
    Type.String({ description: 'Filter deployments by status: pending, building, deploying, healthy, failed' }),
  ),
})

const QueryClustersParams = Type.Object({
  tenant_id: Type.String({ description: 'Tenant UUID' }),
  status: Type.Optional(
    Type.String({ description: 'Filter by cluster status: pending, provisioning, ready, draining, error' }),
  ),
})
