import { Type } from '@sinclair/typebox'
import type { AgentTool } from '@mariozechner/pi-agent-core'
import type { Env } from '../config.js'
import { insertHoneytoken, queryHoneytokens } from '../clients/db.js'

type TokenType = 'aws_access_key' | 'api_key' | 'db_connection_string' | 'github_pat' | 'slack_webhook' | 'jwt_secret'

function randomAlphanumeric(len: number): string {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
  const arr = new Uint8Array(len)
  crypto.getRandomValues(arr)
  return Array.from(arr, (b) => chars[b % chars.length]).join('')
}

function randomBase64(bytes: number): string {
  const arr = new Uint8Array(bytes)
  crypto.getRandomValues(arr)
  return btoa(String.fromCharCode(...arr))
}

function generateTokenValue(tokenType: TokenType): string {
  switch (tokenType) {
    case 'aws_access_key':
      return `AKIA${randomAlphanumeric(16)}`
    case 'api_key':
      return `sk-${crypto.randomUUID()}`
    case 'db_connection_string': {
      const ip = `10.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`
      return `postgresql://admin:${randomAlphanumeric(16)}@${ip}:5432/prod`
    }
    case 'github_pat':
      return `ghp_${randomAlphanumeric(36)}`
    case 'slack_webhook':
      return `https://hooks.slack.com/services/T${randomAlphanumeric(8)}/B${randomAlphanumeric(8)}/${randomAlphanumeric(24)}`
    case 'jwt_secret':
      return randomBase64(32)
    default:
      return `tok-${crypto.randomUUID()}`
  }
}

const DeployHoneytokenParams = Type.Object({
  tenant_id: Type.String({ description: 'Tenant UUID' }),
  token_type: Type.String({ description: 'Token type: aws_access_key, api_key, db_connection_string, github_pat, slack_webhook, jwt_secret' }),
  deployment_method: Type.String({ description: 'Deployment method: k8s_secret, config_map, env_var' }),
  cluster_id: Type.Optional(Type.String({ description: 'Target cluster ID' })),
  namespace: Type.Optional(Type.String({ description: 'Target Kubernetes namespace' })),
  placement_reasoning: Type.Optional(Type.String({ description: 'Why this honeytoken is being placed here' })),
})

export function createDeployHoneytokenTool(env: Env): AgentTool<typeof DeployHoneytokenParams> {
  return {
    name: 'deploy_honeytoken',
    label: 'Deploy Honeytoken',
    description:
      'Deploy a fake credential (honeytoken) as a K8s Secret, ConfigMap, or env var. Access triggers immediate investigation — highest-fidelity signal.',
    parameters: DeployHoneytokenParams,
    execute: async (_toolCallId, params) => {
      const VALID_TOKEN_TYPES = new Set<string>(['aws_access_key', 'api_key', 'db_connection_string', 'github_pat', 'slack_webhook', 'jwt_secret'])
      if (!VALID_TOKEN_TYPES.has(params.token_type)) {
        return {
          content: [{ type: 'text' as const, text: JSON.stringify({ error: `Unknown token_type: ${params.token_type}. Valid types: ${[...VALID_TOKEN_TYPES].join(', ')}` }) }],
          details: { error: 'invalid_token_type' },
        }
      }
      const tokenValue = generateTokenValue(params.token_type as TokenType)

      const honeytokenId = await insertHoneytoken(env.DB, {
        tenant_id: params.tenant_id,
        token_type: params.token_type,
        token_value: tokenValue,
        deployment_method: params.deployment_method,
        cluster_id: params.cluster_id,
        namespace: params.namespace,
        placement_reasoning: params.placement_reasoning,
      })

      return {
        content: [{
          type: 'text' as const,
          text: JSON.stringify({
            honeytoken_id: honeytokenId,
            token_type: params.token_type,
            deployment_method: params.deployment_method,
            status: 'active',
            message: 'Honeytoken deployed. Any access will trigger immediate investigation.',
          }, null, 2),
        }],
        details: { honeytoken_id: honeytokenId, token_type: params.token_type },
      }
    },
  }
}

const QueryHoneytokensParams = Type.Object({
  tenant_id: Type.String({ description: 'Tenant UUID' }),
  status: Type.Optional(Type.String({ description: 'Filter by status: active, accessed, rotated, retired' })),
})

export function createQueryHoneytokensTool(env: Env): AgentTool<typeof QueryHoneytokensParams> {
  return {
    name: 'query_honeytokens',
    label: 'Query Honeytokens',
    description:
      'Query deployed honeytokens for a tenant. Returns token metadata, status, and access counts.',
    parameters: QueryHoneytokensParams,
    execute: async (_toolCallId, params) => {
      const { results } = await queryHoneytokens(env.DB, params.tenant_id, params.status)
      // Redact token_value — the actual credential should not enter agent context or audit logs
      const redacted = (results ?? []).map((row: Record<string, unknown>) => {
        const { token_value: _, ...rest } = row
        return rest
      })
      return {
        content: [{ type: 'text' as const, text: JSON.stringify(redacted, null, 2) }],
        details: { count: redacted.length },
      }
    },
  }
}
