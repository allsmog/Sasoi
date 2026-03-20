import { Type } from '@sinclair/typebox'
import type { AgentTool } from '@mariozechner/pi-agent-core'
import type { Env } from '../config.js'
import { insertResponseAction } from '../clients/db.js'
import * as orchestrator from '../clients/orchestrator.js'

const MAX_BLOCK_TTL_SECONDS = 86400 // 24 hours

const IPV4_RE = /^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$/
const IPV6_RE = /^[\da-fA-F:]+$/

function isValidIP(ip: string): boolean {
  return IPV4_RE.test(ip) || (ip.includes(':') && IPV6_RE.test(ip))
}

const BlockIPParams = Type.Object({
  tenant_id: Type.String({ description: 'Tenant UUID' }),
  ip: Type.String({ description: 'IP address to block' }),
  cluster_id: Type.String({ description: 'Cluster where NetworkPolicy will be applied' }),
  ttl_seconds: Type.Optional(Type.Number({ description: 'Block duration in seconds (max 86400 = 24h)', minimum: 60, maximum: 86400 })),
  reason: Type.String({ description: 'Reason for blocking this IP' }),
})

export function createBlockIPTool(env: Env): AgentTool<typeof BlockIPParams> {
  return {
    name: 'block_ip',
    label: 'Block IP',
    description:
      'Block an attacker IP via NetworkPolicy on the orchestrator. Max 24h TTL. Requires responder_opt_in AND autonomy >= 2.',
    parameters: BlockIPParams,
    execute: async (_toolCallId, params) => {
      if (!isValidIP(params.ip)) {
        return {
          content: [{ type: 'text' as const, text: JSON.stringify({ error: `Invalid IP address format: ${params.ip}` }) }],
          details: { error: 'invalid_ip' },
        }
      }
      const ttl = Math.min(params.ttl_seconds ?? 3600, MAX_BLOCK_TTL_SECONDS)
      const expiresAt = new Date(Date.now() + ttl * 1000).toISOString()

      await orchestrator.blockIP(env, {
        ip: params.ip,
        cluster_id: params.cluster_id,
        ttl_seconds: ttl,
      })

      const actionId = await insertResponseAction(env.DB, {
        tenant_id: params.tenant_id,
        action_type: 'block_ip',
        target: params.ip,
        config: { cluster_id: params.cluster_id, reason: params.reason },
        ttl_seconds: ttl,
        expires_at: expiresAt,
      })

      return {
        content: [{
          type: 'text' as const,
          text: JSON.stringify({
            action_id: actionId,
            action: 'block_ip',
            ip: params.ip,
            ttl_seconds: ttl,
            expires_at: expiresAt,
            message: `IP ${params.ip} blocked for ${ttl}s via NetworkPolicy`,
          }, null, 2),
        }],
        details: { action_id: actionId },
      }
    },
  }
}

const RedirectAttackerParams = Type.Object({
  tenant_id: Type.String({ description: 'Tenant UUID' }),
  source_deployment_id: Type.String({ description: 'Current honeypot the attacker is in' }),
  target_deployment_id: Type.String({ description: 'Higher-interaction honeypot to redirect to' }),
  attacker_ip: Type.String({ description: 'Attacker IP to redirect' }),
  reason: Type.String({ description: 'Reason for redirect' }),
})

export function createRedirectAttackerTool(env: Env): AgentTool<typeof RedirectAttackerParams> {
  return {
    name: 'redirect_attacker',
    label: 'Redirect Attacker',
    description:
      'Redirect an attacker from a low-interaction honeypot to a higher-interaction one for deeper intelligence collection. Requires responder_opt_in AND autonomy >= 2.',
    parameters: RedirectAttackerParams,
    execute: async (_toolCallId, params) => {
      if (!isValidIP(params.attacker_ip)) {
        return {
          content: [{ type: 'text' as const, text: JSON.stringify({ error: `Invalid IP address format: ${params.attacker_ip}` }) }],
          details: { error: 'invalid_ip' },
        }
      }
      await orchestrator.redirectAttacker(env, {
        source_deployment_id: params.source_deployment_id,
        target_deployment_id: params.target_deployment_id,
        attacker_ip: params.attacker_ip,
      })

      const actionId = await insertResponseAction(env.DB, {
        tenant_id: params.tenant_id,
        action_type: 'redirect_attacker',
        target: params.attacker_ip,
        config: {
          source_deployment_id: params.source_deployment_id,
          target_deployment_id: params.target_deployment_id,
          reason: params.reason,
        },
      })

      return {
        content: [{
          type: 'text' as const,
          text: JSON.stringify({
            action_id: actionId,
            action: 'redirect_attacker',
            attacker_ip: params.attacker_ip,
            from: params.source_deployment_id,
            to: params.target_deployment_id,
            message: `Attacker ${params.attacker_ip} redirected to higher-interaction honeypot`,
          }, null, 2),
        }],
        details: { action_id: actionId },
      }
    },
  }
}
