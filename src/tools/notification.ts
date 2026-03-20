import { Type } from '@sinclair/typebox'
import type { AgentTool } from '@mariozechner/pi-agent-core'
import type { Env } from '../config.js'
import { queryDestinations, updateDeploymentMetadata } from '../clients/db.js'
import { logger } from '../config.js'
import { formatForDestination } from './siem.js'

const PRIVATE_IP_PREFIXES = ['10.', '172.16.', '172.17.', '172.18.', '172.19.', '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.', '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.', '192.168.', '127.', '169.254.', '0.']

function isSafeUrl(urlString: string): boolean {
  try {
    const url = new URL(urlString)
    if (url.protocol !== 'https:' && url.protocol !== 'http:') return false
    if (url.hostname === 'localhost' || url.hostname === '[::1]') return false
    if (PRIVATE_IP_PREFIXES.some((p) => url.hostname.startsWith(p))) return false
    if (url.hostname === '169.254.169.254') return false
    return true
  } catch {
    return false
  }
}

export function createTriggerNotificationTool(env: Env): AgentTool<typeof TriggerNotificationParams> {
  return {
    name: 'trigger_notification',
    label: 'Trigger Notification',
    description:
      'Send a notification to configured destinations (Slack, webhooks, SIEM).',
    parameters: TriggerNotificationParams,
    execute: async (_toolCallId, params) => {
      const { results: destinations } = await queryDestinations(env.DB, params.tenant_id)
      const targetDests =
        params.channel === 'all' || !params.channel
          ? destinations ?? []
          : (destinations ?? []).filter((d: Record<string, unknown>) => d.type === params.channel)

      const sent: string[] = []
      for (const dest of targetDests) {
        const destRecord = dest as { type: string; config_ref: string; format_type?: string }
        try {
          if (destRecord.config_ref && isSafeUrl(destRecord.config_ref)) {
            let body: string
            const contentType = 'application/json'

            if (destRecord.format_type) {
              // SIEM-formatted output
              body = formatForDestination(destRecord.format_type, {
                signal: params.title,
                title: params.title,
                severity: params.severity,
                message: params.message,
                tenant_id: params.tenant_id,
                timestamp: new Date().toISOString(),
                metadata: params.metadata as Record<string, unknown>,
              })
            } else {
              // Default JSON format
              body = JSON.stringify({
                severity: params.severity,
                title: params.title,
                message: params.message,
                metadata: params.metadata,
                timestamp: new Date().toISOString(),
              })
            }

            const controller = new AbortController()
            const timeout = setTimeout(() => controller.abort(), 10_000)
            try {
              await fetch(destRecord.config_ref, {
                method: 'POST',
                headers: { 'Content-Type': contentType },
                body,
                signal: controller.signal,
              })
            } finally {
              clearTimeout(timeout)
            }
          }
          sent.push(destRecord.type)
        } catch (err) {
          logger.error({ err, destination: destRecord.type }, 'Failed to send notification')
        }
      }

      return {
        content: [{ type: 'text' as const, text: `Notification sent to ${sent.length} destination(s): ${sent.join(', ') || 'none configured'}` }],
        details: { sent },
      }
    },
  }
}

export function createIncreaseLoggingDepthTool(env: Env): AgentTool<typeof IncreaseLoggingDepthParams> {
  return {
    name: 'increase_logging_depth',
    label: 'Increase Logging',
    description:
      'Temporarily increase logging depth for a deployment during an active investigation.',
    parameters: IncreaseLoggingDepthParams,
    execute: async (_toolCallId, params) => {
      await updateDeploymentMetadata(env.DB, params.deployment_id, {
        logging_override: {
          level: params.level,
          expires_at: new Date(Date.now() + params.duration_minutes * 60_000).toISOString(),
          reason: params.reason,
        },
      })
      return {
        content: [{ type: 'text' as const, text: `Logging increased to "${params.level}" for deployment ${params.deployment_id} for ${params.duration_minutes} minutes.` }],
        details: { deployment_id: params.deployment_id },
      }
    },
  }
}

const TriggerNotificationParams = Type.Object({
  tenant_id: Type.String({ description: 'Tenant UUID' }),
  severity: Type.String({ description: 'Notification severity: info, warning, critical' }),
  title: Type.String({ description: 'Notification title' }),
  message: Type.String({ description: 'Notification body' }),
  channel: Type.Optional(Type.String({ description: 'Target channel: slack, webhook, all (default all)' })),
  metadata: Type.Optional(Type.Object({}, { description: 'Additional metadata', additionalProperties: true })),
})

const IncreaseLoggingDepthParams = Type.Object({
  deployment_id: Type.String({ description: 'Deployment UUID' }),
  level: Type.String({ description: 'Logging level: verbose, debug, trace' }),
  duration_minutes: Type.Number({ description: 'Duration in minutes (max 60)', minimum: 5, maximum: 60 }),
  reason: Type.String({ description: 'Why logging is being increased' }),
})
