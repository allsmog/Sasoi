import type { AgentEvent } from '@mariozechner/pi-agent-core'
import type { Env } from '../config.js'
import { logToolInvocation } from '../clients/db.js'

interface GuardContext {
  sessionId: string
  agentType: string
  tenantId: string
  env: Env
}

export class SafetyGuard {
  private toolStartTimes = new Map<string, number>()
  private toolArgs = new Map<string, Record<string, unknown>>()

  constructor(private ctx: GuardContext) {}

  preCheck(event: Extract<AgentEvent, { type: 'tool_execution_start' }>): void {
    this.toolStartTimes.set(event.toolCallId, Date.now())
    this.toolArgs.set(event.toolCallId, (event.args ?? {}) as Record<string, unknown>)
  }

  async postCheck(event: Extract<AgentEvent, { type: 'tool_execution_end' }>): Promise<void> {
    const startTime = this.toolStartTimes.get(event.toolCallId)
    const toolArgs = this.toolArgs.get(event.toolCallId) ?? {}
    const durationMs = startTime ? Date.now() - startTime : 0
    this.toolStartTimes.delete(event.toolCallId)
    this.toolArgs.delete(event.toolCallId)

    await logToolInvocation(this.ctx.env.DB, {
      session_id: this.ctx.sessionId,
      tool_name: event.toolName,
      tool_args: toolArgs,
      result: event.result,
      is_error: event.isError,
      duration_ms: durationMs,
    })
  }

  createEventSubscriber() {
    return async (event: AgentEvent) => {
      if (event.type === 'tool_execution_start') {
        this.preCheck(event)
      }
      if (event.type === 'tool_execution_end') {
        await this.postCheck(event)
      }
    }
  }
}

// In-memory rate limiter (resets per Worker instance lifecycle)
const invocationCounts = new Map<string, { count: number; resetAt: number }>()

export function checkRateLimit(tenantId: string, agentType: string, limit: number): boolean {
  const key = `${tenantId}:${agentType}`
  const now = Date.now()

  // Purge expired entries when map grows too large
  if (invocationCounts.size > 500) {
    for (const [k, v] of invocationCounts) {
      if (now > v.resetAt) invocationCounts.delete(k)
    }
  }

  const entry = invocationCounts.get(key)

  if (!entry || now > entry.resetAt) {
    invocationCounts.set(key, { count: 1, resetAt: now + 60_000 })
    return true
  }
  if (entry.count >= limit) return false
  entry.count++
  return true
}
