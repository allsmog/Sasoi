import type { Env } from '../config.js'
import { logger } from '../config.js'
import { runInvestigator } from '../agents/investigator.js'
import { runStrategist } from '../agents/strategist.js'
import { checkRateLimit } from '../safety/guard.js'

// Called by Cloudflare Cron Triggers (defined in wrangler.toml)
export async function handleScheduled(event: ScheduledEvent, env: Env): Promise<void> {
  const cron = event.cron

  if (cron === '*/30 * * * *') {
    // Investigator sweep
    logger.info({}, 'Investigator cron triggered')
    let tenants: string[]
    try {
      tenants = await getActiveTenants(env, 'investigator')
    } catch (err) {
      logger.error({ err }, 'Failed to fetch active tenants for investigator cron')
      return
    }
    for (const tenantId of tenants) {
      if (!checkRateLimit(tenantId, 'investigator', 20)) continue
      try {
        await runInvestigator(env, { tenantId, trigger: 'cron' })
      } catch (err) {
        logger.error({ err, tenantId }, 'Investigator cron run failed')
      }
    }
  } else if (cron === '0 */6 * * *') {
    // Strategist analysis
    logger.info({}, 'Strategist cron triggered')
    let tenants: string[]
    try {
      tenants = await getActiveTenants(env, 'strategist')
    } catch (err) {
      logger.error({ err }, 'Failed to fetch active tenants for strategist cron')
      return
    }
    for (const tenantId of tenants) {
      if (!checkRateLimit(tenantId, 'strategist', 5)) continue
      try {
        await runStrategist(env, { tenantId, trigger: 'cron' })
      } catch (err) {
        logger.error({ err, tenantId }, 'Strategist cron run failed')
      }
    }
  }
}

async function getActiveTenants(env: Env, agentType: string): Promise<string[]> {
  const { results } = await env.DB.prepare(
    'SELECT tenant_id, enabled_agents FROM tenant_agent_config',
  ).all()

  return (results ?? [])
    .filter((row) => {
      try {
        const agents = JSON.parse(row.enabled_agents as string) as string[]
        return agents.includes(agentType)
      } catch {
        logger.error({ tenantId: row.tenant_id }, 'Corrupted enabled_agents config, skipping tenant')
        return false
      }
    })
    .map((row) => row.tenant_id as string)
}
