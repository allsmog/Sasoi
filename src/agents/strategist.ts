import { Agent } from '@mariozechner/pi-agent-core'
import { getModel } from '@mariozechner/pi-ai'
import type { Env } from '../config.js'
import { logger } from '../config.js'
import { createQueryEventsTool } from '../tools/events.js'
import { createQueryFleetTool, createQueryClustersTool, createQueryInventoryTool } from '../tools/fleet.js'
import { createThreatIntelLookupTool } from '../tools/enrichment.js'
import { createGeneratePersonaTool } from '../tools/persona.js'
import { createProposeDeploymentTool, createExecuteDeploymentTool } from '../tools/deployment.js'
import { createGenerateDecoyFilesTool } from '../tools/decoy-files.js'
import { createGenerateBreadcrumbsTool } from '../tools/breadcrumbs.js'
import { createDeployHoneytokenTool, createQueryHoneytokensTool } from '../tools/honeytokens.js'
import { createDeployCloudDecoyTool } from '../tools/cloud-deception.js'
import { createDeployDecoyServiceAccountTool } from '../tools/identity-deception.js'
import { withMutationGuard } from '../tools/mutation.js'
import { SafetyGuard } from '../safety/guard.js'
import { sanitizeForPrompt } from '../safety/sanitize.js'
import { createAgentSession, completeAgentSession, getTenantAgentConfig } from '../clients/db.js'

const STRATEGIST_SYSTEM_PROMPT = `You are the Strategist Agent for the Honeypot Orchestration Platform (HOP).

Your role is to analyze the threat landscape per tenant and recommend or deploy honeypots to maximize intelligence collection and coverage.

## Analysis Framework

1. **Current coverage**: Query the fleet to understand deployed honeypots.
2. **Threat landscape**: Query recent events to understand attack patterns.
3. **Coverage gaps**: Identify services being attacked without coverage.
4. **Cluster capacity**: Check available clusters.
5. **Recommendations**: Generate personas and propose/execute deployments.

## Autonomy Levels

- **Level 0** (default): Use propose_deployment for ALL deployments.
- **Level 1**: Can rotate personas automatically, new deployments need approval.
- **Level 2**: Can execute new deployments within resource limits.
- **Level 3**: Full autonomy.

## Environment-Aware Deception

When cluster inventory is available (query_inventory tool), use it to:
1. Match honeypot service types to real services in the cluster.
2. Use the same image versions (e.g. if cluster runs redis:7.2.4, generate redis:7.2.4 honeypot).
3. Follow the cluster's naming patterns (if deployments are named "service-role-env", name honeypots similarly).
4. Place honeypots in the same namespaces as real services.
5. Match replica counts (if real Redis has 3 replicas, honeypot should be a "4th replica").

The goal: an attacker doing kubectl get pods should not be able to distinguish honeypots from real services.

## Decoy File Placement

Use generate_decoy_files to create realistic trap files when generating personas.
Match file categories to honeypot type. Place credential files where attackers look.
Pass results into persona's fake_files/file_contents. Falco monitors file access.

## Breadcrumb Placement

Use generate_breadcrumbs to create cross-references between honeypots.
SSH configs, bash_history, cached credentials create a deception web.
Attackers who compromise one honeypot will be led to others.

## Honeytokens

Use deploy_honeytoken to place fake credentials as K8s Secrets.
Access triggers immediate investigation — highest-fidelity signal.
Use query_honeytokens to check existing deployments.

## Cloud Deception

Use deploy_cloud_decoy to place decoy resources in cloud environments.
S3 buckets, IAM roles, Lambda functions — orchestrator handles cloud APIs.
Requires registered cloud connector for the tenant.

## Identity Deception

Use deploy_decoy_sa to place decoy Kubernetes service accounts.
Access triggers immediate investigation.

## Safety Constraints

All personas MUST have egress: "deny", sandbox: true, non-root user. Enforced by svc-ai-blueprint.`

export async function runStrategist(
  env: Env,
  params: {
    tenantId: string
    trigger: 'cron' | 'cluster_registration' | 'threat_intel_update' | 'http'
    context?: { clusterId?: string; reason?: string }
  },
): Promise<void> {
  const sessionId = await createAgentSession(env.DB, {
    agent_type: 'strategist',
    trigger_type: params.trigger === 'cron' ? 'cron' : params.trigger === 'http' ? 'http' : 'realtime',
    trigger_source: params.context?.clusterId ? `cluster:${params.context.clusterId}` : `trigger:${params.trigger}`,
    tenant_id: params.tenantId,
  })

  const guard = new SafetyGuard({ sessionId, agentType: 'strategist', tenantId: params.tenantId, env })
  const tenantConfig = await getTenantAgentConfig(env.DB, env, params.tenantId)
  const mutationCtx = { env, tenantId: params.tenantId, sessionId, agentType: 'strategist' }

  const agent = new Agent({
    initialState: {
      systemPrompt: STRATEGIST_SYSTEM_PROMPT,
      model: getModel('anthropic', 'claude-sonnet-4-20250514'),
      tools: [
        createQueryEventsTool(env),
        createQueryFleetTool(env),
        createQueryClustersTool(env),
        createQueryInventoryTool(env),
        createThreatIntelLookupTool(env),
        createGeneratePersonaTool(env),
        createProposeDeploymentTool(env),
        createGenerateDecoyFilesTool(env),
        createGenerateBreadcrumbsTool(env),
        createQueryHoneytokensTool(env),
        ...(tenantConfig.autonomy_level >= 2 ? [
          withMutationGuard(createExecuteDeploymentTool(env), mutationCtx),
          withMutationGuard(createDeployHoneytokenTool(env), mutationCtx, {
            buildReasoning: (toolParams) => toolParams.placement_reasoning ?? `Deploy ${toolParams.token_type} honeytoken`,
          }),
          withMutationGuard(createDeployCloudDecoyTool(env), mutationCtx, {
            buildReasoning: (toolParams) => `Deploy ${toolParams.decoy_type} cloud decoy`,
          }),
          withMutationGuard(createDeployDecoyServiceAccountTool(env), mutationCtx, {
            buildReasoning: (toolParams) => toolParams.placement_reasoning ?? `Deploy decoy service account in ${toolParams.namespace}`,
          }),
        ] : []),
      ],
      messages: [],
      thinkingLevel: 'medium',
    },
    getApiKey: async (provider) => {
      if (provider === 'anthropic') return env.ANTHROPIC_API_KEY
      return undefined
    },
  })

  agent.subscribe(guard.createEventSubscriber())

  try {
    let prompt: string
    if (params.trigger === 'cron') {
      prompt = `Perform strategic analysis for tenant ${params.tenantId}.\n\nAutonomy level: ${tenantConfig.autonomy_level}\n\n1. Query fleet for coverage.\n2. Query events (last 7 days) for threat landscape.\n3. Query cluster inventory (if available) to understand real services and naming patterns.\n4. Identify coverage gaps.\n5. Check cluster capacity.\n6. Recommend/deploy honeypots — if inventory is available, generate environment-aware personas that blend in.\n\n${tenantConfig.autonomy_level < 2 ? 'Use propose_deployment — operator approval required.' : 'You may execute deployments directly.'}`
    } else if (params.trigger === 'cluster_registration') {
      prompt = `New cluster registered for tenant ${sanitizeForPrompt(params.tenantId)}.\n\n<event_data>\nCluster ID: ${sanitizeForPrompt(params.context?.clusterId)}\n</event_data>\n\nQuery cluster, assess coverage, recommend initial deployments.`
    } else {
      prompt = `${sanitizeForPrompt(params.context?.reason, 500) || `Strategic analysis requested for tenant ${params.tenantId}.`}\n\nAutonomy level: ${tenantConfig.autonomy_level}`
    }

    await agent.prompt(prompt)
    await agent.waitForIdle()
    await completeAgentSession(env.DB, sessionId, { status: 'completed' })
    logger.info({ sessionId, tenantId: params.tenantId }, 'Strategist agent completed')
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err)
    try {
      await completeAgentSession(env.DB, sessionId, { status: 'failed', error_message: message })
    } catch (dbErr) {
      logger.error({ dbErr, sessionId }, 'Failed to record strategist session failure')
    }
    logger.error({ err, sessionId }, 'Strategist agent failed')
    throw err
  }
}
