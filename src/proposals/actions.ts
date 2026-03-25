import { z } from 'zod'
import type { Env } from '../config.js'
import { getCloudConnector } from '../clients/db.js'
import { getClusterById, getDeploymentById } from '../clients/db.js'
import { createExecuteDeploymentTool } from '../tools/deployment.js'
import { createRotatePersonaTool, createGenerateVariationTool } from '../tools/persona.js'
import { createIncreaseLoggingDepthTool } from '../tools/notification.js'
import { createDeployHoneytokenTool } from '../tools/honeytokens.js'
import { createBlockIPTool, createRedirectAttackerTool } from '../tools/response.js'
import { createDeployCloudDecoyTool } from '../tools/cloud-deception.js'
import { createDeployDecoyServiceAccountTool } from '../tools/identity-deception.js'
import { executeCanaryDeploymentRequest, type CanaryDeploymentPayload } from '../tools/deployment.js'

const recordSchema = z.record(z.string(), z.unknown())

const executeDeploymentSchema = z.object({
  blueprint_id: z.string(),
  config: recordSchema,
  deployment_location: z.string().optional(),
  connector_id: z.string().optional(),
  cluster_id: z.string().optional(),
})

const deployCanarySchema = z.object({
  service_type: z.string(),
  target_ips: z.array(z.string()).min(1),
  persona: recordSchema,
  deployment_request: executeDeploymentSchema,
})

const rotatePersonaSchema = z.object({
  deployment_id: z.string(),
})

const generateVariationSchema = z.object({
  persona_id: z.string(),
})

const increaseLoggingSchema = z.object({
  deployment_id: z.string(),
  level: z.string(),
  duration_minutes: z.number().min(5).max(60),
  reason: z.string(),
})

const deployHoneytokenSchema = z.object({
  token_type: z.string(),
  deployment_method: z.string(),
  cluster_id: z.string().optional(),
  namespace: z.string().optional(),
  placement_reasoning: z.string().optional(),
})

const blockIpSchema = z.object({
  ip: z.string(),
  cluster_id: z.string(),
  ttl_seconds: z.number().min(60).max(86400).optional(),
  reason: z.string(),
})

const redirectAttackerSchema = z.object({
  source_deployment_id: z.string(),
  target_deployment_id: z.string(),
  attacker_ip: z.string(),
  reason: z.string(),
})

const deployCloudDecoySchema = z.object({
  connector_id: z.string(),
  decoy_type: z.string(),
  region: z.string().optional(),
  config: recordSchema.optional(),
})

const deployDecoyServiceAccountSchema = z.object({
  cluster_id: z.string(),
  namespace: z.string(),
  service_account_name: z.string().optional(),
  placement_reasoning: z.string().optional(),
})

export type ProposalActionType =
  | 'execute_deployment'
  | 'deploy_canary'
  | 'rotate_persona'
  | 'generate_persona_variation'
  | 'increase_logging_depth'
  | 'deploy_honeytoken'
  | 'block_ip'
  | 'redirect_attacker'
  | 'deploy_cloud_decoy'
  | 'deploy_decoy_sa'

export class ProposalActionError extends Error {
  constructor(
    message: string,
    readonly httpStatus: number,
  ) {
    super(message)
  }
}

interface ProposalExecutionContext {
  env: Env
  tenantId: string
}

interface ProposalActionDefinition {
  schema: z.ZodTypeAny
  execute: (ctx: ProposalExecutionContext, payload: any) => Promise<unknown>
}

const actionSchemas = {
  execute_deployment: executeDeploymentSchema,
  deploy_canary: deployCanarySchema,
  rotate_persona: rotatePersonaSchema,
  generate_persona_variation: generateVariationSchema,
  increase_logging_depth: increaseLoggingSchema,
  deploy_honeytoken: deployHoneytokenSchema,
  block_ip: blockIpSchema,
  redirect_attacker: redirectAttackerSchema,
  deploy_cloud_decoy: deployCloudDecoySchema,
  deploy_decoy_sa: deployDecoyServiceAccountSchema,
} as const

async function assertDeploymentOwnership(env: Env, tenantId: string, deploymentId: string): Promise<void> {
  const row = await getDeploymentById(env.DB, deploymentId)
  if (!row) throw new ProposalActionError(`Deployment ${deploymentId} not found.`, 404)
  if (row.tenant_id !== tenantId) {
    throw new ProposalActionError(`Deployment ${deploymentId} does not belong to tenant ${tenantId}.`, 403)
  }
}

async function assertClusterOwnership(env: Env, tenantId: string, clusterId: string): Promise<void> {
  const row = await getClusterById(env.DB, clusterId)
  if (!row) throw new ProposalActionError(`Cluster ${clusterId} not found.`, 404)
  if ((row.tenant_id as string) !== tenantId) {
    throw new ProposalActionError(`Cluster ${clusterId} does not belong to tenant ${tenantId}.`, 403)
  }
}

async function assertConnectorOwnership(env: Env, tenantId: string, connectorId: string): Promise<void> {
  const row = await getCloudConnector(env.DB, connectorId)
  if (!row) throw new ProposalActionError(`Cloud connector ${connectorId} not found.`, 404)
  if ((row.tenant_id as string) !== tenantId) {
    throw new ProposalActionError(`Cloud connector ${connectorId} does not belong to tenant ${tenantId}.`, 403)
  }
}

const actionDefinitions: Record<ProposalActionType, ProposalActionDefinition> = {
  execute_deployment: {
    schema: executeDeploymentSchema,
    execute: async ({ env, tenantId }, payload) => {
      if (payload.cluster_id) {
        await assertClusterOwnership(env, tenantId, payload.cluster_id)
      }
      if (payload.connector_id) {
        await assertConnectorOwnership(env, tenantId, payload.connector_id)
      }

      const tool = createExecuteDeploymentTool(env)
      const result = await tool.execute('proposal-execution', payload)
      return result.details
    },
  },
  deploy_canary: {
    schema: deployCanarySchema,
    execute: async ({ env, tenantId }, payload) => {
      if (payload.deployment_request.cluster_id) {
        await assertClusterOwnership(env, tenantId, payload.deployment_request.cluster_id)
      }
      if (payload.deployment_request.connector_id) {
        await assertConnectorOwnership(env, tenantId, payload.deployment_request.connector_id)
      }

      return executeCanaryDeploymentRequest(env, tenantId, payload as CanaryDeploymentPayload)
    },
  },
  rotate_persona: {
    schema: rotatePersonaSchema,
    execute: async ({ env, tenantId }, payload) => {
      await assertDeploymentOwnership(env, tenantId, payload.deployment_id)
      const tool = createRotatePersonaTool(env)
      const result = await tool.execute('proposal-execution', payload)
      return result.details
    },
  },
  generate_persona_variation: {
    schema: generateVariationSchema,
    execute: async ({ env }, payload) => {
      const tool = createGenerateVariationTool(env)
      const result = await tool.execute('proposal-execution', payload)
      return result.details
    },
  },
  increase_logging_depth: {
    schema: increaseLoggingSchema,
    execute: async ({ env, tenantId }, payload) => {
      await assertDeploymentOwnership(env, tenantId, payload.deployment_id)
      const tool = createIncreaseLoggingDepthTool(env)
      const result = await tool.execute('proposal-execution', payload)
      return result.details
    },
  },
  deploy_honeytoken: {
    schema: deployHoneytokenSchema,
    execute: async ({ env, tenantId }, payload) => {
      if (payload.cluster_id) {
        await assertClusterOwnership(env, tenantId, payload.cluster_id)
      }
      const tool = createDeployHoneytokenTool(env)
      const result = await tool.execute('proposal-execution', { tenant_id: tenantId, ...payload })
      return result.details
    },
  },
  block_ip: {
    schema: blockIpSchema,
    execute: async ({ env, tenantId }, payload) => {
      await assertClusterOwnership(env, tenantId, payload.cluster_id)
      const tool = createBlockIPTool(env)
      const result = await tool.execute('proposal-execution', { tenant_id: tenantId, ...payload })
      return result.details
    },
  },
  redirect_attacker: {
    schema: redirectAttackerSchema,
    execute: async ({ env, tenantId }, payload) => {
      await assertDeploymentOwnership(env, tenantId, payload.source_deployment_id)
      await assertDeploymentOwnership(env, tenantId, payload.target_deployment_id)
      const tool = createRedirectAttackerTool(env)
      const result = await tool.execute('proposal-execution', { tenant_id: tenantId, ...payload })
      return result.details
    },
  },
  deploy_cloud_decoy: {
    schema: deployCloudDecoySchema,
    execute: async ({ env, tenantId }, payload) => {
      await assertConnectorOwnership(env, tenantId, payload.connector_id)
      const tool = createDeployCloudDecoyTool(env)
      const result = await tool.execute('proposal-execution', { tenant_id: tenantId, ...payload })
      return result.details
    },
  },
  deploy_decoy_sa: {
    schema: deployDecoyServiceAccountSchema,
    execute: async ({ env, tenantId }, payload) => {
      await assertClusterOwnership(env, tenantId, payload.cluster_id)
      const tool = createDeployDecoyServiceAccountTool(env)
      const result = await tool.execute('proposal-execution', { tenant_id: tenantId, ...payload })
      return result.details
    },
  },
}

export function getProposalActionDefinition(actionType: string) {
  return actionDefinitions[actionType as ProposalActionType]
}
