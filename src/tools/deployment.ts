import { Type } from '@sinclair/typebox'
import type { AgentTool } from '@mariozechner/pi-agent-core'
import type { Env } from '../config.js'
import * as orchestrator from '../clients/orchestrator.js'
import * as blueprintClient from '../clients/blueprint.js'
import { createProposal } from '../clients/db.js'
import { validatePersonaSafety } from '../safety/schemas.js'

export interface DeploymentRequest {
  blueprint_id: string
  config: Record<string, unknown>
  deployment_location?: string
  connector_id?: string
  cluster_id?: string
}

export interface CanaryDeploymentPayload {
  service_type: string
  target_ips: string[]
  persona: Record<string, unknown>
  deployment_request: DeploymentRequest
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function extractDeploymentRequest(buildPlan: Record<string, unknown>): DeploymentRequest | null {
  const candidate = isRecord(buildPlan.deployment_request) ? buildPlan.deployment_request : buildPlan
  if (typeof candidate.blueprint_id !== 'string' || !isRecord(candidate.config)) {
    return null
  }

  return {
    blueprint_id: candidate.blueprint_id,
    config: candidate.config,
    deployment_location: typeof candidate.deployment_location === 'string' ? candidate.deployment_location : undefined,
    connector_id: typeof candidate.connector_id === 'string' ? candidate.connector_id : undefined,
    cluster_id: typeof candidate.cluster_id === 'string' ? candidate.cluster_id : undefined,
  }
}

export async function prepareCanaryDeploymentPayload(
  env: Env,
  params: { service_type: string; target_ips: string[] },
): Promise<CanaryDeploymentPayload> {
  const personaResult = (await blueprintClient.generatePersona(env, {
    service_type: params.service_type,
    complexity: 'high',
    target_environment: `Canary for tracking IPs: ${params.target_ips.join(', ')}`,
  })) as {
    persona: Record<string, unknown>
    buildPlan?: Record<string, unknown>
  }

  const safetyCheck = validatePersonaSafety(personaResult.persona)
  if (!safetyCheck.valid) {
    throw new Error(`Persona generation returned unsafe persona: ${safetyCheck.violations.join(', ')}`)
  }

  if (!isRecord(personaResult.buildPlan)) {
    throw new Error('Canary persona buildPlan missing from blueprint response')
  }

  const deploymentRequest = extractDeploymentRequest(personaResult.buildPlan)
  if (!deploymentRequest) {
    throw new Error('Canary buildPlan did not include an executable deployment request')
  }

  return {
    service_type: params.service_type,
    target_ips: params.target_ips,
    persona: personaResult.persona,
    deployment_request: deploymentRequest,
  }
}

export async function executeCanaryDeploymentRequest(
  env: Env,
  tenantId: string,
  payload: CanaryDeploymentPayload,
) {
  const result = await orchestrator.createDeployment(env, payload.deployment_request)
  return {
    tenant_id: tenantId,
    service_type: payload.service_type,
    target_ips: payload.target_ips,
    persona: payload.persona,
    deployment_request: payload.deployment_request,
    deployment_result: result,
  }
}

export function createProposeDeploymentTool(env: Env): AgentTool<typeof ProposeDeploymentParams> {
  return {
    name: 'propose_deployment',
    label: 'Propose Deployment',
    description:
      'Create a deployment proposal for operator review. At autonomy level 0, all deployments go through this path.',
    parameters: ProposeDeploymentParams,
    execute: async (_toolCallId, params) => {
      const proposalId = await createProposal(env.DB, env, {
        session_id: null,
        agent_type: 'strategist',
        tenant_id: params.tenant_id,
        action_type: 'execute_deployment',
        action_payload: {
          blueprint_id: params.blueprint_id,
          cluster_id: params.cluster_id,
          connector_id: params.connector_id,
          deployment_location: params.deployment_location ?? 'customer_managed',
          config: params.config ?? {},
        },
        reasoning: params.reasoning,
      })
      return {
        content: [{ type: 'text' as const, text: `Deployment proposal created (ID: ${proposalId}). Blueprint ${params.blueprint_id} awaiting operator approval.` }],
        details: { proposal_id: proposalId },
      }
    },
  }
}

export function createExecuteDeploymentTool(env: Env): AgentTool<typeof ExecuteDeploymentParams> {
  return {
    name: 'execute_deployment',
    label: 'Execute Deployment',
    description:
      'Directly execute a honeypot deployment via the orchestrator API. Requires autonomy level >= 2.',
    parameters: ExecuteDeploymentParams,
    execute: async (_toolCallId, params) => {
      const result = await orchestrator.createDeployment(env, {
        blueprint_id: params.blueprint_id,
        config: (params.config ?? {}) as Record<string, unknown>,
        deployment_location: params.deployment_location,
        connector_id: params.connector_id,
        cluster_id: params.cluster_id,
      })
      return {
        content: [{ type: 'text' as const, text: JSON.stringify(result, null, 2) }],
        details: { result },
      }
    },
  }
}

export function createDeployCanaryTool(env: Env): AgentTool<typeof DeployCanaryParams> {
  return {
    name: 'deploy_canary',
    label: 'Deploy Canary',
    description:
      'Deploy a canary honeypot to attract known attacker IPs. Generates a fresh persona and uses the blueprint build plan to launch the deployment.',
    parameters: DeployCanaryParams,
    execute: async (_toolCallId, params) => {
      const payload = await prepareCanaryDeploymentPayload(env, {
        service_type: params.service_type,
        target_ips: params.target_ips,
      })
      const result = await executeCanaryDeploymentRequest(env, params.tenant_id, payload)
      return {
        content: [{
          type: 'text' as const,
          text: JSON.stringify({
            service_type: params.service_type,
            target_ips: params.target_ips,
            deployment_request: payload.deployment_request,
            deployment_result: result.deployment_result,
          }, null, 2),
        }],
        details: result,
      }
    },
  }
}

const ProposeDeploymentParams = Type.Object({
  tenant_id: Type.String({ description: 'Tenant UUID' }),
  blueprint_id: Type.String({ description: 'Blueprint UUID to deploy' }),
  cluster_id: Type.Optional(Type.String({ description: 'Target cluster UUID' })),
  connector_id: Type.Optional(Type.String({ description: 'Connector UUID' })),
  deployment_location: Type.Optional(Type.String({ description: 'customer_managed or hop_shared' })),
  reasoning: Type.String({ description: 'Why this deployment is recommended' }),
  config: Type.Optional(Type.Object({}, { description: 'Additional deployment config', additionalProperties: true })),
})

const ExecuteDeploymentParams = Type.Object({
  blueprint_id: Type.String({ description: 'Blueprint UUID to deploy' }),
  config: Type.Optional(Type.Object({}, { description: 'Deployment configuration', additionalProperties: true })),
  deployment_location: Type.Optional(Type.String({ description: 'customer_managed or hop_shared' })),
  connector_id: Type.Optional(Type.String({ description: 'Connector UUID' })),
  cluster_id: Type.Optional(Type.String({ description: 'Target cluster UUID' })),
})

const DeployCanaryParams = Type.Object({
  tenant_id: Type.String({ description: 'Tenant UUID' }),
  service_type: Type.String({ description: 'Service type for canary honeypot' }),
  target_ips: Type.Array(Type.String(), { description: 'Attacker IPs to attract' }),
  reasoning: Type.String({ description: 'Why a canary is being deployed' }),
})
