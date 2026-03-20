import { Type } from '@sinclair/typebox'
import type { AgentTool } from '@mariozechner/pi-agent-core'
import type { Env } from '../config.js'
import * as orchestrator from '../clients/orchestrator.js'
import * as blueprintClient from '../clients/blueprint.js'
import { createProposal } from '../clients/db.js'

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
        action_type: 'deploy_honeypot',
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
      'Deploy a canary honeypot to attract known attacker IPs. Generates a fresh persona tailored to the attack pattern.',
    parameters: DeployCanaryParams,
    execute: async (_toolCallId, params) => {
      const personaResult = (await blueprintClient.generatePersona(env, {
        service_type: params.service_type,
        complexity: 'high',
        target_environment: `Canary for tracking IPs: ${params.target_ips.join(', ')}`,
      })) as { persona: Record<string, unknown> }

      const proposalId = await createProposal(env.DB, env, {
        session_id: null,
        agent_type: 'responder',
        tenant_id: params.tenant_id,
        action_type: 'deploy_canary',
        action_payload: {
          service_type: params.service_type,
          target_ips: params.target_ips,
          persona: personaResult.persona,
        },
        reasoning: params.reasoning,
      })
      return {
        content: [{ type: 'text' as const, text: `Canary deployment proposed (ID: ${proposalId}). Service: ${params.service_type}, tracking ${params.target_ips.length} IPs.` }],
        details: { proposal_id: proposalId },
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
