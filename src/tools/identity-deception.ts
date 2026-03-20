import { Type } from '@sinclair/typebox'
import type { AgentTool } from '@mariozechner/pi-agent-core'
import type { Env } from '../config.js'
import { insertHoneytoken } from '../clients/db.js'
import * as orchestrator from '../clients/orchestrator.js'

const DeployDecoyServiceAccountParams = Type.Object({
  tenant_id: Type.String({ description: 'Tenant UUID' }),
  cluster_id: Type.String({ description: 'Target cluster ID' }),
  namespace: Type.String({ description: 'Target Kubernetes namespace' }),
  service_account_name: Type.Optional(Type.String({ description: 'Name for the decoy service account (auto-generated if omitted)' })),
  placement_reasoning: Type.Optional(Type.String({ description: 'Why this decoy SA is being placed here' })),
})

export function createDeployDecoyServiceAccountTool(env: Env): AgentTool<typeof DeployDecoyServiceAccountParams> {
  return {
    name: 'deploy_decoy_sa',
    label: 'Deploy Decoy Service Account',
    description:
      'Deploy a decoy Kubernetes service account that looks like a real workload identity. Access triggers immediate investigation.',
    parameters: DeployDecoyServiceAccountParams,
    execute: async (_toolCallId, params) => {
      const saName = params.service_account_name ?? `svc-${crypto.randomUUID().slice(0, 8)}`

      // Create via orchestrator
      const result = await orchestrator.createServiceAccount(env, {
        cluster_id: params.cluster_id,
        namespace: params.namespace,
        name: saName,
      }) as { token?: string }

      const tokenValue = result.token ?? `k8s-sa-${crypto.randomUUID()}`

      // Track as a honeytoken with type k8s_service_account
      const honeytokenId = await insertHoneytoken(env.DB, {
        tenant_id: params.tenant_id,
        token_type: 'k8s_service_account',
        token_value: tokenValue,
        deployment_method: 'k8s_secret',
        cluster_id: params.cluster_id,
        namespace: params.namespace,
        placement_reasoning: params.placement_reasoning ?? `Decoy service account: ${saName}`,
      })

      return {
        content: [{
          type: 'text' as const,
          text: JSON.stringify({
            honeytoken_id: honeytokenId,
            service_account_name: saName,
            namespace: params.namespace,
            cluster_id: params.cluster_id,
            message: 'Decoy service account deployed. Token access will trigger investigation.',
          }, null, 2),
        }],
        details: { honeytoken_id: honeytokenId, service_account_name: saName },
      }
    },
  }
}
