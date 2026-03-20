import { Type } from '@sinclair/typebox'
import type { AgentTool } from '@mariozechner/pi-agent-core'
import type { Env } from '../config.js'
import { getCloudConnector, insertCloudDecoy } from '../clients/db.js'
import * as orchestrator from '../clients/orchestrator.js'

const DeployCloudDecoyParams = Type.Object({
  tenant_id: Type.String({ description: 'Tenant UUID' }),
  connector_id: Type.String({ description: 'Cloud connector ID (registered via API)' }),
  decoy_type: Type.String({ description: 'Decoy type: s3_bucket, iam_role, lambda_function, blob_storage, managed_identity, gcs_bucket, service_account' }),
  region: Type.Optional(Type.String({ description: 'Cloud region (e.g., us-east-1, westus2, us-central1)' })),
  config: Type.Optional(Type.Object({}, { description: 'Provider-specific configuration', additionalProperties: true })),
})

export function createDeployCloudDecoyTool(env: Env): AgentTool<typeof DeployCloudDecoyParams> {
  return {
    name: 'deploy_cloud_decoy',
    label: 'Deploy Cloud Decoy',
    description:
      'Deploy a cloud deception resource (S3 bucket, IAM role, Lambda, Blob storage, etc.) via the orchestrator. The orchestrator handles cloud provider APIs — agentic-hop stays cloud-agnostic.',
    parameters: DeployCloudDecoyParams,
    execute: async (_toolCallId, params) => {
      // Validate connector belongs to tenant and is active
      const connector = await getCloudConnector(env.DB, params.connector_id)
      if (!connector) {
        return {
          content: [{ type: 'text' as const, text: 'Cloud connector not found.' }],
          details: { error: 'connector_not_found' },
        }
      }
      if (connector.tenant_id !== params.tenant_id) {
        return {
          content: [{ type: 'text' as const, text: 'Cloud connector does not belong to this tenant.' }],
          details: { error: 'tenant_mismatch' },
        }
      }
      if (connector.status !== 'active') {
        return {
          content: [{ type: 'text' as const, text: 'Cloud connector is not active.' }],
          details: { error: 'connector_inactive' },
        }
      }

      // Check region allowlist
      const enabledRegions: string[] = JSON.parse((connector.enabled_regions as string) ?? '[]')
      if (params.region && enabledRegions.length > 0 && !enabledRegions.includes(params.region)) {
        return {
          content: [{ type: 'text' as const, text: `Region ${params.region} not in connector's allowed regions: ${enabledRegions.join(', ')}` }],
          details: { error: 'region_not_allowed' },
        }
      }

      // Check decoy type allowlist
      const allowedTypes: string[] = JSON.parse((connector.allowed_decoy_types as string) ?? '[]')
      if (allowedTypes.length > 0 && !allowedTypes.includes(params.decoy_type)) {
        return {
          content: [{ type: 'text' as const, text: `Decoy type ${params.decoy_type} not in connector's allowed types: ${allowedTypes.join(', ')}` }],
          details: { error: 'decoy_type_not_allowed' },
        }
      }

      // Call orchestrator to create the cloud decoy
      const result = await orchestrator.createCloudDecoy(env, {
        connector_id: params.connector_id,
        provider: connector.provider as string,
        decoy_type: params.decoy_type,
        region: params.region,
        config: params.config ?? {},
      }) as { resource_ref?: string; monitoring_status?: string }

      // Store in DB
      const decoyId = await insertCloudDecoy(env.DB, {
        tenant_id: params.tenant_id,
        connector_id: params.connector_id,
        provider: connector.provider as string,
        decoy_type: params.decoy_type,
        resource_ref: result.resource_ref,
        region: params.region,
        monitoring_status: result.monitoring_status ?? 'pending',
      })

      return {
        content: [{
          type: 'text' as const,
          text: JSON.stringify({
            decoy_id: decoyId,
            provider: connector.provider,
            decoy_type: params.decoy_type,
            region: params.region,
            resource_ref: result.resource_ref,
            monitoring_status: result.monitoring_status ?? 'pending',
            message: 'Cloud decoy deployed. Monitoring pipeline being configured by orchestrator.',
          }, null, 2),
        }],
        details: { decoy_id: decoyId, provider: connector.provider },
      }
    },
  }
}
