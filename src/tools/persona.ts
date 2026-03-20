import { Type } from '@sinclair/typebox'
import type { AgentTool } from '@mariozechner/pi-agent-core'
import type { Env } from '../config.js'
import * as blueprintClient from '../clients/blueprint.js'
import * as orchestratorClient from '../clients/orchestrator.js'
import { validatePersonaSafety } from '../safety/schemas.js'

export function createGeneratePersonaTool(env: Env): AgentTool<typeof GeneratePersonaParams> {
  return {
    name: 'generate_persona',
    label: 'Generate Persona',
    description:
      'Generate a new honeypot persona via svc-ai-blueprint. All personas are safety-validated (egress:deny, sandbox:true, non-root).',
    parameters: GeneratePersonaParams,
    execute: async (_toolCallId, params) => {
      const result = (await blueprintClient.generatePersona(env, params)) as {
        persona: Record<string, unknown>
        buildPlan: Record<string, unknown>
        safety_validated: boolean
      }
      const safetyCheck = validatePersonaSafety(result.persona)
      if (!safetyCheck.valid) {
        return {
          content: [{ type: 'text' as const, text: `Persona generation returned unsafe persona. Violations: ${safetyCheck.violations.join(', ')}. Persona rejected.` }],
          details: { safe: false, violations: safetyCheck.violations },
        }
      }
      return {
        content: [{ type: 'text' as const, text: JSON.stringify(result, null, 2) }],
        details: { safe: true, service_type: params.service_type },
      }
    },
  }
}

export function createRotatePersonaTool(env: Env): AgentTool<typeof RotatePersonaParams> {
  return {
    name: 'rotate_persona',
    label: 'Rotate Persona',
    description:
      'Trigger persona rotation for an existing deployment. Generates a fresh persona identity while maintaining the same service type and security properties.',
    parameters: RotatePersonaParams,
    execute: async (_toolCallId, params) => {
      await orchestratorClient.rotatePersona(env, params.deployment_id)
      return {
        content: [{ type: 'text' as const, text: `Persona rotation triggered for deployment ${params.deployment_id}` }],
        details: { deployment_id: params.deployment_id },
      }
    },
  }
}

export function createGenerateVariationTool(env: Env): AgentTool<typeof GenerateVariationParams> {
  return {
    name: 'generate_persona_variation',
    label: 'Generate Variation',
    description:
      'Generate a variation of an existing persona for A/B testing honeypot strategies.',
    parameters: GenerateVariationParams,
    execute: async (_toolCallId, params) => {
      const result = await blueprintClient.generateVariation(env, params.persona_id)
      return {
        content: [{ type: 'text' as const, text: JSON.stringify(result, null, 2) }],
        details: { persona_id: params.persona_id },
      }
    },
  }
}

const GeneratePersonaParams = Type.Object({
  service_type: Type.String({ description: 'Honeypot service type: ssh, http, https, ftp, telnet, smtp, pop3, imap, mysql, postgres, redis, mongodb, smb, rdp' }),
  complexity: Type.Optional(Type.String({ description: 'Persona complexity: low, medium, high' })),
  target_environment: Type.Optional(Type.String({ description: 'Target environment description' })),
  cve_hints: Type.Optional(Type.Array(Type.String(), { description: 'CVE IDs to simulate' })),
})

const RotatePersonaParams = Type.Object({
  deployment_id: Type.String({ description: 'Deployment UUID to rotate persona for' }),
})

const GenerateVariationParams = Type.Object({
  persona_id: Type.String({ description: 'Existing persona ID to create a variation of' }),
})
