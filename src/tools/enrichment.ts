import { Type } from '@sinclair/typebox'
import type { AgentTool } from '@mariozechner/pi-agent-core'
import type { Env } from '../config.js'
import * as enrichmentClient from '../clients/enrichment.js'
import { getEventEnrichment, updateEventEnrichment, insertEscalation } from '../clients/db.js'

export function createGeoipLookupTool(env: Env): AgentTool<typeof GeoipLookupParams> {
  return {
    name: 'geoip_lookup',
    label: 'GeoIP Lookup',
    description:
      'Look up geographic information for an IP address. Returns country, city, ASN, ISP, and timezone.',
    parameters: GeoipLookupParams,
    execute: async (_toolCallId, params) => {
      const result = (await enrichmentClient.enrichIP(env, params.ip)) as Record<string, unknown>
      return {
        content: [{ type: 'text' as const, text: JSON.stringify(result.geo ?? {}, null, 2) }],
        details: { ip: params.ip },
      }
    },
  }
}

export function createThreatIntelLookupTool(env: Env): AgentTool<typeof ThreatIntelParams> {
  return {
    name: 'threat_intel_lookup',
    label: 'Threat Intel Lookup',
    description:
      'Check an IP against threat intelligence sources (AbuseIPDB, VirusTotal, IPQualityScore, AlienVault OTX). Returns abuse confidence, malicious vendor counts, fraud score, proxy/VPN/Tor detection.',
    parameters: ThreatIntelParams,
    execute: async (_toolCallId, params) => {
      const result = (await enrichmentClient.enrichIP(env, params.ip)) as Record<string, unknown>
      return {
        content: [{ type: 'text' as const, text: JSON.stringify(result.threat ?? {}, null, 2) }],
        details: { ip: params.ip },
      }
    },
  }
}

export function createMlPredictTool(env: Env): AgentTool<typeof MlPredictParams> {
  return {
    name: 'ml_predict',
    label: 'ML Predict',
    description:
      'Run ML model prediction on event data. Returns threat classification, anomaly score, and predicted attacker intent.',
    parameters: MlPredictParams,
    execute: async (_toolCallId, params) => {
      const controller = new AbortController()
      const timeout = setTimeout(() => controller.abort(), 10_000)
      let res: Response
      try {
        res = await fetch(`${env.HOP_ML_URL}/predict`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(params.event_data),
          signal: controller.signal,
        })
      } finally {
        clearTimeout(timeout)
      }
      if (!res.ok) throw new Error(`ML service returned ${res.status}`)
      const prediction = await res.json()
      return {
        content: [{ type: 'text' as const, text: JSON.stringify(prediction, null, 2) }],
        details: { model: 'svc-ml' },
      }
    },
  }
}

export function createUpdateEventEnrichmentTool(env: Env): AgentTool<typeof UpdateEventEnrichmentParams> {
  return {
    name: 'update_event_enrichment',
    label: 'Update Event Enrichment',
    description:
      'Update the enrichment field of an event with new data (geo, threat intel, ML predictions). Merges with existing enrichment.',
    parameters: UpdateEventEnrichmentParams,
    execute: async (_toolCallId, params) => {
      const existing = await getEventEnrichment(env.DB, params.event_id)
      const current = existing?.enrichment ? JSON.parse(existing.enrichment as string) : {}
      const merged = { ...current, ...params.enrichment }
      await updateEventEnrichment(env.DB, params.event_id, merged)
      return {
        content: [{ type: 'text' as const, text: `Updated enrichment for event ${params.event_id}` }],
        details: { event_id: params.event_id },
      }
    },
  }
}

export function createEscalateToInvestigatorTool(env: Env): AgentTool<typeof EscalateParams> {
  return {
    name: 'escalate_to_investigator',
    label: 'Escalate to Investigator',
    description:
      'Escalate an event to the investigator agent for deeper analysis and correlation. Use when enrichment reveals high-risk indicators.',
    parameters: EscalateParams,
    execute: async (_toolCallId, params) => {
      await insertEscalation(env.DB, {
        source_agent: 'enricher',
        target_agent: 'investigator',
        event_id: params.event_id,
        tenant_id: params.tenant_id,
        reason: params.reason,
      })
      return {
        content: [{ type: 'text' as const, text: `Escalated event ${params.event_id} to investigator: ${params.reason}` }],
        details: { event_id: params.event_id },
      }
    },
  }
}

// --- Schemas ---

const GeoipLookupParams = Type.Object({
  ip: Type.String({ description: 'IP address to look up' }),
})

const ThreatIntelParams = Type.Object({
  ip: Type.String({ description: 'IP address to check against threat intelligence sources' }),
})

const MlPredictParams = Type.Object({
  event_data: Type.Object({
    src_ip: Type.String({ description: 'Source IP' }),
    signal: Type.String({ description: 'Event signal type' }),
    hp_type: Type.Optional(Type.String({ description: 'Honeypot type' })),
    ua: Type.Optional(Type.String({ description: 'User agent string' })),
  }),
})

const UpdateEventEnrichmentParams = Type.Object({
  event_id: Type.String({ description: 'Event UUID to update' }),
  enrichment: Type.Object({}, { description: 'Enrichment data to merge', additionalProperties: true }),
})

const EscalateParams = Type.Object({
  event_id: Type.String({ description: 'Event UUID that warrants investigation' }),
  tenant_id: Type.String({ description: 'Tenant UUID' }),
  reason: Type.String({ description: 'Why this event should be investigated' }),
})
