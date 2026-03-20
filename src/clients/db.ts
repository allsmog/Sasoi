// Re-export all from domain submodules for backwards compatibility
export {
  createAgentSession,
  completeAgentSession,
  logToolInvocation,
  createProposal,
  getTenantAgentConfig,
  insertEscalation,
} from './db/agent.js'
export type { TenantAgentConfig, AgentSessionRow } from './db/agent.js'

export {
  queryEvents,
  correlateSessionsQuery,
  getEventEnrichment,
  updateEventEnrichment,
} from './db/events.js'
export type { EventRow } from './db/events.js'

export {
  insertInvestigation,
  getInvestigation,
  updateInvestigationReport,
  insertCampaign,
} from './db/investigations.js'
export type { InvestigationRow, CampaignRow } from './db/investigations.js'

export {
  queryDeployments,
  queryClusters,
  queryDestinations,
  updateDeploymentMetadata,
  upsertClusterInventory,
  getLatestInventory,
  queryDeploymentsByCluster,
} from './db/fleet.js'
export type { DeploymentRow, InventoryService } from './db/fleet.js'

export {
  insertHoneytoken,
  queryHoneytokens,
  getHoneytokenByValue,
  getHoneytokenById,
  recordHoneytokenAccess,
} from './db/honeytokens.js'
export type { HoneytokenRow } from './db/honeytokens.js'

export {
  getCloudConnector,
  queryCloudConnectors,
  insertCloudConnector,
  insertCloudDecoy,
} from './db/cloud.js'
export type { CloudConnectorRow, CloudDecoyRow } from './db/cloud.js'

export {
  insertResponseAction,
  computeTenantMetrics,
} from './db/metrics.js'
export type { ResponseActionRow } from './db/metrics.js'
