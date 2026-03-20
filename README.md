# Sasoi (誘い) — Autonomous AI Agents for Honeypot Orchestration

> *Sasoi* (誘い) — a judo term meaning "invitation" or "lure." In judo, sasoi draws the opponent into a committed attack that exposes them. In cybersecurity, Sasoi draws attackers into honeypots that expose their techniques.

Sasoi is an autonomous AI agent system that orchestrates sophisticated deception operations — honeypots, honeytokens, cloud decoys — at scale. Four specialized Claude-powered agents form a threat intelligence pipeline that enriches events, correlates attack campaigns, deploys intelligent traps, and adapts deception in real time.

Built on Cloudflare Workers with D1 and Claude as the agent backbone.

---

## Architecture

Four agents form an autonomous pipeline, each with distinct responsibilities and escalation paths:

```
┌─────────────┐    webhook     ┌─────────────┐   escalation   ┌───────────────┐
│  HOP Event  │───────────────▶│  Enricher   │───────────────▶│ Investigator  │
│  Ingestion  │                │ (Haiku 4.5) │                │  (Sonnet 4)   │
└─────────────┘                └─────────────┘                └───────┬───────┘
                                                                      │
                                                              campaign detected
                                                                      │
┌─────────────┐    cron (6hr)  ┌─────────────┐                ┌──────▼────────┐
│  Coverage   │◀───────────────│ Strategist  │                │  Responder    │
│  Analysis   │───────────────▶│  (Sonnet 4) │                │  (Sonnet 4)   │
└─────────────┘  deploy traps  └─────────────┘                └───────────────┘
```

| Agent | Model | Trigger | Role |
|-------|-------|---------|------|
| **Enricher** | Claude Haiku 4.5 | Realtime (webhooks) | GeoIP, threat intel, ML prediction, escalation decisions |
| **Investigator** | Claude Sonnet 4 | Cron (30 min) + escalation | Event correlation, campaign detection, MITRE ATT&CK mapping |
| **Strategist** | Claude Sonnet 4 | Cron (6 hr) + events | Coverage gap analysis, environment-aware honeypot deployment |
| **Responder** | Claude Sonnet 4 | Campaign detection | Adaptive deception, persona rotation, active response |

### Agent Details

**Enricher** — The first responder. Receives raw honeypot events via webhook and decides which enrichment steps to run. Skips expensive lookups for known scanners. Escalates to the Investigator when abuse score exceeds 80%, known malware is detected, or multiple honeypots are hit. Falco runtime alerts and honeytoken accesses are always escalated.

**Investigator** — The analyst. Correlates events across sessions, identifies attack campaigns (3+ honeypots from same source, subnet patterns, kill chain progression), and maps techniques to MITRE ATT&CK (T1078, T1110, T1046, T1068, and more). Reconstructs full kill chains by correlating Falco runtime alerts with network events.

**Strategist** — The architect. Analyzes threat landscape, identifies coverage gaps, and recommends honeypot deployments. Queries real cluster inventory to match image versions, naming patterns, and replica counts so traps blend with production. Generates decoy files (credentials, configs, backups) and breadcrumbs linking honeypots together.

**Responder** — The adapter. Activates when campaigns are detected. Increases logging depth, deploys canaries, rotates personas, and triggers notifications. With opt-in enabled, can block IPs (24h max TTL) and redirect attackers to higher-interaction honeypots. Requires explicit `responder_opt_in` flag + autonomy level ≥ 2 for active response.

---

## Safety & Governance

### 4-Level Autonomy System

| Level | Permissions |
|-------|-------------|
| **0** | Propose only — all mutations require human approval |
| **1** | Can rotate personas and adjust logging; deployments need approval |
| **2** | Can execute deployments, deploy canaries/honeytokens, and active response |
| **3** | Full autonomous operation |

### Human-in-the-Loop Proposals

When an agent attempts an action above its tenant's autonomy level, the action is queued as a **proposal** with:
- The full action payload and agent reasoning
- 24-hour expiry window
- Atomic approval/rejection (prevents double-approval race conditions)

### Security Controls

- **Prompt injection mitigation** — `sanitizeForPrompt()` strips control characters and enforces length limits on all attacker-controlled data. XML-tagged boundaries isolate untrusted content in agent prompts.
- **Cross-tenant authorization** — All queries filter by `tenant_id`. Every API endpoint validates tenant ownership.
- **Constant-time token comparison** — Bearer token auth uses `constantTimeEqual()` to prevent timing attacks.
- **HMAC webhook verification** — Internal webhooks signed with `HMAC-SHA256` via `X-HOP-Signature`.
- **Rate limiting** — Per-tenant, per-agent limits with automatic memory cleanup (purge at 500+ entries).
- **Persona safety validation** — Zod schemas enforce `egress: 'deny'`, `sandbox: true`, non-root user, and capabilities drop on all generated personas.
- **Error disclosure prevention** — Generic error messages on all auth failures; no stack traces in responses.
- **SSRF protection** — Cloud connector region and decoy type allowlists with tenant ownership validation.

---

## Deception Capabilities

### Honeypot Deployment
- 14 service types with configurable auth behaviors (always-fail, fake-success, delay-fail, honeypot-response)
- **Environment-aware matching** — queries real K8s cluster inventory to match image versions, naming patterns, namespaces, and replica counts so honeypots blend with production
- Security-hardened deployments: read-only filesystem, seccomp, capabilities drop, no new privileges

### Honeytoken Deployment
Six token types with realistic formats:

| Type | Format Example |
|------|----------------|
| AWS Access Key | `AKIA` + 16 alphanumeric chars |
| API Key | `sk-` + UUID |
| DB Connection String | `postgresql://admin:pass@10.x.x.x:5432/prod` |
| GitHub PAT | `ghp_` + 36 alphanumeric chars |
| Slack Webhook | `https://hooks.slack.com/services/T.../B.../...` |
| JWT Secret | Base64-encoded 32 random bytes |

Deployed as K8s Secrets, ConfigMaps, or environment variables. Access triggers immediate investigation — highest fidelity signal.

### Decoy Files
100+ realistic trap file templates per service type across four categories:
- **Credentials** — `~/.aws/credentials`, `~/.ssh/id_rsa`, `/var/www/.env`
- **Data** — database dumps, backup scripts with embedded passwords
- **System** — `.pgpass`, `.mongoshrc.js`, Docker configs
- **History** — `.bash_history` with sensitive commands

Each file is annotated for Falco file access monitoring.

### Breadcrumbs
Cross-references between honeypots that create a deception web:
- SSH configs pointing to other honeypots
- `.bash_history` entries with internal service references
- Cached credentials for adjacent systems
- `known_hosts`, AWS configs, Docker configs

Compromise one honeypot → breadcrumbs lead the attacker to others → full kill chain captured.

### Cloud Deception (Multi-Cloud)

| Provider | Decoy Types |
|----------|-------------|
| AWS | S3 buckets, IAM roles, Lambda functions |
| Azure | Blob storage, Managed identities |
| GCP | GCS buckets, Service accounts |

### Identity Deception
Decoy Kubernetes service accounts that appear as real workload identities. Token access triggers investigation.

### Falco Runtime Integration
In-container detection via Falco runtime alerts:
- Process execution, file access, network attempts inside honeypot containers
- Reverse shell detection, container escape attempts, lateral movement
- Always escalated to Investigator for correlation with network events

---

## Setup

```bash
# Install dependencies
npm install

# Create D1 database
npm run d1:create

# Run migrations
npm run d1:migrate:local

# Set secrets
wrangler secret put ANTHROPIC_API_KEY
wrangler secret put INTERNAL_API_SECRET
wrangler secret put API_KEY

# Development
npm run dev

# Deploy
npm run deploy
```

### Environment Variables

| Variable | Description |
|----------|-------------|
| `ANTHROPIC_API_KEY` | Claude API key for agent inference |
| `INTERNAL_API_SECRET` | HMAC signing key for internal webhooks |
| `API_KEY` | Bearer token for HTTP API authentication |

---

## Testing

```bash
npm test           # 200 tests across 32 files
npm run test:watch # Watch mode
```

Tests cover all layers of the system:

| Area | Files | Coverage |
|------|-------|----------|
| Agents | 6 | Initialization, tool calling, session management, error handling, Falco correlation |
| Middleware | 2 | Bearer auth, HMAC verification, timing-attack resistance |
| Safety | 3 | Autonomy enforcement, proposal creation, sanitization, persona schema validation |
| Tools | 13 | All 16 agent tools — queries, deployments, deception operations |
| Triggers | 8 | HTTP endpoints, webhook handlers, cron scheduling, rate limiting |

---

## API Reference

### HTTP Endpoints

All HTTP endpoints require `Authorization: Bearer <API_KEY>`.

#### Agent Triggers

| Method | Path | Rate Limit | Description |
|--------|------|------------|-------------|
| POST | `/v1/agents/enricher/run` | 100/min | Manual enricher trigger |
| POST | `/v1/agents/investigator/run` | 20/min | Manual investigator trigger |
| POST | `/v1/agents/strategist/run` | 5/min | Manual strategist trigger |
| POST | `/v1/agents/responder/run` | 10/min | Manual responder trigger |

#### Proposal Management

| Method | Path | Description |
|--------|------|-------------|
| GET | `/v1/proposals?tenant_id=` | List pending proposals |
| POST | `/v1/proposals/:id/approve` | Approve proposal (requires `tenant_id`, `reviewed_by`) |
| POST | `/v1/proposals/:id/reject` | Reject proposal (requires `tenant_id`, `reviewed_by`) |

#### Configuration & Observability

| Method | Path | Description |
|--------|------|-------------|
| GET | `/v1/sessions?tenant_id=` | Agent session history (limit 1–1000) |
| GET | `/v1/config/:tenantId` | Get tenant config (autonomy level, enabled agents, rate limits) |
| PUT | `/v1/config/:tenantId` | Update tenant config |
| GET | `/v1/metrics/:tenantId` | Operational metrics (supports `since`/`until` params) |
| POST | `/v1/cloud-connectors` | Register cloud connector |
| GET | `/v1/cloud-connectors?tenant_id=` | List cloud connectors |

#### Health

| Method | Path | Description |
|--------|------|-------------|
| GET | `/healthz` | Liveness check (always 200) |
| GET | `/readyz` | Readiness check (tests D1 connection) |

### Webhook Endpoints

Webhook endpoints require HMAC signature in `X-HOP-Signature` header.

| Path | Trigger |
|------|---------|
| `/v1/webhooks/event-ingested` | New honeypot event → Enricher |
| `/v1/webhooks/campaign-created` | Campaign flagged → Responder |
| `/v1/webhooks/cluster-inventory` | Cluster scan complete → inventory upsert |
| `/v1/webhooks/honeytoken-accessed` | Honeytoken used → access recording + investigation |
| `/v1/webhooks/cloud-decoy-accessed` | Cloud decoy triggered → access recording |

---

## Security Audit Status

Three rounds of deep security audits completed:

1. **JSON.parse crash guards** — all webhook/config parsing wrapped in try-catch
2. **Cross-tenant authorization** — explicit `tenant_id` checks on proposals, config, and metrics
3. **Prompt injection mitigation** — sanitization + XML-tagged data boundaries on all attacker-controlled input
4. **Atomic database operations** — honeytoken access recording and proposal status transitions
5. **Rate limiter memory cleanup** — purge at 500+ entries prevents unbounded growth
6. **Input validation** — IP format (IPv4/IPv6), token type enum, autonomy level bounds (0–3), date parsing
7. **Error information disclosure** — no stack traces or internal details in error responses
8. **Constant-time API key comparison** — timing-attack resistant
9. **SSRF protection** — region and decoy type allowlists on cloud connectors
10. **Unbounded query result limits** — explicit `LIMIT` clauses on all database queries
11. **Agent session failure handling** — failed sessions logged with error context

---

## Stack

| Component | Technology |
|-----------|------------|
| Runtime | Cloudflare Workers |
| Database | Cloudflare D1 (SQLite) |
| AI | Claude (Haiku 4.5, Sonnet 4) via pi-agent-core |
| Framework | Hono |
| Validation | Zod, TypeBox |
| Language | TypeScript 5.7 (strict mode) |
| Testing | Vitest + @cloudflare/vitest-pool-workers |
| Deployment | Wrangler |

---

## License

Proprietary. All rights reserved.
