import { z } from 'zod'

// Re-export safety-critical schemas from HOP shared-types
// These define the invariants agents must never bypass

export const PersonaDSLSchema = z.object({
  service: z.enum([
    'ssh', 'http', 'https', 'ftp', 'telnet', 'smtp', 'pop3', 'imap',
    'mysql', 'postgres', 'redis', 'mongodb', 'smb', 'rdp',
  ]),
  banner: z.string().optional(),
  port: z.number().int().min(1).max(65535),
  auth_behavior: z.enum(['always-fail', 'fake-success', 'delay-fail', 'honeypot-response']),
  users: z.array(z.string()).optional(),
  fake_credentials: z.array(z.object({ username: z.string(), password: z.string() })).optional(),
  egress: z.literal('deny'),
  allowed_destinations: z.array(z.string()).optional(),
  sandbox: z.literal(true),
  privileged: z.literal(false).optional(),
  user: z.string().refine((u) => u !== 'root', { message: 'user must not be root' }),
  cve_markers: z.array(z.string().regex(/^CVE-\d{4}-\d{4,}$/)).optional(),
  vulnerability_hints: z.array(z.string()).optional(),
  fs_layout: z.record(z.string()).optional(),
  fake_files: z.array(z.string()).optional(),
  file_contents: z.record(z.string()).optional(),
  response_templates: z.record(z.string()).optional(),
  error_messages: z.record(z.string()).optional(),
  protocols: z.record(z.unknown()).optional(),
  description: z.string().optional(),
  tags: z.array(z.string()).optional(),
  organization: z.string().optional(),
  environment_style: z.string().optional(),
  breadcrumbs: z.array(z.object({
    type: z.enum(['ssh_config', 'bash_history', 'cached_credentials', 'known_hosts', 'aws_config', 'docker_config']),
    target_deployment_id: z.string().uuid(),
    content: z.string().max(4096),
    placement_path: z.string().optional(),
  })).optional(),
})

export const BuildPlanSchema = z.object({
  dockerfile: z.string(),
  base_image: z.string(),
  hardening: z.object({
    non_root: z.literal(true),
    read_only_fs: z.literal(true),
    seccomp: z.literal(true),
    capabilities_drop: z.array(z.string()),
    no_new_privileges: z.literal(true),
  }),
  network_policy: z.object({
    egress: z.array(z.unknown()),
  }),
  deployment: z.object({
    security_context: z.record(z.unknown()),
  }),
})

// Validate that a persona meets HOP safety requirements
export function validatePersonaSafety(persona: unknown): { valid: boolean; violations: string[] } {
  const result = PersonaDSLSchema.safeParse(persona)
  if (result.success) return { valid: true, violations: [] }

  return {
    valid: false,
    violations: result.error.issues.map((i) => `${i.path.join('.')}: ${i.message}`),
  }
}
