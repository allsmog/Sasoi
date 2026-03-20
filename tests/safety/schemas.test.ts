import { describe, it, expect } from 'vitest'
import { validatePersonaSafety } from '../../src/safety/schemas.js'

describe('PersonaDSLSchema safety validation', () => {
  const validPersona = {
    service: 'ssh',
    port: 22,
    banner: 'OpenSSH_8.9p1 Ubuntu-3ubuntu0.1',
    auth_behavior: 'delay-fail',
    egress: 'deny',
    sandbox: true,
    user: 'honeypot',
    cve_markers: ['CVE-2023-38408'],
  }

  it('accepts a valid persona', () => {
    const result = validatePersonaSafety(validPersona)
    expect(result.valid).toBe(true)
    expect(result.violations).toHaveLength(0)
  })

  it('rejects persona with egress not "deny"', () => {
    const result = validatePersonaSafety({ ...validPersona, egress: 'allow' })
    expect(result.valid).toBe(false)
    expect(result.violations.some((v) => v.includes('egress'))).toBe(true)
  })

  it('rejects persona with sandbox false', () => {
    const result = validatePersonaSafety({ ...validPersona, sandbox: false })
    expect(result.valid).toBe(false)
    expect(result.violations.some((v) => v.includes('sandbox'))).toBe(true)
  })

  it('rejects persona with root user', () => {
    const result = validatePersonaSafety({ ...validPersona, user: 'root' })
    expect(result.valid).toBe(false)
    expect(result.violations.some((v) => v.includes('root'))).toBe(true)
  })

  it('rejects persona with invalid service type', () => {
    const result = validatePersonaSafety({ ...validPersona, service: 'invalid' })
    expect(result.valid).toBe(false)
  })

  it('rejects persona with port out of range', () => {
    const result = validatePersonaSafety({ ...validPersona, port: 70000 })
    expect(result.valid).toBe(false)
  })

  it('rejects persona with invalid CVE format', () => {
    const result = validatePersonaSafety({ ...validPersona, cve_markers: ['not-a-cve'] })
    expect(result.valid).toBe(false)
  })

  it('rejects persona missing required fields', () => {
    const result = validatePersonaSafety({ service: 'ssh' })
    expect(result.valid).toBe(false)
    expect(result.violations.length).toBeGreaterThan(0)
  })

  it('accepts all valid service types', () => {
    const serviceTypes = [
      'ssh', 'http', 'https', 'ftp', 'telnet', 'smtp', 'pop3', 'imap',
      'mysql', 'postgres', 'redis', 'mongodb', 'smb', 'rdp',
    ]

    for (const service of serviceTypes) {
      const result = validatePersonaSafety({ ...validPersona, service })
      expect(result.valid).toBe(true)
    }
  })

  it('accepts all valid auth behaviors', () => {
    const behaviors = ['always-fail', 'fake-success', 'delay-fail', 'honeypot-response']

    for (const auth_behavior of behaviors) {
      const result = validatePersonaSafety({ ...validPersona, auth_behavior })
      expect(result.valid).toBe(true)
    }
  })

  it('accepts persona with valid breadcrumbs', () => {
    const result = validatePersonaSafety({
      ...validPersona,
      breadcrumbs: [
        {
          type: 'ssh_config',
          target_deployment_id: '550e8400-e29b-41d4-a716-446655440000',
          content: 'Host target\n  HostName 10.0.1.50\n  User admin',
          placement_path: '~/.ssh/config',
        },
        {
          type: 'bash_history',
          target_deployment_id: '550e8400-e29b-41d4-a716-446655440001',
          content: 'ssh admin@10.0.1.50',
        },
      ],
    })
    expect(result.valid).toBe(true)
  })

  it('rejects breadcrumb with invalid type', () => {
    const result = validatePersonaSafety({
      ...validPersona,
      breadcrumbs: [{
        type: 'invalid_type',
        target_deployment_id: '550e8400-e29b-41d4-a716-446655440000',
        content: 'test',
      }],
    })
    expect(result.valid).toBe(false)
  })

  it('rejects breadcrumb with non-UUID target_deployment_id', () => {
    const result = validatePersonaSafety({
      ...validPersona,
      breadcrumbs: [{
        type: 'ssh_config',
        target_deployment_id: 'not-a-uuid',
        content: 'test',
      }],
    })
    expect(result.valid).toBe(false)
  })

  it('rejects breadcrumb with content exceeding 4096 chars', () => {
    const result = validatePersonaSafety({
      ...validPersona,
      breadcrumbs: [{
        type: 'ssh_config',
        target_deployment_id: '550e8400-e29b-41d4-a716-446655440000',
        content: 'x'.repeat(4097),
      }],
    })
    expect(result.valid).toBe(false)
  })

  it('accepts persona without breadcrumbs (optional field)', () => {
    const result = validatePersonaSafety(validPersona)
    expect(result.valid).toBe(true)
  })

  it('accepts all valid breadcrumb types', () => {
    const types = ['ssh_config', 'bash_history', 'cached_credentials', 'known_hosts', 'aws_config', 'docker_config']
    for (const type of types) {
      const result = validatePersonaSafety({
        ...validPersona,
        breadcrumbs: [{
          type,
          target_deployment_id: '550e8400-e29b-41d4-a716-446655440000',
          content: 'test content',
        }],
      })
      expect(result.valid).toBe(true)
    }
  })
})
