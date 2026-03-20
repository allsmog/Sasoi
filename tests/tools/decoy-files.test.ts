import { describe, it, expect } from 'vitest'
import { createGenerateDecoyFilesTool } from '../../src/tools/decoy-files.js'

describe('createGenerateDecoyFilesTool', () => {
  const tool = createGenerateDecoyFilesTool()

  it('has correct metadata', () => {
    expect(tool.name).toBe('generate_decoy_files')
    expect(tool.label).toBe('Generate Decoy Files')
    expect(tool.description).toContain('decoy files')
  })

  it('generates SSH-appropriate files for SSH honeypot', async () => {
    const result = await tool.execute('call-1', { honeypot_type: 'ssh' })
    const files = JSON.parse(result.content[0].text)
    expect(files.length).toBeGreaterThan(0)
    const paths = files.map((f: { path: string }) => f.path)
    expect(paths.some((p: string) => p.includes('.ssh') || p.includes('credentials') || p.includes('shadow'))).toBe(true)
  })

  it('generates HTTP-appropriate files for HTTP honeypot', async () => {
    const result = await tool.execute('call-2', { honeypot_type: 'http' })
    const files = JSON.parse(result.content[0].text)
    expect(files.length).toBeGreaterThan(0)
    const paths = files.map((f: { path: string }) => f.path)
    expect(paths.some((p: string) => p.includes('/var/www') || p.includes('.env'))).toBe(true)
  })

  it('generates DB-appropriate files for mysql honeypot', async () => {
    const result = await tool.execute('call-3', { honeypot_type: 'mysql' })
    const files = JSON.parse(result.content[0].text)
    expect(files.length).toBeGreaterThan(0)
    const paths = files.map((f: { path: string }) => f.path)
    expect(paths.some((p: string) => p.includes('.my.cnf') || p.includes('dump.sql'))).toBe(true)
  })

  it('filters by category', async () => {
    const result = await tool.execute('call-4', { honeypot_type: 'ssh', categories: ['credentials'] })
    const files = JSON.parse(result.content[0].text)
    expect(files.length).toBeGreaterThan(0)
    for (const file of files) {
      expect(file.category).toBe('credentials')
    }
  })

  it('respects count limit', async () => {
    const result = await tool.execute('call-5', { honeypot_type: 'ssh', count: 2 })
    const files = JSON.parse(result.content[0].text)
    expect(files.length).toBeLessThanOrEqual(2)
  })

  it('generates fake AWS key format in SSH credentials', async () => {
    const result = await tool.execute('call-6', { honeypot_type: 'ssh', categories: ['credentials'] })
    const files = JSON.parse(result.content[0].text)
    const awsFile = files.find((f: { path: string }) => f.path.includes('credentials'))
    expect(awsFile).toBeDefined()
    expect(awsFile.content).toContain('AKIA')
  })
})
