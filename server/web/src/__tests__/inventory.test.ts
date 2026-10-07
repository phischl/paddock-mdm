import { describe, expect, it } from 'vitest'
import { formatScore, hasVulnerabilities, hasVulnerabilitiesFilter, severities, severityFilter } from '../lib/inventory'
import en from '../locales/en.json'

describe('inventory', () => {
  it('filters by every severity, each with a label, unknown included (Fleet free reports no score)', () => {
    expect(severityFilter.kind === 'enum' && severityFilter.options.map((o) => o.value)).toEqual(severities)
    expect(severities).toContain('unknown')
    for (const s of severities) expect(en.inventory.severities[s]).toBeTruthy()
  })

  it('filters by matched CVEs only when exactly one of yes and no is chosen', () => {
    const p = { page: 1, page_size: 25 as const, sort: 'name' }
    expect(hasVulnerabilities({ ...p, has_vulnerabilities: ['true'] })).toBe(true)
    expect(hasVulnerabilities({ ...p, has_vulnerabilities: ['false'] })).toBe(false)
    expect(hasVulnerabilities({ ...p, has_vulnerabilities: ['true', 'false'] })).toBeUndefined()
    expect(hasVulnerabilities(p)).toBeUndefined()
    expect(hasVulnerabilitiesFilter.kind === 'enum' && hasVulnerabilitiesFilter.options.map((o) => o.value)).toEqual(['true', 'false'])
  })

  it('shows scores with one decimal and a dash when unknown', () => {
    expect(formatScore(9.8)).toBe('9.8')
    expect(formatScore(7)).toBe('7.0')
    expect(formatScore(null)).toBe('–')
    expect(formatScore(undefined)).toBe('–')
  })
})
