import { describe, expect, it } from 'vitest'
import { mount } from '@vue/test-utils'
import { h } from 'vue'
import { VApp } from 'vuetify/components'
import CvssScore from '../components/CvssScore.vue'
import { createPortalI18n } from '../i18n'
import { vuetify } from '../plugins/vuetify'
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

  it('offers the CVSS vector of Ubuntu\'s data to pointer and keyboard users, and shows a plain score without one', () => {
    const vector = 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H'
    const render = (props: { score: number | null, vector: string | null }) =>
      mount(() => h(VApp, null, { default: () => h(CvssScore, props) }), { global: { plugins: [createPortalI18n(), vuetify] } })
    const withVector = render({ score: null, vector })
    const cell = withVector.get('[data-testid="cvss-vector"]')
    expect(cell.text()).toBe('–')
    expect(cell.attributes('tabindex')).toBe('0')
    expect(cell.attributes('aria-label')).toBe(`CVSS –, vector ${vector}`)
    withVector.unmount()
    const without = render({ score: 7.5, vector: null })
    expect(without.find('[data-testid="cvss-vector"]').exists()).toBe(false)
    expect(without.text()).toBe('7.5')
    without.unmount()
  })
})
