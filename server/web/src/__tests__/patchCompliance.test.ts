import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { h } from 'vue'
import { createPinia, setActivePinia } from 'pinia'
import { createMemoryHistory, createRouter, RouterView, type Router } from 'vue-router'
import { flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import { VApp } from 'vuetify/components'
import PatchComplianceView from '../views/PatchCompliance.vue'
import PatchSlaSettingsView from '../views/PatchSlaSettings.vue'
import { createPortalI18n } from '../i18n'
import { vuetify } from '../plugins/vuetify'
import { useSessionStore } from '../stores/session'
import {
  patchCells, patchExportUrl, patchSections, validSlaDays, type PatchComplianceReport, type PatchSlaSettings, type PatchSlaSettingsUpdate,
} from '../lib/patchCompliance'
import { navigationGroups } from '../lib/navigation'

let report: PatchComplianceReport
let problem: string | null
const getReport = vi.fn<(group: string) => Promise<PatchComplianceReport | string>>()
const save = vi.fn<(s: PatchSlaSettingsUpdate) => Promise<PatchSlaSettings | string>>()
const stored: PatchSlaSettings = { critical_days: 7, high_days: 30, medium_days: 90, low_days: 0, updated_at: '2026-11-14T08:00:00Z' }

vi.mock('../lib/patchCompliance', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/patchCompliance')>()),
  getPatchCompliance: (group: string) => getReport(group),
  getPatchSla: () => Promise.resolve({ ...stored }),
  savePatchSla: (s: PatchSlaSettingsUpdate) => save(s),
}))
vi.mock('../lib/devices', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/devices')>()),
  allGroups: () => Promise.resolve([{ id: 'g-1', name: 'laptops' }]),
}))

function fullReport(): PatchComplianceReport {
  return {
    generated_at: '2026-11-14T10:00:00Z', device_group_id: null,
    sla: { critical_days: 7, high_days: 30, medium_days: 90, low_days: 0 },
    summary: { devices: 3, compliant: 2, breached: 1 },
    by_severity: [
      { severity: 'critical', findings_open: 2, findings_breached: 1, median_days_open: 6, p90_days_open: 8 },
      { severity: 'high', findings_open: 1, findings_breached: 0, median_days_open: 10, p90_days_open: 10 },
    ],
    by_group: [{ device_group_id: 'g-1', device_group: 'laptops', devices: 2, breached: 1 }],
    devices: [{
      device_id: 'd-1', hostname: 'laptop-1',
      breached: [{ cve: 'CVE-2026-0001', package: 'openssl', severity: 'critical', days_open: 8, fixed_version: '3.0.2-1', sla_days: 7 }],
    }],
    devices_total: 1, row_cap: 1000,
    catalog: [{ assignment_id: 'a-1', entry: 'Firefox', required_version: '120.0', devices_behind: 2 }],
  }
}

let wrapper: VueWrapper | null = null
let router: Router

beforeEach(() => {
  problem = null
  report = fullReport()
  getReport.mockReset()
  getReport.mockImplementation(() => Promise.resolve(problem ?? report))
  save.mockReset()
})

afterEach(() => {
  wrapper?.unmount()
  wrapper = null
})

async function mountPage(path: string, role = 'org_auditor'): Promise<VueWrapper> {
  const pinia = createPinia()
  setActivePinia(pinia)
  useSessionStore().me = { id: 'a', username: 'alice', display_name: 'Alice', role, locale: 'en', organization: null } as never
  router = createRouter({
    history: createMemoryHistory(),
    routes: [
      { path: '/patch-compliance', name: 'patch-compliance', component: PatchComplianceView },
      { path: '/settings/patch-sla', name: 'patch-sla-settings', component: PatchSlaSettingsView },
    ],
  })
  await router.push(path)
  await router.isReady()
  wrapper = mount(() => h(VApp, null, { default: () => h(RouterView) }), {
    global: { plugins: [createPortalI18n(), vuetify, router, pinia] }, attachTo: document.body,
  })
  await flushPromises()
  return wrapper
}

describe('patch compliance helpers (plan M13c decision 18)', () => {
  it('validates SLA days between 0 and 365', () => {
    expect([0, 7, 365].every(validSlaDays)).toBe(true)
    expect([-1, 366, 1.5, Number.NaN].some(validSlaDays)).toBe(false)
  })

  it('builds the tables: one breach row per breached finding, severities translated', () => {
    const sections = patchSections(report, (s) => s.toUpperCase())
    expect(sections.map((s) => s.key)).toEqual(['severity', 'groups', 'breaches', 'catalog'])
    const breaches = sections[2]
    expect(breaches.total).toBe(1)
    expect(breaches.rows[0]).toEqual({
      hostname: 'laptop-1', cve: 'CVE-2026-0001', package: 'openssl', severity: 'CRITICAL', days_open: 8, sla_days: 7, fixed_version: '3.0.2-1',
    })
    expect(sections[0].rows.map((r) => r.severity)).toEqual(['CRITICAL', 'HIGH'])
    expect(sections[3].rows).toEqual([{ entry: 'Firefox', required_version: '120.0', devices_behind: 2 }])
  })

  it('gives the cards with the breached findings and the SLA', () => {
    const cells = patchCells(report)
    expect(cells.map((c) => [c.key, c.value, c.status])).toEqual([
      ['devices', 3, 'neutral'], ['compliant', 2, 'ok'], ['breached', 1, 'critical'], ['sla', '7 / 30 / 90 / 0', 'info'],
    ])
    expect(cells[2].noteValues).toEqual({ findings: 1 })
    report.summary = { devices: 3, compliant: 3, breached: 0 }
    expect(patchCells(report)[2].status).toBe('ok')
  })

  it('builds the export URL with the group and the format, never a period', () => {
    expect(patchExportUrl('', 'csv')).toBe('/api/v1/patch-compliance/export?format=csv')
    expect(patchExportUrl('g-1', 'json')).toBe('/api/v1/patch-compliance/export?format=json&device_group_id=g-1')
  })

  it('is in the navigation for every organization role', () => {
    const items = navigationGroups.flatMap((g) => g.items)
    expect(items.find((i) => i.to === '/patch-compliance')?.label).toBe('nav.patchCompliance')
    expect(items.find((i) => i.to === '/settings/patch-sla')?.label).toBe('nav.patchSlaSettings')
  })
})

describe('PatchCompliance page (plan M13c decision 18)', () => {
  it('shows the state at generation without a period selector, the cards, the sections and the exports', async () => {
    const w = await mountPage('/patch-compliance')
    expect(w.find('h1').text()).toBe('Patch compliance')
    expect(w.find('[data-testid="kpi-breached"]').text()).toContain('SLA breached')
    expect(w.find('[data-testid="kpi-breached"]').text()).toContain('1 finding open too long')
    expect(w.find('[data-testid="kpi-sla"]').text()).toContain('7 / 30 / 90 / 0')
    expect(w.find('[data-testid="review-breaches"]').text()).toContain('Findings open longer than the SLA (1)')
    expect(w.find('[data-testid="review-catalog"]').text()).toContain('Pinned required software (1)')
    expect(w.find('[data-testid="patch-state-at"]').text()).toMatch(/^State at /)
    expect(w.find('[data-testid="patch-state-at"] time').attributes('datetime')).toBe('2026-11-14T10:00:00Z')
    for (const id of ['preset-30', 'preset-90', 'custom-from', 'custom-to', 'custom-apply']) {
      expect(w.find(`[data-testid="${id}"]`).exists(), id).toBe(false)
    }
    expect(w.text()).not.toContain('Last 90 days')
    expect(w.find('[data-testid="export-csv"]').attributes('href')).toBe('/api/v1/patch-compliance/export?format=csv')
    expect(w.find('[data-testid="patch-cap"]').exists()).toBe(false)
    expect(w.find('[data-testid="patch-empty"]').exists()).toBe(false)
    expect(getReport).toHaveBeenCalledTimes(1)
    expect(getReport.mock.calls[0][0]).toBe('')
  })

  it('says "Stand vom" in German', async () => {
    const pinia = createPinia()
    setActivePinia(pinia)
    useSessionStore().me = { id: 'a', username: 'alice', display_name: 'Alice', role: 'org_auditor', locale: 'de', organization: null } as never
    const i18n = createPortalI18n('de')
    router = createRouter({ history: createMemoryHistory(), routes: [{ path: '/patch-compliance', component: PatchComplianceView }] })
    await router.push('/patch-compliance')
    await router.isReady()
    wrapper = mount(() => h(VApp, null, { default: () => h(RouterView) }), {
      global: { plugins: [i18n, vuetify, router, pinia] }, attachTo: document.body,
    })
    await flushPromises()
    expect(wrapper.find('[data-testid="patch-state-at"]').text()).toMatch(/^Stand vom /)
  })

  it('passes the group filter of the route to the API and keeps it in the export', async () => {
    const w = await mountPage('/patch-compliance?group=g-1')
    expect(getReport.mock.calls[0][0]).toBe('g-1')
    expect(w.find('[data-testid="export-json"]').attributes('href')).toContain('device_group_id=g-1')
  })

  it('states the device cap and an organization without inventory', async () => {
    report.devices_total = 1500
    let w = await mountPage('/patch-compliance')
    expect(w.find('[data-testid="patch-cap"]').text()).toContain('Showing the breaches of 1 of 1,500 devices')
    wrapper?.unmount()
    report = { ...fullReport(), summary: { devices: 0, compliant: 0, breached: 0 }, by_severity: [], by_group: [], devices: [], devices_total: 0, catalog: [] }
    w = await mountPage('/patch-compliance')
    expect(w.find('[data-testid="patch-empty"]').text()).toContain('No inventory yet')
  })

  it('shows a refusal as an empty state', async () => {
    problem = 'forbidden'
    const w = await mountPage('/patch-compliance')
    expect(w.find('[data-testid="patch-forbidden"]').text()).toContain('No access to the patch compliance report')
    expect(w.find('[data-testid="export-csv"]').exists()).toBe(false)
  })
})

describe('PatchSlaSettings page (plan M13c decision 17)', () => {
  function input(field: string): HTMLInputElement {
    return document.querySelector('#patch-sla-' + field) as HTMLInputElement
  }
  async function set(field: string, value: string): Promise<void> {
    input(field).value = value
    input(field).dispatchEvent(new Event('input'))
    await flushPromises()
  }
  async function submit(): Promise<void> {
    ;(document.querySelector('form') as HTMLFormElement).dispatchEvent(new Event('submit'))
    await flushPromises()
  }

  it('lets an administrator change the SLA and confirms with a snackbar', async () => {
    save.mockImplementation((s) => Promise.resolve({ ...s, updated_at: '2026-11-14T09:00:00Z' }))
    await mountPage('/settings/patch-sla', 'org_admin')
    expect(input('critical_days').value).toBe('7')
    await set('critical_days', '3')
    await submit()
    expect(save).toHaveBeenCalledWith({ critical_days: 3, high_days: 30, medium_days: 90, low_days: 0 })
    expect(document.body.textContent).toContain('The patch SLA was saved.')
  })

  it('refuses days out of range inline without saving', async () => {
    const w = await mountPage('/settings/patch-sla', 'org_admin')
    for (const value of ['-1', '366']) {
      await set('low_days', value)
      await submit()
      expect(w.text()).toContain('Enter a whole number of days from 0 to 365.')
    }
    expect(save).not.toHaveBeenCalled()
  })

  it.each(['org_operator', 'org_auditor'])('is read-only for %s', async (role) => {
    const w = await mountPage('/settings/patch-sla', role)
    expect(input('high_days').value).toBe('30')
    expect(input('high_days').matches(':disabled')).toBe(true)
    expect(w.find('[data-testid="save-patch-sla"]').exists()).toBe(false)
    expect(w.find('[data-testid="patch-sla-read-only"]').text()).toContain('Only organization administrators')
  })
})
