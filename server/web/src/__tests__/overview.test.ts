import { afterEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import { h } from 'vue'
import { createRouter, createMemoryHistory } from 'vue-router'
import { VApp } from 'vuetify/components'
import { createPinia, setActivePinia } from 'pinia'
import type { AttentionDevice, AuditEvent, Overview } from '../api/client'
import { createPortalI18n } from '../i18n'
import { kpiCells, severitySegments } from '../lib/overview'
import { vuetify } from '../plugins/vuetify'
import { useSessionStore } from '../stores/session'
import OverviewView from '../views/Overview.vue'

function overviewOf(over: Partial<Overview> = {}): Overview {
  return {
    generated_at: '2026-10-10T12:30:05Z',
    devices: {
      total: 12, active: 10, pending: 1, quarantined: 1, retired: 2, rejected: 0, online: 6, silent: 1, silent_critical: 1,
      presumed_lost: 1, never_contacted: 1,
    },
    encryption: { encrypted: 7, not_encrypted: 1, partial: 1, not_reported: 1 },
    vulnerabilities: {
      by_highest_severity: { critical: 2, high: 3, medium: 0, low: 1, unknown: 1, none: 4 },
      top: [{ cve: 'CVE-2026-0001', severity: 'critical', devices: 2, packages: ['openssh-server'] }],
    },
    updates: {
      security_overdue: 4, reboot_required: 2, os_releases: [{ release: '24.04', devices: 10 }],
      agent: { current_version: null, on_current: 0, outdated: 0, unknown: 10 },
    },
    attention: { conditions: 5, devices: 3 },
    ...over,
  }
}

const twoConditions: AttentionDevice = {
  device_id: 'd1', hostname: 'acme-lt-0142', state: 'active', os_release: { VERSION_ID: '24.04' }, last_contact_at: null,
  severity: 'critical', since: '2026-10-09T10:00:00Z',
  conditions: [
    { kind: 'presumed_lost', since: '2026-10-09T10:00:00Z', detail: '' },
    { kind: 'stale_critical', since: '2026-10-08T10:00:00Z', detail: '' },
  ],
}
const event: AuditEvent = {
  event_id: 'e1', occurred_at: '2026-10-10T12:00:00Z', recorded_at: '2026-10-10T12:00:00Z', code: 'device.approved', outcome: 'success',
  source: 'portal', actor: { type: 'admin', display: 'alice', step_up: false }, target: null, params: { hostname: 'acme-lt-0142' },
  correlation_id: 'c', device: null,
} as never

let overview: Overview | string = overviewOf()
let attentionItems: AttentionDevice[] = [twoConditions]
const auditCalls: number[] = []
vi.mock('../lib/overview', async (original) => ({
  ...(await original<typeof import('../lib/overview')>()),
  getOverview: () => Promise.resolve(overview),
  overviewAttention: () => Promise.resolve({ items: attentionItems, page: 1, page_size: 10, total: attentionItems.length, total_capped: false, sort: '-severity' }),
  recentAuditEvents: () => {
    auditCalls.push(1)
    return Promise.resolve({ items: [event], page: 1, page_size: 10, total: 1, total_capped: false, sort: '-occurred_at' })
  },
}))

let wrapper: VueWrapper | null = null
afterEach(() => {
  wrapper?.unmount()
  wrapper = null
  overview = overviewOf()
  attentionItems = [twoConditions]
  auditCalls.length = 0
})

async function mountOverview(role = 'org_admin'): Promise<VueWrapper> {
  const pinia = createPinia()
  setActivePinia(pinia)
  useSessionStore().me = {
    id: 'a', username: 'alice', display_name: 'Alice', role, locale: 'en', theme: 'system',
    organization: { id: 'o', slug: 'acme', name: 'Acme Corporation' }, revocation_enabled: true,
  } as never
  const stub = { render: () => null }
  const router = createRouter({
    history: createMemoryHistory(),
    routes: [
      { path: '/', name: 'home', component: stub },
      { path: '/attention', name: 'attention', component: stub },
      { path: '/audit', name: 'audit', component: stub },
      { path: '/devices', name: 'devices', component: stub },
      { path: '/devices/:id', name: 'device', component: stub },
      { path: '/vulnerabilities', name: 'vulnerabilities', component: stub },
      { path: '/vulnerabilities/:cve', name: 'vulnerability', component: stub },
    ],
  })
  await router.push('/')
  wrapper = mount(() => h(VApp, null, { default: () => h(OverviewView) }), {
    global: { plugins: [createPortalI18n(), vuetify, router, pinia] }, attachTo: document.body,
  })
  await flushPromises()
  return wrapper
}

describe('overview helpers (plan M7c decision 28)', () => {
  it('links every KPI cell but reboot required to its pre-filtered list and takes the values from the API', () => {
    const cells = kpiCells(overviewOf())
    const byKey = Object.fromEntries(cells.map((c) => [c.key, c]))
    expect(byKey.online.value).toBe(6)
    expect(byKey.online.to).toEqual({ path: '/devices', query: { state: 'active', contact: 'ok' } })
    expect(byKey.silent.value).toBe(2)
    expect(byKey['presumed-lost'].to).toEqual({ path: '/attention', query: { kind: 'presumed_lost' } })
    expect(byKey['critical-high'].value).toBe(5)
    expect(byKey['critical-high'].to).toEqual({ path: '/vulnerabilities', query: { severity: ['critical', 'high'] } })
    expect(byKey['reboot-required'].to).toBeUndefined()
  })

  it('orders the severity segments and links every level but none', () => {
    const segments = severitySegments(overviewOf().vulnerabilities.by_highest_severity)
    expect(segments.map((s) => s.level)).toEqual(['critical', 'high', 'medium', 'low', 'unknown', 'none'])
    expect(segments.find((s) => s.level === 'none')?.to).toBeUndefined()
    expect(segments.find((s) => s.level === 'unknown')?.to).toEqual({ path: '/vulnerabilities', query: { severity: 'unknown' } })
  })
})

describe('overview page (plan M7c decision 28)', () => {
  it('shows the heading, the subtitle, the KPI strip and the severity bar with a label listing every segment', async () => {
    const w = await mountOverview()
    expect(w.find('h1').text()).toBe('Overview')
    expect(w.text()).toContain('Acme Corporation · 12 enrolled devices · updated')
    const kpis = w.find('[data-testid="overview-kpis"]')
    expect(kpis.findAll('a')).toHaveLength(7)
    expect(kpis.find('[data-testid="kpi-reboot-required"]').element.tagName).toBe('DIV')
    const bar = w.find('[data-testid="severity-bar"]')
    expect(bar.attributes('role')).toBe('img')
    expect(bar.attributes('aria-label')).toBe(
      'Devices by highest severity: Critical 2, High 3, Medium 0, Low 1, Unknown 1, No findings 4',
    )
    const legend = w.find('[data-testid="overview-vulnerabilities"]').findAll('a').map((a) => a.text())
    expect(legend.some((t) => t.startsWith('Critical'))).toBe(true)
    expect(legend.some((t) => t.startsWith('No findings'))).toBe(false)
  })

  it('shows a device with two conditions once with both chips, most severe first, and one action', async () => {
    const w = await mountOverview()
    const rows = w.find('[data-testid="overview-attention"]').findAll('tbody tr')
    expect(rows).toHaveLength(1)
    const chips = rows[0].findAll('.pd-chip').map((c) => c.text())
    expect(chips).toEqual(['Presumed lost', 'Silent (critical)'])
    expect(rows[0].findAll('a.v-btn').map((b) => b.text())).toEqual(['Retire, lock or keep'])
    expect(rows[0].text()).toContain('never')
  })

  it('collapses more than three conditions into a +n chip', async () => {
    attentionItems = [{
      ...twoConditions, conditions: [
        ...twoConditions.conditions, { kind: 'disk_not_compliant', since: '2026-10-08T10:00:00Z', detail: '' },
        { kind: 'agent_outdated', since: '2026-10-08T10:00:00Z', detail: '' },
      ],
    }]
    const w = await mountOverview()
    const chips = w.find('[data-testid="overview-attention"]').findAll('.pd-chip')
    expect(chips).toHaveLength(4)
    expect(chips[3].text()).toBe('+1')
    expect(chips[3].attributes('title')).toBe('Agent outdated')
  })

  it('shows the empty states when nothing needs attention and nothing was found', async () => {
    attentionItems = []
    overview = overviewOf({
      vulnerabilities: { by_highest_severity: { critical: 0, high: 0, medium: 0, low: 0, unknown: 0, none: 0 }, top: [] },
    })
    const w = await mountOverview()
    expect(w.find('[data-testid="overview-attention"]').text()).toContain('Nothing needs attention')
    expect(w.find('[data-testid="overview-vulnerabilities"]').text()).toContain('No findings yet')
    expect(w.find('[data-testid="overview-updates"]').text()).toContain('No agent release published yet')
  })

  it('shows recent audit activity to administrators and hides it from operators', async () => {
    const admin = await mountOverview('org_admin')
    expect(admin.find('[data-testid="overview-audit"]').exists()).toBe(true)
    expect(admin.find('[data-testid="overview-audit"]').text()).toContain('device.approved')
    admin.unmount()
    wrapper = null
    auditCalls.length = 0
    const operator = await mountOverview('org_operator')
    expect(operator.find('[data-testid="overview-audit"]').exists()).toBe(false)
    expect(auditCalls).toHaveLength(0)
  })

  it('shows the problem when the overview cannot be read', async () => {
    overview = 'forbidden'
    const w = await mountOverview()
    expect(w.find('[role="alert"]').exists()).toBe(true)
    expect(w.find('[data-testid="overview-kpis"]').exists()).toBe(false)
  })
})
