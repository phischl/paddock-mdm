import { afterEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import { h } from 'vue'
import { createRouter, createMemoryHistory } from 'vue-router'
import { VApp } from 'vuetify/components'
import { createPinia, setActivePinia } from 'pinia'
import type { AuditIntegrity, AuditManifest, AuditVerificationRun } from '../api/client'
import { createPortalI18n } from '../i18n'
import { booleanFilter, integrityCells, resultStatus } from '../lib/auditIntegrity'
import { vuetify } from '../plugins/vuetify'
import AuditIntegrityView from '../views/AuditIntegrity.vue'

const failedRun: AuditVerificationRun = {
  id: 'r2', trigger: 'cli', from_day: '2026-10-24', to_day: '2026-10-25', started_at: '2026-10-25T08:10:00Z',
  finished_at: '2026-10-25T08:11:00Z', days: 2, objects: 4, ok: false, problems: ['2026-10-25: no manifest (chain broken)'], event_id: 'e2',
}
const okRun: AuditVerificationRun = {
  ...failedRun, id: 'r1', trigger: 'nightly', from_day: '2026-10-24', to_day: '2026-10-24', started_at: '2026-10-25T00:45:00Z',
  finished_at: '2026-10-25T00:46:00Z', days: 1, ok: true, problems: [], event_id: 'e1',
}
const manifest: AuditManifest = {
  day: '2026-10-24', sha256: 'ab'.repeat(32), prev_sha256: null, key_version: 1, object_key: 'org/x/manifests/2026-10-24.json',
  last_verified_at: '2026-10-25T08:11:00Z', last_verified_ok: false,
}

function integrityOf(over: Partial<AuditIntegrity> = {}): AuditIntegrity {
  return {
    sealed_through: '2026-10-24', manifests: 12, verification_window_days: 7, last_run: failedRun,
    last_success_at: okRun.finished_at, last_failure_at: failedRun.finished_at, ...over,
  }
}

describe('evidence integrity KPI cells (plan M8b decision 32)', () => {
  const now = new Date('2026-10-25T12:00:00Z')
  it('shows the sealed day, the manifests with the window, the last run and an open failure', () => {
    const cells = integrityCells(integrityOf(), now)
    expect(cells.map((c) => c.key)).toEqual(['sealed-through', 'manifests', 'last-run', 'last-failure'])
    expect(cells[0]).toMatchObject({ value: '2026-10-24', status: 'ok' })
    expect(cells[1]).toMatchObject({ value: 12, noteValues: { days: 7 }, status: 'info' })
    expect(cells[2]).toMatchObject({ note: 'auditIntegrity.result.failed', status: 'critical' })
    expect(cells[3]).toMatchObject({ note: 'auditIntegrity.kpi.failureOpen', status: 'critical' })
  })

  it('marks a failure followed by a successful run as resolved', () => {
    const cells = integrityCells(integrityOf({ last_run: okRun, last_success_at: '2026-10-25T09:00:00Z' }), now)
    expect(cells[2]).toMatchObject({ note: 'auditIntegrity.result.ok', status: 'ok' })
    expect(cells[3]).toMatchObject({ note: 'auditIntegrity.kpi.failureResolved', status: 'warn' })
  })

  it('shows dashes before the first seal and run', () => {
    const cells = integrityCells(integrityOf({ sealed_through: null, manifests: 0, last_run: null, last_success_at: null, last_failure_at: null }), now)
    expect(cells.map((c) => c.value)).toEqual(['–', 0, '–', '–'])
    expect(cells[0].status).toBe('neutral')
    expect(cells[2]).toMatchObject({ note: 'auditIntegrity.kpi.neverVerified', status: 'warn' })
    expect(cells[3]).toMatchObject({ note: 'auditIntegrity.kpi.noFailure', status: 'ok' })
  })
})

describe('evidence integrity filters', () => {
  it('sends a boolean only when exactly one value is chosen', () => {
    expect(booleanFilter(['true'])).toBe(true)
    expect(booleanFilter(['false'])).toBe(false)
    expect(booleanFilter(['true', 'false'])).toBeUndefined()
    expect(booleanFilter(undefined)).toBeUndefined()
  })

  it('names a day without a covering run "not verified", never ok', () => {
    expect(resultStatus(null)).toEqual({ status: 'neutral', label: 'auditIntegrity.result.none' })
    expect(resultStatus(true).status).toBe('ok')
    expect(resultStatus(false).status).toBe('critical')
  })
})

let summary: AuditIntegrity | string = integrityOf()
vi.mock('../lib/auditIntegrity', async (original) => ({
  ...(await original<typeof import('../lib/auditIntegrity')>()),
  getAuditIntegrity: () => Promise.resolve(summary),
  listVerificationRuns: () => Promise.resolve({ items: [failedRun, okRun], page: 1, page_size: 25, total: 2, total_capped: false, sort: '-started_at' }),
  listManifests: () => Promise.resolve({ items: [manifest], page: 1, page_size: 25, total: 1, total_capped: false, sort: '-day' }),
}))

let wrapper: VueWrapper | null = null
afterEach(() => {
  wrapper?.unmount()
  wrapper = null
  summary = integrityOf()
})

async function mountView(): Promise<VueWrapper> {
  const pinia = createPinia()
  setActivePinia(pinia)
  const router = createRouter({ history: createMemoryHistory(), routes: [
      { path: '/audit/integrity', component: AuditIntegrityView },
      { path: '/audit/exports', name: 'audit-exports', component: { render: () => null } },
    ],
  })
  await router.push('/audit/integrity')
  wrapper = mount(() => h(VApp, null, { default: () => h(AuditIntegrityView) }), {
    global: { plugins: [createPortalI18n(), vuetify, router, pinia] }, attachTo: document.body,
  })
  await flushPromises()
  return wrapper
}

describe('evidence integrity page', () => {
  it('shows the KPI strip, the runs with their result and problems, and the manifests', async () => {
    const w = await mountView()
    expect(w.find('h1').text()).toBe('Evidence integrity')
    expect(w.find('[data-testid="kpi-sealed-through"]').text()).toContain('2026-10-24')
    expect(w.find('[data-testid="kpi-last-run"]').text()).toContain('Failed')
    const runs = w.find('[data-testid="verification-runs"]')
    expect(runs.findAll('tbody tr .run-result').map((c) => c.text())).toEqual(['Failed', 'Intact'])
    expect(runs.find('tbody tr').text()).toContain('2026-10-24 – 2026-10-25')
    await runs.find('button[aria-expanded]').trigger('click')
    expect(w.find('[data-testid="run-problems"]').text()).toContain('no manifest (chain broken)')
    const manifests = w.find('[data-testid="audit-manifests"]')
    const hash = manifests.find('tbody tr span.mono[title]')
    expect(hash.attributes('title')).toBe(manifest.sha256)
    expect(hash.text()).toBe('abababababab…')
    expect(manifests.find('.manifest-result').text()).toBe('Failed')
  })

  it('shows the access state instead of the lists for a role without access', async () => {
    summary = 'forbidden'
    const w = await mountView()
    expect(w.find('[data-testid="audit-integrity-forbidden"]').text()).toContain('No access to the evidence integrity')
    expect(w.find('[data-testid="verification-runs"]').exists()).toBe(false)
  })

  it('uses the German glossary terms', () => {
    const i18n = createPortalI18n()
    i18n.global.locale.value = 'de'
    expect(i18n.global.t('auditIntegrity.title')).toBe('Nachweisintegrität')
    expect(i18n.global.t('auditIntegrity.runs.title')).toBe('Prüfläufe')
    expect(i18n.global.t('auditIntegrity.manifests.title')).toBe('Manifeste')
  })
})
