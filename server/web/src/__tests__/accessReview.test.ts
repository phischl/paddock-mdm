import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { h } from 'vue'
import { createPinia, setActivePinia } from 'pinia'
import { createMemoryHistory, createRouter, RouterView, type Router } from 'vue-router'
import { flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import { VApp } from 'vuetify/components'
import AccessReviewView from '../views/AccessReview.vue'
import PlatformAccessReviewView from '../views/PlatformAccessReview.vue'
import { createPortalI18n } from '../i18n'
import { vuetify } from '../plugins/vuetify'
import { useSessionStore } from '../stores/session'
import { clientPage, customRangeError, exportUrl, resolvePeriod, type AccessReviewReport, type ResolvedPeriod } from '../lib/accessReview'
import type { ListParams } from '../lib/listQuery'
import { navigationGroups } from '../lib/navigation'

const empty = { total: 0, items: [] }
let report: AccessReviewReport
let problem: string | null
const getAccessReview = vi.fn<(p: ResolvedPeriod) => Promise<AccessReviewReport | string>>()

vi.mock('../lib/accessReview', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/accessReview')>()),
  getAccessReview: (p: ResolvedPeriod) => getAccessReview(p),
}))

let wrapper: VueWrapper | null = null
let router: Router

beforeEach(() => {
  problem = null
  report = {
    generated_at: '2026-11-04T10:00:00Z', period: { from: '2026-08-06T10:00:00Z', to: '2026-11-04T10:00:00Z' }, row_cap: 1000,
    roles: [{ role: 'org_admin', snapshot_taken_at: '2026-11-04T09:00:00Z', total: 1, members: [{ username: 'alice', authentik_pk: '1', first_seen_at: '2026-10-01T00:00:00Z' }] }],
    role_changes: empty,
    accounts: { total: 1, items: [{ username: 'alice', display_name: 'Alice', role: 'org_admin', last_login_at: null, disabled: false }] },
    api_tokens: empty, token_denials: 3,
    reveals: {
      total: 1500, items: [
        { at: '2026-10-02T00:00:00Z', code: 'device.escrow_revealed', actor: 'alice', device_hostname: 'laptop-1', params: { generation: 2 } },
        { at: '2026-10-03T00:00:00Z', code: 'device.escrow_revealed', actor: 'bob', device_hostname: 'laptop-2', params: { generation: 1 } },
      ],
    },
    step_up: { succeeded: 4, failed: 1 }, sessions_revoked: empty, break_glass_accounts: [], destructive: empty,
  }
  getAccessReview.mockReset()
  getAccessReview.mockImplementation(() => Promise.resolve(problem ?? report))
})

afterEach(() => {
  wrapper?.unmount()
  wrapper = null
})

async function mountPage(path: string): Promise<VueWrapper> {
  const pinia = createPinia()
  setActivePinia(pinia)
  useSessionStore().me = { id: 'a', username: 'alice', display_name: 'Alice', role: 'org_auditor', locale: 'en', organization: null } as never
  router = createRouter({
    history: createMemoryHistory(),
    routes: [
      { path: '/access-review', name: 'access-review', component: AccessReviewView },
      { path: '/platform/access-review', name: 'platform-access-review', component: PlatformAccessReviewView },
    ],
  })
  await router.push(path)
  await router.isReady()
  const App = () => h(VApp, null, { default: () => h(RouterView) })
  wrapper = mount(App, { global: { plugins: [createPortalI18n(), vuetify, router, pinia] }, attachTo: document.body })
  await flushPromises()
  return wrapper
}

describe('AccessReview page (plan M12 decision 27)', () => {
  it('shows every section with its total, the step-up counts and the export links of the period', async () => {
    const w = await mountPage('/access-review')
    for (const key of ['roles', 'changes', 'accounts', 'tokens', 'reveals', 'sessions', 'destructive', 'breakglass']) {
      expect(w.find(`[data-testid="review-${key}"]`).exists()).toBe(true)
    }
    expect(w.find('[data-testid="review-reveals"]').text()).toContain('Reveals and downloads of secrets (1500)')
    expect(w.find('[data-testid="review-stepup"]').text()).toContain('4 successful actions')
    const csv = w.find('[data-testid="export-csv"]').attributes('href') ?? ''
    const sent = getAccessReview.mock.calls[0]![0]
    expect(csv).toBe(exportUrl('organization', sent, 'csv'))
    expect(csv).toContain('format=csv')
    expect(w.find('[data-testid="export-json"]').attributes('href')).toContain('format=json')
  })

  it('names the cap when a total exceeds the rows and filters rows in the browser', async () => {
    const w = await mountPage('/access-review')
    await w.find('[data-testid="review-reveals"] button').trigger('click')
    await flushPromises()
    expect(w.find('[data-testid="review-cap"]').text()).toContain('Showing 2 of 1,500 rows')
    expect(w.find('[data-testid="review-reveals"]').text()).toContain('laptop-2')
  })

  it('a preset changes the query and reloads the report for that period', async () => {
    const w = await mountPage('/access-review')
    await w.find('[data-testid="preset-30"]').trigger('click')
    await flushPromises()
    expect(router.currentRoute.value.query).toEqual({ days: '30' })
    expect(getAccessReview).toHaveBeenCalledTimes(2)
    const [a, b] = getAccessReview.mock.calls.map((c) => c[0])
    expect(Date.parse(b!.to) - Date.parse(b!.from)).toBe(30 * 86_400_000)
    expect(Date.parse(a!.to) - Date.parse(a!.from)).toBe(90 * 86_400_000)
  })

  it('refuses a custom range of more than 400 days with an inline alert and sends nothing', async () => {
    const w = await mountPage('/access-review')
    getAccessReview.mockClear()
    await w.find('[data-testid="custom-from"] input').setValue('2025-01-01')
    await w.find('[data-testid="custom-to"] input').setValue('2026-11-01')
    await w.find('[data-testid="custom-apply"]').trigger('click')
    await flushPromises()
    expect(w.find('[data-testid="review-period-error"]').text()).toBe('The period may span at most 400 days.')
    expect(w.find('[data-testid="review-period-error"]').attributes('role')).toBe('alert')
    expect(getAccessReview).not.toHaveBeenCalled()
    expect(router.currentRoute.value.query).toEqual({})
  })

  it('applies a valid custom range through the query', async () => {
    const w = await mountPage('/access-review')
    await w.find('[data-testid="custom-from"] input').setValue('2026-10-01')
    await w.find('[data-testid="custom-to"] input').setValue('2026-10-31')
    await w.find('[data-testid="custom-apply"]').trigger('click')
    await flushPromises()
    expect(router.currentRoute.value.query).toEqual({ from: '2026-10-01', to: '2026-10-31' })
    const sent = getAccessReview.mock.calls.at(-1)![0]
    expect(sent.from).toBe('2026-10-01T00:00:00.000Z')
    expect(sent.to).toBe('2026-11-01T00:00:00.000Z')
  })

  it('shows the no-access page when the API refuses the role', async () => {
    problem = 'forbidden'
    const w = await mountPage('/access-review')
    expect(w.find('[data-testid="review-forbidden"]').text()).toContain('No access to the access review')
    expect(w.find('[data-testid="export-csv"]').exists()).toBe(false)
  })
})

describe('access review period and rows', () => {
  it('resolves presets, falls back to 90 days and validates custom days', () => {
    const now = new Date('2026-11-04T10:00:00Z')
    expect(resolvePeriod({ days: '365' }, now).preset).toBe(365)
    expect(resolvePeriod({ days: '7' }, now).preset).toBe(90)
    expect(resolvePeriod({ from: '2026-10-05', to: '2026-10-01' }, now).error).toBe('accessReview.errors.order')
    expect(resolvePeriod({ from: 'x', to: '2026-10-01' }, now).error).toBe('accessReview.errors.dates')
    expect(customRangeError('2025-10-01', '2026-11-05')).toBe('accessReview.errors.tooLong')
    expect(customRangeError('2025-10-01', '2026-11-04')).toBe('')
  })

  it('sorts descending with empty values last, searches and pages', () => {
    const rows = [{ n: 'a', t: '2026-01-01' }, { n: 'b', t: null }, { n: 'c', t: '2026-03-01' }]
    const p: ListParams = { page: 1, page_size: 10, sort: '-t' }
    expect(clientPage(rows, p).items.map((r) => r.n)).toEqual(['c', 'a', 'b'])
    expect(clientPage(rows, { ...p, q: 'B' }).total).toBe(1)
    expect(clientPage(rows, { ...p, page: 2, page_size: 10 }).items).toEqual([])
  })

  it('is in the navigation for auditors and administrators, not for operators', () => {
    const item = navigationGroups.flatMap((g) => g.items).find((i) => i.to === '/access-review')!
    const access = { isPlatform: false, canWrite: false, canDelete: false, canReadGroups: true }
    expect(item.visible({ ...access, canReadAudit: true })).toBe(true)
    expect(item.visible({ ...access, canReadAudit: false })).toBe(false)
  })
})
