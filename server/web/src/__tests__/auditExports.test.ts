import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import { h } from 'vue'
import { createRouter, createMemoryHistory } from 'vue-router'
import { VApp } from 'vuetify/components'
import { createPinia, setActivePinia } from 'pinia'
import type { AuditEvidenceKey, AuditExport } from '../api/client'
import { createPortalI18n } from '../i18n'
import { chainStatus, defaultRange, downloadUrl, exportStatus, formatSize, hasOpenExport, validateExport } from '../lib/auditExports'
import { vuetify } from '../plugins/vuetify'
import AuditExportsView from '../views/AuditExports.vue'

const base: AuditExport = {
  id: '11111111-1111-1111-1111-111111111111', status: 'ready', from_day: '2026-10-01', to_day: '2026-10-28',
  purpose: 'ISO audit\n<b>second line</b>', requested_by: { type: 'user', id: 'u1', display: 'Bob Auditor', step_up: true },
  requested_at: '2026-10-29T08:00:00Z', ready_at: '2026-10-29T08:05:00Z', expires_at: '2026-11-05T08:05:00Z', event_count: 120,
  object_count: 28, size: 5_000_000, package_sha256: 'ab'.repeat(32), verify_ok: true, verify_problems: [], key_version: 1, error: null,
}
const pending: AuditExport = {
  ...base, id: '22222222-2222-2222-2222-222222222222', status: 'pending', ready_at: null, expires_at: null, event_count: null,
  object_count: null, size: null, package_sha256: null, verify_ok: null, key_version: null, purpose: 'second',
}
const failed: AuditExport = { ...pending, id: '33333333-3333-3333-3333-333333333333', status: 'failed', error: 'object store unreachable', purpose: 'third' }
const broken: AuditExport = { ...base, id: '44444444-4444-4444-4444-444444444444', verify_ok: false, verify_problems: ['2026-10-05: hash mismatch'], purpose: 'fourth' }
const key: AuditEvidenceKey = { key_version: 1, public_key: 'AAAA', fingerprint: 'cd'.repeat(32), first_seen_at: '2026-10-01T00:00:00Z' }

const mocks = vi.hoisted(() => ({
  startStepUp: vi.fn(),
  resumeStepUp: vi.fn(),
  createAuditExport: vi.fn(),
  keys: { value: [] as unknown },
}))
vi.mock('../lib/stepUp', async (original) => ({
  ...(await original<typeof import('../lib/stepUp')>()),
  startStepUp: mocks.startStepUp,
  resumeStepUp: mocks.resumeStepUp,
  withoutStepUpParam: () => '/audit/exports',
}))
vi.mock('../lib/auditExports', async (original) => ({
  ...(await original<typeof import('../lib/auditExports')>()),
  listAuditExports: () => Promise.resolve({ items: [base, pending, failed, broken], page: 1, page_size: 25, total: 4, total_capped: false, sort: '-requested_at' }),
  listAuditKeys: () => Promise.resolve(mocks.keys.value),
  createAuditExport: mocks.createAuditExport,
}))

describe('evidence export helpers', () => {
  it('defaults to the 365 days ending yesterday', () => {
    expect(defaultRange(new Date('2026-10-30T12:00:00Z'))).toEqual({ from: '2025-10-30', to: '2026-10-29' })
  })

  it('validates the order of the days and a non-empty purpose', () => {
    expect(validateExport('2026-10-01', '2026-10-02', 'audit')).toEqual({})
    expect(validateExport('2026-10-01', '2026-10-01', 'audit')).toEqual({})
    expect(validateExport('2026-10-03', '2026-10-02', 'audit')).toEqual({ to: 'auditExports.errors.order' })
    expect(validateExport('', '2026-10-02', ' \n ')).toEqual({ from: 'auditExports.errors.fromRequired', purpose: 'auditExports.errors.purposeRequired' })
    expect(validateExport('2026-10-01', '', 'x')).toEqual({ to: 'auditExports.errors.toRequired' })
  })

  it('maps statuses and the chain check; unknown chain has no chip', () => {
    expect(exportStatus('ready').status).toBe('ok')
    expect(exportStatus('failed').status).toBe('critical')
    expect(exportStatus('running').status).toBe('info')
    expect(exportStatus('expired').status).toBe('neutral')
    expect(chainStatus(null)).toBeNull()
    expect(chainStatus(true)?.label).toBe('auditExports.chain.intact')
    expect(chainStatus(false)?.status).toBe('critical')
    expect(hasOpenExport([base, pending])).toBe(true)
    expect(hasOpenExport([base, failed])).toBe(false)
  })

  it('formats a size in the largest fitting unit', () => {
    expect(formatSize(0, 'en')).toBe('0 byte')
    expect(formatSize(2_500, 'en')).toBe('2.5 kB')
    expect(formatSize(5_000_000, 'en')).toBe('5 MB')
    expect(formatSize(3_200_000_000, 'en')).toBe('3.2 GB')
  })

  it('builds the download URL of the export', () => {
    expect(downloadUrl(base.id)).toBe('/api/v1/audit/exports/' + base.id + '/download')
  })

  it('has German texts for the page', () => {
    const i18n = createPortalI18n()
    i18n.global.locale.value = 'de'
    expect(i18n.global.t('auditExports.title')).toBe('Nachweis-Exporte')
    expect(i18n.global.t('nav.auditExports')).toBe('Nachweis-Exporte')
  })
})

let wrapper: VueWrapper | null = null
beforeEach(() => {
  mocks.keys.value = [key]
  mocks.resumeStepUp.mockReturnValue(null)
})
afterEach(() => {
  wrapper?.unmount()
  wrapper = null
  vi.clearAllMocks()
  document.body.innerHTML = ''
})

async function mountView(): Promise<VueWrapper> {
  const pinia = createPinia()
  setActivePinia(pinia)
  const router = createRouter({ history: createMemoryHistory(), routes: [{ path: '/audit/exports', name: 'audit-exports', component: AuditExportsView }] })
  await router.push('/audit/exports')
  wrapper = mount(() => h(VApp, null, { default: () => h(AuditExportsView) }), {
    global: { plugins: [createPortalI18n(), vuetify, router, pinia] }, attachTo: document.body,
  })
  await flushPromises()
  return wrapper
}

const dialogText = () => document.querySelector('[data-testid="export-dialog"]')?.textContent ?? ''
async function type(testid: string, value: string): Promise<void> {
  const el = document.querySelector<HTMLInputElement>(`[data-testid="${testid}"] input, [data-testid="${testid}"] textarea`)!
  el.value = value
  el.dispatchEvent(new Event('input'))
  await flushPromises()
}
async function click(testid: string): Promise<void> {
  document.querySelector<HTMLElement>(`[data-testid="${testid}"]`)!.click()
  await flushPromises()
}

describe('evidence exports page', () => {
  it('lists the exports with status, requester, size, chain and a download link only for ready ones', async () => {
    const w = await mountView()
    const rows = w.findAll('[data-testid="audit-exports"] tbody tr')
    expect(rows).toHaveLength(4)
    expect(rows[0].text()).toContain('2026-10-01 – 2026-10-28')
    expect(rows[0].text()).toContain('Ready')
    expect(rows[0].text()).toContain('Bob Auditor')
    expect(rows[0].text()).toContain('5 MB')
    expect(rows[0].find('.export-chain').text()).toBe('Intact')
    const link = rows[0].find('a.export-download')
    expect(link.attributes('href')).toBe('/api/v1/audit/exports/' + base.id + '/download')
    expect(link.text()).toBe('Download')
    expect(rows[1].find('a.export-download').exists()).toBe(false)
    expect(rows[1].text()).toContain('Pending')
    expect(rows[2].find('a.export-download').exists()).toBe(false)
    expect(rows[2].text()).toContain('object store unreachable')
    expect(rows[3].find('.export-chain').text()).toBe('Problems')
    expect(rows[3].find('.export-chain').attributes('title')).toContain('hash mismatch')
  })

  it('shows the purpose as text, never as markup', async () => {
    const w = await mountView()
    const purpose = w.find('[data-testid="audit-exports"] tbody tr .export-purpose')
    expect(purpose.text()).toContain('<b>second line</b>')
    expect(purpose.find('b').exists()).toBe(false)
  })

  it('lists every signing key with its fingerprint and the comparison hint', async () => {
    const w = await mountView()
    const keys = w.find('[data-testid="audit-keys"]')
    expect(keys.find('h2').text()).toBe('Signing keys')
    expect(keys.text()).toContain('Compare with the fingerprint your ISMS recorded')
    expect(keys.findAll('[data-testid="audit-key"]').map((r) => r.text())).toEqual([expect.stringContaining('cd'.repeat(32))])
  })

  it('shows the problem of the keys card as an alert', async () => {
    mocks.keys.value = 'forbidden'
    const w = await mountView()
    expect(w.find('[data-testid="audit-keys"] [role="alert"]').exists()).toBe(true)
  })

  it('validates the range and the purpose before it starts the step-up', async () => {
    await mountView()
    await click('new-export')
    await type('export-from', '2026-10-03')
    await type('export-to', '2026-10-02')
    await click('export-submit')
    expect(dialogText()).toContain('The last day must not be before the first day.')
    expect(dialogText()).toContain('Enter the purpose.')
    expect(mocks.startStepUp).not.toHaveBeenCalled()
  })

  it('starts the step-up with the trimmed request', async () => {
    await mountView()
    await click('new-export')
    await type('export-from', '2026-10-01')
    await type('export-to', '2026-10-28')
    await type('export-purpose', '  ISO audit  ')
    await click('export-submit')
    expect(mocks.startStepUp).toHaveBeenCalledWith('audit-export', 'exports', { from: '2026-10-01', to: '2026-10-28', purpose: 'ISO audit' })
  })

  it('posts after the step-up and confirms the request', async () => {
    mocks.resumeStepUp.mockReturnValue({ failed: false, payload: { from: '2026-10-01', to: '2026-10-28', purpose: 'ISO audit' } })
    mocks.createAuditExport.mockResolvedValue(pending)
    const w = await mountView()
    expect(mocks.createAuditExport).toHaveBeenCalledWith({ from_day: '2026-10-01', to_day: '2026-10-28', purpose: 'ISO audit' })
    expect(w.find('[data-testid="export-requested"]').text()).toContain('The export was requested')
  })

  it.each([
    ['day_not_sealed', 'A day of the range is not sealed yet'],
    ['too_many_exports', 'Two exports are already pending or running'],
    ['range_too_large', 'The time range is too large.'],
    ['step_up_required', 'Confirm your identity to continue.'],
  ])('shows %s as an inline alert in the reopened dialog', async (code, text) => {
    mocks.resumeStepUp.mockReturnValue({ failed: false, payload: { from: '2026-10-01', to: '2026-10-28', purpose: 'ISO audit' } })
    mocks.createAuditExport.mockResolvedValue(code)
    await mountView()
    const alert = document.querySelector('[data-testid="export-dialog-problem"]')
    expect(alert?.getAttribute('role')).toBe('alert')
    expect(alert?.textContent).toContain(text)
  })

  it('shows a refused step-up as an alert and posts nothing', async () => {
    mocks.resumeStepUp.mockReturnValue({ failed: true })
    const w = await mountView()
    expect(w.find('[data-testid="export-problem"]').text()).toContain('The identity confirmation failed')
    expect(mocks.createAuditExport).not.toHaveBeenCalled()
  })
})
