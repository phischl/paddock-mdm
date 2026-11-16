import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { h } from 'vue'
import { createPinia, setActivePinia } from 'pinia'
import { createMemoryHistory, createRouter, RouterView, type Router } from 'vue-router'
import { flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import { VApp } from 'vuetify/components'
import DeletedOrganizationAudit from '../views/DeletedOrganizationAudit.vue'
import type { AuditExport, Organization } from '../api/client'
import { createPortalI18n } from '../i18n'
import { vuetify } from '../plugins/vuetify'

const deletion = {
  requested_at: '2026-11-01T00:00:00Z', requested_by: 'pat', reason: 'contract ended', delete_after: '2026-12-01T00:00:00Z',
  recovery_export_until: '2026-11-30T23:40:00Z',
  step: null, last_error_code: null, deleted_at: '2026-12-01T01:00:00Z', uninstalls_issued: 3, uninstalls_skipped: 0,
  audit_final_verified_at: '2026-12-01T00:30:00Z', audit_final_outcome: 'verified' as 'verified' | 'failed' | null,
}
let org: Organization
const ready: AuditExport = {
  id: 'x1', requested_at: '2026-12-02T00:00:00Z', requested_by: 'pat', from_day: '2026-11-01', to_day: '2026-11-30', purpose: 'audit',
  status: 'ready', size: 2048, verify_ok: true, verify_problems: [], error: null, package_sha256: 'ab', event_count: 5, object_count: 1,
  key_version: 1, expires_at: '2027-01-01T00:00:00Z',
} as unknown as AuditExport
const eventsFor = vi.fn()
const exportsFor = vi.fn()
const resumed = { value: null as null | { failed: false; payload: { from: string; to: string; purpose: string } } | { failed: true } }
const createExport = vi.fn()

vi.mock('../lib/organizations', async (original) => ({
  ...(await original<typeof import('../lib/organizations')>()),
  getOrganization: () => Promise.resolve(org),
  listDeletedOrganizationAuditEvents: (id: string) => (p: unknown) => {
    eventsFor(id, p)
    return Promise.resolve({ items: [], page: 1, page_size: 25, total: 0, total_capped: false, sort: '-occurred_at' })
  },
  listDeletedOrganizationAuditExports: () => (p: unknown) => {
    exportsFor(p)
    return Promise.resolve({ items: [ready], page: 1, page_size: 25, total: 1, total_capped: false, sort: '-requested_at' })
  },
  createDeletedOrganizationAuditExport: (...args: unknown[]) => createExport(...args),
}))

const startStepUp = vi.fn()
vi.mock('../lib/stepUp', async (original) => ({
  ...(await original<typeof import('../lib/stepUp')>()),
  startStepUp: (...args: unknown[]) => startStepUp(...args),
  resumeStepUp: (action: string) => (action === 'organization-audit-export' ? resumed.value : null),
  withoutStepUpParam: () => '/platform/organizations/o1/audit',
}))

let wrapper: VueWrapper | null = null
beforeEach(() => {
  org = { id: 'o1', slug: 'acme', name: 'Acme', status: 'deleted', domains: [], created_at: '2026-10-01T00:00:00Z', deletion }
  deletion.audit_final_outcome = 'verified'
  eventsFor.mockReset()
  exportsFor.mockReset()
  resumed.value = null
  createExport.mockReset()
  startStepUp.mockReset()
})
afterEach(() => {
  wrapper?.unmount()
  wrapper = null
})

let router: Router

async function mountView(): Promise<VueWrapper> {
  setActivePinia(createPinia())
  router = createRouter({
    history: createMemoryHistory(),
    routes: [
      { path: '/platform/organizations/:id/audit', component: DeletedOrganizationAudit },
      { path: '/platform/organizations', name: 'organizations', component: { render: () => null } },
    ],
  })
  await router.push('/platform/organizations/o1/audit')
  await router.isReady()
  wrapper = mount(() => h(VApp, null, { default: () => h(RouterView) }),
    { global: { plugins: [createPortalI18n(), vuetify, router, createPinia()] }, attachTo: document.body })
  await flushPromises()
  return wrapper
}

describe('retained audit of a deleted organization', () => {
  it('loads the audit log of the organization in the route and shows the verified outcome with its date', async () => {
    const w = await mountView()
    expect(eventsFor).toHaveBeenCalled()
    expect(eventsFor.mock.calls[0]?.[0]).toBe('o1')
    expect(w.get('[data-testid="audit-final-verified"]').text()).toContain('was verified before its deletion')
    expect(w.find('[data-testid="audit-final-failed"]').exists()).toBe(false)
  })

  it('shows a failed final verification as an error alert', async () => {
    deletion.audit_final_outcome = 'failed'
    const w = await mountView()
    const alert = w.get('[data-testid="audit-final-failed"]')
    expect(alert.attributes('role')).toBe('alert')
    expect(alert.text()).toContain('did not verify')
    expect(w.find('[data-testid="audit-final-verified"]').exists()).toBe(false)
  })

  it('lists the evidence exports with a download for a ready one', async () => {
    const w = await mountView()
    const link = w.get('[data-testid="export-download-x1"]')
    expect(link.attributes('href')).toBe('/api/platform/v1/organizations/o1/audit-exports/x1/download')
  })

  it('requests an export through the step-up with the dialog input', async () => {
    const w = await mountView()
    await w.get('[data-testid="new-export"]').trigger('click')
    await flushPromises()
    const purpose = document.querySelector('[data-testid="export-purpose"] textarea') as HTMLTextAreaElement
    purpose.value = ' external audit '
    purpose.dispatchEvent(new Event('input'))
    await flushPromises()
    ;(document.querySelector('[data-testid="export-submit"]') as HTMLButtonElement).click()
    await flushPromises()
    expect(startStepUp).toHaveBeenCalledOnce()
    expect(startStepUp.mock.calls[0]?.[0]).toBe('organization-audit-export')
    expect(startStepUp.mock.calls[0]?.[2]).toMatchObject({ purpose: 'external audit' })
  })

  it('refuses an export without a purpose', async () => {
    const w = await mountView()
    await w.get('[data-testid="new-export"]').trigger('click')
    await flushPromises()
    ;(document.querySelector('[data-testid="export-submit"]') as HTMLButtonElement).click()
    await flushPromises()
    expect(startStepUp).not.toHaveBeenCalled()
  })

  it('keeps the query of the audit log and of the export list apart', async () => {
    const w = await mountView()
    await router.push({ query: { 'log.q': 'login', 'log.page': '2' } })
    await flushPromises()
    const lastExports = exportsFor.mock.calls.at(-1)?.[0] as { q?: string; page: number }
    expect(lastExports.q ?? '').toBe('')
    expect(lastExports.page).toBe(1)
    const input = w.find('[data-testid="deleted-organization-exports"] [data-testid="list-search"] input')
    ;(input.element as HTMLInputElement).value = 'audit'
    await input.trigger('input')
    await vi.waitFor(() => expect(router.currentRoute.value.query['exports.q']).toBe('audit'))
    expect(router.currentRoute.value.query['log.q']).toBe('login')
    expect(router.currentRoute.value.query['log.page']).toBe('2')
    expect(router.currentRoute.value.query.q).toBeUndefined()
  })

  it('repeats the export request once after the step-up without a second step-up', async () => {
    createExport.mockResolvedValue({ ...ready, status: 'pending' })
    resumed.value = { failed: false, payload: { from: '2026-11-01', to: '2026-11-30', purpose: 'audit' } }
    const w = await mountView()
    expect(createExport).toHaveBeenCalledExactlyOnceWith('o1', { from_day: '2026-11-01', to_day: '2026-11-30', purpose: 'audit' })
    expect(startStepUp).not.toHaveBeenCalled()
    expect(w.find('[data-testid="export-requested"]').exists()).toBe(true)
  })

  it('does not loop when the repeated request asks for a step-up again, and shows the problem', async () => {
    createExport.mockResolvedValue('step_up_required')
    resumed.value = { failed: false, payload: { from: '2026-11-01', to: '2026-11-30', purpose: 'audit' } }
    await mountView()
    expect(createExport).toHaveBeenCalledOnce()
    expect(startStepUp).not.toHaveBeenCalled()
    expect(document.querySelector('[data-testid="export-dialog-problem"]')).not.toBeNull()
  })

  it('shows a problem and sends nothing when the step-up was refused', async () => {
    resumed.value = { failed: true }
    const w = await mountView()
    expect(createExport).not.toHaveBeenCalled()
    expect(w.get('[data-testid="export-problem"]').text()).toContain('identity')
  })
})
