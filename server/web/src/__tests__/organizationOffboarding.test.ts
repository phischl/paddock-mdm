import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { h } from 'vue'
import { createPinia, setActivePinia } from 'pinia'
import { createMemoryHistory, createRouter, RouterView } from 'vue-router'
import { flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import { VApp } from 'vuetify/components'
import Organizations from '../views/Organizations.vue'
import OrganizationDeletionBanner from '../components/OrganizationDeletionBanner.vue'
import type { Me, Organization } from '../api/client'
import type { OrganizationDeletionInput } from '../lib/organizations'
import { createPortalI18n } from '../i18n'
import { vuetify } from '../plugins/vuetify'
import { useSessionStore } from '../stores/session'
import { pendingConfirm, settleConfirm } from '../composables/useConfirm'

const deletion = {
  requested_at: '2026-11-01T00:00:00Z', requested_by: 'pat', reason: 'contract ended', delete_after: '2026-12-01T00:00:00Z',
  recovery_export_until: '2026-11-30T23:40:00Z',
  step: null, last_error_code: null, deleted_at: null, uninstalls_issued: 3, uninstalls_skipped: 0,
  audit_final_verified_at: null, audit_final_outcome: null,
}
const active: Organization = {
  id: 'o1', slug: 'acme', name: 'Acme', status: 'active', domains: [], created_at: '2026-10-01T00:00:00Z', deletion: null,
}
let rows: Organization[] = [active]
const requestDeletion = vi.fn<(input: OrganizationDeletionInput) => Promise<string | null>>()
const cancelDeletion = vi.fn<(id: string) => Promise<string | null>>()

vi.mock('../lib/organizations', async (original) => ({
  ...(await original<typeof import('../lib/organizations')>()),
  listOrganizations: () => Promise.resolve({ items: rows, page: 1, page_size: 25, total: rows.length, total_capped: false, sort: 'slug' }),
  requestOrganizationDeletion: (input: OrganizationDeletionInput) => requestDeletion(input),
  cancelOrganizationDeletion: (id: string) => cancelDeletion(id),
}))

const startStepUp = vi.fn()
let resumed: { failed: false; payload: OrganizationDeletionInput } | { failed: true } | null = null
vi.mock('../lib/stepUp', async (original) => ({
  ...(await original<typeof import('../lib/stepUp')>()),
  startStepUp: (...args: unknown[]) => startStepUp(...args),
  resumeStepUp: (action: string) => (action === 'organization-delete' ? resumed : null),
  withoutStepUpParam: () => '/platform/organizations',
}))

let wrapper: VueWrapper | null = null

beforeEach(() => {
  rows = [active]
  requestDeletion.mockReset()
  cancelDeletion.mockReset()
  startStepUp.mockReset()
  resumed = null
})

afterEach(() => {
  wrapper?.unmount()
  wrapper = null
})

async function mountView(): Promise<VueWrapper> {
  const pinia = createPinia()
  setActivePinia(pinia)
  const router = createRouter({ history: createMemoryHistory(), routes: [
    { path: '/platform/organizations', component: Organizations },
    { path: '/platform/organizations/:id/audit', name: 'organization-audit', component: { render: () => null } },
  ] })
  await router.push('/platform/organizations')
  await router.isReady()
  wrapper = mount(() => h(VApp, null, { default: () => h(RouterView) }),
    { global: { plugins: [createPortalI18n(), vuetify, router, pinia] }, attachTo: document.body })
  await flushPromises()
  return wrapper
}

function fill(selector: string, value: string): void {
  const el = document.querySelector(selector) as HTMLInputElement | HTMLTextAreaElement
  el.value = value
  el.dispatchEvent(new Event('input'))
}

function acceptButton(): HTMLButtonElement {
  return document.querySelector('[data-testid="confirm-accept"]') as HTMLButtonElement
}

async function openDelete(w: VueWrapper): Promise<void> {
  await w.get('[data-testid="org-delete-acme"]').trigger('click')
  await flushPromises()
}

describe('requesting the deletion of an organization', () => {
  it('keeps the delete button disabled until the typed slug matches and a reason is given', async () => {
    const w = await mountView()
    await openDelete(w)
    expect(acceptButton().disabled).toBe(true)
    fill('[data-testid="confirm-reason"] textarea', 'contract ended')
    fill('[data-testid="confirm-typed"] input', 'acm')
    await flushPromises()
    expect(acceptButton().disabled).toBe(true)
    fill('[data-testid="confirm-typed"] input', 'acme')
    await flushPromises()
    expect(acceptButton().disabled).toBe(false)
  })

  it('requires a reason of at least two characters', async () => {
    const w = await mountView()
    await openDelete(w)
    fill('[data-testid="confirm-typed"] input', 'acme')
    fill('[data-testid="confirm-reason"] textarea', 'x')
    await flushPromises()
    expect(acceptButton().disabled).toBe(true)
  })

  it('offers 30 days of grace and shows a validation message outside 7 to 90', async () => {
    const w = await mountView()
    await openDelete(w)
    expect((document.querySelector('[data-testid="delete-grace-days"] input') as HTMLInputElement).value).toBe('30')
    expect(document.body.textContent).not.toContain('Enter a whole number of days from 7 to 90.')
    for (const value of ['6', '91', '', '7.5']) {
      fill('[data-testid="delete-grace-days"] input', value)
      await flushPromises()
      expect(document.body.textContent).toContain('Enter a whole number of days from 7 to 90.')
    }
    fill('[data-testid="delete-grace-days"] input', '90')
    await flushPromises()
    expect(document.body.textContent).not.toContain('Enter a whole number of days from 7 to 90.')
  })

  it('does not send the request while the grace period is invalid', async () => {
    const w = await mountView()
    await openDelete(w)
    fill('[data-testid="confirm-typed"] input', 'acme')
    fill('[data-testid="confirm-reason"] textarea', 'contract ended')
    fill('[data-testid="delete-grace-days"] input', '3')
    await flushPromises()
    acceptButton().click()
    await flushPromises()
    expect(requestDeletion).not.toHaveBeenCalled()
    expect(document.querySelector('[data-testid="confirm-dialog"]')).not.toBeNull()
  })

  it('sends slug, reason and grace days', async () => {
    requestDeletion.mockResolvedValue(null)
    const w = await mountView()
    await openDelete(w)
    fill('[data-testid="confirm-typed"] input', 'acme')
    fill('[data-testid="confirm-reason"] textarea', ' contract ended ')
    fill('[data-testid="delete-grace-days"] input', '14')
    await flushPromises()
    acceptButton().click()
    await flushPromises()
    expect(requestDeletion).toHaveBeenCalledExactlyOnceWith({ id: 'o1', slug: 'acme', reason: 'contract ended', graceDays: 14 })
    expect(document.querySelector('[data-testid="confirm-dialog"]')).toBeNull()
  })

  it('starts the step-up when the server asks for it', async () => {
    requestDeletion.mockResolvedValue('step_up_required')
    const w = await mountView()
    await openDelete(w)
    fill('[data-testid="confirm-typed"] input', 'acme')
    fill('[data-testid="confirm-reason"] textarea', 'contract ended')
    await flushPromises()
    acceptButton().click()
    await flushPromises()
    expect(startStepUp).toHaveBeenCalledExactlyOnceWith('organization-delete', 'organization',
      { id: 'o1', slug: 'acme', reason: 'contract ended', graceDays: 30 })
  })

  it('repeats the request once after the step-up without starting another', async () => {
    requestDeletion.mockResolvedValue('step_up_required')
    resumed = { failed: false, payload: { id: 'o1', slug: 'acme', reason: 'contract ended', graceDays: 14 } }
    await mountView()
    expect(requestDeletion).toHaveBeenCalledExactlyOnceWith({ id: 'o1', slug: 'acme', reason: 'contract ended', graceDays: 14 })
    expect(startStepUp).not.toHaveBeenCalled()
  })

  it('shows a problem and sends nothing when the step-up was refused', async () => {
    resumed = { failed: true }
    const w = await mountView()
    expect(requestDeletion).not.toHaveBeenCalled()
    expect(w.find('[data-testid="organization-deletion-problem"]').exists()).toBe(true)
  })

  it('shows the problem of a refused request', async () => {
    requestDeletion.mockResolvedValue('invalid_state')
    const w = await mountView()
    await openDelete(w)
    fill('[data-testid="confirm-typed"] input', 'acme')
    fill('[data-testid="confirm-reason"] textarea', 'contract ended')
    await flushPromises()
    acceptButton().click()
    await flushPromises()
    expect(w.get('[data-testid="organization-deletion-problem"]').text()).toContain('This action is not possible in the current state.')
  })
})

describe('a pending deletion', () => {
  it('shows the date and offers cancel instead of delete', async () => {
    rows = [{ ...active, deletion }]
    const w = await mountView()
    expect(w.get('[data-testid="org-deletion-pending-acme"]').text()).toContain('Deletion on')
    expect(w.find('[data-testid="org-cancel-deletion-acme"]').exists()).toBe(true)
    expect(w.find('[data-testid="org-delete-acme"]').exists()).toBe(false)
  })

  it('offers no cancel for an organization without deletion', async () => {
    const w = await mountView()
    expect(w.find('[data-testid="org-cancel-deletion-acme"]').exists()).toBe(false)
    expect(w.find('[data-testid="org-deletion-pending-acme"]').exists()).toBe(false)
  })

  it('offers no cancel once the deletion runs, and shows step and last error', async () => {
    rows = [{ ...active, status: 'deleting', deletion: { ...deletion, step: 'fleet', last_error_code: 'upstream_unavailable' } }]
    const w = await mountView()
    expect(w.find('[data-testid="org-cancel-deletion-acme"]').exists()).toBe(false)
    expect(w.find('[data-testid="org-delete-acme"]').exists()).toBe(false)
    const text = w.get('[data-testid="org-deletion-step-acme"]').text()
    expect(text).toContain('Step: fleet')
    expect(text).toContain('The identity provider is not reachable.')
  })

  it('cancels after confirmation', async () => {
    rows = [{ ...active, deletion }]
    cancelDeletion.mockResolvedValue(null)
    const w = await mountView()
    await w.get('[data-testid="org-cancel-deletion-acme"]').trigger('click')
    await flushPromises()
    expect(pendingConfirm.value?.options.title).toBe('Cancel the deletion of Acme?')
    expect(cancelDeletion).not.toHaveBeenCalled()
    settleConfirm({ reason: '' })
    await flushPromises()
    expect(cancelDeletion).toHaveBeenCalledExactlyOnceWith('o1')
  })

  it('does not cancel when the confirmation is declined', async () => {
    rows = [{ ...active, deletion }]
    const w = await mountView()
    await w.get('[data-testid="org-cancel-deletion-acme"]').trigger('click')
    await flushPromises()
    settleConfirm(false)
    await flushPromises()
    expect(cancelDeletion).not.toHaveBeenCalled()
  })
})

describe('the deletion banner for organization administrators', () => {
  const me: Me = {
    id: '00000000-0000-0000-0000-000000000001', username: 'alice@acme.test', display_name: 'Alice Admin',
    role: 'org_admin', organization: { id: '00000000-0000-0000-0000-0000000000aa', slug: 'acme', name: 'Acme', domains: [] },
    locale: 'en', theme: 'system', revocation_enabled: false, client_ip: '198.51.100.7', step_up_valid_until: null,
    server_version: '0.1.0-alpha.6', alternate_role: null, channel: 'portal', mcp_write_enabled: false,
    mcp_write_enabled_at: null, organization_deletion: null, mfa_enrolment_notice: null,
  }

  function mountBanner(value: Me): VueWrapper {
    const pinia = createPinia()
    setActivePinia(pinia)
    useSessionStore().me = value
    wrapper = mount(() => h(VApp, null, { default: () => h(OrganizationDeletionBanner) }),
      { global: { plugins: [createPortalI18n(), vuetify, pinia] }, attachTo: document.body })
    return wrapper
  }

  it('warns with the date and the advice while the deletion is pending', () => {
    const w = mountBanner({ ...me, organization_deletion: { delete_after: '2026-12-01T00:00:00Z', recovery_export_until: '2026-11-30T23:40:00Z', devices_pending: 0 } })
    const text = w.get('[data-testid="organization-deletion-banner"]').text()
    expect(text).toContain('scheduled for deletion on')
    expect(text).toContain('recovery keys')
    expect(text).toContain('local administrators')
  })

  it('counts the devices still pending approval when there are some', () => {
    const w = mountBanner({ ...me, organization_deletion: { delete_after: '2026-12-01T00:00:00Z', recovery_export_until: '2026-11-30T23:40:00Z', devices_pending: 2 } })
    const text = w.get('[data-testid="organization-deletion-pending"]').text()
    expect(text).toContain('2 devices are still pending approval')
    expect(text).toContain('apt purge paddock-agent paddock-supervisor')
  })

  it('does not mention pending devices when there are none', () => {
    const w = mountBanner({ ...me, organization_deletion: { delete_after: '2026-12-01T00:00:00Z', recovery_export_until: '2026-11-30T23:40:00Z', devices_pending: 0 } })
    expect(w.find('[data-testid="organization-deletion-pending"]').exists()).toBe(false)
  })

  it('is absent without a pending deletion', () => {
    const w = mountBanner(me)
    expect(w.find('[data-testid="organization-deletion-banner"]').exists()).toBe(false)
  })

  it('is absent for a platform administrator', () => {
    const w = mountBanner({ ...me, role: 'platform_admin', organization: null })
    expect(w.find('[data-testid="organization-deletion-banner"]').exists()).toBe(false)
  })
})

describe('deleted organizations in the list', () => {
  it('links a deleted organization to its retained audit and flags a failed final verification', async () => {
    rows = [{
      ...active, status: 'deleted',
      deletion: { ...deletion, deleted_at: '2026-12-01T01:00:00Z', audit_final_verified_at: '2026-12-01T00:30:00Z', audit_final_outcome: 'failed' },
    }]
    const w = await mountView()
    expect(w.find('[data-testid="org-audit-acme"]').exists()).toBe(true)
    expect(w.get('[data-testid="org-audit-failed-acme"]').text()).toContain('Audit verification failed')
    expect(w.find('[data-testid="org-delete-acme"]').exists()).toBe(false)
  })

  it('offers no retained audit for an active organization', async () => {
    const w = await mountView()
    expect(w.find('[data-testid="org-audit-acme"]').exists()).toBe(false)
  })
})
