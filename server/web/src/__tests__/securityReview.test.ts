import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { h } from 'vue'
import { createPinia, setActivePinia } from 'pinia'
import { createMemoryHistory, createRouter, RouterView } from 'vue-router'
import { flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import { VApp } from 'vuetify/components'
import SecurityReviewView from '../views/SecurityReview.vue'
import { createPortalI18n } from '../i18n'
import { vuetify } from '../plugins/vuetify'
import { pendingConfirm, settleConfirm } from '../composables/useConfirm'
import type { PermissionProfile, SecurityReview } from '../api/client'
import type { ReviewConfirmation } from '../lib/securityReview'
import { useSessionStore } from '../stores/session'

const shell: PermissionProfile = {
  id: 'p1', name: 'legacy shell', class: 'restricted', commands: ['/usr/bin/bash'], require_password: true,
  timestamp_timeout_min: 5, lecture: 'once', root_equivalent: true, effective_class: 'full',
  root_equivalent_commands: ['/usr/bin/bash'], invalid_commands: [], root_grant_confirmed_at: null,
  created_at: '2026-10-01T00:00:00Z', updated_at: '2026-10-01T00:00:00Z',
}
const empty = { total: 0, items: [] }
let review: SecurityReview
const confirmReviewItem = vi.fn<(c: ReviewConfirmation) => Promise<string | null>>()

vi.mock('../lib/securityReview', () => ({
  getSecurityReview: () => Promise.resolve(review),
  confirmReviewItem: (c: ReviewConfirmation) => confirmReviewItem(c),
}))

let wrapper: VueWrapper | null = null
const assign = vi.fn()

beforeEach(() => {
  sessionStorage.clear()
  confirmReviewItem.mockReset()
  assign.mockReset()
  review = {
    generated_at: '2026-10-16T00:00:00Z', root_grants: { total: 1, items: [{ profile: shell, assignments: 2 }] },
    sensitive_files: empty, denied_files: {
      total: 1, items: [{
        id: 'f1', device_group_id: null, path: '/etc/ld.so.preload', mode: '0644', owner: 'root', group: 'root', content: '',
        tier: 'denied', sensitive_confirmed_at: null, created_at: '2026-10-01T00:00:00Z', updated_at: '2026-10-01T00:00:00Z',
      }],
    },
  }
  Object.defineProperty(window, 'location', {
    value: { ...window.location, assign, href: 'https://admin.test/security-review', search: '' }, writable: true,
  })
})

afterEach(() => {
  wrapper?.unmount()
  wrapper = null
})

async function mountReview(): Promise<VueWrapper> {
  const pinia = createPinia()
  setActivePinia(pinia)
  useSessionStore().me = { id: 'a', username: 'alice', display_name: 'Alice', role: 'org_admin', locale: 'en', organization: null } as never
  const stub = { render: () => null }
  const router = createRouter({
    history: createMemoryHistory(),
    routes: [
      { path: '/security-review', name: 'security-review', component: SecurityReviewView },
      { path: '/permission-profiles/:id', name: 'permission-profile', component: stub },
      { path: '/managed-files', name: 'managed-files', component: stub },
    ],
  })
  await router.push('/security-review')
  await router.isReady()
  const App = () => h(VApp, null, { default: () => h(RouterView) })
  wrapper = mount(App, { global: { plugins: [createPortalI18n(), vuetify, router, pinia] }, attachTo: document.body })
  await flushPromises()
  return wrapper
}

describe('SecurityReview (ADR 0034 decision 7)', () => {
  it('lists the root grants with their assignments and the denied files with a link to their definition', async () => {
    const w = await mountReview()
    const grants = w.find('[data-testid="review-root-grants"]')
    expect(grants.text()).toContain('legacy shell')
    expect(grants.text()).toContain('Full (effective)')
    const denied = w.find('[data-testid="review-denied-files"]')
    expect(denied.find('a').attributes('href')).toBe('/managed-files?q=/etc/ld.so.preload')
  })

  it('confirms a row after the dialog and the step-up, and the row is gone after the return', async () => {
    confirmReviewItem.mockResolvedValueOnce('step_up_required')
    const w = await mountReview()
    await w.find('[data-testid="review-root-grants"] button').trigger('click')
    await flushPromises()
    expect(pendingConfirm.value?.options.message).toContain('legacy shell')
    settleConfirm({ reason: '' })
    await flushPromises()
    expect(confirmReviewItem).toHaveBeenCalledWith({ kind: 'profile', id: 'p1' })
    expect(assign).toHaveBeenCalledWith('/api/auth/stepup?return_to=%2Fsecurity-review')
    wrapper?.unmount()

    confirmReviewItem.mockImplementationOnce(async () => {
      review = { ...review, root_grants: empty }
      return null
    })
    const resumed = await mountReview()
    expect(confirmReviewItem).toHaveBeenCalledTimes(2)
    expect(resumed.find('[data-testid="review-root-grants"]').exists()).toBe(false)
    expect(resumed.text()).toContain('Nothing to review.')
  })
})
